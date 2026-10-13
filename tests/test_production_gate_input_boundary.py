"""Release input boundaries reject ambiguous or mistyped readiness evidence."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tools import production_gate


@pytest.fixture
def inputs(tmp_path):
    stub = tmp_path / "stub.fixture"
    stub.write_bytes(b"synthetic native evidence artifact - never executed")
    matrix = {
        "schema": 1,
        "status_values": sorted(production_gate.VALID_STATUSES),
        "features": [{
            "id": "fixture.required", "title": "Synthetic evidence boundary",
            "applies_to": ["exe", "dll"], "required": True, "status": "proven",
            "native_checks": ["fixture.runtime"],
            "evidence": [{"path": "tests/test_production_gate.py", "type": "pytest",
                          "claim": "Synthetic parser fixture, not product acceptance"}],
        }],
    }
    evidence = {
        "schema": 1, "source_commit": "a" * 40, "tracked_source_dirty": False,
        "stub_path": str(stub),
        "stub_sha256": hashlib.sha256(stub.read_bytes()).hexdigest(),
        "tests": [{"id": "fixture.runtime", "status": "passed"}],
        "passed": 1, "total": 1, "ready": True,
    }
    return matrix, evidence


def document(tmp_path, name, payload):
    path = tmp_path / (name + ".json")
    path.write_bytes(json.dumps(payload).encode("utf-8"))
    return path


def load(kind, path):
    return (production_gate.load_matrix if kind == "matrix"
            else production_gate.load_evidence)(path)


@pytest.mark.parametrize("scope", ["all", "exe", "dll"])
@pytest.mark.parametrize("bom", [False, True])
def test_valid_native_bom_and_all_supported_scopes_keep_exact_results(inputs, tmp_path, scope, bom):
    matrix, evidence = inputs
    m = production_gate.load_matrix(document(tmp_path, "matrix", matrix))
    path = document(tmp_path, "evidence", evidence)
    if bom:
        path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    e = production_gate.load_evidence(path)
    assert production_gate.evaluate(m, scope, e) == {
        "schema": 1, "scope": scope, "ready": True, "required_features": 1,
        "proven_features": 1, "blocker_count": 0, "blockers": [],
    }


@pytest.mark.parametrize("scope", ["", "EXE", "alll", None, 1, True, [], {}])
def test_invalid_programmatic_scope_never_becomes_empty_green_gate(inputs, tmp_path, scope):
    matrix, _ = inputs
    matrix = production_gate.load_matrix(document(tmp_path, "matrix", matrix))
    with pytest.raises(production_gate.MatrixError, match="scope"):
        production_gate.evaluate(matrix, scope)


@pytest.mark.parametrize(("kind", "old", "new"), [
    ("matrix", '"schema": 1', '"schema": 1, "schema": 1'),
    ("matrix", '"status": "proven"', '"status": "blocked", "status": "proven"'),
    ("matrix", '"required": true', '"required": false, "required": true'),
    ("matrix", '"schema": 1', '"schema": 1, "\\u0073chema": 1'),
    ("evidence", '"schema": 1', '"schema": 1, "schema": 1'),
    ("evidence", '"status": "passed"', '"status": "failed", "status": "passed"'),
    ("evidence", '"tracked_source_dirty": false', '"tracked_source_dirty": true, "tracked_source_dirty": false'),
    ("evidence", '"passed": 1', '"passed": 0, "passed": 1'),
    ("evidence", '"schema": 1', '"schema": 1, "\\u0073chema": 1'),
])
def test_duplicate_keys_reject_even_equal_values_and_escaped_aliases(inputs, tmp_path, kind, old, new):
    payload = inputs[kind == "evidence"]
    raw = json.dumps(payload)
    assert raw.count(old) == 1
    path = tmp_path / (kind + ".json")
    path.write_bytes(raw.replace(old, new).encode())
    with pytest.raises(production_gate.MatrixError, match="duplicate"):
        load(kind, path)


@pytest.mark.parametrize("kind", ["matrix", "evidence"])
@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e9999"])
def test_nonfinite_numbers_reject_even_in_unknown_metadata(inputs, tmp_path, kind, number):
    raw = json.dumps(inputs[kind == "evidence"])
    path = tmp_path / (kind + ".json")
    path.write_bytes((raw[:-1] + ', "unused": ' + number + '}').encode())
    with pytest.raises(production_gate.MatrixError, match="nonfinite"):
        load(kind, path)


@pytest.mark.parametrize(("kind", "field"), [
    ("matrix", "schema"), ("evidence", "schema"),
    ("evidence", "passed"), ("evidence", "total"),
])
@pytest.mark.parametrize("value", [True, 1.0])
def test_schema_and_summary_counts_require_exact_integers(inputs, tmp_path, kind, field, value):
    payload = inputs[kind == "evidence"]
    payload[field] = value
    with pytest.raises(production_gate.MatrixError, match=field):
        load(kind, document(tmp_path, kind, payload))


@pytest.mark.parametrize(("field", "value"), [
    ("status_values", ["proven", "failing", "blocked", "partial", "experimental", "unverified", "proven"]),
    ("status_values", [{}, "proven"]), ("status_values", [["proven"]]),
    ("applies_to", ["exe", {}]), ("applies_to", [["exe"]]),
    ("applies_to", ["exe", 1]), ("applies_to", ["exe", "exe"]),
    ("native_checks", ["fixture.runtime", {}]),
    ("native_checks", [["fixture.runtime"]]),
    ("native_checks", ["fixture.runtime", "fixture.runtime"]),
    ("status", []), ("status", {}), ("status", 1),
])
def test_malformed_matrix_members_have_typed_diagnostics(inputs, tmp_path, field, value):
    matrix, _ = inputs
    target = matrix if field == "status_values" else matrix["features"][0]
    target[field] = value
    with pytest.raises(production_gate.MatrixError):
        production_gate.load_matrix(document(tmp_path, "matrix", matrix))


@pytest.mark.parametrize("status", [[], {}, 1, None])
def test_malformed_native_status_has_typed_diagnostic(inputs, tmp_path, status):
    _, evidence = inputs
    evidence["tests"][0]["status"] = status
    with pytest.raises(production_gate.MatrixError, match="status"):
        production_gate.load_evidence(document(tmp_path, "evidence", evidence))


@pytest.mark.parametrize("path", ["invalid\0path", "invalid\ud800path"])
def test_invalid_repository_evidence_path_has_typed_diagnostic(inputs, tmp_path, path):
    matrix, _ = inputs
    matrix["features"][0]["evidence"][0]["path"] = path
    with pytest.raises(production_gate.MatrixError):
        production_gate.load_matrix(document(tmp_path, "matrix", matrix))


@pytest.mark.parametrize("kind", ["matrix", "evidence"])
@pytest.mark.parametrize("raw", [b"[]", b"null", b"{} {}", b'{"bad":"\xff"}', b'{"bad":}'])
def test_bad_encoding_syntax_or_root_has_typed_diagnostic(inputs, tmp_path, kind, raw):
    path = tmp_path / (kind + ".json")
    path.write_bytes(raw)
    with pytest.raises(production_gate.MatrixError):
        load(kind, path)


@pytest.mark.parametrize("kind", ["matrix", "evidence"])
@pytest.mark.parametrize("bound", ["bytes", "depth", "nodes"])
def test_bounded_json_rejects_large_deep_or_flat_input(inputs, tmp_path, kind, bound):
    raw = json.dumps(inputs[kind == "evidence"]).encode()
    if bound == "bytes":
        raw += b" " * (1_048_577 - len(raw))
    elif bound == "depth":
        raw = raw[:-1] + b',"unused":' + b'[' * 64 + b'0' + b']' * 64 + b'}'
    else:
        raw = raw[:-1] + b',"unused":[' + b'0,' * 100_000 + b'0]}'
    path = tmp_path / (kind + ".json")
    path.write_bytes(raw)
    with pytest.raises(production_gate.MatrixError, match="limit"):
        load(kind, path)


@pytest.mark.parametrize(("kind", "bom"), [("matrix", False), ("evidence", False), ("evidence", True)])
def test_document_byte_bound_is_inclusive_including_native_bom(inputs, tmp_path, kind, bom):
    raw = (b"\xef\xbb\xbf" if bom else b"") + json.dumps(inputs[kind == "evidence"]).encode()
    raw += b" " * (1_048_576 - len(raw))
    path = tmp_path / (kind + ".json")
    path.write_bytes(raw)
    assert load(kind, path)["schema"] == 1
    path.write_bytes(raw + b" ")
    with pytest.raises(production_gate.MatrixError, match="limit"):
        load(kind, path)


def test_matrix_bom_stays_rejected(inputs, tmp_path):
    matrix, _ = inputs
    path = document(tmp_path, "matrix", matrix)
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    with pytest.raises(production_gate.MatrixError):
        production_gate.load_matrix(path)


def test_stub_read_failure_has_typed_diagnostic(inputs, tmp_path, monkeypatch):
    _, evidence = inputs
    path = document(tmp_path, "evidence", evidence)
    original = Path.read_bytes
    def fail_stub_read(self):
        if self == Path(evidence["stub_path"]):
            raise PermissionError("synthetic native artifact read failure")
        return original(self)
    monkeypatch.setattr(Path, "read_bytes", fail_stub_read)
    with pytest.raises(production_gate.MatrixError, match="read"):
        production_gate.load_evidence(path)


@pytest.mark.parametrize("mode", ["script", "module"])
@pytest.mark.parametrize("malformed", ["duplicate-matrix", "duplicate-evidence", "unhashable-matrix", "unhashable-evidence"])
def test_cli_reports_invalid_json_without_traceback_or_false_green(inputs, tmp_path, mode, malformed):
    matrix, evidence = inputs
    m = document(tmp_path, "matrix", matrix)
    e = document(tmp_path, "evidence", evidence)
    if malformed == "duplicate-matrix":
        m.write_bytes(m.read_bytes().replace(b'"status": "proven"', b'"status": "blocked", "status": "proven"'))
    elif malformed == "duplicate-evidence":
        e.write_bytes(e.read_bytes().replace(b'"status": "passed"', b'"status": "failed", "status": "passed"'))
    elif malformed == "unhashable-matrix":
        matrix["features"][0]["applies_to"] = [{}]
        document(tmp_path, "matrix", matrix)
    else:
        evidence["tests"][0]["status"] = []
        document(tmp_path, "evidence", evidence)
    command = [sys.executable, "-B"]
    command += ([str(production_gate.ROOT / "tools" / "production_gate.py")]
                if mode == "script" else ["-m", "tools.production_gate"])
    command += ["--matrix", str(m), "--evidence", str(e), "--format", "json"]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(production_gate.ROOT)
    result = subprocess.run(command, cwd=production_gate.ROOT, env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 2, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["ready"] is False and payload["error"]
    assert result.stderr == ""
