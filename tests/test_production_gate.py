"""Contracts for the machine-readable EXE/DLL production readiness gate."""
from __future__ import annotations

import json
import hashlib
import struct
from pathlib import Path

import pytest

from tools import pe_feature_probe, production_gate, release_check


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "production_compatibility.json"


def test_repository_matrix_is_valid_and_explicitly_red() -> None:
    matrix = production_gate.load_matrix(MATRIX)
    all_result = production_gate.evaluate(matrix, "all")
    exe_result = production_gate.evaluate(matrix, "exe")
    dll_result = production_gate.evaluate(matrix, "dll")

    assert not all_result["ready"]
    assert not exe_result["ready"]
    assert not dll_result["ready"]
    assert {item["id"] for item in all_result["blockers"]} >= {
        "mitigation.load_config_cfg_xfg",
        "virtualization.selected_functions",
        "hardening.process_policy",
        "hardening.antidebug",
        "hardening.memory_guard_native",
        "provenance.fresh_native_stub",
        "release.clean_vm_matrix",
    }


def test_runtime_hardening_rows_have_independent_scope_and_maturity() -> None:
    matrix = production_gate.load_matrix(MATRIX)
    by_id = {feature["id"]: feature for feature in matrix["features"]}

    assert "hardening.runtime_layers" not in by_id
    assert by_id["hardening.antidump_metadata"]["status"] == "proven"
    assert by_id["hardening.antidump_metadata"]["applies_to"] == ["exe", "dll"]
    assert by_id["hardening.process_policy"]["status"] == "partial"
    assert by_id["hardening.process_policy"]["applies_to"] == ["exe"]
    assert by_id["hardening.antidebug"]["status"] == "experimental"
    assert by_id["hardening.antidebug"]["applies_to"] == ["exe", "dll"]
    assert by_id["hardening.memory_guard_native"]["status"] == "experimental"
    assert by_id["hardening.memory_guard_native"]["applies_to"] == ["exe"]


def test_json_cli_result_is_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    assert production_gate.main(["--scope", "exe", "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == 1
    assert payload["scope"] == "exe"
    assert payload["ready"] is False
    assert payload["blocker_count"] > 0


def test_native_checks_require_clean_passing_evidence(tmp_path: Path) -> None:
    matrix = production_gate.load_matrix(MATRIX)
    missing = production_gate.evaluate(matrix, "exe")
    assert any(item["status"] == "evidence-missing" for item in missing["blockers"])

    checks = sorted({
        check
        for feature in matrix["features"]
        for check in feature.get("native_checks", [])
    })
    stub = tmp_path / "stub.dll"
    stub.write_bytes(b"native candidate")
    tests = [{"id": check, "status": "passed"} for check in checks]
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps({
        "schema": 1,
        "source_commit": "a" * 40,
        "tracked_source_dirty": False,
        "stub_path": str(stub),
        "stub_sha256": hashlib.sha256(stub.read_bytes()).hexdigest(),
        "passed": len(tests),
        "total": len(tests),
        "ready": True,
        "tests": tests,
    }), encoding="utf-8")
    evidence = production_gate.load_evidence(evidence_path)
    result = production_gate.evaluate(matrix, "exe", evidence)
    assert not any(item["status"] == "evidence-missing" for item in result["blockers"])
    assert not any(item["status"] == "evidence-failed" for item in result["blockers"])

    dirty_path = tmp_path / "dirty.json"
    dirty_payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    dirty_payload["tracked_source_dirty"] = True
    dirty_path.write_text(json.dumps(dirty_payload), encoding="utf-8")
    dirty = production_gate.load_evidence(dirty_path)
    dirty_result = production_gate.evaluate(matrix, "exe", dirty)
    assert any(item["id"] == "evidence.source_tree" for item in dirty_result["blockers"])


def test_validate_only_checks_contract_without_false_pass(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert production_gate.main(["--validate-only", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["validated_only"] is True
    assert payload["ready"] is False


def test_public_release_check_does_not_treat_validate_only_as_readiness(
) -> None:
    errors: list[str] = []

    release_check._check_production_matrix(errors, {"evidence": []})

    assert errors and "independently evaluate" in errors[0]


def test_required_non_proven_entry_needs_actionable_blocker(tmp_path: Path) -> None:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    target = next(item for item in matrix["features"] if item["status"] != "proven")
    target.pop("blocker")
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(matrix), encoding="utf-8")

    with pytest.raises(production_gate.MatrixError, match="needs a blocker"):
        production_gate.load_matrix(path)


def test_proven_entry_still_requires_repository_evidence(tmp_path: Path) -> None:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    target = next(item for item in matrix["features"] if item["status"] == "proven")
    target["evidence"][0]["path"] = "tests/does_not_exist.py"
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(matrix), encoding="utf-8")

    with pytest.raises(production_gate.MatrixError, match="missing evidence path"):
        production_gate.load_matrix(path)


def test_feature_probe_reads_bounded_pe32_plus_directory() -> None:
    blob = bytearray(0x200)
    blob[:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x80)
    blob[0x80:0x84] = b"PE\0\0"
    optional = 0x80 + 24
    struct.pack_into("<H", blob, optional, 0x20B)
    struct.pack_into("<I", blob, optional + 108, 16)
    struct.pack_into("<II", blob, optional + 112 + 13 * 8, 0x3450, 0x40)

    assert pe_feature_probe._directory(bytes(blob), 13) == (0x3450, 0x40)
    assert pe_feature_probe._directory(bytes(blob), 16) == (0, 0)
    with pytest.raises(ValueError, match="DOS header"):
        pe_feature_probe._directory(b"not-a-pe", 13)
