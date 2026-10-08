"""Read-only scanner receipt contracts; no scanners or production keys used."""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from packer import scanner_evidence as evidence


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _shift(value: str, seconds: int) -> str:
    return (evidence.parse_utc(value, "test") + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Case:
    path: Path
    output: Path
    scanner: dict
    scan: dict
    subject: dict
    receipt: dict
    issued: str = "2026-10-07T12:03:00Z"

    def save(self, data: bytes | None = None) -> None:
        data = data if data is not None else json.dumps(self.receipt, sort_keys=True).encode()
        self.path.write_bytes(data)
        self.scan["receipt_sha256"] = _digest(data)

    def validate(self) -> None:
        evidence.validate_scan_receipt(
            self.path, scanner=self.scanner, scan=self.scan, subject=self.subject,
            raw_output_path=self.output, issued_at_utc=self.issued)

    def definitions(self, value: str) -> None:
        self.receipt["definitions_updated_at_utc"] = value
        for field in ("defender_before", "defender_after"):
            if field in self.receipt:
                self.receipt[field]["AntivirusSignatureLastUpdated"] = value


def _case(tmp_path: Path, *, defender: bool = True) -> Case:
    scanner = {"scanner_id": "microsoft-defender" if defender else "independent-engine",
               "tool_name": "Fixture scanner", "tool_version": "4.18.1",
               "engine_version": "1.1.1", "definitions_version": "1.2.3"}
    subject = {"subject_id": "product-exe", "subject_sha256": _digest(b"subject"),
               "subject_size_bytes": 123, "source_commit": "a" * 40,
               "candidate_manifest_sha256": "b" * 64,
               "protected_with_stub_sha256": "c" * 64}
    output = tmp_path / "scanner-output.txt"
    output.write_bytes(b"Fixture engine completed: clean; zero detections.\n")
    digest = _digest(output.read_bytes())
    scan = {"scanner_id": scanner["scanner_id"], "status": "passed", "detections": 0,
            "scan_time_utc": "2026-10-07T12:01:00Z", "output_sha256": digest}
    receipt = {
        "schema": 1, "kind": "lethe-scanner-receipt", **scanner,
        "subject_id": subject["subject_id"],
        "subject_sha256_before": subject["subject_sha256"],
        "subject_sha256_after": subject["subject_sha256"],
        "subject_size_bytes_before": subject["subject_size_bytes"],
        "subject_size_bytes_after": subject["subject_size_bytes"],
        "source_commit": subject["source_commit"],
        "candidate_manifest_sha256": subject["candidate_manifest_sha256"],
        "protected_with_stub_sha256": subject["protected_with_stub_sha256"],
        "scan_started_at_utc": "2026-10-07T12:00:00Z",
        "scan_completed_at_utc": scan["scan_time_utc"],
        "collected_at_utc": "2026-10-07T12:02:00Z",
        "definitions_updated_at_utc": "2026-10-07T11:00:00Z",
        "status": "completed", "verdict": "clean", "detections": 0,
        "exit_code": 0, "output_sha256": digest,
    }
    if defender:
        for field, observed in (("defender_before", "2026-10-07T11:59:00Z"),
                                ("defender_after", "2026-10-07T12:01:30Z")):
            receipt[field] = {"observed_at_utc": observed, "AMServiceEnabled": True,
                              "AntivirusEnabled": True, "RealTimeProtectionEnabled": True,
                              "AMEngineVersion": scanner["engine_version"],
                              "AntivirusSignatureVersion": scanner["definitions_version"],
                              "AntivirusSignatureLastUpdated": receipt["definitions_updated_at_utc"]}
    case = Case(tmp_path / "receipt.json", output, scanner, scan, subject, receipt)
    case.save()
    return case


@pytest.mark.parametrize("defender", [False, True])
def test_valid_receipt_is_read_only(tmp_path: Path, defender: bool) -> None:
    case = _case(tmp_path, defender=defender)
    files = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    metadata = copy.deepcopy((case.scanner, case.scan, case.subject))
    assert case.validate() is None
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == files
    assert (case.scanner, case.scan, case.subject) == metadata


def test_defender_realtime_flag_is_recorded_not_required_true(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case.receipt["defender_before"]["RealTimeProtectionEnabled"] = False
    case.receipt["defender_after"]["RealTimeProtectionEnabled"] = False
    case.save()
    case.validate()


@pytest.mark.parametrize("value", [None, True, 123, "", "2026-10-07", "2026-10-07T12:00:00+00:00",
                                   "2026-10-07T12:00:00.000Z", "2026-10-07t12:00:00Z",
                                   "2026-10-07T12:00:00z", "2026-02-30T12:00:00Z",
                                   "2026-10-07T12:00:60Z", "0000-01-01T00:00:00Z",
                                   "2026-10-07T12:00:00Z\n"])
def test_parse_utc_rejects_noncanonical_or_invalid(value) -> None:
    with pytest.raises(evidence.ScannerEvidenceError):
        evidence.parse_utc(value, "test")


def test_parse_utc_returns_aware_utc() -> None:
    assert evidence.parse_utc("2024-02-29T12:34:56Z", "test") == datetime(2024, 2, 29, 12, 34, 56, tzinfo=timezone.utc)


@pytest.mark.parametrize("data", [b"[]", b"null", b"{bad", b'\xef\xbb\xbf{}', b'\xff',
                                  b'{"schema":1,"schema":1}', b'{"x":NaN}',
                                  b'{"x":Infinity}', b'{"x":1e999}',
                                  b'{"x":' + b'[' * 65 + b']' * 65 + b'}'])
def test_receipt_strict_json(tmp_path: Path, data: bytes) -> None:
    case = _case(tmp_path)
    case.save(data)
    with pytest.raises(evidence.ScannerEvidenceError):
        case.validate()


@pytest.mark.parametrize("field,value", [
    ("schema", True), ("schema", 1.0), ("schema", 2), ("kind", "other"),
    ("scanner_id", "other"), ("tool_name", "other"), ("tool_version", "other"),
    ("engine_version", "other"), ("definitions_version", "other"),
    ("subject_id", "other"), ("subject_sha256_before", "d" * 64),
    ("subject_sha256_after", "d" * 64), ("subject_size_bytes_before", 122),
    ("subject_size_bytes_after", 124), ("subject_size_bytes_before", True),
    ("subject_size_bytes_after", 123.0), ("source_commit", "d" * 40),
    ("candidate_manifest_sha256", "d" * 64), ("protected_with_stub_sha256", "d" * 64),
    ("status", "started"), ("verdict", "unknown"), ("detections", True),
    ("detections", 0.0), ("detections", 1), ("exit_code", False),
    ("exit_code", 0.0), ("exit_code", 1), ("output_sha256", "d" * 64),
    ("scan_completed_at_utc", "2026-10-07T12:01:01Z"),
])
def test_receipt_types_and_bindings_rejected(tmp_path: Path, field: str, value) -> None:
    case = _case(tmp_path)
    case.receipt[field] = value
    case.save()
    with pytest.raises(evidence.ScannerEvidenceError):
        case.validate()


@pytest.mark.parametrize("defender", [False, True])
@pytest.mark.parametrize("extra", [False, True])
def test_exact_receipt_fields(tmp_path: Path, defender: bool, extra: bool) -> None:
    case = _case(tmp_path, defender=defender)
    if extra:
        case.receipt["unexpected"] = True
    else:
        del case.receipt["engine_version"]
    case.save()
    with pytest.raises(evidence.ScannerEvidenceError, match="fields"):
        case.validate()


@pytest.mark.parametrize("observation", ["defender_before", "defender_after"])
@pytest.mark.parametrize("field,value", [
    ("AMServiceEnabled", False), ("AMServiceEnabled", 1), ("AMServiceEnabled", None),
    ("AntivirusEnabled", False), ("AntivirusEnabled", "true"),
    ("RealTimeProtectionEnabled", 0), ("RealTimeProtectionEnabled", "false"),
    ("AMEngineVersion", "next"), ("AntivirusSignatureVersion", "next"),
    ("AntivirusSignatureLastUpdated", "2026-10-07T10:00:00Z"),
])
def test_defender_state_and_binding_rejected(tmp_path: Path, observation: str, field: str, value) -> None:
    case = _case(tmp_path)
    case.receipt[observation][field] = value
    case.save()
    with pytest.raises(evidence.ScannerEvidenceError):
        case.validate()


@pytest.mark.parametrize("state", [None, [], {}, {"unexpected": True}])
def test_defender_exact_observation_fields(tmp_path: Path, state) -> None:
    case = _case(tmp_path)
    case.receipt["defender_before"] = state
    case.save()
    with pytest.raises(evidence.ScannerEvidenceError, match="observation fields"):
        case.validate()


@pytest.mark.parametrize("boundary", ["definitions-age", "evidence-age", "collection-skew",
                                       "before-start", "complete-after", "after-collection",
                                       "independent-complete-collection"])
@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_freshness_boundaries(tmp_path: Path, boundary: str, delta: int) -> None:
    case = _case(tmp_path, defender=not boundary.startswith("independent"))
    receipt = case.receipt
    if boundary == "definitions-age":
        case.definitions(_shift(receipt["scan_completed_at_utc"], -(86400 + delta)))
    elif boundary == "evidence-age":
        case.issued = _shift(receipt["collected_at_utc"], 86400 + delta)
    elif boundary == "collection-skew":
        case.issued = _shift(receipt["collected_at_utc"], -(300 + delta))
    elif boundary == "before-start":
        receipt["defender_before"]["observed_at_utc"] = _shift(receipt["scan_started_at_utc"], -(300 + delta))
    elif boundary == "complete-after":
        receipt["defender_after"]["observed_at_utc"] = _shift(receipt["scan_completed_at_utc"], 300 + delta)
        receipt["collected_at_utc"] = receipt["defender_after"]["observed_at_utc"]
        case.issued = receipt["collected_at_utc"]
    elif boundary == "after-collection":
        receipt["collected_at_utc"] = _shift(receipt["defender_after"]["observed_at_utc"], 300 + delta)
        case.issued = receipt["collected_at_utc"]
    else:
        receipt["collected_at_utc"] = _shift(receipt["scan_completed_at_utc"], 300 + delta)
        case.issued = receipt["collected_at_utc"]
    case.save()
    if delta > 0:
        with pytest.raises(evidence.ScannerEvidenceError):
            case.validate()
    else:
        case.validate()


@pytest.mark.parametrize("boundary", ["definitions-before", "definitions-start"])
@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_definitions_cannot_be_future_even_with_clock_skew(tmp_path: Path, boundary: str, delta: int) -> None:
    case = _case(tmp_path, defender=boundary == "definitions-before")
    basis = (case.receipt["defender_before"]["observed_at_utc"] if boundary == "definitions-before"
             else case.receipt["scan_started_at_utc"])
    case.definitions(_shift(basis, delta))
    case.save()
    if delta > 0:
        with pytest.raises(evidence.ScannerEvidenceError, match="future"):
            case.validate()
    else:
        case.validate()


@pytest.mark.parametrize("change", ["before-after-start", "start-after-complete", "after-before-complete", "collection-before-after", "independent-collection-before-complete"])
def test_ordering_violations(tmp_path: Path, change: str) -> None:
    case = _case(tmp_path, defender=not change.startswith("independent"))
    r = case.receipt
    if change == "before-after-start":
        r["defender_before"]["observed_at_utc"] = _shift(r["scan_started_at_utc"], 1)
    elif change == "start-after-complete":
        r["scan_started_at_utc"] = _shift(r["scan_completed_at_utc"], 1)
    elif change == "after-before-complete":
        r["defender_after"]["observed_at_utc"] = _shift(r["scan_completed_at_utc"], -1)
    elif change == "collection-before-after":
        r["collected_at_utc"] = _shift(r["defender_after"]["observed_at_utc"], -1)
    else:
        r["collected_at_utc"] = _shift(r["scan_completed_at_utc"], -1)
    case.save()
    with pytest.raises(evidence.ScannerEvidenceError, match="ordering"):
        case.validate()


@pytest.mark.parametrize("issued", [None, "9999-12-31T23:59:59Z", "0001-01-01T00:00:00Z"])
def test_issuance_errors_remain_typed(tmp_path: Path, issued) -> None:
    case = _case(tmp_path)
    case.issued = issued
    with pytest.raises(evidence.ScannerEvidenceError):
        case.validate()


@pytest.mark.parametrize("field,value", [("receipt_sha256", "0" * 64), ("receipt_sha256", "d" * 64),
                                       ("output_sha256", "0" * 64), ("scanner_id", "other"),
                                       ("detections", False), ("status", "unknown"),
                                       ("scan_time_utc", "2026-10-07T12:00:59Z")])
def test_outer_scan_bindings(tmp_path: Path, field: str, value) -> None:
    case = _case(tmp_path)
    case.scan[field] = value
    with pytest.raises(evidence.ScannerEvidenceError):
        case.validate()


def test_receipt_hash_is_checked_before_json_parse(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case.path.write_bytes(b"invalid JSON")
    with pytest.raises(evidence.ScannerEvidenceError, match="receipt hash mismatch"):
        case.validate()


def test_raw_output_hash_is_checked(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case.output.write_bytes(b"Changed scanner output")
    with pytest.raises(evidence.ScannerEvidenceError, match="raw output hash mismatch"):
        case.validate()


@pytest.mark.parametrize("raw", [b"", b" \t\r\n", bytes(32), b"\x01\x02\x7f"])
def test_meaningless_raw_output_is_rejected_even_with_matching_hash(tmp_path: Path, raw: bytes) -> None:
    case = _case(tmp_path)
    case.output.write_bytes(raw)
    case.scan["output_sha256"] = case.receipt["output_sha256"] = _digest(raw)
    case.save()
    with pytest.raises(evidence.ScannerEvidenceError, match="meaningful"):
        case.validate()


@pytest.mark.parametrize("target", ["receipt", "raw output"])
def test_oversized_read_rejected_before_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    case = _case(tmp_path)
    path = case.path if target == "receipt" else case.output
    with path.open("wb") as stream:
        stream.truncate((evidence.MAX_RECEIPT_BYTES if target == "receipt" else evidence.MAX_RAW_OUTPUT_BYTES) + 1)
    original_open = Path.open

    def observed_open(self, *args, **kwargs):
        if self == path:
            pytest.fail("oversized backing should be rejected before opening")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", observed_open)
    with pytest.raises(evidence.ScannerEvidenceError, match="byte limit"):
        case.validate()


@pytest.mark.parametrize("target", ["receipt", "raw output"])
@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_missing_and_nonregular_files_rejected(tmp_path: Path, target: str, kind: str) -> None:
    case = _case(tmp_path)
    path = case.path if target == "receipt" else case.output
    path.unlink()
    if kind == "directory":
        path.mkdir()
    with pytest.raises(evidence.ScannerEvidenceError):
        case.validate()


def test_reader_uses_limit_plus_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case = _case(tmp_path)
    original_open = Path.open
    observed = []

    class Stream:
        def __init__(self, stream, path):
            self.stream, self.path = stream, path

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, size):
            observed.append((self.path, size))
            return self.stream.read(size)

    def observed_open(path, *args, **kwargs):
        return Stream(original_open(path, *args, **kwargs), path)

    monkeypatch.setattr(Path, "open", observed_open)
    case.validate()
    assert observed == [(case.path, evidence.MAX_RECEIPT_BYTES + 1),
                        (case.output, evidence.MAX_RAW_OUTPUT_BYTES + 1)]


@pytest.mark.parametrize("target", ["scanner", "scan", "subject"])
def test_input_context_requires_objects(tmp_path: Path, target: str) -> None:
    case = _case(tmp_path)
    setattr(case, target, [])
    with pytest.raises(evidence.ScannerEvidenceError, match="objects"):
        case.validate()


@pytest.mark.parametrize("field,value", [("subject_size_bytes", True), ("subject_size_bytes", 0),
                                       ("subject_size_bytes", 123.0), ("subject_sha256", "0" * 64)])
def test_subject_context_types(tmp_path: Path, field: str, value) -> None:
    case = _case(tmp_path)
    case.subject[field] = value
    with pytest.raises(evidence.ScannerEvidenceError):
        case.validate()
