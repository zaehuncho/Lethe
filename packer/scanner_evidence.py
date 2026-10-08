"""Strict, read-only scanner receipts for the production release gate.

Provider authentication and evidence-root containment are the caller's job.
This module validates the exact bounded receipt/output bytes and their semantic
bindings. It does not run a scanner or infer a verdict from vendor output.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .strict_json import StrictJSONError, load_json_object_bytes

MAX_RECEIPT_BYTES = 64 * 1024
MAX_RAW_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_OBSERVATION_GAP = timedelta(minutes=5)
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_DEFINITIONS_AGE = timedelta(hours=24)
MAX_EVIDENCE_AGE = timedelta(hours=24)
_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z", re.ASCII)

RECEIPT_FIELDS = frozenset({
    "schema", "kind", "scanner_id", "tool_name", "tool_version",
    "engine_version", "definitions_version", "subject_id",
    "subject_sha256_before", "subject_sha256_after",
    "subject_size_bytes_before", "subject_size_bytes_after", "source_commit",
    "candidate_manifest_sha256", "protected_with_stub_sha256",
    "scan_started_at_utc", "scan_completed_at_utc", "collected_at_utc",
    "definitions_updated_at_utc", "status", "verdict", "detections",
    "exit_code", "output_sha256",
})
DEFENDER_FIELDS = frozenset({
    "observed_at_utc", "AMServiceEnabled", "AntivirusEnabled",
    "RealTimeProtectionEnabled", "AMEngineVersion", "AntivirusSignatureVersion",
    "AntivirusSignatureLastUpdated",
})


class ScannerEvidenceError(ValueError):
    """A scanner receipt is ambiguous, unbound, stale, or not a clean run."""


def parse_utc(value: Any, label: str) -> datetime:
    """Accept exactly canonical UTC seconds, with no offsets or fractions."""
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise ScannerEvidenceError(f"scanner {label} must be canonical UTC seconds")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise ScannerEvidenceError(f"scanner {label} is not a valid UTC timestamp") from exc


def _hash(value: Any, label: str) -> str:
    if (type(value) is not str or _SHA256_RE.fullmatch(value) is None
            or value == "0" * 64):
        raise ScannerEvidenceError(f"scanner {label} must be a nonzero SHA-256")
    return value


def _bounded_read(path: Path, *, maximum: int, label: str) -> bytes:
    def identity(info: os.stat_result) -> tuple[int, int, int, int]:
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns

    try:
        before = path.lstat()
        if (path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())
                or not stat.S_ISREG(before.st_mode)):
            raise ScannerEvidenceError(f"scanner {label} must be a regular non-symlink file")
        if before.st_size > maximum:
            raise ScannerEvidenceError(f"scanner {label} exceeds the {maximum}-byte limit")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(before):
                raise ScannerEvidenceError(f"scanner {label} changed while opening")
            data = stream.read(maximum + 1)
            after_read = os.fstat(stream.fileno())
        after = path.lstat()
        if len(data) > maximum:
            raise ScannerEvidenceError(f"scanner {label} exceeds the {maximum}-byte limit")
        if (path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())
                or not stat.S_ISREG(after.st_mode)
                or identity(opened) != identity(after_read)
                or identity(opened) != identity(after) or len(data) != opened.st_size):
            raise ScannerEvidenceError(f"scanner {label} changed while reading")
    except OSError as exc:
        raise ScannerEvidenceError(f"scanner {label} cannot be read: {exc}") from exc
    return data


def _matching_text(actual: Any, expected: Any, label: str) -> None:
    if (type(actual) is not str or not actual.strip()
            or type(expected) is not str or actual != expected):
        raise ScannerEvidenceError(f"scanner receipt {label} binding is invalid")


def _defender_observation(
    observation: Any, receipt: dict[str, Any], *, label: str,
) -> datetime:
    if type(observation) is not dict or set(observation) != DEFENDER_FIELDS:
        raise ScannerEvidenceError(f"Defender {label} observation fields are malformed")
    for field in ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled"):
        if type(observation[field]) is not bool:
            raise ScannerEvidenceError(f"Defender {label} {field} must be a boolean")
    if not observation["AMServiceEnabled"] or not observation["AntivirusEnabled"]:
        raise ScannerEvidenceError(f"Defender {label} service and antivirus must be enabled")
    _matching_text(observation["AMEngineVersion"], receipt["engine_version"],
                   f"Defender {label} engine version")
    _matching_text(observation["AntivirusSignatureVersion"], receipt["definitions_version"],
                   f"Defender {label} definitions version")
    _matching_text(observation["AntivirusSignatureLastUpdated"],
                   receipt["definitions_updated_at_utc"], f"Defender {label} definitions timestamp")
    observed = parse_utc(observation["observed_at_utc"], f"Defender {label} observation")
    if parse_utc(observation["AntivirusSignatureLastUpdated"], "definitions timestamp") > observed:
        raise ScannerEvidenceError(f"Defender {label} definitions timestamp is in the future")
    return observed


def validate_scan_receipt(
    receipt_path: Path, *, scanner: dict, scan: dict, subject: dict,
    raw_output_path: Path, issued_at_utc: str,
) -> None:
    """Validate one provider-bound run; all file reads are bounded and read-only."""
    if any(type(value) is not dict for value in (scanner, scan, subject)):
        raise ScannerEvidenceError("scanner, scan, and subject must be objects")
    receipt_hash = _hash(scan.get("receipt_sha256"), "receipt SHA-256")
    output_hash = _hash(scan.get("output_sha256"), "output SHA-256")
    encoded = _bounded_read(receipt_path, maximum=MAX_RECEIPT_BYTES, label="receipt")
    if hashlib.sha256(encoded).hexdigest() != receipt_hash:
        raise ScannerEvidenceError("scanner receipt hash mismatch")
    try:
        receipt = load_json_object_bytes(encoded, what="scanner receipt", max_bytes=MAX_RECEIPT_BYTES)
    except StrictJSONError as exc:
        raise ScannerEvidenceError(str(exc)) from exc
    defender = scanner.get("scanner_id") == "microsoft-defender"
    fields = RECEIPT_FIELDS | ({"defender_before", "defender_after"} if defender else set())
    if (set(receipt) != fields or type(receipt.get("schema")) is not int
            or receipt["schema"] != 1 or receipt.get("kind") != "lethe-scanner-receipt"):
        raise ScannerEvidenceError("scanner receipt schema, kind, or fields are malformed")
    for field in ("scanner_id", "tool_name", "tool_version", "engine_version", "definitions_version"):
        _matching_text(receipt[field], scanner.get(field), field)
    if _ID_RE.fullmatch(receipt["scanner_id"]) is None:
        raise ScannerEvidenceError("scanner receipt scanner_id is invalid")
    _matching_text(receipt["scanner_id"], scan.get("scanner_id"), "scan scanner_id")
    if (scan.get("status") != "passed" or type(scan.get("detections")) is not int
            or scan["detections"] != 0):
        raise ScannerEvidenceError("scanner scan result is not a clean pass")
    _matching_text(receipt["subject_id"], subject.get("subject_id"), "subject_id")
    if _ID_RE.fullmatch(receipt["subject_id"]) is None:
        raise ScannerEvidenceError("scanner receipt subject_id is invalid")
    expected_subject_hash = _hash(subject.get("subject_sha256"), "subject SHA-256")
    expected_size = subject.get("subject_size_bytes")
    if type(expected_size) is not int or expected_size <= 0:
        raise ScannerEvidenceError("scanner subject size must be a positive integer")
    for suffix in ("before", "after"):
        if _hash(receipt[f"subject_sha256_{suffix}"], f"subject {suffix} SHA-256") != expected_subject_hash:
            raise ScannerEvidenceError(f"scanner receipt subject {suffix} hash binding is invalid")
        value = receipt[f"subject_size_bytes_{suffix}"]
        if type(value) is not int or value != expected_size:
            raise ScannerEvidenceError(f"scanner receipt subject {suffix} size binding is invalid")
    for field in ("source_commit", "candidate_manifest_sha256", "protected_with_stub_sha256"):
        _matching_text(receipt[field], subject.get(field), field)
        if field == "source_commit":
            if _COMMIT_RE.fullmatch(receipt[field]) is None or receipt[field] == "0" * 40:
                raise ScannerEvidenceError("scanner receipt source_commit is invalid")
        else:
            _hash(receipt[field], field)
    if (receipt["status"] != "completed" or receipt["verdict"] != "clean"
            or type(receipt["detections"]) is not int or receipt["detections"] != 0
            or type(receipt["exit_code"]) is not int or receipt["exit_code"] != 0):
        raise ScannerEvidenceError("scanner receipt is not a completed clean zero-detection run")
    if _hash(receipt["output_sha256"], "receipt output SHA-256") != output_hash:
        raise ScannerEvidenceError("scanner receipt output hash binding is invalid")
    started = parse_utc(receipt["scan_started_at_utc"], "scan start")
    completed = parse_utc(receipt["scan_completed_at_utc"], "scan completion")
    collected = parse_utc(receipt["collected_at_utc"], "collection")
    definitions = parse_utc(receipt["definitions_updated_at_utc"], "definitions update")
    issued = parse_utc(issued_at_utc, "release issuance")
    if parse_utc(scan.get("scan_time_utc"), "scan result time") != completed:
        raise ScannerEvidenceError("scanner receipt completion time differs from scan result")
    if not started <= completed <= collected:
        raise ScannerEvidenceError("scanner receipt start/completion/collection ordering is invalid")
    if definitions > started or completed - definitions > MAX_DEFINITIONS_AGE:
        raise ScannerEvidenceError("scanner definitions are future-dated or older than 24 hours")
    if collected - issued > MAX_CLOCK_SKEW or issued - collected > MAX_EVIDENCE_AGE:
        raise ScannerEvidenceError("scanner collection is outside the release issuance freshness window")
    if defender:
        before = _defender_observation(receipt["defender_before"], receipt, label="before")
        after = _defender_observation(receipt["defender_after"], receipt, label="after")
        if not before <= started <= completed <= after <= collected:
            raise ScannerEvidenceError("Defender observation/start/completion/collection ordering is invalid")
        if any(gap > MAX_OBSERVATION_GAP for gap in
               (started - before, after - completed, collected - after)):
            raise ScannerEvidenceError("Defender observation or collection gap exceeds five minutes")
    elif collected - completed > MAX_OBSERVATION_GAP:
        raise ScannerEvidenceError("scanner completion-to-collection gap exceeds five minutes")
    raw_output = _bounded_read(raw_output_path, maximum=MAX_RAW_OUTPUT_BYTES, label="raw output")
    if not any(byte > 0x20 and byte != 0x7F for byte in raw_output):
        raise ScannerEvidenceError("scanner raw output has no meaningful nonempty bytes")
    if hashlib.sha256(raw_output).hexdigest() != output_hash:
        raise ScannerEvidenceError("scanner raw output hash mismatch")


__all__ = [
    "ScannerEvidenceError", "validate_scan_receipt", "parse_utc",
    "MAX_RECEIPT_BYTES", "MAX_RAW_OUTPUT_BYTES", "MAX_OBSERVATION_GAP",
    "MAX_CLOCK_SKEW", "MAX_DEFINITIONS_AGE", "MAX_EVIDENCE_AGE",
]
