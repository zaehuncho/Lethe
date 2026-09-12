"""In-process, evidence-only preparation and finalization over retained bytes.

This module neither builds nor executes artifacts, collects observations, nor
authorizes a release. Authenticode requires an explicitly supplied trusted
integration that enforces chain, timestamp, and revocation verification.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import external_evidence_v2 as evidence
from .pe_content_id import FileSnapshot, parse_pe_image, pe_content_id_from_bytes, snapshot_file
from .strict_json import load_json_object_bytes


_CONTEXT_DOMAIN = b"lethe-external-evidence-prepared-context-v2\x00"
_ARTIFACT_NAME = re.compile(r"artifact-[0-9]{5,}-[0-9a-f]{64}\.bin\Z")
_MANIFEST_FIELDS = frozenset({
    "schema", "kind", "context_id", "challenge_id", "release_authorized",
    "finalized_at_utc", "initial_trust_sha256", "current_trust_sha256",
    "candidate_verification", "authenticode", "files",
})


class PhaseBError(ValueError):
    """Evidence preparation, ingestion, finalization, or publication failed."""


@dataclass(frozen=True)
class CandidateInput:
    source_commit: str
    stub_path: Path
    manifest_path: Path
    production_native_path: Path


@dataclass(frozen=True)
class SubjectInput:
    subject_id: str
    subject_kind: str
    unsigned_subject_path: Path
    input_path: Path
    pack_report_path: Path
    protection_profile_path: Path


@dataclass(frozen=True)
class PreparedCandidate:
    source_commit: str
    stub: FileSnapshot
    manifest: FileSnapshot
    production_native: FileSnapshot


@dataclass(frozen=True)
class PreparedSubject:
    subject_id: str
    subject_kind: str
    unsigned: FileSnapshot
    input: FileSnapshot
    pack_report: FileSnapshot
    protection_profile: FileSnapshot


@dataclass(frozen=True)
class CandidateVerificationResult:
    source_commit: str
    stub_sha256: str
    manifest_sha256: str
    production_native_sha256: str
    verifier_id: str
    verifier_version: str
    valid: bool


@dataclass(frozen=True)
class PreparedEvidence:
    challenge_bytes: bytes
    trust_bytes: bytes
    context_id: str
    candidate: PreparedCandidate
    candidate_verification: CandidateVerificationResult
    subjects: tuple[PreparedSubject, ...]


@dataclass(frozen=True)
class AuthenticodeResult:
    subject_sha256: str
    subject_size: int
    signer_thumbprint: str
    tsa_thumbprint: str
    verified_at_utc: datetime
    verifier_id: str
    verifier_version: str
    valid: bool


@dataclass(frozen=True)
class EvidenceFile:
    relative_path: str
    data: bytes
    purpose: str


@dataclass(frozen=True)
class FinalizedEvidence:
    manifest_bytes: bytes
    files: tuple[EvidenceFile, ...]
    context_id: str
    release_authorized: bool = False


def _now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if (type(value) is not datetime or value.tzinfo is None
            or value.utcoffset() is None):
        raise PhaseBError("verification time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _document(data: bytes, what: str) -> dict[str, Any]:
    try:
        return load_json_object_bytes(data, what=what)
    except ValueError as exc:
        raise PhaseBError(str(exc)) from exc


def _policy(data: bytes) -> dict[str, Any]:
    try:
        return evidence.validate_evidence_trust_store_v2(_document(data, "v2 trust store"))
    except ValueError as exc:
        raise PhaseBError(str(exc)) from exc


def _snapshot(path: Path, what: str) -> FileSnapshot:
    try:
        return snapshot_file(path, what=what, reject_hardlinks=True)
    except ValueError as exc:
        raise PhaseBError(str(exc)) from exc


def _check_snapshot(value: FileSnapshot, what: str) -> FileSnapshot:
    try:
        return evidence._validated_snapshot(value, what)
    except ValueError as exc:
        raise PhaseBError(str(exc)) from exc


def _candidate_identity(candidate: PreparedCandidate) -> dict[str, str]:
    return {
        "source_commit": candidate.source_commit,
        "candidate_stub_sha256": candidate.stub.sha256,
        "candidate_manifest_sha256": candidate.manifest.sha256,
        "production_native_sha256": candidate.production_native.sha256,
    }


def _candidate_verification_record(
    result: CandidateVerificationResult, candidate: PreparedCandidate,
) -> dict[str, Any]:
    identity = _candidate_identity(candidate)
    if (type(result) is not CandidateVerificationResult or result.valid is not True
            or result.source_commit != identity["source_commit"]
            or result.stub_sha256 != identity["candidate_stub_sha256"]
            or result.manifest_sha256 != identity["candidate_manifest_sha256"]
            or result.production_native_sha256 != identity["production_native_sha256"]):
        raise PhaseBError("candidate verification result is invalid or mismatched")
    for value in (result.verifier_id, result.verifier_version):
        if type(value) is not str or not value.strip() or len(value) > 256 or "\x00" in value:
            raise PhaseBError("candidate verifier identity is invalid")
    return {
        "source_commit": result.source_commit,
        "candidate_stub_sha256": result.stub_sha256,
        "candidate_manifest_sha256": result.manifest_sha256,
        "production_native_sha256": result.production_native_sha256,
        "verifier_id": result.verifier_id,
        "verifier_version": result.verifier_version,
        "valid": True,
    }


def _subject_identity(subject: PreparedSubject, stub_hash: str) -> dict[str, Any]:
    try:
        info = parse_pe_image(subject.unsigned.data, label="prepared unsigned subject")
        stable_id = pe_content_id_from_bytes(subject.unsigned.data)
    except ValueError as exc:
        raise PhaseBError(str(exc)) from exc
    if (info.subject_kind != subject.subject_kind or info.certificate_offset
            or info.certificate_size or subject.unsigned.size % 8):
        raise PhaseBError("unsigned subject PE kind, certificate, or alignment is invalid")
    return {
        "subject_id": subject.subject_id, "subject_kind": subject.subject_kind,
        "format": evidence.SUBJECT_FORMAT, "input_sha256": subject.input.sha256,
        "unsigned_subject_sha256": subject.unsigned.sha256,
        "unsigned_subject_size_bytes": subject.unsigned.size,
        "signing_stable_pe_id": stable_id, "pack_report_sha256": subject.pack_report.sha256,
        "protection_profile_sha256": subject.protection_profile.sha256,
        "protected_with_stub_sha256": stub_hash,
    }


def _material(prepared: PreparedEvidence) -> tuple[tuple[str, FileSnapshot], ...]:
    candidate = prepared.candidate
    result = [("candidate-stub", candidate.stub), ("candidate-manifest", candidate.manifest),
              ("production-native", candidate.production_native)]
    for subject in prepared.subjects:
        result.extend((f"{subject.subject_id}:{field}", getattr(subject, field))
                      for field in ("unsigned", "input", "pack_report", "protection_profile"))
    return tuple(result)


def _context_id(prepared: PreparedEvidence) -> str:
    content = {
        "challenge_sha256": _hash(prepared.challenge_bytes),
        "trust_sha256": _hash(prepared.trust_bytes),
        "candidate_verification": _candidate_verification_record(
            prepared.candidate_verification, prepared.candidate),
        "material": [{"purpose": purpose, "sha256": snapshot.sha256, "size": snapshot.size}
                     for purpose, snapshot in _material(prepared)],
    }
    return _hash(_CONTEXT_DOMAIN + evidence.canonical_json_bytes(content))


def _prepared_state(
    prepared: PreparedEvidence, policy: dict[str, Any], current: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if (type(prepared) is not PreparedEvidence
            or type(prepared.candidate) is not PreparedCandidate
            or type(prepared.candidate_verification) is not CandidateVerificationResult
            or type(prepared.subjects) is not tuple
            or not all(type(subject) is PreparedSubject for subject in prepared.subjects)):
        raise PhaseBError("prepared evidence is malformed")
    challenge = _document(prepared.challenge_bytes, "prepared challenge")
    _policy(prepared.trust_bytes)
    if evidence.canonical_json_bytes(challenge) != prepared.challenge_bytes:
        raise PhaseBError("prepared challenge is not canonical")
    for purpose, snapshot in _material(prepared):
        _check_snapshot(snapshot, purpose)
    _candidate_verification_record(
        prepared.candidate_verification, prepared.candidate)
    if (type(prepared.context_id) is not str or prepared.context_id != _context_id(prepared)
            or challenge.get("candidate") != _candidate_identity(prepared.candidate)
            or challenge.get("subjects") != [
                _subject_identity(subject, prepared.candidate.stub.sha256)
                for subject in prepared.subjects]):
        raise PhaseBError("prepared context or retained material binding does not match")
    try:
        state = evidence.validate_challenge(challenge, trust_policy=policy, now=current)
    except ValueError as exc:
        raise PhaseBError(str(exc)) from exc
    return challenge, state


def prepare_evidence(
    candidate: CandidateInput, subjects: Sequence[SubjectInput], requirements: dict,
    trust_document: bytes, *,
    candidate_verifier: Callable[
        [bytes, bytes, bytes, str], CandidateVerificationResult
    ] | None = None,
    now: datetime | None = None,
    lifetime: timedelta = timedelta(hours=24),
) -> PreparedEvidence:
    """Capture already-built material and create a fresh, private challenge."""
    current = _now(now)
    if (type(candidate) is not CandidateInput or type(lifetime) is not timedelta
            or lifetime <= timedelta(0) or lifetime > evidence.MAX_CHALLENGE_LIFETIME):
        raise PhaseBError("candidate or challenge lifetime is invalid")
    if not isinstance(subjects, Sequence) or isinstance(subjects, (str, bytes)):
        raise PhaseBError("subjects must be a sequence")
    inputs = tuple(subjects)
    if not all(type(subject) is SubjectInput for subject in inputs):
        raise PhaseBError("subject input is malformed")
    policy = _policy(trust_document)
    try:
        private_requirements = evidence._private_value(requirements, what="requirements")
    except ValueError as exc:
        raise PhaseBError(str(exc)) from exc
    retained_candidate = PreparedCandidate(
        candidate.source_commit, _snapshot(candidate.stub_path, "candidate stub"),
        _snapshot(candidate.manifest_path, "candidate manifest"),
        _snapshot(candidate.production_native_path, "production native"))
    if not callable(candidate_verifier):
        raise PhaseBError("an explicit trusted candidate verifier is required")
    verification = candidate_verifier(
        retained_candidate.stub.data,
        retained_candidate.manifest.data,
        retained_candidate.production_native.data,
        retained_candidate.source_commit,
    )
    _candidate_verification_record(verification, retained_candidate)
    retained_subjects = tuple(PreparedSubject(
        subject.subject_id, subject.subject_kind,
        _snapshot(subject.unsigned_subject_path, "unsigned subject"),
        _snapshot(subject.input_path, "subject input"),
        _snapshot(subject.pack_report_path, "pack report"),
        _snapshot(subject.protection_profile_path, "protection profile"),
    ) for subject in inputs)
    challenge = {
        "schema": evidence.CHALLENGE_SCHEMA, "kind": evidence.CHALLENGE_KIND,
        "challenge_id": "", "nonce_base64": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "created_at_utc": _stamp(current), "expires_at_utc": _stamp(current + lifetime),
        "candidate": _candidate_identity(retained_candidate),
        "subjects": [_subject_identity(subject, retained_candidate.stub.sha256)
                     for subject in retained_subjects],
        "requirements": private_requirements,
    }
    try:
        challenge["challenge_id"] = evidence.compute_challenge_id(challenge)
        evidence.validate_challenge(challenge, trust_policy=policy, now=current)
        challenge_bytes = evidence.canonical_json_bytes(challenge)
    except ValueError as exc:
        raise PhaseBError(str(exc)) from exc
    temporary = PreparedEvidence(
        challenge_bytes, trust_document, "", retained_candidate, verification,
        retained_subjects)
    return PreparedEvidence(
        challenge_bytes, trust_document, _context_id(temporary),
        retained_candidate, verification, retained_subjects)


def ingest_receipt(
    prepared: PreparedEvidence, envelope_bytes: bytes, *, signed_subject_path: Path,
    backing_root: Path, now: datetime | None = None,
) -> evidence.VerifiedReceipt:
    """Read signed/backing sources once; reuse the retained unsigned bytes."""
    current = _now(now)
    if type(prepared) is not PreparedEvidence:
        raise PhaseBError("prepared evidence is malformed")
    policy = _policy(prepared.trust_bytes)
    challenge, state = _prepared_state(prepared, policy, current)
    envelope = _document(envelope_bytes, "receipt envelope")
    receipt = envelope.get("receipt")
    subject = receipt.get("subject") if type(receipt) is dict else None
    subject_id = subject.get("subject_id") if type(subject) is dict else None
    if type(subject_id) is not str or subject_id not in state["subjects"]:
        raise PhaseBError("receipt subject is not in the prepared challenge")
    retained = next(item for item in prepared.subjects if item.subject_id == subject_id)
    backings = receipt.get("backings")
    role = receipt.get("role")
    if (type(role) is not str or role not in evidence.ROLES or type(backings) is not list
            or len(backings) != len(evidence.REQUIRED_BACKING_IDS[role])):
        raise PhaseBError("receipt backing set is malformed")
    backing_snapshots = {}
    seen_paths = set()
    try:
        for backing in backings:
            if type(backing) is not dict or set(backing) != evidence.BACKING_FIELDS:
                raise PhaseBError("receipt backing metadata is malformed")
            relative = backing["path"]
            evidence._normalized_backing_path(relative, "receipt backing")
            if relative.casefold() in seen_paths:
                raise PhaseBError("receipt backing identity is duplicated")
            seen_paths.add(relative.casefold())
            path = evidence._regular_backing(backing_root, relative, "receipt backing")
            backing_snapshots[relative] = _snapshot(path, "receipt backing")
        return evidence.verify_detached_receipt_snapshots(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_snapshot=retained.unsigned,
            signed_snapshot=_snapshot(signed_subject_path, "signed subject"),
            backing_snapshots=backing_snapshots, now=current)
    except ValueError as exc:
        raise PhaseBError(str(exc)) from exc


def _reverify(
    receipt: evidence.VerifiedReceipt, prepared: PreparedEvidence,
    challenge: dict, policy: dict, current: datetime,
) -> evidence.VerifiedReceipt:
    if (type(receipt) is not evidence.VerifiedReceipt
            or type(receipt.canonical_receipt) is not bytes or type(receipt.signature) is not bytes
            or type(receipt.signature_payload) is not bytes
            or receipt.signature_payload != evidence.RECEIPT_SIGNATURE_DOMAIN + receipt.canonical_receipt
            or type(receipt.backings) is not tuple
            or not all(type(item) is evidence.VerifiedBacking for item in receipt.backings)):
        raise PhaseBError("retained receipt or signature payload is malformed")
    body = _document(receipt.canonical_receipt, "retained receipt")
    if evidence.canonical_json_bytes(body) != receipt.canonical_receipt:
        raise PhaseBError("retained receipt is not canonical")
    if type(receipt.subject_id) is not str:
        raise PhaseBError("retained receipt subject is invalid")
    subject = next((item for item in prepared.subjects if item.subject_id == receipt.subject_id), None)
    if subject is None or receipt.prepared_subject != subject.unsigned:
        raise PhaseBError("retained receipt prepared subject does not match context")
    backings = {}
    for item in receipt.backings:
        if type(item.relative_path) is not str or item.relative_path in backings:
            raise PhaseBError("retained receipt backing identity is invalid or duplicated")
        backings[item.relative_path] = item.snapshot
    envelope = {"schema": evidence.RECEIPT_SCHEMA, "kind": evidence.RECEIPT_KIND,
                "receipt": body, "signature_base64": base64.b64encode(receipt.signature).decode("ascii")}
    try:
        result = evidence.verify_detached_receipt_snapshots(
            envelope, challenge=challenge, trust_policy=policy, prepared_snapshot=subject.unsigned,
            signed_snapshot=receipt.signed_subject, backing_snapshots=backings, now=current)
    except ValueError as exc:
        raise PhaseBError(str(exc)) from exc
    if result != receipt:
        raise PhaseBError("retained receipt fields do not match verified evidence")
    return result


def _authenticode(
    verifier: Callable[[bytes, datetime], AuthenticodeResult], snapshot: FileSnapshot,
    policy: dict, current: datetime,
) -> AuthenticodeResult:
    result = verifier(snapshot.data, current)
    if (type(result) is not AuthenticodeResult or result.valid is not True
            or type(result.subject_sha256) is not str or result.subject_sha256 != snapshot.sha256
            or type(result.subject_size) is not int or result.subject_size != snapshot.size
            or type(result.verified_at_utc) is not datetime or result.verified_at_utc != current
            or type(result.signer_thumbprint) is not str
            or result.signer_thumbprint not in policy["allowed_signer_thumbprints"]
            or type(result.tsa_thumbprint) is not str
            or result.tsa_thumbprint not in policy["allowed_tsa_thumbprints"]):
        raise PhaseBError("Authenticode result is invalid, stale, mismatched, or outside current pins")
    for value in (result.verifier_id, result.verifier_version):
        if type(value) is not str or not value.strip() or len(value) > 256 or "\x00" in value:
            raise PhaseBError("Authenticode verifier identity is invalid")
    return result


def _file_record(item: EvidenceFile) -> dict[str, Any]:
    return {"relative_path": item.relative_path, "sha256": _hash(item.data),
            "size_bytes": len(item.data), "purpose": item.purpose}


def finalize_evidence(
    prepared: PreparedEvidence, receipts: Sequence[evidence.VerifiedReceipt], *,
    current_trust_document: bytes,
    authenticode_verifier: Callable[[bytes, datetime], AuthenticodeResult] | None = None,
    now: datetime | None = None,
) -> FinalizedEvidence:
    """Reverify retained bytes under current trust, without source filesystem I/O.

    The callback is trusted integration code, not a receipt field. It must
    perform real Authenticode chain/time/revocation verification; no built-in
    successful result exists. It must use only supplied subject bytes and its
    independent trust material, without executing subjects, recollecting
    observations, or reopening accepted source paths. Callback exceptions abort
    finalization without publishing. A completed bundle grants no release authority.
    """
    current = _now(now)
    policy = _policy(current_trust_document)
    challenge, state = _prepared_state(prepared, policy, current)
    if not callable(authenticode_verifier):
        raise PhaseBError("an explicit trusted Authenticode verifier is required")
    if not isinstance(receipts, Sequence) or isinstance(receipts, (str, bytes)):
        raise PhaseBError("receipts must be a sequence")
    expected = {(subject_id, role, scope_id) for subject_id in state["subjects"]
                for role, scopes in state["requirements"].items() for scope_id in scopes}
    accepted = []
    covered = set()
    signed = {}
    for item in tuple(receipts):
        receipt = _reverify(item, prepared, challenge, policy, current)
        key = (receipt.subject_id, receipt.role, receipt.scope_id)
        if key not in expected or key in covered:
            raise PhaseBError("receipt coverage contains duplicate or extra entries")
        if (receipt.subject_id in signed
                and signed[receipt.subject_id].data != receipt.signed_subject.data):
            raise PhaseBError("receipts contain conflicting signed subject bytes")
        covered.add(key)
        signed[receipt.subject_id] = receipt.signed_subject
        accepted.append(receipt)
    if covered != expected:
        raise PhaseBError("receipt coverage is incomplete")
    auth_results = {subject.subject_id: _authenticode(
        authenticode_verifier, signed[subject.subject_id], policy, current)
        for subject in prepared.subjects}
    files: list[EvidenceFile] = []

    def append(purpose: str, data: bytes) -> None:
        files.append(EvidenceFile(f"artifact-{len(files):05d}-{_hash(data)}.bin", data, purpose))

    append("challenge", prepared.challenge_bytes)
    append("initial-trust", prepared.trust_bytes)
    append("current-trust", current_trust_document)
    for purpose, snapshot in _material(prepared):
        append(purpose, snapshot.data)
    for subject in prepared.subjects:
        append(f"{subject.subject_id}:signed", signed[subject.subject_id].data)
    for index, receipt in enumerate(sorted(accepted, key=lambda item: (item.subject_id, item.role, item.scope_id))):
        append(f"receipt-{index}:canonical", receipt.canonical_receipt)
        append(f"receipt-{index}:signature", receipt.signature)
        for backing in receipt.backings:
            append(f"receipt-{index}:backing:{backing.backing_id}", backing.snapshot.data)
    manifest = {
        "schema": 2, "kind": "lethe-external-evidence-bundle", "context_id": prepared.context_id,
        "challenge_id": challenge["challenge_id"], "release_authorized": False,
        "finalized_at_utc": _stamp(current), "initial_trust_sha256": _hash(prepared.trust_bytes),
        "current_trust_sha256": _hash(current_trust_document),
        "candidate_verification": _candidate_verification_record(
            prepared.candidate_verification, prepared.candidate),
        "authenticode": [{"subject_id": subject_id, "subject_sha256": result.subject_sha256,
                          "subject_size": result.subject_size, "signer_thumbprint": result.signer_thumbprint,
                          "tsa_thumbprint": result.tsa_thumbprint, "verified_at_utc": _stamp(current),
                          "verifier_id": result.verifier_id, "verifier_version": result.verifier_version,
                          "valid": True} for subject_id, result in auth_results.items()],
        "files": [_file_record(item) for item in files],
    }
    return FinalizedEvidence(evidence.canonical_json_bytes(manifest), tuple(files), prepared.context_id)


def publish_evidence(finalized: FinalizedEvidence, output_dir: Path) -> Path:
    """Exclusively write retained artifacts, then manifest.json as completion marker.

    An I/O failure leaves a partial directory for inspection. This function
    never overwrites, cleans up recursively, or reads any original source path.
    The caller supplies a private, stable output parent; exclusive path-based
    writes are not an atomic or immutable publication guarantee against ancestor
    replacement by another process.
    """
    if (type(finalized) is not FinalizedEvidence or finalized.release_authorized is not False
            or type(finalized.files) is not tuple):
        raise PhaseBError("finalized evidence is malformed or claims release authority")
    manifest = _document(finalized.manifest_bytes, "evidence manifest")
    if (set(manifest) != _MANIFEST_FIELDS or type(manifest.get("schema")) is not int
            or manifest["schema"] != 2 or manifest.get("kind") != "lethe-external-evidence-bundle"
            or manifest.get("context_id") != finalized.context_id
            or type(finalized.context_id) is not str or evidence.SHA256_RE.fullmatch(finalized.context_id) is None
            or manifest.get("release_authorized") is not False
            or evidence.canonical_json_bytes(manifest) != finalized.manifest_bytes):
        raise PhaseBError("evidence manifest identity is invalid")
    purposes = set()
    for index, item in enumerate(finalized.files):
        if (type(item) is not EvidenceFile or type(item.data) is not bytes
                or type(item.relative_path) is not str or _ARTIFACT_NAME.fullmatch(item.relative_path) is None
                or item.relative_path != f"artifact-{index:05d}-{_hash(item.data)}.bin"
                or type(item.purpose) is not str or not item.purpose or item.purpose in purposes):
            raise PhaseBError("evidence file name, bytes, or purpose is invalid")
        purposes.add(item.purpose)
    records = manifest.get("files")
    if (type(records) is not list or any(type(record) is not dict or type(record.get("size_bytes")) is not int
                                       for record in records)
            or records != [_file_record(item) for item in finalized.files]):
        raise PhaseBError("manifest file hashes or metadata do not match retained bytes")
    target = Path(output_dir).absolute()
    try:
        evidence._reject_linklike_ancestors(target, "evidence output")
        target.mkdir(parents=False, exist_ok=False)
        for item in finalized.files:
            with (target / item.relative_path).open("xb") as stream:
                stream.write(item.data)
        manifest_path = target / "manifest.json"
        with manifest_path.open("xb") as stream:
            stream.write(finalized.manifest_bytes)
    except (OSError, ValueError) as exc:
        raise PhaseBError(f"evidence publication failed; any partial directory is retained: {exc}") from exc
    return manifest_path


__all__ = [
    "AuthenticodeResult", "CandidateInput", "CandidateVerificationResult", "EvidenceFile",
    "FinalizedEvidence", "PhaseBError",
    "PreparedCandidate", "PreparedEvidence", "PreparedSubject", "SubjectInput", "finalize_evidence",
    "ingest_receipt", "prepare_evidence", "publish_evidence",
]
