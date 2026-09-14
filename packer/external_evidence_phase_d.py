"""Strict reload and independent reverification of finalized Phase B bundles.

The manifest and context IDs are caller-held commitments, not bundle-provided
trust.  Publication is replayed twice from captured bytes: once under current
time/trust and once at the recorded reference time for exact historical-byte
comparison.  No executable is run and successful reload grants no release
authority.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from . import external_evidence_phase_b as phase_b
from . import external_evidence_phase_c as phase_c
from . import external_evidence_v2 as evidence
from .pe_content_id import FileSnapshot, snapshot_file
from .strict_json import load_json_object_bytes


_MANIFEST = "manifest.json"
_JSON_MAX_BYTES = 1048576
_MANIFEST_FIELDS = frozenset({
    "schema", "kind", "context_id", "challenge_id", "release_authorized",
    "finalized_at_utc", "initial_trust_sha256", "current_trust_sha256",
    "candidate_verification", "authenticode", "files",
})
_FILE_FIELDS = frozenset({"relative_path", "sha256", "size_bytes", "purpose"})
_VERIFICATION_FIELDS = frozenset({
    "source_commit", "candidate_stub_sha256", "candidate_manifest_sha256",
    "production_native_sha256", "verifier_id", "verifier_version", "valid",
})
_AUTHENTICODE_FIELDS = frozenset({
    "subject_id", "subject_sha256", "subject_size", "signer_thumbprint",
    "tsa_thumbprint", "verified_at_utc", "verifier_id", "verifier_version", "valid",
})
_SUBJECT_FIELDS = ("unsigned", "input", "pack_report", "protection_profile")


class FinalizedBundleError(ValueError):
    """A finalized bundle, caller pin, replay, or storage boundary is invalid."""


@dataclass(frozen=True)
class ReverifiedFinalizedEvidence:
    """Current verification plus the byte-exact historical publication."""

    published: phase_b.FinalizedEvidence
    fresh: phase_b.FinalizedEvidence
    prepared: phase_b.PreparedEvidence
    receipts: tuple[evidence.VerifiedReceipt, ...]
    recorded_finalized_at_utc: datetime
    release_authorized: bool = False


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: Any, what: str, *, commit: bool = False) -> str:
    pattern = evidence.COMMIT_RE if commit else evidence.SHA256_RE
    if type(value) is not str or pattern.fullmatch(value) is None or set(value) == {"0"}:
        raise FinalizedBundleError(f"{what} is invalid")
    return value


def _string(value: Any, what: str) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256 or "\x00" in value:
        raise FinalizedBundleError(f"{what} is invalid")
    return value


def _record(record: Any, index: int) -> dict[str, Any]:
    if type(record) is not dict or set(record) != _FILE_FIELDS:
        raise FinalizedBundleError(f"manifest file[{index}] fields are invalid")
    digest = _hex(record.get("sha256"), f"manifest file[{index}] digest")
    expected_name = f"artifact-{index:05d}-{digest}.bin"
    if type(record.get("relative_path")) is not str or record["relative_path"] != expected_name:
        raise FinalizedBundleError(f"manifest file[{index}] name or order is invalid")
    if type(record.get("size_bytes")) is not int or record["size_bytes"] < 0:
        raise FinalizedBundleError(f"manifest file[{index}] size is invalid")
    _string(record.get("purpose"), f"manifest file[{index}] purpose")
    return record


def _decode_manifest(data: bytes) -> dict[str, Any]:
    document = load_json_object_bytes(
        data, what="finalized evidence manifest", max_bytes=_JSON_MAX_BYTES)
    if (set(document) != _MANIFEST_FIELDS
            or type(document.get("schema")) is not int or document["schema"] != 2
            or document.get("kind") != "lethe-external-evidence-bundle"
            or document.get("release_authorized") is not False):
        raise FinalizedBundleError("finalized manifest schema, kind, or authority is invalid")
    _hex(document.get("context_id"), "manifest context ID")
    _hex(document.get("challenge_id"), "manifest challenge ID")
    _hex(document.get("initial_trust_sha256"), "manifest initial trust digest")
    _hex(document.get("current_trust_sha256"), "manifest current trust digest")
    try:
        evidence._timestamp(document.get("finalized_at_utc"), "manifest finalization time")
    except ValueError as exc:
        raise FinalizedBundleError(str(exc)) from exc
    verification = document.get("candidate_verification")
    if (type(verification) is not dict or set(verification) != _VERIFICATION_FIELDS
            or verification.get("valid") is not True):
        raise FinalizedBundleError("candidate verification record is malformed")
    _hex(verification.get("source_commit"), "candidate source commit", commit=True)
    for field in ("candidate_stub_sha256", "candidate_manifest_sha256", "production_native_sha256"):
        _hex(verification.get(field), f"candidate verification {field}")
    _string(verification.get("verifier_id"), "candidate verifier ID")
    _string(verification.get("verifier_version"), "candidate verifier version")
    authenticode = document.get("authenticode")
    if type(authenticode) is not list:
        raise FinalizedBundleError("manifest Authenticode records are malformed")
    for index, item in enumerate(authenticode):
        if type(item) is not dict or set(item) != _AUTHENTICODE_FIELDS or item.get("valid") is not True:
            raise FinalizedBundleError(f"manifest Authenticode record[{index}] is malformed")
        _string(item.get("subject_id"), f"manifest Authenticode record[{index}] subject")
        _hex(item.get("subject_sha256"), f"manifest Authenticode record[{index}] digest")
        if type(item.get("subject_size")) is not int or item["subject_size"] <= 0:
            raise FinalizedBundleError(f"manifest Authenticode record[{index}] size is invalid")
        for field in ("signer_thumbprint", "tsa_thumbprint"):
            value = item.get(field)
            if type(value) is not str or not 40 <= len(value) <= 128 or any(
                    character not in "0123456789abcdef" for character in value):
                raise FinalizedBundleError(
                    f"manifest Authenticode record[{index}] {field} is invalid")
        try:
            evidence._timestamp(
                item.get("verified_at_utc"),
                f"manifest Authenticode record[{index}] verification time")
        except ValueError as exc:
            raise FinalizedBundleError(str(exc)) from exc
        _string(item.get("verifier_id"), f"manifest Authenticode record[{index}] verifier ID")
        _string(item.get("verifier_version"), f"manifest Authenticode record[{index}] verifier version")
    records = document.get("files")
    if type(records) is not list or not records:
        raise FinalizedBundleError("manifest file records are missing")
    paths: set[str] = set()
    aliases: set[str] = set()
    purposes: set[str] = set()
    for index, item in enumerate(records):
        record = _record(item, index)
        path = record["relative_path"]
        alias = path.casefold()
        if path in paths or alias in aliases or record["purpose"] in purposes:
            raise FinalizedBundleError("manifest paths, aliases, or purposes are duplicated")
        paths.add(path)
        aliases.add(alias)
        purposes.add(record["purpose"])
    if evidence.canonical_json_bytes(document) != data:
        raise FinalizedBundleError("finalized manifest must use canonical JSON")
    return document


def _snapshot_matches_record(snapshot: FileSnapshot, record: dict[str, Any], what: str) -> None:
    if snapshot.sha256 != record["sha256"] or snapshot.size != record["size_bytes"]:
        raise FinalizedBundleError(f"{what} bytes do not match manifest digest or size")


def _unchanged(snapshot: FileSnapshot) -> None:
    try:
        info = snapshot.path.stat(follow_symlinks=False)
    except OSError as exc:
        raise FinalizedBundleError(f"captured artifact identity changed: {exc}") from exc
    actual = ((info.st_dev, info.st_ino, info.st_size) if os.name == "nt" else
              (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
    expected = ((snapshot.device, snapshot.inode, snapshot.size) if os.name == "nt" else
                (snapshot.device, snapshot.inode, snapshot.size,
                 snapshot.mtime_ns, snapshot.ctime_ns))
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or actual != expected:
        raise FinalizedBundleError("captured artifact identity changed while loading")


def load_finalized_evidence(
    bundle_dir: Path,
    *,
    expected_context_id: str,
    expected_manifest_sha256: str,
    current_trust_document: bytes,
    authenticode_verifier: Callable[[bytes, datetime], phase_b.AuthenticodeResult],
    now: datetime | None = None,
) -> ReverifiedFinalizedEvidence:
    """Reload, currently reverify, and byte-replay a Phase B publication.

    The caller must retain both expected hashes independently.  Manifest,
    receipt, challenge, trust, and signature reads use fixed limits.  Material
    reads use either the externally pinned prepared-context sizes or sizes from
    provider-signed receipt metadata.  Every bundle file is snapshotted once.
    """
    try:
        expected_context_id = _hex(expected_context_id, "expected external context ID")
        expected_manifest_sha256 = _hex(
            expected_manifest_sha256, "expected external manifest digest")
        current = phase_b._now(now)
        if not isinstance(bundle_dir, Path):
            raise FinalizedBundleError("bundle_dir must be a Path")
        if type(current_trust_document) is not bytes:
            raise FinalizedBundleError("current trust document must be bytes")
        if len(current_trust_document) > _JSON_MAX_BYTES:
            raise FinalizedBundleError("current trust document exceeds the JSON boundary")
        if not callable(authenticode_verifier):
            raise FinalizedBundleError("an explicit bytes-only Authenticode verifier is required")
        current_policy = phase_b._policy(current_trust_document)

        root = bundle_dir.absolute()
        phase_c._directory(root)
        manifest_snapshot = snapshot_file(
            root / _MANIFEST, what="finalized evidence manifest",
            reject_hardlinks=True, max_bytes=_JSON_MAX_BYTES)
        # This external hash check intentionally precedes directory inventory
        # and every manifest-directed read.
        if manifest_snapshot.sha256 != expected_manifest_sha256:
            raise FinalizedBundleError(
                "finalized manifest does not match the expected external digest")
        manifest = _decode_manifest(manifest_snapshot.data)
        if manifest["context_id"] != expected_context_id:
            raise FinalizedBundleError(
                "finalized context does not match the expected external pin")

        before = phase_c._inventory(root)
        records: list[dict[str, Any]] = manifest["files"]
        expected_names = frozenset({_MANIFEST, *(record["relative_path"] for record in records)})
        if before[1] != expected_names:
            raise FinalizedBundleError(
                "bundle directory has extra, missing, or aliased entries")

        snapshots: dict[str, FileSnapshot] = {}

        def capture(record: dict[str, Any], *, maximum: int, what: str) -> FileSnapshot:
            path = record["relative_path"]
            if path in snapshots:
                return snapshots[path]
            if type(maximum) is not int or maximum <= 0:
                raise FinalizedBundleError(f"{what} read boundary is invalid")
            captured = snapshot_file(
                root / path, what=what, reject_hardlinks=True, max_bytes=maximum)
            _snapshot_matches_record(captured, record, what)
            snapshots[path] = captured
            return captured

        if len(records) < 3:
            raise FinalizedBundleError("manifest control file set is incomplete")
        controls = ("challenge", "initial-trust", "current-trust")
        for record, purpose in zip(records[:3], controls):
            if record["purpose"] != purpose or not 1 <= record["size_bytes"] <= _JSON_MAX_BYTES:
                raise FinalizedBundleError("manifest control purpose, order, or size is invalid")
        challenge_snapshot = capture(
            records[0], maximum=_JSON_MAX_BYTES, what="finalized challenge")
        initial_trust_snapshot = capture(
            records[1], maximum=_JSON_MAX_BYTES, what="finalized initial trust")
        current_trust_snapshot = capture(
            records[2], maximum=_JSON_MAX_BYTES, what="finalized current trust")
        if (records[1]["sha256"] != manifest["initial_trust_sha256"]
                or records[2]["sha256"] != manifest["current_trust_sha256"]):
            raise FinalizedBundleError("manifest trust bindings are inconsistent")
        if current_trust_snapshot.data != current_trust_document:
            raise FinalizedBundleError(
                "bundled current trust does not exactly match caller trust bytes")
        challenge = phase_b._document(challenge_snapshot.data, "finalized challenge")
        if evidence.canonical_json_bytes(challenge) != challenge_snapshot.data:
            raise FinalizedBundleError("finalized challenge must use canonical JSON")
        phase_b._policy(initial_trust_snapshot.data)
        if evidence.canonical_json_bytes(
                phase_b._document(initial_trust_snapshot.data, "finalized initial trust")
        ) != initial_trust_snapshot.data:
            raise FinalizedBundleError("finalized initial trust must use canonical JSON")
        if evidence.canonical_json_bytes(
                phase_b._document(current_trust_snapshot.data, "finalized current trust")
        ) != current_trust_snapshot.data:
            raise FinalizedBundleError("finalized current trust must use canonical JSON")
        state = evidence.validate_challenge(
            challenge, trust_policy=current_policy, now=current)
        if manifest["challenge_id"] != challenge.get("challenge_id"):
            raise FinalizedBundleError("manifest challenge binding is inconsistent")

        subject_documents = challenge["subjects"]
        subject_ids = [subject["subject_id"] for subject in subject_documents]
        material_purposes = ["candidate-stub", "candidate-manifest", "production-native"]
        for subject_id in subject_ids:
            material_purposes.extend(
                f"{subject_id}:{field}" for field in _SUBJECT_FIELDS)
        material_start = 3
        material_end = material_start + len(material_purposes)
        signed_end = material_end + len(subject_ids)
        if len(records) < signed_end:
            raise FinalizedBundleError("manifest prepared or signed material is incomplete")
        material_records = records[material_start:material_end]
        if [record["purpose"] for record in material_records] != material_purposes:
            raise FinalizedBundleError("manifest prepared material purpose order is invalid")
        if [record["purpose"] for record in records[material_end:signed_end]] != [
                f"{subject_id}:signed" for subject_id in subject_ids]:
            raise FinalizedBundleError("manifest signed-subject purpose order is invalid")

        verification = manifest["candidate_verification"]
        candidate_identity = challenge.get("candidate")
        if (type(candidate_identity) is not dict
                or candidate_identity != {
                    "source_commit": verification["source_commit"],
                    "candidate_stub_sha256": verification["candidate_stub_sha256"],
                    "candidate_manifest_sha256": verification["candidate_manifest_sha256"],
                    "production_native_sha256": verification["production_native_sha256"],
                }
                or verification["candidate_stub_sha256"] != material_records[0]["sha256"]
                or verification["candidate_manifest_sha256"] != material_records[1]["sha256"]
                or verification["production_native_sha256"] != material_records[2]["sha256"]):
            raise FinalizedBundleError(
                "candidate verification, challenge, and material bindings differ")
        context_content = {
            "challenge_sha256": records[0]["sha256"],
            "trust_sha256": records[1]["sha256"],
            "candidate_verification": verification,
            "material": [{
                "purpose": record["purpose"], "sha256": record["sha256"],
                "size": record["size_bytes"],
            } for record in material_records],
        }
        if _digest(
            phase_b._CONTEXT_DOMAIN + evidence.canonical_json_bytes(context_content)
        ) != expected_context_id:
            raise FinalizedBundleError(
                "manifest prepared metadata does not match the expected context pin")

        # Prepared material sizes become read budgets only after the context
        # commitment above has matched the independently retained pin.
        material_snapshots = [capture(
            record, maximum=max(1, record["size_bytes"]), what="finalized prepared material")
            for record in material_records]
        by_purpose = {
            record["purpose"]: captured
            for record, captured in zip(material_records, material_snapshots)
        }
        candidate = phase_b.PreparedCandidate(
            source_commit=verification["source_commit"],
            stub=by_purpose["candidate-stub"],
            manifest=by_purpose["candidate-manifest"],
            production_native=by_purpose["production-native"],
        )
        verification_result = phase_b.CandidateVerificationResult(
            source_commit=verification["source_commit"],
            stub_sha256=verification["candidate_stub_sha256"],
            manifest_sha256=verification["candidate_manifest_sha256"],
            production_native_sha256=verification["production_native_sha256"],
            verifier_id=verification["verifier_id"],
            verifier_version=verification["verifier_version"],
            valid=True,
        )
        subjects = tuple(phase_b.PreparedSubject(
            subject_id=subject["subject_id"], subject_kind=subject["subject_kind"],
            **{
                field: by_purpose[f"{subject['subject_id']}:{field}"]
                for field in _SUBJECT_FIELDS
            },
        ) for subject in subject_documents)
        prepared = phase_b.PreparedEvidence(
            challenge_bytes=challenge_snapshot.data,
            trust_bytes=initial_trust_snapshot.data,
            context_id=expected_context_id,
            candidate=candidate,
            candidate_verification=verification_result,
            subjects=subjects,
        )
        phase_b._prepared_state(prepared, current_policy, current)

        expected_receipts = sorted(
            (subject_id, role, scope_id)
            for subject_id in state["subjects"]
            for role, scopes in state["requirements"].items()
            for scope_id in scopes
        )
        groups: list[tuple[tuple[str, str, str], dict[str, Any], dict[str, Any], list[dict[str, Any]]]] = []
        cursor = signed_end
        for receipt_index, key in enumerate(expected_receipts):
            backing_count = len(evidence.REQUIRED_BACKING_IDS[key[1]])
            end = cursor + 2 + backing_count
            if end > len(records):
                raise FinalizedBundleError("manifest receipt file set is incomplete")
            canonical_record, signature_record = records[cursor:cursor + 2]
            backing_records = records[cursor + 2:end]
            if (canonical_record["purpose"] != f"receipt-{receipt_index}:canonical"
                    or signature_record["purpose"] != f"receipt-{receipt_index}:signature"
                    or signature_record["size_bytes"] != 64
                    or not 1 <= canonical_record["size_bytes"] <= _JSON_MAX_BYTES
                    or any(not record["purpose"].startswith(
                        f"receipt-{receipt_index}:backing:") for record in backing_records)):
                raise FinalizedBundleError("manifest receipt purpose, order, or control size is invalid")
            groups.append((key, canonical_record, signature_record, backing_records))
            cursor = end
        if cursor != len(records):
            raise FinalizedBundleError("manifest receipt file set has extras")

        signed_records = {
            subject_id: records[material_end + index]
            for index, subject_id in enumerate(subject_ids)
        }
        subject_snapshots = {subject.subject_id: subject for subject in subjects}
        receipts: list[evidence.VerifiedReceipt] = []
        for receipt_index, (expected_key, canonical_record, signature_record,
                            backing_records) in enumerate(groups):
            canonical_snapshot = capture(
                canonical_record, maximum=_JSON_MAX_BYTES,
                what=f"receipt[{receipt_index}] canonical JSON")
            signature_snapshot = capture(
                signature_record, maximum=64,
                what=f"receipt[{receipt_index}] signature")
            receipt_document = load_json_object_bytes(
                canonical_snapshot.data, what=f"receipt[{receipt_index}] canonical JSON",
                max_bytes=_JSON_MAX_BYTES)
            if evidence.canonical_json_bytes(receipt_document) != canonical_snapshot.data:
                raise FinalizedBundleError(
                    f"receipt[{receipt_index}] canonical JSON is not canonical")
            raw_backings = receipt_document.get("backings")
            if (not isinstance(raw_backings, list)
                    or len(raw_backings) != len(backing_records)
                    or any(type(item) is not dict or set(item) != evidence.BACKING_FIELDS
                           for item in raw_backings)):
                raise FinalizedBundleError(
                    f"receipt[{receipt_index}] backing metadata is malformed")
            if [record["purpose"] for record in backing_records] != [
                    f"receipt-{receipt_index}:backing:{item['id']}"
                    for item in raw_backings]:
                raise FinalizedBundleError(
                    f"receipt[{receipt_index}] backing purpose order is invalid")
            by_relative = {
                item["path"]: (item, backing_records[index])
                for index, item in enumerate(raw_backings)
                if type(item.get("path")) is str
            }
            envelope = {
                "schema": evidence.RECEIPT_SCHEMA,
                "kind": evidence.RECEIPT_KIND,
                "receipt": receipt_document,
                "signature_base64": base64.b64encode(signature_snapshot.data).decode("ascii"),
            }
            subject_id = expected_key[0]

            def signed_subject(size: int, *, subject_id: str = subject_id) -> FileSnapshot:
                record = signed_records[subject_id]
                subject = receipt_document.get("subject")
                signed_hash = subject.get("signed_subject_sha256") if type(subject) is dict else None
                if record["size_bytes"] != size or record["sha256"] != signed_hash:
                    raise FinalizedBundleError(
                        f"receipt[{receipt_index}] signed subject differs from manifest")
                return capture(
                    record, maximum=size, what=f"receipt[{receipt_index}] signed subject")

            def backing(
                relative: str, size: int, what: str,
                *, by_relative: dict[str, tuple[dict[str, Any], dict[str, Any]]] = by_relative,
            ) -> FileSnapshot:
                matched = by_relative.get(relative)
                if matched is None:
                    raise FinalizedBundleError(f"{what} metadata is absent")
                metadata, record = matched
                if record["size_bytes"] != size or record["sha256"] != metadata.get("sha256"):
                    raise FinalizedBundleError(f"{what} differs from manifest")
                return capture(record, maximum=size, what=what)

            verified = evidence.verify_detached_receipt_lazy(
                envelope,
                challenge=challenge,
                trust_policy=current_policy,
                prepared_snapshot=subject_snapshots[subject_id].unsigned,
                get_signed_subject=signed_subject,
                get_backing=backing,
                now=current,
            )
            if (verified.subject_id, verified.role, verified.scope_id) != expected_key:
                raise FinalizedBundleError(
                    f"receipt[{receipt_index}] coverage key or order is invalid")
            receipts.append(verified)

        if len(snapshots) != len(records):
            raise FinalizedBundleError("not every manifest artifact was captured exactly once")
        recorded = evidence._timestamp(
            manifest["finalized_at_utc"], "manifest finalization time")
        created = state["created_at"]
        expires = state["expires_at"]
        if recorded > current or recorded < created or recorded >= expires:
            raise FinalizedBundleError(
                "recorded finalization time is future-dated or outside the challenge")
        if (len(manifest["authenticode"]) != len(subject_ids)
                or [item["subject_id"] for item in manifest["authenticode"]] != subject_ids
                or any(evidence._timestamp(
                    item["verified_at_utc"], "manifest Authenticode verification time")
                    != recorded for item in manifest["authenticode"])):
            raise FinalizedBundleError(
                "manifest Authenticode subject order or reference time is invalid")

        receipt_tuple = tuple(receipts)
        # Current-time verification happens first.  Historical verification is
        # a separate explicit reference-time call and must reproduce every byte.
        fresh = phase_b.finalize_evidence(
            prepared, receipt_tuple,
            current_trust_document=current_trust_document,
            authenticode_verifier=authenticode_verifier,
            now=current,
        )
        historical = phase_b.finalize_evidence(
            prepared, receipt_tuple,
            current_trust_document=current_trust_document,
            authenticode_verifier=authenticode_verifier,
            now=recorded,
        )
        published = phase_b.FinalizedEvidence(
            manifest_bytes=manifest_snapshot.data,
            files=tuple(phase_b.EvidenceFile(
                record["relative_path"], snapshots[record["relative_path"]].data,
                record["purpose"],
            ) for record in records),
            context_id=expected_context_id,
            release_authorized=False,
        )
        if historical != published:
            raise FinalizedBundleError(
                "historical finalization replay does not exactly match publication")
        if fresh.release_authorized is not False or historical.release_authorized is not False:
            raise FinalizedBundleError("reverified evidence claims release authority")
        if phase_c._inventory(root) != before:
            raise FinalizedBundleError(
                "bundle directory identity or membership changed while loading")
        _unchanged(manifest_snapshot)
        for captured in snapshots.values():
            _unchanged(captured)
        return ReverifiedFinalizedEvidence(
            published=published,
            fresh=fresh,
            prepared=prepared,
            receipts=receipt_tuple,
            recorded_finalized_at_utc=recorded,
            release_authorized=False,
        )
    except FinalizedBundleError:
        raise
    except (ValueError, OSError) as exc:
        raise FinalizedBundleError(f"finalized evidence reload failed: {exc}") from exc


__all__ = [
    "FinalizedBundleError", "ReverifiedFinalizedEvidence",
    "load_finalized_evidence",
]
