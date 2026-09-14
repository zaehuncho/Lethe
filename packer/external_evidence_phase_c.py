"""Strict, externally pinned persistence of Phase B prepared evidence.

The descriptor is data, not a source of trust: reload requires a context ID
retained independently by the caller. Candidate verification is a retained
assertion bound by that pin, not a new verification operation. Original snapshot
path/identity fields are omitted; retained contents remain verbatim and may
themselves contain paths. Nothing is executed.
"""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

from . import external_evidence_phase_b as phase_b
from . import external_evidence_v2 as evidence
from .pe_content_id import FileSnapshot, snapshot_file
from .strict_json import load_json_object_bytes


_KIND = "lethe-prepared-evidence-bundle"
_DESCRIPTOR = "prepared.json"
_JSON_MAX_BYTES = 1048576
_FIELDS = frozenset({
    "schema", "kind", "release_authorized", "context_id",
    "candidate_verification", "candidate", "subjects", "files",
})
_VERIFICATION_FIELDS = frozenset({
    "source_commit", "candidate_stub_sha256", "candidate_manifest_sha256",
    "production_native_sha256", "verifier_id", "verifier_version", "valid",
})
_SUBJECT_FIELDS = ("unsigned", "input", "pack_report", "protection_profile")
_INITIAL_PURPOSES = (
    "challenge", "initial-trust", "candidate-stub", "candidate-manifest", "production-native",
)


class PreparedBundleError(ValueError):
    """A prepared bundle, its caller-held pin, or its storage boundary is invalid."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: Any, what: str, *, commit: bool = False) -> None:
    pattern = evidence.COMMIT_RE if commit else evidence.SHA256_RE
    if type(value) is not str or pattern.fullmatch(value) is None or set(value) == {"0"}:
        raise PreparedBundleError(f"{what} is invalid")


def _validate_descriptor(document: dict[str, Any]) -> None:
    if (type(document) is not dict or set(document) != _FIELDS
            or type(document.get("schema")) is not int or document["schema"] != 1
            or document.get("kind") != _KIND or document.get("release_authorized") is not False):
        raise PreparedBundleError("prepared descriptor schema, kind, or authority is invalid")
    _hex(document["context_id"], "prepared context ID")
    candidate = document["candidate"]
    if type(candidate) is not dict or set(candidate) != {"source_commit"}:
        raise PreparedBundleError("prepared candidate fields are invalid")
    _hex(candidate["source_commit"], "candidate source commit", commit=True)
    verification = document["candidate_verification"]
    if (type(verification) is not dict or set(verification) != _VERIFICATION_FIELDS
            or verification.get("valid") is not True):
        raise PreparedBundleError("candidate verification record is malformed")
    _hex(verification["source_commit"], "verified source commit", commit=True)
    for field in ("candidate_stub_sha256", "candidate_manifest_sha256", "production_native_sha256"):
        _hex(verification[field], f"candidate verification {field}")
    for field in ("verifier_id", "verifier_version"):
        value = verification[field]
        if type(value) is not str or not value.strip() or len(value) > 256 or "\x00" in value:
            raise PreparedBundleError(f"candidate verification {field} is invalid")
    subjects = document["subjects"]
    if type(subjects) is not list or len(subjects) < 2:
        raise PreparedBundleError("prepared subjects must include EXE and DLL")
    subject_ids: set[str] = set()
    kinds: set[str] = set()
    purposes = list(_INITIAL_PURPOSES)
    for subject in subjects:
        if type(subject) is not dict or set(subject) != {"subject_id", "subject_kind"}:
            raise PreparedBundleError("prepared subject fields are invalid")
        subject_id, kind = subject["subject_id"], subject["subject_kind"]
        if (type(subject_id) is not str or evidence.ID_RE.fullmatch(subject_id) is None
                or subject_id in subject_ids or type(kind) is not str or kind not in evidence.SUBJECT_KINDS):
            raise PreparedBundleError("prepared subject ID, kind, or order is invalid or duplicated")
        subject_ids.add(subject_id)
        kinds.add(kind)
        purposes.extend(f"{subject_id}:{field}" for field in _SUBJECT_FIELDS)
    if kinds != evidence.SUBJECT_KINDS:
        raise PreparedBundleError("prepared subjects do not cover EXE and DLL")
    records = document["files"]
    if type(records) is not list or len(records) != len(purposes):
        raise PreparedBundleError("prepared file purpose set is incomplete or has extras")
    shared: dict[str, tuple[str, int]] = {}
    for expected_purpose, record in zip(purposes, records):
        if (type(record) is not dict or set(record) != {"purpose", "path", "sha256", "size_bytes"}
                or type(record["purpose"]) is not str or record["purpose"] != expected_purpose):
            raise PreparedBundleError("prepared file purpose fields or order are invalid or duplicated")
        _hex(record["sha256"], "prepared file digest")
        if (type(record["path"]) is not str or record["path"] != record["sha256"] + ".bin"
                or type(record["size_bytes"]) is not int or record["size_bytes"] < 0):
            raise PreparedBundleError("prepared file path or size is invalid")
        # Challenge/trust hashes, but not their sizes, are committed by Phase B.
        # Material-file sizes below are included in that context commitment.
        # Preserve the JSON parser's existing bound independently of the pin.
        if (expected_purpose in _INITIAL_PURPOSES[:2]
                and not 1 <= record["size_bytes"] <= _JSON_MAX_BYTES):
            raise PreparedBundleError("prepared challenge or trust size exceeds the JSON boundary")
        identity = (record["sha256"], record["size_bytes"])
        if record["path"] in shared and shared[record["path"]] != identity:
            raise PreparedBundleError("shared prepared artifact metadata conflicts")
        shared[record["path"]] = identity


def _decode_descriptor(data: bytes) -> dict[str, Any]:
    document = load_json_object_bytes(data, what="prepared descriptor", max_bytes=_JSON_MAX_BYTES)
    _validate_descriptor(document)
    if evidence.canonical_json_bytes(document) != data:
        raise PreparedBundleError("prepared descriptor must use canonical JSON")
    return document


def _descriptor_context_id(document: dict[str, Any]) -> str:
    """Mirror Phase B's exact commitment from validated metadata, before I/O.

    This precheck pins material read sizes; full retained-byte validation by
    Phase B remains necessary after capture. Challenge/trust size bounds are
    separate JSON invariants, not fields included in the context commitment.
    """
    records = document["files"]
    verification = document["candidate_verification"]
    if (document["candidate"]["source_commit"] != verification["source_commit"]
            or verification["candidate_stub_sha256"] != records[2]["sha256"]
            or verification["candidate_manifest_sha256"] != records[3]["sha256"]
            or verification["production_native_sha256"] != records[4]["sha256"]):
        raise PreparedBundleError("prepared candidate verification and material bindings do not match")
    content = {
        "challenge_sha256": records[0]["sha256"],
        "trust_sha256": records[1]["sha256"],
        "candidate_verification": verification,
        "material": [{"purpose": record["purpose"], "sha256": record["sha256"],
                      "size": record["size_bytes"]} for record in records[2:]],
    }
    return _digest(phase_b._CONTEXT_DOMAIN + evidence.canonical_json_bytes(content))


def _reject_reparse(path: Path, info: os.stat_result) -> None:
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        raise PreparedBundleError(f"bundle path cannot traverse a link or reparse point: {path.name}")
    is_junction = getattr(path, "is_junction", None)
    if is_junction is not None and is_junction():
        raise PreparedBundleError(f"bundle path cannot traverse a junction: {path.name}")


def _directory(path: Path) -> os.stat_result:
    current = path
    root_info = None
    while True:
        info = current.lstat()
        _reject_reparse(current, info)
        if current == path:
            root_info = info
        if current.parent == current:
            break
        current = current.parent
    if root_info is None or not stat.S_ISDIR(root_info.st_mode):
        raise PreparedBundleError("bundle root is not a directory")
    return root_info


def _inventory(root: Path) -> tuple[tuple[int, ...], frozenset[str]]:
    info = _directory(root)
    names: set[str] = set()
    aliases: set[str] = set()
    for entry in root.iterdir():
        alias = entry.name.casefold()
        if alias in aliases:
            raise PreparedBundleError("bundle directory contains filename aliases")
        aliases.add(alias)
        entry_info = entry.lstat()
        _reject_reparse(entry, entry_info)
        if not stat.S_ISREG(entry_info.st_mode):
            raise PreparedBundleError("bundle contains a directory or non-regular entry")
        if entry_info.st_nlink != 1:
            raise PreparedBundleError("bundle contains a hard-linked entry")
        names.add(entry.name)
    identity = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
    return identity, frozenset(names)


def _write_exclusive(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        if stream.write(data) != len(data):
            raise PreparedBundleError("prepared bundle write was incomplete")
        stream.flush()
        os.fsync(stream.fileno())


def publish_prepared_bundle(
    prepared: phase_b.PreparedEvidence, output_dir: Path, *, now: datetime | None = None,
) -> Path:
    """Publish validated retained bytes into a new, exclusive flat directory.

    The caller provides a private, stable parent. Every file is flushed/fsynced;
    prepared.json is written last. I/O failure leaves a partial directory for
    inspection, not deletion or reuse. A marker is accepted only after complete
    reload validation; its mere existence does not prove completed publication.
    No original source paths are reopened and no release is authorized.
    """
    try:
        if type(prepared) is not phase_b.PreparedEvidence:
            raise PreparedBundleError("prepared evidence is malformed")
        current = phase_b._now(now)
        phase_b._prepared_state(prepared, phase_b._policy(prepared.trust_bytes), current)
        payloads = [("challenge", prepared.challenge_bytes), ("initial-trust", prepared.trust_bytes)]
        payloads.extend((purpose, snapshot.data) for purpose, snapshot in phase_b._material(prepared))
        unique: dict[str, bytes] = {}
        records = []
        for purpose, data in payloads:
            digest = _digest(data)
            filename = digest + ".bin"
            if filename in unique and unique[filename] != data:
                raise PreparedBundleError("different retained bytes share an artifact digest")
            unique[filename] = data
            records.append({"purpose": purpose, "path": filename, "sha256": digest, "size_bytes": len(data)})
        descriptor = {
            "schema": 1, "kind": _KIND, "release_authorized": False,
            "context_id": prepared.context_id,
            "candidate_verification": phase_b._candidate_verification_record(
                prepared.candidate_verification, prepared.candidate),
            "candidate": {"source_commit": prepared.candidate.source_commit},
            "subjects": [{"subject_id": subject.subject_id, "subject_kind": subject.subject_kind}
                         for subject in prepared.subjects],
            "files": records,
        }
        descriptor_bytes = evidence.canonical_json_bytes(descriptor)
        _decode_descriptor(descriptor_bytes)
        if not isinstance(output_dir, Path):
            raise PreparedBundleError("output_dir must be a Path")
        target = output_dir.absolute()
        _directory(target.parent)
        target.mkdir(parents=False, exist_ok=False)
        for filename, data in unique.items():
            _write_exclusive(target / filename, data)
        _write_exclusive(target / _DESCRIPTOR, descriptor_bytes)
        return target / _DESCRIPTOR
    except PreparedBundleError:
        raise
    except (ValueError, OSError) as exc:
        raise PreparedBundleError(f"prepared publication failed; any partial directory is retained: {exc}") from exc


def load_prepared_bundle(
    bundle_dir: Path, *, expected_context_id: str, now: datetime | None = None,
) -> phase_b.PreparedEvidence:
    """Reload only a bundle matching the caller's independently retained pin.

    The descriptor uses a bounded capture; validated metadata must reproduce
    the external pin before material sizes become read budgets. Challenge and
    trust JSON retain their independent parser-size bound. Each unique artifact
    and descriptor is captured once. Root identity and
    exact flat membership are checked before and after loading. This is a
    fail-closed consistency check, not a held-directory guarantee against a
    concurrently hostile storage parent; callers keep that parent stable.
    Restored paths and filesystem identities describe only the bundle captures.
    """
    try:
        _hex(expected_context_id, "expected external context ID")
        current = phase_b._now(now)
        if not isinstance(bundle_dir, Path):
            raise PreparedBundleError("bundle_dir must be a Path")
        root = bundle_dir.absolute()
        before = _inventory(root)
        descriptor_snapshot = snapshot_file(
            root / _DESCRIPTOR, what="prepared descriptor", reject_hardlinks=True,
            max_bytes=_JSON_MAX_BYTES)
        descriptor = _decode_descriptor(descriptor_snapshot.data)
        if descriptor["context_id"] != expected_context_id:
            raise PreparedBundleError("prepared context does not match the expected external pin")
        if _descriptor_context_id(descriptor) != expected_context_id:
            raise PreparedBundleError("prepared descriptor metadata does not match the expected external pin")
        expected_names = frozenset({_DESCRIPTOR, *(record["path"] for record in descriptor["files"])})
        if before[1] != expected_names:
            raise PreparedBundleError("bundle directory has extra, missing, or aliased entries")
        snapshots: dict[str, FileSnapshot] = {}
        by_purpose: dict[str, FileSnapshot] = {}
        for record in descriptor["files"]:
            filename = record["path"]
            if filename not in snapshots:
                # snapshot_file requires a positive bound; an empty opaque
                # artifact still has an exact zero-size/hash check below.
                snapshots[filename] = snapshot_file(
                    root / filename, what="prepared artifact", reject_hardlinks=True,
                    max_bytes=max(1, record["size_bytes"]))
            snapshot = snapshots[filename]
            if snapshot.sha256 != record["sha256"] or snapshot.size != record["size_bytes"]:
                raise PreparedBundleError("prepared artifact bytes do not match declared digest or size")
            by_purpose[record["purpose"]] = snapshot
        candidate = phase_b.PreparedCandidate(
            source_commit=descriptor["candidate"]["source_commit"], stub=by_purpose["candidate-stub"],
            manifest=by_purpose["candidate-manifest"], production_native=by_purpose["production-native"])
        record = descriptor["candidate_verification"]
        verification = phase_b.CandidateVerificationResult(
            source_commit=record["source_commit"], stub_sha256=record["candidate_stub_sha256"],
            manifest_sha256=record["candidate_manifest_sha256"], production_native_sha256=record["production_native_sha256"],
            verifier_id=record["verifier_id"], verifier_version=record["verifier_version"], valid=record["valid"])
        subjects = tuple(phase_b.PreparedSubject(
            subject_id=subject["subject_id"], subject_kind=subject["subject_kind"],
            **{field: by_purpose[f"{subject['subject_id']}:{field}"] for field in _SUBJECT_FIELDS},
        ) for subject in descriptor["subjects"])
        prepared = phase_b.PreparedEvidence(
            challenge_bytes=by_purpose["challenge"].data, trust_bytes=by_purpose["initial-trust"].data,
            context_id=expected_context_id, candidate=candidate, candidate_verification=verification, subjects=subjects)
        phase_b._prepared_state(prepared, phase_b._policy(prepared.trust_bytes), current)
        if _inventory(root) != before:
            raise PreparedBundleError("bundle directory identity or membership changed while loading")
        return prepared
    except PreparedBundleError:
        raise
    except (ValueError, OSError) as exc:
        raise PreparedBundleError(f"prepared bundle reload failed: {exc}") from exc


__all__ = ["PreparedBundleError", "load_prepared_bundle", "publish_prepared_bundle"]
