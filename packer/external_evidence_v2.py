"""Fail-closed primitives for challenge-bound external evidence receipts.

This module deliberately has no collector or release-pipeline integration. It
defines the trust, challenge, receipt, and backing-file boundary that those
later phases must use.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .pe_content_id import (
    FileSnapshot,
    snapshot_file,
    validate_signing_delta_snapshots,
)


TRUST_SCHEMA = 2
CHALLENGE_SCHEMA = 2
RECEIPT_SCHEMA = 2
CHALLENGE_KIND = "lethe-external-evidence-challenge"
RECEIPT_KIND = "lethe-external-evidence-receipt"
RECEIPT_SIGNATURE_DOMAIN = b"lethe-external-evidence-receipt-v2\x00"
CHALLENGE_ID_DOMAIN = b"lethe-external-evidence-challenge-v2\x00"
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_CHALLENGE_LIFETIME = timedelta(hours=72)


@dataclass(frozen=True)
class VerifiedBacking:
    """One receipt backing and the exact bytes accepted by verification."""

    backing_id: str
    relative_path: str
    snapshot: FileSnapshot


@dataclass(frozen=True)
class VerifiedReceipt:
    """Validated receipt identity plus every immutable file snapshot it used."""

    role: str
    provider_key_id: str
    challenge_id: str
    subject_id: str
    scope_id: str
    canonical_receipt: bytes
    receipt_sha256: str
    prepared_subject: FileSnapshot
    signed_subject: FileSnapshot
    backings: tuple[VerifiedBacking, ...]

ROLES = frozenset({"scanner", "clean-vm", "application"})
SUBJECT_KINDS = frozenset({"exe", "dll"})
SUBJECT_FORMAT = "windows-x64-pe32+"
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
KEY_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")

TRUST_FIELDS = frozenset({"schema", "algorithm", "providers", "authenticode"})
PROVIDER_FIELDS = frozenset({
    "id", "public_key_base64", "revoked", "role", "scope",
})
AUTHENTICODE_FIELDS = frozenset({
    "allowed_signer_thumbprints", "allowed_tsa_thumbprints",
})
ROLE_SCOPE_FIELDS = {
    "scanner": frozenset({"scanner_ids"}),
    "clean-vm": frozenset({"vm_cell_ids"}),
    "application": frozenset({"workflow_ids"}),
}
ROLE_SCOPE_LIST_FIELD = {
    "scanner": "scanner_ids",
    "clean-vm": "vm_cell_ids",
    "application": "workflow_ids",
}

CHALLENGE_FIELDS = frozenset({
    "schema", "kind", "challenge_id", "nonce_base64", "created_at_utc",
    "expires_at_utc", "candidate", "subjects", "requirements",
})
CANDIDATE_FIELDS = frozenset({
    "source_commit", "candidate_stub_sha256", "candidate_manifest_sha256",
    "production_native_sha256",
})
CHALLENGE_SUBJECT_FIELDS = frozenset({
    "subject_id", "subject_kind", "format", "input_sha256",
    "unsigned_subject_sha256", "unsigned_subject_size_bytes",
    "signing_stable_pe_id", "pack_report_sha256",
    "protection_profile_sha256", "protected_with_stub_sha256",
})
REQUIREMENTS_FIELDS = frozenset({
    "scanners", "vm_cells", "application_workflows",
})
SCANNER_REQUIREMENT_FIELDS = frozenset({
    "scanner_id", "provider_key_id", "tool_name", "tool_version",
    "definitions_version",
})
VM_REQUIREMENT_FIELDS = frozenset({
    "cell_id", "provider_key_id", "runner_sha256", "os_release", "os_build",
    "patch_level", "arch", "secure_boot", "vbs_enabled", "hvci_enabled",
    "hyper_v_enabled", "image_id", "snapshot_id",
})
APPLICATION_REQUIREMENT_FIELDS = frozenset({
    "workflow_id", "provider_key_id", "definition_sha256",
})

ENVELOPE_FIELDS = frozenset({"schema", "kind", "receipt", "signature_base64"})
RECEIPT_FIELDS = frozenset({
    "schema", "role", "provider_key_id", "challenge_id",
    "challenge_nonce_base64", "candidate", "subject", "scope", "status",
    "observed_at_utc", "observation", "backings",
})
RECEIPT_SUBJECT_FIELDS = frozenset({
    "subject_id", "subject_kind", "signed_subject_sha256",
    "signed_subject_size_bytes", "signing_stable_pe_id",
})
RECEIPT_SCOPE_FIELDS = {
    "scanner": frozenset({"scanner_id"}),
    "clean-vm": frozenset({"cell_id"}),
    "application": frozenset({"workflow_id"}),
}
RECEIPT_SCOPE_FIELD = {
    "scanner": "scanner_id",
    "clean-vm": "cell_id",
    "application": "workflow_id",
}
BACKING_FIELDS = frozenset({"id", "path", "sha256", "size_bytes"})
REQUIRED_BACKING_IDS = {
    "scanner": frozenset({"scanner-output"}),
    "clean-vm": frozenset({"runner", "result-log"}),
    "application": frozenset({"workflow-definition", "result", "log"}),
}
SCANNER_OBSERVATION_FIELDS = frozenset({
    "status", "detections", "tool_name", "tool_version",
    "definitions_version",
})
VM_OBSERVATION_FIELDS = frozenset({
    "status", "os_release", "os_build", "patch_level", "arch",
    "secure_boot", "vbs_enabled", "hvci_enabled", "hyper_v_enabled",
    "image_id", "snapshot_id",
})
APPLICATION_OBSERVATION_FIELDS = frozenset({"status", "exit_code"})


class ExternalEvidenceV2Error(ValueError):
    """A v2 trust document, challenge, receipt, or backing is invalid."""


def canonical_json_bytes(payload: Any) -> bytes:
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ExternalEvidenceV2Error("payload is not canonical JSON data") from exc


def sha256_file(path: Path) -> str:
    try:
        return snapshot_file(path, what="hash input").sha256
    except ValueError as exc:
        raise ExternalEvidenceV2Error(str(exc)) from exc


def public_key_id(raw_public_key: bytes) -> str:
    if not isinstance(raw_public_key, bytes) or len(raw_public_key) != 32:
        raise ExternalEvidenceV2Error("Ed25519 public keys must contain 32 bytes")
    return hashlib.sha256(raw_public_key).hexdigest()


def _decode_b64(value: Any, *, length: int, what: str) -> bytes:
    if not isinstance(value, str):
        raise ExternalEvidenceV2Error(f"{what} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ExternalEvidenceV2Error(f"{what} is not valid base64") from exc
    if len(decoded) != length:
        raise ExternalEvidenceV2Error(f"{what} has the wrong length")
    return decoded


def _is_linklike(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())
    except OSError:
        return True


def _reject_linklike_ancestors(path: Path, what: str) -> None:
    current = path.absolute()
    while True:
        if _is_linklike(current):
            raise ExternalEvidenceV2Error(
                f"{what} cannot traverse a link or junction")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _read_json_object(path: Path, what: str) -> dict[str, Any]:
    try:
        snapshot = snapshot_file(path, what=what, reject_hardlinks=True)
        payload = json.loads(snapshot.data.decode("utf-8-sig"))
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExternalEvidenceV2Error(f"cannot read {what}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ExternalEvidenceV2Error(f"{what} root must be an object")
    return payload


def _nonzero_hex(value: Any, pattern: re.Pattern[str], what: str) -> str:
    if (not isinstance(value, str) or pattern.fullmatch(value) is None
            or set(value) == {"0"}):
        raise ExternalEvidenceV2Error(f"{what} is invalid")
    return value


def _identifier(value: Any, what: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise ExternalEvidenceV2Error(f"{what} is invalid")
    return value


def _timestamp(value: Any, what: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        raise ExternalEvidenceV2Error(f"{what} is not a canonical UTC timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ExternalEvidenceV2Error(f"{what} is not a valid UTC timestamp") from exc


def _normalized_now(now: datetime | None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ExternalEvidenceV2Error("verification time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _string(value: Any, what: str, *, maximum: int = 256) -> str:
    if (not isinstance(value, str) or not value.strip()
            or len(value) > maximum or "\x00" in value):
        raise ExternalEvidenceV2Error(f"{what} is invalid")
    return value


def validate_evidence_trust_store_v2(payload: Any) -> dict[str, Any]:
    """Validate an in-memory v2 trust document and return active providers."""
    if (not isinstance(payload, dict) or set(payload) != TRUST_FIELDS
            or payload.get("schema") != TRUST_SCHEMA
            or payload.get("algorithm") != "ed25519"
            or not isinstance(payload.get("providers"), list)
            or not isinstance(payload.get("authenticode"), dict)):
        raise ExternalEvidenceV2Error("external-evidence v2 trust store is malformed")

    authenticode = payload["authenticode"]
    if (set(authenticode) != AUTHENTICODE_FIELDS
            or not isinstance(authenticode.get("allowed_signer_thumbprints"), list)
            or not isinstance(authenticode.get("allowed_tsa_thumbprints"), list)):
        raise ExternalEvidenceV2Error("v2 Authenticode policy is malformed")

    def thumbprints(values: list[Any], what: str) -> frozenset[str]:
        result: set[str] = set()
        for index, value in enumerate(values):
            if (not isinstance(value, str)
                    or re.fullmatch(r"[0-9a-f]{40,128}", value) is None
                    or value in result or set(value) == {"0"}):
                raise ExternalEvidenceV2Error(f"{what}[{index}] is invalid")
            result.add(value)
        if not result:
            raise ExternalEvidenceV2Error(f"{what} must not be empty")
        return frozenset(result)

    active: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()
    seen_public_keys: set[bytes] = set()
    for index, entry in enumerate(payload["providers"]):
        if (not isinstance(entry, dict) or set(entry) != PROVIDER_FIELDS
                or type(entry.get("revoked")) is not bool):
            raise ExternalEvidenceV2Error(f"provider[{index}] is malformed")
        key_id = _nonzero_hex(entry.get("id"), KEY_ID_RE, f"provider[{index}] id")
        role = entry.get("role")
        if not isinstance(role, str) or role not in ROLES:
            raise ExternalEvidenceV2Error(
                f"provider[{index}] must have exactly one recognized role")
        scope = entry.get("scope")
        expected_scope_fields = ROLE_SCOPE_FIELDS[role]
        scope_field = ROLE_SCOPE_LIST_FIELD[role]
        if (not isinstance(scope, dict) or set(scope) != expected_scope_fields
                or not isinstance(scope.get(scope_field), list)
                or not scope[scope_field]):
            raise ExternalEvidenceV2Error(f"provider[{index}] scope is malformed")
        normalized_scopes = [
            _identifier(value, f"provider[{index}] scope")
            for value in scope[scope_field]
        ]
        if len(normalized_scopes) != len(set(normalized_scopes)):
            raise ExternalEvidenceV2Error(f"provider[{index}] scope is duplicated")
        scopes = frozenset(normalized_scopes)
        raw_public = _decode_b64(
            entry.get("public_key_base64"), length=32,
            what=f"provider[{index}] public key",
        )
        if raw_public in seen_public_keys:
            raise ExternalEvidenceV2Error("duplicate provider public key")
        if key_id in seen_ids:
            raise ExternalEvidenceV2Error(f"duplicate provider id: {key_id}")
        if public_key_id(raw_public) != key_id:
            raise ExternalEvidenceV2Error(
                f"provider[{index}] id does not match its public key")
        seen_ids.add(key_id)
        seen_public_keys.add(raw_public)
        if not entry["revoked"]:
            active[key_id] = {
                "public_key": raw_public,
                "role": role,
                "scopes": scopes,
            }

    return {
        "providers": active,
        "provider_key_ids": frozenset(seen_ids),
        "allowed_signer_thumbprints": thumbprints(
            authenticode["allowed_signer_thumbprints"],
            "allowed signer thumbprint",
        ),
        "allowed_tsa_thumbprints": thumbprints(
            authenticode["allowed_tsa_thumbprints"],
            "allowed TSA thumbprint",
        ),
    }


def load_evidence_trust_store_v2(path: Path) -> dict[str, Any]:
    return validate_evidence_trust_store_v2(
        _read_json_object(path, "external-evidence v2 trust store"))


def compute_challenge_id(challenge: dict[str, Any]) -> str:
    """Compute the domain-separated ID over every challenge field except itself."""
    if not isinstance(challenge, dict):
        raise ExternalEvidenceV2Error("challenge root must be an object")
    body = dict(challenge)
    body.pop("challenge_id", None)
    return hashlib.sha256(
        CHALLENGE_ID_DOMAIN + canonical_json_bytes(body)).hexdigest()


def _active_provider(
    trust_policy: dict[str, Any], key_id: Any, *, role: str, scope: str,
) -> dict[str, Any]:
    if not isinstance(trust_policy, dict):
        raise ExternalEvidenceV2Error("v2 trust policy is malformed")
    providers = trust_policy.get("providers")
    if not isinstance(providers, dict):
        raise ExternalEvidenceV2Error("v2 trust policy has no provider registry")
    if not isinstance(key_id, str) or KEY_ID_RE.fullmatch(key_id) is None:
        raise ExternalEvidenceV2Error("provider key id is invalid")
    provider = providers.get(key_id)
    if not isinstance(provider, dict):
        raise ExternalEvidenceV2Error("provider key is unknown or revoked")
    if provider.get("role") != role:
        raise ExternalEvidenceV2Error("provider key has the wrong role")
    scopes = provider.get("scopes")
    if not isinstance(scopes, frozenset) or scope not in scopes:
        raise ExternalEvidenceV2Error("provider key is not authorized for the scope")
    if (not isinstance(provider.get("public_key"), bytes)
            or len(provider["public_key"]) != 32):
        raise ExternalEvidenceV2Error("provider public key is malformed")
    return provider


def validate_challenge(
    challenge: Any,
    *,
    trust_policy: dict[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate a current challenge and all candidate, subject, and key bindings."""
    if (not isinstance(challenge, dict) or set(challenge) != CHALLENGE_FIELDS
            or challenge.get("schema") != CHALLENGE_SCHEMA
            or challenge.get("kind") != CHALLENGE_KIND):
        raise ExternalEvidenceV2Error("external-evidence challenge is malformed")
    expected_id = compute_challenge_id(challenge)
    if (not isinstance(challenge.get("challenge_id"), str)
            or challenge["challenge_id"] != expected_id):
        raise ExternalEvidenceV2Error("challenge id does not match its canonical content")
    _decode_b64(challenge.get("nonce_base64"), length=32, what="challenge nonce")

    created = _timestamp(challenge.get("created_at_utc"), "challenge creation time")
    expires = _timestamp(challenge.get("expires_at_utc"), "challenge expiry time")
    current = _normalized_now(now)
    if created > current + MAX_CLOCK_SKEW:
        raise ExternalEvidenceV2Error("challenge is future-dated")
    if expires <= current:
        raise ExternalEvidenceV2Error("challenge is expired")
    if expires <= created or expires - created > MAX_CHALLENGE_LIFETIME:
        raise ExternalEvidenceV2Error("challenge lifetime is invalid")

    candidate = challenge.get("candidate")
    if not isinstance(candidate, dict) or set(candidate) != CANDIDATE_FIELDS:
        raise ExternalEvidenceV2Error("challenge candidate identity is malformed")
    _nonzero_hex(candidate.get("source_commit"), COMMIT_RE, "candidate source commit")
    for field in CANDIDATE_FIELDS - {"source_commit"}:
        _nonzero_hex(candidate.get(field), SHA256_RE, f"candidate {field}")

    subjects = challenge.get("subjects")
    if not isinstance(subjects, list) or len(subjects) < 2:
        raise ExternalEvidenceV2Error("challenge must bind EXE and DLL subjects")
    subject_index: dict[str, dict[str, Any]] = {}
    covered_kinds: set[str] = set()
    stable_ids: set[str] = set()
    for index, subject in enumerate(subjects):
        if not isinstance(subject, dict) or set(subject) != CHALLENGE_SUBJECT_FIELDS:
            raise ExternalEvidenceV2Error(f"challenge subject[{index}] is malformed")
        subject_id = _identifier(subject.get("subject_id"), f"subject[{index}] id")
        if subject_id in subject_index:
            raise ExternalEvidenceV2Error(f"duplicate challenge subject: {subject_id}")
        subject_kind = subject.get("subject_kind")
        if (not isinstance(subject_kind, str) or subject_kind not in SUBJECT_KINDS
                or subject.get("format") != SUBJECT_FORMAT):
            raise ExternalEvidenceV2Error(f"subject[{index}] PE identity is invalid")
        if (type(subject.get("unsigned_subject_size_bytes")) is not int
                or subject["unsigned_subject_size_bytes"] <= 0):
            raise ExternalEvidenceV2Error(f"subject[{index}] size is invalid")
        for field in CHALLENGE_SUBJECT_FIELDS - {
                "subject_id", "subject_kind", "format", "unsigned_subject_size_bytes"}:
            _nonzero_hex(subject.get(field), SHA256_RE, f"subject[{index}] {field}")
        if subject["protected_with_stub_sha256"] != candidate["candidate_stub_sha256"]:
            raise ExternalEvidenceV2Error(
                f"subject[{index}] is not bound to the candidate stub")
        if subject["signing_stable_pe_id"] in stable_ids:
            raise ExternalEvidenceV2Error(
                "challenge subjects must have distinct signing-stable identities")
        stable_ids.add(subject["signing_stable_pe_id"])
        subject_index[subject_id] = subject
        covered_kinds.add(subject_kind)
    if covered_kinds != SUBJECT_KINDS:
        raise ExternalEvidenceV2Error("challenge subjects do not cover EXE and DLL")

    requirements = challenge.get("requirements")
    if not isinstance(requirements, dict) or set(requirements) != REQUIREMENTS_FIELDS:
        raise ExternalEvidenceV2Error("challenge requirements are malformed")

    scanners = requirements.get("scanners")
    if not isinstance(scanners, list) or len(scanners) < 2:
        raise ExternalEvidenceV2Error("challenge requires two independent scanners")
    scanner_index: dict[str, dict[str, Any]] = {}
    scanner_keys: set[str] = set()
    for index, requirement in enumerate(scanners):
        if (not isinstance(requirement, dict)
                or set(requirement) != SCANNER_REQUIREMENT_FIELDS):
            raise ExternalEvidenceV2Error(f"scanner requirement[{index}] is malformed")
        scanner_id = _identifier(
            requirement.get("scanner_id"), f"scanner requirement[{index}] id")
        if scanner_id in scanner_index:
            raise ExternalEvidenceV2Error(f"duplicate scanner requirement: {scanner_id}")
        key_id = requirement.get("provider_key_id")
        _active_provider(trust_policy, key_id, role="scanner", scope=scanner_id)
        for field in ("tool_name", "tool_version", "definitions_version"):
            _string(
                requirement.get(field),
                f"scanner requirement[{index}] {field}",
            )
        if key_id in scanner_keys:
            raise ExternalEvidenceV2Error(
                "required scanners must use distinct provider keys")
        scanner_keys.add(key_id)
        scanner_index[scanner_id] = requirement

    def scoped_requirements(
        value: Any,
        *,
        name: str,
        fields: frozenset[str],
        id_field: str,
        role: str,
        hash_field: str,
    ) -> dict[str, dict[str, Any]]:
        if not isinstance(value, list) or not value:
            raise ExternalEvidenceV2Error(f"challenge {name} must not be empty")
        result: dict[str, dict[str, Any]] = {}
        for index, requirement in enumerate(value):
            if not isinstance(requirement, dict) or set(requirement) != fields:
                raise ExternalEvidenceV2Error(f"{name}[{index}] is malformed")
            scope_id = _identifier(
                requirement.get(id_field), f"{name}[{index}] scope")
            if scope_id in result:
                raise ExternalEvidenceV2Error(f"duplicate {name} scope: {scope_id}")
            _nonzero_hex(
                requirement.get(hash_field), SHA256_RE,
                f"{name}[{index}] {hash_field}",
            )
            _active_provider(
                trust_policy, requirement.get("provider_key_id"),
                role=role, scope=scope_id,
            )
            result[scope_id] = requirement
        return result

    vm_index = scoped_requirements(
        requirements.get("vm_cells"), name="VM requirements",
        fields=VM_REQUIREMENT_FIELDS, id_field="cell_id", role="clean-vm",
        hash_field="runner_sha256",
    )
    for cell_id, requirement in vm_index.items():
        if requirement.get("arch") != "x64":
            raise ExternalEvidenceV2Error(
                f"VM requirement {cell_id} architecture is invalid")
        for field in ("secure_boot", "vbs_enabled", "hvci_enabled", "hyper_v_enabled"):
            if type(requirement.get(field)) is not bool:
                raise ExternalEvidenceV2Error(
                    f"VM requirement {cell_id} {field} is not boolean")
        for field in (
                "os_release", "os_build", "patch_level", "image_id", "snapshot_id"):
            _string(requirement.get(field), f"VM requirement {cell_id} {field}")
    application_index = scoped_requirements(
        requirements.get("application_workflows"), name="application requirements",
        fields=APPLICATION_REQUIREMENT_FIELDS, id_field="workflow_id",
        role="application", hash_field="definition_sha256",
    )

    return {
        "challenge": challenge,
        "created_at": created,
        "expires_at": expires,
        "subjects": subject_index,
        "requirements": {
            "scanner": scanner_index,
            "clean-vm": vm_index,
            "application": application_index,
        },
    }


def detached_receipt_signature_payload(receipt: dict[str, Any]) -> bytes:
    """Return domain-separated canonical bytes signed by a receipt provider."""
    if not isinstance(receipt, dict):
        raise ExternalEvidenceV2Error("receipt must be an object")
    return RECEIPT_SIGNATURE_DOMAIN + canonical_json_bytes(receipt)


def _validate_observation(
    role: str,
    observation: Any,
    requirement: dict[str, Any],
) -> None:
    if not isinstance(observation, dict):
        raise ExternalEvidenceV2Error("receipt observation is malformed")
    if role == "scanner":
        if (set(observation) != SCANNER_OBSERVATION_FIELDS
                or observation.get("status") != "passed"
                or type(observation.get("detections")) is not int
                or observation["detections"] != 0):
            raise ExternalEvidenceV2Error("scanner observation is not a clean pass")
        for field in ("tool_name", "tool_version", "definitions_version"):
            _string(observation.get(field), f"scanner {field}")
            if observation[field] != requirement[field]:
                raise ExternalEvidenceV2Error(
                    f"scanner {field} does not match challenge")
        return
    if role == "clean-vm":
        if (set(observation) != VM_OBSERVATION_FIELDS
                or observation.get("status") != "passed"
                or observation.get("arch") != "x64"):
            raise ExternalEvidenceV2Error("clean-VM observation is not a pass")
        for field in ("secure_boot", "vbs_enabled", "hvci_enabled", "hyper_v_enabled"):
            if type(observation.get(field)) is not bool:
                raise ExternalEvidenceV2Error(f"clean-VM {field} is not boolean")
        for field in (
                "os_release", "os_build", "patch_level", "image_id", "snapshot_id"):
            _string(observation.get(field), f"clean-VM {field}")
        expected = {field: requirement[field] for field in VM_OBSERVATION_FIELDS - {"status"}}
        actual = {field: observation[field] for field in VM_OBSERVATION_FIELDS - {"status"}}
        if actual != expected:
            raise ExternalEvidenceV2Error(
                "clean-VM posture or build does not match challenge")
        return
    if (set(observation) != APPLICATION_OBSERVATION_FIELDS
            or observation.get("status") != "passed"
            or type(observation.get("exit_code")) is not int
            or observation["exit_code"] != 0):
        raise ExternalEvidenceV2Error("application observation is not a pass")


def _regular_backing(root: Path, relative: Any, what: str) -> Path:
    if (not isinstance(relative, str) or not relative or "\\" in relative
            or ":" in relative):
        raise ExternalEvidenceV2Error(f"{what} path is invalid")
    relative_path = PurePosixPath(relative)
    if (relative_path.is_absolute() or relative_path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in relative_path.parts)):
        raise ExternalEvidenceV2Error(f"{what} path is not a normalized relative path")

    raw_root = root.absolute()
    _reject_linklike_ancestors(raw_root, "backing root")
    try:
        resolved_root = raw_root.resolve(strict=True)
    except OSError as exc:
        raise ExternalEvidenceV2Error(f"cannot resolve backing root: {exc}") from exc
    if not resolved_root.is_dir():
        raise ExternalEvidenceV2Error("backing root is not a directory")
    current = resolved_root
    for part in relative_path.parts:
        current = current / part
        if _is_linklike(current):
            raise ExternalEvidenceV2Error(f"{what} cannot traverse a link or junction")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise ExternalEvidenceV2Error(f"{what} escapes or is missing") from exc
    if not resolved.is_file():
        raise ExternalEvidenceV2Error(f"{what} is not a regular file")
    return resolved


def verify_detached_receipt(
    envelope: Any,
    *,
    challenge: dict[str, Any],
    trust_policy: dict[str, Any],
    prepared_unsigned_subject_path: Path,
    signed_subject_path: Path,
    backing_root: Path,
    now: datetime | None = None,
) -> VerifiedReceipt:
    """Verify one provider receipt and every referenced local backing byte."""
    if (not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS
            or envelope.get("schema") != RECEIPT_SCHEMA
            or envelope.get("kind") != RECEIPT_KIND
            or not isinstance(envelope.get("receipt"), dict)):
        raise ExternalEvidenceV2Error("detached receipt envelope is malformed")
    receipt = envelope["receipt"]
    if set(receipt) != RECEIPT_FIELDS or receipt.get("schema") != RECEIPT_SCHEMA:
        raise ExternalEvidenceV2Error("detached receipt is malformed")
    role = receipt.get("role")
    if not isinstance(role, str) or role not in ROLES:
        raise ExternalEvidenceV2Error("receipt role is invalid")
    scope = receipt.get("scope")
    scope_field = RECEIPT_SCOPE_FIELD[role]
    if not isinstance(scope, dict) or set(scope) != RECEIPT_SCOPE_FIELDS[role]:
        raise ExternalEvidenceV2Error("receipt scope is malformed")
    scope_id = _identifier(scope.get(scope_field), "receipt scope")
    key_id = receipt.get("provider_key_id")
    provider = _active_provider(
        trust_policy, key_id, role=role, scope=scope_id)
    signature = _decode_b64(
        envelope.get("signature_base64"), length=64, what="receipt signature")
    try:
        Ed25519PublicKey.from_public_bytes(provider["public_key"]).verify(
            signature, detached_receipt_signature_payload(receipt))
    except (InvalidSignature, ValueError) as exc:
        raise ExternalEvidenceV2Error("detached receipt signature is invalid") from exc

    challenge_state = validate_challenge(
        challenge, trust_policy=trust_policy, now=now)
    if (receipt.get("challenge_id") != challenge["challenge_id"]
            or receipt.get("challenge_nonce_base64") != challenge["nonce_base64"]):
        raise ExternalEvidenceV2Error("receipt is bound to a different challenge")
    if receipt.get("candidate") != challenge["candidate"]:
        raise ExternalEvidenceV2Error("receipt candidate identity does not match challenge")
    if receipt.get("status") != "passed":
        raise ExternalEvidenceV2Error("receipt status is not passed")

    observed = _timestamp(receipt.get("observed_at_utc"), "receipt observation time")
    current = _normalized_now(now)
    if (observed < challenge_state["created_at"]
            or observed > challenge_state["expires_at"]
            or observed > current + MAX_CLOCK_SKEW):
        raise ExternalEvidenceV2Error("receipt observation time is outside the challenge")

    requirement = challenge_state["requirements"][role].get(scope_id)
    if requirement is None or requirement.get("provider_key_id") != key_id:
        raise ExternalEvidenceV2Error("receipt does not satisfy a challenge requirement")

    subject = receipt.get("subject")
    if not isinstance(subject, dict) or set(subject) != RECEIPT_SUBJECT_FIELDS:
        raise ExternalEvidenceV2Error("receipt subject identity is malformed")
    subject_id = _identifier(subject.get("subject_id"), "receipt subject id")
    challenged_subject = challenge_state["subjects"].get(subject_id)
    if (challenged_subject is None
            or subject.get("subject_kind") != challenged_subject["subject_kind"]
            or subject.get("signing_stable_pe_id")
                != challenged_subject["signing_stable_pe_id"]):
        raise ExternalEvidenceV2Error("receipt subject does not match challenge")
    expected_signed_hash = _nonzero_hex(
        subject.get("signed_subject_sha256"), SHA256_RE,
        "receipt signed subject hash")
    if (type(subject.get("signed_subject_size_bytes")) is not int
            or subject["signed_subject_size_bytes"] <= 0):
        raise ExternalEvidenceV2Error("receipt signed subject size is invalid")

    try:
        prepared_snapshot = snapshot_file(
            prepared_unsigned_subject_path,
            what="prepared unsigned subject",
            reject_hardlinks=True,
        )
        signed_snapshot = snapshot_file(
            signed_subject_path,
            what="signed subject",
            reject_hardlinks=True,
        )
        signing_delta = validate_signing_delta_snapshots(
            prepared_snapshot,
            signed_snapshot,
            expected_prepared_sha256=challenged_subject["unsigned_subject_sha256"],
            expected_prepared_size=challenged_subject["unsigned_subject_size_bytes"],
            expected_signing_stable_pe_id=challenged_subject["signing_stable_pe_id"],
            expected_subject_kind=challenged_subject["subject_kind"],
        )
    except ValueError as exc:
        raise ExternalEvidenceV2Error(f"subject signing delta is invalid: {exc}") from exc
    if (signing_delta.signed.sha256 != expected_signed_hash
            or signing_delta.signed.size != subject["signed_subject_size_bytes"]):
        raise ExternalEvidenceV2Error("signed subject bytes do not match receipt")

    _validate_observation(role, receipt.get("observation"), requirement)
    backings = receipt.get("backings")
    if not isinstance(backings, list) or len(backings) != len(REQUIRED_BACKING_IDS[role]):
        raise ExternalEvidenceV2Error("receipt backing set is incomplete")
    backing_index: dict[str, dict[str, Any]] = {}
    verified_backings: list[VerifiedBacking] = []
    seen_paths: set[str] = set()
    seen_filesystem_identities: set[tuple[int, int]] = set()
    for index, backing in enumerate(backings):
        if not isinstance(backing, dict) or set(backing) != BACKING_FIELDS:
            raise ExternalEvidenceV2Error(f"receipt backing[{index}] is malformed")
        backing_id = _identifier(backing.get("id"), f"receipt backing[{index}] id")
        relative = backing.get("path")
        expected_hash = _nonzero_hex(
            backing.get("sha256"), SHA256_RE, f"receipt backing[{index}] hash")
        if type(backing.get("size_bytes")) is not int or backing["size_bytes"] <= 0:
            raise ExternalEvidenceV2Error(f"receipt backing[{index}] size is invalid")
        path = _regular_backing(backing_root, relative, f"receipt backing[{index}]")
        normalized_path = relative.casefold()
        if backing_id in backing_index or normalized_path in seen_paths:
            raise ExternalEvidenceV2Error("receipt backing identity is duplicated")
        try:
            backing_snapshot = snapshot_file(
                path,
                what=f"receipt backing[{index}]",
                reject_hardlinks=True,
            )
        except ValueError as exc:
            raise ExternalEvidenceV2Error(
                f"cannot validate receipt backing[{index}]: {exc}") from exc
        filesystem_identity = backing_snapshot.filesystem_identity
        if (filesystem_identity is not None
                and filesystem_identity in seen_filesystem_identities):
            raise ExternalEvidenceV2Error(
                "receipt backing filesystem identity is duplicated")
        if (backing_snapshot.size != backing["size_bytes"]
                or backing_snapshot.sha256 != expected_hash):
            raise ExternalEvidenceV2Error(f"receipt backing[{index}] bytes do not match")
        backing_index[backing_id] = backing
        verified_backings.append(VerifiedBacking(
            backing_id=backing_id,
            relative_path=relative,
            snapshot=backing_snapshot,
        ))
        seen_paths.add(normalized_path)
        if filesystem_identity is not None:
            seen_filesystem_identities.add(filesystem_identity)
    if set(backing_index) != REQUIRED_BACKING_IDS[role]:
        raise ExternalEvidenceV2Error("receipt backing roles are incomplete")
    if (role == "clean-vm"
            and backing_index["runner"]["sha256"] != requirement["runner_sha256"]):
        raise ExternalEvidenceV2Error("clean-VM runner does not match challenge")
    if (role == "application"
            and backing_index["workflow-definition"]["sha256"]
                != requirement["definition_sha256"]):
        raise ExternalEvidenceV2Error(
            "application workflow definition does not match challenge")
    canonical_receipt = canonical_json_bytes(receipt)
    return VerifiedReceipt(
        role=role,
        provider_key_id=key_id,
        challenge_id=challenge["challenge_id"],
        subject_id=subject_id,
        scope_id=scope_id,
        canonical_receipt=canonical_receipt,
        receipt_sha256=hashlib.sha256(canonical_receipt).hexdigest(),
        prepared_subject=prepared_snapshot,
        signed_subject=signed_snapshot,
        backings=tuple(verified_backings),
    )


__all__ = [
    "APPLICATION_OBSERVATION_FIELDS",
    "CHALLENGE_KIND",
    "CHALLENGE_SCHEMA",
    "ExternalEvidenceV2Error",
    "RECEIPT_KIND",
    "RECEIPT_SCHEMA",
    "SCANNER_OBSERVATION_FIELDS",
    "SUBJECT_FORMAT",
    "VerifiedBacking",
    "VerifiedReceipt",
    "VM_OBSERVATION_FIELDS",
    "canonical_json_bytes",
    "compute_challenge_id",
    "detached_receipt_signature_payload",
    "load_evidence_trust_store_v2",
    "public_key_id",
    "sha256_file",
    "validate_challenge",
    "validate_evidence_trust_store_v2",
    "verify_detached_receipt",
]
