"""Detached, signed production-release attestations for native stubs."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import scanner_evidence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TRUST_STORE = Path(__file__).with_name("release_trust.json")
DEFAULT_EVIDENCE_TRUST_STORE = Path(__file__).with_name("evidence_trust.json")
DEFAULT_MATRIX = ROOT / "docs" / "production_compatibility.json"
ATTESTATION_KIND = "lethe-production-release"
EVIDENCE_ATTESTATION_KIND = "lethe-external-evidence"
RELEASE_PAYLOAD_SCHEMA = 2
SCANNER_DOCUMENT_SCHEMA = 2
KEY_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
EVIDENCE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
REQUIRED_EVIDENCE_KINDS = frozenset({
    "authenticode",
    "scanner",
    "clean-vm",
    "application",
    "production-native",
    "production-gate",
    "external-manifest",
    "release-matrix",
    "release-rebuild",
})
EXTERNAL_EVIDENCE_KINDS = frozenset({
    "authenticode", "scanner", "clean-vm", "application", "production-native",
})
PROVIDER_SIGNED_KINDS = frozenset({"scanner", "clean-vm", "application"})
SUBJECT_KINDS = frozenset({"exe", "dll"})
SUBJECT_FORMAT = "windows-x64-pe32+"
PROMOTION_RUNTIME_PROVISIONAL_STATUS = "candidate-runtime-provisional"
PROMOTION_RUNTIME_PROVISIONAL_SCOPE = "promotion-runtime"
PROMOTION_RUNTIME_PROVISIONAL_FIELD = "promotion_runtime_provisional"
PROMOTION_RUNTIME_CAPABILITY_FILENAME = ".lethe-promotion-runtime-capability.json"
PROMOTION_RUNTIME_CAPABILITY_KIND = "lethe-promotion-runtime-capability"
SUBJECT_BASE_FIELDS = frozenset({
    "subject_id", "subject_kind", "format", "subject_path", "subject_sha256",
    "subject_size_bytes", "input_sha256", "pack_report_path", "pack_report_sha256",
    "protection_profile_path", "protection_profile_sha256",
    "protected_with_stub_sha256", "source_commit", "candidate_manifest_sha256",
})
REQUIRED_RELEASE_REPLAY_IDS = frozenset({
    "ctest-inventory", "ctest", "candidate-bound-native-runtime-hardening",
    "roundtrip-fixture-build", "exe-dll-roundtrip", "production-corpus-build",
    "production-corpus",
})
AUTHENTICODE_RECEIPT_FIELDS = frozenset({
    "tool_name", "tool_version", "verified_at_utc", "status",
    "signer_thumbprint", "signer_subject", "signer_not_after_utc",
    "timestamp_thumbprint", "timestamp_subject", "timestamp_not_after_utc",
})
SCANNER_FIELDS = frozenset({
    "scanner_id", "tool_name", "tool_version", "engine_version", "definitions_version",
})
SCAN_RESULT_FIELDS = frozenset({
    "scanner_id", "status", "detections", "scan_time_utc", "output_sha256",
    "output_path", "receipt_path", "receipt_sha256",
})
VM_CELL_FIELDS = frozenset({
    "cell_id", "status", "os_release", "os_build", "patch_level", "arch",
    "secure_boot", "vbs_enabled", "hvci_enabled", "hyper_v_enabled", "image_id",
    "snapshot_id", "runner_sha256", "result_log_path", "result_log_sha256",
})
APPLICATION_WORKFLOW_FIELDS = frozenset({
    "workflow_id", "status", "result_path", "result_sha256", "log_path",
    "log_sha256",
})
REQUIRED_VM_CELLS = {
    "win10-22h2-vbs-off": ("windows-10-22h2", False, False, False),
    "win11-supported-vbs-off": ("windows-11-supported", False, False, False),
    "win11-supported-vbs-hvci-on": ("windows-11-supported", True, True, False),
    "win11-supported-hyper-v-on": ("windows-11-supported", False, False, True),
}


class ReleaseAttestationError(ValueError):
    """A production-release signature or binding is invalid."""


def _utc_now() -> datetime:
    """Injectable clock; evidence freshness is replayed at signed issuance."""
    return datetime.now(timezone.utc)


def _issuance_timestamp() -> str:
    return _utc_now().astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z")


def _validate_release_issuance(value: Any) -> None:
    try:
        issued = scanner_evidence.parse_utc(value, "release issuance")
    except scanner_evidence.ScannerEvidenceError as exc:
        raise ReleaseAttestationError(str(exc)) from exc
    if issued > _utc_now() + timedelta(minutes=5):
        raise ReleaseAttestationError("release issuance is materially in the future")


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def public_key_id(raw_public_key: bytes) -> str:
    if len(raw_public_key) != 32:
        raise ReleaseAttestationError("Ed25519 public keys must contain 32 bytes")
    return hashlib.sha256(raw_public_key).hexdigest()


def _decode_b64(value: Any, *, length: int, what: str) -> bytes:
    if not isinstance(value, str):
        raise ReleaseAttestationError(f"{what} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ReleaseAttestationError(f"{what} is not valid base64") from exc
    if len(decoded) != length:
        raise ReleaseAttestationError(f"{what} has the wrong length")
    return decoded


def _load_trust_store_details(
    path: Path | None = None,
) -> tuple[dict[str, bytes], frozenset[str]]:
    raw_trust_path = (path or DEFAULT_TRUST_STORE).absolute()
    if _is_linklike(raw_trust_path) or _is_linklike(raw_trust_path.parent):
        raise ReleaseAttestationError("release trust store cannot be a link or junction")
    trust_path = raw_trust_path.resolve()
    try:
        payload = json.loads(trust_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseAttestationError(f"cannot read release trust store: {exc}") from exc
    if (not isinstance(payload, dict) or set(payload) != {"schema", "algorithm", "keys"}
            or payload.get("schema") != 1
            or payload.get("algorithm") != "ed25519"
            or not isinstance(payload.get("keys"), list)):
        raise ReleaseAttestationError("release trust store is malformed")
    trusted: dict[str, bytes] = {}
    seen: set[str] = set()
    for index, entry in enumerate(payload["keys"]):
        if (not isinstance(entry, dict)
                or set(entry) != {"id", "public_key_base64", "revoked"}):
            raise ReleaseAttestationError(f"release trust key[{index}] is malformed")
        key_id = entry.get("id")
        if not isinstance(key_id, str) or KEY_ID_RE.fullmatch(key_id) is None:
            raise ReleaseAttestationError(f"release trust key[{index}] has an invalid id")
        if key_id in seen:
            raise ReleaseAttestationError(f"duplicate release trust key: {key_id}")
        seen.add(key_id)
        raw = _decode_b64(
            entry.get("public_key_base64"), length=32,
            what=f"release trust key[{index}] public key",
        )
        if public_key_id(raw) != key_id:
            raise ReleaseAttestationError(
                f"release trust key[{index}] id does not match its public key")
        if type(entry.get("revoked")) is not bool:
            raise ReleaseAttestationError(
                f"release trust key[{index}] has no boolean revoked state")
        if not entry["revoked"]:
            trusted[key_id] = raw
    return trusted, frozenset(seen)


def load_trust_store(path: Path | None = None) -> dict[str, bytes]:
    return _load_trust_store_details(path)[0]


def load_evidence_trust_store(path: Path | None = None) -> dict[str, Any]:
    raw_path = (path or DEFAULT_EVIDENCE_TRUST_STORE).absolute()
    if _is_linklike(raw_path) or _is_linklike(raw_path.parent):
        raise ReleaseAttestationError(
            "external-evidence trust store cannot be a link or junction")
    trust_path = raw_path.resolve()
    payload = _read_json_object(trust_path, "external-evidence trust store")
    if (set(payload) != {"schema", "algorithm", "providers", "authenticode"}
            or payload.get("schema") != 1 or payload.get("algorithm") != "ed25519"
            or not isinstance(payload.get("providers"), list)
            or not isinstance(payload.get("authenticode"), dict)):
        raise ReleaseAttestationError("external-evidence trust store is malformed")
    authenticode = payload["authenticode"]
    if (set(authenticode) != {
            "allowed_signer_thumbprints", "allowed_tsa_thumbprints"}
            or not isinstance(authenticode["allowed_signer_thumbprints"], list)
            or not isinstance(authenticode["allowed_tsa_thumbprints"], list)):
        raise ReleaseAttestationError("external-evidence Authenticode policy is malformed")

    def thumbprints(values: list[Any], what: str) -> frozenset[str]:
        result: set[str] = set()
        for index, value in enumerate(values):
            if (not isinstance(value, str)
                    or re.fullmatch(r"[0-9a-f]{40,128}", value) is None
                    or value in result or set(value) == {"0"}):
                raise ReleaseAttestationError(
                    f"external-evidence {what}[{index}] is invalid")
            result.add(value)
        return frozenset(result)

    providers: dict[str, dict[str, Any]] = {}
    seen_provider_ids: set[str] = set()
    for index, entry in enumerate(payload["providers"]):
        if (not isinstance(entry, dict)
                or set(entry) != {
                    "id", "public_key_base64", "revoked", "allowed_kinds"}
                or type(entry.get("revoked")) is not bool
                or not isinstance(entry.get("allowed_kinds"), list)):
            raise ReleaseAttestationError(
                f"external-evidence provider[{index}] is malformed")
        key_id = entry.get("id")
        allowed = entry["allowed_kinds"]
        if (not isinstance(key_id, str) or KEY_ID_RE.fullmatch(key_id) is None
                or key_id in seen_provider_ids or not allowed
                or len(allowed) != len(set(allowed))
                or not set(allowed) <= PROVIDER_SIGNED_KINDS):
            raise ReleaseAttestationError(
                f"external-evidence provider[{index}] identity is invalid")
        raw = _decode_b64(
            entry.get("public_key_base64"), length=32,
            what=f"external-evidence provider[{index}] public key")
        if public_key_id(raw) != key_id:
            raise ReleaseAttestationError(
                f"external-evidence provider[{index}] id does not match its key")
        seen_provider_ids.add(key_id)
        if not entry["revoked"]:
            providers[key_id] = {
                "public_key": raw,
                "allowed_kinds": frozenset(allowed),
            }
    allowed_signers = thumbprints(
        authenticode["allowed_signer_thumbprints"], "signer thumbprint")
    allowed_tsas = thumbprints(
        authenticode["allowed_tsa_thumbprints"], "TSA thumbprint")
    if not allowed_signers or not allowed_tsas:
        raise ReleaseAttestationError(
            "external-evidence trust must pin Authenticode signer and TSA thumbprints")
    return {
        "providers": providers,
        "provider_key_ids": frozenset(seen_provider_ids),
        "allowed_signer_thumbprints": allowed_signers,
        "allowed_tsa_thumbprints": allowed_tsas,
    }


def candidate_manifest_path(stub_path: Path) -> Path:
    return stub_path.with_suffix(".manifest.json")


def release_attestation_path(stub_path: Path) -> Path:
    return stub_path.with_suffix(".release.json")


def _read_json_object(path: Path, what: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseAttestationError(f"cannot read {what}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseAttestationError(f"{what} root must be an object")
    return value


def _is_linklike(path: Path) -> bool:
    """Reject symlinks and Windows junctions before resolving a trust path."""
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())
    except OSError:
        return True


def _reject_link_chain(path: Path, root: Path) -> None:
    path = path.absolute()
    root = root.absolute()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ReleaseAttestationError("trusted path escapes its bundle") from exc
    current = root
    if _is_linklike(current):
        raise ReleaseAttestationError("trusted bundle cannot be a symlink or junction")
    for part in relative.parts:
        current /= part
        if _is_linklike(current):
            raise ReleaseAttestationError(
                "trusted bundle cannot contain symlinks or junctions")


_PROMOTION_RUNTIME_REQUIRED_EVIDENCE = frozenset({
    "evidence/candidate-policy.json",
    "evidence/candidate-production-matrix.json",
    "evidence/candidate-promoter.py",
    "evidence/daedalus_opcodes_shuffled.py",
    "evidence/daedalus_opcodes_shuffled.h",
    "evidence/uv-sync.json",
    "evidence/cmake-configure.json",
    "evidence/cmake-build.json",
    "evidence/stub-entrypoints.json",
    "evidence/ctest-inventory.json",
    "evidence/ctest.json",
})


def _candidate_toolchain_binding(manifest: dict[str, Any]) -> dict[str, Any]:
    """The source-bound fields shared by final and runtime-provisional bundles."""
    return {
        "configuration": manifest.get("configuration"),
        "cmake_generator": manifest.get("cmake_generator"),
        "cmake_platform": manifest.get("cmake_platform"),
        "compiler_id": manifest.get("compiler_id"),
        "compiler_version": manifest.get("compiler_version"),
        "warning_policy": manifest.get("warning_policy"),
        "reproducible_link": manifest.get("reproducible_link"),
        "python_version": manifest.get("python_version"),
        "uv_version": manifest.get("uv_version"),
        "cmake_version": manifest.get("cmake_version"),
        "ctest_version": manifest.get("ctest_version"),
        "dependency_locks": manifest.get("dependency_locks"),
    }


def _provisional_evidence_records(
    stub_path: Path, manifest: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Verify the pre-runtime evidence a promotion is allowed to consume.

    This intentionally names a smaller set than a final candidate: runtime,
    round-trip, corpus, and gate receipts do not exist until after the runtime
    pack tests.  The distinct provisional state is never a release candidate.
    """
    evidence = manifest.get("evidence")
    if not isinstance(evidence, list):
        raise ReleaseAttestationError(
            "promotion-runtime provisional has no evidence records")
    records: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(evidence):
        if (not isinstance(record, dict)
                or set(record) != {"path", "sha256"}
                or not isinstance(record.get("path"), str)
                or SHA256_RE.fullmatch(str(record.get("sha256", ""))) is None):
            raise ReleaseAttestationError(
                f"promotion-runtime provisional evidence[{index}] is malformed")
        relative = record["path"]
        if relative in records:
            raise ReleaseAttestationError(
                "promotion-runtime provisional repeats an evidence path")
        path = _contained_evidence_path(stub_path.parent, relative)
        if sha256_file(path) != record["sha256"]:
            raise ReleaseAttestationError(
                f"promotion-runtime provisional evidence hash mismatch: {relative}")
        records[relative] = record
    if set(records) != _PROMOTION_RUNTIME_REQUIRED_EVIDENCE:
        raise ReleaseAttestationError(
            "promotion-runtime provisional evidence inventory is incomplete")

    policy_path = stub_path.parent / "evidence/candidate-policy.json"
    matrix_path = stub_path.parent / "evidence/candidate-production-matrix.json"
    promoter_path = stub_path.parent / "evidence/candidate-promoter.py"
    policy_document = _read_json_object(policy_path, "candidate policy snapshot")
    if (hashlib.sha256(canonical_json_bytes(policy_document)).hexdigest()
            != manifest.get("candidate_policy_sha256")
            or policy_document.get("policy_id") != manifest.get("candidate_policy_id")):
        raise ReleaseAttestationError(
            "promotion-runtime provisional policy snapshot binding is invalid")
    if sha256_file(matrix_path) != manifest.get("production_matrix_sha256"):
        raise ReleaseAttestationError(
            "promotion-runtime provisional matrix snapshot binding is invalid")
    if sha256_file(promoter_path) != manifest.get("promotion_tool_sha256"):
        raise ReleaseAttestationError(
            "promotion-runtime provisional promoter snapshot binding is invalid")
    if (sha256_file(stub_path.parent / "evidence/daedalus_opcodes_shuffled.py")
            != manifest.get("dvm_python_map_sha256")
            or sha256_file(stub_path.parent / "evidence/daedalus_opcodes_shuffled.h")
            != manifest.get("dvm_native_map_sha256")):
        raise ReleaseAttestationError(
            "promotion-runtime provisional DVM map binding is invalid")

    expected_commit = manifest["source_commit"]
    expected_hash = manifest["sha256"]
    for filename, name, artifact_bound in (
        ("uv-sync.json", "locked-dependency-sync", False),
        ("cmake-configure.json", "fresh-cmake-configure", False),
        ("cmake-build.json", "fresh-w4-wx-stub-build", False),
        ("ctest-inventory.json", "ctest-inventory", True),
        ("ctest.json", "ctest", True),
    ):
        document = _read_json_object(
            stub_path.parent / "evidence" / filename,
            f"promotion-runtime {filename}",
        )
        if (document.get("schema") != 1 or document.get("name") != name
                or document.get("source_commit") != expected_commit
                or document.get("exit_code") != 0
                or document.get("artifact_sha256") != (
                    expected_hash if artifact_bound else None)):
            raise ReleaseAttestationError(
                f"promotion-runtime provisional {filename} is not source/artifact bound")
    try:
        inventory = json.loads(
            _read_json_object(
                stub_path.parent / "evidence/ctest-inventory.json",
                "promotion-runtime CTest inventory",
            ).get("stdout", ""))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ReleaseAttestationError(
            "promotion-runtime provisional CTest inventory is invalid") from exc
    tests = inventory.get("tests") if isinstance(inventory, dict) else None
    if (not isinstance(tests, list) or not tests
            or not all(isinstance(item, dict) and isinstance(item.get("name"), str)
                       and item["name"] for item in tests)):
        raise ReleaseAttestationError(
            "promotion-runtime provisional CTest inventory is empty or malformed")
    result = _read_json_object(
        stub_path.parent / "evidence/ctest.json", "promotion-runtime CTest result")
    summary = re.search(
        r"(?m)^100% tests passed out of (\d+)\s*$", str(result.get("stdout", "")))
    if summary is None or int(summary.group(1)) != len(tests):
        raise ReleaseAttestationError(
            "promotion-runtime provisional CTest result disagrees with its inventory")
    return records


def validate_promotion_runtime_provisional_candidate(
    stub_path: Path,
    capability_path: Path,
    capability_nonce: str,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Validate the single promotion-only identity accepted during runtime tests.

    A final candidate cannot exist before its own runtime receipt.  This narrow
    verifier accepts only the build-local, hash-bound provisional state paired
    with a high-entropy one-run capability.  It deliberately does *not* make
    the provisional bundle acceptable to regular candidate/release callers.
    """
    raw_stub = stub_path.absolute()
    raw_manifest = (manifest_path or candidate_manifest_path(raw_stub)).absolute()
    raw_capability = capability_path.absolute()
    if (raw_stub.parent.name != "runtime-provisional"
            or raw_capability.name != PROMOTION_RUNTIME_CAPABILITY_FILENAME
            or raw_capability.parent != raw_stub.parent
            or _is_linklike(raw_stub) or _is_linklike(raw_manifest)
            or _is_linklike(raw_capability) or _is_linklike(raw_stub.parent)):
        raise ReleaseAttestationError(
            "promotion-runtime capability is not a private build-local bundle")
    stub = raw_stub.resolve()
    manifest_file = raw_manifest.resolve()
    capability_file = raw_capability.resolve()
    if (stub.parent != manifest_file.parent or stub.parent != capability_file.parent
            or not stub.is_file() or not manifest_file.is_file()
            or not capability_file.is_file()):
        raise ReleaseAttestationError(
            "promotion-runtime provisional bundle is incomplete")
    manifest = _read_json_object(manifest_file, "promotion-runtime provisional manifest")
    expected = {
        "schema": 2,
        "artifact_status": PROMOTION_RUNTIME_PROVISIONAL_STATUS,
        "production_ready": False,
        "candidate_scope": PROMOTION_RUNTIME_PROVISIONAL_SCOPE,
        "artifact": stub.name,
        "size_bytes": stub.stat().st_size,
        "sha256": sha256_file(stub),
        "source_dirty": False,
        "provenance_status": "clean",
    }
    for field, wanted in expected.items():
        if manifest.get(field) != wanted:
            raise ReleaseAttestationError(
                f"promotion-runtime provisional {field!r} does not match its bundle")
    if "production_scope" in manifest:
        raise ReleaseAttestationError(
            "promotion-runtime provisional claims production scope")
    if COMMIT_RE.fullmatch(str(manifest.get("source_commit", ""))) is None:
        raise ReleaseAttestationError(
            "promotion-runtime provisional has no full source commit")
    if (not isinstance(manifest.get(PROMOTION_RUNTIME_PROVISIONAL_FIELD), dict)
            or set(manifest[PROMOTION_RUNTIME_PROVISIONAL_FIELD]) != {
                "schema", "capability_nonce_sha256"}
            or manifest[PROMOTION_RUNTIME_PROVISIONAL_FIELD].get("schema") != 1
            or SHA256_RE.fullmatch(str(
                manifest[PROMOTION_RUNTIME_PROVISIONAL_FIELD].get(
                    "capability_nonce_sha256", ""))) is None):
        raise ReleaseAttestationError(
            "promotion-runtime provisional marker is invalid")
    for field in (
        "candidate_policy_sha256", "promotion_tool_sha256",
        "production_matrix_sha256", "toolchain_binding_sha256",
        "dvm_opcode_mapping_sha256", "dvm_handler_variant_sha256",
        "dvm_python_map_sha256", "dvm_native_map_sha256",
    ):
        if SHA256_RE.fullmatch(str(manifest.get(field, ""))) is None:
            raise ReleaseAttestationError(
                f"promotion-runtime provisional has no valid {field}")
    seed = manifest.get("dvm_shuffle_seed")
    if not isinstance(seed, str) or re.fullmatch(r"[0-9a-f]{64}", seed) is None:
        raise ReleaseAttestationError(
            "promotion-runtime provisional DVM seed is invalid")
    if (manifest.get("dvm_rolling") is not True
            or manifest.get("dvm_roll_poison") is not False
            or manifest.get("dvm_paged_runtime") is not True):
        raise ReleaseAttestationError(
            "promotion-runtime provisional DVM policy is invalid")
    if manifest.get("toolchain_binding_sha256") != hashlib.sha256(
            canonical_json_bytes(_candidate_toolchain_binding(manifest))).hexdigest():
        raise ReleaseAttestationError(
            "promotion-runtime provisional toolchain binding is invalid")
    locks = manifest.get("dependency_locks")
    if (not isinstance(locks, dict) or set(locks) != {"pyproject.toml", "uv.lock"}
            or any(SHA256_RE.fullmatch(str(value)) is None for value in locks.values())):
        raise ReleaseAttestationError(
            "promotion-runtime provisional dependency locks are incomplete")
    if (manifest.get("configuration") != "Release"
            or manifest.get("cmake_generator") != "Visual Studio 17 2022"
            or str(manifest.get("cmake_platform", "")).lower() != "x64"
            or manifest.get("compiler_id") != "MSVC"
            or not str(manifest.get("compiler_version", "")).startswith("19.")
            or manifest.get("warning_policy") != "/W4 /WX /Brepro"
            or manifest.get("reproducible_link") != "/Brepro /INCREMENTAL:NO"
            or manifest.get("uv_version") != "0.11.29"
            or not str(manifest.get("python_version", "")).startswith("3.12.")):
        raise ReleaseAttestationError(
            "promotion-runtime provisional toolchain is outside the pinned policy")
    _provisional_evidence_records(stub, manifest)

    capability = _read_json_object(capability_file, "promotion-runtime capability")
    expected_capability_fields = {
        "schema", "kind", "nonce_sha256", "source_commit", "source_root",
        "bundle_root", "manifest_sha256", "artifact", "artifact_sha256",
        "artifact_size_bytes",
    }
    if set(capability) != expected_capability_fields:
        raise ReleaseAttestationError("promotion-runtime capability fields are invalid")
    nonce_hash = capability.get("nonce_sha256")
    if (capability.get("schema") != 1
            or capability.get("kind") != PROMOTION_RUNTIME_CAPABILITY_KIND
            or not isinstance(capability_nonce, str)
            or SHA256_RE.fullmatch(capability_nonce) is None
            or SHA256_RE.fullmatch(str(nonce_hash)) is None
            or capability.get("source_commit") != manifest["source_commit"]
            or capability.get("source_root") != str(ROOT.resolve())
            or capability.get("bundle_root") != str(stub.parent)
            or capability.get("manifest_sha256") != sha256_file(manifest_file)
            or capability.get("artifact") != stub.name
            or capability.get("artifact_sha256") != manifest["sha256"]
            or capability.get("artifact_size_bytes") != manifest["size_bytes"]
            or hashlib.sha256(capability_nonce.encode("ascii")).hexdigest() != nonce_hash
            or nonce_hash != (
                manifest[PROMOTION_RUNTIME_PROVISIONAL_FIELD][
                    "capability_nonce_sha256"])):
        raise ReleaseAttestationError(
            "promotion-runtime capability does not bind this provisional bundle")
    _require_exact_clean_source(manifest["source_commit"])
    return manifest


def validate_candidate_identity(
    stub_path: Path,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    raw_stub = stub_path.absolute()
    raw_manifest = (manifest_path or candidate_manifest_path(raw_stub)).absolute()
    if (_is_linklike(raw_stub) or _is_linklike(raw_manifest)
            or _is_linklike(raw_stub.parent)):
        raise ReleaseAttestationError("candidate bundle cannot contain links or junctions")
    stub_path = raw_stub.resolve()
    manifest_path = raw_manifest.resolve()
    if stub_path.parent != manifest_path.parent:
        raise ReleaseAttestationError("candidate DLL and manifest are not one bundle")
    if not stub_path.is_file() or not manifest_path.is_file():
        raise ReleaseAttestationError("candidate DLL or manifest is missing")
    manifest = _read_json_object(manifest_path, "candidate manifest")
    if (PROMOTION_RUNTIME_PROVISIONAL_FIELD in manifest
            or manifest.get("artifact_status") == PROMOTION_RUNTIME_PROVISIONAL_STATUS
            or manifest.get("candidate_scope") == PROMOTION_RUNTIME_PROVISIONAL_SCOPE):
        raise ReleaseAttestationError(
            "promotion-runtime provisional manifests are not candidate bundles")
    blob_hash = sha256_file(stub_path)
    checks = {
        "schema": 2,
        "artifact_status": "candidate-verified",
        "production_ready": False,
        "candidate_scope": "all",
        "artifact": stub_path.name,
        "size_bytes": stub_path.stat().st_size,
        "sha256": blob_hash,
        "source_dirty": False,
        "provenance_status": "clean",
    }
    for field, wanted in checks.items():
        if manifest.get(field) != wanted:
            raise ReleaseAttestationError(
                f"candidate manifest {field!r} does not match the verified bundle")
    if "production_scope" in manifest:
        raise ReleaseAttestationError("candidate manifest already claims production scope")
    if COMMIT_RE.fullmatch(str(manifest.get("source_commit", ""))) is None:
        raise ReleaseAttestationError("candidate manifest has no full source commit")
    for field in (
        "candidate_policy_sha256",
        "promotion_tool_sha256",
        "production_matrix_sha256",
        "toolchain_binding_sha256",
        "dvm_opcode_mapping_sha256",
        "dvm_handler_variant_sha256",
    ):
        if SHA256_RE.fullmatch(str(manifest.get(field, ""))) is None:
            raise ReleaseAttestationError(f"candidate manifest has no valid {field}")
    seed = manifest.get("dvm_shuffle_seed")
    if not isinstance(seed, str) or re.fullmatch(r"[0-9a-f]{64}", seed) is None:
        raise ReleaseAttestationError(
            "candidate manifest DVM shuffle seed must encode exactly 32 bytes")
    if manifest.get("dvm_rolling") is not True:
        raise ReleaseAttestationError("candidate manifest lacks rolling DVM support")
    if manifest.get("dvm_roll_poison") is not False:
        raise ReleaseAttestationError(
            "candidate manifest does not disable DVM rolling poison")
    if manifest.get("dvm_paged_runtime") is not True:
        raise ReleaseAttestationError("candidate manifest lacks authenticated DVM paging")
    evidence = manifest.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ReleaseAttestationError("candidate manifest has no evidence records")
    seen: set[str] = set()
    for index, record in enumerate(evidence):
        if (not isinstance(record, dict)
                or set(record) != {"path", "sha256"}
                or not isinstance(record.get("path"), str)
                or SHA256_RE.fullmatch(str(record.get("sha256", ""))) is None):
            raise ReleaseAttestationError(f"candidate evidence[{index}] is malformed")
        relative = record["path"]
        if relative in seen:
            raise ReleaseAttestationError("candidate manifest repeats an evidence path")
        seen.add(relative)
        evidence_path = _contained_evidence_path(stub_path.parent, relative)
        if sha256_file(evidence_path) != record["sha256"]:
            raise ReleaseAttestationError(f"candidate evidence hash mismatch: {relative}")
    policy_snapshot = "evidence/candidate-policy.json"
    matrix_snapshot = "evidence/candidate-production-matrix.json"
    promoter_snapshot = "evidence/candidate-promoter.py"
    if not {policy_snapshot, matrix_snapshot, promoter_snapshot}.issubset(seen):
        raise ReleaseAttestationError("candidate omits policy/matrix/promoter snapshots")
    policy_document = _read_json_object(
        stub_path.parent / policy_snapshot, "candidate policy snapshot")
    if (hashlib.sha256(canonical_json_bytes(policy_document)).hexdigest()
            != manifest["candidate_policy_sha256"]
            or policy_document.get("policy_id") != manifest.get("candidate_policy_id")):
        raise ReleaseAttestationError("candidate policy snapshot binding is invalid")
    if sha256_file(stub_path.parent / matrix_snapshot) != manifest["production_matrix_sha256"]:
        raise ReleaseAttestationError("candidate matrix snapshot binding is invalid")
    if sha256_file(stub_path.parent / promoter_snapshot) != manifest["promotion_tool_sha256"]:
        raise ReleaseAttestationError("candidate promoter snapshot binding is invalid")
    return manifest


def _require_exact_clean_source(
    expected: Any, *, source_root: Path | None = None,
) -> Path:
    """Return the exact clean checkout named by a source-bound manifest."""
    if not isinstance(expected, str) or COMMIT_RE.fullmatch(expected) is None:
        raise ReleaseAttestationError(
            "candidate manifest has no full source commit")
    root = (source_root or ROOT).resolve()
    if not (root / ".git").exists():
        raise ReleaseAttestationError(
            "current candidate source requires an exact Git checkout")

    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith("GIT_")}

    def git(*arguments: str) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(root), *arguments],
                capture_output=True, text=True, encoding="utf-8",
                timeout=10, check=False, env=environment,
            )
        except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
            raise ReleaseAttestationError(
                "current candidate source Git verification failed") from exc
        if result.returncode != 0:
            raise ReleaseAttestationError(
                "current candidate source Git verification failed")
        return result.stdout.strip()

    if Path(git("rev-parse", "--show-toplevel")).resolve() != root:
        raise ReleaseAttestationError(
            "current candidate source is not the exact Git checkout root")
    head = git("rev-parse", "--verify", "HEAD^{commit}")
    if head != expected:
        raise ReleaseAttestationError(
            "candidate source commit does not match the current checkout")
    if git("status", "--porcelain=v1", "--untracked-files=all"):
        raise ReleaseAttestationError(
            "current candidate source checkout is not clean")
    return root


def validate_current_promotion_runtime_source(
    manifest: dict[str, Any], *, source_root: Path | None = None,
) -> None:
    """Bind a capability-gated provisional runtime to the current checkout."""
    _require_exact_clean_source(
        manifest.get("source_commit"), source_root=source_root)


def validate_current_candidate_source(
    manifest: dict[str, Any], *, candidate_root: Path,
    source_root: Path | None = None,
) -> None:
    """Bind experimental packing to the clean source that built its runtime.

    A candidate manifest can remain valid for historical release verification;
    only *new* experimental virtualization needs the current compiler/runtime
    pair.  An extracted source distribution has no authenticated source-commit
    identity, so its candidate path fails closed.  Signed default releases use
    the separate release-bundle verifier and do not enter this check.
    """
    expected = manifest.get("source_commit")
    _require_exact_clean_source(expected, source_root=source_root)

    # The schema-2 identity checker preserves historical candidate replay and
    # therefore does not interpret evidence content.  For a *new* pack, the
    # manifest cannot merely retag an older stub with today's Git commit:
    # these three hash-pinned producer records must agree with both the source
    # and the exact candidate artifact.  Rehash here to close the gap between
    # the earlier bundle validation and these file reads.
    records = manifest.get("evidence")
    if not isinstance(records, list):
        raise ReleaseAttestationError(
            "current candidate has no source-bound evidence inventory")
    by_path = {record.get("path"): record for record in records
               if isinstance(record, dict) and isinstance(record.get("path"), str)}
    artifact_hash = manifest.get("sha256")
    for filename, label in (
        ("production-evidence.json", "production evidence"),
        ("runtime-hardening.json", "native runtime evidence"),
        ("roundtrip.json", "round-trip evidence"),
    ):
        relative = f"evidence/{filename}"
        record = by_path.get(relative)
        if (not isinstance(record, dict)
                or SHA256_RE.fullmatch(str(record.get("sha256", ""))) is None):
            raise ReleaseAttestationError(
                f"current candidate lacks hash-pinned {label}")
        path = _contained_evidence_path(candidate_root, relative)
        try:
            raw = path.read_bytes()
            evidence = json.loads(raw.decode("utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReleaseAttestationError(
                f"current candidate {label} is unreadable") from exc
        if hashlib.sha256(raw).hexdigest() != record["sha256"]:
            raise ReleaseAttestationError(
                f"current candidate {label} hash changed")
        if (not isinstance(evidence, dict)
                or evidence.get("source_commit") != expected
                or evidence.get("schema") != 1):
            raise ReleaseAttestationError(
                f"current candidate {label} source commit mismatches")
        if filename == "production-evidence.json":
            if (evidence.get("stub_sha256") != artifact_hash
                    or evidence.get("tracked_source_dirty") is not False
                    or evidence.get("ready") is not True):
                raise ReleaseAttestationError(
                    "current candidate production evidence is not artifact-bound green")
        elif (evidence.get("artifact_sha256") != artifact_hash
              or evidence.get("exit_code") != 0):
            raise ReleaseAttestationError(
                f"current candidate {label} is not artifact-bound green")


def _contained_evidence_path(bundle_root: Path, relative: Any) -> Path:
    if (not isinstance(relative, str) or not relative or "\\" in relative
            or ":" in relative or "\x00" in relative):
        raise ReleaseAttestationError("release evidence path is malformed")
    candidate = Path(relative)
    if candidate.is_absolute() or any(part in ("", ".", "..") for part in candidate.parts):
        raise ReleaseAttestationError("release evidence path is not canonical relative text")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    for part in candidate.parts:
        if part.endswith((".", " ")) or part.split(".", 1)[0].upper() in reserved:
            raise ReleaseAttestationError("release evidence path is Windows-reserved")
    raw_root = bundle_root.absolute()
    raw_candidate = raw_root / candidate
    _reject_link_chain(raw_candidate, raw_root)
    resolved_root = raw_root.resolve()
    resolved = raw_candidate.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ReleaseAttestationError("release evidence path escapes its bundle") from exc
    if not resolved.is_file():
        raise ReleaseAttestationError("release evidence is missing")
    return resolved


def _validate_backing_file(
    evidence_root: Path,
    relative: Any,
    expected_sha256: Any,
    what: str,
) -> Path:
    if SHA256_RE.fullmatch(str(expected_sha256 or "")) is None:
        raise ReleaseAttestationError(f"{what} has no valid SHA-256")
    path = _contained_evidence_path(evidence_root, relative)
    if sha256_file(path) != expected_sha256:
        raise ReleaseAttestationError(f"{what} hash mismatch")
    return path


def _document_file_references(
    kind: str,
    document: dict[str, Any],
) -> list[dict[str, str]]:
    references: dict[str, str] = {}

    def add(path: Any, digest: Any, what: str) -> None:
        if (not isinstance(path, str) or not path
                or SHA256_RE.fullmatch(str(digest or "")) is None):
            raise ReleaseAttestationError(f"{what} reference is malformed")
        prior = references.get(path)
        if prior is not None and prior != digest:
            raise ReleaseAttestationError(f"{what} path has conflicting hashes")
        references[path] = digest

    for subject in _subject_entries(document, kind):
        if not isinstance(subject, dict):
            raise ReleaseAttestationError(f"{kind} subject reference is malformed")
        add(subject.get("subject_path"), subject.get("subject_sha256"), "subject")
        add(subject.get("pack_report_path"), subject.get("pack_report_sha256"),
            "pack report")
        add(subject.get("protection_profile_path"),
            subject.get("protection_profile_sha256"), "protection profile")
        if kind == "scanner":
            for scan in subject.get("scans", []):
                if not isinstance(scan, dict):
                    raise ReleaseAttestationError("scanner backing reference is malformed")
                add(scan.get("output_path"), scan.get("output_sha256"), "scanner output")
                add(scan.get("receipt_path"), scan.get("receipt_sha256"),
                    "scanner receipt")
        elif kind == "clean-vm":
            for cell in subject.get("cells", []):
                if not isinstance(cell, dict):
                    raise ReleaseAttestationError("clean-vm backing reference is malformed")
                add(cell.get("result_log_path"), cell.get("result_log_sha256"),
                    "clean-vm result log")
        elif kind == "application":
            for workflow in subject.get("workflows", []):
                if not isinstance(workflow, dict):
                    raise ReleaseAttestationError("application backing reference is malformed")
                add(workflow.get("result_path"), workflow.get("result_sha256"),
                    "application result")
                add(workflow.get("log_path"), workflow.get("log_sha256"),
                    "application log")
    return [
        {"path": path, "sha256": references[path]}
        for path in sorted(references)
    ]


def _declared_sha256_values(value: Any) -> list[str]:
    hashes: set[str] = set()

    def visit(item: Any, key: str | None = None) -> None:
        if isinstance(item, dict):
            for child_key, child in item.items():
                visit(child, child_key)
        elif isinstance(item, list):
            for child in item:
                visit(child, key)
        elif (key is not None and key.endswith("sha256") and isinstance(item, str)
              and SHA256_RE.fullmatch(item) is not None):
            hashes.add(item)

    visit(value)
    return sorted(hashes)


def provider_signature_payload(
    *,
    key_id: str,
    evidence_kind: str,
    document: dict[str, Any],
) -> dict[str, Any]:
    if evidence_kind not in PROVIDER_SIGNED_KINDS:
        raise ReleaseAttestationError("evidence kind does not accept provider signatures")
    return {
        "schema": 1,
        "kind": EVIDENCE_ATTESTATION_KIND,
        "key_id": key_id,
        "evidence_kind": evidence_kind,
        "document_sha256": hashlib.sha256(canonical_json_bytes(document)).hexdigest(),
        "declared_sha256": _declared_sha256_values(document),
        "referenced_files": _document_file_references(evidence_kind, document),
    }


def verify_provider_signature(
    record: dict[str, Any],
    document: dict[str, Any],
    *,
    evidence_root: Path,
    trust_policy: dict[str, Any],
) -> dict[str, Any]:
    kind = record.get("kind")
    if kind not in PROVIDER_SIGNED_KINDS:
        raise ReleaseAttestationError("external evidence kind is not provider-signable")
    signature_path = _validate_backing_file(
        evidence_root, record.get("provider_signature_path"),
        record.get("provider_signature_sha256"), "provider signature")
    envelope = _read_json_object(signature_path, "provider signature")
    if (set(envelope) != {"schema", "payload", "signature_base64"}
            or envelope.get("schema") != 1 or not isinstance(envelope.get("payload"), dict)):
        raise ReleaseAttestationError("provider signature envelope is malformed")
    payload = envelope["payload"]
    key_id = payload.get("key_id")
    provider = trust_policy.get("providers", {}).get(key_id)
    if provider is None:
        raise ReleaseAttestationError("provider signing key is unknown or revoked")
    if kind not in provider["allowed_kinds"]:
        raise ReleaseAttestationError("provider signing key is not authorized for this kind")
    expected_payload = provider_signature_payload(
        key_id=key_id, evidence_kind=kind, document=document)
    if payload != expected_payload:
        raise ReleaseAttestationError("provider signature payload binding is invalid")
    signature = _decode_b64(
        envelope.get("signature_base64"), length=64, what="provider signature")
    try:
        Ed25519PublicKey.from_public_bytes(provider["public_key"]).verify(
            signature, canonical_json_bytes(payload))
    except InvalidSignature as exc:
        raise ReleaseAttestationError("provider evidence signature is invalid") from exc
    for reference in payload["referenced_files"]:
        _validate_backing_file(
            evidence_root, reference["path"], reference["sha256"],
            f"{kind} signed backing file")
    return payload


def _validate_semantic_evidence(
    record: dict[str, Any],
    document: dict[str, Any],
    *,
    artifact_sha256: str,
    source_commit: str,
    candidate_manifest_sha256: str,
    gate: dict[str, Any],
    evidence_path: Path,
    issued_at_utc: str | None = None,
) -> None:
    kind = record["kind"]
    if kind == "external-manifest":
        return
    if kind == "release-matrix":
        if document.get("schema") != 1 or not isinstance(document.get("features"), list):
            raise ReleaseAttestationError("release-matrix evidence is malformed")
        return
    if kind == "production-gate":
        if document != gate:
            raise ReleaseAttestationError("production-gate evidence disagrees with attestation")
        return
    if kind == "release-rebuild":
        expected = {
            "schema": 1,
            "status": "passed",
            "source_commit": source_commit,
            "candidate_manifest_sha256": candidate_manifest_sha256,
            "candidate_stub_sha256": artifact_sha256,
            "rebuilt_stub_sha256": artifact_sha256,
            "byte_identical": True,
        }
        if any(document.get(field) != value for field, value in expected.items()):
            raise ReleaseAttestationError("release rebuild evidence is not artifact-identical")
        if (SHA256_RE.fullmatch(str(document.get("toolchain_binding_sha256", ""))) is None
                or not isinstance(document.get("dvm_shuffle_seed"), str)
                or re.fullmatch(r"[0-9a-f]{64}", document["dvm_shuffle_seed"]) is None):
            raise ReleaseAttestationError("release rebuild provenance is malformed")
        if (document.get("dvm_rolling") is not True
                or document.get("dvm_roll_poison") is not False
                or document.get("dvm_paged_runtime") is not True):
            raise ReleaseAttestationError(
                "release rebuild does not preserve the production DVM policy")
        replay = document.get("replay_commands")
        if not isinstance(replay, list) or len(replay) != len(
                REQUIRED_RELEASE_REPLAY_IDS):
            raise ReleaseAttestationError("release rebuild replay evidence is incomplete")
        seen_replays: set[str] = set()
        replay_fields = {
            "id", "status", "argv", "exit_code", "artifact_sha256",
            "stdout_sha256", "stderr_sha256",
        }
        for index, item in enumerate(replay):
            if not isinstance(item, dict) or set(item) != replay_fields:
                raise ReleaseAttestationError(
                    f"release rebuild replay[{index}] is malformed")
            replay_id = item.get("id")
            argv = item.get("argv")
            if (replay_id not in REQUIRED_RELEASE_REPLAY_IDS
                    or replay_id in seen_replays or item.get("status") != "passed"
                    or item.get("exit_code") != 0
                    or item.get("artifact_sha256") != artifact_sha256
                    or not isinstance(argv, list) or not argv
                    or not all(isinstance(arg, str) and arg and "\\" not in arg
                               for arg in argv)
                    or SHA256_RE.fullmatch(str(item.get("stdout_sha256", ""))) is None
                    or SHA256_RE.fullmatch(str(item.get("stderr_sha256", ""))) is None):
                raise ReleaseAttestationError(
                    f"release rebuild replay[{index}] is not a passing portable record")
            seen_replays.add(replay_id)
        if seen_replays != REQUIRED_RELEASE_REPLAY_IDS:
            raise ReleaseAttestationError("release rebuild replay kinds are incomplete")
        return
    expected_schema = SCANNER_DOCUMENT_SCHEMA if kind == "scanner" else 1
    if type(document.get("schema")) is not int or document["schema"] != expected_schema:
        raise ReleaseAttestationError(f"{kind} evidence has an unsupported schema")
    if document.get("source_commit") != source_commit:
        raise ReleaseAttestationError(f"{kind} evidence names a different source commit")
    if document.get("candidate_manifest_sha256") != candidate_manifest_sha256:
        raise ReleaseAttestationError(f"{kind} evidence names a different candidate manifest")
    if kind == "production-native":
        if document.get("stub_sha256") != artifact_sha256:
            raise ReleaseAttestationError("production-native evidence names a different artifact")
        if document.get("ready") is not True:
            raise ReleaseAttestationError("production-native evidence is not green")
        return
    if document.get("status") != "passed":
        raise ReleaseAttestationError(f"{kind} evidence is not passing")
    if kind == "clean-vm":
        if document.get("artifact_sha256") != artifact_sha256:
            raise ReleaseAttestationError(f"{kind} evidence names a different artifact")
    entries = _subject_entries(document, kind)
    scanner_registry = (
        _validate_scanner_registry(document.get("scanners"))
        if kind == "scanner" else {}
    )
    seen_subject_ids: set[str] = set()
    covered_kinds: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ReleaseAttestationError(f"{kind} subject[{index}] is malformed")
        subject_id = entry.get("subject_id")
        subject_kind = entry.get("subject_kind")
        subject_relative = entry.get("subject_path")
        subject_hash = entry.get("subject_sha256")
        if (not isinstance(subject_id, str) or EVIDENCE_ID_RE.fullmatch(subject_id) is None
                or subject_id in seen_subject_ids or subject_kind not in SUBJECT_KINDS
                or entry.get("format") != SUBJECT_FORMAT
                or SHA256_RE.fullmatch(str(subject_hash or "")) is None
                or type(entry.get("subject_size_bytes")) is not int
                or entry["subject_size_bytes"] < 1
                or any(SHA256_RE.fullmatch(str(entry.get(field, ""))) is None
                       or entry[field] == "0" * 64
                       for field in ("input_sha256", "pack_report_sha256",
                                     "protection_profile_sha256"))
                or entry.get("protected_with_stub_sha256") != artifact_sha256
                or entry.get("source_commit") != source_commit
                or entry.get("candidate_manifest_sha256") != candidate_manifest_sha256
                or not isinstance(subject_relative, str)
                or not subject_relative.startswith("subjects/")):
            raise ReleaseAttestationError(f"{kind} subject[{index}] identity is invalid")
        seen_subject_ids.add(subject_id)
        covered_kinds.add(subject_kind)
        subject_path = _contained_evidence_path(evidence_path.parent, subject_relative)
        if (sha256_file(subject_path) != subject_hash
                or subject_path.stat().st_size != entry["subject_size_bytes"]):
            raise ReleaseAttestationError(f"{kind} subject hash mismatch")
        _validate_subject_pe(
            subject_path, subject_kind, require_authenticode=(kind == "authenticode"))
        _validate_backing_file(
            evidence_path.parent, entry.get("pack_report_path"),
            entry.get("pack_report_sha256"), f"{kind} pack report")
        _validate_backing_file(
            evidence_path.parent, entry.get("protection_profile_path"),
            entry.get("protection_profile_sha256"), f"{kind} protection profile")
        if kind == "authenticode":
            if set(entry) != SUBJECT_BASE_FIELDS | {"verification_receipt"}:
                raise ReleaseAttestationError("Authenticode subject receipt is malformed")
            _validate_authenticode_receipt(entry.get("verification_receipt"))
        elif kind == "scanner":
            if set(entry) != SUBJECT_BASE_FIELDS | {"scans"}:
                raise ReleaseAttestationError("scanner subject receipt is malformed")
            scans = entry.get("scans")
            if not isinstance(scans, list) or len(scans) != len(scanner_registry):
                raise ReleaseAttestationError("scanner subject engine set is incomplete")
            by_scanner: dict[str, dict[str, Any]] = {}
            for scan_index, scan in enumerate(scans):
                if not isinstance(scan, dict) or set(scan) != SCAN_RESULT_FIELDS:
                    raise ReleaseAttestationError(
                        f"scanner subject result[{scan_index}] is malformed")
                scanner_id = scan.get("scanner_id")
                if (scanner_id not in scanner_registry or scanner_id in by_scanner
                        or scan.get("status") != "passed"
                        or type(scan.get("detections")) is not int
                        or scan["detections"] != 0
                        or not _valid_utc_timestamp(scan.get("scan_time_utc"))
                        or SHA256_RE.fullmatch(str(scan.get("output_sha256", ""))) is None
                        or scan.get("output_sha256") == "0" * 64
                        or SHA256_RE.fullmatch(str(scan.get("receipt_sha256", ""))) is None
                        or scan.get("receipt_sha256") == "0" * 64):
                    raise ReleaseAttestationError(
                        f"scanner subject result[{scan_index}] is not a clean receipt")
                by_scanner[scanner_id] = scan
                # Resolve paths here; the receipt validator reads/hashes both
                # with explicit bounds rather than hashing unbounded files first.
                output_path = _contained_evidence_path(
                    evidence_path.parent, scan.get("output_path"))
                receipt_path = _contained_evidence_path(
                    evidence_path.parent, scan.get("receipt_path"))
                try:
                    scanner_evidence.validate_scan_receipt(
                        receipt_path, scanner=scanner_registry[scanner_id],
                        scan=scan, subject=entry, raw_output_path=output_path,
                        issued_at_utc=issued_at_utc)
                except scanner_evidence.ScannerEvidenceError as exc:
                    raise ReleaseAttestationError(f"scanner receipt is invalid: {exc}") from exc
            if set(by_scanner) != set(scanner_registry):
                raise ReleaseAttestationError("scanner subject engine set differs from registry")
        elif kind == "clean-vm":
            if set(entry) != SUBJECT_BASE_FIELDS | {"passed", "total", "cells"}:
                raise ReleaseAttestationError("clean-vm subject matrix is malformed")
            _validate_vm_cells(entry, evidence_root=evidence_path.parent)
        else:
            if set(entry) != SUBJECT_BASE_FIELDS | {"passed", "total", "workflows"}:
                raise ReleaseAttestationError("application subject matrix is malformed")
            passed = entry.get("passed")
            total = entry.get("total")
            workflows = entry.get("workflows")
            if (type(passed) is not int or type(total) is not int
                    or total < 2 or passed != total or not isinstance(workflows, list)
                    or len(workflows) != total):
                raise ReleaseAttestationError(
                    f"{kind} subject matrix is not a nontrivial full pass")
            workflow_ids: set[str] = set()
            for workflow_index, workflow in enumerate(workflows):
                if (not isinstance(workflow, dict)
                        or set(workflow) != APPLICATION_WORKFLOW_FIELDS):
                    raise ReleaseAttestationError(
                        f"application workflow[{workflow_index}] is malformed")
                workflow_id = workflow.get("workflow_id")
                if (not isinstance(workflow_id, str)
                        or EVIDENCE_ID_RE.fullmatch(workflow_id) is None
                        or workflow_id in workflow_ids or workflow.get("status") != "passed"):
                    raise ReleaseAttestationError(
                        f"application workflow[{workflow_index}] is not passing")
                workflow_ids.add(workflow_id)
                _validate_backing_file(
                    evidence_path.parent, workflow.get("result_path"),
                    workflow.get("result_sha256"), "application workflow result")
                _validate_backing_file(
                    evidence_path.parent, workflow.get("log_path"),
                    workflow.get("log_sha256"), "application workflow log")
    if covered_kinds != SUBJECT_KINDS:
        raise ReleaseAttestationError(f"{kind} evidence does not cover EXE and DLL lanes")


def _valid_utc_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def _validate_authenticode_receipt(receipt: Any) -> None:
    if not isinstance(receipt, dict) or set(receipt) != AUTHENTICODE_RECEIPT_FIELDS:
        raise ReleaseAttestationError("Authenticode verification receipt is malformed")
    thumbprint = re.compile(r"[0-9a-f]{40,128}\Z")
    if (receipt.get("status") != "valid"
            or not all(isinstance(receipt.get(field), str) and receipt[field].strip()
                       for field in ("tool_name", "tool_version", "signer_subject",
                                     "timestamp_subject"))
            or thumbprint.fullmatch(str(receipt.get("signer_thumbprint", ""))) is None
            or thumbprint.fullmatch(str(receipt.get("timestamp_thumbprint", ""))) is None
            or set(str(receipt.get("signer_thumbprint", ""))) == {"0"}
            or set(str(receipt.get("timestamp_thumbprint", ""))) == {"0"}
            or not all(_valid_utc_timestamp(receipt.get(field)) for field in (
                "verified_at_utc", "signer_not_after_utc", "timestamp_not_after_utc"))):
        raise ReleaseAttestationError("Authenticode verification receipt is not green")


def _validate_scanner_registry(scanners: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(scanners, list) or len(scanners) < 2:
        raise ReleaseAttestationError(
            "scanner evidence requires Defender and an independent scanner")
    registry: dict[str, dict[str, Any]] = {}
    for index, scanner in enumerate(scanners):
        if not isinstance(scanner, dict) or set(scanner) != SCANNER_FIELDS:
            raise ReleaseAttestationError(f"scanner registry[{index}] is malformed")
        scanner_id = scanner.get("scanner_id")
        if (not isinstance(scanner_id, str)
                or EVIDENCE_ID_RE.fullmatch(scanner_id) is None
                or scanner_id in registry
                or not all(isinstance(scanner.get(field), str) and scanner[field].strip()
                           for field in ("tool_name", "tool_version", "engine_version",
                                         "definitions_version"))):
            raise ReleaseAttestationError(f"scanner registry[{index}] is invalid")
        registry[scanner_id] = scanner
    if "microsoft-defender" not in registry or len(registry) < 2:
        raise ReleaseAttestationError(
            "scanner evidence requires Defender and an independent scanner")
    return registry


def _validate_vm_cells(entry: dict[str, Any], *, evidence_root: Path) -> None:
    cells = entry.get("cells")
    if (entry.get("passed") != len(REQUIRED_VM_CELLS)
            or entry.get("total") != len(REQUIRED_VM_CELLS)
            or not isinstance(cells, list) or len(cells) != len(REQUIRED_VM_CELLS)):
        raise ReleaseAttestationError("clean-vm subject matrix is not a four-cell full pass")
    seen: set[str] = set()
    for index, cell in enumerate(cells):
        if not isinstance(cell, dict) or set(cell) != VM_CELL_FIELDS:
            raise ReleaseAttestationError(f"clean-vm cell[{index}] is malformed")
        cell_id = cell.get("cell_id")
        expected = REQUIRED_VM_CELLS.get(cell_id)
        if (expected is None or cell_id in seen or cell.get("status") != "passed"
                or (cell.get("os_release"), cell.get("vbs_enabled"),
                    cell.get("hvci_enabled"), cell.get("hyper_v_enabled")) != expected
                or any(type(cell.get(field)) is not bool for field in (
                    "vbs_enabled", "hvci_enabled", "hyper_v_enabled"))
                or cell.get("arch") != "x64" or type(cell.get("secure_boot")) is not bool
                or re.fullmatch(r"\d{4,5}(?:\.\d+){1,3}",
                                str(cell.get("os_build", ""))) is None
                or re.fullmatch(r"KB\d{6,8}",
                                str(cell.get("patch_level", ""))) is None
                or not isinstance(cell.get("image_id"), str) or not cell["image_id"].strip()
                or not isinstance(cell.get("snapshot_id"), str)
                or not cell["snapshot_id"].strip()
                or SHA256_RE.fullmatch(str(cell.get("runner_sha256", ""))) is None
                or cell.get("runner_sha256") == "0" * 64
                or SHA256_RE.fullmatch(str(cell.get("result_log_sha256", ""))) is None):
            raise ReleaseAttestationError(f"clean-vm cell[{index}] identity is invalid")
        seen.add(cell_id)
        _validate_backing_file(
            evidence_root, cell.get("result_log_path"),
            cell.get("result_log_sha256"), "clean-vm result log")
    if seen != set(REQUIRED_VM_CELLS):
        raise ReleaseAttestationError("clean-vm required cell set is incomplete")


def _subject_entries(document: dict[str, Any], kind: str) -> list[Any]:
    key = "matrix" if kind in ("application", "clean-vm") else "subjects"
    entries = document.get(key)
    if not isinstance(entries, list) or len(entries) < 2:
        raise ReleaseAttestationError(f"{kind} evidence has no representative subject matrix")
    return entries


def _validate_subject_pe(
    path: Path,
    subject_kind: str,
    *,
    require_authenticode: bool = False,
) -> None:
    try:
        data = path.read_bytes()
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if pe_offset < 0x40 or pe_offset + 24 > len(data):
            raise ValueError
        if data[pe_offset:pe_offset + 4] != b"PE\0\0":
            raise ValueError
        machine, section_count = struct.unpack_from("<HH", data, pe_offset + 4)
        optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
        optional_offset = pe_offset + 24
        optional_end = optional_offset + optional_size
        section_table_end = optional_end + section_count * 40
        if (machine != 0x8664 or section_count < 1 or optional_size < 112
                or optional_end > len(data) or section_table_end > len(data)):
            raise ValueError
        optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
        size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
        if (optional_magic != 0x20B or size_of_headers < section_table_end
                or size_of_headers > len(data)):
            raise ValueError
        section_raw_ranges: list[tuple[int, int]] = []
        for index in range(section_count):
            section = optional_end + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, section + 8)
            if virtual_address + max(virtual_size, raw_size) > 0x1_0000_0000:
                raise ValueError
            if raw_size and (raw_offset < size_of_headers
                             or raw_offset + raw_size > len(data)):
                raise ValueError
            if raw_size:
                section_raw_ranges.append((raw_offset, raw_offset + raw_size))
        if require_authenticode:
            directory_count = struct.unpack_from("<I", data, optional_offset + 108)[0]
            security_entry = optional_offset + 112 + 4 * 8
            if directory_count <= 4 or security_entry + 8 > optional_end:
                raise ValueError
            cert_offset, cert_size = struct.unpack_from("<II", data, security_entry)
            if (cert_offset == 0 or cert_size < 8 or cert_offset % 8 != 0
                    or cert_offset < size_of_headers or cert_offset + cert_size > len(data)
                    or any(cert_offset < end and cert_offset + cert_size > start
                           for start, end in section_raw_ranges)):
                raise ValueError
            cursor = cert_offset
            cert_end = cert_offset + cert_size
            while cursor < cert_end:
                if cursor + 8 > cert_end:
                    raise ValueError
                length, revision, cert_type = struct.unpack_from("<IHH", data, cursor)
                if (length < 8 or cursor + length > cert_end
                        or revision != 0x0200 or cert_type != 0x0002):
                    raise ValueError
                cursor += (length + 7) & ~7
            if cursor != cert_end:
                raise ValueError
    except (OSError, ValueError, IndexError, struct.error):
        raise ReleaseAttestationError("protected subject is not a valid PE image") from None
    is_dll = bool(characteristics & 0x2000)
    if is_dll != (subject_kind == "dll"):
        raise ReleaseAttestationError(
            f"protected subject bytes disagree with {subject_kind}/{SUBJECT_FORMAT}")


def _subject_base(entry: dict[str, Any]) -> dict[str, Any]:
    return {field: entry.get(field) for field in SUBJECT_BASE_FIELDS}


def _validate_subject_registry(
    entries: Any,
    *,
    evidence_root: Path,
    artifact_sha256: str,
    source_commit: str,
    candidate_manifest_sha256: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(entries, list) or len(entries) < 2:
        raise ReleaseAttestationError("external subject registry is not representative")
    registry: dict[str, dict[str, Any]] = {}
    kinds: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != SUBJECT_BASE_FIELDS:
            raise ReleaseAttestationError(f"external subject registry[{index}] is malformed")
        subject_id = entry.get("subject_id")
        kind = entry.get("subject_kind")
        relative = entry.get("subject_path")
        digest = entry.get("subject_sha256")
        if (not isinstance(subject_id, str) or EVIDENCE_ID_RE.fullmatch(subject_id) is None
                or subject_id in registry or kind not in SUBJECT_KINDS
                or entry.get("format") != SUBJECT_FORMAT
                or entry.get("protected_with_stub_sha256") != artifact_sha256
                or entry.get("source_commit") != source_commit
                or entry.get("candidate_manifest_sha256") != candidate_manifest_sha256
                or SHA256_RE.fullmatch(str(digest or "")) is None
                or type(entry.get("subject_size_bytes")) is not int
                or entry["subject_size_bytes"] < 1
                or any(SHA256_RE.fullmatch(str(entry.get(field, ""))) is None
                       or entry[field] == "0" * 64
                       for field in ("input_sha256", "pack_report_sha256",
                                     "protection_profile_sha256"))
                or not isinstance(relative, str) or not relative.startswith("subjects/")):
            raise ReleaseAttestationError(f"external subject registry[{index}] is invalid")
        subject_path = _contained_evidence_path(evidence_root, relative)
        if (sha256_file(subject_path) != digest
                or subject_path.stat().st_size != entry["subject_size_bytes"]):
            raise ReleaseAttestationError("external subject registry hash mismatch")
        _validate_subject_pe(subject_path, kind)
        _validate_backing_file(
            evidence_root, entry.get("pack_report_path"),
            entry.get("pack_report_sha256"), "external subject pack report")
        _validate_backing_file(
            evidence_root, entry.get("protection_profile_path"),
            entry.get("protection_profile_sha256"),
            "external subject protection profile")
        registry[subject_id] = dict(entry)
        kinds.add(kind)
    if kinds != SUBJECT_KINDS:
        raise ReleaseAttestationError("external subject registry must cover EXE and DLL")
    return registry


def _validate_subject_document_sets(
    registry: dict[str, dict[str, Any]],
    documents: dict[str, dict[str, Any]],
) -> None:
    for kind in ("authenticode", "scanner", "application", "clean-vm"):
        entries = _subject_entries(documents[kind], kind)
        actual: dict[str, dict[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("subject_id"), str):
                raise ReleaseAttestationError(f"{kind} evidence subject set is malformed")
            actual[entry["subject_id"]] = _subject_base(entry)
        if actual != registry:
            raise ReleaseAttestationError(
                f"{kind} evidence subject set differs from the external registry")


def verify_release_bundle(
    stub_path: Path,
    *,
    manifest_path: Path | None = None,
    attestation_path: Path | None = None,
    trust_store_path: Path | None = None,
    evidence_trust_store_path: Path | None = None,
    matrix_path: Path | None = None,
) -> dict[str, Any]:
    raw_stub = stub_path.absolute()
    raw_manifest = (manifest_path or candidate_manifest_path(raw_stub)).absolute()
    raw_attestation = (
        attestation_path or release_attestation_path(raw_stub)).absolute()
    if (any(_is_linklike(path) for path in (raw_stub, raw_manifest, raw_attestation))
            or _is_linklike(raw_stub.parent)):
        raise ReleaseAttestationError("release bundle cannot contain links or junctions")
    stub_path = raw_stub.resolve()
    manifest_path = raw_manifest.resolve()
    attestation_path = raw_attestation.resolve()
    if not (stub_path.parent == manifest_path.parent == attestation_path.parent):
        raise ReleaseAttestationError("release DLL, manifest, and attestation are not one bundle")
    manifest = validate_candidate_identity(stub_path, manifest_path)
    envelope = _read_json_object(attestation_path, "release attestation")
    if (set(envelope) != {"schema", "payload", "signature_base64"}
            or envelope.get("schema") != 1
            or not isinstance(envelope.get("payload"), dict)):
        raise ReleaseAttestationError("release attestation envelope is malformed")
    payload = envelope["payload"]
    payload_fields = {
        "schema", "kind", "key_id", "production_ready", "artifact", "candidate",
        "release_matrix_sha256", "release_source_commit", "production_gate",
        "evidence", "issued_at_utc",
    }
    if (set(payload) != payload_fields or type(payload.get("schema")) is not int
            or payload["schema"] != RELEASE_PAYLOAD_SCHEMA
            or payload.get("kind") != ATTESTATION_KIND):
        raise ReleaseAttestationError("release attestation payload is malformed")
    key_id = payload.get("key_id")
    trusted, release_key_ids = _load_trust_store_details(trust_store_path)
    evidence_trust = load_evidence_trust_store(evidence_trust_store_path)
    if release_key_ids & evidence_trust["provider_key_ids"]:
        raise ReleaseAttestationError(
            "release and external-evidence signing key roles overlap")
    if not isinstance(key_id, str) or key_id not in trusted:
        raise ReleaseAttestationError("release attestation key is unknown or revoked")
    signature = _decode_b64(
        envelope.get("signature_base64"), length=64,
        what="release attestation signature",
    )
    try:
        Ed25519PublicKey.from_public_bytes(trusted[key_id]).verify(
            signature, canonical_json_bytes(payload))
    except InvalidSignature as exc:
        raise ReleaseAttestationError("release attestation signature is invalid") from exc

    # Authenticate the issuance time before using it as the freshness reference.
    # There is no wall-clock age expiry for a previously valid installed release.
    _validate_release_issuance(payload.get("issued_at_utc"))

    artifact = payload.get("artifact")
    if artifact != {
        "name": stub_path.name,
        "sha256": sha256_file(stub_path),
        "size_bytes": stub_path.stat().st_size,
    }:
        raise ReleaseAttestationError("release attestation artifact binding is invalid")
    manifest_hash = sha256_file(manifest_path)
    candidate = payload.get("candidate")
    expected_candidate = {
        "manifest_name": manifest_path.name,
        "manifest_sha256": manifest_hash,
        "source_commit": manifest["source_commit"],
        "candidate_policy_id": manifest.get("candidate_policy_id"),
        "candidate_policy_sha256": manifest["candidate_policy_sha256"],
        "promotion_tool_sha256": manifest["promotion_tool_sha256"],
        "candidate_matrix_sha256": manifest["production_matrix_sha256"],
        "toolchain_binding_sha256": manifest["toolchain_binding_sha256"],
        "dvm_rolling": manifest["dvm_rolling"],
        "dvm_roll_poison": manifest["dvm_roll_poison"],
        "dvm_paged_runtime": manifest["dvm_paged_runtime"],
    }
    if candidate != expected_candidate:
        raise ReleaseAttestationError("release attestation candidate binding is invalid")
    raw_matrix = (matrix_path or DEFAULT_MATRIX).absolute()
    if _is_linklike(raw_matrix) or _is_linklike(raw_matrix.parent):
        raise ReleaseAttestationError("release matrix cannot be a link or junction")
    current_matrix = raw_matrix.resolve()
    release_matrix_hash = payload.get("release_matrix_sha256")
    if (SHA256_RE.fullmatch(str(release_matrix_hash or "")) is None
            or sha256_file(current_matrix) != release_matrix_hash):
        raise ReleaseAttestationError("release attestation release-matrix binding is stale")
    if COMMIT_RE.fullmatch(str(payload.get("release_source_commit", ""))) is None:
        raise ReleaseAttestationError("release attestation has no valid release source commit")

    gate = payload.get("production_gate")
    if (not isinstance(gate, dict) or gate.get("schema") != 1
            or gate.get("scope") != "all" or gate.get("ready") is not True
            or gate.get("blocker_count") != 0 or gate.get("blockers") != []):
        raise ReleaseAttestationError("release attestation has no green all-scope gate")
    if payload.get("production_ready") is not True:
        raise ReleaseAttestationError("release attestation does not claim production readiness")
    records = payload.get("evidence")
    if not isinstance(records, list) or not records:
        raise ReleaseAttestationError("release attestation has no evidence records")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    kinds: set[str] = set()
    evidence_paths: dict[str, Path] = {}
    evidence_documents: dict[str, dict[str, Any]] = {}
    bundle_root = attestation_path.parent.resolve()
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != {"id", "kind", "path", "sha256"}:
            raise ReleaseAttestationError(f"release evidence[{index}] is malformed")
        record_id = record["id"]
        kind = record["kind"]
        relative = record["path"]
        expected_hash = record["sha256"]
        if (not isinstance(record_id, str) or EVIDENCE_ID_RE.fullmatch(record_id) is None
                or not isinstance(kind, str) or kind not in REQUIRED_EVIDENCE_KINDS
                or SHA256_RE.fullmatch(str(expected_hash)) is None):
            raise ReleaseAttestationError(f"release evidence[{index}] identity is invalid")
        if record_id in seen_ids or relative in seen_paths or kind in kinds:
            raise ReleaseAttestationError("release attestation repeats evidence identity/path/kind")
        seen_ids.add(record_id)
        seen_paths.add(relative)
        kinds.add(kind)
        evidence_path = _contained_evidence_path(bundle_root, relative)
        if sha256_file(evidence_path) != expected_hash:
            raise ReleaseAttestationError(f"release evidence hash mismatch: {record_id}")
        document = _read_json_object(evidence_path, f"release evidence {record_id}")
        evidence_paths[kind] = evidence_path
        evidence_documents[kind] = document
        _validate_semantic_evidence(
            record, document,
            artifact_sha256=artifact["sha256"],
            source_commit=manifest["source_commit"],
            candidate_manifest_sha256=manifest_hash,
            gate=gate,
            evidence_path=evidence_path,
            issued_at_utc=payload["issued_at_utc"],
        )
    if kinds != REQUIRED_EVIDENCE_KINDS:
        missing = REQUIRED_EVIDENCE_KINDS - kinds
        extra = kinds - REQUIRED_EVIDENCE_KINDS
        detail = sorted(missing or extra)
        raise ReleaseAttestationError(
            "release attestation evidence kinds are incomplete: " + ", ".join(detail))
    external_manifest = evidence_documents["external-manifest"]
    external_expected = {
        "schema": 1,
        "candidate_stub_sha256": artifact["sha256"],
        "candidate_manifest_sha256": manifest_hash,
        "source_commit": manifest["source_commit"],
    }
    if (set(external_manifest) != {*external_expected, "subjects", "records"}
            or any(external_manifest.get(key) != value
                   for key, value in external_expected.items())):
        raise ReleaseAttestationError("external evidence manifest binding is invalid")
    registry = _validate_subject_registry(
        external_manifest.get("subjects"),
        evidence_root=evidence_paths["external-manifest"].parent,
        artifact_sha256=artifact["sha256"],
        source_commit=manifest["source_commit"],
        candidate_manifest_sha256=manifest_hash,
    )
    _validate_subject_document_sets(registry, evidence_documents)
    external_records = external_manifest.get("records")
    if not isinstance(external_records, list) or len(external_records) != len(
            EXTERNAL_EVIDENCE_KINDS):
        raise ReleaseAttestationError("external evidence manifest records are malformed")
    external_by_kind: dict[str, dict[str, Any]] = {}
    external_ids: set[str] = set()
    external_paths: set[str] = set()
    for index, record in enumerate(external_records):
        if not isinstance(record, dict):
            raise ReleaseAttestationError(
                f"external evidence manifest record[{index}] is malformed")
        record_id = record.get("id")
        kind = record.get("kind")
        expected_fields = {"id", "kind", "path", "sha256"}
        if kind in PROVIDER_SIGNED_KINDS:
            expected_fields |= {"provider_signature_path", "provider_signature_sha256"}
        if set(record) != expected_fields:
            raise ReleaseAttestationError(
                f"external evidence manifest record[{index}] is malformed")
        relative = record.get("path")
        digest = record.get("sha256")
        if (not isinstance(record_id, str)
                or EVIDENCE_ID_RE.fullmatch(record_id) is None
                or kind not in EXTERNAL_EVIDENCE_KINDS
                or not isinstance(relative, str)
                or SHA256_RE.fullmatch(str(digest or "")) is None
                or record_id in external_ids or relative in external_paths
                or kind in external_by_kind):
            raise ReleaseAttestationError(
                f"external evidence manifest record[{index}] identity is invalid")
        external_ids.add(record_id)
        external_paths.add(relative)
        external_by_kind[kind] = record
    if set(external_by_kind) != EXTERNAL_EVIDENCE_KINDS:
        raise ReleaseAttestationError("external evidence manifest kinds are incomplete")
    for kind in EXTERNAL_EVIDENCE_KINDS:
        record = external_by_kind.get(kind)
        if (not isinstance(record, dict)
                or record.get("sha256") != sha256_file(evidence_paths[kind])):
            raise ReleaseAttestationError(
                f"external evidence manifest does not bind {kind} evidence")
    external_root = evidence_paths["external-manifest"].parent
    for kind in PROVIDER_SIGNED_KINDS:
        verify_provider_signature(
            external_by_kind[kind], evidence_documents[kind],
            evidence_root=external_root, trust_policy=evidence_trust)
    allowed_signers = evidence_trust["allowed_signer_thumbprints"]
    allowed_tsas = evidence_trust["allowed_tsa_thumbprints"]
    for entry in _subject_entries(evidence_documents["authenticode"], "authenticode"):
        receipt = entry["verification_receipt"]
        if receipt["signer_thumbprint"] not in allowed_signers:
            raise ReleaseAttestationError("Authenticode signer is not pinned")
        if receipt["timestamp_thumbprint"] not in allowed_tsas:
            raise ReleaseAttestationError("Authenticode timestamper is not pinned")
    bundled_matrix = evidence_paths["release-matrix"]
    if sha256_file(bundled_matrix) != release_matrix_hash:
        raise ReleaseAttestationError("bundled release matrix disagrees with its attestation")
    rebuild = evidence_documents["release-rebuild"]
    if (rebuild.get("dvm_shuffle_seed") != manifest["dvm_shuffle_seed"]
            or rebuild.get("toolchain_binding_sha256") != manifest["toolchain_binding_sha256"]
            or rebuild.get("dvm_rolling") != manifest["dvm_rolling"]
            or rebuild.get("dvm_roll_poison") != manifest["dvm_roll_poison"]
            or rebuild.get("dvm_paged_runtime") != manifest["dvm_paged_runtime"]):
        raise ReleaseAttestationError("release rebuild disagrees with candidate provenance")
    try:
        from tools import production_gate
        matrix = production_gate.load_matrix(bundled_matrix)
        native = production_gate.load_evidence(
            evidence_paths["production-native"], artifact_path=stub_path)
        evaluated_gate = production_gate.evaluate(matrix, "all", native)
    except (OSError, production_gate.MatrixError) as exc:
        raise ReleaseAttestationError(
            f"cannot independently replay bundled production evidence: {exc}") from exc
    if (native.get("source_commit") != manifest["source_commit"]
            or native.get("tracked_source_dirty") is not False
            or evaluated_gate != gate or evaluated_gate.get("ready") is not True):
        raise ReleaseAttestationError(
            "signed production gate disagrees with bundled evidence-aware evaluation")
    return payload


__all__ = [
    "ATTESTATION_KIND",
    "DEFAULT_MATRIX",
    "DEFAULT_EVIDENCE_TRUST_STORE",
    "DEFAULT_TRUST_STORE",
    "EXTERNAL_EVIDENCE_KINDS",
    "PROVIDER_SIGNED_KINDS",
    "REQUIRED_EVIDENCE_KINDS",
    "REQUIRED_RELEASE_REPLAY_IDS",
    "ReleaseAttestationError",
    "canonical_json_bytes",
    "candidate_manifest_path",
    "load_trust_store",
    "load_evidence_trust_store",
    "provider_signature_payload",
    "public_key_id",
    "release_attestation_path",
    "sha256_file",
    "validate_candidate_identity",
    "verify_release_bundle",
    "verify_provider_signature",
]
