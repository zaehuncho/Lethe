#!/usr/bin/env python3
"""Create a signed, portable production-release bundle from one candidate."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packer import release_attestation
from tools import production_gate, promote_stub


ROOT = Path(__file__).resolve().parents[1]
INPUT_EVIDENCE_KINDS = frozenset({
    "authenticode", "scanner", "clean-vm", "application", "production-native",
})
RESERVED_EVIDENCE_IDS = frozenset({"external-manifest", "production-gate"})
CANDIDATE_TO_RELEASE_ALLOWED_PATHS = frozenset({
    "docs/production_compatibility.json",
})


class ReleaseError(RuntimeError):
    """A production-release precondition was not satisfied."""


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={ROOT.as_posix()}", *args],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise ReleaseError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout


def _git_blob(commit: str, path: str) -> bytes:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={ROOT.as_posix()}", "show", f"{commit}:{path}"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode != 0:
        raise ReleaseError(
            f"candidate source omits tracked {path}: "
            + completed.stderr.decode("utf-8", errors="replace").strip())
    return completed.stdout


def _validate_candidate_git_provenance(
    candidate_dir: Path,
    candidate: dict[str, Any],
) -> None:
    commit = candidate["source_commit"]
    verified = _git("rev-parse", "--verify", f"{commit}^{{commit}}").strip()
    if verified != commit:
        raise ReleaseError("candidate source identity is not an exact Git commit")
    for relative, expected_hash in candidate["dependency_locks"].items():
        actual = hashlib.sha256(_git_blob(commit, relative)).hexdigest()
        if actual != expected_hash:
            raise ReleaseError(f"candidate lock binding disagrees with Git: {relative}")
    bindings = (
        ("tools/promote_stub.py", "evidence/candidate-promoter.py",
         "promotion_tool_sha256"),
        ("docs/production_compatibility.json",
         "evidence/candidate-production-matrix.json", "production_matrix_sha256"),
    )
    for tracked_path, snapshot_path, field in bindings:
        tracked = _git_blob(commit, tracked_path)
        snapshot = release_attestation._contained_evidence_path(
            candidate_dir, snapshot_path).read_bytes()
        digest = hashlib.sha256(tracked).hexdigest()
        if tracked != snapshot or digest != candidate[field]:
            raise ReleaseError(
                f"candidate {tracked_path} snapshot does not match its Git source")


def _validate_release_matrix_git(commit: str, matrix_path: Path) -> None:
    if _git_blob(commit, "docs/production_compatibility.json") != matrix_path.read_bytes():
        raise ReleaseError("release matrix snapshot does not match the release Git commit")


def _archive_source(commit: str, destination: Path) -> None:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={ROOT.as_posix()}",
         "archive", "--format=tar", commit],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode != 0:
        raise ReleaseError(
            "cannot archive candidate source: "
            + completed.stderr.decode("utf-8", errors="replace").strip())
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            if (member.issym() or member.islnk() or path.is_absolute()
                    or any(part in ("", ".", "..") for part in path.parts)):
                raise ReleaseError("candidate Git archive contains an unsafe path or link")
        archive.extractall(destination, filter="data")


def _run_build(argv: list[str], *, cwd: Path, label: str) -> None:
    completed = subprocess.run(
        argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout)[-4000:].strip()
        raise ReleaseError(f"deterministic candidate {label} failed: {detail}")


def _rebuild_candidate_stub(
    candidate: dict[str, Any],
    rebuild_root: Path,
    _expected_stub: Path,
) -> bytes:
    source = rebuild_root / "source"
    build = rebuild_root / "build"
    _archive_source(candidate["source_commit"], source)
    try:
        host = promote_stub.inspect_host(ROOT)
    except promote_stub.PromotionError as exc:
        raise ReleaseError(f"release rebuild host is invalid: {exc}") from exc
    host_bindings = {
        "python_version": host["python_version"],
        "uv_version": host["uv_version"],
        "cmake_version": host["cmake_version"],
        "ctest_version": host["ctest_version"],
    }
    for field, actual in host_bindings.items():
        if candidate.get(field) != actual:
            raise ReleaseError(f"release rebuild {field} differs from the candidate")
    configure = [
        host["cmake"], "-S", str(source / "stub"), "-B", str(build),
        "-G", candidate["cmake_generator"], "-A", candidate["cmake_platform"],
        "-DBUILD_TESTING=ON", f"-DPython3_EXECUTABLE={host['python']}",
        f"-DDVM_SHUFFLE_SEED={candidate['dvm_shuffle_seed']}",
        "-DCMAKE_C_FLAGS=/W4 /WX /Brepro",
        "-DCMAKE_C_FLAGS_RELEASE=/O2 /Brepro",
        "-DCMAKE_SHARED_LINKER_FLAGS_RELEASE=/Brepro /INCREMENTAL:NO",
        "-DCMAKE_EXE_LINKER_FLAGS_RELEASE=/Brepro",
    ]
    _run_build(configure, cwd=source, label="configure")
    try:
        toolchain = promote_stub.inspect_cmake_toolchain(build)
    except promote_stub.PromotionError as exc:
        raise ReleaseError(f"release rebuild toolchain is invalid: {exc}") from exc
    expected_toolchain = {
        "cmake_generator": candidate["cmake_generator"],
        "cmake_platform": candidate["cmake_platform"],
        "compiler_id": candidate["compiler_id"],
        "compiler_version": candidate["compiler_version"],
        "compile_policy": candidate["warning_policy"],
        "link_policy": candidate["reproducible_link"],
    }
    if toolchain != expected_toolchain:
        raise ReleaseError("release rebuild toolchain differs from the candidate")
    _run_build(
        [host["cmake"], "--build", str(build), "--config", "Release",
         "--parallel", "2", "--verbose"],
        cwd=source, label="build",
    )
    built_stub = build / "Release" / promote_stub.PREBUILT.name
    if not built_stub.is_file():
        raise ReleaseError("deterministic rebuild produced no native stub")
    try:
        dvm = promote_stub.inspect_generated_dvm_provenance(
            build, candidate["dvm_shuffle_seed"])
    except promote_stub.PromotionError as exc:
        raise ReleaseError(f"release rebuild DVM provenance is invalid: {exc}") from exc
    for field in (
        "dvm_shuffle_seed", "dvm_opcode_mapping_sha256",
        "dvm_handler_variant_sha256", "dvm_python_map_sha256",
        "dvm_native_map_sha256", "dvm_rolling", "dvm_paged_runtime",
    ):
        if dvm.get(field) != candidate.get(field):
            raise ReleaseError(f"release rebuild {field} differs from the candidate")
    return built_stub.read_bytes()


def _portable_replay_record(
    record: promote_stub.CommandRecord,
    portable_argv: list[str],
) -> dict[str, Any]:
    return {
        "id": record.name,
        "status": "passed" if record.exit_code == 0 else "failed",
        "argv": portable_argv,
        "exit_code": record.exit_code,
        "artifact_sha256": record.artifact_sha256,
        "stdout_sha256": hashlib.sha256(record.stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(record.stderr.encode("utf-8")).hexdigest(),
    }


def _replay_rebuilt_candidate(
    candidate: dict[str, Any],
    rebuild_root: Path,
    rebuilt_stub: Path,
) -> list[dict[str, Any]]:
    source = rebuild_root / "source"
    build = rebuild_root / "build"
    artifact_hash = release_attestation.sha256_file(rebuilt_stub)
    try:
        host = promote_stub.inspect_host(ROOT)
    except promote_stub.PromotionError as exc:
        raise ReleaseError(f"release replay host is invalid: {exc}") from exc
    records: list[dict[str, Any]] = []

    def run(
        argv: list[str | os.PathLike[str]],
        *,
        name: str,
        portable_argv: list[str],
        env_overrides: dict[str, str] | None = None,
    ) -> promote_stub.CommandRecord:
        record = promote_stub._run(
            argv, name=name, source_commit=candidate["source_commit"],
            artifact_sha256=artifact_hash, cwd=source,
            env_overrides=env_overrides,
        )
        records.append(_portable_replay_record(record, portable_argv))
        if record.exit_code != 0:
            raise ReleaseError(f"release replay {name} failed with exit {record.exit_code}")
        try:
            promote_stub._require_unchanged_artifact(
                rebuilt_stub, artifact_hash, f"release replay {name}")
        except promote_stub.PromotionError as exc:
            raise ReleaseError(str(exc)) from exc
        return record

    inventory = run(
        [host["ctest"], "--test-dir", build, "-C", "Release", "--show-only=json-v1"],
        name="ctest-inventory",
        portable_argv=["tool://ctest", "--test-dir", "build", "-C", "Release",
                       "--show-only=json-v1"],
    )
    try:
        inventory_payload = json.loads(inventory.stdout)
        expected_total = candidate["ctest"]["total"]
        if len(inventory_payload.get("tests", [])) != expected_total:
            raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ReleaseError("release replay CTest inventory differs from the candidate") from None
    run(
        [host["ctest"], "--test-dir", build, "-C", "Release", "--output-on-failure"],
        name="ctest",
        portable_argv=["tool://ctest", "--test-dir", "build", "-C", "Release",
                       "--output-on-failure"],
    )
    test_environment = {
        "PYTHONPATH": str(source),
        "LETHE_RUN_NATIVE_RUNTIME_STRESS": "1",
        "LETHE_NATIVE_RUNTIME_STUB_PATH": str(rebuilt_stub),
    }
    runtime = run(
        [host["python"], "-m", "pytest", "-q", "-p", "no:cacheprovider",
         source / "tests" / "test_native_runtime_hardening_stress.py"],
        name="candidate-bound-native-runtime-hardening",
        portable_argv=["tool://python", "-m", "pytest", "-q", "-p",
                       "no:cacheprovider",
                       "repo://tests/test_native_runtime_hardening_stress.py"],
        env_overrides=test_environment,
    )
    try:
        promote_stub.validate_runtime_hardening_record(runtime, artifact_hash)
    except promote_stub.PromotionError as exc:
        raise ReleaseError(f"release runtime-hardening replay is invalid: {exc}") from exc

    sample_dir = rebuild_root / "roundtrip"
    run(
        [host["powershell"], "-NoProfile", "-File",
         source / "tests" / "build_samples.ps1", "-OutDir", sample_dir],
        name="roundtrip-fixture-build",
        portable_argv=["tool://powershell", "-NoProfile", "-File",
                       "repo://tests/build_samples.ps1", "-OutDir", "work://roundtrip"],
        env_overrides={"PYTHONPATH": str(source)},
    )
    roundtrip = run(
        [host["powershell"], "-NoProfile", "-File", source / "tests" / "roundtrip.ps1",
         "-StubPath", rebuilt_stub, "-PythonExe", host["python"],
         "-BuildDir", sample_dir],
        name="exe-dll-roundtrip",
        portable_argv=["tool://powershell", "-NoProfile", "-File",
                       "repo://tests/roundtrip.ps1", "-StubPath", "artifact://stub",
                       "-PythonExe", "tool://python", "-BuildDir", "work://roundtrip"],
        env_overrides={"PYTHONPATH": str(source)},
    )
    try:
        replay_counts = promote_stub.validate_roundtrip_record(roundtrip, artifact_hash)
        actual_counts = candidate["native_roundtrip_actual"]
        if replay_counts != (actual_counts["passed"], actual_counts["total"]):
            raise ReleaseError("release round-trip replay count differs from the candidate")
    except (KeyError, TypeError, promote_stub.PromotionError) as exc:
        raise ReleaseError(f"release round-trip replay is invalid: {exc}") from exc

    corpus_dir = rebuild_root / "corpus"
    corpus_evidence = rebuild_root / "production-evidence.json"
    run(
        [host["powershell"], "-NoProfile", "-File",
         source / "tests" / "build_production_corpus.ps1", "-OutDir", corpus_dir],
        name="production-corpus-build",
        portable_argv=["tool://powershell", "-NoProfile", "-File",
                       "repo://tests/build_production_corpus.ps1", "-OutDir",
                       "work://corpus"],
        env_overrides={"PYTHONPATH": str(source)},
    )
    run(
        [host["powershell"], "-NoProfile", "-File",
         source / "tests" / "production_corpus.ps1", "-StubPath", rebuilt_stub,
         "-PythonExe", host["python"], "-BuildDir", corpus_dir,
         "-EvidencePath", corpus_evidence, "-SourceCommit", candidate["source_commit"]],
        name="production-corpus",
        portable_argv=["tool://powershell", "-NoProfile", "-File",
                       "repo://tests/production_corpus.ps1", "-StubPath",
                       "artifact://stub", "-PythonExe", "tool://python", "-BuildDir",
                       "work://corpus", "-EvidencePath", "work://production-evidence.json",
                       "-SourceCommit", candidate["source_commit"]],
        env_overrides={"PYTHONPATH": str(source)},
    )
    try:
        promote_stub.validate_corpus_evidence(
            corpus_evidence, expected_commit=candidate["source_commit"],
            expected_hash=artifact_hash)
    except (promote_stub.PromotionError, production_gate.MatrixError) as exc:
        raise ReleaseError(f"release production-corpus replay is invalid: {exc}") from exc
    return records


def _inspect_release_source(candidate_commit: str) -> str:
    if _git("status", "--porcelain=v1", "--untracked-files=all").strip():
        raise ReleaseError("release source tree is not clean")
    head = _git("rev-parse", "HEAD").strip()
    if release_attestation.COMMIT_RE.fullmatch(head) is None:
        raise ReleaseError("release HEAD is not a full lowercase Git commit")
    _git("cat-file", "-e", f"{candidate_commit}^{{commit}}")
    _git("merge-base", "--is-ancestor", candidate_commit, head)
    drift = {
        line for line in _git("diff", "--name-only", candidate_commit, head).splitlines()
        if line
    }
    unexpected = drift - CANDIDATE_TO_RELEASE_ALLOWED_PATHS
    if unexpected:
        raise ReleaseError(
            "source changed outside the release compatibility declaration: "
            + ", ".join(sorted(unexpected)))
    return head


def _read_json(path: Path, what: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read {what}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReleaseError(f"{what} root must be an object")
    return payload


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _load_private_key(path: Path, password: bytes | None = None) -> Ed25519PrivateKey:
    if (not path.is_file() or path.is_symlink()
            or bool(getattr(path, "is_junction", lambda: False)())):
        raise ReleaseError("release private key must be a regular external file")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    except (OSError, ValueError, TypeError) as exc:
        raise ReleaseError(f"cannot load Ed25519 private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ReleaseError("release private key is not Ed25519")
    return key


def _external_record_path(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ReleaseError("external evidence path is malformed")
    value = Path(relative)
    if value.is_absolute() or any(part in ("", ".", "..") for part in value.parts):
        raise ReleaseError("external evidence path must be canonical relative text")
    try:
        return release_attestation._contained_evidence_path(root, relative)
    except release_attestation.ReleaseAttestationError as exc:
        raise ReleaseError(f"external evidence path is invalid: {exc}") from exc


def _verify_windows_authenticode(path: Path) -> dict[str, Any]:
    """Independently replay Windows trust verification for one snapshotted PE."""
    if os.name != "nt":
        raise ReleaseError("independent Authenticode verification requires Windows")
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if powershell is None:
        raise ReleaseError("PowerShell is required for independent Authenticode verification")
    script = r"""
$ErrorActionPreference = 'Stop'
$signature = Get-AuthenticodeSignature -LiteralPath $env:LETHE_AUTHENTICODE_VERIFY_PATH
$signer = $signature.SignerCertificate
$timestamp = $signature.TimeStamperCertificate
[ordered]@{
  tool_name = 'powershell-get-authenticodesignature'
  tool_version = $PSVersionTable.PSVersion.ToString()
  verified_at_utc = [DateTime]::UtcNow.ToString('o')
  status = $signature.Status.ToString().ToLowerInvariant()
  signer_thumbprint = if ($signer) { $signer.Thumbprint.ToLowerInvariant() } else { '' }
  signer_subject = if ($signer) { $signer.Subject } else { '' }
  signer_not_after_utc = if ($signer) { $signer.NotAfter.ToUniversalTime().ToString('o') } else { '' }
  timestamp_thumbprint = if ($timestamp) { $timestamp.Thumbprint.ToLowerInvariant() } else { '' }
  timestamp_subject = if ($timestamp) { $timestamp.Subject } else { '' }
  timestamp_not_after_utc = if ($timestamp) { $timestamp.NotAfter.ToUniversalTime().ToString('o') } else { '' }
} | ConvertTo-Json -Compress
"""
    environment = os.environ.copy()
    environment["LETHE_AUTHENTICODE_VERIFY_PATH"] = str(path)
    completed = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=path.parent, env=environment, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise ReleaseError(
            "independent Authenticode verification failed: "
            + (completed.stderr or completed.stdout).strip())
    try:
        receipt = json.loads(completed.stdout)
        release_attestation._validate_authenticode_receipt(receipt)
    except (json.JSONDecodeError, release_attestation.ReleaseAttestationError) as exc:
        raise ReleaseError(f"independent Authenticode result is invalid: {exc}") from exc
    return receipt


def _reject_link_tree(root: Path, what: str) -> None:
    raw_root = root.absolute()
    if release_attestation._is_linklike(raw_root) or not raw_root.is_dir():
        raise ReleaseError(f"{what} root must be a regular directory")
    for current, directories, files in os.walk(raw_root, followlinks=False):
        for name in [*directories, *files]:
            path = Path(current) / name
            if release_attestation._is_linklike(path):
                raise ReleaseError(f"{what} cannot contain links or junctions")


def _snapshot_tree(source: Path, destination: Path, what: str) -> None:
    _reject_link_tree(source, what)
    shutil.copytree(source.absolute(), destination, symlinks=True)
    _reject_link_tree(destination, f"snapshotted {what}")


def _snapshot_release_inputs(
    root: Path,
    *,
    candidate_dir: Path,
    external_manifest: Path,
    matrix_path: Path,
    trust_store_path: Path,
    evidence_trust_store_path: Path,
) -> dict[str, Path]:
    raw_external = external_manifest.absolute()
    raw_matrix = matrix_path.absolute()
    raw_trust = trust_store_path.absolute()
    raw_evidence_trust = evidence_trust_store_path.absolute()
    for path, what in ((raw_external, "external evidence manifest"),
                       (raw_matrix, "release matrix"),
                       (raw_trust, "release trust store"),
                       (raw_evidence_trust, "external-evidence trust store")):
        if release_attestation._is_linklike(path) or not path.is_file():
            raise ReleaseError(f"{what} must be a regular non-link file")
    candidate_copy = root / "candidate"
    external_copy = root / "external"
    _snapshot_tree(candidate_dir, candidate_copy, "candidate bundle")
    _snapshot_tree(raw_external.parent, external_copy, "external evidence bundle")
    matrix_copy = root / "release-matrix.json"
    trust_copy = root / "release-trust.json"
    evidence_trust_copy = root / "evidence-trust.json"
    shutil.copyfile(raw_matrix, matrix_copy)
    shutil.copyfile(raw_trust, trust_copy)
    shutil.copyfile(raw_evidence_trust, evidence_trust_copy)
    return {
        "candidate_dir": candidate_copy,
        "external_manifest": external_copy / raw_external.name,
        "matrix": matrix_copy,
        "trust": trust_copy,
        "evidence_trust": evidence_trust_copy,
    }


def _validate_external_manifest(
    path: Path,
    *,
    stub: Path,
    candidate_manifest: Path,
    candidate: dict[str, Any],
    evidence_trust_store_path: Path | None = None,
) -> tuple[dict[str, Any], list[tuple[dict[str, str], Path, dict[str, Any]]]]:
    manifest = _read_json(path, "external evidence manifest")
    stub_hash = release_attestation.sha256_file(stub)
    candidate_hash = release_attestation.sha256_file(candidate_manifest)
    required = {
        "schema": 1,
        "candidate_stub_sha256": stub_hash,
        "candidate_manifest_sha256": candidate_hash,
        "source_commit": candidate["source_commit"],
    }
    if set(manifest) != {*required, "subjects", "records"}:
        raise ReleaseError("external evidence manifest has unexpected or missing fields")
    for field, wanted in required.items():
        if manifest.get(field) != wanted:
            raise ReleaseError(f"external evidence manifest {field!r} binding is invalid")
    raw_records = manifest.get("records")
    if not isinstance(raw_records, list) or not raw_records:
        raise ReleaseError("external evidence manifest has no records")
    raw_manifest = path.absolute()
    if (raw_manifest.is_symlink()
            or bool(getattr(raw_manifest, "is_junction", lambda: False)())):
        raise ReleaseError("external evidence manifest cannot be a link or junction")
    root = raw_manifest.resolve().parent
    try:
        trust_policy = release_attestation.load_evidence_trust_store(
            evidence_trust_store_path)
        registry = release_attestation._validate_subject_registry(
            manifest["subjects"], evidence_root=root, artifact_sha256=stub_hash,
            source_commit=candidate["source_commit"],
            candidate_manifest_sha256=candidate_hash)
    except release_attestation.ReleaseAttestationError as exc:
        raise ReleaseError(f"external subject registry is invalid: {exc}") from exc
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    seen_kinds: set[str] = set()
    records: list[tuple[dict[str, str], Path, dict[str, Any]]] = []
    documents: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(raw_records):
        if not isinstance(record, dict):
            raise ReleaseError(f"external evidence[{index}] is malformed")
        kind = record.get("kind")
        expected_fields = {"id", "kind", "path", "sha256"}
        if kind in release_attestation.PROVIDER_SIGNED_KINDS:
            expected_fields |= {"provider_signature_path", "provider_signature_sha256"}
        if set(record) != expected_fields:
            raise ReleaseError(f"external evidence[{index}] is malformed")
        record_id = record["id"]
        relative = record["path"]
        digest = record["sha256"]
        if (not isinstance(record_id, str)
                or release_attestation.EVIDENCE_ID_RE.fullmatch(record_id) is None
                or record_id in RESERVED_EVIDENCE_IDS):
            raise ReleaseError(f"external evidence[{index}] has an invalid id")
        if kind not in INPUT_EVIDENCE_KINDS:
            raise ReleaseError(f"external evidence[{index}] has an unsupported kind")
        if (not isinstance(digest, str)
                or release_attestation.SHA256_RE.fullmatch(digest) is None):
            raise ReleaseError(f"external evidence[{index}] has an invalid SHA-256")
        if record_id in seen_ids or relative in seen_paths or kind in seen_kinds:
            raise ReleaseError("external evidence id, path, and kind must be unique")
        seen_ids.add(record_id)
        seen_paths.add(relative)
        seen_kinds.add(kind)
        evidence_path = _external_record_path(root, relative)
        if evidence_path.parent != root:
            raise ReleaseError("external evidence records must be direct manifest siblings")
        if release_attestation.sha256_file(evidence_path) != digest:
            raise ReleaseError(f"external evidence hash mismatch: {record_id}")
        document = _read_json(evidence_path, f"external evidence {record_id}")
        try:
            release_attestation._validate_semantic_evidence(
                record, document,
                artifact_sha256=stub_hash,
                source_commit=candidate["source_commit"],
                candidate_manifest_sha256=candidate_hash,
                gate={},
                evidence_path=evidence_path,
            )
        except release_attestation.ReleaseAttestationError as exc:
            raise ReleaseError(f"external evidence {record_id} is invalid: {exc}") from exc
        if kind in release_attestation.PROVIDER_SIGNED_KINDS:
            try:
                release_attestation.verify_provider_signature(
                    record, document, evidence_root=root, trust_policy=trust_policy)
            except release_attestation.ReleaseAttestationError as exc:
                raise ReleaseError(
                    f"external evidence {record_id} provider signature is invalid: {exc}") from exc
        if kind == "authenticode":
            for entry in release_attestation._subject_entries(document, kind):
                subject_path = _external_record_path(root, entry["subject_path"])
                live_receipt = _verify_windows_authenticode(subject_path)
                claimed_receipt = entry["verification_receipt"]
                identity_fields = (
                    "status", "signer_thumbprint", "signer_subject",
                    "signer_not_after_utc", "timestamp_thumbprint",
                    "timestamp_subject", "timestamp_not_after_utc",
                )
                if any(live_receipt[field] != claimed_receipt[field]
                       for field in identity_fields):
                    raise ReleaseError(
                        f"independent Authenticode identity differs for "
                        f"{entry['subject_id']}")
                allowed_signers = trust_policy["allowed_signer_thumbprints"]
                allowed_tsas = trust_policy["allowed_tsa_thumbprints"]
                if live_receipt["signer_thumbprint"] not in allowed_signers:
                    raise ReleaseError(
                        f"Authenticode signer is not pinned for {entry['subject_id']}")
                if live_receipt["timestamp_thumbprint"] not in allowed_tsas:
                    raise ReleaseError(
                        f"Authenticode timestamper is not pinned for {entry['subject_id']}")
        records.append((dict(record), evidence_path, document))
        documents[kind] = document
    if seen_kinds != INPUT_EVIDENCE_KINDS:
        raise ReleaseError(
            "external evidence kinds are incomplete: "
            + ", ".join(sorted(INPUT_EVIDENCE_KINDS - seen_kinds)))
    try:
        release_attestation._validate_subject_document_sets(registry, documents)
    except release_attestation.ReleaseAttestationError as exc:
        raise ReleaseError(f"external evidence subject coverage is invalid: {exc}") from exc
    return manifest, records


def _create_release_bundle_from_snapshot(
    *,
    candidate_dir: Path,
    external_evidence_manifest: Path,
    private_key: Ed25519PrivateKey,
    output_dir: Path,
    trust_store_path: Path,
    evidence_trust_store_path: Path,
    release_matrix_path: Path,
    snapshot_root: Path,
) -> Path:
    candidate_dir = candidate_dir.absolute()
    stub = candidate_dir / promote_stub.PREBUILT.name
    candidate_manifest = candidate_dir / promote_stub.PREBUILT_MANIFEST.name
    try:
        candidate = promote_stub.validate_candidate_bundle(stub, candidate_manifest)
    except (OSError, promote_stub.PromotionError) as exc:
        raise ReleaseError(f"candidate bundle validation failed: {exc}") from exc
    try:
        release_attestation.validate_candidate_identity(stub, candidate_manifest)
        _validate_candidate_git_provenance(candidate_dir, candidate)
    except (OSError, ReleaseError, release_attestation.ReleaseAttestationError) as exc:
        raise ReleaseError(f"candidate Git provenance validation failed: {exc}") from exc
    release_source_commit = _inspect_release_source(candidate["source_commit"])
    release_matrix = release_matrix_path.absolute()
    _validate_release_matrix_git(release_source_commit, release_matrix)
    rebuilt = _rebuild_candidate_stub(candidate, snapshot_root / "rebuild", stub)
    candidate_bytes = stub.read_bytes()
    if rebuilt != candidate_bytes or hashlib.sha256(rebuilt).hexdigest() != candidate["sha256"]:
        raise ReleaseError("deterministic release rebuild is not byte-identical to the candidate")
    replay_records = _replay_rebuilt_candidate(
        candidate, snapshot_root / "rebuild",
        snapshot_root / "rebuild" / "build" / "Release" / stub.name,
    )
    _external_manifest, records = _validate_external_manifest(
        external_evidence_manifest.resolve(), stub=stub,
        candidate_manifest=candidate_manifest, candidate=candidate,
        evidence_trust_store_path=evidence_trust_store_path,
    )
    native_record = next(item for item in records if item[0]["kind"] == "production-native")
    try:
        native = production_gate.load_evidence(native_record[1], artifact_path=stub)
        if native["source_commit"] != candidate["source_commit"]:
            raise ReleaseError("production-native evidence source commit is stale")
        if native["tracked_source_dirty"]:
            raise ReleaseError("production-native evidence came from dirty source")
        matrix = production_gate.load_matrix(release_matrix)
        gate = production_gate.evaluate(matrix, "all", native)
    except production_gate.MatrixError as exc:
        raise ReleaseError(f"production compatibility evidence is invalid: {exc}") from exc
    if (gate.get("ready") is not True or gate.get("blocker_count") != 0
            or gate.get("blockers") != []):
        ids = ", ".join(item.get("id", "unknown") for item in gate.get("blockers", []))
        raise ReleaseError(f"full production gate is red: {ids or 'unknown blockers'}")

    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = release_attestation.public_key_id(raw_public)
    trusted, release_key_ids = release_attestation._load_trust_store_details(
        trust_store_path)
    evidence_trust = release_attestation.load_evidence_trust_store(
        evidence_trust_store_path)
    if release_key_ids & evidence_trust["provider_key_ids"]:
        raise ReleaseError("release and external-evidence signing key roles overlap")
    if trusted.get(key_id) != raw_public:
        raise ReleaseError("release private key is not pinned and non-revoked")

    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise ReleaseError(f"release output already exists: {output_dir}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_dir.with_name(f".{output_dir.name}.{uuid.uuid4().hex}.tmp")
    temporary.mkdir()
    try:
        output_stub = temporary / stub.name
        output_manifest = temporary / candidate_manifest.name
        shutil.copyfile(stub, output_stub)
        shutil.copyfile(candidate_manifest, output_manifest)
        for candidate_record in candidate["evidence"]:
            try:
                candidate_source = release_attestation._contained_evidence_path(
                    candidate_dir, candidate_record["path"])
            except release_attestation.ReleaseAttestationError as exc:
                raise ReleaseError(f"candidate evidence copy failed: {exc}") from exc
            candidate_destination = temporary / candidate_record["path"]
            candidate_destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate_source, candidate_destination)
        evidence_dir = temporary / "release-evidence"
        evidence_dir.mkdir()
        signed_records: list[dict[str, str]] = []
        copied_external: dict[Path, str] = {}

        def copy_external(source: Path, destination: Path, expected_hash: str) -> None:
            actual_hash = release_attestation.sha256_file(source)
            if actual_hash != expected_hash:
                raise ReleaseError("external evidence backing hash changed after validation")
            prior = copied_external.get(destination)
            if prior is not None:
                if prior != actual_hash:
                    raise ReleaseError("external evidence files collide by path")
                return
            if destination.exists():
                raise ReleaseError("external evidence file collides with a release record")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            copied_external[destination] = actual_hash

        for record, source, document in records:
            destination = evidence_dir / record["path"]
            copy_external(source, destination, record["sha256"])
            if record["kind"] in {"authenticode", "scanner", "application", "clean-vm"}:
                for reference in release_attestation._document_file_references(
                        record["kind"], document):
                    backing_source = _external_record_path(
                        source.parent, reference["path"])
                    backing_destination = evidence_dir / reference["path"]
                    copy_external(
                        backing_source, backing_destination, reference["sha256"])
            if record["kind"] in release_attestation.PROVIDER_SIGNED_KINDS:
                signature_source = _external_record_path(
                    source.parent, record["provider_signature_path"])
                signature_destination = evidence_dir / record["provider_signature_path"]
                copy_external(
                    signature_source, signature_destination,
                    record["provider_signature_sha256"])
            signed_records.append({
                "id": record["id"],
                "kind": record["kind"],
                "path": destination.relative_to(temporary).as_posix(),
                "sha256": release_attestation.sha256_file(destination),
            })
        external_copy = evidence_dir / "external-manifest.json"
        shutil.copyfile(external_evidence_manifest, external_copy)
        signed_records.append({
            "id": "external-manifest",
            "kind": "external-manifest",
            "path": external_copy.relative_to(temporary).as_posix(),
            "sha256": release_attestation.sha256_file(external_copy),
        })
        gate_path = evidence_dir / "production-gate.json"
        _atomic_json(gate_path, gate)
        signed_records.append({
            "id": "production-gate",
            "kind": "production-gate",
            "path": gate_path.relative_to(temporary).as_posix(),
            "sha256": release_attestation.sha256_file(gate_path),
        })
        matrix_copy = evidence_dir / "release-matrix.json"
        shutil.copyfile(release_matrix, matrix_copy)
        signed_records.append({
            "id": "release-matrix",
            "kind": "release-matrix",
            "path": matrix_copy.relative_to(temporary).as_posix(),
            "sha256": release_attestation.sha256_file(matrix_copy),
        })
        rebuild_path = evidence_dir / "release-rebuild.json"
        _atomic_json(rebuild_path, {
            "schema": 1,
            "status": "passed",
            "source_commit": candidate["source_commit"],
            "candidate_manifest_sha256": release_attestation.sha256_file(output_manifest),
            "candidate_stub_sha256": candidate["sha256"],
            "rebuilt_stub_sha256": hashlib.sha256(rebuilt).hexdigest(),
            "byte_identical": rebuilt == candidate_bytes,
            "toolchain_binding_sha256": candidate["toolchain_binding_sha256"],
            "dvm_shuffle_seed": candidate["dvm_shuffle_seed"],
            "replay_commands": replay_records,
        })
        signed_records.append({
            "id": "release-rebuild",
            "kind": "release-rebuild",
            "path": rebuild_path.relative_to(temporary).as_posix(),
            "sha256": release_attestation.sha256_file(rebuild_path),
        })
        payload = {
            "schema": 1,
            "kind": release_attestation.ATTESTATION_KIND,
            "key_id": key_id,
            "production_ready": True,
            "artifact": {
                "name": output_stub.name,
                "sha256": release_attestation.sha256_file(output_stub),
                "size_bytes": output_stub.stat().st_size,
            },
            "candidate": {
                "manifest_name": output_manifest.name,
                "manifest_sha256": release_attestation.sha256_file(output_manifest),
                "source_commit": candidate["source_commit"],
                "candidate_policy_id": candidate.get("candidate_policy_id"),
                "candidate_policy_sha256": candidate["candidate_policy_sha256"],
                "promotion_tool_sha256": candidate["promotion_tool_sha256"],
                "candidate_matrix_sha256": candidate["production_matrix_sha256"],
                "toolchain_binding_sha256": candidate["toolchain_binding_sha256"],
            },
            "release_matrix_sha256": release_attestation.sha256_file(release_matrix),
            "release_source_commit": release_source_commit,
            "production_gate": gate,
            "evidence": sorted(signed_records, key=lambda item: item["id"]),
        }
        signature = private_key.sign(release_attestation.canonical_json_bytes(payload))
        attestation = {
            "schema": 1,
            "payload": payload,
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }
        output_attestation = release_attestation.release_attestation_path(output_stub)
        _atomic_json(output_attestation, attestation)
        release_attestation.verify_release_bundle(
            output_stub, manifest_path=output_manifest,
            attestation_path=output_attestation,
            trust_store_path=trust_store_path,
            evidence_trust_store_path=evidence_trust_store_path,
            matrix_path=release_matrix,
        )
        os.replace(temporary, output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return output_dir


def create_release_bundle(
    *,
    candidate_dir: Path,
    external_evidence_manifest: Path,
    private_key_path: Path,
    output_dir: Path,
    trust_store_path: Path | None = None,
    evidence_trust_store_path: Path | None = None,
    release_matrix_path: Path | None = None,
    private_key_password: bytes | None = None,
) -> Path:
    output_dir = output_dir.absolute()
    if output_dir.exists():
        raise ReleaseError(f"release output already exists: {output_dir}")
    private_key = _load_private_key(private_key_path.absolute(), private_key_password)
    snapshot_root = Path(tempfile.mkdtemp(prefix="lethe-release-input-"))
    try:
        snapshots = _snapshot_release_inputs(
            snapshot_root,
            candidate_dir=candidate_dir.absolute(),
            external_manifest=external_evidence_manifest.absolute(),
            matrix_path=(release_matrix_path or promote_stub.PRODUCTION_MATRIX).absolute(),
            trust_store_path=(trust_store_path or release_attestation.DEFAULT_TRUST_STORE).absolute(),
            evidence_trust_store_path=(
                evidence_trust_store_path
                or release_attestation.DEFAULT_EVIDENCE_TRUST_STORE).absolute(),
        )
        return _create_release_bundle_from_snapshot(
            candidate_dir=snapshots["candidate_dir"],
            external_evidence_manifest=snapshots["external_manifest"],
            private_key=private_key,
            output_dir=output_dir,
            trust_store_path=snapshots["trust"],
            evidence_trust_store_path=snapshots["evidence_trust"],
            release_matrix_path=snapshots["matrix"],
            snapshot_root=snapshot_root,
        )
    finally:
        shutil.rmtree(snapshot_root, ignore_errors=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--external-evidence-manifest", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    password = parser.add_mutually_exclusive_group()
    password.add_argument("--private-key-password-file", type=Path)
    password.add_argument("--private-key-password-env")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        key_password = None
        if args.private_key_password_file:
            password_path = args.private_key_password_file.absolute()
            if (not password_path.is_file() or password_path.is_symlink()
                    or bool(getattr(password_path, "is_junction", lambda: False)())):
                raise ReleaseError("private-key password file must be a regular file")
            key_password = password_path.read_bytes().rstrip(b"\r\n")
        elif args.private_key_password_env:
            value = os.environ.get(args.private_key_password_env)
            if value is None:
                raise ReleaseError("private-key password environment variable is unset")
            key_password = value.encode("utf-8")
        if key_password == b"":
            raise ReleaseError("private-key password cannot be empty")
        output = create_release_bundle(
            candidate_dir=args.candidate_dir,
            external_evidence_manifest=args.external_evidence_manifest,
            private_key_path=args.private_key,
            output_dir=args.output_dir,
            private_key_password=key_password,
        )
    except (OSError, ReleaseError, release_attestation.ReleaseAttestationError) as exc:
        print(f"Release: FAILED\n  - {exc}", file=sys.stderr)
        return 1
    print(f"Signed production-release bundle staged at {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
