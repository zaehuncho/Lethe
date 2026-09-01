"""Adversarial contracts for signed production-release bundles."""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packer import assemble, release_attestation
from tools import production_gate, promote_stub, release_stub


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "a" * 40
RELEASE_COMMIT = "b" * 40
REAL_VALIDATE_CANDIDATE_GIT = release_stub._validate_candidate_git_provenance


@pytest.fixture(autouse=True)
def _release_source_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        release_stub, "_inspect_release_source", lambda _candidate: RELEASE_COMMIT)
    monkeypatch.setattr(
        release_stub, "_validate_candidate_git_provenance",
        lambda _candidate_dir, _candidate: None)
    monkeypatch.setattr(
        release_stub, "_validate_release_matrix_git",
        lambda _commit, _matrix: None)
    monkeypatch.setattr(
        release_stub, "_rebuild_candidate_stub",
        lambda _candidate, _root, expected: expected.read_bytes())
    monkeypatch.setattr(
        release_stub, "_replay_rebuilt_candidate", _fixture_replay_records)
    monkeypatch.setattr(
        release_stub, "_verify_windows_authenticode", lambda _path: _auth_receipt())


def _json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def _candidate(tmp_path: Path) -> tuple[Path, Path, dict]:
    candidate = tmp_path / "candidate"
    evidence = candidate / "evidence"
    evidence.mkdir(parents=True)
    stub = candidate / "lethe_stub_x64.dll"
    stub.write_bytes((ROOT / "stub/prebuilt/lethe_stub_x64.dll").read_bytes())
    image = assemble._StubImage(stub.read_bytes())
    tls_rva, _tls_size = image.dir(assemble.DIR_TLS)
    callbacks_va = struct.unpack_from("<Q", image.read_at_rva(tls_rva, 40), 24)[0]
    callbacks_rva = callbacks_va - image.image_base
    callback_rva = image.sections[0].rva + 0x900
    sites = (
        image.find_export_rva("StubExeEntry"),
        image.find_export_rva("StubDllMain"),
        callback_rva,
    )
    target = image.sections[0].rva + 0x800
    blob = bytearray(stub.read_bytes())
    callbacks_offset = image.rva_to_off(callbacks_rva)
    struct.pack_into(
        "<QQ", blob, callbacks_offset, image.image_base + callback_rva, 0)
    for site in sites:
        assert site is not None
        offset = image.rva_to_off(site)
        blob[offset:offset + 5] = b"\xe9" + struct.pack("<i", target - site - 5)
    stub.write_bytes(blob)
    policy = promote_stub.candidate_policy_payload()
    policy_path = evidence / "candidate-policy.json"
    matrix_path = evidence / "candidate-production-matrix.json"
    promoter_path = evidence / "candidate-promoter.py"
    promote_stub.atomic_write_json(policy_path, policy)
    matrix_path.write_bytes((ROOT / "docs/production_compatibility.json").read_bytes())
    promoter_path.write_bytes(Path(promote_stub.__file__).read_bytes())
    artifact_hash = release_attestation.sha256_file(stub)
    matrix = production_gate.load_matrix(matrix_path)
    checks = sorted({
        check for feature in matrix["features"]
        for check in feature.get("native_checks", [])
    })
    native = {
        "schema": 1, "source_commit": SOURCE_COMMIT,
        "tracked_source_dirty": False, "stub_path": stub.name,
        "stub_sha256": artifact_hash, "passed": len(checks), "total": len(checks),
        "ready": True,
        "tests": [{"id": check, "status": "passed"} for check in checks],
    }
    _json(evidence / "production-evidence.json", native)
    gate = production_gate.evaluate(
        matrix, "all", production_gate.load_evidence(
            evidence / "production-evidence.json", artifact_path=stub))

    def command(name: str, path_name: str, *, bound: bool, stdout: str = "ok\n",
                exit_code: int = 0, argv: list[str] | None = None) -> None:
        promote_stub._record(
            evidence / path_name,
            promote_stub.CommandRecord(
                name=name, argv=argv or ["tool://fixture.exe"],
                exit_code=exit_code, stdout=stdout, stderr="",
                source_commit=SOURCE_COMMIT,
                artifact_sha256=artifact_hash if bound else None,
            ),
        )

    command("locked-dependency-sync", "uv-sync.json", bound=False)
    command("fresh-cmake-configure", "cmake-configure.json", bound=False)
    command("fresh-w4-wx-stub-build", "cmake-build.json", bound=False)
    command("ctest-inventory", "ctest-inventory.json", bound=True,
            stdout=json.dumps({"tests": [{"name": str(i)} for i in range(4)]}))
    command("ctest", "ctest.json", bound=True)
    command("candidate-bound-native-runtime-hardening", "runtime-hardening.json",
            bound=True, stdout="3 passed in 1.00s\n",
            argv=["tool://python.exe", "-m", "pytest", "-q", "-p",
                  "no:cacheprovider",
                  "repo://tests/test_native_runtime_hardening_stress.py"])
    command("roundtrip-fixture-build", "roundtrip-fixture-build.json", bound=True)
    command("exe-dll-roundtrip", "roundtrip.json", bound=True,
            stdout="11/11 passed -- PASS\n")
    command("production-corpus-build", "production-corpus-build.json", bound=True)
    command("production-corpus", "production-corpus.json", bound=True)
    command("all-scope-production-gate", "production-gate.json", bound=True,
            stdout=json.dumps(gate), exit_code=0 if gate["ready"] else 1)
    _json(evidence / "stub-entrypoints.json", {
        "schema": 1, **promote_stub.inspect_stub_entrypoints(stub)})

    evidence_paths = [candidate / relative for relative in
                      sorted(promote_stub.REQUIRED_CANDIDATE_EVIDENCE)]
    manifest = promote_stub.build_manifest(
        staged_stub=stub,
        source={"source_commit": SOURCE_COMMIT, "locked_files": {
            "pyproject.toml": hashlib.sha256(b"locked-project").hexdigest(),
            "uv.lock": hashlib.sha256(b"locked-uv").hexdigest()}},
        host={"python_version": "3.12.10", "uv_version": promote_stub.SUPPORTED_UV,
              "cmake_version": "4.4.0", "ctest_version": "4.4.0"},
        toolchain={"cmake_generator": promote_stub.SUPPORTED_GENERATOR,
                   "cmake_platform": promote_stub.SUPPORTED_PLATFORM,
                   "compiler_id": "MSVC", "compiler_version": "19.44.35219.0",
                   "compile_policy": "/W4 /WX /Brepro",
                   "link_policy": "/Brepro /INCREMENTAL:NO"},
        dvm_provenance={"dvm_shuffle_seed": "22" * 32,
                        "dvm_opcode_mapping_sha256": "2" * 64,
                        "dvm_handler_variant_sha256": "3" * 64,
                        "dvm_python_map_sha256": "4" * 64,
                        "dvm_native_map_sha256": "5" * 64,
                        "dvm_rolling": True, "dvm_paged_runtime": True},
        roundtrip_counts=(11, 11), ctest_count=4,
        evidence_paths=evidence_paths, stage_dir=candidate, gate_payload=gate,
    )
    manifest_path = candidate / "lethe_stub_x64.manifest.json"
    _json(manifest_path, manifest)
    return stub, manifest_path, manifest


def _green_matrix(path: Path) -> dict:
    matrix = json.loads((ROOT / "docs/production_compatibility.json").read_text(
        encoding="utf-8"))
    for feature in matrix["features"]:
        feature["status"] = "proven"
        feature.pop("blocker", None)
    _json(path, matrix)
    return matrix


def _trust(tmp_path: Path, key: Ed25519PrivateKey, *, revoked: bool = False) -> Path:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = release_attestation.public_key_id(raw)
    path = tmp_path / f"trust-{key_id[:12]}-{'revoked' if revoked else 'active'}.json"
    _json(path, {
        "schema": 1,
        "algorithm": "ed25519",
        "keys": [{
            "id": key_id,
            "public_key_base64": base64.b64encode(raw).decode("ascii"),
            "revoked": revoked,
        }],
    })
    return path


def _auth_receipt() -> dict:
    return {
        "tool_name": "powershell-get-authenticodesignature",
        "tool_version": "5.1.26100.1",
        "verified_at_utc": "2026-09-01T12:00:00Z",
        "status": "valid",
        "signer_thumbprint": "1" * 40,
        "signer_subject": "CN=Lethe Test Signer",
        "signer_not_after_utc": "2030-01-01T00:00:00Z",
        "timestamp_thumbprint": "2" * 40,
        "timestamp_subject": "CN=Lethe Test Timestamp",
        "timestamp_not_after_utc": "2030-01-01T00:00:00Z",
    }


def _fixture_replay_records(candidate: dict, _root: Path, _stub: Path) -> list[dict]:
    return [{
        "id": replay_id,
        "status": "passed",
        "argv": [f"tool://{replay_id}"],
        "exit_code": 0,
        "artifact_sha256": candidate["sha256"],
        "stdout_sha256": hashlib.sha256(f"{replay_id}:ok".encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
    } for replay_id in sorted(release_attestation.REQUIRED_RELEASE_REPLAY_IDS)]


def _signed_subject_bytes(stub_bytes: bytes, *, is_dll: bool) -> bytes:
    image = bytearray(stub_bytes)
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    characteristics = struct.unpack_from("<H", image, pe_offset + 22)[0]
    if is_dll:
        characteristics |= 0x2000
    else:
        characteristics &= ~0x2000
    struct.pack_into("<H", image, pe_offset + 22, characteristics)
    optional_offset = pe_offset + 24
    certificate_offset = (len(image) + 7) & ~7
    image.extend(bytes(certificate_offset - len(image)))
    certificate_payload = b"fixture-pkcs7-signed-data"
    certificate_length = 8 + len(certificate_payload)
    certificate = struct.pack("<IHH", certificate_length, 0x0200, 0x0002)
    certificate += certificate_payload
    certificate += bytes((8 - len(certificate) % 8) % 8)
    image.extend(certificate)
    security_entry = optional_offset + 112 + 4 * 8
    struct.pack_into("<II", image, security_entry, certificate_offset, len(certificate))
    return bytes(image)


def _backing(root: Path, relative: str, content: str) -> tuple[str, str]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return relative, release_attestation.sha256_file(path)


def _vm_cells(root: Path, subject_id: str) -> list[dict]:
    cells = []
    for cell_id, (release, vbs, hvci, hyper_v) in (
            release_attestation.REQUIRED_VM_CELLS.items()):
        log_path, log_hash = _backing(
            root, f"vm/{subject_id}/{cell_id}.log", f"{subject_id}:{cell_id}:passed\n")
        cells.append({
            "cell_id": cell_id,
            "status": "passed",
            "os_release": release,
            "os_build": "26100.4946" if release.startswith("windows-11") else "19045.6216",
            "patch_level": "KB5064081",
            "arch": "x64",
            "secure_boot": True,
            "vbs_enabled": vbs,
            "hvci_enabled": hvci,
            "hyper_v_enabled": hyper_v,
            "image_id": f"image-{cell_id}",
            "snapshot_id": f"snapshot-{subject_id}-{cell_id}",
            "runner_sha256": hashlib.sha256(b"clean-vm-runner-v1").hexdigest(),
            "result_log_path": log_path,
            "result_log_sha256": log_hash,
        })
    return cells


def _external(
    tmp_path: Path,
    stub: Path,
    candidate_manifest: Path,
    release_matrix: dict,
    *,
    provider_key: Ed25519PrivateKey | None = None,
) -> Path:
    root = tmp_path / "external"
    root.mkdir()
    artifact_hash = release_attestation.sha256_file(stub)
    manifest_hash = release_attestation.sha256_file(candidate_manifest)
    checks = sorted({
        check
        for feature in release_matrix["features"]
        for check in feature.get("native_checks", [])
    })
    native = {
        "schema": 1,
        "source_commit": SOURCE_COMMIT,
        "candidate_manifest_sha256": manifest_hash,
        "tracked_source_dirty": False,
        "stub_path": stub.name,
        "stub_sha256": artifact_hash,
        "passed": len(checks),
        "total": len(checks),
        "ready": True,
        "tests": [{"id": check, "status": "passed"} for check in checks],
    }
    subjects = root / "subjects"
    subjects.mkdir()
    dll_subject = subjects / "protected.dll"
    exe_subject = subjects / "protected.exe"
    dll_subject.write_bytes(_signed_subject_bytes(stub.read_bytes(), is_dll=True))
    exe_subject.write_bytes(_signed_subject_bytes(stub.read_bytes(), is_dll=False))
    registry = []
    for subject_id, subject_kind, subject in (
        ("representative-exe", "exe", exe_subject),
        ("representative-dll", "dll", dll_subject),
    ):
        pack_path, pack_hash = _backing(
            root, f"pack-reports/{subject_id}.json",
            json.dumps({"schema": 1, "subject_id": subject_id, "status": "passed"}))
        profile_path, profile_hash = _backing(
            root, f"protection-profiles/{subject_id}.json",
            json.dumps({"schema": 1, "subject_id": subject_id,
                        "profile": "production-representative"}))
        registry.append({
            "subject_id": subject_id,
            "subject_kind": subject_kind,
            "format": release_attestation.SUBJECT_FORMAT,
            "subject_path": subject.relative_to(root).as_posix(),
            "subject_sha256": release_attestation.sha256_file(subject),
            "subject_size_bytes": subject.stat().st_size,
            "input_sha256": hashlib.sha256(f"input:{subject_id}".encode()).hexdigest(),
            "pack_report_path": pack_path,
            "pack_report_sha256": pack_hash,
            "protection_profile_path": profile_path,
            "protection_profile_sha256": profile_hash,
            "protected_with_stub_sha256": artifact_hash,
            "source_commit": SOURCE_COMMIT,
            "candidate_manifest_sha256": manifest_hash,
        })
    scanners = [
        {"scanner_id": "microsoft-defender", "tool_name": "Microsoft Defender",
         "tool_version": "4.18.26070.2004", "definitions_version": "1.437.42.0"},
        {"scanner_id": "independent-engine", "tool_name": "Independent Scanner",
         "tool_version": "3.2.1", "definitions_version": "2026.09.01"},
    ]
    common = {
        "schema": 1, "status": "passed", "source_commit": SOURCE_COMMIT,
        "candidate_manifest_sha256": manifest_hash,
    }
    scanner_subjects = []
    vm_subjects = []
    application_subjects = []
    for item in registry:
        scans = []
        for scanner in scanners:
            scanner_id = scanner["scanner_id"]
            output_path, output_hash = _backing(
                root, f"scanner/{item['subject_id']}/{scanner_id}.output.json",
                json.dumps({"status": "clean", "detections": 0}))
            receipt_path, receipt_hash = _backing(
                root, f"scanner/{item['subject_id']}/{scanner_id}.receipt.json",
                json.dumps({"scanner_id": scanner_id, "verified": True}))
            scans.append({
                "scanner_id": scanner_id,
                "status": "passed",
                "detections": 0,
                "scan_time_utc": "2026-09-01T12:00:00Z",
                "output_path": output_path,
                "output_sha256": output_hash,
                "receipt_path": receipt_path,
                "receipt_sha256": receipt_hash,
            })
        scanner_subjects.append({**item, "scans": scans})
        vm_subjects.append({
            **item, "passed": 4, "total": 4,
            "cells": _vm_cells(root, item["subject_id"]),
        })
        workflows = []
        for workflow_id in ("startup", "shutdown"):
            result_path, result_hash = _backing(
                root, f"application/{item['subject_id']}/{workflow_id}.result.json",
                json.dumps({"workflow_id": workflow_id, "status": "passed"}))
            log_path, log_hash = _backing(
                root, f"application/{item['subject_id']}/{workflow_id}.log",
                f"{item['subject_id']}:{workflow_id}:passed\n")
            workflows.append({
                "workflow_id": workflow_id,
                "status": "passed",
                "result_path": result_path,
                "result_sha256": result_hash,
                "log_path": log_path,
                "log_sha256": log_hash,
            })
        application_subjects.append({
            **item, "passed": 2, "total": 2, "workflows": workflows,
        })

    documents = {
        "authenticode": {
            **common,
            "subjects": [{**item, "verification_receipt": _auth_receipt()}
                         for item in registry],
        },
        "scanner": {
            **common, "scanners": scanners,
            "subjects": scanner_subjects,
        },
        "clean-vm": {
            **common, "artifact_sha256": artifact_hash,
            "matrix": vm_subjects,
        },
        "application": {
            **common,
            "matrix": application_subjects,
        },
        "production-native": native,
    }
    provider_key = provider_key or Ed25519PrivateKey.generate()
    provider_public = provider_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    provider_id = release_attestation.public_key_id(provider_public)
    _json(tmp_path / "evidence-trust.json", {
        "schema": 1,
        "algorithm": "ed25519",
        "providers": [{
            "id": provider_id,
            "public_key_base64": base64.b64encode(provider_public).decode("ascii"),
            "revoked": False,
            "allowed_kinds": sorted(release_attestation.PROVIDER_SIGNED_KINDS),
        }],
        "authenticode": {
            "allowed_signer_thumbprints": [_auth_receipt()["signer_thumbprint"]],
            "allowed_tsa_thumbprints": [_auth_receipt()["timestamp_thumbprint"]],
        },
    })
    records = []
    for kind, document in documents.items():
        evidence_path = root / f"{kind}.json"
        _json(evidence_path, document)
        record = {
            "id": kind,
            "kind": kind,
            "path": evidence_path.name,
            "sha256": release_attestation.sha256_file(evidence_path),
        }
        if kind in release_attestation.PROVIDER_SIGNED_KINDS:
            payload = release_attestation.provider_signature_payload(
                key_id=provider_id, evidence_kind=kind, document=document)
            envelope = {
                "schema": 1,
                "payload": payload,
                "signature_base64": base64.b64encode(provider_key.sign(
                    release_attestation.canonical_json_bytes(payload))).decode("ascii"),
            }
            signature_path = root / "provider-signatures" / f"{kind}.json"
            _json(signature_path, envelope)
            record.update({
                "provider_signature_path": signature_path.relative_to(root).as_posix(),
                "provider_signature_sha256": release_attestation.sha256_file(
                    signature_path),
            })
        records.append(record)
    external = root / "external.json"
    _json(external, {
        "schema": 1,
        "candidate_stub_sha256": artifact_hash,
        "candidate_manifest_sha256": manifest_hash,
        "source_commit": SOURCE_COMMIT,
        "subjects": registry,
        "records": records,
    })
    return external


def _release(tmp_path: Path):
    stub, manifest, _candidate_payload = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest, matrix)
    key = Ed25519PrivateKey.generate()
    trust = _trust(tmp_path, key)
    private = tmp_path / "release-key.pem"
    private.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    output = release_stub.create_release_bundle(
        candidate_dir=stub.parent,
        external_evidence_manifest=external,
        private_key_path=private,
        output_dir=tmp_path / "release",
        trust_store_path=trust,
        evidence_trust_store_path=_evidence_trust(external),
        release_matrix_path=matrix_path,
    )
    return output, trust, matrix_path, key, _evidence_trust(external)


def _refresh_external_record(external: Path, kind: str) -> dict:
    manifest = json.loads(external.read_text(encoding="utf-8"))
    record = next(item for item in manifest["records"] if item["kind"] == kind)
    record["sha256"] = release_attestation.sha256_file(external.parent / record["path"])
    _json(external, manifest)
    return manifest


def _evidence_trust(external: Path) -> Path:
    return external.parent.parent / "evidence-trust.json"


def test_signed_release_accepts_different_green_release_matrix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output, trust, matrix, _key, evidence_trust = _release(tmp_path)
    stub = output / "lethe_stub_x64.dll"
    payload = release_attestation.verify_release_bundle(
        stub, trust_store_path=trust, evidence_trust_store_path=evidence_trust,
        matrix_path=matrix)
    assert payload["production_ready"] is True
    assert payload["candidate"]["candidate_matrix_sha256"] != payload["release_matrix_sha256"]

    monkeypatch.setattr(release_attestation, "DEFAULT_TRUST_STORE", trust)
    monkeypatch.setattr(
        release_attestation, "DEFAULT_EVIDENCE_TRUST_STORE", evidence_trust)
    monkeypatch.setattr(release_attestation, "DEFAULT_MATRIX", matrix)
    assemble._validate_release_stub_manifest(str(stub), stub.read_bytes())


def test_unsigned_claim_wrong_key_revocation_and_tampering_fail(
    tmp_path: Path,
) -> None:
    output, trust, matrix, key, evidence_trust = _release(tmp_path)
    stub = output / "lethe_stub_x64.dll"
    attestation = output / "lethe_stub_x64.release.json"

    wrong_trust = _trust(tmp_path, Ed25519PrivateKey.generate())
    with pytest.raises(release_attestation.ReleaseAttestationError, match="unknown or revoked"):
        release_attestation.verify_release_bundle(
            stub, trust_store_path=wrong_trust,
            evidence_trust_store_path=evidence_trust, matrix_path=matrix)
    revoked = _trust(tmp_path, key, revoked=True)
    with pytest.raises(release_attestation.ReleaseAttestationError, match="unknown or revoked"):
        release_attestation.verify_release_bundle(
            stub, trust_store_path=revoked,
            evidence_trust_store_path=evidence_trust, matrix_path=matrix)

    envelope = json.loads(attestation.read_text(encoding="utf-8"))
    envelope["payload"]["production_ready"] = False
    _json(attestation, envelope)
    with pytest.raises(release_attestation.ReleaseAttestationError, match="signature"):
        release_attestation.verify_release_bundle(
            stub, trust_store_path=trust,
            evidence_trust_store_path=evidence_trust, matrix_path=matrix)


def test_signed_evidence_hash_and_path_escape_fail(tmp_path: Path) -> None:
    output, trust, matrix, _key, evidence_trust = _release(tmp_path)
    stub = output / "lethe_stub_x64.dll"
    evidence = output / "release-evidence/scanner.json"
    document = json.loads(evidence.read_text(encoding="utf-8"))
    document["detections"] = 1
    _json(evidence, document)
    with pytest.raises(release_attestation.ReleaseAttestationError, match="hash mismatch"):
        release_attestation.verify_release_bundle(
            stub, trust_store_path=trust,
            evidence_trust_store_path=evidence_trust, matrix_path=matrix)


def test_signed_subject_tamper_and_resigned_path_escape_fail(tmp_path: Path) -> None:
    output, trust, matrix, key, evidence_trust = _release(tmp_path)
    stub = output / "lethe_stub_x64.dll"
    subject = output / "release-evidence/subjects/protected.exe"
    subject.write_bytes(b"tampered signed application")
    with pytest.raises(release_attestation.ReleaseAttestationError, match="subject hash"):
        release_attestation.verify_release_bundle(
            stub, trust_store_path=trust,
            evidence_trust_store_path=evidence_trust, matrix_path=matrix)

    source_subject = output / "release-evidence/subjects/protected.dll"
    restored = bytearray(source_subject.read_bytes())
    pe_offset = struct.unpack_from("<I", restored, 0x3C)[0]
    characteristics = struct.unpack_from("<H", restored, pe_offset + 22)[0]
    struct.pack_into("<H", restored, pe_offset + 22, characteristics & ~0x2000)
    subject.write_bytes(restored)
    attestation = output / "lethe_stub_x64.release.json"
    envelope = json.loads(attestation.read_text(encoding="utf-8"))
    scanner = next(
        record for record in envelope["payload"]["evidence"]
        if record["kind"] == "scanner")
    scanner["path"] = "../scanner.json"
    envelope["signature_base64"] = base64.b64encode(key.sign(
        release_attestation.canonical_json_bytes(envelope["payload"]))).decode("ascii")
    _json(attestation, envelope)
    with pytest.raises(release_attestation.ReleaseAttestationError, match="canonical relative"):
        release_attestation.verify_release_bundle(
            stub, trust_store_path=trust,
            evidence_trust_store_path=evidence_trust, matrix_path=matrix)


def test_release_signer_replays_candidate_evidence_and_supports_encrypted_key(
    tmp_path: Path,
) -> None:
    stub, manifest_path, manifest = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    key = Ed25519PrivateKey.generate()
    trust = _trust(tmp_path, key)
    password = b"fixture-password"
    private = tmp_path / "encrypted-release-key.pem"
    private.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    ))
    external = _external(tmp_path, stub, manifest_path, matrix)
    output = release_stub.create_release_bundle(
        candidate_dir=stub.parent, external_evidence_manifest=external,
        private_key_path=private, private_key_password=password,
        output_dir=tmp_path / "encrypted-release", trust_store_path=trust,
        evidence_trust_store_path=_evidence_trust(external),
        release_matrix_path=matrix_path,
    )
    assert (output / "lethe_stub_x64.release.json").is_file()

    command_path = stub.parent / "evidence/uv-sync.json"
    command = json.loads(command_path.read_text(encoding="utf-8"))
    command["exit_code"] = 1
    _json(command_path, command)
    for record in manifest["evidence"]:
        if record["path"] == "evidence/uv-sync.json":
            record["sha256"] = release_attestation.sha256_file(command_path)
    _json(manifest_path, manifest)
    with pytest.raises(release_stub.ReleaseError, match="candidate bundle validation failed"):
        release_stub.create_release_bundle(
            candidate_dir=stub.parent, external_evidence_manifest=external,
            private_key_path=private, private_key_password=password,
            output_dir=tmp_path / "forged-release", trust_store_path=trust,
            evidence_trust_store_path=_evidence_trust(external),
            release_matrix_path=matrix_path,
        )


def test_legacy_environment_cannot_bypass_explicit_stub_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = tmp_path / "raw.dll"
    stub.write_bytes((ROOT / "stub/prebuilt/lethe_stub_x64.dll").read_bytes())
    monkeypatch.setenv("LETHE_ALLOW_UNVERIFIED_STUB_FOR_TESTS", "1")
    with pytest.raises(assemble.AssembleError, match="verified candidate"):
        assemble._load_stub(str(stub))
    assemble._load_stub(str(stub), allow_unverified_stub_for_tests=True)


def test_release_signing_requires_byte_identical_clean_source_rebuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub, manifest, _candidate_payload = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest, matrix)
    key = Ed25519PrivateKey.generate()
    trust = _trust(tmp_path, key)
    private = tmp_path / "release-key.pem"
    private.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    monkeypatch.setattr(
        release_stub, "_rebuild_candidate_stub",
        lambda _candidate, _root, _expected: b"not-the-candidate",
    )

    with pytest.raises(release_stub.ReleaseError, match="not byte-identical"):
        release_stub.create_release_bundle(
            candidate_dir=stub.parent, external_evidence_manifest=external,
            private_key_path=private, output_dir=tmp_path / "release",
            trust_store_path=trust,
            evidence_trust_store_path=_evidence_trust(external),
            release_matrix_path=matrix_path,
        )
    assert not (tmp_path / "release").exists()


def test_candidate_promoter_snapshot_must_match_tracked_candidate_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub, _manifest_path, candidate = _candidate(tmp_path)
    promoter = stub.parent / "evidence/candidate-promoter.py"
    tracked_promoter = promoter.read_bytes()
    matrix = (stub.parent / "evidence/candidate-production-matrix.json").read_bytes()
    promoter.write_bytes(tracked_promoter + b"\n# forged snapshot\n")
    candidate["promotion_tool_sha256"] = release_attestation.sha256_file(promoter)
    blobs = {
        "pyproject.toml": b"locked-project",
        "uv.lock": b"locked-uv",
        "tools/promote_stub.py": tracked_promoter,
        "docs/production_compatibility.json": matrix,
    }
    monkeypatch.setattr(
        release_stub, "_git",
        lambda *args: SOURCE_COMMIT + "\n" if args[:2] == (
            "rev-parse", "--verify") else "",
    )
    monkeypatch.setattr(release_stub, "_git_blob", lambda _commit, path: blobs[path])

    with pytest.raises(release_stub.ReleaseError, match="does not match its Git source"):
        REAL_VALIDATE_CANDIDATE_GIT(stub.parent, candidate)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("exe-only", "not representative"),
        ("defender-only", "independent scanner"),
        ("shallow-vm", "four-cell full pass"),
    ],
)
def test_external_evidence_requires_both_lanes_and_nontrivial_independent_checks(
    tmp_path: Path, mutation: str, message: str,
) -> None:
    stub, manifest_path, candidate = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    external_payload = json.loads(external.read_text(encoding="utf-8"))
    if mutation == "exe-only":
        external_payload["subjects"] = [
            item for item in external_payload["subjects"]
            if item["subject_kind"] == "exe"
        ]
        _json(external, external_payload)
    elif mutation == "defender-only":
        scanner = external.parent / "scanner.json"
        scanner_payload = json.loads(scanner.read_text(encoding="utf-8"))
        scanner_payload["scanners"] = ["microsoft-defender"]
        _json(scanner, scanner_payload)
        _refresh_external_record(external, "scanner")
    else:
        clean_vm = external.parent / "clean-vm.json"
        clean_payload = json.loads(clean_vm.read_text(encoding="utf-8"))
        for entry in clean_payload["matrix"]:
            entry["passed"] = 3
            entry["total"] = 3
            entry["cells"] = entry["cells"][:3]
        _json(clean_vm, clean_payload)
        _refresh_external_record(external, "clean-vm")

    with pytest.raises(release_stub.ReleaseError, match=message):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate,
            evidence_trust_store_path=_evidence_trust(external),
        )


def test_release_inputs_are_validated_only_from_immutable_snapshot(tmp_path: Path) -> None:
    stub, manifest_path, _candidate_payload = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    trust = _trust(tmp_path, Ed25519PrivateKey.generate())
    snapshot_root = tmp_path / "snapshot"
    snapshot_root.mkdir()
    snapshots = release_stub._snapshot_release_inputs(
        snapshot_root, candidate_dir=stub.parent,
        external_manifest=external, matrix_path=matrix_path,
        trust_store_path=trust,
        evidence_trust_store_path=_evidence_trust(external),
    )
    snapshot_stub_hash = release_attestation.sha256_file(
        snapshots["candidate_dir"] / stub.name)
    snapshot_external_hash = release_attestation.sha256_file(
        snapshots["external_manifest"])
    stub.write_bytes(b"source changed after snapshot")
    external.write_text("{}\n", encoding="utf-8")
    matrix_path.write_text("{}\n", encoding="utf-8")
    trust.write_text("{}\n", encoding="utf-8")
    _evidence_trust(external).write_text("{}\n", encoding="utf-8")

    assert release_attestation.sha256_file(
        snapshots["candidate_dir"] / stub.name) == snapshot_stub_hash
    assert release_attestation.sha256_file(
        snapshots["external_manifest"]) == snapshot_external_hash
    assert snapshots["matrix"].read_text(encoding="utf-8") != "{}\n"
    assert snapshots["trust"].read_text(encoding="utf-8") != "{}\n"
    assert snapshots["evidence_trust"].read_text(encoding="utf-8") != "{}\n"


def test_resigned_green_gate_claim_is_replayed_against_bundled_evidence(
    tmp_path: Path,
) -> None:
    output, trust, matrix, key, evidence_trust = _release(tmp_path)
    stub = output / "lethe_stub_x64.dll"
    gate_path = output / "release-evidence/production-gate.json"
    gate = json.loads(gate_path.read_text(encoding="utf-8"))
    gate["forged-green-claim"] = True
    _json(gate_path, gate)
    attestation = output / "lethe_stub_x64.release.json"
    envelope = json.loads(attestation.read_text(encoding="utf-8"))
    envelope["payload"]["production_gate"] = gate
    gate_record = next(
        item for item in envelope["payload"]["evidence"]
        if item["kind"] == "production-gate")
    gate_record["sha256"] = release_attestation.sha256_file(gate_path)
    envelope["signature_base64"] = base64.b64encode(key.sign(
        release_attestation.canonical_json_bytes(envelope["payload"]))).decode("ascii")
    _json(attestation, envelope)

    with pytest.raises(
        release_attestation.ReleaseAttestationError,
        match="evidence-aware evaluation",
    ):
        release_attestation.verify_release_bundle(
            stub, trust_store_path=trust,
            evidence_trust_store_path=evidence_trust, matrix_path=matrix)


@pytest.mark.parametrize(
    ("relative", "message"),
    [
        ("release-evidence/scanner.json:payload", "malformed"),
        ("release-evidence/CON.json", "Windows-reserved"),
        ("release-evidence/trailing. ", "Windows-reserved"),
    ],
)
def test_release_evidence_rejects_windows_alias_paths(
    tmp_path: Path, relative: str, message: str,
) -> None:
    with pytest.raises(release_attestation.ReleaseAttestationError, match=message):
        release_attestation._contained_evidence_path(tmp_path, relative)


def test_release_evidence_rejects_symlink_before_resolution(tmp_path: Path) -> None:
    evidence = tmp_path / "release-evidence"
    evidence.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    linked = evidence / "linked.json"
    try:
        linked.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows host")
    with pytest.raises(release_attestation.ReleaseAttestationError, match="symlinks or junctions"):
        release_attestation._contained_evidence_path(
            tmp_path, "release-evidence/linked.json")


def test_subject_pe_rejects_arm64_bad_sections_and_missing_certificate(
    tmp_path: Path,
) -> None:
    original = _signed_subject_bytes(
        (ROOT / "stub/prebuilt/lethe_stub_x64.dll").read_bytes(), is_dll=False)
    subject = tmp_path / "subject.exe"
    subject.write_bytes(original)
    release_attestation._validate_subject_pe(
        subject, "exe", require_authenticode=True)
    pe_offset = struct.unpack_from("<I", original, 0x3C)[0]

    arm64 = bytearray(original)
    struct.pack_into("<H", arm64, pe_offset + 4, 0xAA64)
    subject.write_bytes(arm64)
    with pytest.raises(release_attestation.ReleaseAttestationError, match="valid PE"):
        release_attestation._validate_subject_pe(
            subject, "exe", require_authenticode=True)

    bad_section = bytearray(original)
    optional_size = struct.unpack_from("<H", bad_section, pe_offset + 20)[0]
    first_section = pe_offset + 24 + optional_size
    struct.pack_into("<II", bad_section, first_section + 16, 0x1000, len(bad_section) + 1)
    subject.write_bytes(bad_section)
    with pytest.raises(release_attestation.ReleaseAttestationError, match="valid PE"):
        release_attestation._validate_subject_pe(
            subject, "exe", require_authenticode=True)

    unsigned = bytearray(original)
    security_entry = pe_offset + 24 + 112 + 4 * 8
    struct.pack_into("<II", unsigned, security_entry, 0, 0)
    subject.write_bytes(unsigned)
    with pytest.raises(release_attestation.ReleaseAttestationError, match="valid PE"):
        release_attestation._validate_subject_pe(
            subject, "exe", require_authenticode=True)


def test_release_signer_independently_rechecks_authenticode_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub, manifest_path, candidate = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    mismatched = _auth_receipt()
    mismatched["signer_not_after_utc"] = "2031-01-01T00:00:00Z"
    calls: list[Path] = []

    def verify(path: Path) -> dict:
        calls.append(path)
        return mismatched

    monkeypatch.setattr(release_stub, "_verify_windows_authenticode", verify)
    with pytest.raises(release_stub.ReleaseError, match="identity differs"):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate,
            evidence_trust_store_path=_evidence_trust(external),
        )
    assert len(calls) == 1


def test_scanner_subject_must_include_every_declared_engine(tmp_path: Path) -> None:
    stub, manifest_path, candidate = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    scanner = external.parent / "scanner.json"
    document = json.loads(scanner.read_text(encoding="utf-8"))
    document["subjects"][0]["scans"] = document["subjects"][0]["scans"][:1]
    _json(scanner, document)
    _refresh_external_record(external, "scanner")
    with pytest.raises(release_stub.ReleaseError, match="engine set is incomplete"):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate,
            evidence_trust_store_path=_evidence_trust(external),
        )


def test_subject_registry_requires_pack_and_input_identity(tmp_path: Path) -> None:
    stub, manifest_path, candidate = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    manifest = json.loads(external.read_text(encoding="utf-8"))
    del manifest["subjects"][0]["pack_report_sha256"]
    _json(external, manifest)
    with pytest.raises(release_stub.ReleaseError, match=r"registry\[0\] is malformed"):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate,
            evidence_trust_store_path=_evidence_trust(external),
        )


def test_forged_candidate_command_claim_cannot_sign_when_release_replay_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub, manifest, _candidate_payload = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest, matrix)
    key = Ed25519PrivateKey.generate()
    trust = _trust(tmp_path, key)
    private = tmp_path / "release-key.pem"
    private.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))

    def fail_replay(_candidate: dict, _root: Path, _stub: Path) -> list[dict]:
        raise release_stub.ReleaseError("release replay ctest failed with exit 1")

    monkeypatch.setattr(release_stub, "_replay_rebuilt_candidate", fail_replay)
    with pytest.raises(release_stub.ReleaseError, match="release replay ctest failed"):
        release_stub.create_release_bundle(
            candidate_dir=stub.parent, external_evidence_manifest=external,
            private_key_path=private, output_dir=tmp_path / "release",
            trust_store_path=trust,
            evidence_trust_store_path=_evidence_trust(external),
            release_matrix_path=matrix_path,
        )
    assert not (tmp_path / "release").exists()


def test_provider_signature_rejects_forged_document(tmp_path: Path) -> None:
    stub, manifest_path, candidate = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    scanner = external.parent / "scanner.json"
    document = json.loads(scanner.read_text(encoding="utf-8"))
    document["scanners"][1]["tool_version"] = "9.9.9-forged"
    _json(scanner, document)
    _refresh_external_record(external, "scanner")

    with pytest.raises(release_stub.ReleaseError, match="payload binding is invalid"):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate,
            evidence_trust_store_path=_evidence_trust(external),
        )


def test_provider_signature_rejects_resigned_manifest_with_tampered_signature(
    tmp_path: Path,
) -> None:
    stub, manifest_path, candidate = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    external_document = json.loads(external.read_text(encoding="utf-8"))
    scanner_record = next(
        item for item in external_document["records"] if item["kind"] == "scanner")
    signature_path = external.parent / scanner_record["provider_signature_path"]
    signature = json.loads(signature_path.read_text(encoding="utf-8"))
    signature["signature_base64"] = base64.b64encode(bytes(64)).decode("ascii")
    _json(signature_path, signature)
    scanner_record["provider_signature_sha256"] = release_attestation.sha256_file(
        signature_path)
    _json(external, external_document)

    with pytest.raises(release_stub.ReleaseError, match="signature is invalid"):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate,
            evidence_trust_store_path=_evidence_trust(external),
        )


@pytest.mark.parametrize("mutation", ["missing", "tampered"])
def test_provider_evidence_requires_intact_backing_files(
    tmp_path: Path, mutation: str,
) -> None:
    stub, manifest_path, candidate = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    scanner = json.loads((external.parent / "scanner.json").read_text(encoding="utf-8"))
    backing = external.parent / scanner["subjects"][0]["scans"][0]["output_path"]
    if mutation == "missing":
        backing.unlink()
        message = "evidence is missing"
    else:
        backing.write_text("fabricated scan output\n", encoding="utf-8")
        message = "raw output hash mismatch"

    with pytest.raises(release_stub.ReleaseError, match=message):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate,
            evidence_trust_store_path=_evidence_trust(external),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [("wrong-kind", "not authorized"), ("revoked", "unknown or revoked")],
)
def test_provider_trust_rejects_wrong_kind_and_revoked_keys(
    tmp_path: Path, mutation: str, message: str,
) -> None:
    stub, manifest_path, candidate = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    trust_path = _evidence_trust(external)
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    if mutation == "wrong-kind":
        trust["providers"][0]["allowed_kinds"] = ["application", "clean-vm"]
    else:
        trust["providers"][0]["revoked"] = True
    _json(trust_path, trust)

    with pytest.raises(release_stub.ReleaseError, match=message):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate, evidence_trust_store_path=trust_path,
        )


def test_empty_provider_trust_and_unpinned_code_signer_fail_closed(
    tmp_path: Path,
) -> None:
    stub, manifest_path, candidate = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    with pytest.raises(release_stub.ReleaseError, match="must pin"):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate,
            evidence_trust_store_path=release_attestation.DEFAULT_EVIDENCE_TRUST_STORE,
        )

    trust_path = _evidence_trust(external)
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["authenticode"]["allowed_signer_thumbprints"] = ["3" * 40]
    _json(trust_path, trust)
    with pytest.raises(release_stub.ReleaseError, match="signer is not pinned"):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate, evidence_trust_store_path=trust_path,
        )


def test_empty_authenticode_tsa_allowlist_fails_closed(tmp_path: Path) -> None:
    stub, manifest_path, candidate = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    external = _external(tmp_path, stub, manifest_path, matrix)
    trust_path = _evidence_trust(external)
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["authenticode"]["allowed_tsa_thumbprints"] = []
    _json(trust_path, trust)

    with pytest.raises(release_stub.ReleaseError, match="must pin"):
        release_stub._validate_external_manifest(
            external, stub=stub, candidate_manifest=manifest_path,
            candidate=candidate, evidence_trust_store_path=trust_path,
        )


def test_release_producer_rejects_release_provider_key_role_overlap(
    tmp_path: Path,
) -> None:
    stub, manifest_path, _candidate_payload = _candidate(tmp_path)
    matrix_path = tmp_path / "release-matrix.json"
    matrix = _green_matrix(matrix_path)
    key = Ed25519PrivateKey.generate()
    external = _external(
        tmp_path, stub, manifest_path, matrix, provider_key=key)
    trust = _trust(tmp_path, key)
    private = tmp_path / "overlapping-key.pem"
    private.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

    with pytest.raises(release_stub.ReleaseError, match="key roles overlap"):
        release_stub.create_release_bundle(
            candidate_dir=stub.parent, external_evidence_manifest=external,
            private_key_path=private, output_dir=tmp_path / "release",
            trust_store_path=trust,
            evidence_trust_store_path=_evidence_trust(external),
            release_matrix_path=matrix_path,
        )


def test_release_verifier_rejects_any_trust_key_role_overlap(tmp_path: Path) -> None:
    output, trust, matrix, release_key, evidence_trust = _release(tmp_path)
    raw = release_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    policy = json.loads(evidence_trust.read_text(encoding="utf-8"))
    policy["providers"].append({
        "id": release_attestation.public_key_id(raw),
        "public_key_base64": base64.b64encode(raw).decode("ascii"),
        "revoked": False,
        "allowed_kinds": ["application"],
    })
    _json(evidence_trust, policy)

    with pytest.raises(
        release_attestation.ReleaseAttestationError,
        match="key roles overlap",
    ):
        release_attestation.verify_release_bundle(
            output / "lethe_stub_x64.dll", trust_store_path=trust,
            evidence_trust_store_path=evidence_trust, matrix_path=matrix)


def test_release_verifier_rechecks_provider_signed_backing_files(tmp_path: Path) -> None:
    output, trust, matrix, _key, evidence_trust = _release(tmp_path)
    stub = output / "lethe_stub_x64.dll"
    clean_vm = json.loads(
        (output / "release-evidence/clean-vm.json").read_text(encoding="utf-8"))
    result_log = output / "release-evidence" / clean_vm["matrix"][0]["cells"][0][
        "result_log_path"]
    result_log.write_text("fabricated clean-vm result\n", encoding="utf-8")

    with pytest.raises(
        release_attestation.ReleaseAttestationError,
        match="result log hash mismatch",
    ):
        release_attestation.verify_release_bundle(
            stub, trust_store_path=trust,
            evidence_trust_store_path=evidence_trust, matrix_path=matrix)


def test_release_verifier_rejects_revoked_evidence_provider(tmp_path: Path) -> None:
    output, trust, matrix, _key, evidence_trust = _release(tmp_path)
    policy = json.loads(evidence_trust.read_text(encoding="utf-8"))
    policy["providers"][0]["revoked"] = True
    _json(evidence_trust, policy)

    with pytest.raises(
        release_attestation.ReleaseAttestationError,
        match="unknown or revoked",
    ):
        release_attestation.verify_release_bundle(
            output / "lethe_stub_x64.dll", trust_store_path=trust,
            evidence_trust_store_path=evidence_trust, matrix_path=matrix)
