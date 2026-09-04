from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import os
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packer import external_evidence_v2 as evidence
from packer.pe_content_id import pe_content_id


NOW = datetime(2026, 9, 3, 15, 0, tzinfo=timezone.utc)
PE_MODULE = importlib.import_module("packer.pe_content_id")


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _minimal_pe(*, is_dll: bool = False) -> bytes:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    file_header = e_lfanew + 4
    optional_header = file_header + 20
    struct.pack_into("<H", data, file_header, 0x8664)
    struct.pack_into("<H", data, file_header + 2, 1)
    struct.pack_into("<H", data, file_header + 16, 0xF0)
    if is_dll:
        struct.pack_into("<H", data, file_header + 18, 0x2000)
    struct.pack_into("<H", data, optional_header, 0x20B)
    struct.pack_into("<I", data, optional_header + 0x3C, 0x200)
    struct.pack_into("<I", data, optional_header + 0x6C, 16)
    section = optional_header + 0xF0
    data[section:section + 5] = b".text"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    data[0x200:0x210] = b"receipt-subject!"
    return bytes(data)


def _signed_pe(unsigned: bytes) -> bytes:
    signed = bytearray(unsigned)
    optional_header = 0x80 + 4 + 20
    struct.pack_into("<I", signed, optional_header + 0x40, 0x12345678)
    payload = b"PKCS7"
    length = 8 + len(payload)
    certificate = (
        struct.pack("<IHH", length, 0x0200, 0x0002)
        + payload
        + b"\x00" * ((-length) & 7)
    )
    certificate_offset = (len(signed) + 7) & ~7
    signed.extend(b"\x00" * (certificate_offset - len(signed)))
    struct.pack_into(
        "<II", signed, optional_header + 0x70 + 4 * 8,
        certificate_offset, len(certificate),
    )
    signed.extend(certificate)
    return bytes(signed)


def _provider(
    role: str,
    scopes: list[str],
) -> tuple[Ed25519PrivateKey, dict]:
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    scope_field = {
        "scanner": "scanner_ids",
        "clean-vm": "vm_cell_ids",
        "application": "workflow_ids",
    }[role]
    return key, {
        "id": evidence.public_key_id(raw),
        "public_key_base64": base64.b64encode(raw).decode("ascii"),
        "revoked": False,
        "role": role,
        "scope": {scope_field: scopes},
    }


def _trust() -> tuple[dict, dict[str, Ed25519PrivateKey], dict[str, str]]:
    definitions = (
        ("scanner-a", "scanner", ["defender"]),
        ("scanner-b", "scanner", ["independent"]),
        ("vm", "clean-vm", ["win11-hvci"]),
        ("application", "application", ["startup"]),
    )
    entries = []
    keys: dict[str, Ed25519PrivateKey] = {}
    ids: dict[str, str] = {}
    for name, role, scopes in definitions:
        key, entry = _provider(role, scopes)
        entries.append(entry)
        keys[name] = key
        ids[name] = entry["id"]
    document = {
        "schema": 2,
        "algorithm": "ed25519",
        "providers": entries,
        "authenticode": {
            "allowed_signer_thumbprints": ["1" * 40],
            "allowed_tsa_thumbprints": ["2" * 40],
        },
    }
    return document, keys, ids


def _challenge(prepared_subject_path: Path, ids: dict[str, str]) -> dict:
    exe_stable_id = pe_content_id(prepared_subject_path)
    dll_path = prepared_subject_path.with_suffix(".dll")
    dll_path.write_bytes(_minimal_pe(is_dll=True))
    dll_stable_id = pe_content_id(dll_path)
    candidate = {
        "source_commit": "1" * 40,
        "candidate_stub_sha256": "2" * 64,
        "candidate_manifest_sha256": "3" * 64,
        "production_native_sha256": "4" * 64,
    }

    def subject(
        subject_id: str,
        kind: str,
        marker: bytes,
        stable_id: str,
        prepared_bytes: bytes,
    ) -> dict:
        return {
            "subject_id": subject_id,
            "subject_kind": kind,
            "format": evidence.SUBJECT_FORMAT,
            "input_sha256": _hash(b"input-" + marker),
            "unsigned_subject_sha256": _hash(prepared_bytes),
            "unsigned_subject_size_bytes": len(prepared_bytes),
            "signing_stable_pe_id": stable_id,
            "pack_report_sha256": _hash(b"report-" + marker),
            "protection_profile_sha256": _hash(b"profile-" + marker),
            "protected_with_stub_sha256": candidate["candidate_stub_sha256"],
        }

    challenge = {
        "schema": 2,
        "kind": evidence.CHALLENGE_KIND,
        "challenge_id": "",
        "nonce_base64": base64.b64encode(bytes(range(32))).decode("ascii"),
        "created_at_utc": _timestamp(NOW - timedelta(minutes=10)),
        "expires_at_utc": _timestamp(NOW + timedelta(hours=2)),
        "candidate": candidate,
        "subjects": [
            subject(
                "representative-exe", "exe", b"exe", exe_stable_id,
                prepared_subject_path.read_bytes(),
            ),
            subject(
                "representative-dll", "dll", b"dll", dll_stable_id,
                dll_path.read_bytes(),
            ),
        ],
        "requirements": {
            "scanners": [
                {
                    "scanner_id": "defender",
                    "provider_key_id": ids["scanner-a"],
                    "tool_name": "Microsoft Defender",
                    "tool_version": "4.18",
                    "definitions_version": "1.2.3",
                },
                {
                    "scanner_id": "independent",
                    "provider_key_id": ids["scanner-b"],
                    "tool_name": "Independent",
                    "tool_version": "2.0",
                    "definitions_version": "2026.09.03",
                },
            ],
            "vm_cells": [{
                "cell_id": "win11-hvci",
                "provider_key_id": ids["vm"],
                "runner_sha256": _hash(b"runner"),
                "os_release": "windows-11-supported",
                "os_build": "26100.4946",
                "patch_level": "KB5064081",
                "arch": "x64",
                "secure_boot": True,
                "vbs_enabled": True,
                "hvci_enabled": True,
                "hyper_v_enabled": False,
                "image_id": "image-1",
                "snapshot_id": "snapshot-1",
            }],
            "application_workflows": [{
                "workflow_id": "startup",
                "provider_key_id": ids["application"],
                "definition_sha256": _hash(b"workflow"),
            }],
        },
    }
    challenge["challenge_id"] = evidence.compute_challenge_id(challenge)
    return challenge


def _write_backing(root: Path, relative: str, value: bytes) -> dict:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return {
        "path": relative,
        "sha256": _hash(value),
        "size_bytes": len(value),
    }


def _receipt(
    role: str,
    *,
    challenge: dict,
    key: Ed25519PrivateKey,
    key_id: str,
    subject_path: Path,
    backing_root: Path,
) -> dict:
    if role == "scanner":
        scope = {"scanner_id": "defender"}
        backings = [{
            "id": "scanner-output",
            **_write_backing(backing_root, "scanner/output.txt", b"clean"),
        }]
        observation = {
            "status": "passed",
            "detections": 0,
            "tool_name": "Microsoft Defender",
            "tool_version": "4.18",
            "definitions_version": "1.2.3",
        }
    elif role == "clean-vm":
        scope = {"cell_id": "win11-hvci"}
        backings = [
            {"id": "runner", **_write_backing(
                backing_root, "vm/runner.ps1", b"runner")},
            {"id": "result-log", **_write_backing(
                backing_root, "vm/result.log", b"passed")},
        ]
        observation = {
            "status": "passed",
            "os_release": "windows-11-supported",
            "os_build": "26100.4946",
            "patch_level": "KB5064081",
            "arch": "x64",
            "secure_boot": True,
            "vbs_enabled": True,
            "hvci_enabled": True,
            "hyper_v_enabled": False,
            "image_id": "image-1",
            "snapshot_id": "snapshot-1",
        }
    else:
        scope = {"workflow_id": "startup"}
        backings = [
            {"id": "workflow-definition", **_write_backing(
                backing_root, "application/workflow.json", b"workflow")},
            {"id": "result", **_write_backing(
                backing_root, "application/result.json", b"passed")},
            {"id": "log", **_write_backing(
                backing_root, "application/run.log", b"log")},
        ]
        observation = {"status": "passed", "exit_code": 0}

    receipt = {
        "schema": 2,
        "role": role,
        "provider_key_id": key_id,
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce_base64": challenge["nonce_base64"],
        "candidate": copy.deepcopy(challenge["candidate"]),
        "subject": {
            "subject_id": "representative-exe",
            "subject_kind": "exe",
            "signed_subject_sha256": evidence.sha256_file(subject_path),
            "signed_subject_size_bytes": subject_path.stat().st_size,
            "signing_stable_pe_id": pe_content_id(subject_path),
        },
        "scope": scope,
        "status": "passed",
        "observed_at_utc": _timestamp(NOW),
        "observation": observation,
        "backings": backings,
    }
    return {
        "schema": 2,
        "kind": evidence.RECEIPT_KIND,
        "receipt": receipt,
        "signature_base64": base64.b64encode(
            key.sign(evidence.detached_receipt_signature_payload(receipt))
        ).decode("ascii"),
    }


def _resign(envelope: dict, key: Ed25519PrivateKey) -> None:
    envelope["signature_base64"] = base64.b64encode(key.sign(
        evidence.detached_receipt_signature_payload(envelope["receipt"])
    )).decode("ascii")


@pytest.fixture
def evidence_context(tmp_path: Path):
    subject = tmp_path / "subject.exe"
    prepared = tmp_path / "subject.unsigned.exe"
    prepared.write_bytes(_minimal_pe())
    subject.write_bytes(_signed_pe(prepared.read_bytes()))
    trust_document, keys, ids = _trust()
    policy = evidence.validate_evidence_trust_store_v2(trust_document)
    challenge = _challenge(prepared, ids)
    return subject, trust_document, policy, challenge, keys, ids


def _prepared(subject: Path) -> Path:
    return subject.with_suffix(".unsigned.exe")


def test_v2_trust_enforces_one_role_and_role_specific_scopes(evidence_context):
    _, _, policy, _, _, ids = evidence_context
    assert policy["providers"][ids["scanner-a"]]["role"] == "scanner"
    assert policy["providers"][ids["scanner-a"]]["scopes"] == frozenset({"defender"})


def test_v2_trust_rejects_multiple_roles(evidence_context):
    _, document, _, _, _, _ = evidence_context
    malformed = copy.deepcopy(document)
    malformed["providers"][0]["role"] = ["scanner", "application"]
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="exactly one"):
        evidence.validate_evidence_trust_store_v2(malformed)


def test_v2_trust_rejects_wrong_role_scope_shape(evidence_context):
    _, document, _, _, _, _ = evidence_context
    malformed = copy.deepcopy(document)
    malformed["providers"][0]["scope"] = {"workflow_ids": ["defender"]}
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="scope"):
        evidence.validate_evidence_trust_store_v2(malformed)


def test_v2_trust_rejects_unhashable_scope_value_as_validation_error(evidence_context):
    _, document, _, _, _, _ = evidence_context
    malformed = copy.deepcopy(document)
    malformed["providers"][0]["scope"] = {"scanner_ids": [{"not": "text"}]}
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="scope"):
        evidence.validate_evidence_trust_store_v2(malformed)


def test_v2_trust_rejects_duplicate_public_key(evidence_context):
    _, document, _, _, _, _ = evidence_context
    malformed = copy.deepcopy(document)
    malformed["providers"].append(copy.deepcopy(malformed["providers"][0]))
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="duplicate provider public key"):
        evidence.validate_evidence_trust_store_v2(malformed)


def test_challenge_validates_candidate_subject_and_provider_bindings(evidence_context):
    _, _, policy, challenge, _, _ = evidence_context
    state = evidence.validate_challenge(challenge, trust_policy=policy, now=NOW)
    assert set(state["subjects"]) == {"representative-exe", "representative-dll"}
    assert set(state["requirements"]) == {"scanner", "clean-vm", "application"}


def test_challenge_rejects_content_change_without_new_id(evidence_context):
    _, _, policy, challenge, _, _ = evidence_context
    altered = copy.deepcopy(challenge)
    altered["candidate"]["candidate_stub_sha256"] = "9" * 64
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="challenge id"):
        evidence.validate_challenge(altered, trust_policy=policy, now=NOW)


def test_challenge_id_rejects_non_json_numbers(evidence_context):
    _, _, _, challenge, _, _ = evidence_context
    altered = copy.deepcopy(challenge)
    altered["subjects"][0]["unsigned_subject_size_bytes"] = float("nan")
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="canonical JSON"):
        evidence.compute_challenge_id(altered)


def test_challenge_rejects_expired_nonce(evidence_context):
    _, _, policy, challenge, _, _ = evidence_context
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="expired"):
        evidence.validate_challenge(
            challenge, trust_policy=policy, now=NOW + timedelta(hours=3))


def test_challenge_rejects_wrong_nonce_length(evidence_context):
    _, _, policy, challenge, _, _ = evidence_context
    altered = copy.deepcopy(challenge)
    altered["nonce_base64"] = base64.b64encode(b"short").decode("ascii")
    altered["challenge_id"] = evidence.compute_challenge_id(altered)
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="nonce.*wrong length"):
        evidence.validate_challenge(altered, trust_policy=policy, now=NOW)


def test_challenge_rejects_same_provider_for_required_scanners(evidence_context):
    subject, document, _, _, _, ids = evidence_context
    altered_trust = copy.deepcopy(document)
    altered_trust["providers"][0]["scope"]["scanner_ids"].append("independent")
    policy = evidence.validate_evidence_trust_store_v2(altered_trust)
    altered = _challenge(_prepared(subject), ids)
    altered["requirements"]["scanners"][1]["provider_key_id"] = ids["scanner-a"]
    altered["challenge_id"] = evidence.compute_challenge_id(altered)
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="distinct provider keys"):
        evidence.validate_challenge(altered, trust_policy=policy, now=NOW)


def test_challenge_rejects_two_exe_subjects_as_false_coverage(evidence_context):
    _, _, policy, challenge, _, _ = evidence_context
    altered = copy.deepcopy(challenge)
    altered["subjects"][1]["subject_kind"] = "exe"
    altered["challenge_id"] = evidence.compute_challenge_id(altered)
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="cover EXE and DLL"):
        evidence.validate_challenge(altered, trust_policy=policy, now=NOW)


@pytest.mark.parametrize(
    ("role", "key_name"),
    (("scanner", "scanner-a"), ("clean-vm", "vm"), ("application", "application")),
)
def test_detached_receipt_verifies_role_scope_subject_and_backings(
    evidence_context, tmp_path: Path, role: str, key_name: str,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    backing_root = tmp_path / role
    backing_root.mkdir()
    envelope = _receipt(
        role, challenge=challenge, key=keys[key_name], key_id=ids[key_name],
        subject_path=subject, backing_root=backing_root)
    verified = evidence.verify_detached_receipt(
        envelope, challenge=challenge, trust_policy=policy,
        prepared_unsigned_subject_path=_prepared(subject),
        signed_subject_path=subject, backing_root=backing_root, now=NOW)
    assert verified.role == role
    assert isinstance(verified, evidence.VerifiedReceipt)
    assert verified.prepared_subject.data == _prepared(subject).read_bytes()
    assert verified.signed_subject.data == subject.read_bytes()
    assert {item.backing_id for item in verified.backings} == (
        evidence.REQUIRED_BACKING_IDS[role])


def test_verified_receipt_retains_immutable_accepted_bytes_after_path_mutation(
    evidence_context, tmp_path: Path,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    prepared_path = _prepared(subject)
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    verified = evidence.verify_detached_receipt(
        envelope, challenge=challenge, trust_policy=policy,
        prepared_unsigned_subject_path=prepared_path,
        signed_subject_path=subject, backing_root=root, now=NOW)

    accepted_prepared = verified.prepared_subject.data
    accepted_signed = verified.signed_subject.data
    accepted_backings = {
        item.backing_id: item.snapshot.data for item in verified.backings
    }
    prepared_path.write_bytes(b"changed prepared path")
    subject.write_bytes(b"changed signed path")
    for item in verified.backings:
        item.snapshot.path.write_bytes(b"changed backing path")

    assert verified.prepared_subject.data == accepted_prepared
    assert verified.signed_subject.data == accepted_signed
    assert {
        item.backing_id: item.snapshot.data for item in verified.backings
    } == accepted_backings


def test_receipt_rejects_scanner_tool_constraint_mismatch(
    evidence_context, tmp_path: Path,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    envelope["receipt"]["observation"]["tool_version"] = "4.19"
    _resign(envelope, keys["scanner-a"])
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="tool_version"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_vm_posture_mismatch(evidence_context, tmp_path: Path):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "clean-vm", challenge=challenge, key=keys["vm"], key_id=ids["vm"],
        subject_path=subject, backing_root=root)
    envelope["receipt"]["observation"]["hvci_enabled"] = False
    _resign(envelope, keys["vm"])
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="posture or build"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_validly_signed_wrong_nonce(evidence_context, tmp_path: Path):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    envelope["receipt"]["challenge_nonce_base64"] = base64.b64encode(
        b"x" * 32).decode("ascii")
    envelope["signature_base64"] = base64.b64encode(keys["scanner-a"].sign(
        evidence.detached_receipt_signature_payload(envelope["receipt"]))
    ).decode("ascii")
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="different challenge"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_tampered_detached_signature(evidence_context, tmp_path: Path):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    envelope["receipt"]["observation"]["detections"] = 1
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="signature"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_provider_outside_scope(evidence_context, tmp_path: Path):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    envelope["receipt"]["scope"] = {"scanner_id": "independent"}
    envelope["signature_base64"] = base64.b64encode(keys["scanner-a"].sign(
        evidence.detached_receipt_signature_payload(envelope["receipt"]))
    ).decode("ascii")
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="not authorized"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_signed_subject_substitution(evidence_context, tmp_path: Path):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    changed = bytearray(subject.read_bytes())
    changed[0x205] ^= 0xFF
    subject.write_bytes(changed)
    with pytest.raises(
        evidence.ExternalEvidenceV2Error,
        match="signing-stable PE identity|outside signing fields|bytes do not match",
    ):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_prepared_subject_snapshot_substitution(
    evidence_context, tmp_path: Path,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    prepared = bytearray(_prepared(subject).read_bytes())
    prepared[0x205] ^= 0x40
    _prepared(subject).write_bytes(prepared)
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="prepared subject SHA-256"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_actual_signed_pe_kind_mismatch(
    evidence_context, tmp_path: Path,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    signed = bytearray(subject.read_bytes())
    characteristics = 0x80 + 4 + 18
    struct.pack_into("<H", signed, characteristics,
                     struct.unpack_from("<H", signed, characteristics)[0] | 0x2000)
    subject.write_bytes(signed)
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="signed subject PE kind"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_actual_prepared_pe_kind_mismatch(
    evidence_context, tmp_path: Path,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    prepared = bytearray(_prepared(subject).read_bytes())
    characteristics = 0x80 + 4 + 18
    struct.pack_into("<H", prepared, characteristics,
                     struct.unpack_from("<H", prepared, characteristics)[0] | 0x2000)
    prepared[0x205] ^= 0x20
    _prepared(subject).write_bytes(prepared)
    subject.write_bytes(_signed_pe(bytes(prepared)))
    challenged = challenge["subjects"][0]
    challenged["unsigned_subject_sha256"] = _hash(bytes(prepared))
    challenged["unsigned_subject_size_bytes"] = len(prepared)
    challenged["signing_stable_pe_id"] = pe_content_id(_prepared(subject))
    challenge["challenge_id"] = evidence.compute_challenge_id(challenge)
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="prepared subject PE kind"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_backing_mutation(evidence_context, tmp_path: Path):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    (root / "scanner" / "output.txt").write_bytes(b"not-clean")
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="bytes do not match"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_case_alias_backing_role_reuse(
    evidence_context, tmp_path: Path,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "application", challenge=challenge, key=keys["application"],
        key_id=ids["application"], subject_path=subject, backing_root=root)
    workflow = next(
        item for item in envelope["receipt"]["backings"]
        if item["id"] == "workflow-definition")
    result = next(
        item for item in envelope["receipt"]["backings"]
        if item["id"] == "result")
    result.update({
        "path": "APPLICATION/WORKFLOW.JSON",
        "sha256": workflow["sha256"],
        "size_bytes": workflow["size_bytes"],
    })
    _resign(envelope, keys["application"])
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="identity is duplicated"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_hardlink_backing_role_reuse(
    evidence_context, tmp_path: Path,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "application", challenge=challenge, key=keys["application"],
        key_id=ids["application"], subject_path=subject, backing_root=root)
    workflow_path = root / "application" / "workflow.json"
    result_path = root / "application" / "result.json"
    result_path.unlink()
    try:
        os.link(workflow_path, result_path)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    workflow = next(
        item for item in envelope["receipt"]["backings"]
        if item["id"] == "workflow-definition")
    result = next(
        item for item in envelope["receipt"]["backings"]
        if item["id"] == "result")
    result.update({
        "sha256": workflow["sha256"],
        "size_bytes": workflow["size_bytes"],
    })
    _resign(envelope, keys["application"])
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="hard-linked"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


@pytest.mark.parametrize(
    ("role", "key_name", "backing_id", "relative", "message"),
    (
        ("clean-vm", "vm", "runner", "vm/runner.ps1", "runner does not match"),
        (
            "application", "application", "workflow-definition",
            "application/workflow.json", "definition does not match",
        ),
    ),
)
def test_receipt_rejects_challenge_prebound_backing_substitution(
    evidence_context, tmp_path: Path, role: str, key_name: str,
    backing_id: str, relative: str, message: str,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        role, challenge=challenge, key=keys[key_name], key_id=ids[key_name],
        subject_path=subject, backing_root=root)
    replacement = b"replacement"
    (root / relative).write_bytes(replacement)
    metadata = next(
        entry for entry in envelope["receipt"]["backings"]
        if entry["id"] == backing_id)
    metadata["sha256"] = _hash(replacement)
    metadata["size_bytes"] = len(replacement)
    envelope["signature_base64"] = base64.b64encode(keys[key_name].sign(
        evidence.detached_receipt_signature_payload(envelope["receipt"]))
    ).decode("ascii")
    with pytest.raises(evidence.ExternalEvidenceV2Error, match=message):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_backing_path_escape(evidence_context, tmp_path: Path):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    envelope["receipt"]["backings"][0]["path"] = "../outside.txt"
    envelope["signature_base64"] = base64.b64encode(keys["scanner-a"].sign(
        evidence.detached_receipt_signature_payload(envelope["receipt"]))
    ).decode("ascii")
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="normalized relative"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_unhashable_backing_path_as_validation_error(
    evidence_context, tmp_path: Path,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    envelope["receipt"]["backings"][0]["path"] = {"not": "text"}
    envelope["signature_base64"] = base64.b64encode(keys["scanner-a"].sign(
        evidence.detached_receipt_signature_payload(envelope["receipt"]))
    ).decode("ascii")
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="path is invalid"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=subject, backing_root=root, now=NOW)


def test_receipt_rejects_nested_subject_link_ancestor(
    evidence_context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    nested = tmp_path / "linked" / "nested"
    nested.mkdir(parents=True)
    nested_subject = nested / "subject.exe"
    nested_subject.write_bytes(subject.read_bytes())
    original_is_linklike = PE_MODULE._is_linklike
    monkeypatch.setattr(
        PE_MODULE, "_is_linklike",
        lambda path: path.name == "linked" or original_is_linklike(path),
    )
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="link or junction"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject),
            signed_subject_path=nested_subject, backing_root=root, now=NOW)
