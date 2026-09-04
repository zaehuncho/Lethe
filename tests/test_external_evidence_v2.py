from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import os
import struct
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packer import external_evidence_phase_b as phase_b
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


def _captured_receipt(evidence_context, root: Path, role="scanner", key_name="scanner-a"):
    subject, _, policy, challenge, keys, ids = evidence_context
    root.mkdir()
    envelope = _receipt(
        role, challenge=challenge, key=keys[key_name], key_id=ids[key_name],
        subject_path=subject, backing_root=root)
    snapshots = {
        "prepared_snapshot": evidence.snapshot_file(_prepared(subject), what="fixture"),
        "signed_snapshot": evidence.snapshot_file(subject, what="fixture"),
        "backing_snapshots": {
            backing["path"]: evidence.snapshot_file(root / backing["path"], what="fixture")
            for backing in envelope["receipt"]["backings"]
        },
    }
    return envelope, challenge, policy, snapshots


def test_validate_challenge_returns_private_containers(evidence_context):
    _, _, policy, challenge, _, _ = evidence_context
    original = copy.deepcopy(challenge)
    state = evidence.validate_challenge(challenge, trust_policy=policy, now=NOW)
    state["challenge"]["candidate"]["source_commit"] = "7" * 40
    state["subjects"]["representative-exe"]["subject_kind"] = "dll"
    state["requirements"]["scanner"]["defender"]["tool_version"] = "changed"
    assert challenge == original
    challenge["subjects"][1]["subject_id"] = "changed"
    assert state["subjects"]["representative-dll"]["subject_id"] == "representative-dll"


@pytest.mark.parametrize("target", ["trust", "challenge", "envelope", "receipt"])
def test_schema_versions_require_exact_integer(evidence_context, tmp_path, target):
    subject, document, policy, challenge, keys, ids = evidence_context
    if target == "trust":
        document["schema"] = 2.0
        with pytest.raises(evidence.ExternalEvidenceV2Error, match="malformed"):
            evidence.validate_evidence_trust_store_v2(document)
        return
    if target == "challenge":
        challenge["schema"] = 2.0
        challenge["challenge_id"] = evidence.compute_challenge_id(challenge)
        with pytest.raises(evidence.ExternalEvidenceV2Error, match="malformed"):
            evidence.validate_challenge(challenge, trust_policy=policy, now=NOW)
        return
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    (envelope if target == "envelope" else envelope["receipt"])["schema"] = 2.0
    _resign(envelope, keys["scanner-a"])
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="malformed"):
        evidence.verify_detached_receipt(
            envelope, challenge=challenge, trust_policy=policy,
            prepared_unsigned_subject_path=_prepared(subject), signed_subject_path=subject,
            backing_root=root, now=NOW)


def test_trust_file_uses_duplicate_rejecting_json_loader(evidence_context, tmp_path):
    _, document, _, _, _, _ = evidence_context
    encoded = evidence.canonical_json_bytes(document)
    path = tmp_path / "trust.json"
    path.write_bytes(encoded.replace(b'"schema":2', b'"schema":2,"schema":2'))
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="duplicate"):
        evidence.load_evidence_trust_store_v2(path)


def test_verifier_detaches_inputs_and_serializes_signed_receipt_once(
    evidence_context, tmp_path, monkeypatch,
):
    subject, _, policy, challenge, keys, ids = evidence_context
    root = tmp_path / "backings"
    root.mkdir()
    envelope = _receipt(
        "scanner", challenge=challenge, key=keys["scanner-a"],
        key_id=ids["scanner-a"], subject_path=subject, backing_root=root)
    expected = evidence.canonical_json_bytes(envelope["receipt"])
    expected_signature = base64.b64decode(envelope["signature_base64"])
    original_canonical = evidence.canonical_json_bytes
    receipt_calls = []

    def canonical_with_caller_update(payload):
        result = original_canonical(payload)
        if "role" in payload:
            receipt_calls.append(result)
            envelope["receipt"]["observation"]["definitions_version"] = "next"
            envelope["signature_base64"] = "changed"
            challenge["candidate"]["source_commit"] = "7" * 40
            challenge["requirements"]["scanners"][0]["tool_version"] = "next"
            policy["providers"].clear()
        return result

    monkeypatch.setattr(evidence, "canonical_json_bytes", canonical_with_caller_update)
    verified = evidence.verify_detached_receipt(
        envelope, challenge=challenge, trust_policy=policy,
        prepared_unsigned_subject_path=_prepared(subject), signed_subject_path=subject,
        backing_root=root, now=NOW)
    assert receipt_calls == [expected]
    assert verified.canonical_receipt is receipt_calls[0]
    assert verified.signature == expected_signature
    assert verified.signature_payload == evidence.RECEIPT_SIGNATURE_DOMAIN + expected
    keys["scanner-a"].public_key().verify(verified.signature, verified.signature_payload)


@pytest.mark.parametrize("role,key_name", [
    ("scanner", "scanner-a"), ("clean-vm", "vm"), ("application", "application"),
])
def test_pure_snapshot_verifier_matches_path_verifier_without_any_io(
    evidence_context, tmp_path, monkeypatch, role, key_name,
):
    root = tmp_path / "backings"
    envelope, challenge, policy, snapshots = _captured_receipt(
        evidence_context, root, role, key_name)
    subject = evidence_context[0]
    path_result = evidence.verify_detached_receipt(
        envelope, challenge=challenge, trust_policy=policy,
        prepared_unsigned_subject_path=_prepared(subject), signed_subject_path=subject,
        backing_root=root, now=NOW)

    def unexpected_io(*args, **kwargs):
        raise AssertionError("snapshot-only verification attempted filesystem access")

    with monkeypatch.context() as guard:
        guard.setattr(evidence, "snapshot_file", unexpected_io)
        for name in ("open", "stat", "lstat", "resolve", "is_file", "is_dir"):
            guard.setattr(Path, name, unexpected_io)
        result = evidence.verify_detached_receipt_snapshots(
            envelope, challenge=challenge, trust_policy=policy, now=NOW, **snapshots)
    assert result == path_result


def test_pure_snapshot_verifier_retains_capture_after_source_updates(
    evidence_context, tmp_path,
):
    envelope, challenge, policy, snapshots = _captured_receipt(
        evidence_context, tmp_path / "backings")
    for snapshot in (
        snapshots["prepared_snapshot"], snapshots["signed_snapshot"],
        *snapshots["backing_snapshots"].values(),
    ):
        snapshot.path.write_bytes(b"later source version")
    result = evidence.verify_detached_receipt_snapshots(
        envelope, challenge=challenge, trust_policy=policy, now=NOW, **snapshots)
    assert result.prepared_subject == snapshots["prepared_snapshot"]
    assert result.backings[0].snapshot.data == b"clean"


@pytest.mark.parametrize("which", ["prepared_snapshot", "signed_snapshot", "backing"])
@pytest.mark.parametrize("field,value", [
    ("sha256", "1" * 64), ("size", 1), ("link_count", 2), ("size", True),
])
def test_pure_snapshot_verifier_rejects_inconsistent_metadata(
    evidence_context, tmp_path, which, field, value,
):
    envelope, challenge, policy, snapshots = _captured_receipt(
        evidence_context, tmp_path / "backings")
    if which == "backing":
        key = next(iter(snapshots["backing_snapshots"]))
        snapshots["backing_snapshots"][key] = replace(
            snapshots["backing_snapshots"][key], **{field: value})
    else:
        snapshots[which] = replace(snapshots[which], **{field: value})
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="snapshot"):
        evidence.verify_detached_receipt_snapshots(
            envelope, challenge=challenge, trust_policy=policy, now=NOW, **snapshots)


@pytest.mark.parametrize("change,message", [
    ("missing", "missing"), ("extra", "extra"), ("relative", "normalized relative"),
])
def test_pure_snapshot_verifier_requires_exact_normalized_backing_map(
    evidence_context, tmp_path, change, message,
):
    envelope, challenge, policy, snapshots = _captured_receipt(
        evidence_context, tmp_path / "backings")
    backing_map = snapshots["backing_snapshots"]
    key = next(iter(backing_map))
    if change == "missing":
        backing_map.pop(key)
    else:
        backing_map["../other.txt" if change == "relative" else "other.txt"] = backing_map[key]
    with pytest.raises(evidence.ExternalEvidenceV2Error, match=message):
        evidence.verify_detached_receipt_snapshots(
            envelope, challenge=challenge, trust_policy=policy, now=NOW, **snapshots)


def test_pure_snapshot_verifier_rejects_backing_filesystem_identity_reuse(
    evidence_context, tmp_path,
):
    envelope, challenge, policy, snapshots = _captured_receipt(
        evidence_context, tmp_path / "backings", "application", "application")
    backing_map = snapshots["backing_snapshots"]
    first, second, *_ = backing_map
    backing_map[second] = replace(
        backing_map[second], device=backing_map[first].device, inode=backing_map[first].inode)
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="filesystem identity is duplicated"):
        evidence.verify_detached_receipt_snapshots(
            envelope, challenge=challenge, trust_policy=policy, now=NOW, **snapshots)


@pytest.mark.parametrize("mode", ["path", "snapshots"])
@pytest.mark.parametrize("at_expiry", [False, True])
def test_receipt_observation_uses_exclusive_expiry_boundary(
    evidence_context, tmp_path, mode, at_expiry,
):
    root = tmp_path / "backings"
    envelope, challenge, policy, snapshots = _captured_receipt(evidence_context, root)
    expiry = datetime.fromisoformat(challenge["expires_at_utc"].replace("Z", "+00:00"))
    envelope["receipt"]["observed_at_utc"] = _timestamp(
        expiry if at_expiry else expiry - timedelta(microseconds=1))
    _resign(envelope, evidence_context[4]["scanner-a"])
    if mode == "path":
        function = evidence.verify_detached_receipt
        kwargs = {
            "prepared_unsigned_subject_path": _prepared(evidence_context[0]),
            "signed_subject_path": evidence_context[0], "backing_root": root,
        }
    else:
        function = evidence.verify_detached_receipt_snapshots
        kwargs = snapshots
    if at_expiry:
        with pytest.raises(evidence.ExternalEvidenceV2Error, match="outside the challenge"):
            function(envelope, challenge=challenge, trust_policy=policy,
                     now=expiry - timedelta(minutes=1), **kwargs)
    else:
        assert function(envelope, challenge=challenge, trust_policy=policy,
                        now=expiry - timedelta(minutes=1), **kwargs).role == "scanner"


def test_challenge_expiry_is_exclusive(evidence_context):
    _, _, policy, challenge, _, _ = evidence_context
    expiry = datetime.fromisoformat(challenge["expires_at_utc"].replace("Z", "+00:00"))
    with pytest.raises(evidence.ExternalEvidenceV2Error, match="expired"):
        evidence.validate_challenge(challenge, trust_policy=policy, now=expiry)


def _test_candidate_verifier(
    stub: bytes, manifest: bytes, production_native: bytes, source_commit: str,
) -> phase_b.CandidateVerificationResult:
    return phase_b.CandidateVerificationResult(
        source_commit,
        _hash(stub),
        _hash(manifest),
        _hash(production_native),
        "test-only-candidate-verifier",
        "1.0",
        True,
    )


def _phase_b_context(tmp_path: Path, candidate_verifier=_test_candidate_verifier):
    tmp_path.mkdir(parents=True, exist_ok=True)
    trust, keys, ids = _trust()
    trust_bytes = evidence.canonical_json_bytes(trust)
    candidate_files = {
        "stub": tmp_path / "candidate-stub.dll",
        "manifest": tmp_path / "candidate-manifest.json",
        "production_native": tmp_path / "production-native.dll",
    }
    candidate_files["stub"].write_bytes(b"candidate-stub")
    candidate_files["manifest"].write_bytes(evidence.canonical_json_bytes({
        "source_commit": "1" * 40,
    }))
    candidate_files["production_native"].write_bytes(b"production-native")

    exe_unsigned = tmp_path / "representative-exe.unsigned.exe"
    exe_unsigned.write_bytes(_minimal_pe())
    requirement_fixture = _challenge(exe_unsigned, ids)
    dll_unsigned = exe_unsigned.with_suffix(".dll")
    subject_paths = {
        "representative-exe": {
            "kind": "exe", "unsigned": exe_unsigned,
            "signed": tmp_path / "representative-exe.signed.exe",
        },
        "representative-dll": {
            "kind": "dll", "unsigned": dll_unsigned,
            "signed": tmp_path / "representative-dll.signed.dll",
        },
    }
    inputs = []
    source_paths = list(candidate_files.values())
    for subject_id, paths in subject_paths.items():
        paths["signed"].write_bytes(_signed_pe(paths["unsigned"].read_bytes()))
        metadata = {}
        for field in ("input", "pack_report", "protection_profile"):
            path = tmp_path / f"{subject_id}.{field}.bin"
            path.write_bytes(f"{subject_id}:{field}".encode())
            metadata[field] = path
        inputs.append(phase_b.SubjectInput(
            subject_id, paths["kind"], paths["unsigned"], metadata["input"],
            metadata["pack_report"], metadata["protection_profile"],
        ))
        source_paths.extend((paths["unsigned"], paths["signed"], *metadata.values()))
    prepared = phase_b.prepare_evidence(
        phase_b.CandidateInput(
            "1" * 40, candidate_files["stub"], candidate_files["manifest"],
            candidate_files["production_native"],
        ),
        inputs,
        requirement_fixture["requirements"],
        trust_bytes,
        candidate_verifier=candidate_verifier,
        now=NOW,
    )
    return prepared, trust, trust_bytes, keys, ids, subject_paths, source_paths


def _phase_b_receipt(
    prepared: phase_b.PreparedEvidence,
    *,
    subject_id: str,
    subject_kind: str,
    signed_subject_path: Path,
    role: str,
    scope_id: str,
    key_name: str,
    keys: dict[str, Ed25519PrivateKey],
    ids: dict[str, str],
    root: Path,
) -> tuple[dict, Path]:
    challenge = evidence.load_json_object_bytes(prepared.challenge_bytes)
    envelope = _receipt(
        role,
        challenge=challenge,
        key=keys[key_name],
        key_id=ids[key_name],
        subject_path=signed_subject_path,
        backing_root=root,
    )
    envelope["receipt"]["subject"] = {
        "subject_id": subject_id,
        "subject_kind": subject_kind,
        "signed_subject_sha256": _hash(signed_subject_path.read_bytes()),
        "signed_subject_size_bytes": signed_subject_path.stat().st_size,
        "signing_stable_pe_id": pe_content_id(signed_subject_path),
    }
    if role == "scanner" and scope_id == "independent":
        envelope["receipt"]["scope"] = {"scanner_id": scope_id}
        envelope["receipt"]["observation"].update({
            "tool_name": "Independent",
            "tool_version": "2.0",
            "definitions_version": "2026.09.03",
        })
    _resign(envelope, keys[key_name])
    return envelope, root


def _phase_b_receipts(context, tmp_path: Path):
    prepared, _, _, keys, ids, subject_paths, _ = context
    scopes = (
        ("scanner", "defender", "scanner-a"),
        ("scanner", "independent", "scanner-b"),
        ("clean-vm", "win11-hvci", "vm"),
        ("application", "startup", "application"),
    )
    result = []
    for subject_id, paths in subject_paths.items():
        for role, scope_id, key_name in scopes:
            root = tmp_path / f"{subject_id}-{role}-{scope_id}"
            root.mkdir()
            envelope, root = _phase_b_receipt(
                prepared,
                subject_id=subject_id,
                subject_kind=paths["kind"],
                signed_subject_path=paths["signed"],
                role=role,
                scope_id=scope_id,
                key_name=key_name,
                keys=keys,
                ids=ids,
                root=root,
            )
            result.append(phase_b.ingest_receipt(
                prepared,
                evidence.canonical_json_bytes(envelope),
                signed_subject_path=paths["signed"],
                backing_root=root,
                now=NOW,
            ))
    return result


def _test_authenticode(data: bytes, current: datetime) -> phase_b.AuthenticodeResult:
    return phase_b.AuthenticodeResult(
        _hash(data), len(data), "1" * 40, "2" * 40, current,
        "test-only-bytes-verifier", "1.0", True,
    )


def test_phase_b_finalizes_complete_retained_evidence_without_reopening_sources(tmp_path):
    context = _phase_b_context(tmp_path)
    prepared, _, trust_bytes, _, _, _, source_paths = context
    receipts = _phase_b_receipts(context, tmp_path)

    for path in source_paths:
        if path.exists():
            path.write_bytes(b"changed after capture")

    finalized = phase_b.finalize_evidence(
        prepared,
        receipts,
        current_trust_document=trust_bytes,
        authenticode_verifier=_test_authenticode,
        now=NOW,
    )
    manifest = evidence.load_json_object_bytes(finalized.manifest_bytes)
    assert finalized.release_authorized is False
    assert manifest["release_authorized"] is False
    assert len(manifest["authenticode"]) == 2
    assert manifest["candidate_verification"] == phase_b._candidate_verification_record(
        prepared.candidate_verification, prepared.candidate)
    records = {record["purpose"]: record for record in manifest["files"]}
    context_input = {
        "challenge_sha256": records["challenge"]["sha256"],
        "trust_sha256": records["initial-trust"]["sha256"],
        "candidate_verification": manifest["candidate_verification"],
        "material": [{
            "purpose": purpose,
            "sha256": records[purpose]["sha256"],
            "size": records[purpose]["size_bytes"],
        } for purpose, _ in phase_b._material(prepared)],
    }
    assert _hash(
        phase_b._CONTEXT_DOMAIN + evidence.canonical_json_bytes(context_input)
    ) == finalized.context_id
    retained_data = {item.data for item in finalized.files}
    assert all(receipt.canonical_receipt in retained_data for receipt in receipts)
    assert all(receipt.signature in retained_data for receipt in receipts)
    assert b"changed after capture" not in retained_data

    published = phase_b.publish_evidence(finalized, tmp_path / "published")
    assert published.read_bytes() == finalized.manifest_bytes
    for item in finalized.files:
        assert (published.parent / item.relative_path).read_bytes() == item.data


def test_phase_b_uses_fresh_nonce_and_private_caller_state(tmp_path):
    first_context = _phase_b_context(tmp_path / "first")
    second_context = _phase_b_context(tmp_path / "second")
    first = evidence.load_json_object_bytes(first_context[0].challenge_bytes)
    second = evidence.load_json_object_bytes(second_context[0].challenge_bytes)
    assert first["nonce_base64"] != second["nonce_base64"]
    assert len(base64.b64decode(first["nonce_base64"], validate=True)) == 32
    assert first_context[0].context_id != second_context[0].context_id


def test_phase_b_requires_exact_candidate_bundle_verification(tmp_path):
    with pytest.raises(phase_b.PhaseBError, match="candidate verifier is required"):
        _phase_b_context(tmp_path / "missing", candidate_verifier=None)

    def mismatched(stub, manifest, production_native, source_commit):
        result = _test_candidate_verifier(
            stub, manifest, production_native, source_commit)
        return replace(result, stub_sha256="0" * 64)

    with pytest.raises(phase_b.PhaseBError, match="invalid or mismatched"):
        _phase_b_context(tmp_path / "mismatched", candidate_verifier=mismatched)


def test_phase_b_rejects_missing_authenticode_or_incomplete_receipt_coverage(tmp_path):
    context = _phase_b_context(tmp_path)
    prepared, _, trust_bytes, _, _, _, _ = context
    receipts = _phase_b_receipts(context, tmp_path)
    with pytest.raises(phase_b.PhaseBError, match="Authenticode verifier"):
        phase_b.finalize_evidence(
            prepared, receipts, current_trust_document=trust_bytes, now=NOW)
    with pytest.raises(phase_b.PhaseBError, match="coverage is incomplete"):
        phase_b.finalize_evidence(
            prepared, receipts[:-1], current_trust_document=trust_bytes,
            authenticode_verifier=_test_authenticode, now=NOW)


def test_phase_b_rejects_current_provider_revocation_and_authenticode_pin_mismatch(tmp_path):
    context = _phase_b_context(tmp_path)
    prepared, trust, _, _, ids, _, _ = context
    receipts = _phase_b_receipts(context, tmp_path)
    revoked = copy.deepcopy(trust)
    next(provider for provider in revoked["providers"]
         if provider["id"] == ids["scanner-a"])["revoked"] = True
    with pytest.raises(phase_b.PhaseBError, match="revoked|active"):
        phase_b.finalize_evidence(
            prepared,
            receipts,
            current_trust_document=evidence.canonical_json_bytes(revoked),
            authenticode_verifier=_test_authenticode,
            now=NOW,
        )

    def wrong_pin(data: bytes, current: datetime) -> phase_b.AuthenticodeResult:
        result = _test_authenticode(data, current)
        return replace(result, signer_thumbprint="3" * 40)

    with pytest.raises(phase_b.PhaseBError, match="outside current pins"):
        phase_b.finalize_evidence(
            prepared,
            receipts,
            current_trust_document=evidence.canonical_json_bytes(trust),
            authenticode_verifier=wrong_pin,
            now=NOW,
        )


def test_phase_b_rejects_conflicting_signed_bytes_for_one_subject(tmp_path):
    context = _phase_b_context(tmp_path)
    prepared, _, trust_bytes, keys, ids, subject_paths, _ = context
    receipts = _phase_b_receipts(context, tmp_path)
    alternate = tmp_path / "alternate.exe"
    unsigned = subject_paths["representative-exe"]["unsigned"].read_bytes()
    alternate_signed = bytearray(_signed_pe(unsigned))
    alternate_signed[0x408] ^= 1
    alternate.write_bytes(alternate_signed)
    root = tmp_path / "alternate-receipt"
    root.mkdir()
    envelope, _ = _phase_b_receipt(
        prepared,
        subject_id="representative-exe",
        subject_kind="exe",
        signed_subject_path=alternate,
        role="scanner",
        scope_id="defender",
        key_name="scanner-a",
        keys=keys,
        ids=ids,
        root=root,
    )
    alternate_receipt = phase_b.ingest_receipt(
        prepared,
        evidence.canonical_json_bytes(envelope),
        signed_subject_path=alternate,
        backing_root=root,
        now=NOW,
    )
    replaced = [alternate_receipt if (
        item.subject_id == "representative-exe"
        and item.role == "scanner"
        and item.scope_id == "defender"
    ) else item for item in receipts]
    with pytest.raises(phase_b.PhaseBError, match="conflicting signed subject bytes"):
        phase_b.finalize_evidence(
            prepared,
            replaced,
            current_trust_document=trust_bytes,
            authenticode_verifier=_test_authenticode,
            now=NOW,
        )


def test_phase_b_publish_rejects_tampered_manifest_and_files(tmp_path):
    context = _phase_b_context(tmp_path)
    prepared, _, trust_bytes, _, _, _, _ = context
    receipts = _phase_b_receipts(context, tmp_path)
    finalized = phase_b.finalize_evidence(
        prepared,
        receipts,
        current_trust_document=trust_bytes,
        authenticode_verifier=_test_authenticode,
        now=NOW,
    )
    with pytest.raises(phase_b.PhaseBError, match="manifest identity"):
        phase_b.publish_evidence(
            replace(finalized, manifest_bytes=finalized.manifest_bytes + b" "),
            tmp_path / "bad-manifest",
        )
    tampered = replace(
        finalized.files[0], data=finalized.files[0].data + b"tamper")
    with pytest.raises(phase_b.PhaseBError, match="file name, bytes, or purpose"):
        phase_b.publish_evidence(
            replace(finalized, files=(tampered, *finalized.files[1:])),
            tmp_path / "bad-files",
        )
