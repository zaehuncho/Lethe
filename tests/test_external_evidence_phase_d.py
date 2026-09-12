"""Non-executing checks for finalized-evidence reload and exact replay."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import timedelta
from pathlib import Path

import pytest

from packer import external_evidence_phase_b as phase_b
from packer import external_evidence_phase_c as phase_c
from packer import external_evidence_phase_d as phase_d
from packer import external_evidence_v2 as evidence
from test_external_evidence_v2 import (
    NOW,
    _phase_b_context,
    _phase_b_receipt,
    _phase_b_receipts,
    _resign,
    _test_authenticode,
)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path) -> dict:
    return json.loads(path.read_bytes())


def _write(path: Path, document: dict) -> None:
    path.write_bytes(evidence.canonical_json_bytes(document))


def _replace_artifact(folder: Path, record: dict, data: bytes) -> None:
    old_path = folder / record["relative_path"]
    digest = _hash(data)
    index = int(record["relative_path"].split("-", 2)[1])
    new_path = folder / f"artifact-{index:05d}-{digest}.bin"
    old_path.unlink()
    new_path.write_bytes(data)
    record["relative_path"] = new_path.name
    record["sha256"] = digest
    record["size_bytes"] = len(data)


@pytest.fixture
def finalized_case(tmp_path):
    context = _phase_b_context(tmp_path / "sources")
    prepared, _, trust_bytes, _, _, _, _ = context
    receipt_root = tmp_path / "receipts"
    receipt_root.mkdir()
    receipts = _phase_b_receipts(context, receipt_root)
    finalized = phase_b.finalize_evidence(
        prepared, receipts,
        current_trust_document=trust_bytes,
        authenticode_verifier=_test_authenticode,
        now=NOW,
    )
    folder = tmp_path / "published"
    manifest = phase_b.publish_evidence(finalized, folder)
    return context, receipts, finalized, folder, manifest


def _reload(case, **overrides):
    context, _, finalized, folder, manifest = case
    kwargs = {
        "expected_context_id": finalized.context_id,
        "expected_manifest_sha256": _hash(manifest.read_bytes()),
        "current_trust_document": context[2],
        "authenticode_verifier": _test_authenticode,
        "now": NOW,
    }
    kwargs.update(overrides)
    return phase_d.load_finalized_evidence(folder, **kwargs)


def test_finalized_bundle_roundtrip_reverifies_current_and_exact_historical_bytes(
        finalized_case):
    calls = []

    def verifier(data, reference_time):
        calls.append((_hash(data), reference_time))
        return _test_authenticode(data, reference_time)

    current = NOW + timedelta(hours=1)
    result = _reload(
        finalized_case, authenticode_verifier=verifier, now=current)
    assert result.release_authorized is False
    assert result.published == finalized_case[2]
    assert result.fresh.release_authorized is False
    assert result.fresh.manifest_bytes != result.published.manifest_bytes
    assert result.recorded_finalized_at_utc == NOW
    assert [reference for _, reference in calls] == [current, current, NOW, NOW]
    assert result.prepared.context_id == finalized_case[2].context_id
    assert len(result.receipts) == 8


def test_manifest_external_digest_precedes_inventory_and_manifest_directed_reads(
        finalized_case, monkeypatch):
    events = []
    actual_snapshot = phase_d.snapshot_file

    def snapshot(path, **kwargs):
        events.append(("snapshot", Path(path).name))
        return actual_snapshot(path, **kwargs)

    def inventory(_root):
        events.append(("inventory", None))
        raise AssertionError("inventory must not run after a bad external manifest pin")

    monkeypatch.setattr(phase_d, "snapshot_file", snapshot)
    monkeypatch.setattr(phase_c, "_inventory", inventory)
    with pytest.raises(phase_d.FinalizedBundleError, match="expected external digest"):
        _reload(finalized_case, expected_manifest_sha256="f" * 64)
    assert events == [("snapshot", "manifest.json")]


def test_context_pin_rejects_untrusted_material_size_before_material_read(
        finalized_case, monkeypatch):
    manifest = finalized_case[4]
    document = _read(manifest)
    document["files"][3]["size_bytes"] += 1 << 40
    _write(manifest, document)
    captured = []
    actual = phase_d.snapshot_file

    def snapshot(path, **kwargs):
        captured.append(Path(path).name)
        return actual(path, **kwargs)

    monkeypatch.setattr(phase_d, "snapshot_file", snapshot)
    with pytest.raises(phase_d.FinalizedBundleError, match="expected context pin"):
        _reload(finalized_case, expected_manifest_sha256=_hash(manifest.read_bytes()))
    assert captured == [
        "manifest.json",
        document["files"][0]["relative_path"],
        document["files"][1]["relative_path"],
        document["files"][2]["relative_path"],
    ]


def test_every_bundle_file_is_snapshotted_once_with_a_positive_bound(
        finalized_case, monkeypatch):
    calls = []
    actual = phase_d.snapshot_file

    def snapshot(path, **kwargs):
        calls.append((Path(path).name, kwargs.get("max_bytes")))
        return actual(path, **kwargs)

    monkeypatch.setattr(phase_d, "snapshot_file", snapshot)
    _reload(finalized_case)
    assert len(calls) == len(set(name for name, _ in calls))
    assert all(type(limit) is int and limit > 0 for _, limit in calls)
    assert {name for name, _ in calls} == {
        path.name for path in finalized_case[3].iterdir()
    }


def test_lazy_verifier_rejects_malformed_later_backing_before_any_callback(tmp_path):
    context = _phase_b_context(tmp_path / "sources")
    prepared, trust, _, keys, ids, subject_paths, _ = context
    root = tmp_path / "backings"
    root.mkdir()
    paths = subject_paths["representative-exe"]
    envelope, _ = _phase_b_receipt(
        prepared,
        subject_id="representative-exe",
        subject_kind="exe",
        signed_subject_path=paths["signed"],
        role="application",
        scope_id="startup",
        key_name="application",
        keys=keys,
        ids=ids,
        root=root,
    )
    envelope["receipt"]["backings"][-1] = {"malformed": True}
    _resign(envelope, keys["application"])
    callbacks = []

    def signed(_size):
        callbacks.append("signed")
        raise AssertionError("signed callback must not run")

    def backing(*_args):
        callbacks.append("backing")
        raise AssertionError("backing callback must not run")

    challenge = evidence.load_json_object_bytes(prepared.challenge_bytes)
    policy = evidence.validate_evidence_trust_store_v2(trust)
    with pytest.raises(evidence.ExternalEvidenceV2Error, match=r"backing\[2\] is malformed"):
        evidence.verify_detached_receipt_lazy(
            envelope,
            challenge=challenge,
            trust_policy=policy,
            prepared_snapshot=prepared.subjects[0].unsigned,
            get_signed_subject=signed,
            get_backing=backing,
            now=NOW,
        )
    assert callbacks == []


def test_invalid_receipt_signature_never_reads_signed_subject_or_backing(
        finalized_case, monkeypatch):
    folder = finalized_case[3]
    manifest = finalized_case[4]
    document = _read(manifest)
    signature_record = next(
        item for item in document["files"] if item["purpose"] == "receipt-0:signature")
    signature = bytearray((folder / signature_record["relative_path"]).read_bytes())
    signature[0] ^= 1
    _replace_artifact(folder, signature_record, bytes(signature))
    _write(manifest, document)
    captured_purposes = []
    names_to_purposes = {
        record["relative_path"]: record["purpose"] for record in document["files"]
    }
    actual = phase_d.snapshot_file

    def snapshot(path, **kwargs):
        captured_purposes.append(names_to_purposes.get(Path(path).name, "manifest"))
        return actual(path, **kwargs)

    monkeypatch.setattr(phase_d, "snapshot_file", snapshot)
    with pytest.raises(phase_d.FinalizedBundleError, match="signature is invalid"):
        _reload(finalized_case, expected_manifest_sha256=_hash(manifest.read_bytes()))
    assert not any(
        purpose.endswith(":signed") or ":backing:" in purpose
        for purpose in captured_purposes
    )


def test_rejects_caller_trust_that_is_not_byte_identical_to_bundle(finalized_case):
    document = evidence.load_json_object_bytes(finalized_case[0][2])
    different = evidence.canonical_json_bytes({**document, "providers": list(reversed(document["providers"]))})
    with pytest.raises(phase_d.FinalizedBundleError, match="caller trust bytes"):
        _reload(finalized_case, current_trust_document=different)


@pytest.mark.parametrize("field", [
    "schema", "kind", "release_authorized", "context_id", "challenge_id",
    "initial_trust_sha256", "current_trust_sha256",
])
def test_rejects_manifest_control_tampering_even_with_a_new_manifest_pin(
        finalized_case, field):
    manifest = finalized_case[4]
    document = _read(manifest)
    values = {
        "schema": 3,
        "kind": "other",
        "release_authorized": True,
        "context_id": "f" * 64,
        "challenge_id": "f" * 64,
        "initial_trust_sha256": "f" * 64,
        "current_trust_sha256": "f" * 64,
    }
    document[field] = values[field]
    _write(manifest, document)
    with pytest.raises(phase_d.FinalizedBundleError):
        _reload(finalized_case, expected_manifest_sha256=_hash(manifest.read_bytes()))


def test_rejects_duplicate_json_unknown_fields_and_noncanonical_manifest(
        finalized_case):
    manifest = finalized_case[4]
    original = manifest.read_bytes()
    variants = [
        original[:-1] + b',"schema":2}',
        original[:-1] + b',"unknown":false}',
        original + b" ",
    ]
    for index, data in enumerate(variants):
        manifest.write_bytes(data)
        with pytest.raises(phase_d.FinalizedBundleError):
            _reload(finalized_case, expected_manifest_sha256=_hash(data))
        manifest.write_bytes(original)


def test_rejects_extra_missing_directory_and_artifact_tampering(finalized_case):
    folder = finalized_case[3]
    manifest = finalized_case[4]
    extra = folder / "extra.bin"
    extra.write_bytes(b"extra")
    with pytest.raises(phase_d.FinalizedBundleError, match="extra, missing"):
        _reload(finalized_case)
    extra.unlink()

    artifact = next(path for path in folder.iterdir() if path.name != "manifest.json")
    original = artifact.read_bytes()
    artifact.write_bytes(original + b"tamper")
    with pytest.raises(phase_d.FinalizedBundleError, match="digest or size|exceeds"):
        _reload(finalized_case)
    artifact.write_bytes(original)

    missing = artifact.with_suffix(".missing")
    artifact.rename(missing)
    with pytest.raises(phase_d.FinalizedBundleError, match="extra, missing"):
        _reload(finalized_case)


def test_rejects_hardlinks_subdirectories_and_case_aliases(finalized_case, monkeypatch):
    source = next(path for path in finalized_case[3].iterdir() if path.name != "manifest.json")
    alias = finalized_case[3] / "hardlink.bin"
    try:
        os.link(source, alias)
    except OSError:
        pytest.skip("hardlinks are unavailable")
    with pytest.raises(phase_d.FinalizedBundleError, match="hard"):
        _reload(finalized_case)
    alias.unlink()

    nested = finalized_case[3] / "nested"
    nested.mkdir()
    with pytest.raises(phase_d.FinalizedBundleError, match="non-regular"):
        _reload(finalized_case)
    nested.rmdir()

    actual = phase_c._inventory

    def aliased(root):
        identity, names = actual(root)
        raise phase_c.PreparedBundleError("bundle directory contains filename aliases")

    monkeypatch.setattr(phase_c, "_inventory", aliased)
    with pytest.raises(phase_d.FinalizedBundleError, match="filename aliases"):
        _reload(finalized_case)


def test_rejects_future_and_out_of_challenge_recorded_finalization(finalized_case):
    manifest = finalized_case[4]
    original = _read(manifest)
    for timestamp in (
        NOW + timedelta(hours=2),
        NOW - timedelta(hours=1),
    ):
        document = copy.deepcopy(original)
        text = timestamp.isoformat().replace("+00:00", "Z")
        document["finalized_at_utc"] = text
        for item in document["authenticode"]:
            item["verified_at_utc"] = text
        _write(manifest, document)
        with pytest.raises(phase_d.FinalizedBundleError, match="future-dated|historical"):
            _reload(
                finalized_case,
                expected_manifest_sha256=_hash(manifest.read_bytes()),
                now=NOW + timedelta(hours=1),
            )
    _write(manifest, original)


def test_rejects_authenticode_time_different_from_recorded_finalization(finalized_case):
    manifest = finalized_case[4]
    document = _read(manifest)
    document["authenticode"][0]["verified_at_utc"] = (
        NOW + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    _write(manifest, document)
    with pytest.raises(phase_d.FinalizedBundleError, match="reference time"):
        _reload(finalized_case, expected_manifest_sha256=_hash(manifest.read_bytes()))


def test_rejects_historical_replay_that_differs_from_signed_manifest(finalized_case):
    manifest = finalized_case[4]
    document = _read(manifest)
    document["authenticode"][0]["verifier_version"] = "different"
    _write(manifest, document)
    with pytest.raises(phase_d.FinalizedBundleError, match="historical finalization replay"):
        _reload(finalized_case, expected_manifest_sha256=_hash(manifest.read_bytes()))


def test_rejects_manifest_identity_or_membership_change_during_load(
        finalized_case, monkeypatch):
    before = phase_c._inventory(finalized_case[3])
    calls = 0

    def inventory(_root):
        nonlocal calls
        calls += 1
        if calls == 1:
            return before
        return ((*(before[0][:-1]), before[0][-1] + 1), before[1])

    monkeypatch.setattr(phase_c, "_inventory", inventory)
    with pytest.raises(phase_d.FinalizedBundleError, match="identity or membership changed"):
        _reload(finalized_case)


def test_api_rejects_missing_pins_verifier_and_naive_time(finalized_case):
    with pytest.raises(phase_d.FinalizedBundleError):
        _reload(finalized_case, expected_context_id="0" * 64)
    with pytest.raises(phase_d.FinalizedBundleError):
        _reload(finalized_case, expected_manifest_sha256="0" * 64)
    with pytest.raises(phase_d.FinalizedBundleError, match="Authenticode verifier"):
        _reload(finalized_case, authenticode_verifier=None)
    with pytest.raises(phase_d.FinalizedBundleError, match="timezone-aware"):
        _reload(finalized_case, now=NOW.replace(tzinfo=None))
