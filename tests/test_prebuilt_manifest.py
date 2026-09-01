"""Integrity metadata for the tracked native stub."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from packer import assemble


ROOT = Path(__file__).resolve().parents[1]
STUB = ROOT / "stub" / "prebuilt" / "lethe_stub_x64.dll"
MANIFEST = STUB.with_name("lethe_stub_x64.manifest.json")


def test_prebuilt_manifest_matches_tracked_stub():
    metadata = json.loads(MANIFEST.read_text(encoding="utf-8"))
    blob = STUB.read_bytes()

    assert metadata["schema"] == 1
    assert metadata["artifact"] == STUB.name
    assert metadata["size_bytes"] == len(blob)
    assert metadata["sha256"] == hashlib.sha256(blob).hexdigest()
    if (metadata.get("provenance_status") == "clean" and
            metadata.get("source_dirty") is False):
        assemble._validate_release_stub_manifest(str(STUB), blob)
    else:
        with pytest.raises(assemble.AssembleError, match="not release-approved"):
            assemble._validate_release_stub_manifest(str(STUB), blob)


def test_legacy_manifest_is_never_release_approved(tmp_path):
    stub = tmp_path / "lethe_stub_x64.dll"
    manifest = tmp_path / "lethe_stub_x64.manifest.json"
    blob = b"stub candidate"
    stub.write_bytes(blob)
    manifest.write_text(json.dumps({
        "schema": 1,
        "artifact": stub.name,
        "size_bytes": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "source_dirty": None,
        "provenance_status": "legacy-unverified",
    }), encoding="utf-8")

    with pytest.raises(assemble.AssembleError, match="not release-approved"):
        assemble._validate_release_stub_manifest(str(stub), blob)


def test_clean_matching_manifest_is_release_approved(tmp_path):
    stub = tmp_path / "lethe_stub_x64.dll"
    manifest = tmp_path / "lethe_stub_x64.manifest.json"
    blob = b"fresh stub candidate"
    stub.write_bytes(blob)
    manifest.write_text(json.dumps({
        "schema": 1,
        "artifact": stub.name,
        "size_bytes": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "source_dirty": False,
        "provenance_status": "clean",
        "native_roundtrip": "passed-9-of-9",
        "native_roundtrip_actual": {"passed": 11, "total": 11},
        "production_scope": "all",
        "dvm_shuffle_seed": "00112233",
        "dvm_opcode_mapping_sha256": "1" * 64,
        "dvm_handler_variant_sha256": "2" * 64,
        "dvm_python_map_sha256": "3" * 64,
        "dvm_native_map_sha256": "4" * 64,
    }), encoding="utf-8")

    assemble._validate_release_stub_manifest(str(stub), blob)


def test_clean_manifest_with_wrong_hash_is_rejected(tmp_path):
    stub = tmp_path / "lethe_stub_x64.dll"
    manifest = tmp_path / "lethe_stub_x64.manifest.json"
    blob = b"fresh stub candidate"
    stub.write_bytes(blob)
    manifest.write_text(json.dumps({
        "schema": 1,
        "artifact": stub.name,
        "size_bytes": len(blob),
        "sha256": "0" * 64,
        "source_dirty": False,
        "provenance_status": "clean",
        "native_roundtrip": "passed-9-of-9",
    }), encoding="utf-8")

    with pytest.raises(assemble.AssembleError, match="SHA-256 does not match"):
        assemble._validate_release_stub_manifest(str(stub), blob)


def test_clean_manifest_without_roundtrip_evidence_is_rejected(tmp_path):
    stub = tmp_path / "lethe_stub_x64.dll"
    manifest = tmp_path / "lethe_stub_x64.manifest.json"
    blob = b"untested clean candidate"
    stub.write_bytes(blob)
    manifest.write_text(json.dumps({
        "schema": 1,
        "artifact": stub.name,
        "size_bytes": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "source_dirty": False,
        "provenance_status": "clean",
        "native_roundtrip": "not-run",
    }), encoding="utf-8")

    with pytest.raises(assemble.AssembleError, match="round-trip"):
        assemble._validate_release_stub_manifest(str(stub), blob)


def test_compatibility_marker_cannot_replace_actual_roundtrip_counts(tmp_path):
    stub = tmp_path / "lethe_stub_x64.dll"
    manifest = tmp_path / "lethe_stub_x64.manifest.json"
    blob = b"marker-only candidate"
    stub.write_bytes(blob)
    manifest.write_text(json.dumps({
        "schema": 1,
        "artifact": stub.name,
        "size_bytes": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "source_dirty": False,
        "provenance_status": "clean",
        "native_roundtrip": "passed-9-of-9",
        "native_roundtrip_actual": {"passed": 10, "total": 11},
    }), encoding="utf-8")

    with pytest.raises(assemble.AssembleError, match="full N/N"):
        assemble._validate_release_stub_manifest(str(stub), blob)
