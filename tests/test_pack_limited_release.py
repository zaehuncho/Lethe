"""Constrained shipping-bundle orchestration regressions."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import pack_limited_release as limited


def _args(tmp_path: Path, exe: Path, dll: Path):
    return SimpleNamespace(
        stub_path=str(tmp_path / "candidate" / "lethe_stub_x64.dll"),
        output_dir=str(tmp_path / "dist"),
        exe=[str(exe)],
        dll=[str(dll)],
        compression_level=9,
    )


def _candidate(tmp_path: Path) -> Path:
    directory = tmp_path / "candidate"
    directory.mkdir()
    stub = directory / "lethe_stub_x64.dll"
    stub.write_bytes(b"candidate-stub")
    stub.with_suffix(".manifest.json").write_text("{}", encoding="ascii")
    return stub


def _patch_candidate(monkeypatch, stub: Path):
    monkeypatch.setattr(
        limited.release_attestation,
        "validate_candidate_identity",
        lambda path: {
            "sha256": hashlib.sha256(stub.read_bytes()).hexdigest(),
            "source_commit": "a" * 40,
        },
    )


def test_bundle_packs_exe_and_dll_transactionally(monkeypatch, tmp_path):
    stub = _candidate(tmp_path)
    exe = tmp_path / "product.exe"
    dll = tmp_path / "product.dll"
    exe.write_bytes(b"exe-source")
    dll.write_bytes(b"dll-source")
    _patch_candidate(monkeypatch, stub)
    monkeypatch.setattr(
        limited.orchestrator,
        "detect_is_dll",
        lambda path: Path(path).suffix.casefold() == ".dll",
    )
    observed = []

    def fake_pack(source, options):
        observed.append(
            {
                "source": Path(source).name,
                "dll_gate": os.environ.get("LETHE_ENABLE_EXPERIMENTAL_DLL"),
                "options": options,
            }
        )
        Path(options.output_path).write_bytes(Path(source).read_bytes() + b"-packed")
        return SimpleNamespace(ok=True, error=None, build_id=Path(source).stem)

    monkeypatch.setattr(limited.orchestrator, "pack_file", fake_pack)
    monkeypatch.setattr(
        limited.report,
        "validate_packed",
        lambda _path: SimpleNamespace(ok=True, reason=None),
    )

    manifest_path = limited.build_bundle(_args(tmp_path, exe, dll))

    assert manifest_path == tmp_path / "dist" / limited.MANIFEST_NAME
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["profile"] == limited.PROFILE_ID
    assert payload["status"] == "packed-awaiting-product-validation-and-signing"
    assert [row["kind"] for row in payload["artifacts"]] == ["exe", "dll"]
    assert (tmp_path / "dist" / "product.exe").read_bytes() == b"exe-source-packed"
    assert (tmp_path / "dist" / "product.dll").read_bytes() == b"dll-source-packed"
    assert observed[0]["dll_gate"] is None
    assert observed[1]["dll_gate"] == "1"
    for row in observed:
        options = row["options"]
        assert options.anti_debug is False
        assert options.memory_guard is False
        assert options.process_hardening is False
        assert options.server_shard is False
        assert options.virtualization_specs == ()
        assert options.stub_path == str(stub)
    assert "LETHE_ENABLE_EXPERIMENTAL_DLL" not in os.environ


def test_bundle_rejects_kind_mismatch_before_packing(monkeypatch, tmp_path):
    stub = _candidate(tmp_path)
    exe = tmp_path / "product.exe"
    dll = tmp_path / "product.dll"
    exe.write_bytes(b"exe-source")
    dll.write_bytes(b"dll-source")
    _patch_candidate(monkeypatch, stub)
    monkeypatch.setattr(limited.orchestrator, "detect_is_dll", lambda _path: False)
    called = False

    def fake_pack(_source, _options):
        nonlocal called
        called = True

    monkeypatch.setattr(limited.orchestrator, "pack_file", fake_pack)
    with pytest.raises(limited.LimitedReleaseError, match="supplied as DLL"):
        limited.build_bundle(_args(tmp_path, exe, dll))
    assert called is False
    assert not (tmp_path / "dist").exists()


def test_bundle_failure_is_not_published(monkeypatch, tmp_path):
    stub = _candidate(tmp_path)
    exe = tmp_path / "product.exe"
    dll = tmp_path / "product.dll"
    exe.write_bytes(b"exe-source")
    dll.write_bytes(b"dll-source")
    _patch_candidate(monkeypatch, stub)
    monkeypatch.setattr(
        limited.orchestrator,
        "detect_is_dll",
        lambda path: Path(path).suffix.casefold() == ".dll",
    )

    def fake_pack(source, options):
        if Path(source).suffix.casefold() == ".dll":
            return SimpleNamespace(ok=False, error="fixture failure", build_id=None)
        Path(options.output_path).write_bytes(b"packed")
        return SimpleNamespace(ok=True, error=None, build_id="exe")

    monkeypatch.setattr(limited.orchestrator, "pack_file", fake_pack)
    monkeypatch.setattr(
        limited.report,
        "validate_packed",
        lambda _path: SimpleNamespace(ok=True, reason=None),
    )
    with pytest.raises(limited.LimitedReleaseError, match="fixture failure"):
        limited.build_bundle(_args(tmp_path, exe, dll))
    assert not (tmp_path / "dist").exists()
    assert list(tmp_path.glob(".dist.stage-*")) == []


def test_bundle_rejects_source_drift_before_publication(monkeypatch, tmp_path):
    stub = _candidate(tmp_path)
    exe = tmp_path / "product.exe"
    dll = tmp_path / "product.dll"
    exe.write_bytes(b"exe-source")
    dll.write_bytes(b"dll-source")
    _patch_candidate(monkeypatch, stub)
    monkeypatch.setattr(
        limited.orchestrator,
        "detect_is_dll",
        lambda path: Path(path).suffix.casefold() == ".dll",
    )

    def fake_pack(source, options):
        Path(options.output_path).write_bytes(b"packed")
        if Path(source).suffix.casefold() == ".exe":
            Path(source).write_bytes(b"changed-during-pack")
        return SimpleNamespace(ok=True, error=None, build_id="build")

    monkeypatch.setattr(limited.orchestrator, "pack_file", fake_pack)
    monkeypatch.setattr(
        limited.report,
        "validate_packed",
        lambda _path: SimpleNamespace(ok=True, reason=None),
    )

    with pytest.raises(limited.LimitedReleaseError, match="source changed"):
        limited.build_bundle(_args(tmp_path, exe, dll))
    assert not (tmp_path / "dist").exists()
    assert list(tmp_path.glob(".dist.stage-*")) == []


def test_bundle_never_replaces_existing_output(monkeypatch, tmp_path):
    stub = _candidate(tmp_path)
    exe = tmp_path / "product.exe"
    dll = tmp_path / "product.dll"
    exe.write_bytes(b"exe-source")
    dll.write_bytes(b"dll-source")
    _patch_candidate(monkeypatch, stub)
    destination = tmp_path / "dist"
    destination.mkdir()
    marker = destination / "keep.txt"
    marker.write_text("original", encoding="ascii")

    with pytest.raises(limited.LimitedReleaseError, match="already exists"):
        limited.build_bundle(_args(tmp_path, exe, dll))
    assert marker.read_text(encoding="ascii") == "original"
