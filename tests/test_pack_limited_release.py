"""Constrained shipping-bundle orchestration regressions."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import pack_limited_release as limited
from packer import pe_analyze


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
        pe_analyze, "analyze_pe",
        lambda _path: SimpleNamespace(export_directory_rva=0, export_directory_size=0),
    )
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
        assert options.tamper_monitor is False
        assert options.server_shard is False
        assert options.virtualization_specs == ()
        assert options.stub_path == str(stub)
    assert "tamper-monitor" in payload["disabled_features"]
    steps = payload["required_before_distribution"]
    assert steps.index("Authenticode-sign and timestamp after packing") < steps.index(
        "regenerate and sign product integrity manifests over final distributed bytes")
    assert steps.index("regenerate and sign product integrity manifests over final distributed bytes") < steps.index(
        "run product-specific EXE and DLL-host workflows with integrity verification enabled")
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


@pytest.mark.parametrize(("rva", "size"), [(0x2000, 0), (0, 80)])
def test_bundle_rejects_exe_exports_before_any_packing(monkeypatch, tmp_path, rva, size):
    stub = _candidate(tmp_path)
    exe, dll = tmp_path / "product.exe", tmp_path / "product.dll"
    exe.write_bytes(b"exe-source")
    dll.write_bytes(b"dll-source")
    _patch_candidate(monkeypatch, stub)
    monkeypatch.setattr(limited.orchestrator, "detect_is_dll", lambda p: p.endswith(".dll"))
    monkeypatch.setattr(
        pe_analyze, "analyze_pe",
        lambda _path: SimpleNamespace(export_directory_rva=rva, export_directory_size=size),
    )
    calls = []
    monkeypatch.setattr(limited.orchestrator, "pack_file", lambda *args: calls.append(args))

    with pytest.raises(limited.LimitedReleaseError, match="incomplete EXE export directory"):
        limited.build_bundle(_args(tmp_path, exe, dll))
    assert calls == []
    assert not (tmp_path / "dist").exists()
    assert not list(tmp_path.glob(".dist.stage-*"))
    assert exe.read_bytes() == b"exe-source"
    assert dll.read_bytes() == b"dll-source"


def test_exported_exe_preflight_defers_to_export_capable_assembler(monkeypatch, tmp_path):
    exe = tmp_path / "exports.exe"
    exe.write_bytes(b"source")
    monkeypatch.setattr(limited.orchestrator, "detect_is_dll", lambda _p: False)
    monkeypatch.setattr(pe_analyze, "analyze_pe", lambda _p: SimpleNamespace(
        export_directory_rva=0x2000, export_directory_size=80))
    assert limited._inputs(SimpleNamespace(exe=[str(exe)], dll=[])) == [("exe", exe)]
    assert exe.read_bytes() == b"source"


def test_exe_export_preflight_parser_error_fails_closed(monkeypatch, tmp_path):
    exe = tmp_path / "product.exe"
    exe.write_bytes(b"invalid-source")
    monkeypatch.setattr(limited.orchestrator, "detect_is_dll", lambda _p: False)

    def fail(_path):
        raise ValueError("fixture malformed directory")

    monkeypatch.setattr(pe_analyze, "analyze_pe", fail)
    with pytest.raises(limited.LimitedReleaseError, match="fixture malformed directory"):
        limited._inputs(SimpleNamespace(exe=[str(exe)], dll=[]))


def _integrity_fixture(monkeypatch, tmp_path, *, exe_name="product.exe"):
    stub = _candidate(tmp_path)
    exe, dll = tmp_path / exe_name, tmp_path / "product.dll"
    exe.write_bytes(b"exe-source")
    dll.write_bytes(b"dll-source")
    _patch_candidate(monkeypatch, stub)
    monkeypatch.setattr(
        limited.orchestrator, "detect_is_dll",
        lambda path: Path(path).suffix.casefold() == ".dll",
    )
    monkeypatch.setattr(
        limited.report, "validate_packed",
        lambda _path: SimpleNamespace(ok=True, reason=None),
    )
    return _args(tmp_path, exe, dll), exe, dll


def _assert_unpublished(tmp_path):
    assert not (tmp_path / "dist").exists()
    assert list(tmp_path.glob(".dist.stage-*")) == []


def test_profile_explicitly_disables_tamper_monitor_if_core_default_changes(monkeypatch, tmp_path):
    args, exe, dll = _integrity_fixture(monkeypatch, tmp_path)
    original_options = limited.orchestrator.PackOptions
    def future_options(**kwargs):
        kwargs.setdefault("tamper_monitor", True)
        return original_options(**kwargs)
    monkeypatch.setattr(limited.orchestrator, "PackOptions", future_options)
    observed = []
    def fake_pack(source, options):
        observed.append(options.tamper_monitor)
        Path(options.output_path).write_bytes(b"packed-fixture")
        return SimpleNamespace(ok=True, error=None, build_id="fixture")
    monkeypatch.setattr(limited.orchestrator, "pack_file", fake_pack)
    limited.build_bundle(args)
    assert observed == [False, False]


@pytest.mark.parametrize("name", [limited.MANIFEST_NAME, limited.MANIFEST_NAME.upper()])
def test_bundle_reserves_manifest_filename_case_insensitively(monkeypatch, tmp_path, name):
    args, exe, dll = _integrity_fixture(monkeypatch, tmp_path, exe_name=name)
    calls = []

    def fake_pack(source, options):
        calls.append(source)
        Path(options.output_path).write_bytes(b"packed-fixture")
        return SimpleNamespace(ok=True, error=None, build_id="fixture")

    monkeypatch.setattr(limited.orchestrator, "pack_file", fake_pack)
    with pytest.raises(limited.LimitedReleaseError, match="reserved|manifest"):
        limited.build_bundle(args)
    assert calls == []
    assert exe.read_bytes() == b"exe-source"
    assert dll.read_bytes() == b"dll-source"
    _assert_unpublished(tmp_path)


def test_bundle_rechecks_earlier_output_before_publication(monkeypatch, tmp_path):
    args, exe, dll = _integrity_fixture(monkeypatch, tmp_path)
    outputs = []

    def fake_pack(_source, options):
        output = Path(options.output_path)
        output.write_bytes(b"packed-fixture")
        if outputs:
            # Same-length replacement must be caught by a digest, not size only.
            outputs[0].write_bytes(b"altered-output")
        outputs.append(output)
        return SimpleNamespace(ok=True, error=None, build_id="fixture")

    monkeypatch.setattr(limited.orchestrator, "pack_file", fake_pack)
    with pytest.raises(limited.LimitedReleaseError, match="output.*changed|changed.*output"):
        limited.build_bundle(args)
    assert len(outputs) == 2
    assert exe.read_bytes() == b"exe-source"
    assert dll.read_bytes() == b"dll-source"
    _assert_unpublished(tmp_path)


def test_bundle_rechecks_earlier_source_before_publication(monkeypatch, tmp_path):
    args, exe, dll = _integrity_fixture(monkeypatch, tmp_path)
    calls = []

    def fake_pack(source, options):
        calls.append(Path(source))
        Path(options.output_path).write_bytes(b"packed-fixture")
        if len(calls) == 2:
            exe.write_bytes(b"EXE-SOURCE")
        return SimpleNamespace(ok=True, error=None, build_id="fixture")

    monkeypatch.setattr(limited.orchestrator, "pack_file", fake_pack)
    with pytest.raises(limited.LimitedReleaseError, match="source changed"):
        limited.build_bundle(args)
    assert calls == [exe, dll]
    # Never roll back a concurrent source update while discarding our stage.
    assert exe.read_bytes() == b"EXE-SOURCE"
    assert dll.read_bytes() == b"dll-source"
    _assert_unpublished(tmp_path)


def test_bundle_pins_later_source_before_first_pack(monkeypatch, tmp_path):
    args, exe, dll = _integrity_fixture(monkeypatch, tmp_path)
    calls = []

    def fake_pack(source, options):
        calls.append(Path(source))
        Path(options.output_path).write_bytes(b"packed-fixture")
        if len(calls) == 1:
            dll.write_bytes(b"DLL-SOURCE")
        return SimpleNamespace(ok=True, error=None, build_id="fixture")

    monkeypatch.setattr(limited.orchestrator, "pack_file", fake_pack)
    with pytest.raises(limited.LimitedReleaseError, match="source changed"):
        limited.build_bundle(args)
    assert calls == [exe]
    assert exe.read_bytes() == b"exe-source"
    assert dll.read_bytes() == b"DLL-SOURCE"
    _assert_unpublished(tmp_path)


def test_snapshot_detects_same_size_bytes_with_original_mtime(tmp_path):
    path = tmp_path / "source.exe"
    path.write_bytes(b"original")
    original_stat = path.stat()
    expected = limited._snapshot(path, "source")
    path.write_bytes(b"modified")
    os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    with pytest.raises(limited.LimitedReleaseError, match="source changed"):
        limited._require_snapshot(path, expected, "source")
    assert path.read_bytes() == b"modified"


def test_snapshot_detects_replacement_even_with_identical_bytes(tmp_path):
    path = tmp_path / "source.exe"
    path.write_bytes(b"original")
    original_stat = path.stat()
    expected = limited._snapshot(path, "source")
    replacement = tmp_path / "replacement.exe"
    replacement.write_bytes(b"original")
    os.utime(replacement, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    assert replacement.stat().st_ino != original_stat.st_ino
    replacement.replace(path)
    with pytest.raises(limited.LimitedReleaseError, match="source changed"):
        limited._require_snapshot(path, expected, "source")
    assert path.read_bytes() == b"original"


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_snapshot_rejects_non_regular_input(tmp_path, kind):
    path = tmp_path / kind
    if kind == "directory":
        path.mkdir()
    with pytest.raises(limited.LimitedReleaseError, match="source changed"):
        limited._snapshot(path, "source")


def test_bundle_binds_structural_validation_to_output_bytes(monkeypatch, tmp_path):
    args, exe, dll = _integrity_fixture(monkeypatch, tmp_path)

    def fake_pack(source, options):
        Path(options.output_path).write_bytes(b"packed-fixture")
        return SimpleNamespace(ok=True, error=None, build_id="fixture")

    def mutate_during_validation(path):
        Path(path).write_bytes(b"altered-output")
        return SimpleNamespace(ok=True, reason=None)

    monkeypatch.setattr(limited.orchestrator, "pack_file", fake_pack)
    monkeypatch.setattr(limited.report, "validate_packed", mutate_during_validation)
    with pytest.raises(limited.LimitedReleaseError, match="output changed"):
        limited.build_bundle(args)
    assert exe.read_bytes() == b"exe-source"
    assert dll.read_bytes() == b"dll-source"
    _assert_unpublished(tmp_path)
