"""Strict generated EXE/DLL return-slot alias parity for imported CALL.

The fixture passes a stack-slot pointer from an outer caller to a selected
function.  The imported call overwrites that slot with its source return RIP;
without the materialized source-slot write, packed output diverges.  This is
not a proof about a native callee reading its own physical [RSP].
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from lifter import direct_control_flow
from packer import assemble, orchestrator, pe_analyze
from tests import test_native_virtualization_runtime as native_fixture

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "native_source_slot"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(argv: list[Path | str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(x) for x in argv], cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=120, check=False)


@pytest.mark.skipif(os.name != "nt" or
                    os.environ.get(native_fixture._RUN_GATE) != "1",
                    reason="opt-in Windows native materialized acceptance")
def test_source_call_slot_import_alias_materializes_exe_and_dll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not shutil.which("cmake") or not native_fixture._visual_studio_available():
        pytest.skip("CMake and Visual Studio x64 toolchain required")
    source = tmp_path / "source"
    shutil.copytree(FIXTURE, source)
    build = tmp_path / "build"
    for command in (["cmake", "-S", str(source), "-B", str(build),
                     "-G", "Visual Studio 17 2022", "-A", "x64"],
                    ["cmake", "--build", str(build), "--config", "Release"]):
        result = _run(command, tmp_path)
        assert result.returncode == 0, (command, result.stdout, result.stderr)
    release = build / "Release"
    host = release / "reference_host.exe"
    assert host.is_file()
    strict = os.environ.get("LETHE_STRICT_REFERENCE_STUB_PATH")
    if not strict:
        pytest.skip("pinned LETHE_STRICT_REFERENCE_STUB_PATH candidate required")
    stub = Path(strict).resolve()
    assert stub.is_file() and stub.with_suffix(".manifest.json").is_file()
    stub_pin = _sha(stub)
    manifest_pin = _sha(stub.with_suffix(".manifest.json"))
    monkeypatch.setenv(native_fixture._VIRTUALIZATION_GATE, "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")

    for kind in ("exe", "dll"):
        original = release / f"probe_{kind}.{kind}"
        original_pin = _sha(original)
        argv = [original] if kind == "exe" else [host, original]
        baseline = _run(argv, release)
        assert baseline.returncode == 0 and baseline.stderr == b""
        assert baseline.stdout.startswith(b"IMPORT_OPAQUE_RETURN_SLOT delta=")
        parsed = pe_analyze.analyze_pe(str(original))
        entry = assemble._StubImage(original.read_bytes()).find_export_rva("vm_probe")
        row, = (r for r in parsed.runtime_functions if r.begin_rva == entry)
        gaps = direct_control_flow._compute_coverage_gaps(
            direct_control_flow._normalize_sections(parsed),
            tuple((r.begin_rva, r.end_rva) for r in parsed.runtime_functions),
        )
        output_dir = tmp_path / f"packed_{kind}"
        output_dir.mkdir()
        output = output_dir / original.name
        options = orchestrator.PackOptions(
            output_path=str(output), is_dll=kind == "dll", stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec(
                "vm_probe", entry, row.end_rva - entry),),
            virtualization_gap_acknowledgements=tuple(
                orchestrator.VirtualizationGapAcknowledgement(
                    gap.rva, gap.size, "Generated source-slot fixture gap")
                for gap in gaps),
            acknowledge_unproven_indirect_targets=True,
            _allow_unverified_stub_for_tests=False,
        )
        packed = orchestrator.pack_file(str(original), options)
        assert packed.ok, packed.error
        assert output.is_file() and _sha(output) != original_pin
        actual = _run([output] if kind == "exe" else [host, output], release)
        assert (actual.returncode, actual.stdout, actual.stderr) == (
            baseline.returncode, baseline.stdout, baseline.stderr)
        assert _sha(original) == original_pin
    assert _sha(stub) == stub_pin
    assert _sha(stub.with_suffix(".manifest.json")) == manifest_pin