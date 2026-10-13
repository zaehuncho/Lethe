"""Generated EXE/DLL source return-slot alias remains a native-callee negative.

The VM can materialize the source caller's [RSP-8] write, but the physical
imported callee executes on the bridge's separate frame. Its [RSP] and mutable
Win64 home slots have no proven source-equivalent contract, so packing rejects.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from lifter import direct_control_flow, function_discovery, virtualization_plan as plan
from packer import assemble, orchestrator, pe_analyze
_RUN_GATE = "LETHE_RUN_NATIVE_VM_E2E"

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "native_source_slot"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(argv: list[Path | str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(x) for x in argv], cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=120, check=False)


@pytest.mark.skipif(os.name != "nt" or
                    os.environ.get(_RUN_GATE) != "1",
                    reason="opt-in Windows native materialized acceptance")
def test_source_call_slot_import_alias_rejects_unproven_callee_exe_and_dll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not shutil.which("cmake"):
        pytest.skip("CMake and Visual Studio x64 toolchain required")
    stub_text = (os.environ.get("LETHE_STRICT_REFERENCE_STUB_PATH") or
                 os.environ.get("LETHE_NATIVE_RUNTIME_STUB_PATH"))
    assert stub_text, "strict verified candidate path required for pack-path regression"
    stub = Path(stub_text).resolve()
    assert stub.is_file() and stub.with_suffix(".manifest.json").is_file()
    stub_pin = _sha(stub)
    manifest_pin = _sha(stub.with_suffix(".manifest.json"))
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
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
        spec = plan.FunctionSpec("vm_probe", entry, row.end_rva - entry)
        records = tuple(plan.SourceRuntimeFunction(
            r.begin_rva, r.end_rva, r.unwind_info_rva,
            r.unwind_flags, r.chain_primary_rva,
        ) for r in parsed.runtime_functions)
        exceptions = plan.SourceExceptionMetadata(parsed.pdata_rva, records)
        imports = tuple(function.iat_rva for dll in parsed.imports for function in dll.funcs)
        text_rva = (parsed.size_of_image + 0xFFF) & ~0xFFF
        with pytest.raises(plan.FunctionRejected, match="opaque native CALL lacks physical callee return-address"):
            plan.compile_virtualization_manifest(
                (spec,), plan.SectionImage.from_parsed_sections(parsed.sections),
                generated_text_rva=text_rva, generated_data_rva=text_rva + 0x2000,
                source_exception_metadata=exceptions, source_import_iat_rvas=imports,
            )
        candidate = next(r for r in function_discovery.discover_functions(parsed).candidates
                         if r.rva == entry)
        assert not candidate.liftable
        assert "opaque native CALL lacks physical callee return-address" in candidate.rejection_reason
        gaps = direct_control_flow._compute_coverage_gaps(
            direct_control_flow._normalize_sections(parsed),
            tuple((r.begin_rva, r.end_rva) for r in parsed.runtime_functions),
        )
        output = tmp_path / f"packed_{kind}.{kind}"
        options = orchestrator.PackOptions(
            output_path=str(output), is_dll=kind == "dll", stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec(
                "vm_probe", entry, row.end_rva - entry),),
            virtualization_gap_acknowledgements=tuple(
                orchestrator.VirtualizationGapAcknowledgement(
                    gap.rva, gap.size, "Exact generated source-slot fixture gap")
                for gap in gaps),
            acknowledge_unproven_indirect_targets=True,
            _allow_unverified_stub_for_tests=False,
        )
        packed = orchestrator.pack_file(str(original), options)
        assert not packed.ok
        assert "opaque native CALL lacks physical callee return-address" in packed.error
        assert "shadow-space effects proof" in packed.error
        assert not output.exists()
        assert _sha(original) == original_pin
    assert _sha(stub) == stub_pin
    assert _sha(stub.with_suffix(".manifest.json")) == manifest_pin
