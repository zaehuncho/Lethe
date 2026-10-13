"""Production native-call admission requires the physical callee-frame contract.

The diagnostic VM bridge still exists, but opaque import and GuardCF targets
may inspect physical [RSP] or mutate Win64 caller home slots. Exact IAT/PDATA
identity does not prove equivalence. Selected internal VM CALL remains positive.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
from types import SimpleNamespace

import pytest
from keystone import KS_ARCH_X86, KS_MODE_64, Ks

from lifter import direct_control_flow, function_discovery, virtualization_plan as plan
from packer import assemble, orchestrator, pe_analyze


_EXEC = 0x60000020
_DATA = 0x40000040
_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "native_import_contract"
_EXPECTED = {
    "return_site": b"IMPORT_RETURN byte=72 passed=true\n",
    "home_write": b"IMPORT_HOME value=42 passed=true\n",
}


def _image(code: bytes, *, slot: int = 0x3000):
    sections = (
        plan.SectionBytes(".text", 0x1000, 0x100, code + b"\xCC" * (0x100 - len(code)), _EXEC),
        plan.SectionBytes(".rdata", slot, 0x40, bytes(0x40), _DATA),
    )
    records = (plan.SourceRuntimeFunction(0x1000, 0x1000 + len(code), 0x4000),)
    return sections, records


def _plan(code: bytes, sections, records, *, imports=(), guard=None):
    return plan.compile_virtualization_manifest(
        (plan.FunctionSpec("caller", 0x1000, len(code)),),
        plan.SectionImage(sections), generated_text_rva=0x6000,
        generated_data_rva=0x8000,
        source_exception_metadata=plan.SourceExceptionMetadata(0x5000, records),
        source_import_iat_rvas=tuple(imports), guard_cf_dispatch_rva=guard,
    )


def _discover(code: bytes, sections, records, *, imports=()):
    parsed = SimpleNamespace(
        path="generated-contract.exe", image_base=0x140000000,
        size_of_image=0x9000, sections=sections, pdata_rva=0x5000,
        pdata_count=len(records), runtime_functions=records,
        imports=(SimpleNamespace(funcs=tuple(SimpleNamespace(iat_rva=i) for i in imports)),),
    )
    report = function_discovery.discover_functions(parsed, exports=())
    return next(row for row in report.candidates if row.rva == 0x1000)


@pytest.mark.parametrize("kind", ("import", "guard", "opaque_pointer"))
def test_rip_indirect_native_call_rejects_before_materialization(kind: str) -> None:
    slot = 0x3000
    call_end = 0x100A
    code = (b"\x48\x83\xEC\x28\xFF\x15" + struct.pack("<i", slot - call_end)
            + b"\x48\x83\xC4\x28\xC3")
    sections, records = _image(code)
    imports = (slot,) if kind == "import" else ()
    guard = slot if kind == "guard" else None
    with pytest.raises(plan.FunctionRejected, match=r"opaque native CALL lacks physical callee return-address.*0x1004"):
        _plan(code, sections, records, imports=imports, guard=guard)
    row = _discover(code, sections, records, imports=imports)
    assert not row.liftable
    assert "opaque native CALL lacks physical callee return-address" in row.rejection_reason
    assert row.first_unsupported_instruction.rva == 0x1004


def test_internal_vm_call_remains_materializable_and_discoverable() -> None:
    source = "jmp entry; inner: mov eax,42; ret; entry: call inner; ret"
    encoded, _ = Ks(KS_ARCH_X86, KS_MODE_64).asm(source, addr=0x1000)
    code = bytes(encoded)
    sections, records = _image(code)
    manifest = _plan(code, sections, records)
    assert len(manifest.functions) == 1
    function = manifest.functions[0]
    assert len(function.internal_call_rvas) == 1
    assert function.capabilities["direct_internal_calls_supported"] is True
    assert function.capabilities["external_calls_supported"] is False
    row = _discover(code, sections, records)
    assert row.liftable, row.rejection_reason
    assert row.internal_direct_call_count == 1


def _run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=180, check=False)


def _planner_for_generated(image_path: Path):
    parsed = pe_analyze.analyze_pe(str(image_path))
    entry = assemble._StubImage(image_path.read_bytes()).find_export_rva("vm_probe")
    row, = (item for item in parsed.runtime_functions if item.begin_rva == entry)
    spec = plan.FunctionSpec("vm_probe", entry, row.end_rva - entry)
    records = tuple(plan.SourceRuntimeFunction(
        item.begin_rva, item.end_rva, item.unwind_info_rva,
        item.unwind_flags, item.chain_primary_rva,
    ) for item in parsed.runtime_functions)
    exceptions = plan.SourceExceptionMetadata(parsed.pdata_rva, records)
    imports = tuple(function.iat_rva for dll in parsed.imports for function in dll.funcs)
    text_rva = (parsed.size_of_image + 0xFFF) & ~0xFFF
    data_rva = text_rva + 0x2000
    with pytest.raises(plan.FunctionRejected, match="opaque native CALL lacks physical callee return-address") as caught:
        plan.compile_virtualization_manifest(
            (spec,), plan.SectionImage.from_parsed_sections(parsed.sections),
            generated_text_rva=text_rva, generated_data_rva=data_rva,
            source_exception_metadata=exceptions, source_import_iat_rvas=imports,
        )
    discovered = function_discovery.discover_functions(parsed)
    candidate = next(item for item in discovered.candidates if item.rva == entry)
    assert not candidate.liftable
    assert "opaque native CALL lacks physical callee return-address" in candidate.rejection_reason
    return str(caught.value)


@pytest.mark.skipif(os.name != "nt" or os.environ.get("LETHE_RUN_NATIVE_VM_E2E") != "1",
                    reason="opt-in Windows generated EXE/DLL contract regression")
@pytest.mark.parametrize("fixture", ("return_site", "home_write"))
def test_generated_imported_callee_contract_rejects_exe_and_dll(
    fixture: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not shutil.which("cmake"):
        pytest.skip("CMake and Visual Studio x64 toolchain required")
    stub_text = (os.environ.get("LETHE_STRICT_REFERENCE_STUB_PATH") or
                 os.environ.get("LETHE_NATIVE_RUNTIME_STUB_PATH"))
    assert stub_text, "strict verified candidate path required for pack-path regression"
    stub = Path(stub_text).resolve()
    assert stub.is_file() and stub.with_suffix(".manifest.json").is_file()
    stub_pin = hashlib.sha256(stub.read_bytes()).hexdigest()
    manifest_pin = hashlib.sha256(stub.with_suffix(".manifest.json").read_bytes()).hexdigest()
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    source = tmp_path / "source"
    shutil.copytree(_FIXTURES / fixture, source)
    build = tmp_path / "build"
    for command in (["cmake", "-S", str(source), "-B", str(build),
                     "-G", "Visual Studio 17 2022", "-A", "x64"],
                    ["cmake", "--build", str(build), "--config", "Release"]):
        result = _run(command, tmp_path)
        assert result.returncode == 0, (command, result.stdout, result.stderr)
    release = build / "Release"
    prefix = "import_return" if fixture == "return_site" else "import_home"
    host = release / "reference_host.exe"
    for kind in ("exe", "dll"):
        original = release / f"{prefix}_{kind}.{kind}"
        original_bytes = original.read_bytes()
        argv = [str(original)] if kind == "exe" else [str(host), str(original)]
        normal = _run(argv, release)
        assert (normal.returncode, normal.stdout, normal.stderr) == (0, _EXPECTED[fixture], b"")
        rejection = _planner_for_generated(original)
        assert "shadow-space effects proof" in rejection
        parsed = pe_analyze.analyze_pe(str(original))
        entry = assemble._StubImage(original_bytes).find_export_rva("vm_probe")
        row, = (item for item in parsed.runtime_functions if item.begin_rva == entry)
        gaps = direct_control_flow._compute_coverage_gaps(
            direct_control_flow._normalize_sections(parsed),
            tuple((item.begin_rva, item.end_rva) for item in parsed.runtime_functions),
        )
        output = tmp_path / f"packed_{fixture}_{kind}.{kind}"
        options = orchestrator.PackOptions(
            output_path=str(output), is_dll=kind == "dll", stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec(
                "vm_probe", entry, row.end_rva - entry),),
            virtualization_gap_acknowledgements=tuple(
                orchestrator.VirtualizationGapAcknowledgement(
                    gap.rva, gap.size, "Exact generated opaque-callee fixture gap")
                for gap in gaps),
            acknowledge_unproven_indirect_targets=True,
            _allow_unverified_stub_for_tests=False,
        )
        packed = orchestrator.pack_file(str(original), options)
        assert not packed.ok
        assert "opaque native CALL lacks physical callee return-address" in packed.error
        assert "shadow-space effects proof" in packed.error
        assert not output.exists()
        assert original.read_bytes() == original_bytes
    assert hashlib.sha256(stub.read_bytes()).hexdigest() == stub_pin
    assert hashlib.sha256(stub.with_suffix(".manifest.json").read_bytes()).hexdigest() == manifest_pin
