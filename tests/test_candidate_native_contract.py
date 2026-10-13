"""Candidate-bound generated EXE/DLL VM-positive and opaque-native negatives.

Promotion runs this against its fresh raw stub via LETHE_NATIVE_RUNTIME_STUB_PATH;
the test-only bound copy exists because the schema-2 bundle is not staged yet.
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
from tests import test_native_virtualization_runtime as runtime

_RUN_GATE = "LETHE_RUN_NATIVE_VM_E2E"
_SOURCE = Path(__file__).resolve().parent / "fixtures" / "native_import_contract"
_SAFE_ASM = """OPTION CASEMAP:NONE
PUBLIC vm_probe
.data
PUBLIC reference_slot
reference_slot QWORD retained_anchor
.code
vm_probe PROC FRAME
 sub rsp,28h
 .allocstack 28h
 .endprolog
 jmp vm_entry
vm_inner:
 mov eax,42
 ret
vm_entry:
 call vm_inner
 add rsp,28h
 ret
vm_probe ENDP
retained_anchor PROC FRAME
 .endprolog
 xor eax,eax
 ret
retained_anchor ENDP
END
"""
_DIRECT_ASM = """OPTION CASEMAP:NONE
PUBLIC vm_probe
.data
PUBLIC reference_slot
reference_slot QWORD retained_anchor
.code
vm_probe PROC FRAME
 sub rsp,28h
 .allocstack 28h
 .endprolog
 call retained_anchor
 add rsp,28h
 ret
vm_probe ENDP
retained_anchor PROC FRAME
 .endprolog
 mov eax,42
 ret
retained_anchor ENDP
END
"""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(argv: list[str | Path], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(part) for part in argv], cwd=cwd,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=120, check=False)


@pytest.fixture(scope="module")
def bound_stub(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if os.name != "nt" or os.environ.get(_RUN_GATE) != "1":
        pytest.skip("opt-in Windows materialized candidate contract")
    if not shutil.which("cmake") or not runtime._visual_studio_available():
        pytest.skip("CMake + Visual Studio x64 toolchain required")
    work = tmp_path_factory.mktemp("native-contract-runtime")
    stub = runtime._candidate_stub_or_build(work)
    raw_text = os.environ.get("LETHE_NATIVE_RUNTIME_STUB_PATH")
    if raw_text:
        raw = Path(raw_text).resolve()
        assert raw.is_file() and _sha(stub) == _sha(raw)
    assert stub.is_file() and Path(str(stub) + ".manifest.json").is_file()
    return stub


def _build_case(work: Path, *, case: str) -> tuple[Path, Path, Path]:
    source = work / "source"
    shutil.copytree(_SOURCE / (case if case in ("return_site", "home_write") else "return_site"), source)
    if case in ("safe_internal", "direct_pdata"):
        (source / "fixture.asm").write_text(
            _SAFE_ASM if case == "safe_internal" else _DIRECT_ASM,
            encoding="ascii")
        c = (source / "fixture.c").read_text(encoding="ascii")
        c = c.replace("(v==0x48)", "(v==42)").replace(
            "IMPORT_RETURN byte=", "VM_INTERNAL value=" if case == "safe_internal" else "NATIVE_DIRECT value=")
        (source / "fixture.c").write_text(c, encoding="ascii")
    build = work / "build"
    for argv in (("cmake", "-S", str(source), "-B", str(build),
                  "-G", "Visual Studio 17 2022", "-A", "x64"),
                 ("cmake", "--build", str(build), "--config", "Release")):
        result = _run(list(argv), work)
        assert result.returncode == 0, (argv, result.stdout, result.stderr)
    release = build / "Release"
    prefix = "import_home" if case == "home_write" else "import_return"
    return release / f"{prefix}_exe.exe", release / f"{prefix}_dll.dll", release / "reference_host.exe"


def _spec_and_gaps(source: Path) -> tuple[plan.FunctionSpec, tuple[orchestrator.VirtualizationGapAcknowledgement, ...]]:
    image = assemble._StubImage(source.read_bytes())
    parsed = pe_analyze.analyze_pe(str(source))
    entry = image.find_export_rva("vm_probe")
    assert entry is not None
    row, = (record for record in parsed.runtime_functions if record.begin_rva == entry)
    spec = plan.FunctionSpec("vm_probe", entry, row.end_rva - entry)
    gaps = direct_control_flow._compute_coverage_gaps(
        direct_control_flow._normalize_sections(parsed),
        tuple((record.begin_rva, record.end_rva) for record in parsed.runtime_functions))
    # The generated EXE has ten CC alignment bytes; the generated DLL also
    # exposes the exact six-byte DllMain leaf before the same ten CC bytes.
    # Constrain this fixture-specific acknowledgement to those exact bytes.
    assert len(gaps) == 1
    gap_bytes = pe_analyze._slice_at_rva(
        parsed.sections, gaps[0].rva, gaps[0].size,
        what="generated alignment gap")
    expected_gap = (b"\xB8\x01\x00\x00\x00\xC3" if source.suffix.lower() == ".dll" else b"") + b"\xCC" * 10
    assert gap_bytes == expected_gap
    approvals = tuple(orchestrator.VirtualizationGapAcknowledgement(
        gap.rva, gap.size, "generated candidate contract fixture executable gap")
        for gap in gaps)
    return spec, approvals


def _pack(source: Path, target: Path, stub: Path, spec: plan.FunctionSpec,
          approvals: tuple[orchestrator.VirtualizationGapAcknowledgement, ...]):
    return orchestrator.pack_file(str(source), orchestrator.PackOptions(
        output_path=str(target), is_dll=source.suffix.lower() == ".dll",
        stub_path=str(stub), virtualization_specs=(
            orchestrator.VirtualizationSpec(spec.name, spec.rva, spec.size),),
        virtualization_gap_acknowledgements=approvals,
        acknowledge_unproven_indirect_targets=True,
        _allow_unverified_stub_for_tests=True))


def test_materialized_internal_vm_call_exe_and_dll_parity(
    bound_stub: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    exe, dll, host = _build_case(tmp_path, case="safe_internal")
    stub_pin = _sha(bound_stub)
    for source in (exe, dll):
        original_pin = _sha(source)
        argv = [source] if source == exe else [host, source]
        before = _run(argv, source.parent)
        assert (before.returncode, before.stdout, before.stderr) == (
            0, b"VM_INTERNAL value=42 passed=true\n", b"")
        spec, approvals = _spec_and_gaps(source)
        output = source.with_name(source.stem + ".packed" + source.suffix)
        outcome = _pack(source, output, bound_stub, spec, approvals)
        assert outcome.ok, outcome.error
        after = _run([output] if source == exe else [host, output], source.parent)
        assert (after.returncode, after.stdout, after.stderr) == (
            before.returncode, before.stdout, before.stderr)
        assert _sha(source) == original_pin
    assert _sha(bound_stub) == stub_pin


@pytest.mark.parametrize("case", ("direct_pdata", "return_site", "home_write"))
def test_native_callee_without_physical_frame_rejects_exe_and_dll(
    case: str, bound_stub: Path, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    exe, dll, host = _build_case(tmp_path, case=case)
    expected = ("retained PDATA native CALL lacks physical return-slot"
                if case == "direct_pdata" else
                "opaque native CALL lacks physical callee return-address")
    stub_pin = _sha(bound_stub)
    for source in (exe, dll):
        original_pin = _sha(source)
        argv = [source] if source == exe else [host, source]
        before = _run(argv, source.parent)
        assert before.returncode == 0 and before.stderr == b"" and b"passed=true" in before.stdout
        spec, approvals = _spec_and_gaps(source)
        parsed = pe_analyze.analyze_pe(str(source))
        candidate, = (item for item in function_discovery.discover_functions(parsed).candidates
                      if item.rva == spec.rva)
        assert not candidate.liftable and expected in candidate.rejection_reason
        output = source.with_name(source.stem + ".must-not-exist" + source.suffix)
        outcome = _pack(source, output, bound_stub, spec, approvals)
        assert not outcome.ok and expected in outcome.error
        assert not output.exists() and _sha(source) == original_pin
    assert _sha(bound_stub) == stub_pin
