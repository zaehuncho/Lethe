"""Opt-in native corpus for multi-function selected-code virtualization.

The fixture is assembled by the MSVC x64 toolchain so the instruction corpus is
stable across optimizer revisions.  Every selected routine has explicit x64
unwind metadata; its export RVA must exactly match a ``.pdata`` extent before it
is admitted to the pack.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from daedalus import shuffle_opcodes
from iced_x86 import Decoder, Mnemonic
from lifter import direct_control_flow, virtualization_plan, x64_lifter
from packer import assemble, orchestrator, pe_analyze, virtualize


ROOT = Path(__file__).resolve().parents[1]
_RUN_GATE = "LETHE_RUN_NATIVE_VM_CORPUS"
_VIRTUALIZATION_GATE = "LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION"
_SHUFFLE_SEED = "5a" * 32
_EXPECTED_STDOUT = (
    b"narrow=1122334455666634 select=20/29 "
    b"carry=0000000000000000 bswap=04030201 "
    b"wide=ce8ece0ece8ecfad\r\n"
)


def _visual_studio_available() -> bool:
    if shutil.which("cl.exe") and shutil.which("ml64.exe"):
        return True
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return False
    probe = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _run_checked(command: list[str], *, cwd: Path) -> None:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=240,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout


def _build_fixture(work: Path) -> Path:
    source = work / "corpus_source"
    build = work / "corpus_build"
    source.mkdir()
    (source / "fixture.c").write_text(
        r"""
#include <stdint.h>
#include <windows.h>

uint64_t vm_narrow(uint64_t x, uint64_t y);
uint32_t vm_select(int32_t x, int32_t y);
uint64_t vm_carry(uint64_t x, uint64_t y, uint64_t carry, uint64_t sub);
uint32_t vm_bswap_mem(const uint32_t *value, uint32_t mix);
uint64_t vm_wide_mul(uint64_t x, uint64_t y);

__declspec(noreturn) void corpus_entry(void)
{
    static const char ok[] =
        "narrow=1122334455666634 select=20/29 "
        "carry=0000000000000000 bswap=04030201 "
        "wide=ce8ece0ece8ecfad\r\n";
    static const char mismatch[] = "corpus-mismatch\r\n";
    const uint32_t memory_value = 0x01020304UL;
    const uint64_t narrow = vm_narrow(0x80ULL, 0x1234ULL);
    const uint32_t select_low = vm_select(7, 19);
    const uint32_t select_high = vm_select(29, 11);
    const uint64_t carry = vm_carry(
        0xfffffffffffffffdULL, 5ULL, 1ULL, 2ULL);
    const uint32_t swapped = vm_bswap_mem(&memory_value, 0x10UL);
    const uint64_t wide = vm_wide_mul(
        0xfffffffffffffff0ULL, 0x123456789abcdef0ULL);
    const int valid = narrow == 0x1122334455666634ULL
        && select_low == 20UL
        && select_high == 29UL
        && carry == 0ULL
        && swapped == 0x04030201UL
        && wide == 0xce8ece0ece8ecfadULL;
    const char *message = valid ? ok : mismatch;
    const DWORD size = valid ? (DWORD)(sizeof(ok) - 1) : (DWORD)(sizeof(mismatch) - 1);
    DWORD written = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, size, &written, NULL);
    ExitProcess(valid ? 0U : 19U);
}
""".lstrip(),
        encoding="ascii",
    )
    (source / "fixture.asm").write_text(
        r"""
OPTION CASEMAP:NONE

.code

PUBLIC vm_narrow
vm_narrow PROC FRAME
    sub rsp, 40h
    .allocstack 40h
    .endprolog
    mov r10, 1122334455667700h
    mov r10b, cl
    mov word ptr [rsp+20h], dx
    mov byte ptr [rsp+22h], r10b
    movzx eax, word ptr [rsp+20h]
    movsx r9d, byte ptr [rsp+22h]
    movsxd r8, r9d
    add rax, r8
    xor rax, r10
    add rsp, 40h
    ret
vm_narrow ENDP

PUBLIC vm_select
vm_select PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    cmp ecx, edx
    setl al
    movzx eax, al
    mov r8d, edx
    cmovg r8d, ecx
    add eax, r8d
    add rsp, 28h
    ret
vm_select ENDP

PUBLIC vm_carry
vm_carry PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rax, rcx
    and r8d, 1
    neg r8
    adc rax, rdx
    sbb rax, r9
    add rsp, 28h
    ret
vm_carry ENDP

PUBLIC vm_bswap_mem
vm_bswap_mem PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov eax, dword ptr [rcx]
    bswap eax
    add eax, edx
    xchg eax, edx
    xor eax, edx
    add rsp, 28h
    ret
vm_bswap_mem ENDP

PUBLIC vm_wide_mul
vm_wide_mul PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov r8, rdx
    xor r10d, r10d
    xor r11d, r11d
    mov rax, rcx
    mul r8
    setc r10b
    seto r11b
    shl r11, 8
    or r10, r11
    mov r9, rax
    xor r9, rdx
    xor r9, r10
    xor r10d, r10d
    xor r11d, r11d
    mov rax, -17
    mov r8, 19
    imul r8
    setc r10b
    seto r11b
    shl r11, 8
    or r10, r11
    xor rax, rdx
    xor rax, r9
    xor rax, r10
    add rsp, 28h
    ret
vm_wide_mul ENDP

END
""".lstrip(),
        encoding="ascii",
    )
    (source / "CMakeLists.txt").write_text(
        r"""
cmake_minimum_required(VERSION 3.20)
project(lethe_native_vm_corpus LANGUAGES C ASM_MASM)
add_executable(vm_corpus fixture.c fixture.asm)
set_source_files_properties(fixture.c PROPERTIES
    COMPILE_OPTIONS "/W4;/WX;/O2;/GS-")
target_link_options(vm_corpus PRIVATE
    /INCREMENTAL:NO /OPT:NOICF /FIXED /NXCOMPAT
    /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:corpus_entry /SUBSYSTEM:CONSOLE
    /EXPORT:vm_narrow /EXPORT:vm_select /EXPORT:vm_carry
    /EXPORT:vm_bswap_mem /EXPORT:vm_wide_mul)
target_link_libraries(vm_corpus PRIVATE kernel32.lib)
""".lstrip(),
        encoding="ascii",
    )
    _run_checked(
        [
            "cmake",
            "-S",
            str(source),
            "-B",
            str(build),
            "-G",
            "Visual Studio 17 2022",
            "-A",
            "x64",
        ],
        cwd=work,
    )
    _run_checked(
        ["cmake", "--build", str(build), "--config", "Release"],
        cwd=work,
    )
    executable = build / "Release" / "vm_corpus.exe"
    assert executable.is_file()
    return executable


def _build_stub(work: Path) -> Path:
    build = work / "stub_build"
    _run_checked(
        [
            "cmake",
            "-S",
            str(ROOT / "stub"),
            "-B",
            str(build),
            "-G",
            "Visual Studio 17 2022",
            "-A",
            "x64",
            f"-DDVM_SHUFFLE_SEED={_SHUFFLE_SEED}",
            "-DDVM_ROLLING=OFF",
            "-DDVM_ROLL_POISON=OFF",
            "-DBUILD_TESTING=OFF",
        ],
        cwd=work,
    )
    _run_checked(
        ["cmake", "--build", str(build), "--config", "Release"],
        cwd=work,
    )
    stub = build / "Release" / "lethe_stub_x64.dll"
    stub_bytes = stub.read_bytes()
    shuffled = shuffle_opcodes.generate_shuffle(bytes.fromhex(_SHUFFLE_SEED))
    manifest = {
        "schema": 1,
        "artifact": stub.name,
        "size_bytes": len(stub_bytes),
        "sha256": hashlib.sha256(stub_bytes).hexdigest(),
        "dvm_shuffle_seed": _SHUFFLE_SEED,
        "dvm_handler_variant_sha256": shuffled["handler_variant_sha256"],
        "dvm_rolling": False,
        "dvm_paged_runtime": True,
    }
    Path(str(stub) + ".manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    return stub


def _function_specs(
    executable: Path,
) -> tuple[pe_analyze.ParsedPE, tuple[virtualization_plan.FunctionSpec, ...]]:
    parsed = pe_analyze.analyze_pe(str(executable))
    image = assemble._StubImage(executable.read_bytes())
    specs = []
    for name in (
        "vm_narrow", "vm_select", "vm_carry", "vm_bswap_mem", "vm_wide_mul"
    ):
        export_rva = image.find_export_rva(name)
        assert export_rva is not None, f"missing fixture export {name}"
        records = tuple(
            item for item in parsed.runtime_functions
            if item.begin_rva == export_rva
        )
        assert len(records) == 1, (
            f"{name} export RVA 0x{export_rva:X} did not name one exact .pdata extent"
        )
        record = records[0]
        assert record.end_rva > record.begin_rva
        specs.append(
            virtualization_plan.FunctionSpec(
                name, record.begin_rva, record.end_rva - record.begin_rva
            )
        )
    return parsed, tuple(specs)


def _mnemonics(
    parsed: pe_analyze.ParsedPE,
    spec: virtualization_plan.FunctionSpec,
) -> frozenset[Mnemonic]:
    raw = pe_analyze._slice_at_rva(
        parsed.sections, spec.rva, spec.size, what=f"native corpus {spec.name}"
    )
    instructions = tuple(Decoder(64, raw, ip=spec.rva))
    assert instructions
    assert sum(instruction.len for instruction in instructions) == spec.size
    x64_lifter.lift_function(raw, spec.rva)
    return frozenset(instruction.mnemonic for instruction in instructions)


def _run(executable: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(executable)],
        cwd=str(executable.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


@pytest.mark.skipif(os.name != "nt", reason="native loader is Windows-only")
def test_native_selected_function_corpus_matches_original(monkeypatch) -> None:
    if os.environ.get(_RUN_GATE) != "1":
        pytest.skip(f"set {_RUN_GATE}=1 to run the native virtualization corpus")
    pytest.importorskip("lief")
    pytest.importorskip("iced_x86")
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio C/ML64 x64 toolchain are required")

    root = ROOT.resolve()
    work = Path(tempfile.mkdtemp(prefix=".native_vm_corpus_", dir=root)).resolve()
    if work.parent != root or not work.name.startswith(".native_vm_corpus_"):
        pytest.fail(f"native corpus directory escaped repository root: {work}")
    try:
        source = _build_fixture(work)
        parsed, specs = _function_specs(source)
        by_name = {spec.name: _mnemonics(parsed, spec) for spec in specs}
        assert {Mnemonic.MOVZX, Mnemonic.MOVSX, Mnemonic.MOVSXD} <= by_name[
            "vm_narrow"
        ]
        assert {Mnemonic.SETL, Mnemonic.CMOVG} <= by_name["vm_select"]
        assert {Mnemonic.ADC, Mnemonic.SBB} <= by_name["vm_carry"]
        assert {Mnemonic.BSWAP, Mnemonic.XCHG} <= by_name["vm_bswap_mem"]
        assert {Mnemonic.MUL, Mnemonic.IMUL} <= by_name["vm_wide_mul"]

        proof = direct_control_flow.analyze_direct_control_flow(
            parsed, specs, production=False
        )
        for spec in specs:
            assert any(
                transfer.target_rva == spec.rva
                and transfer.target_is_selected_entry
                for transfer in proof.direct_transfers
            ), f"no decoded direct call targets {spec.name}"
        gap_acknowledgements = tuple(
            orchestrator.VirtualizationGapAcknowledgement(
                gap.rva,
                gap.size,
                "exact first-party native corpus linker/compiler executable gap",
            )
            for gap in proof.coverage_gaps
        )

        original_run = _run(source)
        assert original_run.returncode == 0
        assert original_run.stdout == _EXPECTED_STDOUT
        assert original_run.stderr == b""

        stub = _build_stub(work)
        (_stub_bytes, _stub_sha256, opcode_table,
         handler_variant_sha256, rolling) = (
            orchestrator._load_virtualization_build(
                str(stub), allow_unverified_stub_for_tests=True)
        )
        shuffled = shuffle_opcodes.generate_shuffle(bytes.fromhex(_SHUFFLE_SEED))
        assert not opcode_table.is_canonical
        assert handler_variant_sha256 == shuffled["handler_variant_sha256"]
        assert rolling is False
        captured = {}
        materialize = virtualize.materialize_selected_functions

        def capture_materialization(*args, **kwargs):
            result = materialize(*args, **kwargs)
            captured["result"] = result
            return result

        monkeypatch.setattr(
            virtualize, "materialize_selected_functions", capture_materialization
        )
        monkeypatch.setenv(_VIRTUALIZATION_GATE, "1")
        packed = work / "vm_corpus.packed.exe"
        progress: list[str] = []
        result = orchestrator.pack_file(
            str(source),
            orchestrator.PackOptions(
                output_path=str(packed),
                is_dll=False,
                stub_path=str(stub),
                virtualization_specs=tuple(
                    orchestrator.VirtualizationSpec(
                        spec.name, spec.rva, spec.size
                    )
                    for spec in specs
                ),
                virtualization_gap_acknowledgements=gap_acknowledgements,
                acknowledge_unproven_indirect_targets=True,
                _allow_unverified_stub_for_tests=True,
            ),
            progress.append,
        )
        assert result.ok, result.error
        assert packed.is_file()
        assert len(captured["result"].manifest.functions) == len(specs)
        assert any("virtualized 5 selected function" in line for line in progress)

        packed_run = _run(packed)
        assert packed_run.returncode == original_run.returncode
        assert packed_run.stdout == original_run.stdout
        assert packed_run.stderr == original_run.stderr
    finally:
        if (
            work.parent == root
            and work.name.startswith(".native_vm_corpus_")
            and work.exists()
        ):
            shutil.rmtree(work)
