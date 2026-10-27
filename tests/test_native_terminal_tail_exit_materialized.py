"""Materialized EXE/DLL parity for a proven terminal direct E9 native tail.

The selected wrapper ends in one raw E9.  It computes CF in virtualized code;
the retained native target consumes that flag, the original register arguments,
the caller's fifth stack argument, and a Win64 home slot.  This therefore
exercises the status-2 continuation, exact source RSP, flags, GPRs, split
unwind metadata, and the static target E9 rather than treating a normal RET
as a substitute.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import tempfile

import pytest

from lifter import direct_control_flow, virtualization_plan, win64_thunk
from packer import assemble, bytecode_pages, orchestrator, pe_analyze, virtualize


ROOT = Path(__file__).resolve().parents[1]
_RUN_GATE = "LETHE_RUN_NATIVE_VM_E2E"
_VIRTUALIZATION_GATE = "LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION"
_DLL_GATE = "LETHE_ENABLE_EXPERIMENTAL_DLL"
_SHUFFLE_SEED = "3141592653589793238462643383279502884197169399375105820974944592"
_EXPECTED = b"tail-answer=151\r\n"


def _visual_studio_available() -> bool:
    if shutil.which("cl.exe"):
        return True
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return False
    probe = subprocess.run(
        [
            str(vswhere), "-latest", "-products", "*",
            "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property", "installationPath",
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
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout


def _build_stub(work: Path) -> Path:
    build = work / "stub_build"
    _run_checked(
        [
            "cmake", "-S", str(ROOT / "stub"), "-B", str(build),
            "-G", "Visual Studio 17 2022", "-A", "x64",
            f"-DDVM_SHUFFLE_SEED={_SHUFFLE_SEED}",
            "-DDVM_ROLLING=ON", "-DDVM_ROLL_POISON=OFF", "-DBUILD_TESTING=OFF",
        ],
        cwd=work,
    )
    _run_checked(["cmake", "--build", str(build), "--config", "Release"], cwd=work)
    stub = build / "Release" / "lethe_stub_x64.dll"
    assert stub.is_file()
    generated = runpy.run_path(str(build / "daedalus_opcodes_shuffled.py"))
    raw = stub.read_bytes()
    Path(str(stub) + ".manifest.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "artifact": stub.name,
                "size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "dvm_shuffle_seed": _SHUFFLE_SEED,
                "dvm_handler_variant_sha256": generated["HANDLER_VARIANT_SHA256"],
                "dvm_rolling": True,
                "dvm_paged_runtime": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n",
        encoding="ascii",
    )
    return stub


def _build_tail_fixture(work: Path, kind: str) -> tuple[Path, Path | None]:
    source = work / f"{kind}_source"
    build = work / f"{kind}_build"
    source.mkdir()
    (source / "tail.asm").write_text(
        r"""
OPTION CASEMAP:NONE
.data
ALIGN 8
PUBLIC tail_relocation_anchor
tail_relocation_anchor QWORD OFFSET tail_target
.code
PUBLIC tail_invoke
PUBLIC vm_tail_wrapper
PUBLIC tail_target

; The selected wrapper is deliberately an exact, flag-neutral E9 body.  Its
; caller establishes EAX=0 and CF=1 before jumping here, so tail_target must
; observe that incoming architectural state at the unmodified source RSP.
tail_invoke PROC FRAME
    .endprolog
    xor eax, eax
    stc
    jmp vm_tail_wrapper
tail_invoke ENDP

vm_tail_wrapper PROC FRAME
    .endprolog
    db 0E9h
    dd tail_target-($+4)
vm_tail_wrapper ENDP

tail_target PROC FRAME
    .endprolog
    ; Validate both source RSP/home-slot continuity and the fifth argument.
    mov qword ptr [rsp+8], rcx
    mov r10, qword ptr [rsp+8]
    adc eax, dword ptr [rsp+28h]
    add eax, r10d
    add eax, edx
    add eax, r8d
    add eax, r9d
    ret
tail_target ENDP
END
""".lstrip(),
        encoding="ascii",
    )
    # Run both the original and the packed image through the same force-relocate
    # launcher.  The 0x300 process-creation policy is the maintained Win32
    # ``FORCE_RELOCATE_IMAGES_ALWAYS_ON`` form used by the other native
    # materialization tests; this checks that the source and generated REL32 /
    # DIR64 bindings remain correct away from the preferred base.
    (source / "force_aslr.c").write_text(
        r"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t **argv)
{
    SIZE_T bytes = 0;
    STARTUPINFOEXW startup = {0};
    PROCESS_INFORMATION process = {0};
    DWORD64 policy = 0x300;
    DWORD exit_code = 0xFFFFFFFFu;
    wchar_t command[32768];
    if (argc != 2 && argc != 3)
        return 90;
    if (!InitializeProcThreadAttributeList(NULL, 1, 0, &bytes) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return 91;
    startup.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
    if (!startup.lpAttributeList)
        return 92;
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &bytes))
        return 93;
    if (!UpdateProcThreadAttribute(
            startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            &policy, sizeof(policy), NULL, NULL))
        return 94;
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if ((argc == 2 && swprintf_s(
            command, sizeof(command) / sizeof(command[0]), L"\"%s\"", argv[1]) < 0)
        || (argc == 3 && swprintf_s(
            command, sizeof(command) / sizeof(command[0]), L"\"%s\" \"%s\"",
            argv[1], argv[2]) < 0))
        return 95;
    if (!CreateProcessW(
            argv[1], command, NULL, NULL, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            NULL, NULL, &startup.StartupInfo, &process))
        return 96;
    if (WaitForSingleObject(process.hProcess, 30000) != WAIT_OBJECT_0)
        return 97;
    if (!GetExitCodeProcess(process.hProcess, &exit_code))
        return 98;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
    return (int)exit_code;
}
""".lstrip(),
        encoding="ascii",
    )
    if kind == "exe":
        (source / "fixture.c").write_text(
            r"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int tail_invoke(int, int, int, int, int);

__declspec(noreturn) void fixture_entry(void)
{
    static const char output[] = "tail-answer=151\r\n";
    DWORD written = 0;
    volatile int answer = tail_invoke(10, 20, 30, 40, 50);
    if (answer == 151) {
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output,
                  (DWORD)(sizeof(output) - 1u), &written, NULL);
        ExitProcess(0);
    }
    ExitProcess(3);
}
""".lstrip(),
            encoding="ascii",
        )
        cmake = r"""
cmake_minimum_required(VERSION 3.20)
project(lethe_terminal_tail_exe C ASM_MASM)
add_executable(tail_fixture fixture.c tail.asm)
target_compile_options(tail_fixture PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/W4;/WX;/O2;/GS-;/guard:cf->)
target_link_options(tail_fixture PRIVATE
    /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA:NO /CETCOMPAT:NO
    /NODEFAULTLIB /ENTRY:fixture_entry /SUBSYSTEM:CONSOLE
    /EXPORT:tail_invoke /EXPORT:vm_tail_wrapper /EXPORT:tail_target)
target_link_libraries(tail_fixture PRIVATE kernel32.lib)
""".lstrip()
        executable = build / "Release" / "tail_fixture.exe"
        host = None
    elif kind == "dll":
        (source / "dllmain.c").write_text(
            r"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
""".lstrip(),
            encoding="ascii",
        )
        (source / "host.c").write_text(
            r"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef int (__cdecl *TailFn)(int, int, int, int, int);
int wmain(int argc, wchar_t **argv)
{
    HMODULE module;
    TailFn tail;
    int answer;
    if (argc != 2) return 90;
    module = LoadLibraryW(argv[1]);
    if (!module) return 91;
    tail = (TailFn)GetProcAddress(module, "tail_invoke");
    if (!tail) { FreeLibrary(module); return 92; }
    answer = tail(10, 20, 30, 40, 50);
    printf("tail-answer=%d\n", answer);
    if (!FreeLibrary(module)) return 93;
    return answer == 151 ? 0 : 94;
}
""".lstrip(),
            encoding="ascii",
        )
        cmake = r"""
cmake_minimum_required(VERSION 3.20)
project(lethe_terminal_tail_dll C ASM_MASM)
add_library(tail_fixture SHARED dllmain.c tail.asm)
add_executable(tail_host host.c)
target_compile_options(tail_fixture PRIVATE
    $<$<COMPILE_LANGUAGE:C>:/W4;/WX;/O2;/GS-;/guard:cf->)
target_compile_options(tail_host PRIVATE /W4 /WX /O2)
target_link_options(tail_fixture PRIVATE
    /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /CETCOMPAT:NO /GUARD:NO
    /NODEFAULTLIB /ENTRY:DllMain /MANIFEST:NO
    /EXPORT:tail_invoke /EXPORT:vm_tail_wrapper /EXPORT:tail_target)
""".lstrip()
        executable = build / "Release" / "tail_fixture.dll"
        host = build / "Release" / "tail_host.exe"
    else:
        raise AssertionError(kind)
    cmake += """
add_executable(force_aslr force_aslr.c)
target_compile_options(force_aslr PRIVATE /W4 /WX /O2)
""".lstrip()
    (source / "CMakeLists.txt").write_text(cmake, encoding="ascii")
    _run_checked(
        ["cmake", "-S", str(source), "-B", str(build),
         "-G", "Visual Studio 17 2022", "-A", "x64"],
        cwd=work,
    )
    _run_checked(["cmake", "--build", str(build), "--config", "Release"], cwd=work)
    assert executable.is_file()
    if host is not None:
        assert host.is_file()
    return executable, host


def _slice(parsed: pe_analyze.ParsedPE, rva: int, size: int) -> bytes:
    return pe_analyze._slice_at_rva(
        parsed.sections, rva, size, what="terminal-tail materialized test"
    )


def _run_image(
    kind: str,
    image: Path,
    host: Path | None,
    launcher: Path,
) -> subprocess.CompletedProcess:
    assert launcher.is_file()
    command = (
        [str(launcher), str(image)]
        if kind == "exe"
        else [str(launcher), str(host), str(image)]
    )
    return subprocess.run(
        command,
        cwd=str(image.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=45,
        check=False,
    )


@pytest.mark.skipif(os.name != "nt", reason="native loader is Windows-only")
@pytest.mark.parametrize("kind", ("exe", "dll"))
def test_materialized_terminal_direct_e9_tail_preserves_state_exe_and_dll(
    kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.environ.get(_RUN_GATE) != "1":
        pytest.skip(f"set {_RUN_GATE}=1 to run materialized terminal-tail proof")
    pytest.importorskip("lief")
    pytest.importorskip("iced_x86")
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    root = ROOT.resolve()
    work = Path(tempfile.mkdtemp(prefix=".native_terminal_tail_", dir=root)).resolve()
    if work.parent != root or not work.name.startswith(".native_terminal_tail_"):
        pytest.fail(f"native test directory escaped repository root: {work}")
    try:
        source, host = _build_tail_fixture(work, kind)
        launcher = source.parent / "force_aslr.exe"
        original = _run_image(kind, source, host, launcher)
        assert (original.returncode, original.stdout, original.stderr) == (0, _EXPECTED, b"")

        parsed = pe_analyze.analyze_pe(str(source))
        source_image = assemble._StubImage(source.read_bytes())
        wrapper_rva = source_image.find_export_rva("vm_tail_wrapper")
        target_rva = source_image.find_export_rva("tail_target")
        assert wrapper_rva is not None and target_rva is not None
        wrapper_record, = (
            record for record in parsed.runtime_functions
            if record.begin_rva == wrapper_rva
        )
        target_record, = (
            record for record in parsed.runtime_functions
            if record.begin_rva == target_rva
        )
        wrapper_size = wrapper_record.end_rva - wrapper_rva
        wrapper = _slice(parsed, wrapper_rva, wrapper_size)
        target = _slice(parsed, target_rva, target_record.end_rva - target_rva)
        assert wrapper[-5:] == b"\xE9" + struct.pack(
            "<i", target_rva - wrapper_record.end_rva
        )
        assert target_record.unwind_flags == 0
        assert target_record.chain_primary_rva == 0

        spec = orchestrator.VirtualizationSpec(
            "vm_tail_wrapper", wrapper_rva, wrapper_size
        )
        approval = orchestrator.VirtualizationTailExitApproval(
            wrapper_rva, wrapper_record.end_rva - 5, target_rva,
            "materialized terminal direct E9 ABI regression",
        )
        proof = direct_control_flow.analyze_direct_control_flow(
            parsed,
            (virtualization_plan.FunctionSpec(spec.name, spec.rva, spec.size),),
            tail_exit_policy=direct_control_flow.TailExitPolicy((
                direct_control_flow.TailExitApproval(
                    approval.function_rva, approval.instruction_rva,
                    approval.target_rva, approval.rationale,
                ),
            )),
            production=False,
        )
        assert proof.selected_flows[0].approved_tail_exits
        gaps = tuple(
            orchestrator.VirtualizationGapAcknowledgement(
                gap.rva, gap.size,
                "exact native terminal-tail fixture executable gap",
            )
            for gap in proof.coverage_gaps
        )

        stub = _build_stub(work)
        captured: dict[str, object] = {}
        materialize = virtualize.materialize_selected_functions

        def capture_materialization(*args, **kwargs):
            captured["tail_exit_proof"] = kwargs.get("tail_exit_proof")
            result = materialize(*args, **kwargs)
            captured["result"] = result
            return result

        monkeypatch.setattr(virtualize, "materialize_selected_functions", capture_materialization)
        monkeypatch.setenv(_VIRTUALIZATION_GATE, "1")
        if kind == "dll":
            monkeypatch.setenv(_DLL_GATE, "1")
        packed = work / ("tail_fixture.packed.exe" if kind == "exe" else "tail_fixture.packed.dll")
        result = orchestrator.pack_file(
            str(source),
            orchestrator.PackOptions(
                output_path=str(packed),
                is_dll=(kind == "dll"),
                stub_path=str(stub),
                virtualization_specs=(spec,),
                virtualization_gap_acknowledgements=gaps,
                virtualization_tail_exit_approvals=(approval,),
                acknowledge_unproven_indirect_targets=True,
                _allow_unverified_stub_for_tests=True,
            ),
        )
        assert result.ok, result.error
        assert packed.is_file()
        assert captured["tail_exit_proof"] is not None

        materialized = captured["result"]
        function = materialized.manifest.functions[0]
        assert function.tail_exit is not None
        assert function.tail_exit.instruction_rva == wrapper_record.end_rva - 5
        assert function.tail_exit.target_rva == target_rva
        assert function.tail_exit.target_body_sha256 == hashlib.sha256(target).hexdigest()
        assert function.program_id[:4] == struct.pack("<I", target_rva)
        assert len(function.tail_unwind) == 2
        assert function.capabilities["terminal_direct_tail_exit"] is True
        assert function.capabilities["cet_shadow_stack_balanced"] is True
        descriptor = _slice(materialized.parsed, function.descriptor_rva, 48)
        version, _size, _envelope, program_id, _base, descriptor_target, reserved = (
            struct.unpack("<IIQ16sQII", descriptor)
        )
        assert version == virtualization_plan.DESCRIPTOR_VERSION_PAGED_TAIL
        assert program_id == function.program_id
        assert descriptor_target == target_rva
        assert reserved == 0
        thunk = _slice(
            materialized.parsed,
            function.generated_executable_ranges[0].rva,
            win64_thunk.TAIL_THUNK_CODE_SIZE,
        )
        assert thunk[win64_thunk.TAIL_THUNK_JUMP_OFFSET] == 0xE9
        displacement, = struct.unpack_from(
            "<i", thunk, win64_thunk.TAIL_THUNK_TARGET_REL32_OFFSET
        )
        assert (
            function.generated_executable_ranges[0].rva
            + win64_thunk.TAIL_THUNK_TARGET_REL32_OFFSET + 4 + displacement
            == target_rva
        )
        assert _slice(
            materialized.parsed, target_rva, target_record.end_rva - target_rva
        ) == target

        packed_run = _run_image(kind, packed, host, launcher)
        assert (packed_run.returncode, packed_run.stdout, packed_run.stderr) == (
            original.returncode, original.stdout, original.stderr,
        )
    finally:
        if work.parent == root and work.name.startswith(".native_terminal_tail_") and work.exists():
            shutil.rmtree(work)
