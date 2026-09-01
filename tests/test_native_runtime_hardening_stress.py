"""Opt-in native stress proof for interacting EXE runtime hardening layers."""

from __future__ import annotations

import itertools
import os
import shutil
import struct
import subprocess
import time
from pathlib import Path

import pytest

from packer import orchestrator, pe_analyze
from tools import handler_shape_audit


ROOT = Path(__file__).resolve().parents[1]
_RUN_GATE = "LETHE_RUN_NATIVE_RUNTIME_STRESS"
_SHUFFLE_SEED = (
    "2718281828459045235360287471352662497757247093699959574966967627"
)
_LAUNCH_REPETITIONS = 3


def _run_checked(command: list[str], *, cwd: Path, timeout: int = 180) -> None:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout


def _build_fixture(work: Path) -> Path:
    source = work / "fixture_source"
    build = work / "fixture_build"
    source.mkdir()
    (source / "fixture.c").write_text(
        r'''
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <stdint.h>

#define AD_POLICY_EXTENSION_POINT_DISABLE 6u
#define AD_POLICY_IMAGE_LOAD              10u
#define AD_EXT_DISABLE_EXTENSION_POINTS   0x1u
#define AD_IMG_NO_REMOTE_IMAGES           0x1u
#define AD_IMG_PREFER_SYSTEM32             0x4u

typedef BOOL (WINAPI *GetProcMitigation_t)(HANDLE, DWORD, PVOID, SIZE_T);

#pragma code_seg(push, ".xone")
__declspec(noinline) static uint32_t probe_one(uint32_t value)
{
    return (value * 7u) + 3u;
}
#pragma code_seg(pop)

#pragma code_seg(push, ".xtwo")
__declspec(noinline) static uint32_t probe_two(uint32_t value)
{
    return (value ^ 0x13579BDFu) + 11u;
}
#pragma code_seg(pop)

#pragma code_seg(push, ".xidle")
__declspec(noinline) static uint32_t idle_probe(uint32_t value)
{
    return (value * 13u) ^ 0x2468ACE0u;
}
#pragma code_seg(pop)

#pragma code_seg(push, ".xrace")
__declspec(noinline) static uint32_t race_probe(uint32_t value)
{
    return (value * 17u) ^ 0x55AA33CCu;
}
#pragma code_seg(pop)

#pragma section(".xreloc", read, execute)
__declspec(allocate(".xreloc"))
static void * volatile executable_relocation = (void *)&probe_one;

typedef uint32_t (__cdecl *ProbeFn)(uint32_t);

typedef struct RaceWorker {
    HANDLE gate;
    uint32_t input;
} RaceWorker;

static DWORD WINAPI race_worker(void *opaque)
{
    RaceWorker *worker = (RaceWorker *)opaque;
    if (WaitForSingleObject(worker->gate, 30000u) != WAIT_OBJECT_0)
        return 0xFFFFFFFFu;
    return race_probe(worker->input);
}

static int run_concurrent_first_touch(void)
{
    enum { WORKER_COUNT = 24 };
    RaceWorker workers[WORKER_COUNT];
    HANDLE threads[WORKER_COUNT];
    HANDLE gate;
    DWORD index;
    int ok = 1;

    gate = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!gate)
        return 0;
    for (index = 0; index < WORKER_COUNT; ++index) {
        workers[index].gate = gate;
        workers[index].input = index + 1u;
        threads[index] = CreateThread(NULL, 0, race_worker, &workers[index],
                                      0, NULL);
        if (!threads[index]) {
            DWORD prior;
            (void)SetEvent(gate);
            for (prior = 0; prior < index; ++prior) {
                (void)WaitForSingleObject(threads[prior], 30000u);
                (void)CloseHandle(threads[prior]);
            }
            (void)CloseHandle(gate);
            return 0;
        }
    }
    if (!SetEvent(gate))
        ok = 0;
    for (index = 0; index < WORKER_COUNT; ++index) {
        DWORD result = 0;
        const DWORD expected = ((index + 1u) * 17u) ^ 0x55AA33CCu;
        if (WaitForSingleObject(threads[index], 30000u) != WAIT_OBJECT_0 ||
            !GetExitCodeThread(threads[index], &result) || result != expected)
            ok = 0;
        if (!CloseHandle(threads[index]))
            ok = 0;
    }
    if (!CloseHandle(gate))
        ok = 0;
    return ok;
}

static int env_enabled(const wchar_t *name)
{
    wchar_t value[2];
    return GetEnvironmentVariableW(name, value, 2u) != 0u;
}

static int page_has_protection(const void *address, DWORD expected)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi)) != sizeof(mbi))
        return 0;
    return mbi.State == MEM_COMMIT && (mbi.Protect & 0xffu) == expected;
}

static int headers_are_sanitized(void)
{
    const uint8_t *base = (const uint8_t *)GetModuleHandleW(NULL);
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS64 *nt;
    if (!base)
        return 0;
    dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return 0;
    nt = (const IMAGE_NT_HEADERS64 *)(base + (uint32_t)dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IAT)
        return 0;
    return nt->OptionalHeader.AddressOfEntryPoint == 0u &&
           nt->OptionalHeader.CheckSum == 0u &&
           nt->OptionalHeader.DataDirectory[
               IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0u &&
           nt->OptionalHeader.DataDirectory[
               IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress == 0u;
}

static int image_was_relocated(void)
{
    const uint8_t *base = (const uint8_t *)GetModuleHandleW(NULL);
    return (uintptr_t)base != (uintptr_t)0x7ffe0000u;
}

static int process_hardening_is_effective(void)
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    GetProcMitigation_t get_policy;
    DWORD effective = 0;
    if (!kernel32)
        return 0;
    get_policy = (GetProcMitigation_t)GetProcAddress(
        kernel32, "GetProcessMitigationPolicy");
    if (!get_policy)
        return 0;
    if (!get_policy(GetCurrentProcess(), AD_POLICY_EXTENSION_POINT_DISABLE,
                    &effective, sizeof(effective)) ||
        (effective & AD_EXT_DISABLE_EXTENSION_POINTS) == 0u)
        return 0;
    effective = 0;
    if (!get_policy(GetCurrentProcess(), AD_POLICY_IMAGE_LOAD,
                    &effective, sizeof(effective)) ||
        (effective & (AD_IMG_NO_REMOTE_IMAGES | AD_IMG_PREFER_SYSTEM32)) !=
            (AD_IMG_NO_REMOTE_IMAGES | AD_IMG_PREFER_SYSTEM32))
        return 0;
    return 1;
}

static void emit_marker(const char *message, DWORD size)
{
    DWORD written = 0;
    (void)WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, size,
                    &written, NULL);
}

uint32_t __cdecl fixture_entry(void)
{
    static const char pass[] = "runtime-hardening: PASS\r\n";
    static const char fail[] = "runtime-hardening: FAIL\r\n";
    const int expect_memguard = env_enabled(L"LETHE_EXPECT_MEMGUARD");
    const int expect_process = env_enabled(L"LETHE_EXPECT_PROCESS_HARDENING");
    ProbeFn relocated_probe = (ProbeFn)executable_relocation;
    volatile uint32_t one = relocated_probe(17u);
    volatile uint32_t two = probe_two(one);
    uint32_t failure = 0;

    if (one != 122u || two != ((122u ^ 0x13579BDFu) + 11u))
        failure |= 1u;
    if (!page_has_protection((const void *)(uintptr_t)&probe_one,
                             PAGE_EXECUTE_READ) ||
        !page_has_protection((const void *)(uintptr_t)&probe_two,
                             PAGE_EXECUTE_READ))
        failure |= 2u;
    if (expect_memguard) {
        if (!page_has_protection((const void *)(uintptr_t)&idle_probe,
                                 PAGE_NOACCESS))
            failure |= 4u;
    } else if (!page_has_protection((const void *)(uintptr_t)&idle_probe,
                                    PAGE_EXECUTE_READ)) {
        failure |= 4u;
    }
    if (!headers_are_sanitized())
        failure |= 8u;
    if (!image_was_relocated())
        failure |= 16u;
    if (!run_concurrent_first_touch())
        failure |= 32u;
    if (!page_has_protection((const void *)(uintptr_t)&race_probe,
                             PAGE_EXECUTE_READ) ||
        !page_has_protection((const void *)(uintptr_t)&executable_relocation,
                             PAGE_EXECUTE_READ))
        failure |= 64u;
    if (expect_process && !process_hardening_is_effective())
        failure |= 128u;

    if (failure == 0u) {
        emit_marker(pass, (DWORD)(sizeof(pass) - 1u));
        return 0;
    }
    emit_marker(fail, (DWORD)(sizeof(fail) - 1u));
    return failure;
}
'''.lstrip(),
        encoding="ascii",
    )
    (source / "CMakeLists.txt").write_text(
        """
cmake_minimum_required(VERSION 3.20)
project(lethe_runtime_hardening_fixture C)
add_executable(runtime_hardening_fixture fixture.c)
target_compile_definitions(runtime_hardening_fixture PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(runtime_hardening_fixture PRIVATE
    /W4 /WX /O2 /GS- /guard:cf-)
target_link_options(runtime_hardening_fixture PRIVATE
    /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA
    /BASE:0x7ffe0000
    /CETCOMPAT:NO /NODEFAULTLIB /ENTRY:fixture_entry /SUBSYSTEM:CONSOLE
    /OPT:NOICF)
target_link_libraries(runtime_hardening_fixture PRIVATE kernel32.lib)
""".lstrip(),
        encoding="ascii",
    )
    _run_checked(
        [
            "cmake", "-S", str(source), "-B", str(build),
            "-G", "Visual Studio 17 2022", "-A", "x64",
        ],
        cwd=work,
    )
    _run_checked(
        ["cmake", "--build", str(build), "--config", "Release"],
        cwd=work,
    )
    executable = build / "Release/runtime_hardening_fixture.exe"
    assert executable.is_file()
    return executable


def _build_stub(work: Path, *, name: str = "stub_build",
                compile_definition: str | None = None) -> Path:
    build = work / name
    configure = [
        "cmake", "-S", str(ROOT / "stub"), "-B", str(build),
        "-G", "Visual Studio 17 2022", "-A", "x64",
        f"-DDVM_SHUFFLE_SEED={_SHUFFLE_SEED}",
        "-DDVM_ROLLING=OFF",
        "-DDVM_ROLL_POISON=OFF",
        "-DBUILD_TESTING=OFF",
    ]
    if compile_definition:
        configure.append(f"-DCMAKE_C_FLAGS=/D{compile_definition}")
    _run_checked(
        configure,
        cwd=work,
    )
    _run_checked(
        ["cmake", "--build", str(build), "--config", "Release"],
        cwd=work,
        timeout=300,
    )
    stub = build / "Release/lethe_stub_x64.dll"
    assert stub.is_file()
    return stub


def _run_packed(executable: Path, *, memory_guard: bool,
                process_hardening: bool,
                cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env.pop("LETHE_EXPECT_MEMGUARD", None)
    env.pop("LETHE_EXPECT_PROCESS_HARDENING", None)
    if memory_guard:
        env["LETHE_EXPECT_MEMGUARD"] = "1"
    if process_hardening:
        env["LETHE_EXPECT_PROCESS_HARDENING"] = "1"
    return subprocess.run(
        [str(executable)],
        cwd=str(cwd or executable.parent),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


def _run_packed_forced_aslr(
    executable: Path,
    *,
    memory_guard: bool,
    process_hardening: bool,
    debugged: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    import ctypes
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = (
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        )

    class StartupInfoW(ctypes.Structure):
        _fields_ = (
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        )

    class StartupInfoExW(ctypes.Structure):
        _fields_ = (
            ("StartupInfo", StartupInfoW),
            ("lpAttributeList", ctypes.c_void_p),
        )

    class ProcessInformation(ctypes.Structure):
        _fields_ = (
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        )

    class DebugEventPayload(ctypes.Union):
        _fields_ = (
            ("raw", ctypes.c_byte * 160),
            ("alignment", ctypes.c_void_p),
            ("file", wintypes.HANDLE),
        )

    class DebugEvent(ctypes.Structure):
        _fields_ = (
            ("dwDebugEventCode", wintypes.DWORD),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
            ("payload", DebugEventPayload),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.InitializeProcThreadAttributeList.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    )
    kernel32.UpdateProcThreadAttribute.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    kernel32.CreateProcessW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(StartupInfoW),
        ctypes.POINTER(ProcessInformation),
    )

    security = SecurityAttributes(
        ctypes.sizeof(SecurityAttributes), None, True
    )
    stdout_read = wintypes.HANDLE()
    stdout_write = wintypes.HANDLE()
    stderr_read = wintypes.HANDLE()
    stderr_write = wintypes.HANDLE()
    assert kernel32.CreatePipe(
        ctypes.byref(stdout_read), ctypes.byref(stdout_write),
        ctypes.byref(security), 0,
    )
    assert kernel32.CreatePipe(
        ctypes.byref(stderr_read), ctypes.byref(stderr_write),
        ctypes.byref(security), 0,
    )
    for read_handle in (stdout_read, stderr_read):
        assert kernel32.SetHandleInformation(read_handle, 1, 0)

    attribute_size = ctypes.c_size_t()
    kernel32.InitializeProcThreadAttributeList(
        None, 1, 0, ctypes.byref(attribute_size)
    )
    attribute_storage = ctypes.create_string_buffer(attribute_size.value)
    attribute_list = ctypes.cast(attribute_storage, ctypes.c_void_p)
    assert kernel32.InitializeProcThreadAttributeList(
        attribute_list, 1, 0, ctypes.byref(attribute_size)
    )
    force_relocations_require_relocs = ctypes.c_ulonglong(0x300)
    assert kernel32.UpdateProcThreadAttribute(
        attribute_list,
        0,
        0x00020007,
        ctypes.byref(force_relocations_require_relocs),
        ctypes.sizeof(force_relocations_require_relocs),
        None,
        None,
    )

    startup = StartupInfoExW()
    startup.StartupInfo.cb = ctypes.sizeof(StartupInfoExW)
    startup.StartupInfo.dwFlags = 0x00000100
    startup.StartupInfo.hStdInput = kernel32.GetStdHandle(-10)
    startup.StartupInfo.hStdOutput = stdout_write
    startup.StartupInfo.hStdError = stderr_write
    startup.lpAttributeList = attribute_list
    process = ProcessInformation()
    command_line = ctypes.create_unicode_buffer(f'"{executable}"')
    env = os.environ.copy()
    env.pop("LETHE_EXPECT_MEMGUARD", None)
    env.pop("LETHE_EXPECT_PROCESS_HARDENING", None)
    if memory_guard:
        env["LETHE_EXPECT_MEMGUARD"] = "1"
    if process_hardening:
        env["LETHE_EXPECT_PROCESS_HARDENING"] = "1"
    env_text = "\0".join(
        f"{key}={value}" for key, value in sorted(
            env.items(), key=lambda item: item[0].upper()
        )
    ) + "\0\0"
    env_block = ctypes.create_unicode_buffer(env_text)

    try:
        created = kernel32.CreateProcessW(
            str(executable),
            command_line,
            None,
            None,
            True,
            0x00080400 | (0x00000002 if debugged else 0),
            ctypes.cast(env_block, ctypes.c_void_p),
            str(executable.parent),
            ctypes.byref(startup.StartupInfo),
            ctypes.byref(process),
        )
        assert created, ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(stdout_write)
        stdout_write = wintypes.HANDLE()
        kernel32.CloseHandle(stderr_write)
        stderr_write = wintypes.HANDLE()
        if debugged:
            deadline = time.monotonic() + 30.0
            while True:
                remaining_ms = int((deadline - time.monotonic()) * 1000)
                assert remaining_ms > 0, "debugged child timed out"
                event = DebugEvent()
                assert kernel32.WaitForDebugEvent(
                    ctypes.byref(event), remaining_ms
                ), ctypes.WinError(ctypes.get_last_error())
                if event.dwDebugEventCode in (3, 6) and event.payload.file:
                    kernel32.CloseHandle(event.payload.file)
                exited = event.dwDebugEventCode == 5
                assert kernel32.ContinueDebugEvent(
                    event.dwProcessId, event.dwThreadId, 0x00010002
                )
                if exited:
                    break
        else:
            wait_result = kernel32.WaitForSingleObject(process.hProcess, 30000)
            assert wait_result == 0, (
                f"forced-ASLR child wait failed: {wait_result}"
            )
        exit_code = wintypes.DWORD()
        assert kernel32.GetExitCodeProcess(
            process.hProcess, ctypes.byref(exit_code)
        )

        def read_pipe(handle: wintypes.HANDLE) -> bytes:
            chunks: list[bytes] = []
            while True:
                buffer = ctypes.create_string_buffer(4096)
                read = wintypes.DWORD()
                if not kernel32.ReadFile(
                    handle, buffer, len(buffer), ctypes.byref(read), None
                ):
                    assert ctypes.get_last_error() == 109
                    break
                if read.value == 0:
                    break
                chunks.append(buffer.raw[:read.value])
            return b"".join(chunks)

        stdout = read_pipe(stdout_read)
        stderr = read_pipe(stderr_read)
        return subprocess.CompletedProcess(
            [str(executable)], exit_code.value, stdout, stderr
        )
    finally:
        kernel32.DeleteProcThreadAttributeList(attribute_list)
        for handle in (
            stdout_read,
            stdout_write,
            stderr_read,
            stderr_write,
            process.hThread,
            process.hProcess,
        ):
            if handle:
                kernel32.CloseHandle(handle)


def _build_cwd_probe_fixture(work: Path) -> tuple[Path, Path]:
    source = work / "cwd_probe_source"
    build = work / "cwd_probe_build"
    source.mkdir()
    (source / "probe.c").write_text(
        r'''
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static void emit(const char *message, DWORD size)
{
    DWORD written = 0;
    (void)WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, size,
                    &written, NULL);
}

__declspec(dllexport) int __cdecl cwd_probe_value(void)
{
    return 4080;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    static const char loaded[] = "cwd-probe: LOADED\r\n";
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        emit(loaded, (DWORD)(sizeof(loaded) - 1u));
    return TRUE;
}
'''.lstrip(),
        encoding="ascii",
    )
    (source / "fixture.c").write_text(
        r'''
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

__declspec(dllimport) int __cdecl cwd_probe_value(void);

static void emit(const char *message, DWORD size)
{
    DWORD written = 0;
    (void)WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, size,
                    &written, NULL);
}

int __cdecl fixture_entry(void)
{
    static const char pass[] = "cwd-fixture: PASS\r\n";
    static const char fail[] = "cwd-fixture: FAIL\r\n";
    if (cwd_probe_value() != 4080) {
        emit(fail, (DWORD)(sizeof(fail) - 1u));
        return 97;
    }
    emit(pass, (DWORD)(sizeof(pass) - 1u));
    return 0;
}
'''.lstrip(),
        encoding="ascii",
    )
    (source / "CMakeLists.txt").write_text(
        """
cmake_minimum_required(VERSION 3.20)
project(lethe_cwd_probe_fixture C)
add_library(cwd_probe SHARED probe.c)
set_target_properties(cwd_probe PROPERTIES OUTPUT_NAME cwd_probe)
target_compile_options(cwd_probe PRIVATE /W4 /WX /O2 /GS-)
target_link_options(cwd_probe PRIVATE
    /INCREMENTAL:NO /NODEFAULTLIB /ENTRY:DllMain)
target_link_libraries(cwd_probe PRIVATE kernel32.lib)
add_executable(cwd_probe_fixture fixture.c)
target_compile_options(cwd_probe_fixture PRIVATE /W4 /WX /O2 /GS-)
target_link_options(cwd_probe_fixture PRIVATE
    /INCREMENTAL:NO /FIXED /DYNAMICBASE:NO /NXCOMPAT /HIGHENTROPYVA:NO
    /NODEFAULTLIB /ENTRY:fixture_entry /SUBSYSTEM:CONSOLE)
target_link_libraries(cwd_probe_fixture PRIVATE cwd_probe kernel32.lib)
""".lstrip(),
        encoding="ascii",
    )
    _run_checked(
        [
            "cmake", "-S", str(source), "-B", str(build),
            "-G", "Visual Studio 17 2022", "-A", "x64",
        ],
        cwd=work,
    )
    _run_checked(
        ["cmake", "--build", str(build), "--config", "Release"],
        cwd=work,
    )
    executable = build / "Release/cwd_probe_fixture.exe"
    probe = build / "Release/cwd_probe.dll"
    assert executable.is_file()
    assert probe.is_file()
    return executable, probe


def _raw_section_range(blob: bytes, name: bytes) -> tuple[int, int]:
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise AssertionError("packed fixture has no DOS header")
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    if pe + 24 > len(blob) or blob[pe:pe + 4] != b"PE\0\0":
        raise AssertionError("packed fixture has no PE signature")
    section_count = struct.unpack_from("<H", blob, pe + 6)[0]
    optional_size = struct.unpack_from("<H", blob, pe + 20)[0]
    section_table = pe + 24 + optional_size
    for index in range(section_count):
        off = section_table + index * 40
        if off + 40 > len(blob):
            raise AssertionError("packed fixture has a truncated section table")
        section_name = blob[off:off + 8].split(b"\0", 1)[0]
        if section_name == name:
            raw_size, raw_offset = struct.unpack_from("<II", blob, off + 16)
            if raw_size == 0 or raw_offset > len(blob) - raw_size:
                raise AssertionError("packed payload section is out of range")
            return raw_offset, raw_size
    raise AssertionError(f"packed fixture has no {name!r} section")


def _tamper_payload(source: Path, destination: Path) -> None:
    blob = bytearray(source.read_bytes())
    raw_offset, _raw_size = _raw_section_range(blob, b".rdata2")
    blob[raw_offset] ^= 0x80
    destination.write_bytes(blob)


def _pack(source: Path, stub: Path, output: Path, *,
          anti_debug: bool = False, memory_guard: bool = False,
          process_hardening: bool = False) -> None:
    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(output),
            is_dll=False,
            stub_path=str(stub),
            anti_debug=anti_debug,
            memory_guard=memory_guard,
            process_hardening=process_hardening,
        ),
    )
    assert result.ok, result.error


@pytest.mark.skipif(os.name != "nt", reason="native loader is Windows-only")
def test_native_exe_hardening_matrix_repeated_and_fail_closed(
    tmp_path: Path,
) -> None:
    if os.environ.get(_RUN_GATE) != "1":
        pytest.skip(f"set {_RUN_GATE}=1 to run the native hardening stress proof")
    pytest.importorskip("lief")
    if not shutil.which("cmake") or handler_shape_audit.find_msvc() is None:
        pytest.skip("CMake plus the Visual Studio x64 toolchain are required")

    source = _build_fixture(tmp_path)
    parsed = pe_analyze.analyze_pe(str(source))
    executable_sections = {
        section.name
        for section in parsed.sections
        if section.characteristics & 0x20000000
    }
    assert {
        ".text", ".xone", ".xtwo", ".xidle", ".xrace", ".xreloc"
    } <= executable_sections
    assert parsed.image_base == 0x7FFE0000
    assert parsed.dll_characteristics & 0x40
    executable_reloc_section = next(
        section for section in parsed.sections if section.name == ".xreloc"
    )
    assert any(
        executable_reloc_section.rva <= relocation.target_rva <
        executable_reloc_section.rva + executable_reloc_section.virtual_size
        for relocation in parsed.dir64_relocations
    )
    stub = _build_stub(tmp_path)

    packed_by_flags: dict[tuple[bool, bool, bool], Path] = {}
    for anti_debug, memory_guard, process_hardening in itertools.product(
        (False, True), repeat=3
    ):
        flags = (anti_debug, memory_guard, process_hardening)
        suffix = "".join("1" if enabled else "0" for enabled in flags)
        packed = tmp_path / f"runtime_hardening_{suffix}.exe"
        _pack(
            source,
            stub,
            packed,
            anti_debug=anti_debug,
            memory_guard=memory_guard,
            process_hardening=process_hardening,
        )
        packed_by_flags[flags] = packed

        for _ in range(_LAUNCH_REPETITIONS):
            ran = _run_packed_forced_aslr(
                packed,
                memory_guard=memory_guard,
                process_hardening=process_hardening,
            )
            assert ran.returncode == 0, (
                flags, ran.returncode, ran.stdout, ran.stderr
            )
            assert ran.stdout == b"runtime-hardening: PASS\r\n"
            assert ran.stderr == b""

    tampered = tmp_path / "runtime_hardening_all_tampered.exe"
    _tamper_payload(packed_by_flags[(True, True, True)], tampered)
    for _ in range(_LAUNCH_REPETITIONS):
        ran = _run_packed_forced_aslr(
            tampered,
            memory_guard=True,
            process_hardening=True,
        )
        assert ran.returncode == 13, (ran.returncode, ran.stdout, ran.stderr)
        assert b"runtime-hardening:" not in ran.stdout
        assert ran.stderr == b""

    fault_builds = (
        (
            "stub_fail_loader_lock",
            "LETHE_PE_LOADER_TEST_FAIL_VIRTUAL_LOCK",
            False,
        ),
        (
            "stub_fail_memguard_lock",
            "LETHE_MEMGUARD_TEST_FAIL_VIRTUAL_LOCK",
            True,
        ),
        (
            "stub_fail_wipe_restore",
            "LETHE_PE_LOADER_TEST_FAIL_WIPE_RESTORE",
            False,
        ),
    )
    for name, compile_definition, memory_guard in fault_builds:
        fault_stub = _build_stub(
            tmp_path,
            name=name,
            compile_definition=compile_definition,
        )
        fault_packed = tmp_path / f"{name}.exe"
        _pack(
            source,
            fault_stub,
            fault_packed,
            anti_debug=True,
            memory_guard=memory_guard,
            process_hardening=True,
        )
        for _ in range(_LAUNCH_REPETITIONS):
            ran = _run_packed_forced_aslr(
                fault_packed,
                memory_guard=memory_guard,
                process_hardening=True,
            )
            assert ran.returncode == 1, (
                name, ran.returncode, ran.stdout, ran.stderr
            )
            assert b"runtime-hardening:" not in ran.stdout
            assert ran.stderr == b""


@pytest.mark.skipif(os.name != "nt", reason="native loader is Windows-only")
def test_antidebug_detects_positive_debug_process_launch(
    tmp_path: Path,
) -> None:
    if os.environ.get(_RUN_GATE) != "1":
        pytest.skip(f"set {_RUN_GATE}=1 to run the native hardening stress proof")
    pytest.importorskip("lief")
    if not shutil.which("cmake") or handler_shape_audit.find_msvc() is None:
        pytest.skip("CMake plus the Visual Studio x64 toolchain are required")

    source = _build_fixture(tmp_path)
    stub = _build_stub(tmp_path, name="debug_process_stub")
    control = tmp_path / "debug_process_control.exe"
    protected = tmp_path / "debug_process_protected.exe"
    _pack(source, stub, control, anti_debug=False)
    _pack(source, stub, protected, anti_debug=True)

    control_run = _run_packed_forced_aslr(
        control,
        memory_guard=False,
        process_hardening=False,
        debugged=True,
    )
    assert control_run.returncode == 0, (
        control_run.returncode,
        control_run.stdout,
        control_run.stderr,
    )
    assert control_run.stdout == b"runtime-hardening: PASS\r\n"
    assert control_run.stderr == b""

    protected_run = _run_packed_forced_aslr(
        protected,
        memory_guard=False,
        process_hardening=False,
        debugged=True,
    )
    assert protected_run.returncode == 0, (
        protected_run.returncode,
        protected_run.stdout,
        protected_run.stderr,
    )
    assert b"runtime-hardening:" not in protected_run.stdout
    assert protected_run.stderr == b""


@pytest.mark.skipif(os.name != "nt", reason="native loader is Windows-only")
def test_process_hardening_excludes_current_directory_from_first_import(
    tmp_path: Path,
) -> None:
    if os.environ.get(_RUN_GATE) != "1":
        pytest.skip(f"set {_RUN_GATE}=1 to run the native hardening stress proof")
    pytest.importorskip("lief")
    if not shutil.which("cmake") or handler_shape_audit.find_msvc() is None:
        pytest.skip("CMake plus the Visual Studio x64 toolchain are required")

    source, probe = _build_cwd_probe_fixture(tmp_path)
    stub = _build_stub(tmp_path, name="cwd_probe_stub")
    application_dir = tmp_path / "cwd_probe_application"
    launch_dir = tmp_path / "cwd_probe_launch"
    application_dir.mkdir()
    launch_dir.mkdir()
    shutil.copy2(probe, launch_dir / probe.name)

    ordinary = application_dir / "cwd_probe_ordinary.exe"
    hardened = application_dir / "cwd_probe_hardened.exe"
    _pack(source, stub, ordinary, process_hardening=False)
    _pack(source, stub, hardened, process_hardening=True)

    ordinary_run = _run_packed(
        ordinary,
        memory_guard=False,
        process_hardening=False,
        cwd=launch_dir,
    )
    assert ordinary_run.returncode == 0, (
        ordinary_run.returncode,
        ordinary_run.stdout,
        ordinary_run.stderr,
    )
    assert ordinary_run.stdout == (
        b"cwd-probe: LOADED\r\ncwd-fixture: PASS\r\n"
    )
    assert ordinary_run.stderr == b""

    hardened_run = _run_packed(
        hardened,
        memory_guard=False,
        process_hardening=True,
        cwd=launch_dir,
    )
    assert hardened_run.returncode == 1, (
        hardened_run.returncode,
        hardened_run.stdout,
        hardened_run.stderr,
    )
    assert b"cwd-probe:" not in hardened_run.stdout
    assert b"cwd-fixture:" not in hardened_run.stdout
    assert hardened_run.stderr == b""
