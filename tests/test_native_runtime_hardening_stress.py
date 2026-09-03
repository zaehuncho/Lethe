"""Opt-in native stress proof for interacting EXE runtime hardening layers."""

from __future__ import annotations

import itertools
import os
import shutil
import struct
import subprocess
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
    volatile uint32_t one = probe_one(17u);
    volatile uint32_t two = probe_two(one);
    int ok = 1;

    if (one != 122u || two != ((122u ^ 0x13579BDFu) + 11u))
        ok = 0;
    if (!page_has_protection((const void *)(uintptr_t)&probe_one,
                             PAGE_EXECUTE_READ) ||
        !page_has_protection((const void *)(uintptr_t)&probe_two,
                             PAGE_EXECUTE_READ))
        ok = 0;
    if (expect_memguard) {
        if (!page_has_protection((const void *)(uintptr_t)&idle_probe,
                                 PAGE_NOACCESS))
            ok = 0;
    } else if (!page_has_protection((const void *)(uintptr_t)&idle_probe,
                                    PAGE_EXECUTE_READ)) {
        ok = 0;
    }
    if (!headers_are_sanitized())
        ok = 0;
    if (expect_process && !process_hardening_is_effective())
        ok = 0;

    if (ok) {
        emit_marker(pass, (DWORD)(sizeof(pass) - 1u));
        return 0;
    }
    emit_marker(fail, (DWORD)(sizeof(fail) - 1u));
    return 97;
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
    /INCREMENTAL:NO /FIXED /DYNAMICBASE:NO /NXCOMPAT /HIGHENTROPYVA:NO
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
                process_hardening: bool) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env.pop("LETHE_EXPECT_MEMGUARD", None)
    env.pop("LETHE_EXPECT_PROCESS_HARDENING", None)
    if memory_guard:
        env["LETHE_EXPECT_MEMGUARD"] = "1"
    if process_hardening:
        env["LETHE_EXPECT_PROCESS_HARDENING"] = "1"
    return subprocess.run(
        [str(executable)],
        cwd=str(executable.parent),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


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
    assert {".text", ".xone", ".xtwo", ".xidle"} <= executable_sections
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
            ran = _run_packed(
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
        ran = _run_packed(
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
            ran = _run_packed(
                fault_packed,
                memory_guard=memory_guard,
                process_hardening=True,
            )
            assert ran.returncode == 1, (
                name, ran.returncode, ran.stdout, ran.stderr
            )
            assert b"runtime-hardening:" not in ran.stdout
            assert ran.stderr == b""
