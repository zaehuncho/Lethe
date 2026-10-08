"""Opt-in native proof of ordinary EXE export and initialization compatibility.

The explicit candidate stub is copied without alteration and used only through
the existing internal test capability. This is not a public promotion bypass.
The fixture has no installed-product, networking, or anti-analysis dependency.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from packer import orchestrator
from tools import handler_shape_audit


_RUN_GATE = "LETHE_RUN_NATIVE_EXE_EXPORTS"
_STUB_PATH_ENV = "LETHE_NATIVE_RUNTIME_STUB_PATH"
_ENTRY_MARKER = b"exports-payload-entered\r\n"
_EXPECTED_OUTPUT = (
    _ENTRY_MARKER
    + b"exports-pass named=42 ordinal=73 data=1234ABCD forwarder=1 attach=42\r\n"
)
pytestmark = pytest.mark.skipif(os.name != "nt", reason="native loader is Windows-only")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_checked(command: list[str], *, cwd: Path) -> None:
    completed = subprocess.run(
        command, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=180, check=False,
    )
    assert completed.returncode == 0, completed.stdout


def _run(executable: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(executable)], cwd=str(executable.parent), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30, check=False,
    )


def _build_fixture(work: Path, *, early_attach: bool = False) -> tuple[Path, Path]:
    source = work / "source"
    build = work / "build"
    source.mkdir()
    (source / "fixture.c").write_text(
        r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef EARLY_ATTACH
__declspec(dllimport) DWORD WINAPI consumer_attach_answer(void);
#endif

DWORD exported_value = 0x1234ABCDu;
DWORD *volatile relocation_anchor = &exported_value;

DWORD WINAPI named_answer(void)
{
    return 42u;
}

DWORD WINAPI ordinal_answer(void)
{
    return 73u;
}

typedef DWORD (WINAPI *AnswerFn)(void);
typedef union ExportAddress {
    FARPROC raw;
    AnswerFn answer;
    DWORD *data;
} ExportAddress;

static void emit(const char *value, DWORD size)
{
    DWORD written = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), value, size, &written, NULL)
        || written != size)
        ExitProcess(90u);
}

__declspec(noreturn) void fixture_entry(void)
{
    static const char entered[] = "exports-payload-entered\r\n";
    static const char passed[] =
        "exports-pass named=42 ordinal=73 data=1234ABCD forwarder=1 attach=42\r\n";
    HMODULE self = GetModuleHandleW(NULL);
    ExportAddress named, ordinal, data, forward;
#ifndef EARLY_ATTACH
    HMODULE consumer;
    ExportAddress attachment;
#endif
    emit(entered, (DWORD)(sizeof(entered) - 1u));
    if (!self)
        ExitProcess(10u);
    if (relocation_anchor != &exported_value)
        ExitProcess(19u);
    named.raw = GetProcAddress(self, "named_answer");
    ordinal.raw = GetProcAddress(self, (LPCSTR)(ULONG_PTR)9u);
    data.raw = GetProcAddress(self, "exported_value");
    forward.raw = GetProcAddress(self, "forward_pid");
    if (!named.raw || !ordinal.raw || !data.raw || !forward.raw)
        ExitProcess(11u);
    if (named.answer() != 42u || ordinal.answer() != 73u)
        ExitProcess(12u);
    if (*data.data != 0x1234ABCDu)
        ExitProcess(13u);
    if (forward.answer() != GetCurrentProcessId())
        ExitProcess(14u);
#ifdef EARLY_ATTACH
    if (consumer_attach_answer() != 42u)
        ExitProcess(15u);
#else
    consumer = LoadLibraryW(L"export_consumer.dll");
    if (!consumer)
        ExitProcess(17u);
    attachment.raw = GetProcAddress(consumer, "consumer_attach_answer");
    if (!attachment.raw || attachment.answer() != 42u)
        ExitProcess(15u);
    if (!FreeLibrary(consumer))
        ExitProcess(18u);
#endif
    /* This NONAME entry must remain ordinal-only. */
    if (GetProcAddress(self, "ordinal_answer") != NULL)
        ExitProcess(16u);
    emit(passed, (DWORD)(sizeof(passed) - 1u));
    ExitProcess(0u);
}
'''.lstrip(), encoding="ascii",
    )
    (source / "fixture.def").write_text(
        "NAME exe_exports.exe\nEXPORTS\n"
        "    named_answer @7\n"
        "    ordinal_answer @9 NONAME\n"
        "    exported_value @11 DATA\n"
        "    forward_pid=KERNEL32.GetCurrentProcessId @13\n",
        encoding="ascii",
    )
    # Produce the EXE import library independently: the executable imports its
    # consumer, and that consumer imports one EXE export during DLL attachment.
    # A normal CMake target dependency in both directions would be cyclic.
    (source / "fixture_import.def").write_text(
        "LIBRARY exe_exports.exe\nEXPORTS\n    named_answer @7\n",
        encoding="ascii",
    )
    (source / "consumer.c").write_text(
        r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__declspec(dllimport) DWORD WINAPI named_answer(void);
static DWORD attach_answer;

__declspec(dllexport) DWORD WINAPI consumer_attach_answer(void)
{
    return attach_answer;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        attach_answer = named_answer();
        if (attach_answer != 42u)
            return FALSE;
    }
    return TRUE;
}
'''.lstrip(), encoding="ascii",
    )
    (source / "CMakeLists.txt").write_text(
        r'''
cmake_minimum_required(VERSION 3.20)
project(lethe_native_exe_exports C)
if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This fixture requires the MSVC x64 toolchain")
endif()
set(import_lib "${CMAKE_CURRENT_BINARY_DIR}/fixture_import.lib")
add_custom_command(OUTPUT "${import_lib}"
    COMMAND "${CMAKE_AR}" /NOLOGO /MACHINE:X64
        "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/fixture_import.def"
        "/OUT:${import_lib}"
    DEPENDS fixture_import.def VERBATIM)
add_custom_target(fixture_import DEPENDS "${import_lib}")
add_library(export_consumer SHARED consumer.c)
add_dependencies(export_consumer fixture_import)
target_link_libraries(export_consumer PRIVATE "${import_lib}")
target_link_options(export_consumer PRIVATE /ENTRY:DllMain /NODEFAULTLIB)
add_executable(exe_exports fixture.c fixture.def)
target_link_libraries(exe_exports PRIVATE kernel32)
option(EARLY_ATTACH "Characterize source dependency callback before EXE startup" OFF)
if(EARLY_ATTACH)
    target_compile_definitions(exe_exports PRIVATE EARLY_ATTACH)
    target_link_libraries(exe_exports PRIVATE export_consumer)
endif()
target_link_options(exe_exports PRIVATE
    "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/fixture.def"
    /ENTRY:fixture_entry /NODEFAULTLIB /SUBSYSTEM:CONSOLE /DYNAMICBASE /NXCOMPAT)
foreach(target export_consumer exe_exports)
    target_compile_options(${target} PRIVATE /W4 /WX /O2 /GS- /Zl)
endforeach()
'''.lstrip(), encoding="ascii",
    )
    _run_checked(
        ["cmake", "-S", str(source), "-B", str(build), "-G",
         "Visual Studio 17 2022", "-A", "x64",
         "-DEARLY_ATTACH=" + ("ON" if early_attach else "OFF")], cwd=work,
    )
    _run_checked(["cmake", "--build", str(build), "--config", "Release"], cwd=work)
    executable = build / "Release" / "exe_exports.exe"
    consumer = build / "Release" / "export_consumer.dll"
    assert executable.is_file() and consumer.is_file()
    return executable, consumer


def _export_layout(data: bytes) -> tuple[int, int, int, int]:
    """Return the PE64 export-directory field, RVA, size, and raw offset."""
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_offset:pe_offset + 4] == b"PE\0\0"
    optional = pe_offset + 24
    assert struct.unpack_from("<H", data, optional)[0] == 0x20B
    field = optional + 0x70
    rva, size = struct.unpack_from("<II", data, field)
    assert rva and size >= 40, "packed EXE lost the source export directory"
    sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    table = optional + struct.unpack_from("<H", data, pe_offset + 20)[0]
    for index in range(sections):
        section = table + index * 40
        section_rva, raw_size, raw_offset = struct.unpack_from("<III", data, section + 12)
        if section_rva <= rva and rva + size <= section_rva + raw_size:
            offset = raw_offset + rva - section_rva
            assert offset + size <= len(data)
            return field, rva, size, offset
    raise AssertionError("export snapshot must be entirely file-backed")


@dataclass(frozen=True)
class _ExportFixture:
    work: Path
    original: Path
    packed: Path
    consumer: Path
    stub_sha256: str


def _prepare_fixture(work: Path, *, early_attach: bool = False):
    if os.environ.get(_RUN_GATE) != "1":
        pytest.skip(f"set {_RUN_GATE}=1 for the native EXE export compatibility proof")
    configured = os.environ.get(_STUB_PATH_ENV)
    assert configured, f"the enabled gate requires an explicit {_STUB_PATH_ENV}"
    source_stub = Path(configured).resolve()
    assert source_stub.is_file(), f"{_STUB_PATH_ENV} is not a file: {source_stub}"
    assert shutil.which("cmake"), "the enabled gate requires CMake"
    assert handler_shape_audit.find_msvc() is not None, "the enabled gate requires MSVC x64"
    before = _sha256(source_stub)
    stub = work / "candidate_stub.dll"
    shutil.copyfile(source_stub, stub)
    assert _sha256(stub) == before
    evidence = {
        "stub_source": str(source_stub), "stub_copy": str(stub),
        "stub_sha256_before": before, "stub_copy_sha256_before": _sha256(stub),
    }
    try:
        original, consumer = _build_fixture(work, early_attach=early_attach)
        baseline = _run(original)
        evidence["baseline"] = {
            "command": [str(original)], "sha256": _sha256(original),
            "exit": baseline.returncode,
            "stdout": baseline.stdout.decode("ascii", errors="replace"),
            "stderr": baseline.stderr.decode("ascii", errors="replace"),
        }
        print("EXE_EXPORT_BASELINE=" + json.dumps(evidence["baseline"], sort_keys=True))
        assert baseline.returncode == 0, (baseline.stdout, baseline.stderr)
        assert baseline.stdout == _EXPECTED_OUTPUT
        assert baseline.stderr == b""
        _export_layout(original.read_bytes())
        output = work / "packed"
        output.mkdir()
        shutil.copyfile(consumer, output / consumer.name)
        packed = output / original.name
        result = orchestrator.pack_file(
            str(original),
            orchestrator.PackOptions(
                output_path=str(packed), is_dll=False, stub_path=str(stub),
                _allow_unverified_stub_for_tests=True,
            ),
        )
        evidence["pack"] = {"ok": result.ok, "error": result.error}
        assert result.ok, result.error
        assert packed.is_file()
        evidence["packed_sha256"] = _sha256(packed)
        yield _ExportFixture(work, original, packed, consumer, before)
    finally:
        evidence["stub_sha256_after"] = _sha256(source_stub)
        evidence["stub_copy_sha256_after"] = _sha256(stub)
        path = work / "native-exe-exports-evidence.json"
        path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("EXE_EXPORT_STUB_EVIDENCE=" + json.dumps(evidence, sort_keys=True))
        assert evidence["stub_sha256_after"] == before
        assert evidence["stub_copy_sha256_after"] == before


@pytest.fixture(scope="module")
def export_fixture(tmp_path_factory: pytest.TempPathFactory):
    yield from _prepare_fixture(tmp_path_factory.mktemp("native-exe-exports"))


def _assert_packed_parity(export_fixture: _ExportFixture) -> None:
    completed = _run(export_fixture.packed)
    print("EXE_EXPORT_PACKED=" + json.dumps({
        "command": [str(export_fixture.packed)], "exit": completed.returncode,
        "stdout": completed.stdout.decode("ascii", errors="replace"),
        "stderr": completed.stderr.decode("ascii", errors="replace"),
        "stub_sha256": export_fixture.stub_sha256,
    }, sort_keys=True))
    _export_layout(export_fixture.packed.read_bytes())
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    assert completed.stdout == _EXPECTED_OUTPUT
    assert completed.stderr == b""


def test_packed_exe_preserves_exports_after_startup(export_fixture: _ExportFixture) -> None:
    """Prove lookup and a post-startup plugin's DLL_PROCESS_ATTACH callback."""
    _assert_packed_parity(export_fixture)


def test_packed_exe_preserves_exports_during_early_dependency_attach(tmp_path: Path) -> None:
    """Characterization only: early source-import callbacks are not proven.

    Unlike the normal positive test, the imported DLL calls EXE code before the
    EXE loader finishes relocations, TLS, unwind, and page-protection setup.
    This test intentionally demands parity and must not be included as a passed
    promotion gate until a correct initialization lifecycle is implemented.
    """
    gate = "LETHE_RUN_NATIVE_EXE_EXPORTS_EARLY_ATTACH"
    if os.environ.get(gate) != "1":
        pytest.skip(f"set {gate}=1 to characterize early dependency callbacks")
    fixture = _prepare_fixture(tmp_path, early_attach=True)
    try:
        _assert_packed_parity(next(fixture))
    finally:
        fixture.close()


@pytest.mark.parametrize("mutation", [
    "directory-count", "directory-size", "function-count", "eat-target", "forwarder-name",
])
def test_packed_exe_rejects_visible_export_tamper(
    export_fixture: _ExportFixture, mutation: str,
) -> None:
    """Reject malformed metadata and structurally valid altered export bytes."""
    data = bytearray(export_fixture.packed.read_bytes())
    field, rva, size, raw = _export_layout(data)
    if mutation == "directory-count":
        struct.pack_into("<I", data, field - 4, 0)
    elif mutation == "directory-size":
        struct.pack_into("<I", data, field + 4, size + 1)
    elif mutation == "function-count":
        struct.pack_into("<I", data, raw + 20, 0xFFFFFFFF)
    elif mutation == "eat-target":
        ordinal_base, count = struct.unpack_from("<II", data, raw + 16)
        eat_rva = struct.unpack_from("<I", data, raw + 28)[0]
        assert ordinal_base <= 7 < ordinal_base + count
        assert ordinal_base <= 9 < ordinal_base + count
        eat_offset = raw + eat_rva - rva
        assert raw <= eat_offset and eat_offset + count * 4 <= raw + size
        alternate = struct.unpack_from("<I", data, eat_offset + (9 - ordinal_base) * 4)[0]
        struct.pack_into("<I", data, eat_offset + (7 - ordinal_base) * 4, alternate)
    else:
        forwarder = b"KERNEL32.GetCurrentProcessId\0"
        position = data.find(forwarder, raw, raw + size)
        assert position >= raw, "fixture must contain its original forwarder string"
        data[position] = ord("X")
    assert bytes(data) != export_fixture.packed.read_bytes()
    target_dir = export_fixture.work / ("tampered-" + mutation)
    target_dir.mkdir()
    tampered = target_dir / export_fixture.original.name
    tampered.write_bytes(data)
    shutil.copyfile(export_fixture.consumer, target_dir / export_fixture.consumer.name)
    completed = _run(tampered)
    evidence = {
        "mutation": mutation, "command": [str(tampered)], "sha256": _sha256(tampered),
        "exit": completed.returncode,
        "stdout": completed.stdout.decode("ascii", errors="replace"),
        "stderr": completed.stderr.decode("ascii", errors="replace"),
        "stub_sha256": export_fixture.stub_sha256,
    }
    (target_dir / "result.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    print("EXE_EXPORT_TAMPER=" + json.dumps(evidence, sort_keys=True))
    assert completed.returncode != 0, evidence
    assert _ENTRY_MARKER not in completed.stdout, evidence
    assert b"exports-pass" not in completed.stdout, evidence
