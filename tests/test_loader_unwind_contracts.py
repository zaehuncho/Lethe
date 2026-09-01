from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOADER = (ROOT / "stub" / "src" / "pe_loader.c").read_text(encoding="utf-8")
STUB_MAIN = (ROOT / "stub" / "src" / "stub_main.c").read_text(encoding="utf-8")
UNWIND_DLL = (ROOT / "tests" / "sample" / "unwind_dll.cpp").read_text(
    encoding="utf-8")
UNWIND_HOST = (ROOT / "tests" / "sample" / "unwind_host.c").read_text(
    encoding="utf-8")


def _loader_function() -> str:
    start = LOADER.index("int pe_loader_run(")
    end = LOADER.index("/* ---- OS TLS anchor dispatch", start)
    return LOADER[start:end]


def test_pdata_registration_is_recorded_only_after_success() -> None:
    source = _loader_function()
    assert "int pdata_registered = 0;" in source
    validation = source.index("validate_pdata_geometry(")
    registration = source.index("RtlAddFunctionTable(")
    assert validation < registration
    assert re.search(
        r"if \(!RtlAddFunctionTable\(.*?\)\)\s*"
        r"goto fail;\s*pdata_registered = 1;",
        source,
        re.DOTALL,
    )


def test_pdata_geometry_is_bounded_and_non_overlapping() -> None:
    start = LOADER.index("static int validate_pdata_geometry(")
    end = LOADER.index("/* ---- TLS", start)
    source = LOADER[start:end]

    assert "(uint64_t)pdata_count * 12u" in source
    assert "(uint64_t)pdata_rva + table_size" in source
    assert "table_end > image_size" in source
    assert "begin == 0 || begin >= end || end > image_size" in source
    assert "begin < previous_end" in source
    assert "(unwind_rva & 3u) != 0" in source
    assert "(uint64_t)unwind_rva + 4u > image_size" in source
    assert "version < 1 || version > 3" in source


def test_exception_flag_and_metadata_presence_must_agree() -> None:
    source = _loader_function()
    assert re.search(
        r"if \(cpi->flags & LETHE_FLAG_HAS_EXCEPTIONS\).*?"
        r"validate_pdata_geometry\(.*?RtlAddFunctionTable\(.*?"
        r"else if \(cpi->pdata_rva \|\| cpi->pdata_count\) \{\s*"
        r"goto fail;",
        source,
        re.DOTALL,
    )


def test_every_post_registration_failure_converges_on_rollback() -> None:
    source = _loader_function()
    fail_label = source.index("\nfail:")
    success_path = source[:fail_label]
    failure_path = source[fail_label:]

    assert "RtlDeleteFunctionTable" not in success_path
    assert re.search(
        r"if \(pdata_registered\) \{\s*"
        r"RtlDeleteFunctionTable\(\s*"
        r"\(PRUNTIME_FUNCTION\)\(base \+ cpi->pdata_rva\)\);\s*"
        r"pdata_registered = 0;\s*\}",
        failure_path,
        re.DOTALL,
    )
    assert failure_path.index("RtlDeleteFunctionTable") < failure_path.index(
        "return 1;")


def test_successful_dll_lifecycle_owns_detach_cleanup() -> None:
    process_detach = STUB_MAIN[STUB_MAIN.index(
        "if (reason == DLL_PROCESS_DETACH"):STUB_MAIN.index(
            "if (reason == DLL_THREAD_ATTACH")]
    cleanup = STUB_MAIN[STUB_MAIN.index("static void release_dll_runtime("):
                        STUB_MAIN.index("void __cdecl StubExeEntryImpl(")]
    assert "release_dll_runtime(hInst, reason, reserved);" in process_detach
    assert "RtlDeleteFunctionTable(" in cleanup
    assert "(PRUNTIME_FUNCTION)((uint8_t *)hInst + s_pdata_rva)" in cleanup


def test_native_dll_unwind_fixture_throws_catches_and_reloads() -> None:
    assert "throw value + 11" in UNWIND_DLL
    assert "catch (int caught)" in UNWIND_DLL
    assert 'GetProcAddress(module, "unwind_value")' in UNWIND_HOST
    assert "function() != 72u" in UNWIND_HOST
    assert "iteration < 8u" in UNWIND_HOST
    assert "FreeLibrary(module)" in UNWIND_HOST
