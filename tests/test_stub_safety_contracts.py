"""Source-level release contracts for the freestanding Lethe stub.

These checks complement the native round-trip harness.  They deliberately pin
the fail-closed ownership and loader-lock rules that are easy to regress while
refactoring code that cannot be unit-injected without changing the stub ABI.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


PACKER_ROOT = Path(__file__).resolve().parents[1]
STUB_ROOT = PACKER_ROOT / "stub"
SRC = STUB_ROOT / "src"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_cmake_sources_exist_and_rng_dependency_is_loader_resolved() -> None:
    """The CNG entropy provider must be resolved before packed DLL DllMain."""
    cmake = _read(STUB_ROOT / "CMakeLists.txt")
    listed_sources = re.findall(r"\bsrc/[A-Za-z0-9_.-]+\.(?:c|asm)\b", cmake)

    assert listed_sources
    assert all((STUB_ROOT / source).is_file() for source in listed_sources)
    assert "src/stub_junk_imports.c" not in listed_sources
    assert "src/bcrypt_dyn.c" not in listed_sources

    # Both dependencies are static so Windows resolves them before DllMain.
    link = re.search(
        r"target_link_libraries\s*\(\s*lethe_stub_x64\s+PRIVATE([^)]*)\)",
        cmake,
        re.DOTALL,
    )
    assert link, "expected target_link_libraries(lethe_stub_x64 PRIVATE ...)"
    linked = link.group(1)
    assert "kernel32" in linked
    assert "bcrypt" in linked.lower()

    compiled = "\n".join(
        _read(STUB_ROOT / source)
        for source in listed_sources
        if source.endswith(".c")
    )
    # No source may pull bcrypt in through a link pragma either.
    assert not re.search(
        r'#pragma\s+comment\s*\(\s*lib\s*,\s*"bcrypt',
        compiled,
        re.IGNORECASE,
    )

    # Entropy is a static bcrypt import so the OS resolves the dependency before
    # a protected DLL enters DllMain. Decrypt/hash primitives remain local.
    crypto = _read(SRC / "crypto.c")
    assert "bcrypt_dyn_init" not in compiled
    assert "p_BCrypt" not in compiled
    assert "int crypto_csprng(" in crypto
    assert "BCryptGenRandom(" in crypto
    assert "LoadLibraryA" not in crypto and "GetProcAddress" not in crypto


def test_freestanding_miniz_disables_crt_assertions_after_shared_flags() -> None:
    cmake = _read(STUB_ROOT / "CMakeLists.txt")
    shared_flags = cmake.index("set_source_files_properties(${_C_SOURCES}")
    miniz_flags = cmake.index("set_source_files_properties(src/miniz.c")
    miniz_block = cmake[miniz_flags:cmake.index("\n)", miniz_flags) + 2]

    assert shared_flags < miniz_flags
    assert "NDEBUG" in miniz_block
    assert "LETHE_FREESTANDING_ALLOC" in miniz_block
    assert "/W3;/WX-;/GS-;/Oi;/O2" in miniz_block


def test_os_entrypoints_use_aligned_masm_veneers() -> None:
    cmake = _read(STUB_ROOT / "CMakeLists.txt")
    entrypoints = _read(SRC / "stub_entrypoints.asm")
    entry = _read(SRC / "stub_main.c")
    tls = _read(SRC / "tls_anchor.c")

    assert "src/stub_entrypoints.asm" in cmake
    assert "/INCREMENTAL:NO" in cmake
    for name in ("StubExeEntry", "StubDllMain"):
        assert f"/EXPORT:{name}" in cmake
        assert f"PUBLIC {name}" in entrypoints
        assert re.search(rf"ALIGN 16\s+{name} PROC", entrypoints)
        assert f"jmp {name}Impl" in entrypoints
    assert "void __cdecl StubExeEntryImpl(void)" in entry
    assert "BOOL WINAPI StubDllMainImpl(" in entry
    assert "__declspec(dllexport)\nvoid __cdecl StubExeEntry" not in entry
    assert re.search(
        r"ALIGN 16\s+lethe_stub_tls_callback PROC", entrypoints)
    assert "jmp lethe_stub_tls_callback_impl" in entrypoints
    assert "void NTAPI lethe_stub_tls_callback_impl(" in tls


def test_memguard_relocation_recipe_is_staged_fail_closed() -> None:
    header = _read(SRC / "stub_hooks.h")
    guard = _read(SRC / "memguard.c")
    loader = _read(SRC / "pe_loader.c")

    assert re.search(r"\bint\s+memguard_set_relocs\s*\(", header)
    assert "if (!s_pending_reloc_blob)\n        return 1;" in guard
    assert "memguard_discard_pending_relocs();" in guard
    assert "if (memguard_set_relocs(" in loader
    assert "if (memguard_install(image_base, cpi, secs) != 0)" in loader
    assert "mg_ok = 1;" in loader
    assert "memguard_discard_pending_relocs();" in loader


def test_memguard_request_never_downgrades_to_eager_plaintext() -> None:
    loader = _read(SRC / "pe_loader.c")
    install = loader[loader.index("/* 10. Mandatory authenticated memguard install."):
                     loader.index("/* Memguard and authenticated VM pages")]

    assert "RELOC_FILTER_NONEXEC" in loader
    assert re.search(
        r"mg_want\s*\?\s*RELOC_FILTER_NONEXEC\s*:\s*RELOC_FILTER_ALL",
        loader,
    )
    assert "decrypt_section(" not in install
    assert "goto fail;" in install


def test_paged_vm_owns_scattered_key_until_module_teardown() -> None:
    loader = _read(SRC / "pe_loader.c")
    entry = _read(SRC / "stub_main.c")

    assert "LETHE_FLAG_PAGED_DVM" in loader
    assert re.search(
        r"if\s*\(!mg_ok\s*&&\s*!\(cpi->flags\s*&\s*"
        r"LETHE_FLAG_PAGED_DVM\)\)\s*key_scatter_destroy\(\);",
        loader,
    )
    assert "release_dll_runtime(hInst, reason, reserved);" in entry
    cleanup = entry[entry.index("static void release_dll_runtime("):
                    entry.index("void __cdecl StubExeEntryImpl(")]
    assert "key_scatter_destroy();" in cleanup
    assert re.search(r"fail:.*?key_scatter_destroy\(\);", loader, re.DOTALL)


def test_tls_roundtrip_fixture_exercises_a_new_worker_thread() -> None:
    sample = _read(PACKER_ROOT / "tests" / "sample" / "sample_dll.c")
    host = _read(PACKER_ROOT / "tests" / "sample" / "host.c")

    assert "__declspec(thread)" in sample
    assert "sample_dll_tls_value" in sample
    assert 'allocate(".xreloc")' in sample
    assert "CreateThread" in host
    assert "TLS main=%u worker=%u" in host


def test_tls_capacity_matches_between_builder_and_stub() -> None:
    payload = _read(PACKER_ROOT / "packer" / "payload.py")
    anchor = _read(SRC / "tls_anchor.h")

    py_capacity = re.search(r"^STUB_TLS_CAPACITY\s*=\s*(\d+)", payload, re.MULTILINE)
    c_capacity = re.search(
        r"^#define\s+ORION_STUB_TLS_CAPACITY\s+(\d+)u?",
        anchor,
        re.MULTILINE,
    )
    assert py_capacity and c_capacity
    assert int(py_capacity.group(1)) == int(c_capacity.group(1)) == 4096
    assert "tls_total_size > STUB_TLS_CAPACITY" in payload


def test_oversize_tls_template_is_rejected_before_assembly() -> None:
    sys.path.insert(0, str(PACKER_ROOT))
    try:
        from packer import payload
    finally:
        sys.path.pop(0)

    parsed = SimpleNamespace(
        sections=[],
        imports=[],
        tls=SimpleNamespace(
            index_rva=0x100,
            raw_start_rva=0x200,
            raw_end_rva=0x200 + payload.STUB_TLS_CAPACITY + 1,
            zero_fill=0,
            callback_rvas=[],
        ),
        reloc_blob=b"",
        pdata_count=0,
        oep_rva=0,
        is_dll=True,
        image_base=0x180000000,
        size_of_image=0x1000,
        pdata_rva=0,
        rsrc_rva=0,
        rsrc_bytes=b"",
    )
    with pytest.raises(ValueError, match="TLS template is 4097 bytes"):
        payload.build_payload(parsed, SimpleNamespace())


def test_memguard_dll_does_not_join_a_worker_from_dllmain() -> None:
    guard = _read(SRC / "memguard.c")

    assert "CreateThread(" not in guard
    assert "WaitForSingleObject(" not in guard
    assert "reenc_thread" not in guard


@pytest.mark.parametrize("option", ["memory_guard", "process_hardening"])
def test_payload_rejects_dll_process_global_options(option) -> None:
    sys.path.insert(0, str(PACKER_ROOT))
    try:
        from packer import payload
    finally:
        sys.path.pop(0)

    parsed = SimpleNamespace(is_dll=True, requires_paged_vm=False)
    with pytest.raises(ValueError, match="DLL|DLLs"):
        payload.build_payload(parsed, SimpleNamespace(**{option: True}))


def test_packed_dll_does_not_mutate_process_wide_loader_policy() -> None:
    antidump = _read(SRC / "antidump.c")
    loader = _read(SRC / "pe_loader.c")

    early = re.search(
        r"int\s+antidump_harden_early\s*\(int\s+is_dll\)\s*\{(?P<body>.*?)\n\}",
        antidump,
        re.DOTALL,
    )
    assert early
    body = early.group("body")
    assert re.search(r"if\s*\(is_dll\)\s*return\s+1\s*;", body)
    assert "harden_process_mitigations() != 0" in body
    assert "return harden_dll_search_order();" in body
    assert "cpi->flags & LETHE_FLAG_PROCESS_HARDENING" in loader
    assert "antidump_harden_early(cpi->is_dll) != 0" in loader
    assert "LETHE_FLAG_MEMGUARD |" in loader
    assert "LETHE_FLAG_PROCESS_HARDENING)))" in loader


def test_dll_antidebug_detection_returns_failure_without_killing_host() -> None:
    antidebug = _read(SRC / "antidebug.c")
    loader = _read(SRC / "pe_loader.c")
    entry = _read(SRC / "stub_main.c")

    tripwire_region = antidebug[antidebug.index("/* Tripwire 1:"):
                                antidebug.index("int antidbg_check(void)")]
    assert "ExitProcess(" not in tripwire_region
    for name in ("peb", "ntgf", "rdtsc", "hwbp"):
        assert f"int antidbg_tripwire_{name}(void)" in antidebug
    assert "ExitProcess(" not in loader
    assert re.search(
        r"if \(antidebug_on && antidbg_tripwire_rdtsc\(\)\)\s*"
        r"return FALSE;",
        entry,
    )


def test_antidump_writes_restore_and_verify_page_protections() -> None:
    antidump = _read(SRC / "antidump.c")
    loader = _read(SRC / "pe_loader.c")

    assert "static int ad_range_has_protection(" in antidump
    assert "#define AD_VIRTUAL_PROTECT VirtualProtect" in antidump
    assert "#define AD_VIRTUAL_QUERY   VirtualQuery" in antidump
    assert "AD_VIRTUAL_QUERY(" in antidump
    assert "mbi.Protect != expected" in antidump
    assert "int antidump_erase_headers(" in antidump
    assert "int antidump_harden(" in antidump
    assert re.search(
        r"if \(!AD_VIRTUAL_PROTECT\(\s*"
        r"image_base, size_of_headers, old_prot, &tmp_prot\)\)\s*return 1;",
        antidump,
    )
    assert re.search(
        r"if \(!AD_VIRTUAL_PROTECT\(\s*"
        r"meta, pi->meta_stored_size, old_prot, &tmp_prot\)\)\s*return 1;",
        antidump,
    )
    assert "if (antidump_erase_headers(image_base, cpi->is_dll) != 0)" in loader
    assert "if (antidump_harden(image_base, cpi) != 0)" in loader
    assert loader.index("antidump_harden(image_base, cpi)") < loader.index(
        "tls_process_attach()")


def test_loader_sensitive_buffers_are_locked_or_startup_fails() -> None:
    loader = _read(SRC / "pe_loader.c")
    run = loader[loader.index("int pe_loader_run("):]
    decrypt = loader[loader.index("static int decrypt_section("):
                     loader.index("static int pl_all_zero(")]

    assert "if (!VirtualLock(scratch, sd->stored_size))" in decrypt
    assert "VirtualUnlock(scratch, sd->stored_size);" in decrypt
    assert "if (!VirtualLock(meta_dec, cpi->meta_stored_size))" in run
    assert "if (!VirtualLock(meta_buf, cpi->meta_uncompressed_size))" in run
    assert "VirtualUnlock(meta_dec, cpi->meta_stored_size);" in run
    assert "VirtualUnlock(meta_buf, cpi->meta_uncompressed_size);" in run
    assert "if (wipe_stored(base, &secs[i]) != 0)" in run


def test_all_section_descriptors_are_preflighted_before_decryption() -> None:
    loader = _read(SRC / "pe_loader.c")
    validator = loader[loader.index("static int validate_section_desc("):
                       loader.index("static int decrypt_section(")]
    for required in (
        "sd->rva == 0", "sd->virtual_size == 0", "sd->stored_rva == 0",
        "sd->stored_size == 0", "sd->uncompressed_size == 0",
        "sd->uncompressed_size > sd->virtual_size",
        "(uint64_t)sd->rva + sd->virtual_size > target_bound",
        "(uint64_t)sd->stored_rva + sd->stored_size > stored_bound",
    ):
        assert required in validator
    main = loader[loader.index("int pe_loader_run("):]
    preflight = main.index("validate_section_desc(&secs[i]")
    snapshot = main.index("snapshot_preloaded_iat(")
    decrypt = main.index("drc = decrypt_section(")
    assert preflight < snapshot < decrypt


def test_final_section_protection_failure_is_always_fatal() -> None:
    loader = _read(SRC / "pe_loader.c")
    final = loader[loader.index("/* 11. Set every authenticated"):
                   loader.index("DIAG(10);")]
    assert re.search(r"if \(!VirtualProtect\(.*?\)\)\s*goto fail;", final,
                     re.DOTALL)
    assert "non-fatal" not in final


def test_returning_custom_exe_entry_status_reaches_exitprocess() -> None:
    stub_main = _read(SRC / "stub_main.c")
    build = _read(PACKER_ROOT / "tests" / "build_samples.ps1")
    fixture = _read(PACKER_ROOT / "tests" / "sample" / "return_entry_exe.c")
    assert "typedef uint32_t (__cdecl *ExeEntry_t)(void);" in stub_main
    assert "ExitProcess(invoke_exe_oep());" in stub_main
    assert "return 37u;" in fixture
    assert "/NODEFAULTLIB /SUBSYSTEM:CONSOLE /ENTRY:return_37" in build
