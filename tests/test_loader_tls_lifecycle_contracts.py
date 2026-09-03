from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "stub" / "src"
LOADER = (SRC / "pe_loader.c").read_text(encoding="utf-8")
ANCHOR = (SRC / "tls_anchor.c").read_text(encoding="utf-8")
ANCHOR_H = (SRC / "tls_anchor.h").read_text(encoding="utf-8")
STUB_MAIN = (SRC / "stub_main.c").read_text(encoding="utf-8")
ANTIDUMP = (SRC / "antidump.c").read_text(encoding="utf-8")
SAMPLE_EXE = (ROOT / "tests" / "sample" / "sample_exe.c").read_text(
    encoding="utf-8")
SAMPLE_DLL = (ROOT / "tests" / "sample" / "sample_dll.c").read_text(
    encoding="utf-8")
HOST = (ROOT / "tests" / "sample" / "host.c").read_text(encoding="utf-8")
STATIC_HOST = (ROOT / "tests" / "sample" / "static_host.c").read_text(
    encoding="utf-8")
RELOAD_HOST = (ROOT / "tests" / "sample" / "reload_host.c").read_text(
    encoding="utf-8")
PREEXISTING_HOST = (ROOT / "tests" / "sample" / "preexisting_tls_host.c").read_text(
    encoding="utf-8")
NOENTRY_HOST = (ROOT / "tests" / "sample" / "noentry_host.c").read_text(
    encoding="utf-8")
REJECT_HOST = (ROOT / "tests" / "sample" / "reject_host.c").read_text(
    encoding="utf-8")
TLSFREE_DLL = (ROOT / "tests" / "sample" / "tlsfree_dll.c").read_text(
    encoding="utf-8")
TLSFREE_HOST = (ROOT / "tests" / "sample" / "tlsfree_host.c").read_text(
    encoding="utf-8")
AUDIT = (ROOT / "docs" / "LOADER_COVERAGE_AUDIT.md").read_text(
    encoding="utf-8")


def _function(source: str, signature: str, next_marker: str) -> str:
    start = source.index(signature)
    end = source.index(next_marker, start)
    return source[start:end]


def test_anchor_has_a_real_null_terminated_dispatcher() -> None:
    assert "lethe_stub_tls_callback" in ANCHOR
    assert re.search(
        r"s_orion_tls_callbacks\[2\]\s*=\s*\{\s*"
        r"lethe_stub_tls_callback,\s*NULL\s*\}",
        ANCHOR,
        re.DOTALL,
    )
    callback = _function(
        ANCHOR, "static void NTAPI lethe_stub_tls_callback(",
        "__declspec(allocate(\".tls$AAA\"))")
    assert "pe_loader_tls_anchor_dispatch(module, reason, reserved);" in callback


def test_anchor_has_private_per_thread_state_after_protected_capacity() -> None:
    assert "ORION_STUB_TLS_CAPACITY 4096u" in ANCHOR_H
    assert "ORION_STUB_TLS_STATE_SIZE 16u" in ANCHOR_H
    assert "ORION_STUB_TLS_ALLOCATION_SIZE" in ANCHOR_H
    assert "s_orion_tls_reserve[ORION_STUB_TLS_ALLOCATION_SIZE]" in ANCHOR
    assert "storage + ORION_STUB_TLS_CAPACITY" in LOADER


def test_recipe_survives_metadata_and_callback_paths_do_not_allocate() -> None:
    setup = _function(LOADER, "static int setup_tls(",
                      "/* ---- diagnostic")
    assert "ProtectedTlsRecipe" in setup
    assert "VirtualAlloc(" in setup
    assert "tls_recipe_callbacks(recipe)" in setup
    assert "tls_recipe_template(recipe)" in setup

    dispatch = _function(LOADER, "void pe_loader_tls_anchor_dispatch(",
                         "void pe_loader_tls_dll_detach(")
    for forbidden in ("LoadLibrary", "HeapAlloc", "HeapFree", "VirtualAlloc"):
        assert forbidden not in dispatch
    assert "process loader lock" in dispatch
    assert "must never load modules" in dispatch


def test_process_attach_is_manual_and_exactly_once() -> None:
    attach = _function(LOADER, "static int tls_process_attach(",
                       "static void tls_thread_attach(")
    assert "if (s_tls_process_attached)" in attach
    assert attach.index("s_tls_process_attached = 1;") < attach.index(
        "tls_invoke_callbacks(DLL_PROCESS_ATTACH);")
    assert "if (tls_process_attach() != 0)" in LOADER


def test_live_pe_header_path_is_preserved_for_windows_runtime_apis() -> None:
    assert "if (antidump_erase_headers(image_base, cpi->is_dll) != 0)" in LOADER
    erase = _function(ANTIDUMP, "static int erase_headers(",
                      "static int wipe_metadata_envelope(")
    assert "dos->e_magic  = 0" not in erase
    assert "nt->Signature = 0" not in erase
    assert "NumberOfSections   = 0" not in erase
    assert "sizeof(IMAGE_SECTION_HEADER)" not in erase
    assert "ad_clear_dir(nt, IMAGE_DIRECTORY_ENTRY_RESOURCE)" not in erase
    assert "ad_clear_dir(nt, IMAGE_DIRECTORY_ENTRY_TLS)" not in erase


def test_thread_attach_initializes_before_callbacks_and_detach_wipes_after() -> None:
    attach = _function(LOADER, "static void tls_thread_attach(",
                       "static void tls_thread_detach(")
    detach = _function(LOADER, "static void tls_thread_detach(",
                       "static void tls_process_detach(")
    assert attach.index("tls_initialize_current()") < attach.index(
        "tls_invoke_callbacks(DLL_THREAD_ATTACH);")
    assert detach.index("tls_invoke_callbacks(DLL_THREAD_DETACH);") < detach.index(
        "pl_zero(storage, ORION_STUB_TLS_ALLOCATION_SIZE);")
    assert "state->magic != TLS_THREAD_STATE_MAGIC" in detach
    assert "!state->initialized" in detach
    assert "!state->attach_delivered" in detach
    assert "tls_initialize_current()" not in detach


def test_dll_detach_preserves_native_dllmain_then_tls_order() -> None:
    assert "pe_loader_tls_thread_init" not in STUB_MAIN
    assert "pe_loader_tls_thread_free" not in STUB_MAIN
    process_detach = STUB_MAIN[
        STUB_MAIN.index("if (reason == DLL_PROCESS_DETACH"):
        STUB_MAIN.index("if (reason == DLL_THREAD_ATTACH")]
    thread_detach = STUB_MAIN[
        STUB_MAIN.index("if (reason == DLL_THREAD_DETACH"):
        STUB_MAIN.index("return TRUE;", STUB_MAIN.index(
            "if (reason == DLL_THREAD_DETACH"))]
    assert process_detach.index("invoke_dll_oep") < process_detach.index(
        "release_dll_runtime")
    cleanup = _function(STUB_MAIN, "static void release_dll_runtime(",
                        "__declspec(dllexport)\nvoid __cdecl StubExeEntry(")
    assert cleanup.index("pe_loader_tls_dll_detach") < cleanup.index(
        "memguard_shutdown")
    assert thread_detach.index("invoke_dll_oep") < thread_detach.index(
        "pe_loader_tls_dll_detach")


def test_failure_unpublishes_and_destroys_recipe() -> None:
    fail = LOADER[LOADER.index("\nfail:"):LOADER.index(
        "/* ---- OS TLS anchor dispatch")]
    assert "tls_release_state();" in fail
    release = _function(LOADER, "static void tls_release_state(",
                        "static int tls_process_attach(")
    assert release.index("s_tls_active = 0;") < release.index("VirtualFree(")
    assert "pl_zero(recipe, recipe->allocation_size);" in release


def test_native_exe_fixture_covers_full_worker_lifecycle() -> None:
    assert 'allocate(".CRT$XLB")' in SAMPLE_EXE
    assert "DLL_PROCESS_ATTACH" in SAMPLE_EXE
    assert "DLL_THREAD_ATTACH" in SAMPLE_EXE
    assert "DLL_THREAD_DETACH" in SAMPLE_EXE
    assert "CreateThread" in SAMPLE_EXE
    assert "g_tls_process_attach_count != 1" in SAMPLE_EXE
    assert "g_tls_thread_attach_count != 1" in SAMPLE_EXE
    assert "g_tls_thread_detach_count != 1" in SAMPLE_EXE


def test_native_dll_fixture_has_real_callbacks_and_post_load_worker() -> None:
    assert 'allocate(".CRT$XLB")' in SAMPLE_DLL
    assert "g_sample_dll_tls_callback" in SAMPLE_DLL
    assert "DLL_PROCESS_ATTACH" in SAMPLE_DLL
    assert "DLL_THREAD_ATTACH" in SAMPLE_DLL
    assert "DLL_THREAD_DETACH" in SAMPLE_DLL
    assert "sample_dll_tls_lifecycle_ok" in SAMPLE_DLL

    load = HOST.index("LoadLibraryA")
    worker = HOST.index("CreateThread")
    verify = HOST.index("tls_lifecycle_fn()")
    assert load < worker < verify
    assert "callbacks=PASS" in HOST


def test_static_dll_consumer_proves_pre_entry_export_resolution() -> None:
    assert "__declspec(dllimport)" in STATIC_HOST
    assert "LoadLibrary" not in STATIC_HOST
    assert "GetProcAddress" not in STATIC_HOST
    assert "sample_dll_value()" in STATIC_HOST
    assert "static_host: PASS" in STATIC_HOST


def test_dll_import_restore_path_never_resolves_under_loader_lock() -> None:
    assert "LETHE_FLAG_DLL_PRELOAD_IAT" in LOADER
    assert "snapshot_preloaded_iat(" in LOADER
    assert "restore_preloaded_iat(" in LOADER
    import_step = LOADER[LOADER.index("/* 6. resolve imports */"):LOADER.index(
        "DIAG(6);")]
    assert "!(cpi->flags & LETHE_FLAG_DLL_PRELOAD_IAT)" in import_step


def test_reload_host_exercises_balanced_module_lifecycle() -> None:
    assert "LoadLibraryA" in RELOAD_HOST
    assert "GetProcAddress" in RELOAD_HOST
    assert "FreeLibrary" in RELOAD_HOST
    assert "iteration < 8u" in RELOAD_HOST
    assert "reload_host: PASS cycles=8" in RELOAD_HOST


def test_preexisting_thread_fixture_records_native_tls_semantics() -> None:
    assert PREEXISTING_HOST.index("CreateThread") < PREEXISTING_HOST.index(
        "LoadLibraryA")
    assert "main_value == 105u" in PREEXISTING_HOST
    assert "before.value == 105u" in PREEXISTING_HOST
    assert "after.value == 105u" in PREEXISTING_HOST
    assert "lifecycle == 0u" in PREEXISTING_HOST


def test_noentry_and_attach_rejection_have_balanced_native_hosts() -> None:
    assert "pre/post-workers=PASS" in NOENTRY_HOST
    assert "iteration < 8u" in NOENTRY_HOST
    assert "ERROR_DLL_INIT_FAILED" in REJECT_HOST
    assert "detach=8 clean-retries=PASS" in REJECT_HOST
    assert "WaitForSingleObject(semaphore, 0) != WAIT_TIMEOUT" in REJECT_HOST


def test_tls_free_fixture_requires_disable_thread_library_calls() -> None:
    assert "DisableThreadLibraryCalls(module)" in TLSFREE_DLL
    assert "g_thread_notifications == 0" in TLSFREE_DLL
    assert "CreateThread" in TLSFREE_HOST
    assert "DisableThreadLibraryCalls cycles=4" in TLSFREE_HOST


def test_tls_alignment_is_authenticated_and_emitted_on_outer_directory() -> None:
    analyzer = (ROOT / "packer" / "pe_analyze.py").read_text(encoding="utf-8")
    payload = (ROOT / "packer" / "payload.py").read_text(encoding="utf-8")
    assembler = (ROOT / "packer" / "assemble.py").read_text(encoding="utf-8")
    assert "characteristics: int = 0" in analyzer
    assert "reserved alignment code 15" in analyzer
    assert "characteristics=t.characteristics" in payload
    assert "source_tls_characteristics" in assembler
    setup = _function(LOADER, "static int setup_tls(", "/* ---- diagnostic")
    assert "*(const uint32_t *)(base + tls_rva + 36u) != characteristics" in setup
    assert "__declspec(align(64))" in SAMPLE_EXE
    assert "__declspec(align(64))" in SAMPLE_DLL


def test_stub_tracks_encoded_null_oep_and_attach_rejection_explicitly() -> None:
    stash = _function(STUB_MAIN, "__declspec(noinline) static int stash_oep(",
                      "__declspec(noinline) static uint32_t invoke_exe_oep(")
    assert "if (!raw)" in stash
    assert "s_oep = NULL;" in stash
    assert "s_oep_key = 0;" in stash
    assert "s_has_oep = 0;" in stash
    assert "crypto_csprng" in stash and "!= 0" in stash
    assert "k == 0" in stash
    assert "if (s_has_oep)" in STUB_MAIN
    rejected = STUB_MAIN[STUB_MAIN.index("if (!invoke_dll_oep"):
                         STUB_MAIN.index("if (reason == DLL_PROCESS_DETACH")]
    assert "release_dll_runtime" not in rejected
    assert "Windows immediately calls" in rejected


def test_loader_audit_states_exact_tls_support_boundary() -> None:
    assert "OK WITH SCOPE LIMITS" in AUDIT
    assert "threads created after unpack" in AUDIT
    assert "does **not** retrofit protected TLS" in AUDIT
    assert "TerminateThread" in AUDIT
    assert "TerminateProcess" in AUDIT
    assert "ERROR_BAD_EXE_FORMAT" in AUDIT
    assert "strongest full-header anti-dump erasure" in AUDIT
