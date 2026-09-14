from __future__ import annotations

import re
from pathlib import Path


MEMGUARD = (
    Path(__file__).resolve().parents[1] / "stub" / "src" / "memguard.c"
)


def _source() -> str:
    return MEMGUARD.read_text(encoding="utf-8")


def _function_body(source: str, name: str) -> str:
    start = source.index(name)
    brace = source.index("{", start)
    depth = 0
    for offset in range(brace, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : offset]
    raise AssertionError(f"unterminated function {name}")


def test_write_access_violation_is_forwarded_before_resident_fast_path() -> None:
    body = _function_body(_source(), "memguard_veh(")

    classify = body.index("access = er->ExceptionInformation[0]")
    reject = body.index("access != 0u && access != 8u")
    resident = body.index("state == PG_ACTIVE")

    assert classify < reject < resident
    assert body[reject:resident].count("EXCEPTION_CONTINUE_SEARCH") == 1


def test_fault_handler_accepts_only_read_and_execute_access_kinds() -> None:
    body = _function_body(_source(), "memguard_veh(")

    assert "access != 0u && access != 8u" in body
    assert "access != 1u" not in body


def test_every_memguard_virtualprotect_result_is_inspected() -> None:
    source = _source()

    # A bare call silently discards the only indication that a protection
    # transition failed. Calls used as an if condition are explicitly checked.
    assert not re.search(r"(?m)^\s*VirtualProtect\s*\(", source)
    assert source.count("VirtualProtect(") == source.count("if (!VirtualProtect(") + source.count(
        "if (VirtualProtect("
    )


def test_failed_page_and_section_states_are_not_retried_as_valid_ciphertext() -> None:
    source = _source()
    activate = _function_body(source, "mg_activate_page(")
    veh = _function_body(source, "memguard_veh(")

    assert "g->state != PG_XOR_ENC" in activate
    assert "S->state == SEC_ENCRYPTED" in veh
    assert "S->state == SEC_SPLIT" in veh
    assert "result = EXCEPTION_CONTINUE_SEARCH" in veh


def test_managed_transition_failure_terminates_only_after_unlock() -> None:
    veh = _function_body(_source(), "memguard_veh(")

    unlock = veh.index("LeaveCriticalSection(&g_lock);")
    terminate = veh.index("TerminateProcess(GetCurrentProcess(), ERROR_INVALID_DATA)")
    fast_fail = veh.index("__fastfail(FAST_FAIL_FATAL_APP_EXIT)")
    assert "managed_failure = 1;" in veh
    assert unlock < terminate < fast_fail


def test_native_page_activation_is_monotonic_and_race_free() -> None:
    source = _source()

    assert "race-free monotonic per-page activation" in source
    assert "native executable bytes are never rewritten" in source
    assert "static int mg_reencrypt_page(" not in source
    assert "static int mg_evict_lru(" not in source
    assert "memguard_reencrypt_thread" not in source
    assert "CreateThread(" not in source


def test_memguard_page_counts_and_layout_use_checked_arithmetic() -> None:
    source = _source()
    install = _function_body(source, "int memguard_install(")

    assert "virtual_size + MG_PAGE_SIZE - 1u" not in install
    assert "page_count > UINT32_MAX - pages" in install
    assert "mg_size_add(" in install
    assert "mg_size_mul(" in install
    assert "mg_size_align(" in install
    assert "mg_align8(" not in source
    assert "mg_align_page(" not in source


def test_memguard_relocation_range_math_is_64_bit_checked() -> None:
    source = _source()
    apply_relocs = _function_body(source, "mg_apply_relocs_in_range(")

    assert "uint64_t sec_end_rva" in apply_relocs
    assert "uint64_t rva" in apply_relocs
    assert "rva + 8u <= sec_end_rva" in apply_relocs


def test_memguard_key_region_lock_failure_is_fatal() -> None:
    source = _source()
    install = _function_body(source, "int memguard_install(")

    assert "if (!VirtualLock(data, data_bytes))" in install
    lock_failure = install[install.index("if (!VirtualLock(data, data_bytes))"):
                           install.index("ctx = (MemGuardCtx *)data")]
    assert "VirtualFree(region, 0, MEM_RELEASE);" in lock_failure
    assert "return 1;" in lock_failure


def test_memguard_decryption_scratch_lock_failure_is_fatal() -> None:
    source = _source()
    decrypt = _function_body(source, "mg_decrypt_section(")

    assert "if (!VirtualLock(scratch, S->stored_size))" in decrypt
    lock_failure = decrypt[
        decrypt.index("if (!VirtualLock(scratch, S->stored_size))"):
        decrypt.index("/* Prefer the scattered key")
    ]
    assert "VirtualFree(scratch, 0, MEM_RELEASE);" in lock_failure
    assert "return -1;" in lock_failure
    assert decrypt.count("VirtualUnlock(scratch, S->stored_size);") >= 5
