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


def test_cmake_sources_exist_and_bcrypt_is_a_static_system_import() -> None:
    cmake = _read(STUB_ROOT / "CMakeLists.txt")
    listed_sources = re.findall(r"\bsrc/[A-Za-z0-9_.-]+\.(?:c|asm)\b", cmake)

    assert listed_sources
    assert all((STUB_ROOT / source).is_file() for source in listed_sources)
    assert "src/bcrypt_dyn.c" not in listed_sources
    assert re.search(
        r"target_link_libraries\s*\(\s*lethe_stub_x64\s+PRIVATE"
        r"[^)]*\bkernel32\b[^)]*\bbcrypt\b",
        cmake,
        re.DOTALL,
    )

    compiled = "\n".join(
        _read(STUB_ROOT / source)
        for source in listed_sources
        if source.endswith(".c")
    )
    assert "bcrypt_dyn_init" not in compiled
    assert "p_BCrypt" not in compiled


def test_memguard_relocation_recipe_is_staged_fail_closed() -> None:
    header = _read(SRC / "stub_hooks.h")
    guard = _read(SRC / "memguard.c")
    loader = _read(SRC / "pe_loader.c")

    assert re.search(r"\bint\s+memguard_set_relocs\s*\(", header)
    assert "if (!s_pending_reloc_blob)\n        return 1;" in guard
    assert "memguard_discard_pending_relocs();" in guard
    assert "int reloc_ready = memguard_set_relocs" in loader
    assert "mg_ok = reloc_ready &&" in loader
    assert "memguard_discard_pending_relocs();" in loader


def test_memguard_fallback_relocates_only_newly_decrypted_code() -> None:
    loader = _read(SRC / "pe_loader.c")

    assert "RELOC_FILTER_NONEXEC" in loader
    assert "RELOC_FILTER_EXEC" in loader
    assert re.search(
        r"mg_want\s*\?\s*RELOC_FILTER_NONEXEC\s*:\s*RELOC_FILTER_ALL",
        loader,
    )
    assert re.search(
        r"if\s*\(!mg_ok\).*?decrypt_section\(.*?"
        r"apply_relocs\(.*?RELOC_FILTER_EXEC",
        loader,
        re.DOTALL,
    )


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

    assert re.search(
        r"if\s*\(!pi->is_dll\)\s*\{\s*"
        r"ctx->reenc_thread\s*=\s*CreateThread",
        guard,
        re.DOTALL,
    )
