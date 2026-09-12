"""Hostile PE32+ load-config and Guard target inventory tests."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import struct
import subprocess

import pytest

from packer import pe_analyze


IMAGE_BASE = 0x140000000
IMAGE_SIZE = 0x5000
LOAD_CONFIG_RVA = 0x2000
EXEC = 0x60000020


def _fixture() -> tuple[bytes, list[pe_analyze.ParsedSection]]:
    raw = bytearray(b"\x90" * 0x3000)
    blob = bytearray(328)
    struct.pack_into("<IHH", blob, 0, len(blob), 0, 0)
    struct.pack_into("<HH", blob, 8, 3, 7)
    struct.pack_into("<Q", blob, 88, IMAGE_BASE + 0x2400)
    struct.pack_into("<Q", blob, 112, IMAGE_BASE + 0x2410)
    struct.pack_into("<Q", blob, 120, IMAGE_BASE + 0x2418)

    guard_flags = (
        0x10000000
        | 0x00000100
        | 0x00000400
        | 0x01000000
        | 0x02000000
    )
    struct.pack_into("<I", blob, 144, guard_flags)
    cf_table = b"".join((struct.pack("<IB", 0x1000, 0), struct.pack("<IB", 0x1010, 2)))
    raw[0x1200:0x1200 + len(cf_table)] = cf_table
    struct.pack_into("<QQ", blob, 128, IMAGE_BASE + 0x2200, 2)

    raw[0x1300:0x130A] = b"".join((
        struct.pack("<IB", 0x2500, 0),
        struct.pack("<IB", 0x2508, 0),
    ))
    struct.pack_into("<QQ", blob, 160, IMAGE_BASE + 0x2300, 2)

    raw[0x1320:0x132A] = b"".join((
        struct.pack("<IB", 0x1020, 0),
        struct.pack("<IB", 0x1030, 0),
    ))
    struct.pack_into("<QQ", blob, 176, IMAGE_BASE + 0x2320, 2)
    struct.pack_into("<I", blob, 144, guard_flags | 0x00010000)

    raw[0x1340:0x134A] = b"".join((
        struct.pack("<IB", 0x1033, 0),
        struct.pack("<IB", 0x1045, 0),
    ))
    struct.pack_into("<QQ", blob, 264, IMAGE_BASE + 0x2340, 2)
    flags, = struct.unpack_from("<I", blob, 144)
    struct.pack_into("<I", blob, 144, flags | 0x00400000)
    struct.pack_into("<Q", blob, 304, IMAGE_BASE + 0x2420)
    struct.pack_into("<Q", blob, 312, IMAGE_BASE + 0x2428)

    raw[LOAD_CONFIG_RVA - 0x1000:LOAD_CONFIG_RVA - 0x1000 + len(blob)] = blob
    return bytes(blob), [
        pe_analyze.ParsedSection(
            ".all", 0x1000, len(raw), bytes(raw), EXEC
        )
    ]


def _parse(blob: bytes, sections: list[pe_analyze.ParsedSection]):
    return pe_analyze._parse_load_config(
        blob,
        LOAD_CONFIG_RVA,
        image_base=IMAGE_BASE,
        image_size=IMAGE_SIZE,
        sections=sections,
    )


def _replace_blob_in_sections(
    blob: bytes, sections: list[pe_analyze.ParsedSection]
) -> list[pe_analyze.ParsedSection]:
    section = sections[0]
    raw = bytearray(section.raw)
    offset = LOAD_CONFIG_RVA - section.rva
    raw[offset:offset + len(blob)] = blob
    return [pe_analyze.ParsedSection(
        section.name,
        section.rva,
        section.virtual_size,
        bytes(raw),
        section.characteristics,
    )]


def test_strict_load_config_inventory_converts_vas_and_preserves_metadata() -> None:
    blob, sections = _fixture()
    parsed = _parse(blob, sections)

    assert parsed is not None
    assert (parsed.declared_size, parsed.major_version, parsed.minor_version) == (
        328, 3, 7)
    assert parsed.security_cookie_rva == 0x2400
    assert parsed.guard_cf_check_function_pointer_rva == 0x2410
    assert parsed.guard_cf_dispatch_function_pointer_rva == 0x2418
    assert parsed.guard_cf_function_table_rva == 0x2200
    assert parsed.guard_cf_targets == (
        pe_analyze.ParsedGuardTarget(0x1000, b"\0"),
        pe_analyze.ParsedGuardTarget(0x1010, b"\x02"),
    )
    assert tuple(target.rva for target in parsed.guard_address_taken_iat_entries) == (
        0x2500, 0x2508)
    assert tuple(target.rva for target in parsed.guard_long_jump_targets) == (
        0x1020, 0x1030)
    assert tuple(target.rva for target in parsed.guard_eh_continuation_targets) == (
        0x1033, 0x1045)
    assert parsed.guard_flags & 0x01000000
    assert parsed.guard_flags & 0x02000000
    assert parsed.cast_guard_os_determined_failure_mode_rva == 0x2420
    assert parsed.guard_memcpy_function_pointer_rva == 0x2428
    assert parsed.has_guard_cf is True
    assert parsed.unsupported_features == ()
    assert parsed.raw == blob


@pytest.mark.parametrize(
    ("size", "expected"),
    [
        (108, r"supported PE32\+ bounds"),
        (116, "truncates GuardCFCheckFunctionPointer"),
        (324, "truncates UmaFunctionPointers"),
        (332, r"supported PE32\+ bounds"),
    ],
)
def test_load_config_size_and_field_version_bounds_fail_closed(size, expected) -> None:
    original, sections = _fixture()
    blob = bytearray(original[:size].ljust(size, b"\0"))
    struct.pack_into("<I", blob, 0, size)
    sections = _replace_blob_in_sections(bytes(blob), sections)
    with pytest.raises(ValueError, match=expected):
        _parse(bytes(blob), sections)


def test_load_config_directory_and_declared_sizes_must_match() -> None:
    blob, sections = _fixture()
    malformed = bytearray(blob)
    struct.pack_into("<I", malformed, 0, len(blob) - 8)
    with pytest.raises(ValueError, match="size disagree"):
        _parse(bytes(malformed), sections)


def test_load_config_directory_rva_must_be_naturally_aligned() -> None:
    blob, sections = _fixture()
    with pytest.raises(ValueError, match="RVA must be 8-byte aligned"):
        pe_analyze._parse_load_config(
            blob,
            LOAD_CONFIG_RVA + 4,
            image_base=IMAGE_BASE,
            image_size=IMAGE_SIZE,
            sections=sections,
        )


@pytest.mark.parametrize(
    ("flag", "size", "name", "minimum"),
    [
        (0x01000000, 308, "IMAGE_GUARD_CASTGUARD_PRESENT", "0x138"),
        (0x02000000, 316, "IMAGE_GUARD_MEMCPY_PRESENT", "0x140"),
    ],
)
def test_current_sdk_guard_flag_requires_complete_loader_slot(
    flag: int,
    size: int,
    name: str,
    minimum: str,
) -> None:
    original, sections = _fixture()
    blob = bytearray(original[:size])
    struct.pack_into("<I", blob, 0, size)
    existing, = struct.unpack_from("<I", blob, 144)
    existing &= ~(0x01000000 | 0x02000000)
    struct.pack_into("<I", blob, 144, existing | flag)
    sections = _replace_blob_in_sections(bytes(blob), sections)

    with pytest.raises(ValueError, match=rf"{name} requires.*{minimum}"):
        _parse(bytes(blob), sections)


def test_current_sdk_guard_flags_allow_loader_populated_zero_slots() -> None:
    original, sections = _fixture()
    blob = bytearray(original[:320])
    struct.pack_into("<I", blob, 0, len(blob))
    struct.pack_into("<QQ", blob, 304, 0, 0)
    sections = _replace_blob_in_sections(bytes(blob), sections)

    parsed = _parse(bytes(blob), sections)

    assert parsed is not None
    assert parsed.guard_flags & 0x01000000
    assert parsed.guard_flags & 0x02000000
    assert parsed.cast_guard_os_determined_failure_mode_rva == 0
    assert parsed.guard_memcpy_function_pointer_rva == 0


def test_reserved_guard_flag_and_language_handler_gfid_remain_fail_closed() -> None:
    blob, sections = _fixture()
    reserved = bytearray(blob)
    flags, = struct.unpack_from("<I", reserved, 144)
    struct.pack_into("<I", reserved, 144, flags | 0x00200000)
    with pytest.raises(ValueError, match="unsupported load-config GuardFlags"):
        _parse(bytes(reserved), sections)

    section = sections[0]
    raw = bytearray(section.raw)
    raw[0x1204] = 0x04
    language_handler_sections = [pe_analyze.ParsedSection(
        section.name,
        section.rva,
        section.virtual_size,
        bytes(raw),
        section.characteristics,
    )]
    with pytest.raises(ValueError, match="target metadata flags 0x04"):
        _parse(blob, language_handler_sections)


def test_guard_table_pointer_count_range_and_sorting_are_strict() -> None:
    blob, sections = _fixture()
    malformed = bytearray(blob)
    struct.pack_into("<Q", malformed, 136, 0)
    with pytest.raises(ValueError, match="table VA and count presence disagree"):
        _parse(bytes(malformed), sections)

    malformed = bytearray(blob)
    struct.pack_into("<Q", malformed, 128, IMAGE_BASE + IMAGE_SIZE + 0x100)
    with pytest.raises(ValueError, match="outside the image"):
        _parse(bytes(malformed), sections)

    section = sections[0]
    raw = bytearray(section.raw)
    raw[0x1200:0x120A] = struct.pack("<IBIB", 0x1010, 0, 0x1000, 0)
    bad_sections = [pe_analyze.ParsedSection(
        section.name, section.rva, section.virtual_size, bytes(raw), EXEC)]
    with pytest.raises(ValueError, match="strictly sorted"):
        _parse(blob, bad_sections)


def test_guard_targets_reject_misalignment_nonimage_and_nonexec() -> None:
    blob, sections = _fixture()
    section = sections[0]
    raw = bytearray(section.raw)
    raw[0x1200:0x1205] = struct.pack("<IB", 0x1001, 0)
    bad_sections = [pe_analyze.ParsedSection(
        section.name, section.rva, section.virtual_size, bytes(raw), EXEC)]
    with pytest.raises(ValueError, match="16-byte aligned"):
        _parse(blob, bad_sections)

    nonexec_sections = [pe_analyze.ParsedSection(
        section.name, section.rva, section.virtual_size, section.raw, 0x40000040)]
    with pytest.raises(ValueError, match="not in an executable section"):
        _parse(blob, nonexec_sections)

    malformed = bytearray(blob)
    section_raw = bytearray(section.raw)
    section_raw[0x1305:0x1309] = struct.pack("<I", IMAGE_SIZE)
    bad_sections = [pe_analyze.ParsedSection(
        section.name, section.rva, section.virtual_size, bytes(section_raw), EXEC)]
    with pytest.raises(ValueError, match="IAT RVA.*in-image"):
        _parse(bytes(malformed), bad_sections)


def test_eh_continuation_targets_are_exact_but_need_not_be_code_aligned() -> None:
    blob, sections = _fixture()
    parsed = _parse(blob, sections)
    assert tuple(target.rva for target in parsed.guard_eh_continuation_targets) == (
        0x1033, 0x1045)


def test_dynamic_reloc_and_chpe_are_unsupported_while_xfg_slots_are_inventory() -> None:
    blob, sections = _fixture()
    unsupported = bytearray(blob)
    struct.pack_into("<Q", unsupported, 192, IMAGE_BASE + 0x2600)
    struct.pack_into("<Q", unsupported, 200, IMAGE_BASE + 0x2700)
    struct.pack_into("<Q", unsupported, 280, IMAGE_BASE + 0x2420)
    parsed = _parse(bytes(unsupported), sections)

    assert parsed.dynamic_value_relocations_present is True
    assert parsed.chpe_metadata_present is True
    assert parsed.xfg_present is True
    assert {"dynamic_value_relocations", "chpe_metadata"} <= set(
        parsed.unsupported_features)
    assert "xfg" not in parsed.unsupported_features
    assert parsed.guard_xfg_check_function_pointer_rva == 0x2420

    xfg_enabled = bytearray(blob)
    flags, = struct.unpack_from("<I", xfg_enabled, 144)
    struct.pack_into("<I", xfg_enabled, 144, flags | 0x00800000)
    parsed_global_xfg = _parse(bytes(xfg_enabled), sections)
    assert parsed_global_xfg.xfg_present is True
    assert parsed_global_xfg.unsupported_features == ()


@pytest.fixture(scope="module")
def fresh_msvc_guard_cf_fixture(tmp_path_factory) -> Path:
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if os.name != "nt" or powershell is None:
        pytest.skip("Windows PowerShell and MSVC are required")
    output = tmp_path_factory.mktemp("guard-cf-sample")
    script = Path(__file__).parent / "build_samples.ps1"
    built = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-OutDir",
            str(output),
            "-Config",
            "Release",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if built.returncode == 3:
        pytest.skip("MSVC x64 toolchain is unavailable")
    assert built.returncode == 0, built.stdout + built.stderr
    fixture = output / "sample_exe.exe"
    assert fixture.is_file()
    return fixture


def test_fresh_msvc_guard_cf_fixture_inventory_when_available(
    fresh_msvc_guard_cf_fixture: Path,
) -> None:
    fixture = fresh_msvc_guard_cf_fixture
    parsed = pe_analyze.analyze_pe(str(fixture))
    assert parsed.load_config is not None
    assert parsed.load_config.has_guard_cf is True
    assert parsed.load_config.guard_cf_targets
    assert all(target.rva % 16 == 0 for target in parsed.load_config.guard_cf_targets)
    assert parsed.dll_characteristics & 0x4000
