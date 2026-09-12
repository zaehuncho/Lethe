from __future__ import annotations

import dataclasses
import struct
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("lief")
from packer import pe_analyze  # noqa: E402


STUB = ROOT / "stub" / "prebuilt" / "lethe_stub_x64.dll"


def test_extended_dll_characteristics_inventory_finds_cet_and_unknown_bits() -> None:
    section_rva = 0x1000
    debug_size = pe_analyze._IMAGE_DEBUG_DIRECTORY.size
    raw = bytearray(debug_size + 4)
    struct.pack_into(
        "<IIHHIIII", raw, 0,
        0, 0, 0, 0, 20, 4, section_rva + debug_size, 0,
    )

    for bits in (0x0001, 0x0040, 0x80000000):
        candidate = bytearray(raw)
        struct.pack_into("<I", candidate, debug_size, bits)
        section = pe_analyze.ParsedSection(
            ".rdata", section_rva, len(candidate), bytes(candidate), 0x40000040)
        assert pe_analyze._parse_extended_dll_characteristics(
            bytes(candidate[:debug_size]), image_size=0x3000,
            sections=[section]) == bits


def test_extended_dll_characteristics_directory_is_strict() -> None:
    section = pe_analyze.ParsedSection(
        ".rdata", 0x1000, 64, bytes(64), 0x40000040)
    with pytest.raises(ValueError, match="partial entry"):
        pe_analyze._parse_extended_dll_characteristics(
            bytes(27), image_size=0x3000, sections=[section])

    duplicate = b"".join(struct.pack(
        "<IIHHIIII", 0, 0, 0, 0, 20, 4, 0x1038, 0)
        for _ in range(2))
    with pytest.raises(ValueError, match="duplicate"):
        pe_analyze._parse_extended_dll_characteristics(
            duplicate, image_size=0x3000, sections=[section])


def _section(name: str, rva: int, raw: bytes):
    return pe_analyze.ParsedSection(name, rva, len(raw), raw, 0)


def _reloc_block(page_rva: int, *entries: int) -> bytes:
    body = b"".join(struct.pack("<H", entry) for entry in entries)
    while (8 + len(body)) % 4:
        body += b"\0\0"
    return struct.pack("<II", page_rva, 8 + len(body)) + body


def _manual_dir64_targets(blob: bytes) -> tuple[int, ...]:
    result = []
    pos = 0
    while pos < len(blob):
        page_rva, block_size = struct.unpack_from("<II", blob, pos)
        for entry_pos in range(pos + 8, pos + block_size, 2):
            entry, = struct.unpack_from("<H", blob, entry_pos)
            if entry >> 12 == 10:
                result.append(page_rva + (entry & 0xFFF))
        pos += block_size
    return tuple(result)


def test_relocation_inventory_exactly_matches_validated_blob_order() -> None:
    blob = (_reloc_block(0x2000, 0xA018, 0, 0xA008) +
            _reloc_block(0x1000, 0xA120, 0))
    inventory = pe_analyze._validate_relocations(blob, 0x4000)

    assert inventory == (
        pe_analyze.ParsedDir64Relocation(0x2018),
        pe_analyze.ParsedDir64Relocation(0x2008),
        pe_analyze.ParsedDir64Relocation(0x1120),
    )
    assert tuple(item.target_rva for item in inventory) == (
        0x2018, 0x2008, 0x1120)
    assert tuple(item.target_rva for item in inventory) == (
        _manual_dir64_targets(blob))


def test_runtime_inventory_exactly_matches_pdata_and_unwind_flags() -> None:
    text = _section(".text", 0x1000, b"\x90" * 0x400)
    handler_unwind = bytes((1 | (1 << 3), 0, 0, 0)) + struct.pack(
        "<I", 0x1000)
    plain_unwind = bytes((1, 0, 0, 0))
    xdata = _section(
        ".xdata", 0x2000,
        handler_unwind + b"\0" * 8 + plain_unwind,
    )
    pdata = (struct.pack("<III", 0x1000, 0x1080, 0x2000) +
             struct.pack("<III", 0x1080, 0x1100, 0x2010))

    inventory = pe_analyze._parse_pdata(
        pdata, 0x2800, 0x4000, [text, xdata])

    assert inventory == (
        pe_analyze.ParsedRuntimeFunction(0x1000, 0x1080, 0x2000, 1),
        pe_analyze.ParsedRuntimeFunction(0x1080, 0x1100, 0x2010, 0),
    )
    assert tuple(
        (item.begin_rva, item.end_rva, item.unwind_info_rva)
        for item in inventory
    ) == tuple(struct.iter_unpack("<III", pdata))


def test_inventory_empty_cases_and_parsed_pe_defaults_are_immutable() -> None:
    assert pe_analyze._validate_relocations(b"", 0x1000) == ()
    assert pe_analyze._parse_pdata(b"", 0, 0x1000) == ()

    parsed = pe_analyze.ParsedPE(
        "empty.exe", False, 0x140000000, 0x1000, 0, [], [], b"", None,
        0, 0, 0, 0, 0, b"",
    )
    assert parsed.dir64_relocations == ()
    assert parsed.runtime_functions == ()

    relocation = pe_analyze.ParsedDir64Relocation(0x100)
    runtime = pe_analyze.ParsedRuntimeFunction(0x100, 0x110, 0x200, 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        relocation.target_rva = 0x200  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        runtime.begin_rva = 0x200  # type: ignore[misc]


@pytest.mark.skipif(not STUB.is_file(), reason="prebuilt stub absent")
def test_real_fixture_inventories_match_preserved_blobs() -> None:
    parsed = pe_analyze.analyze_pe(str(STUB))

    assert tuple(item.target_rva for item in parsed.dir64_relocations) == (
        _manual_dir64_targets(parsed.reloc_blob))

    pdata = pe_analyze._slice_at_rva(
        parsed.sections,
        parsed.pdata_rva,
        parsed.pdata_count * 12,
        what="test exception directory",
    )
    triples = tuple(struct.iter_unpack("<III", pdata))
    assert tuple(
        (item.begin_rva, item.end_rva, item.unwind_info_rva)
        for item in parsed.runtime_functions
    ) == triples
    assert tuple(item.unwind_flags for item in parsed.runtime_functions) == tuple(
        pe_analyze._slice_at_rva(
            parsed.sections, unwind_rva, 1, what="test UNWIND_INFO header"
        )[0] >> 3
        for _, _, unwind_rva in triples
    )
