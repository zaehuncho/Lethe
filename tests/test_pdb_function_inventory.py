"""Exact RSDS/DIA function-inventory binding contracts."""

from __future__ import annotations

from hashlib import sha256
from types import SimpleNamespace
import struct
from uuid import UUID

import pytest

from lifter import pdb_function_inventory as inv


GUID = UUID("c375d47d-1e81-4103-b5e2-79793b45e776")
HASH = sha256(b"fixture").hexdigest()


def fixture_image() -> bytearray:
    raw = bytearray(0x600)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x80)
    raw[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", raw, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0)
    struct.pack_into("<H", raw, 0x98, 0x20B)
    struct.pack_into("<I", raw, 0x98 + 0x6C, 16)
    struct.pack_into("<II", raw, 0x98 + 0x70 + 6 * 8, 0x2000, 28)
    raw[0x188:0x18D] = b".text"
    struct.pack_into("<IIII", raw, 0x188 + 8, 0x200, 0x1000, 0x200, 0x200)
    raw[0x188 + 36:0x188 + 40] = (0x60000020).to_bytes(4, "little")
    raw[0x1B0:0x1B6] = b".rdata"
    struct.pack_into("<IIII", raw, 0x1B0 + 8, 0x200, 0x2000, 0x200, 0x400)
    raw[0x1B0 + 36:0x1B0 + 40] = (0x40000040).to_bytes(4, "little")
    raw[0x200:0x400] = b"\x90" * 0x200
    payload = b"RSDS" + GUID.bytes_le + struct.pack("<I", 7) + b"fixture.pdb\0"
    struct.pack_into("<IIHHIIII", raw, 0x400, 0, 0, 0, 0, 2, len(payload), 0x2020, 0x420)
    raw[0x420:0x420 + len(payload)] = payload
    return raw


def fixture_parsed():
    return SimpleNamespace(
        size_of_image=0x3000,
        sections=(
            SimpleNamespace(name=".text", rva=0x1000, virtual_size=0x200,
                            raw=b"\x90" * 0x200, characteristics=0x60000020),
            SimpleNamespace(name=".rdata", rva=0x2000, virtual_size=0x200,
                            raw=b"\0" * 0x200, characteristics=0x40000040),
        ),
        runtime_functions=(SimpleNamespace(begin_rva=0x1000, end_rva=0x1010),),
    )


def helper_output(*rows: tuple[int, int], age: int = 7, guid: UUID = GUID) -> str:
    body = "".join(f"FUNCTION rva={rva:08X} size={size}\n" for rva, size in rows)
    return (f"PDB_IDENTITY guid={{{str(guid).upper()}}} age={age} machine=8664\n"
            f"{body}FUNCTION_SUMMARY emitted={len(rows)}\n")


def bind(image=None, parsed=None, output=None):
    return inv.bind_inventory(
        fixture_parsed() if parsed is None else parsed,
        bytes(fixture_image() if image is None else image),
        HASH, HASH,
        helper_output((0x1000, 0x10), (0x1020, 2), (0x1020, 2))
        if output is None else output,
    )


def test_exact_identity_and_duplicate_alias_yield_one_supplemental_range() -> None:
    result = bind()
    assert result.identity == inv.CodeViewIdentity(GUID, 7)
    assert result.symbol_count == 3
    assert result.distinct_ranges == ((0x1000, 0x1010), (0x1020, 0x1022))
    assert result.supplemental_ranges == ((0x1020, 0x1022),)
    assert result.image_sha256 == sha256(fixture_image()).hexdigest()


@pytest.mark.parametrize("mutation,match", [
    (lambda b: b.__setitem__(slice(0x420, 0x424), b"NB10"), "RSDS"),
    (lambda b: struct.pack_into("<I", b, 0x420 + 20, 0), "age"),
    (lambda b: struct.pack_into("<I", b, 0x400 + 24, 0x421), "disagree"),
    (lambda b: struct.pack_into("<I", b, 0x98 + 0x70 + 6 * 8 + 4, 29), "debug directory"),
])
def test_malformed_pe_debug_identity_fails_closed(mutation, match) -> None:
    image = fixture_image()
    mutation(image)
    with pytest.raises(inv.PdbInventoryError, match=match):
        bind(image=image)


def test_stale_pdb_identity_fails_closed() -> None:
    with pytest.raises(inv.PdbInventoryError, match="GUID/age"):
        bind(output=helper_output((0x1000, 0x10), age=8))
    with pytest.raises(inv.PdbInventoryError, match="GUID/age"):
        bind(output=helper_output((0x1000, 0x10), guid=UUID(int=1)))


@pytest.mark.parametrize("output,match", [
    ("PDB_IDENTITY guid={X} age=7 machine=8664\nFUNCTION_SUMMARY emitted=0\n", "identity"),
    (helper_output((0x1000, 0x10)).replace("emitted=1", "emitted=2"), "count"),
    (helper_output((0x1000, 0x10)).replace("size=16", "size=16 name=forged"), "record"),
    (helper_output((0x1000, 0)), "extent"),
    (helper_output((0x1000, 0x10)).replace("machine=8664", "machine=014C"), "identity"),
])
def test_helper_protocol_is_strict(output, match) -> None:
    with pytest.raises(inv.PdbInventoryError, match=match):
        bind(output=output)


def test_overlapping_or_partial_pdata_extents_fail_closed() -> None:
    with pytest.raises(inv.PdbInventoryError, match="overlap"):
        bind(output=helper_output((0x1020, 8), (0x1024, 8)))
    with pytest.raises(inv.PdbInventoryError, match="partially overlaps PDATA"):
        bind(output=helper_output((0x1001, 0x10)))


def test_nonexecutable_and_nonfilebacked_function_rejected() -> None:
    with pytest.raises(ValueError, match="non-executable"):
        bind(output=helper_output((0x2000, 2)))
    parsed = fixture_parsed()
    parsed.sections[0].raw = b"\x90" * 0x20
    with pytest.raises(ValueError, match="non-file-backed"):
        bind(parsed=parsed, output=helper_output((0x1020, 2)))


def test_distinct_aliases_of_contiguous_pdata_group_are_not_supplemental() -> None:
    parsed = fixture_parsed()
    parsed.runtime_functions = (
        SimpleNamespace(begin_rva=0x1000, end_rva=0x1008),
        SimpleNamespace(begin_rva=0x1008, end_rva=0x1010),
    )
    assert bind(parsed=parsed).supplemental_ranges == ((0x1020, 0x1022),)
