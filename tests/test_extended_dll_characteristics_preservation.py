"""Regression coverage for CET Shadow Stack (extended DLL characteristics)
preservation across the pack.

The packer previously failed closed on any IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
bit because it emitted no outer debug directory. It now re-declares the bits it
can honour (CET Shadow Stack) by synthesizing a minimal outer debug directory,
still fails closed on bits it cannot back (forward-edge CFI / IBT), and refuses
to declare a bit the resident stub image itself does not carry.
"""
from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from packer import assemble
from packer import pe_analyze


_DEBUG_ENTRY = struct.Struct("<IIHHIIII")  # IMAGE_DEBUG_DIRECTORY, 28 bytes


def _data_dir(path, index: int) -> tuple[int, int]:
    data = path.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe_offset + 24
    return struct.unpack_from("<II", data, optional + 112 + index * 8)


def _rva_to_off(data: bytes, rva: int) -> int:
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    table = pe_offset + 24 + opt_size
    for i in range(num_sections):
        _n, vsize, va, rsize, ptr = struct.unpack_from("<8sIIII", data, table + i * 40)
        if va <= rva < va + max(vsize, rsize):
            return ptr + (rva - va)
    raise AssertionError(f"rva 0x{rva:x} is in no section")


# ---------------------------------------------------------------------------
# policy constants
# ---------------------------------------------------------------------------
def test_supported_mask_is_cet_only() -> None:
    assert pe_analyze.IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT == 0x0001
    assert pe_analyze.IMAGE_DLLCHARACTERISTICS_EX_FORWARD_CFI_COMPAT == 0x0040
    # CET Shadow Stack is honoured; forward-edge CFI (IBT) is not.
    assert pe_analyze.SUPPORTED_EXTENDED_DLL_CHARACTERISTICS == 0x0001
    assert not (pe_analyze.SUPPORTED_EXTENDED_DLL_CHARACTERISTICS
                & pe_analyze.IMAGE_DLLCHARACTERISTICS_EX_FORWARD_CFI_COMPAT)


# ---------------------------------------------------------------------------
# serializer synthesis
# ---------------------------------------------------------------------------
def _serialize_min(output, ext_dll_characteristics: int) -> None:
    sections = [assemble._OutSection(
        ".text", 0x1000, 0x200,
        assemble.IMAGE_SCN_CNT_CODE | assemble.IMAGE_SCN_MEM_READ
        | assemble.IMAGE_SCN_MEM_EXECUTE,
        bytes(0x200),
    )]
    assemble._serialize(
        str(output), sections, 0x180000000, 0x1000, 0x200,
        assemble._OrigHeader(), False,
        entry_rva=0x1000,
        base_of_code=0x1000,
        import_dir=(0, 0),
        reloc_dir=(0, 0),
        iat_dir=(0, 0),
        rsrc_dir=(0, 0),
        export_dir=(0, 0),
        tls_dir=(0, 0),
        ext_dll_characteristics=ext_dll_characteristics,
    )


def test_serializer_emits_cet_debug_directory(tmp_path) -> None:
    output = tmp_path / "cet.exe"
    _serialize_min(output, pe_analyze.IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT)
    data = output.read_bytes()

    dbg_rva, dbg_size = _data_dir(output, 6)  # DIR_DEBUG
    assert dbg_size == _DEBUG_ENTRY.size, "debug directory must hold exactly one entry"

    entry_off = _rva_to_off(data, dbg_rva)
    (chars, _ts, maj, minr, dtype, dsize, addr_rva, ptr) = _DEBUG_ENTRY.unpack_from(
        data, entry_off)
    assert chars == 0 and maj == 0 and minr == 0
    assert dtype == 20, "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS"
    assert dsize == 4

    # AddressOfRawData (RVA) and PointerToRawData (file offset) must both resolve
    # to the same 4-byte characteristics DWORD, and it must declare CET.
    assert _rva_to_off(data, addr_rva) == ptr
    value = struct.unpack_from("<I", data, ptr)[0]
    assert value == pe_analyze.IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT


def test_serializer_omits_debug_directory_when_no_ext(tmp_path) -> None:
    output = tmp_path / "plain.exe"
    _serialize_min(output, 0)
    assert _data_dir(output, 6) == (0, 0)


# ---------------------------------------------------------------------------
# stub-capability gate: never declare a bit the resident stub cannot back
# ---------------------------------------------------------------------------
def _fake_stub(ext_bits: int | None):
    """A stub stand-in exposing dir()/read_at_rva() over a crafted debug dir."""
    if ext_bits is None:
        return SimpleNamespace(dir=lambda i: (0, 0),
                               read_at_rva=lambda r, n: b"")
    entry_rva, dword_rva = 0x2000, 0x2000 + _DEBUG_ENTRY.size
    entry = _DEBUG_ENTRY.pack(0, 0, 0, 0, 20, 4, dword_rva, 0)
    blob = {entry_rva: entry, dword_rva: struct.pack("<I", ext_bits)}

    def read_at_rva(rva, n):
        return blob[rva][:n]

    return SimpleNamespace(
        dir=lambda i: (entry_rva, _DEBUG_ENTRY.size) if i == assemble.DIR_DEBUG else (0, 0),
        read_at_rva=read_at_rva,
    )


def test_stub_capability_reads_declared_cet() -> None:
    stub = _fake_stub(pe_analyze.IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT)
    assert assemble._stub_extended_dll_characteristics(stub) == 0x1


def test_stub_capability_zero_when_no_debug_directory() -> None:
    stub = _fake_stub(None)
    assert assemble._stub_extended_dll_characteristics(stub) == 0
