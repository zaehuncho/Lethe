from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from packer import assemble


def _fixture(*, names_rva: int = 0x206C):
    raw = bytearray(0x200)
    export_rva = 0x2040
    export_size = 0x80
    offset = export_rva - 0x2000
    struct.pack_into(
        "<IIHHIIIIIII",
        raw,
        offset,
        0,
        0,
        0,
        0,
        0x2080,
        1,
        1,
        1,
        0x2068,
        names_rva,
        0x2070,
    )
    struct.pack_into("<I", raw, 0x68, 0x1000)
    if names_rva == 0x206C:
        struct.pack_into("<I", raw, 0x6C, 0x2090)
    struct.pack_into("<H", raw, 0x70, 0)
    raw[0x80:0x8B] = b"sample.dll\0"
    raw[0x90:0x9D] = b"sample_value\0"
    section = SimpleNamespace(
        name=".rdata",
        rva=0x2000,
        virtual_size=0x300,
        raw=bytes(raw),
        characteristics=0x40000040,
    )
    parsed = SimpleNamespace(size_of_image=0x5000, sections=[section])
    orig = assemble._OrigHeader(export_rva=export_rva, export_size=export_size)
    return parsed, orig, bytes(raw)


def test_dll_export_snapshot_preserves_only_declared_export_span() -> None:
    parsed, orig, source = _fixture()

    snapshot = assemble._dll_export_snapshot(parsed, orig)

    assert set(snapshot) == {0x2000}
    assert snapshot[0x2000][0x40:0xC0] == source[0x40:0xC0]
    assert snapshot[0x2000][:0x40] == b"\0" * 0x40
    assert snapshot[0x2000][0xC0:] == b"\0" * 0x140


def test_dll_export_snapshot_rejects_reference_outside_declared_span() -> None:
    parsed, orig, _source = _fixture(names_rva=0x2100)

    with pytest.raises(
        assemble.AssembleError,
        match="name-pointer table escapes",
    ):
        assemble._dll_export_snapshot(parsed, orig)


def test_dll_without_exports_needs_no_snapshot() -> None:
    parsed = SimpleNamespace(size_of_image=0x3000, sections=[])
    assert assemble._dll_export_snapshot(
        parsed, assemble._OrigHeader(export_rva=0, export_size=0)
    ) == {}
