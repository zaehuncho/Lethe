from __future__ import annotations

import struct

import pytest

from packer import assemble, pe_analyze


def _section(name: str, rva: int, size: int) -> pe_analyze.ParsedSection:
    return pe_analyze.ParsedSection(name, rva, size, bytes(size), 0x40000040)


def _descriptor(attributes: int = 1, timestamp: int = 0) -> bytes:
    return struct.pack(
        "<8I", attributes, 0x2100, 0x3000, 0x4000, 0x2200,
        0, 0x4010, timestamp,
    )


def _sections() -> list[pe_analyze.ParsedSection]:
    rdata = bytearray(0x300)
    name = b"fixture_dependency.dll\0"
    rdata[0x100:0x100 + len(name)] = name
    return [
        pe_analyze.ParsedSection(
            ".rdata", 0x2000, len(rdata), bytes(rdata), 0x40000040),
        _section(".data", 0x3000, 0x100),
        _section(".didat", 0x4000, 0x100),
    ]


def test_rva_delay_descriptor_shape_is_accepted() -> None:
    pe_analyze._validate_delay_import_directory(
        _descriptor() + bytes(32), image_size=0x5000, sections=_sections())


@pytest.mark.parametrize(
    ("blob", "message"),
    [
        (_descriptor(attributes=0) + bytes(32), "RVA-based"),
        (_descriptor(), "missing null terminator"),
        (_descriptor(timestamp=1) + bytes(32), "timestamp without bound IAT"),
        (_descriptor() + bytes(31), "partial descriptor"),
    ],
)
def test_unsupported_delay_descriptor_shapes_fail_closed(
        blob: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        pe_analyze._validate_delay_import_directory(
            blob, image_size=0x5000, sections=_sections())


def test_serializer_keeps_delay_directory_for_unload_helper(tmp_path) -> None:
    output = tmp_path / "delay.dll"
    assemble._serialize(
        str(output),
        [assemble._OutSection(
            ".rdata", 0x1000, 0x200,
            assemble.IMAGE_SCN_CNT_INITIALIZED_DATA | assemble.IMAGE_SCN_MEM_READ,
            bytes(0x200),
        )],
        0x180000000, 0x1000, 0x200, assemble._OrigHeader(), True,
        entry_rva=0,
        base_of_code=0x1000,
        import_dir=(0, 0),
        reloc_dir=(0, 0),
        iat_dir=(0, 0),
        rsrc_dir=(0, 0),
        export_dir=(0, 0),
        tls_dir=(0, 0),
        delay_import_dir=(0x1080, 0x40),
    )
    data = output.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe_offset + 24
    assert struct.unpack_from(
        "<II", data, optional + 112 + 13 * 8) == (0x1080, 0x40)
