from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from packer import assemble
from tools.pe_resource_probe import probe_resource_geometry


def _resource_directory(path) -> tuple[int, int]:
    data = path.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe_offset + 24
    return struct.unpack_from("<II", data, optional + 112 + 2 * 8)


def test_extract_resource_keeps_owner_and_directory_geometry_distinct() -> None:
    parsed = SimpleNamespace(
        rsrc_rva=0x3000,
        rsrc_bytes=bytes(0x200),
        rsrc_directory_rva=0x3040,
        rsrc_directory_size=0x90,
    )
    assert assemble._extract_rsrc(parsed) == (
        0x3000, bytes(0x200), 0x3040, 0x90)


def test_extract_resource_rejects_directory_outside_owner() -> None:
    parsed = SimpleNamespace(
        rsrc_rva=0x3000,
        rsrc_bytes=bytes(0x80),
        rsrc_directory_rva=0x3040,
        rsrc_directory_size=0x80,
    )
    with pytest.raises(assemble.AssembleError, match="outside"):
        assemble._extract_rsrc(parsed)


def test_serializer_emits_exact_resource_directory_pair(tmp_path) -> None:
    output = tmp_path / "resource-geometry.dll"
    sections = [assemble._OutSection(
        ".rsrc", 0x1000, 0x200,
        assemble.IMAGE_SCN_CNT_INITIALIZED_DATA | assemble.IMAGE_SCN_MEM_READ,
        bytes(0x200),
    )]
    assemble._serialize(
        str(output), sections, 0x180000000, 0x1000, 0x200,
        assemble._OrigHeader(), True,
        entry_rva=0,
        base_of_code=0x1000,
        import_dir=(0, 0),
        reloc_dir=(0, 0),
        iat_dir=(0, 0),
        rsrc_dir=(0x1040, 0x90),
        export_dir=(0, 0),
        tls_dir=(0, 0),
    )
    assert _resource_directory(output) == (0x1040, 0x90)
    geometry = probe_resource_geometry(output)
    assert geometry["resource_rva"] == 0x1000
    assert geometry["resource_directory_offset"] == 0x40
    assert geometry["resource_directory_size"] == 0x90
