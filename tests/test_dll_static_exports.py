from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from packer import assemble


def _fixture(*, names_rva: int = 0x206C, target_rva: int = 0x1000):
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
    struct.pack_into("<I", raw, 0x68, target_rva)
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
    code = SimpleNamespace(
        name=".text", rva=0x1000, virtual_size=0x180,
        raw=b"\x90" * 0x200, characteristics=0x60000020,
    )
    bss = SimpleNamespace(
        name=".bss", rva=0x3000, virtual_size=0x100,
        raw=b"", characteristics=0xC0000080,
    )
    parsed = SimpleNamespace(size_of_image=0x5000, sections=[section, code, bss])
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


@pytest.mark.parametrize("target_rva", [0, 0x1000, 0x11FF, 0x2000, 0x22FF, 0x3000, 0x30FF])
def test_export_snapshot_preserves_mapped_code_data_bss_and_ordinal_holes(target_rva):
    parsed, orig, _source = _fixture(target_rva=target_rva)
    snapshot = assemble._dll_export_snapshot(parsed, orig)
    assert struct.unpack_from("<I", snapshot[0x2000], 0x68)[0] == target_rva


@pytest.mark.parametrize("target_rva", [0x40, 0xFFF, 0x1200, 0x2300, 0x3100, 0x4FFF, 0x5000, 0xFFFFFFFF])
def test_export_snapshot_rejects_header_gap_padding_and_out_of_image_targets(target_rva):
    parsed, orig, _source = _fixture(target_rva=target_rva)
    with pytest.raises(assemble.AssembleError, match="direct target.*mapped source section"):
        assemble._dll_export_snapshot(parsed, orig)


def test_export_snapshot_preserves_bounded_forwarder():
    parsed, orig, _source = _fixture(target_rva=0x20A0)
    raw = bytearray(parsed.sections[0].raw)
    raw[0xA0:0xB5] = b"KERNEL32.ExitProcess\0"
    parsed.sections[0].raw = bytes(raw)
    snapshot = assemble._dll_export_snapshot(parsed, orig)
    assert snapshot[0x2000][0xA0:0xB5] == b"KERNEL32.ExitProcess\0"


@pytest.mark.parametrize("marker_rva, marker", [(None, "1"), (0x6000, ""), (0x6000, "0"), (0x6000, "2")])
@pytest.mark.parametrize("export_rva, export_size", [(0x2040, 0x80), (0, 0x80), (0x2040, 0)])
def test_exported_exe_requires_exact_runtime_capability(marker_rva, marker, export_rva, export_size):
    stub = SimpleNamespace(
        find_export_rva=lambda name: marker_rva,
        cstr_at_rva=lambda rva: marker,
    )
    orig = assemble._OrigHeader(export_rva=export_rva, export_size=export_size)
    with pytest.raises(assemble.AssembleError, match="lethe_exe_export_abi=1"):
        assemble._require_exe_export_support(stub, orig, is_dll=False)


def test_exported_exe_accepts_exact_runtime_capability():
    calls = []
    stub = SimpleNamespace(
        find_export_rva=lambda name: calls.append(name) or 0x6000,
        cstr_at_rva=lambda rva: "1" if rva == 0x6000 else "",
    )
    assemble._require_exe_export_support(
        stub, assemble._OrigHeader(export_rva=0x2040, export_size=0x80), is_dll=False)
    assert calls == ["lethe_exe_export_abi"]


@pytest.mark.parametrize("is_dll, export_rva, export_size", [(True, 0x2040, 0x80), (True, 0, 0), (False, 0, 0)])
def test_dll_and_exportless_exe_do_not_require_new_capability(is_dll, export_rva, export_size):
    # No stub methods: these cases must not query the EXE-specific marker.
    assemble._require_exe_export_support(
        SimpleNamespace(), assemble._OrigHeader(export_rva=export_rva, export_size=export_size),
        is_dll=is_dll,
    )


def test_original_header_uses_parsed_export_directory_geometry():
    orig = assemble._read_original_header(None, SimpleNamespace(
        export_directory_rva=0x2040, export_directory_size=0x80))
    assert (orig.export_rva, orig.export_size) == (0x2040, 0x80)
