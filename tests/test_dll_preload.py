from __future__ import annotations

import struct

import pytest

from packer import container
from packer.dll_preload import DllPreloadError, build_dll_preload_image


def test_preload_image_combines_stub_and_source_descriptors() -> None:
    stub = struct.pack("<IIIII", 0x8100, 0, 0, 0x8200, 0x8300)
    imports = [
        container.ImportDll(
            "KERNEL32.dll",
            [
                container.ImportFunc(0x2000, name="Sleep"),
                container.ImportFunc(0x2008, by_ordinal=True, ordinal=7),
            ],
        )
    ]

    image = build_dll_preload_image(
        [stub], imports, section_rva=0x9000, image_size=0xC000)

    assert image.descriptor_size == 60
    assert image.data[:20] == stub
    oft, timestamp, forwarder, name_rva, first_thunk = struct.unpack_from(
        "<IIIII", image.data, 20)
    assert (timestamp, forwarder) == (0, 0)
    assert image.data[name_rva - 0x9000:].startswith(b"KERNEL32.dll\0")
    first = struct.unpack_from("<Q", image.data, oft - 0x9000)[0]
    second = struct.unpack_from("<Q", image.data, oft - 0x9000 + 8)[0]
    terminator = struct.unpack_from("<Q", image.data, oft - 0x9000 + 16)[0]
    assert image.data[first - 0x9000 + 2:].startswith(b"Sleep\0")
    assert second == (1 << 63) | 7
    assert terminator == 0
    assert image.preload_iat_rvas == (first_thunk, first_thunk + 8)
    assert struct.unpack_from("<Q", image.data, first_thunk - 0x9000)[0] == first
    assert struct.unpack_from("<Q", image.data, first_thunk - 0x9000 + 8)[0] == second
    assert image.data[40:60] == b"\0" * 20

    import_blob = container.build_import_blob(imports)
    bound = container.bind_preload_iat_rvas(
        import_blob, list(image.preload_iat_rvas))
    parsed = container.parse_import_blob(bound)
    assert [f.preload_iat_rva for f in parsed[0].funcs] == [
        first_thunk, first_thunk + 8]


def test_preload_rejects_noncontiguous_source_iat() -> None:
    imports = [
        container.ImportDll(
            "x.dll",
            [
                container.ImportFunc(0x2000, name="a"),
                container.ImportFunc(0x2010, name="b"),
            ],
        )
    ]
    with pytest.raises(DllPreloadError, match="not contiguous"):
        build_dll_preload_image(
            [], imports, section_rva=0x9000, image_size=0xC000)
