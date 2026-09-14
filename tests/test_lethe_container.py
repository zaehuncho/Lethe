"""Container-ABI round-trip tests for Lethe (the custom x64 PE packer).

These exercise ``packer/container.py`` -- the single source
of truth for the on-disk / in-image format shared between the Python builder and
the native C stub loader. The module has **no third-party dependencies** (only
``struct`` + ``dataclasses``), so this whole file PASSES NOW, before any of the
stub / builder / GUI pieces exist.

It is loaded with ``importlib.util.spec_from_file_location`` because the packer
tools are not an installed package.

Part of the standalone Lethe test suite (``pytest`` from the repo root runs it
via ``pytest.ini``); release commands live in ``docs/RELEASE_CHECKLIST.md``.
"""
from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest


# --- load container.py by path (tools are not an installed package) ----------
ROOT = Path(__file__).resolve().parents[1]
CONTAINER_PATH = ROOT / "packer" / "container.py"

if not CONTAINER_PATH.is_file():  # pragma: no cover - defensive, ships with repo
    pytest.skip(
        f"Lethe container ABI not found at {CONTAINER_PATH}",
        allow_module_level=True,
    )

_SPEC = importlib.util.spec_from_file_location("lethe_container", CONTAINER_PATH)
container = importlib.util.module_from_spec(_SPEC)
# Register in sys.modules BEFORE exec: container.py uses @dataclass under
# ``from __future__ import annotations``, and dataclasses resolves the (string)
# annotations via ``sys.modules[cls.__module__]``. Without this the load fails
# with "NoneType object has no attribute '__dict__'". (test_packing_workflow.py
# doesn't need this only because its target module has no dataclasses.)
sys.modules[_SPEC.name] = container
_SPEC.loader.exec_module(container)


# ---------------------------------------------------------------------------
# constants / frozen sizes
# ---------------------------------------------------------------------------

def test_packinfo_size_is_192():
    assert container.PACKINFO_SIZE == 192


def test_sectiondesc_size_is_52():
    assert container.SECTIONDESC_SIZE == 52


def test_magic_and_format_version():
    # 8 bytes incl. trailing NUL; the stub magic-scans its own image for this.
    assert container.MAGIC == b"LETHE01\x00"
    assert len(container.MAGIC) == 8
    assert container.FORMAT_VERSION == 2


def test_flag_bits_are_distinct_powers_of_two():
    bits = [
        container.FLAG_HAS_TLS,
        container.FLAG_HAS_EXCEPTIONS,
        container.FLAG_ANTIDEBUG,
        container.FLAG_MEMGUARD,
        container.FLAG_PAGED_DVM,
        container.FLAG_LOAD_CONFIG,
        container.FLAG_DLL_PRELOAD_IAT,
        container.FLAG_PROCESS_HARDENING,
    ]
    assert bits == [1, 2, 4, 8, 16, 32, 64, 128]
    # no overlap, so flags OR/AND cleanly
    assert 0 == container.FLAG_HAS_TLS & container.FLAG_HAS_EXCEPTIONS


# ---------------------------------------------------------------------------
# PackInfo (fixed 192 bytes)
# ---------------------------------------------------------------------------

def _sample_packinfo():
    return container.PackInfo(
        original_image_base=0x140000000,
        original_size_of_image=0x9000,
        oep_rva=0x1500,
        is_dll=0,
        flags=container.FLAG_HAS_TLS | container.FLAG_HAS_EXCEPTIONS
        | container.FLAG_ANTIDEBUG,
        section_count=3,
        meta_rva=0x8000,
        meta_stored_size=1234,
        meta_uncompressed_size=4096,
        meta_nonce=b"\x11" * 12,
        meta_tag=b"\x22" * 16,
        sections_off=0,
        imports_off=156,
        imports_size=64,
        relocs_off=224,
        relocs_size=48,
        tls_off=272,
        pdata_rva=0x7000,
        pdata_count=42,
        aes_key_enc=b"\x33" * 32,
        kdf_salt=b"\x44" * 16,
        stub_text_rva=0x8800,
        stub_text_size=0x600,
        dll_export_rva=0x2800,
        dll_export_size=0xA0,
        dll_export_sha256_128=b"\x55" * 16,
    )


def test_packinfo_packs_to_exactly_192_bytes():
    blob = _sample_packinfo().pack()
    assert len(blob) == 192 == container.PACKINFO_SIZE


def test_packinfo_round_trip_preserves_every_field():
    pi = _sample_packinfo()
    assert container.PackInfo.from_bytes(pi.pack()) == pi


def test_packinfo_default_round_trip():
    # A default-constructed PackInfo must also survive pack/unpack.
    pi = container.PackInfo()
    assert container.PackInfo.from_bytes(pi.pack()) == pi


def test_packinfo_layout_places_magic_and_version_first():
    blob = _sample_packinfo().pack()
    assert blob[:8] == container.MAGIC
    (ver,) = struct.unpack_from("<I", blob, 8)
    assert ver == container.FORMAT_VERSION


def test_packinfo_rejects_bad_magic():
    blob = bytearray(_sample_packinfo().pack())
    blob[0] = ord("X")
    with pytest.raises(ValueError):
        container.PackInfo.from_bytes(bytes(blob))


def test_packinfo_rejects_unsupported_version():
    blob = bytearray(_sample_packinfo().pack())
    struct.pack_into("<I", blob, 8, 999)  # format_ver field lives right after magic
    with pytest.raises(ValueError):
        container.PackInfo.from_bytes(bytes(blob))


def test_packinfo_rejects_legacy_v1_format():
    blob = bytearray(_sample_packinfo().pack())
    struct.pack_into("<I", blob, 8, 1)
    with pytest.raises(ValueError, match="format version 1"):
        container.PackInfo.from_bytes(bytes(blob))


@pytest.mark.parametrize(
    "field, value",
    [
        ("aes_key_enc", b"\x00" * 31),
        ("meta_nonce", b"\x00" * 11),
        ("meta_tag", b"\x00" * 15),
        ("kdf_salt", b"\x00" * 17),
        ("dll_export_sha256_128", b"\x00" * 15),
    ],
)
def test_packinfo_pack_validates_fixed_width_fields(field, value):
    pi = _sample_packinfo()
    setattr(pi, field, value)
    with pytest.raises(ValueError):
        pi.pack()


# ---------------------------------------------------------------------------
# SectionDesc (fixed 52 bytes)
# ---------------------------------------------------------------------------

def _sample_sectiondesc():
    return container.SectionDesc(
        rva=0x1000,
        virtual_size=0x2000,
        stored_size=900,
        uncompressed_size=0x1800,
        stored_rva=0x8100,
        characteristics=0x60000020,  # IMAGE_SCN_MEM_EXECUTE|READ|CNT_CODE
        gcm_nonce=b"\xAA" * 12,
        gcm_tag=b"\xBB" * 16,
    )


def test_sectiondesc_packs_to_exactly_52_bytes():
    blob = _sample_sectiondesc().pack()
    assert len(blob) == 52 == container.SECTIONDESC_SIZE


def test_sectiondesc_round_trip_preserves_every_field():
    sd = _sample_sectiondesc()
    assert container.SectionDesc.from_bytes(sd.pack()) == sd


@pytest.mark.parametrize(
    "field, value",
    [("gcm_nonce", b"\x00" * 11), ("gcm_tag", b"\x00" * 17)],
)
def test_sectiondesc_pack_validates_nonce_and_tag_width(field, value):
    sd = _sample_sectiondesc()
    setattr(sd, field, value)
    with pytest.raises(ValueError):
        sd.pack()


def test_pack_section_descs_concatenates_in_order():
    sd1 = _sample_sectiondesc()
    sd2 = container.SectionDesc(
        rva=0x3000, virtual_size=0x400, stored_size=128, uncompressed_size=0x400,
        stored_rva=0x8500, characteristics=0xC0000040,
        gcm_nonce=b"\x01" * 12, gcm_tag=b"\x02" * 16,
    )
    blob = container.pack_section_descs([sd1, sd2])
    assert len(blob) == 2 * container.SECTIONDESC_SIZE
    assert blob == sd1.pack() + sd2.pack()
    # and it parses back field-for-field
    assert container.SectionDesc.from_bytes(blob[:52]) == sd1
    assert container.SectionDesc.from_bytes(blob[52:]) == sd2


# ---------------------------------------------------------------------------
# Import blob (this is what hides the original import table)
# ---------------------------------------------------------------------------

def _sample_dlls():
    return [
        container.ImportDll("KERNEL32.dll", [
            container.ImportFunc(0x2000, name="LoadLibraryA"),
            container.ImportFunc(0x2008, name="GetProcAddress"),
            container.ImportFunc(0x2010, by_ordinal=True, ordinal=17),
        ]),
        container.ImportDll("USER32.dll", [
            container.ImportFunc(0x2100, name="MessageBoxA"),
        ]),
    ]


def test_import_blob_round_trip_including_ordinal_import():
    dlls = _sample_dlls()
    blob = container.build_import_blob(dlls)
    parsed = container.parse_import_blob(blob)
    # DLL names survive (XOR-encrypted, not hashed)
    assert [d.name for d in parsed] == [d.name for d in dlls]
    # function counts match
    assert [len(d.funcs) for d in parsed] == [len(d.funcs) for d in dlls]
    # ordinal import preserved
    ordinal_func = parsed[0].funcs[2]
    assert ordinal_func.by_ordinal is True
    assert ordinal_func.ordinal == 17
    assert ordinal_func.name == ""
    # by-name imports are hash-based (name not recoverable from blob)
    named_func = parsed[0].funcs[0]
    assert named_func.by_ordinal is False
    assert named_func.iat_rva == 0x2000
    # no plaintext function names in the blob
    assert b"LoadLibraryA" not in blob
    assert b"GetProcAddress" not in blob
    assert b"MessageBoxA" not in blob


def test_import_blob_encodes_hint_or_ordinal_field():
    """The stub distinguishes ordinal vs. by-hash via hint_or_ordinal (u16)."""
    dlls = _sample_dlls()
    blob = container.build_import_blob(dlls)
    (enc_pool_size,) = struct.unpack_from("<I", blob, 0)
    pos = 4 + enc_pool_size
    # First DLL entry (KERNEL32.dll)
    (dll_hash,) = struct.unpack_from("<I", blob, pos);  pos += 4
    assert dll_hash != 0   # not the terminator
    pos += 1 + 4           # skip xor_key, enc_offset
    (func_count,) = struct.unpack_from("<I", blob, pos);  pos += 4
    assert func_count == 3
    hints = []
    for _ in range(func_count):
        pos += 4           # skip iat_rva
        (h,) = struct.unpack_from("<H", blob, pos);  pos += 2
        pos += 4           # skip func_name_hash
        pos += 4           # skip preload_iat_rva
        hints.append(h)
    # first two are by-hash (0xFFFF); third is ordinal 17
    assert hints[0] == container.IMPORT_HINT_BY_HASH
    assert hints[1] == container.IMPORT_HINT_BY_HASH
    assert hints[2] == 17


def test_import_blob_no_plaintext_names_in_blob():
    # Hash-based format: function names are never stored; DLL names are XOR'd.
    dlls = [
        container.ImportDll("A.dll", [container.ImportFunc(0x10, name="Shared")]),
        container.ImportDll("B.dll", [container.ImportFunc(0x20, name="Shared")]),
    ]
    blob = container.build_import_blob(dlls)
    # Function names must NOT appear as plaintext
    assert b"Shared" not in blob
    # DLL names must NOT appear as plaintext (XOR-encrypted)
    assert b"A.dll\x00" not in blob
    assert b"B.dll\x00" not in blob
    # But DLL names are recoverable
    parsed = container.parse_import_blob(blob)
    assert [d.name for d in parsed] == ["A.dll", "B.dll"]


def test_import_blob_empty_is_valid():
    blob = container.build_import_blob([])
    assert container.parse_import_blob(blob) == []


def test_import_blob_rejects_ordinal_that_collides_with_hash_sentinel():
    """Ordinal 0xFFFF would be indistinguishable from the by-hash sentinel and
    would silently misresolve at runtime — the builder must refuse it."""
    dlls = [container.ImportDll("EDGE.dll", [
        container.ImportFunc(0x30, by_ordinal=True,
                             ordinal=container.IMPORT_HINT_BY_HASH)])]
    with pytest.raises(ValueError, match="collides with the by-hash sentinel"):
        container.build_import_blob(dlls)


def test_import_blob_rejects_out_of_range_ordinal():
    """PE ordinals are u16; anything larger cannot round-trip through the field."""
    dlls = [container.ImportDll("EDGE.dll", [
        container.ImportFunc(0x30, by_ordinal=True, ordinal=0x1_0000)])]
    with pytest.raises(ValueError, match="out of range"):
        container.build_import_blob(dlls)


def test_import_blob_dll_with_no_functions():
    dlls = [container.ImportDll("EMPTY.dll", [])]
    blob = container.build_import_blob(dlls)
    parsed = container.parse_import_blob(blob)
    assert len(parsed) == 1
    assert parsed[0].name == "EMPTY.dll"
    assert parsed[0].funcs == []


# ---------------------------------------------------------------------------
# TLS blob
# ---------------------------------------------------------------------------

def test_build_tls_blob_layout_and_callbacks():
    blob = container.build_tls_blob(
        index_rva=0x3000, raw_start_rva=0x3100, raw_end_rva=0x3200,
        zero_fill=64, callback_rvas=[0x4000, 0x4008],
        characteristics=0x00600000,
    )
    index, raw_start, raw_end, zero_fill, characteristics, count = (
        struct.unpack_from("<IIIIII", blob, 0))
    assert (index, raw_start, raw_end, zero_fill, characteristics, count) == (
        0x3000, 0x3100, 0x3200, 64, 0x00600000, 2)
    callbacks = struct.unpack_from("<II", blob, 24)
    assert list(callbacks) == [0x4000, 0x4008]
    assert len(blob) == 24 + 2 * 4


def test_build_tls_blob_no_callbacks():
    blob = container.build_tls_blob(0x1, 0x2, 0x3, 0, [])
    (count,) = struct.unpack_from("<I", blob, 20)
    assert count == 0
    assert len(blob) == 24


# ---------------------------------------------------------------------------
# Metadata envelope layout: [SectionDesc[]][imports][relocs][tls], 4-byte aligned
# ---------------------------------------------------------------------------

def test_build_metadata_offsets_and_alignment():
    sd_blob = container.pack_section_descs([_sample_sectiondesc()])  # 52B (already /4)
    import_blob = container.build_import_blob(_sample_dlls())
    reloc_blob = b"\xCC" * 13  # deliberately NOT a multiple of 4 -> forces padding
    tls_blob = container.build_tls_blob(0x3000, 0x3100, 0x3200, 64, [0x4000])

    buf, offs = container.build_metadata(sd_blob, import_blob, reloc_blob, tls_blob)

    # section descriptors always start the buffer
    assert offs.sections_off == 0

    # every sub-blob offset is 4-byte aligned
    for off in (offs.imports_off, offs.relocs_off, offs.tls_off):
        assert off % 4 == 0, f"offset {off} not 4-aligned"

    # recorded sizes match the inputs
    assert offs.imports_size == len(import_blob)
    assert offs.relocs_size == len(reloc_blob)

    # each offset points at exactly the bytes that were placed there
    assert buf[offs.sections_off:offs.sections_off + len(sd_blob)] == sd_blob
    assert buf[offs.imports_off:offs.imports_off + len(import_blob)] == import_blob
    assert buf[offs.relocs_off:offs.relocs_off + len(reloc_blob)] == reloc_blob
    assert buf[offs.tls_off:offs.tls_off + len(tls_blob)] == tls_blob

    # the odd-length reloc blob must be followed by zero padding up to the next /4
    pad_start = offs.relocs_off + len(reloc_blob)
    assert offs.tls_off >= pad_start
    assert set(buf[pad_start:offs.tls_off]) <= {0}


def test_build_metadata_is_gap_free_between_aligned_regions():
    # With all-/4 blob lengths there is no padding: regions are contiguous.
    sd_blob = container.pack_section_descs([_sample_sectiondesc()])   # 52
    import_blob = b"\x00" * 8
    reloc_blob = b"\x11" * 12
    tls_blob = b"\x22" * 4
    buf, offs = container.build_metadata(sd_blob, import_blob, reloc_blob, tls_blob)
    assert offs.sections_off == 0
    assert offs.imports_off == 52
    assert offs.relocs_off == 52 + 8
    assert offs.tls_off == 52 + 8 + 12
    assert len(buf) == 52 + 8 + 12 + 4
