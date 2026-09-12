"""Cryptographic staged-output validation and publication gating."""
from __future__ import annotations

import dataclasses
import hashlib
import struct
import zlib
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from packer import (
    assemble, container, keyed_validation, orchestrator, payload, pe_analyze,
    report,
)

_PACKINFO_FILE_OFFSET = 0x400
_STUB_TEXT_FILE_OFFSET = 0x800
_PAYLOAD_FILE_OFFSET = 0xC00
_RSRC_FILE_OFFSET = 0x1400
_STUB_TEXT_RVA = 0x4000
_PAYLOAD_RVA = 0x5000
_META_RVA = 0x5100


@dataclass
class _Fixture:
    data: bytearray
    artifacts: SimpleNamespace
    assembly: SimpleNamespace
    shard: bytes


def _derive(master: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(), length=32, salt=salt, info=info
    ).derive(master)


def _section(blob: bytearray, table: int, index: int, name: bytes,
             virtual_size: int, rva: int, raw_size: int, raw_ptr: int,
             characteristics: int) -> None:
    offset = table + index * 40
    blob[offset:offset + 8] = name.ljust(8, b"\0")
    struct.pack_into(
        "<IIII", blob, offset + 8,
        virtual_size, rva, raw_size, raw_ptr)
    struct.pack_into("<I", blob, offset + 36, characteristics)


def _build_fixture() -> _Fixture:
    master_key = bytes(range(1, 33))
    salt = b"fixture-kdf-salt"
    shard = bytes([0xA5]) * 32
    section_plain = (b"authenticated Lethe payload\0" * 7)[:173]
    section_nonce = b"S" * 12
    section_key = _derive(
        master_key, salt,
        container.HKDF_INFO_SECTION + struct.pack("<I", 0x1000))
    section_sealed = AESGCM(section_key).encrypt(
        section_nonce, zlib.compress(section_plain, 9),
        struct.pack("<I", 0x1000))
    section_ciphertext, section_tag = section_sealed[:-16], section_sealed[-16:]
    desc = container.SectionDesc(
        rva=0x1000,
        virtual_size=0x800,
        stored_size=len(section_ciphertext),
        uncompressed_size=len(section_plain),
        stored_rva=_PAYLOAD_RVA,
        characteristics=0x60000020,
        gcm_nonce=section_nonce,
        gcm_tag=section_tag,
    )

    import_blob = container.build_import_blob([])
    reloc_blob = b""
    tls_blob = b""
    metadata_plain, offsets = container.build_metadata(
        desc.pack(), import_blob, reloc_blob, tls_blob)
    meta_nonce = b"M" * 12
    meta_key = _derive(master_key, salt, container.HKDF_INFO_META)
    meta_compressed = zlib.compress(metadata_plain, 9)
    aad_info = container.PackInfo(
        original_image_base=0x140000000,
        original_size_of_image=0x3000,
        oep_rva=0x1000,
        is_dll=0,
        flags=0,
        section_count=1,
        meta_rva=_META_RVA,
        meta_stored_size=len(meta_compressed),
        meta_uncompressed_size=len(metadata_plain),
        sections_off=offsets.sections_off,
        imports_off=offsets.imports_off,
        imports_size=offsets.imports_size,
        relocs_off=offsets.relocs_off,
        relocs_size=offsets.relocs_size,
        tls_off=offsets.tls_off,
        pdata_rva=0,
        pdata_count=0,
        stub_text_rva=_STUB_TEXT_RVA,
        stub_text_size=0x100,
    )
    meta_sealed = AESGCM(meta_key).encrypt(
        meta_nonce, meta_compressed, container.build_metadata_aad(aad_info))
    meta_ciphertext, meta_tag = meta_sealed[:-16], meta_sealed[-16:]
    resource_bytes = b"Lethe preserved resource bytes\0"
    metadata = payload.MetadataEnvelope(
        meta_stored=meta_ciphertext,
        meta_nonce=meta_nonce,
        meta_tag=meta_tag,
        meta_uncompressed_size=len(metadata_plain),
        offsets=offsets,
    )
    stored = payload.StoredSection(desc=desc, data=section_ciphertext)
    artifacts = SimpleNamespace(
        aes_key=master_key,
        kdf_salt=salt,
        stored_sections=[stored],
        metadata=metadata,
        flags=0,
        oep_rva=0x1000,
        is_dll=0,
        original_image_base=0x140000000,
        original_size_of_image=0x3000,
        pdata_rva=0,
        pdata_count=0,
        import_blob=import_blob,
        reloc_blob=reloc_blob,
        tls_blob=tls_blob,
        rsrc_rva=0x2000,
        rsrc_bytes=resource_bytes,
    )

    blob = bytearray(0x1600)
    blob[:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x80)
    blob[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into(
        "<HHIIIHH", blob, coff, 0x8664, 5, 0, 0, 0, 0xF0, 0x0022)
    optional = coff + 20
    struct.pack_into("<H", blob, optional, 0x20B)
    struct.pack_into("<I", blob, optional + 0x38, 0x6000)
    section_table = optional + 0xF0
    _section(blob, section_table, 0, b".text", 0x800, 0x1000, 0, 0,
             0xC0000080)
    _section(blob, section_table, 1, b".ldata", 0x400, 0x3000, 0x400,
             0x400, 0xC0000040)
    _section(blob, section_table, 2, b".ltext", 0x400, _STUB_TEXT_RVA,
             0x400, _STUB_TEXT_FILE_OFFSET, 0x60000020)
    _section(blob, section_table, 3, b".rdata2", 0x800, _PAYLOAD_RVA,
             0x800, _PAYLOAD_FILE_OFFSET, 0x40000040)
    _section(blob, section_table, 4, b".rsrc", len(resource_bytes), 0x2000,
             0x200, _RSRC_FILE_OFFSET, 0x40000040)

    stub_text = bytes([0x90]) * 0x100
    blob[_STUB_TEXT_FILE_OFFSET:_STUB_TEXT_FILE_OFFSET + len(stub_text)] = stub_text
    blob[_PAYLOAD_FILE_OFFSET:
         _PAYLOAD_FILE_OFFSET + len(section_ciphertext)] = section_ciphertext
    meta_file_offset = _PAYLOAD_FILE_OFFSET + (_META_RVA - _PAYLOAD_RVA)
    blob[meta_file_offset:meta_file_offset + len(meta_ciphertext)] = meta_ciphertext
    blob[_RSRC_FILE_OFFSET:
         _RSRC_FILE_OFFSET + len(resource_bytes)] = resource_bytes

    text_hash = hashlib.sha256(stub_text).digest()
    mask = _derive(text_hash, salt, container.HKDF_INFO_CODEHASH)
    masked_key = bytes(
        key ^ mask_byte ^ shard_byte
        for key, mask_byte, shard_byte in zip(master_key, mask, shard))
    info = dataclasses.replace(
        aad_info,
        meta_nonce=meta_nonce,
        meta_tag=meta_tag,
        aes_key_enc=masked_key,
        kdf_salt=salt,
        stub_text_rva=_STUB_TEXT_RVA,
        stub_text_size=len(stub_text),
    )
    blob[_PACKINFO_FILE_OFFSET:
         _PACKINFO_FILE_OFFSET + container.PACKINFO_SIZE] = info.pack()
    assembly = SimpleNamespace(
        server_shard=shard,
        stub_text_rva=_STUB_TEXT_RVA,
        stub_text_size=len(stub_text),
    )
    return _Fixture(blob, artifacts, assembly, shard)


def _info(fixture: _Fixture) -> container.PackInfo:
    return container.PackInfo.from_bytes(
        fixture.data[_PACKINFO_FILE_OFFSET:
                     _PACKINFO_FILE_OFFSET + container.PACKINFO_SIZE])


def _replace_info(fixture: _Fixture, **changes) -> None:
    updated = dataclasses.replace(_info(fixture), **changes)
    fixture.data[_PACKINFO_FILE_OFFSET:
                 _PACKINFO_FILE_OFFSET + container.PACKINFO_SIZE] = updated.pack()


def _meta_file_offset(fixture: _Fixture) -> int:
    return _PAYLOAD_FILE_OFFSET + (_info(fixture).meta_rva - _PAYLOAD_RVA)


def _reseal_metadata_compressed(fixture: _Fixture, compressed: bytes) -> None:
    info = _info(fixture)
    updated = dataclasses.replace(info, meta_stored_size=len(compressed))
    key = _derive(
        fixture.artifacts.aes_key, fixture.artifacts.kdf_salt,
        container.HKDF_INFO_META)
    sealed = AESGCM(key).encrypt(
        updated.meta_nonce, compressed, container.build_metadata_aad(updated))
    ciphertext, tag = sealed[:-16], sealed[-16:]
    offset = _meta_file_offset(fixture)
    assert offset + len(ciphertext) <= len(fixture.data)
    fixture.data[offset:offset + len(ciphertext)] = ciphertext
    _replace_info(fixture, meta_stored_size=len(ciphertext), meta_tag=tag)


def _tamper_metadata_ciphertext(fixture: _Fixture) -> None:
    fixture.data[_meta_file_offset(fixture)] ^= 0x40


def _tamper_metadata_nonce(fixture: _Fixture) -> None:
    nonce = bytearray(_info(fixture).meta_nonce)
    nonce[0] ^= 1
    _replace_info(fixture, meta_nonce=bytes(nonce))


def _tamper_metadata_tag(fixture: _Fixture) -> None:
    tag = bytearray(_info(fixture).meta_tag)
    tag[-1] ^= 1
    _replace_info(fixture, meta_tag=bytes(tag))


def _tamper_metadata_import_offset(fixture: _Fixture) -> None:
    info = _info(fixture)
    _replace_info(fixture, imports_off=info.imports_off - 4)


def _use_wrong_key(fixture: _Fixture) -> None:
    fixture.artifacts.aes_key = bytes([0xFE]) * 32


def _authenticate_malformed_compressed_metadata(fixture: _Fixture) -> None:
    _reseal_metadata_compressed(
        fixture, bytes([0x7F]) * _info(fixture).meta_stored_size)


def _authenticate_malformed_plaintext_metadata(fixture: _Fixture) -> None:
    malformed = bytes(_info(fixture).meta_uncompressed_size)
    _reseal_metadata_compressed(fixture, zlib.compress(malformed, 9))


def _tamper_payload_ciphertext(fixture: _Fixture) -> None:
    fixture.data[_PAYLOAD_FILE_OFFSET] ^= 0x20


def _tamper_preserved_resource(fixture: _Fixture) -> None:
    fixture.data[_RSRC_FILE_OFFSET] ^= 0x08


_FAILURES = (
    (_tamper_metadata_ciphertext, "metadata envelope AES-GCM authentication"),
    (_tamper_metadata_nonce, "metadata envelope AES-GCM authentication"),
    (_tamper_metadata_tag, "metadata envelope AES-GCM authentication"),
    (_tamper_metadata_import_offset,
     "metadata envelope AES-GCM authentication"),
    (_use_wrong_key, "code-hash key binding"),
    (_authenticate_malformed_compressed_metadata, "valid zlib stream"),
    (_authenticate_malformed_plaintext_metadata, "metadata plaintext hash"),
    (_tamper_payload_ciphertext, "protected section 0 AES-GCM authentication"),
    (_tamper_preserved_resource, "preserved resource hash"),
)


def _validate(path, fixture: _Fixture):
    structural = report.validate_packed(str(path))
    assert structural.ok, structural.reason
    return keyed_validation.validate_staged_output(
        str(path), fixture.artifacts,
        server_shard=fixture.shard,
        expected_stub_text_rva=fixture.assembly.stub_text_rva,
        expected_stub_text_size=fixture.assembly.stub_text_size,
        structural=structural,
    )


def test_metadata_aad_v2_golden_vector_is_stable():
    info = container.PackInfo(
        flags=0x01020304,
        original_image_base=0x1122334455667788,
        original_size_of_image=0x99AABBCC,
        oep_rva=0x01020304,
        is_dll=1,
        section_count=0x0A0B0C0D,
        meta_rva=0x10203040,
        meta_stored_size=0x50607080,
        meta_uncompressed_size=0x90A0B0C0,
        sections_off=0x0D0E0F10,
        imports_off=0x11121314,
        imports_size=0x15161718,
        relocs_off=0x21222324,
        relocs_size=0x25262728,
        tls_off=0x31323334,
        pdata_rva=0x35363738,
        pdata_count=0x41424344,
        stub_text_rva=0x45464748,
        stub_text_size=0x51525354,
        dll_export_rva=0x61626364,
        dll_export_size=0x71727374,
        dll_export_sha256_128=bytes(range(0x80, 0x90)),
    )
    assert container.build_metadata_aad(info).hex() == (
        "4c455448452d4d4554412d4141443200"
        "02000000040302018877665544332211"
        "ccbbaa9904030201010000000d0c0b0a"
        "4030201080706050c0b0a090100f0e0d"
        "14131211181716152423222128272625"
        "34333231383736354443424148474645"
        "545352516463626174737271"
        "808182838485868788898a8b8c8d8e8f"
    )


def test_assembler_rejects_legacy_v1_stub_before_layout(monkeypatch):
    legacy_header = container.MAGIC + struct.pack("<I", 1)
    legacy_stub = SimpleNamespace(
        find_packinfo_rva=lambda: 0x2000,
        read_at_rva=lambda _rva, _size: legacy_header,
    )
    monkeypatch.setattr(assemble, "_load_stub", lambda *_args, **_kwargs: legacy_stub)
    parsed = SimpleNamespace(
        image_base=0x140000000,
        size_of_image=0x3000,
        is_dll=False,
        oep_rva=0x1000,
    )
    artifacts = SimpleNamespace(is_dll=0)

    with pytest.raises(assemble.AssembleError, match="format v1.*format v2"):
        assemble.build_output_pe(
            parsed, artifacts, "unused.exe", options=SimpleNamespace(
                server_shard=False))


def _fallback_metadata_artifacts(metadata):
    return SimpleNamespace(
        aes_key=bytes(range(32)),
        kdf_salt=b"fallback-kdf-key",
        import_blob=container.build_import_blob([]),
        reloc_blob=b"",
        tls_blob=b"",
        metadata=metadata,
    )


def test_finalize_metadata_fallback_commits_exact_envelope_for_keyed_validation():
    stale = object()
    artifacts = _fallback_metadata_artifacts(stale)
    desc = container.SectionDesc(
        rva=0x1000,
        virtual_size=0x80,
        stored_size=0x30,
        uncompressed_size=0x70,
        stored_rva=0x9000,
        characteristics=0x60000020,
        gcm_nonce=b"N" * 12,
        gcm_tag=b"T" * 16,
    )
    aad_info = container.PackInfo(
        original_image_base=0x140000000,
        original_size_of_image=0xA000,
        oep_rva=0x1000,
        section_count=1,
        meta_rva=0x9100,
        stub_text_rva=0x6000,
        stub_text_size=0x500,
    )

    finalized = assemble._finalize_metadata(artifacts, [desc], 9, aad_info)

    assert artifacts.metadata is finalized
    assert artifacts.metadata is not stale
    final_info = dataclasses.replace(
        aad_info,
        meta_stored_size=finalized.meta_stored_size,
        meta_uncompressed_size=finalized.meta_uncompressed_size,
        sections_off=finalized.offsets.sections_off,
        imports_off=finalized.offsets.imports_off,
        imports_size=finalized.offsets.imports_size,
        relocs_off=finalized.offsets.relocs_off,
        relocs_size=finalized.offsets.relocs_size,
        tls_off=finalized.offsets.tls_off,
    )
    meta_key = _derive(
        artifacts.aes_key, artifacts.kdf_salt, container.HKDF_INFO_META)
    compressed = AESGCM(meta_key).decrypt(
        finalized.meta_nonce,
        finalized.meta_stored + finalized.meta_tag,
        container.build_metadata_aad(final_info),
    )
    plaintext = zlib.decompress(compressed)
    expected, expected_offsets = container.build_metadata(
        desc.pack(), artifacts.import_blob, artifacts.reloc_blob,
        artifacts.tls_blob)
    assert plaintext == expected
    assert finalized.offsets == expected_offsets


def test_finalize_metadata_fallback_fails_closed_for_read_only_state():
    class ReadOnlyMetadataArtifacts(SimpleNamespace):
        @property
        def metadata(self):
            return self._metadata

    base = _fallback_metadata_artifacts(object())
    artifacts = ReadOnlyMetadataArtifacts(
        **{key: value for key, value in vars(base).items()
           if key != "metadata"},
        _metadata=base.metadata,
    )
    aad_info = container.PackInfo(
        section_count=0,
        meta_rva=0x5000,
        stub_text_rva=0x2000,
        stub_text_size=0x100,
    )

    with pytest.raises(
            assemble.AssembleError,
            match="cannot accept finalized metadata state"):
        assemble._finalize_metadata(artifacts, [], 9, aad_info)

    assert artifacts.metadata is base.metadata

@pytest.mark.parametrize("field", [
    "flags",
    "original_image_base",
    "original_size_of_image",
    "oep_rva",
    "is_dll",
    "section_count",
    "meta_rva",
    "meta_stored_size",
    "meta_uncompressed_size",
    "sections_off",
    "imports_off",
    "imports_size",
    "relocs_off",
    "relocs_size",
    "tls_off",
    "pdata_rva",
    "pdata_count",
    "stub_text_rva",
    "stub_text_size",
    "dll_export_rva",
    "dll_export_size",
])
def test_every_critical_packinfo_geometry_field_is_authenticated(field):
    fixture = _build_fixture()
    info = _info(fixture)
    meta_offset = _meta_file_offset(fixture)
    ciphertext = bytes(
        fixture.data[meta_offset:meta_offset + info.meta_stored_size])
    key = _derive(
        fixture.artifacts.aes_key, fixture.artifacts.kdf_salt,
        container.HKDF_INFO_META)
    original_value = getattr(info, field)
    tampered = dataclasses.replace(info, **{field: original_value ^ 1})

    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(
            info.meta_nonce, ciphertext + info.meta_tag,
            container.build_metadata_aad(tampered))


def test_keyed_validator_authenticates_and_round_trips_every_live_unit(tmp_path):
    fixture = _build_fixture()
    staged = tmp_path / "staged.exe"
    staged.write_bytes(fixture.data)

    result = _validate(staged, fixture)

    assert result.ok, result.reason
    assert result.section_count == 1
    assert result.plaintext_bytes > 173
    summary = result.summary()
    assert fixture.artifacts.aes_key.hex() not in summary
    assert fixture.shard.hex() not in summary


@pytest.mark.parametrize("mutate, expected", _FAILURES,
                         ids=[item[0].__name__ for item in _FAILURES])
def test_keyed_validator_rejects_tamper_wrong_key_and_malformed_data(
        tmp_path, mutate, expected):
    fixture = _build_fixture()
    mutate(fixture)
    staged = tmp_path / "staged.exe"
    staged.write_bytes(fixture.data)

    result = _validate(staged, fixture)

    assert not result.ok
    assert expected in result.reason
    assert fixture.artifacts.aes_key.hex() not in result.reason
    assert fixture.shard.hex() not in result.reason


@pytest.mark.parametrize("mutate, _expected", _FAILURES,
                         ids=[item[0].__name__ for item in _FAILURES])
def test_real_keyed_failures_preserve_existing_output_and_remove_stage(
        monkeypatch, tmp_path, mutate, _expected):
    fixture = _build_fixture()
    mutate(fixture)
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    output.write_bytes(b"previous release")
    stages: list[str] = []
    uploads: list[dict] = []
    content_ids: list[str] = []

    monkeypatch.setattr(
        pe_analyze, "analyze_pe", lambda _path: SimpleNamespace(is_dll=False))
    monkeypatch.setattr(
        payload, "build_payload", lambda *_args: fixture.artifacts)

    def fake_assemble(_parsed, _artifacts, output_path, **_kwargs):
        stages.append(output_path)
        with open(output_path, "wb") as stream:
            stream.write(fixture.data)
        return fixture.assembly

    monkeypatch.setattr(assemble, "build_output_pe", fake_assemble)
    monkeypatch.setattr(
        orchestrator, "_upload_shard",
        lambda *_args, **kwargs: uploads.append(kwargs))
    monkeypatch.setattr(
        orchestrator, "_pe_content_id",
        lambda path: content_ids.append(path) or "a" * 64)

    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(
            output_path=str(output), is_dll=False,
            server_shard=True,
            shard_url=f"https://{orchestrator._SHARD_API_HOST}",
            shard_auth="build-token", shard_license_id="license-1",
            shard_hwid_hash="b" * 64))

    assert not result.ok
    assert "staged output failed keyed validation" in result.error
    assert output.read_bytes() == b"previous release"
    assert uploads == []
    assert content_ids == []
    assert len(stages) == 1
    assert not __import__("os").path.exists(stages[0])
