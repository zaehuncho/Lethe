"""Signing-stable build identifier used by the shard store and bootstrap."""

from __future__ import annotations

import struct

import pytest

from packer.orchestrator import _pe_content_id


def _minimal_pe() -> bytearray:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    file_header = e_lfanew + 4
    optional_header = file_header + 20
    struct.pack_into("<H", data, file_header, 0x8664)
    struct.pack_into("<H", data, file_header + 16, 0xF0)
    struct.pack_into("<H", data, optional_header, 0x20B)
    struct.pack_into("<I", data, optional_header + 0x6C, 16)
    data[0x200:0x211] = b"signed-id-content"
    return data


def test_content_id_ignores_checksum_and_authenticode_certificate(tmp_path):
    unsigned = _minimal_pe()
    unsigned_path = tmp_path / "unsigned.exe"
    unsigned_path.write_bytes(unsigned)
    expected = _pe_content_id(str(unsigned_path))

    signed = bytearray(unsigned)
    optional_header = 0x80 + 4 + 20
    struct.pack_into("<I", signed, optional_header + 0x40, 0x12345678)
    cert = b"AUTHENTICODE-CERTIFICATE-BYTES" + b"\x00" * 3
    cert_off = len(signed)
    struct.pack_into("<II", signed, optional_header + 0x70 + 4 * 8,
                     cert_off, len(cert))
    signed.extend(cert)
    signed_path = tmp_path / "signed.exe"
    signed_path.write_bytes(signed)

    assert _pe_content_id(str(signed_path)) == expected


def test_content_id_changes_when_executable_content_changes(tmp_path):
    original = _minimal_pe()
    original_path = tmp_path / "original.exe"
    original_path.write_bytes(original)

    changed = bytearray(original)
    changed[0x205] ^= 0xFF
    changed_path = tmp_path / "changed.exe"
    changed_path.write_bytes(changed)

    assert _pe_content_id(str(changed_path)) != _pe_content_id(str(original_path))


def test_content_id_rejects_out_of_range_certificate_table(tmp_path):
    malformed = _minimal_pe()
    optional_header = 0x80 + 4 + 20
    struct.pack_into("<II", malformed, optional_header + 0x70 + 4 * 8,
                     len(malformed) + 8, 32)
    path = tmp_path / "malformed.exe"
    path.write_bytes(malformed)

    with pytest.raises(ValueError, match="out-of-range certificate table"):
        _pe_content_id(str(path))


def test_content_id_rejects_non_amd64_image(tmp_path):
    image = _minimal_pe()
    struct.pack_into("<H", image, 0x80 + 4, 0xAA64)
    path = tmp_path / "arm64.exe"
    path.write_bytes(image)

    with pytest.raises(ValueError, match="not an AMD64 PE"):
        _pe_content_id(str(path))
