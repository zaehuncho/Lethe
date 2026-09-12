"""Golden vectors and hostile-input tests for the KR2 wire format."""
from __future__ import annotations

import hashlib
import struct
from dataclasses import replace
from pathlib import Path

import pytest

from packer import key_release_protocol as kr2


VECTOR_PATH = Path(__file__).with_name("vectors") / "key_release_v2.txt"


REQUEST_HEX = (
    "4c4b523202010006000000d10100000020000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f020000000a4c49432d323032365f410300"
    "000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d"
    "3e3f0400000020404142434445464748494a4b4c4d4e4f50515253545556575859"
    "5a5b5c5d5e5f0500000041040102030405060708090a0b0c0d0e0f101112131415"
    "161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343536"
    "3738393a3b3c3d3e3f4006000000080000000069800e80"
)

RESPONSE_HEX = (
    "4c4b523202020002000001c5010000017b4c4b52320204000b0000016f01000000"
    "20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "020000000a4c49432d323032365f410300000020202122232425262728292a2b2c2d"
    "2e2f303132333435363738393a3b3c3d3e3f040000002040414243444546474849"
    "4a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0500000041040102030405"
    "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526"
    "2728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4006000000410441"
    "42434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162"
    "636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80070000"
    "0010101112131415161718191a1b1c1d1e1f08000000080000000069800e850900"
    "0000080000000069800ec10a0000000c000102030405060708090a0b0b00000020"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "0200000040404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
    "5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c"
    "7d7e7f"
)

TRANSCRIPT_HEX = (
    "4c4b5232020300020000026201000000dd4c4b523202010006000000d101000000"
    "20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "020000000a4c49432d323032365f410300000020202122232425262728292a2b2c2d"
    "2e2f303132333435363738393a3b3c3d3e3f040000002040414243444546474849"
    "4a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0500000041040102030405"
    "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526"
    "2728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4006000000080000"
    "000069800e80020000017b4c4b52320204000b0000016f0100000020000102030405"
    "060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f020000000a4c49"
    "432d323032365f410300000020202122232425262728292a2b2c2d2e2f3031323334"
    "35363738393a3b3c3d3e3f0400000020404142434445464748494a4b4c4d4e4f50"
    "5152535455565758595a5b5c5d5e5f0500000041040102030405060708090a0b0c"
    "0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d"
    "2e2f303132333435363738393a3b3c3d3e3f400600000041044142434445464748"
    "494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263646566676869"
    "6a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8007000000101011121314"
    "15161718191a1b1c1d1e1f08000000080000000069800e85090000000800000000"
    "69800ec10a0000000c000102030405060708090a0b0b00000020a0a1a2a3a4a5a6"
    "a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
)


def _models():
    request = kr2.KeyReleaseRequest(
        build_id=bytes(range(32)),
        license_id="LIC-2026_A",
        device_id=bytes(range(32, 64)),
        challenge=bytes(range(64, 96)),
        client_ephemeral_key=bytes([4]) + bytes(range(1, 65)),
        requested_at=1_770_000_000,
    )
    grant = kr2.KeyReleaseGrant(
        build_id=request.build_id,
        license_id=request.license_id,
        device_id=request.device_id,
        challenge=request.challenge,
        client_ephemeral_key=request.client_ephemeral_key,
        server_ephemeral_key=bytes([4]) + bytes(range(65, 129)),
        launch_id=bytes(range(16, 32)),
        issued_at=1_770_000_005,
        expires_at=1_770_000_065,
        ciphertext_nonce=bytes(range(12)),
        ciphertext=bytes(range(160, 192)),
    )
    return request, grant, kr2.KeyReleaseResponse(
        grant=grant, signature=bytes(range(64, 128)))


def _field_tag_offset(message: bytes, index: int) -> int:
    cursor = 12
    for current in range(index + 1):
        if cursor + 5 > len(message):
            raise AssertionError("test fixture has no such field")
        if current == index:
            return cursor
        value_size = struct.unpack_from(">I", message, cursor + 1)[0]
        cursor += 5 + value_size
    raise AssertionError("unreachable")


def _replace_tag(message: bytes, index: int, tag: int) -> bytes:
    changed = bytearray(message)
    changed[_field_tag_offset(message, index)] = tag
    return bytes(changed)


def test_request_response_and_transcript_round_trip():
    request, grant, response = _models()

    assert kr2.decode_request(kr2.encode_request(request)) == request
    assert kr2.decode_response(kr2.encode_response(response)) == response
    assert kr2.decode_transcript(
        kr2.encode_transcript(request, grant)) == (request, grant)
    kr2.validate_response_binding(request, response)


def test_stable_golden_vectors():
    request, grant, response = _models()
    encoded = (
        kr2.encode_request(request),
        kr2.encode_response(response),
        kr2.encode_transcript(request, grant),
    )

    assert encoded == tuple(map(bytes.fromhex, (
        REQUEST_HEX, RESPONSE_HEX, TRANSCRIPT_HEX)))
    vector_file = dict(
        line.split("=", 1)
        for line in VECTOR_PATH.read_text(encoding="ascii").splitlines()
        if line and not line.startswith("#"))
    assert encoded == tuple(bytes.fromhex(vector_file[name]) for name in (
        "request", "response", "transcript"))
    assert tuple(map(len, encoded)) == (221, 465, 622)
    assert tuple(hashlib.sha256(value).hexdigest() for value in encoded) == (
        "73d0bb921c59ff32f83f1aaa575be9dbe468391a1ab736ddd1246e1a6ff795a9",
        "833bfc8035cd2da19eb90a4c12f6c94476435e025264a0543ae93af3dab7de23",
        "7be1888ed2483b266fd07fdde4b13e7c351553e4ac997ed9a5125a0267350f53",
    )


@pytest.mark.parametrize("decoder,encoded", [
    (kr2.decode_request, lambda: kr2.encode_request(_models()[0])),
    (kr2.decode_response, lambda: kr2.encode_response(_models()[2])),
    (kr2.decode_transcript,
     lambda: kr2.encode_transcript(_models()[0], _models()[1])),
])
def test_decoders_reject_truncation_and_trailing_bytes(decoder, encoded):
    message = encoded()
    with pytest.raises(kr2.ProtocolError):
        decoder(message[:-1])
    with pytest.raises(kr2.ProtocolError, match="body size|trailing"):
        decoder(message + b"\x00")


@pytest.mark.parametrize("decoder,encoded", [
    (kr2.decode_request, lambda: kr2.encode_request(_models()[0])),
    (kr2.decode_response, lambda: kr2.encode_response(_models()[2])),
    (kr2.decode_transcript,
     lambda: kr2.encode_transcript(_models()[0], _models()[1])),
])
def test_decoders_reject_duplicate_unknown_and_noncanonical_tags(decoder, encoded):
    message = encoded()
    with pytest.raises(kr2.ProtocolError, match="duplicate"):
        decoder(_replace_tag(message, 1, 1))
    with pytest.raises(kr2.ProtocolError, match="unknown"):
        decoder(_replace_tag(message, 0, 127))
    reordered = _replace_tag(_replace_tag(message, 0, 2), 1, 1)
    with pytest.raises(kr2.ProtocolError, match="canonical order"):
        decoder(reordered)


def test_response_rejects_unknown_nested_grant_field():
    response = bytearray(kr2.encode_response(_models()[2]))
    grant_start = 12 + 5
    response[grant_start + 12] = 127

    with pytest.raises(kr2.ProtocolError, match="unknown field tag"):
        kr2.decode_response(bytes(response))


def test_decoder_rejects_declared_oversized_field_before_copying():
    request = bytearray(kr2.encode_request(_models()[0]))
    struct.pack_into(">I", request, 13, kr2.MAX_REQUEST_SIZE + 1)

    with pytest.raises(kr2.ProtocolError, match="exceeds message bound"):
        kr2.decode_request(bytes(request))


def test_decoders_enforce_total_message_bounds():
    request = kr2.encode_request(_models()[0])
    oversized = request + bytes(kr2.MAX_REQUEST_SIZE + 1 - len(request))

    with pytest.raises(kr2.ProtocolError, match="message exceeds"):
        kr2.decode_request(oversized)


def test_decoder_rejects_noncanonical_license_identifier():
    request = bytearray(kr2.encode_request(_models()[0]))
    license_value_offset = _field_tag_offset(request, 1) + 5
    request[license_value_offset] = ord("/")

    with pytest.raises(kr2.ProtocolError, match="canonical identifier"):
        kr2.decode_request(bytes(request))


@pytest.mark.parametrize("offset,value,match", [
    (4, 3, "unsupported KR2 version"),
    (5, 2, "unexpected KR2 message kind"),
])
def test_request_rejects_wrong_version_and_kind(offset, value, match):
    request = bytearray(kr2.encode_request(_models()[0]))
    request[offset] = value

    with pytest.raises(kr2.ProtocolError, match=match):
        kr2.decode_request(bytes(request))


def test_response_binding_rejects_every_mismatched_identity_field():
    request, grant, _response = _models()
    mutations = (
        replace(grant, build_id=b"x" * kr2.BUILD_ID_SIZE),
        replace(grant, license_id="OTHER-LICENSE"),
        replace(grant, device_id=b"x" * kr2.DEVICE_ID_SIZE),
        replace(grant, challenge=b"x" * kr2.CHALLENGE_SIZE),
        replace(
            grant,
            client_ephemeral_key=bytes([4]) + b"x" * 64),
    )

    for changed in mutations:
        with pytest.raises(kr2.ProtocolError, match="does not match request"):
            kr2.encode_transcript(request, changed)


def test_model_bounds_fail_closed():
    request, grant, _response = _models()
    with pytest.raises(kr2.ProtocolError, match="canonical identifier"):
        replace(request, license_id="x" * (kr2.MAX_LICENSE_ID_SIZE + 1))
    with pytest.raises(kr2.ProtocolError, match="ciphertext exceeds"):
        replace(grant, ciphertext=b"x" * (kr2.MAX_CIPHERTEXT_SIZE + 1))
    with pytest.raises(kr2.ProtocolError, match="grant lifetime exceeds"):
        replace(
            grant,
            expires_at=grant.issued_at + kr2.MAX_GRANT_LIFETIME_SECONDS + 1)
    with pytest.raises(kr2.ProtocolError, match="uncompressed SEC1"):
        replace(grant, server_ephemeral_key=b"x" * kr2.EPHEMERAL_KEY_SIZE)
    with pytest.raises(kr2.ProtocolError, match="signature"):
        kr2.KeyReleaseResponse(grant, b"short")
