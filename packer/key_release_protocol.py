"""Canonical binary wire format for the Lethe Key Release v2 protocol.

This module owns serialization only.  It deliberately performs no networking,
signature verification, ECDH, or key release.  Keeping the format independent
from those concerns gives the Python builder, backend, bootstrap, and native
stub one bounded transcript with stable golden vectors.

Every record uses the following big-endian framing::

    magic[4] | version:u8 | kind:u8 | field_count:u16 | body_size:u32
    repeated: tag:u8 | value_size:u32 | value[value_size]

Tags must appear exactly once and in increasing order.  Decoders reject unknown
tags, alternate orderings, trailing bytes, overlong values, and non-canonical
identifiers.  A response signature covers ``encode_transcript(request, grant)``.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Final, Mapping, Sequence


PROTOCOL_VERSION: Final = 2

BUILD_ID_SIZE: Final = 32
DEVICE_ID_SIZE: Final = 32
CHALLENGE_SIZE: Final = 32
EPHEMERAL_KEY_SIZE: Final = 65
LAUNCH_ID_SIZE: Final = 16
AEAD_NONCE_SIZE: Final = 12
SIGNATURE_SIZE: Final = 64

MAX_LICENSE_ID_SIZE: Final = 128
MAX_CIPHERTEXT_SIZE: Final = 1024
MAX_GRANT_LIFETIME_SECONDS: Final = 300
MAX_REQUEST_SIZE: Final = 1024
MAX_GRANT_SIZE: Final = 2048
MAX_RESPONSE_SIZE: Final = 2304
MAX_TRANSCRIPT_SIZE: Final = 4096
MAX_GRANT_AAD_SIZE: Final = 2048

_MAGIC: Final = b"LKR2"
_HEADER = struct.Struct(">4sBBHI")
_FIELD_HEADER = struct.Struct(">BI")
_U64 = struct.Struct(">Q")
_MAX_I64: Final = (1 << 63) - 1

_KIND_REQUEST: Final = 1
_KIND_RESPONSE: Final = 2
_KIND_TRANSCRIPT: Final = 3
_KIND_GRANT: Final = 4
_KIND_GRANT_AAD: Final = 5

_REQUEST_TAGS: Final = (1, 2, 3, 4, 5, 6)
_GRANT_TAGS: Final = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
_RESPONSE_TAGS: Final = (1, 2)
_TRANSCRIPT_TAGS: Final = (1, 2)

_IDENTIFIER = re.compile(rb"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class ProtocolError(ValueError):
    """The message or model violates the canonical KR2 wire contract."""


def _require_bytes(name: str, value: bytes, size: int | None = None, *,
                   minimum: int = 0, maximum: int | None = None) -> None:
    if type(value) is not bytes:
        raise ProtocolError(f"{name} must be bytes")
    if size is not None and len(value) != size:
        raise ProtocolError(f"{name} must be exactly {size} bytes")
    if len(value) < minimum:
        raise ProtocolError(f"{name} must be at least {minimum} bytes")
    if maximum is not None and len(value) > maximum:
        raise ProtocolError(f"{name} exceeds {maximum} bytes")


def _require_identifier(name: str, value: str) -> None:
    if type(value) is not str:
        raise ProtocolError(f"{name} must be a string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolError(f"{name} must contain canonical ASCII") from exc
    if not _IDENTIFIER.fullmatch(encoded):
        raise ProtocolError(
            f"{name} must be 1-{MAX_LICENSE_ID_SIZE} canonical identifier bytes")


def _identifier_bytes(name: str, value: str) -> bytes:
    _require_identifier(name, value)
    return value.encode("ascii")


def _decode_identifier(name: str, value: bytes) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ProtocolError(
            f"{name} must be 1-{MAX_LICENSE_ID_SIZE} canonical identifier bytes")
    return value.decode("ascii")


def _require_timestamp(name: str, value: int) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_I64:
        raise ProtocolError(f"{name} must be a non-negative signed-64-bit integer")


def _timestamp_bytes(name: str, value: int) -> bytes:
    _require_timestamp(name, value)
    return _U64.pack(value)


def _decode_timestamp(name: str, value: bytes) -> int:
    if len(value) != _U64.size:
        raise ProtocolError(f"{name} must use the canonical 8-byte encoding")
    decoded = _U64.unpack(value)[0]
    _require_timestamp(name, decoded)
    return decoded


def _require_ephemeral_key(name: str, value: bytes) -> None:
    _require_bytes(name, value, EPHEMERAL_KEY_SIZE)
    if value[0] != 0x04:
        raise ProtocolError(
            f"{name} must be an uncompressed SEC1 P-256 public key")


@dataclass(frozen=True)
class KeyReleaseRequest:
    build_id: bytes
    license_id: str
    device_id: bytes
    challenge: bytes
    client_ephemeral_key: bytes
    requested_at: int

    def __post_init__(self) -> None:
        _require_bytes("build_id", self.build_id, BUILD_ID_SIZE)
        _require_identifier("license_id", self.license_id)
        _require_bytes("device_id", self.device_id, DEVICE_ID_SIZE)
        _require_bytes("challenge", self.challenge, CHALLENGE_SIZE)
        _require_ephemeral_key(
            "client_ephemeral_key", self.client_ephemeral_key)
        _require_timestamp("requested_at", self.requested_at)


@dataclass(frozen=True)
class KeyReleaseGrant:
    build_id: bytes
    license_id: str
    device_id: bytes
    challenge: bytes
    client_ephemeral_key: bytes
    server_ephemeral_key: bytes
    launch_id: bytes
    issued_at: int
    expires_at: int
    ciphertext_nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        _require_bytes("build_id", self.build_id, BUILD_ID_SIZE)
        _require_identifier("license_id", self.license_id)
        _require_bytes("device_id", self.device_id, DEVICE_ID_SIZE)
        _require_bytes("challenge", self.challenge, CHALLENGE_SIZE)
        _require_ephemeral_key(
            "client_ephemeral_key", self.client_ephemeral_key)
        _require_ephemeral_key(
            "server_ephemeral_key", self.server_ephemeral_key)
        _require_bytes("launch_id", self.launch_id, LAUNCH_ID_SIZE)
        _require_timestamp("issued_at", self.issued_at)
        _require_timestamp("expires_at", self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ProtocolError("expires_at must be later than issued_at")
        if self.expires_at - self.issued_at > MAX_GRANT_LIFETIME_SECONDS:
            raise ProtocolError(
                f"grant lifetime exceeds {MAX_GRANT_LIFETIME_SECONDS} seconds")
        _require_bytes(
            "ciphertext_nonce", self.ciphertext_nonce, AEAD_NONCE_SIZE)
        _require_bytes(
            "ciphertext", self.ciphertext, minimum=16,
            maximum=MAX_CIPHERTEXT_SIZE)


@dataclass(frozen=True)
class KeyReleaseResponse:
    grant: KeyReleaseGrant
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.grant, KeyReleaseGrant):
            raise ProtocolError("grant must be a KeyReleaseGrant")
        _require_bytes("signature", self.signature, SIGNATURE_SIZE)


def _pack_message(kind: int, fields: Sequence[tuple[int, bytes]], *,
                  maximum: int) -> bytes:
    body = bytearray()
    previous = 0
    for tag, value in fields:
        if not 1 <= tag <= 255:
            raise ProtocolError("field tag is outside the u8 range")
        if tag <= previous:
            raise ProtocolError("fields must be unique and in canonical order")
        _require_bytes(f"field {tag}", value)
        body += _FIELD_HEADER.pack(tag, len(value))
        body += value
        previous = tag
    message = _HEADER.pack(
        _MAGIC, PROTOCOL_VERSION, kind, len(fields), len(body)) + bytes(body)
    if len(message) > maximum:
        raise ProtocolError(f"encoded message exceeds {maximum} bytes")
    return message


def _parse_message(data: bytes, *, expected_kind: int,
                   expected_tags: tuple[int, ...], maximum: int) -> Mapping[int, bytes]:
    _require_bytes("message", data)
    if len(data) > maximum:
        raise ProtocolError(f"message exceeds {maximum} bytes")
    if len(data) < _HEADER.size:
        raise ProtocolError("truncated message header")

    magic, version, kind, field_count, body_size = _HEADER.unpack_from(data)
    if magic != _MAGIC:
        raise ProtocolError("bad KR2 message magic")
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported KR2 version {version}")
    if kind != expected_kind:
        raise ProtocolError(f"unexpected KR2 message kind {kind}")
    if field_count != len(expected_tags):
        raise ProtocolError(
            f"unexpected field count {field_count}; expected {len(expected_tags)}")
    if body_size != len(data) - _HEADER.size:
        raise ProtocolError("non-canonical body size or trailing bytes")

    cursor = _HEADER.size
    previous = 0
    fields: dict[int, bytes] = {}
    for _ in range(field_count):
        if cursor + _FIELD_HEADER.size > len(data):
            raise ProtocolError("truncated field header")
        tag, value_size = _FIELD_HEADER.unpack_from(data, cursor)
        cursor += _FIELD_HEADER.size
        if tag in fields:
            raise ProtocolError(f"duplicate field tag {tag}")
        if tag <= previous:
            raise ProtocolError("fields are not in canonical order")
        if tag not in expected_tags:
            raise ProtocolError(f"unknown field tag {tag}")
        if value_size > maximum:
            raise ProtocolError(f"field {tag} exceeds message bound")
        end = cursor + value_size
        if end > len(data):
            raise ProtocolError(f"truncated field {tag}")
        fields[tag] = data[cursor:end]
        cursor = end
        previous = tag

    if cursor != len(data):
        raise ProtocolError("trailing bytes after final field")
    if tuple(fields) != expected_tags:
        missing = sorted(set(expected_tags) - set(fields))
        raise ProtocolError(f"missing required field tag(s): {missing}")
    return fields


def encode_request(request: KeyReleaseRequest) -> bytes:
    if not isinstance(request, KeyReleaseRequest):
        raise ProtocolError("request must be a KeyReleaseRequest")
    return _pack_message(_KIND_REQUEST, (
        (1, request.build_id),
        (2, _identifier_bytes("license_id", request.license_id)),
        (3, request.device_id),
        (4, request.challenge),
        (5, request.client_ephemeral_key),
        (6, _timestamp_bytes("requested_at", request.requested_at)),
    ), maximum=MAX_REQUEST_SIZE)


def decode_request(data: bytes) -> KeyReleaseRequest:
    fields = _parse_message(
        data, expected_kind=_KIND_REQUEST,
        expected_tags=_REQUEST_TAGS, maximum=MAX_REQUEST_SIZE)
    return KeyReleaseRequest(
        build_id=fields[1],
        license_id=_decode_identifier("license_id", fields[2]),
        device_id=fields[3],
        challenge=fields[4],
        client_ephemeral_key=fields[5],
        requested_at=_decode_timestamp("requested_at", fields[6]),
    )


def _encode_grant(grant: KeyReleaseGrant) -> bytes:
    if not isinstance(grant, KeyReleaseGrant):
        raise ProtocolError("grant must be a KeyReleaseGrant")
    return _pack_message(_KIND_GRANT, (
        (1, grant.build_id),
        (2, _identifier_bytes("license_id", grant.license_id)),
        (3, grant.device_id),
        (4, grant.challenge),
        (5, grant.client_ephemeral_key),
        (6, grant.server_ephemeral_key),
        (7, grant.launch_id),
        (8, _timestamp_bytes("issued_at", grant.issued_at)),
        (9, _timestamp_bytes("expires_at", grant.expires_at)),
        (10, grant.ciphertext_nonce),
        (11, grant.ciphertext),
    ), maximum=MAX_GRANT_SIZE)


def _decode_grant(data: bytes) -> KeyReleaseGrant:
    fields = _parse_message(
        data, expected_kind=_KIND_GRANT,
        expected_tags=_GRANT_TAGS, maximum=MAX_GRANT_SIZE)
    return KeyReleaseGrant(
        build_id=fields[1],
        license_id=_decode_identifier("license_id", fields[2]),
        device_id=fields[3],
        challenge=fields[4],
        client_ephemeral_key=fields[5],
        server_ephemeral_key=fields[6],
        launch_id=fields[7],
        issued_at=_decode_timestamp("issued_at", fields[8]),
        expires_at=_decode_timestamp("expires_at", fields[9]),
        ciphertext_nonce=fields[10],
        ciphertext=fields[11],
    )


def encode_response(response: KeyReleaseResponse) -> bytes:
    if not isinstance(response, KeyReleaseResponse):
        raise ProtocolError("response must be a KeyReleaseResponse")
    return _pack_message(_KIND_RESPONSE, (
        (1, _encode_grant(response.grant)),
        (2, response.signature),
    ), maximum=MAX_RESPONSE_SIZE)


def decode_response(data: bytes) -> KeyReleaseResponse:
    fields = _parse_message(
        data, expected_kind=_KIND_RESPONSE,
        expected_tags=_RESPONSE_TAGS, maximum=MAX_RESPONSE_SIZE)
    return KeyReleaseResponse(
        grant=_decode_grant(fields[1]),
        signature=fields[2],
    )


_BOUND_FIELDS: Final = (
    "build_id", "license_id", "device_id", "challenge",
    "client_ephemeral_key",
)


def validate_response_binding(request: KeyReleaseRequest,
                              response: KeyReleaseResponse | KeyReleaseGrant) -> None:
    """Reject a grant that does not echo every request identity field exactly."""
    if not isinstance(request, KeyReleaseRequest):
        raise ProtocolError("request must be a KeyReleaseRequest")
    grant = response.grant if isinstance(response, KeyReleaseResponse) else response
    if not isinstance(grant, KeyReleaseGrant):
        raise ProtocolError("response must be a KeyReleaseResponse or KeyReleaseGrant")
    for name in _BOUND_FIELDS:
        if getattr(request, name) != getattr(grant, name):
            raise ProtocolError(f"response {name} does not match request")


def encode_transcript(request: KeyReleaseRequest,
                      grant: KeyReleaseGrant) -> bytes:
    """Return the canonical bytes covered by the server response signature."""
    validate_response_binding(request, grant)
    return _pack_message(_KIND_TRANSCRIPT, (
        (1, encode_request(request)),
        (2, _encode_grant(grant)),
    ), maximum=MAX_TRANSCRIPT_SIZE)


def encode_grant_aad(request: KeyReleaseRequest,
                     grant: KeyReleaseGrant) -> bytes:
    """Canonical AES-GCM context excluding ciphertext and signature.

    The request timestamp is included alongside every response identity and
    key-agreement field.  Ciphertext is deliberately absent to avoid a circular
    AEAD dependency; it is covered by :func:`encode_transcript` and the response
    signature after encryption.
    """
    validate_response_binding(request, grant)
    return _pack_message(_KIND_GRANT_AAD, (
        (1, grant.build_id),
        (2, _identifier_bytes("license_id", grant.license_id)),
        (3, grant.device_id),
        (4, grant.challenge),
        (5, grant.client_ephemeral_key),
        (6, _timestamp_bytes("requested_at", request.requested_at)),
        (7, grant.server_ephemeral_key),
        (8, grant.launch_id),
        (9, _timestamp_bytes("issued_at", grant.issued_at)),
        (10, _timestamp_bytes("expires_at", grant.expires_at)),
        (11, grant.ciphertext_nonce),
    ), maximum=MAX_GRANT_AAD_SIZE)


def decode_transcript(data: bytes) -> tuple[KeyReleaseRequest, KeyReleaseGrant]:
    """Strictly decode a stored golden transcript or backend audit record."""
    fields = _parse_message(
        data, expected_kind=_KIND_TRANSCRIPT,
        expected_tags=_TRANSCRIPT_TAGS, maximum=MAX_TRANSCRIPT_SIZE)
    request = decode_request(fields[1])
    grant = _decode_grant(fields[2])
    validate_response_binding(request, grant)
    return request, grant


__all__ = [
    "AEAD_NONCE_SIZE",
    "BUILD_ID_SIZE",
    "CHALLENGE_SIZE",
    "DEVICE_ID_SIZE",
    "EPHEMERAL_KEY_SIZE",
    "KeyReleaseGrant",
    "KeyReleaseRequest",
    "KeyReleaseResponse",
    "LAUNCH_ID_SIZE",
    "MAX_CIPHERTEXT_SIZE",
    "MAX_GRANT_LIFETIME_SECONDS",
    "MAX_GRANT_AAD_SIZE",
    "MAX_GRANT_SIZE",
    "MAX_LICENSE_ID_SIZE",
    "MAX_REQUEST_SIZE",
    "MAX_RESPONSE_SIZE",
    "MAX_TRANSCRIPT_SIZE",
    "PROTOCOL_VERSION",
    "ProtocolError",
    "SIGNATURE_SIZE",
    "decode_request",
    "decode_response",
    "decode_transcript",
    "encode_request",
    "encode_response",
    "encode_grant_aad",
    "encode_transcript",
    "validate_response_binding",
]
