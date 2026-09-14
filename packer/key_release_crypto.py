"""Reference cryptography for the Lethe Key Release v2 protocol.

Suite (fixed for protocol version 2):

* ECDH over NIST P-256 using uncompressed SEC1 public points;
* HKDF-SHA256 to a 32-byte release key;
* AES-256-GCM over exactly one 32-byte release share;
* ECDSA-P256/SHA-256 with a fixed 64-byte IEEE-P1363 ``r || s`` signature.

This module performs no networking, persistence, replay accounting, or runtime
handoff.  It is the Python reference that backend and native implementations
must match byte-for-byte.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import replace
from typing import Final

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import key_release_protocol as protocol


RELEASE_SHARE_SIZE: Final = 32
AES_KEY_SIZE: Final = 32
GCM_TAG_SIZE: Final = 16

HKDF_SALT_DOMAIN: Final = b"LETHE-KR2-HKDF-SALT\x00"
HKDF_INFO_DOMAIN: Final = b"LETHE-KR2-RELEASE-SHARE-AES256GCM\x00"

_P256_ORDER: Final = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
_P256_HALF_ORDER: Final = _P256_ORDER // 2
_MAX_I64: Final = (1 << 63) - 1


class KeyReleaseCryptoError(ValueError):
    """A KR2 cryptographic key, binding, signature, time, or tag is invalid."""


def _require_bytes(name: str, value: bytes, size: int) -> None:
    if type(value) is not bytes or len(value) != size:
        raise KeyReleaseCryptoError(f"{name} must be exactly {size} bytes")


def _require_private_key(name: str, key) -> ec.EllipticCurvePrivateKey:
    if (not isinstance(key, ec.EllipticCurvePrivateKey)
            or not isinstance(key.curve, ec.SECP256R1)):
        raise KeyReleaseCryptoError(f"{name} must be a P-256 private key")
    return key


def _require_public_key(name: str, key) -> ec.EllipticCurvePublicKey:
    if (not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)):
        raise KeyReleaseCryptoError(f"{name} must be a P-256 public key")
    return key


def generate_p256_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_key_sec1(key) -> bytes:
    """Return a P-256 public key as ``0x04 || X[32] || Y[32]``."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        key = _require_private_key("key", key).public_key()
    public_key = _require_public_key("key", key)
    return public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def load_p256_public_key(encoded: bytes) -> ec.EllipticCurvePublicKey:
    """Parse and validate an uncompressed SEC1 point on NIST P-256."""
    _require_bytes("encoded public key", encoded, protocol.EPHEMERAL_KEY_SIZE)
    if encoded[0] != 0x04:
        raise KeyReleaseCryptoError(
            "encoded public key must be an uncompressed SEC1 point")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), encoded)
    except ValueError as exc:
        raise KeyReleaseCryptoError(
            "encoded public key is not a valid P-256 point") from exc
    return _require_public_key("encoded public key", key)


def _validate_binding(request: protocol.KeyReleaseRequest,
                      grant: protocol.KeyReleaseGrant) -> None:
    try:
        protocol.validate_response_binding(request, grant)
    except protocol.ProtocolError as exc:
        raise KeyReleaseCryptoError(str(exc)) from exc


def _validate_time_relationship(request: protocol.KeyReleaseRequest,
                                grant: protocol.KeyReleaseGrant) -> None:
    if grant.issued_at < request.requested_at:
        raise KeyReleaseCryptoError(
            "grant issued_at precedes the signed request timestamp")


def _require_now(now: int) -> None:
    if type(now) is not int or not 0 <= now <= _MAX_I64:
        raise KeyReleaseCryptoError(
            "current time must be a non-negative signed-64-bit integer")


def _signature_to_p1363(der_signature: bytes) -> bytes:
    r, s = decode_dss_signature(der_signature)
    if not 1 <= r < _P256_ORDER or not 1 <= s < _P256_ORDER:
        raise KeyReleaseCryptoError("ECDSA signer returned an invalid scalar")
    if s > _P256_HALF_ORDER:
        s = _P256_ORDER - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _signature_to_der(signature: bytes) -> bytes:
    _require_bytes("signature", signature, protocol.SIGNATURE_SIZE)
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not 1 <= r < _P256_ORDER or not 1 <= s < _P256_ORDER:
        raise KeyReleaseCryptoError("signature contains an invalid P-256 scalar")
    if s > _P256_HALF_ORDER:
        raise KeyReleaseCryptoError("signature contains a non-canonical high-S scalar")
    return encode_dss_signature(r, s)


def _derive_key_from_aad(local_private_key, peer_public_sec1: bytes,
                         aad: bytes) -> bytes:
    private_key = _require_private_key("local private key", local_private_key)
    peer_public = load_p256_public_key(peer_public_sec1)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public)
    if len(shared_secret) != 32:
        raise KeyReleaseCryptoError("P-256 ECDH returned a non-canonical secret")
    context_hash = hashlib.sha256(aad).digest()
    salt = hashlib.sha256(HKDF_SALT_DOMAIN + context_hash).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=HKDF_INFO_DOMAIN + context_hash,
    ).derive(shared_secret)


def derive_release_key(local_private_key, peer_public_sec1: bytes,
                       request: protocol.KeyReleaseRequest,
                       grant: protocol.KeyReleaseGrant) -> bytes:
    """Derive the bound AES key from either side of the P-256 exchange."""
    _validate_binding(request, grant)
    _validate_time_relationship(request, grant)
    private_key = _require_private_key("local private key", local_private_key)
    local_public = public_key_sec1(private_key)
    if local_public == grant.client_ephemeral_key:
        expected_peer = grant.server_ephemeral_key
    elif local_public == grant.server_ephemeral_key:
        expected_peer = grant.client_ephemeral_key
    else:
        raise KeyReleaseCryptoError(
            "local private key does not match either bound ephemeral key")
    if peer_public_sec1 != expected_peer:
        raise KeyReleaseCryptoError(
            "peer public key does not match the bound ECDH role")
    aad = protocol.encode_grant_aad(request, grant)
    return _derive_key_from_aad(private_key, peer_public_sec1, aad)


def sign_response(request: protocol.KeyReleaseRequest,
                  grant: protocol.KeyReleaseGrant,
                  signing_private_key) -> protocol.KeyReleaseResponse:
    """Sign the complete request + ciphertext-bearing grant transcript."""
    _validate_binding(request, grant)
    _validate_time_relationship(request, grant)
    private_key = _require_private_key(
        "server signing private key", signing_private_key)
    transcript = protocol.encode_transcript(request, grant)
    der_signature = private_key.sign(
        transcript, ec.ECDSA(hashes.SHA256()))
    return protocol.KeyReleaseResponse(
        grant=grant,
        signature=_signature_to_p1363(der_signature),
    )


def verify_response_signature(request: protocol.KeyReleaseRequest,
                              response: protocol.KeyReleaseResponse,
                              signing_public_key) -> None:
    """Verify the fixed-width ECDSA signature over the canonical transcript."""
    if not isinstance(response, protocol.KeyReleaseResponse):
        raise KeyReleaseCryptoError(
            "response must be a KeyReleaseResponse")
    _validate_binding(request, response.grant)
    _validate_time_relationship(request, response.grant)
    public_key = _require_public_key(
        "server signing public key", signing_public_key)
    transcript = protocol.encode_transcript(request, response.grant)
    signature = _signature_to_der(response.signature)
    try:
        public_key.verify(
            signature, transcript, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise KeyReleaseCryptoError(
            "response signature verification failed") from exc


def seal_release_share(
        request: protocol.KeyReleaseRequest,
        release_share: bytes,
        server_ephemeral_private_key,
        server_signing_private_key,
        *,
        launch_id: bytes,
        issued_at: int,
        expires_at: int,
        nonce: bytes | None = None) -> protocol.KeyReleaseResponse:
    """Encrypt one 32-byte release share and sign its response transcript."""
    _require_bytes("release share", release_share, RELEASE_SHARE_SIZE)
    _require_bytes("launch_id", launch_id, protocol.LAUNCH_ID_SIZE)
    if nonce is None:
        nonce = os.urandom(protocol.AEAD_NONCE_SIZE)
    _require_bytes("nonce", nonce, protocol.AEAD_NONCE_SIZE)

    server_private = _require_private_key(
        "server ephemeral private key", server_ephemeral_private_key)
    server_public = public_key_sec1(server_private)
    client_public = load_p256_public_key(request.client_ephemeral_key)
    placeholder = bytes(RELEASE_SHARE_SIZE + GCM_TAG_SIZE)
    grant = protocol.KeyReleaseGrant(
        build_id=request.build_id,
        license_id=request.license_id,
        device_id=request.device_id,
        challenge=request.challenge,
        client_ephemeral_key=request.client_ephemeral_key,
        server_ephemeral_key=server_public,
        launch_id=launch_id,
        issued_at=issued_at,
        expires_at=expires_at,
        ciphertext_nonce=nonce,
        ciphertext=placeholder,
    )
    _validate_time_relationship(request, grant)
    aad = protocol.encode_grant_aad(request, grant)
    key = _derive_key_from_aad(server_private, public_key_sec1(client_public), aad)
    ciphertext = AESGCM(key).encrypt(nonce, release_share, aad)
    if len(ciphertext) != RELEASE_SHARE_SIZE + GCM_TAG_SIZE:
        raise KeyReleaseCryptoError("AES-GCM returned an unexpected ciphertext size")
    return sign_response(
        request, replace(grant, ciphertext=ciphertext),
        server_signing_private_key)


def open_release_share(
        request: protocol.KeyReleaseRequest,
        response: protocol.KeyReleaseResponse,
        client_ephemeral_private_key,
        server_signing_public_key,
        *,
        now: int | None = None) -> bytes:
    """Verify first, then decrypt and return the exact 32-byte release share."""
    if not isinstance(response, protocol.KeyReleaseResponse):
        raise KeyReleaseCryptoError("response must be a KeyReleaseResponse")
    client_private = _require_private_key(
        "client ephemeral private key", client_ephemeral_private_key)
    if public_key_sec1(client_private) != request.client_ephemeral_key:
        raise KeyReleaseCryptoError(
            "client private key does not match the signed request")

    # Authenticity is established before parsing the peer point, deriving a
    # secret, or asking AES-GCM to process attacker-controlled ciphertext.
    verify_response_signature(request, response, server_signing_public_key)

    effective_now = int(time.time()) if now is None else now
    _require_now(effective_now)
    grant = response.grant
    if effective_now < grant.issued_at:
        raise KeyReleaseCryptoError("release grant is not yet valid")
    if effective_now >= grant.expires_at:
        raise KeyReleaseCryptoError("release grant has expired")

    key = derive_release_key(
        client_private, grant.server_ephemeral_key, request, grant)
    aad = protocol.encode_grant_aad(request, grant)
    try:
        share = AESGCM(key).decrypt(
            grant.ciphertext_nonce, grant.ciphertext, aad)
    except InvalidTag as exc:
        raise KeyReleaseCryptoError(
            "release-share ciphertext authentication failed") from exc
    if len(share) != RELEASE_SHARE_SIZE:
        raise KeyReleaseCryptoError(
            "decrypted release share is not exactly 32 bytes")
    return share


__all__ = [
    "AES_KEY_SIZE",
    "GCM_TAG_SIZE",
    "HKDF_INFO_DOMAIN",
    "HKDF_SALT_DOMAIN",
    "KeyReleaseCryptoError",
    "RELEASE_SHARE_SIZE",
    "derive_release_key",
    "generate_p256_private_key",
    "load_p256_public_key",
    "open_release_share",
    "public_key_sec1",
    "seal_release_share",
    "sign_response",
    "verify_response_signature",
]
