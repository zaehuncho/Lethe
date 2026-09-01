"""Reference-suite and tamper tests for KR2 cryptographic interoperability."""
from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from packer import key_release_crypto as crypto
from packer import key_release_protocol as protocol


REQUESTED_AT = 1_770_000_000
ISSUED_AT = REQUESTED_AT + 5
EXPIRES_AT = ISSUED_AT + 60
NONCE = bytes(range(12))
SHARE = bytes(range(128, 160))
P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
CRYPTO_VECTOR_PATH = Path(__file__).parent / "vectors" / "key_release_crypto_v2.txt"


def _crypto_vectors():
    values = {}
    for raw_line in CRYPTO_VECTOR_PATH.read_text(encoding="ascii").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, encoded = line.split("=", 1)
        assert name not in values
        values[name] = bytes.fromhex(encoded)
    return values


def _private(scalar: int):
    return ec.derive_private_key(scalar, ec.SECP256R1())


def _keys():
    return _private(0x12345), _private(0x23456), _private(0x34567)


def _request(client_private=None):
    client_private = client_private or _keys()[0]
    return protocol.KeyReleaseRequest(
        build_id=bytes(range(32)),
        license_id="LIC-2026_A",
        device_id=bytes(range(32, 64)),
        challenge=bytes(range(64, 96)),
        client_ephemeral_key=crypto.public_key_sec1(client_private),
        requested_at=REQUESTED_AT,
    )


def _sealed():
    client, server, signer = _keys()
    request = _request(client)
    response = crypto.seal_release_share(
        request, SHARE, server, signer,
        launch_id=bytes(range(16, 32)),
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        nonce=NONCE,
    )
    return client, server, signer, request, response


def test_reference_suite_round_trip_and_fixed_interop_vector():
    client, server, signer, request, response = _sealed()
    grant = response.grant
    aad = protocol.encode_grant_aad(request, grant)
    client_key = crypto.derive_release_key(
        client, grant.server_ephemeral_key, request, grant)
    server_key = crypto.derive_release_key(
        server, grant.client_ephemeral_key, request, grant)

    assert client_key == server_key
    assert crypto.public_key_sec1(client).hex() == (
        "0450d4670bde75244f28d2838a0d25558a7a72686d4522d4c8273fb6442aebfa93"
        "dbdd37551afd263b5dfd617f3960c65a8c298850ff99f20366dce7d4367217f4")
    assert crypto.public_key_sec1(server).hex() == (
        "04758a142779be89e829e71984cb40ef758cc4ad775fc5b9a3e1c8ed52f6fa36d9"
        "a79d247692f4eda3a6bdab77d6aa6474a464ae4934663c5265ba7018ba091f79")
    assert crypto.public_key_sec1(signer).hex() == (
        "04269d4c8fdeb66a74e4ef8c0d5dcc597ddfe6029c2affc4936008cd2cc1045d816"
        "dda6a1310f4b067bd5dabdad741b7cef36457e196b1bfa97fd5f8fbb3926adb")
    assert client_key.hex() == (
        "8e393a1a1bd4f35b29a5a27f0abb4180"
        "fd9a26312dab2908f1373f1f04069d37")
    assert grant.ciphertext.hex() == (
        "7eba2d987cdc77f3d2dccbf3cd7b18e85d928e8b1808a5f85685a851cdb68552"
        "e0a0e5ee49b5d79ae2ec867529edb663")
    assert len(aad) == 355
    assert hashlib.sha256(aad).hexdigest() == (
        "29e5c58a1e193867e449f3a664ff4c570f14bb236b89848c85e134b439845d8b")
    assert hashlib.sha256(
        protocol.encode_transcript(request, grant)).hexdigest() == (
            "5d5c99c570229e3da15d60d35d059d51c01a047d335d258e92759ed5914769ae")
    assert len(response.signature) == protocol.SIGNATURE_SIZE
    assert int.from_bytes(response.signature[32:], "big") <= P256_ORDER // 2

    wire_response = protocol.decode_response(protocol.encode_response(response))
    crypto.verify_response_signature(request, wire_response, signer.public_key())
    assert crypto.open_release_share(
        request, wire_response, client, signer.public_key(),
        now=ISSUED_AT + 1) == SHARE


def test_stored_python_native_crypto_vectors_are_self_consistent():
    vectors = _crypto_vectors()
    request = protocol.decode_request(vectors["request"])
    response = protocol.decode_response(vectors["response"])
    bad_tag_response = protocol.decode_response(
        vectors["response_bad_tag_signed"])
    invalid_server_response = protocol.decode_response(
        vectors["response_invalid_server_signed"])
    client = ec.derive_private_key(
        int.from_bytes(vectors["client_private"], "big"), ec.SECP256R1())
    signer = crypto.load_p256_public_key(vectors["signing_public"])

    assert protocol.encode_transcript(request, response.grant) == \
        vectors["transcript"]
    assert protocol.encode_grant_aad(request, response.grant) == vectors["aad"]
    assert request.client_ephemeral_key == vectors["client_public"]
    assert response.grant.server_ephemeral_key == vectors["server_public"]
    assert response.grant.ciphertext_nonce == vectors["nonce"]
    assert response.grant.ciphertext == vectors["ciphertext"]
    assert response.signature == vectors["signature"]
    assert crypto.derive_release_key(
        client, response.grant.server_ephemeral_key,
        request, response.grant) == vectors["aes_key"]
    assert crypto.open_release_share(
        request, response, client, signer, now=ISSUED_AT) == vectors["share"]

    crypto.verify_response_signature(request, bad_tag_response, signer)
    with pytest.raises(
            crypto.KeyReleaseCryptoError, match="ciphertext authentication failed"):
        crypto.open_release_share(
            request, bad_tag_response, client, signer, now=ISSUED_AT)
    crypto.verify_response_signature(request, invalid_server_response, signer)
    with pytest.raises(crypto.KeyReleaseCryptoError, match="valid P-256 point"):
        crypto.open_release_share(
            request, invalid_server_response, client, signer, now=ISSUED_AT)


def test_grant_aad_has_a_stable_canonical_encoding():
    _client, _server, _signer, request, response = _sealed()

    assert protocol.encode_grant_aad(request, response.grant).hex() == (
        "4c4b52320205000b000001570100000020000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f020000000a4c49432d323032365f410300"
        "000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d"
        "3e3f0400000020404142434445464748494a4b4c4d4e4f50515253545556575859"
        "5a5b5c5d5e5f05000000410450d4670bde75244f28d2838a0d25558a7a72686d"
        "4522d4c8273fb6442aebfa93dbdd37551afd263b5dfd617f3960c65a8c298850f"
        "f99f20366dce7d4367217f406000000080000000069800e80070000004104758a"
        "142779be89e829e71984cb40ef758cc4ad775fc5b9a3e1c8ed52f6fa36d9a79d"
        "247692f4eda3a6bdab77d6aa6474a464ae4934663c5265ba7018ba091f79080000"
        "0010101112131415161718191a1b1c1d1e1f09000000080000000069800e850a00"
        "0000080000000069800ec10b0000000c000102030405060708090a0b")


def test_aad_binds_every_identity_key_time_and_nonce_field():
    _client, _server, _signer, request, response = _sealed()
    grant = response.grant
    original = protocol.encode_grant_aad(request, grant)
    other_client = crypto.public_key_sec1(_private(0x45678))
    other_server = crypto.public_key_sec1(_private(0x56789))
    mutations = (
        (replace(request, build_id=b"b" * 32),
         replace(grant, build_id=b"b" * 32)),
        (replace(request, license_id="LIC-OTHER"),
         replace(grant, license_id="LIC-OTHER")),
        (replace(request, device_id=b"d" * 32),
         replace(grant, device_id=b"d" * 32)),
        (replace(request, challenge=b"c" * 32),
         replace(grant, challenge=b"c" * 32)),
        (replace(request, client_ephemeral_key=other_client),
         replace(grant, client_ephemeral_key=other_client)),
        (replace(request, requested_at=REQUESTED_AT + 1), grant),
        (request, replace(grant, server_ephemeral_key=other_server)),
        (request, replace(grant, launch_id=b"l" * 16)),
        (request, replace(grant, issued_at=ISSUED_AT + 1)),
        (request, replace(grant, expires_at=EXPIRES_AT - 1)),
        (request, replace(grant, ciphertext_nonce=b"n" * 12)),
    )

    for changed_request, changed_grant in mutations:
        assert protocol.encode_grant_aad(
            changed_request, changed_grant) != original

    ciphertext_only = replace(grant, ciphertext=b"x" * len(grant.ciphertext))
    assert protocol.encode_grant_aad(request, ciphertext_only) == original
    assert protocol.encode_transcript(request, ciphertext_only) != \
        protocol.encode_transcript(request, grant)


def test_signature_verification_precedes_ciphertext_processing():
    client, _server, signer, request, response = _sealed()
    changed = bytearray(response.grant.ciphertext)
    changed[0] ^= 1
    unsigned_tamper = protocol.KeyReleaseResponse(
        replace(response.grant, ciphertext=bytes(changed)),
        response.signature,
    )

    with pytest.raises(
            crypto.KeyReleaseCryptoError, match="signature verification failed"):
        crypto.open_release_share(
            request, unsigned_tamper, client, signer.public_key(), now=ISSUED_AT)


@pytest.mark.parametrize("field,value", [
    ("ciphertext", b"x" * 48),
    ("ciphertext_nonce", b"n" * 12),
    ("launch_id", b"l" * 16),
    ("expires_at", EXPIRES_AT - 1),
    ("server_ephemeral_key", crypto.public_key_sec1(_private(0x56789))),
])
def test_validly_signed_aead_context_tamper_fails_authentication(field, value):
    client, _server, signer, request, response = _sealed()
    changed_grant = replace(response.grant, **{field: value})
    resigned = crypto.sign_response(request, changed_grant, signer)

    with pytest.raises(
            crypto.KeyReleaseCryptoError, match="ciphertext authentication failed"):
        crypto.open_release_share(
            request, resigned, client, signer.public_key(), now=ISSUED_AT)


@pytest.mark.parametrize("field,value", [
    ("build_id", b"b" * 32),
    ("license_id", "LIC-OTHER"),
    ("device_id", b"d" * 32),
    ("challenge", b"c" * 32),
])
def test_wrong_request_identity_is_rejected(field, value):
    client, _server, signer, request, response = _sealed()
    wrong_request = replace(request, **{field: value})

    with pytest.raises(crypto.KeyReleaseCryptoError, match="does not match request"):
        crypto.open_release_share(
            wrong_request, response, client, signer.public_key(), now=ISSUED_AT)


def test_wrong_client_ephemeral_key_is_rejected():
    _client, _server, signer, request, response = _sealed()
    wrong_client = _private(0x77777)

    with pytest.raises(crypto.KeyReleaseCryptoError, match="client private key"):
        crypto.open_release_share(
            request, response, wrong_client, signer.public_key(), now=ISSUED_AT)


def test_wrong_signing_key_and_invalid_signature_scalars_are_rejected():
    client, _server, signer, request, response = _sealed()
    wrong_signer = _private(0x88888)
    with pytest.raises(
            crypto.KeyReleaseCryptoError, match="signature verification failed"):
        crypto.open_release_share(
            request, response, client, wrong_signer.public_key(), now=ISSUED_AT)

    zero_signature = protocol.KeyReleaseResponse(
        response.grant, bytes(protocol.SIGNATURE_SIZE))
    with pytest.raises(crypto.KeyReleaseCryptoError, match="invalid P-256 scalar"):
        crypto.open_release_share(
            request, zero_signature, client, signer.public_key(), now=ISSUED_AT)


def test_malleated_high_s_signature_is_rejected():
    client, _server, signer, request, response = _sealed()
    r = response.signature[:32]
    s = int.from_bytes(response.signature[32:], "big")
    assert 1 <= s <= P256_ORDER // 2
    malleated = protocol.KeyReleaseResponse(
        response.grant,
        r + (P256_ORDER - s).to_bytes(32, "big"),
    )

    with pytest.raises(crypto.KeyReleaseCryptoError, match="high-S"):
        crypto.open_release_share(
            request, malleated, client, signer.public_key(), now=ISSUED_AT)


def test_invalid_sec1_points_are_rejected_by_cryptography():
    client, server, signer, request, response = _sealed()
    invalid_point = b"\x04" + bytes(64)
    invalid_request = replace(request, client_ephemeral_key=invalid_point)
    with pytest.raises(crypto.KeyReleaseCryptoError, match="valid P-256 point"):
        crypto.seal_release_share(
            invalid_request, SHARE, server, signer,
            launch_id=bytes(16), issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT, nonce=NONCE)

    invalid_grant = replace(response.grant, server_ephemeral_key=invalid_point)
    signed_invalid_point = crypto.sign_response(request, invalid_grant, signer)
    with pytest.raises(crypto.KeyReleaseCryptoError, match="valid P-256 point"):
        crypto.open_release_share(
            request, signed_invalid_point, client,
            signer.public_key(), now=ISSUED_AT)


def test_release_window_is_enforced_after_signature_verification():
    client, _server, signer, request, response = _sealed()
    assert crypto.open_release_share(
        request, response, client, signer.public_key(), now=ISSUED_AT) == SHARE
    assert crypto.open_release_share(
        request, response, client, signer.public_key(),
        now=EXPIRES_AT - 1) == SHARE
    with pytest.raises(crypto.KeyReleaseCryptoError, match="not yet valid"):
        crypto.open_release_share(
            request, response, client, signer.public_key(), now=ISSUED_AT - 1)
    with pytest.raises(crypto.KeyReleaseCryptoError, match="expired"):
        crypto.open_release_share(
            request, response, client, signer.public_key(), now=EXPIRES_AT)


def test_server_rejects_grant_issued_before_request():
    _client, server, signer, request, _response = _sealed()
    with pytest.raises(crypto.KeyReleaseCryptoError, match="precedes"):
        crypto.seal_release_share(
            request, SHARE, server, signer,
            launch_id=bytes(16), issued_at=REQUESTED_AT - 1,
            expires_at=REQUESTED_AT + 1, nonce=NONCE)


@pytest.mark.parametrize("share", [bytes(31), bytes(33)])
def test_release_share_must_be_exactly_32_bytes(share):
    _client, server, signer = _keys()
    with pytest.raises(crypto.KeyReleaseCryptoError, match="exactly 32 bytes"):
        crypto.seal_release_share(
            _request(), share, server, signer,
            launch_id=bytes(16), issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT, nonce=NONCE)


def test_non_p256_keys_are_rejected():
    _client, server, signer, request, _response = _sealed()
    p384 = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(crypto.KeyReleaseCryptoError, match="P-256 private key"):
        crypto.seal_release_share(
            request, SHARE, p384, signer,
            launch_id=bytes(16), issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT, nonce=NONCE)
    with pytest.raises(crypto.KeyReleaseCryptoError, match="P-256 private key"):
        crypto.seal_release_share(
            request, SHARE, server, p384,
            launch_id=bytes(16), issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT, nonce=NONCE)
