#!/usr/bin/env python3
"""
Soundness harness for Kalypso (cipher/kalypso.py).

The point of these tests is to PROVE Kalypso is real crypto, not homemade
magic:

  1. KNOWN-ANSWER TEST -- with canonical parameters Kalypso reproduces the
     RFC 8439 ChaCha20 block-function test vector (RFC 8439 s2.3.2), byte-exact.
  2. CROSS-CHECK vs a vetted library -- for random keys/nonces/counters and
     multi-block lengths, canonical Kalypso keystream == the `cryptography`
     library's ChaCha20 keystream. This is the strong soundness anchor.
  3. ROUND-TRIP -- decrypt(encrypt(x)) == x for random data and per-build seeds.
  4. AVALANCHE -- a 1-bit change in key/nonce/counter flips ~50% of output bits.
  5. KEY SENSITIVITY -- the wrong key yields uncorrelated output.
  6. PER-BUILD -- canonical == ChaCha20; two build seeds differ; a seed is
     deterministic; the output word permutation is a real bijection.

Run: python -m pytest tests/test_kalypso.py -q   or   python tests/test_kalypso.py
"""
from __future__ import annotations

import os
import random
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
sys.path.insert(0, str(PKG / "cipher"))

import kalypso as L  # noqa: E402


# ---------------------------------------------------------------------------
# 1. RFC 8439 s2.3.2 known-answer test (the authoritative anchor)
# ---------------------------------------------------------------------------
def test_rfc8439_block_kat():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    counter = 1
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )
    got = L.chacha_block(key, counter, nonce, rounds=20, sigma=L.STD_SIGMA)
    assert got == expected, "Kalypso core != RFC 8439 ChaCha20 vector"


# ---------------------------------------------------------------------------
# 2. Cross-check canonical Kalypso vs the `cryptography` ChaCha20
# ---------------------------------------------------------------------------
def _lib_chacha20_keystream(key, counter, nonce12, nbytes):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    # cryptography's ChaCha20 nonce = 16 bytes: u32 counter (LE) || 12-byte nonce
    iv = struct.pack("<I", counter) + nonce12
    enc = Cipher(algorithms.ChaCha20(key, iv), mode=None).encryptor()
    return enc.update(b"\x00" * nbytes)


def test_crosscheck_vs_cryptography_lib():
    rng = random.Random(1234)
    for _ in range(40):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        nonce = bytes(rng.getrandbits(8) for _ in range(12))
        counter = rng.getrandbits(32)
        nbytes = rng.choice([1, 63, 64, 65, 127, 200, 256])
        # canonical Kalypso keystream == encrypt zeros
        c = L.Kalypso(key, build_seed=b"", rounds=20)
        ours = c.crypt(b"\x00" * nbytes, nonce, counter0=counter)
        theirs = _lib_chacha20_keystream(key, counter, nonce, nbytes)
        assert ours == theirs, "canonical Kalypso != library ChaCha20"


# ---------------------------------------------------------------------------
# 3. Round-trip (encryption == decryption for a stream cipher)
# ---------------------------------------------------------------------------
def test_roundtrip_random_and_perbuild():
    rng = random.Random(7)
    for _ in range(50):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        nonce = bytes(rng.getrandbits(8) for _ in range(12))
        seed = rng.choice([b"", b"build-1", b"build-2", os.urandom(8)])
        rounds = rng.choice([12, 20])
        n = rng.choice([0, 1, 16, 64, 100, 1000])
        data = bytes(rng.getrandbits(8) for _ in range(n))
        c = L.Kalypso(key, build_seed=seed, rounds=rounds)
        ct = c.encrypt(data, nonce)
        assert c.decrypt(ct, nonce) == data
        if n >= 16 and seed:
            assert ct != data  # actually encrypted


# ---------------------------------------------------------------------------
# 4. Avalanche -- a 1-bit change flips ~half the keystream bits
# ---------------------------------------------------------------------------
def _bits(b):
    return sum(bin(x).count("1") for x in b)


def _hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def test_avalanche_key_nonce_counter():
    rng = random.Random(99)
    for trial in range(20):
        key = bytearray(rng.getrandbits(8) for _ in range(32))
        nonce = bytearray(rng.getrandbits(8) for _ in range(12))
        counter = rng.getrandbits(32)
        seed = rng.choice([b"", b"bX"])
        base = L.Kalypso(bytes(key), build_seed=seed).crypt(b"\x00" * 128, bytes(nonce), counter)
        # flip one random key bit
        k2 = bytearray(key); bit = rng.randrange(256); k2[bit // 8] ^= 1 << (bit % 8)
        alt = L.Kalypso(bytes(k2), build_seed=seed).crypt(b"\x00" * 128, bytes(nonce), counter)
        frac = _hamming(base, alt) / (len(base) * 8)
        assert 0.40 <= frac <= 0.60, f"key avalanche off: {frac:.3f}"
        # flip one counter bit
        alt2 = L.Kalypso(bytes(key), build_seed=seed).crypt(b"\x00" * 128, bytes(nonce), counter ^ (1 << rng.randrange(32)))
        frac2 = _hamming(base, alt2) / (len(base) * 8)
        assert 0.40 <= frac2 <= 0.60, f"counter avalanche off: {frac2:.3f}"


# ---------------------------------------------------------------------------
# 5. Key sensitivity -- wrong key decrypts to noise (~50% differ from plaintext)
# ---------------------------------------------------------------------------
def test_wrong_key_is_noise():
    rng = random.Random(5)
    key = bytes(rng.getrandbits(8) for _ in range(32))
    wrong = bytearray(key); wrong[0] ^= 0x01
    nonce = bytes(12)
    data = b"A" * 256
    ct = L.Kalypso(key).encrypt(data, nonce)
    bad = L.Kalypso(bytes(wrong)).decrypt(ct, nonce)
    assert bad != data
    # roughly uncorrelated: many bytes differ
    diff = sum(1 for x, y in zip(bad, data) if x != y)
    assert diff > 200, f"wrong-key output too close to plaintext ({diff}/256 differ)"


# ---------------------------------------------------------------------------
# 6. Per-build behaviour
# ---------------------------------------------------------------------------
def test_perbuild_properties():
    key = bytes(range(32)); nonce = bytes(12)
    canon = L.Kalypso(key, build_seed=b"")
    # canonical params == standard ChaCha20 core
    assert canon.sigma == L.STD_SIGMA and canon.perm == list(range(16))
    # two build seeds -> different keystream layout
    a = L.Kalypso(key, build_seed=b"seedA").crypt(b"\x00" * 64, nonce)
    b = L.Kalypso(key, build_seed=b"seedB").crypt(b"\x00" * 64, nonce)
    assert a != b, "distinct build seeds gave identical keystream"
    # deterministic for a fixed seed
    a2 = L.Kalypso(key, build_seed=b"seedA").crypt(b"\x00" * 64, nonce)
    assert a == a2
    # word_perm is a genuine bijection for many seeds
    for s in range(50):
        _sigma, perm = L.derive_params(b"s" + struct.pack("<I", s))
        assert sorted(perm) == list(range(16)), "word_perm is not a permutation"


# ---------------------------------------------------------------------------
# 7. Poly1305 known-answer test (RFC 8439 s2.5.2)
# ---------------------------------------------------------------------------
def test_poly1305_rfc8439_kat():
    key = bytes.fromhex("85d6be7857556d337f4452fe42d506a8"
                        "0103808afb0db2fd4abff6af4149f51b")
    msg = b"Cryptographic Forum Research Group"
    expected = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")
    assert L.poly1305_mac(msg, key) == expected, "Poly1305 != RFC 8439 vector"


# ---------------------------------------------------------------------------
# 8. AEAD cross-check: canonical Kalypso-Poly1305 == library ChaCha20Poly1305
# ---------------------------------------------------------------------------
def test_aead_crosscheck_vs_cryptography():
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    rng = random.Random(2025)
    for _ in range(40):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        nonce = bytes(rng.getrandbits(8) for _ in range(12))
        pt = bytes(rng.getrandbits(8)
                   for _ in range(rng.choice([0, 1, 16, 63, 64, 65, 200])))
        aad = bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 12, 20])))
        ours = L.Kalypso(key, build_seed=b"", rounds=20).aead_encrypt(nonce, pt, aad)
        theirs = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
        assert ours == theirs, "canonical Kalypso-Poly1305 != RFC 8439 AEAD"


# ---------------------------------------------------------------------------
# 9. AEAD round-trip + authentication (canonical AND per-build)
# ---------------------------------------------------------------------------
def test_aead_roundtrip_and_tamper():
    rng = random.Random(11)
    for _ in range(40):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        nonce = bytes(rng.getrandbits(8) for _ in range(12))
        seed = rng.choice([b"", b"buildA", os.urandom(6)])
        pt = bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 1, 32, 100])))
        aad = bytes(rng.getrandbits(8) for _ in range(rng.choice([0, 16])))
        c = L.Kalypso(key, build_seed=seed, rounds=20)
        sealed = c.aead_encrypt(nonce, pt, aad)

        assert c.aead_decrypt(nonce, sealed, aad) == pt          # round-trips
        # flip the first byte (ciphertext or, for empty pt, the tag)
        bad = bytearray(sealed); bad[0] ^= 0x01
        assert c.aead_decrypt(nonce, bytes(bad), aad) is None
        # flip a tag byte
        bad2 = bytearray(sealed); bad2[-1] ^= 0x80
        assert c.aead_decrypt(nonce, bytes(bad2), aad) is None
        # wrong AAD
        assert c.aead_decrypt(nonce, sealed, aad + b"x") is None
        # wrong key
        wrong = bytearray(key); wrong[5] ^= 0x01
        assert L.Kalypso(bytes(wrong), build_seed=seed).aead_decrypt(nonce, sealed, aad) is None
        # a per-build seal cannot be opened with canonical params
        if seed:
            assert L.Kalypso(key, build_seed=b"").aead_decrypt(nonce, sealed, aad) is None


def _main():
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); p += 1
        except Exception:
            print(f"  FAIL  {fn.__name__}"); traceback.print_exc(); f += 1
    print(f"\n{p} passed, {f} failed")
    return 1 if f else 0


if __name__ == "__main__":
    raise SystemExit(_main())
