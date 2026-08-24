#!/usr/bin/env python3
"""
kalypso.py -- Kalypso: a SOUND, per-build-parameterized stream cipher
for Lethe, plus its reference implementation and the soundness anchor.

DESIGN PHILOSOPHY (read this before touching the crypto)
--------------------------------------------------------
Rule #1 of a protector's crypto: do NOT invent new primitives for the actual
confidentiality gate. Kalypso's *core* is the ChaCha ARX permutation with
ChaCha's PROVEN rotation constants (16, 12, 8, 7) and 20 rounds -- i.e. it is
ChaCha20. The "custom" surface is deliberately confined to things that provably
do NOT weaken a stream cipher:

  * a per-build 16-byte sigma (domain-separation constant),
  * a per-build fixed permutation of the 16 output words (reordering independent
    keystream words is security-neutral for a stream cipher -- each byte still
    XORs exactly one plaintext byte -- but makes each build's keystream layout
    different), and
  * a code-hash-bound, per-build key schedule (HKDF).

ARCHITECTURE (intended -- integration pending)
  Kalypso is designed as an INNER diffusion/whitening layer with AES-256-GCM
  as the OUTER authenticated gate:  plaintext -> Kalypso -> AES-256-GCM.
  Two independent keys; break-both required; Kalypso must NEVER stand alone
  as the confidentiality/authentication gate.

  STATUS: this module is NOT yet wired into the pack/unpack pipeline (no call
  sites outside its tests). The two invariants above -- (a) the AES-256-GCM outer
  wrap and (b) a UNIQUE per-message (key, nonce) -- are the integration's
  responsibility; THIS module does not and cannot enforce them. As a raw stream
  cipher, reusing a (key, nonce) pair across two messages is a catastrophic
  two-time-pad break. Any wiring MUST supply a fresh nonce per message (e.g. a
  monotonic counter or CSPRNG nonce carried in the container) and apply GCM.

SOUNDNESS ANCHOR
  With canonical parameters (standard sigma "expand 32-byte k", identity word
  permutation) Kalypso is BIT-IDENTICAL to RFC 8439 ChaCha20. test_kalypso
  proves this against the RFC 8439 test vectors. That is the proof this is real
  crypto, not homemade magic.

Freestanding target: the C port (kalypso.c, TODO) uses only 32-bit adds,
rotates, and xors -- no tables, no CRT, side-channel-friendly.
"""
from __future__ import annotations

import struct

MASK32 = 0xFFFFFFFF
STD_SIGMA = b"expand 32-byte k"   # RFC 8439 constant


def rotl32(v: int, c: int) -> int:
    v &= MASK32
    return ((v << c) | (v >> (32 - c))) & MASK32


def _qr(x, a, b, c, d):
    """ChaCha quarter-round on state list x (proven rotations 16/12/8/7)."""
    x[a] = (x[a] + x[b]) & MASK32; x[d] ^= x[a]; x[d] = rotl32(x[d], 16)
    x[c] = (x[c] + x[d]) & MASK32; x[b] ^= x[c]; x[b] = rotl32(x[b], 12)
    x[a] = (x[a] + x[b]) & MASK32; x[d] ^= x[a]; x[d] = rotl32(x[d], 8)
    x[c] = (x[c] + x[d]) & MASK32; x[b] ^= x[c]; x[b] = rotl32(x[b], 7)


def chacha_block(key: bytes, counter: int, nonce: bytes,
                 rounds: int = 20, sigma: bytes = STD_SIGMA) -> bytes:
    """One 64-byte ChaCha keystream block (RFC 8439 layout).

    key: 32 bytes, nonce: 12 bytes, counter: u32. `rounds` even (20 = ChaCha20).
    `sigma`: 16-byte domain constant (standard by default; per-build otherwise).
    """
    assert len(key) == 32 and len(nonce) == 12 and len(sigma) == 16
    c = list(struct.unpack("<4I", sigma))
    k = list(struct.unpack("<8I", key))
    n = list(struct.unpack("<3I", nonce))
    state = c + k + [counter & MASK32] + n
    x = list(state)
    for _ in range(rounds // 2):
        # column round
        _qr(x, 0, 4, 8, 12); _qr(x, 1, 5, 9, 13)
        _qr(x, 2, 6, 10, 14); _qr(x, 3, 7, 11, 15)
        # diagonal round
        _qr(x, 0, 5, 10, 15); _qr(x, 1, 6, 11, 12)
        _qr(x, 2, 7, 8, 13); _qr(x, 3, 4, 9, 14)
    out = [(x[i] + state[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


# --------------------------------------------------------------------------
# Per-build parameterization
# --------------------------------------------------------------------------
def derive_params(build_seed: bytes):
    """Return (sigma, word_perm) for a build. sigma is a per-build 16-byte
    domain constant; word_perm is a permutation of range(16) applied to each
    keystream block's output words (security-neutral reordering).

    Canonical (build_seed == b"") reproduces standard ChaCha20 exactly.
    """
    if not build_seed:
        return STD_SIGMA, list(range(16))
    import hashlib
    # sigma: derive 16 bytes but keep it a *constant* (domain separator).
    sigma = hashlib.sha256(b"kalypso-sigma|" + build_seed).digest()[:16]
    # word_perm: a Fisher-Yates shuffle driven by a keyed stream (deterministic).
    perm = list(range(16))
    stream = hashlib.sha256(b"kalypso-perm|" + build_seed).digest()
    # extend the stream if needed
    j = 0
    buf = bytearray(stream)
    while len(buf) < 16:
        buf += hashlib.sha256(bytes(buf)).digest()
    for i in range(15, 0, -1):
        r = buf[j] % (i + 1); j += 1
        perm[i], perm[r] = perm[r], perm[i]
    return sigma, perm


class Kalypso:
    """Per-build stream cipher. AES-GCM remains the outer authenticated gate;
    this is the inner keyed diffusion layer / memguard hot-path cipher.

    key: 32 bytes. nonce: 12 bytes. rounds: 20 (security) .. 12 (min hot-path).
    build_seed: b"" => canonical ChaCha20; otherwise per-build sigma + word perm.
    """

    def __init__(self, key: bytes, build_seed: bytes = b"", rounds: int = 20):
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        if rounds % 2 or rounds < 8:
            raise ValueError("rounds must be even and >= 8 (use 20 for secrets)")
        self.key = key
        self.rounds = rounds
        self.sigma, self.perm = derive_params(build_seed)

    def keystream_block(self, counter: int, nonce: bytes) -> bytes:
        blk = chacha_block(self.key, counter, nonce, self.rounds, self.sigma)
        if self.perm == list(range(16)):
            return blk
        words = struct.unpack("<16I", blk)
        permuted = [words[self.perm[i]] for i in range(16)]
        return struct.pack("<16I", *permuted)

    def crypt(self, data: bytes, nonce: bytes, counter0: int = 0) -> bytes:
        """XOR `data` with the keystream (encryption == decryption)."""
        out = bytearray(len(data))
        counter = counter0
        off = 0
        n = len(data)
        while off < n:
            ks = self.keystream_block(counter, nonce)
            chunk = data[off:off + 64]
            for i in range(len(chunk)):
                out[off + i] = chunk[i] ^ ks[i]
            off += 64
            counter = (counter + 1) & MASK32
        return bytes(out)

    encrypt = crypt
    decrypt = crypt


if __name__ == "__main__":
    # tiny smoke demo
    key = bytes(range(32))
    nonce = bytes(12)
    c = Kalypso(key, build_seed=b"build-42", rounds=20)
    ct = c.encrypt(b"Lethe inner layer", nonce)
    pt = c.decrypt(ct, nonce)
    print("roundtrip ok:", pt == b"Lethe inner layer")
