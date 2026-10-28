"""Tests for the per-build metamorphism seed substrate (daedalus/metamorph_seed).

Correctness is proven two ways:
* against the ``cryptography`` library's HKDF (an independent implementation of
  RFC 5869) used as an oracle, and
* against frozen known-answer vectors so the derivation can never silently drift.
"""

from __future__ import annotations

import pytest

from daedalus import metamorph_seed as ms
from daedalus.metamorph_seed import MetamorphSeed

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# The master seed recorded in the generated shuffled-opcode module.
MASTER_HEX = "a8088df29c2372fba7637e9d737e308b4d4c667752d7e986da66d51581dad14d"
MASTER = bytes.fromhex(MASTER_HEX)


def _oracle(master: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=ms.HKDF_SALT,
        info=info,
    ).derive(master)


# --- correctness against the cryptography HKDF oracle -----------------------

@pytest.mark.parametrize("domain", ms.DOMAINS)
@pytest.mark.parametrize("length", [1, 16, 32, 48, 64, 200])
def test_subseed_matches_cryptography_hkdf(domain, length):
    seed = MetamorphSeed(MASTER)
    assert seed.subseed(domain, length) == _oracle(MASTER, domain.encode(), length)


@pytest.mark.parametrize("symbol", ["derive_key", "key_scatter", "n_sha256"])
def test_subseed_for_program_matches_oracle(symbol):
    seed = MetamorphSeed(MASTER)
    info = ms.DOMAIN_ROLLING.encode() + b"|" + symbol.encode()
    assert seed.subseed_for_program(ms.DOMAIN_ROLLING, symbol, 16) == _oracle(
        MASTER, info, 16
    )


# --- frozen known-answer vectors (regression pins) --------------------------

def test_frozen_kat_vectors():
    seed = MetamorphSeed.from_hex(MASTER_HEX)
    assert seed.subseed(ms.DOMAIN_SHUFFLE, 32).hex() == (
        "4a70d2954c4d63a95067da03e6f82fd89a0d746e7596625149fb8a163fca1482"
    )
    assert seed.subseed16(ms.DOMAIN_ROLLING).hex() == "2471399794430a3dc141ed1c4f351b34"
    assert seed.subseed(ms.DOMAIN_STRENC, 32).hex() == (
        "70c61cab5027aa38f38a56cff5c35e831e46652c29f6155a5df39e763492df4a"
    )
    assert seed.subseed_for_program(ms.DOMAIN_ROLLING, "derive_key", 16).hex() == (
        "5d12809ae21058fd92fdda52014512b6"
    )


# --- determinism ------------------------------------------------------------

def test_determinism_same_master():
    a = MetamorphSeed(MASTER)
    b = MetamorphSeed(MASTER)
    for domain in ms.DOMAINS:
        assert a.subseed(domain) == b.subseed(domain)


def test_hex_and_bytes_master_agree():
    assert MetamorphSeed.from_hex(MASTER_HEX).subseed(ms.DOMAIN_MBA) == MetamorphSeed(
        MASTER
    ).subseed(ms.DOMAIN_MBA)


def test_different_master_differs():
    other = bytes(MASTER[:-1]) + bytes([MASTER[-1] ^ 0x01])
    assert MetamorphSeed(MASTER).subseed(ms.DOMAIN_ROLLING) != MetamorphSeed(
        other
    ).subseed(ms.DOMAIN_ROLLING)


# --- domain separation ------------------------------------------------------

def test_domains_are_independent():
    seed = MetamorphSeed(MASTER)
    outs = [seed.subseed(d) for d in ms.DOMAINS]
    assert len(outs) == len(set(outs)), "domains must not collide"


def test_program_seed_varies_by_symbol():
    seed = MetamorphSeed(MASTER)
    a = seed.subseed_for_program(ms.DOMAIN_ROLLING, "derive_key")
    b = seed.subseed_for_program(ms.DOMAIN_ROLLING, "key_scatter")
    assert a != b


# --- avalanche --------------------------------------------------------------

def test_one_bit_master_flip_avalanches():
    base = MetamorphSeed(MASTER).subseed(ms.DOMAIN_SHUFFLE, 32)
    flipped_master = bytes([MASTER[0] ^ 0x01]) + MASTER[1:]
    flipped = MetamorphSeed(flipped_master).subseed(ms.DOMAIN_SHUFFLE, 32)
    hamming = sum(bin(x ^ y).count("1") for x, y in zip(base, flipped))
    # 256-bit output: expect ~128 differing bits; require a wide safe band.
    assert 80 <= hamming <= 176, f"weak avalanche: {hamming} bits"


# --- length handling & validation ------------------------------------------

def test_length_zero_is_empty():
    assert MetamorphSeed(MASTER).subseed(ms.DOMAIN_MBA, 0) == b""


def test_length_over_maximum_raises():
    seed = MetamorphSeed(MASTER)
    with pytest.raises(ValueError):
        seed.subseed(ms.DOMAIN_MBA, 255 * ms.HASH_LEN + 1)


def test_empty_master_rejected():
    with pytest.raises(ValueError):
        MetamorphSeed(b"")


def test_empty_domain_rejected():
    with pytest.raises(ValueError):
        MetamorphSeed(MASTER).subseed("")


def test_bad_master_type_rejected():
    with pytest.raises(TypeError):
        MetamorphSeed(1234)  # type: ignore[arg-type]


# --- int_below --------------------------------------------------------------

def test_int_below_in_range_and_deterministic():
    seed = MetamorphSeed(MASTER)
    for bound in (1, 2, 3, 255, 256, 1000, 65537):
        v1 = seed.int_below(ms.DOMAIN_NOISE, bound)
        v2 = seed.int_below(ms.DOMAIN_NOISE, bound)
        assert 0 <= v1 < bound
        assert v1 == v2


def test_int_below_rejects_nonpositive():
    seed = MetamorphSeed(MASTER)
    with pytest.raises(ValueError):
        seed.int_below(ms.DOMAIN_NOISE, 0)


def test_int_below_spreads_across_range():
    # Distinct domains should not all collapse to the same small-range value.
    seed = MetamorphSeed(MASTER)
    vals = {seed.int_below(f"spread/{i}", 100) for i in range(40)}
    assert len(vals) >= 20
