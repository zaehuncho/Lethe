"""Per-build metamorphism seed substrate for Lethe.

Every per-build variance layer in Lethe (the opcode wire map, native handler
variant selection, per-program rolling seeds, MBA template choice, decoy/noise
seeding, and the string-encoder keys) should derive from ONE master build seed
through a domain-separated key-derivation function, so that:

* a single recorded master seed reproduces an entire build bit-for-bit, and
* each layer gets an independent sub-seed (recovering one layer's key tells an
  analyst nothing about the others).

The KDF is HKDF-SHA256 (RFC 5869): a single Extract over the master seed with a
fixed salt, then a per-domain Expand. This module is deliberately tiny, has no
third-party dependencies (stdlib ``hashlib``/``hmac`` only), and is validated in
``tests/test_metamorph_seed.py`` against the ``cryptography`` library's HKDF.

The master seed is the same value already recorded as ``BUILD_SEED`` in the
generated ``daedalus_opcodes_shuffled.py`` (a 32-byte value, usually written as
64 hex characters). Adopting this substrate does NOT change any existing output
on its own: a layer's behaviour only changes once that layer is switched over to
read its sub-seed from here.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = [
    "HKDF_SALT",
    "HASH_LEN",
    "DOMAIN_SHUFFLE",
    "DOMAIN_ROLLING",
    "DOMAIN_MBA",
    "DOMAIN_NOISE",
    "DOMAIN_STRENC",
    "DOMAIN_LLVM_OBF",
    "DOMAIN_TRACING",
    "DOMAINS",
    "MetamorphSeed",
]

# Fixed salt binds the whole hierarchy to Lethe and to this format version.
HKDF_SALT = b"lethe-metamorph-v1"

_HASH = hashlib.sha256
HASH_LEN = 32  # SHA-256 output length in bytes

# Domain labels. Each names one observable variance layer. The "/v1" suffix lets
# a layer rotate its derivation independently without disturbing the others.
DOMAIN_SHUFFLE = "shuffle/v1"
DOMAIN_ROLLING = "rolling/v1"
DOMAIN_MBA = "mba/v1"
DOMAIN_NOISE = "noise/v1"
DOMAIN_STRENC = "strenc/v1"
DOMAIN_LLVM_OBF = "llvm-obf/v1"
DOMAIN_TRACING = "tracing/v1"

DOMAINS = (
    DOMAIN_SHUFFLE,
    DOMAIN_ROLLING,
    DOMAIN_MBA,
    DOMAIN_NOISE,
    DOMAIN_STRENC,
    DOMAIN_LLVM_OBF,
    DOMAIN_TRACING,
)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 Extract: PRK = HMAC-Hash(salt, IKM)."""
    return hmac.new(salt, ikm, _HASH).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 Expand: OKM of ``length`` bytes from ``prk`` and ``info``."""
    if length < 0:
        raise ValueError("length must be non-negative")
    max_len = 255 * HASH_LEN
    if length > max_len:
        raise ValueError(f"length {length} exceeds HKDF-SHA256 maximum {max_len}")
    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), _HASH).digest()
        okm.extend(block)
        counter += 1
    return bytes(okm[:length])


def _coerce_master(master: object) -> bytes:
    """Accept a hex string (like ``BUILD_SEED``), raw bytes, or UTF-8 text."""
    if isinstance(master, str):
        text = master.strip()
        try:
            return bytes.fromhex(text)
        except ValueError:
            return text.encode("utf-8")
    if isinstance(master, (bytes, bytearray)):
        return bytes(master)
    raise TypeError(f"master seed must be str or bytes, got {type(master).__name__}")


class MetamorphSeed:
    """A master build seed and its domain-separated sub-seed hierarchy.

    Construct with the recorded ``BUILD_SEED`` (hex string) or raw bytes; every
    ``subseed*`` call is a pure, deterministic function of the master seed and
    the requested domain.
    """

    __slots__ = ("_master", "_prk")

    def __init__(self, master: object) -> None:
        self._master = _coerce_master(master)
        if not self._master:
            raise ValueError("master seed must be non-empty")
        self._prk = _hkdf_extract(HKDF_SALT, self._master)

    @classmethod
    def from_hex(cls, seed_hex: str) -> "MetamorphSeed":
        return cls(bytes.fromhex(seed_hex.strip()))

    @property
    def master(self) -> bytes:
        return self._master

    def subseed(self, domain: str, length: int = HASH_LEN) -> bytes:
        """A ``length``-byte sub-seed for ``domain`` (default 32)."""
        if not domain:
            raise ValueError("domain must be non-empty")
        return _hkdf_expand(self._prk, domain.encode("utf-8"), length)

    def subseed16(self, domain: str) -> bytes:
        """A 16-byte sub-seed (e.g. for the rolling container seed field)."""
        return self.subseed(domain, 16)

    def subseed_for_program(
        self, domain: str, symbol: str, length: int = 16
    ) -> bytes:
        """A per-program sub-seed: same master + domain, distinct per ``symbol``."""
        if not domain:
            raise ValueError("domain must be non-empty")
        if not symbol:
            raise ValueError("symbol must be non-empty")
        info = domain.encode("utf-8") + b"|" + symbol.encode("utf-8")
        return _hkdf_expand(self._prk, info, length)

    def int_below(self, domain: str, bound: int, *, length: int = HASH_LEN) -> int:
        """A deterministic, unbiased integer in ``[0, bound)`` for ``domain``.

        Rejection-samples over the sub-seed stream so the result is uniform (no
        modulo bias); ``bound`` must be positive.
        """
        if bound <= 0:
            raise ValueError("bound must be positive")
        if bound == 1:
            return 0
        nbytes = (bound.bit_length() + 7) // 8
        limit = (1 << (nbytes * 8)) // bound * bound  # largest unbiased multiple
        stream = self.subseed(domain, length)
        counter = 0
        while True:
            for off in range(0, len(stream) - nbytes + 1, nbytes):
                value = int.from_bytes(stream[off:off + nbytes], "big")
                if value < limit:
                    return value % bound
            counter += 1
            stream = _hkdf_expand(
                self._prk,
                domain.encode("utf-8") + b"|int|" + counter.to_bytes(4, "big"),
                max(length, nbytes * 8),
            )
