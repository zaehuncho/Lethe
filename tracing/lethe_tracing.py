"""Per-customer build variance + traitor tracing for Lethe.

Every customer (or session) gets a UNIQUELY morphed binary: the per-build seed
that drives Daedalus's opcode shuffle and Kalypso's sigma / word-permutation /
key schedule is derived from the customer identity under a server-held master
secret. Two payoffs:

  * a crack for one customer's build does NOT transfer to another's, and
  * TRAITOR TRACING -- a leaked or cracked binary can be matched back to the exact
    customer it was issued to, from the morph fingerprint alone (the morph is
    observable in the binary; the seed that produced it is not recoverable).

The master secret stays server-side. A customer cannot forge another customer's
morph because the seed is HMAC'd under that secret. This module is the derivation
primitive + the tracer; issuing builds and storing the registry is the license
backend's job.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# derive_params (sigma + word-perm) is the single source of the observable morph.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "cipher"))
from kalypso import derive_params  # noqa: E402

SCHEME = "lethe-trace-v1"


def derive_build_seed(master_secret: bytes, customer_id: str,
                      license_key: str, product: str = "lethe") -> bytes:
    """HMAC-SHA256(master_secret, scheme|product|customer|license) -> 16-byte seed.

    Deterministic given the identity, but unpredictable without master_secret, so
    a customer cannot compute (or forge) another customer's morph."""
    if not master_secret:
        raise ValueError("master_secret required")
    msg = b"|".join([SCHEME.encode(), product.encode(),
                     customer_id.encode(), license_key.encode()])
    return hmac.new(master_secret, msg, hashlib.sha256).digest()[:16]


def morph_for_seed(build_seed: bytes) -> Tuple[bytes, List[int]]:
    """The observable morph (sigma, word_perm) a build seed produces."""
    sigma, perm = derive_params(build_seed)
    return sigma, perm


def fingerprint_morph(sigma: bytes, perm: List[int]) -> str:
    """A stable public fingerprint of a build's morph. Recoverable from a leaked
    binary (extract its sigma + word-perm), so it can be matched to a customer
    WITHOUT knowing the seed."""
    blob = bytes(sigma) + bytes(perm)
    return hashlib.sha256(b"lethe-fp|" + blob).hexdigest()[:16]


def fingerprint_for_seed(build_seed: bytes) -> str:
    """Convenience: the fingerprint a seed will produce (issuance side)."""
    sigma, perm = morph_for_seed(build_seed)
    return fingerprint_morph(sigma, perm)


@dataclass
class Registry:
    """Maps morph fingerprints back to the customers they were issued to."""
    by_fingerprint: Dict[str, str] = field(default_factory=dict)  # fp -> customer

    def register(self, customer_id: str, fingerprint: str) -> None:
        self.by_fingerprint[fingerprint] = customer_id

    def trace(self, suspect_fingerprint: str) -> Optional[str]:
        """Return the customer a leaked build belongs to, or None if unknown."""
        return self.by_fingerprint.get(suspect_fingerprint)


def build_registry(master_secret: bytes,
                   issuances: List[Tuple[str, str, str]]) -> Registry:
    """Build a fingerprint->customer registry from issuances (customer, license,
    product). Store this server-side to trace leaks later."""
    reg = Registry()
    for customer_id, license_key, product in issuances:
        seed = derive_build_seed(master_secret, customer_id, license_key, product)
        reg.register(customer_id, fingerprint_for_seed(seed))
    return reg
