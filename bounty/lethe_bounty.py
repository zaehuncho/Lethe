"""Lethe bounty challenge core: Argon2id (or scrypt) + AES-256-GCM.

This is the money-bounty successor to the red-team crackme (cipher/gen_check_vm.py).
It is built to survive a *fully reversed client* -- the attacker is assumed to know
the entire algorithm, the salt, the nonce and the ciphertext. Security rests only
on the two things reversing can't hand them:

  1. a high-entropy password they must supply, and
  2. a slow, memory-hard KDF that makes each guess expensive,

with the flag sealed under AES-256-GCM so a wrong password fails *authentication*
(no plaintext, no oracle) rather than decrypting to garbage.

Crypto is deliberately NOT hand-rolled: Argon2id comes from argon2-cffi (the
reference Argon2 C core) and AES-GCM from `cryptography`. The password/flag never
appear in the shipped challenge -- only salt, nonce and ciphertext do (see
audit_bounty.py, which proves it).
"""
from __future__ import annotations

import base64
import json
import secrets
from dataclasses import asdict, dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEME = "lethe-bounty-v1"
# Bound into the GCM tag so a challenge can't be replayed under a different scheme.
AAD = b"lethe-bounty-v1"

# Strong production defaults. Argon2id: t=4, 256 MiB, 1 lane, 32-byte key -- each
# guess costs ~256 MiB and hundreds of ms, so brute force is hopeless well before
# the password-entropy argument even applies.
DEFAULT_ARGON2 = {"time_cost": 4, "memory_cost": 262144, "parallelism": 1,
                  "hash_len": 32}
# stdlib scrypt fallback (no argon2 install): N=2**16 (~64 MiB), r=8, p=1.
DEFAULT_SCRYPT = {"n": 1 << 16, "r": 8, "p": 1, "dklen": 32, "maxmem": 1 << 27}


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def have_argon2() -> bool:
    try:
        import argon2.low_level  # noqa: F401
        return True
    except Exception:
        return False


def derive_key(kdf: str, password: bytes, salt: bytes, params: dict) -> bytes:
    """Run the configured memory-hard KDF. Same work for a right or wrong guess."""
    if kdf == "argon2id":
        from argon2.low_level import Type, hash_secret_raw
        return hash_secret_raw(
            secret=password, salt=salt,
            time_cost=int(params["time_cost"]),
            memory_cost=int(params["memory_cost"]),
            parallelism=int(params["parallelism"]),
            hash_len=int(params["hash_len"]),
            type=Type.ID,
        )
    if kdf == "scrypt":
        import hashlib
        return hashlib.scrypt(
            password, salt=salt,
            n=int(params["n"]), r=int(params["r"]), p=int(params["p"]),
            dklen=int(params["dklen"]),
            maxmem=int(params.get("maxmem", 0)) or (1 << 27),
        )
    raise ValueError(f"unknown kdf: {kdf!r}")


@dataclass
class Challenge:
    """The public challenge artifact. Contains NO password, flag or key."""

    scheme: str
    kdf: str
    params: dict
    salt: str        # base64
    nonce: str       # base64 (96-bit GCM nonce)
    ciphertext: str  # base64 (AES-256-GCM ciphertext with tag appended)
    note: str = ("Recover the plaintext sealed here (the flag). You are given the "
                 "full algorithm, salt, nonce and ciphertext; only the password is "
                 "withheld. Brute force is intended to be infeasible.")

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, text: str) -> "Challenge":
        d = json.loads(text)
        return cls(scheme=d["scheme"], kdf=d["kdf"], params=d["params"],
                   salt=d["salt"], nonce=d["nonce"], ciphertext=d["ciphertext"],
                   note=d.get("note", ""))

    # convenience accessors
    def salt_bytes(self) -> bytes:
        return _b64d(self.salt)

    def nonce_bytes(self) -> bytes:
        return _b64d(self.nonce)

    def ciphertext_bytes(self) -> bytes:
        return _b64d(self.ciphertext)


def generate(password: bytes, flag: bytes, *, kdf: Optional[str] = None,
             params: Optional[dict] = None) -> Challenge:
    """Seal ``flag`` under a key derived from ``password``. Returns the public
    Challenge (salt/nonce/ciphertext only -- never the password/flag/key)."""
    if not password:
        raise ValueError("password is empty")
    if not flag:
        raise ValueError("flag is empty")
    if kdf is None:
        kdf = "argon2id" if have_argon2() else "scrypt"
    if params is None:
        params = dict(DEFAULT_ARGON2 if kdf == "argon2id" else DEFAULT_SCRYPT)

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(kdf, password, salt, params)
    ciphertext = AESGCM(key).encrypt(nonce, flag, AAD)
    return Challenge(scheme=SCHEME, kdf=kdf, params=params,
                     salt=_b64(salt), nonce=_b64(nonce),
                     ciphertext=_b64(ciphertext))


def attempt(challenge: Challenge, guess: bytes) -> Optional[bytes]:
    """Return the flag if ``guess`` is the password, else None.

    The KDF runs regardless of correctness (no early-out), and a wrong guess
    fails GCM *authentication* -- there is no decrypt-to-garbage oracle, and the
    real password is never referenced (it isn't in the challenge to begin with).
    """
    key = derive_key(challenge.kdf, guess, challenge.salt_bytes(),
                     challenge.params)
    try:
        return AESGCM(key).decrypt(challenge.nonce_bytes(),
                                   challenge.ciphertext_bytes(), AAD)
    except InvalidTag:
        return None
