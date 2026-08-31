"""Tests for the money-bounty challenge (bounty/): Argon2id/scrypt + AES-256-GCM."""
import base64
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bounty"))

import lethe_bounty as lb  # noqa: E402

# Light KDF params so the suite stays fast; production defaults live in the module.
ARGON2_LIGHT = {"time_cost": 1, "memory_cost": 64, "parallelism": 1, "hash_len": 32}
SCRYPT_LIGHT = {"n": 1 << 8, "r": 8, "p": 1, "dklen": 32, "maxmem": 1 << 24}

KDFS = ["scrypt"] + (["argon2id"] if lb.have_argon2() else [])
PW = b"correct horse battery staple 2026!"
FLAG = b"NEXUS{test_flag_value_not_the_real_one}"


def _params(kdf):
    return dict(ARGON2_LIGHT if kdf == "argon2id" else SCRYPT_LIGHT)


@pytest.mark.parametrize("kdf", KDFS)
def test_roundtrip_correct_and_wrong(kdf):
    ch = lb.generate(PW, FLAG, kdf=kdf, params=_params(kdf))
    assert lb.attempt(ch, PW) == FLAG
    assert lb.attempt(ch, PW + b"x") is None
    assert lb.attempt(ch, b"") is None
    assert lb.attempt(ch, FLAG) is None            # the flag is not the password


@pytest.mark.parametrize("kdf", KDFS)
def test_artifact_holds_no_secrets(kdf):
    ch = lb.generate(PW, FLAG, kdf=kdf, params=_params(kdf))
    blob = ch.to_json().encode()
    key = lb.derive_key(kdf, PW, ch.salt_bytes(), ch.params)
    assert PW not in blob
    assert FLAG not in blob
    assert key not in blob
    assert FLAG not in ch.ciphertext_bytes()       # flag isn't sitting in the clear


@pytest.mark.parametrize("kdf", KDFS)
def test_gcm_tamper_is_detected(kdf):
    ch = lb.generate(PW, FLAG, kdf=kdf, params=_params(kdf))
    ct = bytearray(ch.ciphertext_bytes())
    ct[0] ^= 0x01
    ch.ciphertext = base64.b64encode(bytes(ct)).decode()
    assert lb.attempt(ch, PW) is None              # authentication catches the flip


@pytest.mark.parametrize("kdf", KDFS)
def test_key_is_deterministic_and_input_sensitive(kdf):
    salt = b"\x11" * 16
    p = _params(kdf)
    k1 = lb.derive_key(kdf, PW, salt, p)
    assert k1 == lb.derive_key(kdf, PW, salt, p) and len(k1) == 32
    assert lb.derive_key(kdf, PW + b"!", salt, p) != k1
    assert lb.derive_key(kdf, PW, b"\x22" * 16, p) != k1   # salt matters


def test_json_roundtrip_preserves_challenge():
    ch = lb.generate(PW, FLAG, kdf="scrypt", params=SCRYPT_LIGHT)
    ch2 = lb.Challenge.from_json(ch.to_json())
    assert lb.attempt(ch2, PW) == FLAG


def test_empty_inputs_rejected():
    with pytest.raises(ValueError):
        lb.generate(b"", FLAG, kdf="scrypt", params=SCRYPT_LIGHT)
    with pytest.raises(ValueError):
        lb.generate(PW, b"", kdf="scrypt", params=SCRYPT_LIGHT)


def test_audit_passes_clean_and_flags_a_planted_leak():
    from audit_bounty import audit
    ch = lb.generate(PW, FLAG, kdf="scrypt", params=SCRYPT_LIGHT)
    clean = {"challenge.json": ch.to_json().encode()}
    assert audit(ch, PW, FLAG, clean) == []
    # a binary that accidentally embeds the password must be caught
    leaky = {"challenge.json": ch.to_json().encode(),
             "check.exe": b"\x00prologue" + PW + b"epilogue\x00"}
    fails = audit(ch, PW, FLAG, leaky)
    assert any("password" in f for f in fails)
