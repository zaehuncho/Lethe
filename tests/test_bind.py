"""Tests for bind/lethe_bind.py: dependency hash-pinning + optional signing."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bind"))
import lethe_bind as lb  # noqa: E402

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey)


def _w(p: Path, data: bytes) -> str:
    p.write_bytes(data)
    return str(p)


def test_build_and_verify_ok(tmp_path):
    exe = _w(tmp_path / "app.exe", b"MZ" + b"\x00" * 100)
    _w(tmp_path / "core.dll", b"core-bytes")
    _w(tmp_path / "vision.dll", b"vision-bytes")
    m = lb.build_manifest(exe, [str(tmp_path / "core.dll"),
                                str(tmp_path / "vision.dll")])
    assert set(m.deps) == {"core.dll", "vision.dll"}
    assert lb.verify_manifest(m, str(tmp_path)) == []
    assert lb.verify_manifest(m, str(tmp_path), check_main=True) == []


def test_tamper_detected(tmp_path):
    exe = _w(tmp_path / "app.exe", b"MZ")
    _w(tmp_path / "core.dll", b"core-bytes")
    m = lb.build_manifest(exe, [str(tmp_path / "core.dll")])
    _w(tmp_path / "core.dll", b"core-bytes-PATCHED")     # swap the dll
    fails = lb.verify_manifest(m, str(tmp_path))
    assert any("hash mismatch" in f and "core.dll" in f for f in fails)


def test_missing_dependency(tmp_path):
    exe = _w(tmp_path / "app.exe", b"MZ")
    _w(tmp_path / "core.dll", b"x")
    m = lb.build_manifest(exe, [str(tmp_path / "core.dll")])
    (tmp_path / "core.dll").unlink()
    fails = lb.verify_manifest(m, str(tmp_path))
    assert any("missing" in f and "core.dll" in f for f in fails)


def test_json_roundtrip(tmp_path):
    exe = _w(tmp_path / "a.exe", b"MZ")
    m = lb.build_manifest(exe, [])
    assert lb.Manifest.from_json(m.to_json()) == m


def test_signature_roundtrip_wrong_key_and_tamper(tmp_path):
    exe = _w(tmp_path / "a.exe", b"MZ")
    _w(tmp_path / "core.dll", b"c")
    m = lb.build_manifest(exe, [str(tmp_path / "core.dll")])
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    pub = sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    sig = lb.sign_manifest(m, priv)
    assert lb.verify_signature(m, sig, pub) is True
    # a different key must not validate
    other_pub = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    assert lb.verify_signature(m, sig, other_pub) is False
    # tampering the manifest invalidates the signature
    m.deps["core.dll"] = "0" * 64
    assert lb.verify_signature(m, sig, pub) is False
