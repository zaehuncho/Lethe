"""Release-facing contracts for V3 server-shard upload and pipe forwarding."""
from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from packer.orchestrator import _upload_shard


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "bootstrap" / "shard_bootstrap.c").read_text(encoding="utf-8")


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, *_args):
        return b'{"ok":true,"build_id":"' + (b"a" * 64) + b'"}'


@pytest.fixture
def signing_key(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    path = tmp_path / "publisher.pem"
    path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return path, private_key.public_key()


def test_upload_uses_v3_build_scoped_schema_and_one_time_signature(signing_key):
    captured = {}

    def fake_open(request, *, timeout, context):
        captured["request"] = request
        captured["timeout"] = timeout
        return _Response()

    fragment = bytes(range(32))
    with patch("packer.orchestrator._open_shard_request", side_effect=fake_open):
        _upload_shard(
            url="https://api.zaeorion.com/ignored-by-client",
            signing_key_pem=str(signing_key[0]),
            reason="release qualification",
            build_id="a" * 64,
            shard=fragment,
            ttl_hours=7,
        )

    request = captured["request"]
    body = json.loads(request.data)
    assert request.full_url == "https://api.zaeorion.com/api/shard/v3/store"
    assert body["build_id"] == "a" * 64
    assert body["shard"] == fragment.hex()
    assert body["ttl_hours"] == 7
    assert body["reason"] == "release qualification"
    assert isinstance(body["publish_timestamp"], int)
    assert len(body["publish_nonce"]) >= 16
    canonical = {
        "protocol": 1,
        "build_id": body["build_id"],
        "shard": body["shard"],
        "ttl_hours": body["ttl_hours"],
        "reason": body["reason"],
        "publish_timestamp": body["publish_timestamp"],
        "publish_nonce": body["publish_nonce"],
    }
    transcript = (b"orion-shard-v3-store-publish\n" + json.dumps(
        canonical, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
    signature = base64.urlsafe_b64decode(body["signature"] + "==")
    signing_key[1].verify(signature, transcript)
    assert set(request.headers) == {"Content-type"}
    assert "Authorization" not in request.headers


def test_upload_rejects_legacy_per_customer_storage_knobs(signing_key):
    with pytest.raises(ValueError, match="build-scoped"):
        _upload_shard(
            url="https://api.zaeorion.com", signing_key_pem=str(signing_key[0]),
            reason="release qualification",
            build_id="a" * 64, shard=bytes(32), license_id="legacy-license",
        )


def test_upload_failure_does_not_echo_fragment(signing_key):
    fragment = bytes(range(32))
    with patch(
        "packer.orchestrator._open_shard_request",
        side_effect=OSError("network unavailable"),
    ), pytest.raises(RuntimeError) as exc:
        _upload_shard(
            url="https://api.zaeorion.com", signing_key_pem=str(signing_key[0]),
            reason="release qualification",
            build_id="b" * 64, shard=fragment,
        )
    assert fragment.hex() not in str(exc.value)


def test_bootstrap_forwards_only_the_broker_pipe_and_never_fetches_or_caches():
    assert "PROC_THREAD_ATTRIBUTE_HANDLE_LIST" in SOURCE
    assert "OrionNative.packed.exe" in SOURCE
    for forbidden in (
        "CryptUnprotectData", "shard_session.dat", "WriteFile", "RegSetValue",
        "WinHttp", "NV_RT_GATE", "/api/shard/retrieve", "license_key",
    ):
        assert forbidden not in SOURCE
