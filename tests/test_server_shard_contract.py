"""Release-facing contracts for Lethe server-shard upload and bootstrap fetch."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

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


def test_upload_uses_admin_and_edge_headers_without_customer_identity():
    captured = {}

    def fake_open(request, *, timeout, context):
        captured["request"] = request
        captured["timeout"] = timeout
        return _Response()

    fragment = bytes(range(32))
    with patch("packer.orchestrator._open_shard_request", side_effect=fake_open):
        _upload_shard(
            url="https://api.zaeorion.com/api/shard/store",
            auth="owner-secret",
            build_id="a" * 64,
            shard=fragment,
            edge_auth="edge-secret",
            admin_totp="123456",
        )

    request = captured["request"]
    body = json.loads(request.data)
    assert body["build_id"] == "a" * 64
    assert body["license_id"] == ""
    assert body["hwid_hash"] == ""
    assert body["max_activations"] == 0
    assert request.headers["X-orion-admin-secret"] == "owner-secret"
    assert request.headers["X-edge-auth"] == "edge-secret"
    assert request.headers["X-orion-admin-totp"] == "123456"
    assert "Authorization" not in request.headers
    assert fragment.hex() in request.data.decode("utf-8")


def test_upload_failure_does_not_echo_fragment():
    fragment = bytes(range(32))
    with patch(
        "packer.orchestrator._open_shard_request",
        side_effect=OSError("network unavailable"),
    ), pytest.raises(RuntimeError) as exc:
        _upload_shard(
            url="https://api.zaeorion.com/api/shard/store",
            auth="owner-secret",
            build_id="b" * 64,
            shard=fragment,
        )
    assert fragment.hex() not in str(exc.value)


def test_bootstrap_uses_exact_retrieve_wire_shape():
    assert '\"{\\\"build_id\\\":\\\"%s\\\",\\\"machine_id\\\":\\\"%s\\\"}\"' in SOURCE
    assert '"Authorization: Bearer %s\\r\\n"' in SOURCE
    assert '"X-Orion-Token-Id: %s\\r\\n"' in SOURCE
    assert '"hwid"' not in SOURCE
    assert '"license_key"' not in SOURCE


def test_bootstrap_reads_dpapi_session_and_never_caches_fragment():
    assert "CryptUnprotectData" in SOURCE
    assert "shard_session.dat" in SOURCE
    assert "WriteFile" not in SOURCE
    assert "RegSetValue" not in SOURCE
    assert "OrionNative.packed.exe" in SOURCE
