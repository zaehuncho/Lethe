"""Shard-upload identity, validation, and host pinning.

A misrouted shard upload permanently bricks the packed binary: the binary is
keyed to a shard the real gate never receives, so it can never be released. The
uploader must therefore HARD-FAIL on a hostname mismatch (unless explicitly
overridden) and refuse plaintext HTTP outright. Both guards fire before any
network I/O, so these tests are deterministic and offline.
"""

import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packer import orchestrator  # noqa: E402

_BUILD_ID = "0" * 64
_SHARD = b"\x00" * 32
_PINNED_URL = f"https://{orchestrator._SHARD_API_HOST}/api/shard"


class _Response:
    def __init__(self, build_id: str):
        self.status = 201
        self._build_id = build_id

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        payload = (
            '{"ok":true,"build_id":"' + self._build_id + '"}'
        ).encode("ascii")
        return payload if size < 0 else payload[:size]


@pytest.fixture
def signing_key(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "publisher.pem"
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return str(path)


def test_wrong_host_hard_fails_before_any_network(signing_key):
    with pytest.raises(ValueError, match="does not match the pinned"):
        orchestrator._upload_shard(
            _SHARD,
            build_id=_BUILD_ID,
            url="https://evil.example.com/api/shard",
            signing_key_pem=signing_key,
            reason="host guard test",
        )


def test_non_https_is_refused_before_any_network(signing_key):
    with pytest.raises(ValueError, match="requires HTTPS"):
        orchestrator._upload_shard(
            _SHARD,
            build_id=_BUILD_ID,
            url=f"http://{orchestrator._SHARD_API_HOST}/api/shard",
            signing_key_pem=signing_key,
            reason="scheme guard test",
        )


def test_override_flag_bypasses_the_host_guard(monkeypatch, signing_key):
    def offline(*_args, **_kwargs):
        raise OSError("offline test")

    monkeypatch.setattr(orchestrator, "_open_shard_request", offline)
    with pytest.raises(Exception) as excinfo:
        orchestrator._upload_shard(
            _SHARD,
            build_id=_BUILD_ID,
            url="https://staging.nonexistent.invalid/api/shard",
            signing_key_pem=signing_key,
            reason="staging host test",
            allow_unpinned_host=True,
        )
    assert "does not match the pinned" not in str(excinfo.value)


def test_invalid_build_id_fails_before_network(signing_key):
    with pytest.raises(ValueError, match="64-character"):
        orchestrator._upload_shard(
            _SHARD,
            build_id="00000000-0000-0000-0000-000000000000",
            url=_PINNED_URL,
            signing_key_pem=signing_key,
            reason="build id test",
        )


def test_upload_requires_matching_response_build_id(monkeypatch, signing_key):
    monkeypatch.setattr(
        orchestrator,
        "_open_shard_request",
        lambda *_args, **_kwargs: _Response("f" * 64),
    )
    with pytest.raises(RuntimeError, match="mismatched build_id"):
        orchestrator._upload_shard(
            _SHARD,
            build_id=_BUILD_ID,
            url=_PINNED_URL,
            signing_key_pem=signing_key,
            reason="response test",
        )


def test_upload_accepts_exact_response_build_id(monkeypatch, signing_key):
    monkeypatch.setattr(
        orchestrator,
        "_open_shard_request",
        lambda *_args, **_kwargs: _Response(_BUILD_ID.upper()),
    )
    result = orchestrator._upload_shard(
        _SHARD,
        build_id=_BUILD_ID,
        url=_PINNED_URL,
        signing_key_pem=signing_key,
        reason="response test",
    )
    assert result["ok"] is True


def test_redirect_handler_never_constructs_a_followup_request():
    handler = orchestrator._RejectRedirects()
    request = orchestrator.urllib.request.Request(
        f"https://{orchestrator._SHARD_API_HOST}/api/shard/store",
        headers={"Authorization": "Bearer secret"},
    )
    assert handler.redirect_request(
        request, None, 302, "Found", {}, "https://evil.example/shard") is None


def test_oversized_response_is_rejected(monkeypatch, signing_key):
    class Oversized(_Response):
        def read(self, size=-1):
            return b"x" * (orchestrator._MAX_SHARD_RESPONSE + 1)

    monkeypatch.setattr(
        orchestrator,
        "_open_shard_request",
        lambda *_args, **_kwargs: Oversized(_BUILD_ID),
    )
    with pytest.raises(RuntimeError, match="exceeds 64 KiB"):
        orchestrator._upload_shard(
            _SHARD,
            build_id=_BUILD_ID,
            url=_PINNED_URL,
            signing_key_pem=signing_key,
            reason="response size test",
        )
