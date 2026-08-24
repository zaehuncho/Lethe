"""Shard-upload host pinning (critique #7).

A misrouted shard upload permanently bricks the packed binary: the binary is
keyed to a shard the real gate never receives, so it can never be released. The
uploader must therefore HARD-FAIL on a hostname mismatch (unless explicitly
overridden) and refuse plaintext HTTP outright. Both guards fire before any
network I/O, so these tests are deterministic and offline.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packer import orchestrator  # noqa: E402

_BUILD_ID = "00000000-0000-0000-0000-000000000000"


def test_wrong_host_hard_fails_before_any_network():
    with pytest.raises(ValueError, match="does not match the pinned"):
        orchestrator._upload_shard(
            b"\x00" * 16,
            build_id=_BUILD_ID,
            url="https://evil.example.com/api/shard",
            auth="token",
        )


def test_non_https_is_refused_before_any_network():
    with pytest.raises(ValueError, match="requires HTTPS"):
        orchestrator._upload_shard(
            b"\x00" * 16,
            build_id=_BUILD_ID,
            url="http://api.zaeorion.com/api/shard",
            auth="token",
        )


def test_override_flag_bypasses_the_host_guard():
    # With allow_unpinned_host=True the host guard must NOT raise; the call then
    # fails later at the network layer, proving the guard was bypassed rather
    # than the request. The failure must not be the host-pin ValueError.
    with pytest.raises(Exception) as excinfo:
        orchestrator._upload_shard(
            b"\x00" * 16,
            build_id=_BUILD_ID,
            url="https://staging.nonexistent.invalid/api/shard",
            auth="token",
            allow_unpinned_host=True,
        )
    assert "does not match the pinned" not in str(excinfo.value)
