"""Fail-closed core gates for runtime paths that are not release-approved."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from packer import assemble


@pytest.mark.parametrize(
    "is_dll, server_shard, expected",
    [
        (True, False, "DLL packing is experimental"),
        (False, True, "server-shard packing is experimental"),
    ],
)
def test_core_rejects_experimental_paths_by_default(
        monkeypatch, is_dll, server_shard, expected):
    monkeypatch.delenv("LETHE_ENABLE_EXPERIMENTAL_DLL", raising=False)
    monkeypatch.delenv("LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD", raising=False)

    with pytest.raises(assemble.AssembleError, match=expected):
        assemble._require_experimental_runtime_paths(
            is_dll=is_dll, server_shard=server_shard)


def test_core_requires_exact_opt_in_value(monkeypatch):
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "true")
    with pytest.raises(assemble.AssembleError, match="DLL packing is experimental"):
        assemble._require_experimental_runtime_paths(is_dll=True, server_shard=False)

    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    assemble._require_experimental_runtime_paths(is_dll=True, server_shard=False)


def test_core_accepts_explicit_opt_ins(monkeypatch):
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD", "1")
    assemble._require_experimental_runtime_paths(is_dll=True, server_shard=True)


@pytest.mark.parametrize(
    "is_dll, server_shard, expected",
    [
        (True, False, "DLL packing is experimental"),
        (False, True, "server-shard packing is experimental"),
    ],
)
def test_builder_wires_fail_closed_gate_before_stub_loading(
        monkeypatch, tmp_path, is_dll, server_shard, expected):
    monkeypatch.delenv("LETHE_ENABLE_EXPERIMENTAL_DLL", raising=False)
    monkeypatch.delenv("LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD", raising=False)
    parsed = SimpleNamespace(image_base=0x140000000, size_of_image=0x2000)
    artifacts = SimpleNamespace(is_dll=is_dll)
    options = SimpleNamespace(server_shard=server_shard)

    with pytest.raises(assemble.AssembleError, match=expected):
        assemble.build_output_pe(
            parsed, artifacts, str(tmp_path / "must-not-exist.exe"), options=options)

    assert not (tmp_path / "must-not-exist.exe").exists()
