"""CLI parsing, environment handoff, and human-readable output regressions."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

import lethe
from packer import orchestrator


def _result(**overrides):
    fields = {
        "input_path": "input.exe",
        "output_path": "output.exe",
        "ok": True,
        "error": None,
        "original_size": 100,
        "packed_size": 125,
        "ratio": 1.25,
        "elapsed_ms": 2.0,
        "build_id": "a" * 64,
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def test_summary_reports_growth_and_build_id(capsys):
    lethe._print_summary(_result(), verbose=False)
    output = capsys.readouterr().out
    assert "grew 25.0%" in output
    assert "saved -" not in output
    assert "a" * 64 in output


@pytest.mark.parametrize("flag", ["--shard-max-activations", "--shard-ttl-hours"])
def test_shard_limits_reject_negative_values(flag):
    with pytest.raises(SystemExit):
        lethe.build_parser().parse_args(["input.exe", flag, "-1"])


def test_cli_defaults_are_release_safe():
    args = lethe.build_parser().parse_args(["input.exe"])
    assert args.anti_debug == "off"
    assert orchestrator.PackOptions().anti_debug is False
    assert args.memory_guard is False
    assert args.enable_experimental_dll is False
    assert args.enable_experimental_server_shard is False


@pytest.mark.parametrize(
    "feature_args, expected",
    [
        (["--dll"], "--enable-experimental-dll"),
        (["--server-shard"], "--enable-experimental-server-shard"),
        (["--enable-experimental-server-shard"], "requires --server-shard"),
    ],
)
def test_experimental_paths_require_named_acknowledgment(
        feature_args, expected, tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"test fixture")

    assert lethe.main([str(input_path), *feature_args]) == lethe.EXIT_USAGE
    assert expected in capsys.readouterr().err


def test_experimental_acknowledgments_are_scoped_to_pack_call(monkeypatch, tmp_path):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"test fixture")
    observed = {}

    def fake_pack(_path, _options, progress=None):
        observed["dll"] = os.environ.get("LETHE_ENABLE_EXPERIMENTAL_DLL")
        observed["shard"] = os.environ.get(
            "LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD")
        return _result()

    monkeypatch.setattr(orchestrator, "pack_file", fake_pack)
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "previous")
    monkeypatch.delenv("LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD", raising=False)

    rc = lethe.main([
        str(input_path), "--dll", "--enable-experimental-dll",
        "--server-shard", "--enable-experimental-server-shard",
    ])

    assert rc == lethe.EXIT_OK
    assert observed == {"dll": "1", "shard": "1"}
    assert os.environ["LETHE_ENABLE_EXPERIMENTAL_DLL"] == "previous"
    assert "LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD" not in os.environ


def test_environment_secrets_are_passed_to_core(monkeypatch, tmp_path):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"test fixture")
    captured = {}

    def fake_pack(path, options, progress=None):
        captured["path"] = path
        captured["options"] = options
        captured["progress"] = progress
        return _result(input_path=path)

    monkeypatch.setattr(orchestrator, "pack_file", fake_pack)
    monkeypatch.setenv("LETHE_SHARD_AUTH", "env-token")
    monkeypatch.setenv("LETHE_SHARD_PIN_PEM", "pin.pem")

    rc = lethe.main([str(input_path), "output.exe"])

    assert rc == lethe.EXIT_OK
    assert captured["options"].shard_auth == "env-token"
    assert captured["options"].shard_pin_pem == "pin.pem"


def test_cli_secret_overrides_environment(monkeypatch, tmp_path):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"test fixture")
    captured = {}

    def fake_pack(_path, options, progress=None):
        captured["options"] = options
        return _result()

    monkeypatch.setattr(orchestrator, "pack_file", fake_pack)
    monkeypatch.setenv("LETHE_SHARD_AUTH", "env-token")

    rc = lethe.main([
        str(input_path), "output.exe", "--shard-auth", "cli-token",
        "--stub-path", "fresh-stub.dll",
    ])

    assert rc == lethe.EXIT_OK
    assert captured["options"].shard_auth == "cli-token"
    assert captured["options"].stub_path == "fresh-stub.dll"
