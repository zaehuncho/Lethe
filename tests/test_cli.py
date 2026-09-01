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
    assert args.process_hardening is False
    assert orchestrator.PackOptions().process_hardening is False
    assert args.enable_experimental_dll is False
    assert args.enable_experimental_server_shard is False
    assert args.enable_experimental_virtualization is False
    assert args.virtualize_function == []
    assert args.virtualization_gap == []
    assert args.virtualization_tail_exit == []
    assert args.acknowledge_unproven_indirect_targets is False
    assert orchestrator.PackOptions().virtualization_specs == ()
    assert orchestrator.PackOptions().virtualization_gap_acknowledgements == ()
    assert orchestrator.PackOptions().virtualization_tail_exit_approvals == ()
    assert orchestrator.PackOptions().acknowledge_unproven_indirect_targets is False


def test_virtualization_specs_accept_decimal_and_hex():
    args = lethe.build_parser().parse_args([
        "input.exe",
        "--virtualize-function", "Init:0x1200:64",
        "--virtualize-function", "Tick:8192:0x20",
    ])
    assert args.virtualize_function == [
        ("Init", 0x1200, 64),
        ("Tick", 8192, 0x20),
    ]


def test_virtualization_proof_options_accept_decimal_hex_and_colon_rationales():
    args = lethe.build_parser().parse_args([
        "input.exe",
        "--virtualization-gap", "0x1200:64:linker:padding",
        "--virtualization-tail-exit", "4096:0x1004:8192:tail:dispatch",
        "--acknowledge-unproven-indirect-targets",
    ])
    assert args.virtualization_gap == [(0x1200, 64, "linker:padding")]
    assert args.virtualization_tail_exit == [
        (4096, 0x1004, 8192, "tail:dispatch")
    ]
    assert args.acknowledge_unproven_indirect_targets is True


@pytest.mark.parametrize(
    "value",
    ["missing", ":0x1000:20", "name:nope:20", "name:0x1000:4"],
)
def test_virtualization_specs_reject_malformed_values(value):
    with pytest.raises(SystemExit):
        lethe.build_parser().parse_args([
            "input.exe", "--virtualize-function", value,
        ])


@pytest.mark.parametrize(
    "flag, value",
    [
        ("--virtualization-gap", "0x1000:0:"),
        ("--virtualization-gap", "nope:16:padding"),
        ("--virtualization-tail-exit", "0x1000:0x1004:tail"),
        ("--virtualization-tail-exit", "0:0x1004:0x2000:tail"),
    ],
)
def test_virtualization_proof_options_reject_malformed_values(flag, value):
    with pytest.raises(SystemExit):
        lethe.build_parser().parse_args(["input.exe", flag, value])


@pytest.mark.parametrize(
    "feature_args, expected",
    [
        (["--dll"], "--enable-experimental-dll"),
        (["--server-shard"], "--enable-experimental-server-shard"),
        (["--enable-experimental-server-shard"], "requires --server-shard"),
        (["--virtualize-function", "Init:0x1000:16"],
         "--enable-experimental-virtualization"),
        (["--enable-experimental-virtualization"],
         "requires at least one --virtualize-function"),
        (["--virtualize-function", "Init:0x1000:16",
          "--enable-experimental-virtualization"],
         "requires an explicit fresh --stub-path"),
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
        observed["virtualization"] = os.environ.get(
            "LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION")
        return _result()

    monkeypatch.setattr(orchestrator, "pack_file", fake_pack)
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "previous")
    monkeypatch.delenv("LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD", raising=False)
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", "previous")

    rc = lethe.main([
        str(input_path), "--dll", "--enable-experimental-dll",
        "--server-shard", "--enable-experimental-server-shard",
        "--virtualize-function", "Init:0x1000:16",
        "--enable-experimental-virtualization", "--stub-path", "fresh.dll",
        "--acknowledge-unproven-indirect-targets",
    ])

    assert rc == lethe.EXIT_OK
    assert observed == {"dll": "1", "shard": "1", "virtualization": "1"}
    assert os.environ["LETHE_ENABLE_EXPERIMENTAL_DLL"] == "previous"
    assert "LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD" not in os.environ
    assert os.environ["LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION"] == "previous"


@pytest.mark.parametrize(
    "specs, expected",
    [
        (["One:0x1000:16", "One:0x2000:16"], "duplicate"),
        (["One:0x1000:32", "Two:0x1010:16"], "overlapping"),
    ],
)
def test_cli_rejects_duplicate_or_overlapping_virtualization_specs(
        specs, expected, tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"test fixture")
    argv = [str(input_path), "--enable-experimental-virtualization",
            "--stub-path", "fresh.dll",
            "--acknowledge-unproven-indirect-targets"]
    for spec in specs:
        argv.extend(["--virtualize-function", spec])

    assert lethe.main(argv) == lethe.EXIT_USAGE
    assert expected in capsys.readouterr().err


def test_cli_passes_immutable_virtualization_specs(monkeypatch, tmp_path):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"test fixture")
    captured = {}

    def fake_pack(_path, options, progress=None):
        captured["specs"] = options.virtualization_specs
        captured["gaps"] = options.virtualization_gap_acknowledgements
        captured["tails"] = options.virtualization_tail_exit_approvals
        captured["indirect"] = options.acknowledge_unproven_indirect_targets
        return _result()

    monkeypatch.setattr(orchestrator, "pack_file", fake_pack)
    rc = lethe.main([
        str(input_path), "--enable-experimental-virtualization",
        "--stub-path", "fresh.dll",
        "--virtualize-function", "Init:0x1200:64",
        "--virtualization-gap", "0x1000:0x20:linker padding",
        "--virtualization-tail-exit", "0x1200:0x1204:0x2000:known tail",
        "--acknowledge-unproven-indirect-targets",
    ])

    assert rc == lethe.EXIT_OK
    assert captured["specs"] == (
        orchestrator.VirtualizationSpec("Init", 0x1200, 64),
    )
    assert captured["gaps"] == (
        orchestrator.VirtualizationGapAcknowledgement(
            0x1000, 0x20, "linker padding"),
    )
    assert captured["tails"] == (
        orchestrator.VirtualizationTailExitApproval(
            0x1200, 0x1204, 0x2000, "known tail"),
    )
    assert captured["indirect"] is True


@pytest.mark.parametrize(
    "proof_args",
    [
        ["--virtualization-gap", "0x1000:16:padding"],
        ["--virtualization-tail-exit", "0x1000:0x1004:0x2000:tail"],
        ["--acknowledge-unproven-indirect-targets"],
    ],
)
def test_cli_rejects_virtualization_proof_options_without_selection(
        proof_args, tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"test fixture")

    assert lethe.main([str(input_path), *proof_args]) == lethe.EXIT_USAGE
    assert "require at least one --virtualize-function" in capsys.readouterr().err


def test_cli_requires_explicit_indirect_target_acknowledgement(tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"test fixture")

    assert lethe.main([
        str(input_path),
        "--virtualize-function", "Init:0x1000:16",
        "--enable-experimental-virtualization",
        "--stub-path", "fresh.dll",
    ]) == lethe.EXIT_USAGE
    assert "--acknowledge-unproven-indirect-targets" in capsys.readouterr().err


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
