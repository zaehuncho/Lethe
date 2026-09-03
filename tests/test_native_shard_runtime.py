"""Opt-in native proof that the server shard is mandatory at runtime."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from packer import assemble, keyed_validation, payload, pe_analyze, report
from packer.orchestrator import PackOptions


def _configured_fixture(name: str) -> Path:
    raw = os.environ.get(name)
    if not raw:
        pytest.skip(f"{name} is required for native shard runtime proof")
    path = Path(raw).resolve()
    if not path.is_file():
        pytest.skip(f"{name} does not name a file: {path}")
    return path


def _run(executable: Path, gate: str | None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    for name in tuple(env):
        if name.upper() == "NV_RT_GATE":
            del env[name]
    if gate is not None:
        env["NV_RT_GATE"] = gate
    return subprocess.run(
        [str(executable)],
        cwd=str(executable.parent),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


@pytest.mark.skipif(os.name != "nt", reason="native loader is Windows-only")
def test_native_server_shard_rejects_missing_and_wrong_gate(tmp_path,
                                                            monkeypatch):
    stub = _configured_fixture("LETHE_NATIVE_STUB_PATH")
    sample = _configured_fixture("LETHE_NATIVE_SAMPLE_EXE")
    packed = tmp_path / "sample_exe.sharded.exe"
    options = PackOptions(server_shard=True, stub_path=str(stub))
    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD", "1")

    parsed = pe_analyze.analyze_pe(str(sample))
    artifacts = payload.build_payload(parsed, options)
    assembly = assemble.build_output_pe(
        parsed,
        artifacts,
        str(packed),
        input_path=str(sample),
        options=options,
        stub_path=str(stub),
    )
    assert assembly.server_shard is not None
    structural = report.validate_packed(str(packed))
    assert structural.ok, structural.reason
    keyed = keyed_validation.validate_staged_output(
        str(packed),
        artifacts,
        server_shard=assembly.server_shard,
        expected_stub_text_rva=assembly.stub_text_rva,
        expected_stub_text_size=assembly.stub_text_size,
        structural=structural,
    )
    assert keyed.ok, keyed.reason

    expected = _run(sample, None)
    missing = _run(packed, None)
    wrong_bytes = bytes(byte ^ 0xFF for byte in assembly.server_shard)
    wrong = _run(packed, wrong_bytes.hex())
    correct = _run(packed, assembly.server_shard.hex())

    assert missing.returncode == 1
    assert wrong.returncode == 1
    assert correct.returncode == expected.returncode
    assert correct.stdout == expected.stdout
    assert correct.stderr == expected.stderr
