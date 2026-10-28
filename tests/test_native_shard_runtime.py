"""Opt-in native proof that the server shard is mandatory at runtime."""
from __future__ import annotations

import os
import subprocess
import struct
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


def _vsg3_frame(shard: bytes, *, trailing: bytes = b"") -> bytes:
    assert len(shard) == 32
    return b"VSG3" + struct.pack("<HH", 3, 32) + shard + trailing


def _run(executable: Path, frame: bytes | None) -> subprocess.CompletedProcess:
    kwargs = {}
    if frame is not None:
        # subprocess closes its write end after the bytes are sent, which proves
        # the runtime's mandatory EOF condition as well as the fixed wire frame.
        kwargs["input"] = frame
    return subprocess.run(
        [str(executable)],
        cwd=str(executable.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
        **kwargs,
    )


@pytest.mark.skipif(os.name != "nt", reason="native loader is Windows-only")
def test_native_server_shard_rejects_missing_wrong_and_trailing_pipe_frames(tmp_path,
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
    missing = _run(packed, b"")
    wrong_bytes = bytes(byte ^ 0xFF for byte in assembly.server_shard)
    wrong = _run(packed, _vsg3_frame(wrong_bytes))
    trailing = _run(packed, _vsg3_frame(assembly.server_shard, trailing=b"x"))
    correct = _run(packed, _vsg3_frame(assembly.server_shard))

    assert missing.returncode == 1
    assert wrong.returncode == 1
    assert trailing.returncode == 1
    assert correct.returncode == expected.returncode
    assert correct.stdout == expected.stdout
    assert correct.stderr == expected.stderr
