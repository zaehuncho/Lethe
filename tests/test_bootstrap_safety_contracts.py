"""Source-level containment contracts for the experimental shard bootstrap."""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "bootstrap" / "shard_bootstrap.c").read_text(encoding="utf-8")


def test_content_id_handle_stays_locked_through_launch():
    assert "static int pe_content_id(HANDLE hFile" in SOURCE
    assert "CreateFileA(packedPath, GENERIC_READ, FILE_SHARE_READ" in SOURCE
    assert SOURCE.count("pe_content_id(packedFile,") == 2
    assert SOURCE.index("CreateFileA(packedPath") < SOURCE.index(
        "CreateProcessA(packedPath") < SOURCE.index(
            "CloseHandle(packedFile);\n    packedFile = INVALID_HANDLE_VALUE;")


def test_secret_buffers_are_wiped_on_centralized_cleanup_paths():
    assert "SecureZeroMemory(data, dataSize);" in SOURCE
    assert "SecureZeroMemory(body, sizeof(body));" in SOURCE
    assert "SecureZeroMemory(response, sizeof(response));" in SOURCE
    assert "if (result != 0 && shard_out) SecureZeroMemory(shard_out, 65);" in SOURCE
    assert "SecureZeroMemory(licenseKey, sizeof(licenseKey));" in SOURCE


def test_runtime_gate_environment_is_fail_closed():
    assert 'if (!SetEnvironmentVariableA("NV_RT_GATE", shard))' in SOURCE
    assert 'if (gateSet) SetEnvironmentVariableA("NV_RT_GATE", NULL);' in SOURCE
