"""Source-level containment contracts for the V3 pipe-only bootstrap."""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "bootstrap" / "shard_bootstrap.c").read_text(encoding="utf-8")


def test_packed_file_stays_locked_through_child_lifetime():
    assert "CreateFileA(packedPath, GENERIC_READ, FILE_SHARE_READ" in SOURCE
    assert "FILE_FLAG_OPEN_REPARSE_POINT" in SOURCE
    assert "WaitForSingleObject(process.hProcess, INFINITE)" in SOURCE
    assert SOURCE.index("CreateFileA(packedPath") < SOURCE.index(
        "CreateProcessA(packedPath") < SOURCE.index("CloseHandle(packedFile)")


def test_bootstrap_has_no_secret_or_network_role():
    for forbidden in (
        "WinHttp", "CryptUnprotectData", "NV_RT_GATE", "shard_session.dat",
        "/api/shard/retrieve", "SetEnvironmentVariable", "Authorization:",
    ):
        assert forbidden not in SOURCE
    assert "OrionNative.packed.exe" in SOURCE


def test_only_a_closed_anonymous_pipe_can_reach_the_packed_child():
    assert "GetFileType(stdinPipe) != FILE_TYPE_PIPE" in SOURCE
    assert "PROC_THREAD_ATTRIBUTE_HANDLE_LIST" in SOURCE
    assert "HANDLE allowed[2] = {stdinPipe, nullOutput}" in SOURCE
    assert "STARTF_USESTDHANDLES" in SOURCE
    assert "startup.StartupInfo.hStdInput = stdinPipe" in SOURCE
    assert "startup.StartupInfo.hStdOutput = nullOutput" in SOURCE
    assert "startup.StartupInfo.hStdError = nullOutput" in SOURCE


def test_direct_startup_delegates_only_to_the_hash_bound_verified_broker():
    assert "Venice must be started by its verified launcher." in SOURCE
    assert "lethe_launch_sibling_broker(exeDir)" in SOURCE
    assert "LETHE_ORION_ACTIVATE_SHA256_MARKER" in SOURCE
    assert "s_broker_binding_marker" in SOURCE
    assert "static const volatile char" in SOURCE
    assert "broker_binding_marker_is_present" in SOURCE
    assert "SetHandleInformation(stdinPipe, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)" in SOURCE
