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
    assert "SecureZeroMemory(body, sizeof(body));" in SOURCE
    assert "SecureZeroMemory(response, sizeof(response));" in SOURCE
    assert "if (result != 0 && shard_out) SecureZeroMemory(shard_out, 65);" in SOURCE
    assert "SecureZeroMemory(token, sizeof(token));" in SOURCE
    assert "SecureZeroMemory(tokenId, sizeof(tokenId));" in SOURCE
    assert "SecureZeroMemory(machineId, sizeof(machineId));" in SOURCE
    assert "CryptUnprotectData" in SOURCE


def test_runtime_gate_environment_is_fail_closed():
    assert 'if (!SetEnvironmentVariableA("NV_RT_GATE", shard))' in SOURCE
    assert 'if (gateSet) SetEnvironmentVariableA("NV_RT_GATE", NULL);' in SOURCE


def test_retrieve_contract_is_session_bound_and_has_no_shared_edge_secret():
    assert '#define SHARD_PATH      L"/api/shard/retrieve"' in SOURCE
    assert '\"{\\\"build_id\\\":\\\"%s\\\",\\\"machine_id\\\":\\\"%s\\\"}\"' in SOURCE
    assert '"Authorization: Bearer %s\\r\\n"' in SOURCE
    assert '"X-Orion-Token-Id: %s\\r\\n"' in SOURCE
    assert "X-Edge-Auth" not in SOURCE
    assert "license_key" not in SOURCE
    assert "settings.json" not in SOURCE


def test_tls_and_redirect_policy_are_fail_closed():
    assert "WINHTTP_FLAG_SECURE" in SOURCE
    assert "WINHTTP_OPTION_REDIRECT_POLICY_NEVER" in SOURCE
    assert "WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2" in SOURCE


def test_product_errors_are_mapped_to_plain_english_actions():
    for code in (
        "machine_mismatch",
        "build_revoked",
        "rate_limited",
        "license_inactive",
        "license_expired",
    ):
        assert code in SOURCE
    assert "Subscribe at zaeorion.com" in SOURCE
    assert "Use /hwid_reset" in SOURCE
