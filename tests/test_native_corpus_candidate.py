"""Candidate corpus profile contracts; no compiler or native process runs."""
from dataclasses import replace
import hashlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import test_native_virtualization_corpus as corpus


def _profile_fixture(monkeypatch, tmp_path):
    stub = tmp_path / "lethe_stub_x64.dll"
    stub.write_bytes(b"unit fixture, never executed")
    manifest = stub.with_suffix(".manifest.json")
    manifest.write_text('{"unit":"candidate"}', encoding="utf-8")
    digest = hashlib.sha256(stub.read_bytes()).hexdigest()
    opcodes = SimpleNamespace(is_canonical=False)
    validate = Mock(return_value={"sha256": digest})
    load = Mock(return_value=(stub.read_bytes(), digest, opcodes, "handler-hash", True))
    monkeypatch.setattr(corpus, "validate_candidate_bundle", validate)
    monkeypatch.setattr(corpus.orchestrator, "_load_virtualization_build", load)
    monkeypatch.setenv(corpus._CANDIDATE_GATE, str(stub))
    return stub, manifest, digest, validate, load


def test_absent_candidate_keeps_self_built_fixture_mode_without_validation(monkeypatch):
    monkeypatch.delenv(corpus._CANDIDATE_GATE, raising=False)
    validate = Mock(side_effect=AssertionError("unexpected verification"))
    load = Mock(side_effect=AssertionError("unexpected runtime load"))
    monkeypatch.setattr(corpus, "validate_candidate_bundle", validate)
    monkeypatch.setattr(corpus.orchestrator, "_load_virtualization_build", load)
    assert corpus._candidate_runtime_from_environment() is None
    validate.assert_not_called()
    load.assert_not_called()


@pytest.mark.parametrize("value", ["", " ", "bad\0path"])
def test_explicit_empty_or_invalid_path_never_falls_back(monkeypatch, value):
    # The OS rejects embedded NULs before setenv; exercise the parser directly.
    monkeypatch.setattr(corpus.os, "environ", {corpus._CANDIDATE_GATE: value})
    with pytest.raises(ValueError, match="must name an intact candidate"):
        corpus._candidate_runtime_from_environment()


def test_complete_validation_precedes_strict_loading(monkeypatch, tmp_path):
    stub, manifest, digest, validate, load = _profile_fixture(monkeypatch, tmp_path)
    calls = []
    validate.side_effect = lambda *_: calls.append("validate") or {"sha256": digest}
    result = load.return_value
    load.side_effect = lambda *_args, **_kwargs: calls.append("load") or result
    profile = corpus._candidate_runtime_from_environment()
    assert calls == ["validate", "load"]
    validate.assert_called_once_with(stub, manifest)
    load.assert_called_once_with(str(stub), allow_unverified_stub_for_tests=False)
    assert profile.stub == stub and profile.sha256 == digest
    assert profile.rolling is True
    assert profile.allow_unverified_stub_for_tests is False
    assert profile.manifest_sha256 == hashlib.sha256(manifest.read_bytes()).hexdigest()


def test_verification_error_never_uses_unverified_loading(monkeypatch, tmp_path):
    _stub, _manifest, _digest, validate, load = _profile_fixture(monkeypatch, tmp_path)
    validate.side_effect = ValueError("candidate evidence rejected")
    with pytest.raises(ValueError, match="evidence rejected"):
        corpus._candidate_runtime_from_environment()
    load.assert_not_called()


def test_native_entry_point_rejects_bad_candidate_before_build_or_execution(monkeypatch, tmp_path):
    monkeypatch.setenv(corpus._RUN_GATE, "1")
    monkeypatch.setenv(corpus._CANDIDATE_GATE, str(tmp_path / "missing.dll"))
    guarded = []
    for name in ("_build_fixture", "_build_stub", "_run", "_visual_studio_available"):
        operation = Mock(side_effect=AssertionError("candidate failed too late"))
        monkeypatch.setattr(corpus, name, operation)
        guarded.append(operation)
    with pytest.raises(FileNotFoundError):
        corpus.test_native_selected_function_corpus_matches_original(monkeypatch)
    for operation in guarded:
        operation.assert_not_called()


def test_preflight_rejects_artifact_change(monkeypatch, tmp_path):
    _stub, _manifest, _digest, _validate, load = _profile_fixture(monkeypatch, tmp_path)
    blob, _digest, opcodes, handler, rolling = load.return_value
    load.return_value = (blob, "0"*64, opcodes, handler, rolling)
    with pytest.raises(ValueError, match="artifact changed during corpus preflight"):
        corpus._candidate_runtime_from_environment()


def test_preflight_rejects_manifest_change(monkeypatch, tmp_path):
    _stub, manifest, _digest, _validate, load = _profile_fixture(monkeypatch, tmp_path)
    result = load.return_value
    def changing_load(*_args, **_kwargs):
        manifest.write_text("changed", encoding="utf-8")
        return result
    load.side_effect = changing_load
    with pytest.raises(ValueError, match="manifest changed during corpus preflight"):
        corpus._candidate_runtime_from_environment()


def test_reload_pins_same_verified_runtime_and_mode(monkeypatch, tmp_path):
    stub, _manifest, digest, _validate, load = _profile_fixture(monkeypatch, tmp_path)
    profile = corpus._candidate_runtime_from_environment()
    load.reset_mock()
    reloaded = corpus._reload_candidate_runtime(profile)
    assert reloaded.sha256 == digest and reloaded.manifest_sha256 == profile.manifest_sha256
    assert reloaded.allow_unverified_stub_for_tests is False
    assert reloaded.rolling is True
    load.assert_called_once_with(str(stub), allow_unverified_stub_for_tests=False)


@pytest.mark.parametrize("change", [{"allow_unverified_stub_for_tests": True}, {"manifest_sha256": None}])
def test_reload_rejects_non_verified_profile(monkeypatch, tmp_path, change):
    _stub, _manifest, _digest, _validate, load = _profile_fixture(monkeypatch, tmp_path)
    profile = replace(corpus._candidate_runtime_from_environment(), **change)
    load.reset_mock()
    with pytest.raises(ValueError, match="verified preflight profile"):
        corpus._reload_candidate_runtime(profile)
    load.assert_not_called()


def test_reload_rejects_manifest_change_before_loading(monkeypatch, tmp_path):
    _stub, manifest, _digest, _validate, load = _profile_fixture(monkeypatch, tmp_path)
    profile = corpus._candidate_runtime_from_environment()
    manifest.write_text("changed", encoding="utf-8")
    load.reset_mock()
    with pytest.raises(ValueError, match="manifest changed after corpus preflight"):
        corpus._reload_candidate_runtime(profile)
    load.assert_not_called()


def test_reload_rejects_artifact_change(monkeypatch, tmp_path):
    _stub, _manifest, _digest, _validate, load = _profile_fixture(monkeypatch, tmp_path)
    profile = corpus._candidate_runtime_from_environment()
    blob, _digest, opcodes, handler, rolling = load.return_value
    load.return_value = (blob, "0"*64, opcodes, handler, rolling)
    with pytest.raises(ValueError, match="artifact changed after corpus preflight"):
        corpus._reload_candidate_runtime(profile)


def test_reload_rejects_manifest_change_during_loading(monkeypatch, tmp_path):
    _stub, manifest, _digest, _validate, load = _profile_fixture(monkeypatch, tmp_path)
    profile = corpus._candidate_runtime_from_environment()
    result = load.return_value
    def changing_load(*_args, **_kwargs):
        manifest.write_text("changed", encoding="utf-8")
        return result
    load.side_effect = changing_load
    with pytest.raises(ValueError, match="manifest changed during corpus reload"):
        corpus._reload_candidate_runtime(profile)
