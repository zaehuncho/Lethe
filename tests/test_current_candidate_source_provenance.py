"""Experimental candidates must run only with the source that produced them.

The schema-2 identity verifier deliberately also supports old-bundle release
replay.  Only a new production pack operation requires an exact clean checkout.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from daedalus import shuffle_opcodes
from lifter import direct_control_flow
from packer import orchestrator, pe_analyze, release_attestation, virtualize
from tests.test_virtualization_orchestration import _patch_post_materialization_pipeline


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True,
        text=True, encoding="utf-8", check=True,
    )
    return result.stdout.strip()


def _checkout(repo: Path) -> str:
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "source.py").write_text("value = 1\n", encoding="ascii")
    _git(repo, "add", "source.py")
    _git(repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-qm", "source")
    return _git(repo, "rev-parse", "HEAD")


def _candidate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
               source_commit: str | None, *,
               evidence_commit: str | None = None) -> Path:
    stub = tmp_path / "candidate" / "lethe_stub_x64.dll"
    stub.parent.mkdir()
    blob = b"synthetic candidate runtime"
    stub.write_bytes(blob)
    stub.with_suffix(".manifest.json").write_text("{}\n", encoding="ascii")
    generated = shuffle_opcodes.generate_shuffle(bytes.fromhex("11" * 32))
    metadata = {
        "schema": 2, "artifact": stub.name, "size_bytes": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "dvm_shuffle_seed": "11" * 32,
        "dvm_handler_variant_sha256": generated["handler_variant_sha256"],
        "dvm_rolling": True, "dvm_paged_runtime": True,
    }
    if source_commit is not None:
        metadata["source_commit"] = source_commit
    evidence_dir = stub.parent / "evidence"
    evidence_dir.mkdir()
    metadata["evidence"] = []
    for name, document in (
        ("production-evidence.json", {
            "schema": 1, "source_commit": evidence_commit or source_commit,
            "stub_sha256": metadata["sha256"],
            "tracked_source_dirty": False, "ready": True,
        }),
        ("runtime-hardening.json", {
            "schema": 1, "source_commit": evidence_commit or source_commit,
            "artifact_sha256": metadata["sha256"], "exit_code": 0,
        }),
        ("roundtrip.json", {
            "schema": 1, "source_commit": evidence_commit or source_commit,
            "artifact_sha256": metadata["sha256"], "exit_code": 0,
        }),
    ):
        path = evidence_dir / name
        raw = (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")
        path.write_bytes(raw)
        metadata["evidence"].append({
            "path": f"evidence/{name}",
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    # This fixture isolates the post-identity current-source gate.  Existing
    # candidate identity tests exercise the full on-disk schema/evidence path.
    monkeypatch.setattr(release_attestation, "validate_candidate_identity",
                        lambda _stub, _manifest: metadata)
    return stub


def test_exact_clean_checkout_loads_current_candidate(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    head = _checkout(repo)
    monkeypatch.setattr(release_attestation, "ROOT", repo)
    stub = _candidate(tmp_path, monkeypatch, head)
    blob, digest, table, _variant, rolling = orchestrator._load_virtualization_build(
        str(stub))
    assert blob == stub.read_bytes()
    assert digest == hashlib.sha256(blob).hexdigest()
    assert len(table.entries) > 0 and rolling is True


def test_stale_candidate_rejects_before_runtime_load(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    old_head = _checkout(repo)
    (repo / "source.py").write_text("value = 2\n", encoding="ascii")
    _git(repo, "add", "source.py")
    _git(repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-qm", "new source")
    monkeypatch.setattr(release_attestation, "ROOT", repo)
    stub = _candidate(tmp_path, monkeypatch, old_head)
    with pytest.raises(ValueError, match="source commit does not match"):
        orchestrator._load_virtualization_build(str(stub))


@pytest.mark.parametrize("dirty_kind", ["tracked", "untracked"])
def test_dirty_checkout_rejects_current_candidate(tmp_path, monkeypatch, dirty_kind):
    repo = tmp_path / "repo"
    head = _checkout(repo)
    if dirty_kind == "tracked":
        (repo / "source.py").write_text("value = 3\n", encoding="ascii")
    else:
        (repo / "new_source.py").write_text("value = 3\n", encoding="ascii")
    monkeypatch.setattr(release_attestation, "ROOT", repo)
    stub = _candidate(tmp_path, monkeypatch, head)
    with pytest.raises(ValueError, match="checkout is not clean"):
        orchestrator._load_virtualization_build(str(stub))


def test_non_git_distribution_rejects_experimental_candidate(tmp_path, monkeypatch):
    source = tmp_path / "extracted_source"
    source.mkdir()
    monkeypatch.setattr(release_attestation, "ROOT", source)
    stub = _candidate(tmp_path, monkeypatch, "a" * 40)
    with pytest.raises(ValueError, match="requires an exact Git checkout"):
        orchestrator._load_virtualization_build(str(stub))


def test_nested_directory_does_not_borrow_parent_git_identity(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    head = _checkout(repo)
    nested = repo / "extracted_source"
    nested.mkdir()
    monkeypatch.setattr(release_attestation, "ROOT", nested)
    stub = _candidate(tmp_path, monkeypatch, head)
    with pytest.raises(ValueError, match="requires an exact Git checkout"):
        orchestrator._load_virtualization_build(str(stub))


def test_candidate_without_typed_source_commit_rejects(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    _checkout(repo)
    monkeypatch.setattr(release_attestation, "ROOT", repo)
    stub = _candidate(tmp_path, monkeypatch, None)
    with pytest.raises(ValueError, match="no full source commit"):
        orchestrator._load_virtualization_build(str(stub))


def test_manifest_only_retag_of_old_runtime_rejects(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    old_head = _checkout(repo)
    (repo / "source.py").write_text("value = 5\n", encoding="ascii")
    _git(repo, "add", "source.py")
    _git(repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-qm", "new source")
    current_head = _git(repo, "rev-parse", "HEAD")
    monkeypatch.setattr(release_attestation, "ROOT", repo)
    stub = _candidate(tmp_path, monkeypatch, current_head,
                      evidence_commit=old_head)
    with pytest.raises(ValueError, match="evidence source commit mismatches"):
        orchestrator._load_virtualization_build(str(stub))


def test_explicit_test_only_override_retains_old_bundle_replay(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    _checkout(repo)
    monkeypatch.setattr(release_attestation, "ROOT", repo)
    stub = _candidate(tmp_path, monkeypatch, "a" * 40)
    blob, *_rest = orchestrator._load_virtualization_build(
        str(stub), allow_unverified_stub_for_tests=True)
    assert blob == stub.read_bytes()


def test_pack_file_rejects_stale_candidate_without_output(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    old_head = _checkout(repo)
    (repo / "source.py").write_text("value = 4\n", encoding="ascii")
    _git(repo, "add", "source.py")
    _git(repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-qm", "new compiler")
    monkeypatch.setattr(release_attestation, "ROOT", repo)
    stub = _candidate(tmp_path, monkeypatch, old_head)
    source = tmp_path / "app.exe"
    source.write_bytes(b"synthetic source")
    output = tmp_path / "packed.exe"
    source_parsed = SimpleNamespace(is_dll=False)
    materialized = SimpleNamespace(is_dll=False)
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")
    monkeypatch.setattr(pe_analyze, "analyze_pe", lambda _path: source_parsed)
    monkeypatch.setattr(direct_control_flow, "analyze_direct_control_flow",
                        lambda *_args, **_kwargs: SimpleNamespace(
                            direct_transfers=(), coverage_gaps=(),
                            acknowledged_coverage_gaps=(), indirect_transfers=(),
                            direct_reference_gate_passed=True,
                            indirect_target_closure_proven=False))
    monkeypatch.setattr(virtualize, "materialize_selected_functions",
                        lambda *_args, **_kwargs: SimpleNamespace(
                            parsed=materialized,
                            manifest=SimpleNamespace(functions=(object(),))))
    _patch_post_materialization_pipeline(monkeypatch, materialized, {})
    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(
            output_path=str(output), is_dll=False, stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec(
                "Selected", 0x1000, 16),),
            acknowledge_unproven_indirect_targets=True,
        ))
    assert result.ok is False
    assert "source commit does not match" in result.error
    assert not output.exists()
    assert source.read_bytes() == b"synthetic source"
