"""Fail-closed contracts for native-stub release-candidate staging."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from tools import promote_stub


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _clean_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "candidate"\nversion = "0.0.0"\n'
        'requires-python = ">=3.12,<3.13"\n',
        encoding="utf-8",
    )
    (repo / "uv.lock").write_text(
        'version = 1\nrevision = 3\nrequires-python = "==3.12.*"\n',
        encoding="utf-8",
    )
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Lethe Test")
    _git(repo, "config", "user.email", "lethe-test@example.invalid")
    _git(repo, "add", "pyproject.toml", "uv.lock")
    _git(repo, "commit", "-q", "-m", "fixture")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_repository_gate_requires_exact_clean_committed_source(tmp_path: Path) -> None:
    repo, commit = _clean_repo(tmp_path)

    inspected = promote_stub.inspect_repository(repo, commit)

    assert inspected["source_commit"] == commit
    assert set(inspected["locked_files"]) == {"pyproject.toml", "uv.lock"}

    (repo / "untracked.txt").write_text("dirty", encoding="utf-8")
    with pytest.raises(promote_stub.PromotionError, match="not clean"):
        promote_stub.inspect_repository(repo, commit)


def test_repository_gate_rejects_non_exact_source_commit(tmp_path: Path) -> None:
    repo, commit = _clean_repo(tmp_path)

    with pytest.raises(promote_stub.PromotionError, match="full lowercase"):
        promote_stub.inspect_repository(repo, commit[:12])
    with pytest.raises(promote_stub.PromotionError, match="source commit mismatch"):
        promote_stub.inspect_repository(repo, "0" * 40)


def test_atomic_manifest_write_never_replaces_target_on_swap_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "manifest.json"
    target.write_text('{"old": true}\n', encoding="utf-8")

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("swap denied")

    monkeypatch.setattr(promote_stub.os, "replace", fail_replace)
    with pytest.raises(OSError, match="swap denied"):
        promote_stub.atomic_write_json(target, {"new": True})

    assert json.loads(target.read_text(encoding="utf-8")) == {"old": True}
    assert not list(tmp_path.glob(".*.tmp"))


def test_roundtrip_evidence_requires_same_hash_and_full_summary() -> None:
    digest = "a" * 64
    passing = promote_stub.CommandRecord(
        name="roundtrip",
        argv=["roundtrip.ps1"],
        exit_code=0,
        stdout="  11/11 passed -- PASS\n",
        stderr="",
        source_commit="b" * 40,
        artifact_sha256=digest,
    )

    assert promote_stub.validate_roundtrip_record(passing, digest) == (11, 11)

    with pytest.raises(promote_stub.PromotionError, match="different artifact"):
        promote_stub.validate_roundtrip_record(passing, "c" * 64)
    red = promote_stub.CommandRecord(
        **{**passing.__dict__, "exit_code": 1, "stdout": "10/11 passed (1 failed) -- FAIL\n"}
    )
    with pytest.raises(promote_stub.PromotionError, match="gate failed"):
        promote_stub.validate_roundtrip_record(red, digest)


def test_corpus_evidence_is_bound_to_commit_and_artifact(tmp_path: Path) -> None:
    stub = tmp_path / "candidate.dll"
    stub.write_bytes(b"candidate")
    commit = "d" * 40
    digest = hashlib.sha256(stub.read_bytes()).hexdigest()
    evidence_path = tmp_path / "evidence.json"
    evidence = {
        "schema": 1,
        "source_commit": commit,
        "tracked_source_dirty": False,
        "stub_path": str(stub),
        "stub_sha256": digest,
        "passed": 1,
        "total": 1,
        "ready": True,
        "tests": [{"id": "exe.runtime", "status": "passed"}],
    }
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    assert promote_stub.validate_corpus_evidence(
        evidence_path,
        expected_commit=commit,
        expected_hash=digest,
    )["ready"] is True

    with pytest.raises(promote_stub.PromotionError, match="different source commit"):
        promote_stub.validate_corpus_evidence(
            evidence_path,
            expected_commit="e" * 40,
            expected_hash=digest,
        )
    evidence["tracked_source_dirty"] = True
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(promote_stub.PromotionError, match="tracked-dirty"):
        promote_stub.validate_corpus_evidence(
            evidence_path,
            expected_commit=commit,
            expected_hash=digest,
        )


def test_all_scope_gate_must_be_green() -> None:
    promote_stub.validate_gate_payload({
        "schema": 1,
        "scope": "all",
        "ready": True,
        "blocker_count": 0,
        "blockers": [],
    })
    with pytest.raises(promote_stub.PromotionError, match="gate is red"):
        promote_stub.validate_gate_payload({
            "schema": 1,
            "scope": "all",
            "ready": False,
            "blocker_count": 1,
            "blockers": [{"id": "dll.dynamic_exports"}],
        })


def test_manifest_keeps_legacy_field_but_records_actual_hashed_evidence(
    tmp_path: Path,
) -> None:
    staged_stub = tmp_path / "lethe_stub_x64.dll"
    staged_stub.write_bytes(b"candidate")
    evidence = tmp_path / "evidence" / "roundtrip.json"
    promote_stub.atomic_write_json(evidence, {"ready": True})
    manifest = promote_stub.build_manifest(
        staged_stub=staged_stub,
        source={
            "source_commit": "f" * 40,
            "locked_files": {"uv.lock": "1" * 64},
        },
        host={
            "python_version": "3.12.10",
            "uv_version": "0.11.29",
            "cmake_version": "4.4.0",
            "ctest_version": "4.4.0",
        },
        toolchain={
            "cmake_generator": "Visual Studio 17 2022",
            "cmake_platform": "x64",
            "compiler_id": "MSVC",
            "compiler_version": "19.44.35219.0",
            "compile_policy": "/W4 /WX /Brepro",
            "link_policy": "/Brepro",
        },
        dvm_provenance={
            "dvm_shuffle_seed": "00112233",
            "dvm_opcode_mapping_sha256": "2" * 64,
            "dvm_handler_variant_sha256": "3" * 64,
            "dvm_python_map_sha256": "4" * 64,
            "dvm_native_map_sha256": "5" * 64,
        },
        roundtrip_counts=(11, 11),
        ctest_count=4,
        evidence_paths=[evidence],
        stage_dir=tmp_path,
    )

    assert manifest["native_roundtrip"] == "passed-9-of-9"
    assert manifest["native_roundtrip_actual"] == {"passed": 11, "total": 11}
    assert manifest["dvm_handler_variant_sha256"] == "3" * 64
    assert manifest["evidence"] == [{
        "path": "evidence/roundtrip.json",
        "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
    }]


def test_generated_dvm_provenance_binds_seed_and_native_map(tmp_path: Path) -> None:
    seed = "00112233"
    mapping = "a" * 64
    handlers = "b" * 64
    (tmp_path / "daedalus_opcodes_shuffled.py").write_text(
        f"BUILD_SEED = {seed!r}\n"
        f"OPCODE_MAPPING_SHA256 = {mapping!r}\n"
        f"HANDLER_VARIANT_SHA256 = {handlers!r}\n",
        encoding="utf-8",
    )
    (tmp_path / "daedalus_opcodes_shuffled.h").write_text(
        f'#define DVM_OPCODE_MAPPING_SHA256 "{mapping}"\n'
        f'#define DVM_HANDLER_VARIANT_SHA256 "{handlers}"\n',
        encoding="utf-8",
    )

    result = promote_stub.inspect_generated_dvm_provenance(tmp_path, seed)

    assert result["dvm_shuffle_seed"] == seed
    assert result["dvm_opcode_mapping_sha256"] == mapping
    assert result["dvm_handler_variant_sha256"] == handlers

    with pytest.raises(promote_stub.PromotionError, match="requested seed"):
        promote_stub.inspect_generated_dvm_provenance(tmp_path, "deadbeef")

    (tmp_path / "daedalus_opcodes_shuffled.h").write_text(
        f'#define DVM_OPCODE_MAPPING_SHA256 "{"c" * 64}"\n'
        f'#define DVM_HANDLER_VARIANT_SHA256 "{handlers}"\n',
        encoding="utf-8",
    )
    with pytest.raises(promote_stub.PromotionError, match="maps disagree"):
        promote_stub.inspect_generated_dvm_provenance(tmp_path, seed)


def test_promotion_pins_nonincremental_link_and_inspects_aligned_veneers() -> None:
    source = Path(promote_stub.__file__).read_text(encoding="utf-8")

    assert "-DCMAKE_SHARED_LINKER_FLAGS_RELEASE=/Brepro /INCREMENTAL:NO" in source
    assert 'required_link = ("/Brepro", "/INCREMENTAL:NO")' in source
    assert "def inspect_stub_entrypoints(" in source
    assert 'image.find_export_rva("StubExeEntry")' in source
    assert 'image.find_export_rva("StubDllMain")' in source
    assert "rva % 16" in source
    assert "veneer[0] != 0xE9" in source
    assert "terminator != 0" in source


def test_legacy_build_script_cannot_update_tracked_prebuilt() -> None:
    source = (promote_stub.ROOT / "stub" / "build_stub.ps1").read_text(encoding="utf-8")

    assert "Direct prebuilt promotion is disabled" in source
    assert "Move-Item -LiteralPath $DllStage" not in source
    assert "Tracked prebuilt files were not modified" in source
