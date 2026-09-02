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


def test_command_environment_overrides_inherit_without_recording_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}
    monkeypatch.setenv("LETHE_TEST_SECRET_SENTINEL", "do-not-record")

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

    monkeypatch.setattr(promote_stub.subprocess, "run", fake_run)
    record = promote_stub._run(
        ["probe"],
        name="environment-test",
        source_commit="a" * 40,
        env_overrides={
            "LETHE_RUN_NATIVE_RUNTIME_STRESS": "1",
            "LETHE_NATIVE_RUNTIME_STUB_PATH": r"C:\candidate\stub.dll",
        },
    )

    assert captured["env"]["LETHE_TEST_SECRET_SENTINEL"] == "do-not-record"
    assert captured["env"]["LETHE_RUN_NATIVE_RUNTIME_STRESS"] == "1"
    assert captured["env"]["LETHE_NATIVE_RUNTIME_STUB_PATH"].endswith("stub.dll")
    assert "do-not-record" not in json.dumps(record.__dict__, sort_keys=True)
    assert os.environ["LETHE_TEST_SECRET_SENTINEL"] == "do-not-record"


def test_runtime_hardening_evidence_is_artifact_bound_and_cannot_skip() -> None:
    digest = "a" * 64
    passing = promote_stub.CommandRecord(
        name="runtime-hardening",
        argv=["python", "-m", "pytest"],
        exit_code=0,
        stdout="...                                                                      [100%]\n"
               "3 passed in 42.00s\n",
        stderr="",
        source_commit="b" * 40,
        artifact_sha256=digest,
    )

    assert promote_stub.validate_runtime_hardening_record(passing, digest) == 3
    with pytest.raises(promote_stub.PromotionError, match="different artifact"):
        promote_stub.validate_runtime_hardening_record(passing, "c" * 64)
    skipped = promote_stub.CommandRecord(
        **{**passing.__dict__, "stdout": "2 passed, 1 skipped in 1.00s\n"}
    )
    with pytest.raises(promote_stub.PromotionError, match="skipped"):
        promote_stub.validate_runtime_hardening_record(skipped, digest)

    incomplete_release_gate = promote_stub.CommandRecord(
        **{**passing.__dict__, "stdout": "4 passed in 1.00s\n"}
    )
    with pytest.raises(promote_stub.PromotionError, match="exact pass summary"):
        promote_stub.validate_runtime_hardening_record(
            incomplete_release_gate, digest,
            expected_tests=promote_stub.REQUIRED_NATIVE_RUNTIME_PASS_COUNT)
    oversized_release_gate = promote_stub.CommandRecord(
        **{**passing.__dict__, "stdout": "8 passed in 1.00s\n"}
    )
    with pytest.raises(promote_stub.PromotionError, match="exact pass summary"):
        promote_stub.validate_runtime_hardening_record(
            oversized_release_gate, digest,
            expected_tests=promote_stub.REQUIRED_NATIVE_RUNTIME_PASS_COUNT)


def test_release_runtime_gate_mandates_paged_virtualization_e2e() -> None:
    assert promote_stub.REQUIRED_NATIVE_RUNTIME_TESTS == (
        "test_native_runtime_hardening_stress.py",
        "test_native_virtualization_runtime.py",
    )
    assert promote_stub.REQUIRED_NATIVE_RUNTIME_PASS_COUNT == 7


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


def _known_candidate_gate() -> dict:
    blockers = [
        {"id": blocker_id, "status": status}
        for blocker_id, status in promote_stub.CANDIDATE_ALLOWED_BLOCKERS.items()
    ]
    return {
        "schema": 1,
        "scope": "all",
        "ready": False,
        "blocker_count": len(blockers),
        "blockers": blockers,
    }


def test_candidate_policy_matches_every_declared_nonproven_feature() -> None:
    matrix = json.loads(promote_stub.PRODUCTION_MATRIX.read_text(encoding="utf-8"))
    declared = {
        feature["id"]: feature["status"]
        for feature in matrix["features"]
        if feature["required"] and feature["status"] != "proven"
    }

    assert declared == promote_stub.CANDIDATE_ALLOWED_BLOCKERS


def test_candidate_gate_accepts_only_the_pinned_production_blockers() -> None:
    blockers = promote_stub.validate_candidate_gate_payload(_known_candidate_gate())

    assert blockers == [
        {"id": blocker_id, "status": status}
        for blocker_id, status in sorted(
            promote_stub.CANDIDATE_ALLOWED_BLOCKERS.items())
    ]

    green = {
        "schema": 1,
        "scope": "all",
        "ready": True,
        "blocker_count": 0,
        "blockers": [],
    }
    assert promote_stub.validate_candidate_gate_payload(green) == []


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda payload: payload["blockers"].append(
            {"id": "loader.unknown", "status": "partial"}), "not candidate-eligible"),
        (lambda payload: payload["blockers"].__setitem__(
            0, {**payload["blockers"][0], "status": "evidence-missing"}),
         "not candidate-eligible"),
        (lambda payload: payload.__setitem__("blocker_count", 0), "count"),
        (lambda payload: payload["blockers"].append(payload["blockers"][0]), "duplicate"),
    ],
)
def test_candidate_gate_rejects_unknown_evidence_and_malformed_blockers(
    mutate,
    message: str,
) -> None:
    payload = _known_candidate_gate()
    mutate(payload)

    with pytest.raises(promote_stub.PromotionError, match=message):
        promote_stub.validate_candidate_gate_payload(payload)


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
            "locked_files": {
                "pyproject.toml": "0" * 64,
                "uv.lock": "1" * 64,
            },
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
            "dvm_shuffle_seed": "00" * 32,
            "dvm_opcode_mapping_sha256": "2" * 64,
            "dvm_handler_variant_sha256": "3" * 64,
            "dvm_python_map_sha256": "4" * 64,
            "dvm_native_map_sha256": "5" * 64,
            "dvm_rolling": True,
            "dvm_roll_poison": False,
            "dvm_paged_runtime": True,
        },
        roundtrip_counts=(11, 11),
        ctest_count=4,
        evidence_paths=[evidence],
        stage_dir=tmp_path,
        gate_payload=_known_candidate_gate(),
    )

    assert manifest["schema"] == 2
    assert manifest["artifact_status"] == "candidate-verified"
    assert manifest["production_ready"] is False
    assert manifest["candidate_scope"] == "all"
    assert "production_scope" not in manifest
    assert manifest["native_roundtrip"] == "passed-9-of-9"
    assert manifest["native_roundtrip_actual"] == {"passed": 11, "total": 11}
    assert manifest["dvm_handler_variant_sha256"] == "3" * 64
    assert manifest["dvm_roll_poison"] is False
    assert manifest["evidence"] == [{
        "path": "evidence/roundtrip.json",
        "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
    }]
    assert manifest["release_blockers"] == promote_stub.validate_candidate_gate_payload(
        _known_candidate_gate())
    assert manifest["production_matrix_sha256"] == promote_stub.sha256_file(
        promote_stub.PRODUCTION_MATRIX)
    assert manifest["promotion_tool_sha256"] == promote_stub.sha256_file(
        Path(promote_stub.__file__))
    assert manifest["candidate_policy_sha256"] == promote_stub.candidate_policy_sha256()


def test_candidate_bundle_validation_rejects_tampered_evidence_and_release_status(
    tmp_path: Path,
) -> None:
    staged_stub = tmp_path / "lethe_stub_x64.dll"
    staged_stub.write_bytes(b"candidate")
    evidence_paths = []
    for relative in sorted(promote_stub.REQUIRED_CANDIDATE_EVIDENCE):
        evidence_path = tmp_path / relative
        if relative.endswith("candidate-policy.json"):
            promote_stub.atomic_write_json(
                evidence_path, promote_stub.candidate_policy_payload())
        elif relative.endswith("candidate-production-matrix.json"):
            evidence_path.parent.mkdir(parents=True, exist_ok=True)
            evidence_path.write_bytes(promote_stub.PRODUCTION_MATRIX.read_bytes())
        elif relative.endswith("candidate-promoter.py"):
            evidence_path.parent.mkdir(parents=True, exist_ok=True)
            evidence_path.write_bytes(Path(promote_stub.__file__).read_bytes())
        else:
            promote_stub.atomic_write_json(evidence_path, {"ready": True})
        evidence_paths.append(evidence_path)
    promote_stub._record(
        tmp_path / "evidence" / "runtime-hardening.json",
        promote_stub.CommandRecord(
            name="candidate-bound-native-runtime-hardening",
            argv=[
                "python", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                str(promote_stub.ROOT / "tests" /
                    "test_native_runtime_hardening_stress.py"),
            ],
            exit_code=0,
            stdout="3 passed in 42.00s\n",
            stderr="",
            source_commit="f" * 40,
            artifact_sha256=hashlib.sha256(staged_stub.read_bytes()).hexdigest(),
        ),
    )
    evidence = tmp_path / "evidence" / "roundtrip.json"
    manifest = promote_stub.build_manifest(
        staged_stub=staged_stub,
        source={
            "source_commit": "f" * 40,
            "locked_files": {
                "pyproject.toml": "0" * 64,
                "uv.lock": "1" * 64,
            },
        },
        host={
            "python_version": "3.12.10",
            "uv_version": "0.11.29",
            "cmake_version": "4.4.0",
            "ctest_version": "4.4.0",
        },
        toolchain={
            "cmake_generator": promote_stub.SUPPORTED_GENERATOR,
            "cmake_platform": promote_stub.SUPPORTED_PLATFORM,
            "compiler_id": "MSVC",
            "compiler_version": "19.44.35219.0",
            "compile_policy": "/W4 /WX /Brepro",
            "link_policy": "/Brepro /INCREMENTAL:NO",
        },
        dvm_provenance={
            "dvm_shuffle_seed": "00" * 32,
            "dvm_opcode_mapping_sha256": "2" * 64,
            "dvm_handler_variant_sha256": "3" * 64,
            "dvm_python_map_sha256": "4" * 64,
            "dvm_native_map_sha256": "5" * 64,
            "dvm_rolling": True,
            "dvm_roll_poison": False,
            "dvm_paged_runtime": True,
        },
        roundtrip_counts=(11, 11),
        ctest_count=4,
        evidence_paths=evidence_paths,
        stage_dir=tmp_path,
        gate_payload=_known_candidate_gate(),
    )
    manifest_path = tmp_path / "lethe_stub_x64.manifest.json"
    promote_stub.atomic_write_json(manifest_path, manifest)

    evidence.write_text('{"ready": false}\n', encoding="utf-8")
    with pytest.raises(promote_stub.PromotionError, match="evidence SHA-256"):
        promote_stub.validate_candidate_bundle(staged_stub, manifest_path)

    promote_stub.atomic_write_json(evidence, {"ready": True})
    manifest["dvm_roll_poison"] = True
    promote_stub.atomic_write_json(manifest_path, manifest)
    with pytest.raises(promote_stub.PromotionError, match="roll poison disabled"):
        promote_stub.validate_candidate_bundle(staged_stub, manifest_path)

    manifest["dvm_roll_poison"] = False
    manifest["artifact_status"] = "production-released"
    manifest["production_ready"] = True
    promote_stub.atomic_write_json(manifest_path, manifest)
    with pytest.raises(promote_stub.PromotionError, match="candidate-verified"):
        promote_stub.validate_candidate_bundle(staged_stub, manifest_path)


def test_generated_dvm_provenance_binds_seed_and_native_map(tmp_path: Path) -> None:
    seed = "00" * 32
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
    (tmp_path / "CMakeCache.txt").write_text(
        "DVM_SHUFFLE_OPCODES:BOOL=ON\n"
        "DVM_ROLLING:BOOL=ON\n"
        "DVM_ROLL_POISON:BOOL=OFF\n",
        encoding="utf-8",
    )

    result = promote_stub.inspect_generated_dvm_provenance(tmp_path, seed)

    assert result["dvm_shuffle_seed"] == seed
    assert result["dvm_opcode_mapping_sha256"] == mapping
    assert result["dvm_handler_variant_sha256"] == handlers
    assert result["dvm_rolling"] is True
    assert result["dvm_roll_poison"] is False
    assert result["dvm_paged_runtime"] is True

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


def test_promotion_configure_enables_rolling_without_debug_poison(tmp_path: Path) -> None:
    seed = "ab" * 32
    argv = promote_stub._promotion_configure_argv(
        {"cmake": "cmake", "python": "python"}, tmp_path / "build", seed)

    assert f"-DDVM_SHUFFLE_SEED={seed}" in argv
    assert argv.count("-DDVM_ROLLING=ON") == 1
    assert argv.count("-DDVM_ROLL_POISON=OFF") == 1
    assert not any(str(argument).startswith("-DDVM_ROLL_POISON=ON") for argument in argv)


def test_legacy_build_script_cannot_update_tracked_prebuilt() -> None:
    source = (promote_stub.ROOT / "stub" / "build_stub.ps1").read_text(encoding="utf-8")

    assert "Direct prebuilt promotion is disabled" in source
    assert "Move-Item -LiteralPath $DllStage" not in source
    assert "Tracked prebuilt files were not modified" in source


def test_candidate_workflow_stages_outside_checkout_and_cannot_lose_evidence() -> None:
    workflow = (
        promote_stub.ROOT / ".github" / "workflows" / "release-candidate.yml"
    ).read_text(encoding="utf-8")

    assert "${{ runner.temp }}\\lethe-native-candidate" in workflow
    assert "if-no-files-found: error" in workflow
    assert "--stage-dir .\\.test-release-candidate" not in workflow


def test_ordinary_ci_validates_contract_without_demanding_a_release() -> None:
    workflow = (
        promote_stub.ROOT / ".github" / "workflows" / "ci.yml"
    ).read_text(encoding="utf-8")

    assert "tools\\production_gate.py --validate-only" in workflow
    assert "tools\\release_check.py" not in workflow
