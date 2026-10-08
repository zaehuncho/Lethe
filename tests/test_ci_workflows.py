"""Regression contracts for the actual release-candidate workflow scripts."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from tools import promote_stub


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _run_script(step_name: str) -> str:
    """Read a literal run block from this repository's fixed workflow layout."""
    lines = (WORKFLOWS / "release-candidate.yml").read_text(encoding="utf-8").splitlines()
    start = lines.index(f"      - name: {step_name}")
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("      - ")), len(lines))
    block = lines[start:end]
    run = next(i for i, line in enumerate(block) if line.startswith("        run: "))
    assert block[run] == "        run: |", "Use a literal PowerShell script block"
    script = []
    for line in block[run + 1:]:
        if line and not line.startswith("          "):
            break
        script.append(line[10:])
    return "\n".join(script)


def test_ci_native_and_preflight_seeds_match_the_promoter_contract() -> None:
    workflow = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    seeds = re.findall(r"(?:--shuffle-seed|-ShuffleSeed)\s+([0-9a-f]+)", workflow)
    assert len(seeds) == 2
    assert len(set(seeds)) == 1
    for seed in seeds:
        assert len(seed) == 64
        assert f"-DDVM_SHUFFLE_SEED={seed}" in promote_stub.release_dvm_configure_args(seed)


def test_dispatch_inputs_are_environment_data_not_inline_script_source() -> None:
    workflow = (WORKFLOWS / "release-candidate.yml").read_text(encoding="utf-8")
    assert "LETHE_SOURCE_COMMIT: ${{ inputs.source_commit }}" in workflow
    assert "LETHE_SHUFFLE_SEED: ${{ inputs.shuffle_seed }}" in workflow
    for step in ("Verify exact checkout", "Stage candidate under pinned blocker policy"):
        assert "${{" not in _run_script(step)


def test_stage_uses_validated_environment_and_propagates_failure() -> None:
    script = _run_script("Stage candidate under pinned blocker policy")
    assert "--source-commit $env:LETHE_SOURCE_COMMIT" in script
    assert "--shuffle-seed $env:LETHE_SHUFFLE_SEED" in script
    assert "Join-Path $env:RUNNER_TEMP 'lethe-native-candidate'" in script
    assert "--stage-dir $stageDir" in script
    assert "exit $LASTEXITCODE" in script


def _verify_checkout(commit: str, seed: str, *, path_prefix: Path | None = None):
    shell = shutil.which("powershell") if os.name == "nt" else None
    if not shell:
        pytest.skip("Windows PowerShell workflow requires Windows")
    env = os.environ.copy()
    env.update(LETHE_SOURCE_COMMIT=commit, LETHE_SHUFFLE_SEED=seed)
    if path_prefix is not None:
        env["PATH"] = str(path_prefix) + os.pathsep + env["PATH"]
    return subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-Command", _run_script("Verify exact checkout")],
        cwd=ROOT, env=env, text=True, capture_output=True, timeout=30,
    )


def test_checkout_verifier_accepts_exact_commit_and_seed() -> None:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    result = _verify_checkout(commit, "ab" * 32)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Workflow inputs and checkout verified." in result.stdout


@pytest.mark.parametrize(("commit", "seed", "message"), [
    ("", "ab" * 32, "source_commit must be"),
    ("a" * 39, "ab" * 32, "source_commit must be"),
    ("A" * 40, "ab" * 32, "source_commit must be"),
    ("a" * 40 + "\n", "ab" * 32, "source_commit must be"),
    ("a" * 40, "ab" * 16, "shuffle_seed must be"),
    ("a" * 40, "AB" * 32, "shuffle_seed must be"),
    ("a" * 40, "ab" * 32 + "\n", "shuffle_seed must be"),
    ("0" * 40, "ab" * 32, "Checkout mismatch"),
])
def test_checkout_verifier_rejects_invalid_or_mismatched_inputs(commit, seed, message) -> None:
    result = _verify_checkout(commit, seed)
    assert result.returncode != 0
    assert message in result.stdout + result.stderr
    assert "Workflow inputs and checkout verified." not in result.stdout


def test_checkout_verifier_rejects_failed_git_even_with_matching_stdout(tmp_path: Path) -> None:
    # The workflow must check the process status, not merely compare stdout.
    commit = "a" * 40
    (tmp_path / "git.cmd").write_text(f"@echo off\necho {commit}\nexit /b 17\n", encoding="ascii")
    result = _verify_checkout(commit, "ab" * 32, path_prefix=tmp_path)
    assert result.returncode != 0
    assert "git rev-parse failed" in result.stdout + result.stderr
