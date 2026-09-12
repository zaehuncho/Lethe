#!/usr/bin/env python3
"""Fail-closed checks for a Lethe public-release source tree."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packer import release_attestation  # noqa: E402
from tools import production_gate  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
STUB = ROOT / "stub" / "prebuilt" / "lethe_stub_x64.dll"
MANIFEST = STUB.with_name("lethe_stub_x64.manifest.json")
REQUIRED_FILES = (
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "THIRD_PARTY_NOTICES.md",
    "CHANGELOG.md",
    "pyproject.toml",
    "uv.lock",
    "docs/PRODUCTION_COMPATIBILITY.md",
    "docs/production_compatibility.json",
    "tools/production_gate.py",
    "tools/promote_stub.py",
    "tools/release_stub.py",
    "packer/release_attestation.py",
    "packer/release_trust.json",
    "packer/evidence_trust.json",
    ".github/workflows/release-candidate.yml",
)
PRIVATE_FILES = {
    ".env",
    "IMPLEMENTATION_STATUS.md",
    "NEXTGEN_PROTECTION_PLAN.md",
    "NEXTGEN_PROTECTION_PLAN_fable.md",
    "OPERATIONS.md",
    "PHASE2_PHASE3_PLAN.md",
    "RUNBOOK.md",
}
SECRET_SUFFIXES = {".key", ".pem", ".pfx", ".p12", ".ppk", ".jks", ".keystore"}
THIRD_PARTY_TEXT_ALLOWLIST = {"stub/src/miniz.c", "stub/src/miniz.h"}
BLOCKED_PATTERNS = (
    re.compile(r"(?i)\b[A-Z]:\\Users\\"),
    re.compile(r"(?i)\b[\w.+-]+@(gmail|outlook|yahoo|protonmail)\.[a-z]{2,}\b"),
)
NATIVE_PROVENANCE_PATHS = (
    "stub/CMakeLists.txt",
    "stub/src",
    "cipher/kalypso.c",
    "cipher/kalypso.h",
    "daedalus",
)
RELEASE_OUTPUT_PATHS = {
    "stub/prebuilt/lethe_stub_x64.dll",
    "stub/prebuilt/lethe_stub_x64.manifest.json",
    "stub/prebuilt/lethe_stub_x64.release.json",
}
RELEASE_EVIDENCE_PREFIX = "stub/prebuilt/release-evidence/"
CANDIDATE_TO_RELEASE_ALLOWED_PATHS = {
    "docs/production_compatibility.json",
}


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={ROOT.as_posix()}", *args],
        cwd=ROOT, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8",
    )
    return completed.stdout


def _tracked_files() -> list[str]:
    return [line for line in _git("ls-files").splitlines() if line]


def _check_manifest(errors: list[str]) -> dict | None:
    try:
        payload = release_attestation.verify_release_bundle(STUB)
    except (OSError, release_attestation.ReleaseAttestationError) as exc:
        errors.append(f"signed prebuilt release is invalid: {exc}")
        return None
    source_commit = payload["candidate"]["source_commit"]
    release_source_commit = payload["release_source_commit"]
    try:
        _git("cat-file", "-e", f"{source_commit}^{{commit}}")
        _git("cat-file", "-e", f"{release_source_commit}^{{commit}}")
        _git("merge-base", "--is-ancestor", source_commit, release_source_commit)
        _git("merge-base", "--is-ancestor", release_source_commit, "HEAD")
        assessment_drift = _git(
            "diff", "--name-only", source_commit, release_source_commit)
        publication_drift = _git(
            "diff", "--name-only", release_source_commit, "HEAD")
    except subprocess.CalledProcessError as exc:
        errors.append(f"cannot verify prebuilt source commit: {exc}")
        return None
    unexpected_assessment = [
        path for path in assessment_drift.splitlines()
        if path not in CANDIDATE_TO_RELEASE_ALLOWED_PATHS
    ]
    if unexpected_assessment:
        errors.append(
            "source changed outside the release compatibility declaration: "
            + ", ".join(unexpected_assessment))
    unexpected_publication = [
        path for path in publication_drift.splitlines()
        if path not in RELEASE_OUTPUT_PATHS and not path.startswith(RELEASE_EVIDENCE_PREFIX)
    ]
    if unexpected_publication:
        errors.append(
            "source changed outside signed release outputs after release attestation: "
            + ", ".join(unexpected_publication))
    return payload


def _check_workflow_pins(errors: list[str]) -> None:
    for workflow in (ROOT / ".github" / "workflows").glob("*.y*ml"):
        for line_no, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            match = re.search(r"\buses:\s*[^\s@]+@([^\s#]+)", line)
            if match and not re.fullmatch(r"[0-9a-f]{40}", match.group(1)):
                errors.append(f"{workflow.relative_to(ROOT)}:{line_no}: action is not SHA-pinned")


def _check_production_matrix(errors: list[str], payload: dict | None) -> None:
    if payload is None:
        return
    try:
        native_record = next(
            item for item in payload["evidence"]
            if item["kind"] == "production-native")
        native_path = STUB.parent / native_record["path"]
        native = production_gate.load_evidence(native_path, artifact_path=STUB)
        matrix = production_gate.load_matrix(ROOT / "docs" / "production_compatibility.json")
        result = production_gate.evaluate(matrix, "all", native)
    except (OSError, KeyError, StopIteration, production_gate.MatrixError) as exc:
        errors.append(f"cannot independently evaluate production readiness: {exc}")
        return
    if result != payload.get("production_gate") or result.get("ready") is not True:
        errors.append("signed production gate does not match current evidence-aware evaluation")


def main() -> int:
    errors: list[str] = []
    tracked = _tracked_files()
    tracked_set = set(tracked)
    dirty = _git("status", "--porcelain=v1", "--untracked-files=all")
    if dirty.strip():
        errors.append("public release source tree is not clean")

    for required in REQUIRED_FILES:
        if required not in tracked_set:
            errors.append(f"required publication file is not tracked: {required}")
    for path in sorted(PRIVATE_FILES & tracked_set):
        errors.append(f"private/internal file is tracked: {path}")
    for path in tracked:
        if Path(path).suffix.lower() in SECRET_SUFFIXES:
            errors.append(f"key/certificate material is tracked: {path}")

    for path in tracked:
        candidate = ROOT / path
        try:
            text = candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if path in THIRD_PARTY_TEXT_ALLOWLIST:
            continue
        for blocked in BLOCKED_PATTERNS:
            if blocked.search(text):
                errors.append(f"private user identifier appears in {path}")

    shard_source = (ROOT / "packer" / "orchestrator.py").read_text(encoding="utf-8")
    bootstrap_source = (ROOT / "bootstrap" / "shard_bootstrap.c").read_text(encoding="utf-8")
    if '_SHARD_API_HOST = "shard.example.invalid"' not in shard_source:
        errors.append("experimental Python shard client is not pinned to the reserved example host")
    if '#define SHARD_HOST      L"shard.example.invalid"' not in bootstrap_source:
        errors.append("experimental bootstrap is not pinned to the reserved example host")

    release_payload = _check_manifest(errors)
    _check_workflow_pins(errors)
    _check_production_matrix(errors, release_payload)

    if errors:
        print("Public release check: FAILED", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"Public release check: PASS ({len(tracked)} tracked files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
