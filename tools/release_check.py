#!/usr/bin/env python3
"""Fail-closed checks for a Lethe public-release source tree."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


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


def _check_manifest(errors: list[str]) -> None:
    try:
        metadata = json.loads(MANIFEST.read_text(encoding="utf-8"))
        blob = STUB.read_bytes()
    except (OSError, ValueError) as exc:
        errors.append(f"cannot read prebuilt/manifest: {exc}")
        return

    expected = hashlib.sha256(blob).hexdigest()
    checks = {
        "schema": 1,
        "artifact": STUB.name,
        "sha256": expected,
        "size_bytes": len(blob),
        "source_dirty": False,
        "provenance_status": "clean",
        "native_roundtrip": "passed-9-of-9",
    }
    for key, wanted in checks.items():
        if metadata.get(key) != wanted:
            errors.append(
                f"prebuilt manifest {key!r} is {metadata.get(key)!r}, expected {wanted!r}")

    actual_roundtrip = metadata.get("native_roundtrip_actual")
    if not isinstance(actual_roundtrip, dict):
        errors.append("prebuilt manifest has no actual native round-trip counts")
    else:
        passed = actual_roundtrip.get("passed")
        total = actual_roundtrip.get("total")
        if (type(passed) is not int or type(total) is not int or
                total < 1 or passed != total):
            errors.append("prebuilt manifest native round-trip counts are not full N/N")

    if metadata.get("production_scope") != "all":
        errors.append("prebuilt manifest is not bound to the all-scope production gate")
    seed = metadata.get("dvm_shuffle_seed")
    if (not isinstance(seed, str) or not re.fullmatch(r"[0-9a-f]+", seed) or
            len(seed) % 2):
        errors.append("prebuilt manifest has no valid generated DVM shuffle seed")
    for key in (
        "dvm_opcode_mapping_sha256",
        "dvm_handler_variant_sha256",
        "dvm_python_map_sha256",
        "dvm_native_map_sha256",
    ):
        value = metadata.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            errors.append(f"prebuilt manifest has no valid {key}")

    source_commit = metadata.get("source_commit")
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        errors.append("prebuilt manifest has no full source_commit")
        return
    try:
        _git("cat-file", "-e", f"{source_commit}^{{commit}}")
        drift = _git("diff", "--name-only", source_commit, "HEAD", "--", *NATIVE_PROVENANCE_PATHS)
    except subprocess.CalledProcessError as exc:
        errors.append(f"cannot verify prebuilt source commit: {exc}")
        return
    if drift.strip():
        errors.append("native inputs changed after prebuilt promotion: " + ", ".join(drift.splitlines()))


def _check_workflow_pins(errors: list[str]) -> None:
    for workflow in (ROOT / ".github" / "workflows").glob("*.y*ml"):
        for line_no, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            match = re.search(r"\buses:\s*[^\s@]+@([^\s#]+)", line)
            if match and not re.fullmatch(r"[0-9a-f]{40}", match.group(1)):
                errors.append(f"{workflow.relative_to(ROOT)}:{line_no}: action is not SHA-pinned")


def _check_production_matrix(errors: list[str]) -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "production_gate.py"), "--validate-only"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        errors.append(f"production compatibility matrix is invalid: {detail}")


def main() -> int:
    errors: list[str] = []
    tracked = _tracked_files()
    tracked_set = set(tracked)

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

    _check_manifest(errors)
    _check_workflow_pins(errors)
    _check_production_matrix(errors)

    if errors:
        print("Public release check: FAILED", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"Public release check: PASS ({len(tracked)} tracked files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
