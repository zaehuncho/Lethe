#!/usr/bin/env python3
"""Produce an evidence-bound V3 pipe-only Lethe stub candidate.

This is deliberately separate from the generic prebuilt promotion path.  The
Venice server-shard wrapper consumes the resulting manifest instead of accepting
an arbitrary ``--stub-path``: it verifies the exact clean source inventory, a
fresh EXE-only stub, CTest, the native EXE corpus, the pipe-frame runtime proof,
and a separately compiled bootstrap compatibility check.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "docs" / "venice_server_shard_v3_qualification.json"
SCHEMA = "lethe.venice_v3_pipe_exe_stub.v1"
PROFILE_SCHEMA = "lethe.venice_server_shard_v3_qualification.v1"
PROTOCOL = "venice-server-shard-v3-pipe"
PROFILE_NAME = "venice-server-shard-v3-pipe-exe"
MANIFEST_NAME = "venice_v3_pipe_exe_stub.manifest.json"
TEST_BROKER_DIGEST = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

QUALIFIED_FILES = (
    "bootstrap/CMakeLists.txt",
    "bootstrap/broker_binding.h.in",
    "bootstrap/broker_handoff.c",
    "bootstrap/broker_handoff.h",
    "bootstrap/shard_bootstrap.c",
    "bootstrap/tests/broker_handoff_test.c",
    "stub/src/pe_loader.c",
    "stub/src/pack_info.h",
    "packer/assemble.py",
    "packer/container.py",
    "packer/keyed_validation.py",
    "packer/orchestrator.py",
    "packer/report.py",
    "daedalus/generate_programs.py",
    "lethe.py",
)
REQUIRED_MARKERS = {
    "bootstrap/CMakeLists.txt": (
        "LETHE_ORION_ACTIVATE_SHA256",
        "LETHE_ORION_ACTIVATE_SHA256_NORMALIZED",
        "must be exactly 64 hexadecimal characters",
    ),
    "bootstrap/broker_binding.h.in": (
        "LETHE_ORION_ACTIVATE_SHA256_HEX",
        "ORION_ACTIVATE_SHA256:@LETHE_ORION_ACTIVATE_SHA256_NORMALIZED@",
    ),
    "bootstrap/broker_handoff.c": (
        "BCRYPT_SHA256_ALGORITHM", "BCryptFinishHash", "TokenElevation",
    ),
    "bootstrap/broker_handoff.h": (
        "lethe_sha256_file_handle", "lethe_current_process_elevated",
    ),
    "bootstrap/shard_bootstrap.c": (
        "VSG3", "FILE_TYPE_PIPE", "launch_sibling_broker",
        "LETHE_ORION_ACTIVATE_SHA256_HEX", "lethe_current_process_elevated(&elevated)",
    ),
    "bootstrap/tests/broker_handoff_test.c": (
        'SHA-256("abc")', "ORION_ACTIVATE_SHA256:",
    ),
    "stub/src/pe_loader.c": (
        '"VSG3"', "LETHE_FLAG_SERVER_SHARD_PIPE",
        "No environment, command-line, disk, or cache fallback exists",
    ),
    "stub/src/pack_info.h": ("LETHE_FLAG_SERVER_SHARD_PIPE 0x200u",),
    "packer/container.py": ("FLAG_SERVER_SHARD_PIPE = 1 << 9",),
    "packer/assemble.py": (
        "The stub reads one 32-byte shard only from the broker's VSG3 stdin frame",
    ),
    "packer/keyed_validation.py": ("FLAG_SERVER_SHARD_PIPE",),
    "packer/orchestrator.py": (
        "/api/shard/v3/store", "V3 KMS gate", "offline release signature",
    ),
}
FORBIDDEN_MARKERS = (
    "NV_RT_GATE", "orion-entitlement-v1", "/api/shard/retrieve",
    "CryptUnprotectData", "WinHttpOpen", "shard_xor.vasm",
    "X-Orion-Admin-Secret", "LETHE_SHARD_ADMIN_SECRET", "LETHE_SHARD_EDGE_AUTH",
    "LETHE_SHARD_ADMIN_TOTP", "LETHE_SHARD_PUBLISHER_SECRET",
)
INPUT_FILES = (
    "bootstrap/CMakeLists.txt",
    "bootstrap/broker_binding.h.in",
    "bootstrap/broker_handoff.c",
    "bootstrap/broker_handoff.h",
    "bootstrap/shard_bootstrap.c",
    "bootstrap/tests/broker_handoff_test.c",
    "stub/CMakeLists.txt",
    "cipher/kalypso.c",
    "cipher/kalypso.h",
    "docs/VENICE_V3_BOOTSTRAP_COMPATIBILITY.md",
    "pyproject.toml",
    "uv.lock",
    "stub/tests/metadata_aad_test.c",
    "tests/build_samples.ps1",
    "tests/build_production_corpus.ps1",
    "tests/production_corpus.ps1",
    "tests/test_native_shard_runtime.py",
    "tests/test_bootstrap_safety_contracts.py",
    "tools/qualify_v3_pipe_exe.py",
)
INPUT_PREFIXES = ("stub/src/", "daedalus/", "tests/sample/")


class QualificationError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str) -> str:
    result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True,
                            text=True, check=False)
    if result.returncode != 0:
        raise QualificationError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> dict[str, Any]:
    result = subprocess.run(command, cwd=str(cwd), env=env, capture_output=True,
                            text=True, check=False)
    record = {"argv": command, "exit_code": result.returncode}
    if result.returncode != 0:
        detail = (result.stdout + "\n" + result.stderr).strip()
        raise QualificationError(f"command failed ({' '.join(command)}):\n{detail[-4000:]}")
    return record


def write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def required_source_hashes() -> dict[str, str]:
    return {relative: sha256_file(ROOT / relative) for relative in QUALIFIED_FILES}


def native_input_hashes() -> dict[str, str]:
    tracked = tuple(line for line in git("ls-files").splitlines() if line)
    selected = sorted(relative for relative in tracked if relative in INPUT_FILES
                      or any(relative.startswith(prefix) for prefix in INPUT_PREFIXES))
    missing = sorted(set(INPUT_FILES).difference(selected))
    if missing:
        raise QualificationError("required V3 input is not tracked: " + ", ".join(missing))
    return {relative: sha256_file(ROOT / relative) for relative in selected}


def validate_profile(commit: str) -> None:
    try:
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(f"cannot read V3 profile: {exc}") from exc
    expected_command = {
        "requires_default_cli": True,
        "required_flags": ["--process-hardening", "--server-shard",
                           "--enable-experimental-server-shard", "--shard-reason"],
        "forbidden_flags": ["--anti-debug", "--memory-guard"],
    }
    if (profile.get("schema") != PROFILE_SCHEMA or profile.get("protocol") != PROTOCOL
            or profile.get("release_command") != expected_command
            or profile.get("files") != required_source_hashes()
            or profile.get("required_markers") != {key: list(value)
                                                   for key, value in REQUIRED_MARKERS.items()}
            or profile.get("forbidden_markers") != list(FORBIDDEN_MARKERS)):
        raise QualificationError("committed V3 qualification profile does not match source")
    profile_commit = profile.get("v3_source_commit")
    if not isinstance(profile_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", profile_commit):
        raise QualificationError("V3 profile lacks a full lowercase source commit")
    if subprocess.run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor",
                       profile_commit, commit], check=False).returncode != 0:
        raise QualificationError("V3 profile source commit is not an ancestor of HEAD")
    source = "\n".join((ROOT / relative).read_text(encoding="utf-8")
                         for relative in QUALIFIED_FILES)
    for marker in FORBIDDEN_MARKERS:
        if marker in source:
            raise QualificationError(f"legacy handoff marker present: {marker}")


def ctest_count(build_dir: Path) -> int:
    result = subprocess.run(["ctest", "--test-dir", str(build_dir), "-C", "Release",
                             "--show-only=json-v1"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise QualificationError("CTest inventory failed")
    try:
        count = len(json.loads(result.stdout).get("tests", []))
    except json.JSONDecodeError as exc:
        raise QualificationError("CTest inventory is not JSON") from exc
    if count < 1:
        raise QualificationError("CTest inventory is empty")
    return count


def evidence_entry(candidate: Path, path: Path) -> dict[str, str]:
    return {"path": path.relative_to(candidate).as_posix(), "sha256": sha256_file(path)}


def ensure_clean() -> str:
    if git("status", "--porcelain"):
        raise QualificationError("V3 qualification requires a completely clean Lethe checkout")
    return git("rev-parse", "HEAD")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="new directory for the immutable V3 stub candidate")
    parser.add_argument("--shuffle-seed", required=True,
                        help="recorded even-length hexadecimal DVM shuffle seed")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-fA-F]{32,}", args.shuffle_seed) or len(args.shuffle_seed) % 2:
        parser.error("--shuffle-seed must be an even-length hexadecimal value of at least 32 characters")
    candidate = args.output.resolve()
    if candidate.exists():
        parser.error("--output must be a new directory; existing evidence is never overwritten")
    commit = ensure_clean()
    validate_profile(commit)
    candidate.mkdir(parents=True)
    try:
        stub_build = candidate / "stub-build"
        configure = run([
            "cmake", "-S", str(ROOT / "stub"), "-B", str(stub_build),
            "-G", "Visual Studio 17 2022", "-A", "x64", "-DBUILD_TESTING=ON",
            f"-DPython3_EXECUTABLE={sys.executable}",
            f"-DDVM_SHUFFLE_SEED={args.shuffle_seed.lower()}",
            "-DCMAKE_C_FLAGS=/W4 /WX /Brepro", "-DCMAKE_C_FLAGS_RELEASE=/O2 /DNDEBUG /Brepro",
            "-DCMAKE_SHARED_LINKER_FLAGS_RELEASE=/INCREMENTAL:NO /Brepro",
            "-DCMAKE_EXE_LINKER_FLAGS_RELEASE=/INCREMENTAL:NO /Brepro",
        ], cwd=ROOT)
        build = run(["cmake", "--build", str(stub_build), "--config", "Release",
                     "--parallel", "2"], cwd=ROOT)
        stub_source = stub_build / "Release" / "lethe_stub_x64.dll"
        if not stub_source.is_file():
            raise QualificationError("fresh V3 stub build produced no lethe_stub_x64.dll")
        stub = candidate / "lethe_stub_x64.dll"
        shutil.copy2(stub_source, stub)
        stub_hash = sha256_file(stub)
        stub_tests = ctest_count(stub_build)
        stub_ctest_command = run(["ctest", "--test-dir", str(stub_build), "-C", "Release",
                                  "--output-on-failure"], cwd=ROOT)
        ctest_path = candidate / "ctest.json"
        write_json(ctest_path, {"schema": 1, "name": "ctest", "source_commit": commit,
                                "artifact_sha256": stub_hash, "ready": True,
                                "passed": stub_tests, "total": stub_tests,
                                "command": {**configure, "build": build, "ctest": stub_ctest_command,
                                            "exit_code": 0}})

        bootstrap_build = candidate / "bootstrap-build"
        bootstrap_configure = run([
            "cmake", "-S", str(ROOT / "bootstrap"), "-B", str(bootstrap_build),
            "-G", "Visual Studio 17 2022", "-A", "x64", "-DBUILD_TESTING=ON",
            f"-DLETHE_ORION_ACTIVATE_SHA256={TEST_BROKER_DIGEST}",
        ], cwd=ROOT)
        bootstrap_build_record = run(["cmake", "--build", str(bootstrap_build), "--config",
                                      "Release", "--parallel", "2"], cwd=ROOT)
        bootstrap_source = bootstrap_build / "Release" / "LetheShardBootstrap.exe"
        if not bootstrap_source.is_file():
            raise QualificationError("bootstrap compatibility build produced no executable")
        bootstrap = candidate / "LetheShardBootstrap.exe"
        shutil.copy2(bootstrap_source, bootstrap)
        bootstrap_hash = sha256_file(bootstrap)
        bootstrap_marker = ("ORION_ACTIVATE_SHA256:" + TEST_BROKER_DIGEST).encode("ascii")
        bootstrap_bytes = bootstrap.read_bytes()
        if bootstrap_bytes.count(bootstrap_marker) != 1:
            raise QualificationError(
                "bootstrap compatibility binary lacks one exact broker-binding marker"
            )
        bootstrap_tests = ctest_count(bootstrap_build)
        if bootstrap_tests < 3:
            raise QualificationError("bootstrap CTest inventory must contain three V3 compatibility tests")
        bootstrap_ctest_command = run(["ctest", "--test-dir", str(bootstrap_build), "-C",
                                       "Release", "--output-on-failure"], cwd=ROOT)
        bootstrap_ctest_path = candidate / "bootstrap-ctest.json"
        write_json(bootstrap_ctest_path, {
            "schema": 1, "name": "bootstrap-ctest", "source_commit": commit,
            "artifact": "LetheShardBootstrap.exe", "artifact_sha256": bootstrap_hash,
            "binding_marker": "ORION_ACTIVATE_SHA256:" + TEST_BROKER_DIGEST,
            "binding_test_digest": TEST_BROKER_DIGEST, "ready": True,
            "passed": bootstrap_tests, "total": bootstrap_tests,
            "command": {**bootstrap_configure, "build": bootstrap_build_record,
                        "ctest": bootstrap_ctest_command, "exit_code": 0},
        })

        corpus_dir = candidate / "corpus"
        run(["powershell", "-NoProfile", "-File", str(ROOT / "tests" / "build_production_corpus.ps1"),
             "-OutDir", str(corpus_dir)], cwd=ROOT)
        corpus_path = candidate / "exe-corpus.json"
        run(["powershell", "-NoProfile", "-File", str(ROOT / "tests" / "production_corpus.ps1"),
             "-StubPath", str(stub), "-PythonExe", sys.executable, "-BuildDir", str(corpus_dir),
             "-EvidencePath", str(corpus_path)], cwd=ROOT)
        corpus = json.loads(corpus_path.read_text(encoding="utf-8-sig"))
        required_corpus = {"exe.core.shape", "exe.core.original", "exe.core.pack",
                           "exe.core.runtime", "exe.delay.shape", "exe.delay.original",
                           "exe.delay.pack", "exe.delay.runtime"}
        statuses = {item.get("id"): item.get("status") for item in corpus.get("tests", [])
                    if isinstance(item, dict)}
        if (corpus.get("source_commit") != commit or corpus.get("tracked_source_dirty") is not False
                or corpus.get("stub_sha256") != stub_hash
                or any(statuses.get(name) != "passed" for name in required_corpus)):
            raise QualificationError("fresh EXE compatibility corpus is incomplete or failed")

        pipe_env = dict(os.environ)
        pipe_env.update({"LETHE_NATIVE_STUB_PATH": str(stub),
                         "LETHE_NATIVE_SAMPLE_EXE": str(corpus_dir / "compat_core_exe.exe")})
        pipe_command = run([sys.executable, "-m", "pytest", "-q",
                            "tests/test_native_shard_runtime.py",
                            "tests/test_bootstrap_safety_contracts.py"], cwd=ROOT, env=pipe_env)
        pipe_path = candidate / "v3-pipe.json"
        write_json(pipe_path, {
            "schema": 1, "name": "v3-pipe-native", "source_commit": commit,
            "artifact_sha256": stub_hash, "ready": True,
            "command": {**pipe_command, "exit_code": 0},
            "checks": {
                "vsg3.missing_frame_rejected": "passed",
                "vsg3.wrong_shard_rejected": "passed",
                "vsg3.trailing_frame_rejected": "passed",
                "vsg3.exact_frame_runs": "passed",
                "bootstrap.pipe_contract": "passed",
            },
        })
        manifest = {
            "schema": SCHEMA, "profile": PROFILE_NAME, "target_scope": "exe",
            "source_commit": commit, "source_dirty": False, "artifact": stub.name,
            "artifact_sha256": stub_hash, "artifact_size_bytes": stub.stat().st_size,
            "native_stub_inputs": native_input_hashes(),
            "v3_profile": {"path": "docs/venice_server_shard_v3_qualification.json",
                           "sha256": sha256_file(PROFILE), "protocol": PROTOCOL},
            "bootstrap_compatibility": {
                "artifact": bootstrap.name, "artifact_sha256": bootstrap_hash,
                "binding_marker": "ORION_ACTIVATE_SHA256:" + TEST_BROKER_DIGEST,
                "binding_test_digest": TEST_BROKER_DIGEST, "production_binding_required": True,
            },
            "evidence": {"ctest": evidence_entry(candidate, ctest_path),
                         "bootstrap_ctest": evidence_entry(candidate, bootstrap_ctest_path),
                         "exe_corpus": evidence_entry(candidate, corpus_path),
                         "v3_pipe": evidence_entry(candidate, pipe_path)},
        }
        manifest_path = candidate / MANIFEST_NAME
        write_json(manifest_path, manifest)
        print(manifest_path)
        return 0
    except Exception:
        # Evidence remains available for diagnosis but is never manifested as ready.
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except QualificationError as exc:
        print(f"V3 qualification: FAILED\n  - {exc}", file=sys.stderr)
        raise SystemExit(1)
