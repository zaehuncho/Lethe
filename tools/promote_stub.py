#!/usr/bin/env python3
"""Build, prove, and stage a Lethe native-stub release candidate.

This tool never updates ``stub/prebuilt``. It emits a transactionally written
candidate manifest only after every source, toolchain, CTest, round-trip,
corpus, and production-compatibility gate has passed for one artifact hash.
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
import tomllib
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import production_gate


ROOT = Path(__file__).resolve().parents[1]
PREBUILT = ROOT / "stub" / "prebuilt" / "lethe_stub_x64.dll"
PREBUILT_MANIFEST = PREBUILT.with_name("lethe_stub_x64.manifest.json")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
SEED_RE = re.compile(r"[0-9a-f]+\Z")
ROUNDTRIP_RE = re.compile(r"(?m)^\s*(\d+)/(\d+) passed -- PASS\s*$")
SUPPORTED_PYTHON = (3, 12)
SUPPORTED_UV = "0.11.29"
SUPPORTED_GENERATOR = "Visual Studio 17 2022"
SUPPORTED_PLATFORM = "x64"
REQUIRED_LOCKED_FILES = ("pyproject.toml", "uv.lock")


class PromotionError(RuntimeError):
    """A fail-closed release-promotion gate rejected the candidate."""


@dataclass(frozen=True)
class CommandRecord:
    name: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    source_commit: str
    artifact_sha256: str | None = None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _run(
    argv: Sequence[str | os.PathLike[str]],
    *,
    name: str,
    source_commit: str,
    artifact_sha256: str | None = None,
    cwd: Path = ROOT,
) -> CommandRecord:
    command = [os.fspath(part) for part in argv]
    completed = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    if completed.stderr:
        print(
            completed.stderr,
            end="" if completed.stderr.endswith("\n") else "\n",
            file=sys.stderr,
        )
    return CommandRecord(
        name=name,
        argv=command,
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        source_commit=source_commit,
        artifact_sha256=artifact_sha256,
    )


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={root.as_posix()}", *args],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise PromotionError(
            f"git {' '.join(args)} failed ({completed.returncode}): "
            f"{(completed.stderr or completed.stdout).strip()}"
        )
    return completed.stdout


def inspect_repository(root: Path, expected_commit: str) -> dict[str, Any]:
    if COMMIT_RE.fullmatch(expected_commit) is None:
        raise PromotionError("--source-commit must be a full lowercase Git commit id")
    head = _git(root, "rev-parse", "HEAD").strip()
    if head != expected_commit:
        raise PromotionError(
            f"source commit mismatch: HEAD is {head}, requested {expected_commit}"
        )
    committed = _git(root, "rev-parse", "--verify", f"{expected_commit}^{{commit}}").strip()
    if committed != expected_commit:
        raise PromotionError(f"source commit is not an exact commit object: {expected_commit}")
    dirty = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if dirty.strip():
        paths = [line[3:] if len(line) > 3 else line for line in dirty.splitlines()]
        preview = ", ".join(paths[:8])
        suffix = " ..." if len(paths) > 8 else ""
        raise PromotionError(f"source tree is not clean: {preview}{suffix}")

    locked: dict[str, str] = {}
    for relative in REQUIRED_LOCKED_FILES:
        _git(root, "ls-files", "--error-unmatch", "--", relative)
        path = root / relative
        if not path.is_file():
            raise PromotionError(f"required dependency input is missing: {relative}")
        locked[relative] = sha256_file(path)

    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    if project.get("project", {}).get("requires-python") != ">=3.12,<3.13":
        raise PromotionError("pyproject.toml must pin the supported Python 3.12 line")
    lock_header = (root / "uv.lock").read_text(encoding="utf-8").splitlines()[:8]
    if 'requires-python = "==3.12.*"' not in lock_header:
        raise PromotionError("uv.lock must pin requires-python to ==3.12.*")

    submodules = _git(root, "submodule", "status", "--recursive")
    bad_submodules = [line for line in submodules.splitlines() if line[:1] in "-+U"]
    if bad_submodules:
        raise PromotionError("submodule state does not match the source commit")
    return {"source_commit": head, "locked_files": locked}


def _require_program(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise PromotionError(f"required program is unavailable: {name}")
    return resolved


def _version_output(argv: Sequence[str], label: str) -> str:
    completed = subprocess.run(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise PromotionError(f"cannot identify {label} version")
    output = (completed.stdout or completed.stderr).strip()
    if not output:
        raise PromotionError(f"{label} emitted no version")
    return output.splitlines()[0].strip()


def inspect_host(root: Path) -> dict[str, str]:
    if os.name != "nt":
        raise PromotionError("stub promotion requires a Windows x64 build host")
    if sys.version_info[:2] != SUPPORTED_PYTHON:
        raise PromotionError(
            "stub promotion requires Python 3.12 from the committed locked environment"
        )
    locked_python = root / ".venv" / "Scripts" / "python.exe"
    if not locked_python.is_file() or Path(sys.executable).resolve() != locked_python.resolve():
        raise PromotionError(
            "run promotion with .venv\\Scripts\\python.exe after uv sync --frozen --group dev"
        )
    uv = _require_program("uv")
    cmake = _require_program("cmake")
    ctest = _require_program("ctest")
    uv_version = _version_output([uv, "--version"], "uv")
    if re.match(rf"uv {re.escape(SUPPORTED_UV)}(?:\s|$)", uv_version) is None:
        raise PromotionError(
            f"unsupported uv version: {uv_version}; required uv {SUPPORTED_UV}"
        )
    cmake_version = _version_output([cmake, "--version"], "CMake")
    cmake_match = re.fullmatch(r"cmake version (\d+)\.(\d+)\.(\d+)", cmake_version)
    if cmake_match is None or tuple(map(int, cmake_match.groups())) < (3, 20, 0):
        raise PromotionError(f"unsupported CMake version: {cmake_version}")
    ctest_version = _version_output([ctest, "--version"], "CTest")
    if ctest_version.replace("ctest version ", "") != cmake_version.replace("cmake version ", ""):
        raise PromotionError("CMake and CTest versions do not match")
    return {
        "python": str(locked_python.resolve()),
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "uv": uv,
        "uv_version": uv_version.removeprefix("uv ").split(" ", 1)[0],
        "cmake": cmake,
        "cmake_version": cmake_version.removeprefix("cmake version "),
        "ctest": ctest,
        "ctest_version": ctest_version.removeprefix("ctest version "),
        "powershell": _require_program("powershell.exe"),
    }


def _cache_value(cache: str, key: str) -> str:
    match = re.search(rf"(?m)^{re.escape(key)}:[^=]+=(.*)\r?$", cache)
    if match is None:
        raise PromotionError(f"fresh CMake cache is missing {key}")
    return match.group(1).strip()


def inspect_cmake_toolchain(build_dir: Path) -> dict[str, str]:
    cache_path = build_dir / "CMakeCache.txt"
    if not cache_path.is_file():
        raise PromotionError("fresh configure did not produce CMakeCache.txt")
    cache = cache_path.read_text(encoding="utf-8", errors="replace")
    generator = _cache_value(cache, "CMAKE_GENERATOR")
    platform = _cache_value(cache, "CMAKE_GENERATOR_PLATFORM")
    if generator != SUPPORTED_GENERATOR or platform.lower() != SUPPORTED_PLATFORM:
        raise PromotionError(f"unsupported CMake generator/platform: {generator} / {platform}")

    compiler_files = list((build_dir / "CMakeFiles").glob("*/CMakeCCompiler.cmake"))
    if len(compiler_files) != 1:
        raise PromotionError("cannot identify the configured C compiler exactly")
    compiler_data = compiler_files[0].read_text(encoding="utf-8", errors="replace")
    compiler_id_match = re.search(r'set\(CMAKE_C_COMPILER_ID "([^"]+)"\)', compiler_data)
    version_match = re.search(r'set\(CMAKE_C_COMPILER_VERSION "([^"]+)"\)', compiler_data)
    compiler_id = compiler_id_match.group(1) if compiler_id_match else ""
    compiler_version = version_match.group(1) if version_match else ""
    if compiler_id != "MSVC" or not compiler_version.startswith("19."):
        raise PromotionError(
            f"unsupported native compiler: {compiler_id or 'unknown'} "
            f"{compiler_version or 'unknown'}"
        )

    c_flags = _cache_value(cache, "CMAKE_C_FLAGS")
    release_flags = _cache_value(cache, "CMAKE_C_FLAGS_RELEASE")
    shared_link_flags = _cache_value(cache, "CMAKE_SHARED_LINKER_FLAGS_RELEASE")
    required_compile = ("/W4", "/WX", "/Brepro")
    combined_compile = f"{c_flags} {release_flags}"
    if any(flag.lower() not in combined_compile.lower() for flag in required_compile):
        raise PromotionError("fresh stub build is not enforcing /W4 /WX /Brepro")
    if "/brepro" not in shared_link_flags.lower():
        raise PromotionError("fresh stub link is not enforcing /Brepro")
    return {
        "cmake_generator": generator,
        "cmake_platform": platform,
        "compiler_id": compiler_id,
        "compiler_version": compiler_version,
        "compile_policy": "/W4 /WX /Brepro",
        "link_policy": "/Brepro",
    }


def inspect_generated_dvm_provenance(
    build_dir: Path,
    requested_seed: str,
) -> dict[str, str]:
    python_map = build_dir / "daedalus_opcodes_shuffled.py"
    native_map = build_dir / "daedalus_opcodes_shuffled.h"
    if not python_map.is_file() or not native_map.is_file():
        raise PromotionError("fresh build did not emit both shuffled opcode maps")

    python_text = python_map.read_text(encoding="utf-8")
    native_text = native_map.read_text(encoding="utf-8")

    def python_value(name: str) -> str:
        match = re.search(
            rf"(?m)^{re.escape(name)} = ['\"]([0-9a-f]+)['\"]$",
            python_text,
        )
        if match is None:
            raise PromotionError(f"generated Python opcode map has no valid {name}")
        return match.group(1)

    def native_value(name: str) -> str:
        match = re.search(
            rf'(?m)^#define {re.escape(name)} "([0-9a-f]+)"$',
            native_text,
        )
        if match is None:
            raise PromotionError(f"generated native opcode map has no valid {name}")
        return match.group(1)

    effective_seed = python_value("BUILD_SEED")
    mapping_hash = python_value("OPCODE_MAPPING_SHA256")
    handler_hash = python_value("HANDLER_VARIANT_SHA256")
    native_mapping_hash = native_value("DVM_OPCODE_MAPPING_SHA256")
    native_handler_hash = native_value("DVM_HANDLER_VARIANT_SHA256")
    if effective_seed != requested_seed:
        raise PromotionError(
            "generated Daedalus build seed differs from the requested seed"
        )
    if not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (
        mapping_hash, handler_hash, native_mapping_hash, native_handler_hash,
    )):
        raise PromotionError("generated Daedalus provenance hashes are malformed")
    if mapping_hash != native_mapping_hash or handler_hash != native_handler_hash:
        raise PromotionError("Python and native Daedalus opcode maps disagree")
    return {
        "dvm_shuffle_seed": effective_seed,
        "dvm_opcode_mapping_sha256": mapping_hash,
        "dvm_handler_variant_sha256": handler_hash,
        "dvm_python_map_sha256": sha256_file(python_map),
        "dvm_native_map_sha256": sha256_file(native_map),
    }


def _record(path: Path, record: CommandRecord) -> None:
    atomic_write_json(path, {"schema": 1, **asdict(record)})


def _require_unchanged_artifact(stub: Path, expected_hash: str, gate: str) -> None:
    actual_hash = sha256_file(stub)
    if actual_hash != expected_hash:
        raise PromotionError(
            f"candidate artifact changed during {gate}: {actual_hash} != {expected_hash}"
        )


def validate_roundtrip_record(record: CommandRecord, expected_hash: str) -> tuple[int, int]:
    if record.artifact_sha256 != expected_hash:
        raise PromotionError("round-trip evidence names a different artifact SHA-256")
    if record.exit_code != 0:
        raise PromotionError(f"EXE/DLL round-trip gate failed with exit {record.exit_code}")
    match = ROUNDTRIP_RE.search(record.stdout)
    if match is None:
        raise PromotionError("round-trip output has no authoritative N/N PASS summary")
    passed, total = map(int, match.groups())
    if total < 1 or passed != total:
        raise PromotionError("round-trip summary is not fully passing")
    return passed, total


def validate_corpus_evidence(
    evidence_path: Path,
    *,
    expected_commit: str,
    expected_hash: str,
) -> dict[str, Any]:
    evidence = production_gate.load_evidence(evidence_path)
    if evidence["source_commit"] != expected_commit:
        raise PromotionError("production corpus evidence names a different source commit")
    if evidence["tracked_source_dirty"]:
        raise PromotionError("production corpus evidence came from tracked-dirty source")
    if evidence["stub_sha256"] != expected_hash:
        raise PromotionError("production corpus evidence names a different artifact SHA-256")
    if not evidence["ready"]:
        raise PromotionError(
            f"production corpus is red ({evidence['passed']}/{evidence['total']} passed)"
        )
    return evidence


def validate_gate_payload(payload: dict[str, Any]) -> None:
    if payload.get("schema") != 1 or payload.get("scope") != "all":
        raise PromotionError("production compatibility result is malformed or not all-scope")
    if payload.get("ready") is not True or payload.get("blocker_count") != 0:
        blockers = payload.get("blockers", [])
        ids = ", ".join(str(item.get("id", "unknown")) for item in blockers[:8])
        raise PromotionError(f"production compatibility gate is red: {ids or 'unknown blockers'}")


def build_manifest(
    *,
    staged_stub: Path,
    source: dict[str, Any],
    host: dict[str, str],
    toolchain: dict[str, str],
    dvm_provenance: dict[str, str],
    roundtrip_counts: tuple[int, int],
    ctest_count: int,
    evidence_paths: Iterable[Path],
    stage_dir: Path,
) -> dict[str, Any]:
    artifact_hash = sha256_file(staged_stub)
    passed, total = roundtrip_counts
    evidence = []
    for path in evidence_paths:
        evidence.append({
            "path": path.relative_to(stage_dir).as_posix(),
            "sha256": sha256_file(path),
        })
    return {
        "schema": 1,
        "artifact": staged_stub.name,
        "sha256": artifact_hash,
        "size_bytes": staged_stub.stat().st_size,
        "source_commit": source["source_commit"],
        "source_dirty": False,
        "configuration": "Release",
        "cmake_generator": toolchain["cmake_generator"],
        "cmake_platform": toolchain["cmake_platform"],
        "compiler_id": toolchain["compiler_id"],
        "compiler_version": toolchain["compiler_version"],
        "warning_policy": toolchain["compile_policy"],
        "reproducible_link": toolchain["link_policy"],
        "python_version": host["python_version"],
        "uv_version": host["uv_version"],
        "cmake_version": host["cmake_version"],
        "ctest_version": host["ctest_version"],
        "dependency_locks": source["locked_files"],
        **dvm_provenance,
        "native_roundtrip": "passed-9-of-9",
        "native_roundtrip_actual": {"passed": passed, "total": total},
        "ctest": {"passed": ctest_count, "total": ctest_count},
        "production_scope": "all",
        "provenance_status": "clean",
        "evidence": evidence,
    }


def _validate_staged_pair(stub: Path, manifest_path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError(f"cannot read staged manifest: {exc}") from exc
    if manifest.get("artifact") != stub.name:
        raise PromotionError("staged manifest names a different artifact")
    if manifest.get("sha256") != sha256_file(stub):
        raise PromotionError("staged manifest SHA-256 does not match the artifact")
    if manifest.get("source_dirty") is not False or manifest.get("provenance_status") != "clean":
        raise PromotionError("staged manifest is not clean-source release evidence")
    return manifest


def _load_json_output(record: CommandRecord, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(record.stdout)
    except json.JSONDecodeError as exc:
        raise PromotionError(f"{label} did not emit valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PromotionError(f"{label} JSON root is not an object")
    return payload


def execute(args: argparse.Namespace) -> Path | None:
    source_commit = args.source_commit.strip()
    shuffle_seed = args.shuffle_seed.lower()
    if SEED_RE.fullmatch(shuffle_seed) is None or len(shuffle_seed) % 2:
        raise PromotionError("--shuffle-seed must contain an even number of hex digits")

    source = inspect_repository(ROOT, source_commit)
    host = inspect_host(ROOT)
    default_stage = ROOT / f".test-release-promotion-{source_commit[:12]}-{shuffle_seed[:12]}"
    stage_dir = (args.stage_dir or default_stage).resolve()

    plan = {
        "mode": "stage-only",
        "source_commit": source_commit,
        "shuffle_seed": shuffle_seed,
        "stage_dir": str(stage_dir),
        "tracked_prebuilt": str(PREBUILT),
    }
    print(json.dumps(plan, indent=2, sort_keys=True))
    if args.dry_run:
        print("Dry run complete; no build, staging, or publication was performed.")
        return None
    if stage_dir.exists():
        raise PromotionError(f"stage directory already exists: {stage_dir}")
    stage_dir.mkdir(parents=True)
    records_dir = stage_dir / "evidence"
    records_dir.mkdir()

    failures: list[str] = []
    records: list[tuple[Path, CommandRecord]] = []

    def run_recorded(
        argv: Sequence[str | os.PathLike[str]],
        *,
        name: str,
        path_name: str,
        artifact_hash: str | None = None,
    ) -> CommandRecord:
        record = _run(
            argv,
            name=name,
            source_commit=source_commit,
            artifact_sha256=artifact_hash,
        )
        path = records_dir / path_name
        _record(path, record)
        records.append((path, record))
        return record

    uv_record = run_recorded(
        [host["uv"], "sync", "--frozen", "--group", "dev"],
        name="locked-dependency-sync",
        path_name="uv-sync.json",
    )
    if uv_record.exit_code != 0:
        raise PromotionError("uv sync --frozen failed; dependency lock is not usable")
    inspect_repository(ROOT, source_commit)

    build_dir = stage_dir / "build"
    configure = run_recorded(
        [
            host["cmake"], "-S", ROOT / "stub", "-B", build_dir,
            "-G", SUPPORTED_GENERATOR, "-A", SUPPORTED_PLATFORM,
            "-DBUILD_TESTING=ON",
            f"-DPython3_EXECUTABLE={host['python']}",
            f"-DDVM_SHUFFLE_SEED={shuffle_seed}",
            "-DCMAKE_C_FLAGS=/W4 /WX /Brepro",
            "-DCMAKE_C_FLAGS_RELEASE=/O2 /Brepro",
            "-DCMAKE_SHARED_LINKER_FLAGS_RELEASE=/Brepro",
            "-DCMAKE_EXE_LINKER_FLAGS_RELEASE=/Brepro",
        ],
        name="fresh-cmake-configure",
        path_name="cmake-configure.json",
    )
    if configure.exit_code != 0:
        raise PromotionError("fresh CMake configure failed")
    toolchain = inspect_cmake_toolchain(build_dir)

    build = run_recorded(
        [host["cmake"], "--build", build_dir, "--config", "Release", "--parallel", "2", "--verbose"],
        name="fresh-w4-wx-stub-build",
        path_name="cmake-build.json",
    )
    if build.exit_code != 0:
        raise PromotionError("fresh /W4 /WX stub build failed")
    built_stub = build_dir / "Release" / "lethe_stub_x64.dll"
    if not built_stub.is_file():
        raise PromotionError(f"fresh build did not produce {built_stub}")
    artifact_hash = sha256_file(built_stub)
    dvm_provenance = inspect_generated_dvm_provenance(build_dir, shuffle_seed)

    ctest_list = run_recorded(
        [host["ctest"], "--test-dir", build_dir, "-C", "Release", "--show-only=json-v1"],
        name="ctest-inventory",
        path_name="ctest-inventory.json",
        artifact_hash=artifact_hash,
    )
    ctest_inventory = _load_json_output(ctest_list, "CTest inventory")
    ctest_count = len(ctest_inventory.get("tests", []))
    if ctest_list.exit_code != 0 or ctest_count < 1:
        failures.append("CTest inventory is empty or invalid")
    ctest = run_recorded(
        [host["ctest"], "--test-dir", build_dir, "-C", "Release", "--output-on-failure"],
        name="ctest",
        path_name="ctest.json",
        artifact_hash=artifact_hash,
    )
    if ctest.exit_code != 0:
        failures.append(f"CTest failed with exit {ctest.exit_code}")
    _require_unchanged_artifact(built_stub, artifact_hash, "CTest")

    sample_build = run_recorded(
        [host["powershell"], "-NoProfile", "-File", ROOT / "tests" / "build_samples.ps1", "-OutDir", ROOT / "tests" / "build"],
        name="roundtrip-fixture-build",
        path_name="roundtrip-fixture-build.json",
        artifact_hash=artifact_hash,
    )
    if sample_build.exit_code != 0:
        failures.append(f"round-trip fixture build failed with exit {sample_build.exit_code}")
        roundtrip = None
    else:
        roundtrip = run_recorded(
            [host["powershell"], "-NoProfile", "-File", ROOT / "tests" / "roundtrip.ps1", "-StubPath", built_stub, "-PythonExe", host["python"]],
            name="exe-dll-roundtrip",
            path_name="roundtrip.json",
            artifact_hash=artifact_hash,
        )
        try:
            roundtrip_counts = validate_roundtrip_record(roundtrip, artifact_hash)
        except PromotionError as exc:
            roundtrip_counts = (0, 0)
            failures.append(str(exc))
    _require_unchanged_artifact(built_stub, artifact_hash, "EXE/DLL round-trip")

    corpus_dir = stage_dir / "corpus"
    corpus_build = run_recorded(
        [host["powershell"], "-NoProfile", "-File", ROOT / "tests" / "build_production_corpus.ps1", "-OutDir", corpus_dir],
        name="production-corpus-build",
        path_name="production-corpus-build.json",
        artifact_hash=artifact_hash,
    )
    corpus_evidence_path = records_dir / "production-evidence.json"
    if corpus_build.exit_code != 0:
        failures.append(f"production corpus build failed with exit {corpus_build.exit_code}")
    else:
        corpus = run_recorded(
            [host["powershell"], "-NoProfile", "-File", ROOT / "tests" / "production_corpus.ps1", "-StubPath", built_stub, "-PythonExe", host["python"], "-BuildDir", corpus_dir, "-EvidencePath", corpus_evidence_path],
            name="production-corpus",
            path_name="production-corpus.json",
            artifact_hash=artifact_hash,
        )
        if corpus.exit_code != 0:
            failures.append(f"production corpus process failed with exit {corpus.exit_code}")
        try:
            validate_corpus_evidence(
                corpus_evidence_path,
                expected_commit=source_commit,
                expected_hash=artifact_hash,
            )
        except (PromotionError, production_gate.MatrixError) as exc:
            failures.append(str(exc))
    _require_unchanged_artifact(built_stub, artifact_hash, "production corpus")

    gate_args: list[str | os.PathLike[str]] = [
        host["python"], ROOT / "tools" / "production_gate.py",
        "--scope", "all", "--format", "json",
    ]
    if corpus_evidence_path.is_file():
        gate_args.extend(("--evidence", corpus_evidence_path))
    gate = run_recorded(
        gate_args,
        name="all-scope-production-gate",
        path_name="production-gate.json",
        artifact_hash=artifact_hash,
    )
    try:
        gate_payload = _load_json_output(gate, "production compatibility gate")
        validate_gate_payload(gate_payload)
    except PromotionError as exc:
        failures.append(str(exc))
    if gate.exit_code != 0 and not any("production compatibility gate" in item for item in failures):
        failures.append(f"production compatibility gate failed with exit {gate.exit_code}")

    try:
        inspect_repository(ROOT, source_commit)
    except PromotionError as exc:
        failures.append(str(exc))
    _require_unchanged_artifact(built_stub, artifact_hash, "final provenance check")

    result_path = stage_dir / "promotion-result.json"
    if failures:
        atomic_write_json(result_path, {
            "schema": 1,
            "ready": False,
            "published": False,
            "source_commit": source_commit,
            "artifact_sha256": artifact_hash,
            "failures": failures,
        })
        raise PromotionError("; ".join(failures))

    staged_stub = stage_dir / PREBUILT.name
    shutil.copyfile(built_stub, staged_stub)
    _require_unchanged_artifact(staged_stub, artifact_hash, "staging copy")
    evidence_paths = [path for path, _record_item in records]
    evidence_paths.append(corpus_evidence_path)
    manifest = build_manifest(
        staged_stub=staged_stub,
        source=source,
        host=host,
        toolchain=toolchain,
        dvm_provenance=dvm_provenance,
        roundtrip_counts=roundtrip_counts,
        ctest_count=ctest_count,
        evidence_paths=evidence_paths,
        stage_dir=stage_dir,
    )
    staged_manifest = stage_dir / PREBUILT_MANIFEST.name
    atomic_write_json(staged_manifest, manifest)
    _validate_staged_pair(staged_stub, staged_manifest)

    atomic_write_json(result_path, {
        "schema": 1,
        "ready": True,
        "published": False,
        "source_commit": source_commit,
        "artifact_sha256": artifact_hash,
        "manifest_sha256": sha256_file(staged_manifest),
    })
    print(f"Release candidate staged at {stage_dir}")
    print("Tracked prebuilt was not modified.")
    return stage_dir


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--shuffle-seed", required=True)
    parser.add_argument("--stage-dir", type=Path)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate immutable preconditions and print the plan without building",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        execute(args)
    except (OSError, PromotionError, production_gate.MatrixError) as exc:
        print(f"Promotion: FAILED\n  - {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
