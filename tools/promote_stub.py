#!/usr/bin/env python3
"""Build, prove, and stage a locally verified Lethe native-stub candidate.

This tool never updates ``stub/prebuilt``. It emits a transactionally written
candidate manifest only after every local source, toolchain, CTest, round-trip,
and corpus gate has passed for one artifact hash. A fixed set of declared
production blockers may remain; the resulting bundle is never a production
release and cannot authorize the default bundled stub.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tomllib
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import production_gate


ROOT = Path(__file__).resolve().parents[1]
PREBUILT = ROOT / "stub" / "prebuilt" / "lethe_stub_x64.dll"
PREBUILT_MANIFEST = PREBUILT.with_name("lethe_stub_x64.manifest.json")
PRODUCTION_MATRIX = ROOT / "docs" / "production_compatibility.json"
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SEED_RE = re.compile(r"[0-9a-f]+\Z")
ROUNDTRIP_RE = re.compile(r"(?m)^\s*(\d+)/(\d+) passed -- PASS\s*$")
PYTEST_PASSED_RE = re.compile(r"(?m)(\d+) passed(?:,| in )")
SUPPORTED_PYTHON = (3, 12)
SUPPORTED_UV = "0.11.29"
SUPPORTED_GENERATOR = "Visual Studio 17 2022"
SUPPORTED_PLATFORM = "x64"
REQUIRED_LOCKED_FILES = ("pyproject.toml", "uv.lock")
REQUIRED_NATIVE_RUNTIME_TESTS = (
    "test_native_runtime_hardening_stress.py",
    "test_native_virtualization_runtime.py",
)
REQUIRED_NATIVE_RUNTIME_PASS_COUNT = 5
CANDIDATE_POLICY_ID = "lethe-native-candidate-v1"
CANDIDATE_ALLOWED_BLOCKERS = {
    "mitigation.load_config_cfg_xfg": "partial",
    "virtualization.selected_functions": "partial",
    "hardening.process_policy": "partial",
    "hardening.antidebug": "experimental",
    "hardening.memory_guard_native": "experimental",
    "provenance.fresh_native_stub": "blocked",
    "release.clean_vm_matrix": "unverified",
}
REQUIRED_CANDIDATE_EVIDENCE = frozenset({
    "evidence/candidate-policy.json",
    "evidence/candidate-production-matrix.json",
    "evidence/candidate-promoter.py",
    "evidence/uv-sync.json",
    "evidence/cmake-configure.json",
    "evidence/cmake-build.json",
    "evidence/stub-entrypoints.json",
    "evidence/ctest-inventory.json",
    "evidence/ctest.json",
    "evidence/runtime-hardening.json",
    "evidence/roundtrip-fixture-build.json",
    "evidence/roundtrip.json",
    "evidence/production-corpus-build.json",
    "evidence/production-corpus.json",
    "evidence/production-evidence.json",
    "evidence/production-gate.json",
})


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


def release_dvm_configure_args(shuffle_seed: str) -> list[str]:
    if re.fullmatch(r"[0-9a-f]{64}", shuffle_seed) is None:
        raise PromotionError("DVM shuffle seed must encode exactly 32 bytes")
    return [
        f"-DDVM_SHUFFLE_SEED={shuffle_seed}",
        "-DDVM_ROLLING=ON",
        "-DDVM_ROLL_POISON=OFF",
    ]


def _promotion_configure_argv(
    host: Mapping[str, str],
    build_dir: Path,
    shuffle_seed: str,
) -> list[str | os.PathLike[str]]:
    return [
        host["cmake"], "-S", ROOT / "stub", "-B", build_dir,
        "-G", SUPPORTED_GENERATOR, "-A", SUPPORTED_PLATFORM,
        "-DBUILD_TESTING=ON",
        f"-DPython3_EXECUTABLE={host['python']}",
        *release_dvm_configure_args(shuffle_seed),
        "-DCMAKE_C_FLAGS=/W4 /WX /Brepro",
        "-DCMAKE_C_FLAGS_RELEASE=/O2 /Brepro",
        "-DCMAKE_SHARED_LINKER_FLAGS_RELEASE=/Brepro /INCREMENTAL:NO",
        "-DCMAKE_EXE_LINKER_FLAGS_RELEASE=/Brepro",
    ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def candidate_policy_payload() -> dict[str, Any]:
    return {
        "schema": 1,
        "policy_id": CANDIDATE_POLICY_ID,
        "allowed_blockers": CANDIDATE_ALLOWED_BLOCKERS,
        "python": ".".join(map(str, SUPPORTED_PYTHON)),
        "uv": SUPPORTED_UV,
        "cmake_generator": SUPPORTED_GENERATOR,
        "cmake_platform": SUPPORTED_PLATFORM,
        "compile_policy": "/W4 /WX /Brepro",
        "link_policy": "/Brepro /INCREMENTAL:NO",
        "required_evidence": sorted(REQUIRED_CANDIDATE_EVIDENCE),
    }


def candidate_policy_sha256() -> str:
    return _canonical_sha256(candidate_policy_payload())


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
    env_overrides: Mapping[str, str] | None = None,
) -> CommandRecord:
    command = [os.fspath(part) for part in argv]
    recorded_overrides: dict[str, str] = {}
    command_environment = None
    if env_overrides is not None:
        for key, value in env_overrides.items():
            if (not isinstance(key, str) or not key or "=" in key or "\0" in key
                    or not isinstance(value, str) or "\0" in value):
                raise PromotionError("command environment overrides must be valid strings")
            recorded_overrides[key] = value
        command_environment = os.environ.copy()
        command_environment.update(recorded_overrides)
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=command_environment,
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
    required_link = ("/Brepro", "/INCREMENTAL:NO")
    if any(flag.lower() not in shared_link_flags.lower() for flag in required_link):
        raise PromotionError(
            "fresh stub link is not enforcing /Brepro /INCREMENTAL:NO")
    return {
        "cmake_generator": generator,
        "cmake_platform": platform,
        "compiler_id": compiler_id,
        "compiler_version": compiler_version,
        "compile_policy": "/W4 /WX /Brepro",
        "link_policy": "/Brepro /INCREMENTAL:NO",
    }


def inspect_stub_entrypoints(stub: Path) -> dict[str, int | str]:
    from packer import assemble

    image = assemble._StubImage(stub.read_bytes())
    executable = 0x20000000

    def validate_veneer(rva: int | None, name: str) -> int:
        if rva is None or rva <= 0 or rva % 16:
            raise PromotionError(f"{name} is missing or not 16-byte aligned")
        section = image.section_containing(rva)
        if section is None or not section.characteristics & executable:
            raise PromotionError(f"{name} is outside executable stub code")
        veneer = image.read_at_rva(rva, 5)
        if len(veneer) != 5 or veneer[0] != 0xE9:
            raise PromotionError(f"{name} is not a direct rel32 veneer")
        destination = rva + 5 + struct.unpack_from("<i", veneer, 1)[0]
        target_section = image.section_containing(destination)
        if target_section is None or not target_section.characteristics & executable:
            raise PromotionError(f"{name} veneer destination is not executable")
        return destination

    exe_rva = image.find_export_rva("StubExeEntry")
    dll_rva = image.find_export_rva("StubDllMain")
    exe_target = validate_veneer(exe_rva, "StubExeEntry")
    dll_target = validate_veneer(dll_rva, "StubDllMain")

    tls_rva, tls_size = image.dir(assemble.DIR_TLS)
    if tls_rva <= 0 or tls_size < 40:
        raise PromotionError("stub has no complete TLS anchor directory")
    callbacks_va = struct.unpack_from("<Q", image.read_at_rva(tls_rva, 40), 24)[0]
    if not image.image_base <= callbacks_va < image.image_base + 0x1_0000_0000:
        raise PromotionError("stub TLS callback array VA is outside the image")
    callbacks_rva = callbacks_va - image.image_base
    first_va, terminator = struct.unpack(
        "<QQ", image.read_at_rva(callbacks_rva, 16))
    if not image.image_base <= first_va < image.image_base + 0x1_0000_0000:
        raise PromotionError("stub TLS callback VA is outside the image")
    if terminator != 0:
        raise PromotionError("stub TLS callback array is not singly terminated")
    tls_callback_rva = first_va - image.image_base
    tls_target = validate_veneer(tls_callback_rva, "TLS anchor callback")

    return {
        "artifact_sha256": sha256_file(stub),
        "stub_exe_entry_rva": exe_rva,
        "stub_exe_target_rva": exe_target,
        "stub_dll_entry_rva": dll_rva,
        "stub_dll_target_rva": dll_target,
        "tls_callback_rva": tls_callback_rva,
        "tls_callback_target_rva": tls_target,
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
    cache = (build_dir / "CMakeCache.txt").read_text(
        encoding="utf-8", errors="replace")
    for option, expected in (
        ("DVM_SHUFFLE_OPCODES", "ON"),
        ("DVM_ROLLING", "ON"),
        ("DVM_ROLL_POISON", "OFF"),
    ):
        if re.search(rf"(?m)^{option}:BOOL={expected}\r?$", cache) is None:
            raise PromotionError(
                f"fresh candidate did not configure {option}={expected}")
    return {
        "dvm_shuffle_seed": effective_seed,
        "dvm_opcode_mapping_sha256": mapping_hash,
        "dvm_handler_variant_sha256": handler_hash,
        "dvm_python_map_sha256": sha256_file(python_map),
        "dvm_native_map_sha256": sha256_file(native_map),
        "dvm_rolling": True,
        "dvm_roll_poison": False,
        "dvm_paged_runtime": True,
    }


def _record(path: Path, record: CommandRecord) -> None:
    payload = asdict(record)
    portable_argv: list[str] = []
    root = ROOT.resolve()
    candidate_root = path.resolve().parent.parent

    def portable_path(value: str, *, executable: bool) -> str:
        candidate = Path(value)
        if not candidate.is_absolute():
            return value
        for prefix, base in (("repo://", root), ("candidate://", candidate_root)):
            try:
                relative = candidate.resolve().relative_to(base)
            except (OSError, ValueError):
                continue
            return prefix + relative.as_posix()
        scheme = "tool://" if executable else "external://"
        return scheme + candidate.name

    for index, argument in enumerate(payload["argv"]):
        if "=" in argument:
            prefix, value = argument.split("=", 1)
            normalized = portable_path(value, executable=False)
            argument = prefix + "=" + normalized
        else:
            argument = portable_path(argument, executable=index == 0)
        portable_argv.append(argument)
    payload["argv"] = portable_argv
    atomic_write_json(path, {"schema": 1, **payload})


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


def validate_runtime_hardening_record(
    record: CommandRecord,
    expected_hash: str,
    *,
    minimum_tests: int = 3,
) -> int:
    if record.artifact_sha256 != expected_hash:
        raise PromotionError(
            "runtime-hardening evidence names a different artifact SHA-256")
    if record.exit_code != 0:
        raise PromotionError(
            f"candidate-bound native runtime hardening failed with exit {record.exit_code}")
    if re.search(r"\b\d+ skipped\b", record.stdout):
        raise PromotionError("candidate-bound native runtime hardening skipped tests")
    match = PYTEST_PASSED_RE.search(record.stdout)
    if match is None or int(match.group(1)) < minimum_tests:
        raise PromotionError(
            "candidate-bound native runtime hardening has no complete pass summary")
    return int(match.group(1))


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


def validate_candidate_gate_payload(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Accept a green all-scope gate or only the pinned candidate blockers."""
    if not isinstance(payload, dict):
        raise PromotionError("candidate compatibility result root is malformed")
    if payload.get("schema") != 1 or payload.get("scope") != "all":
        raise PromotionError("candidate compatibility result is malformed or not all-scope")
    ready = payload.get("ready")
    blockers = payload.get("blockers")
    blocker_count = payload.get("blocker_count")
    if type(ready) is not bool or not isinstance(blockers, list):
        raise PromotionError("candidate compatibility readiness/blockers are malformed")

    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, blocker in enumerate(blockers):
        if not isinstance(blocker, dict):
            raise PromotionError(f"candidate blocker[{index}] is malformed")
        blocker_id = blocker.get("id")
        status = blocker.get("status")
        if not isinstance(blocker_id, str) or not isinstance(status, str):
            raise PromotionError(f"candidate blocker[{index}] has no valid id/status")
        if blocker_id in seen:
            raise PromotionError(f"candidate compatibility gate has duplicate blocker: {blocker_id}")
        seen.add(blocker_id)
        expected_status = CANDIDATE_ALLOWED_BLOCKERS.get(blocker_id)
        if status != expected_status:
            raise PromotionError(
                f"production blocker is not candidate-eligible: {blocker_id} [{status}]"
            )
        normalized.append({"id": blocker_id, "status": status})

    if type(blocker_count) is not int or blocker_count != len(blockers):
        raise PromotionError("candidate compatibility blocker count is inconsistent")
    if ready is (len(blockers) != 0):
        raise PromotionError("candidate compatibility ready state is inconsistent")
    return sorted(normalized, key=lambda item: item["id"])


def _toolchain_binding(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "configuration": manifest.get("configuration"),
        "cmake_generator": manifest.get("cmake_generator"),
        "cmake_platform": manifest.get("cmake_platform"),
        "compiler_id": manifest.get("compiler_id"),
        "compiler_version": manifest.get("compiler_version"),
        "warning_policy": manifest.get("warning_policy"),
        "reproducible_link": manifest.get("reproducible_link"),
        "python_version": manifest.get("python_version"),
        "uv_version": manifest.get("uv_version"),
        "cmake_version": manifest.get("cmake_version"),
        "ctest_version": manifest.get("ctest_version"),
        "dependency_locks": manifest.get("dependency_locks"),
    }


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
    gate_payload: dict[str, Any],
) -> dict[str, Any]:
    artifact_hash = sha256_file(staged_stub)
    passed, total = roundtrip_counts
    release_blockers = validate_candidate_gate_payload(gate_payload)
    evidence = []
    for path in evidence_paths:
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(stage_dir.resolve()).as_posix()
        except ValueError as exc:
            raise PromotionError(f"candidate evidence escapes the stage directory: {path}") from exc
        evidence.append({
            "path": relative,
            "sha256": sha256_file(resolved),
        })
    manifest = {
        "schema": 2,
        "artifact_status": "candidate-verified",
        "production_ready": False,
        "candidate_scope": "all",
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
        "provenance_status": "clean",
        "release_gate": {
            "schema": 1,
            "scope": "all",
            "ready": not release_blockers,
            "blocker_count": len(release_blockers),
            "blockers": release_blockers,
        },
        "release_blockers": release_blockers,
        "production_matrix_sha256": sha256_file(PRODUCTION_MATRIX),
        "promotion_tool_sha256": sha256_file(Path(__file__)),
        "candidate_policy_id": CANDIDATE_POLICY_ID,
        "candidate_policy_sha256": candidate_policy_sha256(),
        "evidence": sorted(evidence, key=lambda item: item["path"]),
    }
    manifest["toolchain_binding_sha256"] = _canonical_sha256(
        _toolchain_binding(manifest))
    return manifest


def validate_candidate_bundle(stub: Path, manifest_path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError(f"cannot read staged manifest: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != 2:
        raise PromotionError("staged candidate manifest must use schema 2")
    if manifest.get("artifact_status") != "candidate-verified":
        raise PromotionError("staged manifest is not candidate-verified evidence")
    if manifest.get("production_ready") is not False:
        raise PromotionError("candidate manifest must never claim production readiness")
    if manifest.get("candidate_scope") != "all" or "production_scope" in manifest:
        raise PromotionError("candidate manifest has invalid candidate/production scope")
    if manifest.get("artifact") != stub.name:
        raise PromotionError("staged manifest names a different artifact")
    if manifest.get("size_bytes") != stub.stat().st_size:
        raise PromotionError("staged manifest size does not match the artifact")
    if manifest.get("sha256") != sha256_file(stub):
        raise PromotionError("staged manifest SHA-256 does not match the artifact")
    if manifest.get("source_dirty") is not False or manifest.get("provenance_status") != "clean":
        raise PromotionError("staged manifest is not clean-source candidate evidence")
    if COMMIT_RE.fullmatch(str(manifest.get("source_commit", ""))) is None:
        raise PromotionError("candidate manifest has no full source commit")
    if manifest.get("candidate_policy_id") != CANDIDATE_POLICY_ID:
        raise PromotionError("candidate manifest policy id is unsupported")
    stage_dir = manifest_path.parent.resolve()
    policy_snapshot = stage_dir / "evidence" / "candidate-policy.json"
    matrix_snapshot = stage_dir / "evidence" / "candidate-production-matrix.json"
    promoter_snapshot = stage_dir / "evidence" / "candidate-promoter.py"
    try:
        policy_payload = json.loads(policy_snapshot.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError(f"candidate policy snapshot is invalid: {exc}") from exc
    if (manifest.get("candidate_policy_sha256") != _canonical_sha256(policy_payload)
            or policy_payload != candidate_policy_payload()):
        raise PromotionError("candidate policy snapshot binding is invalid")
    if (not matrix_snapshot.is_file()
            or manifest.get("production_matrix_sha256") != sha256_file(matrix_snapshot)):
        raise PromotionError("candidate matrix snapshot binding is invalid")
    if (not promoter_snapshot.is_file()
            or manifest.get("promotion_tool_sha256") != sha256_file(promoter_snapshot)):
        raise PromotionError("candidate promoter snapshot binding is invalid")
    if manifest.get("toolchain_binding_sha256") != _canonical_sha256(
            _toolchain_binding(manifest)):
        raise PromotionError("candidate manifest toolchain binding is inconsistent")
    if (manifest.get("configuration") != "Release"
            or manifest.get("cmake_generator") != SUPPORTED_GENERATOR
            or str(manifest.get("cmake_platform", "")).lower() != SUPPORTED_PLATFORM
            or manifest.get("compiler_id") != "MSVC"
            or not str(manifest.get("compiler_version", "")).startswith("19.")
            or manifest.get("warning_policy") != "/W4 /WX /Brepro"
            or manifest.get("reproducible_link") != "/Brepro /INCREMENTAL:NO"
            or manifest.get("uv_version") != SUPPORTED_UV
            or not str(manifest.get("python_version", "")).startswith("3.12.")):
        raise PromotionError("candidate manifest toolchain is outside the pinned policy")
    locks = manifest.get("dependency_locks")
    if (not isinstance(locks, dict)
            or set(locks) != set(REQUIRED_LOCKED_FILES)
            or any(SHA256_RE.fullmatch(str(value)) is None for value in locks.values())):
        raise PromotionError("candidate manifest dependency locks are incomplete")
    seed = manifest.get("dvm_shuffle_seed")
    if (not isinstance(seed, str)
            or re.fullmatch(r"[0-9a-f]{64}", seed) is None):
        raise PromotionError(
            "candidate manifest DVM shuffle seed must encode exactly 32 bytes")
    if (manifest.get("dvm_rolling") is not True
            or manifest.get("dvm_roll_poison") is not False
            or manifest.get("dvm_paged_runtime") is not True):
        raise PromotionError(
            "candidate manifest lacks the production DVM rolling/paging policy "
            "with roll poison disabled")
    for field in (
        "dvm_opcode_mapping_sha256",
        "dvm_handler_variant_sha256",
        "dvm_python_map_sha256",
        "dvm_native_map_sha256",
    ):
        if SHA256_RE.fullmatch(str(manifest.get(field, ""))) is None:
            raise PromotionError(f"candidate manifest has no valid {field}")

    release_blockers = validate_candidate_gate_payload(manifest.get("release_gate", {}))
    if manifest.get("release_blockers") != release_blockers:
        raise PromotionError("candidate manifest release blockers disagree with its gate")

    actual = manifest.get("native_roundtrip_actual")
    if (manifest.get("native_roundtrip") != "passed-9-of-9"
            or not isinstance(actual, dict)
            or type(actual.get("passed")) is not int
            or type(actual.get("total")) is not int
            or actual["total"] < 1
            or actual["passed"] != actual["total"]):
        raise PromotionError("candidate manifest has no full native round-trip result")
    ctest = manifest.get("ctest")
    if (not isinstance(ctest, dict)
            or type(ctest.get("passed")) is not int
            or type(ctest.get("total")) is not int
            or ctest["total"] < 1
            or ctest["passed"] != ctest["total"]):
        raise PromotionError("candidate manifest has no full CTest result")

    evidence = manifest.get("evidence")
    if not isinstance(evidence, list):
        raise PromotionError("candidate manifest evidence must be a list")
    seen: set[str] = set()
    for index, record in enumerate(evidence):
        if not isinstance(record, dict):
            raise PromotionError(f"candidate evidence[{index}] is malformed")
        relative = record.get("path")
        expected_hash = record.get("sha256")
        if (not isinstance(relative, str) or not relative
                or SHA256_RE.fullmatch(str(expected_hash)) is None):
            raise PromotionError(f"candidate evidence[{index}] has invalid path/hash")
        if relative in seen:
            raise PromotionError(f"candidate manifest repeats evidence path: {relative}")
        seen.add(relative)
        evidence_path = (stage_dir / relative).resolve()
        try:
            evidence_path.relative_to(stage_dir)
        except ValueError as exc:
            raise PromotionError(f"candidate evidence path escapes the bundle: {relative}") from exc
        if not evidence_path.is_file():
            raise PromotionError(f"candidate evidence is missing: {relative}")
        if sha256_file(evidence_path) != expected_hash:
            raise PromotionError(f"candidate evidence SHA-256 mismatch: {relative}")
    missing = REQUIRED_CANDIDATE_EVIDENCE - seen
    if missing:
        raise PromotionError(
            "candidate manifest omits required evidence: " + ", ".join(sorted(missing))
        )
    unexpected = seen - REQUIRED_CANDIDATE_EVIDENCE
    if unexpected:
        raise PromotionError(
            "candidate manifest contains undeclared evidence: "
            + ", ".join(sorted(unexpected))
        )

    def load_command(
        filename: str,
        name: str,
        *,
        artifact_bound: bool,
        allowed_exit_codes: tuple[int, ...] = (0,),
    ) -> dict[str, Any]:
        command_path = stage_dir / "evidence" / filename
        try:
            payload = json.loads(command_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PromotionError(f"candidate command evidence is invalid: {filename}: {exc}") from exc
        required_keys = {
            "schema", "name", "argv", "exit_code", "stdout", "stderr",
            "source_commit", "artifact_sha256",
        }
        if (not isinstance(payload, dict) or set(payload) != required_keys
                or payload.get("schema") != 1 or payload.get("name") != name
                or not isinstance(payload.get("argv"), list) or not payload["argv"]
                or not all(isinstance(item, str) and item for item in payload["argv"])
                or type(payload.get("exit_code")) is not int
                or payload["exit_code"] not in allowed_exit_codes
                or not isinstance(payload.get("stdout"), str)
                or not isinstance(payload.get("stderr"), str)
                or payload.get("source_commit") != manifest["source_commit"]):
            raise PromotionError(f"candidate command evidence is malformed or red: {filename}")
        expected_artifact = manifest["sha256"] if artifact_bound else None
        if payload.get("artifact_sha256") != expected_artifact:
            raise PromotionError(f"candidate command evidence artifact binding is invalid: {filename}")
        for argument in payload["argv"]:
            raw_value = argument.split("=", 1)[-1]
            if Path(raw_value).is_absolute() or re.search(r"(?i)^[a-z]:[\\/]", raw_value):
                raise PromotionError(f"candidate command evidence is machine-local: {filename}")
        return payload

    command_specs = (
        ("uv-sync.json", "locked-dependency-sync", False),
        ("cmake-configure.json", "fresh-cmake-configure", False),
        ("cmake-build.json", "fresh-w4-wx-stub-build", False),
        ("ctest-inventory.json", "ctest-inventory", True),
        ("ctest.json", "ctest", True),
        ("roundtrip-fixture-build.json", "roundtrip-fixture-build", True),
        ("roundtrip.json", "exe-dll-roundtrip", True),
        ("production-corpus-build.json", "production-corpus-build", True),
        ("production-corpus.json", "production-corpus", True),
    )
    commands = {
        filename: load_command(filename, name, artifact_bound=artifact_bound)
        for filename, name, artifact_bound in command_specs
    }
    configure_argv = commands["cmake-configure.json"]["argv"]
    for expected in release_dvm_configure_args(manifest["dvm_shuffle_seed"]):
        option = expected.split("=", 1)[0] + "="
        matches = [argument for argument in configure_argv if argument.startswith(option)]
        if matches != [expected]:
            raise PromotionError(
                f"candidate configure evidence does not pin {expected}")
    try:
        inventory = json.loads(commands["ctest-inventory.json"]["stdout"])
    except json.JSONDecodeError as exc:
        raise PromotionError("candidate CTest inventory output is invalid") from exc
    if (not isinstance(inventory, dict) or not isinstance(inventory.get("tests"), list)
            or len(inventory["tests"]) != ctest["total"]):
        raise PromotionError("candidate CTest inventory disagrees with its manifest")
    roundtrip_payload = commands["roundtrip.json"]
    roundtrip_record = CommandRecord(
        name=roundtrip_payload["name"], argv=roundtrip_payload["argv"],
        exit_code=roundtrip_payload["exit_code"], stdout=roundtrip_payload["stdout"],
        stderr=roundtrip_payload["stderr"], source_commit=roundtrip_payload["source_commit"],
        artifact_sha256=roundtrip_payload["artifact_sha256"],
    )
    if validate_roundtrip_record(roundtrip_record, manifest["sha256"]) != (
            actual["passed"], actual["total"]):
        raise PromotionError("candidate round-trip evidence disagrees with its manifest")

    entrypoint_path = stage_dir / "evidence" / "stub-entrypoints.json"
    try:
        entrypoint_payload = json.loads(entrypoint_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError(f"candidate entrypoint evidence is invalid: {exc}") from exc
    if entrypoint_payload != {"schema": 1, **inspect_stub_entrypoints(stub)}:
        raise PromotionError("candidate entrypoint evidence disagrees with the artifact")

    native_evidence_path = stage_dir / "evidence" / "production-evidence.json"
    try:
        native_evidence = production_gate.load_evidence(
            native_evidence_path, artifact_path=stub)
        candidate_matrix = production_gate.load_matrix(matrix_snapshot)
        evaluated_gate = production_gate.evaluate(candidate_matrix, "all", native_evidence)
    except production_gate.MatrixError as exc:
        raise PromotionError(f"candidate production evidence is invalid: {exc}") from exc
    if (native_evidence["source_commit"] != manifest["source_commit"]
            or native_evidence["tracked_source_dirty"]
            or native_evidence["ready"] is not True):
        raise PromotionError("candidate production evidence is stale, dirty, or red")
    if validate_candidate_gate_payload(evaluated_gate) != release_blockers:
        raise PromotionError("candidate matrix/evidence evaluation disagrees with its manifest")

    gate_payload = load_command(
        "production-gate.json", "all-scope-production-gate",
        artifact_bound=True, allowed_exit_codes=(0, 1),
    )
    try:
        recorded_gate = json.loads(gate_payload["stdout"])
    except json.JSONDecodeError as exc:
        raise PromotionError("candidate production-gate output is invalid") from exc
    if validate_candidate_gate_payload(recorded_gate) != release_blockers:
        raise PromotionError("candidate production-gate output disagrees with its manifest")
    expected_gate_exit = 0 if recorded_gate.get("ready") is True else 1
    if gate_payload["exit_code"] != expected_gate_exit:
        raise PromotionError("candidate production-gate exit code disagrees with its output")

    runtime_path = stage_dir / "evidence" / "runtime-hardening.json"
    try:
        runtime_payload = json.loads(runtime_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError(f"cannot read runtime-hardening evidence: {exc}") from exc
    if (not isinstance(runtime_payload, dict)
            or runtime_payload.get("schema") != 1
            or runtime_payload.get("name") != "candidate-bound-native-runtime-hardening"
            or runtime_payload.get("source_commit") != manifest["source_commit"]
            or not isinstance(runtime_payload.get("argv"), list)
            or not all(isinstance(item, str) for item in runtime_payload["argv"])
            or type(runtime_payload.get("exit_code")) is not int
            or not isinstance(runtime_payload.get("stdout"), str)
            or not isinstance(runtime_payload.get("stderr"), str)):
        raise PromotionError("runtime-hardening evidence record is malformed")
    if set(runtime_payload) != {
            "schema", "name", "argv", "exit_code", "stdout", "stderr",
            "source_commit", "artifact_sha256"}:
        raise PromotionError("runtime-hardening evidence has unexpected fields")
    expected_runtime_argv = [
        "-m", "pytest", "-q", "-p", "no:cacheprovider",
        *(f"repo://tests/{name}" for name in REQUIRED_NATIVE_RUNTIME_TESTS),
    ]
    if runtime_payload["argv"][1:] != expected_runtime_argv:
        raise PromotionError("runtime-hardening evidence names an unexpected command")
    runtime_record = CommandRecord(
        name=runtime_payload["name"],
        argv=runtime_payload["argv"],
        exit_code=runtime_payload["exit_code"],
        stdout=runtime_payload["stdout"],
        stderr=runtime_payload["stderr"],
        source_commit=runtime_payload["source_commit"],
        artifact_sha256=runtime_payload.get("artifact_sha256"),
    )
    validate_runtime_hardening_record(
        runtime_record, manifest["sha256"],
        minimum_tests=REQUIRED_NATIVE_RUNTIME_PASS_COUNT)
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
    if re.fullmatch(r"[0-9a-f]{64}", shuffle_seed) is None:
        raise PromotionError("--shuffle-seed must encode exactly 32 bytes as 64 hex digits")

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
        env_overrides: Mapping[str, str] | None = None,
    ) -> CommandRecord:
        record = _run(
            argv,
            name=name,
            source_commit=source_commit,
            artifact_sha256=artifact_hash,
            env_overrides=env_overrides,
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
        _promotion_configure_argv(host, build_dir, shuffle_seed),
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
    entrypoint_evidence_path = records_dir / "stub-entrypoints.json"
    atomic_write_json(
        entrypoint_evidence_path,
        {"schema": 1, **inspect_stub_entrypoints(built_stub)},
    )
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

    runtime_hardening = run_recorded(
        [
            host["python"], "-m", "pytest", "-q", "-p", "no:cacheprovider",
            *(ROOT / "tests" / name for name in REQUIRED_NATIVE_RUNTIME_TESTS),
        ],
        name="candidate-bound-native-runtime-hardening",
        path_name="runtime-hardening.json",
        artifact_hash=artifact_hash,
        env_overrides={
            "LETHE_RUN_NATIVE_RUNTIME_STRESS": "1",
            "LETHE_RUN_NATIVE_VM_E2E": "1",
            "LETHE_NATIVE_RUNTIME_STUB_PATH": str(built_stub.resolve()),
        },
    )
    try:
        validate_runtime_hardening_record(
            runtime_hardening, artifact_hash,
            minimum_tests=REQUIRED_NATIVE_RUNTIME_PASS_COUNT)
    except PromotionError as exc:
        failures.append(str(exc))
    _require_unchanged_artifact(
        built_stub, artifact_hash, "candidate-bound native runtime hardening")

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
    gate_payload: dict[str, Any] | None = None
    release_blockers: list[dict[str, str]] = []
    try:
        gate_payload = _load_json_output(gate, "production compatibility gate")
        release_blockers = validate_candidate_gate_payload(gate_payload)
        expected_gate_exit = 0 if gate_payload["ready"] else 1
        if gate.exit_code != expected_gate_exit:
            failures.append(
                "production compatibility gate exit code disagrees with its payload"
            )
    except PromotionError as exc:
        failures.append(str(exc))

    try:
        inspect_repository(ROOT, source_commit)
    except PromotionError as exc:
        failures.append(str(exc))
    _require_unchanged_artifact(built_stub, artifact_hash, "final provenance check")

    result_path = stage_dir / "promotion-result.json"
    if failures:
        atomic_write_json(result_path, {
            "schema": 2,
            "artifact_status": "candidate-rejected",
            "candidate_verified": False,
            "production_ready": False,
            "published": False,
            "source_commit": source_commit,
            "artifact_sha256": artifact_hash,
            "failures": failures,
        })
        raise PromotionError("; ".join(failures))
    if gate_payload is None:
        raise PromotionError("production compatibility gate produced no candidate result")

    staged_stub = stage_dir / PREBUILT.name
    shutil.copyfile(built_stub, staged_stub)
    _require_unchanged_artifact(staged_stub, artifact_hash, "staging copy")
    policy_snapshot = records_dir / "candidate-policy.json"
    matrix_snapshot = records_dir / "candidate-production-matrix.json"
    promoter_snapshot = records_dir / "candidate-promoter.py"
    atomic_write_json(policy_snapshot, candidate_policy_payload())
    shutil.copyfile(PRODUCTION_MATRIX, matrix_snapshot)
    shutil.copyfile(Path(__file__), promoter_snapshot)
    evidence_paths = [path for path, _record_item in records]
    evidence_paths.extend((policy_snapshot, matrix_snapshot, promoter_snapshot))
    evidence_paths.append(entrypoint_evidence_path)
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
        gate_payload=gate_payload,
    )
    staged_manifest = stage_dir / PREBUILT_MANIFEST.name
    atomic_write_json(staged_manifest, manifest)
    try:
        validate_candidate_bundle(staged_stub, staged_manifest)
        inspect_repository(ROOT, source_commit)
        _require_unchanged_artifact(staged_stub, artifact_hash, "bundle validation")
    except (OSError, PromotionError):
        staged_manifest.unlink(missing_ok=True)
        raise

    atomic_write_json(result_path, {
        "schema": 2,
        "artifact_status": "candidate-verified",
        "candidate_verified": True,
        "production_ready": False,
        "published": False,
        "source_commit": source_commit,
        "artifact_sha256": artifact_hash,
        "manifest_sha256": sha256_file(staged_manifest),
        "release_blockers": release_blockers,
    })
    print(f"Locally verified candidate staged at {stage_dir}")
    print(f"Production ready: no ({len(release_blockers)} recorded release blockers)")
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
