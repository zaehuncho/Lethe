from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pefile
import pytest

from packer import orchestrator
from tools import handler_shape_audit


_RUN_GATE = "LETHE_RUN_DLL_EXPORT_FILTER_E2E"
_STUB_ENV = "LETHE_NATIVE_RUNTIME_STUB_PATH"
_NAMES = (
    "sample_dll_value",
    "sample_dll_tls_value",
    "sample_dll_tls_alignment_ok",
)
pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="native Windows loader is required")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(executable: Path, *, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(executable)], cwd=str(cwd), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=30, check=False,
    )


def _export_inventory(path: Path) -> tuple[dict[int, int], set[str]]:
    pe = pefile.PE(str(path), fast_load=False)
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        raise AssertionError(f"missing export table: {path}")
    by_ordinal = {}
    names = set()
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        by_ordinal[symbol.ordinal] = symbol.address
        if symbol.name is not None:
            names.add(symbol.name.decode("ascii"))
    return by_ordinal, names


def test_filtered_exports_keep_static_import_contract_and_drop_unlisted_names(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.environ.get(_RUN_GATE) != "1":
        pytest.skip(f"set {_RUN_GATE}=1 for native DLL export-filter acceptance")
    configured = os.environ.get(_STUB_ENV)
    assert configured, f"the enabled gate requires explicit {_STUB_ENV}"
    source_stub = Path(configured).resolve()
    assert source_stub.is_file(), source_stub
    assert shutil.which("cmake"), "CMake is required for the native sample DLL"
    assert handler_shape_audit.find_msvc() is not None, "MSVC x64 is required"

    stub_before = _sha256(source_stub)

    project = Path(__file__).resolve().parents[1]
    sample_build = tmp_path / "samples"
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        pytest.skip("PowerShell is required for tests/build_samples.ps1")
    built = subprocess.run(
        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(project / "tests" / "build_samples.ps1"), "-OutDir", str(sample_build)],
        cwd=str(project), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=240, check=False,
    )
    if built.returncode == 3:
        pytest.skip("build_samples.ps1 found no MSVC x64 toolchain")
    assert built.returncode == 0, built.stdout
    original = sample_build / "sample_dll.dll"
    static_host = sample_build / "static_host.exe"
    assert original.is_file() and static_host.is_file(), built.stdout

    baseline_dir = tmp_path / "baseline"
    baseline_dir.mkdir()
    shutil.copyfile(static_host, baseline_dir / static_host.name)
    shutil.copyfile(original, baseline_dir / "sample_dll.dll")
    baseline = _run(baseline_dir / static_host.name, cwd=baseline_dir)
    assert baseline.returncode == 0, (baseline.stdout, baseline.stderr)
    assert baseline.stderr == b""
    assert baseline.stdout.startswith(b"static_host: PASS")

    monkeypatch.setenv("LETHE_ENABLE_EXPERIMENTAL_DLL", "1")
    packed_dir = tmp_path / "packed"
    packed_dir.mkdir()
    packed = packed_dir / "sample_dll.packed.dll"
    result = orchestrator.pack_file(
        str(original),
        orchestrator.PackOptions(
            output_path=str(packed), is_dll=True, stub_path=str(source_stub),
            dll_export_name_allowlist=_NAMES,
        ),
    )
    assert result.ok, result.error
    assert packed.is_file()
    original_ordinals, original_names = _export_inventory(original)
    packed_ordinals, packed_names = _export_inventory(packed)
    assert packed_names == set(_NAMES)
    assert packed_ordinals == original_ordinals
    dropped = original_names - set(_NAMES)
    packed_bytes = packed.read_bytes()
    assert all(name.encode("ascii") not in packed_bytes for name in dropped)

    filtered_dir = tmp_path / "filtered-static-consumer"
    filtered_dir.mkdir()
    shutil.copyfile(static_host, filtered_dir / static_host.name)
    shutil.copyfile(packed, filtered_dir / "sample_dll.dll")
    filtered = _run(filtered_dir / static_host.name, cwd=filtered_dir)
    assert filtered.returncode == baseline.returncode, (
        baseline.stdout, baseline.stderr, filtered.stdout, filtered.stderr)
    assert filtered.stdout == baseline.stdout
    assert filtered.stderr == b""

    evidence = {
        "baseline": {
            "command": [str(baseline_dir / static_host.name)],
            "exit": baseline.returncode,
            "stdout": baseline.stdout.decode("ascii"),
            "stderr": baseline.stderr.decode("ascii"),
        },
        "packed": {
            "command": [str(filtered_dir / static_host.name)],
            "exit": filtered.returncode,
            "stdout": filtered.stdout.decode("ascii"),
            "stderr": filtered.stderr.decode("ascii"),
            "sha256": _sha256(packed),
            "kept_names": sorted(packed_names),
            "dropped_names_absent_from_raw_image": sorted(dropped),
            "ordinal_addresses_preserved": True,
            "candidate_stub_path": str(source_stub),
            "candidate_stub_sha256": stub_before,
        },
    }
    (tmp_path / "dll-export-filter-e2e.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("DLL_EXPORT_FILTER_E2E=" + json.dumps(evidence, sort_keys=True))
    assert _sha256(source_stub) == stub_before
