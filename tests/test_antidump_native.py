"""Native fault injection for anti-dump protection transitions."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tools import handler_shape_audit


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name != "nt", reason="the production stub is Windows-only")
def test_native_antidump_protection_faults_fail_closed(tmp_path: Path) -> None:
    if not shutil.which("cmake") or handler_shape_audit.find_msvc() is None:
        pytest.skip("CMake plus the Visual Studio x64 toolchain are required")

    source = ROOT / "stub/src/antidump.c"
    harness = ROOT / "stub/tests/antidump_fault_test.c"
    include = ROOT / "stub/src"
    (tmp_path / "CMakeLists.txt").write_text(
        f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_antidump_fault_test C)
add_library(antidump_production OBJECT "{source.as_posix()}")
target_include_directories(antidump_production PRIVATE "{include.as_posix()}")
target_compile_definitions(antidump_production PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
add_executable(antidump_fault
    "{harness.as_posix()}"
    "{source.as_posix()}"
)
target_include_directories(antidump_fault PRIVATE "{include.as_posix()}")
target_compile_definitions(antidump_fault PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    LETHE_ANTIDUMP_TEST_HOOKS
)
if(MSVC)
    target_compile_options(antidump_production PRIVATE /W4 /WX /O2)
    target_compile_options(antidump_fault PRIVATE /W4 /WX /O2)
endif()
""".lstrip(),
        encoding="utf-8",
    )
    build = tmp_path / "build"
    configured = subprocess.run(
        [
            "cmake", "-S", str(tmp_path), "-B", str(build),
            "-G", "Visual Studio 17 2022", "-A", "x64",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert configured.returncode == 0, configured.stdout + configured.stderr
    compiled = subprocess.run(
        ["cmake", "--build", str(build), "--config", "Release"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    ran = subprocess.run(
        [str(build / "Release/antidump_fault.exe")],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert "anti-dump fault injection: PASS" in ran.stdout
