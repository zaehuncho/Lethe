from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _visual_studio_available() -> bool:
    if shutil.which("cl.exe"):
        return True
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return False
    result = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def test_key_scatter_lifetime_is_locked_and_revocation_is_terminal() -> None:
    source = (ROOT / "stub/src/key_scatter.c").read_text(encoding="utf-8")
    header = (ROOT / "stub/src/key_scatter.h").read_text(encoding="utf-8")

    assert "static SRWLOCK       g_key_lock = SRWLOCK_INIT" in source
    assert re.search(
        r"int key_scatter_get\(.*?AcquireSRWLockShared\(&g_key_lock\);"
        r".*?ks_read_locked\(out_key\).*?ReleaseSRWLockShared\(&g_key_lock\);",
        source,
        re.DOTALL,
    )
    assert re.search(
        r"ks_release_ready_locked\(LONG next_state\).*?"
        r"InterlockedExchange\(&g_state, next_state\);.*?ks_free_plain\(local\);",
        source,
        re.DOTALL,
    )
    assert "void key_scatter_invalidate(void);" in header
    assert "KS_STATE_REVOKED" in source
    assert "VirtualLock(page + offset, FRAGMENT_SIZE)" in source
    assert "table[i].locked = 1u" in source
    assert re.search(
        r"ks_zero\(table\[i\]\.page, size\);.*?"
        r"VirtualUnlock\(table\[i\]\.page \+ table\[i\]\.offset, FRAGMENT_SIZE\);"
        r".*?VirtualFree\(table\[i\]\.page, 0, MEM_RELEASE\);",
        source,
        re.DOTALL,
    )


def test_antidebug_revokes_scattered_key_before_exit() -> None:
    source = (ROOT / "stub/src/antidebug.c").read_text(encoding="utf-8")
    wipe = re.search(
        r"static void wipe_master_key\(void\)\s*\{(?P<body>.*?)\n\}",
        source,
        re.DOTALL,
    )
    assert wipe is not None
    assert "key_scatter_invalidate();" in wipe.group("body")


@pytest.mark.skipif(os.name != "nt", reason="the production stub is Windows-only")
def test_native_readers_race_migration_destroy_and_revocation(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake plus the Visual Studio x64 toolchain are required")

    source_dir = ROOT / "stub/src"
    harness = ROOT / "stub/tests/key_scatter_stress_test.c"
    cmake_source = f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_key_scatter_stress C)
set(CMAKE_C_STANDARD 11)
add_executable(key_scatter_stress
    "{harness.as_posix()}"
    "{(source_dir / 'key_scatter.c').as_posix()}"
)
target_include_directories(key_scatter_stress PRIVATE "{source_dir.as_posix()}")
target_compile_definitions(key_scatter_stress PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(key_scatter_stress PRIVATE bcrypt)
if(MSVC)
    target_compile_options(key_scatter_stress PRIVATE /W4 /WX /O2)
endif()
"""
    (tmp_path / "CMakeLists.txt").write_text(cmake_source, encoding="utf-8")
    build = tmp_path / "build"
    configured = subprocess.run(
        [
            "cmake",
            "-S",
            str(tmp_path),
            "-B",
            str(build),
            "-G",
            "Visual Studio 17 2022",
            "-A",
            "x64",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert configured.returncode == 0, configured.stdout + configured.stderr
    compiled = subprocess.run(
        ["cmake", "--build", str(build), "--config", "Release"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    result = subprocess.run(
        [str(build / "Release/key_scatter_stress.exe")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "key scatter concurrency: PASS" in result.stdout
