"""Real MSVC XFG inventory and generated-thunk fail-closed preflight."""

from __future__ import annotations

import copy
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from packer import assemble, cfg_preservation, container, pe_analyze, virtualize


def _visual_studio_available() -> bool:
    if shutil.which("cl.exe"):
        return True
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return False
    probe = subprocess.run(
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
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _generated_manifest() -> SimpleNamespace:
    return SimpleNamespace(
        functions=(
            SimpleNamespace(
                target_rva=0x1000,
                target_size=0x20,
                cfg_target_rvas=(0x5000,),
                generated_executable_ranges=(
                    SimpleNamespace(rva=0x5000, size=0x40),
                ),
            ),
        )
    )


@pytest.fixture(scope="module")
def real_msvc_xfg_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if os.name != "nt" or not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")
    work = tmp_path_factory.mktemp("real-msvc-xfg")
    source = work / "xfg_fixture.c"
    source.write_text(
        """
typedef int (__cdecl *operation)(int);

__declspec(noinline) static int increment(int value)
{
    return value + 1;
}

int main(void)
{
    volatile operation selected = increment;
    return selected(41) == 42 ? 0 : 1;
}
""".lstrip(),
        encoding="utf-8",
    )
    cmake_source = f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_real_xfg_fixture C)
add_executable(real_xfg "{source.as_posix()}")
target_compile_options(real_xfg PRIVATE /W4 /WX /O2 /guard:xfg)
target_link_options(real_xfg PRIVATE /guard:xfg /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO)
""".lstrip()
    (work / "CMakeLists.txt").write_text(cmake_source, encoding="utf-8")
    build = work / "build"
    configured = subprocess.run(
        [
            "cmake",
            "-S",
            str(work),
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
    output = build / "Release/real_xfg.exe"
    assert output.is_file()
    executed = subprocess.run(
        [str(output)], capture_output=True, text=True, check=False
    )
    assert executed.returncode == 0, executed.stdout + executed.stderr
    return output


def test_real_xfg_global_flag_blocks_generated_thunks_before_output(
    real_msvc_xfg_image: Path,
    tmp_path: Path,
) -> None:
    parsed = pe_analyze.analyze_pe(str(real_msvc_xfg_image))
    assert parsed.load_config is not None
    assert parsed.load_config.guard_flags & 0x00800000
    assert parsed.load_config.xfg_present is True
    assert parsed.load_config.guard_cf_targets
    assert not any(
        target.metadata and target.metadata[0] & 0x08
        for target in parsed.load_config.guard_cf_targets
    )
    plan = cfg_preservation.build_cfg_preservation_plan(
        parsed, _generated_manifest()
    )
    assert plan.generated_thunk_targets
    assert plan.preservation_supported is False
    assert any(
        "generated VM thunk RVAs" in blocker
        and "8-byte XFG function hashes" in blocker
        for blocker in plan.blockers
    )

    before = copy.deepcopy(parsed)
    with pytest.raises(
        virtualize.VirtualizationCfgPreservationError,
        match="generated VM thunk RVAs.*8-byte XFG function hashes",
    ):
        virtualize._commit_manifest(
            parsed,
            _generated_manifest(),
            acknowledge_no_interior_entries=True,
        )
    assert parsed == before

    metadata_size = (parsed.load_config.guard_flags >> 28) & 0xF
    parsed.generated_cfg_targets = (
        pe_analyze.ParsedGuardTarget(0x5000, bytes(metadata_size)),
    )
    output = tmp_path / "must-not-pack.exe"
    with pytest.raises(
        assemble.AssembleError,
        match="generated VM thunk RVAs.*8-byte XFG function hashes",
    ):
        assemble.build_output_pe(
            parsed,
            SimpleNamespace(is_dll=False, flags=container.FLAG_LOAD_CONFIG),
            str(output),
        )
    assert output.exists() is False
