"""Real MSVC XFG direct-only virtualization and forged-GFID preflight."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import runpy
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from lifter import direct_control_flow, virtualization_plan
from packer import (
    assemble,
    cfg_preservation,
    container,
    orchestrator,
    pe_analyze,
    virtualize,
)


ROOT = Path(__file__).resolve().parents[1]
_SHUFFLE_SEED = "8f" * 32
_VIRTUALIZATION_GATE = "LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION"


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


def _direct_only_manifest() -> SimpleNamespace:
    return SimpleNamespace(
        functions=(
            SimpleNamespace(
                target_rva=0x1000,
                target_size=0x20,
                cfg_target_rvas=(),
                generated_executable_ranges=(
                    SimpleNamespace(rva=0x5000, size=0x40),
                ),
                capabilities={"direct_only_thunk": True},
            ),
        )
    )


def _forged_generated_gfid_manifest() -> SimpleNamespace:
    manifest = _direct_only_manifest()
    function = manifest.functions[0]
    function.cfg_target_rvas = (0x5000,)
    function.capabilities = {"direct_only_thunk": False}
    return manifest


@pytest.fixture(scope="module")
def real_msvc_xfg_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if os.name != "nt" or not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")
    work = tmp_path_factory.mktemp("real-msvc-xfg")
    source = work / "xfg_fixture.c"
    source.write_text(
        """
typedef int (__cdecl *operation)(int);

__declspec(dllexport) __declspec(noinline) int increment(int value)
{
    return value * 9 + 5;
}

__declspec(dllexport) operation selected = increment;
""".lstrip(),
        encoding="utf-8",
    )
    caller = work / "xfg_caller.c"
    caller.write_text(
        """
typedef int (__cdecl *operation)(int);
extern operation selected;

int main(void)
{
    operation current = selected;
    return current(41) == 374 ? 0 : 1;
}
""".lstrip(),
        encoding="utf-8",
    )
    cmake_source = f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_real_xfg_fixture C)
add_executable(real_xfg "{source.as_posix()}" "{caller.as_posix()}")
target_compile_options(real_xfg PRIVATE /W4 /WX /O2 /guard:cf /guard:xfg)
target_link_options(real_xfg PRIVATE /guard:cf /guard:xfg /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO)
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


@pytest.fixture(scope="module")
def xfg_virtualization_stub(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if os.name != "nt" or not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")
    work = tmp_path_factory.mktemp("real-msvc-xfg-stub")
    build = work / "build"
    configured = subprocess.run(
        [
            "cmake",
            "-S",
            str(ROOT / "stub"),
            "-B",
            str(build),
            "-G",
            "Visual Studio 17 2022",
            "-A",
            "x64",
            f"-DDVM_SHUFFLE_SEED={_SHUFFLE_SEED}",
            "-DDVM_ROLLING=OFF",
            "-DDVM_ROLL_POISON=OFF",
            "-DBUILD_TESTING=OFF",
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
    stub = build / "Release/lethe_stub_x64.dll"
    stub_bytes = stub.read_bytes()
    generated = runpy.run_path(str(build / "daedalus_opcodes_shuffled.py"))
    Path(str(stub) + ".manifest.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "artifact": stub.name,
                "size_bytes": len(stub_bytes),
                "sha256": hashlib.sha256(stub_bytes).hexdigest(),
                "dvm_shuffle_seed": _SHUFFLE_SEED,
                "dvm_handler_variant_sha256": generated[
                    "HANDLER_VARIANT_SHA256"
                ],
                "dvm_rolling": False,
                "dvm_paged_runtime": True,
            },
            sort_keys=True,
        ),
        encoding="ascii",
    )
    return stub


def test_real_xfg_direct_only_plan_preserves_source_gfid_identity(
    real_msvc_xfg_image: Path,
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
        parsed, _direct_only_manifest()
    )
    assert plan.generated_thunk_targets == ()
    assert plan.preservation_supported is True
    assert plan.blockers == ()
    assert plan.retained_source_targets == plan.source_targets
    assert plan.merged_declared_targets == plan.source_targets


def test_real_xfg_forged_generated_gfid_blocks_before_output(
    real_msvc_xfg_image: Path,
    tmp_path: Path,
) -> None:
    parsed = pe_analyze.analyze_pe(str(real_msvc_xfg_image))
    plan = cfg_preservation.build_cfg_preservation_plan(
        parsed, _forged_generated_gfid_manifest()
    )
    assert [target.rva for target in plan.generated_thunk_targets] == [0x5000]
    assert plan.preservation_supported is False
    assert any("8-byte XFG function hashes" in item for item in plan.blockers)

    before = copy.deepcopy(parsed)
    with pytest.raises(
        cfg_preservation.CfgPreservationBlocked,
        match="generated VM thunk RVAs.*8-byte XFG function hashes",
    ):
        cfg_preservation.require_cfg_preservation_supported(
            parsed, _forged_generated_gfid_manifest()
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


def test_real_xfg_selected_function_pack_preserves_indirect_call_parity(
    real_msvc_xfg_image: Path,
    xfg_virtualization_stub: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pytest.importorskip("iced_x86")
    pytest.importorskip("lief")
    source_bytes = real_msvc_xfg_image.read_bytes()
    source_image = assemble._StubImage(source_bytes)
    target_rva = source_image.find_export_rva("increment")
    assert target_rva is not None
    target_window = source_image.read_at_rva(target_rva, 32)
    ret_offset = target_window.find(b"\xC3")
    assert ret_offset >= virtualization_plan.TARGET_ENTRY_PATCH_SIZE
    target_size = ret_offset + 1

    parsed = pe_analyze.analyze_pe(str(real_msvc_xfg_image))
    assert parsed.load_config is not None and parsed.load_config.xfg_present
    source_gfid = next(
        target for target in parsed.load_config.guard_cf_targets
        if target.rva == target_rva
    )
    source_owner = next(
        section for section in parsed.sections
        if section.rva <= target_rva
        and target_rva + target_size <= section.rva + len(section.raw)
    )
    source_owner_raw = source_owner.raw
    source_offset = target_rva - source_owner.rva

    function_spec = virtualization_plan.FunctionSpec(
        "increment", target_rva, target_size
    )
    discovery = direct_control_flow.analyze_direct_control_flow(
        parsed, (function_spec,), production=False
    )
    gap_acknowledgements = tuple(
        orchestrator.VirtualizationGapAcknowledgement(
            gap.rva,
            gap.size,
            "exact real-XFG fixture compiler/linker executable gap",
        )
        for gap in discovery.coverage_gaps
    )

    captured: dict[str, virtualize.MaterializationResult] = {}
    materialize = virtualize.materialize_selected_functions

    def capture_materialization(*args, **kwargs):
        result = materialize(*args, **kwargs)
        captured["result"] = result
        return result

    monkeypatch.setattr(
        virtualize, "materialize_selected_functions", capture_materialization
    )
    monkeypatch.setenv(_VIRTUALIZATION_GATE, "1")
    monkeypatch.setenv("LETHE_ALLOW_UNVERIFIED_STUB_FOR_TESTS", "1")
    packed = tmp_path / "real_xfg.packed.exe"
    result = orchestrator.pack_file(
        str(real_msvc_xfg_image),
        orchestrator.PackOptions(
            output_path=str(packed),
            is_dll=False,
            stub_path=str(xfg_virtualization_stub),
            virtualization_specs=(
                orchestrator.VirtualizationSpec(
                    "increment", target_rva, target_size
                ),
            ),
            virtualization_gap_acknowledgements=gap_acknowledgements,
            acknowledge_unproven_indirect_targets=True,
        ),
    )
    assert result.ok, result.error
    executed = subprocess.run(
        [str(packed)], capture_output=True, text=True, check=False, timeout=30
    )
    assert executed.returncode == 0, executed.stdout + executed.stderr

    materialized = captured["result"]
    function = materialized.manifest.functions[0]
    thunk_rva = function.generated_executable_ranges[0].rva
    assert function.cfg_target_rvas == ()
    assert function.capabilities["direct_only_thunk"] is True
    assert function.capabilities["cfg_target_declared"] is False
    assert function.capabilities["xfg_function_hash_emitted"] is False
    assert materialized.parsed.generated_cfg_targets == ()
    assert materialized.parsed.load_config == parsed.load_config
    materialized_owner = next(
        section for section in materialized.parsed.sections
        if section.name == source_owner.name and section.rva == source_owner.rva
    )
    assert materialized_owner.raw[:source_offset] == source_owner_raw[:source_offset]
    assert materialized_owner.raw[source_offset + target_size:] == (
        source_owner_raw[source_offset + target_size:]
    )
    entry = pe_analyze._slice_at_rva(
        materialized.parsed.sections,
        target_rva,
        target_size,
        what="materialized direct-only entry",
    )
    assert entry[0] == 0xE9
    displacement = int.from_bytes(entry[1:5], "little", signed=True)
    assert target_rva + 5 + displacement == thunk_rva

    preserved_plan = cfg_preservation.build_cfg_preservation_plan(
        materialized.parsed, materialized.manifest
    )
    assert preserved_plan.preservation_supported is True
    assert preserved_plan.generated_thunk_targets == ()
    assert source_gfid in tuple(
        pe_analyze.ParsedGuardTarget(target.rva, target.metadata)
        for target in preserved_plan.merged_declared_targets
    )

    packed_bytes = packed.read_bytes()
    packed_image = assemble._StubImage(packed_bytes)
    load_config_rva, load_config_size = packed_image.dir(
        assemble.DIR_LOAD_CONFIG
    )
    packed_load_config = packed_image.read_at_rva(
        load_config_rva, load_config_size
    )
    table_va = int.from_bytes(packed_load_config[128:136], "little")
    table_count = int.from_bytes(packed_load_config[136:144], "little")
    guard_flags = int.from_bytes(packed_load_config[144:148], "little")
    assert guard_flags & 0x00800000
    metadata_size = (guard_flags >> 28) & 0xF
    stride = 4 + metadata_size
    table_rva = table_va - packed_image.image_base
    table = packed_image.read_at_rva(table_rva, table_count * stride)
    packed_targets = tuple(
        pe_analyze.ParsedGuardTarget(
            int.from_bytes(table[offset:offset + 4], "little"),
            table[offset + 4:offset + stride],
        )
        for offset in range(0, len(table), stride)
    )
    assert any(
        target.rva == source_gfid.rva and target.metadata == source_gfid.metadata
        for target in packed_targets
    )
    assert all(
        target.rva != thunk_rva
        for target in packed_targets
    )
