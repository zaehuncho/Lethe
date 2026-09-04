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
_DLL_GATE = "LETHE_ENABLE_EXPERIMENTAL_DLL"
_STUB_PATH_ENV = "LETHE_NATIVE_RUNTIME_STUB_PATH"


def _xfg_callsite_hashes(
    body: bytes,
    *,
    ip: int,
    dispatch_slot_va: int,
) -> tuple[bytes, ...]:
    """Pair each R10 type hash with its XFG dispatch-slot indirect call."""
    from iced_x86 import Decoder, Mnemonic, OpKind, Register

    pending: bytes | None = None
    hashes: list[bytes] = []
    for instruction in Decoder(64, body, ip=ip):
        if (
            instruction.mnemonic == Mnemonic.MOV
            and instruction.op0_kind == OpKind.REGISTER
            and instruction.op0_register == Register.R10
            and instruction.op1_kind == OpKind.IMMEDIATE64
        ):
            pending = instruction.immediate64.to_bytes(8, "little")
        elif (
            instruction.mnemonic == Mnemonic.CALL
            and instruction.op0_kind == OpKind.MEMORY
            and instruction.memory_displacement == dispatch_slot_va
        ):
            assert pending is not None, "XFG dispatch call has no paired R10 type hash"
            hashes.append(pending)
            pending = None
    return tuple(hashes)


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
def real_msvc_xfg_dll_bundle(
    tmp_path_factory: pytest.TempPathFactory,
) -> SimpleNamespace:
    if os.name != "nt" or not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")
    work = tmp_path_factory.mktemp("real-msvc-xfg-dll")
    dll_source = work / "xfg_dll.c"
    dll_source.write_text(
        """
__declspec(dllexport) __declspec(noinline) int __cdecl xfg_i32(int value)
{
    return value * 9 + 5;
}

__declspec(dllexport) __declspec(noinline) unsigned __int64 __cdecl xfg_u64(
    unsigned __int64 left,
    unsigned __int64 right)
{
    return ((left << 3) + left) ^ (right + 0x102030405060708ui64);
}

__declspec(dllexport) __declspec(noinline) int __cdecl xfg_i32x3(
    int first,
    int second,
    int third)
{
    return ((first + second) ^ third) + 23;
}

__declspec(dllexport) __declspec(noinline) unsigned __int64 __cdecl xfg_noargs(void)
{
    return 0x123456789ABCDEF0ui64;
}

__declspec(dllexport) __declspec(noinline) unsigned __int64 __cdecl xfg_u64x6(
    unsigned __int64 first,
    unsigned __int64 second,
    unsigned __int64 third,
    unsigned __int64 fourth,
    unsigned __int64 fifth,
    unsigned __int64 sixth)
{
    return (((first + second) ^ third) + fourth) ^ (fifth + sixth);
}

__declspec(dllexport) __declspec(noinline) unsigned int __cdecl xfg_ptr_read(
    const unsigned int *values,
    unsigned int salt)
{
    return values[0] + (values[1] ^ salt);
}

__declspec(dllexport) __declspec(noinline) void __cdecl xfg_ptr_write(
    unsigned __int64 *destination,
    unsigned __int64 value)
{
    *destination = value ^ 0x0F1E2D3C4B5A6978ui64;
}

typedef int (__cdecl *xfg_i32_fn)(int);
typedef unsigned __int64 (__cdecl *xfg_u64_fn)(unsigned __int64, unsigned __int64);
typedef int (__cdecl *xfg_i32x3_fn)(int, int, int);
typedef unsigned __int64 (__cdecl *xfg_noargs_fn)(void);
typedef unsigned __int64 (__cdecl *xfg_u64x6_fn)(
    unsigned __int64,
    unsigned __int64,
    unsigned __int64,
    unsigned __int64,
    unsigned __int64,
    unsigned __int64);
typedef unsigned int (__cdecl *xfg_ptr_read_fn)(const unsigned int *, unsigned int);
typedef void (__cdecl *xfg_ptr_write_fn)(unsigned __int64 *, unsigned __int64);

__declspec(dllexport) xfg_i32_fn volatile selected_xfg_i32 = xfg_i32;
__declspec(dllexport) xfg_u64_fn volatile selected_xfg_u64 = xfg_u64;
__declspec(dllexport) xfg_i32x3_fn volatile selected_xfg_i32x3 = xfg_i32x3;
__declspec(dllexport) xfg_noargs_fn volatile selected_xfg_noargs = xfg_noargs;
__declspec(dllexport) xfg_u64x6_fn volatile selected_xfg_u64x6 = xfg_u64x6;
__declspec(dllexport) xfg_ptr_read_fn volatile selected_xfg_ptr_read = xfg_ptr_read;
__declspec(dllexport) xfg_ptr_write_fn volatile selected_xfg_ptr_write = xfg_ptr_write;

__declspec(dllexport) __declspec(noinline) int __cdecl xfg_run_all(void)
{
    const unsigned int input[2] = { 13u, 29u };
    unsigned __int64 written = 0;
    int ok = selected_xfg_i32(41) == 374;
    ok = ok && selected_xfg_u64(
        0x1122334455667788ui64,
        0x8877665544332211ui64)
        == (((0x1122334455667788ui64 << 3) + 0x1122334455667788ui64)
            ^ (0x8877665544332211ui64 + 0x102030405060708ui64));
    ok = ok && selected_xfg_i32x3(19, 37, 11)
        == (((19 + 37) ^ 11) + 23);
    ok = ok && selected_xfg_noargs() == 0x123456789ABCDEF0ui64;
    ok = ok && selected_xfg_u64x6(3, 5, 7, 11, 13, 17)
        == ((((3ui64 + 5ui64) ^ 7ui64) + 11ui64) ^ (13ui64 + 17ui64));
    ok = ok && selected_xfg_ptr_read(input, 0x55AAu)
        == (13u + (29u ^ 0x55AAu));
    selected_xfg_ptr_write(&written, 0x8877665544332211ui64);
    ok = ok && written
        == (0x8877665544332211ui64 ^ 0x0F1E2D3C4B5A6978ui64);
    return ok;
}
""".lstrip(),
        encoding="utf-8",
    )
    host_source = work / "xfg_dll_host.c"
    host_source.write_text(
        """
#include <windows.h>

typedef int (__cdecl *xfg_i32_fn)(int);
typedef unsigned __int64 (__cdecl *xfg_u64_fn)(unsigned __int64, unsigned __int64);
typedef int (__cdecl *xfg_i32x3_fn)(int, int, int);
typedef unsigned __int64 (__cdecl *xfg_noargs_fn)(void);
typedef unsigned __int64 (__cdecl *xfg_u64x6_fn)(
    unsigned __int64,
    unsigned __int64,
    unsigned __int64,
    unsigned __int64,
    unsigned __int64,
    unsigned __int64);
typedef unsigned int (__cdecl *xfg_ptr_read_fn)(const unsigned int *, unsigned int);
typedef void (__cdecl *xfg_ptr_write_fn)(unsigned __int64 *, unsigned __int64);
typedef int (__cdecl *xfg_run_all_fn)(void);

static int run_once(const char *path)
{
    HMODULE module = LoadLibraryA(path);
    xfg_i32_fn i32;
    xfg_u64_fn u64;
    xfg_i32x3_fn i32x3;
    xfg_noargs_fn noargs;
    xfg_u64x6_fn u64x6;
    xfg_ptr_read_fn ptr_read;
    xfg_ptr_write_fn ptr_write;
    xfg_run_all_fn run_all;
    const unsigned int input[2] = { 13u, 29u };
    unsigned __int64 written = 0;
    int ok;
    if (module == NULL) {
        return 10;
    }
    i32 = (xfg_i32_fn)GetProcAddress(module, "xfg_i32");
    u64 = (xfg_u64_fn)GetProcAddress(module, "xfg_u64");
    i32x3 = (xfg_i32x3_fn)GetProcAddress(module, "xfg_i32x3");
    noargs = (xfg_noargs_fn)GetProcAddress(module, "xfg_noargs");
    u64x6 = (xfg_u64x6_fn)GetProcAddress(module, "xfg_u64x6");
    ptr_read = (xfg_ptr_read_fn)GetProcAddress(module, "xfg_ptr_read");
    ptr_write = (xfg_ptr_write_fn)GetProcAddress(module, "xfg_ptr_write");
    run_all = (xfg_run_all_fn)GetProcAddress(module, "xfg_run_all");
    if (i32 == NULL || u64 == NULL || i32x3 == NULL || noargs == NULL ||
        u64x6 == NULL || ptr_read == NULL || ptr_write == NULL ||
        run_all == NULL) {
        FreeLibrary(module);
        return 11;
    }
    ok = i32(41) == 374;
    ok = ok && u64(0x1122334455667788ui64, 0x8877665544332211ui64)
        == (((0x1122334455667788ui64 << 3) + 0x1122334455667788ui64)
            ^ (0x8877665544332211ui64 + 0x102030405060708ui64));
    ok = ok && i32x3(19, 37, 11) == (((19 + 37) ^ 11) + 23);
    ok = ok && noargs() == 0x123456789ABCDEF0ui64;
    ok = ok && u64x6(3, 5, 7, 11, 13, 17)
        == ((((3ui64 + 5ui64) ^ 7ui64) + 11ui64) ^ (13ui64 + 17ui64));
    ok = ok && ptr_read(input, 0x55AAu) == (13u + (29u ^ 0x55AAu));
    ptr_write(&written, 0x8877665544332211ui64);
    ok = ok && written
        == (0x8877665544332211ui64 ^ 0x0F1E2D3C4B5A6978ui64);
    ok = ok && run_all() == 1;
    if (!FreeLibrary(module)) {
        return 12;
    }
    return ok ? 0 : 13;
}

int main(int argc, char **argv)
{
    int cycle;
    if (argc != 2) {
        return 2;
    }
    for (cycle = 0; cycle < 3; ++cycle) {
        int result = run_once(argv[1]);
        if (result != 0) {
            return result;
        }
    }
    return 0;
}
""".lstrip(),
        encoding="utf-8",
    )
    cmake_source = f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_real_xfg_dll_fixture C)
add_library(real_xfg_dll SHARED "{dll_source.as_posix()}")
target_compile_options(real_xfg_dll PRIVATE /W4 /WX /O2 /guard:cf /guard:xfg)
target_link_options(real_xfg_dll PRIVATE /guard:cf /guard:xfg /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO)
add_executable(real_xfg_dll_host "{host_source.as_posix()}")
target_compile_options(real_xfg_dll_host PRIVATE /W4 /WX /O2 /guard:cf /guard:xfg)
target_link_options(real_xfg_dll_host PRIVATE /guard:cf /guard:xfg /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO)
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
    dll = build / "Release/real_xfg_dll.dll"
    host = build / "Release/real_xfg_dll_host.exe"
    assert dll.is_file() and host.is_file()
    executed = subprocess.run(
        [str(host), str(dll)], capture_output=True, text=True, check=False
    )
    assert executed.returncode == 0, executed.stdout + executed.stderr
    return SimpleNamespace(dll=dll, host=host)


@pytest.fixture(scope="module")
def xfg_virtualization_stub(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if os.name != "nt" or not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")
    work = tmp_path_factory.mktemp("real-msvc-xfg-stub")
    configured_stub = os.environ.get(_STUB_PATH_ENV)
    if configured_stub:
        source_stub = Path(configured_stub).resolve()
        assert source_stub.is_file(), (
            f"{_STUB_PATH_ENV} does not name a file: {source_stub}"
        )
        build = source_stub.parent.parent
        cache = (build / "CMakeCache.txt").read_text(
            encoding="utf-8", errors="replace"
        )
        assert "DVM_ROLLING:BOOL=ON" in cache
        assert "DVM_ROLL_POISON:BOOL=OFF" in cache
        generated = runpy.run_path(str(build / "daedalus_opcodes_shuffled.py"))
        stub = work / source_stub.name
        shutil.copyfile(source_stub, stub)
        shuffle_seed = generated["BUILD_SEED"]
        rolling = True
    else:
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
                "-DDVM_ROLLING=ON",
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
        generated = runpy.run_path(str(build / "daedalus_opcodes_shuffled.py"))
        shuffle_seed = _SHUFFLE_SEED
        rolling = True
    stub_bytes = stub.read_bytes()
    Path(str(stub) + ".manifest.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "artifact": stub.name,
                "size_bytes": len(stub_bytes),
                "sha256": hashlib.sha256(stub_bytes).hexdigest(),
                "dvm_shuffle_seed": shuffle_seed,
                "dvm_handler_variant_sha256": generated[
                    "HANDLER_VARIANT_SHA256"
                ],
                "dvm_rolling": rolling,
                "dvm_roll_poison": False,
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
            _allow_unverified_stub_for_tests=True,
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


def test_real_xfg_dll_selected_signatures_preserve_indirect_call_parity(
    real_msvc_xfg_dll_bundle: SimpleNamespace,
    xfg_virtualization_stub: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pytest.importorskip("iced_x86")
    pytest.importorskip("lief")
    dll = real_msvc_xfg_dll_bundle.dll
    host = real_msvc_xfg_dll_bundle.host
    source_image = assemble._StubImage(dll.read_bytes())
    names = (
        "xfg_i32",
        "xfg_u64",
        "xfg_i32x3",
        "xfg_noargs",
        "xfg_u64x6",
        "xfg_ptr_read",
        "xfg_ptr_write",
    )
    specs: list[virtualization_plan.FunctionSpec] = []
    for name in names:
        target_rva = source_image.find_export_rva(name)
        assert target_rva is not None
        ret_offset = source_image.read_at_rva(target_rva, 64).find(b"\xC3")
        assert ret_offset >= virtualization_plan.TARGET_ENTRY_PATCH_SIZE
        specs.append(
            virtualization_plan.FunctionSpec(name, target_rva, ret_offset + 1)
        )
    parsed = pe_analyze.analyze_pe(str(dll))
    assert parsed.is_dll is True
    assert parsed.load_config is not None
    assert parsed.load_config.guard_flags & 0x00800000
    assert parsed.load_config.xfg_present is True
    run_all_rva = source_image.find_export_rva("xfg_run_all")
    assert run_all_rva is not None
    run_all_runtime = next(
        runtime
        for runtime in parsed.runtime_functions
        if runtime.begin_rva == run_all_rva
    )
    run_all_size = run_all_runtime.end_rva - run_all_runtime.begin_rva
    dispatch_slot_va = (
        parsed.image_base
        + parsed.load_config.guard_xfg_dispatch_function_pointer_rva
    )
    source_callsite_hashes = _xfg_callsite_hashes(
        source_image.read_at_rva(run_all_rva, run_all_size),
        ip=parsed.image_base + run_all_rva,
        dispatch_slot_va=dispatch_slot_va,
    )
    assert len(source_callsite_hashes) == len(specs)
    assert all(value != bytes(8) for value in source_callsite_hashes)
    assert len(set(source_callsite_hashes)) == len(specs)
    source_gfids = {
        target.rva: target
        for target in parsed.load_config.guard_cf_targets
        if target.rva in {spec.rva for spec in specs}
    }
    assert set(source_gfids) == {spec.rva for spec in specs}

    discovery = direct_control_flow.analyze_direct_control_flow(
        parsed, tuple(specs), production=False
    )
    gap_acknowledgements = tuple(
        orchestrator.VirtualizationGapAcknowledgement(
            gap.rva,
            gap.size,
            "exact real-XFG DLL fixture compiler/linker executable gap",
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
    monkeypatch.setenv(_DLL_GATE, "1")
    packed = tmp_path / "real_xfg_dll.packed.dll"
    result = orchestrator.pack_file(
        str(dll),
        orchestrator.PackOptions(
            output_path=str(packed),
            is_dll=True,
            stub_path=str(xfg_virtualization_stub),
            virtualization_specs=tuple(
                orchestrator.VirtualizationSpec(
                    spec.name, spec.rva, spec.size
                )
                for spec in specs
            ),
            virtualization_gap_acknowledgements=gap_acknowledgements,
            acknowledge_unproven_indirect_targets=True,
            _allow_unverified_stub_for_tests=True,
        ),
    )
    assert result.ok, result.error
    executed = subprocess.run(
        [str(host), str(packed)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert executed.returncode == 0, executed.stdout + executed.stderr

    materialized = captured["result"]
    assert materialized.parsed.load_config == parsed.load_config
    assert materialized.parsed.generated_cfg_targets == ()
    assert len(materialized.manifest.functions) == len(specs)
    thunk_rvas: set[int] = set()
    functions_by_name = {
        function.name: function
        for function in materialized.manifest.functions
    }
    assert set(functions_by_name) == set(names)
    for spec in specs:
        function = functions_by_name[spec.name]
        assert function.target_rva == spec.rva
        assert function.cfg_target_rvas == ()
        assert function.capabilities["direct_only_thunk"] is True
        assert function.capabilities["cfg_target_declared"] is False
        assert function.capabilities["xfg_function_hash_emitted"] is False
        assert function.capabilities["stack_arguments_supported"] is True
        assert function.capabilities["xmm_state_supported"] is False
        thunk_rva = function.generated_executable_ranges[0].rva
        thunk_rvas.add(thunk_rva)
        entry = pe_analyze._slice_at_rva(
            materialized.parsed.sections,
            spec.rva,
            spec.size,
            what=f"materialized direct-only DLL entry {spec.name}",
        )
        assert entry[0] == 0xE9
        displacement = int.from_bytes(entry[1:5], "little", signed=True)
        assert spec.rva + 5 + displacement == thunk_rva
    materialized_callsite_hashes = _xfg_callsite_hashes(
        pe_analyze._slice_at_rva(
            materialized.parsed.sections,
            run_all_rva,
            run_all_size,
            what="materialized XFG call-site hash body",
        ),
        ip=materialized.parsed.image_base + run_all_rva,
        dispatch_slot_va=(
            materialized.parsed.image_base
            + materialized.parsed.load_config.guard_xfg_dispatch_function_pointer_rva
        ),
    )
    assert materialized_callsite_hashes == source_callsite_hashes

    preserved_plan = cfg_preservation.build_cfg_preservation_plan(
        materialized.parsed, materialized.manifest
    )
    assert preserved_plan.preservation_supported is True
    assert preserved_plan.generated_thunk_targets == ()
    merged = {
        target.rva: target.metadata for target in preserved_plan.merged_declared_targets
    }
    for target_rva, source_gfid in source_gfids.items():
        assert merged[target_rva] == source_gfid.metadata
    assert thunk_rvas.isdisjoint(merged)

    packed_image = assemble._StubImage(packed.read_bytes())
    load_config_rva, load_config_size = packed_image.dir(assemble.DIR_LOAD_CONFIG)
    packed_load_config = packed_image.read_at_rva(load_config_rva, load_config_size)
    table_va = int.from_bytes(packed_load_config[128:136], "little")
    table_count = int.from_bytes(packed_load_config[136:144], "little")
    guard_flags = int.from_bytes(packed_load_config[144:148], "little")
    assert guard_flags & 0x00800000
    metadata_size = (guard_flags >> 28) & 0xF
    stride = 4 + metadata_size
    table = packed_image.read_at_rva(
        table_va - packed_image.image_base, table_count * stride
    )
    packed_targets = {
        int.from_bytes(table[offset:offset + 4], "little"):
            table[offset + 4:offset + stride]
        for offset in range(0, len(table), stride)
    }
    for target_rva, source_gfid in source_gfids.items():
        assert packed_targets[target_rva] == source_gfid.metadata
    assert thunk_rvas.isdisjoint(packed_targets)
