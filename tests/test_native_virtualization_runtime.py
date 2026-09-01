"""Opt-in native proof for the selected-function virtualization pipeline."""
from __future__ import annotations

import hashlib
import json
import os
import runpy
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

import pytest

from lifter import direct_control_flow, virtualization_plan, win64_thunk
from packer import assemble, bytecode_pages, orchestrator, pe_analyze, virtualize


ROOT = Path(__file__).resolve().parents[1]
_RUN_GATE = "LETHE_RUN_NATIVE_VM_E2E"
_VIRTUALIZATION_GATE = "LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION"
_SHUFFLE_SEED = "3141592653589793238462643383279502884197169399375105820974944592"
_LEAF_BYTES = bytes.fromhex("b82a000000c3")


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


def _run_checked(command: list[str], *, cwd: Path) -> None:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout


def _build_fixture(work: Path) -> Path:
    source = work / "fixture_source"
    build = work / "fixture_build"
    source.mkdir()
    (source / "fixture.c").write_text(
        """
#include <windows.h>

__declspec(dllexport) __declspec(noinline)
int __cdecl vm_leaf(void)
{
    return 42;
}

__declspec(noreturn) void fixture_entry(void)
{
    static const char output[] = "vm-answer=42\\r\\n";
    DWORD written = 0;
    volatile int answer = vm_leaf();
    if (answer == 42) {
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output,
                  (DWORD)(sizeof(output) - 1u), &written, NULL);
        ExitProcess(0);
    }
    ExitProcess(3);
}
""".lstrip(),
        encoding="ascii",
    )
    (source / "CMakeLists.txt").write_text(
        """
cmake_minimum_required(VERSION 3.20)
project(lethe_native_vm_fixture C)
add_executable(vm_fixture fixture.c)
target_compile_options(vm_fixture PRIVATE /W4 /WX /O2 /GS- /guard:cf-)
target_link_options(vm_fixture PRIVATE
    /INCREMENTAL:NO /FIXED /DYNAMICBASE:NO /NXCOMPAT /HIGHENTROPYVA:NO /CETCOMPAT:NO
    /NODEFAULTLIB /ENTRY:fixture_entry /SUBSYSTEM:CONSOLE)
target_link_libraries(vm_fixture PRIVATE kernel32.lib)
""".lstrip(),
        encoding="ascii",
    )
    _run_checked(
        [
            "cmake", "-S", str(source), "-B", str(build),
            "-G", "Visual Studio 17 2022", "-A", "x64",
        ],
        cwd=work,
    )
    _run_checked(
        ["cmake", "--build", str(build), "--config", "Release"],
        cwd=work,
    )
    executable = build / "Release" / "vm_fixture.exe"
    assert executable.is_file()
    return executable


def _build_stub(work: Path) -> Path:
    build = work / "stub_build"
    _run_checked(
        [
            "cmake", "-S", str(ROOT / "stub"), "-B", str(build),
            "-G", "Visual Studio 17 2022", "-A", "x64",
            f"-DDVM_SHUFFLE_SEED={_SHUFFLE_SEED}",
            "-DDVM_ROLLING=OFF",
            "-DDVM_ROLL_POISON=OFF",
            "-DBUILD_TESTING=OFF",
        ],
        cwd=work,
    )
    _run_checked(
        ["cmake", "--build", str(build), "--config", "Release"],
        cwd=work,
    )
    stub = build / "Release" / "lethe_stub_x64.dll"
    stub_bytes = stub.read_bytes()
    generated = runpy.run_path(str(build / "daedalus_opcodes_shuffled.py"))
    manifest = {
        "schema": 1,
        "artifact": stub.name,
        "size_bytes": len(stub_bytes),
        "sha256": hashlib.sha256(stub_bytes).hexdigest(),
        "dvm_shuffle_seed": _SHUFFLE_SEED,
        "dvm_handler_variant_sha256": generated["HANDLER_VARIANT_SHA256"],
        "dvm_rolling": False,
        "dvm_paged_runtime": True,
    }
    Path(str(stub) + ".manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    return stub


def _run(executable: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(executable)],
        cwd=str(executable.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )


def _slice(parsed: pe_analyze.ParsedPE, rva: int, size: int) -> bytes:
    return pe_analyze._slice_at_rva(
        parsed.sections, rva, size, what="native virtualization proof"
    )


@pytest.mark.skipif(os.name != "nt", reason="native loader is Windows-only")
@pytest.mark.parametrize("memory_guard", [False, True], ids=["eager", "memguard"])
def test_packed_executable_calls_virtualized_leaf(
    monkeypatch, memory_guard: bool
) -> None:
    if os.environ.get(_RUN_GATE) != "1":
        pytest.skip(f"set {_RUN_GATE}=1 to run the native virtualization proof")
    pytest.importorskip("lief")
    pytest.importorskip("iced_x86")
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    root = ROOT.resolve()
    work = Path(tempfile.mkdtemp(prefix=".native_vm_e2e_", dir=root)).resolve()
    if work.parent != root or not work.name.startswith(".native_vm_e2e_"):
        pytest.fail(f"native test directory escaped repository root: {work}")
    try:
        source = _build_fixture(work)
        source_image = assemble._StubImage(source.read_bytes())
        leaf_rva = source_image.find_export_rva("vm_leaf")
        assert leaf_rva is not None
        leaf_window = source_image.read_at_rva(leaf_rva, 16)
        ret_offset = leaf_window.find(b"\xC3")
        assert ret_offset >= 0
        leaf_size = ret_offset + 1
        assert leaf_size == len(_LEAF_BYTES)
        assert leaf_window[:leaf_size] == _LEAF_BYTES
        parsed_source = pe_analyze.analyze_pe(str(source))
        function_spec = virtualization_plan.FunctionSpec(
            "vm_leaf", leaf_rva, leaf_size
        )
        discovery = direct_control_flow.analyze_direct_control_flow(
            parsed_source, (function_spec,), production=False
        )
        assert any(
            transfer.target_rva == leaf_rva
            and transfer.target_is_selected_entry
            for transfer in discovery.direct_transfers
        )
        gap_acknowledgements = tuple(
            orchestrator.VirtualizationGapAcknowledgement(
                gap.rva,
                gap.size,
                "exact native fixture linker/compiler executable gap",
            )
            for gap in discovery.coverage_gaps
        )

        stub = _build_stub(work)
        _stub_bytes, _stub_hash, opcode_table, _handler_hash, rolling = (
            orchestrator._load_virtualization_build(
                str(stub), allow_unverified_stub_for_tests=True)
        )
        assert not opcode_table.is_canonical
        assert rolling is False

        captured = {}
        materialize = virtualize.materialize_selected_functions

        def capture_materialization(*args, **kwargs):
            captured["page_master_key"] = kwargs["page_master_key"]
            result = materialize(*args, **kwargs)
            captured["result"] = result
            return result

        monkeypatch.setattr(
            virtualize, "materialize_selected_functions", capture_materialization
        )
        monkeypatch.setenv(_VIRTUALIZATION_GATE, "1")
        packed = work / "vm_fixture.packed.exe"
        progress: list[str] = []
        result = orchestrator.pack_file(
            str(source),
            orchestrator.PackOptions(
                output_path=str(packed),
                is_dll=False,
                stub_path=str(stub),
                memory_guard=memory_guard,
                virtualization_specs=(
                    orchestrator.VirtualizationSpec(
                        "vm_leaf", leaf_rva, leaf_size
                    ),
                ),
                virtualization_gap_acknowledgements=gap_acknowledgements,
                acknowledge_unproven_indirect_targets=True,
                _allow_unverified_stub_for_tests=True,
            ),
            progress.append,
        )
        assert result.ok, result.error
        assert packed.is_file()
        assert any("virtualized 1 selected function" in line for line in progress)

        materialized = captured["result"]
        function = materialized.manifest.functions[0]
        generated = function.generated_executable_ranges[0]
        entry = _slice(materialized.parsed, leaf_rva, leaf_size)
        assert entry[0] == 0xE9
        entry_displacement, = struct.unpack("<i", entry[1:5])
        assert leaf_rva + 5 + entry_displacement == generated.rva
        assert entry[5:] == b"\xCC" * (leaf_size - 5)

        thunk = _slice(
            materialized.parsed, generated.rva, win64_thunk.THUNK_CODE_SIZE
        )
        assert thunk[5] == 0xE8
        common_displacement, = struct.unpack(
            "<i",
            thunk[
                win64_thunk.THUNK_COMMON_REL32_OFFSET:
                win64_thunk.THUNK_COMMON_REL32_OFFSET + 4
            ],
        )
        common_rva = (
            generated.rva
            + win64_thunk.THUNK_COMMON_REL32_OFFSET
            + 4
            + common_displacement
        )
        assert common_rva == materialized.manifest.runtime_common_rva
        assert common_rva == materialized.stub.runtime_common_rva
        descriptor_va, = struct.unpack(
            "<Q",
            thunk[
                win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET:
                win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET + 8
            ],
        )
        assert descriptor_va == (
            materialized.parsed.image_base + function.descriptor_rva
        )
        descriptor = _slice(materialized.parsed, function.descriptor_rva, 40)
        version, envelope_size, envelope_va, expected_program_id, image_base = struct.unpack(
            "<IIQ16sQ", descriptor
        )
        assert version == virtualization_plan.DESCRIPTOR_VERSION_PAGED
        assert envelope_size == len(function.program)
        assert envelope_va == materialized.parsed.image_base + function.program_rva
        assert expected_program_id == function.program_id
        assert image_base == materialized.parsed.image_base
        envelope = _slice(
            materialized.parsed, function.program_rva, envelope_size
        )
        envelope_view = bytecode_pages.parse_envelope(envelope)
        assert envelope_view.program_id == expected_program_id
        assert bytecode_pages.open_program(
            envelope, captured["page_master_key"]
        )

        original_run = _run(source)
        packed_run = _run(packed)
        assert original_run.returncode == 0
        assert original_run.stdout == b"vm-answer=42\r\n"
        assert original_run.stderr == b""
        assert packed_run.returncode == original_run.returncode
        assert packed_run.stdout == original_run.stdout
        assert packed_run.stderr == original_run.stderr
    finally:
        if (work.parent == root and work.name.startswith(".native_vm_e2e_")
                and work.exists()):
            shutil.rmtree(work)
