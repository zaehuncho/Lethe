"""Transactional selected-function virtualization materializer tests."""
from __future__ import annotations

import copy
import dataclasses
import os
import runpy
import shutil
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("lief")

from daedalus import daedalus_ref, daedalus_rolling, shuffle_opcodes  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402
from lifter import virtualization_plan as plan  # noqa: E402
from lifter import win64_thunk  # noqa: E402
from packer import (  # noqa: E402
    assemble,
    bytecode_pages,
    container,
    keyed_validation,
    payload,
    pe_analyze,
    report,
)
from packer import virtualize  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_IMAGE_BASE = 0x140000000
_ROLLING_SEED = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
_PAGE_MASTER_KEY = bytes(range(32))


def _asm(source: str, *, rva: int = 0x1000) -> bytes:
    encoded, _ = _KS.asm(source, addr=rva)
    return bytes(encoded)


def _reloc_blob(*targets: int) -> bytes:
    by_page: dict[int, list[int]] = {}
    for target in sorted(targets):
        by_page.setdefault(target & ~0xFFF, []).append(target & 0xFFF)
    result = bytearray()
    for page, offsets in sorted(by_page.items()):
        entries = [(10 << 12) | offset for offset in offsets]
        if len(entries) & 1:
            entries.append(0)
        result += struct.pack("<II", page, 8 + len(entries) * 2)
        result += struct.pack(f"<{len(entries)}H", *entries)
    return bytes(result)


def _parsed(*, selected_unwind_flags: int = 0) -> tuple[pe_analyze.ParsedPE, bytes]:
    selected = _asm("mov eax, 42; ret")
    retained_rva = 0x1020
    text = bytearray(b"\xCC" * (retained_rva - 0x1000 + 1))
    text[: len(selected)] = selected
    text[-1] = 0xC3
    pdata = b"".join(
        (
            struct.pack("<III", 0x1000, 0x1000 + len(selected), 0x3000),
            struct.pack("<III", retained_rva, retained_rva + 1, 0x3010),
        )
    )
    if selected_unwind_flags:
        selected_unwind = bytes(((selected_unwind_flags << 3) | 1, 0, 0, 0))
        selected_unwind += struct.pack("<I", retained_rva)
    else:
        selected_unwind = b"\x01\x00\x00\x00"
    xdata = selected_unwind.ljust(0x10, b"\x00") + b"\x01\x00\x00\x00"
    reloc = _reloc_blob(0x4000)
    sections = [
        pe_analyze.ParsedSection(
            ".text", 0x1000, len(text), bytes(text), 0x60000020
        ),
        pe_analyze.ParsedSection(
            ".pdata", 0x2000, len(pdata), pdata, 0x40000040
        ),
        pe_analyze.ParsedSection(
            ".xdata", 0x3000, len(xdata), xdata, 0x40000040
        ),
        pe_analyze.ParsedSection(
            ".rdata", 0x4000, 8, struct.pack("<Q", _IMAGE_BASE + 0x1020), 0x40000040
        ),
    ]
    runtime = (
        pe_analyze.ParsedRuntimeFunction(
            0x1000, 0x1000 + len(selected), 0x3000, selected_unwind_flags
        ),
        pe_analyze.ParsedRuntimeFunction(retained_rva, retained_rva + 1, 0x3010, 0),
    )
    return (
        pe_analyze.ParsedPE(
            path="synthetic-no-file.exe",
            is_dll=False,
            image_base=_IMAGE_BASE,
            size_of_image=0x5000,
            oep_rva=0x1000,
            sections=sections,
            imports=[],
            reloc_blob=reloc,
            tls=None,
            pdata_rva=0x2000,
            pdata_count=2,
            rsrc_rva=0,
            file_characteristics=0x22,
            dll_characteristics=0x140,
            dir64_relocations=(pe_analyze.ParsedDir64Relocation(0x4000),),
            runtime_functions=runtime,
        ),
        selected,
    )


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


@pytest.fixture(scope="module", params=[False, True], ids=["plain-stub", "rolling-stub"])
def fresh_stub(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory):
    if os.name != "nt" or not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")
    rolling = bool(request.param)
    build = tmp_path_factory.mktemp(f"virtualize-stub-{'rolling' if rolling else 'plain'}")
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
            f"-DDVM_ROLLING={'ON' if rolling else 'OFF'}",
            "-DDVM_ROLL_POISON=OFF",
            f"-DDVM_SHUFFLE_SEED={'11' * 32}",
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
    generated = runpy.run_path(str(build / "daedalus_opcodes_shuffled.py"))
    table = plan.OpcodeTable.from_mapping(
        generated["SHUFFLED_OPCODES"], identity=f"fresh-{'rolling' if rolling else 'plain'}"
    )
    stub_path = build / "Release/lethe_stub_x64.dll"
    return (
        rolling,
        stub_path,
        stub_path.read_bytes(),
        table,
        generated["HANDLER_VARIANT_SHA256"],
    )


def _slice(parsed: pe_analyze.ParsedPE, rva: int, size: int) -> bytes:
    return pe_analyze._slice_at_rva(parsed.sections, rva, size, what="test artifact")


class _PlainDecoder:
    def __init__(self, code: bytes, optable):
        self.code = code
        self.optable = optable

    def fetch(self, pc: int):
        for _offset, mnemonic, width, kind, operand in daedalus_ref.iter_instructions(
            self.code[pc:], self.optable
        ):
            plain = self.code[pc : pc + 1 + width]
            return mnemonic, width, kind, operand, plain
        raise AssertionError("plain shuffled decoder ran past code")


def _run_program(function: plan.VirtualizedFunction, table: plan.OpcodeTable) -> tuple[int, int]:
    if function.program_format == "paged-v1":
        program = bytecode_pages.open_program(function.program, _PAGE_MASTER_KEY)
        data_size, = struct.unpack_from("<H", program)
        data = program[2 : 2 + data_size]
        code = program[2 + data_size :]
        decoder = _PlainDecoder(code, table.decoder_mapping())
    elif function.program_format == "rolling":
        seed, data, code, leaders = daedalus_rolling.unpack_rolling_blob(function.program)
        decoder = daedalus_rolling.RollingDecoder(
            code, seed, leaders, optable=table.decoder_mapping()
        )
    else:
        data_size, = struct.unpack_from("<H", function.program)
        data = function.program[2 : 2 + data_size]
        code = function.program[2 + data_size :]
        decoder = _PlainDecoder(code, table.decoder_mapping())
    vm = daedalus_ref.RefVM(code, data, decoder=decoder)
    halt = vm.run()
    return halt, int.from_bytes(vm.locals[:8], "little")


def test_fresh_stub_materialization_round_trips_through_keyed_output(
    fresh_stub, tmp_path: Path
) -> None:
    rolling, stub_path, stub_bytes, table, handler_hash = fresh_stub
    parsed, selected = _parsed()
    before = copy.deepcopy(parsed)
    specs = (plan.FunctionSpec("answer", 0x1000, len(selected)),)
    result = virtualize.materialize_selected_functions(
        parsed,
        specs,
        stub_bytes=stub_bytes,
        opcode_table=table,
        expected_handler_variant_sha256=handler_hash,
        page_master_key=_PAGE_MASTER_KEY,
        acknowledge_no_interior_entries=True,
        rolling=False,
        rolling_seed=None,
    )

    assert parsed == before
    assert result.stub.stub_sha256 == __import__("hashlib").sha256(stub_bytes).hexdigest()
    assert result.stub.opcode_mapping_sha256 == table.sha256
    assert result.stub.handler_variant_sha256 == handler_hash
    assert result.manifest.opcode_mapping_sha256 == table.sha256
    assert result.manifest.runtime_common_rva == result.stub.runtime_common_rva
    assert [section.name for section in result.parsed.sections[-2:]] == [".lvtx", ".lvtd"]
    assert result.parsed.size_of_image == 0x7000

    function = result.manifest.functions[0]
    thunk_rva = function.generated_executable_ranges[0].rva
    assert function.cfg_target_rvas == ()
    assert function.capabilities["direct_only_thunk"] is True
    assert result.parsed.generated_cfg_targets == ()
    assert _slice(result.parsed, 0x1000, len(selected)) == function.target_entry_patch.patch
    assert function.target_entry_patch.patch[5:] == b"\xCC" * (len(selected) - 5)
    call_displacement, = struct.unpack(
        "<i",
        _slice(
            result.parsed,
            thunk_rva + win64_thunk.THUNK_COMMON_REL32_OFFSET,
            4,
        ),
    )
    assert thunk_rva + win64_thunk.THUNK_COMMON_REL32_OFFSET + 4 + call_displacement == result.stub.runtime_common_rva
    descriptor_va, = struct.unpack(
        "<Q",
        _slice(
            result.parsed,
            thunk_rva + win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET,
            8,
        ),
    )
    assert descriptor_va == _IMAGE_BASE + function.descriptor_rva
    descriptor = _slice(result.parsed, function.descriptor_rva, 40)
    version, envelope_size, program_va, program_id, image_base = struct.unpack(
        "<IIQ16sQ", descriptor
    )
    assert version == plan.DESCRIPTOR_VERSION_PAGED
    assert envelope_size == len(function.program)
    assert program_va == _IMAGE_BASE + function.program_rva
    assert program_id == function.program_id
    assert image_base == _IMAGE_BASE
    envelope = bytecode_pages.parse_envelope(function.program)
    assert envelope.program_id == program_id
    assert function.capabilities["authenticated_bytecode_paging"] is True
    assert _slice(
        result.parsed,
        result.parsed.pdata_rva,
        result.parsed.pdata_count * 12,
    ) == result.manifest.exception_table.table
    assert result.parsed.runtime_functions[0].begin_rva == 0x1020
    assert result.parsed.runtime_functions[1].begin_rva == thunk_rva
    assert [item.target_rva for item in result.parsed.dir64_relocations] == [
        0x4000,
        thunk_rva + win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET,
        function.descriptor_rva + 8,
        function.descriptor_rva + 32,
    ]
    assert _run_program(function, table) == (0, 42)

    replay = virtualize.materialize_selected_functions(
        before,
        specs,
        stub_bytes=stub_bytes,
        opcode_table=table,
        expected_handler_variant_sha256=handler_hash,
        page_master_key=_PAGE_MASTER_KEY,
        acknowledge_no_interior_entries=True,
    )
    assert replay.manifest.to_json() == result.manifest.to_json()

    options = SimpleNamespace(
        anti_debug=False,
        memory_guard=False,
        compression_level=1,
        server_shard=False,
    )
    artifacts = payload.build_payload(
        result.parsed,
        options,
        master_key=_PAGE_MASTER_KEY,
        paged_vm=True,
    )
    assert artifacts.aes_key == _PAGE_MASTER_KEY
    assert artifacts.flags & container.FLAG_PAGED_DVM
    with pytest.raises(ValueError, match="paged_vm must match"):
        payload.build_payload(result.parsed, options)
    with pytest.raises(ValueError, match="explicit master key"):
        payload.build_payload(result.parsed, options, paged_vm=True)
    assert artifacts.original_size_of_image == result.parsed.size_of_image
    assert (artifacts.pdata_rva, artifacts.pdata_count) == (
        result.parsed.pdata_rva,
        result.parsed.pdata_count,
    )
    output = tmp_path / f"materialized-{'rolling' if rolling else 'plain'}.exe"
    assembly = assemble.build_output_pe(
        result.parsed,
        artifacts,
        str(output),
        input_path=None,
        options=options,
        stub_path=str(stub_path),
        allow_unverified_stub_for_tests=True,
    )
    assert assembly.graft_delta == result.stub.graft_delta
    structural = report.validate_packed(str(output))
    assert structural.ok, structural.summary()
    keyed = keyed_validation.validate_staged_output(
        str(output),
        artifacts,
        expected_stub_text_rva=assembly.stub_text_rva,
        expected_stub_text_size=assembly.stub_text_size,
        structural=structural,
    )
    assert keyed.ok, keyed.summary()


def test_materializer_rejects_missing_or_mismatched_provenance(fresh_stub) -> None:
    _rolling, _stub_path, stub_bytes, table, handler_hash = fresh_stub
    parsed, selected = _parsed()
    specs = (plan.FunctionSpec("answer", 0x1000, len(selected)),)
    common = dict(
        parsed=parsed,
        specs=specs,
        stub_bytes=stub_bytes,
        expected_handler_variant_sha256=handler_hash,
        page_master_key=_PAGE_MASTER_KEY,
        acknowledge_no_interior_entries=True,
    )
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="explicit immutable"):
        virtualize.materialize_selected_functions(**common, opcode_table=None)
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="shuffled"):
        virtualize.materialize_selected_functions(
            **common, opcode_table=plan.OpcodeTable.canonical()
        )
    different = shuffle_opcodes.generate_shuffle(b"different-stub-map".ljust(32, b"!"))
    wrong_mapping = {
        mnemonic: (
            wire,
            plan.daedalus_asm.OPCODES[mnemonic][1],
            plan.daedalus_asm.OPCODES[mnemonic][2],
        )
        for mnemonic, wire in different["real_map"].items()
    }
    wrong_table = plan.OpcodeTable.from_mapping(wrong_mapping, identity="wrong")
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="does not match"):
        virtualize.materialize_selected_functions(**common, opcode_table=wrong_table)
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="handler variants do not match",
    ):
        virtualize.materialize_selected_functions(
            **{**common, "expected_handler_variant_sha256": "00" * 32},
            opcode_table=table,
        )
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="provenance"):
        virtualize.materialize_selected_functions(
            **{**common, "stub_bytes": b"MZ"}, opcode_table=table
        )


def test_apply_is_atomic_and_rejects_stale_source_or_missing_acknowledgement(
    fresh_stub,
) -> None:
    rolling, _stub_path, stub_bytes, table, handler_hash = fresh_stub
    parsed, selected = _parsed()
    result = virtualize.materialize_selected_functions(
        parsed,
        (plan.FunctionSpec("answer", 0x1000, len(selected)),),
        stub_bytes=stub_bytes,
        opcode_table=table,
        expected_handler_variant_sha256=handler_hash,
        page_master_key=_PAGE_MASTER_KEY,
        acknowledge_no_interior_entries=True,
    )
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="acknowledgement"):
        virtualize.apply_virtualization_manifest(parsed, result.manifest)

    stale = copy.deepcopy(parsed)
    changed = bytearray(stale.sections[0].raw)
    changed[0] ^= 1
    stale.sections[0].raw = bytes(changed)
    stale_before = copy.deepcopy(stale)
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="changed after"):
        virtualize.apply_virtualization_manifest(
            stale,
            result.manifest,
            acknowledge_no_interior_entries=True,
        )
    assert stale == stale_before

    bad_inventory = copy.deepcopy(parsed)
    bad_inventory.dir64_relocations = ()
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="inventory"):
        virtualize.apply_virtualization_manifest(
            bad_inventory,
            result.manifest,
            acknowledge_no_interior_entries=True,
        )


def test_materializer_rejects_unsupported_selected_exception_record(fresh_stub) -> None:
    _rolling, _stub_path, stub_bytes, table, handler_hash = fresh_stub
    parsed, selected = _parsed(selected_unwind_flags=plan.UNW_FLAG_EHANDLER)
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="unsupported unwind flags"):
        virtualize.materialize_selected_functions(
            parsed,
            (plan.FunctionSpec("answer", 0x1000, len(selected)),),
            stub_bytes=stub_bytes,
            opcode_table=table,
            expected_handler_variant_sha256=handler_hash,
            page_master_key=_PAGE_MASTER_KEY,
            acknowledge_no_interior_entries=True,
        )


def test_descriptor_program_identity_mismatch_is_rejected(fresh_stub) -> None:
    _rolling, _stub_path, stub_bytes, table, handler_hash = fresh_stub
    parsed, selected = _parsed()
    result = virtualize.materialize_selected_functions(
        parsed,
        (plan.FunctionSpec("answer", 0x1000, len(selected)),),
        stub_bytes=stub_bytes,
        opcode_table=table,
        expected_handler_variant_sha256=handler_hash,
        page_master_key=_PAGE_MASTER_KEY,
        acknowledge_no_interior_entries=True,
    )
    function = result.manifest.functions[0]
    forged_id = bytes([function.program_id[0] ^ 1]) + function.program_id[1:]
    version, size, pointer, _program_id, image_base = struct.unpack(
        "<IIQ16sQ", function.descriptor_data
    )
    forged = dataclasses.replace(
        function,
        program_id=forged_id,
        descriptor_data=struct.pack(
            "<IIQ16sQ", version, size, pointer, forged_id, image_base
        ),
    )
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="descriptor/envelope identity mismatch",
    ):
        virtualize._validate_function_artifacts(forged, result.manifest)

    for rejected_descriptor in (
        struct.pack("<IIQ16sQ", 2, size, pointer, _program_id, image_base),
        struct.pack("<IIQ16sQ", version, size + 1, pointer, _program_id, image_base),
        struct.pack("<IIQ16sQ", version, size, pointer, _program_id, 1),
    ):
        with pytest.raises(
            virtualize.VirtualizationMaterializationError,
            match="paged descriptor ABI is invalid",
        ):
            virtualize._validate_function_artifacts(
                dataclasses.replace(
                    function, descriptor_data=rejected_descriptor
                ),
                result.manifest,
            )


def test_plain_descriptor_legacy_size_and_image_base_fail_closed() -> None:
    selected = _asm("mov eax, 42; ret")
    manifest = plan.compile_virtualization_manifest(
        (plan.FunctionSpec("answer", 0x1000, len(selected)),),
        plan.SectionImage(
            (
                plan.SectionBytes(
                    ".text", 0x1000, len(selected), selected, 0x60000020
                ),
            )
        ),
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
    )
    function = manifest.functions[0]
    version, size, pointer, image_base = struct.unpack(
        "<IIQQ", function.descriptor_data
    )
    assert (version, pointer, image_base) == (
        plan.DESCRIPTOR_VERSION_PLAIN,
        0,
        0,
    )

    for rejected_descriptor in (
        struct.pack("<IIQQ", 1, size, pointer, image_base),
        struct.pack("<IIQQ", version, size + 1, pointer, image_base),
        struct.pack("<IIQQ", version, size, pointer, 1),
    ):
        with pytest.raises(
            virtualize.VirtualizationMaterializationError,
            match="descriptor ABI is invalid",
        ):
            virtualize._validate_function_artifacts(
                dataclasses.replace(
                    function, descriptor_data=rejected_descriptor
                ),
                manifest,
            )


def test_direct_only_thunk_rejects_generated_cfg_identity(
    fresh_stub,
) -> None:
    _rolling, _stub_path, stub_bytes, table, handler_hash = fresh_stub
    parsed, selected = _parsed()
    result = virtualize.materialize_selected_functions(
        parsed,
        (plan.FunctionSpec("answer", 0x1000, len(selected)),),
        stub_bytes=stub_bytes,
        opcode_table=table,
        expected_handler_variant_sha256=handler_hash,
        page_master_key=_PAGE_MASTER_KEY,
        acknowledge_no_interior_entries=True,
    )
    function = result.manifest.functions[0]
    thunk_rva = function.generated_executable_ranges[0].rva

    forged_function = dataclasses.replace(
        function,
        cfg_target_rvas=(thunk_rva,),
        capabilities={
            **function.capabilities,
            "cfg_target_declared": True,
        },
    )
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="direct-only CFG/XFG contract",
    ):
        virtualize._validate_function_artifacts(
            forged_function, result.manifest
        )

    forged_source = copy.deepcopy(parsed)
    forged_source.generated_cfg_targets = (
        pe_analyze.ParsedGuardTarget(thunk_rva, b""),
    )
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="direct-only thunk appears in generated CFG inventory",
    ):
        virtualize.apply_virtualization_manifest(
            forged_source,
            result.manifest,
            acknowledge_no_interior_entries=True,
        )

    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="unsupported virtualization manifest version 1",
    ):
        virtualize.apply_virtualization_manifest(
            parsed,
            dataclasses.replace(result.manifest, version=1),
            acknowledge_no_interior_entries=True,
        )
