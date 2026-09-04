"""Strict builder-side selected-function virtualization planning contracts."""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")

import virtualization_plan as plan  # noqa: E402
import win64_thunk  # noqa: E402
import daedalus_asm  # noqa: E402
import daedalus_ref  # noqa: E402
import daedalus_rolling  # noqa: E402
import shuffle_opcodes  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_EXEC = 0x60000020


def _asm(source: str, *, rva: int = 0x1000) -> bytes:
    encoded, _ = _KS.asm(source, addr=rva)
    return bytes(encoded)


def _rip_instruction(source: str, *, rva: int, target_rva: int) -> bytes:
    probe = _asm(source.format(mem="[rip]"), rva=rva)
    displacement = target_rva - (rva + len(probe))
    sign = "+" if displacement >= 0 else "-"
    return _asm(
        source.format(mem=f"[rip {sign} 0x{abs(displacement):X}]"),
        rva=rva,
    )


def _image(
    raw: bytes,
    *,
    rva: int = 0x1000,
    virtual_size: int | None = None,
    characteristics: int = _EXEC,
) -> plan.SectionImage:
    return plan.SectionImage(
        [
            plan.SectionBytes(
                ".text",
                rva,
                len(raw) if virtual_size is None else virtual_size,
                raw,
                characteristics,
            )
        ]
    )


def _leaf(*, rva: int = 0x1000) -> bytes:
    return _asm("mov eax, 1; ret", rva=rva)


def _opcode_table(seed: bytes, identity: str) -> tuple[plan.OpcodeTable, str]:
    generated = shuffle_opcodes.generate_shuffle(seed)
    shuffled = generated["real_map"]
    mapping = {
        mnemonic: (
            wire,
            daedalus_asm.OPCODES[mnemonic][1],
            daedalus_asm.OPCODES[mnemonic][2],
        )
        for mnemonic, wire in shuffled.items()
    }
    return (
        plan.OpcodeTable.from_mapping(mapping, identity=identity),
        generated["mapping_sha256"],
    )


def _compile(
    raw: bytes,
    *,
    name: str = "choose_value",
    rva: int = 0x1000,
    size: int | None = None,
    reader=None,
    rolling: bool = False,
    seed: bytes | None = None,
) -> plan.VirtualizationManifest:
    return plan.compile_virtualization_manifest(
        [plan.FunctionSpec(name, rva, len(raw) if size is None else size)],
        reader or _image(raw, rva=rva),
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
        rolling=rolling,
        rolling_seed=seed,
    )


def test_valid_local_branch_leaf_emits_complete_manifest() -> None:
    raw = _asm(
        "cmp rcx, rdx; je equal; mov rax, rcx; ret; "
        "equal: mov rax, rdx; ret"
    )
    manifest = _compile(raw)
    function = manifest.functions[0]

    assert manifest.version == plan.MANIFEST_VERSION == 2
    assert function.target_rva == 0x1000
    assert function.target_size == len(raw)
    assert function.original_sha256 == hashlib.sha256(raw).hexdigest()
    assert function.target_entry_patch.patch[:5] == (
        b"\xE9" + struct.pack("<i", 0x5000 - 0x1005)
    )
    assert len(function.target_entry_patch.patch) == len(raw)
    assert function.target_entry_patch.patch[5:] == b"\xCC" * (len(raw) - 5)
    assert function.target_entry_patch.tombstone_policy == (
        plan.TARGET_TOMBSTONE_POLICY
    )
    assert function.target_entry_patch.destination_rva == 0x5000
    assert function.target_entry_patch.external_entry_assumption == (
        plan.EXTERNAL_ENTRY_ASSUMPTION
    )
    assert manifest.opcode_mapping_identity == "canonical"
    assert manifest.opcode_mapping_sha256 == plan.OpcodeTable.canonical().sha256
    assert function.program_format == "plain"
    assert function.program_sha256 == hashlib.sha256(function.program).hexdigest()
    assert struct.unpack("<IIQQ", function.descriptor_data) == (
        plan.DESCRIPTOR_VERSION_PLAIN,
        len(function.program),
        0,
        0,
    )
    assert function.thunk_symbol in function.thunk_asm
    assert function.descriptor_symbol in function.thunk_asm
    assert function.thunk_template == win64_thunk.THUNK_TEMPLATE
    assert len(function.thunk_template) == win64_thunk.THUNK_CODE_SIZE
    assert function.thunk_sha256 == hashlib.sha256(
        function.thunk_template
    ).hexdigest()
    assert function.thunk_template[
        win64_thunk.THUNK_COMMON_REL32_OFFSET :
        win64_thunk.THUNK_COMMON_REL32_OFFSET + 4
    ] == b"\0" * 4
    assert function.thunk_template[
        win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET :
        win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET + 8
    ] == b"\0" * 8

    generated = function.generated_executable_ranges[0]
    assert generated.rva == 0x5000
    assert generated.size == win64_thunk.THUNK_CODE_SIZE
    assert function.cfg_target_rvas == ()
    assert function.unwind.unwind_info == win64_thunk.THUNK_UNWIND_INFO
    assert struct.unpack("<III", function.unwind.runtime_function) == (
        generated.rva,
        generated.rva + generated.size,
        function.unwind.unwind_info_rva,
    )
    assert function.unwind.runtime_function_rva == (
        manifest.exception_table.generated[0].record_rva
    )
    assert manifest.exception_table.table == function.unwind.runtime_function
    assert manifest.exception_table.output_table_rva >= manifest.generated_data_rva
    assert (
        manifest.exception_table.output_table_rva
        + manifest.exception_table.output_table_size
        <= manifest.generated_data_rva + manifest.generated_data_size
    )

    relocations = function.required_relocations
    assert [(entry.kind, entry.patch_rva) for entry in relocations] == [
        ("REL32", generated.rva + win64_thunk.THUNK_COMMON_REL32_OFFSET),
        ("DIR64", generated.rva + win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET),
        ("DIR64", function.descriptor_rva + 8),
        ("DIR64", function.descriptor_rva + 16),
    ]
    assert relocations[0].target_symbol == "daedalus_x64_enter_common"
    assert relocations[1].target_rva == function.descriptor_rva
    assert relocations[2].target_rva == function.program_rva
    assert relocations[3].target_rva == 0
    assert relocations[3].add_image_base is True
    assert function.capabilities == {
        "cet_shadow_stack_balanced": True,
        "cfg_target_declared": False,
        "direct_only_thunk": True,
        "exception_handlers_supported": False,
        "external_calls_supported": False,
        "external_interior_entries_supported": False,
        "direct_internal_calls_supported": True,
        "leaf_only": True,
        "nonvolatile_registers_preserved": True,
        "stack_arguments_supported": True,
        "target_entry_rel32_patch_emitted": True,
        "unwind_info_emitted": True,
        "unwind_materialized_and_registered": False,
        "whole_function_only": True,
        "xfg_function_hash_emitted": False,
        "xmm_register_state_captured": True,
        "xmm_register_moves_and_xor_supported": True,
        "simd_fp_arithmetic_supported": False,
        "return_address_shadow_validated": False,
        "rip_relative_data_addressing_supported": True,
    }
    assert function.internal_call_rvas == ()
    assert function.max_internal_call_depth == 0
    assert manifest.to_json() == manifest.to_json()


def test_direct_internal_calls_are_reported_with_proven_depth() -> None:
    raw = _asm(
        "jmp entry; inner: add rax, rdx; ret; "
        "outer: call inner; xor rax, r8; ret; "
        "entry: call outer; add rax, r9; ret"
    )
    manifest = _compile(raw)
    function = manifest.functions[0]

    assert len(function.internal_call_rvas) == 2
    assert function.max_internal_call_depth == 2
    assert function.capabilities["direct_internal_calls_supported"] is True
    assert function.capabilities["return_address_shadow_validated"] is True
    assert function.capabilities["leaf_only"] is False
    serialized = manifest.to_dict()["functions"][0]
    assert serialized["internal_call_rvas"] == list(function.internal_call_rvas)
    assert serialized["max_internal_call_depth"] == 2


def test_manifest_is_input_order_independent_and_rolling_deterministic() -> None:
    first = _asm("mov rax, rcx; nop; ret", rva=0x1000)
    second_rva = 0x1100
    second = _asm("add rcx, rdx; mov rax, rcx; ret", rva=second_rva)
    raw = first + b"\x90" * (second_rva - 0x1000 - len(first)) + second
    reader = _image(raw, virtual_size=len(raw))
    specs = [
        plan.FunctionSpec("first", 0x1000, len(first)),
        plan.FunctionSpec("second", second_rva, len(second)),
    ]
    kwargs = dict(
        reader=reader,
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
        rolling=True,
        rolling_seed=bytes.fromhex("00112233445566778899aabbccddeeff"),
    )
    forward = plan.compile_virtualization_manifest(specs, **kwargs)
    reverse = plan.compile_virtualization_manifest(list(reversed(specs)), **kwargs)

    assert forward.to_json() == reverse.to_json()
    assert [entry.target_rva for entry in forward.functions] == [0x1000, 0x1100]
    assert all(entry.program_format == "rolling" for entry in forward.functions)
    assert forward.functions[0].program != forward.functions[1].program
    assert forward.functions[1].generated_executable_ranges[0].rva % 16 == 0
    assert forward.functions[1].program_rva % 16 == 0


def test_parsed_section_adapter_reads_only_explicit_records() -> None:
    raw = _leaf()
    parsed = SimpleNamespace(
        name=".text",
        rva=0x1000,
        virtual_size=len(raw),
        raw=raw,
        characteristics=_EXEC,
    )
    reader = plan.SectionImage.from_parsed_sections([parsed])
    assert _compile(raw, reader=reader).functions[0].target_size == len(raw)


@pytest.mark.parametrize(
    ("specs", "message"),
    [
        ([], "at least one explicit function"),
        ([plan.FunctionSpec("", 0x1000, 1)], "function name"),
        ([plan.FunctionSpec("bad", 0, 1)], "invalid RVA range"),
        ([plan.FunctionSpec("bad", 0x1000, 0)], "invalid RVA range"),
        ([plan.FunctionSpec("bad", 0xFFFFFFF0, 0x20)], "invalid RVA range"),
        ([plan.FunctionSpec("tiny", 0x1000, 4)], "too small for a five-byte"),
        (
            [
                plan.FunctionSpec("one", 0x1000, 8),
                plan.FunctionSpec("two", 0x1004, 8),
            ],
            "overlap",
        ),
    ],
)
def test_spec_boundaries_reject(specs, message: str) -> None:
    with pytest.raises(plan.VirtualizationPlanError, match=message):
        plan.compile_virtualization_manifest(
            specs,
            _image(b"\xC3" * 32),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
        )


def test_section_reader_rejects_nonexec_virtual_tail_crossing_and_overlap() -> None:
    raw = _leaf()
    with pytest.raises(plan.FunctionRejected, match="not executable"):
        _compile(raw, reader=_image(raw, characteristics=0x40000040))
    with pytest.raises(plan.FunctionRejected, match="non-file-backed"):
        _compile(
            raw + b"\x90",
            size=len(raw) + 1,
            reader=_image(raw, virtual_size=len(raw) + 0x100),
        )
    with pytest.raises(plan.FunctionRejected, match="not wholly in one section"):
        _compile(raw, rva=0x0FFF, reader=_image(raw, rva=0x1000))
    with pytest.raises(plan.VirtualizationPlanError, match="sections .* overlap"):
        plan.SectionImage(
            [
                plan.SectionBytes("a", 0x1000, 0x20, b"\x90" * 0x20, _EXEC),
                plan.SectionBytes("b", 0x1010, 0x20, b"\x90" * 0x20, _EXEC),
            ]
        )


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"\x48\xB8\x01\x02\x03", "invalid instruction"),
        (b"\x90" * 5, "must end in a plain RET"),
        (b"\x90\x90\xC2\x08\x00", "must end in a plain RET"),
        (b"\xEB\x01\x48\x89\xC8\xC3", "not an instruction boundary"),
        (_asm("jne 0x2000; ret"), "not an instruction boundary"),
        (_asm("nop; nop; call rax; ret"), "whole-function lift rejected"),
    ],
)
def test_decode_and_whole_function_boundaries_reject(raw: bytes, message: str) -> None:
    with pytest.raises(plan.FunctionRejected, match=message):
        _compile(raw)


def test_strict_reader_cannot_return_partial_or_extra_bytes() -> None:
    raw = _leaf()

    class Truncated:
        def read_file_backed_executable(self, rva: int, size: int) -> bytes:
            return raw[:-1]

    class Extra:
        def read_file_backed_executable(self, rva: int, size: int) -> bytes:
            return raw + b"\x90"

    for reader in (Truncated(), Extra()):
        with pytest.raises(plan.FunctionRejected, match="strict reader returned"):
            _compile(raw, reader=reader)


def test_any_rejected_function_aborts_the_entire_plan() -> None:
    valid = _asm("mov rax, rcx; nop; ret", rva=0x1000)
    bad_rva = 0x1100
    bad = _asm("nop; nop; call rax; ret", rva=bad_rva)
    raw = valid + b"\x90" * (bad_rva - 0x1000 - len(valid)) + bad
    specs = [
        plan.FunctionSpec("valid", 0x1000, len(valid)),
        plan.FunctionSpec("unsupported", bad_rva, len(bad)),
    ]
    with pytest.raises(plan.FunctionRejected, match="unsupported"):
        plan.compile_virtualization_manifest(
            specs,
            _image(raw),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
        )


@pytest.mark.parametrize(
    ("rolling", "seed", "message"),
    [
        (True, None, "requires a deterministic 16-byte seed"),
        (True, b"short", "requires a deterministic 16-byte seed"),
        (False, b"0" * 16, "only valid when rolling=True"),
    ],
)
def test_rolling_configuration_is_never_random(
    rolling: bool, seed: bytes | None, message: str
) -> None:
    raw = _leaf()
    with pytest.raises(plan.VirtualizationPlanError, match=message):
        _compile(raw, rolling=rolling, seed=seed)


def test_generated_layout_rejects_misalignment_overlap_and_rva_overflow() -> None:
    raw = _leaf()
    spec = [plan.FunctionSpec("leaf", 0x1000, len(raw))]
    reader = _image(raw)
    for text_rva, data_rva, message in [
        (0x5001, 0x7000, "16-byte aligned"),
        (0x5000, 0x5000, "reservations overlap"),
    ]:
        with pytest.raises(plan.VirtualizationPlanError, match=message):
            plan.compile_virtualization_manifest(
                spec,
                reader,
                generated_text_rva=text_rva,
                generated_data_rva=data_rva,
            )
    high_rva = 0xFFFFF000
    with pytest.raises(plan.VirtualizationPlanError, match="generated text output"):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("high_leaf", high_rva, len(raw))],
            _image(raw, rva=high_rva),
            generated_text_rva=0xFFFFFFF0,
            generated_data_rva=0x7000,
        )


def test_generated_layout_cannot_overwrite_selected_source_range() -> None:
    raw = _leaf()
    with pytest.raises(plan.VirtualizationPlanError, match="overlaps generated text"):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("leaf", 0x1000, len(raw))],
            _image(raw),
            generated_text_rva=0x1000,
            generated_data_rva=0x7000,
        )


def test_entry_patch_rejects_target_outside_signed_rel32_reach() -> None:
    raw = _leaf()
    with pytest.raises(plan.VirtualizationPlanError, match="signed rel32 range"):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("leaf", 0x1000, len(raw))],
            _image(raw),
            generated_text_rva=0x90000000,
            generated_data_rva=0x7000,
        )


def test_source_dir64_relocations_are_explicit_recorded_and_rejected_in_body() -> None:
    raw = _leaf()
    checked = (
        plan.SourceDir64Relocation(0x3000),
        plan.SourceDir64Relocation(0x2000),
    )
    manifest = plan.compile_virtualization_manifest(
        [plan.FunctionSpec("leaf", 0x1000, len(raw))],
        _image(raw),
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
        source_dir64_relocations=checked,
        require_source_relocation_metadata=True,
    )
    assert manifest.source_relocation_metadata_complete
    assert [
        relocation.target_rva
        for relocation in manifest.checked_source_dir64_relocations
    ] == [0x2000, 0x3000]

    with pytest.raises(plan.FunctionRejected, match="DIR64.*overlaps"):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("leaf", 0x1000, len(raw))],
            _image(raw),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_dir64_relocations=(plan.SourceDir64Relocation(0x0FFC),),
            require_source_relocation_metadata=True,
        )

    with pytest.raises(plan.VirtualizationPlanError, match="requires explicit source DIR64"):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("leaf", 0x1000, len(raw))],
            _image(raw),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            require_source_relocation_metadata=True,
        )


def test_exception_table_plan_removes_selected_and_merges_retained_generated() -> None:
    raw = _asm(
        "cmp rcx, rdx; je equal; mov rax, rcx; ret; "
        "equal: mov rax, rdx; ret"
    )
    source = plan.SourceExceptionMetadata(
        0xA000,
        (
            plan.SourceRuntimeFunction(0x0800, 0x0900, 0x6000),
            plan.SourceRuntimeFunction(0x1000, 0x1000 + len(raw), 0x6010),
            plan.SourceRuntimeFunction(
                0x2000,
                0x2010,
                0x6020,
                plan.UNW_FLAG_EHANDLER,
            ),
        ),
    )
    manifest = plan.compile_virtualization_manifest(
        [plan.FunctionSpec("selected", 0x1000, len(raw))],
        _image(raw),
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
        source_exception_metadata=source,
        require_source_exception_metadata=True,
    )
    exception = manifest.exception_table

    assert manifest.source_exception_metadata_complete
    assert exception.source_table_rva == 0xA000
    assert exception.source_table_size == 3 * 12
    assert [record.begin_rva for record in exception.retained] == [0x0800, 0x2000]
    assert len(exception.removed) == 1
    assert exception.removed[0].begin_rva == 0x1000
    assert exception.removed[0].source_record_rva == 0xA000 + 12
    assert exception.removed[0].record_rva is None
    assert len(exception.generated) == 1
    assert exception.generated[0].begin_rva == 0x5000
    assert [record.begin_rva for record in exception.merged] == [
        0x0800,
        0x2000,
        0x5000,
    ]
    assert [record.record_rva for record in exception.merged] == [
        exception.output_table_rva + index * 12 for index in range(3)
    ]
    assert exception.table == b"".join(
        record.packed for record in exception.merged
    )
    assert manifest.functions[0].unwind.runtime_function_rva == (
        exception.generated[0].record_rva
    )


@pytest.mark.parametrize(
    "flags",
    [
        plan.UNW_FLAG_EHANDLER,
        plan.UNW_FLAG_UHANDLER,
        plan.UNW_FLAG_CHAININFO,
        plan.UNW_FLAG_EHANDLER | plan.UNW_FLAG_UHANDLER,
    ],
)
def test_selected_function_rejects_unsupported_source_unwind_flags(
    flags: int,
) -> None:
    raw = _leaf()
    source = plan.SourceExceptionMetadata(
        0xA000,
        (
            plan.SourceRuntimeFunction(
                0x1000, 0x1000 + len(raw), 0x6000, flags
            ),
        ),
    )
    with pytest.raises(plan.FunctionRejected, match="unsupported unwind flags"):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("leaf", 0x1000, len(raw))],
            _image(raw),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=source,
        )


def test_source_exception_ranges_reject_partial_unsorted_and_overlap() -> None:
    raw = _leaf()
    spec = [plan.FunctionSpec("leaf", 0x1000, len(raw))]
    kwargs = dict(
        specs=spec,
        reader=_image(raw),
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
    )
    with pytest.raises(plan.FunctionRejected, match="partially matches"):
        plan.compile_virtualization_manifest(
            **kwargs,
            source_exception_metadata=plan.SourceExceptionMetadata(
                0xA000,
                (
                    plan.SourceRuntimeFunction(
                        0x1000, 0x1000 + len(raw) + 1, 0x6000
                    ),
                ),
            ),
        )
    with pytest.raises(plan.VirtualizationPlanError, match="not sorted"):
        plan.compile_virtualization_manifest(
            **kwargs,
            source_exception_metadata=plan.SourceExceptionMetadata(
                0xA000,
                (
                    plan.SourceRuntimeFunction(0x2000, 0x2010, 0x6000),
                    plan.SourceRuntimeFunction(0x0800, 0x0900, 0x6010),
                ),
            ),
        )
    with pytest.raises(plan.VirtualizationPlanError, match="ranges overlap"):
        plan.compile_virtualization_manifest(
            **kwargs,
            source_exception_metadata=plan.SourceExceptionMetadata(
                0xA000,
                (
                    plan.SourceRuntimeFunction(0x0800, 0x0900, 0x6000),
                    plan.SourceRuntimeFunction(0x0880, 0x0980, 0x6010),
                ),
            ),
        )
    with pytest.raises(plan.VirtualizationPlanError, match="immutable tuple"):
        plan.SourceExceptionMetadata(0xA000, [])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        (
            plan.SourceExceptionMetadata(
                0xA002,
                (plan.SourceRuntimeFunction(0x2000, 0x2010, 0x6000),),
            ),
            "table RVA must be four-byte aligned",
        ),
        (
            plan.SourceExceptionMetadata(
                0xA000,
                (plan.SourceRuntimeFunction(0x2000, 0x2010, 0x6001),),
            ),
            "unwind-info RVA must be four-byte aligned",
        ),
        (
            plan.SourceExceptionMetadata(
                0xA000,
                (plan.SourceRuntimeFunction(0x2000, 0x2010, 0x6000, 8),),
            ),
            "invalid unwind flags",
        ),
        (
            plan.SourceExceptionMetadata(0xA000, ()),
            "empty source exception table must use RVA zero",
        ),
    ],
)
def test_source_exception_metadata_rejects_malformed_amd64_records(
    metadata: plan.SourceExceptionMetadata, message: str
) -> None:
    raw = _leaf()
    with pytest.raises(plan.VirtualizationPlanError, match=message):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("leaf", 0x1000, len(raw))],
            _image(raw),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=metadata,
        )


def test_generated_runtime_function_cannot_overlap_retained_source_range() -> None:
    raw = _leaf()
    with pytest.raises(
        plan.VirtualizationPlanError,
        match="retained and generated runtime-function ranges overlap",
    ):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("leaf", 0x1000, len(raw))],
            _image(raw),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=plan.SourceExceptionMetadata(
                0xA000,
                (plan.SourceRuntimeFunction(0x4FF0, 0x5100, 0x6000),),
            ),
        )


def test_per_build_opcode_maps_change_wire_bytes_but_execute_equivalently() -> None:
    raw = _asm("mov eax, 42; ret")
    builds = (
        _opcode_table(b"A" * 32, "build-a"),
        _opcode_table(b"B" * 32, "build-b"),
    )
    before = dict(daedalus_asm.OPCODES)
    manifests = []
    for table, stub_hash in builds:
        manifests.append(
            plan.compile_virtualization_manifest(
                [plan.FunctionSpec("answer", 0x1000, len(raw))],
                _image(raw),
                generated_text_rva=0x5000,
                generated_data_rva=0x7000,
                rolling=True,
                rolling_seed=bytes.fromhex(
                    "00112233445566778899aabbccddeeff"
                ),
                opcode_table=table,
                require_shuffled_opcodes=True,
                expected_opcode_mapping_sha256=stub_hash,
                source_dir64_relocations=(),
                runtime_common_rva=0x9000,
                source_exception_metadata=plan.SourceExceptionMetadata(0, ()),
            )
        )

    assert daedalus_asm.OPCODES == before
    assert manifests[0].functions[0].program != manifests[1].functions[0].program
    assert [manifest.opcode_mapping_identity for manifest in manifests] == [
        "build-a",
        "build-b",
    ]
    assert all(
        manifest.functions[0].required_relocations[0].target_rva == 0x9000
        for manifest in manifests
    )

    results = []
    for manifest, (table, _stub_hash) in zip(manifests, builds):
        seed, data, code, leaders = daedalus_rolling.unpack_rolling_blob(
            manifest.functions[0].program
        )
        decoder = daedalus_rolling.RollingDecoder(
            code, seed, leaders, optable=table.decoder_mapping()
        )
        vm = daedalus_ref.RefVM(code, data, decoder=decoder)
        halt_status = vm.run()
        results.append(
            (halt_status, int.from_bytes(vm.locals[0:8], "little"))
        )
    assert results == [(0, 42), (0, 42)]


def test_shuffled_production_mapping_is_mandatory_and_hash_checked() -> None:
    raw = _leaf()
    table, stub_hash = _opcode_table(b"C" * 32, "build-c")
    common = dict(
        specs=[plan.FunctionSpec("leaf", 0x1000, len(raw))],
        reader=_image(raw),
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
        require_shuffled_opcodes=True,
        source_dir64_relocations=(),
        runtime_common_rva=0x9000,
        source_exception_metadata=plan.SourceExceptionMetadata(0, ()),
    )
    with pytest.raises(plan.VirtualizationPlanError, match="explicit non-canonical"):
        plan.compile_virtualization_manifest(**common)
    with pytest.raises(plan.VirtualizationPlanError, match="explicit non-canonical"):
        plan.compile_virtualization_manifest(
            **common, opcode_table=plan.OpcodeTable.canonical()
        )
    with pytest.raises(plan.VirtualizationPlanError, match="does not match"):
        plan.compile_virtualization_manifest(
            **common,
            opcode_table=table,
            expected_opcode_mapping_sha256="00" * 32,
        )
    with pytest.raises(plan.VirtualizationPlanError, match="SHA-256 extracted"):
        plan.compile_virtualization_manifest(
            **common,
            opcode_table=table,
        )
    with pytest.raises(plan.VirtualizationPlanError, match="requires explicit source DIR64"):
        plan.compile_virtualization_manifest(
            **{key: value for key, value in common.items()
               if key != "source_dir64_relocations"},
            opcode_table=table,
            expected_opcode_mapping_sha256=stub_hash,
        )
    with pytest.raises(plan.VirtualizationPlanError, match="numeric runtime common RVA"):
        plan.compile_virtualization_manifest(
            **{key: value for key, value in common.items()
               if key != "runtime_common_rva"},
            opcode_table=table,
            expected_opcode_mapping_sha256=stub_hash,
        )
    with pytest.raises(plan.VirtualizationPlanError, match="source exception metadata"):
        plan.compile_virtualization_manifest(
            **{key: value for key, value in common.items()
               if key != "source_exception_metadata"},
            opcode_table=table,
            expected_opcode_mapping_sha256=stub_hash,
        )


@pytest.mark.parametrize("rolling", [False, True], ids=["plain", "rolling"])
def test_rip_data_reference_is_serialized_for_plain_and_rolling(rolling: bool) -> None:
    rva = 0x1000
    data_rva = 0x3000
    instruction = _rip_instruction(
        "mov eax, dword ptr {mem}", rva=rva, target_rva=data_rva
    )
    raw = instruction + _asm("ret", rva=rva + len(instruction))
    reader = plan.SectionImage(
        (
            plan.SectionBytes(".text", rva, len(raw), raw, _EXEC),
            plan.SectionBytes(".data", data_rva, 0x20, bytes(0x20), 0xC0000040),
        )
    )
    kwargs = {}
    if rolling:
        kwargs = {"rolling": True, "rolling_seed": b"R" * 16}
    manifest = plan.compile_virtualization_manifest(
        [plan.FunctionSpec("rip_load", rva, len(raw))],
        reader,
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
        **kwargs,
    )
    function = manifest.functions[0]

    assert function.capabilities["rip_relative_data_addressing_supported"] is True
    assert [item.to_dict() for item in function.rip_relative_references] == [
        {
            "instruction_rva": rva,
            "target_rva": data_rva,
            "size": 4,
            "access": "read",
            "address_only": False,
        }
    ]
    encoded = function.to_dict()
    assert encoded["rip_relative_references"] == [
        function.rip_relative_references[0].to_dict()
    ]
    assert json.loads(manifest.to_json())["functions"][0][
        "rip_relative_references"
    ] == encoded["rip_relative_references"]


def test_rip_data_reference_can_target_virtual_zero_fill() -> None:
    rva = 0x1000
    data_rva = 0x3000
    instruction = _rip_instruction(
        "mov qword ptr {mem}, rax", rva=rva, target_rva=data_rva + 0x18
    )
    raw = instruction + _asm("ret", rva=rva + len(instruction))
    reader = plan.SectionImage(
        (
            plan.SectionBytes(".text", rva, len(raw), raw, _EXEC),
            plan.SectionBytes(".bss", data_rva, 0x40, b"", 0xC0000080),
        )
    )

    manifest = plan.compile_virtualization_manifest(
        [plan.FunctionSpec("rip_bss", rva, len(raw))],
        reader,
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
    )
    assert manifest.functions[0].rip_relative_references[0].access == "write"


def test_rip_reference_rejects_reader_without_section_geometry() -> None:
    rva = 0x1000
    instruction = _rip_instruction(
        "lea rax, {mem}", rva=rva, target_rva=0x3000
    )
    raw = instruction + _asm("ret", rva=rva + len(instruction))

    class _RawReader:
        def read_file_backed_executable(self, selected_rva: int, size: int) -> bytes:
            assert (selected_rva, size) == (rva, len(raw))
            return raw

    with pytest.raises(plan.FunctionRejected, match="section geometry"):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("rip_unknown", rva, len(raw))],
            _RawReader(),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
        )


def test_rip_reference_cannot_address_another_selected_extent() -> None:
    first_rva = 0x1000
    second_rva = 0x1100
    first_instruction = _rip_instruction(
        "lea rax, {mem}", rva=first_rva, target_rva=second_rva
    )
    first = first_instruction + _asm(
        "ret", rva=first_rva + len(first_instruction)
    )
    second = _asm("mov eax, 7; ret", rva=second_rva)
    text = bytearray(b"\xCC" * (second_rva + len(second) - first_rva))
    text[:len(first)] = first
    text[second_rva - first_rva:] = second
    reader = plan.SectionImage(
        (plan.SectionBytes(".text", first_rva, len(text), bytes(text), _EXEC),)
    )

    with pytest.raises(plan.FunctionRejected, match="overlaps selected extent"):
        plan.compile_virtualization_manifest(
            [
                plan.FunctionSpec("first", first_rva, len(first)),
                plan.FunctionSpec("second", second_rva, len(second)),
            ],
            reader,
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
        )
