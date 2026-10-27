"""Packer-side materialization contracts for terminal E9 tail exits."""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import struct

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")

from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402
from lifter import direct_control_flow, virtualization_plan as plan  # noqa: E402
from lifter import win64_thunk  # noqa: E402
from packer import bytecode_pages, pe_analyze, virtualize  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_IMAGE_BASE = 0x140000000
_MASTER_KEY = bytes(range(32))
_EXEC = 0x60000020
_SOURCE_RVA = 0x1000
_TARGET_RVA = 0x100A
_TARGET_UNWIND_RVA = 0x3010


def _asm(source: str, *, rva: int) -> bytes:
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


def _tail_fixture() -> tuple[
    pe_analyze.ParsedPE,
    plan.FunctionSpec,
    direct_control_flow.DirectControlFlowProof,
]:
    # Keep the selected E9 and retained target contiguous so direct-flow
    # production coverage has no synthetic gap to acknowledge.
    # Keystone shortens a nearby JMP; construct the required exact E9 rel32
    # encoding so this fixture exercises the terminal-tail admission path.
    source = _asm("mov eax, 7", rva=_SOURCE_RVA) + b"\xE9" + struct.pack(
        "<i", _TARGET_RVA - (_SOURCE_RVA + 10)
    )
    assert len(source) == _TARGET_RVA - _SOURCE_RVA
    target = _asm("mov eax, 0x77; ret", rva=_TARGET_RVA)
    text = source + target
    pdata = b"".join((
        struct.pack("<III", _SOURCE_RVA, _TARGET_RVA, 0x3000),
        struct.pack(
            "<III", _TARGET_RVA, _TARGET_RVA + len(target), _TARGET_UNWIND_RVA
        ),
    ))
    xdata = b"\x01\x00\x00\x00".ljust(0x10, b"\x00") + b"\x01\x00\x00\x00"
    parsed = pe_analyze.ParsedPE(
        path="synthetic-terminal-tail.exe",
        is_dll=False,
        image_base=_IMAGE_BASE,
        size_of_image=0x5000,
        oep_rva=_SOURCE_RVA,
        sections=[
            pe_analyze.ParsedSection(".text", _SOURCE_RVA, len(text), text, _EXEC),
            pe_analyze.ParsedSection(".pdata", 0x2000, len(pdata), pdata, 0x40000040),
            pe_analyze.ParsedSection(".xdata", 0x3000, len(xdata), xdata, 0x40000040),
            pe_analyze.ParsedSection(
                ".rdata", 0x4000, 8,
                struct.pack("<Q", _IMAGE_BASE + _TARGET_RVA), 0x40000040,
            ),
        ],
        imports=[],
        reloc_blob=_reloc_blob(0x4000),
        tls=None,
        pdata_rva=0x2000,
        pdata_count=2,
        rsrc_rva=0,
        file_characteristics=0x22,
        dll_characteristics=0x140,
        dir64_relocations=(pe_analyze.ParsedDir64Relocation(0x4000),),
        runtime_functions=(
            pe_analyze.ParsedRuntimeFunction(_SOURCE_RVA, _TARGET_RVA, 0x3000),
            pe_analyze.ParsedRuntimeFunction(
                _TARGET_RVA, _TARGET_RVA + len(target), _TARGET_UNWIND_RVA
            ),
        ),
    )
    tail = plan.TailExitSpec(
        instruction_rva=_TARGET_RVA - 5,
        target_rva=_TARGET_RVA,
        target_size=len(target),
        target_unwind_info_rva=_TARGET_UNWIND_RVA,
        target_body_sha256=hashlib.sha256(target).hexdigest(),
    )
    spec = plan.FunctionSpec("terminal_tail", _SOURCE_RVA, len(source), tail_exit=tail)
    proof = direct_control_flow.analyze_direct_control_flow(
        parsed,
        (spec,),
        tail_exit_policy=direct_control_flow.TailExitPolicy((
            direct_control_flow.TailExitApproval(
                spec.rva, tail.instruction_rva, tail.target_rva, "test terminal tail"
            ),
        )),
        production=True,
    )
    return parsed, spec, proof


def _seal_tail(spec: plan.FunctionSpec, program: bytes) -> tuple[bytes, bytes]:
    assert spec.tail_exit is not None
    program_id = struct.pack("<I", spec.tail_exit.target_rva) + hashlib.sha256(
        b"terminal-tail-test\0" + program
    ).digest()[4:16]
    return (
        bytecode_pages.seal_program(
            program,
            _MASTER_KEY,
            program_id=program_id,
            page_size=bytecode_pages.MIN_PAGE_SIZE,
            salt=b"\xA5" * bytecode_pages.SALT_SIZE,
        ),
        program_id,
    )


def _tail_manifest():
    parsed, spec, proof = _tail_fixture()
    text_rva, data_rva = virtualize._next_generated_rvas(parsed, (spec,))
    manifest = plan.compile_virtualization_manifest(
        (spec,),
        plan.SectionImage.from_parsed_sections(parsed.sections),
        generated_text_rva=text_rva,
        generated_data_rva=data_rva,
        runtime_common_rva=text_rva,
        source_dir64_relocations=tuple(
            plan.SourceDir64Relocation(item.target_rva)
            for item in parsed.dir64_relocations
        ),
        require_source_relocation_metadata=True,
        source_exception_metadata=plan.SourceExceptionMetadata(
            parsed.pdata_rva,
            tuple(
                plan.SourceRuntimeFunction(
                    item.begin_rva,
                    item.end_rva,
                    item.unwind_info_rva,
                    item.unwind_flags,
                    item.chain_primary_rva,
                )
                for item in parsed.runtime_functions
            ),
        ),
        require_source_exception_metadata=True,
        program_sealer=_seal_tail,
    )
    return parsed, spec, proof, manifest


def test_v5_program_identity_binds_tail_identity_before_sealing() -> None:
    parsed, spec, _proof = _tail_fixture()
    program = b"\x00\x00\xFE\xCA"
    program_id, salt_domain = virtualize._derive_paged_program_identity(spec, program)
    assert parsed.size_of_image == 0x5000
    assert spec.tail_exit is not None
    tail = spec.tail_exit
    expected_input = (
        b"Lethe-selected-terminal-tail-page-id-v1\0"
        + spec.name.encode("utf-8")
        + struct.pack("<III", spec.rva, spec.size, spec.body_size)
        + struct.pack(
            "<IIII",
            tail.instruction_rva,
            tail.target_rva,
            tail.target_size,
            tail.target_unwind_info_rva,
        )
        + bytes.fromhex(tail.target_body_sha256)
        + program
    )
    assert program_id == struct.pack("<I", tail.target_rva) + hashlib.sha256(
        expected_input
    ).digest()[4:16]
    assert salt_domain == b"Lethe-selected-terminal-tail-page-salt-v1\0"
    envelope = bytecode_pages.seal_program(
        program,
        _MASTER_KEY,
        program_id=program_id,
        page_size=bytecode_pages.MIN_PAGE_SIZE,
        salt=b"\x5A" * bytecode_pages.SALT_SIZE,
    )
    assert bytecode_pages.parse_envelope(envelope).program_id == program_id

    ordinary = plan.FunctionSpec("ordinary", 0x1200, 5)
    ordinary_id, ordinary_domain = virtualize._derive_paged_program_identity(
        ordinary, program
    )
    v4_input = (
        b"Lethe-selected-function-page-id-v1\0"
        + b"ordinary"
        + struct.pack("<III", 0x1200, 5, 5)
        + hashlib.sha256(program).digest()
    )
    assert ordinary_id == hashlib.sha256(v4_input).digest()[:16]
    assert ordinary_domain == b"Lethe-selected-function-page-salt-v1\0"


def test_tail_materializer_validates_v5_layout_three_unwinds_and_e9_rel32() -> None:
    parsed, spec, proof, manifest = _tail_manifest()
    function = manifest.functions[0]
    assert function.tail_exit == spec.tail_exit
    assert function.tail_thunk is not None
    assert len(function.tail_unwind) == 2
    virtualize._validate_tail_exit_provenance((spec,), proof)
    assert virtualize._validate_function_artifacts(function, manifest) == (
        manifest.generated_text_rva
    )
    virtualize._validate_direct_only_references(parsed, manifest)
    text, _data, _relocations = virtualize._build_generated_sections(parsed, manifest)
    tail_rel32 = struct.unpack_from(
        "<i", text,
        function.tail_thunk.target_rel32_rva - manifest.generated_text_rva,
    )[0]
    assert (
        function.tail_thunk.target_rel32_rva + 4 + tail_rel32
        == function.tail_exit.target_rva
    )
    assert text[function.tail_thunk.jump_rva - manifest.generated_text_rva] == 0xE9

    before = copy.deepcopy(parsed)
    materialized = virtualize.apply_virtualization_manifest(
        parsed,
        manifest,
        acknowledge_no_interior_entries=True,
        tail_exit_proof=proof,
    )
    assert parsed == before
    assert materialized.pdata_count == 4
    generated = tuple(
        item for item in materialized.runtime_functions
        if item.begin_rva >= manifest.generated_text_rva
    )
    assert [(item.begin_rva, item.end_rva) for item in generated] == [
        (function.unwind.begin_rva, function.unwind.end_rva),
        *[(item.begin_rva, item.end_rva) for item in function.tail_unwind],
    ]


def test_tail_materializer_rejects_missing_stale_proof_and_bad_descriptor() -> None:
    parsed, spec, proof, manifest = _tail_manifest()
    before = copy.deepcopy(parsed)
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="require a matching direct-control-flow proof",
    ):
        virtualize.apply_virtualization_manifest(
            parsed, manifest, acknowledge_no_interior_entries=True
        )
    assert parsed == before

    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="stale flows",
    ):
        virtualize._validate_tail_exit_provenance(
            (spec,), dataclasses.replace(proof, selected_flows=())
        )

    transfer = proof.direct_transfers[0]
    for malformed in (
        dataclasses.replace(transfer, source_range_begin_rva=0x2222),
        dataclasses.replace(transfer, source_has_runtime_function=False),
        dataclasses.replace(transfer, target_is_selected_entry=True),
        dataclasses.replace(transfer, target_selected_name="selected"),
    ):
        with pytest.raises(
            virtualize.VirtualizationMaterializationError,
            match="approval is absent",
        ):
            virtualize._validate_tail_exit_provenance(
                (spec,),
                dataclasses.replace(proof, direct_transfers=(malformed,)),
            )

    function = manifest.functions[0]
    assert function.tail_exit is not None
    version, size, pointer, program_id, image_base, target, reserved = struct.unpack(
        "<IIQ16sQII", function.descriptor_data
    )
    forged = dataclasses.replace(
        function,
        descriptor_data=struct.pack(
            "<IIQ16sQII",
            version,
            size,
            pointer,
            program_id,
            image_base,
            target + 1,
            reserved,
        ),
    )
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="terminal-tail descriptor ABI is invalid",
    ):
        virtualize._validate_function_artifacts(forged, manifest)


def test_tail_materializer_rejects_post_plan_retained_target_mutations() -> None:
    """The v5 descriptor never authorizes a stale native destination.

    The selected E9 body deliberately remains unchanged in both variants below.
    A post-plan edit to the retained target body must therefore reach the
    tail-specific hash guard, while a changed target PDATA identity must fail
    before any generated section is written.
    """
    parsed, _spec, proof, manifest = _tail_manifest()

    changed_body = copy.deepcopy(parsed)
    text = next(section for section in changed_body.sections if section.name == ".text")
    offset = _TARGET_RVA - text.rva
    raw = bytearray(text.raw)
    raw[offset] ^= 0x01
    text.raw = bytes(raw)
    before_body = copy.deepcopy(changed_body)
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="tail target body changed after planning",
    ):
        virtualize.apply_virtualization_manifest(
            changed_body,
            manifest,
            acknowledge_no_interior_entries=True,
            tail_exit_proof=proof,
        )
    assert changed_body == before_body

    changed_pdata = copy.deepcopy(parsed)
    changed_pdata.runtime_functions = tuple(
        dataclasses.replace(record, unwind_flags=plan.UNW_FLAG_EHANDLER)
        if record.begin_rva == _TARGET_RVA
        else record
        for record in changed_pdata.runtime_functions
    )
    # Keep the synthetic xdata representation consistent with the PDATA view:
    # version 1 plus UNW_FLAG_EHANDLER is 0x09 at the retained target's header.
    # Supply a file-backed handler RVA so this is a valid changed PDATA
    # inventory, not merely malformed metadata.
    xdata = next(section for section in changed_pdata.sections if section.name == ".xdata")
    xraw = bytearray(xdata.raw)
    xraw[_TARGET_UNWIND_RVA - xdata.rva] = 0x09
    xraw += struct.pack("<I", _SOURCE_RVA)
    xdata.raw = bytes(xraw)
    xdata.virtual_size = len(xraw)
    before_pdata = copy.deepcopy(changed_pdata)
    with pytest.raises(
        virtualize.VirtualizationMaterializationError,
        match="source runtime-function records changed after manifest compilation",
    ):
        virtualize.apply_virtualization_manifest(
            changed_pdata,
            manifest,
            acknowledge_no_interior_entries=True,
            tail_exit_proof=proof,
        )
    assert changed_pdata == before_pdata
