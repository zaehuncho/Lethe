"""Planner/lifter contracts for opt-in terminal direct E9 tail exits."""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lifter"))
sys.path.insert(0, str(ROOT / "daedalus"))

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")

import virtualization_plan as plan  # noqa: E402
import win64_thunk  # noqa: E402
import x64_lifter  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_EXEC = 0x60000020
_SOURCE_RVA = 0x1000
_TARGET_RVA = 0x1100
_TARGET_UNWIND_RVA = 0x3010


def _asm(source: str, *, rva: int = _SOURCE_RVA) -> bytes:
    encoded, _ = _KS.asm(source, addr=rva)
    return bytes(encoded)


def _tail_source(prefix: str = "mov eax, 7") -> bytes:
    return _asm(f"{prefix}; jmp 0x{_TARGET_RVA:X}")


def _target() -> bytes:
    return _asm("mov eax, 0x77; ret", rva=_TARGET_RVA)


def _reader(source: bytes, target: bytes | None = None) -> plan.SectionImage:
    target = _target() if target is None else target
    gap = _TARGET_RVA - (_SOURCE_RVA + len(source))
    assert gap >= 0
    return plan.SectionImage((
        plan.SectionBytes(
            ".text",
            _SOURCE_RVA,
            _TARGET_RVA + len(target) - _SOURCE_RVA,
            source + b"\x90" * gap + target,
            _EXEC,
        ),
    ))


def _tail_spec(source: bytes, target: bytes | None = None, **overrides) -> plan.FunctionSpec:
    target = _target() if target is None else target
    values = {
        "instruction_rva": _SOURCE_RVA + len(source) - 5,
        "target_rva": _TARGET_RVA,
        "target_size": len(target),
        "target_unwind_info_rva": _TARGET_UNWIND_RVA,
        "target_body_sha256": hashlib.sha256(target).hexdigest(),
    }
    values.update(overrides)
    return plan.FunctionSpec(
        "terminal_tail",
        _SOURCE_RVA,
        len(source),
        tail_exit=plan.TailExitSpec(**values),
    )


def _metadata(source: bytes, target: bytes | None = None, *, target_flags: int = 0):
    target = _target() if target is None else target
    return plan.SourceExceptionMetadata(
        0x9000,
        (
            plan.SourceRuntimeFunction(
                _SOURCE_RVA, _SOURCE_RVA + len(source), 0x3000
            ),
            plan.SourceRuntimeFunction(
                _TARGET_RVA,
                _TARGET_RVA + len(target),
                _TARGET_UNWIND_RVA,
                target_flags,
            ),
        ),
    )


def _sealer(spec: plan.FunctionSpec, program: bytes) -> tuple[bytes, bytes]:
    # The production sealer supplies the authenticated v5 target binding.  The
    # planner merely transports this immutable 16-byte identity unchanged.
    assert spec.tail_exit is not None
    program_id = struct.pack("<I", spec.tail_exit.target_rva) + b"T" * 12
    return b"PAGED" + program, program_id


def _compile(source: bytes, *, target: bytes | None = None, **spec_overrides):
    target = _target() if target is None else target
    return plan.compile_virtualization_manifest(
        [_tail_spec(source, target, **spec_overrides)],
        _reader(source, target),
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
        source_exception_metadata=_metadata(source, target),
        require_source_exception_metadata=True,
        program_sealer=_sealer,
    )


def test_terminal_direct_e9_tail_has_v5_descriptor_split_unwind_and_rel32() -> None:
    source = _tail_source()
    manifest = _compile(source)
    function = manifest.functions[0]

    assert function.tail_exit is not None
    assert function.tail_exit.instruction_rva == _SOURCE_RVA + len(source) - 5
    assert function.tail_exit.target_rva == _TARGET_RVA
    assert function.tail_thunk is not None
    assert function.tail_thunk.status_rva == (
        0x5000 + win64_thunk.TAIL_THUNK_TAIL_STATUS_OFFSET
    )
    assert function.tail_thunk.jump_rva == (
        0x5000 + win64_thunk.TAIL_THUNK_JUMP_OFFSET
    )
    assert function.tail_thunk.target_rel32_rva == (
        0x5000 + win64_thunk.TAIL_THUNK_TARGET_REL32_OFFSET
    )
    assert struct.unpack("<IIQ16sQII", function.descriptor_data) == (
        plan.DESCRIPTOR_VERSION_PAGED_TAIL,
        len(function.program),
        0,
        function.program_id,
        0,
        _TARGET_RVA,
        0,
    )
    assert function.unwind.begin_rva == 0x5000
    assert function.unwind.end_rva == (
        0x5000 + win64_thunk.TAIL_THUNK_PRIMARY_END_OFFSET
    )
    assert [(item.begin_rva, item.end_rva, item.unwind_info) for item in function.tail_unwind] == [
        (
            0x5000 + win64_thunk.TAIL_THUNK_POPFQ_OFFSET,
            0x5000 + win64_thunk.TAIL_THUNK_POPFQ_END_OFFSET,
            win64_thunk.TAIL_THUNK_POPFQ_UNWIND_INFO,
        ),
        (
            0x5000 + win64_thunk.TAIL_THUNK_JUMP_OFFSET,
            0x5000 + win64_thunk.TAIL_THUNK_JUMP_END_OFFSET,
            win64_thunk.TAIL_THUNK_JUMP_UNWIND_INFO,
        ),
    ]
    assert len(manifest.exception_table.generated) == 3
    assert [item.begin_rva for item in manifest.exception_table.retained] == [_TARGET_RVA]
    tail_relocations = [
        item for item in function.required_relocations
        if item.patch_rva == function.tail_thunk.target_rel32_rva
    ]
    assert tail_relocations == [
        plan.RelocationRequirement(
            kind="REL32",
            patch_rva=function.tail_thunk.target_rel32_rva,
            target_rva=_TARGET_RVA,
        )
    ]
    assert function.capabilities["terminal_direct_tail_exit"] is True
    assert function.capabilities["authenticated_bytecode_paging"] is True


def test_tail_lifter_emits_existing_halt_status_two_only_under_admission() -> None:
    source = _tail_source()
    text = x64_lifter.lift_function(
        source,
        _SOURCE_RVA,
        source_extent_size=len(source),
        tail_exit=(_SOURCE_RVA + len(source) - 5, _TARGET_RVA),
        tail_stack_window_size=win64_thunk.STACK_WINDOW_SIZE,
    )
    assert "push_imm64 0x0000000000000002" in text
    assert "halt" in text
    with pytest.raises(x64_lifter.LiftUnsupported, match="explicit materialized stack window"):
        x64_lifter.lift_function(
            source,
            _SOURCE_RVA,
            tail_exit=(_SOURCE_RVA + len(source) - 5, _TARGET_RVA),
        )


def test_tail_planner_rejects_page_identity_without_target_binding() -> None:
    source = _tail_source()

    def wrong_identity(
        spec: plan.FunctionSpec, program: bytes
    ) -> tuple[bytes, bytes]:
        assert spec.tail_exit is not None
        return b"PAGED" + program, b"X" * 16

    with pytest.raises(plan.FunctionRejected, match="identity does not bind"):
        plan.compile_virtualization_manifest(
            [_tail_spec(source)],
            _reader(source),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=_metadata(source),
            require_source_exception_metadata=True,
            program_sealer=wrong_identity,
        )


@pytest.mark.parametrize(
    "source, instruction_offset",
    [
        ("jmp 0x1100; nop", 0),
        ("test ecx, ecx; je 0x1100; jmp 0x1100", None),
        ("call 0x1100; jmp 0x1100", None),
        ("nop; nop; nop; jmp rax", -2),
    ],
)
def test_tail_planner_rejects_nonterminal_conditional_call_or_indirect_control_flow(
    source: str, instruction_offset: int | None,
) -> None:
    raw = _asm(source)
    actual_instruction = (
        _SOURCE_RVA + len(raw) - 5
        if instruction_offset is None
        else _SOURCE_RVA + (len(raw) + instruction_offset if instruction_offset < 0 else instruction_offset)
    )
    with pytest.raises(plan.FunctionRejected, match="terminal tail exit"):
        _compile(raw, instruction_rva=actual_instruction)


@pytest.mark.parametrize(
    "source, reason",
    [
        ("sub rsp, 8; jmp 0x1100", "nonzero source stack depth"),
        ("mov r10, rsp; jmp 0x1100", "source stack pointer alias"),
        (
            "mov r10, rsp; mov qword ptr [rcx], r10; jmp 0x1100",
            "source stack pointer escape",
        ),
    ],
)
def test_tail_planner_rejects_nonzero_stack_or_rsp_alias(source: str, reason: str) -> None:
    raw = _asm(source)
    with pytest.raises(plan.FunctionRejected, match=reason):
        _compile(raw)


@pytest.mark.parametrize(
    "prefix", ("add eax, 1", "xor edx, edx", "inc eax", "test ecx, ecx")
)
def test_tail_planner_rejects_unmodeled_rflags(prefix: str) -> None:
    # The native target receives RFLAGS through POPFQ.  AF is not represented
    # by the VM frame, and each of these instructions writes or leaves it
    # undefined, so a tail continuation must fail closed instead of leaking the
    # caller's stale AF to retained native code.
    with pytest.raises(plan.FunctionRejected, match="modifies unmodeled RFLAGS"):
        _compile(_tail_source(prefix))


def test_tail_planner_rejects_undefined_modeled_rflags() -> None:
    # Variable-count ROL writes only modeled CF/OF, but iced marks OF
    # undefined.  The POPFQ tail transfer cannot reproduce that undefined
    # state faithfully, so this must fail even though no unmodeled bit changes.
    with pytest.raises(plan.FunctionRejected, match="leaves RFLAGS undefined"):
        _compile(_tail_source("rol eax, cl"))


def test_tail_planner_keeps_flag_neutral_body() -> None:
    # MOV changes no RFLAGS, so it can reach retained native code without
    # exposing a VM-unmodeled flag through the tail shim's POPFQ.
    neutral = _compile(_tail_source("mov eax, 7"))
    assert neutral.functions[0].tail_exit is not None


def test_tail_rflags_admission_keeps_modeled_only_flag_write() -> None:
    # STC writes only modeled CF.  The main lifter does not implement STC, so
    # exercise the tail-admission proof directly: the RFLAGS contract itself
    # must not turn a modeled-only write into a blanket rejection.
    source = _tail_source("stc")
    assert x64_lifter.validate_terminal_tail_exit(
        source,
        _SOURCE_RVA,
        tail_exit=(_SOURCE_RVA + len(source) - 5, _TARGET_RVA),
        window_size=win64_thunk.STACK_WINDOW_SIZE,
    ) == 0


def test_tail_planner_rejects_stale_target_identity_and_handler_target() -> None:
    source = _tail_source()
    stale = "00" * 32
    with pytest.raises(plan.FunctionRejected, match="target body identity is stale"):
        _compile(source, target_body_sha256=stale)

    target = _target()
    spec = _tail_spec(source, target)
    with pytest.raises(plan.FunctionRejected, match="handler-free primary"):
        plan.compile_virtualization_manifest(
            [spec],
            _reader(source, target),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=_metadata(source, target, target_flags=plan.UNW_FLAG_EHANDLER),
            require_source_exception_metadata=True,
            program_sealer=_sealer,
        )


def test_tail_planner_rejects_missing_or_selected_target_pdata() -> None:
    source = _tail_source()
    target = _target()
    spec = _tail_spec(source, target)
    missing_target_pdata = plan.SourceExceptionMetadata(
        0x9000,
        (plan.SourceRuntimeFunction(_SOURCE_RVA, _SOURCE_RVA + len(source), 0x3000),),
    )
    with pytest.raises(plan.FunctionRejected, match="exact retained PDATA"):
        plan.compile_virtualization_manifest(
            [spec],
            _reader(source, target),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=missing_target_pdata,
            require_source_exception_metadata=True,
            program_sealer=_sealer,
        )

    with pytest.raises(plan.VirtualizationPlanError, match="tail target overlaps selected"):
        plan.compile_virtualization_manifest(
            [
                spec,
                plan.FunctionSpec("selected_target", _TARGET_RVA, len(target)),
            ],
            _reader(source, target),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=_metadata(source, target),
            require_source_exception_metadata=True,
            program_sealer=_sealer,
        )


def test_tail_planner_rejects_post_proof_bytecode_mutation() -> None:
    source = _tail_source()
    with pytest.raises(plan.FunctionRejected, match="post-proof bytecode mutation"):
        plan.compile_virtualization_manifest(
            [_tail_spec(source)],
            _reader(source),
            generated_text_rva=0x5000,
            generated_data_rva=0x7000,
            source_exception_metadata=_metadata(source),
            require_source_exception_metadata=True,
            program_sealer=_sealer,
            mutate_level=1,
        )


def test_ordinary_ret_plan_remains_plain_v3_without_tail_metadata() -> None:
    source = _asm("mov eax, 9; ret")
    manifest = plan.compile_virtualization_manifest(
        [plan.FunctionSpec("ordinary", _SOURCE_RVA, len(source))],
        plan.SectionImage((plan.SectionBytes(".text", _SOURCE_RVA, len(source), source, _EXEC),)),
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
    )
    function = manifest.functions[0]
    assert function.tail_exit is None
    assert function.tail_thunk is None
    assert function.tail_unwind == ()
    assert struct.unpack("<IIQQ", function.descriptor_data)[0] == plan.DESCRIPTOR_VERSION_PLAIN
