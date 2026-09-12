"""Conservative direct control-transfer proof tests."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lifter"))

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")

import direct_control_flow as flow  # noqa: E402
from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_EXEC = 0x60000020


def _asm(source: str, rva: int) -> bytes:
    encoded, _ = _KS.asm(source, addr=rva)
    return bytes(encoded)


def _parsed(
    functions: list[tuple[int, bytes]],
    *,
    section_start: int | None = None,
    section_end: int | None = None,
):
    ordered = sorted(functions)
    start = ordered[0][0] if section_start is None else section_start
    end = (
        max(rva + len(raw) for rva, raw in ordered)
        if section_end is None
        else section_end
    )
    raw = bytearray(b"\xCC" * (end - start))
    records = []
    for rva, code in ordered:
        raw[rva - start : rva - start + len(code)] = code
        records.append(
            SimpleNamespace(
                begin_rva=rva,
                end_rva=rva + len(code),
                unwind_info_rva=0x3000,
                unwind_flags=0,
            )
        )
    return SimpleNamespace(
        sections=[
            SimpleNamespace(
                name=".text",
                rva=start,
                virtual_size=len(raw),
                raw=bytes(raw),
                characteristics=_EXEC,
            )
        ],
        runtime_functions=tuple(records),
    )


def _spec(name: str, rva: int, raw: bytes):
    return SimpleNamespace(name=name, rva=rva, size=len(raw))


def test_external_call_into_selected_interior_is_rejected() -> None:
    source_rva = 0x1000
    selected_rva = 0x1100
    source = _asm(f"call 0x{selected_rva + 1:X}; ret", source_rva)
    selected = _asm("nop; mov eax, 1; ret", selected_rva)

    with pytest.raises(flow.DirectControlFlowError, match="enters selected.*interior"):
        flow.analyze_direct_control_flow(
            _parsed([(source_rva, source), (selected_rva, selected)]),
            [_spec("selected", selected_rva, selected)],
            production=False,
        )


def test_external_jump_into_selected_interior_is_rejected() -> None:
    source_rva = 0x1000
    selected_rva = 0x1100
    source = _asm(f"jmp 0x{selected_rva + 1:X}", source_rva)
    selected = _asm("nop; mov eax, 1; ret", selected_rva)

    with pytest.raises(flow.DirectControlFlowError, match="direct jump.*interior"):
        flow.analyze_direct_control_flow(
            _parsed([(source_rva, source), (selected_rva, selected)]),
            [_spec("selected", selected_rva, selected)],
            production=False,
        )


def test_cross_selected_function_interior_entry_is_rejected() -> None:
    first_rva = 0x1000
    second_rva = 0x1100
    first = _asm(f"jmp 0x{second_rva + 1:X}", first_rva)
    second = _asm("nop; mov eax, 2; ret", second_rva)
    policy = flow.TailExitPolicy(
        (
            flow.TailExitApproval(
                first_rva,
                first_rva,
                second_rva + 1,
                "fixture cross-entry",
            ),
        )
    )

    with pytest.raises(flow.DirectControlFlowError, match="interior"):
        flow.analyze_direct_control_flow(
            _parsed([(first_rva, first), (second_rva, second)]),
            [_spec("first", first_rva, first), _spec("second", second_rva, second)],
            tail_exit_policy=policy,
            production=False,
        )


def test_undecodable_runtime_function_is_rejected() -> None:
    malformed = b"\x48\xB8\x01\x02\x03"
    parsed = _parsed([(0x1000, malformed)])

    with pytest.raises(flow.DirectControlFlowError, match="undecodable"):
        flow.analyze_direct_control_flow(
            parsed,
            [_spec("bad", 0x1000, malformed)],
            production=False,
        )


def test_benign_calls_to_runtime_entry_and_outside_selected_extent_are_recorded() -> None:
    callee_rva = 0x1000
    selected_rva = 0x1100
    callee = _asm("ret", callee_rva)
    selected = _asm(f"call 0x{callee_rva:X}; mov eax, 7; ret", selected_rva)
    parsed = _parsed([(callee_rva, callee), (selected_rva, selected)])

    proof = flow.analyze_direct_control_flow(
        parsed,
        [_spec("selected", selected_rva, selected)],
        production=False,
    )

    edge = next(item for item in proof.direct_transfers if item.source_selected_name)
    assert edge.kind == "call"
    assert edge.target_rva == callee_rva
    assert edge.reachable_from_selected_entry is True
    assert proof.direct_reference_gate_passed is False


def test_internal_branch_to_selected_interior_is_not_an_external_entry() -> None:
    selected_rva = 0x1000
    selected = _asm("test ecx, ecx; jz zero; mov eax, 1; ret; zero: xor eax, eax; ret", selected_rva)
    proof = flow.analyze_direct_control_flow(
        _parsed([(selected_rva, selected)]),
        [_spec("selected", selected_rva, selected)],
    )

    branch = next(
        item for item in proof.direct_transfers if item.kind == "conditional_jump"
    )
    assert branch.target_selected_name == "selected"
    assert branch.target_is_selected_entry is False
    assert branch.reachable_from_selected_entry is True


def test_reachable_conditional_exit_and_unapproved_tail_exit_are_rejected() -> None:
    selected_rva = 0x1000
    conditional = _asm("test ecx, ecx; jz 0x1100; ret", selected_rva)
    with pytest.raises(flow.DirectControlFlowError, match="conditional_jump exit"):
        flow.analyze_direct_control_flow(
            _parsed([(selected_rva, conditional)]),
            [_spec("conditional", selected_rva, conditional)],
            production=False,
        )

    tail = _asm("jmp 0x1100", selected_rva)
    with pytest.raises(flow.DirectControlFlowError, match="unapproved direct tail exit"):
        flow.analyze_direct_control_flow(
            _parsed([(selected_rva, tail)]),
            [_spec("tail", selected_rva, tail)],
            production=False,
        )


def test_reachable_loop_family_exit_is_classified_and_rejected() -> None:
    selected_rva = 0x1000
    selected = _asm("loop 0x1040; ret", selected_rva)
    with pytest.raises(flow.DirectControlFlowError, match="reachable loop exit"):
        flow.analyze_direct_control_flow(
            _parsed([(selected_rva, selected)]),
            [_spec("loop_exit", selected_rva, selected)],
            production=False,
        )


def test_exact_tail_exit_approval_to_runtime_entry_is_consumed() -> None:
    selected_rva = 0x1000
    target_rva = 0x1100
    selected = _asm(f"jmp 0x{target_rva:X}", selected_rva)
    target = _asm("ret", target_rva)
    approval = flow.TailExitApproval(
        selected_rva,
        selected_rva,
        target_rva,
        "known ABI-compatible tail target",
    )
    proof = flow.analyze_direct_control_flow(
        _parsed([(selected_rva, selected), (target_rva, target)]),
        [_spec("selected", selected_rva, selected)],
        tail_exit_policy=flow.TailExitPolicy((approval,)),
        production=False,
    )

    assert proof.selected_flows[0].approved_tail_exits == (approval,)


def test_indirect_transfer_is_explicitly_unproven() -> None:
    selected_rva = 0x1000
    selected = _asm("call rax; mov eax, 1; ret", selected_rva)
    proof = flow.analyze_direct_control_flow(
        _parsed([(selected_rva, selected)]),
        [_spec("selected", selected_rva, selected)],
    )

    assert proof.indirect_target_closure_proven is False
    assert len(proof.indirect_transfers) == 1
    assert proof.indirect_transfers[0].kind == "indirect_call"
    assert proof.indirect_transfers[0].reachable_from_selected_entry is True
    assert "Indirect and address-taken" in proof.limitations[0]


def test_selected_leaf_without_runtime_record_is_strictly_decoded() -> None:
    selected_rva = 0x1000
    selected = _asm("mov eax, 1; ret", selected_rva)
    parsed = _parsed([(selected_rva, selected)])
    parsed.runtime_functions = ()

    proof = flow.analyze_direct_control_flow(
        parsed,
        [_spec("leaf_without_pdata", selected_rva, selected)],
    )

    assert proof.decoded_runtime_functions == ()
    assert proof.selected_flows[0].reachable_instruction_rvas == (
        selected_rva,
        selected_rva + 5,
    )
    assert proof.direct_runtime_coverage_complete is True


def test_production_fails_closed_on_gap_and_accepts_only_exact_acknowledgement() -> None:
    selected_rva = 0x1010
    selected = _asm("mov eax, 1; ret", selected_rva)
    parsed = _parsed(
        [(selected_rva, selected)], section_start=0x1000, section_end=0x1020
    )

    with pytest.raises(flow.CoverageGapError) as rejected:
        flow.analyze_direct_control_flow(parsed, [_spec("selected", selected_rva, selected)])
    assert [(gap.rva, gap.size) for gap in rejected.value.gaps] == [
        (0x1000, 0x10),
        (selected_rva + len(selected), 0x1020 - selected_rva - len(selected)),
    ]

    acknowledgements = tuple(
        flow.CoverageGapAcknowledgement(gap.rva, gap.size, "known linker padding")
        for gap in rejected.value.gaps
    )
    proof = flow.analyze_direct_control_flow(
        parsed,
        [_spec("selected", selected_rva, selected)],
        coverage_acknowledgements=acknowledgements,
    )
    assert proof.direct_runtime_coverage_complete is False
    assert proof.direct_reference_gate_passed is True
    assert proof.acknowledged_coverage_gaps == acknowledgements

    with pytest.raises(flow.DirectControlFlowError, match="does not match an exact gap"):
        flow.analyze_direct_control_flow(
            parsed,
            [_spec("selected", selected_rva, selected)],
            coverage_acknowledgements=(
                flow.CoverageGapAcknowledgement(0x1000, 1, "stale partial gap"),
            ),
        )


def test_executable_virtual_tail_is_an_honest_coverage_gap() -> None:
    selected_rva = 0x1000
    selected = _asm("ret", selected_rva)
    parsed = _parsed([(selected_rva, selected)])
    parsed.sections[0].virtual_size = 0x10

    with pytest.raises(flow.CoverageGapError) as rejected:
        flow.analyze_direct_control_flow(
            parsed,
            [_spec("selected", selected_rva, selected)],
        )
    assert [(item.rva, item.size) for item in rejected.value.gaps] == [
        (selected_rva + 1, 0x0F)
    ]


def test_malformed_overlapping_ranges_and_non_exact_selection_fail() -> None:
    first = _asm("nop; ret", 0x1000)
    parsed = _parsed([(0x1000, first)])
    parsed.runtime_functions = (
        SimpleNamespace(begin_rva=0x1000, end_rva=0x1002),
        SimpleNamespace(begin_rva=0x1001, end_rva=0x1002),
    )
    with pytest.raises(flow.DirectControlFlowError, match="runtime-function ranges overlap"):
        flow.analyze_direct_control_flow(
            parsed, [_spec("selected", 0x1000, first)], production=False
        )

    parsed = _parsed([(0x1000, first)])
    with pytest.raises(flow.DirectControlFlowError, match="partially overlaps"):
        flow.analyze_direct_control_flow(
            parsed,
            [SimpleNamespace(name="partial", rva=0x1000, size=1)],
            production=False,
        )
