"""Conservative direct control-transfer analysis for whole-function selection.

The pass proves only properties of direct x64 control transfers found in
strictly decoded AMD64 runtime-function ranges.  It intentionally does not
claim that address-taken or indirect targets are closed.  Executable bytes
outside runtime-function records are surfaced as explicit coverage gaps; the
default production mode rejects every gap unless the caller acknowledges its
exact range and records a rationale.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from iced_x86 import Decoder, FlowControl, Mnemonic, OpKind


IMAGE_SCN_MEM_EXECUTE = 0x20000000
PROOF_VERSION = 1
_RVA_LIMIT = 0x1_0000_0000
_NEAR_BRANCH_KINDS = {
    OpKind.NEAR_BRANCH16,
    OpKind.NEAR_BRANCH32,
    OpKind.NEAR_BRANCH64,
}
_LOOP_MNEMONICS = {
    Mnemonic.LOOP,
    Mnemonic.LOOPE,
    Mnemonic.LOOPNE,
    Mnemonic.JCXZ,
    Mnemonic.JECXZ,
    Mnemonic.JRCXZ,
}
_INDIRECT_LIMITATION = (
    "Indirect and address-taken target closure is unproven; this pass only "
    "classifies direct control transfers in decoded runtime-function ranges."
)
_COVERAGE_LIMITATION = (
    "Executable bytes outside decoded runtime-function and selected ranges may "
    "contain code or embedded data and are not linear-swept by this pass."
)


class DirectControlFlowError(ValueError):
    """A malformed image or unsafe direct control-flow edge was rejected."""


class CoverageGapError(DirectControlFlowError):
    """Production analysis found executable coverage without acknowledgement."""

    def __init__(self, gaps: Sequence["CoverageGap"], reason: str) -> None:
        self.gaps = tuple(gaps)
        super().__init__(reason)


@dataclass(frozen=True, order=True)
class SelectedFunctionRange:
    name: str
    rva: int
    size: int

    @property
    def end_rva(self) -> int:
        return self.rva + self.size


@dataclass(frozen=True, order=True)
class CoverageGap:
    rva: int
    size: int
    section_name: str

    @property
    def end_rva(self) -> int:
        return self.rva + self.size


@dataclass(frozen=True, order=True)
class CoverageGapAcknowledgement:
    rva: int
    size: int
    rationale: str


@dataclass(frozen=True, order=True)
class TailExitApproval:
    """Approval for one exact reachable unconditional direct JMP edge."""

    function_rva: int
    instruction_rva: int
    target_rva: int
    rationale: str


@dataclass(frozen=True)
class TailExitPolicy:
    approvals: tuple[TailExitApproval, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.approvals, tuple):
            raise DirectControlFlowError("tail-exit approvals must be an immutable tuple")
        seen = set()
        for approval in self.approvals:
            if not isinstance(approval, TailExitApproval):
                raise DirectControlFlowError(
                    "tail-exit policy entries must be TailExitApproval"
                )
            _validate_range(approval.function_rva, 1, "tail-exit function")
            _validate_range(approval.instruction_rva, 1, "tail-exit instruction")
            _validate_range(approval.target_rva, 1, "tail-exit target")
            if (
                not isinstance(approval.rationale, str)
                or not approval.rationale.strip()
                or "\0" in approval.rationale
            ):
                raise DirectControlFlowError(
                    "tail-exit approval requires a non-NUL rationale"
                )
            identity = (
                approval.function_rva,
                approval.instruction_rva,
                approval.target_rva,
            )
            if identity in seen:
                raise DirectControlFlowError("duplicate tail-exit approval")
            seen.add(identity)


@dataclass(frozen=True)
class DecodedRuntimeFunction:
    begin_rva: int
    end_rva: int
    instruction_count: int


@dataclass(frozen=True)
class DirectControlTransfer:
    source_rva: int
    source_range_begin_rva: int
    source_has_runtime_function: bool
    kind: str
    target_rva: int
    source_selected_name: str | None
    target_selected_name: str | None
    target_is_selected_entry: bool
    reachable_from_selected_entry: bool


@dataclass(frozen=True)
class IndirectControlTransfer:
    source_rva: int
    source_range_begin_rva: int
    source_has_runtime_function: bool
    kind: str
    source_selected_name: str | None
    reachable_from_selected_entry: bool


@dataclass(frozen=True)
class SelectedFunctionFlow:
    name: str
    rva: int
    size: int
    reachable_instruction_rvas: tuple[int, ...]
    approved_tail_exits: tuple[TailExitApproval, ...]


@dataclass(frozen=True)
class DirectControlFlowProof:
    version: int
    selected_functions: tuple[SelectedFunctionRange, ...]
    decoded_runtime_functions: tuple[DecodedRuntimeFunction, ...]
    direct_transfers: tuple[DirectControlTransfer, ...]
    indirect_transfers: tuple[IndirectControlTransfer, ...]
    selected_flows: tuple[SelectedFunctionFlow, ...]
    coverage_gaps: tuple[CoverageGap, ...]
    acknowledged_coverage_gaps: tuple[CoverageGapAcknowledgement, ...]
    direct_runtime_coverage_complete: bool
    direct_reference_gate_passed: bool
    indirect_target_closure_proven: bool
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class _Section:
    name: str
    rva: int
    virtual_size: int
    raw: bytes
    characteristics: int

    @property
    def mapped_end(self) -> int:
        return self.rva + max(self.virtual_size, len(self.raw))

    @property
    def raw_end(self) -> int:
        return self.rva + len(self.raw)


@dataclass(frozen=True)
class _RuntimeDecode:
    begin_rva: int
    end_rva: int
    instructions: tuple[Any, ...]
    starts: frozenset[int]


def _validate_range(rva: int, size: int, label: str) -> None:
    if type(rva) is not int or type(size) is not int:
        raise DirectControlFlowError(f"{label} RVA and size must be integers")
    end = rva + size
    if rva <= 0 or size <= 0 or end > _RVA_LIMIT:
        raise DirectControlFlowError(
            f"{label} has invalid RVA range 0x{rva:X}+0x{size:X}"
        )


def _normalize_sections(parsed: Any) -> tuple[_Section, ...]:
    try:
        source = tuple(parsed.sections)
    except (AttributeError, TypeError) as exc:
        raise DirectControlFlowError("ParsedPE sections are required") from exc
    if not source:
        raise DirectControlFlowError("ParsedPE must contain sections")

    sections = []
    for item in source:
        try:
            name = item.name
            rva = item.rva
            virtual_size = item.virtual_size
            raw = item.raw
            characteristics = item.characteristics
        except AttributeError as exc:
            raise DirectControlFlowError("invalid ParsedPE section record") from exc
        if (
            not isinstance(name, str)
            or type(rva) is not int
            or type(virtual_size) is not int
            or not isinstance(raw, (bytes, bytearray, memoryview))
            or type(characteristics) is not int
        ):
            raise DirectControlFlowError("invalid ParsedPE section record")
        try:
            section = _Section(
                name=name,
                rva=rva,
                virtual_size=virtual_size,
                raw=bytes(raw),
                characteristics=characteristics,
            )
        except (TypeError, ValueError) as exc:
            raise DirectControlFlowError("invalid ParsedPE section record") from exc
        if section.virtual_size < 0:
            raise DirectControlFlowError(
                f"section {section.name!r} has negative virtual size"
            )
        _validate_range(
            section.rva,
            max(section.virtual_size, len(section.raw)),
            f"section {section.name!r}",
        )
        sections.append(section)
    sections.sort(key=lambda item: item.rva)
    for previous, current in zip(sections, sections[1:]):
        if current.rva < previous.mapped_end:
            raise DirectControlFlowError(
                f"sections {previous.name!r} and {current.name!r} overlap"
            )
    return tuple(sections)


def _normalize_selected(specs: Sequence[Any]) -> tuple[SelectedFunctionRange, ...]:
    if not specs:
        raise DirectControlFlowError("at least one selected function is required")
    normalized = []
    for spec in specs:
        try:
            name = spec.name
            rva = spec.rva
            size = spec.size
        except AttributeError as exc:
            raise DirectControlFlowError("invalid selected function record") from exc
        if (
            not isinstance(name, str)
            or type(rva) is not int
            or type(size) is not int
        ):
            raise DirectControlFlowError("invalid selected function record")
        try:
            selected = SelectedFunctionRange(
                name=name,
                rva=rva,
                size=size,
            )
        except (TypeError, ValueError) as exc:
            raise DirectControlFlowError("invalid selected function record") from exc
        if not selected.name or len(selected.name) > 128 or "\0" in selected.name:
            raise DirectControlFlowError(
                "selected function name must be 1..128 non-NUL characters"
            )
        _validate_range(selected.rva, selected.size, f"function {selected.name!r}")
        normalized.append(selected)
    normalized.sort(key=lambda item: (item.rva, item.size, item.name))
    for previous, current in zip(normalized, normalized[1:]):
        if current.rva < previous.end_rva:
            raise DirectControlFlowError(
                f"selected functions {previous.name!r} and {current.name!r} overlap"
            )
    return tuple(normalized)


def _normalize_runtime_functions(parsed: Any) -> tuple[tuple[int, int], ...]:
    try:
        source = tuple(parsed.runtime_functions)
    except (AttributeError, TypeError) as exc:
        raise DirectControlFlowError(
            "ParsedPE runtime_functions inventory is required"
        ) from exc
    ranges = []
    for item in source:
        try:
            begin = item.begin_rva
            end = item.end_rva
        except AttributeError as exc:
            raise DirectControlFlowError("invalid runtime-function record") from exc
        if type(begin) is not int or type(end) is not int:
            raise DirectControlFlowError("invalid runtime-function record")
        _validate_range(begin, end - begin, "runtime function")
        ranges.append((begin, end))
    ranges.sort()
    for previous, current in zip(ranges, ranges[1:]):
        if current[0] < previous[1]:
            raise DirectControlFlowError("runtime-function ranges overlap")
    return tuple(ranges)


def _read_executable(
    sections: Sequence[_Section], rva: int, size: int, label: str
) -> bytes:
    end = rva + size
    owner = next(
        (
            section
            for section in sections
            if section.rva <= rva and end <= section.mapped_end
        ),
        None,
    )
    if owner is None:
        raise DirectControlFlowError(
            f"{label} is not wholly contained in one section"
        )
    if not owner.characteristics & IMAGE_SCN_MEM_EXECUTE:
        raise DirectControlFlowError(
            f"{label} is in non-executable section {owner.name!r}"
        )
    if end > owner.raw_end:
        raise DirectControlFlowError(
            f"{label} reaches non-file-backed bytes in section {owner.name!r}"
        )
    offset = rva - owner.rva
    result = owner.raw[offset : offset + size]
    if len(result) != size:
        raise DirectControlFlowError(f"{label} read was truncated")
    return result


def _decode_runtime(
    sections: Sequence[_Section], begin: int, end: int
) -> _RuntimeDecode:
    code = _read_executable(
        sections, begin, end - begin, f"runtime function 0x{begin:X}"
    )
    instructions = tuple(Decoder(64, code, ip=begin))
    if not instructions:
        raise DirectControlFlowError(
            f"runtime function 0x{begin:X} contains no instructions"
        )
    cursor = begin
    starts = set()
    for instruction in instructions:
        if instruction.ip != cursor or instruction.code == 0 or instruction.len <= 0:
            raise DirectControlFlowError(
                f"undecodable runtime function at RVA 0x{cursor:X}"
            )
        starts.add(instruction.ip)
        cursor += instruction.len
    if cursor != end:
        raise DirectControlFlowError(
            f"runtime function 0x{begin:X} decoder consumed 0x{cursor - begin:X} "
            f"bytes, expected 0x{end - begin:X}"
        )
    return _RuntimeDecode(begin, end, instructions, frozenset(starts))


def _selected_owner(
    selected: Sequence[SelectedFunctionRange], rva: int
) -> SelectedFunctionRange | None:
    return next((item for item in selected if item.rva <= rva < item.end_rva), None)


def _direct_kind(instruction: Any) -> str | None:
    flow = instruction.flow_control
    if flow == FlowControl.CALL:
        return "call"
    if flow == FlowControl.UNCONDITIONAL_BRANCH:
        return "jump"
    if flow == FlowControl.CONDITIONAL_BRANCH:
        return (
            "loop"
            if instruction.mnemonic in _LOOP_MNEMONICS
            else "conditional_jump"
        )
    return None


def _direct_target(instruction: Any, kind: str) -> int:
    if instruction.op_count < 1 or instruction.op_kind(0) not in _NEAR_BRANCH_KINDS:
        raise DirectControlFlowError(
            f"unsupported non-near direct {kind} at RVA 0x{instruction.ip:X}"
        )
    target = int(instruction.near_branch_target)
    _validate_range(target, 1, f"direct {kind} target")
    return target


def _compute_coverage_gaps(
    sections: Sequence[_Section], runtime_ranges: Sequence[tuple[int, int]]
) -> tuple[CoverageGap, ...]:
    gaps = []
    for section in sections:
        if not section.characteristics & IMAGE_SCN_MEM_EXECUTE or not section.raw:
            continue
        start = section.rva
        end = section.mapped_end
        covered = []
        for begin, finish in runtime_ranges:
            overlap_start = max(start, begin)
            overlap_end = min(end, finish)
            if overlap_start < overlap_end:
                covered.append((overlap_start, overlap_end))
        cursor = start
        for begin, finish in covered:
            if cursor < begin:
                gaps.append(CoverageGap(cursor, begin - cursor, section.name))
            cursor = max(cursor, finish)
        if cursor < end:
            gaps.append(CoverageGap(cursor, end - cursor, section.name))
    return tuple(gaps)


def _validate_acknowledgements(
    gaps: Sequence[CoverageGap],
    acknowledgements: Sequence[CoverageGapAcknowledgement],
) -> tuple[CoverageGapAcknowledgement, ...]:
    normalized = []
    identities = set()
    for acknowledgement in acknowledgements:
        if not isinstance(acknowledgement, CoverageGapAcknowledgement):
            raise DirectControlFlowError(
                "coverage acknowledgements must be CoverageGapAcknowledgement"
            )
        _validate_range(
            acknowledgement.rva,
            acknowledgement.size,
            "coverage acknowledgement",
        )
        if (
            not isinstance(acknowledgement.rationale, str)
            or not acknowledgement.rationale.strip()
            or "\0" in acknowledgement.rationale
        ):
            raise DirectControlFlowError(
                "coverage acknowledgement requires a non-NUL rationale"
            )
        identity = (acknowledgement.rva, acknowledgement.size)
        if identity in identities:
            raise DirectControlFlowError("duplicate coverage acknowledgement")
        identities.add(identity)
        normalized.append(acknowledgement)
    gap_identities = {(gap.rva, gap.size) for gap in gaps}
    stale = identities - gap_identities
    if stale:
        rva, size = sorted(stale)[0]
        raise DirectControlFlowError(
            f"coverage acknowledgement 0x{rva:X}+0x{size:X} does not match an exact gap"
        )
    return tuple(sorted(normalized))


def _reachable_selected(
    spec: SelectedFunctionRange,
    decoded: _RuntimeDecode,
    policy: TailExitPolicy,
    decoded_entries: frozenset[int],
) -> tuple[frozenset[int], tuple[TailExitApproval, ...]]:
    instruction_by_rva = {instruction.ip: instruction for instruction in decoded.instructions}
    pending = [spec.rva]
    reachable = set()
    used_approvals = []
    approval_by_edge = {
        (item.function_rva, item.instruction_rva, item.target_rva): item
        for item in policy.approvals
    }

    def enqueue_fallthrough(instruction: Any) -> None:
        next_rva = instruction.ip + instruction.len
        if next_rva >= spec.end_rva:
            raise DirectControlFlowError(
                f"selected function {spec.name!r} has reachable fallthrough "
                f"outside its extent at RVA 0x{instruction.ip:X}"
            )
        pending.append(next_rva)

    while pending:
        rva = pending.pop()
        if rva in reachable:
            continue
        instruction = instruction_by_rva.get(rva)
        if instruction is None:
            raise DirectControlFlowError(
                f"selected function {spec.name!r} reaches non-instruction RVA 0x{rva:X}"
            )
        reachable.add(rva)
        flow = instruction.flow_control
        kind = _direct_kind(instruction)
        if kind == "call":
            target = _direct_target(instruction, kind)
            if spec.rva <= target < spec.end_rva:
                pending.append(target)
            enqueue_fallthrough(instruction)
        elif kind == "jump":
            target = _direct_target(instruction, kind)
            if spec.rva <= target < spec.end_rva:
                pending.append(target)
                continue
            approval = approval_by_edge.get((spec.rva, instruction.ip, target))
            if approval is None:
                raise DirectControlFlowError(
                    f"selected function {spec.name!r} has unapproved direct tail exit "
                    f"at RVA 0x{instruction.ip:X} to RVA 0x{target:X}"
                )
            if target not in decoded_entries:
                raise DirectControlFlowError(
                    f"approved tail exit for {spec.name!r} does not target a known "
                    "decoded range entry"
                )
            used_approvals.append(approval)
        elif kind in {"conditional_jump", "loop"}:
            target = _direct_target(instruction, kind)
            if not spec.rva <= target < spec.end_rva:
                raise DirectControlFlowError(
                    f"selected function {spec.name!r} has reachable {kind} exit "
                    f"at RVA 0x{instruction.ip:X} to RVA 0x{target:X}"
                )
            pending.append(target)
            enqueue_fallthrough(instruction)
        elif flow == FlowControl.INDIRECT_CALL:
            enqueue_fallthrough(instruction)
        elif flow == FlowControl.INDIRECT_BRANCH:
            pass
        elif flow == FlowControl.RETURN:
            pass
        elif flow == FlowControl.NEXT:
            enqueue_fallthrough(instruction)
        elif flow in {FlowControl.EXCEPTION, FlowControl.INTERRUPT}:
            pass
        else:
            raise DirectControlFlowError(
                f"selected function {spec.name!r} uses unsupported control flow "
                f"at RVA 0x{instruction.ip:X}"
            )
    return frozenset(reachable), tuple(sorted(set(used_approvals)))


def _validate_direct_targets(
    decodes: Sequence[_RuntimeDecode],
    selected: Sequence[SelectedFunctionRange],
) -> None:
    """Reject every decoded direct edge that violates entry boundaries."""

    all_instruction_starts = {
        instruction.ip
        for decoded in decodes
        for instruction in decoded.instructions
    }
    for decoded in decodes:
        for instruction in decoded.instructions:
            kind = _direct_kind(instruction)
            if kind is None:
                continue
            target = _direct_target(instruction, kind)
            source_selected = _selected_owner(selected, instruction.ip)
            target_selected = _selected_owner(selected, target)
            same_selected = (
                source_selected is not None
                and target_selected is not None
                and source_selected.rva == target_selected.rva
            )
            if (
                target_selected is not None
                and target != target_selected.rva
                and not same_selected
            ):
                raise DirectControlFlowError(
                    f"direct {kind} at RVA 0x{instruction.ip:X} enters selected "
                    f"function {target_selected.name!r} at interior RVA 0x{target:X}"
                )
            target_runtime = next(
                (
                    item
                    for item in decodes
                    if item.begin_rva <= target < item.end_rva
                ),
                None,
            )
            if target_runtime is not None and target not in all_instruction_starts:
                raise DirectControlFlowError(
                    f"direct {kind} at RVA 0x{instruction.ip:X} targets "
                    f"non-instruction RVA 0x{target:X}"
                )


def analyze_direct_control_flow(
    parsed: Any,
    selected_specs: Sequence[Any],
    *,
    tail_exit_policy: TailExitPolicy = TailExitPolicy(),
    coverage_acknowledgements: Sequence[CoverageGapAcknowledgement] = (),
    production: bool = True,
) -> DirectControlFlowProof:
    """Analyze direct x64 transfers that could bypass selected entry patches.

    ``selected_specs`` accepts :class:`SelectedFunctionRange` or structural
    records such as ``virtualization_plan.FunctionSpec``.  Production mode
    rejects unacknowledged executable coverage gaps.  Exact acknowledgements
    waive that gate but remain visible and never turn coverage into a proof.
    """

    if not isinstance(tail_exit_policy, TailExitPolicy):
        raise DirectControlFlowError("tail_exit_policy must be TailExitPolicy")
    sections = _normalize_sections(parsed)
    selected = _normalize_selected(selected_specs)
    runtime_ranges = _normalize_runtime_functions(parsed)

    exact_runtime = set(runtime_ranges)
    for spec in selected:
        selected_range = (spec.rva, spec.end_rva)
        if selected_range in exact_runtime:
            continue
        for begin, end in runtime_ranges:
            if begin < spec.end_rva and spec.rva < end:
                raise DirectControlFlowError(
                    f"selected function {spec.name!r} partially overlaps runtime "
                    f"function 0x{begin:X}..0x{end:X}"
                )

    runtime_decodes = tuple(
        _decode_runtime(sections, begin, end) for begin, end in runtime_ranges
    )
    extra_selected_ranges = tuple(
        (spec.rva, spec.end_rva)
        for spec in selected
        if (spec.rva, spec.end_rva) not in exact_runtime
    )
    selected_decodes = tuple(
        _decode_runtime(sections, begin, end)
        for begin, end in extra_selected_ranges
    )
    decodes = tuple(
        sorted((*runtime_decodes, *selected_decodes), key=lambda item: item.begin_rva)
    )
    _validate_direct_targets(decodes, selected)
    decoded_by_begin = {item.begin_rva: item for item in decodes}
    decoded_entries = frozenset(decoded_by_begin)
    selected_reachable = {}
    selected_flows = []
    used_approvals = set()
    for spec in selected:
        reachable, approvals = _reachable_selected(
            spec, decoded_by_begin[spec.rva], tail_exit_policy, decoded_entries
        )
        selected_reachable[spec.rva] = reachable
        used_approvals.update(approvals)
        selected_flows.append(
            SelectedFunctionFlow(
                spec.name,
                spec.rva,
                spec.size,
                tuple(sorted(reachable)),
                approvals,
            )
        )
    stale_approvals = set(tail_exit_policy.approvals) - used_approvals
    if stale_approvals:
        stale = sorted(stale_approvals)[0]
        raise DirectControlFlowError(
            f"tail-exit approval at RVA 0x{stale.instruction_rva:X} was not "
            "consumed by a reachable exact edge"
        )

    direct = []
    indirect = []
    runtime_range_set = set(runtime_ranges)
    for decoded in decodes:
        for instruction in decoded.instructions:
            source_selected = _selected_owner(selected, instruction.ip)
            reachable = bool(
                source_selected
                and instruction.ip in selected_reachable[source_selected.rva]
            )
            kind = _direct_kind(instruction)
            if kind is not None:
                target = _direct_target(instruction, kind)
                target_selected = _selected_owner(selected, target)
                direct.append(
                    DirectControlTransfer(
                        source_rva=instruction.ip,
                        source_range_begin_rva=decoded.begin_rva,
                        source_has_runtime_function=(
                            (decoded.begin_rva, decoded.end_rva)
                            in runtime_range_set
                        ),
                        kind=kind,
                        target_rva=target,
                        source_selected_name=(
                            source_selected.name if source_selected else None
                        ),
                        target_selected_name=(
                            target_selected.name if target_selected else None
                        ),
                        target_is_selected_entry=bool(
                            target_selected and target == target_selected.rva
                        ),
                        reachable_from_selected_entry=reachable,
                    )
                )
            elif instruction.flow_control in {
                FlowControl.INDIRECT_CALL,
                FlowControl.INDIRECT_BRANCH,
            }:
                indirect.append(
                    IndirectControlTransfer(
                        source_rva=instruction.ip,
                        source_range_begin_rva=decoded.begin_rva,
                        source_has_runtime_function=(
                            (decoded.begin_rva, decoded.end_rva)
                            in runtime_range_set
                        ),
                        kind=(
                            "indirect_call"
                            if instruction.flow_control == FlowControl.INDIRECT_CALL
                            else "indirect_jump"
                        ),
                        source_selected_name=(
                            source_selected.name if source_selected else None
                        ),
                        reachable_from_selected_entry=reachable,
                    )
                )

    decoded_ranges = tuple(
        (item.begin_rva, item.end_rva) for item in decodes
    )
    gaps = _compute_coverage_gaps(sections, decoded_ranges)
    acknowledgements = _validate_acknowledgements(
        gaps, coverage_acknowledgements
    )
    acknowledged_ids = {(item.rva, item.size) for item in acknowledgements}
    unacknowledged = tuple(
        gap for gap in gaps if (gap.rva, gap.size) not in acknowledged_ids
    )
    if production and unacknowledged:
        first = unacknowledged[0]
        raise CoverageGapError(
            unacknowledged,
            f"production direct-control analysis has unacknowledged executable "
            f"coverage gap 0x{first.rva:X}+0x{first.size:X}",
        )

    limitations = [_INDIRECT_LIMITATION]
    if gaps:
        limitations.append(_COVERAGE_LIMITATION)
    return DirectControlFlowProof(
        version=PROOF_VERSION,
        selected_functions=selected,
        decoded_runtime_functions=tuple(
            DecodedRuntimeFunction(
                item.begin_rva, item.end_rva, len(item.instructions)
            )
            for item in runtime_decodes
        ),
        direct_transfers=tuple(direct),
        indirect_transfers=tuple(indirect),
        selected_flows=tuple(selected_flows),
        coverage_gaps=gaps,
        acknowledged_coverage_gaps=acknowledgements,
        direct_runtime_coverage_complete=not gaps,
        direct_reference_gate_passed=not unacknowledged,
        indirect_target_closure_proven=False,
        limitations=tuple(limitations),
    )


__all__ = [
    "CoverageGap",
    "CoverageGapAcknowledgement",
    "CoverageGapError",
    "DecodedRuntimeFunction",
    "DirectControlFlowError",
    "DirectControlFlowProof",
    "DirectControlTransfer",
    "IndirectControlTransfer",
    "SelectedFunctionFlow",
    "SelectedFunctionRange",
    "TailExitApproval",
    "TailExitPolicy",
    "analyze_direct_control_flow",
]
