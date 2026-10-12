"""Exact-PDB-bound executable coverage for conservative direct-flow proof.

Only DIA function extents bound to the PE RSDS record and four fixed byte
forms may supplement PDATA: INT3 padding, one compiler NOP10, exact normal-IAT
FF25 jumps, and one this-adjustor form jumping to a proven function entry.
Every admitted byte is also strictly decoded by direct_control_flow; this
module never acknowledges an arbitrary executable gap.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from . import direct_control_flow, native_tail_calls, pdb_function_inventory


_NOP10 = bytes.fromhex("66660F1F840000000000")
_ADJUSTOR = bytes.fromhex("4883E910E9")
_DISCARDABLE = 0x02000000


class PdbCoverageError(ValueError):
    """A source-bound executable byte or direct edge remains unproven."""


@dataclass(frozen=True)
class CanonicalCodeToken:
    rva: int
    size: int
    kind: str
    target_rva: int | None = None


@dataclass(frozen=True)
class PdbCoverageProof:
    inventory: pdb_function_inventory.BoundPdbInventory
    residual_ranges: tuple[direct_control_flow.CoverageGap, ...]
    tokens: tuple[CanonicalCodeToken, ...]
    direct_flow: direct_control_flow.DirectControlFlowProof


def _source_iat_slots(parsed: Any) -> frozenset[int]:
    try:
        entries = tuple(
            function.iat_rva
            for dll in parsed.imports
            for function in dll.funcs
        )
    except (AttributeError, TypeError) as exc:
        raise PdbCoverageError("source import inventory is malformed") from exc
    try:
        return native_tail_calls.validated_import_iat_rvas(entries)
    except ValueError as exc:
        raise PdbCoverageError(str(exc)) from exc


def _classify_residual(
    sections: Sequence[Any],
    gaps: Sequence[direct_control_flow.CoverageGap],
    function_entries: frozenset[int],
    import_slots: frozenset[int],
) -> tuple[CanonicalCodeToken, ...]:
    tokens = []
    for gap in gaps:
        owner = next(
            (
                section for section in sections
                if section.rva <= gap.rva
                and gap.end_rva <= section.mapped_end
            ),
            None,
        )
        if owner is None or owner.characteristics & _DISCARDABLE:
            raise PdbCoverageError(
                f"residual 0x{gap.rva:X}+0x{gap.size:X} is not retained"
            )
        try:
            code = direct_control_flow._read_executable(
                sections, gap.rva, gap.size, "PDB residual"
            )
        except direct_control_flow.DirectControlFlowError as exc:
            raise PdbCoverageError(str(exc)) from exc
        offset = 0
        while offset < len(code):
            rva = gap.rva + offset
            remain = len(code) - offset
            if remain >= 6 and code[offset:offset + 2] == b"\xFF\x25":
                displacement = int.from_bytes(
                    code[offset + 2:offset + 6], "little", signed=True
                )
                slot = rva + 6 + displacement
                if (
                    slot not in import_slots
                    or native_tail_calls._read(
                        sections, slot, 8, executable=False
                    ) is None
                ):
                    raise PdbCoverageError(
                        f"unproven FF25 import slot at RVA 0x{rva:X}"
                    )
                tokens.append(CanonicalCodeToken(rva, 6, "exact_import_jump", slot))
                offset += 6
                continue
            if remain >= 9 and code[offset:offset + 5] == _ADJUSTOR:
                displacement = int.from_bytes(
                    code[offset + 5:offset + 9], "little", signed=True
                )
                target = rva + 9 + displacement
                if target not in function_entries:
                    raise PdbCoverageError(
                        f"this-adjustor at RVA 0x{rva:X} misses a function entry"
                    )
                tokens.append(CanonicalCodeToken(rva, 9, "this_adjustor", target))
                offset += 9
                continue
            if remain >= 10 and code[offset:offset + 10] == _NOP10:
                tokens.append(CanonicalCodeToken(rva, 10, "canonical_nop10"))
                offset += 10
                continue
            if code[offset] == 0xCC:
                tokens.append(CanonicalCodeToken(rva, 1, "int3_padding"))
                offset += 1
                continue
            raise PdbCoverageError(
                f"unclassified executable byte at RVA 0x{rva:X}: "
                f"0x{code[offset]:02X}"
            )
    return tuple(tokens)


def prove_pdb_executable_coverage(
    parsed: Any,
    image_path: Path,
    pdb_path: Path,
    helper_path: Path,
    msdia_path: Path,
    selected_specs: Sequence[Any],
    *,
    tail_exit_policy: direct_control_flow.TailExitPolicy = direct_control_flow.TailExitPolicy(),
) -> PdbCoverageProof:
    """Prove direct-reference coverage without a handwritten gap waiver.

    This does not prove indirect/address-taken closure, native-call admission,
    materialization, or runtime behavior. Those remain independent gates.
    """
    bound = pdb_function_inventory.run_bound_inventory(
        parsed, image_path, pdb_path, helper_path, msdia_path
    )
    sections = direct_control_flow._normalize_sections(parsed)
    for begin, end in bound.supplemental_ranges:
        owner = next(
            (section for section in sections
             if section.rva <= begin and end <= section.mapped_end),
            None,
        )
        if owner is None or owner.characteristics & _DISCARDABLE:
            raise PdbCoverageError(
                f"PDB function 0x{begin:X}..0x{end:X} is not retained"
            )
    pdata = direct_control_flow._normalize_runtime_functions(parsed)
    known = tuple(sorted((*pdata, *bound.supplemental_ranges)))
    gaps = direct_control_flow._compute_coverage_gaps(sections, known)
    slots = _source_iat_slots(parsed)
    entries = frozenset(begin for begin, _ in known)
    tokens = _classify_residual(sections, gaps, entries, slots)
    supplement = tuple(sorted((*bound.supplemental_ranges, *((g.rva, g.end_rva) for g in gaps))))
    try:
        proof = direct_control_flow.analyze_direct_control_flow(
            parsed,
            selected_specs,
            tail_exit_policy=tail_exit_policy,
            production=True,
            _supplemental_code_ranges=supplement,
        )
    except direct_control_flow.DirectControlFlowError as exc:
        raise PdbCoverageError(str(exc)) from exc
    if proof.coverage_gaps or not proof.direct_reference_gate_passed:
        raise PdbCoverageError("PDB-bound executable coverage remains incomplete")
    return PdbCoverageProof(bound, gaps, tokens, proof)
