"""Exact-PDB-bound executable coverage for conservative direct-flow proof.

Only DIA function extents bound to the PE RSDS record and four fixed byte
forms may supplement PDATA: INT3 padding, one compiler NOP10, exact normal-IAT
FF25 jumps, and one this-adjustor form jumping to a proven function entry.
Every admitted byte is also strictly decoded by direct_control_flow; this
module never acknowledges an arbitrary executable gap.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, fields, is_dataclass, replace
from hashlib import sha256
from pathlib import Path
import re
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
    source_parsed_sha256: str


@dataclass(frozen=True)
class PdbCommitBinding:
    """Immutable preflight facts that the materializer must recheck at commit."""

    image_sha256: str
    pdb_sha256: str
    helper_sha256: str
    msdia_sha256: str
    source_parsed_sha256: str
    selected_functions: tuple[tuple[str, int, int, int], ...]
    supplemental_ranges: tuple[tuple[int, int], ...]
    tail_exit_policy: direct_control_flow.TailExitPolicy
    direct_flow: direct_control_flow.DirectControlFlowProof
    binding_sha256: str


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def parsed_source_sha256(parsed: Any) -> str:
    """Pin every parsed source field, including nonselected bytes and metadata."""
    digest = sha256()

    def feed(value: Any) -> None:
        if value is None:
            digest.update(b"N")
        elif type(value) is bool:
            digest.update(b"B1" if value else b"B0")
        elif type(value) is int:
            data = str(value).encode("ascii")
            digest.update(b"I" + len(data).to_bytes(8, "little") + data)
        elif type(value) is str:
            data = value.encode("utf-8")
            digest.update(b"S" + len(data).to_bytes(8, "little") + data)
        elif type(value) is bytes:
            digest.update(b"Y" + len(value).to_bytes(8, "little") + value)
        elif isinstance(value, (list, tuple)):
            digest.update(b"L" if isinstance(value, list) else b"T")
            digest.update(len(value).to_bytes(8, "little"))
            for item in value:
                feed(item)
        elif is_dataclass(value) and not isinstance(value, type):
            members = tuple((item.name, getattr(value, item.name)) for item in fields(value))
            feed((type(value).__module__, type(value).__qualname__, members))
        elif type(value).__name__ == "SimpleNamespace" and type(value).__module__ == "types":
            feed(tuple(sorted(vars(value).items())))
        else:
            raise PdbCoverageError("source PE contains an unsupported field type")

    feed(parsed)
    return digest.hexdigest()


def _image_sha256(parsed: Any) -> str:
    try:
        path = Path(parsed.path)
        digest = sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (AttributeError, TypeError, ValueError, OSError) as exc:
        raise PdbCoverageError("PDB source image is unavailable at commit") from exc


def _selected_identity(selected: Sequence[Any]) -> tuple[tuple[str, int, int, int], ...]:
    try:
        normalized = direct_control_flow._normalize_selected(selected)
    except direct_control_flow.DirectControlFlowError as exc:
        raise PdbCoverageError(str(exc)) from exc
    return tuple((item.name, item.rva, item.size, item.body_size) for item in normalized)


def _binding_sha256(binding: PdbCommitBinding) -> str:
    return parsed_source_sha256((
        binding.image_sha256, binding.pdb_sha256,
        binding.helper_sha256, binding.msdia_sha256,
        binding.source_parsed_sha256, binding.selected_functions,
        binding.supplemental_ranges, binding.tail_exit_policy,
        binding.direct_flow,
    ))


def bind_pdb_commit_proof(
    parsed: Any, proof: PdbCoverageProof, selected_specs: Sequence[Any]
) -> PdbCommitBinding:
    """Bind a completed exact-PDB proof to its unchanged parsed/file source."""
    if not isinstance(proof, PdbCoverageProof):
        raise PdbCoverageError("PDB materialization requires a bound coverage proof")
    inventory = proof.inventory
    digests = (
        inventory.image_sha256, inventory.pdb_sha256,
        inventory.helper_sha256, inventory.msdia_sha256,
        proof.source_parsed_sha256,
    )
    if any(type(item) is not str or not _SHA256.fullmatch(item) for item in digests):
        raise PdbCoverageError("PDB commit proof has invalid source digests")
    if _image_sha256(parsed) != inventory.image_sha256:
        raise PdbCoverageError("PDB source image changed after preflight")
    if parsed_source_sha256(parsed) != proof.source_parsed_sha256:
        raise PdbCoverageError("PDB parsed source changed after preflight")
    selected = _selected_identity(selected_specs)
    if selected != _selected_identity(proof.direct_flow.selected_functions):
        raise PdbCoverageError("PDB selected functions differ from the proof")
    ranges = tuple(
        (item.begin_rva, item.end_rva)
        for item in proof.direct_flow.decoded_supplemental_ranges
    )
    if proof.direct_flow.coverage_gaps or not proof.direct_flow.direct_reference_gate_passed:
        raise PdbCoverageError("PDB direct-reference proof is incomplete")
    approvals = tuple(sorted({
        approval
        for item in proof.direct_flow.selected_flows
        for approval in item.approved_tail_exits
    }, key=lambda item: (item.function_rva, item.instruction_rva, item.target_rva)))
    binding = PdbCommitBinding(
        *digests, selected, ranges,
        direct_control_flow.TailExitPolicy(approvals), proof.direct_flow, "",
    )
    binding = replace(binding, binding_sha256=_binding_sha256(binding))
    validate_pdb_commit_binding(parsed, selected_specs, binding)
    return binding


def validate_pdb_commit_binding(
    parsed: Any, selected_specs: Sequence[Any], binding: PdbCommitBinding
) -> None:
    """Re-decode the exact supplemental ranges at low-level commit, fail closed."""
    if not isinstance(binding, PdbCommitBinding):
        raise PdbCoverageError("PDB commit binding is missing or malformed")
    if (
        type(binding.binding_sha256) is not str
        or not _SHA256.fullmatch(binding.binding_sha256)
        or binding.binding_sha256 != _binding_sha256(binding)
    ):
        raise PdbCoverageError("PDB commit binding changed after preflight")
    if (
        _selected_identity(selected_specs) != binding.selected_functions
        or _selected_identity(binding.direct_flow.selected_functions) != binding.selected_functions
    ):
        raise PdbCoverageError("PDB commit selected functions differ from preflight")
    if (
        tuple((item.begin_rva, item.end_rva)
              for item in binding.direct_flow.decoded_supplemental_ranges)
        != binding.supplemental_ranges
    ):
        raise PdbCoverageError("PDB supplemental ranges differ from preflight")
    if (
        _image_sha256(parsed) != binding.image_sha256
        or parsed_source_sha256(parsed) != binding.source_parsed_sha256
    ):
        raise PdbCoverageError("PDB source changed after preflight")
    try:
        replay = direct_control_flow.analyze_direct_control_flow(
            parsed,
            binding.direct_flow.selected_functions,
            tail_exit_policy=binding.tail_exit_policy,
            production=True,
            _supplemental_code_ranges=binding.supplemental_ranges,
        )
    except direct_control_flow.DirectControlFlowError as exc:
        raise PdbCoverageError(f"PDB commit direct-reference check failed: {exc}") from exc
    if replay != binding.direct_flow or not replay.direct_reference_gate_passed:
        raise PdbCoverageError("PDB commit direct-reference proof changed")


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
    _structured_entry_thunks: tuple[direct_control_flow._EntryThunkRange, ...] = (),
) -> PdbCoverageProof:
    """Prove direct-reference coverage without a handwritten gap waiver.

    This does not prove indirect/address-taken closure, native-call admission,
    materialization, or runtime behavior. Those remain independent gates.
    """
    bound = pdb_function_inventory.run_bound_inventory(
        parsed, image_path, pdb_path, helper_path, msdia_path
    )
    # Coverage uses distinct DIA extents, but selecting a PDB-only leaf needs
    # the raw function-symbol multiplicity. An ICF alias at the same RVA is not
    # proof that one named helper owns the machine-code entry exclusively.
    rows = bound.range_multiplicities
    if type(rows) is not tuple or type(bound.symbol_count) is not int:
        raise PdbCoverageError("PDB alias multiplicity inventory is malformed")
    spans = bound.distinct_ranges
    if type(spans) is not tuple or not spans:
        raise PdbCoverageError("PDB alias multiplicity inventory is malformed")
    previous_end = 0
    for span in spans:
        if (type(span) is not tuple or len(span) != 2
                or type(span[0]) is not int or type(span[1]) is not int
                or not 0 < span[0] < span[1] <= 0x1_0000_0000
                or span[0] < previous_end):
            raise PdbCoverageError("PDB alias multiplicity inventory is malformed")
        previous_end = span[1]
    if len(rows) != len(spans):
        raise PdbCoverageError("PDB alias multiplicity inventory is incomplete")
    total = 0
    by_span = {}
    for row, span in zip(rows, spans):
        if (type(row) is not tuple or len(row) != 3
                or type(row[0]) is not int or type(row[1]) is not int
                or type(row[2]) is not int or row[:2] != span
                or row[2] <= 0):
            raise PdbCoverageError("PDB alias multiplicity inventory is malformed")
        by_span[span] = row[2]
        total += row[2]
    if total != bound.symbol_count:
        raise PdbCoverageError("PDB alias multiplicity inventory is incomplete")
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
    try:
        selected = direct_control_flow._normalize_selected(selected_specs)
    except direct_control_flow.DirectControlFlowError as exc:
        raise PdbCoverageError(str(exc)) from exc
    # A PDB-only leaf selected for virtualization is already strictly decoded
    # as a selected source extent by analyze_direct_control_flow. Keep its
    # exact PDB span in `known` for coverage and edge-entry classification,
    # but do not submit it a second time as supplemental code. This exception
    # is PDB-bound; raw supplements and every partial overlap still reject.
    pdb_occurrences = Counter(bound.supplemental_ranges)
    exact_pdb_leaves = {
        (item.rva, item.end_rva)
        for item in selected
        if pdb_occurrences[(item.rva, item.end_rva)]
        and all(end <= item.rva or begin >= item.end_rva for begin, end in pdata)
    }
    for span in exact_pdb_leaves:
        if pdb_occurrences[span] == 1 and by_span.get(span) != 1:
            raise PdbCoverageError(
                f"selected leaf 0x{span[0]:X} has an aliased PDB function range"
            )
    selected_pdb_leaves = {
        span for span in exact_pdb_leaves if pdb_occurrences[span] == 1
    }
    supplement = tuple(sorted((
        *(span for span in bound.supplemental_ranges if span not in selected_pdb_leaves),
        *((g.rva, g.end_rva) for g in gaps),
    )))
    try:
        proof = direct_control_flow.analyze_direct_control_flow(
            parsed,
            selected_specs,
            tail_exit_policy=tail_exit_policy,
            production=True,
            _supplemental_code_ranges=supplement,
            _structured_entry_thunks=_structured_entry_thunks,
        )
    except direct_control_flow.DirectControlFlowError as exc:
        raise PdbCoverageError(str(exc)) from exc
    if proof.coverage_gaps or not proof.direct_reference_gate_passed:
        raise PdbCoverageError("PDB-bound executable coverage remains incomplete")
    return PdbCoverageProof(bound, gaps, tokens, proof, parsed_source_sha256(parsed))
