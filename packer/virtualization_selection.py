"""Canonical, source-bound selected-function virtualization manifests.

The report tool emits this evidence.  The packer treats it only as a requested
selection and set of acknowledgements: every source identity, function extent,
byte hash, runtime-function record, and read-only direct-reference verdict is
recomputed against the private source snapshot before the normal production
control-flow gate runs.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .pe_content_id import pe_content_id, snapshot_file


SCHEMA = "lethe.virtualization-selection"
LEGACY_VERSION = 2
VERSION = 3
MAX_MANIFEST_BYTES = 1024 * 1024
AMD64_MACHINE = 0x8664
_HEX = frozenset("0123456789abcdef")


class VirtualizationSelectionError(ValueError):
    """The selection manifest is malformed, stale, or fails current proof."""


@dataclass(frozen=True, order=True)
class SelectedFunction:
    name: str
    rva: int
    source_extent_size: int
    lifted_body_size: int | None = None

    @property
    def size(self) -> int:
        """Compatibility alias for version-2 callers."""
        return self.source_extent_size

    @property
    def body_size(self) -> int:
        return (
            self.source_extent_size
            if self.lifted_body_size is None
            else self.lifted_body_size
        )


@dataclass(frozen=True, order=True)
class GapAcknowledgement:
    rva: int
    size: int
    rationale: str


@dataclass(frozen=True, order=True)
class TailExitApproval:
    function_rva: int
    instruction_rva: int
    target_rva: int
    rationale: str


@dataclass(frozen=True)
class VerifiedSelection:
    functions: tuple[SelectedFunction, ...]
    gaps: tuple[GapAcknowledgement, ...]
    tail_exits: tuple[TailExitApproval, ...]
    acknowledge_unproven_indirect_targets: bool


def canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ) + "\n").encode("ascii")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VirtualizationSelectionError(
                f"selection manifest contains duplicate field {key!r}")
        result[key] = value
    return result


def _parse_canonical(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise VirtualizationSelectionError(
            "selection manifest is empty or exceeds the 1 MiB limit")
    try:
        text = raw.decode("ascii")
        def parse_integer(token: str) -> int:
            if len(token.lstrip("-")) > 20:
                raise VirtualizationSelectionError(
                    "selection manifest integer token is too large")
            return int(token)

        def reject_float(token: str) -> float:
            raise VirtualizationSelectionError(
                f"selection manifest contains non-integer number {token}")

        value = json.loads(
            text, object_pairs_hook=_pairs,
            parse_int=parse_integer,
            parse_float=reject_float,
            parse_constant=lambda token: (_ for _ in ()).throw(
                VirtualizationSelectionError(
                    f"selection manifest contains invalid number {token}")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise VirtualizationSelectionError(
            f"selection manifest is not canonical JSON: {exc}") from exc
    if type(value) is not dict:
        raise VirtualizationSelectionError("selection manifest root must be an object")
    if canonical_json(value) != raw:
        raise VirtualizationSelectionError(
            "selection manifest JSON is not in the canonical encoding")
    return value


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise VirtualizationSelectionError(f"{label} must be an object")
    actual = set(value)
    if actual != fields:
        unknown = sorted(actual - fields)
        missing = sorted(fields - actual)
        detail = []
        if unknown:
            detail.append("unknown=" + ",".join(unknown))
        if missing:
            detail.append("missing=" + ",".join(missing))
        raise VirtualizationSelectionError(
            f"{label} fields are not exact ({'; '.join(detail)})")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0,
             maximum: int = 0xFFFFFFFF) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise VirtualizationSelectionError(f"{label} is outside its integer range")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise VirtualizationSelectionError(f"{label} must be boolean")
    return value


def _string(value: Any, label: str, *, allow_empty: bool = False,
            maximum: int = 512) -> str:
    if (type(value) is not str or len(value) > maximum or "\0" in value
            or (not allow_empty and not value)):
        raise VirtualizationSelectionError(f"{label} is not a valid string")
    return value


def _digest(value: Any, label: str) -> str:
    value = _string(value, label, maximum=64)
    if len(value) != 64 or any(char not in _HEX for char in value):
        raise VirtualizationSelectionError(f"{label} must be lowercase SHA-256 hex")
    return value


def _list(value: Any, label: str, *, limit: int = 100000) -> list[Any]:
    if type(value) is not list or len(value) > limit:
        raise VirtualizationSelectionError(f"{label} must be a bounded array")
    return value


def _extent_bytes(parsed: Any, rva: int, size: int) -> bytes:
    end = rva + size
    if rva <= 0 or size < 5 or end > 0x1_0000_0000:
        raise VirtualizationSelectionError("selected source extent is invalid")
    owner = next((
        section for section in parsed.sections
        if section.rva <= rva and end <= section.rva + len(section.raw)
    ), None)
    if owner is None or not owner.characteristics & 0x20000000:
        raise VirtualizationSelectionError(
            "selected source extent is not fully file-backed executable data")
    offset = rva - owner.rva
    return bytes(owner.raw[offset:offset + size])


def _runtime_identity(parsed: Any, rva: int, size: int) -> dict[str, int]:
    matches = [
        (index, record) for index, record in enumerate(parsed.runtime_functions)
        if record.begin_rva == rva and record.end_rva == rva + size
    ]
    if len(matches) != 1:
        raise VirtualizationSelectionError(
            "selected extent does not have one exact runtime-function record")
    index, record = matches[0]
    return {
        "begin_rva": record.begin_rva,
        "end_rva": record.end_rva,
        "index": index,
        "unwind_flags": record.unwind_flags,
        "unwind_info_rva": record.unwind_info_rva,
    }


def build_manifest(
    report: Any,
    parsed: Any,
    *,
    source_sha256: str,
    source_pe_content_id: str,
) -> dict[str, Any]:
    """Build a deterministic, fail-closed starter manifest.

    Human decisions remain false/empty.  A caller must explicitly acknowledge
    every exact gap and the unproven indirect closure before the packer accepts
    the manifest.
    """
    source_sha256 = _digest(source_sha256, "source SHA-256")
    source_pe_content_id = _digest(
        source_pe_content_id, "source PE content identity")
    selected = []
    for item in report.candidates:
        if not (
            item.exact_extent
            and item.extent_kind == "runtime_function"
            and item.unwind_flags == 0
            and item.liftable
            and item.direct_control_proof_status == "passed"
        ):
            continue
        source_extent_size = item.size
        lifted_body_size = item.body_size
        original = _extent_bytes(parsed, item.rva, source_extent_size)
        selected.append((item, original, source_extent_size, lifted_body_size))

    # Version 2 remains the byte-for-byte equal-extent format.  A report that
    # contains any canonical padding trim is promoted as a unit to version 3,
    # avoiding mixed per-entry interpretation.
    version = (
        VERSION if any(body_size != source_size for _, _, source_size, body_size
                       in selected)
        else LEGACY_VERSION
    )
    selections = []
    for item, original, source_extent_size, lifted_body_size in selected:
        gaps = [{
            "acknowledged": False,
            "rationale": "",
            "rva": gap.rva,
            "section": gap.section_name,
            "size": gap.size,
        } for gap in item.executable_coverage_gaps]
        selection = {
            "coverage_gaps": gaps,
            "direct_reference_verdict": {
                "gate_passed": item.direct_reference_gate_passed,
                "status": item.direct_control_proof_status,
            },
            "indirect_target_closure": {
                "acknowledged": False,
                "proven": item.indirect_target_closure_proven,
            },
            "lifted_body_extent": {
                "rva": item.rva,
                "size": lifted_body_size,
            },
            "name": item.name,
            "runtime_function": _runtime_identity(
                parsed, item.rva, source_extent_size),
            "source_extent": {
                "rva": item.rva,
                "size": source_extent_size,
            },
            "tail_exit_approvals": [],
        }
        if version == LEGACY_VERSION:
            selection["original_bytes_sha256"] = hashlib.sha256(
                original).hexdigest()
        else:
            suffix_size = source_extent_size - lifted_body_size
            selection.update({
                "lifted_body_sha256": hashlib.sha256(
                    original[:lifted_body_size]).hexdigest(),
                "padding_proof": {
                    "canonical_body_size": lifted_body_size,
                    "source_extent_runtime_bound": True,
                    "status": "passed" if suffix_size else "not_applicable",
                    "suffix_rva": item.rva + lifted_body_size,
                    "suffix_size": suffix_size,
                },
                "source_extent_sha256": hashlib.sha256(original).hexdigest(),
            })
        selections.append(selection)
    selections.sort(key=lambda item: item["source_extent"]["rva"])
    return {
        "schema": SCHEMA,
        "selections": selections,
        "source": {
            "image_base": parsed.image_base,
            "machine": AMD64_MACHINE,
            "pe_content_id": source_pe_content_id,
            "pe_kind": "dll" if parsed.is_dll else "exe",
            "sha256": source_sha256,
            "size_of_image": parsed.size_of_image,
        },
        "version": version,
    }


def _load_bytes(path: str) -> bytes:
    if type(path) is not str or not path or "\0" in path:
        raise VirtualizationSelectionError("selection manifest path is invalid")
    try:
        return snapshot_file(
            Path(path), what="virtualization selection manifest",
            reject_hardlinks=True, max_bytes=MAX_MANIFEST_BYTES,
        ).data
    except (OSError, ValueError) as exc:
        raise VirtualizationSelectionError(str(exc)) from exc


def _verify_gap(value: Any, current: Any, label: str) -> GapAcknowledgement:
    item = _exact(value, {
        "acknowledged", "rationale", "rva", "section", "size",
    }, label)
    rva = _integer(item["rva"], f"{label}.rva", minimum=1)
    size = _integer(item["size"], f"{label}.size", minimum=1)
    section = _string(item["section"], f"{label}.section", maximum=8)
    acknowledged = _boolean(item["acknowledged"], f"{label}.acknowledged")
    rationale = _string(
        item["rationale"], f"{label}.rationale",
        allow_empty=not acknowledged, maximum=512,
    )
    if (rva, size, section) != (current.rva, current.size, current.section_name):
        raise VirtualizationSelectionError(
            f"{label} does not match the current executable coverage gap")
    if not acknowledged:
        raise VirtualizationSelectionError(f"{label} is not explicitly acknowledged")
    return GapAcknowledgement(rva, size, rationale)


def _verify_tail(value: Any, function_rva: int, label: str) -> TailExitApproval:
    item = _exact(value, {
        "function_rva", "instruction_rva", "rationale", "target_rva",
    }, label)
    bound = _integer(item["function_rva"], f"{label}.function_rva", minimum=1)
    if bound != function_rva:
        raise VirtualizationSelectionError(
            f"{label} is bound to a different selected function")
    return TailExitApproval(
        bound,
        _integer(item["instruction_rva"], f"{label}.instruction_rva", minimum=1),
        _integer(item["target_rva"], f"{label}.target_rva", minimum=1),
        _string(item["rationale"], f"{label}.rationale"),
    )


def _current_padding_proof(
    *, rva: int, source_extent_size: int, lifted_body_size: int,
    source_bytes: bytes,
) -> dict[str, Any]:
    """Recompute the canonical padding split; never trust report JSON alone."""
    if not 5 <= lifted_body_size <= source_extent_size:
        raise VirtualizationSelectionError(
            "selected lifted body is outside its source extent")
    try:
        from lifter import x64_lifter
    except ImportError as exc:
        raise VirtualizationSelectionError(
            f"cannot load the canonical padding verifier: {exc}") from exc
    try:
        current_body_size = x64_lifter.canonical_lifted_body_size(
            source_bytes, base=rva)
    except (ValueError, x64_lifter.LiftUnsupported) as exc:
        raise VirtualizationSelectionError(
            f"cannot reproduce selected padding proof: {exc}") from exc
    if current_body_size != lifted_body_size:
        raise VirtualizationSelectionError(
            "selected lifted body or canonical padding suffix changed")
    suffix_size = source_extent_size - lifted_body_size
    return {
        "canonical_body_size": lifted_body_size,
        "source_extent_runtime_bound": True,
        "status": "passed" if suffix_size else "not_applicable",
        "suffix_rva": rva + lifted_body_size,
        "suffix_size": suffix_size,
    }


def verify_manifest_bytes(
    raw: bytes,
    *,
    parsed: Any,
    report: Any,
    source_sha256: str,
    source_pe_content_id: str,
) -> VerifiedSelection:
    root = _exact(_parse_canonical(raw), {
        "schema", "selections", "source", "version",
    }, "selection manifest")
    _string(root["schema"], "selection manifest schema", maximum=64)
    version = _integer(
        root["version"], "selection manifest version",
        minimum=LEGACY_VERSION, maximum=VERSION)
    if root["schema"] != SCHEMA or version not in (LEGACY_VERSION, VERSION):
        raise VirtualizationSelectionError(
            "selection manifest schema/version is unsupported")
    source = _exact(root["source"], {
        "image_base", "machine", "pe_content_id", "pe_kind", "sha256",
        "size_of_image",
    }, "selection manifest source")
    _integer(source["image_base"], "selection manifest source.image_base",
             maximum=0xFFFFFFFFFFFFFFFF)
    _integer(source["machine"], "selection manifest source.machine")
    _digest(source["pe_content_id"], "selection manifest source.pe_content_id")
    _string(source["pe_kind"], "selection manifest source.pe_kind", maximum=3)
    _digest(source["sha256"], "selection manifest source.sha256")
    _integer(source["size_of_image"], "selection manifest source.size_of_image",
             minimum=1)
    expected_source = {
        "image_base": parsed.image_base,
        "machine": AMD64_MACHINE,
        "pe_content_id": _digest(
            source_pe_content_id, "current source PE content identity"),
        "pe_kind": "dll" if parsed.is_dll else "exe",
        "sha256": _digest(source_sha256, "current source SHA-256"),
        "size_of_image": parsed.size_of_image,
    }
    if source != expected_source:
        raise VirtualizationSelectionError(
            "selection manifest is stale or bound to a different/rebased source PE")

    candidates = {item.rva: item for item in report.candidates}
    values = _list(root["selections"], "selection manifest selections")
    if not values:
        raise VirtualizationSelectionError("selection manifest selects no functions")
    functions: list[SelectedFunction] = []
    gaps: list[GapAcknowledgement] = []
    tails: list[TailExitApproval] = []
    seen_names: set[str] = set()
    previous_rva = -1
    for index, value in enumerate(values):
        label = f"selection[{index}]"
        common_fields = {
            "coverage_gaps", "direct_reference_verdict",
            "indirect_target_closure", "lifted_body_extent", "name",
            "runtime_function", "source_extent", "tail_exit_approvals",
        }
        version_fields = (
            {"original_bytes_sha256"}
            if version == LEGACY_VERSION
            else {
                "lifted_body_sha256", "padding_proof",
                "source_extent_sha256",
            }
        )
        item = _exact(value, common_fields | version_fields, label)
        name = _string(item["name"], f"{label}.name", maximum=128)
        source_extent = _exact(
            item["source_extent"], {"rva", "size"}, f"{label}.source_extent")
        rva = _integer(source_extent["rva"], f"{label}.source_extent.rva", minimum=1)
        size = _integer(source_extent["size"], f"{label}.source_extent.size", minimum=5)
        if rva <= previous_rva:
            raise VirtualizationSelectionError(
                "selection entries are duplicated or not in increasing RVA order")
        if name in seen_names:
            raise VirtualizationSelectionError("selection names must be unique")
        previous_rva = rva
        seen_names.add(name)
        body = _exact(
            item["lifted_body_extent"], {"rva", "size"},
            f"{label}.lifted_body_extent")
        body_rva = _integer(
            body["rva"], f"{label}.lifted_body_extent.rva", minimum=1)
        body_size = _integer(
            body["size"], f"{label}.lifted_body_extent.size", minimum=5)
        if body_rva != rva or body_size > size:
            raise VirtualizationSelectionError(
                f"{label} lifted body must be a prefix of the source extent")
        if version == LEGACY_VERSION and body != source_extent:
            raise VirtualizationSelectionError(
                f"{label} version-2 lifted body must equal the source extent")

        candidate = candidates.get(rva)
        if (candidate is None or not candidate.exact_extent
                or candidate.extent_kind != "runtime_function"
                or candidate.size != size or candidate.body_size != body_size
                or not candidate.liftable
                or candidate.unwind_flags != 0):
            raise VirtualizationSelectionError(
                f"{label} is not a currently liftable exact non-handler function")
        verdict = _exact(item["direct_reference_verdict"], {
            "gate_passed", "status",
        }, f"{label}.direct_reference_verdict")
        _boolean(
            verdict["gate_passed"],
            f"{label}.direct_reference_verdict.gate_passed")
        _string(
            verdict["status"], f"{label}.direct_reference_verdict.status",
            maximum=32)
        current_verdict = {
            "gate_passed": candidate.direct_reference_gate_passed,
            "status": candidate.direct_control_proof_status,
        }
        if verdict != current_verdict or verdict["status"] != "passed":
            raise VirtualizationSelectionError(
                f"{label} direct-reference verdict fails the current audit")
        indirect = _exact(item["indirect_target_closure"], {
            "acknowledged", "proven",
        }, f"{label}.indirect_target_closure")
        if (_boolean(indirect["proven"], f"{label}.indirect.proven")
                != candidate.indirect_target_closure_proven):
            raise VirtualizationSelectionError(
                f"{label} indirect-closure proof does not match the current audit")
        if candidate.indirect_target_closure_proven:
            raise VirtualizationSelectionError(
                "selection manifest version 2 expects closure to remain unproven")
        if not _boolean(
                indirect["acknowledged"], f"{label}.indirect.acknowledged"):
            raise VirtualizationSelectionError(
                f"{label} does not acknowledge unproven indirect target closure")

        runtime = _exact(item["runtime_function"], {
            "begin_rva", "end_rva", "index", "unwind_flags", "unwind_info_rva",
        }, f"{label}.runtime_function")
        for field in (
                "begin_rva", "end_rva", "index", "unwind_flags",
                "unwind_info_rva"):
            _integer(
                runtime[field], f"{label}.runtime_function.{field}",
                minimum=0)
        if runtime != _runtime_identity(parsed, rva, size):
            raise VirtualizationSelectionError(
                f"{label} runtime-function identity changed")
        source_bytes = _extent_bytes(parsed, rva, size)
        actual_source_hash = hashlib.sha256(source_bytes).hexdigest()
        if version == LEGACY_VERSION:
            if _digest(
                    item["original_bytes_sha256"],
                    f"{label}.original_bytes_sha256") != actual_source_hash:
                raise VirtualizationSelectionError(
                    f"{label} original bytes changed")
        else:
            if _digest(
                    item["source_extent_sha256"],
                    f"{label}.source_extent_sha256") != actual_source_hash:
                raise VirtualizationSelectionError(
                    f"{label} source extent changed")
            actual_body_hash = hashlib.sha256(
                source_bytes[:body_size]).hexdigest()
            if _digest(
                    item["lifted_body_sha256"],
                    f"{label}.lifted_body_sha256") != actual_body_hash:
                raise VirtualizationSelectionError(
                    f"{label} lifted body changed")
            padding = _exact(item["padding_proof"], {
                "canonical_body_size", "source_extent_runtime_bound", "status",
                "suffix_rva", "suffix_size",
            }, f"{label}.padding_proof")
            _integer(
                padding["canonical_body_size"],
                f"{label}.padding_proof.canonical_body_size", minimum=5)
            _boolean(
                padding["source_extent_runtime_bound"],
                f"{label}.padding_proof.source_extent_runtime_bound")
            _string(
                padding["status"], f"{label}.padding_proof.status",
                maximum=32)
            _integer(
                padding["suffix_rva"],
                f"{label}.padding_proof.suffix_rva", minimum=1)
            _integer(
                padding["suffix_size"],
                f"{label}.padding_proof.suffix_size")
            current_padding = _current_padding_proof(
                rva=rva,
                source_extent_size=size,
                lifted_body_size=body_size,
                source_bytes=source_bytes,
            )
            if padding != current_padding:
                raise VirtualizationSelectionError(
                    f"{label} padding proof does not match the current audit")

        gap_values = _list(item["coverage_gaps"], f"{label}.coverage_gaps")
        if len(gap_values) != len(candidate.executable_coverage_gaps):
            raise VirtualizationSelectionError(
                f"{label} coverage-gap inventory does not match the current audit")
        for gap_index, (gap_value, current_gap) in enumerate(zip(
                gap_values, candidate.executable_coverage_gaps)):
            gaps.append(_verify_gap(
                gap_value, current_gap, f"{label}.coverage_gaps[{gap_index}]"))
        tail_values = _list(
            item["tail_exit_approvals"], f"{label}.tail_exit_approvals")
        for tail_index, tail_value in enumerate(tail_values):
            tails.append(_verify_tail(
                tail_value, rva, f"{label}.tail_exit_approvals[{tail_index}]"))
        functions.append(SelectedFunction(
            name,
            rva,
            size,
            body_size if version == VERSION else None,
        ))

    # Candidate gap inventories are commonly identical.  Require any repeated
    # acknowledgement to be byte-for-byte semantically consistent, then dedupe.
    gap_by_range: dict[tuple[int, int], GapAcknowledgement] = {}
    for gap in gaps:
        key = gap.rva, gap.size
        previous = gap_by_range.get(key)
        if previous is not None and previous != gap:
            raise VirtualizationSelectionError(
                "repeated coverage-gap acknowledgements disagree")
        gap_by_range[key] = gap
    if len(set(tails)) != len(tails):
        raise VirtualizationSelectionError("tail-exit approvals are duplicated")
    return VerifiedSelection(
        tuple(functions),
        tuple(sorted(gap_by_range.values())),
        tuple(sorted(tails)),
        True,
    )


def load_and_verify(
    path: str,
    *,
    parsed: Any,
    report: Any,
    source_sha256: str,
    source_snapshot_path: str,
) -> VerifiedSelection:
    raw = _load_bytes(path)
    try:
        content_id = pe_content_id(source_snapshot_path)
    except (OSError, ValueError) as exc:
        raise VirtualizationSelectionError(
            f"cannot compute current source PE content identity: {exc}") from exc
    return verify_manifest_bytes(
        raw, parsed=parsed, report=report, source_sha256=source_sha256,
        source_pe_content_id=content_id,
    )
