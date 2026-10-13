"""Read-only discovery and lift-coverage reporting for x64 PE functions.

Candidate extents come from validated AMD64 runtime-function records. Exported
leaf functions without unwind metadata get one deliberately narrow exception:
they may be decoded linearly through a plain ``RET`` under a small byte cap and
are always labelled heuristic. This module never mutates a PE or invokes the
packer pipeline.
"""
from __future__ import annotations

import json
import os
import re
import struct
from dataclasses import dataclass
from typing import Any, Sequence

from iced_x86 import Decoder, FlowControl, Mnemonic, OpKind

try:
    from . import native_tail_calls, win64_thunk, x64_lifter
except ImportError:  # standalone tools/tests
    import native_tail_calls  # type: ignore
    import win64_thunk  # type: ignore
    import x64_lifter  # type: ignore

try:
    from . import jump_table, source_references
except ImportError:  # standalone tools/tests
    import jump_table  # type: ignore
    import source_references  # type: ignore

try:
    from daedalus import daedalus_asm
except ImportError:  # standalone tests
    import daedalus_asm  # type: ignore


REPORT_SCHEMA = "lethe.virtualization-report"
REPORT_VERSION = 3
SELECTION_SCHEMA = "lethe.virtualization-selection"
SELECTION_VERSION = 1
DEFAULT_LEAF_CAP = 64
MAX_LEAF_CAP = 256
IMAGE_SCN_MEM_EXECUTE = 0x20000000
_RVA_LIMIT = 0x1_0000_0000
_MAX_EXPORTS = 1_000_000
_MAX_EXPORT_NAME = 4096
_MAP_ENTRY = re.compile(
    r"^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8,16}\s+"
    r"(?P<name>\S+)\s+(?P<va>[0-9A-Fa-f]{8,16})(?P<tail>.*)$"
)
_MAP_ADDRESS_PREFIX = re.compile(r"^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8,16}\b")
_UNWIND_FLAG_NAMES = (
    (0x1, "EHANDLER"),
    (0x2, "UHANDLER"),
    (0x4, "CHAININFO"),
    (0x8, "LARGE_PROLOG_V3"),
)


class FunctionDiscoveryError(ValueError):
    """Input metadata cannot support a deterministic read-only report."""


@dataclass(frozen=True, order=True)
class ExportSymbol:
    name: str
    ordinal: int
    rva: int


@dataclass(frozen=True, order=True)
class MapSymbol:
    name: str
    rva: int


@dataclass(frozen=True)
class UnsupportedInstruction:
    rva: int
    text: str

    def to_dict(self) -> dict[str, Any]:
        return {"rva": self.rva, "text": self.text}


@dataclass(frozen=True, order=True)
class CoverageGap:
    rva: int
    size: int
    section_name: str

    def to_dict(self) -> dict[str, Any]:
        return {"rva": self.rva, "section": self.section_name, "size": self.size}


@dataclass(frozen=True)
class FunctionCandidate:
    name: str
    source: str
    rva: int
    size: int
    extent_kind: str
    exact_extent: bool
    heuristic: bool
    unwind_flags: int
    unwind_flag_names: tuple[str, ...]
    liftable: bool
    rejection_reason: str | None
    first_unsupported_instruction: UnsupportedInstruction | None
    direct_control_proof_status: str
    direct_control_rejection_reason: str | None
    direct_reference_gate_passed: bool
    executable_coverage_gaps: tuple[CoverageGap, ...]
    indirect_target_closure_proven: bool
    internal_direct_call_count: int = 0
    max_internal_call_depth: int = 0
    rip_relative_references: tuple[x64_lifter.RipRelativeReference, ...] = ()
    lifted_body_size: int | None = None

    @property
    def source_extent_size(self) -> int:
        return self.size

    @property
    def body_size(self) -> int:
        return self.size if self.lifted_body_size is None else self.lifted_body_size

    def to_dict(self, *, coverage_gap_set: str | None = None) -> dict[str, Any]:
        result = {
            "direct_control_proof_status": self.direct_control_proof_status,
            "direct_control_rejection_reason": self.direct_control_rejection_reason,
            "direct_reference_gate_passed": self.direct_reference_gate_passed,
            "exact_extent": self.exact_extent,
            "extent_kind": self.extent_kind,
            "first_unsupported_instruction": (
                self.first_unsupported_instruction.to_dict()
                if self.first_unsupported_instruction else None
            ),
            "heuristic": self.heuristic,
            "indirect_target_closure_proven": self.indirect_target_closure_proven,
            "internal_direct_call_count": self.internal_direct_call_count,
            "liftable": self.liftable,
            "max_internal_call_depth": self.max_internal_call_depth,
            "name": self.name,
            "rejection_reason": self.rejection_reason,
            "rva": self.rva,
            "rip_relative_references": [
                reference.to_dict() for reference in self.rip_relative_references
            ],
            "size": self.size,
            "source_extent_size": self.size,
            "lifted_body_size": self.body_size,
            "source": self.source,
            "unwind_flag_names": list(self.unwind_flag_names),
            "unwind_flags": self.unwind_flags,
        }
        if coverage_gap_set is None:
            result["executable_coverage_gaps"] = [
                gap.to_dict() for gap in self.executable_coverage_gaps
            ]
        else:
            result["executable_coverage_gap_set"] = coverage_gap_set
        return result


@dataclass(frozen=True)
class FunctionDiscoveryReport:
    image_path: str
    image_base: int
    size_of_image: int
    candidates: tuple[FunctionCandidate, ...]
    executable_coverage_gaps: tuple[CoverageGap, ...]
    direct_control_analysis_status: str
    direct_control_analysis_error: str | None
    indirect_target_closure_proven: bool = False
    schema: str = REPORT_SCHEMA
    version: int = REPORT_VERSION

    def to_dict(self) -> dict[str, Any]:
        if self.version != REPORT_VERSION or self.schema != REPORT_SCHEMA:
            raise FunctionDiscoveryError("unsupported virtualization report schema/version")
        # Exact candidates share the whole-image tuple. Cache by tuple identity
        # first: repeatedly hashing that tuple would itself cost O(functions*gaps).
        gap_sets = {"image": self.executable_coverage_gaps}
        by_identity = {id(self.executable_coverage_gaps): "image"}
        by_value = {self.executable_coverage_gaps: "image"}
        candidates = []
        for candidate in self.candidates:
            gaps = candidate.executable_coverage_gaps
            reference = by_identity.get(id(gaps))
            if reference is None:
                reference = by_value.get(gaps)
                if reference is None:
                    reference = f"candidate-{len(gap_sets)}"
                    gap_sets[reference] = gaps
                    by_value[gaps] = reference
                by_identity[id(gaps)] = reference
            candidates.append(candidate.to_dict(coverage_gap_set=reference))
        return {
            "candidates": candidates,
            "direct_control_analysis_error": self.direct_control_analysis_error,
            "direct_control_analysis_status": self.direct_control_analysis_status,
            "executable_coverage_gap_set": "image",
            "coverage_gap_sets": {
                name: [gap.to_dict() for gap in gaps]
                for name, gaps in gap_sets.items()
            },
            "image": {
                "image_base": self.image_base,
                "path": self.image_path,
                "size_of_image": self.size_of_image,
            },
            "indirect_target_closure_proven": self.indirect_target_closure_proven,
            "schema": self.schema,
            "version": self.version,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    def starter_selection_manifest(self) -> dict[str, Any]:
        functions = [
            {"name": item.name, "rva": item.rva, "size": item.size}
            for item in self.candidates
            if (
                item.exact_extent
                and item.body_size == item.size
                and item.unwind_flags == 0
                and item.liftable
                and item.direct_control_proof_status == "passed"
            )
        ]
        return {
            "functions": functions,
            "schema": SELECTION_SCHEMA,
            "source_image": self.image_path,
            "version": SELECTION_VERSION,
        }


@dataclass(frozen=True)
class _RuntimeRange:
    begin: int
    end: int
    unwind_flags: int
    chain_primary_rva: int = 0


@dataclass(frozen=True)
class _Extent:
    name: str
    source: str
    rva: int
    size: int
    lifted_body_size: int
    extent_kind: str
    exact: bool
    heuristic: bool
    unwind_flags: int
    unresolved_reason: str | None = None


@dataclass(frozen=True)
class _DirectEdge:
    source_rva: int
    target_rva: int
    kind: str


def _validate_image(parsed: Any) -> tuple[Any, ...]:
    try:
        image_base = parsed.image_base
        size_of_image = parsed.size_of_image
        sections = tuple(parsed.sections)
    except (AttributeError, TypeError) as exc:
        raise FunctionDiscoveryError("ParsedPE image metadata is required") from exc
    if (type(image_base) is not int or image_base < 0
            or type(size_of_image) is not int or not 0 < size_of_image <= _RVA_LIMIT):
        raise FunctionDiscoveryError("invalid ParsedPE image geometry")
    if not sections:
        raise FunctionDiscoveryError("ParsedPE must contain sections")
    ordered = sorted(sections, key=lambda item: item.rva)
    previous_end = 0
    for section in ordered:
        try:
            name = section.name
            rva = section.rva
            virtual_size = section.virtual_size
            raw = section.raw
            characteristics = section.characteristics
        except AttributeError as exc:
            raise FunctionDiscoveryError("invalid ParsedPE section record") from exc
        if (not isinstance(name, str) or type(rva) is not int
                or type(virtual_size) is not int or virtual_size < 0
                or not isinstance(raw, (bytes, bytearray, memoryview))
                or type(characteristics) is not int):
            raise FunctionDiscoveryError("invalid ParsedPE section record")
        mapped_size = max(virtual_size, len(raw))
        end = rva + mapped_size
        if rva <= 0 or mapped_size <= 0 or end > size_of_image or end > _RVA_LIMIT:
            raise FunctionDiscoveryError(f"invalid section range for {name!r}")
        if rva < previous_end:
            raise FunctionDiscoveryError("ParsedPE sections overlap")
        previous_end = end
    return tuple(ordered)


def _runtime_ranges(parsed: Any, sections: Sequence[Any]) -> tuple[_RuntimeRange, ...]:
    try:
        records = tuple(parsed.runtime_functions)
        pdata_count = parsed.pdata_count
        pdata_rva = parsed.pdata_rva
    except (AttributeError, TypeError) as exc:
        raise FunctionDiscoveryError(
            "strict runtime-function inventory is required") from exc
    if type(pdata_count) is not int or pdata_count != len(records):
        raise FunctionDiscoveryError("runtime-function count does not match inventory")
    if records and (type(pdata_rva) is not int or pdata_rva <= 0):
        raise FunctionDiscoveryError("nonempty runtime-function inventory lacks pdata RVA")
    if not records and pdata_rva != 0:
        raise FunctionDiscoveryError("empty runtime-function inventory must use pdata RVA zero")

    result = []
    previous_end = 0
    for record in records:
        try:
            begin = record.begin_rva
            end = record.end_rva
            flags = record.unwind_flags
            chain_primary = getattr(record, "chain_primary_rva", 0)
        except AttributeError as exc:
            raise FunctionDiscoveryError("invalid runtime-function record") from exc
        if (type(begin) is not int or type(end) is not int or type(flags) is not int
                or type(chain_primary) is not int
                or begin <= 0 or end <= begin or end > parsed.size_of_image
                or flags < 0 or flags & ~0xF
                or chain_primary < 0 or chain_primary >= parsed.size_of_image
                or (not flags & 0x4 and chain_primary != 0)):
            raise FunctionDiscoveryError("invalid runtime-function record")
        if begin < previous_end:
            raise FunctionDiscoveryError("runtime-function ranges overlap or are unsorted")
        _read_executable(sections, begin, end - begin, "runtime function")
        result.append(_RuntimeRange(begin, end, flags, chain_primary))
        previous_end = end
    return tuple(result)


def _read_executable(
        sections: Sequence[Any], rva: int, size: int, label: str) -> bytes:
    if type(rva) is not int or type(size) is not int or rva <= 0 or size <= 0:
        raise FunctionDiscoveryError(f"invalid {label} range")
    end = rva + size
    owner = next(
        (section for section in sections
         if section.rva <= rva
         and end <= section.rva + max(section.virtual_size, len(section.raw))),
        None,
    )
    if owner is None:
        raise FunctionDiscoveryError(f"{label} is not contained in one section")
    if not owner.characteristics & IMAGE_SCN_MEM_EXECUTE:
        raise FunctionDiscoveryError(f"{label} is not executable")
    if end > owner.rva + len(owner.raw):
        raise FunctionDiscoveryError(f"{label} is not fully file-backed")
    offset = rva - owner.rva
    return bytes(owner.raw[offset:offset + size])


def _slice_at_rva(sections: Sequence[Any], rva: int, size: int, label: str) -> bytes:
    if rva <= 0 or size <= 0 or rva + size > _RVA_LIMIT:
        raise FunctionDiscoveryError(f"invalid {label} range")
    cursor = rva
    end = rva + size
    output = bytearray()
    while cursor < end:
        owner = next(
            (section for section in sections
             if section.rva <= cursor < section.rva + len(section.raw)),
            None,
        )
        if owner is None:
            raise FunctionDiscoveryError(f"{label} is not fully file-backed")
        take = min(end - cursor, owner.rva + len(owner.raw) - cursor)
        offset = cursor - owner.rva
        output += bytes(owner.raw[offset:offset + take])
        cursor += take
    return bytes(output)


def _read_c_string(sections: Sequence[Any], rva: int, label: str) -> str:
    data = bytearray()
    for offset in range(_MAX_EXPORT_NAME + 1):
        byte = _slice_at_rva(sections, rva + offset, 1, label)[0]
        if byte == 0:
            if not data:
                raise FunctionDiscoveryError(f"{label} is empty")
            try:
                return data.decode("ascii")
            except UnicodeDecodeError as exc:
                raise FunctionDiscoveryError(f"{label} is not ASCII") from exc
        data.append(byte)
    raise FunctionDiscoveryError(f"{label} exceeds {_MAX_EXPORT_NAME} bytes")


def parse_pe_exports(parsed: Any) -> tuple[ExportSymbol, ...]:
    """Strictly read the PE export directory named and ordinal entries."""
    sections = _validate_image(parsed)
    path = getattr(parsed, "path", None)
    if not isinstance(path, str) or not path or not os.path.isfile(path):
        raise FunctionDiscoveryError("ParsedPE path is required to read exports")
    try:
        with open(path, "rb") as stream:
            image = stream.read()
        if len(image) < 0x40 or image[:2] != b"MZ":
            raise FunctionDiscoveryError("input lacks a DOS header")
        e_lfanew, = struct.unpack_from("<I", image, 0x3C)
        if e_lfanew + 24 > len(image) or image[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise FunctionDiscoveryError("input lacks a PE header")
        file_header = e_lfanew + 4
        optional = file_header + 20
        optional_size, = struct.unpack_from("<H", image, file_header + 16)
        if optional + optional_size > len(image) or optional_size < 0x78:
            raise FunctionDiscoveryError("input has a truncated optional header")
        if struct.unpack_from("<H", image, file_header)[0] != 0x8664:
            raise FunctionDiscoveryError("input is not AMD64")
        if struct.unpack_from("<H", image, optional)[0] != 0x20B:
            raise FunctionDiscoveryError("input is not PE32+")
        directory_count, = struct.unpack_from("<I", image, optional + 0x6C)
        if directory_count == 0:
            export_rva, export_size = 0, 0
        else:
            if optional + 0x78 > optional + optional_size:
                raise FunctionDiscoveryError("input lacks an export directory slot")
            export_rva, export_size = struct.unpack_from("<II", image, optional + 0x70)
    except (OSError, struct.error) as exc:
        raise FunctionDiscoveryError(f"cannot read PE export directory: {exc}") from exc

    if (getattr(parsed, "export_directory_rva", export_rva),
            getattr(parsed, "export_directory_size", export_size)) != (export_rva, export_size):
        raise FunctionDiscoveryError("ParsedPE export directory disagrees with source PE header")
    if export_rva == 0 and export_size == 0:
        return ()
    if export_rva <= 0 or export_size < 40 or export_rva + export_size > parsed.size_of_image:
        raise FunctionDiscoveryError("malformed PE export-directory range")
    directory = _slice_at_rva(sections, export_rva, 40, "export directory")
    (_characteristics, _timestamp, _major, _minor, _dll_name_rva, ordinal_base,
     function_count, name_count, functions_rva, names_rva,
     ordinals_rva) = struct.unpack("<IIHHIIIIIII", directory)
    if function_count > _MAX_EXPORTS or name_count > function_count:
        raise FunctionDiscoveryError("malformed PE export-table counts")
    if function_count == 0:
        if name_count:
            raise FunctionDiscoveryError("named exports exist without function slots")
        return ()
    if functions_rva == 0 or (name_count and (names_rva == 0 or ordinals_rva == 0)):
        raise FunctionDiscoveryError("malformed PE export-table pointers")
    functions = struct.unpack(
        f"<{function_count}I",
        _slice_at_rva(sections, functions_rva, function_count * 4, "export address table"),
    )
    names_by_index: dict[int, str] = {}
    seen_names: set[str] = set()
    if name_count:
        name_rvas = struct.unpack(
            f"<{name_count}I",
            _slice_at_rva(sections, names_rva, name_count * 4, "export name table"),
        )
        ordinals = struct.unpack(
            f"<{name_count}H",
            _slice_at_rva(sections, ordinals_rva, name_count * 2, "export ordinal table"),
        )
        for index, name_rva in zip(ordinals, name_rvas):
            if index >= function_count or index in names_by_index:
                raise FunctionDiscoveryError("ambiguous PE export ordinal binding")
            name = _read_c_string(sections, name_rva, "export name")
            if name in seen_names:
                raise FunctionDiscoveryError(f"duplicate PE export name {name!r}")
            names_by_index[index] = name
            seen_names.add(name)

    exports = []
    seen_rvas: dict[int, str] = {}
    for index, target_rva in enumerate(functions):
        if target_rva == 0:
            continue
        name = names_by_index.get(index, f"ordinal_{ordinal_base + index}")
        if export_rva <= target_rva < export_rva + export_size:
            _read_c_string(sections, target_rva, f"forwarder for {name!r}")
            continue
        if target_rva >= parsed.size_of_image:
            raise FunctionDiscoveryError(f"export {name!r} target is outside SizeOfImage")
        previous = seen_rvas.get(target_rva)
        if previous is not None:
            raise FunctionDiscoveryError(
                f"ambiguous export aliases {previous!r} and {name!r} at RVA "
                f"0x{target_rva:X}")
        seen_rvas[target_rva] = name
        exports.append(ExportSymbol(name, ordinal_base + index, target_rva))
    return tuple(sorted(exports, key=lambda item: (item.rva, item.name, item.ordinal)))


def parse_msvc_map(
        text: str, *, image_base: int,
        runtime_ranges: Sequence[_RuntimeRange]) -> tuple[MapSymbol, ...]:
    """Bind MSVC MAP ``f`` symbols only to exact runtime-function starts."""
    if not isinstance(text, str):
        raise FunctionDiscoveryError("MSVC MAP text must be a string")
    if "Publics by Value" not in text and "Static symbols" not in text:
        raise FunctionDiscoveryError("MSVC MAP lacks a symbol table header")
    by_begin = {record.begin: record for record in runtime_ranges}
    bindings: dict[int, str] = {}
    names: dict[str, int] = {}
    in_symbols = False
    for line_number, line in enumerate(text.splitlines(), 1):
        if "Publics by Value" in line or "Static symbols" in line:
            in_symbols = True
            continue
        if not in_symbols:
            continue
        match = _MAP_ENTRY.match(line)
        if match is None:
            if _MAP_ADDRESS_PREFIX.match(line):
                raise FunctionDiscoveryError(
                    f"malformed MSVC MAP symbol line {line_number}")
            continue
        tail_tokens = match.group("tail").split()
        if "f" not in tail_tokens:
            continue
        name = match.group("name")
        va = int(match.group("va"), 16)
        if va < image_base or va - image_base >= _RVA_LIMIT:
            raise FunctionDiscoveryError(
                f"MSVC MAP function {name!r} has an invalid Rva+Base value")
        rva = va - image_base
        if rva in by_begin:
            previous = bindings.get(rva)
            if previous is not None and previous != name:
                raise FunctionDiscoveryError(
                    f"ambiguous MSVC MAP symbols {previous!r} and {name!r} at "
                    f"RVA 0x{rva:X}")
            prior_rva = names.get(name)
            if prior_rva is not None and prior_rva != rva:
                raise FunctionDiscoveryError(
                    f"ambiguous MSVC MAP symbol {name!r} binds multiple RVAs")
            bindings[rva] = name
            names[name] = rva
            continue
        interior = next(
            (record for record in runtime_ranges if record.begin < rva < record.end),
            None,
        )
        if interior is not None:
            raise FunctionDiscoveryError(
                f"MSVC MAP function {name!r} points inside runtime function "
                f"0x{interior.begin:X}..0x{interior.end:X}")
    return tuple(MapSymbol(name, rva) for rva, name in sorted(bindings.items()))


def _heuristic_leaf_extent(
        sections: Sequence[Any], rva: int, cap: int) -> tuple[int, str | None]:
    owner = next(
        (section for section in sections
         if section.rva <= rva < section.rva + len(section.raw)),
        None,
    )
    if owner is None or not owner.characteristics & IMAGE_SCN_MEM_EXECUTE:
        return 0, "export entry is not file-backed executable code"
    available = min(cap, owner.rva + len(owner.raw) - rva)
    code = bytes(owner.raw[rva - owner.rva:rva - owner.rva + available])
    cursor = rva
    for instruction in Decoder(64, code, ip=rva):
        if instruction.ip != cursor or instruction.code == 0 or instruction.len <= 0:
            return 0, f"invalid instruction at RVA 0x{cursor:X}"
        cursor += instruction.len
        if instruction.flow_control == FlowControl.RETURN:
            if instruction.mnemonic != Mnemonic.RET or instruction.op_count != 0:
                return 0, f"non-plain RET at RVA 0x{instruction.ip:X}"
            return cursor - rva, None
        if instruction.flow_control != FlowControl.NEXT:
            return 0, (
                f"control transfer {instruction} before plain RET at RVA "
                f"0x{instruction.ip:X}"
            )
        if cursor - rva >= cap:
            break
    return 0, f"no plain RET within {cap}-byte heuristic cap"


def _flag_names(flags: int) -> tuple[str, ...]:
    return tuple(name for bit, name in _UNWIND_FLAG_NAMES if flags & bit)


def _strict_decode(
        code: bytes, rva: int
) -> tuple[tuple[Any, ...], str | None, UnsupportedInstruction | None]:
    instructions = tuple(Decoder(64, code, ip=rva))
    if not instructions:
        return (), "declared extent contains no instructions", None
    cursor = rva
    starts = set()
    for instruction in instructions:
        if instruction.ip != cursor or instruction.code == 0 or instruction.len <= 0:
            return (
                instructions,
                f"invalid instruction at RVA 0x{cursor:X}",
                UnsupportedInstruction(instruction.ip, str(instruction)),
            )
        starts.add(instruction.ip)
        cursor += instruction.len
    if cursor != rva + len(code):
        return (
            instructions,
            f"decoder consumed 0x{cursor - rva:X} bytes, expected 0x{len(code):X}",
            None,
        )
    for instruction in instructions:
        if instruction.mnemonic == Mnemonic.JMP or instruction.mnemonic in x64_lifter._CC:
            if instruction.op_kind(0) != OpKind.NEAR_BRANCH64:
                return (
                    instructions,
                    f"indirect or non-near branch at RVA 0x{instruction.ip:X}",
                    UnsupportedInstruction(instruction.ip, str(instruction)),
                )
            if instruction.near_branch_target not in starts:
                return (
                    instructions,
                    f"branch target RVA 0x{instruction.near_branch_target:X} is "
                    "not an instruction boundary",
                    UnsupportedInstruction(instruction.ip, str(instruction)),
                )
    final = instructions[-1]
    if final.mnemonic != Mnemonic.RET or final.op_count != 0:
        return (
            instructions,
            "declared extent must end in a plain RET",
            UnsupportedInstruction(final.ip, str(final)),
        )
    return instructions, None, None


def _traceback_instruction(exc: BaseException) -> UnsupportedInstruction | None:
    traceback = exc.__traceback__
    while traceback is not None:
        instruction = traceback.tb_frame.f_locals.get("instr")
        if instruction is not None and hasattr(instruction, "ip"):
            return UnsupportedInstruction(int(instruction.ip), str(instruction))
        traceback = traceback.tb_next
    return None


def _lift_status(
    extent: _Extent,
    sections: Sequence[Any],
    *,
    padding_rejection: str | None = None,
    native_call_targets: frozenset[int] = frozenset(),
    native_call_rejection: tuple[int, str] | None = None,
) -> tuple[
    bool,
    str | None,
    UnsupportedInstruction | None,
    tuple[x64_lifter.RipRelativeReference, ...],
]:
    # Every materialized native bridge requires a physical callee-frame
    # proof. PDATA and exact IAT identity alone do not provide that proof.
    if extent.unresolved_reason:
        return False, extent.unresolved_reason, None, ()
    if padding_rejection is not None:
        return False, padding_rejection, None, ()
    if extent.unwind_flags:
        return False, (
            "source runtime-function uses unsupported unwind flags "
            + "|".join(_flag_names(extent.unwind_flags))
        ), None, ()
    if extent.size < 5:
        return (
            False,
            "function is too small for a five-byte near-JMP entry patch",
            None,
            (),
        )
    try:
        source = _read_executable(sections, extent.rva, extent.size, "candidate")
    except FunctionDiscoveryError as exc:
        return False, str(exc), None, ()
    code = source[:extent.lifted_body_size]
    _instructions, decode_error, decode_instruction = _strict_decode(code, extent.rva)
    if decode_error:
        return False, decode_error, decode_instruction, ()
    if native_call_rejection is not None:
        site, reason = native_call_rejection
        instruction = next((item for item in _instructions if item.ip == site), None)
        first = (UnsupportedInstruction(site, str(instruction))
                 if instruction is not None else None)
        return False, reason, first, ()
    try:
        references = x64_lifter.validate_rip_relative_references(
            code,
            base=extent.rva,
            image_sections=sections,
            selected_extents=((extent.rva, extent.size),),
        )
        assembly = x64_lifter.lift_function(
            code,
            base=extent.rva,
            image_sections=sections,
            selected_extents=((extent.rva, extent.size),),
            source_extent_size=extent.size,
            native_call_targets=native_call_targets,
        )
        # An ISA-liftable body is not necessarily materializable. Replay the
        # planner's exact source-stack proof before marking it selectable, so
        # generated starter manifests cannot advertise a body the packer must
        # reject for control-frame overlap or an unmodeled pointer escape.
        x64_lifter.validate_materialized_stack_window(
            code,
            base=extent.rva,
            window_size=win64_thunk.STACK_WINDOW_SIZE,
            native_call_targets=native_call_targets,
        )
        daedalus_asm.assemble(assembly)
    except (x64_lifter.LiftUnsupported, SyntaxError, ValueError) as exc:
        first = _traceback_instruction(exc)
        if first is None:
            match = re.search(r"\bat 0x([0-9A-Fa-f]+)\b", str(exc))
            if match is not None:
                rejected_rva = int(match.group(1), 16)
                rejected_instruction = next(
                    (
                        instruction
                        for instruction in _instructions
                        if instruction.ip == rejected_rva
                    ),
                    None,
                )
                if rejected_instruction is not None:
                    first = UnsupportedInstruction(
                        rejected_rva, str(rejected_instruction)
                    )
        reason = f"whole-function lift rejected: {exc}"
        if first is not None:
            if f"0x{first.rva:X}" not in reason:
                reason += f" at RVA 0x{first.rva:X}"
            if first.text not in reason:
                reason += f" ({first.text})"
        return False, reason, first, ()
    return True, None, None, references


def _ranges_overlap(left_rva: int, left_size: int, right_rva: int, right_size: int) -> bool:
    return left_rva < right_rva + right_size and right_rva < left_rva + left_size


def _padding_metadata_rejection(
    parsed: Any,
    extent: _Extent,
    exports: Sequence[ExportSymbol],
    runtime: Sequence[_RuntimeRange],
    direct_transfers: Sequence[_DirectEdge],
) -> str | None:
    """Return the first source binding that makes suffix trimming unsafe."""
    if extent.lifted_body_size == extent.size:
        return None

    suffix_rva = extent.rva + extent.lifted_body_size
    suffix_size = extent.size - extent.lifted_body_size
    points: list[tuple[str, int, int]] = []
    ranges: list[tuple[str, int, int]] = []

    points.extend((f"export {item.name!r}", item.rva, 1) for item in exports)
    oep_rva = getattr(parsed, "oep_rva", 0)
    if type(oep_rva) is int and oep_rva:
        points.append(("image entry point", oep_rva, 1))
    tls = getattr(parsed, "tls", None)
    if tls is not None:
        for callback_rva in tuple(getattr(tls, "callback_rvas", ())):
            points.append(("TLS callback", callback_rva, 1))

    runtime_records = tuple(getattr(parsed, "runtime_functions", ()))
    for record in runtime:
        unwind_rva = next(
            (
                item.unwind_info_rva
                for item in runtime_records
                if item.begin_rva == record.begin and item.end_rva == record.end
            ),
            0,
        )
        if unwind_rva:
            points.append(("unwind info", unwind_rva, 1))

    for relocation in tuple(getattr(parsed, "dir64_relocations", ())):
        ranges.append(("DIR64 relocation", relocation.target_rva, 8))

    export_rva = getattr(parsed, "export_directory_rva", 0)
    export_size = getattr(parsed, "export_directory_size", 0)
    if export_rva and export_size:
        ranges.append(("export directory", export_rva, export_size))

    for transfer in direct_transfers:
        points.append((f"direct {transfer.kind} target", transfer.target_rva, 1))

    load_config = getattr(parsed, "load_config", None)
    if load_config is not None:
        ranges.append(
            (
                "load-config directory",
                load_config.directory_rva,
                load_config.directory_size,
            )
        )
        metadata_size = (load_config.guard_flags >> 28) & 0xF
        stride = 4 + metadata_size
        for label, table_rva, targets in (
            (
                "Guard CF function table",
                load_config.guard_cf_function_table_rva,
                load_config.guard_cf_targets,
            ),
            (
                "Guard address-taken IAT table",
                load_config.guard_address_taken_iat_entry_table_rva,
                load_config.guard_address_taken_iat_entries,
            ),
            (
                "Guard long-jump table",
                load_config.guard_long_jump_target_table_rva,
                load_config.guard_long_jump_targets,
            ),
            (
                "Guard EH-continuation table",
                load_config.guard_eh_continuation_table_rva,
                load_config.guard_eh_continuation_targets,
            ),
        ):
            if table_rva and targets:
                ranges.append((label, table_rva, len(targets) * stride))
            points.extend((f"{label} target", item.rva, 1) for item in targets)
        ranges.extend(
            ("XFG function hash", item.rva - 8, 8)
            for item in load_config.guard_cf_targets
            if item.rva >= 8 and item.metadata and item.metadata[0] & 0x08
        )

        for label in (
            "security_cookie_rva",
            "guard_cf_check_function_pointer_rva",
            "guard_cf_dispatch_function_pointer_rva",
            "guard_xfg_check_function_pointer_rva",
            "guard_xfg_dispatch_function_pointer_rva",
            "guard_xfg_table_dispatch_function_pointer_rva",
            "cast_guard_os_determined_failure_mode_rva",
            "guard_memcpy_function_pointer_rva",
        ):
            value = getattr(load_config, label, 0)
            if value:
                points.append((f"load-config {label}", value, 1))

        volatile = getattr(load_config, "volatile_metadata", None)
        if volatile is not None:
            ranges.append(("volatile metadata", volatile.rva, len(volatile.raw)))
            points.extend(
                ("volatile access target", target, 1)
                for target in volatile.access_rvas
            )
            if len(volatile.raw) >= 24:
                access_rva, access_size, info_rva, info_size = struct.unpack_from(
                    "<IIII", volatile.raw, 8
                )
                if access_rva and access_size:
                    ranges.append(("volatile access table", access_rva, access_size))
                if info_rva and info_size:
                    ranges.append(("volatile info table", info_rva, info_size))

    for label, rva, size in (*points, *ranges):
        if _ranges_overlap(rva, size, suffix_rva, suffix_size):
            return (
                f"padding suffix 0x{suffix_rva:X}..0x{suffix_rva + suffix_size:X} "
                f"contains {label} at RVA 0x{rva:X}"
            )
    return None


def _coverage_gaps(
        sections: Sequence[Any], ranges: Sequence[tuple[int, int]]) -> tuple[CoverageGap, ...]:
    gaps = []
    for section in sections:
        if not section.characteristics & IMAGE_SCN_MEM_EXECUTE:
            continue
        start = section.rva
        end = section.rva + max(section.virtual_size, len(section.raw))
        covered = sorted(
            (max(start, begin), min(end, finish))
            for begin, finish in ranges
            if max(start, begin) < min(end, finish)
        )
        cursor = start
        for begin, finish in covered:
            if cursor < begin:
                gaps.append(CoverageGap(cursor, begin - cursor, section.name))
            cursor = max(cursor, finish)
        if cursor < end:
            gaps.append(CoverageGap(cursor, end - cursor, section.name))
    return tuple(gaps)


def _linear_prefix(code: bytes, begin: int, end: int) -> tuple[Any, ...]:
    """Decode instructions from ``begin`` until the first fault or ``end``."""
    instructions = []
    cursor = begin
    for instruction in Decoder(64, code, ip=begin):
        if instruction.ip != cursor or instruction.code == 0 or instruction.len <= 0:
            break
        instructions.append(instruction)
        cursor += instruction.len
        if cursor >= end:
            break
    return tuple(instructions)


def _scan_direct_control(
        sections: Sequence[Any], runtime: Sequence[_RuntimeRange],
        *, reference_instructions: list[Any] | None = None,
        reference_groups: list[tuple[Any, ...]] | None = None,
) -> tuple[tuple[_DirectEdge, ...], tuple[tuple[int, int], ...]]:
    """Decode the runtime inventory once and record all near direct edges.

    Compiler ``switch`` jump tables sit as data-in-code inside a function's
    extent. They are recognized and their bytes excised as data so they neither
    fabricate edges nor fault the sweep. A function whose data-in-code cannot be
    proven is *isolated* (quarantined): its cleanly decoded prefix still
    contributes its edges, but the function itself becomes unselectable -- it
    no longer poisons the whole-image analysis. Returns
    ``(edges, quarantined_ranges)``.
    """
    decoded = []
    instruction_starts = set()
    quarantined: list[tuple[int, int]] = []
    for record in runtime:
        code = _read_executable(
            sections, record.begin, record.end - record.begin, "runtime function"
        )
        try:
            body = jump_table.decode_function_body(code, record.begin, record.end)
            instructions = body.instructions
            if reference_groups is not None:
                reference_groups.append(tuple(instructions))
        except jump_table.JumpTableUnresolved:
            # Data-in-code we cannot prove: bail this one function to native.
            # Keep its decoded prefix for negative references/direct edges,
            # but never promote a local LEA-to-CALL pair from a partial decode
            # into positive exact-entry proof.
            instructions = _linear_prefix(code, record.begin, record.end)
            quarantined.append((record.begin, record.end))
        for instruction in instructions:
            instruction_starts.add(instruction.ip)
        decoded.extend(instructions)

    if reference_instructions is not None:
        reference_instructions.extend(decoded)

    def _in_quarantine(rva: int) -> bool:
        return any(begin <= rva < end for begin, end in quarantined)

    edges = []
    near_kinds = {OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64}
    for instruction in decoded:
        if instruction.flow_control == FlowControl.CALL:
            kind = "call"
        elif instruction.flow_control == FlowControl.UNCONDITIONAL_BRANCH:
            kind = "jump"
        elif instruction.flow_control == FlowControl.CONDITIONAL_BRANCH:
            kind = "conditional_jump"
        else:
            continue
        if instruction.op_count < 1 or instruction.op_kind(0) not in near_kinds:
            raise FunctionDiscoveryError(
                f"unsupported non-near direct {kind} at RVA 0x{instruction.ip:X}"
            )
        target = int(instruction.near_branch_target)
        if target <= 0 or target >= _RVA_LIMIT:
            raise FunctionDiscoveryError(
                f"direct {kind} at RVA 0x{instruction.ip:X} has an invalid "
                f"target 0x{target:X}"
            )
        owner = next(
            (record for record in runtime if record.begin <= target < record.end), None
        )
        if (owner is not None and target not in instruction_starts
                and not _in_quarantine(target)):
            raise FunctionDiscoveryError(
                f"direct {kind} at RVA 0x{instruction.ip:X} targets "
                f"non-instruction RVA 0x{target:X}"
            )
        edges.append(_DirectEdge(instruction.ip, target, kind))
    return tuple(edges), tuple(quarantined)


def _build_extents(
        parsed: Any, sections: Sequence[Any], runtime: Sequence[_RuntimeRange],
        exports: Sequence[ExportSymbol], maps: Sequence[MapSymbol], leaf_cap: int,
) -> tuple[_Extent, ...]:
    exports_by_rva: dict[int, ExportSymbol] = {}
    export_names: set[str] = set()
    for symbol in exports:
        if not isinstance(symbol, ExportSymbol):
            raise FunctionDiscoveryError("exports must contain ExportSymbol records")
        if (not symbol.name or "\0" in symbol.name or type(symbol.rva) is not int
                or symbol.rva <= 0 or symbol.rva >= parsed.size_of_image):
            raise FunctionDiscoveryError("invalid export symbol")
        if symbol.name in export_names or symbol.rva in exports_by_rva:
            raise FunctionDiscoveryError("duplicate or ambiguous export symbol")
        interior = next(
            (item for item in runtime if item.begin < symbol.rva < item.end), None
        )
        if interior is not None:
            raise FunctionDiscoveryError(
                f"export {symbol.name!r} enters runtime-function interior")
        export_names.add(symbol.name)
        exports_by_rva[symbol.rva] = symbol

    maps_by_rva = {item.rva: item for item in maps}
    if len(maps_by_rva) != len(maps):
        raise FunctionDiscoveryError("duplicate or ambiguous MSVC MAP binding")
    used_names: dict[str, int] = {}
    extents = []
    index = 0
    while index < len(runtime):
        record = runtime[index]
        # A linker-split function can have contiguous CHAININFO continuations.
        # Only the exact primary plus fragments whose validated ultimate root
        # is that primary may be presented as one selectable source extent.
        # A symbol at a fragment entry is an independently reachable interior
        # entry, so leave the records separate and fail closed instead.
        group_end = record.end
        group_next = index + 1
        if record.unwind_flags == 0:
            while group_next < len(runtime):
                fragment = runtime[group_next]
                if (fragment.begin != group_end or fragment.unwind_flags != 0x4
                        or fragment.chain_primary_rva != record.begin):
                    break
                if (fragment.begin in exports_by_rva
                        or fragment.begin in maps_by_rva):
                    break
                group_end = fragment.end
                group_next += 1
        grouped = group_next > index + 1
        # Removing only a prefix would leave a retained CHAININFO record whose
        # primary PDATA record was removed by the materializer.  All fragments
        # of this root must be in the exact contiguous tile.
        if grouped and any(
                other.unwind_flags & 0x4
                and other.chain_primary_rva == record.begin
                for other in runtime[group_next:]):
            grouped = False
        if grouped and any(
                record.begin < symbol_rva < group_end
                for symbol_rva in (*exports_by_rva, *maps_by_rva)):
            grouped = False
        if not grouped:
            group_end = record.end
            group_next = index + 1
        export = exports_by_rva.pop(record.begin, None)
        mapped = maps_by_rva.get(record.begin)
        names = {item.name for item in (export, mapped) if item is not None}
        if len(names) > 1:
            raise FunctionDiscoveryError(
                f"ambiguous export/MAP names at RVA 0x{record.begin:X}: "
                + ", ".join(sorted(names))
            )
        name = next(iter(names), f"sub_{record.begin:08X}")
        source_parts = []
        if export:
            source_parts.append("export")
        if mapped:
            source_parts.append("map")
        source_parts.append("pdata-chain-group" if grouped else "pdata")
        size = group_end - record.begin
        source = _read_executable(sections, record.begin, size, "runtime function")
        if grouped:
            # The planner only subsumes multiple source PDATA records when the
            # entire tiled extent is lifted, never by padding-aware trimming.
            lifted_body_size = size
        else:
            try:
                lifted_body_size = x64_lifter.canonical_lifted_body_size(
                    source, record.begin
                )
            except x64_lifter.LiftUnsupported:
                lifted_body_size = size
        extents.append(_Extent(
            name=name,
            source="+".join(source_parts),
            rva=record.begin,
            size=size,
            lifted_body_size=lifted_body_size,
            extent_kind=("runtime_function_group" if grouped
                         else "runtime_function"),
            exact=True,
            heuristic=False,
            unwind_flags=record.unwind_flags,
        ))
        index = group_next

    for symbol in exports_by_rva.values():
        size, reason = _heuristic_leaf_extent(sections, symbol.rva, leaf_cap)
        extents.append(_Extent(
            name=symbol.name,
            source="export-heuristic" if size else "export-unresolved",
            rva=symbol.rva,
            size=size,
            lifted_body_size=size,
            extent_kind="heuristic_plain_ret" if size else "unresolved",
            exact=False,
            heuristic=bool(size),
            unwind_flags=0,
            unresolved_reason=None if size else (
                "export has no exact runtime range; conservative leaf extent "
                f"rejected: {reason}"
            ),
        ))

    extents.sort(key=lambda item: (item.rva, item.size, item.name))
    for extent in extents:
        prior = used_names.get(extent.name)
        if prior is not None and prior != extent.rva:
            raise FunctionDiscoveryError(
                f"ambiguous symbol name {extent.name!r} binds multiple RVAs")
        used_names[extent.name] = extent.rva
    resolved = [item for item in extents if item.size]
    for previous, current in zip(resolved, resolved[1:]):
        if current.rva < previous.rva + previous.size:
            raise FunctionDiscoveryError(
                f"candidate extents {previous.name!r} and {current.name!r} overlap")
    return tuple(extents)


def discover_functions(
        parsed: Any, *, map_text: str | None = None,
        exports: Sequence[ExportSymbol] | None = None,
        leaf_cap: int = DEFAULT_LEAF_CAP) -> FunctionDiscoveryReport:
    """Create a deterministic report without mutating or packing the image."""
    if type(leaf_cap) is not int or not 1 <= leaf_cap <= MAX_LEAF_CAP:
        raise FunctionDiscoveryError(
            f"leaf_cap must be an integer from 1 through {MAX_LEAF_CAP}")
    sections = _validate_image(parsed)
    runtime = _runtime_ranges(parsed, sections)
    export_records = (
        parse_pe_exports(parsed) if exports is None else tuple(exports)
    )
    map_records = (
        parse_msvc_map(
            map_text, image_base=parsed.image_base, runtime_ranges=runtime
        )
        if map_text is not None else ()
    )
    extents = _build_extents(
        parsed, sections, runtime, export_records, map_records, leaf_cap
    )

    runtime_pairs = tuple((item.begin, item.end) for item in runtime)
    try:
        import_entries = tuple(function.iat_rva
                               for dll in getattr(parsed, "imports", ())
                               for function in dll.funcs)
    except (AttributeError, TypeError) as exc:
        raise FunctionDiscoveryError(
            "source import IAT inventory must contain DLL/function records") from exc
    try:
        import_iat_rvas = native_tail_calls.validated_import_iat_rvas(import_entries)
    except ValueError as exc:
        raise FunctionDiscoveryError(str(exc)) from exc
    global_gaps = _coverage_gaps(sections, runtime_pairs)
    direct_error = None
    direct_transfers = ()
    reference_index = source_references.SourceReferenceIndex(())
    reference_instructions = []
    reference_groups: list[tuple[Any, ...]] = []
    quarantined_ranges: tuple[tuple[int, int], ...] = ()
    try:
        direct_transfers, quarantined_ranges = _scan_direct_control(
            sections, runtime, reference_instructions=reference_instructions,
            reference_groups=reference_groups,
        )
        references = (
            *source_references.instruction_references(reference_instructions),
            *source_references.dir64_references(parsed),
            *source_references.metadata_references(parsed, exports=export_records),
        )
        reference_index = source_references.SourceReferenceIndex(
            references,
            proven_entry_calls=source_references.proven_immediate_entry_calls(
                reference_groups,
                known_entry_targets=(item.target_rva for item in references
                                     if item.address_only),
            ),
        )
        direct_status = "passed"
    except (FunctionDiscoveryError, source_references.SourceReferenceError) as exc:
        direct_status = "rejected"
        direct_error = str(exc)

    candidates = []
    for extent in extents:
        padding_rejection = _padding_metadata_rejection(
            parsed, extent, export_records, runtime, direct_transfers
        )
        # Discovery and planning share the same fail-closed native-call
        # admission. PDATA and exact import thunks identify targets but do not
        # prove the callee's physical return/home-slot contract.
        native_call_targets = frozenset()
        native_call_rejection = None
        if not extent.unwind_flags and not extent.unresolved_reason and padding_rejection is None:
            try:
                candidate_body = _read_executable(sections, extent.rva, extent.lifted_body_size, "candidate")
            except FunctionDiscoveryError:
                pass  # _lift_status retains the original extent/read diagnostic.
            else:
                pdata_sites = native_tail_calls.retained_pdata_call_sites(
                    candidate_body, base=extent.rva, sections=sections,
                    retained_entries=frozenset(
                        item.begin for item in runtime
                        if not (extent.rva <= item.begin < extent.rva + extent.size)
                    ),
                    runtime_ranges=runtime_pairs,
                    selected_extents=((extent.rva, extent.size),),
                    import_iat_rvas=import_iat_rvas,
                )
                if pdata_sites:
                    native_call_rejection = (
                        pdata_sites[0],
                        "retained PDATA native CALL lacks physical return-slot "
                        f"and stack identity proof at 0x{pdata_sites[0]:X}",
                    )
                else:
                    iat_tail_targets = native_tail_calls.proven_tail_call_targets(
                        candidate_body, base=extent.rva, sections=sections,
                        retained_entries=frozenset(), runtime_ranges=runtime_pairs,
                        selected_extents=((extent.rva, extent.size),),
                        import_iat_rvas=import_iat_rvas)
                    opaque_sites = native_tail_calls.opaque_native_call_sites(
                        candidate_body, base=extent.rva,
                        iat_tail_targets=iat_tail_targets)
                    if opaque_sites:
                        native_call_rejection = (
                            opaque_sites[0],
                            "opaque native CALL lacks physical callee return-address "
                            f"and shadow-space effects proof at 0x{opaque_sites[0]:X}",
                        )
        liftable, rejection, first, rip_references = _lift_status(
            extent,
            sections,
            padding_rejection=padding_rejection,
            native_call_targets=native_call_targets,
            native_call_rejection=native_call_rejection,
        )
        internal_call_count = 0
        max_internal_call_depth = 0
        if liftable:
            source = _read_executable(sections, extent.rva, extent.size, "candidate")
            code = source[:extent.lifted_body_size]
            call_analysis = x64_lifter.analyze_internal_calls(
                code,
                base=extent.rva,
                source_extent_size=extent.size,
                native_call_targets=native_call_targets,
            )
            internal_call_count = len(call_analysis.internal_call_rvas)
            max_internal_call_depth = call_analysis.max_call_depth
        candidate_gaps = global_gaps
        if extent.heuristic:
            candidate_gaps = _coverage_gaps(
                sections, (*runtime_pairs, (extent.rva, extent.rva + extent.size))
            )
        control_reason = None
        control_status = "not_run" if extent.size == 0 else "passed"
        extent_quarantined = any(
            begin < extent.rva + extent.size and extent.rva < end
            for begin, end in quarantined_ranges
        )
        if extent.size and direct_error is not None:
            control_status = "rejected"
            control_reason = "global direct-control analysis rejected: " + direct_error
        elif extent.size and extent_quarantined:
            control_status = "rejected"
            control_reason = (
                "function contains unresolved data-in-code; bailed to native "
                "so the rest of the image stays analyzable"
            )
        elif extent.size:
            for transfer in direct_transfers:
                if (
                        extent.rva + extent.lifted_body_size
                        <= transfer.target_rva < extent.rva + extent.size):
                    control_status = "rejected"
                    control_reason = (
                        f"direct {transfer.kind} at RVA 0x{transfer.source_rva:X} "
                        f"targets candidate padding suffix RVA "
                        f"0x{transfer.target_rva:X}"
                    )
                    break
                if (extent.rva < transfer.target_rva < extent.rva + extent.size
                        and not extent.rva <= transfer.source_rva < extent.rva + extent.size):
                    control_status = "rejected"
                    control_reason = (
                        f"direct {transfer.kind} at RVA 0x{transfer.source_rva:X} "
                        f"enters candidate interior RVA 0x{transfer.target_rva:X}"
                    )
                    break
        if extent.size and control_status == "passed":
            control_reason = reference_index.rejection(extent.name, extent.rva, extent.size)
            if control_reason is None and extent.heuristic:
                # Export/MAP-only leaves are absent from the cached pdata scan.
                try:
                    code = _read_executable(sections, extent.rva, extent.size, "candidate")
                    body = jump_table.decode_function_body(code, extent.rva, extent.rva + extent.size)
                    leaf_references = source_references.instruction_references(body.instructions)
                    source_references.SourceReferenceIndex(
                        leaf_references,
                        proven_entry_calls=source_references.proven_immediate_entry_calls(
                            (*reference_groups, tuple(body.instructions)),
                            known_entry_targets=(item.target_rva for item in
                                                 (*reference_index.references, *leaf_references)
                                                 if item.address_only),
                        ),
                    ).validate((extent,))
                except (jump_table.JumpTableUnresolved, source_references.SourceReferenceError) as exc:
                    control_reason = str(exc)
            if control_reason is not None:
                control_status = "rejected"
        candidates.append(FunctionCandidate(
            name=extent.name,
            source=extent.source,
            rva=extent.rva,
            size=extent.size,
            extent_kind=extent.extent_kind,
            exact_extent=extent.exact,
            heuristic=extent.heuristic,
            unwind_flags=extent.unwind_flags,
            unwind_flag_names=_flag_names(extent.unwind_flags),
            liftable=liftable,
            rejection_reason=rejection,
            first_unsupported_instruction=first,
            direct_control_proof_status=control_status,
            direct_control_rejection_reason=control_reason,
            direct_reference_gate_passed=(
                control_status == "passed" and not candidate_gaps
            ),
            executable_coverage_gaps=candidate_gaps,
            indirect_target_closure_proven=False,
            internal_direct_call_count=internal_call_count,
            max_internal_call_depth=max_internal_call_depth,
            rip_relative_references=rip_references,
            lifted_body_size=extent.lifted_body_size,
        ))

    return FunctionDiscoveryReport(
        image_path=str(getattr(parsed, "path", "")),
        image_base=parsed.image_base,
        size_of_image=parsed.size_of_image,
        candidates=tuple(candidates),
        executable_coverage_gaps=global_gaps,
        direct_control_analysis_status=direct_status,
        direct_control_analysis_error=direct_error,
    )


def render_table(report: FunctionDiscoveryReport) -> str:
    """Render a compact deterministic human report."""
    headers = ("RVA", "SIZE", "FLAGS", "LIFT", "CALLS", "DIRECT", "SOURCE", "NAME")
    rows = []
    for item in report.candidates:
        rows.append((
            f"0x{item.rva:08X}",
            f"0x{item.size:X}" if item.size else "?",
            "|".join(item.unwind_flag_names) or "none",
            "yes" if item.liftable else "no",
            f"{item.internal_direct_call_count}/{item.max_internal_call_depth}",
            item.direct_control_proof_status,
            item.source,
            item.name,
        ))
    widths = [len(value) for value in headers]
    for row in rows:
        widths = [max(width, len(value)) for width, value in zip(widths, row)]
    lines = ["  ".join(value.ljust(width) for value, width in zip(headers, widths))]
    lines.append("  ".join("-" * width for width in widths))
    lines.extend(
        "  ".join(value.ljust(width) for value, width in zip(row, widths))
        for row in rows
    )
    lines.append("")
    lines.append(
        f"Candidates: {len(rows)} | coverage gaps: "
        f"{len(report.executable_coverage_gaps)} | indirect closure: unproven"
    )
    rejected = [item for item in report.candidates if not item.liftable]
    for item in rejected:
        lines.append(f"- {item.name}: {item.rejection_reason}")
    for item in report.candidates:
        if item.direct_control_rejection_reason:
            lines.append(
                f"- {item.name} direct proof: "
                f"{item.direct_control_rejection_reason}"
            )
    for gap in report.executable_coverage_gaps:
        lines.append(
            f"- coverage gap {gap.section_name}: "
            f"0x{gap.rva:08X}+0x{gap.size:X}"
        )
    return "\n".join(lines) + "\n"


__all__ = [
    "CoverageGap",
    "DEFAULT_LEAF_CAP",
    "ExportSymbol",
    "FunctionCandidate",
    "FunctionDiscoveryError",
    "FunctionDiscoveryReport",
    "MapSymbol",
    "UnsupportedInstruction",
    "discover_functions",
    "parse_msvc_map",
    "parse_pe_exports",
    "render_table",
]
