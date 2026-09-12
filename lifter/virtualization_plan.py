"""Strict builder-side planning for explicitly selected x64 functions.

This module does not discover functions and does not mutate a PE. It turns an
explicit first-party ``(name, RVA, size)`` allowlist plus a strict executable
byte reader into a deterministic artifact manifest that a later packer stage
can place and relocate atomically.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence

from iced_x86 import Decoder, Mnemonic, OpKind

try:  # package import
    from . import win64_thunk, x64_lifter
except ImportError:  # standalone tests/tools
    import win64_thunk  # type: ignore
    import x64_lifter  # type: ignore

try:
    from daedalus import daedalus_asm, daedalus_rolling
except ImportError:  # standalone tests put daedalus/ directly on sys.path
    import daedalus_asm  # type: ignore
    import daedalus_rolling  # type: ignore


IMAGE_SCN_MEM_EXECUTE = 0x20000000
MANIFEST_VERSION = 2
DESCRIPTOR_VERSION_PLAIN = 3
DESCRIPTOR_VERSION_PAGED = 4
TARGET_ENTRY_PATCH_SIZE = 5
_RVA_LIMIT = 0x1_0000_0000
_NAME_LIMIT = 128
_SYMBOL_SAFE = re.compile(r"[^A-Za-z0-9_]")
EXTERNAL_ENTRY_ASSUMPTION = (
    "No external control-flow edge may enter the selected function at any RVA "
    "after its first byte; every external caller or branch must enter at the "
    "declared target RVA so the five-byte entry JMP cannot be bypassed."
)
STUB_COMMON_ENTRY_EXPORT = "daedalus_x64_enter_common"
STUB_OPCODE_HASH_EXPORT = "daedalus_opcode_mapping_sha256"
STUB_HANDLER_VARIANT_HASH_EXPORT = "daedalus_handler_variant_sha256"
TARGET_TOMBSTONE_POLICY = (
    "Replace the entire selected extent: E9 rel32 at the entry followed by "
    "one-byte INT3 (0xCC) tombstones at every remaining RVA."
)
UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4
_RUNTIME_FUNCTION_SIZE = 12


class VirtualizationPlanError(ValueError):
    """A strict input, lift, or generated-layout contract was rejected."""


class FunctionRejected(VirtualizationPlanError):
    """One selected function failed whole-function validation or lifting."""

    def __init__(self, spec: "FunctionSpec", reason: str) -> None:
        self.spec = spec
        self.reason = reason
        super().__init__(f"function {spec.name!r} at RVA 0x{spec.rva:X}: {reason}")


@dataclass(frozen=True)
class FunctionSpec:
    name: str
    rva: int
    size: int


@dataclass(frozen=True)
class OpcodeTable:
    """Immutable, validated mnemonic-to-wire mapping for one stub build."""

    identity: str
    entries: tuple[tuple[str, int, int, str], ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.identity, str)
            or not self.identity
            or len(self.identity) > _NAME_LIMIT
            or "\0" in self.identity
        ):
            raise VirtualizationPlanError(
                "opcode mapping identity must be 1..128 non-NUL characters"
            )
        if not isinstance(self.entries, tuple):
            raise VirtualizationPlanError("opcode mapping entries must be immutable")

        canonical = daedalus_asm.OPCODES
        names = set()
        wires = set()
        for entry in self.entries:
            if not isinstance(entry, tuple) or len(entry) != 4:
                raise VirtualizationPlanError("invalid opcode mapping entry")
            mnemonic, wire, width, kind = entry
            if (
                not isinstance(mnemonic, str)
                or mnemonic not in canonical
                or mnemonic in names
            ):
                raise VirtualizationPlanError(
                    f"opcode mapping has unknown or duplicate mnemonic {mnemonic!r}"
                )
            canonical_width, canonical_kind = canonical[mnemonic][1:]
            if width != canonical_width or kind != canonical_kind:
                raise VirtualizationPlanError(
                    f"opcode mapping changes operand ABI for {mnemonic!r}"
                )
            if not isinstance(wire, int) or not 0 <= wire <= 0xFF or wire in wires:
                raise VirtualizationPlanError(
                    f"opcode mapping has invalid or duplicate wire byte for {mnemonic!r}"
                )
            names.add(mnemonic)
            wires.add(wire)
        if self.entries != tuple(sorted(self.entries)):
            raise VirtualizationPlanError(
                "opcode mapping entries must use deterministic mnemonic order"
            )
        if names != set(canonical):
            missing = sorted(set(canonical) - names)
            raise VirtualizationPlanError(
                "opcode mapping is incomplete; missing " + ", ".join(missing)
            )

    @classmethod
    def canonical(cls) -> "OpcodeTable":
        return cls.from_mapping(daedalus_asm.OPCODES, identity="canonical")

    @classmethod
    def from_mapping(
        cls,
        mapping: Mapping[str, tuple[int, int, str]],
        *,
        identity: str,
    ) -> "OpcodeTable":
        try:
            entries = tuple(
                sorted(
                    (
                        str(mnemonic),
                        int(spec[0]),
                        int(spec[1]),
                        str(spec[2]),
                    )
                    for mnemonic, spec in mapping.items()
                )
            )
        except (AttributeError, IndexError, TypeError, ValueError) as exc:
            raise VirtualizationPlanError("invalid opcode mapping") from exc
        return cls(identity=identity, entries=entries)

    @property
    def sha256(self) -> str:
        wire_identity = json.dumps(
            self.entries, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return hashlib.sha256(wire_identity).hexdigest()

    @property
    def is_canonical(self) -> bool:
        return self.entries == OpcodeTable.canonical().entries

    def assembler_mapping(self) -> Mapping[str, tuple[int, int, str]]:
        return MappingProxyType(
            {
                mnemonic: (wire, width, kind)
                for mnemonic, wire, width, kind in self.entries
            }
        )

    def decoder_mapping(self) -> Mapping[int, tuple[str, int, str]]:
        return MappingProxyType(
            {
                wire: (mnemonic, width, kind)
                for mnemonic, wire, width, kind in self.entries
            }
        )


@dataclass(frozen=True)
class SectionBytes:
    name: str
    rva: int
    virtual_size: int
    raw: bytes
    characteristics: int


class ExecutableReader(Protocol):
    def read_file_backed_executable(self, rva: int, size: int) -> bytes:
        """Return exactly size bytes or raise VirtualizationPlanError."""


class SectionImage:
    """Strict reader over PE-like section records.

    A selected function must fit in one section's actual raw bytes. Virtual
    zero-fill, adjacent sections, and executable-looking mapped padding never
    count as file-backed code.
    """

    def __init__(self, sections: Iterable[SectionBytes]) -> None:
        normalized = tuple(sorted(sections, key=lambda section: section.rva))
        if not normalized:
            raise VirtualizationPlanError("at least one section is required")
        previous_end = 0
        previous_name = ""
        for section in normalized:
            if section.rva <= 0 or section.rva >= _RVA_LIMIT:
                raise VirtualizationPlanError(
                    f"section {section.name!r} has invalid RVA 0x{section.rva:X}"
                )
            if section.virtual_size < 0:
                raise VirtualizationPlanError(
                    f"section {section.name!r} has negative virtual size"
                )
            raw = bytes(section.raw)
            mapped_size = max(section.virtual_size, len(raw))
            end = section.rva + mapped_size
            if mapped_size <= 0 or end > _RVA_LIMIT:
                raise VirtualizationPlanError(
                    f"section {section.name!r} has invalid mapped range"
                )
            if section.rva < previous_end:
                raise VirtualizationPlanError(
                    f"sections {previous_name!r} and {section.name!r} overlap"
                )
            previous_end = end
            previous_name = section.name
        self.sections = normalized

    @classmethod
    def from_parsed_sections(cls, sections: Iterable[Any]) -> "SectionImage":
        return cls(
            SectionBytes(
                name=str(section.name),
                rva=int(section.rva),
                virtual_size=int(section.virtual_size),
                raw=bytes(section.raw),
                characteristics=int(section.characteristics),
            )
            for section in sections
        )

    def read_file_backed_executable(self, rva: int, size: int) -> bytes:
        _validate_rva_range(rva, size, "selected function")
        end = rva + size
        owner = next(
            (
                section
                for section in self.sections
                if section.rva <= rva
                and end <= section.rva + max(section.virtual_size, len(section.raw))
            ),
            None,
        )
        if owner is None:
            raise VirtualizationPlanError(
                f"RVA range 0x{rva:X}..0x{end:X} is not wholly in one section"
            )
        if not (owner.characteristics & IMAGE_SCN_MEM_EXECUTE):
            raise VirtualizationPlanError(
                f"section {owner.name!r} is not executable"
            )
        raw_end = owner.rva + len(owner.raw)
        if end > raw_end:
            raise VirtualizationPlanError(
                f"RVA range reaches non-file-backed bytes in section {owner.name!r}"
            )
        offset = rva - owner.rva
        result = bytes(owner.raw[offset : offset + size])
        if len(result) != size:
            raise VirtualizationPlanError("strict section reader returned truncated data")
        return result


@dataclass(frozen=True)
class RelocationRequirement:
    kind: str
    patch_rva: int
    target_rva: int | None = None
    target_symbol: str | None = None
    add_image_base: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "patch_rva": self.patch_rva,
            "target_rva": self.target_rva,
            "target_symbol": self.target_symbol,
            "add_image_base": self.add_image_base,
        }


@dataclass(frozen=True)
class TargetEntryPatch:
    patch_rva: int
    destination_rva: int
    displacement: int
    patch: bytes
    original_extent_size: int
    external_entry_assumption: str = EXTERNAL_ENTRY_ASSUMPTION
    tombstone_policy: str = TARGET_TOMBSTONE_POLICY

    def to_dict(self) -> dict[str, Any]:
        return {
            "patch_rva": self.patch_rva,
            "destination_rva": self.destination_rva,
            "displacement": self.displacement,
            "patch_size": len(self.patch),
            "patch_hex": self.patch.hex(),
            "patch_sha256": hashlib.sha256(self.patch).hexdigest(),
            "original_extent_size": self.original_extent_size,
            "external_entry_assumption": self.external_entry_assumption,
            "tombstone_policy": self.tombstone_policy,
        }


@dataclass(frozen=True, order=True)
class SourceDir64Relocation:
    """One source image DIR64 relocation target (the eight-byte patch site)."""

    target_rva: int

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "DIR64", "target_rva": self.target_rva, "size": 8}


@dataclass(frozen=True)
class SourceRuntimeFunction:
    begin_rva: int
    end_rva: int
    unwind_info_rva: int
    unwind_flags: int = 0


@dataclass(frozen=True)
class SourceExceptionMetadata:
    """Complete source AMD64 exception directory metadata in on-disk order."""

    table_rva: int
    records: tuple[SourceRuntimeFunction, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.records, tuple):
            raise VirtualizationPlanError(
                "source exception records must be an immutable tuple"
            )


@dataclass(frozen=True)
class PlannedRuntimeFunction:
    origin: str
    begin_rva: int
    end_rva: int
    unwind_info_rva: int
    unwind_flags: int
    record_rva: int | None
    source_record_rva: int | None = None
    function_name: str | None = None

    @property
    def packed(self) -> bytes:
        return struct.pack(
            "<III", self.begin_rva, self.end_rva, self.unwind_info_rva
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "begin_rva": self.begin_rva,
            "end_rva": self.end_rva,
            "unwind_info_rva": self.unwind_info_rva,
            "unwind_flags": self.unwind_flags,
            "record_rva": self.record_rva,
            "source_record_rva": self.source_record_rva,
            "function_name": self.function_name,
            "record_hex": self.packed.hex(),
        }


@dataclass(frozen=True)
class ExceptionTablePlan:
    source_table_rva: int | None
    source_table_size: int
    output_table_rva: int
    output_table_size: int
    retained: tuple[PlannedRuntimeFunction, ...]
    removed: tuple[PlannedRuntimeFunction, ...]
    generated: tuple[PlannedRuntimeFunction, ...]
    merged: tuple[PlannedRuntimeFunction, ...]
    table: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_table_rva": self.source_table_rva,
            "source_table_size": self.source_table_size,
            "output_table_rva": self.output_table_rva,
            "output_table_size": self.output_table_size,
            "table_hex": self.table.hex(),
            "table_sha256": hashlib.sha256(self.table).hexdigest(),
            "retained": [record.to_dict() for record in self.retained],
            "removed": [record.to_dict() for record in self.removed],
            "generated": [record.to_dict() for record in self.generated],
            "merged": [record.to_dict() for record in self.merged],
        }


@dataclass(frozen=True)
class GeneratedExecutableRange:
    symbol: str
    rva: int
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {"symbol": self.symbol, "rva": self.rva, "size": self.size}


@dataclass(frozen=True)
class UnwindPlan:
    begin_rva: int
    end_rva: int
    unwind_info_rva: int
    unwind_info: bytes
    runtime_function: bytes
    runtime_function_rva: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "begin_rva": self.begin_rva,
            "end_rva": self.end_rva,
            "unwind_info_rva": self.unwind_info_rva,
            "unwind_info_hex": self.unwind_info.hex(),
            "runtime_function_hex": self.runtime_function.hex(),
            "runtime_function_rva": self.runtime_function_rva,
        }


@dataclass(frozen=True)
class VirtualizedFunction:
    name: str
    target_rva: int
    target_size: int
    original_sha256: str
    target_entry_patch: TargetEntryPatch
    program_format: str
    program: bytes
    program_sha256: str
    program_id: bytes
    program_rva: int
    thunk_symbol: str
    descriptor_symbol: str
    thunk_asm: str
    thunk_template: bytes
    thunk_sha256: str
    descriptor_rva: int
    descriptor_data: bytes
    required_relocations: tuple[RelocationRequirement, ...]
    generated_executable_ranges: tuple[GeneratedExecutableRange, ...]
    cfg_target_rvas: tuple[int, ...]
    unwind: UnwindPlan
    capabilities: dict[str, bool]
    internal_call_rvas: tuple[int, ...]
    max_internal_call_depth: int
    rip_relative_references: tuple[x64_lifter.RipRelativeReference, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target_rva": self.target_rva,
            "target_size": self.target_size,
            "original_sha256": self.original_sha256,
            "target_entry_patch": self.target_entry_patch.to_dict(),
            "program_format": self.program_format,
            "program_hex": self.program.hex(),
            "program_sha256": self.program_sha256,
            "program_id_hex": self.program_id.hex(),
            "program_rva": self.program_rva,
            "thunk_symbol": self.thunk_symbol,
            "descriptor_symbol": self.descriptor_symbol,
            "thunk_asm": self.thunk_asm,
            "thunk_template_hex": self.thunk_template.hex(),
            "thunk_sha256": self.thunk_sha256,
            "descriptor_rva": self.descriptor_rva,
            "descriptor_data_hex": self.descriptor_data.hex(),
            "required_relocations": [
                relocation.to_dict() for relocation in self.required_relocations
            ],
            "generated_executable_ranges": [
                generated.to_dict()
                for generated in self.generated_executable_ranges
            ],
            "cfg_target_rvas": list(self.cfg_target_rvas),
            "unwind": self.unwind.to_dict(),
            "capabilities": dict(sorted(self.capabilities.items())),
            "internal_call_rvas": list(self.internal_call_rvas),
            "max_internal_call_depth": self.max_internal_call_depth,
            "rip_relative_references": [
                reference.to_dict() for reference in self.rip_relative_references
            ],
        }


@dataclass(frozen=True)
class VirtualizationManifest:
    version: int
    generated_text_rva: int
    generated_text_size: int
    generated_data_rva: int
    generated_data_size: int
    opcode_mapping_identity: str
    opcode_mapping_sha256: str
    runtime_common_rva: int | None
    source_relocation_metadata_complete: bool
    checked_source_dir64_relocations: tuple[SourceDir64Relocation, ...]
    source_exception_metadata_complete: bool
    exception_table: ExceptionTablePlan
    functions: tuple[VirtualizedFunction, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generated_text_rva": self.generated_text_rva,
            "generated_text_size": self.generated_text_size,
            "generated_data_rva": self.generated_data_rva,
            "generated_data_size": self.generated_data_size,
            "opcode_mapping_identity": self.opcode_mapping_identity,
            "opcode_mapping_sha256": self.opcode_mapping_sha256,
            "opcode_mapping_provenance_export": STUB_OPCODE_HASH_EXPORT,
            "runtime_common_entry_export": STUB_COMMON_ENTRY_EXPORT,
            "runtime_common_rva": self.runtime_common_rva,
            "source_relocation_metadata_complete": (
                self.source_relocation_metadata_complete
            ),
            "checked_source_dir64_relocations": [
                relocation.to_dict()
                for relocation in self.checked_source_dir64_relocations
            ],
            "source_exception_metadata_complete": (
                self.source_exception_metadata_complete
            ),
            "exception_table": self.exception_table.to_dict(),
            "external_entry_assumption": EXTERNAL_ENTRY_ASSUMPTION,
            "functions": [function.to_dict() for function in self.functions],
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            indent=indent,
            separators=(",", ":") if indent is None else None,
        )


@dataclass(frozen=True)
class _Compiled:
    spec: FunctionSpec
    original: bytes
    program: bytes
    program_format: str
    thunk_symbol: str
    descriptor_symbol: str
    thunk_asm: str
    call_analysis: x64_lifter.InternalCallAnalysis
    rip_relative_references: tuple[x64_lifter.RipRelativeReference, ...]
    program_id: bytes = b""


def _validate_rva_range(rva: int, size: int, label: str) -> None:
    if not isinstance(rva, int) or not isinstance(size, int):
        raise VirtualizationPlanError(f"{label} RVA and size must be integers")
    end = rva + size
    if rva <= 0 or size <= 0 or rva >= _RVA_LIMIT or end > _RVA_LIMIT:
        raise VirtualizationPlanError(
            f"{label} has invalid RVA range 0x{rva:X}+0x{size:X}"
        )


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _symbol_stem(spec: FunctionSpec) -> str:
    safe = _SYMBOL_SAFE.sub("_", spec.name).strip("_") or "function"
    if safe[0].isdigit():
        safe = "f_" + safe
    safe = safe[:40]
    identity = f"{spec.name}\0{spec.rva:08X}\0{spec.size:X}".encode("utf-8")
    suffix = hashlib.sha256(identity).hexdigest()[:10]
    return f"lethe_vfn_{spec.rva:08X}_{safe}_{suffix}"


def _validate_specs(specs: Sequence[FunctionSpec]) -> tuple[FunctionSpec, ...]:
    if not specs:
        raise VirtualizationPlanError("at least one explicit function is required")
    ordered = []
    for spec in specs:
        if not isinstance(spec, FunctionSpec):
            raise VirtualizationPlanError("all function entries must be FunctionSpec")
        if not spec.name or len(spec.name) > _NAME_LIMIT or "\0" in spec.name:
            raise VirtualizationPlanError("function name must be 1..128 non-NUL characters")
        _validate_rva_range(spec.rva, spec.size, f"function {spec.name!r}")
        if spec.size < TARGET_ENTRY_PATCH_SIZE:
            raise VirtualizationPlanError(
                f"function {spec.name!r} is too small for a five-byte near-JMP entry patch"
            )
        ordered.append(spec)
    ordered.sort(key=lambda item: (item.rva, item.size, item.name))
    for previous, current in zip(ordered, ordered[1:]):
        if current.rva < previous.rva + previous.size:
            raise VirtualizationPlanError(
                f"selected functions {previous.name!r} and {current.name!r} overlap"
            )
    return tuple(ordered)


def _validate_source_relocations(
    relocations: Sequence[SourceDir64Relocation] | None,
    specs: Sequence[FunctionSpec],
    *,
    required: bool,
) -> tuple[SourceDir64Relocation, ...]:
    if relocations is None:
        if required:
            raise VirtualizationPlanError(
                "production planning requires explicit source DIR64 relocation metadata"
            )
        return ()

    normalized = []
    seen = set()
    for relocation in relocations:
        if not isinstance(relocation, SourceDir64Relocation):
            raise VirtualizationPlanError(
                "all source relocation entries must be SourceDir64Relocation"
            )
        _validate_rva_range(
            relocation.target_rva, 8, "source DIR64 relocation target"
        )
        if relocation.target_rva in seen:
            raise VirtualizationPlanError(
                f"duplicate source DIR64 relocation target RVA 0x{relocation.target_rva:X}"
            )
        seen.add(relocation.target_rva)
        normalized.append(relocation)
    normalized.sort()

    for relocation in normalized:
        relocation_end = relocation.target_rva + 8
        for spec in specs:
            if relocation.target_rva < spec.rva + spec.size and spec.rva < relocation_end:
                raise FunctionRejected(
                    spec,
                    f"source DIR64 relocation target at RVA 0x{relocation.target_rva:X} overlaps the selected extent",
                )
    return tuple(normalized)


def _unwind_flag_names(flags: int) -> str:
    names = []
    if flags & UNW_FLAG_EHANDLER:
        names.append("EHANDLER")
    if flags & UNW_FLAG_UHANDLER:
        names.append("UHANDLER")
    if flags & UNW_FLAG_CHAININFO:
        names.append("CHAININFO")
    return "|".join(names) or "none"


def _validate_source_exceptions(
    metadata: SourceExceptionMetadata | None,
    specs: Sequence[FunctionSpec],
    *,
    required: bool,
) -> tuple[
    tuple[PlannedRuntimeFunction, ...],
    tuple[PlannedRuntimeFunction, ...],
]:
    if metadata is None:
        if required:
            raise VirtualizationPlanError(
                "production planning requires complete source exception metadata"
            )
        return (), ()
    if not isinstance(metadata, SourceExceptionMetadata):
        raise VirtualizationPlanError(
            "source_exception_metadata must be SourceExceptionMetadata"
        )
    if metadata.records:
        _validate_rva_range(
            metadata.table_rva,
            len(metadata.records) * _RUNTIME_FUNCTION_SIZE,
            "source exception table",
        )
        if metadata.table_rva % 4:
            raise VirtualizationPlanError(
                "source exception table RVA must be four-byte aligned"
            )
    elif metadata.table_rva != 0:
        raise VirtualizationPlanError(
            "an empty source exception table must use RVA zero"
        )

    retained = []
    removed = []
    previous: SourceRuntimeFunction | None = None
    for index, record in enumerate(metadata.records):
        if not isinstance(record, SourceRuntimeFunction):
            raise VirtualizationPlanError(
                "all source exception records must be SourceRuntimeFunction"
            )
        _validate_rva_range(
            record.begin_rva,
            record.end_rva - record.begin_rva,
            "source runtime-function range",
        )
        _validate_rva_range(
            record.unwind_info_rva, 1, "source unwind-info RVA"
        )
        if record.unwind_info_rva % 4:
            raise VirtualizationPlanError(
                "source unwind-info RVA must be four-byte aligned"
            )
        if (
            not isinstance(record.unwind_flags, int)
            or record.unwind_flags < 0
            or record.unwind_flags
            & ~(UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO)
        ):
            raise VirtualizationPlanError(
                "source runtime-function has invalid unwind flags"
            )
        if previous is not None:
            if record.begin_rva < previous.begin_rva:
                raise VirtualizationPlanError(
                    "source runtime-function ranges are not sorted by BeginAddress"
                )
            if record.begin_rva < previous.end_rva:
                raise VirtualizationPlanError(
                    "source runtime-function ranges overlap"
                )
        previous = record

        source_record_rva = (
            metadata.table_rva + index * _RUNTIME_FUNCTION_SIZE
        )
        planned = PlannedRuntimeFunction(
            origin="source",
            begin_rva=record.begin_rva,
            end_rva=record.end_rva,
            unwind_info_rva=record.unwind_info_rva,
            unwind_flags=record.unwind_flags,
            record_rva=None,
            source_record_rva=source_record_rva,
        )
        selected = None
        for spec in specs:
            if record.begin_rva < spec.rva + spec.size and spec.rva < record.end_rva:
                selected = spec
                break
        if selected is None:
            retained.append(planned)
            continue
        if (
            record.begin_rva != selected.rva
            or record.end_rva != selected.rva + selected.size
        ):
            raise FunctionRejected(
                selected,
                "source runtime-function only partially matches the selected extent",
            )
        if record.unwind_flags:
            raise FunctionRejected(
                selected,
                "source runtime-function uses unsupported unwind flags "
                + _unwind_flag_names(record.unwind_flags),
            )
        removed.append(replace(planned, function_name=selected.name))
    return tuple(retained), tuple(removed)


def _allocate_exception_table(
    retained: Sequence[PlannedRuntimeFunction],
    removed: Sequence[PlannedRuntimeFunction],
    functions: Sequence[VirtualizedFunction],
    *,
    output_table_rva: int,
    source_table_rva: int | None,
    source_table_size: int,
) -> tuple[ExceptionTablePlan, tuple[VirtualizedFunction, ...]]:
    generated_drafts = tuple(
        PlannedRuntimeFunction(
            origin="generated",
            begin_rva=function.unwind.begin_rva,
            end_rva=function.unwind.end_rva,
            unwind_info_rva=function.unwind.unwind_info_rva,
            unwind_flags=0,
            record_rva=None,
            function_name=function.name,
        )
        for function in functions
    )
    merged_drafts = sorted(
        (*retained, *generated_drafts),
        key=lambda record: (
            record.begin_rva,
            record.end_rva,
            record.unwind_info_rva,
            record.origin,
        ),
    )
    for previous, current in zip(merged_drafts, merged_drafts[1:]):
        if current.begin_rva < previous.end_rva:
            raise VirtualizationPlanError(
                "retained and generated runtime-function ranges overlap"
            )

    allocated = tuple(
        replace(
            record,
            record_rva=output_table_rva + index * _RUNTIME_FUNCTION_SIZE,
        )
        for index, record in enumerate(merged_drafts)
    )
    retained_allocated = tuple(
        record for record in allocated if record.origin == "source"
    )
    generated_allocated = tuple(
        record for record in allocated if record.origin == "generated"
    )
    generated_by_begin = {
        record.begin_rva: record for record in generated_allocated
    }
    updated_functions = tuple(
        replace(
            function,
            unwind=replace(
                function.unwind,
                runtime_function_rva=generated_by_begin[
                    function.unwind.begin_rva
                ].record_rva,
            ),
        )
        for function in functions
    )
    table = b"".join(record.packed for record in allocated)
    return (
        ExceptionTablePlan(
            source_table_rva=source_table_rva,
            source_table_size=source_table_size,
            output_table_rva=output_table_rva,
            output_table_size=len(table),
            retained=retained_allocated,
            removed=tuple(removed),
            generated=generated_allocated,
            merged=allocated,
            table=table,
        ),
        updated_functions,
    )


def _decode_exact(spec: FunctionSpec, code: bytes):
    decoder = Decoder(64, code, ip=spec.rva)
    instructions = list(decoder)
    if not instructions:
        raise FunctionRejected(spec, "declared extent contains no instructions")
    cursor = spec.rva
    starts = set()
    for instruction in instructions:
        if instruction.ip != cursor or instruction.code == 0 or instruction.len <= 0:
            raise FunctionRejected(spec, f"invalid instruction at RVA 0x{cursor:X}")
        starts.add(instruction.ip)
        cursor += instruction.len
    if cursor != spec.rva + spec.size:
        raise FunctionRejected(
            spec,
            f"decoder consumed 0x{cursor - spec.rva:X} bytes, expected 0x{spec.size:X}",
        )
    for instruction in instructions:
        if instruction.mnemonic == Mnemonic.JMP or instruction.mnemonic in x64_lifter._CC:
            if instruction.op_kind(0) != OpKind.NEAR_BRANCH64:
                raise FunctionRejected(spec, "indirect or non-near branch")
            target = instruction.near_branch_target
            if target not in starts:
                raise FunctionRejected(
                    spec,
                    f"branch target RVA 0x{target:X} is not an instruction boundary",
                )
    final = instructions[-1]
    if final.mnemonic != Mnemonic.RET or final.op_count != 0:
        raise FunctionRejected(spec, "declared extent must end in a plain RET")
    return instructions


def _compile_one(
    spec: FunctionSpec,
    reader: ExecutableReader,
    *,
    rolling: bool,
    rolling_seed: bytes | None,
    opcode_table: OpcodeTable,
    image_sections: Sequence[Any] | None,
    selected_extents: Sequence[tuple[int, int]],
) -> _Compiled:
    try:
        original = bytes(reader.read_file_backed_executable(spec.rva, spec.size))
    except FunctionRejected:
        raise
    except (TypeError, ValueError, VirtualizationPlanError) as exc:
        raise FunctionRejected(spec, str(exc)) from exc
    if len(original) != spec.size:
        raise FunctionRejected(
            spec,
            f"strict reader returned {len(original)} bytes, expected {spec.size}",
        )
    _decode_exact(spec, original)
    try:
        call_analysis = x64_lifter.analyze_internal_calls(original, base=spec.rva)
        rip_relative_references = x64_lifter.validate_rip_relative_references(
            original,
            base=spec.rva,
            image_sections=image_sections,
            selected_extents=selected_extents,
        )
        assembly = x64_lifter.lift_function(
            original,
            base=spec.rva,
            image_sections=image_sections,
            selected_extents=selected_extents,
        )
        program = daedalus_asm.assemble(
            assembly, opcodes=opcode_table.assembler_mapping()
        )
    except (x64_lifter.LiftUnsupported, SyntaxError, ValueError) as exc:
        raise FunctionRejected(spec, f"whole-function lift rejected: {exc}") from exc

    program_format = "plain"
    if rolling:
        assert rolling_seed is not None
        function_seed = hashlib.sha256(
            b"Lethe-virtual-function\0"
            + rolling_seed
            + spec.name.encode("utf-8")
            + struct.pack("<II", spec.rva, spec.size)
        ).digest()[:16]
        program = daedalus_rolling.pack_rolling_blob(
            program,
            function_seed,
            optable=opcode_table.decoder_mapping(),
        )
        program_format = "rolling"

    thunk_symbol = _symbol_stem(spec)
    descriptor_symbol = thunk_symbol + "_descriptor"
    return _Compiled(
        spec=spec,
        original=original,
        program=program,
        program_format=program_format,
        thunk_symbol=thunk_symbol,
        descriptor_symbol=descriptor_symbol,
        thunk_asm=win64_thunk.render_entry_thunk(thunk_symbol, descriptor_symbol),
        call_analysis=call_analysis,
        rip_relative_references=rip_relative_references,
    )


def compile_virtualization_manifest(
    specs: Sequence[FunctionSpec],
    reader: ExecutableReader,
    *,
    generated_text_rva: int,
    generated_data_rva: int,
    rolling: bool = False,
    rolling_seed: bytes | None = None,
    opcode_table: OpcodeTable | None = None,
    require_shuffled_opcodes: bool = False,
    expected_opcode_mapping_sha256: str | None = None,
    source_dir64_relocations: Sequence[SourceDir64Relocation] | None = None,
    require_source_relocation_metadata: bool = False,
    runtime_common_rva: int | None = None,
    source_exception_metadata: SourceExceptionMetadata | None = None,
    require_source_exception_metadata: bool = False,
    program_sealer: Callable[[FunctionSpec, bytes], tuple[bytes, bytes]] | None = None,
) -> VirtualizationManifest:
    """Compile an all-or-nothing selected-function virtualization manifest.

    ``generated_text_rva`` and ``generated_data_rva`` are reservations supplied
    by a future packer placement stage. This function only plans bytes, ranges,
    relocations, CFG targets, and unwind records; it never writes an output PE.
    """
    ordered = _validate_specs(specs)
    supplied_opcode_table = opcode_table
    if opcode_table is None:
        opcode_table = OpcodeTable.canonical()
    elif not isinstance(opcode_table, OpcodeTable):
        raise VirtualizationPlanError(
            "opcode_table must be an immutable OpcodeTable instance"
        )
    if require_shuffled_opcodes and (
        supplied_opcode_table is None or opcode_table.is_canonical
    ):
        raise VirtualizationPlanError(
            "shuffled production planning requires an explicit non-canonical opcode table"
        )
    if require_shuffled_opcodes and expected_opcode_mapping_sha256 is None:
        raise VirtualizationPlanError(
            "shuffled production planning requires the opcode mapping SHA-256 extracted from the stub export"
        )
    if expected_opcode_mapping_sha256 is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_opcode_mapping_sha256):
            raise VirtualizationPlanError(
                "expected opcode mapping SHA-256 must be 64 hexadecimal characters"
            )
        if opcode_table.sha256 != expected_opcode_mapping_sha256.lower():
            raise VirtualizationPlanError(
                "opcode mapping SHA-256 does not match the production stub mapping"
            )
    source_relocation_metadata_complete = source_dir64_relocations is not None
    checked_source_relocations = _validate_source_relocations(
        source_dir64_relocations,
        ordered,
        required=(
            require_source_relocation_metadata or require_shuffled_opcodes
        ),
    )
    source_exception_metadata_complete = source_exception_metadata is not None
    retained_runtime_functions, removed_runtime_functions = (
        _validate_source_exceptions(
            source_exception_metadata,
            ordered,
            required=(
                require_source_exception_metadata or require_shuffled_opcodes
            ),
        )
    )
    if runtime_common_rva is not None:
        _validate_rva_range(runtime_common_rva, 1, "runtime common entry")
    elif require_shuffled_opcodes:
        raise VirtualizationPlanError(
            "production planning requires the numeric runtime common RVA resolved from the stub export"
        )
    _validate_rva_range(generated_text_rva, 1, "generated text reservation")
    _validate_rva_range(generated_data_rva, 1, "generated data reservation")
    if generated_text_rva % 16 or generated_data_rva % 16:
        raise VirtualizationPlanError("generated text and data RVAs must be 16-byte aligned")
    if rolling:
        if rolling_seed is None or len(rolling_seed) != 16:
            raise VirtualizationPlanError("rolling mode requires a deterministic 16-byte seed")
        rolling_seed = bytes(rolling_seed)
    elif rolling_seed is not None:
        raise VirtualizationPlanError("rolling_seed is only valid when rolling=True")
    if program_sealer is not None and not callable(program_sealer):
        raise VirtualizationPlanError("program_sealer must be callable")
    if program_sealer is not None and rolling:
        raise VirtualizationPlanError(
            "authenticated page envelopes are incompatible with rolling programs"
        )

    image_sections = getattr(reader, "sections", None)
    selected_extents = tuple((spec.rva, spec.size) for spec in ordered)
    compiled = tuple(
        _compile_one(
            spec,
            reader,
            rolling=rolling,
            rolling_seed=rolling_seed,
            opcode_table=opcode_table,
            image_sections=image_sections,
            selected_extents=selected_extents,
        )
        for spec in ordered
    )
    descriptor_version = DESCRIPTOR_VERSION_PLAIN
    if program_sealer is not None:
        sealed_items = []
        for item in compiled:
            try:
                sealed, program_id = program_sealer(item.spec, item.program)
                sealed = bytes(sealed)
                program_id = bytes(program_id)
            except (TypeError, ValueError) as exc:
                raise FunctionRejected(
                    item.spec, f"authenticated page sealing rejected: {exc}"
                ) from exc
            if not sealed:
                raise FunctionRejected(
                    item.spec, "authenticated page sealer returned an empty envelope"
                )
            if len(program_id) != 16:
                raise FunctionRejected(
                    item.spec,
                    "authenticated page sealer must return a 16-byte program identity",
                )
            sealed_items.append(
                replace(
                    item,
                    program=sealed,
                    program_format="paged-v1",
                    program_id=program_id,
                )
            )
        compiled = tuple(sealed_items)
        descriptor_version = DESCRIPTOR_VERSION_PAGED

    text_cursor = 0
    data_cursor = 0
    functions = []
    for item in compiled:
        thunk_offset = _align(text_cursor, 16)
        thunk_rva = generated_text_rva + thunk_offset
        text_cursor = thunk_offset + win64_thunk.THUNK_CODE_SIZE

        entry_displacement = thunk_rva - (
            item.spec.rva + TARGET_ENTRY_PATCH_SIZE
        )
        if not -(1 << 31) <= entry_displacement <= (1 << 31) - 1:
            raise VirtualizationPlanError(
                f"function {item.spec.name!r} target-to-thunk displacement is outside signed rel32 range"
            )
        target_entry_patch = TargetEntryPatch(
            patch_rva=item.spec.rva,
            destination_rva=thunk_rva,
            displacement=entry_displacement,
            patch=(
                b"\xE9"
                + struct.pack("<i", entry_displacement)
                + b"\xCC" * (item.spec.size - TARGET_ENTRY_PATCH_SIZE)
            ),
            original_extent_size=item.spec.size,
        )
        if runtime_common_rva is not None:
            common_displacement = runtime_common_rva - (
                thunk_rva + win64_thunk.THUNK_COMMON_REL32_OFFSET + 4
            )
            if not -(1 << 31) <= common_displacement <= (1 << 31) - 1:
                raise VirtualizationPlanError(
                    f"function {item.spec.name!r} thunk-to-runtime displacement is outside signed rel32 range"
                )

        program_offset = _align(data_cursor, 16)
        program_rva = generated_data_rva + program_offset
        data_cursor = program_offset + len(item.program)

        unwind_offset = _align(data_cursor, 4)
        unwind_rva = generated_data_rva + unwind_offset
        data_cursor = unwind_offset + len(win64_thunk.THUNK_UNWIND_INFO)

        descriptor_offset = _align(data_cursor, 8)
        descriptor_rva = generated_data_rva + descriptor_offset
        if descriptor_version == DESCRIPTOR_VERSION_PAGED:
            descriptor_data = struct.pack(
                "<IIQ16sQ",
                DESCRIPTOR_VERSION_PAGED,
                len(item.program),
                0,
                item.program_id,
                0,
            )
            image_base_field_offset = 32
        else:
            descriptor_data = struct.pack(
                "<IIQQ", DESCRIPTOR_VERSION_PLAIN, len(item.program), 0, 0
            )
            image_base_field_offset = 16
        data_cursor = descriptor_offset + len(descriptor_data)

        end_rva = thunk_rva + win64_thunk.THUNK_CODE_SIZE
        if end_rva > _RVA_LIMIT:
            raise VirtualizationPlanError(
                "generated text output has an invalid RVA range"
            )
        if descriptor_rva + len(descriptor_data) > _RVA_LIMIT:
            raise VirtualizationPlanError(
                "generated data output has an invalid RVA range"
            )
        runtime_function = struct.pack("<III", thunk_rva, end_rva, unwind_rva)
        relocations = (
            RelocationRequirement(
                kind="REL32",
                patch_rva=thunk_rva + win64_thunk.THUNK_COMMON_REL32_OFFSET,
                target_rva=runtime_common_rva,
                target_symbol=STUB_COMMON_ENTRY_EXPORT,
            ),
            RelocationRequirement(
                kind="DIR64",
                patch_rva=(
                    thunk_rva + win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET
                ),
                target_rva=descriptor_rva,
                add_image_base=True,
            ),
            RelocationRequirement(
                kind="DIR64",
                patch_rva=descriptor_rva + 8,
                target_rva=program_rva,
                add_image_base=True,
            ),
            RelocationRequirement(
                kind="DIR64",
                patch_rva=descriptor_rva + image_base_field_offset,
                target_rva=0,
                add_image_base=True,
            ),
        )
        has_internal_calls = bool(item.call_analysis.internal_call_rvas)
        capabilities = {
            "cet_shadow_stack_balanced": True,
            "cfg_target_declared": False,
            "direct_only_thunk": True,
            "exception_handlers_supported": False,
            "external_calls_supported": False,
            "external_interior_entries_supported": False,
            "direct_internal_calls_supported": True,
            "leaf_only": not has_internal_calls,
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
            "return_address_shadow_validated": has_internal_calls,
            "rip_relative_data_addressing_supported": True,
        }
        if descriptor_version == DESCRIPTOR_VERSION_PAGED:
            capabilities["authenticated_bytecode_paging"] = True
        functions.append(
            VirtualizedFunction(
                name=item.spec.name,
                target_rva=item.spec.rva,
                target_size=item.spec.size,
                original_sha256=hashlib.sha256(item.original).hexdigest(),
                target_entry_patch=target_entry_patch,
                program_format=item.program_format,
                program=item.program,
                program_sha256=hashlib.sha256(item.program).hexdigest(),
                program_id=item.program_id,
                program_rva=program_rva,
                thunk_symbol=item.thunk_symbol,
                descriptor_symbol=item.descriptor_symbol,
                thunk_asm=item.thunk_asm,
                thunk_template=win64_thunk.render_entry_thunk_bytes(),
                thunk_sha256=hashlib.sha256(
                    win64_thunk.render_entry_thunk_bytes()
                ).hexdigest(),
                descriptor_rva=descriptor_rva,
                descriptor_data=descriptor_data,
                required_relocations=relocations,
                generated_executable_ranges=(
                    GeneratedExecutableRange(
                        symbol=item.thunk_symbol,
                        rva=thunk_rva,
                        size=win64_thunk.THUNK_CODE_SIZE,
                    ),
                ),
                # Every native caller continues to target the original RVA.
                # That entry performs a direct E9 transfer to this thunk, so
                # the thunk is deliberately not an indirect CFG/XFG target.
                cfg_target_rvas=(),
                unwind=UnwindPlan(
                    begin_rva=thunk_rva,
                    end_rva=end_rva,
                    unwind_info_rva=unwind_rva,
                    unwind_info=win64_thunk.THUNK_UNWIND_INFO,
                    runtime_function=runtime_function,
                    runtime_function_rva=0,
                ),
                capabilities=capabilities,
                internal_call_rvas=item.call_analysis.internal_call_rvas,
                max_internal_call_depth=item.call_analysis.max_call_depth,
                rip_relative_references=item.rip_relative_references,
            )
        )

    exception_offset = _align(data_cursor, 4)
    exception_table_rva = generated_data_rva + exception_offset
    exception_record_count = len(retained_runtime_functions) + len(functions)
    exception_table_size = exception_record_count * _RUNTIME_FUNCTION_SIZE
    _validate_rva_range(
        exception_table_rva,
        exception_table_size,
        "generated exception-table output",
    )
    exception_table, allocated_functions = _allocate_exception_table(
        retained_runtime_functions,
        removed_runtime_functions,
        functions,
        output_table_rva=exception_table_rva,
        source_table_rva=(
            source_exception_metadata.table_rva
            if source_exception_metadata is not None
            else None
        ),
        source_table_size=(
            len(source_exception_metadata.records) * _RUNTIME_FUNCTION_SIZE
            if source_exception_metadata is not None
            else 0
        ),
    )
    functions = list(allocated_functions)
    data_cursor = exception_offset + exception_table_size

    text_size = _align(text_cursor, 16)
    data_size = _align(data_cursor, 16)
    _validate_rva_range(generated_text_rva, text_size, "generated text output")
    _validate_rva_range(generated_data_rva, data_size, "generated data output")
    generated_ranges = (
        (generated_text_rva, generated_text_rva + text_size, "generated text"),
        (generated_data_rva, generated_data_rva + data_size, "generated data"),
    )
    if not (
        generated_ranges[0][1] <= generated_ranges[1][0]
        or generated_ranges[1][1] <= generated_ranges[0][0]
    ):
        raise VirtualizationPlanError("generated text and data reservations overlap")
    for spec in ordered:
        for start, end, label in generated_ranges:
            if spec.rva < end and start < spec.rva + spec.size:
                raise VirtualizationPlanError(
                    f"function {spec.name!r} overlaps {label} reservation"
                )

    return VirtualizationManifest(
        version=MANIFEST_VERSION,
        generated_text_rva=generated_text_rva,
        generated_text_size=text_size,
        generated_data_rva=generated_data_rva,
        generated_data_size=data_size,
        opcode_mapping_identity=opcode_table.identity,
        opcode_mapping_sha256=opcode_table.sha256,
        runtime_common_rva=runtime_common_rva,
        source_relocation_metadata_complete=(
            source_relocation_metadata_complete
        ),
        checked_source_dir64_relocations=checked_source_relocations,
        source_exception_metadata_complete=source_exception_metadata_complete,
        exception_table=exception_table,
        functions=tuple(functions),
    )


__all__ = [
    "EXTERNAL_ENTRY_ASSUMPTION",
    "ExceptionTablePlan",
    "ExecutableReader",
    "FunctionRejected",
    "FunctionSpec",
    "GeneratedExecutableRange",
    "IMAGE_SCN_MEM_EXECUTE",
    "MANIFEST_VERSION",
    "OpcodeTable",
    "PlannedRuntimeFunction",
    "RelocationRequirement",
    "SectionBytes",
    "SectionImage",
    "SourceDir64Relocation",
    "SourceExceptionMetadata",
    "SourceRuntimeFunction",
    "STUB_COMMON_ENTRY_EXPORT",
    "STUB_HANDLER_VARIANT_HASH_EXPORT",
    "STUB_OPCODE_HASH_EXPORT",
    "TARGET_ENTRY_PATCH_SIZE",
    "TARGET_TOMBSTONE_POLICY",
    "TargetEntryPatch",
    "UNW_FLAG_CHAININFO",
    "UNW_FLAG_EHANDLER",
    "UNW_FLAG_UHANDLER",
    "UnwindPlan",
    "VirtualizationManifest",
    "VirtualizationPlanError",
    "VirtualizedFunction",
    "compile_virtualization_manifest",
]
