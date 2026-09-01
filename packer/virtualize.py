"""Transactional materialization of selected-function virtualization plans.

This module is deliberately not wired into the CLI.  It is the narrow builder
boundary between the strict, no-write planner in :mod:`lifter.virtualization_plan`
and the existing payload/assembler pipeline.  The input :class:`ParsedPE` is
never mutated: every validation and write must succeed before a copied image is
returned.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import re
import struct
from dataclasses import dataclass
from typing import Iterable, Sequence

from lifter import virtualization_plan as plan
from lifter import win64_thunk

from . import bytecode_pages, cfg_preservation, pe_analyze
from .assemble import AssembleError, _StubImage


SECTION_ALIGNMENT = 0x1000
IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
_TEXT_SECTION_NAME = ".lvtx"
_DATA_SECTION_NAME = ".lvtd"
_RUNTIME_FUNCTION_SIZE = 12
_DIR64 = 10
_HASH_RE = re.compile(r"[0-9a-f]{64}")
_PAGED_PROGRAM_SIZE = 256


class VirtualizationMaterializationError(ValueError):
    """A manifest cannot be committed without violating the PE contract."""


class VirtualizationCfgPreservationError(VirtualizationMaterializationError):
    """Guard CF target planning succeeded but runtime preservation is blocked."""

    def __init__(self, plan: cfg_preservation.CfgPreservationPlan) -> None:
        self.preservation_plan = plan
        details = "; ".join(plan.blockers)
        super().__init__(
            "Guard CF preservation blocked before virtualization commit: "
            f"{len(plan.source_targets)} source target(s), "
            f"{len(plan.generated_thunk_targets)} generated target(s): {details}"
        )


@dataclass(frozen=True)
class StubVirtualizationProvenance:
    """Values independently extracted from the exact fresh stub byte image."""

    stub_sha256: str
    opcode_mapping_sha256: str
    handler_variant_sha256: str
    common_export_rva: int
    graft_delta: int
    runtime_common_rva: int


@dataclass(frozen=True)
class MaterializationResult:
    parsed: pe_analyze.ParsedPE
    manifest: plan.VirtualizationManifest
    stub: StubVirtualizationProvenance


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _fail(message: str) -> VirtualizationMaterializationError:
    return VirtualizationMaterializationError(message)


def _section_end(section: pe_analyze.ParsedSection) -> int:
    return section.rva + max(section.virtual_size, len(section.raw))


def _validate_source_image(
    parsed: pe_analyze.ParsedPE,
) -> tuple[
    tuple[pe_analyze.ParsedDir64Relocation, ...],
    tuple[pe_analyze.ParsedRuntimeFunction, ...],
]:
    """Re-derive security inventories instead of trusting caller fields."""
    try:
        pe_analyze._validate_sections(
            parsed.sections, parsed.size_of_image, parsed.section_alignment)
        relocations = pe_analyze._validate_relocations(
            parsed.reloc_blob, parsed.size_of_image, parsed.sections
        )
        pe_analyze._validate_aslr_contract(
            parsed.file_characteristics,
            parsed.dll_characteristics,
            parsed.reloc_blob,
        )
    except (TypeError, ValueError, struct.error) as exc:
        raise _fail(f"source PE validation failed: {exc}") from exc

    if relocations != tuple(parsed.dir64_relocations):
        raise _fail(
            "source DIR64 inventory does not match the validated relocation directory"
        )

    load_config = parsed.load_config
    if load_config is None:
        if parsed.dll_characteristics & 0x4000:
            raise _fail(
                "source DllCharacteristics declares GUARD_CF without a "
                "load-config inventory")
    else:
        try:
            load_config_blob = pe_analyze._slice_at_rva(
                parsed.sections,
                load_config.directory_rva,
                load_config.directory_size,
                what="source load-config directory",
            )
            validated_load_config = pe_analyze._parse_load_config(
                load_config_blob,
                load_config.directory_rva,
                image_base=parsed.image_base,
                image_size=parsed.size_of_image,
                sections=parsed.sections,
            )
        except (TypeError, ValueError, struct.error) as exc:
            raise _fail(f"source load-config validation failed: {exc}") from exc
        if validated_load_config != load_config:
            raise _fail(
                "source load-config inventory does not match validated image bytes")

    if parsed.pdata_count < 0:
        raise _fail("source exception count cannot be negative")
    if parsed.pdata_count == 0:
        if parsed.pdata_rva != 0 or parsed.runtime_functions:
            raise _fail(
                "empty source exception metadata must use RVA zero and no records"
            )
        runtime_functions: tuple[pe_analyze.ParsedRuntimeFunction, ...] = ()
    else:
        if parsed.pdata_count != len(parsed.runtime_functions):
            raise _fail(
                "source runtime-function inventory count does not match pdata_count"
            )
        size = parsed.pdata_count * _RUNTIME_FUNCTION_SIZE
        try:
            pdata = pe_analyze._slice_at_rva(
                parsed.sections,
                parsed.pdata_rva,
                size,
                what="source exception table",
            )
            runtime_functions = pe_analyze._parse_pdata(
                pdata,
                parsed.pdata_rva,
                parsed.size_of_image,
                parsed.sections,
            )
        except (TypeError, ValueError, struct.error) as exc:
            raise _fail(f"source exception metadata validation failed: {exc}") from exc
        if runtime_functions != tuple(parsed.runtime_functions):
            raise _fail(
                "source runtime-function inventory does not match the validated exception directory"
            )
    return relocations, runtime_functions


def _planner_relocations(
    records: Iterable[pe_analyze.ParsedDir64Relocation],
) -> tuple[plan.SourceDir64Relocation, ...]:
    return tuple(plan.SourceDir64Relocation(item.target_rva) for item in records)


def _planner_exceptions(
    parsed: pe_analyze.ParsedPE,
    records: Iterable[pe_analyze.ParsedRuntimeFunction],
) -> plan.SourceExceptionMetadata:
    return plan.SourceExceptionMetadata(
        table_rva=parsed.pdata_rva,
        records=tuple(
            plan.SourceRuntimeFunction(
                begin_rva=item.begin_rva,
                end_rva=item.end_rva,
                unwind_info_rva=item.unwind_info_rva,
                unwind_flags=item.unwind_flags,
            )
            for item in records
        ),
    )


def _read_stub_provenance(
    stub_bytes: bytes,
    opcode_table: plan.OpcodeTable,
    *,
    expected_handler_variant_sha256: str,
    original_size_of_image: int,
) -> tuple[_StubImage, int, str, str]:
    if not isinstance(stub_bytes, bytes) or not stub_bytes:
        raise _fail("a nonempty fresh stub byte image is required")
    if not isinstance(opcode_table, plan.OpcodeTable):
        raise _fail("an explicit immutable opcode table is required")
    if opcode_table.is_canonical:
        raise _fail("production materialization requires a shuffled opcode table")
    if (
        not isinstance(expected_handler_variant_sha256, str)
        or not _HASH_RE.fullmatch(expected_handler_variant_sha256)
    ):
        raise _fail("an exact lowercase handler-variant SHA-256 is required")
    try:
        stub = _StubImage(stub_bytes)
        common_rva = stub.find_export_rva(plan.STUB_COMMON_ENTRY_EXPORT)
        hash_rva = stub.find_export_rva(plan.STUB_OPCODE_HASH_EXPORT)
        handler_hash_rva = stub.find_export_rva(
            plan.STUB_HANDLER_VARIANT_HASH_EXPORT
        )
        if common_rva is None:
            raise _fail(
                f"stub is missing export {plan.STUB_COMMON_ENTRY_EXPORT!r}"
            )
        if hash_rva is None:
            raise _fail(
                f"stub is missing export {plan.STUB_OPCODE_HASH_EXPORT!r}"
            )
        if handler_hash_rva is None:
            raise _fail(
                "stub is missing export "
                f"{plan.STUB_HANDLER_VARIANT_HASH_EXPORT!r}"
            )
        common_section = stub.section_containing(common_rva)
        if common_section is None or not (
            common_section.characteristics & IMAGE_SCN_MEM_EXECUTE
        ):
            raise _fail("stub common-entry export is not in executable mapped bytes")
        exported_hash = stub.cstr_at_rva(hash_rva)
        exported_handler_hash = stub.cstr_at_rva(handler_hash_rva)
    except VirtualizationMaterializationError:
        raise
    except (AssembleError, IndexError, UnicodeError, ValueError, struct.error) as exc:
        raise _fail(f"fresh stub provenance validation failed: {exc}") from exc

    if not _HASH_RE.fullmatch(exported_hash):
        raise _fail("stub opcode-mapping export is not a lowercase SHA-256 string")
    if exported_hash != opcode_table.sha256:
        raise _fail("opcode table does not match the exact stub provenance export")
    if not _HASH_RE.fullmatch(exported_handler_hash):
        raise _fail("stub handler-variant export is not a lowercase SHA-256 string")
    if exported_handler_hash != expected_handler_variant_sha256:
        raise _fail("handler variants do not match the exact stub provenance export")
    if not stub.sections:
        raise _fail("fresh stub has no mapped sections")
    if original_size_of_image <= 0:
        raise _fail("original SizeOfImage must be positive")
    return stub, common_rva, exported_hash, exported_handler_hash


def _next_generated_rvas(parsed: pe_analyze.ParsedPE, function_count: int) -> tuple[int, int]:
    if function_count <= 0:
        raise _fail("at least one selected function is required")
    if any(section.name in {_TEXT_SECTION_NAME, _DATA_SECTION_NAME} for section in parsed.sections):
        raise _fail("source PE already contains a reserved virtualization section")
    image_end = max(
        parsed.size_of_image,
        *(_section_end(section) for section in parsed.sections),
    )
    text_rva = _align(image_end, SECTION_ALIGNMENT)
    predicted_text_size = _align(
        function_count * win64_thunk.THUNK_CODE_SIZE, 16
    )
    data_rva = _align(text_rva + predicted_text_size, SECTION_ALIGNMENT)
    if data_rva >= 0x1_0000_0000:
        raise _fail("generated section placement exceeds the PE RVA space")
    return text_rva, data_rva


def _compile_manifest(
    parsed: pe_analyze.ParsedPE,
    specs: Sequence[plan.FunctionSpec],
    *,
    stub: _StubImage,
    common_export_rva: int,
    exported_hash: str,
    exported_handler_hash: str,
    opcode_table: plan.OpcodeTable,
    source_relocations: tuple[plan.SourceDir64Relocation, ...],
    source_exceptions: plan.SourceExceptionMetadata,
    rolling: bool,
    rolling_seed: bytes | None,
    page_master_key: bytes,
) -> tuple[plan.VirtualizationManifest, StubVirtualizationProvenance]:
    text_rva, data_rva = _next_generated_rvas(parsed, len(specs))
    reader = plan.SectionImage.from_parsed_sections(parsed.sections)
    if len(page_master_key) != bytecode_pages.MASTER_KEY_SIZE:
        raise _fail("authenticated paging master key must be exactly 32 bytes")
    if rolling:
        raise _fail(
            "production selected-function virtualization requires authenticated "
            "paging and cannot use rolling bytecode"
        )

    def seal_program(
        spec: plan.FunctionSpec, program: bytes
    ) -> tuple[bytes, bytes]:
        if len(program) < 3:
            raise ValueError("lifted program is too short")
        data_size = struct.unpack_from("<H", program)[0]
        if data_size != 0:
            raise ValueError(
                "paged selected-function programs currently require an empty data region"
            )
        identity_input = (
            b"Lethe-selected-function-page-id-v1\0"
            + spec.name.encode("utf-8")
            + struct.pack("<II", spec.rva, spec.size)
            + hashlib.sha256(program).digest()
        )
        program_id = hashlib.sha256(identity_input).digest()[:16]
        salt = hmac.new(
            page_master_key,
            b"Lethe-selected-function-page-salt-v1\0" + program_id,
            hashlib.sha256,
        ).digest()[:bytecode_pages.SALT_SIZE]
        envelope = bytecode_pages.seal_program(
            program,
            page_master_key,
            program_id=program_id,
            page_size=_PAGED_PROGRAM_SIZE,
            salt=salt,
        )
        return envelope, program_id

    common_args = dict(
        rolling=rolling,
        rolling_seed=rolling_seed,
        opcode_table=opcode_table,
        require_shuffled_opcodes=True,
        expected_opcode_mapping_sha256=exported_hash,
        source_dir64_relocations=source_relocations,
        require_source_relocation_metadata=True,
        source_exception_metadata=source_exceptions,
        require_source_exception_metadata=True,
        program_sealer=seal_program,
    )
    try:
        sizing = plan.compile_virtualization_manifest(
            specs,
            reader,
            generated_text_rva=text_rva,
            generated_data_rva=data_rva,
            runtime_common_rva=text_rva,
            **common_args,
        )
    except plan.VirtualizationPlanError as exc:
        raise _fail(str(exc)) from exc

    new_size_of_image = _align(
        data_rva + sizing.generated_data_size, SECTION_ALIGNMENT
    )
    min_stub_rva = min(section.rva for section in stub.sections)
    graft_base = _align(max(new_size_of_image, SECTION_ALIGNMENT), SECTION_ALIGNMENT)
    graft_delta = graft_base - min_stub_rva
    runtime_common_rva = common_export_rva + graft_delta
    if not 0 < runtime_common_rva < 0x1_0000_0000:
        raise _fail("post-graft common-entry RVA exceeds the PE RVA space")

    try:
        manifest = plan.compile_virtualization_manifest(
            specs,
            reader,
            generated_text_rva=text_rva,
            generated_data_rva=data_rva,
            runtime_common_rva=runtime_common_rva,
            **common_args,
        )
    except plan.VirtualizationPlanError as exc:
        raise _fail(str(exc)) from exc
    if (
        manifest.generated_text_size != sizing.generated_text_size
        or manifest.generated_data_size != sizing.generated_data_size
        or tuple(item.program_sha256 for item in manifest.functions)
        != tuple(item.program_sha256 for item in sizing.functions)
    ):
        raise _fail("planner output changed between sizing and final stub placement")

    provenance = StubVirtualizationProvenance(
        stub_sha256=hashlib.sha256(stub.data).hexdigest(),
        opcode_mapping_sha256=exported_hash,
        handler_variant_sha256=exported_handler_hash,
        common_export_rva=common_export_rva,
        graft_delta=graft_delta,
        runtime_common_rva=runtime_common_rva,
    )
    return manifest, provenance


class _GeneratedWriter:
    def __init__(self, text_rva: int, text_size: int, data_rva: int, data_size: int):
        self.text_rva = text_rva
        self.data_rva = data_rva
        self.text = bytearray(b"\xCC" * text_size)
        self.data = bytearray(data_size)
        self._claims: list[tuple[int, int, str]] = []

    def _locate(self, rva: int, size: int) -> tuple[bytearray, int]:
        for base, blob in ((self.text_rva, self.text), (self.data_rva, self.data)):
            if base <= rva and rva + size <= base + len(blob):
                return blob, rva - base
        raise _fail(f"generated write at RVA 0x{rva:X}+0x{size:X} is outside reservations")

    def place(self, rva: int, value: bytes, label: str) -> None:
        if not value:
            raise _fail(f"generated artifact {label} is empty")
        end = rva + len(value)
        for prior_start, prior_end, prior_label in self._claims:
            if rva < prior_end and prior_start < end:
                raise _fail(
                    f"generated artifact {label} overlaps {prior_label}"
                )
        blob, offset = self._locate(rva, len(value))
        blob[offset : offset + len(value)] = value
        self._claims.append((rva, end, label))

    def patch(self, rva: int, value: bytes) -> None:
        blob, offset = self._locate(rva, len(value))
        blob[offset : offset + len(value)] = value

    def read(self, rva: int, size: int) -> bytes:
        blob, offset = self._locate(rva, size)
        return bytes(blob[offset : offset + size])


def _validate_manifest_source(
    parsed: pe_analyze.ParsedPE,
    manifest: plan.VirtualizationManifest,
    relocations: tuple[pe_analyze.ParsedDir64Relocation, ...],
    runtime_functions: tuple[pe_analyze.ParsedRuntimeFunction, ...],
) -> None:
    if not manifest.source_relocation_metadata_complete:
        raise _fail("manifest lacks complete source relocation metadata")
    current_relocations = tuple(sorted(item.target_rva for item in relocations))
    planned_relocations = tuple(
        item.target_rva for item in manifest.checked_source_dir64_relocations
    )
    if current_relocations != planned_relocations:
        raise _fail("source relocations changed after manifest compilation")

    exception = manifest.exception_table
    if not manifest.source_exception_metadata_complete:
        raise _fail("manifest lacks complete source exception metadata")
    if exception.source_table_rva != parsed.pdata_rva:
        raise _fail("source exception-table RVA changed after manifest compilation")
    if exception.source_table_size != parsed.pdata_count * _RUNTIME_FUNCTION_SIZE:
        raise _fail("source exception-table size changed after manifest compilation")
    source_records = sorted(
        (*exception.retained, *exception.removed),
        key=lambda item: -1 if item.source_record_rva is None else item.source_record_rva,
    )
    if len(source_records) != len(runtime_functions):
        raise _fail("source runtime-function set changed after manifest compilation")
    for index, (planned, current) in enumerate(zip(source_records, runtime_functions)):
        expected_record_rva = parsed.pdata_rva + index * _RUNTIME_FUNCTION_SIZE
        if (
            planned.origin != "source"
            or planned.source_record_rva != expected_record_rva
            or (planned.begin_rva, planned.end_rva, planned.unwind_info_rva, planned.unwind_flags)
            != (current.begin_rva, current.end_rva, current.unwind_info_rva, current.unwind_flags)
        ):
            raise _fail("source runtime-function records changed after manifest compilation")


def _validate_manifest_layout(
    parsed: pe_analyze.ParsedPE,
    manifest: plan.VirtualizationManifest,
) -> int:
    expected_text_rva, expected_data_rva = _next_generated_rvas(
        parsed, len(manifest.functions)
    )
    if manifest.generated_text_rva != expected_text_rva:
        raise _fail("manifest generated-text reservation is stale")
    if manifest.generated_data_rva != expected_data_rva:
        raise _fail("manifest generated-data reservation is stale")
    if manifest.generated_text_size <= 0 or manifest.generated_data_size <= 0:
        raise _fail("manifest generated reservations must be nonempty")
    text_end = manifest.generated_text_rva + manifest.generated_text_size
    data_end = manifest.generated_data_rva + manifest.generated_data_size
    if text_end > manifest.generated_data_rva:
        raise _fail("manifest generated text and data overlap")
    if data_end >= 0x1_0000_0000:
        raise _fail("manifest generated data exceeds the PE RVA space")
    return _align(data_end, SECTION_ALIGNMENT)


def _validate_function_artifacts(
    function: plan.VirtualizedFunction,
    manifest: plan.VirtualizationManifest,
) -> int:
    if len(function.generated_executable_ranges) != 1:
        raise _fail(f"function {function.name!r} must have exactly one generated thunk")
    generated = function.generated_executable_ranges[0]
    if generated.symbol != function.thunk_symbol or generated.size != win64_thunk.THUNK_CODE_SIZE:
        raise _fail(f"function {function.name!r} has invalid generated thunk metadata")
    if function.thunk_template != win64_thunk.THUNK_TEMPLATE:
        raise _fail(f"function {function.name!r} thunk template does not match the runtime ABI")
    if hashlib.sha256(function.thunk_template).hexdigest() != function.thunk_sha256:
        raise _fail(f"function {function.name!r} thunk hash is stale")
    if hashlib.sha256(function.program).hexdigest() != function.program_sha256:
        raise _fail(f"function {function.name!r} program hash is stale")
    if function.program_format == "paged-v1":
        if len(function.descriptor_data) != 40:
            raise _fail(f"function {function.name!r} paged descriptor size is invalid")
        version, envelope_size, pointer, program_id, image_base = struct.unpack(
            "<IIQ16sQ", function.descriptor_data
        )
        if (
            version != plan.DESCRIPTOR_VERSION_PAGED
            or envelope_size != len(function.program)
            or pointer != 0
            or image_base != 0
            or len(function.program_id) != 16
            or program_id != function.program_id
        ):
            raise _fail(f"function {function.name!r} paged descriptor ABI is invalid")
        try:
            envelope = bytecode_pages.parse_envelope(function.program)
        except bytecode_pages.BytecodePageError as exc:
            raise _fail(
                f"function {function.name!r} page envelope is invalid: {exc}"
            ) from exc
        if envelope.program_id != function.program_id:
            raise _fail(
                f"function {function.name!r} descriptor/envelope identity mismatch"
            )
        if not (
            manifest.generated_data_rva <= function.program_rva
            and function.program_rva + envelope_size
            <= manifest.generated_data_rva + manifest.generated_data_size
        ):
            raise _fail(
                f"function {function.name!r} page envelope is outside restored generated data"
            )
    else:
        if len(function.descriptor_data) != 24:
            raise _fail(f"function {function.name!r} descriptor ABI is invalid")
        version, program_size, pointer, image_base = struct.unpack(
            "<IIQQ", function.descriptor_data
        )
        if (
            version != plan.DESCRIPTOR_VERSION_PLAIN
            or program_size != len(function.program)
            or pointer != 0
            or image_base != 0
            or function.program_id
        ):
            raise _fail(f"function {function.name!r} descriptor ABI is invalid")
    if function.unwind.unwind_info != win64_thunk.THUNK_UNWIND_INFO:
        raise _fail(f"function {function.name!r} unwind ABI is invalid")
    if function.unwind.begin_rva != generated.rva or function.unwind.end_rva != generated.rva + generated.size:
        raise _fail(f"function {function.name!r} unwind range is invalid")

    patch = function.target_entry_patch
    expected_displacement = generated.rva - (function.target_rva + plan.TARGET_ENTRY_PATCH_SIZE)
    expected_patch = b"\xE9" + struct.pack("<i", expected_displacement) + b"\xCC" * (
        function.target_size - plan.TARGET_ENTRY_PATCH_SIZE
    )
    if (
        patch.patch_rva != function.target_rva
        or patch.destination_rva != generated.rva
        or patch.displacement != expected_displacement
        or patch.original_extent_size != function.target_size
        or patch.patch != expected_patch
        or patch.tombstone_policy != plan.TARGET_TOMBSTONE_POLICY
        or patch.external_entry_assumption != plan.EXTERNAL_ENTRY_ASSUMPTION
    ):
        raise _fail(f"function {function.name!r} target patch contract is invalid")

    expected_relocations = (
        plan.RelocationRequirement(
            kind="REL32",
            patch_rva=generated.rva + win64_thunk.THUNK_COMMON_REL32_OFFSET,
            target_rva=manifest.runtime_common_rva,
            target_symbol=plan.STUB_COMMON_ENTRY_EXPORT,
        ),
        plan.RelocationRequirement(
            kind="DIR64",
            patch_rva=generated.rva + win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET,
            target_rva=function.descriptor_rva,
            add_image_base=True,
        ),
        plan.RelocationRequirement(
            kind="DIR64",
            patch_rva=function.descriptor_rva + 8,
            target_rva=function.program_rva,
            add_image_base=True,
        ),
        plan.RelocationRequirement(
            kind="DIR64",
            patch_rva=function.descriptor_rva + (
                32 if function.program_format == "paged-v1" else 16
            ),
            target_rva=0,
            add_image_base=True,
        ),
    )
    if function.required_relocations != expected_relocations:
        raise _fail(f"function {function.name!r} relocation contract is invalid")
    return generated.rva


def _build_generated_sections(
    parsed: pe_analyze.ParsedPE,
    manifest: plan.VirtualizationManifest,
) -> tuple[bytes, bytes, tuple[int, ...]]:
    if manifest.runtime_common_rva is None:
        raise _fail("manifest lacks the post-graft common-entry RVA")
    writer = _GeneratedWriter(
        manifest.generated_text_rva,
        manifest.generated_text_size,
        manifest.generated_data_rva,
        manifest.generated_data_size,
    )
    dir64_targets = []
    for function in manifest.functions:
        thunk_rva = _validate_function_artifacts(function, manifest)
        writer.place(thunk_rva, function.thunk_template, function.thunk_symbol)
        writer.place(function.program_rva, function.program, f"{function.name} program")
        writer.place(
            function.unwind.unwind_info_rva,
            function.unwind.unwind_info,
            f"{function.name} unwind info",
        )
        writer.place(
            function.descriptor_rva,
            function.descriptor_data,
            function.descriptor_symbol,
        )

    exception = manifest.exception_table
    if (
        exception.output_table_size != len(exception.table)
        or exception.table != b"".join(record.packed for record in exception.merged)
        or exception.output_table_size != len(exception.merged) * _RUNTIME_FUNCTION_SIZE
    ):
        raise _fail("manifest merged exception-table bytes are inconsistent")
    writer.place(
        exception.output_table_rva,
        exception.table,
        "merged exception table",
    )

    for function in manifest.functions:
        for relocation in function.required_relocations:
            if relocation.target_rva is None:
                raise _fail("generated relocation has no numeric target RVA")
            if relocation.kind == "REL32":
                displacement = relocation.target_rva - (relocation.patch_rva + 4)
                if not -(1 << 31) <= displacement <= (1 << 31) - 1:
                    raise _fail("generated REL32 target is out of range")
                writer.patch(relocation.patch_rva, struct.pack("<i", displacement))
            elif relocation.kind == "DIR64" and relocation.add_image_base:
                target_va = parsed.image_base + relocation.target_rva
                if not 0 <= target_va <= 0xFFFF_FFFF_FFFF_FFFF:
                    raise _fail("generated DIR64 target VA overflows 64 bits")
                writer.patch(relocation.patch_rva, struct.pack("<Q", target_va))
                dir64_targets.append(relocation.patch_rva)
            else:
                raise _fail(f"unsupported generated relocation kind {relocation.kind!r}")
    return bytes(writer.text), bytes(writer.data), tuple(dir64_targets)


def _patch_selected_functions(
    parsed: pe_analyze.ParsedPE,
    manifest: plan.VirtualizationManifest,
) -> None:
    reader = plan.SectionImage.from_parsed_sections(parsed.sections)
    for function in manifest.functions:
        try:
            current = reader.read_file_backed_executable(
                function.target_rva, function.target_size
            )
        except plan.VirtualizationPlanError as exc:
            raise _fail(f"selected source extent became invalid: {exc}") from exc
        if hashlib.sha256(current).hexdigest() != function.original_sha256:
            raise _fail(
                f"selected function {function.name!r} changed after manifest compilation"
            )
        owner = next(
            section
            for section in parsed.sections
            if section.rva <= function.target_rva
            and function.target_rva + function.target_size <= section.rva + len(section.raw)
        )
        offset = function.target_rva - owner.rva
        updated = bytearray(owner.raw)
        updated[offset : offset + function.target_size] = function.target_entry_patch.patch
        owner.raw = bytes(updated)


def _canonical_relocation_blob(target_rvas: Iterable[int]) -> bytes:
    targets = sorted(set(target_rvas))
    blocks = []
    by_page: dict[int, list[int]] = {}
    for target in targets:
        if not 0 < target < 0x1_0000_0000 or target + 8 > 0x1_0000_0000:
            raise _fail(f"DIR64 target RVA 0x{target:X} is outside the PE RVA space")
        by_page.setdefault(target & ~0xFFF, []).append(target & 0xFFF)
    for page_rva in sorted(by_page):
        entries = [(_DIR64 << 12) | offset for offset in by_page[page_rva]]
        if len(entries) & 1:
            entries.append(0)
        block_size = 8 + len(entries) * 2
        blocks.append(
            struct.pack("<II", page_rva, block_size)
            + struct.pack(f"<{len(entries)}H", *entries)
        )
    return b"".join(blocks)


def _commit_manifest(
    parsed: pe_analyze.ParsedPE,
    manifest: plan.VirtualizationManifest,
    *,
    acknowledge_no_interior_entries: bool,
) -> pe_analyze.ParsedPE:
    if acknowledge_no_interior_entries is not True:
        raise _fail(
            "materialization requires explicit acknowledgement that no external entry targets the overwritten function bodies"
        )
    cfg_plan = cfg_preservation.build_cfg_preservation_plan(parsed, manifest)
    if not cfg_plan.preservation_supported:
        raise VirtualizationCfgPreservationError(cfg_plan)
    source_relocations, source_runtime_functions = _validate_source_image(parsed)
    _validate_manifest_source(
        parsed, manifest, source_relocations, source_runtime_functions
    )
    new_size_of_image = _validate_manifest_layout(parsed, manifest)

    result = copy.deepcopy(parsed)
    result.generated_cfg_targets = tuple(
        pe_analyze.ParsedGuardTarget(item.rva, item.metadata)
        for item in cfg_plan.generated_thunk_targets
    )
    _patch_selected_functions(result, manifest)
    text, data, generated_dir64 = _build_generated_sections(result, manifest)
    result.sections.extend(
        (
            pe_analyze.ParsedSection(
                name=_TEXT_SECTION_NAME,
                rva=manifest.generated_text_rva,
                virtual_size=len(text),
                raw=text,
                characteristics=(
                    IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
                ),
            ),
            pe_analyze.ParsedSection(
                name=_DATA_SECTION_NAME,
                rva=manifest.generated_data_rva,
                virtual_size=len(data),
                raw=data,
                characteristics=IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            ),
        )
    )
    data_section = result.sections[-1]
    for function in manifest.functions:
        if function.program_format != "paged-v1":
            continue
        relative = function.program_rva - data_section.rva
        if (
            not (data_section.characteristics & IMAGE_SCN_MEM_READ)
            or relative < 0
            or relative + len(function.program) > data_section.virtual_size
            or relative + len(function.program) > len(data_section.raw)
        ):
            raise _fail(
                f"function {function.name!r} page envelope is not wholly "
                "inside restored readable file-backed bytes"
            )
    result.requires_paged_vm = any(
        function.program_format == "paged-v1"
        for function in manifest.functions
    )
    result.size_of_image = new_size_of_image

    all_dir64 = tuple(item.target_rva for item in source_relocations) + generated_dir64
    result.reloc_blob = _canonical_relocation_blob(all_dir64)
    result.dir64_relocations = tuple(
        pe_analyze.ParsedDir64Relocation(target_rva)
        for target_rva in sorted(set(all_dir64))
    )
    result.file_characteristics &= ~IMAGE_FILE_RELOCS_STRIPPED
    result.dll_characteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

    exception = manifest.exception_table
    result.pdata_rva = exception.output_table_rva
    result.pdata_count = len(exception.merged)
    result.runtime_functions = tuple(
        pe_analyze.ParsedRuntimeFunction(
            begin_rva=item.begin_rva,
            end_rva=item.end_rva,
            unwind_info_rva=item.unwind_info_rva,
            unwind_flags=item.unwind_flags,
        )
        for item in exception.merged
    )

    try:
        pe_analyze._validate_sections(
            result.sections, result.size_of_image, result.section_alignment)
        validated_relocations = pe_analyze._validate_relocations(
            result.reloc_blob, result.size_of_image, result.sections
        )
        pdata = pe_analyze._slice_at_rva(
            result.sections,
            result.pdata_rva,
            result.pdata_count * _RUNTIME_FUNCTION_SIZE,
            what="materialized exception table",
        )
        validated_runtime = pe_analyze._parse_pdata(
            pdata,
            result.pdata_rva,
            result.size_of_image,
            result.sections,
        )
        pe_analyze._validate_aslr_contract(
            result.file_characteristics,
            result.dll_characteristics,
            result.reloc_blob,
        )
    except (TypeError, ValueError, struct.error) as exc:
        raise _fail(f"materialized PE failed post-commit validation: {exc}") from exc
    if validated_relocations != result.dir64_relocations:
        raise _fail("materialized relocation inventory failed round-trip validation")
    if validated_runtime != result.runtime_functions:
        raise _fail("materialized exception inventory failed round-trip validation")
    return result


def apply_virtualization_manifest(
    parsed: pe_analyze.ParsedPE,
    manifest: plan.VirtualizationManifest,
    *,
    acknowledge_no_interior_entries: bool = False,
) -> pe_analyze.ParsedPE:
    """Atomically apply a previously compiled manifest to a copied ParsedPE.

    This separate commit API makes stale-source detection explicit for callers
    that persist a plan between the compile and materialize phases.
    """
    if not isinstance(parsed, pe_analyze.ParsedPE):
        raise _fail("parsed must be a ParsedPE instance")
    if not isinstance(manifest, plan.VirtualizationManifest):
        raise _fail("manifest must be a VirtualizationManifest instance")
    return _commit_manifest(
        parsed,
        manifest,
        acknowledge_no_interior_entries=acknowledge_no_interior_entries,
    )


def materialize_selected_functions(
    parsed: pe_analyze.ParsedPE,
    specs: Sequence[plan.FunctionSpec],
    *,
    stub_bytes: bytes,
    opcode_table: plan.OpcodeTable,
    expected_handler_variant_sha256: str,
    page_master_key: bytes,
    acknowledge_no_interior_entries: bool = False,
    rolling: bool = False,
    rolling_seed: bytes | None = None,
) -> MaterializationResult:
    """Compile and atomically materialize explicit first-party function specs."""
    if not isinstance(parsed, pe_analyze.ParsedPE):
        raise _fail("parsed must be a ParsedPE instance")
    page_master_key = bytes(page_master_key)
    if len(page_master_key) != bytecode_pages.MASTER_KEY_SIZE:
        raise _fail("authenticated paging master key must be exactly 32 bytes")
    source_relocations, source_runtime_functions = _validate_source_image(parsed)
    stub, common_export_rva, exported_hash, exported_handler_hash = _read_stub_provenance(
        stub_bytes,
        opcode_table,
        expected_handler_variant_sha256=expected_handler_variant_sha256,
        original_size_of_image=parsed.size_of_image,
    )
    manifest, provenance = _compile_manifest(
        parsed,
        specs,
        stub=stub,
        common_export_rva=common_export_rva,
        exported_hash=exported_hash,
        exported_handler_hash=exported_handler_hash,
        opcode_table=opcode_table,
        source_relocations=_planner_relocations(source_relocations),
        source_exceptions=_planner_exceptions(parsed, source_runtime_functions),
        rolling=rolling,
        rolling_seed=rolling_seed,
        page_master_key=page_master_key,
    )
    committed = _commit_manifest(
        parsed,
        manifest,
        acknowledge_no_interior_entries=acknowledge_no_interior_entries,
    )
    return MaterializationResult(
        parsed=committed,
        manifest=manifest,
        stub=provenance,
    )


__all__ = [
    "MaterializationResult",
    "StubVirtualizationProvenance",
    "VirtualizationMaterializationError",
    "VirtualizationCfgPreservationError",
    "apply_virtualization_manifest",
    "materialize_selected_functions",
]
