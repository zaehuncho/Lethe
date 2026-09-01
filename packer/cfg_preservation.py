"""PE32+ load-config and Guard CF preservation for Lethe outputs.

Windows consumes image load-config metadata before the packed entry point runs.
Lethe therefore emits a live, read-only clone in the outer image rather than
trying to register restored image targets after startup. OS-populated pointer
slots live in that clone and authenticated inner metadata tells the manual
loader which original slots receive their final values after decryption. The
same recipe binds the relocation-normalized clone bytes and governing outer PE
header fields before the loader restores any protected section.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any, Iterable

try:
    from . import pe_analyze
except ImportError:  # pragma: no cover
    import pe_analyze  # type: ignore


IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28

RUNTIME_MAGIC = b"LCFGRT1\0"
RUNTIME_VERSION = 3
RUNTIME_HEADER = struct.Struct("<8s10I32s")
RUNTIME_ENTRY = struct.Struct("<II")
RUNTIME_TARGET = struct.Struct("<IB3x")
RUNTIME_RELOCATION = struct.Struct("<I")
LIVE_SECTION_CHARACTERISTICS = 0x40000040


@dataclass(frozen=True, order=True)
class PlannedCfgTarget:
    rva: int
    metadata: bytes
    origin: str


@dataclass(frozen=True, order=True)
class RuntimeSlotCopy:
    source_rva: int
    shadow_rva: int
    name: str


@dataclass(frozen=True)
class LiveLoadConfigImage:
    image_base: int
    section_rva: int
    directory_rva: int
    directory_size: int
    data: bytes
    relocation_target_rvas: tuple[int, ...]
    runtime_slot_copies: tuple[RuntimeSlotCopy, ...]


@dataclass(frozen=True)
class CfgPreservationPlan:
    source_load_config_present: bool
    source_guard_cf_enabled: bool
    source_load_config_rva: int
    source_load_config_size: int
    source_guard_flags: int
    source_targets: tuple[PlannedCfgTarget, ...]
    retained_source_targets: tuple[PlannedCfgTarget, ...]
    removed_tombstoned_interior_targets: tuple[PlannedCfgTarget, ...]
    generated_thunk_targets: tuple[PlannedCfgTarget, ...]
    merged_declared_targets: tuple[PlannedCfgTarget, ...]
    unsupported_source_features: tuple[str, ...]
    live_load_config_emitted: bool
    guard_pointer_initialization_proven: bool
    runtime_target_registration_proven: bool
    preservation_supported: bool
    blockers: tuple[str, ...]


class CfgPreservationBlocked(ValueError):
    def __init__(self, plan: CfgPreservationPlan) -> None:
        self.plan = plan
        details = "; ".join(plan.blockers) or "unspecified preservation blocker"
        contract = "Guard CF" if plan.source_guard_cf_enabled else "load-config"
        super().__init__(
            f"{contract} preservation blocked: "
            f"{len(plan.source_targets)} source target(s), "
            f"{len(plan.generated_thunk_targets)} generated target(s): {details}"
        )


def _load_config(parsed: Any) -> pe_analyze.ParsedLoadConfig | None:
    value = getattr(parsed, "load_config", None)
    if value is not None and not isinstance(value, pe_analyze.ParsedLoadConfig):
        raise ValueError("load_config inventory must be ParsedLoadConfig or None")
    return value


def _generated_targets(manifest: Any, parsed: Any,
                       metadata_size: int) -> tuple[PlannedCfgTarget, ...]:
    generated: list[PlannedCfgTarget] = []
    seen: set[int] = set()
    for target in tuple(getattr(parsed, "generated_cfg_targets", ())):
        if not isinstance(target, pe_analyze.ParsedGuardTarget):
            raise ValueError("generated CFG inventory contains an invalid target")
        if len(target.metadata) != metadata_size:
            raise ValueError(
                f"generated CFG target RVA 0x{target.rva:X} metadata width "
                "disagrees with GuardFlags")
        generated.append(PlannedCfgTarget(
            target.rva, target.metadata, "generated_thunk"))
        seen.add(target.rva)

    if manifest is None:
        return tuple(sorted(generated))
    try:
        functions = tuple(manifest.functions)
    except (AttributeError, TypeError) as exc:
        raise ValueError("virtualization manifest functions are required") from exc
    for function in functions:
        try:
            targets = tuple(function.cfg_target_rvas)
            ranges = tuple(function.generated_executable_ranges)
            capabilities = getattr(function, "capabilities", {})
            if not isinstance(capabilities, dict):
                raise TypeError("capabilities must be a dictionary")
            direct_only = capabilities.get("direct_only_thunk") is True
        except (AttributeError, TypeError) as exc:
            raise ValueError(
                "virtualization function lacks generated CFG target metadata") from exc
        if direct_only:
            if targets:
                raise ValueError(
                    "direct-only virtualization thunk must not declare a generated "
                    "CFG target")
            for target in generated:
                if any(item.rva <= target.rva < item.rva + item.size
                       for item in ranges):
                    raise ValueError(
                        f"direct-only virtualization thunk RVA 0x{target.rva:X} "
                        "appears in generated CFG inventory")
        for target in targets:
            if type(target) is not int or not 0 < target < 0x1_0000_0000:
                raise ValueError("generated CFG target RVA is invalid")
            if target % 16:
                raise ValueError(
                    f"generated CFG target RVA 0x{target:X} is not 16-byte aligned")
            if not any(item.rva <= target < item.rva + item.size for item in ranges):
                raise ValueError(
                    f"generated CFG target RVA 0x{target:X} is outside generated code")
            if target in seen:
                continue
            seen.add(target)
            generated.append(PlannedCfgTarget(
                target, b"\0" * metadata_size, "generated_thunk"))
    return tuple(sorted(generated))


def build_cfg_preservation_plan(parsed: Any, manifest: Any = None
                                ) -> CfgPreservationPlan:
    load_config = _load_config(parsed)
    header_guard = bool(
        int(getattr(parsed, "dll_characteristics", 0))
        & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
    source_guard = bool(header_guard or load_config and load_config.has_guard_cf)
    if header_guard and load_config is None:
        raise ValueError(
            "DllCharacteristics declares GUARD_CF without a load-config inventory")

    guard_flags = load_config.guard_flags if load_config else 0
    metadata_size = (
        guard_flags >> _GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT) & 0xF
    source_targets = tuple(
        PlannedCfgTarget(target.rva, target.metadata, "source")
        for target in (load_config.guard_cf_targets if load_config else ()))
    for target in source_targets:
        if len(target.metadata) != metadata_size:
            raise ValueError(
                f"source CFG target RVA 0x{target.rva:X} metadata width "
                "disagrees with GuardFlags")

    selected_extents = []
    if manifest is not None:
        try:
            selected_extents = [
                (function.target_rva, function.target_rva + function.target_size)
                for function in manifest.functions]
        except (AttributeError, TypeError) as exc:
            raise ValueError("virtualization manifest target extents are required") from exc

    retained: list[PlannedCfgTarget] = []
    interior: list[PlannedCfgTarget] = []
    for target in source_targets:
        owner = next(
            ((start, end) for start, end in selected_extents
             if start <= target.rva < end), None)
        if owner is not None and target.rva != owner[0]:
            interior.append(target)
        else:
            retained.append(target)

    generated = _generated_targets(manifest, parsed, metadata_size)
    merged_by_rva = {target.rva: target for target in retained}
    for target in generated:
        existing = merged_by_rva.get(target.rva)
        if existing is not None and existing.metadata != target.metadata:
            raise ValueError(
                f"CFG target RVA 0x{target.rva:X} has conflicting metadata")
        merged_by_rva[target.rva] = existing or target
    merged = tuple(merged_by_rva[rva] for rva in sorted(merged_by_rva))

    unsupported = load_config.unsupported_features if load_config else ()
    blockers: list[str] = []
    if interior:
        blockers.append(
            "selected tombstoned interiors remain declared source CFG targets at "
            + ", ".join(f"0x{target.rva:X}" for target in interior))
    if unsupported:
        blockers.append(
            "source load-config contains unsupported features: "
            + ", ".join(unsupported))
    if generated and load_config is not None and load_config.xfg_present:
        blockers.append(
            "source XFG is enabled but generated VM thunk RVAs do not carry "
            "source-compatible 8-byte XFG function hashes")
    supported = not blockers
    live = bool(load_config is not None and supported)
    return CfgPreservationPlan(
        source_load_config_present=load_config is not None,
        source_guard_cf_enabled=source_guard,
        source_load_config_rva=load_config.directory_rva if load_config else 0,
        source_load_config_size=load_config.directory_size if load_config else 0,
        source_guard_flags=guard_flags,
        source_targets=source_targets,
        retained_source_targets=tuple(retained),
        removed_tombstoned_interior_targets=tuple(interior),
        generated_thunk_targets=generated,
        merged_declared_targets=merged,
        unsupported_source_features=unsupported,
        live_load_config_emitted=live,
        guard_pointer_initialization_proven=live,
        runtime_target_registration_proven=live,
        preservation_supported=supported,
        blockers=tuple(blockers),
    )


def require_cfg_preservation_supported(parsed: Any, manifest: Any = None
                                       ) -> CfgPreservationPlan:
    plan = build_cfg_preservation_plan(parsed, manifest)
    if not plan.preservation_supported:
        raise CfgPreservationBlocked(plan)
    return plan


def _pack_targets(targets: Iterable[PlannedCfgTarget]) -> bytes:
    return b"".join(struct.pack("<I", target.rva) + target.metadata
                    for target in targets)


def build_runtime_slot_blob(
    copies: Iterable[RuntimeSlotCopy],
    targets: Iterable[PlannedCfgTarget] = (),
    *,
    live_load_config: LiveLoadConfigImage,
    dll_characteristics: int,
    section_characteristics: int = LIVE_SECTION_CHARACTERISTICS,
) -> bytes:
    ordered = tuple(copies)
    ordered_targets = tuple(targets)
    if tuple(live_load_config.runtime_slot_copies) != ordered:
        raise ValueError("outer load-config runtime slot inventory disagrees")
    if len({item.source_rva for item in ordered}) != len(ordered):
        raise ValueError("duplicate load-config runtime destination slot")
    if len({item.shadow_rva for item in ordered}) != len(ordered):
        raise ValueError("duplicate load-config runtime shadow slot")
    if not 0 < live_load_config.image_base < (1 << 64):
        raise ValueError("outer load-config image base is invalid")
    if not 0 <= dll_characteristics <= 0xFFFF:
        raise ValueError("outer DLL characteristics are invalid")
    if not 0 <= section_characteristics <= 0xFFFFFFFF:
        raise ValueError("outer load-config section characteristics are invalid")

    section_start = live_load_config.section_rva
    section_size = len(live_load_config.data)
    section_end = section_start + section_size
    if (
        section_start <= 0
        or section_end >= 0x1_0000_0000
        or live_load_config.directory_size <= 0
        or live_load_config.directory_rva < section_start
        or live_load_config.directory_rva + live_load_config.directory_size
        > section_end
    ):
        raise ValueError("outer load-config binding geometry is invalid")

    shadow_rvas = {item.shadow_rva for item in ordered}
    for item in ordered:
        if item.shadow_rva < section_start or item.shadow_rva + 8 > section_end:
            raise ValueError("outer load-config shadow slot is outside .lcfg")
    relocations = tuple(sorted(set(live_load_config.relocation_target_rvas)))
    if len(relocations) != len(live_load_config.relocation_target_rvas):
        raise ValueError("duplicate outer load-config relocation")

    canonical = bytearray(live_load_config.data)
    for shadow_rva in shadow_rvas:
        offset = shadow_rva - section_start
        canonical[offset:offset + 8] = bytes(8)
    for relocation_rva in relocations:
        if relocation_rva < section_start or relocation_rva + 8 > section_end:
            raise ValueError("outer load-config relocation is outside .lcfg")
        if relocation_rva in shadow_rvas:
            continue
        if any(
            shadow_rva < relocation_rva + 8 and relocation_rva < shadow_rva + 8
            for shadow_rva in shadow_rvas
        ):
            raise ValueError("outer load-config relocation overlaps a shadow slot")
        offset = relocation_rva - section_start
        value, = struct.unpack_from("<Q", canonical, offset)
        if value < live_load_config.image_base:
            raise ValueError("outer load-config relocation value is below image base")
        target_rva = value - live_load_config.image_base
        if target_rva >= 0x1_0000_0000:
            raise ValueError("outer load-config relocation target is outside RVA space")
        struct.pack_into("<Q", canonical, offset, target_rva)

    digest = hashlib.sha256(canonical).digest()
    out = bytearray(RUNTIME_HEADER.pack(
        RUNTIME_MAGIC,
        RUNTIME_VERSION,
        len(ordered),
        len(ordered_targets),
        len(relocations),
        dll_characteristics,
        live_load_config.directory_rva,
        live_load_config.directory_size,
        section_start,
        section_size,
        section_characteristics,
        digest,
    ))
    for item in ordered:
        out += RUNTIME_ENTRY.pack(item.source_rva, item.shadow_rva)
    for target in ordered_targets:
        flags = target.metadata[0] if target.metadata else 0
        out += RUNTIME_TARGET.pack(target.rva, flags)
    for relocation_rva in relocations:
        out += RUNTIME_RELOCATION.pack(relocation_rva)
    return bytes(out)


def build_live_load_config(parsed: pe_analyze.ParsedPE,
                           plan: CfgPreservationPlan, *,
                           section_rva: int,
                           image_base: int,
                           outer_target_rvas: Iterable[int] = (),
                           ) -> LiveLoadConfigImage | None:
    load_config = _load_config(parsed)
    if load_config is None:
        return None
    if not plan.preservation_supported:
        raise CfgPreservationBlocked(plan)
    if section_rva <= 0 or section_rva % 0x1000:
        raise ValueError("live load-config section RVA must be page aligned")

    data = bytearray(load_config.raw)
    relocations: list[int] = []
    copies: list[RuntimeSlotCopy] = []

    live_targets = {target.rva: target for target in plan.merged_declared_targets}
    if plan.source_guard_cf_enabled:
        metadata_size = (
            load_config.guard_flags >> _GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT) & 0xF
        for target_rva in outer_target_rvas:
            if type(target_rva) is not int or not 0 < target_rva < 0x1_0000_0000:
                raise ValueError("outer CFG target RVA is invalid")
            if target_rva % 16:
                raise ValueError(
                    f"outer CFG target RVA 0x{target_rva:X} is not 16-byte aligned")
            live_targets.setdefault(target_rva, PlannedCfgTarget(
                target_rva, b"\0" * metadata_size, "outer_runtime"))
    merged_live_targets = tuple(live_targets[rva] for rva in sorted(live_targets))

    def emit(value: bytes, alignment: int = 8) -> int:
        while len(data) % alignment:
            data.append(0)
        rva = section_rva + len(data)
        data.extend(value)
        return rva

    def write_va(field_offset: int, target_rva: int) -> None:
        if field_offset + 8 > len(data):
            raise ValueError("load-config field is outside its declared size")
        struct.pack_into("<Q", data, field_offset,
                         image_base + target_rva if target_rva else 0)
        if target_rva:
            relocations.append(section_rva + field_offset)

    def emit_table(field_offset: int, count_offset: int,
                   targets: tuple[PlannedCfgTarget, ...]) -> None:
        table = _pack_targets(targets)
        table_rva = emit(table, 8) if table else 0
        write_va(field_offset, table_rva)
        struct.pack_into("<Q", data, count_offset, len(targets))

    def source_qword(rva: int, name: str) -> bytes:
        return pe_analyze._slice_at_rva(
            parsed.sections, rva, 8, what=f"load-config {name} slot")

    def shadow(field_offset: int, source_rva: int, name: str) -> None:
        if not source_rva:
            write_va(field_offset, 0)
            return
        raw = source_qword(source_rva, name)
        shadow_rva = emit(raw, 8)
        write_va(field_offset, shadow_rva)
        initial, = struct.unpack("<Q", raw)
        if image_base <= initial < image_base + parsed.size_of_image:
            relocations.append(shadow_rva)
        copies.append(RuntimeSlotCopy(source_rva, shadow_rva, name))

    emit_table(128, 136, merged_live_targets)
    emit_table(160, 168, tuple(
        PlannedCfgTarget(item.rva, item.metadata, "source")
        for item in load_config.guard_address_taken_iat_entries))
    emit_table(176, 184, tuple(
        PlannedCfgTarget(item.rva, item.metadata, "source")
        for item in load_config.guard_long_jump_targets))
    if load_config.declared_size >= 280:
        emit_table(264, 272, tuple(
            PlannedCfgTarget(item.rva, item.metadata, "source")
            for item in load_config.guard_eh_continuation_targets))

    volatile = load_config.volatile_metadata
    if volatile is not None:
        access_blob = b"".join(struct.pack("<I", item)
                               for item in volatile.access_rvas)
        range_blob = b"".join(struct.pack("<II", *item)
                              for item in volatile.info_ranges)
        access_rva = emit(access_blob, 4) if access_blob else 0
        ranges_rva = emit(range_blob, 4) if range_blob else 0
        volatile_blob = struct.pack(
            "<IHHIIII", 24, volatile.minimum_version,
            volatile.maximum_version, access_rva, len(access_blob),
            ranges_rva, len(range_blob))
        volatile_rva = emit(volatile_blob, 4)
        write_va(256, volatile_rva)
    elif load_config.declared_size >= 264:
        write_va(256, 0)

    for field_offset, source_rva, name in (
        (88, load_config.security_cookie_rva, "SecurityCookie"),
        (112, load_config.guard_cf_check_function_pointer_rva,
         "GuardCFCheckFunctionPointer"),
        (120, load_config.guard_cf_dispatch_function_pointer_rva,
         "GuardCFDispatchFunctionPointer"),
        (280, load_config.guard_xfg_check_function_pointer_rva,
         "GuardXFGCheckFunctionPointer"),
        (288, load_config.guard_xfg_dispatch_function_pointer_rva,
         "GuardXFGDispatchFunctionPointer"),
        (296, load_config.guard_xfg_table_dispatch_function_pointer_rva,
         "GuardXFGTableDispatchFunctionPointer"),
        (304, load_config.cast_guard_os_determined_failure_mode_rva,
         "CastGuardOsDeterminedFailureMode"),
        (312, load_config.guard_memcpy_function_pointer_rva,
         "GuardMemcpyFunctionPointer"),
    ):
        if field_offset < load_config.declared_size:
            shadow(field_offset, source_rva, name)

    return LiveLoadConfigImage(
        image_base=image_base,
        section_rva=section_rva,
        directory_rva=section_rva,
        directory_size=load_config.declared_size,
        data=bytes(data),
        relocation_target_rvas=tuple(sorted(set(relocations))),
        runtime_slot_copies=tuple(copies),
    )


__all__ = [
    "CfgPreservationBlocked", "CfgPreservationPlan", "LiveLoadConfigImage",
    "PlannedCfgTarget", "RuntimeSlotCopy", "RUNTIME_ENTRY",
    "LIVE_SECTION_CHARACTERISTICS", "RUNTIME_HEADER", "RUNTIME_MAGIC",
    "RUNTIME_RELOCATION", "RUNTIME_TARGET", "RUNTIME_VERSION",
    "build_cfg_preservation_plan", "build_live_load_config",
    "build_runtime_slot_blob", "require_cfg_preservation_supported",
]
