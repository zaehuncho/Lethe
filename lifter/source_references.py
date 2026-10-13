"""Non-waivable negative facts about references to overwritten source bytes.

This is not indirect/address-taken closure. Decoded RIP operands, validated
file-backed DIR64 pointer values, exact PE invocation entries and metadata
storage spans participate. Exact metadata invocation entries and a bounded
LEA-to-immediate-CALL use may remain callable. Other address-taken selected
entries, interior entries and reads of overwritten source bytes may not.
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
import os
import struct
from typing import Any, Iterable

from iced_x86 import FlowControl, MemorySizeExt, Mnemonic, OpKind, Register


class SourceReferenceError(ValueError):
    """A known source reference or its required inventory is unsafe."""


@dataclass(frozen=True, order=True)
class SourceReference:
    target_rva: int
    size: int
    source_rva: int
    kind: str
    address_only: bool = False
    metadata_entry: bool = False


_POINTER_REGISTERS = frozenset({
    Register.RAX, Register.RBX, Register.RCX, Register.RDX,
    Register.RSI, Register.RDI, Register.RBP, Register.RSP,
    Register.R8, Register.R9, Register.R10, Register.R11,
    Register.R12, Register.R13, Register.R14, Register.R15,
})


def proven_immediate_entry_calls(
    decoded_groups: Iterable[Any], *,
    known_entry_targets: Iterable[int] = (),
) -> frozenset[tuple[int, int]]:
    """Prove only a local full-width LEA followed by CALL of that exact register.

    Every group must be one already strictly decoded function or supplemental
    extent. No intervening instruction, store, arithmetic, register alias,
    direct branch into the CALL site, or known address-taken CALL-site entry
    earns an exception. This proves a bounded decoded local use, not general
    indirect target closure.
    """
    # Discovery caches each validated function as a tuple; preflight keeps
    # structured decode records. Preserve the same proof for both callers.
    groups = tuple(tuple(getattr(group, "instructions", group))
                   for group in decoded_groups)
    all_instructions = tuple(instruction for group in groups
                             for instruction in group)
    near_kinds = {OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32,
                  OpKind.NEAR_BRANCH64}
    direct_incoming = frozenset(
        int(instruction.near_branch_target)
        for instruction in all_instructions
        if instruction.flow_control in {
            FlowControl.CALL, FlowControl.UNCONDITIONAL_BRANCH,
            FlowControl.CONDITIONAL_BRANCH,
        }
        and instruction.op_count >= 1
        and instruction.op_kind(0) in near_kinds
    )
    entry_targets = frozenset(known_entry_targets)
    proven: set[tuple[int, int]] = set()
    for instructions in groups:
        by_ip = {int(instruction.ip): instruction for instruction in instructions}
        for instruction in instructions:
            if (instruction.mnemonic != Mnemonic.LEA
                    or not instruction.is_ip_rel_memory_operand
                    or instruction.memory_base != Register.RIP
                    or instruction.op_count != 2
                    or instruction.op_kind(0) != OpKind.REGISTER
                    or instruction.op0_register not in _POINTER_REGISTERS):
                continue
            following = by_ip.get(int(instruction.next_ip))
            if (following is not None
                    and int(following.ip) not in direct_incoming
                    and int(following.ip) not in entry_targets
                    and following.mnemonic == Mnemonic.CALL
                    and following.op_count == 1
                    and following.op_kind(0) == OpKind.REGISTER
                    and following.op0_register == instruction.op0_register):
                proven.add((int(instruction.ip), int(instruction.ip_rel_memory_address)))
    return frozenset(proven)


def instruction_references(instructions: Iterable[Any]) -> tuple[SourceReference, ...]:
    references = []
    for instruction in instructions:
        if not instruction.is_ip_rel_memory_operand or instruction.mnemonic == Mnemonic.NOP:
            continue
        # An EIP operand zero-extends the actual VA, not the decoder's RVA.
        # Do not mistake that address-size form for an ordinary RIP operand.
        if instruction.memory_base != Register.RIP:
            raise SourceReferenceError(
                f"unbounded source reference: address-size-relative operand at RVA 0x{instruction.ip:X}"
            )
        address_only = instruction.mnemonic == Mnemonic.LEA
        # FS/GS add a runtime segment base to the effective RIP address.
        # Without a proof of that base, its decoded RVA is not a bounded
        # image reference. LEA does not dereference or add a segment base;
        # NOP was excluded above, and legacy segment bases are zero in x64.
        if not address_only and instruction.memory_segment in {Register.FS, Register.GS}:
            raise SourceReferenceError(
                f"unbounded source reference: segment-relative memory operand at RVA 0x{instruction.ip:X}"
            )
        size = 1 if address_only else MemorySizeExt.size(instruction.memory_size)
        # A register bit-string offset can move beyond the encoded base.
        # Admit only an encoded imm8 *inside* the operand: the complete
        # 2/4/8-byte access then starts at the decoded RIP target. Do not infer
        # bounds from a register or normalize unsupported large immediates.
        bit_string = instruction.mnemonic in {
            Mnemonic.BT, Mnemonic.BTC, Mnemonic.BTR, Mnemonic.BTS,
        }
        bounded_bit = (
            bit_string and size in (2, 4, 8) and instruction.op_count == 2
            and instruction.op_kind(1) == OpKind.IMMEDIATE8
            and instruction.immediate8 < size * 8
        )
        if size <= 0 or (bit_string and not bounded_bit):
            raise SourceReferenceError(
                f"unbounded source reference: memory span at RVA 0x{instruction.ip:X}"
            )
        references.append(SourceReference(
            int(instruction.ip_rel_memory_address), size, int(instruction.ip),
            "RIP address" if address_only else "RIP memory", address_only,
        ))
    return tuple(references)


def dir64_references(parsed: Any) -> tuple[SourceReference, ...]:
    # Partial analysis records may omit the inventory. This does not prove it
    # empty: the materializer independently requires complete source metadata.
    inventory = getattr(parsed, "dir64_relocations", ())
    if not isinstance(inventory, (tuple, list)):
        raise SourceReferenceError("source reference: DIR64 inventory must be a sequence")
    if not inventory:
        return ()
    base = getattr(parsed, "image_base", None)
    if type(base) is not int or not 0 <= base < 1 << 64:
        raise SourceReferenceError("source reference: DIR64s require a valid image base")
    slots = []
    for item in inventory:
        rva = getattr(item, "target_rva", None)
        if type(rva) is not int or not 0 < rva <= (1 << 32) - 8:
            raise SourceReferenceError("source reference: DIR64 has an invalid eight-byte slot")
        slots.append(rva)
    slots.sort()
    if any(right < left + 8 for left, right in zip(slots, slots[1:])):
        raise SourceReferenceError("source reference: DIR64 slots overlap or duplicate")
    references = []
    for rva in slots:
        matches = [s for s in parsed.sections
                   if s.rva <= rva and rva + 8 <= s.rva + len(s.raw)]
        if len(matches) != 1:
            raise SourceReferenceError(
                f"source reference: DIR64 at RVA 0x{rva:X} must be uniquely file-backed"
            )
        section = matches[0]
        offset = rva - section.rva
        target = int.from_bytes(section.raw[offset:offset + 8], "little") - base
        if 0 < target < 1 << 32:
            references.append(SourceReference(target, 1, rva, "DIR64 address", True))
    return tuple(references)


def metadata_references(parsed: Any, *, exports: Iterable[Any] | None = None) -> tuple[SourceReference, ...]:
    """Known PE entry targets and metadata storage in overwritten source bytes.

    This is a negative inventory, not a proof of unknown indirect targets.
    Callable targets at the selected entry remain valid; storage bytes do not.
    """
    references: list[SourceReference] = []
    image_size = getattr(parsed, "size_of_image", None)
    if image_size is None and not hasattr(parsed, "reloc_blob"):
        path = getattr(parsed, "path", None)
        has_file = isinstance(path, str) and os.path.isfile(path)
        material_fields = (
            "oep_rva", "tls", "load_config", "export_directory_rva",
            "export_directory_size", "rsrc_directory_rva",
            "rsrc_directory_size", "delay_import_rva", "delay_import_size",
            "pdata_rva", "pdata_count", "dir64_relocations",
        )
        if not has_file and not any(getattr(parsed, field, None)
                                    for field in material_fields):
            # A decoded-code-only synthetic model has no PE metadata to
            # inventory. Real PE materialization always supplies SizeOfImage.
            return ()
    if type(image_size) is not int or not 0 < image_size <= 1 << 32:
        raise SourceReferenceError("source reference: invalid PE image size")

    def add(kind: str, rva: Any, size: Any = 1, *, entry: bool = False) -> None:
        if (type(rva) is not int or type(size) is not int
                or rva < 0 or size < 0 or rva + size > image_size
                or (rva == 0 and size > 1) or (rva > 0 and size == 0)):
            raise SourceReferenceError(f"source reference: invalid {kind} RVA span")
        if rva and size:
            references.append(SourceReference(rva, size, rva, kind, entry, entry))

    # The strict reader uses the source PE header and current ParsedPE section
    # bytes, so a stale EAT in a persisted manifest is checked at commit too.
    export_rva = getattr(parsed, "export_directory_rva", 0)
    export_size = getattr(parsed, "export_directory_size", 0)
    if export_rva or export_size:
        if not export_rva or not export_size:
            raise SourceReferenceError("source reference: incomplete export directory")
        add("export directory", export_rva, export_size)
    source_path = getattr(parsed, "path", None)
    has_source_path = isinstance(source_path, str) and os.path.isfile(source_path)
    # A caller-supplied export inventory may help name candidates, but it must
    # never hide a real PE export target from the overwrite safety proof.
    supplied_exports = () if exports is None else tuple(exports)
    if export_rva or export_size or has_source_path:
        if has_source_path or exports is None:
            try:
                from . import function_discovery
                source_exports = function_discovery.parse_pe_exports(parsed)
            except (ImportError, OSError, ValueError) as exc:
                raise SourceReferenceError(
                    f"source reference: strict export metadata unavailable: {exc}"
                ) from exc
        else:
            source_exports = ()
    else:
        source_exports = ()
    for item in (*source_exports, *supplied_exports):
        add(f"PE export {item.name!r}", item.rva, entry=True)

    add("image entry point", getattr(parsed, "oep_rva", 0), entry=True)
    tls = getattr(parsed, "tls", None)
    if tls is not None:
        for rva in tuple(getattr(tls, "callback_rvas", ())):
            add("TLS callback", rva, entry=True)
        add("TLS index", getattr(tls, "index_rva", 0), 4)
        raw_begin = getattr(tls, "raw_start_rva", 0)
        raw_end = getattr(tls, "raw_end_rva", 0)
        if type(raw_begin) is not int or type(raw_end) is not int or raw_end < raw_begin:
            raise SourceReferenceError("source reference: invalid TLS raw-data span")
        if raw_end > raw_begin:
            add("TLS raw-data", raw_begin, raw_end - raw_begin)

    # The loader writes ordinary import thunks through their full pointer
    # slots.  They are storage, never executable entry references.
    try:
        from . import native_tail_calls
        import_slots = tuple(
            function.iat_rva
            for dll in getattr(parsed, "imports", ())
            for function in dll.funcs
        )
        native_tail_calls.validated_import_iat_rvas(import_slots)
    except (AttributeError, TypeError, ValueError) as exc:
        raise SourceReferenceError(
            f"source reference: invalid ordinary import IAT inventory: {exc}"
        ) from exc
    for rva in import_slots:
        add("ordinary import IAT slot", rva, 8)

    relocations = getattr(parsed, "dir64_relocations", ())
    for item in relocations:
        add("source DIR64 relocation site", getattr(item, "target_rva", None), 8)
    def source_bytes(rva: int, size: int, kind: str) -> bytes:
        if type(rva) is not int or type(size) is not int or not 0 < rva <= image_size - size:
            raise SourceReferenceError(f"source reference: invalid {kind} byte span")
        matches = [section for section in getattr(parsed, "sections", ())
                   if section.rva <= rva and rva + size <= section.rva + len(section.raw)]
        if len(matches) != 1:
            raise SourceReferenceError(f"source reference: {kind} is not uniquely file-backed")
        owner = matches[0]
        return owner.raw[rva - owner.rva:rva - owner.rva + size]

    if has_source_path and export_rva:
        # The release assembler snapshots only the declared export span. Its
        # EAT/name/ordinal arrays and strings must live inside that span, not
        # merely elsewhere in a file-backed section. Check this before a
        # low-level proof or commit can misclassify external table storage.
        from . import function_discovery
        try:
            directory = function_discovery._slice_at_rva(
                parsed.sections, export_rva, 40, "export directory")
            (module_name_rva, _ordinal_base, function_count, name_count,
             functions_rva, names_rva, ordinals_rva) = struct.unpack_from(
                 "<IIIIIII", directory, 12)

            def within_export(label: str, rva: int, size: int) -> None:
                if rva < export_rva or rva + size > export_rva + export_size:
                    raise SourceReferenceError(
                        f"source reference: export-table storage escapes "
                        f"declared directory: {label}")

            module_name = function_discovery._read_c_string(
                parsed.sections, module_name_rva, "export module name")
            within_export("module name", module_name_rva, len(module_name) + 1)
            if function_count:
                within_export("address table", functions_rva, function_count * 4)
            if name_count:
                within_export("name-pointer table", names_rva, name_count * 4)
                within_export("name-ordinal table", ordinals_rva, name_count * 2)
                name_rvas = struct.unpack(
                    f"<{name_count}I",
                    function_discovery._slice_at_rva(
                        parsed.sections, names_rva, name_count * 4,
                        "export name table"))
                for index, name_rva in enumerate(name_rvas):
                    name = function_discovery._read_c_string(
                        parsed.sections, name_rva, f"export name[{index}]")
                    within_export(f"name[{index}]", name_rva, len(name) + 1)
        except (ValueError, struct.error) as exc:
            if isinstance(exc, SourceReferenceError):
                raise
            raise SourceReferenceError(
                f"source reference: invalid export-table storage: {exc}") from exc

    # A real ParsedPE has validated unwind records. Re-read their complete
    # header/code/handler-or-chain spans, not merely the first header byte.
    # Partial discovery fixtures without source bytes retain a conservative
    # four-byte header negative fact rather than inventing an unwind payload.
    seen_unwind: set[int] = set()
    active_unwind: set[int] = set()

    def add_unwind(rva: int, depth: int = 0) -> None:
        if rva in active_unwind:
            raise SourceReferenceError("source reference: cyclic unwind chain")
        if rva in seen_unwind:
            return
        if depth > 64:
            raise SourceReferenceError("source reference: unwind chain exceeds bound")
        active_unwind.add(rva)
        try:
            if not hasattr(parsed, "reloc_blob"):
                add("source unwind info", rva, 4)
            else:
                header = source_bytes(rva, 4, "UNWIND_INFO header")
                version, flags = header[0] & 7, header[0] >> 3
                if version in (1, 2):
                    payload_size = ((header[2] + 1) & ~1) * 2
                    tail = rva + 4 + payload_size
                elif version == 3:
                    payload_size = header[2] * 2
                    tail = (rva + 4 + payload_size + 3) & ~3
                else:
                    raise SourceReferenceError(
                        "source reference: unsupported UNWIND_INFO version")
                tail_size = 12 if flags & 4 else (4 if flags & 3 else 0)
                size = tail + tail_size - rva
                payload = source_bytes(rva, size, "UNWIND_INFO")
                add("source unwind info", rva, size)
                if flags & 4:
                    chain_begin = int.from_bytes(payload[-12:-8], "little")
                    chain_unwind = int.from_bytes(payload[-4:], "little")
                    add("chained runtime entry", chain_begin, entry=True)
                    add_unwind(chain_unwind, depth + 1)
                elif flags & 3:
                    handler_rva = int.from_bytes(payload[-4:], "little")
                    add("unwind handler entry", handler_rva, entry=True)
                    # EH/UH language data begins immediately after the handler
                    # RVA and has no generic PE-bounded length. Until its
                    # handler-specific format is proven, no later source RVA
                    # can safely be selected for overwrite.
                    language_rva = tail + 4
                    if language_rva < image_size:
                        add("unbounded unwind handler data", language_rva,
                            image_size - language_rva)
        finally:
            active_unwind.remove(rva)
        seen_unwind.add(rva)

    runtime_records = tuple(getattr(parsed, "runtime_functions", ()))
    if hasattr(parsed, "reloc_blob"):
        from packer import pe_analyze
        for item in runtime_records:
            try:
                pe_analyze._validate_runtime_function(
                    item.begin_rva, item.end_rva, item.unwind_info_rva,
                    image_size, parsed.sections, set())
            except (TypeError, ValueError) as exc:
                raise SourceReferenceError(
                    f"source reference: current unwind metadata is invalid: {exc}"
                ) from exc
    for item in runtime_records:
        add_unwind(getattr(item, "unwind_info_rva", None))
    pdata_rva = getattr(parsed, "pdata_rva", 0)
    pdata_count = getattr(parsed, "pdata_count", 0)
    if type(pdata_count) is not int or pdata_count < 0:
        raise SourceReferenceError("source reference: invalid PDATA count")
    if pdata_count:
        add("source exception table", pdata_rva, pdata_count * 12)
    for label, rva, size in (
        ("resource directory", getattr(parsed, "rsrc_directory_rva", 0),
         getattr(parsed, "rsrc_directory_size", 0)),
        ("delay-import directory", getattr(parsed, "delay_import_rva", 0),
         getattr(parsed, "delay_import_size", 0)),
    ):
        if rva or size:
            add(label, rva, size)

    config = getattr(parsed, "load_config", None)
    if config is not None:
        add("load-config directory", getattr(config, "directory_rva", 0),
            getattr(config, "directory_size", 0))
        flags = getattr(config, "guard_flags", 0)
        if type(flags) is not int or not 0 <= flags < 1 << 32:
            raise SourceReferenceError("source reference: invalid GuardFlags")
        stride = 4 + ((flags >> 28) & 15)
        for label, table, targets, callable_target in (
            ("Guard CF", "guard_cf_function_table_rva", "guard_cf_targets", True),
            ("Guard address-taken IAT", "guard_address_taken_iat_entry_table_rva",
             "guard_address_taken_iat_entries", False),
            ("Guard long-jump", "guard_long_jump_target_table_rva",
             "guard_long_jump_targets", True),
            ("Guard EH-continuation", "guard_eh_continuation_table_rva",
             "guard_eh_continuation_targets", True),
        ):
            rows = tuple(getattr(config, targets, ()))
            table_rva = getattr(config, table, 0)
            if table_rva and rows:
                add(f"{label} table", table_rva, len(rows) * stride)
            for item in rows:
                add(f"{label} target", getattr(item, "rva", None),
                    1 if callable_target else 8, entry=callable_target)
        for item in getattr(config, "guard_cf_targets", ()):
            metadata = getattr(item, "metadata", b"")
            if metadata and metadata[0] & 0x08:
                add("XFG function hash", item.rva - 8, 8)
        for field in (
            "security_cookie_rva", "guard_cf_check_function_pointer_rva",
            "guard_cf_dispatch_function_pointer_rva",
            "guard_xfg_check_function_pointer_rva",
            "guard_xfg_dispatch_function_pointer_rva",
            "guard_xfg_table_dispatch_function_pointer_rva",
            "cast_guard_os_determined_failure_mode_rva",
            "guard_memcpy_function_pointer_rva",
        ):
            rva = getattr(config, field, 0)
            if rva:
                add(f"load-config {field}", rva, 8)
        volatile = getattr(config, "volatile_metadata", None)
        if volatile is not None:
            raw = getattr(volatile, "raw", b"")
            if not isinstance(raw, bytes) or len(raw) < 24:
                raise SourceReferenceError("source reference: invalid volatile metadata header")
            volatile_rva = getattr(volatile, "rva", None)
            if hasattr(parsed, "reloc_blob") and source_bytes(
                    volatile_rva, len(raw), "volatile metadata") != raw:
                raise SourceReferenceError(
                    "source reference: volatile metadata changed after analysis")
            add("volatile metadata", volatile_rva, len(raw))
            access_rva, access_size, info_rva, info_size = struct.unpack_from(
                "<IIII", raw, 8)
            for label, rva, size in (
                ("volatile access table", access_rva, access_size),
                ("volatile info table", info_rva, info_size),
            ):
                if bool(rva) != bool(size):
                    raise SourceReferenceError(f"source reference: incomplete {label}")
                if rva:
                    add(label, rva, size)
            for rva in getattr(volatile, "access_rvas", ()):
                add("volatile access target", rva)
            # Info ranges classify executable code for emulation. They are not
            # byte storage, and overlap alone does not name an instruction or
            # alternate entry into a selected body. Exact access RVAs do.
    return tuple(references)


class SourceReferenceIndex:
    """Build once; query candidate extents without rescanning the image."""

    def __init__(self, references: Iterable[SourceReference], *,
                 proven_entry_calls: Iterable[tuple[int, int]] = ()) -> None:
        self.references = tuple(sorted(references))
        self.starts = tuple(item.target_rva for item in self.references)
        self.max_size = max((item.size for item in self.references), default=1)
        self.proven_entry_calls = frozenset(proven_entry_calls)

    def rejection(self, name: str, rva: int, size: int) -> str | None:
        start = bisect_left(self.starts, rva - self.max_size + 1)
        end = bisect_left(self.starts, rva + size)
        for item in self.references[start:end]:
            if item.target_rva + item.size <= rva:
                continue
            if item.target_rva == rva and item.metadata_entry:
                continue
            if (item.target_rva == rva and item.kind == "RIP address"
                    and (item.source_rva, rva) in self.proven_entry_calls):
                continue
            return (
                f"known source reference: {item.kind} at RVA 0x{item.source_rva:X} "
                f"targets 0x{item.target_rva:X}+0x{item.size:X}, overlapping "
                f"overwritten function {name!r} 0x{rva:X}..0x{rva + size:X}"
            )
        return None

    def validate(self, selected: Iterable[Any]) -> None:
        for spec in selected:
            reason = self.rejection(spec.name, spec.rva, spec.size)
            if reason is not None:
                raise SourceReferenceError(reason)
