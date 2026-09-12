"""LIEF-based x64 PE parser for the Lethe builder (build-time tooling only).

This module extracts everything the packer needs from an *original* input PE
(EXE or DLL) into a clean, JSON-free :class:`ParsedPE` dataclass that the payload
builder (:mod:`packer.payload`) and the assembler (:mod:`packer.assemble`)
consume. It performs no crypto and no output generation -- it is pure analysis.

Dependency
----------
Requires **LIEF** (``pip install lief``). LIEF is a build-time-only dependency of
the packer toolchain; it is never shipped in the native stub. Developed and
verified against ``lief == 1.0.0``. The few version-sensitive spots (enum->int,
IAT slot RVA) are written defensively.

Address conventions
--------------------
Every ``*_rva`` field in :class:`ParsedPE` (and its members) is an **RVA within
the original module** -- add :attr:`ParsedPE.image_base` to obtain a runtime VA.
LIEF exposes some values as absolute VAs (TLS directory pointers) and some as
RVAs already (import ``iat_address``); this module normalizes everything to RVAs.

What is extracted
-----------------
* image params: ``is_dll``, ``image_base``, ``size_of_image``, ``oep_rva``
* sections: name, RVA, virtual size, on-disk raw bytes, characteristics
* imports: ``List[ImportDll]`` (container.py types); each ``ImportFunc.iat_rva``
  is the RVA of the IAT slot the stub must write the resolved address into
* relocations: the verbatim base-relocation blob (trimmed to the data-directory
  size, i.e. no file-alignment padding -- the stub walks it by size)
* TLS: index/raw-data/callback RVAs + zero-fill, iff a TLS directory exists
* exceptions: ``.pdata`` RVA + ``pdata_count`` (= exception-table size / 12)
* load config: strict Guard CF/IAT/long-jump/EH-continuation target inventories,
  with explicit unsupported dynamic-relocation, CHPE, and XFG feature markers
* resources: ``.rsrc`` RVA + raw bytes, to be preserved *plaintext* by the
  assembler (icon / RT_VERSION / RT_MANIFEST must stay OS/Authenticode-readable)

Only PE32+ (x64 / AMD64) input is supported; x86 (PE32) and ARM raise a clear
:class:`ValueError`.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

import lief

try:  # package import (normal case)
    from .container import ImportDll, ImportFunc
except ImportError:  # pragma: no cover - allows standalone / importlib file loading
    from container import ImportDll, ImportFunc  # type: ignore

__all__ = [
    "ParsedSection",
    "TlsInfo",
    "ParsedDir64Relocation",
    "ParsedRuntimeFunction",
    "ParsedGuardTarget",
    "ParsedVolatileMetadata",
    "ParsedLoadConfig",
    "ParsedPE",
    "analyze_pe",
    "PEArchError",
]

# PE constants (avoid depending on LIEF enum *names*, which drift across versions)
_PE32_PLUS = 0x20B          # OptionalHeader.Magic for x64
_MACHINE_AMD64 = 0x8664     # IMAGE_FILE_MACHINE_AMD64
_IMAGE_FILE_RELOCS_STRIPPED = 0x0001
_IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
_IMAGE_FILE_SYSTEM = 0x1000
_IMAGE_FILE_DLL = 0x2000    # IMAGE_FILE_DLL characteristic
_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
_IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000
_IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
_IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
_IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
_RUNTIME_FUNCTION_SIZE = 12  # x64 RUNTIME_FUNCTION (.pdata entry) is 12 bytes
_PTR_SIZE = 8                # x64 IAT thunk width
_RELOC_ABSOLUTE = 0
_RELOC_DIR64 = 10
_UNW_FLAG_EHANDLER = 0x01
_UNW_FLAG_UHANDLER = 0x02
_UNW_FLAG_CHAININFO = 0x04
_UNW_FLAG_LARGE_V3 = 0x08
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_OUTPUT_SECTION_ALIGNMENT = 0x1000

_GUARD_CF_INSTRUMENTED = 0x00000100
_GUARD_CFW_INSTRUMENTED = 0x00000200
_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x00000400
_GUARD_SECURITY_COOKIE_UNUSED = 0x00000800
_GUARD_PROTECT_DELAYLOAD_IAT = 0x00001000
_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 0x00002000
_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT = 0x00004000
_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 0x00008000
_GUARD_CF_LONGJUMP_TABLE_PRESENT = 0x00010000
_GUARD_RF_INSTRUMENTED = 0x00020000
_GUARD_RF_ENABLE = 0x00040000
_GUARD_RF_STRICT = 0x00080000
_GUARD_RETPOLINE_PRESENT = 0x00100000
_GUARD_EH_CONTINUATION_TABLE_PRESENT = 0x00400000
_GUARD_XFG_ENABLED = 0x00800000
_GUARD_CASTGUARD_PRESENT = 0x01000000
_GUARD_MEMCPY_PRESENT = 0x02000000
_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28
_GUARD_CF_FUNCTION_TABLE_SIZE_MASK = 0xF0000000
_KNOWN_GUARD_FLAGS = (
    _GUARD_CF_INSTRUMENTED
    | _GUARD_CFW_INSTRUMENTED
    | _GUARD_CF_FUNCTION_TABLE_PRESENT
    | _GUARD_SECURITY_COOKIE_UNUSED
    | _GUARD_PROTECT_DELAYLOAD_IAT
    | _GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION
    | _GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT
    | _GUARD_CF_ENABLE_EXPORT_SUPPRESSION
    | _GUARD_CF_LONGJUMP_TABLE_PRESENT
    | _GUARD_RF_INSTRUMENTED
    | _GUARD_RF_ENABLE
    | _GUARD_RF_STRICT
    | _GUARD_RETPOLINE_PRESENT
    | _GUARD_EH_CONTINUATION_TABLE_PRESENT
    | _GUARD_XFG_ENABLED
    | _GUARD_CASTGUARD_PRESENT
    | _GUARD_MEMCPY_PRESENT
    | _GUARD_CF_FUNCTION_TABLE_SIZE_MASK
)

_LOAD_CONFIG64_MIN_SIZE = 112
_LOAD_CONFIG64_MAX_SIZE = 328


class PEArchError(ValueError):
    """Raised when the input PE is not a supported x64 (PE32+) binary."""


def _i(value) -> int:
    """Coerce a LIEF enum / int-like to a plain ``int`` (version-robust)."""
    try:
        return int(value)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return int(getattr(value, "value", 0))


# ---------------------------------------------------------------------------
# dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ParsedSection:
    """One section of the original image.

    ``raw`` is the on-disk initialized content (``SizeOfRawData`` bytes); it may
    be shorter than ``virtual_size`` (the remainder is zero-fill / BSS) and is
    empty for uninitialized-only sections. The payload builder compresses +
    encrypts ``raw``; the stub decrypts it back to ``rva`` and zero-extends to
    ``virtual_size``.
    """

    name: str
    rva: int                 # RVA of the section (VirtualAddress)
    virtual_size: int        # VirtualSize (mapped size)
    raw: bytes               # on-disk raw bytes (== SizeOfRawData length)
    characteristics: int     # IMAGE_SCN_* -> drives final page protection


@dataclass
class TlsInfo:
    """TLS directory, normalized to module RVAs (present iff the input had TLS)."""

    index_rva: int
    callback_rvas: List[int]
    raw_start_rva: int
    raw_end_rva: int
    zero_fill: int
    characteristics: int = 0


@dataclass(frozen=True, order=True)
class ParsedDir64Relocation:
    """One validated AMD64 DIR64 patch site, as an original-image RVA."""

    target_rva: int


@dataclass(frozen=True)
class ParsedRuntimeFunction:
    """One validated on-disk AMD64 ``RUNTIME_FUNCTION`` record."""

    begin_rva: int
    end_rva: int
    unwind_info_rva: int
    unwind_flags: int = 0


@dataclass(frozen=True, order=True)
class ParsedGuardTarget:
    """One Guard CF target RVA and its opaque per-entry metadata bytes."""

    rva: int
    metadata: bytes = b""


@dataclass(frozen=True)
class ParsedVolatileMetadata:
    """Validated IMAGE_VOLATILE_METADATA and its RVA-based tables."""

    rva: int
    minimum_version: int
    maximum_version: int
    access_rvas: tuple[int, ...]
    info_ranges: tuple[tuple[int, int], ...]
    raw: bytes


@dataclass(frozen=True)
class ParsedLoadConfig:
    """Strict PE32+ load-config mitigation inventory."""

    directory_rva: int
    directory_size: int
    declared_size: int
    major_version: int
    minor_version: int
    guard_flags: int
    security_cookie_rva: int
    guard_cf_check_function_pointer_rva: int
    guard_cf_dispatch_function_pointer_rva: int
    guard_cf_function_table_rva: int
    guard_cf_targets: tuple[ParsedGuardTarget, ...]
    guard_address_taken_iat_entry_table_rva: int
    guard_address_taken_iat_entries: tuple[ParsedGuardTarget, ...]
    guard_long_jump_target_table_rva: int
    guard_long_jump_targets: tuple[ParsedGuardTarget, ...]
    guard_eh_continuation_table_rva: int
    guard_eh_continuation_targets: tuple[ParsedGuardTarget, ...]
    dynamic_value_relocations_present: bool
    chpe_metadata_present: bool
    xfg_present: bool
    unsupported_features: tuple[str, ...]
    raw: bytes
    volatile_metadata: Optional[ParsedVolatileMetadata] = None
    guard_xfg_check_function_pointer_rva: int = 0
    guard_xfg_dispatch_function_pointer_rva: int = 0
    guard_xfg_table_dispatch_function_pointer_rva: int = 0
    cast_guard_os_determined_failure_mode_rva: int = 0
    guard_memcpy_function_pointer_rva: int = 0

    @property
    def has_guard_cf(self) -> bool:
        return bool(
            self.guard_flags
            & (_GUARD_CF_INSTRUMENTED | _GUARD_CFW_INSTRUMENTED
               | _GUARD_CF_FUNCTION_TABLE_PRESENT)
            or self.guard_cf_check_function_pointer_rva
            or self.guard_cf_dispatch_function_pointer_rva
            or self.guard_cf_targets
        )


@dataclass
class ParsedPE:
    """Everything the packer needs from the original input PE.

    All ``*_rva`` values are RVAs within the original module. ``sections`` is in
    on-disk order. ``imports`` uses the container.py ABI types directly, so the
    payload builder can hand them to ``build_import_blob`` unchanged.
    """

    path: str
    is_dll: bool
    image_base: int
    size_of_image: int
    oep_rva: int                         # AddressOfEntryPoint (OEP / DllMain RVA)
    sections: List[ParsedSection]
    imports: List[ImportDll]
    reloc_blob: bytes                    # verbatim IMAGE_BASE_RELOCATION blocks (no padding)
    tls: Optional[TlsInfo]               # None if no TLS directory
    pdata_rva: int                       # 0 if no exception table
    pdata_count: int                     # # of RUNTIME_FUNCTION (size / 12)
    rsrc_rva: int                        # owning resource-section RVA, or 0
    file_characteristics: int            # IMAGE_FILE_* input contract
    dll_characteristics: int             # IMAGE_DLLCHARACTERISTICS_* input contract
    rsrc_bytes: bytes = b""              # owner-section raw bytes, plaintext
    rsrc_directory_rva: int = 0           # exact RESOURCE DataDirectory RVA
    rsrc_directory_size: int = 0          # exact RESOURCE DataDirectory size
    delay_import_rva: int = 0              # exact delay-import directory RVA
    delay_import_size: int = 0             # exact delay-import directory size
    dir64_relocations: tuple[ParsedDir64Relocation, ...] = ()
    runtime_functions: tuple[ParsedRuntimeFunction, ...] = ()
    load_config: Optional[ParsedLoadConfig] = None
    requires_paged_vm: bool = False
    generated_cfg_targets: tuple[ParsedGuardTarget, ...] = ()
    section_alignment: int = _OUTPUT_SECTION_ALIGNMENT

    @property
    def has_tls(self) -> bool:
        return self.tls is not None

    @property
    def has_exceptions(self) -> bool:
        return self.pdata_count > 0


_IMAGE_DEBUG_DIRECTORY = struct.Struct("<IIHHIIII")
_IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20


def _parse_extended_dll_characteristics(
    debug_blob: bytes,
    *,
    image_size: int,
    sections: List[ParsedSection],
) -> int:
    """Inventory loader-visible extended DLL characteristics.

    Lethe does not yet emit an outer debug directory. Any nonzero extended
    characteristic must therefore reject before mutation instead of silently
    stripping CET Shadow Stack or future mitigation declarations.
    """
    if not debug_blob:
        return 0
    if len(debug_blob) % _IMAGE_DEBUG_DIRECTORY.size:
        raise ValueError("malformed debug directory: partial entry")
    found = None
    for offset in range(0, len(debug_blob), _IMAGE_DEBUG_DIRECTORY.size):
        (characteristics, _timestamp, _major, _minor, debug_type,
         data_size, data_rva, _data_pointer) = _IMAGE_DEBUG_DIRECTORY.unpack_from(
             debug_blob, offset)
        if characteristics != 0:
            raise ValueError("malformed debug directory: Characteristics must be zero")
        if debug_type != _IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:
            continue
        if found is not None:
            raise ValueError(
                "malformed debug directory: duplicate extended DLL characteristics")
        if data_size != 4 or data_rva == 0:
            raise ValueError(
                "malformed extended DLL characteristics: expected one mapped DWORD")
        _validate_directory_range(
            "extended DLL characteristics", data_rva, data_size, image_size)
        raw = _slice_at_rva(
            sections, data_rva, data_size,
            what="extended DLL characteristics")
        found, = struct.unpack("<I", raw)
    return found or 0


def _validate_user_mode_contract(
    file_characteristics: int,
    dll_characteristics: int,
    subsystem: int,
) -> None:
    if not file_characteristics & _IMAGE_FILE_EXECUTABLE_IMAGE:
        raise PEArchError("input is not an executable PE image")
    if file_characteristics & _IMAGE_FILE_SYSTEM:
        raise PEArchError("kernel/system images are not supported")
    if dll_characteristics & _IMAGE_DLLCHARACTERISTICS_WDM_DRIVER:
        raise PEArchError("WDM drivers are not supported")
    if subsystem not in (
        _IMAGE_SUBSYSTEM_WINDOWS_GUI,
        _IMAGE_SUBSYSTEM_WINDOWS_CUI,
    ):
        raise PEArchError(
            f"unsupported PE subsystem {subsystem}; Lethe supports Windows GUI/CUI only")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _slice_at_rva(sections: List[ParsedSection], rva: int, size: int,
                  *, what: str = "data directory") -> bytes:
    """Return exactly ``size`` file-backed bytes at module ``rva``.

    A present PE data directory is an integrity contract, not a best-effort
    hint. Returning a truncated prefix makes a malformed relocation or unwind
    table look valid, so missing bytes are rejected explicitly.
    """
    if rva == 0 and size == 0:
        return b""
    if rva <= 0 or size <= 0:
        raise ValueError(
            f"malformed {what}: RVA and size must both be nonzero "
            f"(rva=0x{rva:X}, size=0x{size:X})")

    end = rva + size
    if end > 0x1_0000_0000:
        raise ValueError(f"malformed {what}: RVA range overflows 32 bits")

    cursor = rva
    out = bytearray()
    ordered = sorted(sections, key=lambda sec: sec.rva)
    while cursor < end:
        owner = next(
            (sec for sec in ordered
             if sec.rva <= cursor < sec.rva + len(sec.raw)),
            None,
        )
        if owner is None:
            raise ValueError(
                f"malformed {what}: RVA 0x{cursor:X} is not file-backed")
        take = min(end - cursor, owner.rva + len(owner.raw) - cursor)
        offset = cursor - owner.rva
        out += owner.raw[offset:offset + take]
        cursor += take
    return bytes(out)


def _data_dir(binary, name: str):
    """Return the ``(rva, size)`` of a named data directory, or ``(0, 0)``."""
    try:
        dtype = getattr(lief.PE.DataDirectory.TYPES, name)
    except AttributeError as exc:  # pragma: no cover - unsupported LIEF API
        raise RuntimeError(f"LIEF does not expose PE directory type {name}") from exc
    try:
        dd = binary.data_directory(dtype)
    except (AttributeError, IndexError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError(f"cannot read PE data directory {name}: {exc}") from exc
    if dd is None:
        return 0, 0
    rva, size = _i(dd.rva), _i(dd.size)
    if (rva == 0) != (size == 0):
        raise ValueError(
            f"malformed PE data directory {name}: RVA and size presence "
            f"disagree (rva=0x{rva:X}, size=0x{size:X})")
    return rva, size


_DELAY_DESCRIPTOR = struct.Struct("<8I")


def _validate_delay_import_directory(
        blob: bytes, *, image_size: int,
        sections: List[ParsedSection]) -> None:
    """Validate the RVA-based helper shape Lethe can restore verbatim."""
    if not blob:
        return
    if len(blob) % _DELAY_DESCRIPTOR.size:
        raise ValueError(
            "malformed delay-import directory: partial descriptor")
    terminated = False
    for offset in range(0, len(blob), _DELAY_DESCRIPTOR.size):
        fields = _DELAY_DESCRIPTOR.unpack_from(blob, offset)
        if not any(fields):
            terminated = True
            if any(blob[offset + _DELAY_DESCRIPTOR.size:]):
                raise ValueError(
                    "malformed delay-import directory: data follows terminator")
            break
        (attributes, name_rva, module_handle_rva, iat_rva, int_rva,
         bound_iat_rva, unload_iat_rva, timestamp) = fields
        if attributes != 1:
            raise ValueError(
                "unsupported delay-import descriptor attributes: only "
                "RVA-based descriptors are supported")
        for label, rva, width in (
            ("DLL name", name_rva, 1),
            ("module handle", module_handle_rva, 8),
            ("IAT", iat_rva, 8),
            ("INT", int_rva, 8),
        ):
            if not (0 < rva <= image_size - width):
                raise ValueError(
                    f"malformed delay-import {label}: RVA is outside image")
            _slice_at_rva(
                sections, rva, width,
                what=f"delay-import {label}")
        for label, rva in (
            ("bound IAT", bound_iat_rva),
            ("unload IAT", unload_iat_rva),
        ):
            if rva:
                if rva > image_size - 8:
                    raise ValueError(
                        f"malformed delay-import {label}: RVA is outside image")
                _slice_at_rva(
                    sections, rva, 8,
                    what=f"delay-import {label}")
        name_owner = next(
            (section for section in sections
             if section.rva <= name_rva < section.rva + len(section.raw)),
            None,
        )
        if name_owner is None:
            raise ValueError(
                "malformed delay-import DLL name: RVA is not file-backed")
        name_offset = name_rva - name_owner.rva
        name_end = name_owner.raw.find(b"\0", name_offset)
        if name_end < 0 or name_end == name_offset:
            raise ValueError(
                "malformed delay-import DLL name: missing bounded string")
        try:
            name_owner.raw[name_offset:name_end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "malformed delay-import DLL name: non-ASCII bytes") from exc
        if timestamp and not bound_iat_rva:
            raise ValueError(
                "unsupported delay-import descriptor: timestamp without "
                "bound IAT")
    if not terminated:
        raise ValueError(
            "malformed delay-import directory: missing null terminator")


def _validate_directory_range(name: str, rva: int, size: int,
                              image_size: int) -> None:
    if rva == 0 and size == 0:
        return
    end = rva + size
    if rva <= 0 or size <= 0 or end > image_size or end > 0x1_0000_0000:
        raise ValueError(
            f"malformed {name} directory: range 0x{rva:X}+0x{size:X} "
            f"is outside SizeOfImage 0x{image_size:X}")


def _validate_sections(
        sections: List[ParsedSection], image_size: int,
        section_alignment: int = _OUTPUT_SECTION_ALIGNMENT) -> None:
    """Validate source ranges against Lethe's fixed 4 KiB output geometry.

    The assembler preserves source RVAs but publishes SectionAlignment=0x1000,
    and the runtime applies final permissions with VirtualProtect. Inputs using
    sub-page alignment or sharing a hardware page between sections cannot keep
    their original mapping/protection semantics under that contract.
    """
    if (section_alignment < _OUTPUT_SECTION_ALIGNMENT or
            section_alignment % _OUTPUT_SECTION_ALIGNMENT):
        raise ValueError(
            "unsupported source SectionAlignment "
            f"0x{section_alignment:X}: Lethe emits fixed 0x1000 alignment and "
            "cannot preserve sub-page or non-page-compatible section geometry")
    if image_size <= 0 or image_size % _OUTPUT_SECTION_ALIGNMENT:
        raise ValueError(
            f"malformed SizeOfImage 0x{image_size:X}: fixed 0x1000 output "
            "alignment requires a page-aligned image size")

    ranges = []
    page_ranges = []
    for sec in sections:
        span = max(sec.virtual_size, len(sec.raw))
        if sec.rva <= 0 or span <= 0 or sec.rva + span > image_size:
            raise ValueError(
                f"malformed section {sec.name!r}: mapped range "
                f"0x{sec.rva:X}+0x{span:X} is outside SizeOfImage "
                f"0x{image_size:X}")
        memory_access = sec.characteristics & (
            _IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_MEM_READ |
            _IMAGE_SCN_MEM_WRITE)
        if ((memory_access & _IMAGE_SCN_MEM_EXECUTE) and
                (memory_access & _IMAGE_SCN_MEM_WRITE)):
            raise ValueError(
                f"unsupported section {sec.name!r}: source is writable and "
                "executable, but Lethe's no-RWX runtime would silently remove "
                "write access")
        if not sec.raw and memory_access != (
                _IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_WRITE):
            raise ValueError(
                f"unsupported raw-empty section {sec.name!r}: required memory "
                f"access 0x{memory_access:08X} is not compatible with Lethe's "
                "RW zero-backed placeholder")
        ranges.append((sec.rva, sec.rva + span, sec.name))
        page_start = sec.rva & ~(_OUTPUT_SECTION_ALIGNMENT - 1)
        page_end = (
            sec.rva + span + _OUTPUT_SECTION_ALIGNMENT - 1
        ) & ~(_OUTPUT_SECTION_ALIGNMENT - 1)
        if page_end > image_size:
            raise ValueError(
                f"unsupported section {sec.name!r}: page-rounded mapped range "
                f"0x{sec.rva:X}..0x{page_end:X} escapes SizeOfImage "
                f"0x{image_size:X}")
        page_ranges.append((page_start, page_end, sec.name))
    ranges.sort()
    for (_, previous_end, previous_name), (start, _, name) in zip(
            ranges, ranges[1:]):
        if start < previous_end:
            raise ValueError(
                f"malformed sections: {previous_name!r} overlaps {name!r}")
    page_ranges.sort()
    for (_, previous_end, previous_name), (start, _, name) in zip(
            page_ranges, page_ranges[1:]):
        if start < previous_end:
            raise ValueError(
                "unsupported page-sharing sections: "
                f"{previous_name!r} and {name!r} occupy the same 0x1000-byte "
                "hardware page, so independent final protections are impossible")
    for sec in sections:
        if sec.rva % section_alignment:
            raise ValueError(
                f"malformed section {sec.name!r} RVA 0x{sec.rva:X}: not "
                f"aligned to source SectionAlignment 0x{section_alignment:X}")
        if sec.rva % _OUTPUT_SECTION_ALIGNMENT:
            raise ValueError(
                f"unsupported section {sec.name!r} RVA 0x{sec.rva:X}: Lethe "
                "preserves source RVAs under fixed 0x1000 output alignment")


def _validate_relocations(blob: bytes, image_size: int,
                          sections: Optional[List[ParsedSection]] = None
                          ) -> tuple[ParsedDir64Relocation, ...]:
    pos = 0
    seen_targets = set()
    validated_targets = []
    first_section_rva = min((sec.rva for sec in sections or []),
                            default=image_size)
    while pos < len(blob):
        if len(blob) - pos < 8:
            raise ValueError("malformed base relocations: trailing partial block")
        page_rva, block_size = struct.unpack_from("<II", blob, pos)
        if (page_rva & 0xFFF or block_size < 8
                or block_size > len(blob) - pos or block_size % 4):
            raise ValueError(
                f"malformed base relocation block at offset 0x{pos:X}")
        entries = (block_size - 8) // 2
        for index in range(entries):
            entry, = struct.unpack_from("<H", blob, pos + 8 + index * 2)
            reloc_type, offset = entry >> 12, entry & 0x0FFF
            if reloc_type == _RELOC_ABSOLUTE:
                continue
            if reloc_type != _RELOC_DIR64:
                raise ValueError(
                    f"unsupported AMD64 base relocation type {reloc_type} "
                    f"at blob offset 0x{pos + 8 + index * 2:X}")
            target = page_rva + offset
            if target + _PTR_SIZE > image_size:
                raise ValueError(
                    f"malformed base relocation target 0x{target:X}: "
                    f"outside SizeOfImage 0x{image_size:X}")
            in_section = any(
                sec.rva <= target
                and target + _PTR_SIZE <= sec.rva + max(
                    sec.virtual_size, len(sec.raw))
                for sec in sections or []
            )
            if sections is not None and not (
                    target + _PTR_SIZE <= first_section_rva or in_section):
                raise ValueError(
                    f"malformed base relocation target 0x{target:X}: "
                    "not contained by headers or a mapped section")
            if target in seen_targets:
                raise ValueError(
                    f"malformed base relocations: duplicate DIR64 target "
                    f"0x{target:X}")
            seen_targets.add(target)
            validated_targets.append(ParsedDir64Relocation(target))
        pos += block_size
    return tuple(validated_targets)


def _unwind_bytes(sections: List[ParsedSection], rva: int, size: int,
                  image_size: int, what: str) -> bytes:
    if rva <= 0 or size <= 0 or rva + size > image_size:
        raise ValueError(
            f"malformed {what}: RVA range 0x{rva:X}+0x{size:X} is outside "
            f"SizeOfImage 0x{image_size:X}")
    return _slice_at_rva(sections, rva, size, what=what)


def _validate_classic_unwind_codes(version: int, codes: bytes,
                                   prolog_size: int, frame_register: int) -> None:
    """Validate complete v1/v2 UNWIND_CODE slot consumption.

    v2's UWOP_EPILOG prefix is deliberately handled separately from the
    conventional prolog operations. Its first long-form marker consumes an
    extension slot; subsequent markers consume one slot each.
    """
    slot = 0
    epilog_prefix = True
    previous_code_offset = 0x100
    count = len(codes) // 2
    while slot < count:
        code_offset, encoded = struct.unpack_from("<BB", codes, slot * 2)
        opcode, opinfo = encoded & 0x0F, encoded >> 4

        if opcode == 6:  # UWOP_EPILOG (v2 only)
            if version != 2 or not epilog_prefix:
                raise ValueError("malformed UNWIND_INFO: invalid UWOP_EPILOG")
            slots = 2 if slot == 0 and (opinfo & 1) == 0 else 1
        else:
            epilog_prefix = False
            if code_offset > prolog_size:
                raise ValueError(
                    "malformed UNWIND_INFO: unwind code exceeds prolog")
            if code_offset > previous_code_offset:
                raise ValueError(
                    "malformed UNWIND_INFO: unwind codes are out of order")
            previous_code_offset = code_offset
            if opcode == 0:       # UWOP_PUSH_NONVOL
                slots = 1
            elif opcode == 1:     # UWOP_ALLOC_LARGE
                if opinfo not in (0, 1):
                    raise ValueError(
                        "malformed UNWIND_INFO: invalid UWOP_ALLOC_LARGE")
                slots = 2 if opinfo == 0 else 3
            elif opcode == 2:     # UWOP_ALLOC_SMALL
                slots = 1
            elif opcode == 3:     # UWOP_SET_FPREG
                # Windows system images mirror FrameOffset in OpInfo even
                # though classic descriptions call this nibble unused.
                if frame_register == 0:
                    raise ValueError(
                        "malformed UNWIND_INFO: invalid UWOP_SET_FPREG")
                slots = 1
            elif opcode in (4, 8):   # SAVE_NONVOL / SAVE_XMM128
                slots = 2
            elif opcode in (5, 9):   # *_FAR
                slots = 3
            elif opcode == 10:       # UWOP_PUSH_MACHFRAME
                if opinfo not in (0, 1):
                    raise ValueError(
                        "malformed UNWIND_INFO: invalid UWOP_PUSH_MACHFRAME")
                slots = 1
            elif opcode == 11 and version == 2:  # UWOP_SET_FPREG_LARGE
                if frame_register == 0:
                    raise ValueError(
                        "malformed UNWIND_INFO: invalid UWOP_SET_FPREG_LARGE")
                slots = 3
            else:
                raise ValueError(
                    f"malformed UNWIND_INFO: unsupported unwind opcode {opcode}")

        if slot + slots > count:
            raise ValueError(
                "malformed UNWIND_INFO: truncated unwind-code operands")
        slot += slots


def _v3_wod_size(pool: bytes, offset: int) -> int:
    if offset >= len(pool):
        raise ValueError("malformed UNWIND_INFO v3: WOD is outside payload")
    first = pool[offset]
    low3 = first & 0x07
    if low3 in (4, 7):
        if low3 == 7 and first >> 3 == 31:
            raise ValueError(
                "malformed UNWIND_INFO v3: consecutive push overflows register")
        return 1
    if low3 == 5:
        return 5
    if low3 == 6:
        return 3
    low4 = first & 0x0F
    if low4 == 8:
        return 1
    if low4 == 9:
        return 5
    if low4 == 10:
        return 3
    if first & 0x3F == 0x20:
        return 2
    return {0x00: 2, 0x01: 5, 0x02: 3, 0x03: 2}.get(first, 0)


def _validate_v3_wods(pool: bytes, first_op: int, count: int) -> None:
    cursor = first_op
    for _ in range(count):
        size = _v3_wod_size(pool, cursor)
        if size == 0:
            raise ValueError("malformed UNWIND_INFO v3: invalid WOD opcode")
        if cursor + size > len(pool):
            raise ValueError("malformed UNWIND_INFO v3: truncated WOD")
        cursor += size


def _validate_v3_payload(payload: bytes, header: bytes,
                         function_size: int) -> None:
    flags = header[0] >> 3
    prolog_size = header[1]
    prolog_ops = header[3] & 0x1F
    epilog_count = header[3] >> 5
    cursor = 0

    large_prolog = bool(flags & _UNW_FLAG_LARGE_V3)
    if large_prolog:
        if not payload or payload[0] == 0:
            raise ValueError(
                "malformed UNWIND_INFO v3: invalid large-prolog extension")
        prolog_size |= payload[0] << 8
        cursor = 1

    prolog_width = 2 if large_prolog else 1
    prolog_offsets_size = prolog_ops * prolog_width
    if cursor + prolog_offsets_size > len(payload):
        raise ValueError(
            "malformed UNWIND_INFO v3: truncated prolog offsets")
    prolog_offsets = [
        int.from_bytes(payload[cursor + i * prolog_width:
                               cursor + (i + 1) * prolog_width], "little")
        for i in range(prolog_ops)
    ]
    if (any(offset > prolog_size for offset in prolog_offsets) or
            any(left < right for left, right in
                zip(prolog_offsets, prolog_offsets[1:]))):
        raise ValueError(
            "malformed UNWIND_INFO v3: invalid prolog offset ordering")
    cursor += prolog_offsets_size

    epilog_wods = []
    previous_full = None
    direction = 0
    epilog_position = 0
    for _ in range(epilog_count):
        if cursor + 3 > len(payload):
            raise ValueError(
                "malformed UNWIND_INFO v3: truncated epilog descriptor")
        descriptor = payload[cursor]
        epilog_flags = descriptor & 0x07
        epilog_ops = descriptor >> 3
        epilog_delta, = struct.unpack_from("<h", payload, cursor + 1)
        cursor += 3
        if epilog_flags & 0x04 or epilog_delta == 0:
            raise ValueError(
                "malformed UNWIND_INFO v3: invalid epilog flags or offset")
        this_direction = 1 if epilog_delta > 0 else -1
        if direction and direction != this_direction:
            raise ValueError(
                "malformed UNWIND_INFO v3: mixed epilog ordering")
        direction = this_direction
        if len(epilog_wods) == 0:
            epilog_position = (epilog_delta if epilog_delta > 0
                               else function_size + epilog_delta)
        else:
            epilog_position += epilog_delta
        if not (0 <= epilog_position < function_size):
            raise ValueError(
                "malformed UNWIND_INFO v3: epilog is outside function")

        if epilog_ops == 0:
            if previous_full is None or ((previous_full[2] ^ epilog_flags) & 3):
                raise ValueError(
                    "malformed UNWIND_INFO v3: invalid inherited epilog")
            epilog_wods.append(previous_full[:2])
            continue

        large_epilog = bool(epilog_flags & 0x02)
        extended_size = 4 if large_epilog else 3
        offsets_size = epilog_ops * (2 if large_epilog else 1)
        if cursor + extended_size + offsets_size > len(payload):
            raise ValueError(
                "malformed UNWIND_INFO v3: truncated epilog offsets")
        first_op, = struct.unpack_from("<H", payload, cursor)
        if large_epilog:
            last_ip, = struct.unpack_from("<H", payload, cursor + 2)
        else:
            last_ip = payload[cursor + 2]
        ip_width = 2 if large_epilog else 1
        ip_start = cursor + extended_size
        ip_offsets = [
            int.from_bytes(payload[ip_start + i * ip_width:
                                   ip_start + (i + 1) * ip_width], "little")
            for i in range(epilog_ops)
        ]
        if (any(offset > last_ip for offset in ip_offsets) or
                any(left > right for left, right in
                    zip(ip_offsets, ip_offsets[1:]))):
            raise ValueError(
                "malformed UNWIND_INFO v3: invalid epilog offset ordering")
        cursor += extended_size + offsets_size
        previous_full = (first_op, epilog_ops, epilog_flags)
        epilog_wods.append(previous_full[:2])

    pool = payload[cursor:]
    _validate_v3_wods(pool, 0, prolog_ops)
    for first_op, count in epilog_wods:
        _validate_v3_wods(pool, first_op, count)


def _validate_runtime_function(begin: int, end: int, unwind_rva: int,
                               image_size: int,
                               sections: List[ParsedSection],
                               active_unwind: set[int]) -> int:
    if not (0 < begin < end <= image_size):
        raise ValueError("malformed RUNTIME_FUNCTION: invalid function range")
    if unwind_rva == 0 or unwind_rva & 3:
        raise ValueError("malformed RUNTIME_FUNCTION: unaligned unwind RVA")
    if unwind_rva in active_unwind:
        raise ValueError("malformed UNWIND_INFO: chained unwind cycle")

    header = _unwind_bytes(
        sections, unwind_rva, 4, image_size, "UNWIND_INFO header")
    version, flags = header[0] & 7, header[0] >> 3
    if version not in (1, 2, 3):
        raise ValueError(
            f"malformed UNWIND_INFO: unsupported version {version}")
    allowed_flags = (0x0F if version == 3 else 0x07)
    if flags & ~allowed_flags:
        raise ValueError("malformed UNWIND_INFO: reserved flags are set")
    if ((flags & _UNW_FLAG_CHAININFO) and
            (flags & (_UNW_FLAG_EHANDLER | _UNW_FLAG_UHANDLER))):
        raise ValueError(
            "malformed UNWIND_INFO: CHAININFO cannot carry a handler")

    active_unwind.add(unwind_rva)
    try:
        if version in (1, 2):
            count = header[2]
            frame_register, frame_offset = header[3] & 0x0F, header[3] >> 4
            if frame_register == 0 and frame_offset != 0:
                raise ValueError(
                    "malformed UNWIND_INFO: frame offset without frame register")
            padded_count = (count + 1) & ~1
            codes = _unwind_bytes(
                sections, unwind_rva + 4, padded_count * 2, image_size,
                "UNWIND_INFO codes")[:count * 2] if padded_count else b""
            _validate_classic_unwind_codes(
                version, codes, header[1], frame_register)
            tail_rva = unwind_rva + 4 + padded_count * 2
        else:
            payload_size = header[2] * 2
            payload = (_unwind_bytes(
                sections, unwind_rva + 4, payload_size, image_size,
                "UNWIND_INFO v3 payload") if payload_size else b"")
            _validate_v3_payload(payload, header, end - begin)
            tail_rva = (unwind_rva + 4 + payload_size + 3) & ~3

        if flags & _UNW_FLAG_CHAININFO:
            chain = _unwind_bytes(
                sections, tail_rva, _RUNTIME_FUNCTION_SIZE, image_size,
                "chained RUNTIME_FUNCTION")
            chain_begin, chain_end, chain_unwind = struct.unpack("<III", chain)
            _validate_runtime_function(
                chain_begin, chain_end, chain_unwind, image_size,
                sections, active_unwind)
        elif flags & (_UNW_FLAG_EHANDLER | _UNW_FLAG_UHANDLER):
            handler_bytes = _unwind_bytes(
                sections, tail_rva, 4, image_size, "unwind handler RVA")
            handler_rva, = struct.unpack("<I", handler_bytes)
            _unwind_bytes(
                sections, handler_rva, 1, image_size, "unwind handler target")
    finally:
        active_unwind.remove(unwind_rva)
    return flags


def _parse_pdata(blob: bytes, pdata_rva: int, image_size: int,
                 sections: Optional[List[ParsedSection]] = None
                 ) -> tuple[ParsedRuntimeFunction, ...]:
    if len(blob) % _RUNTIME_FUNCTION_SIZE:
        raise ValueError(
            "malformed x64 exception table: size is not a multiple of "
            f"{_RUNTIME_FUNCTION_SIZE}")
    if blob and (pdata_rva <= 0 or pdata_rva & 3):
        raise ValueError("malformed x64 exception table: unaligned directory RVA")
    previous_end = 0
    runtime_functions = []
    for offset in range(0, len(blob), _RUNTIME_FUNCTION_SIZE):
        begin, end, unwind = struct.unpack_from("<III", blob, offset)
        if not (0 < begin < end <= image_size) or not (0 < unwind < image_size):
            raise ValueError(
                f"malformed RUNTIME_FUNCTION at RVA 0x{pdata_rva + offset:X}")
        if begin < previous_end:
            raise ValueError(
                "malformed x64 exception table: entries are unsorted or overlap")
        if unwind & 3:
            raise ValueError(
                f"malformed RUNTIME_FUNCTION at RVA 0x{pdata_rva + offset:X}: "
                "unaligned unwind RVA")
        unwind_flags = (_validate_runtime_function(
            begin, end, unwind, image_size, sections, set())
            if sections is not None else 0)
        runtime_functions.append(ParsedRuntimeFunction(
            begin_rva=begin,
            end_rva=end,
            unwind_info_rva=unwind,
            unwind_flags=unwind_flags,
        ))
        previous_end = end
    return tuple(runtime_functions)


def _validate_pdata(blob: bytes, pdata_rva: int, image_size: int,
                    sections: Optional[List[ParsedSection]] = None) -> int:
    return len(_parse_pdata(blob, pdata_rva, image_size, sections))


def _validate_aslr_contract(file_characteristics: int,
                            dll_characteristics: int,
                            reloc_blob: bytes) -> None:
    stripped = bool(file_characteristics & _IMAGE_FILE_RELOCS_STRIPPED)
    dynamic = bool(
        dll_characteristics & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    if stripped and reloc_blob:
        raise ValueError(
            "malformed ASLR contract: IMAGE_FILE_RELOCS_STRIPPED is set "
            "but a base relocation directory is present")
    if dynamic and not reloc_blob:
        raise ValueError(
            "malformed ASLR contract: DYNAMIC_BASE is set but no base "
            "relocation directory is present")


def _iat_slot_rva(imp, entry, index: int, image_base: int) -> int:
    """RVA of the IAT slot where the loader writes the resolved address.

    Primary: ``FirstThunk (import_address_table_rva) + index * 8``. This is the
    PE-spec-exact location and is unambiguously an RVA -- LIEF walks entries in
    IAT order, so entry ``index`` occupies slot ``index``. Fallback (only if
    FirstThunk is 0, which does not happen for a valid import): ``iat_address``,
    which LIEF 1.0.0 already exposes as an RVA (verified); older builds may hand
    back a VA, so subtract ``image_base`` when the value looks absolute.
    """
    iat_base = _i(getattr(imp, "import_address_table_rva", 0))
    if iat_base:
        return iat_base + index * _PTR_SIZE
    addr = _i(getattr(entry, "iat_address", 0))
    if addr:
        return addr - image_base if (image_base and addr >= image_base) else addr
    return _i(getattr(entry, "data", 0))  # pragma: no cover - degenerate PE


def _extract_imports(binary, image_base: int) -> List[ImportDll]:
    dlls: List[ImportDll] = []
    for imp in getattr(binary, "imports", []) or []:
        funcs: List[ImportFunc] = []
        for index, entry in enumerate(imp.entries):
            iat_rva = _iat_slot_rva(imp, entry, index, image_base)
            if entry.is_ordinal:
                funcs.append(ImportFunc(
                    iat_rva=iat_rva, by_ordinal=True, ordinal=_i(entry.ordinal)))
            else:
                funcs.append(ImportFunc(
                    iat_rva=iat_rva, by_ordinal=False, name=entry.name or ""))
        dlls.append(ImportDll(name=imp.name, funcs=funcs))
    return dlls


def _extract_tls(binary, image_base: int) -> Optional[TlsInfo]:
    if not getattr(binary, "has_tls", False):
        return None
    tls = binary.tls
    if tls is None:  # pragma: no cover - defensive
        return None
    raw = tls.addressof_raw_data  # tuple (start_va, end_va), absolute VAs
    try:
        raw_start, raw_end = _i(raw[0]), _i(raw[1])
    except (TypeError, IndexError):  # pragma: no cover - API drift
        raw_start = raw_end = 0

    def to_rva(va: int) -> int:
        va = _i(va)
        return va - image_base if va >= image_base else va

    callbacks = [to_rva(cb) for cb in (tls.callbacks or [])]
    characteristics = _i(tls.characteristics)
    if characteristics & ~0x00F00000:
        raise ValueError("malformed TLS directory: reserved Characteristics bits set")
    alignment_code = (characteristics >> 20) & 0xF
    if alignment_code == 0xF:
        raise ValueError("malformed TLS directory: reserved alignment code 15")
    return TlsInfo(
        index_rva=to_rva(tls.addressof_index),
        callback_rvas=callbacks,
        raw_start_rva=to_rva(raw_start) if raw_start else 0,
        raw_end_rva=to_rva(raw_end) if raw_end else 0,
        zero_fill=_i(tls.sizeof_zero_fill),
        characteristics=characteristics,
    )


def _load_config_field(
    blob: bytes,
    declared_size: int,
    offset: int,
    fmt: str,
    name: str,
):
    width = struct.calcsize(fmt)
    if declared_size <= offset:
        return 0
    if declared_size < offset + width:
        raise ValueError(
            f"malformed load-config directory: declared size 0x{declared_size:X} "
            f"truncates {name} at offset 0x{offset:X}")
    return struct.unpack_from(fmt, blob, offset)[0]


def _load_config_va_to_rva(
    va: int,
    *,
    image_base: int,
    image_size: int,
    sections: List[ParsedSection],
    name: str,
    width: int = 1,
    alignment: int = 1,
) -> int:
    if va == 0:
        return 0
    image_end = image_base + image_size
    if image_end > 0x1_0000_0000_0000_0000 or not image_base <= va < image_end:
        raise ValueError(
            f"malformed load-config {name}: VA 0x{va:X} is outside the image")
    rva = va - image_base
    if rva % alignment:
        raise ValueError(
            f"malformed load-config {name}: RVA 0x{rva:X} is not "
            f"{alignment}-byte aligned")
    _slice_at_rva(sections, rva, width, what=f"load-config {name}")
    return rva


def _guard_table_pair(
    table_va: int,
    count: int,
    *,
    image_base: int,
    image_size: int,
    sections: List[ParsedSection],
    name: str,
    stride: int,
) -> tuple[int, bytes]:
    if bool(table_va) != bool(count):
        raise ValueError(
            f"malformed load-config {name}: table VA and count presence disagree")
    if not table_va:
        return 0, b""
    if count > image_size // stride:
        raise ValueError(
            f"malformed load-config {name}: target count is outside image bounds")
    table_rva = _load_config_va_to_rva(
        table_va,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name=f"{name} table",
        width=count * stride,
        alignment=4,
    )
    return table_rva, _slice_at_rva(
        sections,
        table_rva,
        count * stride,
        what=f"load-config {name} table",
    )


def _validate_guard_code_target(
    rva: int,
    *,
    image_size: int,
    sections: List[ParsedSection],
    name: str,
    alignment: int = 1,
) -> None:
    if not 0 < rva < image_size:
        raise ValueError(
            f"malformed load-config {name}: target RVA 0x{rva:X} is outside image")
    if rva % alignment:
        raise ValueError(
            f"malformed load-config {name}: target RVA 0x{rva:X} is not "
            f"{alignment}-byte aligned")
    owner = next(
        (section for section in sections
         if section.rva <= rva
         < section.rva + max(section.virtual_size, len(section.raw))),
        None,
    )
    if owner is None or not owner.characteristics & _IMAGE_SCN_MEM_EXECUTE:
        raise ValueError(
            f"malformed load-config {name}: target RVA 0x{rva:X} is not "
            "in an executable section")
    _slice_at_rva(sections, rva, 1, what=f"load-config {name} target")


def _parse_guard_rva_table(
    table_va: int,
    count: int,
    *,
    image_base: int,
    image_size: int,
    sections: List[ParsedSection],
    name: str,
    target_kind: str,
    stride: int,
) -> tuple[int, tuple[ParsedGuardTarget, ...]]:
    table_rva, table = _guard_table_pair(
        table_va,
        count,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name=name,
        stride=stride,
    )
    targets = tuple(
        ParsedGuardTarget(
            struct.unpack_from("<I", table, offset)[0],
            bytes(table[offset + 4:offset + stride]),
        )
        for offset in range(0, len(table), stride)
    )
    rvas = tuple(target.rva for target in targets)
    if tuple(sorted(set(rvas))) != rvas:
        raise ValueError(
            f"malformed load-config {name}: targets must be strictly sorted")
    for target in targets:
        if target_kind == "iat":
            if not 0 < target.rva <= image_size - 8 or target.rva % 8:
                raise ValueError(
                    f"malformed load-config {name}: IAT RVA 0x{target.rva:X} "
                    "must be an in-image 8-byte-aligned slot")
            _slice_at_rva(
                sections, target.rva, 8, what=f"load-config {name} IAT slot")
        else:
            _validate_guard_code_target(
                target.rva,
                image_size=image_size,
                sections=sections,
                name=name,
            )
    return table_rva, targets


def _parse_volatile_metadata(
    rva: int,
    *,
    image_size: int,
    sections: List[ParsedSection],
) -> Optional[ParsedVolatileMetadata]:
    """Parse the documented 24-byte volatile-metadata header and tables.

    Unlike load-config pointers, the two table locators inside this structure
    are RVAs.  The access table is an array of instruction RVAs and the range
    table is an array of ``(start_rva, size)`` pairs.  Both describe executable
    bytes and are consumed by the Windows loader before Lethe's entry point.
    """
    if not rva:
        return None
    header = _slice_at_rva(
        sections, rva, 24, what="load-config volatile metadata")
    (size, minimum_version, maximum_version, access_rva, access_size,
     ranges_rva, ranges_size) = struct.unpack("<IHHIIII", header)
    if size != 24:
        raise ValueError(
            f"unsupported volatile metadata size 0x{size:X}; expected 0x18")
    if minimum_version > maximum_version:
        raise ValueError("malformed volatile metadata: version range is inverted")
    if bool(access_rva) != bool(access_size):
        raise ValueError(
            "malformed volatile metadata: access table RVA and size presence disagree")
    if bool(ranges_rva) != bool(ranges_size):
        raise ValueError(
            "malformed volatile metadata: range table RVA and size presence disagree")
    if access_size % 4:
        raise ValueError(
            "malformed volatile metadata: access table size is not a multiple of 4")
    if ranges_size % 8:
        raise ValueError(
            "malformed volatile metadata: range table size is not a multiple of 8")

    access_blob = (
        _slice_at_rva(
            sections, access_rva, access_size,
            what="load-config volatile access table")
        if access_size else b""
    )
    range_blob = (
        _slice_at_rva(
            sections, ranges_rva, ranges_size,
            what="load-config volatile range table")
        if ranges_size else b""
    )
    access_rvas = tuple(
        struct.unpack_from("<I", access_blob, offset)[0]
        for offset in range(0, len(access_blob), 4)
    )
    if tuple(sorted(set(access_rvas))) != access_rvas:
        raise ValueError(
            "malformed volatile metadata: access RVAs must be strictly sorted")
    for target in access_rvas:
        _validate_guard_code_target(
            target,
            image_size=image_size,
            sections=sections,
            name="VolatileAccessRvaTable",
        )

    info_ranges = tuple(
        struct.unpack_from("<II", range_blob, offset)
        for offset in range(0, len(range_blob), 8)
    )
    previous_end = 0
    for start, span in info_ranges:
        end = start + span
        if span == 0 or end > image_size or end > 0x1_0000_0000:
            raise ValueError(
                "malformed volatile metadata: range is outside the image")
        if start < previous_end:
            raise ValueError(
                "malformed volatile metadata: ranges overlap or are unsorted")
        owner = next(
            (section for section in sections
             if section.rva <= start
             and end <= section.rva + max(section.virtual_size, len(section.raw))),
            None,
        )
        if owner is None or not owner.characteristics & _IMAGE_SCN_MEM_EXECUTE:
            raise ValueError(
                "malformed volatile metadata: range is not contained by one "
                "executable section")
        previous_end = end

    return ParsedVolatileMetadata(
        rva=rva,
        minimum_version=minimum_version,
        maximum_version=maximum_version,
        access_rvas=access_rvas,
        info_ranges=info_ranges,
        raw=header,
    )


def _parse_load_config(
    blob: bytes,
    directory_rva: int,
    *,
    image_base: int,
    image_size: int,
    sections: List[ParsedSection],
) -> Optional[ParsedLoadConfig]:
    """Parse one exact IMAGE_LOAD_CONFIG_DIRECTORY64 and Guard inventories."""

    if not blob:
        if directory_rva:
            raise ValueError(
                "malformed load-config directory: nonzero RVA with empty data")
        return None
    if directory_rva <= 0 or len(blob) < 4:
        raise ValueError("malformed load-config directory: missing header")
    if directory_rva % 8:
        raise ValueError(
            "malformed load-config directory: RVA must be 8-byte aligned")
    declared_size, = struct.unpack_from("<I", blob, 0)
    if declared_size != len(blob):
        raise ValueError(
            "malformed load-config directory: data-directory size and declared "
            f"size disagree (0x{len(blob):X} != 0x{declared_size:X})")
    if (declared_size < _LOAD_CONFIG64_MIN_SIZE
            or declared_size > _LOAD_CONFIG64_MAX_SIZE
            or declared_size % 4):
        raise ValueError(
            f"unsupported load-config directory size 0x{declared_size:X}; "
            f"supported PE32+ bounds are 0x{_LOAD_CONFIG64_MIN_SIZE:X}.."
            f"0x{_LOAD_CONFIG64_MAX_SIZE:X} on a 4-byte boundary")

    major_version = _load_config_field(
        blob, declared_size, 8, "<H", "MajorVersion")
    minor_version = _load_config_field(
        blob, declared_size, 10, "<H", "MinorVersion")
    security_cookie_va = _load_config_field(
        blob, declared_size, 88, "<Q", "SecurityCookie")
    check_va = _load_config_field(
        blob, declared_size, 112, "<Q", "GuardCFCheckFunctionPointer")
    dispatch_va = _load_config_field(
        blob, declared_size, 120, "<Q", "GuardCFDispatchFunctionPointer")
    cf_table_va = _load_config_field(
        blob, declared_size, 128, "<Q", "GuardCFFunctionTable")
    cf_count = _load_config_field(
        blob, declared_size, 136, "<Q", "GuardCFFunctionCount")
    guard_flags = _load_config_field(
        blob, declared_size, 144, "<I", "GuardFlags")
    for flag, minimum_size, name in (
        (_GUARD_CASTGUARD_PRESENT, 312, "IMAGE_GUARD_CASTGUARD_PRESENT"),
        (_GUARD_MEMCPY_PRESENT, 320, "IMAGE_GUARD_MEMCPY_PRESENT"),
    ):
        if guard_flags & flag and declared_size < minimum_size:
            raise ValueError(
                "malformed load-config directory: "
                f"{name} requires declared size at least 0x{minimum_size:X}"
            )
    code_integrity = bytes(blob[148:160]) if declared_size >= 160 else b""
    if 148 < declared_size < 160:
        raise ValueError(
            "malformed load-config directory: declared size truncates CodeIntegrity")

    address_iat_va = _load_config_field(
        blob, declared_size, 160, "<Q", "GuardAddressTakenIatEntryTable")
    address_iat_count = _load_config_field(
        blob, declared_size, 168, "<Q", "GuardAddressTakenIatEntryCount")
    long_jump_va = _load_config_field(
        blob, declared_size, 176, "<Q", "GuardLongJumpTargetTable")
    long_jump_count = _load_config_field(
        blob, declared_size, 184, "<Q", "GuardLongJumpTargetCount")
    dynamic_reloc_va = _load_config_field(
        blob, declared_size, 192, "<Q", "DynamicValueRelocTable")
    chpe_va = _load_config_field(
        blob, declared_size, 200, "<Q", "CHPEMetadataPointer")
    rf_failure_va = _load_config_field(
        blob, declared_size, 208, "<Q", "GuardRFFailureRoutine")
    rf_failure_pointer_va = _load_config_field(
        blob, declared_size, 216, "<Q", "GuardRFFailureRoutineFunctionPointer")
    dynamic_reloc_offset = _load_config_field(
        blob, declared_size, 224, "<I", "DynamicValueRelocTableOffset")
    dynamic_reloc_section = _load_config_field(
        blob, declared_size, 228, "<H", "DynamicValueRelocTableSection")
    reserved2 = _load_config_field(
        blob, declared_size, 230, "<H", "Reserved2")
    rf_verify_pointer_va = _load_config_field(
        blob, declared_size, 232, "<Q", "GuardRFVerifyStackPointerFunctionPointer")
    hotpatch_offset = _load_config_field(
        blob, declared_size, 240, "<I", "HotPatchTableOffset")
    reserved3 = _load_config_field(
        blob, declared_size, 244, "<I", "Reserved3")
    enclave_va = _load_config_field(
        blob, declared_size, 248, "<Q", "EnclaveConfigurationPointer")
    volatile_va = _load_config_field(
        blob, declared_size, 256, "<Q", "VolatileMetadataPointer")
    eh_table_va = _load_config_field(
        blob, declared_size, 264, "<Q", "GuardEHContinuationTable")
    eh_count = _load_config_field(
        blob, declared_size, 272, "<Q", "GuardEHContinuationCount")
    xfg_check_va = _load_config_field(
        blob, declared_size, 280, "<Q", "GuardXFGCheckFunctionPointer")
    xfg_dispatch_va = _load_config_field(
        blob, declared_size, 288, "<Q", "GuardXFGDispatchFunctionPointer")
    xfg_table_dispatch_va = _load_config_field(
        blob, declared_size, 296, "<Q", "GuardXFGTableDispatchFunctionPointer")
    cast_guard_va = _load_config_field(
        blob, declared_size, 304, "<Q", "CastGuardOsDeterminedFailureMode")
    guard_memcpy_va = _load_config_field(
        blob, declared_size, 312, "<Q", "GuardMemcpyFunctionPointer")
    uma_va = _load_config_field(
        blob, declared_size, 320, "<Q", "UmaFunctionPointers")

    if reserved2 or reserved3:
        raise ValueError("malformed load-config directory: reserved fields are nonzero")
    unknown_flags = guard_flags & ~_KNOWN_GUARD_FLAGS
    if unknown_flags:
        raise ValueError(
            f"unsupported load-config GuardFlags bits 0x{unknown_flags:X}")

    security_cookie_rva = _load_config_va_to_rva(
        security_cookie_va,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="SecurityCookie",
        width=8,
        alignment=8,
    ) if security_cookie_va else 0
    check_rva = _load_config_va_to_rva(
        check_va,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="GuardCFCheckFunctionPointer",
        width=8,
        alignment=8,
    ) if check_va else 0
    dispatch_rva = _load_config_va_to_rva(
        dispatch_va,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="GuardCFDispatchFunctionPointer",
        width=8,
        alignment=8,
    ) if dispatch_va else 0

    if guard_flags & _GUARD_CF_FUNCTION_TABLE_SIZE_MASK:
        extra_size = (
            guard_flags & _GUARD_CF_FUNCTION_TABLE_SIZE_MASK
        ) >> _GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT
    else:
        extra_size = 0
    cf_stride = 4 + extra_size
    cf_table_rva, cf_table = _guard_table_pair(
        cf_table_va,
        cf_count,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="GuardCFFunctionTable",
        stride=cf_stride,
    )
    cf_targets = tuple(
        ParsedGuardTarget(
            struct.unpack_from("<I", cf_table, offset)[0],
            bytes(cf_table[offset + 4:offset + cf_stride]),
        )
        for offset in range(0, len(cf_table), cf_stride)
    )
    cf_rvas = tuple(target.rva for target in cf_targets)
    if tuple(sorted(set(cf_rvas))) != cf_rvas:
        raise ValueError(
            "malformed load-config GuardCFFunctionTable: targets must be "
            "strictly sorted")
    for target in cf_targets:
        _validate_guard_code_target(
            target.rva,
            image_size=image_size,
            sections=sections,
            name="GuardCFFunctionTable",
            alignment=16,
        )
    if cf_targets and not guard_flags & _GUARD_CF_FUNCTION_TABLE_PRESENT:
        raise ValueError(
            "malformed load-config: GuardCFFunctionTable is populated without "
            "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT")
    if extra_size > 1:
        raise ValueError(
            "unsupported Guard CF function-table metadata width "
            f"{extra_size}; Windows currently defines at most one flag byte")
    for target in cf_targets:
        if target.metadata and target.metadata[0] & ~0x0B:
            raise ValueError(
                f"unsupported Guard CF target metadata flags "
                f"0x{target.metadata[0]:02X} at RVA 0x{target.rva:X}")

    address_iat_rva, address_iat_targets = _parse_guard_rva_table(
        address_iat_va,
        address_iat_count,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="GuardAddressTakenIatEntryTable",
        target_kind="iat",
        stride=cf_stride,
    )
    long_jump_rva, long_jump_targets = _parse_guard_rva_table(
        long_jump_va,
        long_jump_count,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="GuardLongJumpTargetTable",
        target_kind="code",
        stride=cf_stride,
    )
    if long_jump_targets and not guard_flags & _GUARD_CF_LONGJUMP_TABLE_PRESENT:
        raise ValueError(
            "malformed load-config: long-jump targets exist without the "
            "GuardFlags presence bit")
    eh_table_rva, eh_targets = _parse_guard_rva_table(
        eh_table_va,
        eh_count,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="GuardEHContinuationTable",
        target_kind="code",
        stride=cf_stride,
    )
    if eh_targets and not guard_flags & _GUARD_EH_CONTINUATION_TABLE_PRESENT:
        raise ValueError(
            "malformed load-config: EH continuation targets exist without the "
            "GuardFlags presence bit")

    xfg_check_rva = _load_config_va_to_rva(
        xfg_check_va,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="GuardXFGCheckFunctionPointer",
        width=8,
        alignment=8,
    ) if xfg_check_va else 0
    xfg_dispatch_rva = _load_config_va_to_rva(
        xfg_dispatch_va,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="GuardXFGDispatchFunctionPointer",
        width=8,
        alignment=8,
    ) if xfg_dispatch_va else 0
    xfg_table_dispatch_rva = _load_config_va_to_rva(
        xfg_table_dispatch_va,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="GuardXFGTableDispatchFunctionPointer",
        width=8,
        alignment=8,
    ) if xfg_table_dispatch_va else 0
    cast_guard_rva = _load_config_va_to_rva(
        cast_guard_va,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="CastGuardOsDeterminedFailureMode",
        width=8,
        alignment=8,
    ) if cast_guard_va else 0
    guard_memcpy_rva = _load_config_va_to_rva(
        guard_memcpy_va,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="GuardMemcpyFunctionPointer",
        width=8,
        alignment=8,
    ) if guard_memcpy_va else 0
    volatile_rva = _load_config_va_to_rva(
        volatile_va,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
        name="VolatileMetadataPointer",
        width=24,
        alignment=4,
    ) if volatile_va else 0
    volatile_metadata = _parse_volatile_metadata(
        volatile_rva,
        image_size=image_size,
        sections=sections,
    )

    unsupported = set()
    dynamic_present = bool(
        dynamic_reloc_va or dynamic_reloc_offset or dynamic_reloc_section)
    if dynamic_present:
        unsupported.add("dynamic_value_relocations")
    chpe_present = bool(chpe_va)
    if chpe_present:
        unsupported.add("chpe_metadata")
    xfg_present = bool(
        guard_flags & _GUARD_XFG_ENABLED
        or xfg_check_va or xfg_dispatch_va or xfg_table_dispatch_va
        or any(target.metadata and target.metadata[0] & 0x08
               for target in cf_targets)
    )
    if code_integrity and any(code_integrity):
        unsupported.add("code_integrity")
    if (guard_flags & (_GUARD_RF_INSTRUMENTED | _GUARD_RF_ENABLE | _GUARD_RF_STRICT)
            or rf_failure_va or rf_failure_pointer_va or rf_verify_pointer_va):
        unsupported.add("return_flow_guard")
    if hotpatch_offset:
        unsupported.add("hotpatch")
    if enclave_va:
        unsupported.add("enclave_configuration")
    if uma_va:
        unsupported.add("uma_function_pointers")

    for name, va in (
        ("DynamicValueRelocTable", dynamic_reloc_va),
        ("CHPEMetadataPointer", chpe_va),
        ("GuardRFFailureRoutine", rf_failure_va),
        ("GuardRFFailureRoutineFunctionPointer", rf_failure_pointer_va),
        ("GuardRFVerifyStackPointerFunctionPointer", rf_verify_pointer_va),
        ("EnclaveConfigurationPointer", enclave_va),
        ("UmaFunctionPointers", uma_va),
    ):
        if va:
            _load_config_va_to_rva(
                va,
                image_base=image_base,
                image_size=image_size,
                sections=sections,
                name=name,
                width=1,
            )

    return ParsedLoadConfig(
        directory_rva=directory_rva,
        directory_size=len(blob),
        declared_size=declared_size,
        major_version=major_version,
        minor_version=minor_version,
        guard_flags=guard_flags,
        security_cookie_rva=security_cookie_rva,
        guard_cf_check_function_pointer_rva=check_rva,
        guard_cf_dispatch_function_pointer_rva=dispatch_rva,
        guard_cf_function_table_rva=cf_table_rva,
        guard_cf_targets=cf_targets,
        guard_address_taken_iat_entry_table_rva=address_iat_rva,
        guard_address_taken_iat_entries=address_iat_targets,
        guard_long_jump_target_table_rva=long_jump_rva,
        guard_long_jump_targets=long_jump_targets,
        guard_eh_continuation_table_rva=eh_table_rva,
        guard_eh_continuation_targets=eh_targets,
        dynamic_value_relocations_present=dynamic_present,
        chpe_metadata_present=chpe_present,
        xfg_present=xfg_present,
        unsupported_features=tuple(sorted(unsupported)),
        raw=bytes(blob),
        volatile_metadata=volatile_metadata,
        guard_xfg_check_function_pointer_rva=xfg_check_rva,
        guard_xfg_dispatch_function_pointer_rva=xfg_dispatch_rva,
        guard_xfg_table_dispatch_function_pointer_rva=xfg_table_dispatch_rva,
        cast_guard_os_determined_failure_mode_rva=cast_guard_rva,
        guard_memcpy_function_pointer_rva=guard_memcpy_rva,
    )


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------


def analyze_pe(path: str) -> ParsedPE:
    """Parse ``path`` as an x64 PE and return a :class:`ParsedPE`.

    Raises :class:`PEArchError` (a ``ValueError``) for non-PE input or for x86 /
    ARM binaries; :class:`ValueError` if LIEF cannot parse the file.
    """
    binary = lief.parse(path)
    if binary is None:
        raise ValueError(f"LIEF could not parse {path!r} as a PE file")
    if not isinstance(binary, lief.PE.Binary):
        raise PEArchError(
            f"{path!r} is not a PE binary (got {type(binary).__name__}); "
            "Lethe packs x64 Windows PE files only")

    opt = binary.optional_header
    magic = _i(opt.magic)
    machine = _i(binary.header.machine)
    if magic != _PE32_PLUS:
        raise PEArchError(
            f"{path!r} is PE32 (x86), not PE32+ (x64) -- magic=0x{magic:X}. "
            "Lethe supports x64 only.")
    if machine != _MACHINE_AMD64:
        raise PEArchError(
            f"{path!r} targets machine 0x{machine:X}, not AMD64 (0x8664). "
            "Lethe supports x64 only (x86/ARM/ARM64 unsupported).")

    # Managed/.NET refusal: a CLR runtime header means the "real" entry point is
    # the .NET runtime, not native code. Packing it the native way (mapping +
    # native OEP transfer) silently breaks it. Fail closed rather than ship a
    # broken pack -- functionality is paramount.
    clr_rva, clr_size = _data_dir(binary, "CLR_RUNTIME_HEADER")
    if clr_rva or clr_size:
        raise PEArchError(
            f"{path!r} is a managed/.NET assembly (CLR runtime header at "
            f"rva=0x{clr_rva:X}); Lethe packs NATIVE x64 PEs only. Packing a "
            "managed binary the native way would silently break it -- refused.")

    image_base = _i(opt.imagebase)
    image_size = _i(opt.sizeof_image)
    section_alignment = _i(opt.section_alignment)
    file_characteristics = _i(binary.header.characteristics)
    dll_characteristics = _i(opt.dll_characteristics)
    subsystem = _i(opt.subsystem)
    _validate_user_mode_contract(
        file_characteristics, dll_characteristics, subsystem)
    is_dll = bool(file_characteristics & _IMAGE_FILE_DLL)

    sections: List[ParsedSection] = []
    for sec in binary.sections:
        sections.append(ParsedSection(
            name=sec.name,
            rva=_i(sec.virtual_address),
            virtual_size=_i(sec.virtual_size),
            raw=bytes(sec.content),
            characteristics=_i(sec.characteristics),
        ))
    _validate_sections(sections, image_size, section_alignment)

    imports = _extract_imports(binary, image_base)

    delay_import_rva, delay_import_size = _data_dir(
        binary, "DELAY_IMPORT_DESCRIPTOR")
    _validate_directory_range(
        "delay-import", delay_import_rva, delay_import_size, image_size)
    delay_import_blob = _slice_at_rva(
        sections, delay_import_rva, delay_import_size,
        what="delay-import directory")
    _validate_delay_import_directory(
        delay_import_blob, image_size=image_size, sections=sections)

    reloc_rva, reloc_size = _data_dir(binary, "BASE_RELOCATION_TABLE")
    _validate_directory_range(
        "base relocation", reloc_rva, reloc_size, image_size)
    reloc_blob = _slice_at_rva(
        sections, reloc_rva, reloc_size, what="base relocation directory")
    dir64_relocations = _validate_relocations(
        reloc_blob, image_size, sections)
    _validate_aslr_contract(
        file_characteristics, dll_characteristics, reloc_blob)

    pdata_rva, pdata_size = _data_dir(binary, "EXCEPTION_TABLE")
    _validate_directory_range(
        "exception", pdata_rva, pdata_size, image_size)
    pdata_blob = _slice_at_rva(
        sections, pdata_rva, pdata_size, what="exception directory")
    runtime_functions = _parse_pdata(
        pdata_blob, pdata_rva, image_size, sections)
    pdata_count = len(runtime_functions)

    rsrc_directory_rva, rsrc_directory_size = _data_dir(
        binary, "RESOURCE_TABLE")
    _validate_directory_range(
        "resource", rsrc_directory_rva, rsrc_directory_size, image_size)
    _slice_at_rva(
        sections, rsrc_directory_rva, rsrc_directory_size,
        what="resource directory")
    rsrc_rva = 0
    rsrc_bytes = b""
    if rsrc_directory_rva:
        # Preserve the whole .rsrc section verbatim at its original RVA so any
        # internal resource RVAs stay valid. Keep the exact DataDirectory
        # geometry separately: a valid resource root need not begin at the
        # owning section's first byte.
        for sec in sections:
            if (sec.rva <= rsrc_directory_rva and
                    rsrc_directory_rva + rsrc_directory_size <=
                    sec.rva + len(sec.raw)):
                rsrc_bytes = sec.raw
                rsrc_rva = sec.rva
                break
        if not rsrc_bytes:
            raise ValueError(
                "malformed resource directory: owning section is not fully "
                "file-backed")

    debug_rva, debug_size = _data_dir(binary, "DEBUG_DIR")
    _validate_directory_range("debug", debug_rva, debug_size, image_size)
    debug_blob = _slice_at_rva(
        sections, debug_rva, debug_size, what="debug directory")
    extended_dll_characteristics = _parse_extended_dll_characteristics(
        debug_blob, image_size=image_size, sections=sections)
    if extended_dll_characteristics:
        labels = []
        if extended_dll_characteristics & 0x0001:
            labels.append("CET Shadow Stack")
        if extended_dll_characteristics & 0x0040:
            labels.append("forward-edge CFI")
        known = 0x0001 | 0x0040
        if extended_dll_characteristics & ~known:
            labels.append(
                f"unknown bits 0x{extended_dll_characteristics & ~known:X}")
        raise ValueError(
            "unsupported extended DLL characteristics would be stripped: "
            + ", ".join(labels))

    tls_rva, tls_size = _data_dir(binary, "TLS_TABLE")
    _validate_directory_range("TLS", tls_rva, tls_size, image_size)
    _slice_at_rva(sections, tls_rva, tls_size, what="TLS directory")
    tls = _extract_tls(binary, image_base)
    if bool(tls_rva) != bool(tls):
        raise ValueError(
            "malformed TLS directory: header presence and parsed TLS state disagree")
    if tls is not None:
        if not (0 < tls.index_rva <= image_size - 4):
            raise ValueError("malformed TLS directory: AddressOfIndex is outside image")
        if tls.raw_end_rva < tls.raw_start_rva:
            raise ValueError("malformed TLS directory: raw-data range is reversed")
        if (tls.raw_start_rva and
                (tls.raw_end_rva > image_size or tls.raw_start_rva >= image_size)):
            raise ValueError("malformed TLS directory: raw-data range is outside image")
        for callback_rva in tls.callback_rvas:
            if not (0 < callback_rva < image_size):
                raise ValueError(
                    f"malformed TLS callback RVA 0x{callback_rva:X}: outside image")

    load_config_rva, load_config_size = _data_dir(binary, "LOAD_CONFIG_TABLE")
    _validate_directory_range(
        "load-config", load_config_rva, load_config_size, image_size)
    load_config_blob = _slice_at_rva(
        sections,
        load_config_rva,
        load_config_size,
        what="load-config directory",
    )
    load_config = _parse_load_config(
        load_config_blob,
        load_config_rva,
        image_base=image_base,
        image_size=image_size,
        sections=sections,
    )
    header_guard_cf = bool(
        dll_characteristics & _IMAGE_DLLCHARACTERISTICS_GUARD_CF)
    if header_guard_cf and (load_config is None or not load_config.has_guard_cf):
        raise ValueError(
            "malformed Guard CF image: DllCharacteristics declares GUARD_CF "
            "without a matching load-config Guard CF contract")
    if load_config is not None and load_config.has_guard_cf and not header_guard_cf:
        raise ValueError(
            "malformed Guard CF image: load-config declares Guard CF while "
            "DllCharacteristics omits GUARD_CF")

    return ParsedPE(
        path=path,
        is_dll=is_dll,
        image_base=image_base,
        size_of_image=image_size,
        oep_rva=_i(opt.addressof_entrypoint),
        sections=sections,
        imports=imports,
        reloc_blob=reloc_blob,
        tls=tls,
        pdata_rva=pdata_rva if pdata_count else 0,
        pdata_count=pdata_count,
        rsrc_rva=rsrc_rva if rsrc_bytes else 0,
        file_characteristics=file_characteristics,
        dll_characteristics=dll_characteristics,
        rsrc_bytes=rsrc_bytes,
        rsrc_directory_rva=(
            rsrc_directory_rva if rsrc_bytes else 0),
        rsrc_directory_size=(
            rsrc_directory_size if rsrc_bytes else 0),
        delay_import_rva=delay_import_rva,
        delay_import_size=delay_import_size,
        dir64_relocations=dir64_relocations,
        runtime_functions=runtime_functions,
        load_config=load_config,
        section_alignment=section_alignment,
    )
