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
* resources: ``.rsrc`` RVA + raw bytes, to be preserved *plaintext* by the
  assembler (icon / RT_VERSION / RT_MANIFEST must stay OS/Authenticode-readable)

Only PE32+ (x64 / AMD64) input is supported; x86 (PE32) and ARM raise a clear
:class:`ValueError`.
"""
from __future__ import annotations

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
    "ParsedPE",
    "analyze_pe",
    "PEArchError",
]

# PE constants (avoid depending on LIEF enum *names*, which drift across versions)
_PE32_PLUS = 0x20B          # OptionalHeader.Magic for x64
_MACHINE_AMD64 = 0x8664     # IMAGE_FILE_MACHINE_AMD64
_IMAGE_FILE_DLL = 0x2000    # IMAGE_FILE_DLL characteristic
_RUNTIME_FUNCTION_SIZE = 12  # x64 RUNTIME_FUNCTION (.pdata entry) is 12 bytes
_PTR_SIZE = 8                # x64 IAT thunk width


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
    rsrc_rva: int                        # 0 if no resources
    rsrc_bytes: bytes = b""              # .rsrc raw bytes, preserved plaintext

    @property
    def has_tls(self) -> bool:
        return self.tls is not None

    @property
    def has_exceptions(self) -> bool:
        return self.pdata_count > 0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _slice_at_rva(sections: List[ParsedSection], rva: int, size: int) -> bytes:
    """Return ``size`` bytes at module ``rva`` from whichever section maps it.

    Uses the already-captured section raw bytes (no LIEF VA/RVA ambiguity). If
    the requested range runs past a section's on-disk bytes it is clamped to
    what is available (trailing bytes were file-alignment zero padding anyway).
    """
    if size <= 0:
        return b""
    for sec in sections:
        span = max(sec.virtual_size, len(sec.raw))
        if sec.rva <= rva < sec.rva + span:
            off = rva - sec.rva
            return bytes(sec.raw[off:off + size])
    return b""


def _data_dir(binary, name: str):
    """Return the ``(rva, size)`` of a named data directory, or ``(0, 0)``."""
    try:
        dtype = getattr(lief.PE.DataDirectory.TYPES, name)
        dd = binary.data_directory(dtype)
    except Exception:  # pragma: no cover - directory absent / API drift
        return 0, 0
    if dd is None:
        return 0, 0
    return _i(dd.rva), _i(dd.size)


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
    return TlsInfo(
        index_rva=to_rva(tls.addressof_index),
        callback_rvas=callbacks,
        raw_start_rva=to_rva(raw_start) if raw_start else 0,
        raw_end_rva=to_rva(raw_end) if raw_end else 0,
        zero_fill=_i(tls.sizeof_zero_fill),
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
    is_dll = bool(_i(binary.header.characteristics) & _IMAGE_FILE_DLL)

    sections: List[ParsedSection] = []
    for sec in binary.sections:
        sections.append(ParsedSection(
            name=sec.name,
            rva=_i(sec.virtual_address),
            virtual_size=_i(sec.virtual_size),
            raw=bytes(sec.content),
            characteristics=_i(sec.characteristics),
        ))

    imports = _extract_imports(binary, image_base)

    reloc_rva, reloc_size = _data_dir(binary, "BASE_RELOCATION_TABLE")
    reloc_blob = _slice_at_rva(sections, reloc_rva, reloc_size)

    pdata_rva, pdata_size = _data_dir(binary, "EXCEPTION_TABLE")
    pdata_count = pdata_size // _RUNTIME_FUNCTION_SIZE

    rsrc_rva, _rsrc_size = _data_dir(binary, "RESOURCE_TABLE")
    rsrc_bytes = b""
    if rsrc_rva:
        # Preserve the whole .rsrc section verbatim at its original RVA so any
        # internal resource RVAs stay valid.
        for sec in sections:
            if sec.rva <= rsrc_rva < sec.rva + max(sec.virtual_size, len(sec.raw)):
                rsrc_bytes = sec.raw
                rsrc_rva = sec.rva
                break

    tls = _extract_tls(binary, image_base)

    return ParsedPE(
        path=path,
        is_dll=is_dll,
        image_base=image_base,
        size_of_image=_i(opt.sizeof_image),
        oep_rva=_i(opt.addressof_entrypoint),
        sections=sections,
        imports=imports,
        reloc_blob=reloc_blob,
        tls=tls,
        pdata_rva=pdata_rva if pdata_count else 0,
        pdata_count=pdata_count,
        rsrc_rva=rsrc_rva if rsrc_bytes else 0,
        rsrc_bytes=rsrc_bytes,
    )
