"""Post-pack reporting for Lethe: section/entropy analysis + structural validation.

Two dependency-free helpers (``struct`` only -- no ``lief``, so they parse the
*packed* output as reliably as the original) shared by the CLI and the GUI so the
two front-ends never drift:

* :func:`section_report` -- per-section name / sizes / R-W-X flags / Shannon
  entropy, for an original-vs-packed comparison (encrypted sections approach the
  8.0 ceiling).
* :func:`validate_packed` -- a *structural* round-trip check that never executes
  the output: it confirms the file is a valid PE, locates the embedded Lethe
  container by magic, parses the 192-byte :class:`~packer.container.PackInfo`, and
  sanity-checks it. Catches a corrupt/short/mis-keyed pack without the risk (or
  the AV noise) of actually running a freshly packed binary.
"""
from __future__ import annotations

import math
import os
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional

from . import container

# COFF / section-header constants.
_IMAGE_FILE_DLL = 0x2000
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000
_PE32_PLUS = 0x20B
_AMD64 = 0x8664

# A sane upper bound on section count (the PE format allows many more, but a
# Lethe-packed output has a handful; an absurd count means we mis-parsed).
_MAX_SECTIONS = 96


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits/byte, 0.0 (uniform) .. 8.0 (random)."""
    if not data:
        return 0.0
    n = len(data)
    ent = 0.0
    # Counter() over a bytes object counts at C speed -- fast even on multi-MB
    # sections, unlike a per-byte Python loop.
    for c in Counter(data).values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


@dataclass
class SectionInfo:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float          # Shannon bits/byte of the on-disk raw bytes
    readable: bool
    writable: bool
    executable: bool

    @property
    def flags(self) -> str:
        return (("R" if self.readable else "-")
                + ("W" if self.writable else "-")
                + ("X" if self.executable else "-"))


@dataclass(frozen=True)
class _RawSection:
    """Section geometry used to tie a PackInfo candidate to mapped PE bytes."""

    rva: int
    virtual_size: int
    raw_size: int
    raw_ptr: int
    characteristics: int

    def contains_file_range(self, offset: int, size: int) -> bool:
        return (self.raw_size > 0 and self.raw_ptr <= offset
                and offset + size <= self.raw_ptr + self.raw_size)

    def contains_rva_range(self, rva: int, size: int, *, raw: bool) -> bool:
        span = self.raw_size if raw else max(self.virtual_size, self.raw_size)
        return span > 0 and self.rva <= rva and rva + size <= self.rva + span


@dataclass(frozen=True)
class _PELayout:
    is_dll: bool
    image_size: int
    sections: List[_RawSection]

    def section_for_file_range(self, offset: int, size: int) -> Optional[_RawSection]:
        return next((s for s in self.sections
                     if s.contains_file_range(offset, size)), None)

    def section_for_rva_range(self, rva: int, size: int, *,
                              raw: bool = False) -> Optional[_RawSection]:
        return next((s for s in self.sections
                     if s.contains_rva_range(rva, size, raw=raw)), None)


def _parse_pe_layout(data: bytes) -> _PELayout:
    """Strictly parse the PE fields needed by post-pack validation."""
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("output is not a PE (no MZ header)")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("output is not a PE (no PE signature)")

    coff = e_lfanew + 4
    machine, num_sections = struct.unpack_from("<HH", data, coff)
    opt_size, characteristics = struct.unpack_from("<HH", data, coff + 16)
    if machine != _AMD64:
        raise ValueError("output is not an AMD64 PE")
    if not (0 < num_sections <= _MAX_SECTIONS):
        raise ValueError(f"implausible section count: {num_sections}")

    optional = coff + 20
    optional_end = optional + opt_size
    if opt_size < 0x70 or optional_end > len(data):
        raise ValueError("output has a truncated PE32+ optional header")
    if struct.unpack_from("<H", data, optional)[0] != _PE32_PLUS:
        raise ValueError("output is not PE32+ (x64)")
    image_size = struct.unpack_from("<I", data, optional + 0x38)[0]
    if image_size == 0:
        raise ValueError("output has a zero SizeOfImage")

    section_table = optional_end
    if section_table + num_sections * 40 > len(data):
        raise ValueError("section table runs past end of file")
    sections: List[_RawSection] = []
    for index in range(num_sections):
        off = section_table + index * 40
        virtual_size, rva, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, off + 8)
        section_chars = struct.unpack_from("<I", data, off + 36)[0]
        if raw_size and (not raw_ptr or raw_ptr + raw_size > len(data)):
            raise ValueError(f"section {index} raw range runs past end of file")
        if rva + max(virtual_size, raw_size) > image_size:
            raise ValueError(f"section {index} mapped range exceeds SizeOfImage")
        sections.append(_RawSection(
            rva, virtual_size, raw_size, raw_ptr, section_chars))
    return _PELayout(
        bool(characteristics & _IMAGE_FILE_DLL), image_size, sections)


def _parse_sections(data: bytes) -> List[SectionInfo]:
    """Walk the PE section table of ``data`` and return per-section info.

    Raises ValueError if ``data`` is not a parseable PE.
    """
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("not a PE (no MZ header)")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (no PE signature)")
    coff = e_lfanew + 4
    num_sections, = struct.unpack_from("<H", data, coff + 2)
    opt_size, = struct.unpack_from("<H", data, coff + 16)
    if not (0 < num_sections <= _MAX_SECTIONS):
        raise ValueError(f"implausible section count: {num_sections}")
    sec_table = coff + 20 + opt_size
    out: List[SectionInfo] = []
    for i in range(num_sections):
        off = sec_table + i * 40
        if off + 40 > len(data):
            raise ValueError("section table runs past end of file")
        raw_name = data[off:off + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("latin-1", "replace") or f"sect{i}"
        vsize, = struct.unpack_from("<I", data, off + 8)
        rawsize, = struct.unpack_from("<I", data, off + 16)
        rawptr, = struct.unpack_from("<I", data, off + 20)
        chars, = struct.unpack_from("<I", data, off + 36)
        raw = data[rawptr:rawptr + rawsize] if rawsize and rawptr else b""
        out.append(SectionInfo(
            name=name,
            virtual_size=vsize,
            raw_size=rawsize,
            entropy=shannon_entropy(raw),
            readable=bool(chars & _SCN_MEM_READ),
            writable=bool(chars & _SCN_MEM_WRITE),
            executable=bool(chars & _SCN_MEM_EXECUTE),
        ))
    return out


def section_report(path: str) -> List[SectionInfo]:
    """Per-section report for the PE at ``path``. Raises ValueError on a bad PE."""
    with open(path, "rb") as fh:
        data = fh.read()
    return _parse_sections(data)


@dataclass
class ValidationResult:
    ok: bool
    reason: str = ""
    section_count: int = 0
    format_version: int = 0
    flags: int = 0
    magic_offset: int = -1
    warnings: List[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.ok:
            base = (f"valid Lethe container: {self.section_count} section(s), "
                    f"format v{self.format_version}, flags 0x{self.flags:08x}")
            if self.warnings:
                base += "  [" + "; ".join(self.warnings) + "]"
            return base
        return f"invalid: {self.reason}"


def _candidate_is_live(info: container.PackInfo, offset: int,
                       layout: _PELayout) -> bool:
    """Return whether a magic-bearing PackInfo is the live mapped container.

    The assembler puts the live structure in a raw-backed writable stub section;
    intentional decoys live in the read-only payload. The range checks tie the
    candidate to the emitted PE instead of accepting arbitrary parseable bytes.
    """
    owner = layout.section_for_file_range(offset, container.PACKINFO_SIZE)
    if owner is None or not (owner.characteristics & _SCN_MEM_WRITE):
        return False
    packinfo_rva = owner.rva + (offset - owner.raw_ptr)

    allowed_flags = (
        container.FLAG_HAS_TLS | container.FLAG_HAS_EXCEPTIONS
        | container.FLAG_ANTIDEBUG | container.FLAG_MEMGUARD
    )
    if info.flags & ~allowed_flags:
        return False
    if info.is_dll not in (0, 1) or bool(info.is_dll) != layout.is_dll:
        return False
    if not (1 <= info.section_count <= _MAX_SECTIONS):
        return False
    if not (0 < info.original_size_of_image <= layout.image_size):
        return False
    if info.oep_rva and info.oep_rva >= info.original_size_of_image:
        return False

    if packinfo_rva < info.original_size_of_image:
        return False
    if info.stub_text_size == 0 or info.stub_text_rva < info.original_size_of_image:
        return False
    text_owner = layout.section_for_rva_range(
        info.stub_text_rva, info.stub_text_size)
    if text_owner is None or not (text_owner.characteristics & _SCN_MEM_EXECUTE):
        return False

    if info.meta_stored_size == 0 or info.meta_uncompressed_size == 0:
        return False
    if info.meta_rva < info.original_size_of_image:
        return False
    meta_owner = layout.section_for_rva_range(
        info.meta_rva, info.meta_stored_size, raw=True)
    if meta_owner is None or not (meta_owner.characteristics & _SCN_MEM_READ):
        return False

    meta_size = info.meta_uncompressed_size
    ranges = (
        (info.sections_off, info.section_count * container.SECTIONDESC_SIZE),
        (info.imports_off, info.imports_size),
        (info.relocs_off, info.relocs_size),
    )
    if any(off + size > meta_size for off, size in ranges):
        return False
    if (info.flags & container.FLAG_HAS_TLS) and info.tls_off + 20 > meta_size:
        return False
    if info.flags & container.FLAG_HAS_EXCEPTIONS:
        if not info.pdata_rva or not info.pdata_count:
            return False
        if info.pdata_rva + info.pdata_count * 12 > info.original_size_of_image:
            return False

    # An untouched stub and low-effort injected decoys use zero-filled crypto
    # fields. Real builds fill every one from CSPRNG/AES-GCM operations.
    if (not any(info.meta_nonce) or not any(info.meta_tag)
            or not any(info.aes_key_enc) or not any(info.kdf_salt)):
        return False
    return True


def validate_packed(path: str) -> ValidationResult:
    """Structural round-trip check of a packed output -- never executes it.

    Confirms ``path`` is a PE, finds the embedded Lethe container by magic, parses
    the PackInfo, and sanity-checks it. This proves the packer emitted a
    well-formed container; it does NOT prove runtime behaviour (that needs the
    separate execution harness), but it catches truncation / corruption / a stub
    that never got its PackInfo populated, cheaply and without AV-triggering runs.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return ValidationResult(False, f"cannot read output: {exc}")

    try:
        layout = _parse_pe_layout(data)
    except (ValueError, struct.error) as exc:
        return ValidationResult(False, str(exc))

    offsets: List[int] = []
    cursor = 0
    while True:
        offset = data.find(container.MAGIC, cursor)
        if offset < 0:
            break
        offsets.append(offset)
        cursor = offset + 1
    if not offsets:
        return ValidationResult(
            False, "no Lethe container found (PackInfo magic absent) -- "
                   "the stub may not be embedded or the pack was aborted")

    candidates = []
    for offset in offsets:
        if offset + container.PACKINFO_SIZE > len(data):
            continue
        try:
            info = container.PackInfo.from_bytes(
                data[offset:offset + container.PACKINFO_SIZE])
        except Exception:
            continue
        if _candidate_is_live(info, offset, layout):
            candidates.append((offset, info))

    if not candidates:
        return ValidationResult(
            False,
            f"found {len(offsets)} PackInfo magic candidate(s), but none is a "
            "structurally valid live container (decoy-only or corrupt output)")
    if len(candidates) != 1:
        return ValidationResult(
            False,
            f"ambiguous output: found {len(candidates)} structurally valid "
            "PackInfo candidates; refusing to guess")

    offset, info = candidates[0]
    warnings: List[str] = []
    ignored = len(offsets) - 1
    if ignored:
        warnings.append(f"ignored {ignored} decoy PackInfo candidate(s)")

    return ValidationResult(
        True, "", section_count=info.section_count,
        format_version=container.FORMAT_VERSION, flags=info.flags,
        magic_offset=offset, warnings=warnings)


def format_report(original: str, packed: Optional[str] = None) -> str:
    """Human-readable section/entropy table: original, and packed if given."""
    lines: List[str] = []

    def _table(title: str, secs: List[SectionInfo]) -> None:
        lines.append(title)
        lines.append(f"  {'section':<10} {'flags':<5} {'raw':>10} "
                     f"{'vsize':>10} {'entropy':>8}")
        for s in secs:
            lines.append(f"  {s.name:<10} {s.flags:<5} {s.raw_size:>10} "
                         f"{s.virtual_size:>10} {s.entropy:>8.3f}")
        if secs:
            avg = sum(s.entropy for s in secs) / len(secs)
            lines.append(f"  {'(mean)':<10} {'':<5} {'':>10} {'':>10} {avg:>8.3f}")

    try:
        _table(f"Sections — original ({os.path.basename(original)}):",
               section_report(original))
    except ValueError as exc:
        lines.append(f"original: cannot analyze ({exc})")
    if packed:
        lines.append("")
        try:
            _table(f"Sections — packed ({os.path.basename(packed)}):",
                   section_report(packed))
        except ValueError as exc:
            lines.append(f"packed: cannot analyze ({exc})")
    return "\n".join(lines)
