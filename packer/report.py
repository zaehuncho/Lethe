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

    if len(data) < 64 or data[:2] != b"MZ":
        return ValidationResult(False, "output is not a PE (no MZ header)")
    try:
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return ValidationResult(False, "output is not a PE (no PE signature)")
    except struct.error:
        return ValidationResult(False, "output is not a PE (truncated header)")

    offset = data.find(container.MAGIC)
    if offset < 0:
        return ValidationResult(
            False, "no Lethe container found (PackInfo magic absent) -- "
                   "the stub may not be embedded or the pack was aborted")
    if offset + container.PACKINFO_SIZE > len(data):
        return ValidationResult(
            False, "Lethe container magic found but the PackInfo is truncated")

    try:
        info = container.PackInfo.from_bytes(
            data[offset:offset + container.PACKINFO_SIZE])
    except Exception as exc:  # noqa: BLE001 -- report any parse/version failure
        return ValidationResult(False, f"PackInfo failed to parse: {exc}",
                                magic_offset=offset)

    warnings: List[str] = []
    if not (1 <= info.section_count <= _MAX_SECTIONS):
        return ValidationResult(
            False,
            f"container has {info.section_count} section(s) -- not a packed "
            f"output (an unpopulated stub reads 0)",
            section_count=info.section_count,
            format_version=container.FORMAT_VERSION,
            flags=info.flags, magic_offset=offset)

    if data.count(container.MAGIC) > 1:
        warnings.append(f"magic appears {data.count(container.MAGIC)}x")

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
