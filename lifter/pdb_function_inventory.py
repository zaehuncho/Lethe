"""Bind DIA function extents to the exact PE CodeView identity.

This is an inventory primitive, not a coverage waiver.  The caller still has
to decode every supplemental body and prove all residual executable bytes.
"""

from __future__ import annotations

from collections import Counter
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from hashlib import sha256
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from typing import Any, Iterator, Sequence
from uuid import UUID

from . import direct_control_flow


_DEBUG_RECORD = struct.Struct("<IIHHIIII")
_IDENTITY = re.compile(r"PDB_IDENTITY guid=\{([0-9A-Fa-f-]{36})\} age=([0-9]+) machine=([0-9A-Fa-f]{4})")
_FUNCTION = re.compile(r"FUNCTION rva=([0-9A-Fa-f]{8}) size=([0-9]+)")
_SUMMARY = re.compile(r"FUNCTION_SUMMARY emitted=([0-9]+)")
_RVA_LIMIT = 0x1_0000_0000


class PdbInventoryError(ValueError):
    """A PDB inventory could not be bound to the exact image."""


@dataclass(frozen=True)
class CodeViewIdentity:
    guid: UUID
    age: int


@dataclass(frozen=True)
class BoundPdbInventory:
    image_sha256: str
    pdb_sha256: str
    helper_sha256: str
    identity: CodeViewIdentity
    symbol_count: int
    distinct_ranges: tuple[tuple[int, int], ...]
    supplemental_ranges: tuple[tuple[int, int], ...]
    # Raw DIA multiplicity survives distinct-span coverage normalization.
    range_multiplicities: tuple[tuple[int, int, int], ...]
    msdia_sha256: str | None = None


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise PdbInventoryError("truncated PE field")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise PdbInventoryError("truncated PE field")
    return struct.unpack_from("<I", data, offset)[0]


def extract_codeview_identity(image: bytes) -> CodeViewIdentity:
    """Read exactly one file-backed RSDS record from a PE32+ debug directory."""
    if not isinstance(image, bytes) or len(image) < 0x40 or image[:2] != b"MZ":
        raise PdbInventoryError("missing DOS header")
    pe = _u32(image, 0x3C)
    if pe + 24 > len(image) or image[pe:pe + 4] != b"PE\0\0":
        raise PdbInventoryError("missing PE signature")
    if _u16(image, pe + 4) != 0x8664:
        raise PdbInventoryError("CodeView proof requires AMD64")
    section_count = _u16(image, pe + 6)
    optional_size = _u16(image, pe + 20)
    optional = pe + 24
    optional_end = optional + optional_size
    if (
        not 1 <= section_count <= 96
        or optional_size < 0x70 + 7 * 8
        or optional_end > len(image)
        or _u16(image, optional) != 0x20B
        or _u32(image, optional + 0x6C) <= 6
    ):
        raise PdbInventoryError("invalid PE32+ debug-directory geometry")
    debug_rva = _u32(image, optional + 0x70 + 6 * 8)
    debug_size = _u32(image, optional + 0x70 + 6 * 8 + 4)
    if not debug_rva or not debug_size or debug_size % _DEBUG_RECORD.size:
        raise PdbInventoryError("missing or malformed debug directory")
    if debug_size > _DEBUG_RECORD.size * 64:
        raise PdbInventoryError("debug directory exceeds bounded inventory")
    table_end = optional_end + section_count * 40
    if table_end > len(image):
        raise PdbInventoryError("truncated section table")
    sections = []
    for index in range(section_count):
        offset = optional_end + index * 40
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", image, offset + 8
        )
        if raw_size and (raw_offset > len(image) or raw_size > len(image) - raw_offset):
            raise PdbInventoryError("section raw range exceeds file")
        if virtual_size and rva + virtual_size > _RVA_LIMIT:
            raise PdbInventoryError("section virtual range exceeds RVA space")
        sections.append((rva, raw_size, raw_offset))

    def file_offset(rva: int, size: int) -> int:
        owners = [
            raw_offset + rva - base
            for base, raw_size, raw_offset in sections
            if base <= rva and size <= raw_size and rva - base <= raw_size - size
        ]
        if len(owners) != 1:
            raise PdbInventoryError("debug RVA is not uniquely file-backed")
        return owners[0]

    debug_offset = file_offset(debug_rva, debug_size)
    found = []
    for offset in range(debug_offset, debug_offset + debug_size, _DEBUG_RECORD.size):
        (
            characteristics, _timestamp, _major, _minor,
            kind, data_size, data_rva, raw_offset,
        ) = _DEBUG_RECORD.unpack_from(image, offset)
        if kind != 2:
            continue
        if characteristics or data_size < 25 or data_size > 4096:
            raise PdbInventoryError("malformed CodeView debug record")
        if raw_offset != file_offset(data_rva, data_size):
            raise PdbInventoryError("CodeView RVA/file offset disagree")
        payload = image[raw_offset:raw_offset + data_size]
        if payload[:4] != b"RSDS" or b"\0" not in payload[24:]:
            raise PdbInventoryError("CodeView record is not terminated RSDS")
        age = _u32(payload, 20)
        if age == 0:
            raise PdbInventoryError("RSDS age must be positive")
        found.append(CodeViewIdentity(UUID(bytes_le=payload[4:20]), age))
    if len(found) != 1:
        raise PdbInventoryError("exactly one RSDS CodeView record is required")
    return found[0]


def parse_dia_inventory(output: str) -> tuple[CodeViewIdentity, tuple[tuple[int, int], ...]]:
    """Parse the tracked DIA helper's name-free, bounded machine protocol."""
    if not isinstance(output, str) or len(output) > 16_000_000 or "\0" in output:
        raise PdbInventoryError("invalid DIA helper output")
    lines = output.splitlines()
    if len(lines) < 2 or len(lines) > 250_002:
        raise PdbInventoryError("invalid DIA helper line count")
    first = _IDENTITY.fullmatch(lines[0])
    final = _SUMMARY.fullmatch(lines[-1])
    if first is None or final is None or first[3].lower() != "8664":
        raise PdbInventoryError("invalid DIA identity or summary")
    try:
        identity = CodeViewIdentity(UUID(first[1]), int(first[2]))
    except ValueError as exc:
        raise PdbInventoryError("invalid DIA identity") from exc
    if identity.age <= 0 or int(final[1]) != len(lines) - 2:
        raise PdbInventoryError("DIA function count mismatch")
    ranges = []
    for line in lines[1:-1]:
        match = _FUNCTION.fullmatch(line)
        if match is None:
            raise PdbInventoryError("malformed DIA function record")
        begin = int(match[1], 16)
        size = int(match[2])
        if begin <= 0 or size <= 0 or begin + size > _RVA_LIMIT:
            raise PdbInventoryError("invalid DIA function extent")
        ranges.append((begin, begin + size))
    return identity, tuple(ranges)


def bind_inventory(
    parsed: Any,
    image: bytes,
    pdb_sha256: str,
    helper_sha256: str,
    helper_output: str,
) -> BoundPdbInventory:
    """Bind exact PE/PDB identities and reject ambiguous function geometry."""
    identity = extract_codeview_identity(image)
    dia_identity, source = parse_dia_inventory(helper_output)
    if identity != dia_identity:
        raise PdbInventoryError("PDB GUID/age does not match PE RSDS")
    if not source:
        raise PdbInventoryError("PDB contains no function extents")
    if (
        type(getattr(parsed, "size_of_image", None)) is not int
        or not 0 < parsed.size_of_image <= _RVA_LIMIT
    ):
        raise PdbInventoryError("invalid parsed image geometry")
    if len(pdb_sha256) != 64 or len(helper_sha256) != 64 or any(
        c not in "0123456789abcdef" for c in pdb_sha256 + helper_sha256
    ):
        raise PdbInventoryError("missing canonical PDB/helper SHA-256")
    try:
        sections = direct_control_flow._normalize_sections(parsed)
        pdata = direct_control_flow._normalize_runtime_functions(parsed)
    except direct_control_flow.DirectControlFlowError as exc:
        raise PdbInventoryError(str(exc)) from exc
    counts = Counter(source)
    distinct = sorted(counts)
    if any(current[0] < previous[1] for previous, current in zip(distinct, distinct[1:])):
        raise PdbInventoryError("PDB function extents overlap")
    supplemental = []
    pidx = 0
    for begin, end in distinct:
        if end > parsed.size_of_image:
            raise PdbInventoryError("PDB function exceeds SizeOfImage")
        try:
            direct_control_flow._read_executable(
                sections, begin, end - begin, "PDB function"
            )
        except direct_control_flow.DirectControlFlowError as exc:
            raise PdbInventoryError(str(exc)) from exc
        while pidx < len(pdata) and pdata[pidx][1] <= begin:
            pidx += 1
        index = pidx
        while index < len(pdata) and pdata[index][0] < end:
            index += 1
        intersecting = pdata[pidx:index]
        if not intersecting:
            supplemental.append((begin, end))
            continue
        if (
            intersecting[0][0] != begin
            or intersecting[-1][1] != end
            or any(left[1] != right[0] for left, right in zip(intersecting, intersecting[1:]))
        ):
            raise PdbInventoryError("PDB function partially overlaps PDATA")
    return BoundPdbInventory(
        image_sha256=sha256(image).hexdigest(),
        pdb_sha256=pdb_sha256,
        helper_sha256=helper_sha256,
        identity=identity,
        symbol_count=len(source),
        distinct_ranges=tuple(distinct),
        supplemental_ranges=tuple(supplemental),
        range_multiplicities=tuple(
            (begin, end, counts[(begin, end)]) for begin, end in distinct
        ),
    )


@contextmanager
def _seal_snapshot_paths(paths: Sequence[Path]) -> Iterator[None]:
    """Keep Windows readers open while denying writes, deletion and renames.

    A read-only attribute or pre/post hash alone does not prevent an ABA swap
    while DIA is running. File share modes enforce the snapshot's lifetime;
    a directory handle also prevents renaming its private parent directory.
    """
    if os.name != "nt":
        raise PdbInventoryError("DIA snapshot sealing requires Windows")
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    invalid = ctypes.c_void_p(-1).value
    parents = {path.parent for path in paths}
    if len(parents) != 1:
        raise PdbInventoryError("DIA snapshots must share one private directory")
    # GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING. Deny write/delete on files.
    requests = [(path, 1, 0x80) for path in paths]
    # FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_BACKUP_SEMANTICS for parent.
    # Directory contents remain writable for readers' incidental files, but
    # FILE_SHARE_DELETE is absent so the snapshot directory cannot be renamed.
    requests.append((next(iter(parents)), 3, 0x02000000))
    with ExitStack() as stack:
        for path, sharing, flags in requests:
            handle = create(str(path), 0x80000000, sharing, None, 3, flags, None)
            if handle == invalid:
                raise PdbInventoryError("could not seal DIA snapshot") from ctypes.WinError(
                    ctypes.get_last_error()
                )
            stack.callback(close, handle)
        yield


def run_bound_inventory(
    parsed: Any, image_path: Path, pdb_path: Path, helper_path: Path, msdia_path: Path
) -> BoundPdbInventory:
    """Run DIA only on exact, mutation-locked private snapshots of all inputs."""
    if not hasattr(parsed, "path") or Path(parsed.path).resolve() != image_path.resolve():
        raise PdbInventoryError("parsed PE path does not match inventory image")
    originals = (image_path, pdb_path, helper_path, msdia_path)
    contents = tuple(path.read_bytes() for path in originals)
    digests = tuple(sha256(data).hexdigest() for data in contents)
    image = contents[0]
    from packer.pe_analyze import analyze_pe

    with tempfile.TemporaryDirectory(prefix="lethe-dia-") as directory:
        root = Path(directory)
        snapshots = tuple(root / name for name in (
            "image.bin", "input.pdb", "pdb_function_dump.exe", "msdia140.dll"
        ))
        for path, data in zip(snapshots, contents):
            path.write_bytes(data)
        with _seal_snapshot_paths(snapshots):
            if any(sha256(path.read_bytes()).hexdigest() != expected
                   for path, expected in zip(snapshots, digests)):
                raise PdbInventoryError("DIA snapshot differs from pinned input")
            fresh = analyze_pe(str(snapshots[0]))
            if (
                parsed.size_of_image != fresh.size_of_image
                or parsed.sections != fresh.sections
                or parsed.runtime_functions != fresh.runtime_functions
            ):
                raise PdbInventoryError("parsed PE inventory differs from current image")
            command = [str(snapshots[index]) for index in (2, 3, 1)]
            try:
                result = subprocess.run(command, capture_output=True, timeout=300, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PdbInventoryError("DIA helper did not complete") from exc
            if result.returncode or result.stderr or len(result.stdout) > 16_000_000:
                raise PdbInventoryError("DIA helper failed or emitted diagnostics")
            for path, expected, diagnostic in zip(originals, digests, (
                "PE changed during PDB inventory", "PDB changed during inventory",
                "DIA helper changed during inventory", "DIA runtime changed during inventory",
            )):
                if sha256(path.read_bytes()).hexdigest() != expected:
                    raise PdbInventoryError(diagnostic)
            try:
                output = result.stdout.decode("ascii")
            except UnicodeDecodeError as exc:
                raise PdbInventoryError("DIA helper output is not ASCII") from exc
            return replace(
                bind_inventory(parsed, image, digests[1], digests[2], output),
                msdia_sha256=digests[3],
            )
