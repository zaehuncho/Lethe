#!/usr/bin/env python3
"""Enable process CFG export suppression on a freshly linked test host."""
from __future__ import annotations

import struct
import sys
from pathlib import Path


IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_GUARD_CF_INSTRUMENTED = 0x100
IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 0x400
IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 0x8000


def _u16(blob: bytearray, offset: int) -> int:
    return struct.unpack_from("<H", blob, offset)[0]


def _u32(blob: bytearray, offset: int) -> int:
    return struct.unpack_from("<I", blob, offset)[0]


def _rva_to_offset(blob: bytearray, optional: int, rva: int) -> int:
    pe = optional - 24
    section_count = _u16(blob, pe + 6)
    optional_size = _u16(blob, pe + 20)
    size_of_headers = _u32(blob, optional + 60)
    if rva < size_of_headers:
        return rva
    sections = optional + optional_size
    for index in range(section_count):
        entry = sections + index * 40
        virtual_size = _u32(blob, entry + 8)
        virtual_address = _u32(blob, entry + 12)
        raw_size = _u32(blob, entry + 16)
        raw_offset = _u32(blob, entry + 20)
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            delta = rva - virtual_address
            if delta >= raw_size:
                raise ValueError("load-config RVA is not file-backed")
            return raw_offset + delta
    raise ValueError("load-config RVA is outside every section")


def enable(path: Path) -> tuple[int, int]:
    blob = bytearray(path.read_bytes())
    if blob[:2] != b"MZ":
        raise ValueError("missing DOS header")
    pe = _u32(blob, 0x3C)
    if blob[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    optional = pe + 24
    if _u16(blob, optional) != 0x20B:
        raise ValueError("fixture must be PE32+")
    if _u32(blob, optional + 108) <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
        raise ValueError("fixture has no load-config directory")
    directory = optional + 112 + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8
    load_config_rva, load_config_size = struct.unpack_from("<II", blob, directory)
    if not load_config_rva or load_config_size < 148:
        raise ValueError("fixture load-config is too small for GuardFlags")
    load_config = _rva_to_offset(blob, optional, load_config_rva)
    if _u32(blob, load_config) < 148:
        raise ValueError("declared load-config is too small for GuardFlags")
    guard_flags_offset = load_config + 144
    before = _u32(blob, guard_flags_offset)
    required = IMAGE_GUARD_CF_INSTRUMENTED | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
    if before & required != required:
        raise ValueError("fixture is not a GuardCF image")
    after = before | IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION
    struct.pack_into("<I", blob, guard_flags_offset, after)
    path.write_bytes(blob)
    return before, after


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: enable_cfg_export_suppression.py <host.exe>", file=sys.stderr)
        return 2
    try:
        before, after = enable(Path(argv[1]))
    except (OSError, ValueError, struct.error) as exc:
        print(f"CFG export-suppression patch failed: {exc}", file=sys.stderr)
        return 1
    print(f"CFG export suppression enabled: 0x{before:08X} -> 0x{after:08X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
