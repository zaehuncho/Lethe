#!/usr/bin/env python3
"""Report exact raw PE resource DataDirectory and owner-section geometry."""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


def probe_resource_geometry(path: Path) -> dict[str, int]:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("input has no DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("input has no bounded PE signature")
    coff = pe_offset + 4
    section_count, optional_size = struct.unpack_from("<2xH12xH", data, coff)
    optional = coff + 20
    optional_end = optional + optional_size
    if optional_size < 0x80 or optional_end > len(data):
        raise ValueError("input has a truncated optional header")
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("input is not PE32+")
    directory_count = struct.unpack_from("<I", data, optional + 108)[0]
    if directory_count <= 2:
        raise ValueError("input has no resource data-directory slot")
    directory_rva, directory_size = struct.unpack_from(
        "<II", data, optional + 112 + 2 * 8)
    if directory_rva == 0 or directory_size == 0:
        return {
            "resource_rva": 0,
            "resource_bytes": 0,
            "resource_directory_rva": 0,
            "resource_directory_size": 0,
            "resource_directory_offset": 0,
        }
    section_table = optional_end
    if section_count == 0 or section_table + section_count * 40 > len(data):
        raise ValueError("input has an invalid section table")
    for index in range(section_count):
        header = section_table + index * 40
        virtual_size, rva, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, header + 8)
        if raw_size and raw_pointer + raw_size > len(data):
            raise ValueError("input has a truncated section")
        if (rva <= directory_rva and
                directory_rva + directory_size <= rva + raw_size):
            return {
                "resource_rva": rva,
                "resource_bytes": raw_size,
                "resource_directory_rva": directory_rva,
                "resource_directory_size": directory_size,
                "resource_directory_offset": directory_rva - rva,
                "resource_virtual_size": virtual_size,
            }
    raise ValueError("resource directory has no file-backed owner section")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        result = probe_resource_geometry(args.input.resolve())
    except (OSError, ValueError, struct.error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **result}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
