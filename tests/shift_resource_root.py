#!/usr/bin/env python3
"""Move a fixture PE's resource tree inside its owning section."""
from __future__ import annotations

import argparse
import os
import struct
import tempfile
from pathlib import Path


_RESOURCE_DIRECTORY_INDEX = 2


def _u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _resource_data_entries(blob: bytes | bytearray, directory_size: int) -> set[int]:
    entries: set[int] = set()
    visited: set[int] = set()

    def walk(relative_offset: int) -> None:
        if relative_offset in visited:
            raise ValueError("resource directory contains a cycle")
        visited.add(relative_offset)
        if relative_offset < 0 or relative_offset + 16 > directory_size:
            raise ValueError("resource subdirectory escapes the directory span")
        named = _u16(blob, relative_offset + 12)
        ids = _u16(blob, relative_offset + 14)
        count = named + ids
        table_end = relative_offset + 16 + count * 8
        if table_end > directory_size:
            raise ValueError("resource directory entry table is truncated")
        for index in range(count):
            entry_offset = relative_offset + 16 + index * 8
            target = _u32(blob, entry_offset + 4)
            target_offset = target & 0x7FFF_FFFF
            if target & 0x8000_0000:
                walk(target_offset)
            else:
                if target_offset + 16 > directory_size:
                    raise ValueError("resource data entry escapes the directory span")
                entries.add(target_offset)

    walk(0)
    if not entries:
        raise ValueError("resource directory contains no data entries")
    return entries


def shift_resource_root(path: Path, shift: int) -> tuple[int, int, int]:
    if shift <= 0 or shift % 16:
        raise ValueError("resource-root shift must be a positive multiple of 16")
    data = bytearray(path.read_bytes())
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("fixture is not a PE image")
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("fixture has no bounded PE signature")
    coff = pe_offset + 4
    section_count = _u16(data, coff + 2)
    optional_size = _u16(data, coff + 16)
    optional = coff + 20
    optional_end = optional + optional_size
    if optional_end > len(data) or optional_size < 0x80:
        raise ValueError("fixture has a truncated optional header")
    if _u16(data, optional) != 0x20B:
        raise ValueError("fixture is not PE32+")
    if _u32(data, optional + 108) <= _RESOURCE_DIRECTORY_INDEX:
        raise ValueError("fixture has no resource data-directory slot")
    section_alignment = _u32(data, optional + 32)
    if section_alignment == 0 or section_alignment & (section_alignment - 1):
        raise ValueError("fixture has invalid SectionAlignment")
    directory_offset = optional + 112 + _RESOURCE_DIRECTORY_INDEX * 8
    resource_rva, resource_size = struct.unpack_from("<II", data, directory_offset)
    if resource_rva == 0 or resource_size == 0:
        raise ValueError("fixture has no resource directory")

    section_table = optional_end
    if section_count == 0 or section_table + section_count * 40 > len(data):
        raise ValueError("fixture has an invalid section table")
    sections: list[tuple[int, int, int, int, int]] = []
    owner = None
    for index in range(section_count):
        header = section_table + index * 40
        virtual_size, rva, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, header + 8)
        if raw_size and raw_pointer + raw_size > len(data):
            raise ValueError("fixture section raw bytes are truncated")
        sections.append((rva, virtual_size, raw_size, raw_pointer, header))
        if rva <= resource_rva and resource_rva + resource_size <= rva + raw_size:
            owner = sections[-1]
    if owner is None:
        raise ValueError("resource directory has no file-backed owner section")
    owner_rva, virtual_size, raw_size, raw_pointer, owner_header = owner
    if resource_rva != owner_rva:
        raise ValueError("fixture resource root is already offset")

    content_size = max(virtual_size, resource_size)
    if shift + content_size > raw_size:
        raise ValueError("resource section lacks raw padding for requested shift")
    new_virtual_size = shift + content_size
    later_rvas = [rva for rva, *_rest in sections if rva > owner_rva]
    if (later_rvas and
            owner_rva + _align_up(new_virtual_size, section_alignment) >
            min(later_rvas)):
        raise ValueError("shifted resource section would overlap the next section")

    content = bytearray(data[raw_pointer:raw_pointer + content_size])
    for entry_offset in _resource_data_entries(content, resource_size):
        data_rva = _u32(content, entry_offset)
        if owner_rva <= data_rva < owner_rva + content_size:
            struct.pack_into("<I", content, entry_offset, data_rva + shift)

    data[raw_pointer:raw_pointer + raw_size] = bytes(raw_size)
    data[raw_pointer + shift:raw_pointer + shift + content_size] = content
    struct.pack_into("<I", data, owner_header + 8, new_virtual_size)
    struct.pack_into("<II", data, directory_offset,
                     resource_rva + shift, resource_size)
    struct.pack_into("<I", data, optional + 64, 0)

    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return owner_rva, resource_rva + shift, resource_size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--shift", type=lambda value: int(value, 0), default=0x40)
    args = parser.parse_args()
    try:
        owner_rva, directory_rva, directory_size = shift_resource_root(
            args.path.resolve(), args.shift)
    except (OSError, ValueError, struct.error) as exc:
        parser.error(str(exc))
    print(
        f"resource root shifted: section=0x{owner_rva:X} "
        f"directory=0x{directory_rva:X} size=0x{directory_size:X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
