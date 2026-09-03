"""Build the outer import table used by packed DLLs before ``DllMain``.

The protected import directory is encrypted.  Native DLL loading, however,
must make every dependency available before entering the module while the
Windows loader owns its lock.  This builder combines the grafted stub import
descriptors with reconstructed source descriptors.  The source descriptors
use a private lookup table but retain the source IAT RVAs, letting Windows
populate those slots before ``StubDllMain`` decrypts the complete sections.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Sequence


IMAGE_ORDINAL_FLAG64 = 1 << 63


class DllPreloadError(ValueError):
    pass


@dataclass(frozen=True)
class DllPreloadImage:
    data: bytes
    descriptor_size: int
    preload_iat_rvas: tuple[int, ...]


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_dll_preload_image(
    stub_descriptors: Sequence[bytes],
    imports: Iterable[object],
    *,
    section_rva: int,
    image_size: int,
) -> DllPreloadImage:
    """Return a self-contained outer import table for a packed x64 DLL."""
    source_imports = tuple(imports)
    if section_rva <= 0 or section_rva > 0xFFFF_FFFF:
        raise DllPreloadError("preload import section RVA escapes PE32+ RVA space")
    for descriptor in stub_descriptors:
        if len(descriptor) != 20:
            raise DllPreloadError("stub import descriptor is not 20 bytes")
        if descriptor == b"\0" * 20:
            raise DllPreloadError("stub descriptor list includes its terminator")

    descriptor_count = len(stub_descriptors) + len(source_imports) + 1
    descriptor_size = descriptor_count * 20
    blob = bytearray(descriptor_size)
    preload_iat_rvas: list[int] = []
    for index, descriptor in enumerate(stub_descriptors):
        blob[index * 20:(index + 1) * 20] = descriptor

    def append(data: bytes, alignment: int = 1) -> int:
        aligned = _align(len(blob), alignment)
        if aligned > len(blob):
            blob.extend(b"\0" * (aligned - len(blob)))
        offset = len(blob)
        blob.extend(data)
        if section_rva + len(blob) > 0xFFFFFFFF:
            raise DllPreloadError("preload import section exceeds PE32+ RVA space")
        return offset

    for dll_index, dll in enumerate(source_imports):
        name = str(getattr(dll, "name", ""))
        funcs = tuple(getattr(dll, "funcs", ()))
        if not name or "\0" in name:
            raise DllPreloadError("source import DLL has an invalid name")
        try:
            name_bytes = name.encode("ascii") + b"\0"
        except UnicodeEncodeError as exc:
            raise DllPreloadError("source import DLL name is not ASCII") from exc
        if not funcs:
            raise DllPreloadError(f"source import {name!r} has no functions")

        iat_rva = int(getattr(funcs[0], "iat_rva"))
        if iat_rva <= 0 or iat_rva % 8:
            raise DllPreloadError(f"source import {name!r} has an unaligned IAT")
        for func_index, func in enumerate(funcs):
            actual_rva = int(getattr(func, "iat_rva"))
            expected_rva = iat_rva + func_index * 8
            if actual_rva != expected_rva:
                raise DllPreloadError(
                    f"source import {name!r} IAT entries are not contiguous")
        if iat_rva + (len(funcs) + 1) * 8 > image_size:
            raise DllPreloadError(f"source import {name!r} IAT escapes SizeOfImage")

        dll_name_offset = append(name_bytes)
        thunk_values: list[int] = []
        for func in funcs:
            if bool(getattr(func, "by_ordinal", False)):
                ordinal = int(getattr(func, "ordinal", 0))
                if not 0 < ordinal <= 0xFFFF:
                    raise DllPreloadError(
                        f"source import {name!r} has an invalid ordinal")
                thunk_values.append(IMAGE_ORDINAL_FLAG64 | ordinal)
                continue

            func_name = str(getattr(func, "name", ""))
            if not func_name or "\0" in func_name:
                raise DllPreloadError(
                    f"source import {name!r} has an invalid function name")
            try:
                import_by_name = b"\0\0" + func_name.encode("ascii") + b"\0"
            except UnicodeEncodeError as exc:
                raise DllPreloadError(
                    f"source import {name!r} function name is not ASCII") from exc
            hint_name_offset = append(import_by_name, 2)
            thunk_values.append(section_rva + hint_name_offset)

        ilt_offset = append(
            b"".join(struct.pack("<Q", value) for value in thunk_values)
            + b"\0" * 8,
            8,
        )
        iat_offset = append(
            b"".join(struct.pack("<Q", value) for value in thunk_values)
            + b"\0" * 8,
            8,
        )
        preload_iat_rvas.extend(
            section_rva + iat_offset + index * 8
            for index in range(len(thunk_values)))
        descriptor = struct.pack(
            "<IIIII",
            section_rva + ilt_offset,
            0,
            0,
            section_rva + dll_name_offset,
            section_rva + iat_offset,
        )
        descriptor_index = len(stub_descriptors) + dll_index
        begin = descriptor_index * 20
        blob[begin:begin + 20] = descriptor

    return DllPreloadImage(
        bytes(blob), descriptor_size, tuple(preload_iat_rvas))
