#!/usr/bin/env python3
"""Read-only, bounded PE checks for a specifically supplied .sys release artifact.

This does not load, rewrite, pack, virtualize, or authenticate drivers. A parsed
report always leaves production readiness false: external driver gates remain.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import sys
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_SECTIONS = 96
MAX_IMPORT_DESCRIPTORS = 4096
MAX_IMPORT_THUNKS = 65536
MAX_MODULE_NAME = 260
MAX_SYMBOL_NAME = 4096
MAX_CERTIFICATES = 1024
PAGE_SIZE = 0x1000
USER_MODE_MODULES = frozenset({
    "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll", "combase.dll",
    "ws2_32.dll", "winhttp.dll", "wininet.dll", "ucrtbase.dll", "msvcrt.dll",
})


class DriverReportError(ValueError):
    """Input cannot be interpreted by this deliberately bounded PE reader."""


def _span(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise DriverReportError(f"{label} is truncated or outside the file")


def _u16(data: bytes, offset: int) -> int:
    _span(data, offset, 2, "16-bit field")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    _span(data, offset, 4, "32-bit field")
    return struct.unpack_from("<I", data, offset)[0]


def _power_of_two(value: int) -> bool:
    return value > 0 and not value & (value - 1)


def _external_gates() -> list[dict[str, str]]:
    return [
        {"id": "driver_project_and_workflows", "status": "unverified",
         "required_evidence": "Exact driver source/project, intended devices, OS matrix, and real host/device workflows."},
        {"id": "wdk_inf_catalog", "status": "unverified",
         "required_evidence": "Reproducible supported WDK build, INF validation, and complete driver package/catalog."},
        {"id": "microsoft_signing", "status": "unverified",
         "required_evidence": "Applicable Microsoft production signing and verified package/file trust on target Windows."},
        {"id": "hvci_runtime", "status": "unverified",
         "required_evidence": "Real driver workflows on clean target systems with Secure Boot and HVCI enabled; PE flags alone are insufficient."},
        {"id": "driver_verifier_hlk", "status": "unverified",
         "required_evidence": "Applicable Driver Verifier, CodeQL/WDK, and HLK results tied to exact release hashes on dedicated test systems."},
        {"id": "deployment_recovery", "status": "unverified",
         "required_evidence": "Install/update/uninstall, reboot, failure recovery, and device/power/IRQL/concurrency tests appropriate to this driver."},
    ]


class _PE:
    def __init__(self, data: bytes):
        self.data = data
        self.thunk_count = 0
        self.iat_ranges: list[tuple[int, int]] = []
        if len(data) > MAX_FILE_BYTES:
            raise DriverReportError("input exceeds the 256 MiB report limit")
        _span(data, 0, 64, "DOS header")
        if data[:2] != b"MZ":
            raise DriverReportError("missing DOS MZ signature")
        pe = _u32(data, 0x3C)
        if pe < 64:
            raise DriverReportError("PE header overlaps the DOS header")
        _span(data, pe, 24, "PE/COFF header")
        if data[pe:pe + 4] != b"PE\0\0":
            raise DriverReportError("missing PE signature")
        self.machine = _u16(data, pe + 4)
        count = _u16(data, pe + 6)
        if not 1 <= count <= MAX_SECTIONS:
            raise DriverReportError("section count is outside the supported 1..96 bound")
        self.characteristics = _u16(data, pe + 22)
        optional_size = _u16(data, pe + 20)
        optional = pe + 24
        _span(data, optional, optional_size, "optional header")
        if optional_size < 112 or _u16(data, optional) != 0x20B:
            raise DriverReportError("report requires a complete PE32+ optional header")
        self.image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        self.entry_rva = _u32(data, optional + 16)
        self.section_alignment = _u32(data, optional + 32)
        self.file_alignment = _u32(data, optional + 36)
        self.image_size = _u32(data, optional + 56)
        self.header_size = _u32(data, optional + 60)
        self.subsystem = _u16(data, optional + 68)
        self.dll_characteristics = _u16(data, optional + 70)
        for value, label in ((self.section_alignment, "section alignment"),
                             (self.file_alignment, "file alignment")):
            if not _power_of_two(value):
                raise DriverReportError(f"{label} is not a positive power of two")
        if self.file_alignment > 65536 or self.section_alignment < self.file_alignment:
            raise DriverReportError("invalid PE file/section alignment relationship")
        if self.section_alignment < PAGE_SIZE and self.file_alignment != self.section_alignment:
            raise DriverReportError("sub-page section alignment must equal file alignment")
        if self.section_alignment >= PAGE_SIZE and self.file_alignment < 512:
            raise DriverReportError("file alignment is below the PE minimum")
        dir_count = _u32(data, optional + 108)
        if dir_count > 16 or 112 + dir_count * 8 > optional_size:
            raise DriverReportError("data-directory count exceeds the optional header or supported bound")
        self.directories = [struct.unpack_from("<II", data, optional + 112 + i * 8)
                            for i in range(dir_count)]
        self.directories += [(0, 0)] * (16 - dir_count)
        section_table = optional + optional_size
        _span(data, section_table, count * 40, "section table")
        if self.header_size < section_table + count * 40 or self.header_size > len(data):
            raise DriverReportError("SizeOfHeaders does not contain the file headers")
        if (self.header_size % self.file_alignment or self.image_size < self.header_size
                or self.image_size % self.section_alignment):
            raise DriverReportError("invalid aligned header/image sizes")
        self.sections: list[dict[str, Any]] = []
        raw_ranges = [(0, self.header_size)]
        virtual_ranges = [(0, self.header_size)]
        for i in range(count):
            off = section_table + 40 * i
            name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", errors="backslashreplace")
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, off + 8)
            flags = _u32(data, off + 36)
            extent = max(virtual_size, raw_size)
            if rva % self.section_alignment:
                raise DriverReportError(f"section {i} RVA violates SectionAlignment")
            if not extent or rva + extent > self.image_size:
                raise DriverReportError(f"section {i} has an empty or out-of-image virtual range")
            if raw_size:
                _span(data, raw_offset, raw_size, f"section {i} raw data")
                if raw_offset % self.file_alignment or raw_size % self.file_alignment:
                    raise DriverReportError(f"section {i} raw range violates FileAlignment")
                raw_ranges.append((raw_offset, raw_offset + raw_size))
            virtual_ranges.append((rva, rva + extent))
            self.sections.append({
                "index": i, "name": name, "rva": rva, "virtual_size": virtual_size,
                "raw_offset": raw_offset, "raw_size": raw_size, "characteristics": flags,
                "readable": bool(flags & 0x40000000), "writable": bool(flags & 0x80000000),
                "executable": bool(flags & 0x20000000), "page_aligned": rva % PAGE_SIZE == 0,
            })
        for ranges, label in ((raw_ranges, "raw"), (virtual_ranges, "virtual")):
            ordered = sorted(ranges)
            if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
                raise DriverReportError(f"overlapping {label} section/header ranges")
        self.raw_end = max(end for _, end in raw_ranges)
        for index, (rva, size) in enumerate(self.directories):
            if index == 4:  # Security is a file offset, not an RVA.
                continue
            if index == 15 and (rva or size):
                raise DriverReportError("reserved data directory is nonzero")
            if bool(rva) != bool(size) and not (index == 8 and rva and not size):
                raise DriverReportError(f"data directory {index} has inconsistent RVA/size")
            if rva:
                self.map_rva(rva, max(size, 1), f"data directory {index}")

    def map_rva(self, rva: int, size: int, label: str) -> tuple[int, int]:
        if size < 1 or rva < 0 or rva + size > self.image_size:
            raise DriverReportError(f"{label} is outside the image")
        if rva < self.header_size and size <= self.header_size - rva:
            return rva, self.header_size - rva
        for section in self.sections:
            delta = rva - section["rva"]
            if delta >= 0 and delta < section["raw_size"] and size <= section["raw_size"] - delta:
                return section["raw_offset"] + delta, section["raw_size"] - delta
        raise DriverReportError(f"{label} has no complete file-backed RVA range")

    def string(self, rva: int, maximum: int, label: str) -> str:
        offset, available = self.map_rva(rva, 1, label)
        end = self.data.find(b"\0", offset, offset + min(available, maximum + 1))
        if end < 0 or end == offset:
            raise DriverReportError(f"{label} is empty, unterminated, or exceeds its bound")
        value = self.data[offset:end]
        if any(byte < 0x21 or byte > 0x7E for byte in value):
            raise DriverReportError(f"{label} contains non-printable/non-ASCII bytes")
        return value.decode("ascii")

    def thunks(self, lookup_rva: int, iat_rva: int, label: str) -> None:
        if not lookup_rva or not iat_rva:
            raise DriverReportError(f"{label} has no import lookup/address table")
        offset, available = self.map_rva(lookup_rva, 8, label)
        iat_offset, iat_available = self.map_rva(iat_rva, 8, label)
        limit = min(available // 8, iat_available // 8, MAX_IMPORT_THUNKS + 1)
        for i in range(limit):
            self.thunk_count += 1
            if self.thunk_count > MAX_IMPORT_THUNKS:
                raise DriverReportError("import thunks exceed the aggregate work bound")
            value = struct.unpack_from("<Q", self.data, offset + i * 8)[0]
            if not value:
                if struct.unpack_from("<Q", self.data, iat_offset + i * 8)[0]:
                    raise DriverReportError(f"{label} lookup/IAT termination differs")
                self.iat_ranges.append((iat_rva, (i + 1) * 8))
                return
            if value & (1 << 63):
                if value & ~((1 << 63) | 0xFFFF):
                    raise DriverReportError(f"{label} has a malformed ordinal thunk")
            else:
                self.map_rva(value, 3, f"{label} hint/name")
                self.string(value + 2, MAX_SYMBOL_NAME, f"{label} symbol")
        raise DriverReportError(f"{label} has no bounded thunk terminator")

    def imports(self, delayed: bool = False) -> list[str]:
        index, width = (13, 32) if delayed else (1, 20)
        rva, size = self.directories[index]
        if not rva:
            return []
        offset, _ = self.map_rva(rva, size, "import directory")
        modules = []
        limit = min(size // width, MAX_IMPORT_DESCRIPTORS + 1)
        for i in range(limit):
            fields = struct.unpack_from("<" + "I" * (width // 4), self.data, offset + i * width)
            if not any(fields):
                return modules
            if i == MAX_IMPORT_DESCRIPTORS:
                raise DriverReportError("import descriptors exceed the work bound")
            if delayed:
                attributes, name, _handle, iat, lookup, _bound, _unload, _timestamp = fields
                if attributes not in (0, 1):
                    raise DriverReportError("unsupported delay import attributes")
                if attributes == 0:
                    name, iat, lookup = (value - self.image_base if value else 0
                                         for value in (name, iat, lookup))
            else:
                lookup, _timestamp, _forwarder, name, iat = fields
                lookup = lookup or iat
            modules.append(self.string(name, MAX_MODULE_NAME, "import module"))
            self.thunks(lookup, iat, "delay import" if delayed else "import")
        raise DriverReportError("import directory has no bounded descriptor terminator")

    def certificates(self) -> dict[str, Any]:
        offset, size = self.directories[4]
        result: dict[str, Any] = {"present": bool(offset or size), "file_offset": offset,
                                  "size": size, "entries": [], "signature_verified": False,
                                  "trust_status": "unverified", "catalog_signature_checked": False}
        if not offset and not size:
            return result
        if not offset or not size or offset % 8 or size % 8 or offset < self.raw_end:
            raise DriverReportError("certificate table has an invalid offset, alignment, or overlap")
        _span(self.data, offset, size, "certificate table")
        cursor = offset
        while cursor < offset + size:
            if len(result["entries"]) >= MAX_CERTIFICATES:
                raise DriverReportError("certificate entries exceed the work bound")
            _span(self.data, cursor, 8, "certificate header")
            length, revision, kind = struct.unpack_from("<IHH", self.data, cursor)
            aligned_length = (length + 7) & ~7
            if length < 8 or aligned_length > offset + size - cursor:
                raise DriverReportError("certificate entry length exceeds the table")
            result["entries"].append({"length": length, "revision": revision, "type": kind})
            cursor += aligned_length
        return result


def analyze_bytes(data: bytes, *, filename: str) -> dict[str, Any]:
    """Report header-based candidacy, never proof of a valid or trusted driver."""
    pe = _PE(data)
    normal_imports = pe.imports()
    delay_imports = pe.imports(delayed=True)
    certificate = pe.certificates()
    managed = bool(pe.directories[14][0])
    if managed and pe.directories[14][1] < 72:
        raise DriverReportError("CLR header is truncated")
    classification = {
        "sys_extension": Path(filename).suffix.lower() == ".sys",
        "amd64": pe.machine == 0x8664, "pe32_plus": True,
        "native_subsystem": pe.subsystem == 1, "managed": managed,
        "executable_image": bool(pe.characteristics & 0x0002),
    }
    candidate = all(classification[key] for key in (
        "sys_extension", "amd64", "native_subsystem", "executable_image")) and not managed
    blockers: list[dict[str, str]] = []

    def block(code: str, message: str) -> None:
        blockers.append({"code": code, "message": message})

    if not candidate:
        block("not_amd64_native_driver_candidate", "Expected an unmanaged AMD64 PE32+ native-subsystem .sys executable image.")
    if not pe.dll_characteristics & 0x0100:
        block("nx_compat_absent", "NX_COMPAT header flag is absent; allocation/runtime NX policy is separately unverified.")
    if pe.section_alignment % PAGE_SIZE or any(not section["page_aligned"] for section in pe.sections):
        block("not_page_aligned", "Image sections are not aligned to 4096-byte pages.")
    for section in pe.sections:
        if section["writable"] and section["executable"]:
            block("writable_executable_section", f"Section {section['index']} ({section['name']}) is writable and executable.")
    for iat_rva, iat_size in set([pe.directories[12], *pe.iat_ranges]):
        if not iat_rva:
            continue
        for section in pe.sections:
            if (section["executable"] and iat_rva < section["rva"] + max(section["virtual_size"], section["raw_size"])
                    and iat_rva + iat_size > section["rva"]):
                if "executable_iat" not in {item["code"] for item in blockers}:
                    block("executable_iat", "An import address table overlaps an executable section.")
    known_user_imports = sorted({name for name in normal_imports + delay_imports
                               if (base := name.replace("\\", "/").rsplit("/", 1)[-1].lower()) in USER_MODE_MODULES
                               or base.startswith(("api-ms-win-", "ext-ms-win-", "vcruntime", "msvcp"))})
    if known_user_imports:
        block("user_mode_imports", "Known user-mode modules are imported: " + ", ".join(known_user_imports))
    if delay_imports:
        block("delay_imports_require_review", "Delay imports require driver-specific compatibility review; this tool does not validate a kernel delay loader.")
    if pe.entry_rva:
        pe.map_rva(pe.entry_rva, 1, "entry point")
        if not any(section["executable"] and section["rva"] <= pe.entry_rva
                   < section["rva"] + max(section["virtual_size"], section["raw_size"])
                   for section in pe.sections):
            block("entry_not_executable", "The nonzero entry point is not in an executable section.")
    block("kernel_packing_not_implemented", "Lethe kernel packing and kernel virtualization are NOT IMPLEMENTED; the user-mode stub is incompatible.")
    return {
        "schema": 1, "input": filename, "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "parsed": True,
        "production_ready": False, "kernel_packing_supported": False,
        "kernel_virtualization_supported": False,
        "classification": {**classification, "candidate": candidate,
                           "basis": "Header/extension classification only, not proof of a driver or loadability."},
        "pe": {"machine": pe.machine, "subsystem": pe.subsystem,
               "entry_rva": pe.entry_rva, "size_of_image": pe.image_size,
               "section_alignment": pe.section_alignment, "file_alignment": pe.file_alignment,
               "nx_compat_header": bool(pe.dll_characteristics & 0x0100),
               "dynamic_base_header": bool(pe.dll_characteristics & 0x0040), "sections": pe.sections},
        "imports": {"normal": normal_imports, "delay": delay_imports,
                    "known_user_mode": known_user_imports, "kernel_ddi_compatibility": "unverified"},
        "certificate_table": certificate, "blockers": blockers,
        "external_gates": _external_gates(),
        "limitations": ["Read-only structural checks; no instructions are executed or modified.",
                        "Static flags do not prove HVCI compatibility, driver correctness, trust, or production readiness.",
                        "Import denylist is not exhaustive; every module and DDI requires target-specific validation.",
                        "Certificate-table presence does not verify signatures; catalog signing is not inspected."],
    }


def report(path: Path) -> dict[str, Any]:
    """Read exactly one named regular file with a hard size limit."""
    if not stat.S_ISREG(path.stat().st_mode):
        raise DriverReportError("input must be a regular file")
    with path.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise DriverReportError("opened input must be a regular file")
        data = stream.read(MAX_FILE_BYTES + 1)
    return analyze_bytes(data, filename=str(path))


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise DriverReportError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Exact driver file to inspect; never a search path")
    try:
        args = parser.parse_args(argv)
        result = report(args.input.resolve())
    except (OSError, DriverReportError) as exc:
        print(json.dumps({"schema": 1, "parsed": False, "production_ready": False,
                          "kernel_packing_supported": False, "kernel_virtualization_supported": False,
                          "error": str(exc), "external_gates": _external_gates()}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1  # External gates and unimplemented kernel support are not success.


if __name__ == "__main__":
    sys.exit(main())
