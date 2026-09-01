#!/usr/bin/env python3
"""Compile and fingerprint every declared Daedalus handler-body variant.

The audit compiles the real ``stub/src/daedalus_vm.c`` translation unit with
the release MSVC optimizer.  Each alternative profile changes exactly one
handler while keeping the opcode map and all other handlers fixed.  Function
bytes are extracted from their COFF COMDAT sections and relocation-covered
fields are zeroed before hashing, so link addresses cannot create fake
diversity.

Exit status is zero only when every declared variant has a distinct normalized
machine body.  Native compilation is intentionally opt-in from pytest; invoke
this tool directly for a release gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from daedalus import shuffle_opcodes  # noqa: E402


_FIXED_MAPPING_SEED = bytes.fromhex("4080" * 16)
_AMD64_RELOCATION_WIDTHS = {
    0x0001: 8,  # IMAGE_REL_AMD64_ADDR64
    0x0002: 4,  # IMAGE_REL_AMD64_ADDR32
    0x0003: 4,  # IMAGE_REL_AMD64_ADDR32NB
    0x0004: 4,  # IMAGE_REL_AMD64_REL32
    0x0005: 4,  # IMAGE_REL_AMD64_REL32_1
    0x0006: 4,  # IMAGE_REL_AMD64_REL32_2
    0x0007: 4,  # IMAGE_REL_AMD64_REL32_3
    0x0008: 4,  # IMAGE_REL_AMD64_REL32_4
    0x0009: 4,  # IMAGE_REL_AMD64_REL32_5
    0x000A: 2,  # IMAGE_REL_AMD64_SECTION
    0x000B: 4,  # IMAGE_REL_AMD64_SECREL
    0x000E: 4,  # IMAGE_REL_AMD64_SREL32
    0x0010: 4,  # IMAGE_REL_AMD64_SSPAN32
}


class HandlerShapeAuditError(RuntimeError):
    pass


@dataclass(frozen=True)
class MsvcCompiler:
    command: str
    vcvars64: Path | None = None

    def invoke(self, arguments: Iterable[str], *, work: Path) -> list[str]:
        args = [self.command, *arguments]
        if self.vcvars64 is None:
            return args
        wrapper = work / "invoke-msvc.cmd"
        wrapper.write_text(
            "@echo off\r\n"
            f'call "{self.vcvars64}" >nul\r\n'
            "if errorlevel 1 exit /b %errorlevel%\r\n"
            f"{subprocess.list2cmdline(args)}\r\n",
            encoding="ascii",
        )
        return ["cmd.exe", "/d", "/c", str(wrapper)]


@dataclass(frozen=True)
class CoffBody:
    symbol: str
    raw: bytes
    normalized: bytes
    relocation_count: int

    def report(self, variant: int) -> dict[str, object]:
        return {
            "variant": variant,
            "size_bytes": len(self.raw),
            "relocation_count": self.relocation_count,
            "raw_sha256": hashlib.sha256(self.raw).hexdigest(),
            "normalized_sha256": hashlib.sha256(self.normalized).hexdigest(),
        }


@dataclass(frozen=True)
class _CoffSection:
    raw_offset: int
    raw_size: int
    relocation_offset: int
    relocation_count: int


def find_msvc() -> MsvcCompiler | None:
    direct = shutil.which("cl.exe")
    if direct:
        return MsvcCompiler(direct)

    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return None
    probe = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if probe.returncode != 0 or not probe.stdout.strip():
        return None
    vcvars64 = Path(probe.stdout.strip()) / "VC/Auxiliary/Build/vcvars64.bat"
    if not vcvars64.is_file():
        return None
    return MsvcCompiler("cl.exe", vcvars64)


def _coff_name(raw_name: bytes, string_table: bytes) -> str:
    if raw_name[:4] == b"\0\0\0\0":
        offset = struct.unpack_from("<I", raw_name, 4)[0]
        if offset < 4 or offset >= len(string_table):
            raise HandlerShapeAuditError("COFF symbol has an invalid string-table offset")
        end = string_table.find(b"\0", offset)
        if end < 0:
            raise HandlerShapeAuditError("COFF symbol string is not terminated")
        return string_table[offset:end].decode("ascii", errors="strict")
    return raw_name.split(b"\0", 1)[0].decode("ascii", errors="strict")


def _normalized_relocations(
    body: bytes,
    *,
    symbol_value: int,
    relocations: Iterable[tuple[int, int]],
) -> bytes:
    normalized = bytearray(body)
    for virtual_address, relocation_type in relocations:
        width = _AMD64_RELOCATION_WIDTHS.get(relocation_type)
        if width is None:
            raise HandlerShapeAuditError(
                f"unsupported AMD64 COFF relocation type 0x{relocation_type:04x}"
            )
        relative = virtual_address - symbol_value
        if relative < 0 or relative + width > len(normalized):
            continue
        normalized[relative:relative + width] = b"\0" * width
    return bytes(normalized)


def extract_coff_body(object_path: Path, symbol: str) -> CoffBody:
    data = object_path.read_bytes()
    if len(data) < 20:
        raise HandlerShapeAuditError(f"truncated COFF object: {object_path}")
    machine, section_count, _timestamp, symbol_offset, symbol_count, optional_size, _ = (
        struct.unpack_from("<HHIIIHH", data, 0)
    )
    if machine != 0x8664:
        raise HandlerShapeAuditError(
            f"expected AMD64 COFF object, found machine 0x{machine:04x}"
        )
    section_table_offset = 20 + optional_size
    if section_table_offset + section_count * 40 > len(data):
        raise HandlerShapeAuditError("truncated COFF section table")
    sections: list[_CoffSection] = []
    for index in range(section_count):
        offset = section_table_offset + index * 40
        raw_size, raw_offset, relocation_offset = struct.unpack_from("<III", data, offset + 16)
        relocation_count = struct.unpack_from("<H", data, offset + 32)[0]
        sections.append(
            _CoffSection(raw_offset, raw_size, relocation_offset, relocation_count)
        )

    symbol_table_end = symbol_offset + symbol_count * 18
    if symbol_offset == 0 or symbol_table_end + 4 > len(data):
        raise HandlerShapeAuditError("COFF object has no valid symbol table")
    string_size = struct.unpack_from("<I", data, symbol_table_end)[0]
    if string_size < 4 or symbol_table_end + string_size > len(data):
        raise HandlerShapeAuditError("invalid COFF string table")
    string_table = data[symbol_table_end:symbol_table_end + string_size]

    found: tuple[int, int] | None = None
    index = 0
    while index < symbol_count:
        offset = symbol_offset + index * 18
        raw_name = data[offset:offset + 8]
        value, section_number, _type = struct.unpack_from("<IhH", data, offset + 8)
        auxiliary_count = data[offset + 17]
        if _coff_name(raw_name, string_table) == symbol:
            if section_number <= 0 or section_number > len(sections):
                raise HandlerShapeAuditError(
                    f"COFF symbol {symbol!r} has no concrete section"
                )
            found = (section_number - 1, value)
            break
        index += 1 + auxiliary_count
    if found is None:
        raise HandlerShapeAuditError(f"COFF symbol {symbol!r} was not emitted")

    section_index, symbol_value = found
    section = sections[section_index]
    raw_end = section.raw_offset + section.raw_size
    if raw_end > len(data) or symbol_value > section.raw_size:
        raise HandlerShapeAuditError(f"invalid section bounds for COFF symbol {symbol!r}")
    body = data[section.raw_offset + symbol_value:raw_end]
    relocations: list[tuple[int, int]] = []
    for relocation_index in range(section.relocation_count):
        offset = section.relocation_offset + relocation_index * 10
        if offset + 10 > len(data):
            raise HandlerShapeAuditError("truncated COFF relocation table")
        virtual_address, _symbol_index, relocation_type = struct.unpack_from(
            "<IIH", data, offset
        )
        relocations.append((virtual_address, relocation_type))
    normalized = _normalized_relocations(
        body,
        symbol_value=symbol_value,
        relocations=relocations,
    )
    return CoffBody(symbol, body, normalized, len(relocations))


def _profile_header(profile: Mapping[str, int]) -> str:
    result = shuffle_opcodes.generate_shuffle(_FIXED_MAPPING_SEED)
    result["handler_variants"] = OrderedDict(
        (name, int(profile[name])) for name in shuffle_opcodes.HANDLER_VARIANT_COUNTS
    )
    result["handler_variant_sha256"] = shuffle_opcodes.handler_variant_sha256(
        result["handler_variants"]
    )
    errors = shuffle_opcodes.verify_shuffle(result)
    if errors:
        raise HandlerShapeAuditError("invalid audit profile: " + "; ".join(errors))
    return shuffle_opcodes.emit_c_header(result)


def _compile_profile(
    compiler: MsvcCompiler,
    work: Path,
    profile: Mapping[str, int],
    tag: str,
) -> Path:
    profile_dir = work / tag
    profile_dir.mkdir()
    (profile_dir / "daedalus_opcodes_shuffled.h").write_text(
        _profile_header(profile), encoding="ascii"
    )
    object_path = profile_dir / "daedalus_vm.obj"
    arguments = [
        "/nologo",
        "/c",
        "/TC",
        "/W4",
        "/WX",
        "/GS-",
        "/Oi",
        "/O2",
        "/Ob2",
        "/Gy",
        "/DNDEBUG",
        "/DDVM_SHUFFLED",
        "/DDVM_PAGED_RUNTIME",
        f"/I{profile_dir}",
        f"/I{ROOT / 'stub' / 'src'}",
        f"/I{ROOT / 'cipher'}",
        f"/Fo{object_path}",
        str(ROOT / "stub" / "src" / "daedalus_vm.c"),
    ]
    compiled = subprocess.run(
        compiler.invoke(arguments, work=profile_dir),
        cwd=str(profile_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=180,
    )
    if compiled.returncode != 0:
        raise HandlerShapeAuditError(
            f"MSVC failed for handler profile {tag}:\n{compiled.stdout}"
        )
    if not object_path.is_file():
        raise HandlerShapeAuditError(f"MSVC emitted no object for handler profile {tag}")
    return object_path


def run_audit(compiler: MsvcCompiler | None = None) -> dict[str, object]:
    compiler = compiler or find_msvc()
    if compiler is None:
        raise HandlerShapeAuditError("release MSVC x64 compiler was not found")

    names = tuple(shuffle_opcodes.HANDLER_VARIANT_COUNTS)
    baseline = OrderedDict((name, 0) for name in names)
    compiled_profiles: dict[tuple[str, int], Path] = {}
    profile_reports: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="lethe-handler-shape-") as raw_work:
        work = Path(raw_work)
        baseline_object = _compile_profile(compiler, work, baseline, "baseline")
        compiled_profiles.update({(name, 0): baseline_object for name in names})
        baseline_dispatch = extract_coff_body(baseline_object, "dvm_run")
        baseline_dispatch_hash = hashlib.sha256(
            baseline_dispatch.normalized
        ).hexdigest()
        dispatch_hashes = {(name, 0): baseline_dispatch_hash for name in names}
        profile_reports.append({
            "profile": "baseline",
            "dvm_run_normalized_sha256": baseline_dispatch_hash,
        })

        for name, count in shuffle_opcodes.HANDLER_VARIANT_COUNTS.items():
            for variant in range(1, count):
                profile = OrderedDict(baseline)
                profile[name] = variant
                tag = f"{name}-{variant}"
                object_path = _compile_profile(compiler, work, profile, tag)
                compiled_profiles[name, variant] = object_path
                dispatch = extract_coff_body(object_path, "dvm_run")
                dispatch_hash = hashlib.sha256(dispatch.normalized).hexdigest()
                dispatch_hashes[name, variant] = dispatch_hash
                profile_reports.append({
                    "profile": tag,
                    "dvm_run_normalized_sha256": dispatch_hash,
                })

        handler_reports: list[dict[str, object]] = []
        for name, count in shuffle_opcodes.HANDLER_VARIANT_COUNTS.items():
            variants = []
            for variant in range(count):
                body_report = extract_coff_body(
                    compiled_profiles[name, variant], f"dvm_sem_{name}"
                ).report(variant)
                body_report["dvm_run_normalized_sha256"] = dispatch_hashes[name, variant]
                variants.append(body_report)
            body_hashes = {entry["normalized_sha256"] for entry in variants}
            integrated_hashes = {
                entry["dvm_run_normalized_sha256"] for entry in variants
            }
            handler_reports.append({
                "handler": name,
                "declared_variant_count": count,
                "effective_unique_variant_count": len(body_hashes),
                "integrated_unique_variant_count": len(integrated_hashes),
                "distinct": (
                    len(body_hashes) == count and len(integrated_hashes) == count
                ),
                "variants": variants,
            })

    ok = all(bool(handler["distinct"]) for handler in handler_reports)
    aggregate = hashlib.sha256()
    for handler in handler_reports:
        aggregate.update(str(handler["handler"]).encode("ascii"))
        for variant in handler["variants"]:
            aggregate.update(str(variant["normalized_sha256"]).encode("ascii"))
    return {
        "schema": 1,
        "ok": ok,
        "compiler": compiler.command,
        "normalization": "zero relocation-covered fields in exact COFF COMDAT bodies",
        "handler_code_sha256": aggregate.hexdigest(),
        "handlers": handler_reports,
        "compiled_profiles": profile_reports,
    }


def _print_report(report: Mapping[str, object]) -> None:
    print("Daedalus compiled handler-shape audit")
    print(f"handler code profile: {report['handler_code_sha256']}")
    for handler in report["handlers"]:
        state = "PASS" if handler["distinct"] else "FAIL"
        print(
            f"{state:4} {handler['handler']:<7} "
            f"body={handler['effective_unique_variant_count']}/"
            f"{handler['declared_variant_count']} "
            f"dispatch={handler['integrated_unique_variant_count']}/"
            f"{handler['declared_variant_count']}"
        )
        for variant in handler["variants"]:
            print(
                f"       v{variant['variant']}: {variant['size_bytes']:>3} bytes  "
                f"{variant['normalized_sha256']}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit stable JSON")
    args = parser.parse_args(argv)
    try:
        report = run_audit()
    except HandlerShapeAuditError as exc:
        print(f"handler-shape audit error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_report(report)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
