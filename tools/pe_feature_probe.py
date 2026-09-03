#!/usr/bin/env python3
"""Emit the PE features exercised by Lethe's native compatibility corpus."""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packer import pe_analyze


DIR_DELAY_IMPORT = 13
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000


def _directory(data: bytes, index: int) -> tuple[int, int]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("input has no DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe_offset + 24
    if optional + 112 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("input has no bounded PE header")
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("input is not PE32+")
    directory_count = struct.unpack_from("<I", data, optional + 108)[0]
    if index >= directory_count:
        return 0, 0
    offset = optional + 112 + index * 8
    if offset + 8 > len(data):
        raise ValueError("data-directory table is truncated")
    return struct.unpack_from("<II", data, offset)


def probe(path: Path) -> dict[str, Any]:
    parsed = pe_analyze.analyze_pe(str(path))
    config = parsed.load_config
    return {
        "schema": 1,
        "path": str(path),
        "kind": "dll" if parsed.is_dll else "exe",
        "image_base": parsed.image_base,
        "size_of_image": parsed.size_of_image,
        "dynamic_base": bool(
            parsed.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        ),
        "nx_compat": bool(
            parsed.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        ),
        "guard_cf_header": bool(
            parsed.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF
        ),
        "normal_import_dlls": len(parsed.imports),
        "dir64_relocations": len(parsed.dir64_relocations),
        "runtime_functions": len(parsed.runtime_functions),
        "has_tls": parsed.has_tls,
        "resource_rva": parsed.rsrc_rva,
        "resource_bytes": len(parsed.rsrc_bytes),
        "resource_directory_rva": parsed.rsrc_directory_rva,
        "resource_directory_size": parsed.rsrc_directory_size,
        "resource_directory_offset": (
            parsed.rsrc_directory_rva - parsed.rsrc_rva
            if parsed.rsrc_directory_rva else 0
        ),
        "delay_import_rva": parsed.delay_import_rva,
        "delay_import_size": parsed.delay_import_size,
        "has_delay_imports": bool(
            parsed.delay_import_rva and parsed.delay_import_size),
        "has_load_config": config is not None,
        "load_config": None
        if config is None
        else {
            "directory_rva": config.directory_rva,
            "directory_size": config.directory_size,
            "guard_flags": config.guard_flags,
            "has_guard_cf": config.has_guard_cf,
            "guard_cf_targets": len(config.guard_cf_targets),
            "address_taken_iat_targets": len(config.guard_address_taken_iat_entries),
            "long_jump_targets": len(config.guard_long_jump_targets),
            "eh_continuation_targets": len(config.guard_eh_continuation_targets),
            "xfg_present": config.xfg_present,
            "unsupported_features": list(config.unsupported_features),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args(argv)
    try:
        result = probe(args.input.resolve())
    except (OSError, ValueError) as exc:
        print(json.dumps({"schema": 1, "ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **result}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
