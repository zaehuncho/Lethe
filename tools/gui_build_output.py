"""Fresh-output and structural artifact checks for the GUI build recipe.

These checks do not execute the GUI, establish dependency closure, or authorize
a production release. A successful compiler exit alone is not an artifact.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packer.pe_content_id import parse_pe_image, snapshot_file


MAX_GUI_EXE_BYTES = 512 * 1024 * 1024


def _absolute_directory(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("GUI output directory must be an absolute, unambiguous path")
    return path


def _directory_info(path: Path, *, allow_missing: bool = False) -> os.stat_result | None:
    result = None
    for current in (path, *path.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            if current == path and not allow_missing:
                raise ValueError("GUI output directory is missing") from None
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("GUI output directory cannot traverse a link or reparse point")
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("GUI output path must traverse directories only")
        if current == path:
            result = info
    return result


def _identity(info: os.stat_result) -> str:
    if not info.st_ino:
        raise ValueError("GUI output directory has no usable filesystem identity")
    return f"{info.st_dev}:{info.st_ino}"


def prepare_output_directory(output_dir: str | Path) -> dict:
    """Allocate a new build root; never reuse, clean, or overwrite an old one."""
    root = _absolute_directory(output_dir)
    if _directory_info(root, allow_missing=True) is not None:
        raise ValueError("GUI output directory already exists; choose a new output directory")
    root.parent.mkdir(parents=True, exist_ok=True)
    _directory_info(root.parent)
    # mkdir without exist_ok atomically refuses an existing leaf, including a
    # competing build that wins the allocation race.
    root.mkdir()
    return {"output_dir": str(root), "identity": _identity(_directory_info(root))}


def verify_build_output(output_dir: str | Path, *, identity: str, layout: str) -> dict:
    """Check the expected newly-built AMD64 GUI EXE without executing it."""
    root = _absolute_directory(output_dir)
    if type(identity) is not str or not re.fullmatch(r"[0-9]+:[1-9][0-9]*", identity):
        raise ValueError("invalid GUI output directory identity")
    if layout not in {"onefile", "standalone"}:
        raise ValueError("invalid GUI build layout")
    if _identity(_directory_info(root)) != identity:
        raise ValueError("GUI output directory identity changed during compilation")
    # gui/app.py -> app.dist under the locked Nuitka build shape. Changing
    # --output-filename changes the EXE basename, not the .dist directory.
    executable = root / ("app.dist/Lethe.exe" if layout == "standalone" else "Lethe.exe")
    parent_identity = _identity(_directory_info(executable.parent))
    image = snapshot_file(executable, what="GUI executable", reject_hardlinks=True,
                          max_bytes=MAX_GUI_EXE_BYTES)
    info = parse_pe_image(image.data, label="GUI executable")
    pe_offset = struct.unpack_from("<I", image.data, 0x3C)[0]
    characteristics = struct.unpack_from("<H", image.data, pe_offset + 22)[0]
    optional_header = pe_offset + 24
    if info.subject_kind != "exe" or not characteristics & 0x0002:
        raise ValueError("GUI output must be an executable image, not a DLL")
    if struct.unpack_from("<H", image.data, optional_header + 0x44)[0] != 2:
        raise ValueError("GUI executable must use the Windows GUI subsystem")
    entry = struct.unpack_from("<I", image.data, optional_header + 0x10)[0]
    image_size = struct.unpack_from("<I", image.data, optional_header + 0x38)[0]
    optional_size = struct.unpack_from("<H", image.data, pe_offset + 20)[0]
    section_count = struct.unpack_from("<H", image.data, pe_offset + 6)[0]
    entry_backed = False
    for index in range(section_count):
        section = optional_header + optional_size + index * 40
        virtual_size, rva, raw_size = struct.unpack_from("<III", image.data, section + 8)
        flags = struct.unpack_from("<I", image.data, section + 36)[0]
        span = min(raw_size, virtual_size or raw_size)
        if flags & 0x20000000 and rva <= entry < rva + span:
            entry_backed = True
    if not 0 < entry < image_size or not entry_backed:
        raise ValueError("GUI executable entry point must have executable file-backed code")
    if _identity(_directory_info(root)) != identity:
        raise ValueError("GUI output directory identity changed during verification")
    if _identity(_directory_info(executable.parent)) != parent_identity:
        raise ValueError("GUI executable parent identity changed during verification")
    return {"schema": 1, "kind": "lethe-gui-build-output", "layout": layout,
            "executable": str(executable), "size": image.size, "sha256": image.sha256,
            "output_identity": identity, "validation": "structural-only"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--output-dir", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--output-dir", required=True)
    verify.add_argument("--identity", required=True)
    verify.add_argument("--layout", choices=("onefile", "standalone"), required=True)
    args = parser.parse_args(argv)
    try:
        result = (prepare_output_directory(args.output_dir) if args.command == "prepare"
                  else verify_build_output(args.output_dir, identity=args.identity, layout=args.layout))
    except (OSError, ValueError) as exc:
        print(f"GUI build output {args.command} failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
