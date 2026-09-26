#!/usr/bin/env python3
"""
generate_programs.py -- emit daedalus_programs_shuffled.h at build time.

The Daedalus VM's ``daedalus_programs.h`` carries hand-written bytecode blobs for
``DVM_PROG_DERIVE_KEY`` and ``DVM_PROG_SHARD_XOR`` encoded with the CANONICAL
opcode map. When ``DVM_SHUFFLE_OPCODES=ON`` (the default) the interpreter is
built to dispatch a per-build randomized map, so the canonical bytecode would
be misinterpreted and every packed binary would fail its first crypto call.

This generator closes that loop: it assembles the ``.vasm`` sources in
``programs/`` with the current build's shuffled opcode map and emits a
drop-in header exposing the same public symbols. ``daedalus_programs.h``
conditionally ``#include``s this file when ``DVM_SHUFFLED`` is defined.

Runs once per configure/build (CMake custom command; depends on the
shuffled-opcode file so a fresh shuffle triggers a re-assembly).

Usage:
    python generate_programs.py \\
        --shuffled-map daedalus_opcodes_shuffled.py \\
        --programs-dir programs \\
        --output daedalus_programs_shuffled.h
"""
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


# Public symbol names emitted by ``daedalus_programs.h``. Each maps to the
# ``.vasm`` source that replaces it under a shuffled opcode map. The list is
# deliberately explicit — silently emitting extra programs would drift from
# what daedalus_programs.h exposes.
PROGRAMS = [
    ("DVM_PROG_DERIVE_KEY", "derive_key.vasm"),
    ("DVM_PROG_SHARD_XOR",  "shard_xor.vasm"),
]


def _load_asm(daedalus_dir: Path):
    """Import daedalus_asm from the sibling dir (it's not an installed package)."""
    if str(daedalus_dir) not in sys.path:
        sys.path.insert(0, str(daedalus_dir))
    import daedalus_asm  # type: ignore
    return daedalus_asm


def _load_shuffled_map(path: Path):
    spec = importlib.util.spec_from_file_location("_dvm_shuffled", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.SHUFFLED_OPCODES


def _mutate_master(shuffled_map_path: Path) -> bytes:
    """Per-build master seed for the mutation engine, deterministic from the
    build's opcode shuffle (unique per build since the shuffle is per build)."""
    import hashlib
    return hashlib.sha256(
        b"daedalus-mutate-master-v1|" + shuffled_map_path.read_bytes()
    ).digest()


def _assemble(vasm_path: Path, shuffled_map: dict, daedalus_asm,
              mba: bool = True, *, mutate_master: bytes | None = None,
              mutate_level: int = 0, symbol: str | None = None) -> bytes:
    source = vasm_path.read_text(encoding="utf-8")
    if mba:
        # Solver-hostile arithmetic: rewrite arithmetic into MBA expansions (and,
        # at higher levels, seeded substitution + junk) BEFORE assembly (proven
        # semantics-preserving by tests/test_mba.py and tests/test_mutate.py).
        # DEFAULT level 0 == the historical fixed MBA expansion, byte-for-byte
        # identical to the pre-metamorphism pipeline.
        import daedalus_mutate
        seed = None
        if mutate_level > 0 and mutate_master is not None and symbol is not None:
            from metamorph_seed import MetamorphSeed, DOMAIN_MBA
            seed = MetamorphSeed(mutate_master).subseed_for_program(
                DOMAIN_MBA, symbol
            )
        source = daedalus_mutate.mutate_source(
            source, seed=seed, level=mutate_level
        )
    blob = daedalus_asm.assemble(source, opcodes=shuffled_map)
    return bytes(blob)


def _shuffled_optable(shuffled_map: dict) -> dict:
    """Invert mnemonic->(byte,width,kind) to byte->(mnemonic,width,kind) so the
    rolling encoder can decode the wire (shuffled) bytecode's boundaries."""
    out = {}
    for mnem, (byte, width, kind) in shuffled_map.items():
        out[byte] = (mnem, width, kind)
    return out


def _derive_seed(shuffled_map_path: Path, sym: str, version: str = "v1") -> bytes:
    """Per-build, per-program 16-byte rolling seed, deterministic from the
    build's opcode shuffle (unique per build since the shuffle is per build).
    The version tag domain-separates v1 ('VR') from v2 ('VS') seeds."""
    import hashlib
    base = shuffled_map_path.read_bytes()
    return hashlib.sha256(
        b"daedalus-rolling-" + version.encode() + b"|" + base + b"|" + sym.encode()
    ).digest()[:16]


def _format_c_array(name: str, data: bytes) -> str:
    lines = [f"static const uint8_t {name}[] = {{"]
    for i in range(0, len(data), 12):
        chunk = data[i:i + 12]
        row = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"    {row},")
    lines.append("};")
    lines.append(f"static const uint32_t {name}_SIZE = sizeof({name});")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--shuffled-map", required=True, type=Path,
                    help="Path to daedalus_opcodes_shuffled.py")
    ap.add_argument("--programs-dir", required=True, type=Path,
                    help="Directory containing the .vasm source programs")
    ap.add_argument("--output", required=True, type=Path,
                    help="Path to write daedalus_programs_shuffled.h")
    rolling_grp = ap.add_mutually_exclusive_group()
    rolling_grp.add_argument("--rolling", action="store_true",
                    help="Emit history-keyed rolling ('VR') containers "
                         "(requires the stub built with -DDVM_ROLLING=ON)")
    rolling_grp.add_argument("--rolling-v2", action="store_true",
                    help="Emit v2 whole-program-chained rolling ('VS') containers "
                         "(requires the stub built with -DDVM_ROLLING_V2=ON). "
                         "Mutually exclusive with --rolling; both imply the "
                         "shuffled optable.")
    ap.add_argument("--whiten", default="",
                    help="Optional 16-byte (32 hex chars) v2 whiten, XORed into "
                         "the effective seed. Default (empty) = zero whiten, which "
                         "is what the shipped stub decodes with; nonzero is for "
                         "differential testing only.")
    ap.add_argument("--no-mba", action="store_true",
                    help="Disable the MBA arithmetic rewrite (on by default)")
    ap.add_argument("--mutate-level", type=int, default=0,
                    help="Metamorphic mutation intensity (0=byte-identical "
                         "legacy MBA; 1=seeded MBA; 2=+subst/junk; 3=+recursion)")
    args = ap.parse_args()

    daedalus_dir = Path(__file__).resolve().parent
    daedalus_asm = _load_asm(daedalus_dir)
    shuffled_map = _load_shuffled_map(args.shuffled_map)
    mba = not args.no_mba
    mutate_level = args.mutate_level
    mutate_master = _mutate_master(args.shuffled_map) if mutate_level > 0 else None
    rolling_any = args.rolling or args.rolling_v2
    optable = _shuffled_optable(shuffled_map) if rolling_any else None
    if args.rolling_v2:
        whiten = bytes.fromhex(args.whiten) if args.whiten else b"\x00" * 16
        if len(whiten) != 16:
            print("error: --whiten must be 16 bytes (32 hex chars)", file=sys.stderr)
            return 1

    header = [
        "/* daedalus_programs_shuffled.h -- generated by generate_programs.py.",
        " *",
        " * DO NOT EDIT. Re-emitted on every build with the shuffled opcode map.",
        " * If DVM_SHUFFLE_OPCODES is OFF, this file is not included; the",
        " * hand-written canonical bytecode in daedalus_programs.h is used instead.",
        " */",
        "#pragma once",
        "#include <stdint.h>",
        "",
    ]

    for sym, filename in PROGRAMS:
        vasm_path = args.programs_dir / filename
        if not vasm_path.is_file():
            print(f"error: {vasm_path} not found", file=sys.stderr)
            return 1
        blob = _assemble(vasm_path, shuffled_map, daedalus_asm, mba=mba,
                         mutate_master=mutate_master, mutate_level=mutate_level,
                         symbol=sym)
        note = ("MBA" if mba else "plain")
        if mba and mutate_level > 0:
            note = f"mutate-L{mutate_level}"
        if args.rolling_v2:
            import daedalus_rolling
            seed = _derive_seed(args.shuffled_map, sym, version="v2")
            blob = daedalus_rolling.pack_rolling_blob_v2(
                blob, seed, whiten=whiten, optable=optable)
            note += "+rolling-v2"
        elif args.rolling:
            import daedalus_rolling
            seed = _derive_seed(args.shuffled_map, sym)
            blob = daedalus_rolling.pack_rolling_blob(blob, seed, optable=optable)
            note += "+rolling"
        header.append(f"/* {sym}: assembled from {filename} "
                      f"({note}, {len(blob)} bytes) */")
        header.append(_format_c_array(sym, blob))
        header.append("")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(header), encoding="utf-8")
    print(f"generate_programs: wrote {args.output} "
          f"({len(PROGRAMS)} programs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
