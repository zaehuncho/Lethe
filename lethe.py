#!/usr/bin/env python3
"""Lethe -- command-line front-end for the custom x64 Windows PE packer.

This is one of two thin front-ends (CLI + PySide6 GUI) over the single core
function :func:`packer.orchestrator.pack_file`; both call the same API so they
never drift. Lethe is an internal build tool -- it *produces* protected
first-party binaries and is never shipped to customers.

Pipeline contract
-----------------
``tools/security/pack_lethe_release.py`` invokes any packer through a
``--packer-command "<cmd> {input} {output}"`` template. This CLI satisfies that
contract exactly::

    python lethe.py <input> <output>

``<input>`` is the PE to protect and ``<output>`` is the exact path the packed
PE must be written to (the pipeline then moves it into place and checks it is
non-empty). The process exits ``0`` on success and non-zero on failure, which is
what ``subprocess.run(..., check=True)`` in the pipeline relies on.

Usage
-----
    python lethe.py INPUT [OUTPUT]
                        [--dll] [--anti-debug {on,off}] [--memory-guard]
                        [--level N] [--verbose]

Runs both as ``python lethe.py ...`` from any working directory and when
frozen with Nuitka: the script's own directory is placed on ``sys.path`` so the
sibling ``packer/`` package imports cleanly in either mode.
"""
from __future__ import annotations

import argparse
import os
import sys

# --- import bootstrap ------------------------------------------------------
# lethe.py lives at lethe.py and the ``packer``
# package sits right beside it. Putting this script's directory at the front of
# sys.path makes ``import packer.orchestrator`` resolve whether we are launched
# as ``python lethe.py ...`` from an arbitrary cwd or from a Nuitka build.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)


# --- exit codes ------------------------------------------------------------
EXIT_OK = 0        # packing succeeded
EXIT_PACK_FAIL = 1  # pack_file ran but reported failure
EXIT_USAGE = 2      # bad arguments / missing input / core import failure


# ---------------------------------------------------------------------------
# formatting helpers
# ---------------------------------------------------------------------------

def _human_size(n: "int | None") -> str:
    """Render a byte count as a compact human-readable string."""
    if n is None:
        return "n/a"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            return f"{int(size)} B" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"  # unreachable, keeps type checkers happy


def _ratio_pct(original: "int | None", packed: "int | None") -> "float | None":
    """Packed size as a percentage of the original (packed / original * 100).

    Computed from the actual sizes so the reported number is unambiguous and
    independent of however ``PackResult.ratio`` happens to be scaled.
    """
    if original and original > 0 and packed is not None:
        return packed / original * 100.0
    return None


def _default_output(input_path: str) -> str:
    """CLI's own default output path: ``<input>.packed<ext>``.

    Kept here (rather than relying on the orchestrator's default) so the CLI's
    documented behaviour is honoured regardless of core internals.
    """
    base, ext = os.path.splitext(input_path)
    return f"{base}.packed{ext}"


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

def _level_type(value: str) -> int:
    try:
        level = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"level must be an integer 0-9, got {value!r}")
    if not 0 <= level <= 9:
        raise argparse.ArgumentTypeError(f"level must be between 0 and 9, got {level}")
    return level


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lethe",
        description="Lethe -- protect an x64 Windows PE (EXE or DLL) in place.",
        epilog="Pipeline drop-in: lethe.py {input} {output}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", help="path to the PE (EXE or DLL) to pack")
    parser.add_argument(
        "output",
        nargs="?",
        default=None,
        help="output path for the packed PE (default: <input>.packed<ext>)",
    )
    parser.add_argument(
        "--dll",
        action="store_true",
        help="force DLL packing (default: auto-detect from the PE header)",
    )
    parser.add_argument(
        "--anti-debug",
        choices=("on", "off"),
        default="on",
        help="gated, AV-clean anti-debug checks in the stub",
    )
    parser.add_argument(
        "--memory-guard",
        action="store_true",
        help="opt-in on-demand page decryption (test against your AV first)",
    )
    parser.add_argument(
        "--level",
        type=_level_type,
        default=9,
        metavar="N",
        help="deflate (zlib) compression level, 0-9",
    )
    parser.add_argument(
        "--server-shard",
        action="store_true",
        help="enable Tier 3 server key shard (requires --shard-url and --shard-auth)",
    )
    parser.add_argument(
        "--shard-url",
        default=None,
        metavar="URL",
        help="shard gate endpoint (e.g. https://api.zaeorion.com/api/shard)",
    )
    parser.add_argument(
        "--shard-auth",
        default=None,
        metavar="TOKEN",
        help="Bearer token for shard upload authentication",
    )
    parser.add_argument(
        "--shard-license-id",
        default=None,
        metavar="LICENSE",
        help="license this build's shard is bound to (required with --server-shard)",
    )
    parser.add_argument(
        "--shard-hwid-hash",
        default=None,
        metavar="HEX",
        help="SHA-256 hex of the target machine HWID (required with --server-shard)",
    )
    parser.add_argument(
        "--shard-max-activations",
        type=int,
        default=0,
        metavar="N",
        help="max shard retrievals for this build (0 = unlimited)",
    )
    parser.add_argument(
        "--shard-ttl-hours",
        type=int,
        default=0,
        metavar="H",
        help="hours until the shard expires server-side (0 = no expiry)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="stream stub/builder progress and print the raw result fields",
    )
    return parser


# ---------------------------------------------------------------------------
# summary rendering
# ---------------------------------------------------------------------------

def _print_summary(result, verbose: bool) -> None:
    ok = bool(getattr(result, "ok", False))
    input_path = getattr(result, "input_path", None)
    output_path = getattr(result, "output_path", None)
    original = getattr(result, "original_size", None)
    packed = getattr(result, "packed_size", None)
    elapsed = getattr(result, "elapsed_ms", None)

    if ok:
        print("Lethe: OK")
        if input_path:
            print(f"  input : {input_path}")
        if output_path:
            print(f"  output: {output_path}")
        pct = _ratio_pct(original, packed)
        size_line = f"  size  : {_human_size(original)} -> {_human_size(packed)}"
        if pct is not None:
            size_line += f"  ({pct:.1f}% of original, saved {100.0 - pct:.1f}%)"
        print(size_line)
        if elapsed is not None:
            print(f"  time  : {int(elapsed)} ms")
    else:
        print("Lethe: FAILED")
        if input_path:
            print(f"  input : {input_path}")
        error = getattr(result, "error", None) or "unknown error"
        print(f"  error : {error}")

    if verbose:
        print("  --- raw PackResult ---")
        for fieldname in (
            "input_path", "output_path", "ok", "error",
            "original_size", "packed_size", "ratio", "elapsed_ms",
        ):
            print(f"    {fieldname} = {getattr(result, fieldname, '<missing>')!r}")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)

    # Friendly pre-flight: a clear message beats a stack trace from the core.
    if not os.path.isfile(args.input):
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return EXIT_USAGE

    # Import the shared core lazily so sys.path (set above) is in effect and any
    # failure produces a clean message rather than a traceback at import time.
    try:
        from packer.orchestrator import PackOptions, pack_file
    except Exception as exc:  # noqa: BLE001 - report any import failure cleanly
        print(f"error: cannot import the Lethe core (packer.orchestrator): {exc}",
              file=sys.stderr)
        return EXIT_USAGE

    output_path = args.output if args.output else _default_output(args.input)

    options = PackOptions(
        anti_debug=(args.anti_debug == "on"),
        memory_guard=args.memory_guard,
        compression_level=args.level,
        output_path=output_path,
        is_dll=(True if args.dll else None),  # None => auto-detect from the header
        server_shard=args.server_shard,
        shard_url=args.shard_url,
        shard_auth=args.shard_auth,
        shard_license_id=args.shard_license_id,
        shard_hwid_hash=args.shard_hwid_hash,
        shard_max_activations=args.shard_max_activations,
        shard_ttl_hours=args.shard_ttl_hours,
    )

    def _progress(line: str) -> None:
        print(f"[pack] {line}", flush=True)

    try:
        result = pack_file(args.input, options, progress=_progress if args.verbose else None)
    except Exception as exc:  # noqa: BLE001 - never leak a traceback to the pipeline
        print("Lethe: FAILED")
        print(f"  input : {args.input}")
        print(f"  error : {exc}")
        return EXIT_PACK_FAIL

    _print_summary(result, args.verbose)
    return EXIT_OK if getattr(result, "ok", False) else EXIT_PACK_FAIL


if __name__ == "__main__":
    sys.exit(main())
