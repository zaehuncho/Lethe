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
                        [--anti-debug {on,off}] [--memory-guard]
                        [--process-hardening] [--level N] [--verbose]

The release-supported input is an unmanaged x64 EXE. DLL and server-shard
paths require explicit experimental acknowledgments and are not release-ready.

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


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"value must be a non-negative integer, got {value!r}")
    if parsed < 0:
        raise argparse.ArgumentTypeError(
            f"value must be non-negative, got {parsed}")
    return parsed


def _virtualization_spec(value: str) -> tuple[str, int, int]:
    parts = value.split(":")
    if len(parts) != 3 or not parts[0].strip():
        raise argparse.ArgumentTypeError(
            "function must use NAME:RVA:SIZE (for example Init:0x1200:64)")

    def _integer(label: str, token: str) -> int:
        token = token.strip()
        base = 16 if token.lower().startswith("0x") else 10
        try:
            return int(token, base)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"function {label} must be decimal or 0x-prefixed hexadecimal")

    name = parts[0].strip()
    rva = _integer("RVA", parts[1])
    size = _integer("size", parts[2])
    if len(name) > 128 or "\0" in name:
        raise argparse.ArgumentTypeError("function name must be 1..128 characters")
    if rva < 0 or size < 5 or rva + size > 0x1_0000_0000:
        raise argparse.ArgumentTypeError(
            "function RVA/size must describe a 5-byte-or-larger uint32 RVA range")
    return name, rva, size


def _virtualization_integer(label: str, token: str) -> int:
    token = token.strip()
    base = 16 if token.lower().startswith("0x") else 10
    try:
        parsed = int(token, base)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{label} must be decimal or 0x-prefixed hexadecimal")
    if parsed <= 0 or parsed >= 0x1_0000_0000:
        raise argparse.ArgumentTypeError(
            f"{label} must be a nonzero uint32 value")
    return parsed


def _virtualization_gap(value: str) -> tuple[int, int, str]:
    parts = value.split(":", 2)
    if len(parts) != 3 or not parts[2].strip() or "\0" in parts[2]:
        raise argparse.ArgumentTypeError(
            "gap must use RVA:SIZE:RATIONALE with a nonempty rationale")
    rva = _virtualization_integer("gap RVA", parts[0])
    size = _virtualization_integer("gap size", parts[1])
    if rva + size > 0x1_0000_0000:
        raise argparse.ArgumentTypeError("gap RVA and size exceed the uint32 RVA space")
    return rva, size, parts[2].strip()


def _virtualization_tail_exit(value: str) -> tuple[int, int, int, str]:
    parts = value.split(":", 3)
    if len(parts) != 4 or not parts[3].strip() or "\0" in parts[3]:
        raise argparse.ArgumentTypeError(
            "tail exit must use "
            "FUNCTION_RVA:INSTRUCTION_RVA:TARGET_RVA:RATIONALE")
    return (
        _virtualization_integer("tail-exit function RVA", parts[0]),
        _virtualization_integer("tail-exit instruction RVA", parts[1]),
        _virtualization_integer("tail-exit target RVA", parts[2]),
        parts[3].strip(),
    )


def _validate_cli_virtualization_specs(
        raw_specs: list[tuple[str, int, int]]) -> tuple[tuple[str, int, int], ...]:
    names: set[str] = set()
    starts: set[int] = set()
    ordered = sorted(raw_specs, key=lambda item: item[1])
    for name, rva, _size in ordered:
        if name in names or rva in starts:
            raise ValueError(
                f"duplicate --virtualize-function name or entry RVA: {name!r}")
        names.add(name)
        starts.add(rva)
    for left, right in zip(ordered, ordered[1:]):
        if left[1] + left[2] > right[1]:
            raise ValueError(
                f"overlapping --virtualize-function ranges: {left[0]!r} and "
                f"{right[0]!r}")
    return tuple(ordered)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lethe",
        description="Lethe -- protect an unmanaged x64 Windows executable.",
        epilog="Pipeline drop-in: lethe.py {input} {output}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", help="path to the unmanaged x64 PE to pack")
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
        "--enable-experimental-dll",
        action="store_true",
        help=("explicitly acknowledge the unsupported DLL loader-lock path; "
              "never use for a release build"),
    )
    parser.add_argument(
        "--anti-debug",
        choices=("on", "off"),
        default="off",
        help="experimental anti-debug checks (off until acceptance-tested)",
    )
    parser.add_argument(
        "--memory-guard",
        action="store_true",
        help="EXPERIMENTAL opt-in page guard (not release-approved)",
    )
    parser.add_argument(
        "--process-hardening",
        action="store_true",
        help=("opt in to irreversible EXE process mitigations and restricted "
              "default DLL search directories"),
    )
    parser.add_argument(
        "--level",
        type=_level_type,
        default=9,
        metavar="N",
        help="zlib/deflate compression level, 0-9",
    )
    parser.add_argument(
        "--server-shard",
        action="store_true",
        help=("request the EXPERIMENTAL server shard path; also requires "
              "--enable-experimental-server-shard"),
    )
    parser.add_argument(
        "--enable-experimental-server-shard",
        action="store_true",
        help=("explicitly acknowledge the unapproved bootstrap/protocol/TLS path; "
              "never use for a release build"),
    )
    parser.add_argument(
        "--shard-url",
        default=None,
        metavar="URL",
        help="experimental shard gate base URL",
    )
    parser.add_argument(
        "--shard-auth",
        default=None,
        metavar="TOKEN",
        help=("Bearer token for shard upload authentication; prefer the "
              "LETHE_SHARD_AUTH environment variable to avoid argv exposure"),
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
        type=_nonnegative_int,
        default=0,
        metavar="N",
        help="max shard retrievals for this build (0 = unlimited)",
    )
    parser.add_argument(
        "--shard-ttl-hours",
        type=_nonnegative_int,
        default=0,
        metavar="H",
        help="hours until the shard expires server-side (0 = no expiry)",
    )
    parser.add_argument(
        "--shard-pin-pem",
        default=None,
        metavar="PATH",
        help=("pinned shard-gate leaf/CA PEM; falls back to "
              "LETHE_SHARD_PIN_PEM"),
    )
    parser.add_argument(
        "--allow-unpinned-host",
        action="store_true",
        help="allow a non-production shard host (staging only)",
    )
    parser.add_argument(
        "--stub-path",
        default=None,
        metavar="PATH",
        help="override the prebuilt native stub (CI/release validation)",
    )
    parser.add_argument(
        "--virtualize-function",
        action="append",
        type=_virtualization_spec,
        default=[],
        metavar="NAME:RVA:SIZE",
        help=("explicit whole function to virtualize; repeatable, with decimal "
              "or 0x-prefixed RVA/size"),
    )
    parser.add_argument(
        "--enable-experimental-virtualization",
        action="store_true",
        help=("acknowledge the experimental explicit-function virtualization "
              "path; requires --stub-path and --virtualize-function"),
    )
    parser.add_argument(
        "--virtualization-gap",
        action="append",
        type=_virtualization_gap,
        default=[],
        metavar="RVA:SIZE:RATIONALE",
        help=("acknowledge one exact executable coverage gap; repeatable, and "
              "does not prove the gap contains no entry references"),
    )
    parser.add_argument(
        "--virtualization-tail-exit",
        action="append",
        type=_virtualization_tail_exit,
        default=[],
        metavar="FUNCTION_RVA:INSTRUCTION_RVA:TARGET_RVA:RATIONALE",
        help="approve one exact selected-function direct JMP tail edge",
    )
    parser.add_argument(
        "--acknowledge-unproven-indirect-targets",
        action="store_true",
        help=("acknowledge that indirect and address-taken target closure remains "
              "unproven; required for selected-function virtualization"),
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
            delta = abs(100.0 - pct)
            change = f"saved {delta:.1f}%" if pct <= 100.0 else f"grew {delta:.1f}%"
            size_line += f"  ({pct:.1f}% of original, {change})"
        print(size_line)
        if elapsed is not None:
            print(f"  time  : {int(elapsed)} ms")
        build_id = getattr(result, "build_id", None)
        if build_id:
            print(f"  build : {build_id}")
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
            "original_size", "packed_size", "ratio", "elapsed_ms", "build_id",
        ):
            print(f"    {fieldname} = {getattr(result, fieldname, '<missing>')!r}")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def main(
    argv: "list[str] | None" = None,
    *,
    _allow_unverified_stub_for_tests: bool = False,
) -> int:
    args = build_parser().parse_args(argv)

    # Friendly pre-flight: a clear message beats a stack trace from the core.
    if not os.path.isfile(args.input):
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return EXIT_USAGE
    if args.dll and not args.enable_experimental_dll:
        print("error: --dll requires --enable-experimental-dll; DLL packing is "
              "not release-approved", file=sys.stderr)
        return EXIT_USAGE
    if args.server_shard and not args.enable_experimental_server_shard:
        print("error: --server-shard requires "
              "--enable-experimental-server-shard; remote shard packing is not "
              "release-approved", file=sys.stderr)
        return EXIT_USAGE
    if args.enable_experimental_server_shard and not args.server_shard:
        print("error: --enable-experimental-server-shard requires --server-shard",
              file=sys.stderr)
        return EXIT_USAGE
    if args.virtualize_function and not args.enable_experimental_virtualization:
        print("error: --virtualize-function requires "
              "--enable-experimental-virtualization", file=sys.stderr)
        return EXIT_USAGE
    if args.enable_experimental_virtualization and not args.virtualize_function:
        print("error: --enable-experimental-virtualization requires at least one "
              "--virtualize-function", file=sys.stderr)
        return EXIT_USAGE
    if args.virtualize_function and not args.stub_path:
        print("error: --virtualize-function requires an explicit fresh "
              "--stub-path", file=sys.stderr)
        return EXIT_USAGE
    if ((args.virtualization_gap or args.virtualization_tail_exit
         or args.acknowledge_unproven_indirect_targets)
            and not args.virtualize_function):
        print("error: virtualization proof acknowledgements require at least one "
              "--virtualize-function", file=sys.stderr)
        return EXIT_USAGE
    if (args.virtualize_function
            and not args.acknowledge_unproven_indirect_targets):
        print("error: --virtualize-function requires "
              "--acknowledge-unproven-indirect-targets", file=sys.stderr)
        return EXIT_USAGE
    try:
        virtualization_specs = _validate_cli_virtualization_specs(
            args.virtualize_function)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # Import the shared core lazily so sys.path (set above) is in effect and any
    # failure produces a clean message rather than a traceback at import time.
    try:
        from packer.orchestrator import (
            PackOptions,
            VirtualizationGapAcknowledgement,
            VirtualizationSpec,
            VirtualizationTailExitApproval,
            pack_file,
        )
    except Exception as exc:  # noqa: BLE001 - report any import failure cleanly
        print(f"error: cannot import the Lethe core (packer.orchestrator): {exc}",
              file=sys.stderr)
        return EXIT_USAGE

    output_path = args.output if args.output else _default_output(args.input)

    options = PackOptions(
        anti_debug=(args.anti_debug == "on"),
        memory_guard=args.memory_guard,
        process_hardening=args.process_hardening,
        compression_level=args.level,
        output_path=output_path,
        is_dll=(True if args.dll else None),  # None => auto-detect from the header
        server_shard=args.server_shard,
        shard_url=args.shard_url,
        shard_auth=(args.shard_auth or os.environ.get("LETHE_SHARD_AUTH")),
        shard_license_id=args.shard_license_id,
        shard_hwid_hash=args.shard_hwid_hash,
        shard_max_activations=args.shard_max_activations,
        shard_ttl_hours=args.shard_ttl_hours,
        allow_unpinned_host=args.allow_unpinned_host,
        shard_pin_pem=(args.shard_pin_pem
                       or os.environ.get("LETHE_SHARD_PIN_PEM")),
        stub_path=args.stub_path,
        virtualization_specs=tuple(
            VirtualizationSpec(name, rva, size)
            for name, rva, size in virtualization_specs
        ),
        virtualization_gap_acknowledgements=tuple(
            VirtualizationGapAcknowledgement(rva, size, rationale)
            for rva, size, rationale in args.virtualization_gap
        ),
        virtualization_tail_exit_approvals=tuple(
            VirtualizationTailExitApproval(
                function_rva, instruction_rva, target_rva, rationale)
            for function_rva, instruction_rva, target_rva, rationale
            in args.virtualization_tail_exit
        ),
        acknowledge_unproven_indirect_targets=(
            args.acknowledge_unproven_indirect_targets
        ),
        _allow_unverified_stub_for_tests=_allow_unverified_stub_for_tests,
    )

    def _progress(line: str) -> None:
        print(f"[pack] {line}", flush=True)

    feature_env = {
        "LETHE_ENABLE_EXPERIMENTAL_DLL": args.enable_experimental_dll,
        "LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD":
            args.enable_experimental_server_shard,
        "LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION":
            args.enable_experimental_virtualization,
    }
    previous_env = {name: os.environ.get(name) for name in feature_env}
    try:
        # CLI callers must use the named acknowledgment flags even if their
        # parent process happens to have one of the core API gates set.
        for name, enabled in feature_env.items():
            if enabled:
                os.environ[name] = "1"
            else:
                os.environ.pop(name, None)
        result = pack_file(args.input, options, progress=_progress if args.verbose else None)
    except Exception as exc:  # noqa: BLE001 - never leak a traceback to the pipeline
        print("Lethe: FAILED")
        print(f"  input : {args.input}")
        print(f"  error : {exc}")
        return EXIT_PACK_FAIL
    finally:
        for name, previous in previous_env.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous

    _print_summary(result, args.verbose)
    return EXIT_OK if getattr(result, "ok", False) else EXIT_PACK_FAIL


if __name__ == "__main__":
    sys.exit(main())
