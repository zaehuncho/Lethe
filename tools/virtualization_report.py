#!/usr/bin/env python3
"""Read-only function discovery and virtualization lift-coverage report."""
from __future__ import annotations

import argparse
from dataclasses import replace
import os
import sys
import tempfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from lifter import function_discovery  # noqa: E402
from packer import pe_analyze  # noqa: E402
from packer.pe_content_id import pe_content_id, snapshot_file  # noqa: E402
from packer.virtualization_selection import (  # noqa: E402
    build_manifest,
    canonical_json,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect exact PE function ranges and report current virtualization "
            "lift coverage without packing or modifying the input"
        )
    )
    parser.add_argument("input", help="unmanaged AMD64 PE to inspect")
    parser.add_argument("--map", dest="map_path", help="optional MSVC linker MAP")
    parser.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="report rendering mode",
    )
    parser.add_argument("--output", help="write the report to this path")
    parser.add_argument(
        "--leaf-cap", type=int, default=function_discovery.DEFAULT_LEAF_CAP,
        help="maximum bytes for heuristic exported-leaf decoding",
    )
    parser.add_argument(
        "--emit-selection-manifest", metavar="PATH",
        help=("write a starter manifest of liftable exact non-handler ranges; "
              "never invokes the packer"),
    )
    return parser


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.realpath(os.path.abspath(left))) == \
        os.path.normcase(os.path.realpath(os.path.abspath(right)))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    snapshot_path = None
    try:
        write_targets = [
            path for path in (args.output, args.emit_selection_manifest) if path
        ]
        if any(_same_path(args.input, path) for path in write_targets):
            raise ValueError("report output must not overwrite the inspected PE")
        if len(write_targets) == 2 and _same_path(*write_targets):
            raise ValueError("report and selection outputs must use different paths")
        source = snapshot_file(args.input, what="inspected PE")
        suffix = os.path.splitext(args.input)[1]
        descriptor, snapshot_path = tempfile.mkstemp(
            prefix=".lethe-virtualization-report-", suffix=suffix)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(source.data)
            stream.flush()
            os.fsync(stream.fileno())
        parsed = pe_analyze.analyze_pe(snapshot_path)
        map_text = None
        if args.map_path:
            with open(args.map_path, "r", encoding="utf-8-sig") as stream:
                map_text = stream.read()
        report = function_discovery.discover_functions(
            parsed, map_text=map_text, leaf_cap=args.leaf_cap
        )
        report = replace(report, image_path=os.path.abspath(args.input))
        rendered = (
            report.to_json() if args.format == "json"
            else function_discovery.render_table(report)
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
        else:
            sys.stdout.write(rendered)
        if args.emit_selection_manifest:
            selection = canonical_json(build_manifest(
                report,
                parsed,
                source_sha256=source.sha256,
                source_pe_content_id=pe_content_id(snapshot_path),
            ))
            with open(
                args.emit_selection_manifest, "wb"
            ) as stream:
                stream.write(selection)
                stream.flush()
                os.fsync(stream.fileno())
        current = snapshot_file(args.input, what="inspected PE")
        if current.sha256 != source.sha256 or current.size != source.size:
            raise ValueError("inspected PE changed while the report was generated")
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if snapshot_path is not None:
            try:
                os.remove(snapshot_path)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
