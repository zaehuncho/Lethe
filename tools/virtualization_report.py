#!/usr/bin/env python3
"""Read-only function discovery and virtualization lift-coverage report."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import os
from pathlib import Path
import stat
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
    try:
        if os.path.samefile(left, right):
            return True
    except (OSError, ValueError):
        pass
    return os.path.normcase(os.path.realpath(os.path.abspath(left))) == \
        os.path.normcase(os.path.realpath(os.path.abspath(right)))


def _is_reparse_path(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if getattr(metadata, "st_file_attributes", 0) & reparse_flag:
        return True
    is_junction = getattr(path, "is_junction", None)
    try:
        return bool(is_junction and is_junction())
    except OSError:
        return True


def _reject_reparse_chain(path: Path, label: str) -> None:
    current = path.absolute()
    while True:
        if os.path.lexists(current) and _is_reparse_path(current):
            raise ValueError(f"{label} cannot use a symlink, junction, or reparse path")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _validate_output_path(path: str, label: str) -> Path:
    if not isinstance(path, str) or not path or "\0" in path:
        raise ValueError(f"{label} path is invalid")
    target = Path(path).absolute()
    _reject_reparse_chain(target, label)
    if not target.parent.is_dir():
        raise ValueError(f"{label} parent directory does not exist")
    if os.path.lexists(target):
        metadata = os.lstat(target)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular file path")
    return target


def _validate_identity_aliases(
    input_path: str,
    map_path: str | None,
    report_path: str | None,
    manifest_path: str | None,
) -> None:
    paths = [
        ("input", input_path),
        ("linker MAP", map_path),
        ("report", report_path),
        ("selection manifest", manifest_path),
    ]
    for left_index, (left_label, left_path) in enumerate(paths):
        if not left_path:
            continue
        for right_label, right_path in paths[left_index + 1:]:
            if right_path and _same_path(left_path, right_path):
                raise ValueError(
                    f"{left_label} and {right_label} paths must identify "
                    "different files")


def _snapshot_identity(value) -> tuple[object, ...]:
    return (
        value.sha256,
        value.size,
        value.device,
        value.inode,
        value.link_count,
        value.mtime_ns,
        value.ctime_ns,
    )


def _relocated_snapshot_identity(value) -> tuple[object, ...]:
    return (
        value.sha256,
        value.size,
        value.device,
        value.inode,
        value.link_count,
        value.mtime_ns,
    )


def _assert_source_current(path: str, expected, label: str = "inspected PE") -> None:
    current = snapshot_file(path, what=label)
    if _snapshot_identity(current) != _snapshot_identity(expected):
        raise ValueError(
            f"{label} path or content changed while the report was generated")


@dataclass
class _Publication:
    label: str
    target: Path
    data: bytes
    previous: object | None = None
    staged: Path | None = None
    staged_snapshot: object | None = None
    backup: Path | None = None
    backup_reservation: object | None = None
    backup_snapshot: object | None = None
    installed_snapshot: object | None = None
    keep_backup: bool = False


def _write_exclusive_sibling(target: Path, data: bytes, purpose: str) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        prefix=f".lethe-{purpose}-", suffix=".tmp", dir=str(target.parent))
    path = Path(raw_path)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return path
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _prepare_publications(
        values: list[tuple[str, str, bytes]]) -> list[_Publication]:
    publications: list[_Publication] = []
    try:
        for label, raw_target, data in values:
            target = _validate_output_path(raw_target, label)
            previous = None
            if os.path.lexists(target):
                previous = snapshot_file(target, what=label)
            publication = _Publication(label, target, data, previous=previous)
            publications.append(publication)
            publication.staged = _write_exclusive_sibling(
                target, data, f"{label.replace(' ', '-')}-new")
            publication.staged_snapshot = snapshot_file(
                publication.staged, what=f"staged {label}")
            if previous is not None:
                publication.backup = _write_exclusive_sibling(
                    target, b"", f"{label.replace(' ', '-')}-backup")
                publication.backup_reservation = snapshot_file(
                    publication.backup, what=f"reserved {label} backup")
        return publications
    except BaseException:
        _cleanup_publications(publications)
        raise


def _assert_target_current(publication: _Publication) -> None:
    _validate_output_path(str(publication.target), publication.label)
    if publication.previous is None:
        if os.path.lexists(publication.target):
            raise ValueError(f"{publication.label} appeared before publication")
        return
    current = snapshot_file(publication.target, what=publication.label)
    if _snapshot_identity(current) != _snapshot_identity(publication.previous):
        raise ValueError(f"{publication.label} changed before publication")


def _assert_snapshot_current(path: Path | None, expected, label: str) -> None:
    if path is None or expected is None:
        raise ValueError(f"{label} is unavailable")
    current = snapshot_file(path, what=label)
    if _snapshot_identity(current) != _snapshot_identity(expected):
        raise ValueError(f"{label} changed before publication")


def _matches_snapshot(path: Path, expected) -> bool:
    try:
        current = snapshot_file(path, what="publication rollback file")
    except (OSError, ValueError):
        return False
    return _snapshot_identity(current) == _snapshot_identity(expected)


def _matches_relocated_snapshot(path: Path, expected) -> bool:
    try:
        current = snapshot_file(path, what="relocated publication file")
    except (OSError, ValueError):
        return False
    return _relocated_snapshot_identity(current) == \
        _relocated_snapshot_identity(expected)


def _matches_filesystem_object(path: Path, expected) -> bool:
    try:
        current = snapshot_file(path, what="publication filesystem object")
    except (OSError, ValueError):
        return False
    return bool(
        expected is not None
        and current.inode
        and expected.inode
        and (current.device, current.inode) == (expected.device, expected.inode)
    )


def _assert_relocated_snapshot_current(
        path: Path | None, expected, label: str) -> None:
    if path is None or expected is None:
        raise ValueError(f"{label} is unavailable")
    current = snapshot_file(path, what=label)
    if (_relocated_snapshot_identity(current)
            != _relocated_snapshot_identity(expected)):
        raise ValueError(f"{label} changed before publication")


def _capture_relocated_snapshot(path: Path | None, expected, label: str):
    if path is None or expected is None:
        raise ValueError(f"{label} is unavailable")
    current = snapshot_file(path, what=label)
    if (_relocated_snapshot_identity(current)
            != _relocated_snapshot_identity(expected)):
        raise ValueError(f"{label} changed before publication")
    return current


def _assert_target_absent(publication: _Publication) -> None:
    _validate_output_path(str(publication.target), publication.label)
    if os.path.lexists(publication.target):
        raise ValueError(f"{publication.label} appeared before publication")


def _cleanup_publications(publications: list[_Publication]) -> None:
    for publication in publications:
        for path in (publication.staged, publication.backup):
            if path is not None:
                if path == publication.backup and publication.keep_backup:
                    continue
                try:
                    path.unlink()
                except OSError:
                    pass


def _commit_publications(publications: list[_Publication]) -> None:
    touched: list[_Publication] = []
    try:
        for publication in publications:
            touched.append(publication)
            _assert_snapshot_current(
                publication.staged,
                publication.staged_snapshot,
                f"staged {publication.label}",
            )
            if publication.previous is not None:
                _assert_snapshot_current(
                    publication.backup,
                    publication.backup_reservation,
                    f"reserved {publication.label} backup",
                )
                _assert_target_current(publication)
                assert publication.backup is not None
                os.replace(publication.target, publication.backup)
                publication.backup_snapshot = _capture_relocated_snapshot(
                    publication.backup,
                    publication.previous,
                    f"original {publication.label} backup",
                )
                _assert_snapshot_current(
                    publication.staged,
                    publication.staged_snapshot,
                    f"staged {publication.label}",
                )
                _assert_target_absent(publication)
            else:
                _assert_target_current(publication)
            assert publication.staged is not None
            os.replace(publication.staged, publication.target)
            publication.installed_snapshot = _capture_relocated_snapshot(
                publication.target,
                publication.staged_snapshot,
                f"installed {publication.label}",
            )
            publication.staged = None
        for publication in publications:
            _assert_snapshot_current(
                publication.target,
                publication.installed_snapshot,
                f"installed {publication.label}",
            )
    except BaseException as publish_error:
        rollback_errors = []
        for publication in reversed(touched):
            try:
                target_exists = os.path.lexists(publication.target)
                target_is_staged = bool(
                    target_exists
                    and publication.staged_snapshot is not None
                    and _matches_filesystem_object(
                        publication.target, publication.staged_snapshot))
                if publication.previous is None:
                    if target_is_staged:
                        publication.target.unlink()
                    elif target_exists:
                        raise RuntimeError(
                            f"{publication.label} changed during rollback")
                    continue

                assert publication.backup is not None
                backup_is_original = bool(
                    publication.backup_snapshot is not None
                    and _matches_snapshot(
                        publication.backup, publication.backup_snapshot))
                target_is_original = bool(
                    target_exists
                    and _matches_filesystem_object(
                        publication.target, publication.previous))
                if backup_is_original:
                    if target_exists and not target_is_staged:
                        publication.keep_backup = True
                        raise RuntimeError(
                            f"{publication.label} changed during rollback; "
                            f"original retained at {publication.backup}")
                    publication.keep_backup = True
                    _assert_snapshot_current(
                        publication.backup,
                        publication.backup_snapshot,
                        f"original {publication.label} backup",
                    )
                    os.replace(publication.backup, publication.target)
                    _assert_relocated_snapshot_current(
                        publication.target,
                        publication.backup_snapshot,
                        f"restored {publication.label}",
                    )
                    publication.keep_backup = False
                    publication.backup = None
                elif not target_is_original:
                    if (os.path.lexists(publication.backup)
                            and not _matches_snapshot(
                                publication.backup,
                                publication.backup_reservation)):
                        publication.keep_backup = True
                    recovery = (
                        f"; recoverable object retained at {publication.backup}"
                        if publication.keep_backup else ""
                    )
                    raise RuntimeError(
                        f"original {publication.label} is unavailable during "
                        f"rollback{recovery}")
            except BaseException as rollback_error:
                rollback_errors.append(
                    f"{publication.label}: {rollback_error}")
        if rollback_errors:
            raise RuntimeError(
                f"publication failed ({publish_error}); rollback failed "
                f"({'; '.join(rollback_errors)})") from publish_error
        raise
    finally:
        _cleanup_publications(publications)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    snapshot_path = None
    try:
        _validate_identity_aliases(
            args.input, args.map_path, args.output,
            args.emit_selection_manifest)
        if args.output:
            _validate_output_path(args.output, "report output")
        if args.emit_selection_manifest:
            _validate_output_path(
                args.emit_selection_manifest, "selection manifest output")
        source = snapshot_file(args.input, what="inspected PE")
        map_source = (
            snapshot_file(args.map_path, what="linker MAP")
            if args.map_path else None
        )
        suffix = os.path.splitext(args.input)[1]
        descriptor, snapshot_path = tempfile.mkstemp(
            prefix=".lethe-virtualization-report-", suffix=suffix)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(source.data)
            stream.flush()
            os.fsync(stream.fileno())
        parsed = pe_analyze.analyze_pe(snapshot_path)
        map_text = (
            map_source.data.decode("utf-8-sig") if map_source is not None
            else None
        )
        report = function_discovery.discover_functions(
            parsed, map_text=map_text, leaf_cap=args.leaf_cap
        )
        report = replace(report, image_path=os.path.abspath(args.input))
        rendered = (
            report.to_json() if args.format == "json"
            else function_discovery.render_table(report)
        )
        rendered_bytes = rendered.encode("utf-8")
        selection = None
        if args.emit_selection_manifest:
            selection_report = (
                function_discovery.discover_functions(
                    parsed, leaf_cap=args.leaf_cap)
                if map_source is not None else report
            )
            selection = canonical_json(build_manifest(
                selection_report,
                parsed,
                source_sha256=source.sha256,
                source_pe_content_id=pe_content_id(snapshot_path),
            ))
        pending = []
        if args.output:
            pending.append(("report output", args.output, rendered_bytes))
        if args.emit_selection_manifest:
            assert selection is not None
            pending.append((
                "selection manifest output",
                args.emit_selection_manifest,
                selection,
            ))
        publications = _prepare_publications(pending)
        try:
            _assert_source_current(args.input, source)
            if map_source is not None:
                _assert_source_current(
                    args.map_path, map_source, "linker MAP")
            _validate_identity_aliases(
                args.input, args.map_path, args.output,
                args.emit_selection_manifest)
            _commit_publications(publications)
        finally:
            _cleanup_publications(publications)
        if not args.output:
            sys.stdout.write(rendered)
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
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
