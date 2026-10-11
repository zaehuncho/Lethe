#!/usr/bin/env python3
"""Build a constrained Lethe shipping bundle from a verified candidate stub.

This profile is intentionally narrower than the full public-release gate.  It
packs unmanaged AMD64 EXEs and DLLs with the stable base container while keeping
anti-debug, memory guard, process hardening, tamper monitoring, server shards, and selected-function
virtualization disabled.  The output is a transactional directory containing
the packed files and a hash manifest.  Product-specific runtime testing and
Authenticode signing still happen after packing. Exported EXEs require a
matching export-capable stub; early dependency-to-EXE callbacks are unsupported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packer import orchestrator, pe_analyze, release_attestation, report  # noqa: E402
from packer import pe_content_id  # noqa: E402


PROFILE_ID = "lethe-limited-v1"
MANIFEST_NAME = "lethe-limited-release.json"
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


class LimitedReleaseError(RuntimeError):
    """The constrained bundle could not be created."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class _FileSnapshot:
    device: int
    inode: int
    size: int
    modified_ns: int
    link_count: int
    sha256: str


def _plain_path(path: Path, label: str) -> Path:
    """Check the supplied spelling before resolve() can erase an alias."""
    path = path.absolute()
    try:
        pe_content_id._reject_linklike_ancestors(path, label)
    except (OSError, ValueError) as exc:
        raise LimitedReleaseError(f"{label} changed or traverses a link: {path}: {exc}") from exc
    return path


def _snapshot(path: Path, label: str) -> _FileSnapshot:
    """Bind a regular, unlinked file's identity and bytes at a checkpoint."""
    def identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_nlink

    try:
        path = _plain_path(path, label)
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise LimitedReleaseError(f"{label} changed or is not a regular file: {path}")
        if before.st_nlink != 1:
            raise LimitedReleaseError(f"{label} must not be hard-linked: {path}")
        digest = hashlib.sha256()
        # Windows holds a read-only sharing handle; POSIX uses O_NOFOLLOW.
        # Do not grow a whole-file buffer just to compute a checkpoint digest.
        with pe_content_id._open_snapshot_stream(path, label) as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(before):
                raise LimitedReleaseError(f"{label} changed while opening: {path}")
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
            after_read = os.fstat(stream.fileno())
        _plain_path(path, label)
        after = path.lstat()
        if (path.is_symlink() or not stat.S_ISREG(after.st_mode)
                or identity(after_read) != identity(before)
                or identity(after) != identity(before)):
            raise LimitedReleaseError(f"{label} changed while hashing: {path}")
    except (OSError, ValueError) as exc:
        raise LimitedReleaseError(f"{label} changed or became inaccessible: {path}: {exc}") from exc
    return _FileSnapshot(*identity(before), digest.hexdigest())


def _require_snapshot(path: Path, expected: _FileSnapshot, label: str) -> None:
    if _snapshot(path, label) != expected:
        raise LimitedReleaseError(f"{label} changed before publication: {path}")


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


@contextmanager
def _dll_gate(enabled: bool) -> Iterator[None]:
    name = "LETHE_ENABLE_EXPERIMENTAL_DLL"
    previous = os.environ.get(name)
    try:
        if enabled:
            os.environ[name] = "1"
        else:
            os.environ.pop(name, None)
        yield
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def _inputs(args: argparse.Namespace) -> list[tuple[str, Path]]:
    rows = [*(('exe', Path(value)) for value in args.exe),
            *(('dll', Path(value)) for value in args.dll)]
    if not rows:
        raise LimitedReleaseError("at least one --exe or --dll input is required")

    normalized: list[tuple[str, Path]] = []
    output_names: set[str] = set()
    identities: set[tuple[int, int]] = set()
    for kind, raw_path in rows:
        absolute = _plain_path(raw_path.expanduser(), f"{kind.upper()} input")
        if absolute.is_symlink() or not absolute.is_file():
            raise LimitedReleaseError(f"{kind.upper()} input is missing or linked: {absolute}")
        path = absolute.resolve()
        stat = path.stat()
        identity = (int(stat.st_dev), int(stat.st_ino))
        if identity in identities:
            raise LimitedReleaseError(f"input is repeated: {path}")
        identities.add(identity)
        folded_name = path.name.casefold()
        if folded_name == MANIFEST_NAME.casefold():
            raise LimitedReleaseError(f"input filename is reserved for the bundle manifest: {path.name}")
        if folded_name in output_names:
            raise LimitedReleaseError(
                f"output filename collision for {path.name!r}; rename one input first"
            )
        output_names.add(folded_name)
        try:
            detected_dll = orchestrator.detect_is_dll(str(path))
        except (OSError, ValueError) as exc:
            raise LimitedReleaseError(f"cannot inspect {path}: {exc}") from exc
        if detected_dll != (kind == "dll"):
            detected = "DLL" if detected_dll else "EXE"
            raise LimitedReleaseError(
                f"{path} was supplied as {kind.upper()} but its PE header is {detected}"
            )
        if kind == "exe":
            try:
                parsed = pe_analyze.analyze_pe(str(path))
            except (OSError, ValueError) as exc:
                raise LimitedReleaseError(f"cannot preflight EXE {path}: {exc}") from exc
            if bool(parsed.export_directory_rva) != bool(parsed.export_directory_size):
                raise LimitedReleaseError(
                    f"incomplete EXE export directory geometry: {path}"
                )
        normalized.append((kind, path))
    return normalized


def _candidate(stub_path: Path) -> tuple[Path, dict[str, Any]]:
    raw = _plain_path(stub_path.expanduser(), "candidate stub")
    if raw.is_symlink() or not raw.is_file():
        raise LimitedReleaseError(f"candidate stub is missing or linked: {raw}")
    path = raw.resolve()
    try:
        manifest = release_attestation.validate_candidate_identity(path)
    except (OSError, release_attestation.ReleaseAttestationError) as exc:
        raise LimitedReleaseError(f"candidate stub validation failed: {exc}") from exc
    return path, manifest


def build_bundle(args: argparse.Namespace) -> Path:
    destination = _plain_path(Path(args.output_dir).expanduser(), "output directory")
    if destination.exists() or destination.is_symlink():
        raise LimitedReleaseError(f"output directory already exists: {destination}")
    stub_path, candidate_manifest = _candidate(Path(args.stub_path))
    candidate_snapshot = _snapshot(stub_path, "candidate stub")
    candidate_stub_sha256 = candidate_snapshot.sha256
    candidate_manifest_path = release_attestation.candidate_manifest_path(stub_path)
    candidate_manifest_snapshot = _snapshot(candidate_manifest_path, "candidate manifest")
    candidate_manifest_sha256 = candidate_manifest_snapshot.sha256
    inputs = _inputs(args)
    source_snapshots = {
        source: _snapshot(source, "source") for _kind, source in inputs
    }

    destination_parent = destination.parent.resolve()
    destination_parent.mkdir(parents=True, exist_ok=True)
    stage = destination_parent / f".{destination.name}.stage-{uuid.uuid4().hex}"
    stage.mkdir()

    artifacts: list[dict[str, Any]] = []
    output_snapshots: dict[Path, _FileSnapshot] = {}
    try:
        for kind, source in inputs:
            packed = stage / source.name
            original = source_snapshots[source]
            _require_snapshot(source, original, "source")
            source_sha256 = original.sha256
            source_size = original.size
            options = orchestrator.PackOptions(
                anti_debug=False,
                memory_guard=False,
                process_hardening=False,
                tamper_monitor=False,
                compression_level=args.compression_level,
                output_path=str(packed),
                is_dll=(kind == "dll"),
                server_shard=False,
                stub_path=str(stub_path),
            )
            with _dll_gate(kind == "dll"):
                result = orchestrator.pack_file(str(source), options)
            if not result.ok:
                raise LimitedReleaseError(
                    f"packing failed for {source}: {result.error or 'unknown error'}"
                )
            if not packed.is_file():
                raise LimitedReleaseError(f"packer reported success without output: {packed}")
            _require_snapshot(source, original, "source")
            packed_snapshot = _snapshot(packed, "output")
            validation = report.validate_packed(str(packed))
            if not validation.ok:
                raise LimitedReleaseError(
                    f"structural validation failed for {packed.name}: "
                    f"{validation.reason or 'unspecified failure'}"
                )
            _require_snapshot(packed, packed_snapshot, "output")
            output_snapshots[packed] = packed_snapshot
            artifacts.append(
                {
                    "build_id": result.build_id,
                    "kind": kind,
                    "output": packed.name,
                    "packed_sha256": packed_snapshot.sha256,
                    "packed_size": packed_snapshot.size,
                    "source_name": source.name,
                    "source_sha256": source_sha256,
                    "source_size": source_size,
                    "structural_validation": "passed",
                }
            )

        # Candidate identity is security-critical input. Revalidate both files
        # after the last pack before publishing anything derived from them.
        final_candidate = release_attestation.validate_candidate_identity(stub_path)
        if (final_candidate != candidate_manifest
                or _sha256(stub_path) != candidate_stub_sha256
                or _sha256(candidate_manifest_path) != candidate_manifest_sha256):
            raise LimitedReleaseError("candidate bundle changed during packing")
        _require_snapshot(stub_path, candidate_snapshot, "candidate stub")
        _require_snapshot(candidate_manifest_path, candidate_manifest_snapshot, "candidate manifest")

        # Recheck the whole transaction, not just the file most recently packed.
        # A later build step can otherwise invalidate an earlier source/output.
        for source, expected in source_snapshots.items():
            _require_snapshot(source, expected, "source")
        for packed, expected in output_snapshots.items():
            _require_snapshot(packed, expected, "output")

        manifest = {
            "artifacts": artifacts,
            "candidate": {
                "artifact_sha256": candidate_stub_sha256,
                "manifest_sha256": candidate_manifest_sha256,
                "source_commit": candidate_manifest["source_commit"],
            },
            "disabled_features": [
                "anti-debug",
                "memory-guard",
                "process-hardening",
                "tamper-monitor",
                "selected-function-virtualization",
                "server-shard",
            ],
            "profile": PROFILE_ID,
            "required_before_distribution": [
                "Authenticode-sign and timestamp after packing",
                "regenerate and sign product integrity manifests over final distributed bytes",
                "run product-specific EXE and DLL-host workflows with integrity verification enabled",
                "scan the exact final package",
                "canary the exact signed hashes before broad rollout",
            ],
            "schema": 1,
            "status": "packed-awaiting-product-validation-and-signing",
        }
        manifest_path = stage / MANIFEST_NAME
        manifest_path.write_bytes(_canonical_json(manifest))
        _plain_path(stage, "staging directory")
        _plain_path(destination, "output directory")
        if destination.exists():
            raise LimitedReleaseError(f"output directory already exists: {destination}")
        # On Windows rename never replaces a concurrently created destination.
        try:
            os.rename(stage, destination)
        except OSError as exc:
            raise LimitedReleaseError(f"bundle publication failed: {destination}: {exc}") from exc
        return destination / MANIFEST_NAME
    except BaseException:
        # Never follow a replaced parent/junction during recursive cleanup.
        try:
            _plain_path(stage, "staging directory")
            if stage.resolve().parent == destination_parent:
                shutil.rmtree(stage, ignore_errors=True)
        except (OSError, LimitedReleaseError):
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stub-path",
        required=True,
        help="path to lethe_stub_x64.dll in an intact schema-2 candidate bundle",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="new directory that receives the packed files and hash manifest",
    )
    parser.add_argument("--exe", action="append", default=[], help="unmanaged x64 EXE")
    parser.add_argument("--dll", action="append", default=[], help="unmanaged x64 DLL")
    parser.add_argument(
        "--compression-level",
        type=int,
        choices=range(10),
        default=9,
        metavar="0..9",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest_path = build_bundle(args)
    except LimitedReleaseError as exc:
        print(f"limited release: FAILED: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print("limited release: PACKED")
    print(f"  profile : {PROFILE_ID}")
    print(f"  manifest: {manifest_path}")
    print("  next    : final signing/manifest regeneration, product smoke tests, scanning")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
