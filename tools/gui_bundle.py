"""Prepare exact, verified data resources for the frozen GUI; never create trust."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packer import release_attestation as release
from packer.pe_content_id import FileSnapshot, snapshot_file
from tools import production_gate

ROOT = Path(__file__).resolve().parents[1]
STUB_DEST = "stub/prebuilt/lethe_stub_x64.dll"
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


class GuiBundleError(ValueError):
    """Resource preparation failed; no approval or fallback was granted."""


@dataclass(frozen=True)
class Resource:
    destination: str
    snapshot: FileSnapshot


def _literal(value: str, *, absolute: bool = False) -> None:
    if (not isinstance(value, str) or not value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(c in value for c in '*?[]="<>|')):
        raise GuiBundleError("resource path contains control, pattern, separator or invalid characters")
    if ":" in value and not (absolute and value.count(":") == 1
                              and len(value) > 2 and value[0].isascii()
                              and value[0].isalpha() and value[1] == ":"
                              and value[2] in "\\/"):
        raise GuiBundleError("resource path contains a non-drive colon")


def _destination(value: str) -> str:
    _literal(value)
    if ("\\" in value
            or str(PurePosixPath(value)) != value or PurePosixPath(value).is_absolute()
            or any(p in (".", "..") or p.endswith((".", " ")) for p in value.split("/"))):
        raise GuiBundleError("resource destination is not canonical literal relative text")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    if any(p.split(".", 1)[0].upper() in reserved for p in value.split("/")):
        raise GuiBundleError("resource destination is Windows-reserved")
    return value


def _snapshot(path: Path) -> FileSnapshot:
    path = path.absolute()
    # Nuitka treats even an explicit include-data-files source as a pattern.
    _literal(str(path), absolute=True)
    try:
        return snapshot_file(path, what="GUI bundle resource", reject_hardlinks=True,
                             max_bytes=MAX_FILE_BYTES)
    except (ValueError, OSError) as exc:
        raise GuiBundleError(str(exc)) from exc


def _document(resource: Resource) -> dict:
    try:
        value = json.loads(resource.snapshot.data.decode("utf-8-sig"))
    except (ValueError, UnicodeError) as exc:
        raise GuiBundleError("resource document is invalid JSON") from exc
    if not isinstance(value, dict):
        raise GuiBundleError("resource document is not an object")
    return value


def _verify(stub: Path, root: Path) -> dict:
    # Use the existing verifier, including all semantic evidence replay.
    try:
        return release.verify_release_bundle(
            stub, trust_store_path=root / "packer/release_trust.json",
            evidence_trust_store_path=root / "packer/evidence_trust.json",
            matrix_path=root / "docs/production_compatibility.json")
    except (ValueError, OSError) as exc:
        raise GuiBundleError(f"approved release bundle required: {exc}") from exc


def collect_resources(stub_path: Path, *, repository_root: Path = ROOT) -> tuple[Resource, ...]:
    """Verify existing public release inputs and enumerate only their exact closure."""
    root = repository_root.absolute()
    if root.resolve() != production_gate.ROOT.resolve():
        raise GuiBundleError("repository root differs from production-gate evidence root")
    stub = stub_path.absolute()
    if stub.name != "lethe_stub_x64.dll":
        raise GuiBundleError("release stub must retain its canonical artifact filename")
    bundle = stub.parent
    resources: dict[str, Resource] = {}

    def add(source: Path, destination: str, expected: str | None = None) -> Resource:
        destination = _destination(destination)
        current = Resource(destination, _snapshot(source))
        if expected is not None and current.snapshot.sha256 != expected:
            raise GuiBundleError("referenced resource hash changed: " + destination)
        folded = destination.casefold()
        for prior in resources.values():
            other = prior.destination.casefold()
            if folded == other:
                if (destination != prior.destination or current.snapshot != prior.snapshot):
                    raise GuiBundleError("resource destination collision: " + destination)
                return prior
            if folded.startswith(other + "/") or other.startswith(folded + "/"):
                raise GuiBundleError("resource file/directory collision: " + destination)
        resources[destination] = current
        if sum(r.snapshot.size for r in resources.values()) > MAX_TOTAL_BYTES:
            raise GuiBundleError("resource closure exceeds the bounded staging budget")
        return current

    def bundle_file(base: Path, relative: str, digest: str) -> Resource:
        try:
            source = release._contained_evidence_path(base, relative)
            destination = "stub/prebuilt/" + source.relative_to(bundle.resolve()).as_posix()
        except (ValueError, OSError) as exc:
            raise GuiBundleError("resource reference escapes the selected bundle") from exc
        return add(source, destination, digest)

    add(stub, STUB_DEST)
    manifest = _document(add(release.candidate_manifest_path(stub),
                             "stub/prebuilt/lethe_stub_x64.manifest.json"))
    envelope = _document(add(release.release_attestation_path(stub),
                             "stub/prebuilt/lethe_stub_x64.release.json"))
    add(root / "packer/release_trust.json", "packer/release_trust.json")
    add(root / "packer/evidence_trust.json", "packer/evidence_trust.json")
    matrix = _document(add(root / "docs/production_compatibility.json",
                           "docs/production_compatibility.json"))
    payload = _verify(stub, root)
    if payload != envelope.get("payload"):
        raise GuiBundleError("release payload changed during verification")
    for record in manifest["evidence"]:
        bundle_file(bundle, record["path"], record["sha256"])
    documents: dict[str, tuple[Path, dict]] = {}
    for record in payload["evidence"]:
        resource = bundle_file(bundle, record["path"], record["sha256"])
        documents[record["kind"]] = (resource.snapshot.path, _document(resource))
    for kind in ("authenticode", "scanner", "clean-vm", "application"):
        path, document = documents[kind]
        for record in release._document_file_references(kind, document):
            bundle_file(path.parent, record["path"], record["sha256"])
    external_path, external = documents["external-manifest"]
    for record in external["records"]:
        bundle_file(external_path.parent, record["path"], record["sha256"])
        if record["kind"] in release.PROVIDER_SIGNED_KINDS:
            bundle_file(external_path.parent, record["provider_signature_path"],
                        record["provider_signature_sha256"])
    for subject in external["subjects"]:
        for path_key, hash_key in (("subject_path", "subject_sha256"),
                                   ("pack_report_path", "pack_report_sha256"),
                                   ("protection_profile_path", "protection_profile_sha256")):
            bundle_file(external_path.parent, subject[path_key], subject[hash_key])
    for feature in matrix["features"]:
        for evidence in feature["evidence"]:
            destination = _destination(evidence["path"])
            # Already mapped canonical release resources satisfy presence references.
            # Never replace the selected manifest with a stale repository prebuilt.
            if destination in resources:
                continue
            try:
                source = release._contained_evidence_path(root, destination)
            except (ValueError, OSError) as exc:
                raise GuiBundleError("matrix evidence escapes repository") from exc
            add(source, destination)
    ordered = tuple(resources[key] for key in sorted(resources))
    # Capture from held handles, then check original identities after verifier reads.
    for resource in ordered:
        if _snapshot(resource.snapshot.path) != resource.snapshot:
            raise GuiBundleError("resource changed while collecting verified closure")
    return ordered


def _check_tree(root: Path, expected: set[str]) -> None:
    found: set[str] = set()
    for parent, directories, files in os.walk(root, followlinks=False):
        for directory in [Path(parent), *(Path(parent) / p for p in directories)]:
            if release._is_linklike(directory):
                raise GuiBundleError("staged tree contains a link or junction")
        for name in files:
            found.add((Path(parent) / name).relative_to(root).as_posix())
    if found != expected:
        raise GuiBundleError("staged resource file set differs from its exact plan")


def prepare_resources(stub_path: Path, output_dir: Path, *, repository_root: Path = ROOT) -> dict:
    resources = collect_resources(stub_path, repository_root=repository_root)
    output = output_dir.absolute()
    _literal(str(output), absolute=True)
    if output.exists() or output.is_symlink():
        raise GuiBundleError("resource stage must be new")
    release._reject_link_chain(output.parent, Path(output.anchor))
    output.mkdir()  # Parent must already exist. No replacement or recursive cleanup.
    data = output / "data"
    data.mkdir()
    records = []
    for resource in resources:
        target = data / resource.destination
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(resource.snapshot.data)
        records.append({"destination": resource.destination,
                        "source": str(resource.snapshot.path),
                        "sha256": resource.snapshot.sha256,
                        "size_bytes": resource.snapshot.size})
    _check_tree(data, {r["destination"] for r in records})
    for record in records:
        snapshot = _snapshot(data / record["destination"])
        if snapshot.sha256 != record["sha256"] or snapshot.size != record["size_bytes"]:
            raise GuiBundleError("staged resource differs from retained verified bytes")
    # This replays the same verifier against copied public trust and evidence bytes;
    # matrix source-presence checks also remain anchored to the unchanged source repo.
    _verify(data / STUB_DEST, data)
    for resource in resources:
        if _snapshot(resource.snapshot.path) != resource.snapshot:
            raise GuiBundleError("original input changed during staging")
    manifest = {"schema": 1, "kind": "lethe-gui-resource-plan",
                "source_root": str(repository_root.absolute()), "staged_root": str(data),
                "include_modules": ["tools.production_gate"], "resources": records}
    plan_path = output / "resource-plan.json"
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    with plan_path.open("xb") as stream:
        stream.write(encoded)
    return {**manifest, "plan_path": str(plan_path),
            "plan_sha256": hashlib.sha256(encoded).hexdigest()}


def validate_resources(plan_path: Path, *, expected_sha256: str) -> dict:
    snapshot = _snapshot(plan_path)
    if snapshot.sha256 != expected_sha256:
        raise GuiBundleError("resource plan hash mismatch")
    plan = _document(Resource("resource-plan.json", snapshot))
    if (set(plan) != {"schema", "kind", "source_root", "staged_root", "include_modules", "resources"}
            or plan["schema"] != 1 or plan["kind"] != "lethe-gui-resource-plan"
            or plan["include_modules"] != ["tools.production_gate"]):
        raise GuiBundleError("resource plan schema differs")
    data = Path(plan["staged_root"])
    if data != plan_path.absolute().parent / "data":
        raise GuiBundleError("resource stage is not adjacent to its plan")
    expected: set[str] = set()
    folded: set[str] = set()
    for record in plan["resources"]:
        if set(record) != {"destination", "source", "sha256", "size_bytes"}:
            raise GuiBundleError("resource plan entry differs")
        destination = _destination(record["destination"])
        if destination.casefold() in folded:
            raise GuiBundleError("duplicate resource destination")
        folded.add(destination.casefold()); expected.add(destination)
        for path in (data / destination, Path(record["source"])):
            actual = _snapshot(path)
            if actual.sha256 != record["sha256"] or actual.size != record["size_bytes"]:
                raise GuiBundleError("resource bytes changed: " + destination)
    _check_tree(data, expected)
    _verify(data / STUB_DEST, data)
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--stub-path", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--plan", type=Path, required=True)
    validate.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    try:
        result = (prepare_resources(args.stub_path, args.output_dir) if args.action == "prepare"
                  else validate_resources(args.plan, expected_sha256=args.plan_sha256))
    except (GuiBundleError, ValueError, OSError, KeyError, TypeError) as exc:
        print(f"GUI resource preflight failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
