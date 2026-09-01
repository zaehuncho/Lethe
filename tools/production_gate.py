#!/usr/bin/env python3
"""Fail closed until Lethe's declared EXE/DLL production contract is proven."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = ROOT / "docs" / "production_compatibility.json"
VALID_TARGETS = frozenset(("exe", "dll"))
VALID_STATUSES = frozenset(
    ("proven", "failing", "blocked", "partial", "experimental", "unverified")
)
ID_PATTERN = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")


class MatrixError(ValueError):
    """The compatibility declaration is malformed or internally dishonest."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MatrixError(message)


def load_matrix(path: Path) -> dict[str, Any]:
    try:
        matrix = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MatrixError(f"cannot read compatibility matrix {path}: {exc}") from exc
    _require(isinstance(matrix, dict), "matrix root must be an object")
    _require(matrix.get("schema") == 1, "matrix schema must be 1")
    declared_statuses = matrix.get("status_values")
    _require(
        isinstance(declared_statuses, list)
        and set(declared_statuses) == VALID_STATUSES,
        "matrix status_values do not match the gate contract",
    )
    features = matrix.get("features")
    _require(isinstance(features, list) and features, "matrix features must be non-empty")

    seen: set[str] = set()
    for index, feature in enumerate(features):
        label = f"feature[{index}]"
        _require(isinstance(feature, dict), f"{label} must be an object")
        feature_id = feature.get("id")
        _require(
            isinstance(feature_id, str) and ID_PATTERN.fullmatch(feature_id) is not None,
            f"{label} has an invalid id",
        )
        _require(feature_id not in seen, f"duplicate feature id: {feature_id}")
        seen.add(feature_id)
        _require(
            isinstance(feature.get("title"), str) and feature["title"].strip(),
            f"{feature_id}: title is required",
        )
        applies_to = feature.get("applies_to")
        _require(
            isinstance(applies_to, list)
            and applies_to
            and len(applies_to) == len(set(applies_to))
            and set(applies_to) <= VALID_TARGETS,
            f"{feature_id}: applies_to must contain unique exe/dll targets",
        )
        _require(
            isinstance(feature.get("required"), bool),
            f"{feature_id}: required must be boolean",
        )
        status = feature.get("status")
        _require(status in VALID_STATUSES, f"{feature_id}: invalid status {status!r}")
        native_checks = feature.get("native_checks", [])
        _require(
            isinstance(native_checks, list)
            and len(native_checks) == len(set(native_checks))
            and all(
                isinstance(check, str) and ID_PATTERN.fullmatch(check) is not None
                for check in native_checks
            ),
            f"{feature_id}: native_checks must contain unique check ids",
        )
        evidence = feature.get("evidence")
        _require(isinstance(evidence, list) and evidence, f"{feature_id}: evidence is required")
        for evidence_index, item in enumerate(evidence):
            _require(
                isinstance(item, dict),
                f"{feature_id}: evidence[{evidence_index}] must be an object",
            )
            evidence_path = item.get("path")
            _require(
                isinstance(evidence_path, str) and evidence_path.strip(),
                f"{feature_id}: evidence[{evidence_index}] path is required",
            )
            resolved = (ROOT / evidence_path).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError as exc:
                raise MatrixError(
                    f"{feature_id}: evidence path escapes repository: {evidence_path}"
                ) from exc
            _require(resolved.is_file(), f"{feature_id}: missing evidence path {evidence_path}")
            _require(
                isinstance(item.get("type"), str) and item["type"].strip(),
                f"{feature_id}: evidence[{evidence_index}] type is required",
            )
            _require(
                isinstance(item.get("claim"), str) and item["claim"].strip(),
                f"{feature_id}: evidence[{evidence_index}] claim is required",
            )
        if feature["required"] and status != "proven":
            _require(
                isinstance(feature.get("blocker"), str) and feature["blocker"].strip(),
                f"{feature_id}: required non-proven feature needs a blocker",
            )
    return matrix


def load_evidence(
    path: Path,
    *,
    artifact_path: Path | None = None,
) -> dict[str, Any]:
    try:
        evidence = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MatrixError(f"cannot read native evidence {path}: {exc}") from exc
    _require(isinstance(evidence, dict), "native evidence root must be an object")
    _require(evidence.get("schema") == 1, "native evidence schema must be 1")
    _require(
        isinstance(evidence.get("tracked_source_dirty"), bool),
        "native evidence tracked_source_dirty must be boolean",
    )
    source_commit = evidence.get("source_commit")
    _require(
        isinstance(source_commit, str)
        and re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None,
        "native evidence source_commit must be a full lowercase Git id",
    )
    stub_path_value = evidence.get("stub_path")
    stub_sha256 = evidence.get("stub_sha256")
    _require(
        isinstance(stub_path_value, str) and stub_path_value,
        "native evidence stub_path is required",
    )
    _require(
        isinstance(stub_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", stub_sha256) is not None,
        "native evidence stub_sha256 must be lowercase SHA-256",
    )
    # Bundled evidence is portable: an attestor may supply the exact artifact
    # whose digest must match instead of trusting a stale machine-local path.
    # Without an override, relative identities resolve beside the evidence.
    stub_path = artifact_path.resolve() if artifact_path is not None else Path(stub_path_value)
    if artifact_path is None and not stub_path.is_absolute():
        stub_path = (path.resolve().parent / stub_path).resolve()
    _require(stub_path.is_file(), f"native evidence stub is missing: {stub_path}")
    actual_stub_sha256 = hashlib.sha256(stub_path.read_bytes()).hexdigest()
    _require(
        actual_stub_sha256 == stub_sha256,
        "native evidence stub SHA-256 does not match the current artifact",
    )
    tests = evidence.get("tests")
    _require(isinstance(tests, list) and tests, "native evidence tests must be non-empty")
    by_id: dict[str, str] = {}
    for index, item in enumerate(tests):
        _require(isinstance(item, dict), f"native evidence test[{index}] must be an object")
        check_id = item.get("id")
        status = item.get("status")
        _require(
            isinstance(check_id, str) and ID_PATTERN.fullmatch(check_id) is not None,
            f"native evidence test[{index}] has invalid id",
        )
        _require(check_id not in by_id, f"duplicate native evidence id: {check_id}")
        _require(status in ("passed", "failed"), f"{check_id}: invalid evidence status")
        by_id[check_id] = status
    passed = sum(status == "passed" for status in by_id.values())
    _require(evidence.get("passed") == passed, "native evidence passed count is inconsistent")
    _require(evidence.get("total") == len(by_id), "native evidence total count is inconsistent")
    _require(
        evidence.get("ready") is (passed == len(by_id)),
        "native evidence ready state is inconsistent",
    )
    return {**evidence, "by_id": by_id}


def evaluate(
    matrix: dict[str, Any],
    scope: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    targets = VALID_TARGETS if scope == "all" else frozenset((scope,))
    selected = [
        feature
        for feature in matrix["features"]
        if feature["required"] and targets.intersection(feature["applies_to"])
    ]
    blockers: list[dict[str, Any]] = []
    proven = 0
    for feature in selected:
        blocker = None
        if feature["status"] != "proven":
            blocker = {
                "id": feature["id"],
                "title": feature["title"],
                "status": feature["status"],
                "applies_to": feature["applies_to"],
                "blocker": feature.get("blocker", ""),
            }
        else:
            required_checks = feature.get("native_checks", [])
            if required_checks and evidence is None:
                blocker = {
                    "id": feature["id"],
                    "title": feature["title"],
                    "status": "evidence-missing",
                    "applies_to": feature["applies_to"],
                    "blocker": "native evidence was not supplied for: "
                    + ", ".join(required_checks),
                }
            elif required_checks:
                failed = [
                    check
                    for check in required_checks
                    if evidence["by_id"].get(check) != "passed"
                ]
                if failed:
                    blocker = {
                        "id": feature["id"],
                        "title": feature["title"],
                        "status": "evidence-failed",
                        "applies_to": feature["applies_to"],
                        "blocker": "native evidence is missing or failed for: "
                        + ", ".join(failed),
                    }
        if blocker is None:
            proven += 1
        else:
            blockers.append(blocker)
    if evidence is not None and evidence["tracked_source_dirty"]:
        blockers.append({
            "id": "evidence.source_tree",
            "title": "Native evidence source provenance",
            "status": "evidence-dirty",
            "applies_to": sorted(targets),
            "blocker": "native evidence was produced from a tracked-dirty source tree",
        })
    return {
        "schema": 1,
        "scope": scope,
        "ready": not blockers,
        "required_features": len(selected),
        "proven_features": proven,
        "blocker_count": len(blockers),
        "blockers": blockers,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--scope", choices=("exe", "dll", "all"), default="all")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--evidence",
        type=Path,
        help="JSON evidence emitted by tests/production_corpus.ps1",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate schema/evidence paths without claiming production readiness",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        matrix = load_matrix(args.matrix.resolve())
        evidence = load_evidence(args.evidence.resolve()) if args.evidence else None
        result = evaluate(matrix, args.scope, evidence)
    except MatrixError as exc:
        if args.format == "json":
            print(json.dumps({"schema": 1, "ready": False, "error": str(exc)}, sort_keys=True))
        else:
            print(f"Production compatibility gate: INVALID\n  - {exc}", file=sys.stderr)
        return 2

    if args.validate_only:
        if args.format == "json":
            print(json.dumps({**result, "validated_only": True}, sort_keys=True))
        else:
            print(
                "Production compatibility matrix: VALID "
                f"({len(matrix['features'])} declared features; readiness not asserted)"
            )
        return 0

    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result["ready"]:
        print(
            f"Production compatibility gate: PASS ({args.scope}; "
            f"{result['proven_features']}/{result['required_features']} proven)"
        )
    else:
        print(
            f"Production compatibility gate: RED ({args.scope}; "
            f"{result['proven_features']}/{result['required_features']} proven)",
            file=sys.stderr,
        )
        for blocker in result["blockers"]:
            print(
                f"  - {blocker['id']} [{blocker['status']}]: {blocker['blocker']}",
                file=sys.stderr,
            )
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
