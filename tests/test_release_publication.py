"""Publication paths must follow an authenticated candidate, not a prefix.

These tests mock the already-successful release-signature boundary and Git
history only. Candidate manifest/backing validation and hash binding are real.
The small non-executable fixture is not release, native-runtime, or signing proof.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from packer import release_attestation
from tools import promote_stub, release_check


SOURCE_COMMIT = "a" * 40
RELEASE_COMMIT = "b" * 40


def _json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")


@pytest.fixture
def publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "repository"
    stub = root / "stub/prebuilt/lethe_stub_x64.dll"
    stub.parent.mkdir(parents=True)
    stub.write_bytes(b"publication identity fixture; not executable\n")
    manifest_path = stub.with_suffix(".manifest.json")
    policy = promote_stub.candidate_policy_payload()
    evidence = []
    for relative in sorted(promote_stub.REQUIRED_CANDIDATE_EVIDENCE):
        path = stub.parent / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == "evidence/candidate-policy.json":
            _json(path, policy)
        else:
            path.write_bytes((relative + "\n").encode("ascii"))
        evidence.append({"path": relative, "sha256": release_attestation.sha256_file(path)})
    hashes = {record["path"]: record["sha256"] for record in evidence}
    manifest = {
        "schema": 2, "artifact_status": "candidate-verified",
        "production_ready": False, "candidate_scope": "all",
        "artifact": stub.name, "size_bytes": stub.stat().st_size,
        "sha256": release_attestation.sha256_file(stub),
        "source_dirty": False, "provenance_status": "clean",
        "source_commit": SOURCE_COMMIT,
        "candidate_policy_id": policy["policy_id"],
        "candidate_policy_sha256": hashlib.sha256(
            release_attestation.canonical_json_bytes(policy)).hexdigest(),
        "promotion_tool_sha256": hashes["evidence/candidate-promoter.py"],
        "production_matrix_sha256": hashes["evidence/candidate-production-matrix.json"],
        "toolchain_binding_sha256": "1" * 64,
        "dvm_opcode_mapping_sha256": "2" * 64,
        "dvm_handler_variant_sha256": "3" * 64,
        "dvm_shuffle_seed": "4" * 64,
        "dvm_rolling": True, "dvm_roll_poison": False,
        "dvm_paged_runtime": True, "evidence": evidence,
    }
    _json(manifest_path, manifest)
    assert release_attestation.validate_candidate_identity(stub, manifest_path) == manifest
    # This return value represents an authenticated release payload. Changes
    # made by individual tests model drift after that verification boundary.
    verified_payload = {
        "candidate": {
            "source_commit": SOURCE_COMMIT,
            "manifest_name": manifest_path.name,
            "manifest_sha256": release_attestation.sha256_file(manifest_path),
        },
        "release_source_commit": RELEASE_COMMIT,
    }
    state = SimpleNamespace(
        root=root, stub=stub, manifest_path=manifest_path, manifest=manifest,
        payload=verified_payload, assessment=["docs/production_compatibility.json"],
        published=sorted(release_check.RELEASE_OUTPUT_PATHS),
        candidate_paths=["stub/prebuilt/" + record["path"] for record in evidence],
        verification_calls=[],
    )

    def verified_release(path: Path):
        assert path == stub
        state.verification_calls.append(path)
        return copy.deepcopy(verified_payload)

    def git(*args: str) -> str:
        if args in (
            ("cat-file", "-e", SOURCE_COMMIT + "^{commit}"),
            ("cat-file", "-e", RELEASE_COMMIT + "^{commit}"),
            ("merge-base", "--is-ancestor", SOURCE_COMMIT, RELEASE_COMMIT),
            ("merge-base", "--is-ancestor", RELEASE_COMMIT, "HEAD"),
        ):
            return ""
        if args == ("diff", "--name-only", SOURCE_COMMIT, RELEASE_COMMIT):
            return "\n".join(state.assessment) + "\n"
        if args == ("diff", "--name-only", RELEASE_COMMIT, "HEAD"):
            return "\n".join(state.published) + "\n"
        raise AssertionError(f"unexpected Git fixture call: {args!r}")

    monkeypatch.setattr(release_check, "ROOT", root)
    monkeypatch.setattr(release_check, "STUB", stub)
    monkeypatch.setattr(release_check, "MANIFEST", manifest_path)
    monkeypatch.setattr(release_check, "_git", git)
    monkeypatch.setattr(release_attestation, "verify_release_bundle", verified_release)
    return state


def test_publication_accepts_all_authenticated_candidate_backings(publication):
    publication.published += publication.candidate_paths
    assert len(publication.candidate_paths) == 16
    errors = []
    payload = release_check._check_manifest(errors)
    assert errors == []
    assert payload == publication.payload
    assert publication.verification_calls == [publication.stub]


def test_publication_keeps_existing_release_output_policy(publication):
    publication.published += ["stub/prebuilt/release-evidence/scanner.json"]
    errors = []
    assert release_check._check_manifest(errors) == publication.payload
    assert errors == []


@pytest.mark.parametrize("unexpected", [
    "stub/prebuilt/evidence/unlisted.json",
    "stub/prebuilt/evidence/unlisted/nested.json",
    "stub/prebuilt/evidence-extra/candidate-policy.json",
    "stub/prebuilt/evidence2/candidate-policy.json",
    "stub/prebuilt/release-evidence-extra/scanner.json",
    "packer/assemble.py",
])
def test_publication_rejects_unlisted_and_near_prefix_paths(publication, unexpected):
    publication.published.append(unexpected)
    path = publication.root / unexpected
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"unlisted publication content\n")
    errors = []
    release_check._check_manifest(errors)
    assert any("outside signed release outputs" in error and unexpected in error
               for error in errors)


def test_publication_rejects_changed_manifest_even_when_new_backing_is_valid(publication):
    relative = "evidence/extra-record.json"
    path = publication.stub.parent / relative
    path.write_bytes(b"validly hashed but not signed candidate identity\n")
    publication.manifest["evidence"].append({
        "path": relative, "sha256": release_attestation.sha256_file(path),
    })
    _json(publication.manifest_path, publication.manifest)
    # Revalidation alone succeeds; the previously verified release manifest hash
    # must independently prevent this newly introduced permission from being used.
    release_attestation.validate_candidate_identity(
        publication.stub, publication.manifest_path)
    publication.published += publication.candidate_paths + ["stub/prebuilt/" + relative]
    errors = []
    result = release_check._check_manifest(errors)
    assert result is None
    assert any("candidate" in error.lower() and "manifest" in error.lower()
               for error in errors)


def test_publication_rejects_manifest_drift_during_candidate_revalidation(
    publication, monkeypatch: pytest.MonkeyPatch,
):
    real_validate = release_attestation.validate_candidate_identity
    calls = []

    def mutate_after_validation(stub: Path, manifest_path: Path):
        candidate = real_validate(stub, manifest_path)
        calls.append(stub)
        # A semantic-equivalent whitespace change still breaks the signed exact
        # manifest-byte binding and must be detected by the final hash check.
        manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
        return candidate

    monkeypatch.setattr(
        release_attestation, "validate_candidate_identity", mutate_after_validation)
    publication.published += publication.candidate_paths
    errors = []
    assert release_check._check_manifest(errors) is None
    assert calls == [publication.stub]
    assert any("candidate publication manifest changed during revalidation" in error
               for error in errors)


@pytest.mark.parametrize("mutation", [
    "manifest-malformed", "manifest-missing", "backing-tampered", "backing-missing",
    "stub-tampered",
])
def test_publication_revalidates_candidate_files_after_release_verification(publication, mutation):
    backing = publication.stub.parent / publication.manifest["evidence"][0]["path"]
    if mutation == "manifest-malformed":
        publication.manifest_path.write_bytes(b"{not-json")
    elif mutation == "manifest-missing":
        publication.manifest_path.unlink()
    elif mutation == "backing-tampered":
        backing.write_bytes(b"changed after release verification\n")
    elif mutation == "backing-missing":
        backing.unlink()
    else:
        publication.stub.write_bytes(b"changed stub after release verification\n")
    errors = []
    result = release_check._check_manifest(errors)
    assert result is None
    assert errors


@pytest.mark.parametrize("drift", ["packer/release_trust.json", "tools/release_check.py"])
def test_publication_still_rejects_candidate_to_release_code_or_trust_drift(publication, drift):
    publication.assessment.append(drift)
    errors = []
    release_check._check_manifest(errors)
    assert any("outside the release compatibility declaration" in error and drift in error
               for error in errors)
