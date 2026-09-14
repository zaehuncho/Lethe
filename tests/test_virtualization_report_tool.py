"""CLI contracts for the read-only virtualization report tool."""
from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from lifter import function_discovery
from packer.virtualization_selection import canonical_json
from tools import virtualization_report


def _patch_empty_success(monkeypatch):
    report = function_discovery.FunctionDiscoveryReport(
        image_path="snapshot.exe", image_base=0x140000000,
        size_of_image=0x3000, candidates=(), executable_coverage_gaps=(),
        direct_control_analysis_status="passed", direct_control_analysis_error=None,
    )
    monkeypatch.setattr(
        virtualization_report.pe_analyze, "analyze_pe",
        lambda path: SimpleNamespace(
            path=path, is_dll=False, image_base=0x140000000,
            size_of_image=0x3000, sections=(), runtime_functions=(),
        ),
    )
    monkeypatch.setattr(
        virtualization_report, "pe_content_id", lambda _path: "b" * 64)
    monkeypatch.setattr(
        virtualization_report.function_discovery, "discover_functions",
        lambda _parsed, **_kwargs: report,
    )
    return report


def _temporary_publications(path):
    return tuple(path.glob(".lethe-*.tmp"))


def _file_identity(path):
    metadata = path.stat()
    return metadata.st_dev, metadata.st_ino


def test_tool_writes_report_and_safe_starter_manifest(monkeypatch, tmp_path):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"input remains unchanged")
    before = input_path.read_bytes()
    output = tmp_path / "report.json"
    selection = tmp_path / "selection.json"
    candidate = function_discovery.FunctionCandidate(
        name="exact",
        source="pdata",
        rva=0x1000,
        size=6,
        extent_kind="runtime_function",
        exact_extent=True,
        heuristic=False,
        unwind_flags=0,
        unwind_flag_names=(),
        liftable=True,
        rejection_reason=None,
        first_unsupported_instruction=None,
        direct_control_proof_status="passed",
        direct_control_rejection_reason=None,
        direct_reference_gate_passed=False,
        executable_coverage_gaps=(),
        indirect_target_closure_proven=False,
    )
    report = function_discovery.FunctionDiscoveryReport(
        image_path=str(input_path), image_base=0x140000000, size_of_image=0x3000,
        candidates=(candidate,), executable_coverage_gaps=(),
        direct_control_analysis_status="passed", direct_control_analysis_error=None,
    )
    monkeypatch.setattr(
        virtualization_report.pe_analyze, "analyze_pe",
        lambda path: SimpleNamespace(
            path=path,
            is_dll=False,
            image_base=0x140000000,
            size_of_image=0x3000,
            sections=(SimpleNamespace(
                rva=0x1000,
                raw=b"\x90" * 6,
                characteristics=0x60000020,
            ),),
            runtime_functions=(SimpleNamespace(
                begin_rva=0x1000,
                end_rva=0x1006,
                unwind_info_rva=0x2000,
                unwind_flags=0,
            ),),
        ),
    )
    monkeypatch.setattr(
        virtualization_report, "pe_content_id", lambda _path: "b" * 64)
    monkeypatch.setattr(
        virtualization_report.function_discovery, "discover_functions",
        lambda _parsed, **_kwargs: report,
    )

    rc = virtualization_report.main([
        str(input_path), "--format", "json", "--output", str(output),
        "--emit-selection-manifest", str(selection),
    ])

    assert rc == 0
    assert input_path.read_bytes() == before
    assert json.loads(output.read_text(encoding="utf-8"))["schema"] == \
        function_discovery.REPORT_SCHEMA
    manifest = json.loads(selection.read_text(encoding="utf-8"))
    assert selection.read_bytes() == canonical_json(manifest)
    assert manifest["schema"] == "lethe.virtualization-selection"
    assert manifest["version"] == 2
    assert manifest["selections"][0]["name"] == "exact"
    assert manifest["selections"][0]["source_extent"] == {
        "rva": 0x1000, "size": 6,
    }
    assert manifest["source"]["sha256"] == hashlib.sha256(before).hexdigest()
    assert manifest["selections"][0]["indirect_target_closure"] == {
        "acknowledged": False, "proven": False,
    }


def test_tool_reports_map_read_failure_cleanly(tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"fixture")

    rc = virtualization_report.main([
        str(input_path), "--map", str(tmp_path / "missing.map"),
    ])

    assert rc == 1
    assert "error:" in capsys.readouterr().err


def test_tool_refuses_to_overwrite_inspected_image(tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"fixture")

    rc = virtualization_report.main([
        str(input_path), "--output", str(input_path),
    ])

    assert rc == 1
    assert input_path.read_bytes() == b"fixture"
    assert "different files" in capsys.readouterr().err


@pytest.mark.parametrize("pair", [
    "input-report", "input-manifest", "report-manifest",
])
def test_tool_rejects_hardlinked_identity_aliases(pair, tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    if pair == "input-report":
        os.link(input_path, report_path)
    elif pair == "input-manifest":
        os.link(input_path, manifest_path)
    else:
        report_path.write_bytes(b"existing report")
        os.link(report_path, manifest_path)
    before = {
        path: path.read_bytes()
        for path in (input_path, report_path, manifest_path) if path.exists()
    }

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert "different files" in capsys.readouterr().err
    assert all(path.read_bytes() == content for path, content in before.items())
    assert not _temporary_publications(tmp_path)


def _symlink(link, target, *, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")


def test_tool_rejects_symlink_or_reparse_output_endpoint(tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    destination = tmp_path / "actual.json"
    link = tmp_path / "report.json"
    input_path.write_bytes(b"input")
    destination.write_bytes(b"existing")
    _symlink(link, destination)

    rc = virtualization_report.main([
        str(input_path), "--output", str(link),
    ])

    assert rc == 1
    assert destination.read_bytes() == b"existing"
    assert "symlink, junction, or reparse" in capsys.readouterr().err
    assert not _temporary_publications(tmp_path)


def test_tool_rejects_symlink_or_reparse_output_ancestor(tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    actual = tmp_path / "actual"
    linked = tmp_path / "linked"
    input_path.write_bytes(b"input")
    actual.mkdir()
    _symlink(linked, actual, directory=True)

    rc = virtualization_report.main([
        str(input_path), "--output", str(linked / "report.json"),
    ])

    assert rc == 1
    assert not (actual / "report.json").exists()
    assert "symlink, junction, or reparse" in capsys.readouterr().err
    assert not _temporary_publications(actual)


def test_late_manifest_construction_failure_preserves_existing_outputs(
        monkeypatch, tmp_path, capsys):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    report_path.write_bytes(b"old report")
    manifest_path.write_bytes(b"old manifest")
    monkeypatch.setattr(
        virtualization_report, "build_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("late manifest construction failure")),
    )

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert "late manifest construction failure" in capsys.readouterr().err
    assert report_path.read_bytes() == b"old report"
    assert manifest_path.read_bytes() == b"old manifest"
    assert not _temporary_publications(tmp_path)


@pytest.mark.parametrize("change", ["content", "same-bytes-replacement"])
def test_source_change_before_publish_preserves_existing_outputs(
        change, monkeypatch, tmp_path, capsys):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    report_path.write_bytes(b"old report")
    manifest_path.write_bytes(b"old manifest")
    real_build = virtualization_report.build_manifest

    def mutate_source(*args, **kwargs):
        result = real_build(*args, **kwargs)
        if change == "content":
            input_path.write_bytes(b"changed")
        else:
            replacement = tmp_path / "replacement.exe"
            replacement.write_bytes(b"input")
            os.replace(replacement, input_path)
        return result

    monkeypatch.setattr(
        virtualization_report, "build_manifest", mutate_source)

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert "changed while the report" in capsys.readouterr().err
    assert report_path.read_bytes() == b"old report"
    assert manifest_path.read_bytes() == b"old manifest"
    assert not _temporary_publications(tmp_path)


@pytest.mark.parametrize("preexisting", [False, True])
def test_second_replace_failure_rolls_back_both_outputs(
        preexisting, monkeypatch, tmp_path, capsys):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    if preexisting:
        report_path.write_bytes(b"old report")
        manifest_path.write_bytes(b"old manifest")
        original_identities = {
            path: _file_identity(path)
            for path in (report_path, manifest_path)
        }
    real_replace = virtualization_report.os.replace
    failed = False

    def fail_second(source, destination):
        nonlocal failed
        if (not failed
                and os.path.normcase(os.path.abspath(destination))
                == os.path.normcase(os.path.abspath(manifest_path))):
            failed = True
            raise OSError("injected second replace failure")
        return real_replace(source, destination)

    monkeypatch.setattr(virtualization_report.os, "replace", fail_second)

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert failed
    assert "injected second replace failure" in capsys.readouterr().err
    if preexisting:
        assert report_path.read_bytes() == b"old report"
        assert manifest_path.read_bytes() == b"old manifest"
        assert {
            path: _file_identity(path)
            for path in (report_path, manifest_path)
        } == original_identities
    else:
        assert not report_path.exists()
        assert not manifest_path.exists()
    assert not _temporary_publications(tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate streams are Windows-only")
def test_second_replace_failure_preserves_original_alternate_streams(
        monkeypatch, tmp_path, capsys):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    report_path.write_bytes(b"old report")
    manifest_path.write_bytes(b"old manifest")
    streams = {
        report_path: b"report metadata",
        manifest_path: b"manifest metadata",
    }
    try:
        for path, content in streams.items():
            with open(str(path) + ":lethe-audit", "wb") as stream:
                stream.write(content)
    except OSError as exc:
        pytest.skip(f"alternate streams unavailable: {exc}")
    real_replace = virtualization_report.os.replace
    failed = False

    def fail_manifest_install(source, destination):
        nonlocal failed
        if (not failed
                and os.path.normcase(os.path.abspath(destination))
                == os.path.normcase(os.path.abspath(manifest_path))):
            failed = True
            raise OSError("injected manifest install failure")
        return real_replace(source, destination)

    monkeypatch.setattr(
        virtualization_report.os, "replace", fail_manifest_install)

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert "injected manifest install failure" in capsys.readouterr().err
    assert report_path.read_bytes() == b"old report"
    assert manifest_path.read_bytes() == b"old manifest"
    for path, content in streams.items():
        with open(str(path) + ":lethe-audit", "rb") as stream:
            assert stream.read() == content
    assert not _temporary_publications(tmp_path)


@pytest.mark.parametrize("preexisting", [False, True])
def test_post_replace_exception_rolls_back_current_and_prior_outputs(
        preexisting, monkeypatch, tmp_path, capsys):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    if preexisting:
        report_path.write_bytes(b"old report")
        manifest_path.write_bytes(b"old manifest")
        original_identities = {
            path: _file_identity(path)
            for path in (report_path, manifest_path)
        }
    real_replace = virtualization_report.os.replace
    injected = False

    def replace_then_fail(source, destination):
        nonlocal injected
        result = real_replace(source, destination)
        if (not injected
                and os.path.normcase(os.path.abspath(destination))
                == os.path.normcase(os.path.abspath(manifest_path))):
            injected = True
            raise OSError("injected post-replace failure")
        return result

    monkeypatch.setattr(
        virtualization_report.os, "replace", replace_then_fail)

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert injected
    assert "injected post-replace failure" in capsys.readouterr().err
    if preexisting:
        assert report_path.read_bytes() == b"old report"
        assert manifest_path.read_bytes() == b"old manifest"
        assert {
            path: _file_identity(path)
            for path in (report_path, manifest_path)
        } == original_identities
    else:
        assert not report_path.exists()
        assert not manifest_path.exists()
    assert not _temporary_publications(tmp_path)


def test_output_change_before_commit_is_preserved_and_rejected(
        monkeypatch, tmp_path, capsys):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    report_path.write_bytes(b"old report")
    manifest_path.write_bytes(b"old manifest")
    real_assert_source = virtualization_report._assert_source_current

    def mutate_after_source_revalidation(path, expected):
        real_assert_source(path, expected)
        report_path.write_bytes(b"external report update")

    monkeypatch.setattr(
        virtualization_report, "_assert_source_current",
        mutate_after_source_revalidation,
    )

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert "changed before publication" in capsys.readouterr().err
    assert report_path.read_bytes() == b"external report update"
    assert manifest_path.read_bytes() == b"old manifest"
    assert not _temporary_publications(tmp_path)


def test_successful_transaction_removes_original_object_backups(
        monkeypatch, tmp_path):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    report_path.write_bytes(b"old report")
    manifest_path.write_bytes(b"old manifest")

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 0
    assert report_path.read_bytes() != b"old report"
    assert manifest_path.read_bytes() != b"old manifest"
    assert not _temporary_publications(tmp_path)
