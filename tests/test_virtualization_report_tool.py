"""CLI contracts for the read-only virtualization report tool."""
from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from lifter import function_discovery
from packer.virtualization_selection import canonical_json, verify_manifest_bytes
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


def test_tool_emits_v3_for_canonical_padding_split(monkeypatch, tmp_path):
    input_path = tmp_path / "padded.exe"
    input_path.write_bytes(b"input remains unchanged")
    selection_path = tmp_path / "selection.json"
    body = b"\xB8\x2A\x00\x00\x00\xC3"
    source = body + b"\xCC\xCC"
    candidate = function_discovery.FunctionCandidate(
        name="padded", source="pdata", rva=0x1000, size=len(source),
        extent_kind="runtime_function", exact_extent=True, heuristic=False,
        unwind_flags=0, unwind_flag_names=(), liftable=True,
        rejection_reason=None, first_unsupported_instruction=None,
        direct_control_proof_status="passed",
        direct_control_rejection_reason=None,
        direct_reference_gate_passed=True,
        executable_coverage_gaps=(), indirect_target_closure_proven=False,
        lifted_body_size=len(body),
    )
    report = function_discovery.FunctionDiscoveryReport(
        image_path=str(input_path), image_base=0x140000000,
        size_of_image=0x3000, candidates=(candidate,),
        executable_coverage_gaps=(), direct_control_analysis_status="passed",
        direct_control_analysis_error=None,
    )
    parsed = SimpleNamespace(
        path="snapshot.exe", is_dll=False, image_base=0x140000000,
        size_of_image=0x3000,
        sections=(SimpleNamespace(
            rva=0x1000, raw=source, characteristics=0x60000020),),
        runtime_functions=(SimpleNamespace(
            begin_rva=0x1000, end_rva=0x1000 + len(source),
            unwind_info_rva=0x2000, unwind_flags=0),),
    )
    monkeypatch.setattr(
        virtualization_report.pe_analyze, "analyze_pe", lambda _path: parsed)
    monkeypatch.setattr(
        virtualization_report, "pe_content_id", lambda _path: "b" * 64)
    monkeypatch.setattr(
        virtualization_report.function_discovery, "discover_functions",
        lambda _parsed, **_kwargs: report)

    rc = virtualization_report.main([
        str(input_path), "--emit-selection-manifest", str(selection_path),
    ])

    assert rc == 0
    manifest = json.loads(selection_path.read_text(encoding="ascii"))
    item = manifest["selections"][0]
    assert manifest["version"] == 3
    assert item["source_extent"]["size"] == len(source)
    assert item["lifted_body_extent"]["size"] == len(body)
    assert item["source_extent_sha256"] == hashlib.sha256(source).hexdigest()
    assert item["lifted_body_sha256"] == hashlib.sha256(body).hexdigest()


def test_tool_reports_map_read_failure_cleanly(tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    input_path.write_bytes(b"fixture")

    rc = virtualization_report.main([
        str(input_path), "--map", str(tmp_path / "missing.map"),
    ])

    assert rc == 1
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("pair", [
    "input-map", "map-report", "map-manifest",
])
def test_tool_rejects_map_identity_aliases(pair, tmp_path, capsys):
    input_path = tmp_path / "input.exe"
    map_path = tmp_path / "input.map"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    if pair == "input-map":
        os.link(input_path, map_path)
    else:
        map_path.write_bytes(b"map")
        os.link(
            map_path,
            report_path if pair == "map-report" else manifest_path,
        )
    before = {
        path: path.read_bytes()
        for path in (input_path, map_path, report_path, manifest_path)
        if path.exists()
    }

    rc = virtualization_report.main([
        str(input_path), "--map", str(map_path),
        "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert "different files" in capsys.readouterr().err
    assert all(path.read_bytes() == content for path, content in before.items())
    assert not _temporary_publications(tmp_path)


def test_map_report_and_pe_only_selection_are_separate_deterministic_views(
        monkeypatch, tmp_path):
    input_path = tmp_path / "input.exe"
    map_path = tmp_path / "input.map"
    output = tmp_path / "report.json"
    selection = tmp_path / "selection.json"
    input_path.write_bytes(b"input remains unchanged")
    map_path.write_text("mapped symbols", encoding="utf-8")

    def candidate(name):
        return function_discovery.FunctionCandidate(
            name=name, source="pdata", rva=0x1000, size=6,
            extent_kind="runtime_function", exact_extent=True,
            heuristic=False, unwind_flags=0, unwind_flag_names=(),
            liftable=True, rejection_reason=None,
            first_unsupported_instruction=None,
            direct_control_proof_status="passed",
            direct_control_rejection_reason=None,
            direct_reference_gate_passed=False,
            executable_coverage_gaps=(),
            indirect_target_closure_proven=False,
        )

    def report(name):
        return function_discovery.FunctionDiscoveryReport(
            image_path=str(input_path), image_base=0x140000000,
            size_of_image=0x3000, candidates=(candidate(name),),
            executable_coverage_gaps=(),
            direct_control_analysis_status="passed",
            direct_control_analysis_error=None,
        )

    parsed = SimpleNamespace(
        path="snapshot.exe", is_dll=False, image_base=0x140000000,
        size_of_image=0x3000,
        sections=(SimpleNamespace(
            rva=0x1000, raw=b"\x90" * 6,
            characteristics=0x60000020,
        ),),
        runtime_functions=(SimpleNamespace(
            begin_rva=0x1000, end_rva=0x1006,
            unwind_info_rva=0x2000, unwind_flags=0,
        ),),
    )
    monkeypatch.setattr(
        virtualization_report.pe_analyze, "analyze_pe", lambda _path: parsed)
    monkeypatch.setattr(
        virtualization_report, "pe_content_id", lambda _path: "b" * 64)
    calls = []

    def discover(_parsed, **kwargs):
        calls.append(kwargs.get("map_text"))
        return report(
            "mapped_exact" if kwargs.get("map_text") is not None
            else "sub_00001000")

    monkeypatch.setattr(
        virtualization_report.function_discovery, "discover_functions", discover)

    rc = virtualization_report.main([
        str(input_path), "--map", str(map_path), "--format", "json",
        "--output", str(output),
        "--emit-selection-manifest", str(selection),
    ])

    assert rc == 0
    assert calls == ["mapped symbols", None]
    assert json.loads(output.read_text(encoding="utf-8"))["candidates"][0][
        "name"] == "mapped_exact"
    manifest = json.loads(selection.read_text(encoding="ascii"))
    assert manifest["selections"][0]["name"] == "sub_00001000"
    assert selection.read_bytes() == canonical_json(manifest)
    manifest["selections"][0]["indirect_target_closure"]["acknowledged"] = True
    verified = verify_manifest_bytes(
        canonical_json(manifest), parsed=parsed,
        report=report("sub_00001000"),
        source_sha256=hashlib.sha256(input_path.read_bytes()).hexdigest(),
        source_pe_content_id="b" * 64,
    )
    assert verified.functions[0].name == "sub_00001000"


def test_map_change_before_publish_preserves_existing_outputs(
        monkeypatch, tmp_path, capsys):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    map_path = tmp_path / "input.map"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    map_path.write_bytes(b"original map")
    report_path.write_bytes(b"old report")
    manifest_path.write_bytes(b"old manifest")
    real_build = virtualization_report.build_manifest

    def mutate_map(*args, **kwargs):
        result = real_build(*args, **kwargs)
        map_path.write_bytes(b"changed map")
        return result

    monkeypatch.setattr(virtualization_report, "build_manifest", mutate_map)

    rc = virtualization_report.main([
        str(input_path), "--map", str(map_path),
        "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert "linker MAP path or content changed" in capsys.readouterr().err
    assert report_path.read_bytes() == b"old report"
    assert manifest_path.read_bytes() == b"old manifest"
    assert not _temporary_publications(tmp_path)


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


def test_hostile_staged_mutation_after_replace_is_rejected_and_rolled_back(
        monkeypatch, tmp_path, capsys):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    report_path.write_bytes(b"old report")
    manifest_path.write_bytes(b"old manifest")
    original_identities = {
        path: _file_identity(path) for path in (report_path, manifest_path)
    }
    real_replace = virtualization_report.os.replace
    injected = False

    def mutate_installed_stage(source, destination):
        nonlocal injected
        result = real_replace(source, destination)
        if (not injected
                and os.path.normcase(os.path.abspath(destination))
                == os.path.normcase(os.path.abspath(report_path))
                and "-new-" in os.path.basename(source)):
            injected = True
            report_path.write_bytes(b"hostile staged bytes")
        return result

    monkeypatch.setattr(
        virtualization_report.os, "replace", mutate_installed_stage)

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert injected
    assert "installed report output changed" in capsys.readouterr().err
    assert report_path.read_bytes() == b"old report"
    assert manifest_path.read_bytes() == b"old manifest"
    assert {
        path: _file_identity(path) for path in (report_path, manifest_path)
    } == original_identities
    assert not _temporary_publications(tmp_path)


def test_hostile_mutation_after_post_install_check_fails_final_verification(
        monkeypatch, tmp_path, capsys):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    manifest_path = tmp_path / "selection.json"
    input_path.write_bytes(b"input")
    report_path.write_bytes(b"old report")
    manifest_path.write_bytes(b"old manifest")
    real_capture = virtualization_report._capture_relocated_snapshot
    injected = False

    def mutate_after_capture(path, expected, label):
        nonlocal injected
        current = real_capture(path, expected, label)
        if not injected and label == "installed report output":
            injected = True
            path.write_bytes(b"hostile after post-install check")
        return current

    monkeypatch.setattr(
        virtualization_report, "_capture_relocated_snapshot",
        mutate_after_capture,
    )

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
        "--emit-selection-manifest", str(manifest_path),
    ])

    assert rc == 1
    assert injected
    assert "installed report output changed" in capsys.readouterr().err
    assert report_path.read_bytes() == b"old report"
    assert manifest_path.read_bytes() == b"old manifest"
    assert not _temporary_publications(tmp_path)


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate streams are Windows-only")
def test_backup_ads_mutation_with_restored_mtime_is_rejected_and_retained(
        monkeypatch, tmp_path, capsys):
    _patch_empty_success(monkeypatch)
    input_path = tmp_path / "input.exe"
    report_path = tmp_path / "report.json"
    input_path.write_bytes(b"input")
    report_path.write_bytes(b"old report")
    try:
        with open(str(report_path) + ":lethe-audit", "wb") as stream:
            stream.write(b"old metadata")
    except OSError as exc:
        pytest.skip(f"alternate streams unavailable: {exc}")
    original_identity = _file_identity(report_path)
    real_capture = virtualization_report._capture_relocated_snapshot
    real_replace = virtualization_report.os.replace
    backup_path = None
    injected = False

    def mutate_after_backup_capture(path, expected, label):
        nonlocal backup_path, injected
        current = real_capture(path, expected, label)
        if not injected and label == "original report output backup":
            injected = True
            backup_path = path
            with open(str(path) + ":lethe-audit", "wb") as stream:
                stream.write(b"hostile metadata")
            metadata = path.stat()
            os.utime(path, ns=(metadata.st_atime_ns, current.mtime_ns))
        return current

    def fail_install(source, destination):
        if (injected
                and os.path.normcase(os.path.abspath(destination))
                == os.path.normcase(os.path.abspath(report_path))):
            raise OSError("injected install failure after ADS mutation")
        return real_replace(source, destination)

    monkeypatch.setattr(
        virtualization_report, "_capture_relocated_snapshot",
        mutate_after_backup_capture,
    )
    monkeypatch.setattr(virtualization_report.os, "replace", fail_install)

    rc = virtualization_report.main([
        str(input_path), "--output", str(report_path),
    ])

    error = capsys.readouterr().err
    assert rc == 1
    assert injected and backup_path is not None
    assert "rollback failed" in error
    assert f"recoverable object retained at {backup_path}" in error
    assert not report_path.exists()
    assert backup_path.exists()
    assert backup_path.read_bytes() == b"old report"
    assert _file_identity(backup_path) == original_identity
    with open(str(backup_path) + ":lethe-audit", "rb") as stream:
        assert stream.read() == b"hostile metadata"
    assert _temporary_publications(tmp_path) == (backup_path,)


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
