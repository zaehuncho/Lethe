"""CLI contracts for the read-only virtualization report tool."""
from __future__ import annotations

import json
from types import SimpleNamespace

from lifter import function_discovery
from tools import virtualization_report


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
        lambda path: SimpleNamespace(path=path),
    )
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
    assert manifest["functions"] == [{"name": "exact", "rva": 0x1000, "size": 6}]


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
    assert "must not overwrite" in capsys.readouterr().err
