"""Shared coverage serialization must preserve proofs without quadratic JSON."""
from dataclasses import replace
import json

import pytest

from lifter import function_discovery as discovery


def _candidate(gaps, number=0):
    return discovery.FunctionCandidate(
        name=f"function_{number}", source="pdata", rva=0x1000+number*16,
        size=8, extent_kind="runtime-function", exact_extent=True,
        heuristic=False, unwind_flags=1, unwind_flag_names=("EHANDLER",),
        liftable=False, rejection_reason="exception handler remains unsupported",
        first_unsupported_instruction=discovery.UnsupportedInstruction(0x1000,"unsupported"),
        direct_control_proof_status="rejected",
        direct_control_rejection_reason="existing rejection",
        direct_reference_gate_passed=False, executable_coverage_gaps=gaps,
        indirect_target_closure_proven=False,
    )


def _report(gaps, candidates):
    return discovery.FunctionDiscoveryReport(
        image_path="test.exe", image_base=0x140000000, size_of_image=0x4000,
        candidates=tuple(candidates), executable_coverage_gaps=gaps,
        direct_control_analysis_status="rejected", direct_control_analysis_error="existing rejection",
    )


def _resolved(payload, row):
    output=dict(row)
    output["executable_coverage_gaps"]=payload["coverage_gap_sets"][output.pop("executable_coverage_gap_set")]
    return output


def test_repeated_gap_sets_are_serialized_once_without_changing_any_candidate_field():
    gaps=(discovery.CoverageGap(0x2000,16,".text"),)
    candidates=tuple(_candidate(gaps,i) for i in range(10))
    payload=json.loads(_report(gaps,candidates).to_json())
    assert payload["version"]==3
    assert payload["executable_coverage_gap_set"]=="image"
    assert payload["coverage_gap_sets"]=={"image":[gap.to_dict() for gap in gaps]}
    for candidate,row in zip(candidates,payload["candidates"]):
        assert _resolved(payload,row)==candidate.to_dict()


def test_equal_distinct_tuples_deduplicate_but_keep_order_and_non_equal_tuples():
    a=discovery.CoverageGap(0x2000,16,".text")
    b=discovery.CoverageGap(0x3000,32,".code")
    image=(a,b)
    equal=tuple([a,b]);assert equal is not image
    other=(b,a)
    report=_report(image,[_candidate(equal),_candidate(other,1),_candidate((),2)])
    payload=report.to_dict()
    assert len(payload["coverage_gap_sets"])==3
    assert payload["candidates"][0]["executable_coverage_gap_set"]=="image"
    for candidate,row in zip(report.candidates,payload["candidates"]):
        assert _resolved(payload,row)==candidate.to_dict()


def test_empty_report_and_empty_gap_set_are_explicit_not_missing():
    payload=_report((),()).to_dict()
    assert payload["coverage_gap_sets"]=={"image":[]}
    assert payload["executable_coverage_gap_set"]=="image"
    assert payload["candidates"]==[]


def test_standalone_candidate_keeps_existing_full_gap_list_api():
    candidate=_candidate((discovery.CoverageGap(0x2000,16,".text"),))
    payload=candidate.to_dict()
    assert "executable_coverage_gap_set" not in payload
    assert payload["executable_coverage_gaps"]==[{"rva":0x2000,"size":16,"section":".text"}]


@pytest.mark.parametrize("change", [{"version":2},{"schema":"unrecognized"}])
def test_references_are_never_emitted_under_an_old_or_unknown_report_version(change):
    with pytest.raises(discovery.FunctionDiscoveryError,match="schema/version"):
        replace(_report((),()),**change).to_json()


def test_output_growth_is_linear_for_shared_image_gaps():
    def size(functions,gap_count):
        gaps=tuple(discovery.CoverageGap(0x2000+i*16,8,".text") for i in range(gap_count))
        return len(_report(gaps,(_candidate(gaps,i) for i in range(functions))).to_json())
    small=size(100,200)
    large=size(200,400)
    assert large < small*2.2
    assert large < 300_000


def test_serialization_does_not_change_selection_decisions_or_table_rendering():
    gaps=(discovery.CoverageGap(0x2000,16,".text"),)
    report=_report(gaps,[_candidate(gaps)])
    selection=report.starter_selection_manifest()
    table=discovery.render_table(report)
    report.to_json()
    assert report.starter_selection_manifest()==selection
    assert discovery.render_table(report)==table
    assert selection["functions"]==[]


def test_no_rejection_or_closure_flag_becomes_positive_on_serialization():
    gaps=(discovery.CoverageGap(0x2000,16,".text"),)
    payload=_report(gaps,[_candidate(gaps)]).to_dict()
    assert payload["direct_control_analysis_status"]=="rejected"
    assert payload["indirect_target_closure_proven"] is False
    row=payload["candidates"][0]
    assert not row["liftable"] and not row["direct_reference_gate_passed"]
    assert not row["indirect_target_closure_proven"]
    assert row["direct_control_rejection_reason"]=="existing rejection"
