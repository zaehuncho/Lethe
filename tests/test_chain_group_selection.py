"""Contiguous, source-bound CHAININFO selection and manifest regressions."""
from __future__ import annotations

import copy
import struct
from dataclasses import replace
from types import SimpleNamespace

import pytest

from lifter import function_discovery, virtualization_plan as plan
from packer import pe_analyze, virtualization_selection as selection


SOURCE_SHA = "a" * 64
CONTENT_ID = "b" * 64
CODE = bytes.fromhex("B807000000C3")  # mov eax, 7; ret
PDATA = struct.pack("<III", 0x1000, 0x1005, 0x2000) + struct.pack(
    "<III", 0x1005, 0x1006, 0x2010)
XDATA = (bytes.fromhex("01000000") + bytes(12) +
         bytes.fromhex("21000000") + struct.pack("<III", 0x1000, 0x1005, 0x2000))


def _fixture():
    sections = (
        SimpleNamespace(name=".text", rva=0x1000, raw=CODE,
                        virtual_size=len(CODE), characteristics=0x60000020),
        SimpleNamespace(name=".xdata", rva=0x2000, raw=XDATA,
                        virtual_size=len(XDATA), characteristics=0x40000040),
        SimpleNamespace(name=".pdata", rva=0x2800, raw=PDATA,
                        virtual_size=len(PDATA), characteristics=0x40000040),
    )
    records = pe_analyze._parse_pdata(PDATA, 0x2800, 0x3000, sections)
    parsed = SimpleNamespace(
        path="group.exe", image_base=0x140000000, size_of_image=0x3000,
        is_dll=False, sections=sections, pdata_rva=0x2800, pdata_count=2,
        runtime_functions=records, imports=(),
    )
    report = function_discovery.discover_functions(parsed, exports=())
    return parsed, report


def _manifest(parsed, report):
    value = selection.build_manifest(
        report, parsed, source_sha256=SOURCE_SHA,
        source_pe_content_id=CONTENT_ID)
    value["selections"][0]["indirect_target_closure"]["acknowledged"] = True
    return value


def _verify(parsed, report, value):
    return selection.verify_manifest_bytes(
        selection.canonical_json(value), parsed=parsed, report=report,
        source_sha256=SOURCE_SHA, source_pe_content_id=CONTENT_ID)


def test_real_pdata_chain_group_is_one_full_body_candidate_and_v4_selection():
    parsed, report = _fixture()
    assert len(report.candidates) == 1
    candidate = report.candidates[0]
    assert (candidate.rva, candidate.size, candidate.body_size) == (0x1000, 6, 6)
    assert candidate.extent_kind == "runtime_function_group"
    assert candidate.liftable and candidate.direct_control_proof_status == "passed"
    value = _manifest(parsed, report)
    assert value["version"] == 4
    item = value["selections"][0]
    assert len(item["runtime_functions"]) == 2
    assert item["runtime_functions"][1]["chain_primary_rva"] == 0x1000
    assert item["padding_proof"]["suffix_size"] == 0
    assert _verify(parsed, report, value).functions == (
        selection.SelectedFunction(candidate.name, 0x1000, 6, 6),)


def test_group_selection_subsumes_both_pdata_records_in_materialization_plan():
    parsed, report = _fixture()
    candidate = report.candidates[0]
    reader = plan.SectionImage((
        plan.SectionBytes(".text", 0x1000, len(CODE), CODE, 0x60000020),
    ))
    source_exceptions = plan.SourceExceptionMetadata(
        0x2800,
        tuple(plan.SourceRuntimeFunction(
            item.begin_rva, item.end_rva, item.unwind_info_rva,
            item.unwind_flags, item.chain_primary_rva,
        ) for item in parsed.runtime_functions),
    )
    manifest = plan.compile_virtualization_manifest(
        [plan.FunctionSpec(candidate.name, candidate.rva, candidate.size)],
        reader,
        generated_text_rva=0x5000,
        generated_data_rva=0x7000,
        source_exception_metadata=source_exceptions,
        require_source_exception_metadata=True,
    )
    assert [item.begin_rva for item in manifest.exception_table.removed] == [
        0x1000, 0x1005]
    assert len(manifest.exception_table.generated) == 1


@pytest.mark.parametrize("mutation,match", (
    (lambda item: item["runtime_functions"][1].__setitem__(
        "chain_primary_rva", 0x1100), "identity changed"),
    (lambda item: item["runtime_functions"][1].__setitem__(
        "unwind_flags", 1), "identity changed"),
    (lambda item: item["runtime_functions"].pop(), "identity changed"),
    (lambda item: item["lifted_body_extent"].__setitem__(
        "size", 5), "currently liftable"),
    (lambda item: item["padding_proof"].__setitem__(
        "suffix_size", 1), "padding proof"),
))
def test_group_manifest_rejects_stale_or_truncated_identity(mutation, match):
    parsed, report = _fixture()
    value = copy.deepcopy(_manifest(parsed, report))
    mutation(value["selections"][0])
    with pytest.raises(selection.VirtualizationSelectionError, match=match):
        _verify(parsed, report, value)


def test_group_manifest_rejects_version_downgrade_and_forged_parsed_root():
    parsed, report = _fixture()
    value = _manifest(parsed, report)
    downgraded = copy.deepcopy(value)
    downgraded["version"] = 3
    with pytest.raises(selection.VirtualizationSelectionError):
        _verify(parsed, report, downgraded)
    forged = SimpleNamespace(**{
        **parsed.__dict__,
        "runtime_functions": (
            parsed.runtime_functions[0],
            replace(parsed.runtime_functions[1], chain_primary_rva=0x1100),
        ),
    })
    with pytest.raises(selection.VirtualizationSelectionError, match="PDATA"):
        _verify(forged, report, value)


@pytest.mark.parametrize("variant", ("wrong_root", "handler", "noncontiguous",
                                       "interior_export"))
def test_unproven_group_is_not_presented_as_one_candidate(variant):
    parsed, _report = _fixture()
    records = list(parsed.runtime_functions)
    sections = list(parsed.sections)
    exports = ()
    if variant == "wrong_root":
        records[1] = replace(records[1], chain_primary_rva=0x1100)
    elif variant == "handler":
        records[1] = replace(records[1], unwind_flags=5)
    elif variant == "noncontiguous":
        records[1] = replace(records[1], begin_rva=0x1006, end_rva=0x1007)
        sections[0] = SimpleNamespace(**{
            **sections[0].__dict__, "raw": CODE[:5] + b"\xCC" + CODE[5:],
            "virtual_size": 7,
        })
    else:
        exports = (function_discovery.ExportSymbol("fragment", 1, 0x1005),)
    changed = SimpleNamespace(**{
        **parsed.__dict__, "sections": tuple(sections),
        "runtime_functions": tuple(records),
    })
    report = function_discovery.discover_functions(changed, exports=exports)
    assert not any(candidate.extent_kind == "runtime_function_group"
                   for candidate in report.candidates)


def test_partial_chain_prefix_is_never_selected_or_bound():
    parsed, _report = _fixture()
    suffix = replace(parsed.runtime_functions[1],
                     begin_rva=0x1007, end_rva=0x1008)
    text = SimpleNamespace(**{
        **parsed.sections[0].__dict__,
        "raw": CODE + b"\xCC\xC3", "virtual_size": 8,
    })
    changed = SimpleNamespace(**{
        **parsed.__dict__,
        "sections": (text, *parsed.sections[1:]),
        "runtime_functions": (*parsed.runtime_functions, suffix),
        "pdata_count": 3,
    })
    report = function_discovery.discover_functions(changed, exports=())
    assert not any(candidate.extent_kind == "runtime_function_group"
                   for candidate in report.candidates)
    with pytest.raises(selection.VirtualizationSelectionError,
                       match="omits a chained fragment"):
        selection._runtime_group_identities(changed, 0x1000, 6)


def test_v4_mixed_group_and_v3_padding_candidate_preserves_both_proofs():
    leaf = bytes.fromhex("B82A000000C3CCCC")
    code = CODE + b"\xCC" * (0x1010 - 0x1000 - len(CODE)) + leaf
    pdata = PDATA + struct.pack("<III", 0x1010, 0x1018, 0x2020)
    xdata = XDATA + bytes(0x2020 - 0x2000 - len(XDATA)) + bytes.fromhex(
        "01000000")
    sections = (
        SimpleNamespace(name=".text", rva=0x1000, raw=code,
                        virtual_size=len(code), characteristics=0x60000020),
        SimpleNamespace(name=".xdata", rva=0x2000, raw=xdata,
                        virtual_size=len(xdata), characteristics=0x40000040),
        SimpleNamespace(name=".pdata", rva=0x2800, raw=pdata,
                        virtual_size=len(pdata), characteristics=0x40000040),
    )
    parsed = SimpleNamespace(
        path="mixed.exe", image_base=0x140000000, size_of_image=0x3000,
        is_dll=False, sections=sections, pdata_rva=0x2800, pdata_count=3,
        runtime_functions=pe_analyze._parse_pdata(
            pdata, 0x2800, 0x3000, sections), imports=(),
    )
    report = function_discovery.discover_functions(parsed, exports=())
    assert [(item.extent_kind, item.body_size, item.size)
            for item in report.candidates] == [
        ("runtime_function_group", 6, 6),
        ("runtime_function", 6, 8),
    ]
    value = _manifest(parsed, report)
    assert value["version"] == 4
    for item in value["selections"]:
        item["indirect_target_closure"]["acknowledged"] = True
        for gap in item["coverage_gaps"]:
            gap["acknowledged"] = True
            gap["rationale"] = "exact test fixture INT3 padding"
    assert [item.body_size for item in _verify(parsed, report, value).functions] == [
        6, 6]


@pytest.mark.parametrize("partition", (
    ((0x1000, 0x1006, 0), (0x1006, 0x1007, 4)),
    ((0x1000, 0x1005, 0), (0x1005, 0x1006, 4),
     (0x1006, 0x1007, 4)),
))
def test_manual_primary_or_prefix_spec_cannot_orphan_chain_fragment(partition):
    reader = plan.SectionImage((
        plan.SectionBytes(".text", 0x1000, 7, CODE + b"\x90", 0x60000020),
    ))
    source_exceptions = plan.SourceExceptionMetadata(
        0x2800,
        tuple(plan.SourceRuntimeFunction(
            begin, end, 0x2000 + index * 0x10,
            flags, 0x1000 if flags else 0,
        ) for index, (begin, end, flags) in enumerate(partition)),
    )
    with pytest.raises(plan.FunctionRejected, match="omits a chained fragment"):
        plan.compile_virtualization_manifest(
            [plan.FunctionSpec("incomplete", 0x1000, 6)], reader,
            generated_text_rva=0x5000, generated_data_rva=0x7000,
            source_exception_metadata=source_exceptions,
            require_source_exception_metadata=True,
        )
