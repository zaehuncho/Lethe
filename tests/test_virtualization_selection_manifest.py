"""Source binding and strict parsing for virtualization selection manifests."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from lifter.function_discovery import CoverageGap, FunctionCandidate
from packer import virtualization_selection as selection


SOURCE_SHA256 = "a" * 64
CONTENT_ID = "b" * 64


def _candidate(name: str, rva: int, size: int, gap: CoverageGap):
    return FunctionCandidate(
        name=name,
        source="pdata",
        rva=rva,
        size=size,
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
        executable_coverage_gaps=(gap,),
        indirect_target_closure_proven=False,
    )


@pytest.fixture
def evidence():
    gap = CoverageGap(0x1080, 0x10, ".text")
    code = bytes(range(0xA0))
    records = (
        SimpleNamespace(
            begin_rva=0x1000, end_rva=0x1010,
            unwind_info_rva=0x2000, unwind_flags=0),
        SimpleNamespace(
            begin_rva=0x1020, end_rva=0x1030,
            unwind_info_rva=0x2010, unwind_flags=0),
    )
    parsed = SimpleNamespace(
        is_dll=False,
        image_base=0x140000000,
        size_of_image=0x3000,
        sections=(SimpleNamespace(
            name=".text", rva=0x1000, raw=code,
            virtual_size=len(code), characteristics=0x60000020),),
        runtime_functions=records,
    )
    report = SimpleNamespace(candidates=(
        _candidate("First", 0x1000, 0x10, gap),
        _candidate("Second", 0x1020, 0x10, gap),
    ))
    manifest = selection.build_manifest(
        report, parsed, source_sha256=SOURCE_SHA256,
        source_pe_content_id=CONTENT_ID)
    for item in manifest["selections"]:
        item["indirect_target_closure"]["acknowledged"] = True
        item["coverage_gaps"][0]["acknowledged"] = True
        item["coverage_gaps"][0]["rationale"] = "reviewed linker padding"
    return parsed, report, manifest


def _verify(evidence, manifest=None):
    parsed, report, original = evidence
    return selection.verify_manifest_bytes(
        selection.canonical_json(original if manifest is None else manifest),
        parsed=parsed,
        report=report,
        source_sha256=SOURCE_SHA256,
        source_pe_content_id=CONTENT_ID,
    )


def test_deterministic_canonical_round_trip_binds_all_source_and_extent_fields(
        evidence):
    parsed, _report, manifest = evidence
    raw = selection.canonical_json(manifest)
    assert raw == selection.canonical_json(json.loads(raw))
    assert raw.endswith(b"\n") and b'": ' not in raw and b', "' not in raw
    assert manifest["source"] == {
        "image_base": 0x140000000,
        "machine": 0x8664,
        "pe_content_id": CONTENT_ID,
        "pe_kind": "exe",
        "sha256": SOURCE_SHA256,
        "size_of_image": 0x3000,
    }
    first = manifest["selections"][0]
    assert first["source_extent"] == first["lifted_body_extent"]
    assert first["runtime_function"]["index"] == 0
    assert first["original_bytes_sha256"] == hashlib.sha256(
        parsed.sections[0].raw[:0x10]).hexdigest()
    verified = _verify(evidence)
    assert verified.functions == (
        selection.SelectedFunction("First", 0x1000, 0x10),
        selection.SelectedFunction("Second", 0x1020, 0x10),
    )
    assert verified.gaps == (
        selection.GapAcknowledgement(
            0x1080, 0x10, "reviewed linker padding"),
    )


@pytest.mark.parametrize("field,value", [
    ("sha256", "c" * 64),
    ("pe_content_id", "c" * 64),
    ("pe_kind", "dll"),
    ("machine", 0x14C),
    ("image_base", 0x180000000),
    ("size_of_image", 0x4000),
])
def test_rejects_stale_different_or_rebased_source(evidence, field, value):
    manifest = copy.deepcopy(evidence[2])
    manifest["source"][field] = value
    with pytest.raises(selection.VirtualizationSelectionError, match="stale"):
        _verify(evidence, manifest)


def test_rejects_one_byte_function_mutation(evidence):
    parsed, report, manifest = evidence
    changed = bytearray(parsed.sections[0].raw)
    changed[3] ^= 1
    mutated = SimpleNamespace(**{
        **parsed.__dict__,
        "sections": (SimpleNamespace(
            **{**parsed.sections[0].__dict__, "raw": bytes(changed)}),),
    })
    with pytest.raises(selection.VirtualizationSelectionError, match="bytes changed"):
        selection.verify_manifest_bytes(
            selection.canonical_json(manifest), parsed=mutated, report=report,
            source_sha256=SOURCE_SHA256, source_pe_content_id=CONTENT_ID)


@pytest.mark.parametrize("mutation,expected", [
    (lambda item: item["runtime_function"].__setitem__("end_rva", 0x1011),
     "runtime-function identity"),
    (lambda item: item["direct_reference_verdict"].__setitem__(
        "gate_passed", True), "direct-reference verdict"),
    (lambda item: item["lifted_body_extent"].__setitem__("size", 15),
     "lifted body"),
])
def test_rejects_fabricated_extent_or_proof(evidence, mutation, expected):
    manifest = copy.deepcopy(evidence[2])
    mutation(manifest["selections"][0])
    with pytest.raises(selection.VirtualizationSelectionError, match=expected):
        _verify(evidence, manifest)


def test_rejects_duplicate_or_reordered_selections(evidence):
    manifest = copy.deepcopy(evidence[2])
    manifest["selections"].reverse()
    with pytest.raises(selection.VirtualizationSelectionError, match="increasing RVA"):
        _verify(evidence, manifest)
    manifest = copy.deepcopy(evidence[2])
    manifest["selections"].append(copy.deepcopy(manifest["selections"][-1]))
    with pytest.raises(selection.VirtualizationSelectionError, match="increasing RVA"):
        _verify(evidence, manifest)


def test_rejects_unknown_duplicate_and_noncanonical_json(evidence):
    raw = selection.canonical_json(evidence[2])
    unknown = copy.deepcopy(evidence[2])
    unknown["surprise"] = 1
    with pytest.raises(selection.VirtualizationSelectionError, match="unknown"):
        _verify(evidence, unknown)
    with pytest.raises(selection.VirtualizationSelectionError, match="canonical"):
        selection.verify_manifest_bytes(
            json.dumps(evidence[2], indent=2).encode(), parsed=evidence[0],
            report=evidence[1], source_sha256=SOURCE_SHA256,
            source_pe_content_id=CONTENT_ID)
    duplicate = raw[:-2] + b',"version":2}\n'
    with pytest.raises(selection.VirtualizationSelectionError, match="duplicate"):
        selection.verify_manifest_bytes(
            duplicate, parsed=evidence[0], report=evidence[1],
            source_sha256=SOURCE_SHA256, source_pe_content_id=CONTENT_ID)
    numeric = raw.replace(b'"version":2', b'"version":2.0')
    with pytest.raises(selection.VirtualizationSelectionError, match="non-integer"):
        selection.verify_manifest_bytes(
            numeric, parsed=evidence[0], report=evidence[1],
            source_sha256=SOURCE_SHA256, source_pe_content_id=CONTENT_ID)


def test_rejects_unacknowledged_gaps_and_indirect_closure(evidence):
    manifest = copy.deepcopy(evidence[2])
    manifest["selections"][0]["coverage_gaps"][0]["acknowledged"] = False
    manifest["selections"][0]["coverage_gaps"][0]["rationale"] = ""
    with pytest.raises(selection.VirtualizationSelectionError, match="not explicitly"):
        _verify(evidence, manifest)
    manifest = copy.deepcopy(evidence[2])
    manifest["selections"][0]["indirect_target_closure"]["acknowledged"] = False
    with pytest.raises(selection.VirtualizationSelectionError, match="does not acknowledge"):
        _verify(evidence, manifest)


def test_tail_approvals_are_function_bound_and_deduplicated(evidence):
    manifest = copy.deepcopy(evidence[2])
    approval = {
        "function_rva": 0x1000,
        "instruction_rva": 0x1008,
        "rationale": "reviewed tail dispatch",
        "target_rva": 0x2000,
    }
    manifest["selections"][0]["tail_exit_approvals"] = [approval]
    assert _verify(evidence, manifest).tail_exits == (
        selection.TailExitApproval(
            0x1000, 0x1008, 0x2000, "reviewed tail dispatch"),
    )
    manifest["selections"][1]["tail_exit_approvals"] = [approval]
    with pytest.raises(selection.VirtualizationSelectionError, match="different"):
        _verify(evidence, manifest)


def test_manifest_file_rejects_hardlinks(evidence, tmp_path):
    original = tmp_path / "selection.json"
    alias = tmp_path / "alias.json"
    original.write_bytes(selection.canonical_json(evidence[2]))
    try:
        os.link(original, alias)
    except OSError:
        pytest.skip("hardlinks unavailable")
    with pytest.raises(selection.VirtualizationSelectionError, match="hard-linked"):
        selection._load_bytes(str(alias))
