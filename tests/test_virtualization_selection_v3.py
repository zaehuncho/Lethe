"""Version-3 source/body extent bindings and fail-closed compatibility."""
from __future__ import annotations

import copy
import hashlib
import struct
from dataclasses import replace
from types import SimpleNamespace

import pytest

from lifter.function_discovery import FunctionCandidate
from packer import virtualization_selection as selection


SOURCE_SHA256 = "a" * 64
CONTENT_ID = "b" * 64
BODY = b"\xB8\x2A\x00\x00\x00\xC3"
SOURCE = BODY + b"\xCC\xCC"
PDATA = struct.pack("<III", 0x1000, 0x1000 + len(SOURCE), 0x2000)


def _evidence():
    candidate = FunctionCandidate(
        name="PaddedLeaf",
        source="pdata",
        rva=0x1000,
        size=len(SOURCE),
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
        direct_reference_gate_passed=True,
        executable_coverage_gaps=(),
        indirect_target_closure_proven=False,
        lifted_body_size=len(BODY),
    )
    parsed = SimpleNamespace(
        is_dll=False,
        image_base=0x140000000,
        size_of_image=0x3000,
        pdata_rva=0x2800,
        pdata_count=1,
        sections=(
            SimpleNamespace(
                name=".text",
                rva=0x1000,
                raw=SOURCE,
                characteristics=0x60000020,
            ),
            SimpleNamespace(
                name=".xdata",
                rva=0x2000,
                raw=b"\x01\x00\x00\x00",
                characteristics=0x40000040,
            ),
            SimpleNamespace(
                name=".pdata",
                rva=0x2800,
                raw=PDATA,
                characteristics=0x40000040,
            ),
        ),
        runtime_functions=(SimpleNamespace(
            begin_rva=0x1000,
            end_rva=0x1000 + len(SOURCE),
            unwind_info_rva=0x2000,
            unwind_flags=0,
        ),),
    )
    report = SimpleNamespace(candidates=(candidate,))
    manifest = selection.build_manifest(
        report,
        parsed,
        source_sha256=SOURCE_SHA256,
        source_pe_content_id=CONTENT_ID,
    )
    manifest["selections"][0]["indirect_target_closure"]["acknowledged"] = True
    return parsed, report, manifest


def _verify(parsed, report, manifest):
    return selection.verify_manifest_bytes(
        selection.canonical_json(manifest),
        parsed=parsed,
        report=report,
        source_sha256=SOURCE_SHA256,
        source_pe_content_id=CONTENT_ID,
    )


def test_v3_binds_unequal_source_and_lifted_body_extents():
    parsed, report, manifest = _evidence()
    item = manifest["selections"][0]

    assert manifest["version"] == 3
    assert item["source_extent"] == {"rva": 0x1000, "size": len(SOURCE)}
    assert item["lifted_body_extent"] == {"rva": 0x1000, "size": len(BODY)}
    assert item["source_extent_sha256"] == hashlib.sha256(SOURCE).hexdigest()
    assert item["lifted_body_sha256"] == hashlib.sha256(BODY).hexdigest()
    assert item["padding_proof"] == {
        "canonical_body_size": len(BODY),
        "source_extent_runtime_bound": True,
        "status": "passed",
        "suffix_rva": 0x1000 + len(BODY),
        "suffix_size": len(SOURCE) - len(BODY),
    }
    assert _verify(parsed, report, manifest).functions == (
        selection.SelectedFunction(
            "PaddedLeaf", 0x1000, len(SOURCE), len(BODY)),
    )


def test_v3_emitter_rejects_unbacked_pdata_claim():
    parsed, report, _manifest = _evidence()
    changed = SimpleNamespace(**{
        **parsed.__dict__,
        "sections": parsed.sections[:2],
    })

    with pytest.raises(selection.VirtualizationSelectionError, match="not file-backed"):
        selection.build_manifest(
            report,
            changed,
            source_sha256=SOURCE_SHA256,
            source_pe_content_id=CONTENT_ID,
        )


@pytest.mark.parametrize(
    "mutation,match",
    (
        (lambda item: item.__setitem__("source_extent_sha256", "c" * 64),
         "source extent changed"),
        (lambda item: item.__setitem__("lifted_body_sha256", "c" * 64),
         "lifted body changed"),
        (lambda item: item["lifted_body_extent"].__setitem__("size", 5),
         "currently liftable"),
        (lambda item: item["padding_proof"].__setitem__("suffix_size", 1),
         "padding proof"),
        (lambda item: item["padding_proof"].__setitem__(
            "source_extent_runtime_bound", False), "padding proof"),
    ),
)
def test_v3_rejects_hash_extent_and_padding_proof_tampering(mutation, match):
    parsed, report, manifest = _evidence()
    mutation(manifest["selections"][0])
    with pytest.raises(selection.VirtualizationSelectionError, match=match):
        _verify(parsed, report, manifest)


def test_v3_rejects_stale_pdata_and_current_body_split():
    parsed, report, manifest = _evidence()
    stale_pdata = SimpleNamespace(**{
        **parsed.__dict__,
        "runtime_functions": (SimpleNamespace(
            begin_rva=0x1000,
            end_rva=0x1000 + len(SOURCE) + 1,
            unwind_info_rva=0x2000,
            unwind_flags=0,
        ),),
    })
    with pytest.raises(selection.VirtualizationSelectionError, match="PDATA bytes"):
        _verify(stale_pdata, report, manifest)

    stale_report = SimpleNamespace(candidates=(replace(
        report.candidates[0], lifted_body_size=len(SOURCE)),))
    with pytest.raises(selection.VirtualizationSelectionError, match="currently liftable"):
        _verify(parsed, stale_report, manifest)


@pytest.mark.parametrize(
    ("mutation", "match"),
    (
        (lambda parsed: delattr(parsed, "pdata_rva"), "requires PDATA"),
        (lambda parsed: setattr(parsed, "pdata_count", 0), "nonempty PDATA"),
        (lambda parsed: setattr(parsed, "pdata_count", 2), "count does not match"),
        (lambda parsed: setattr(parsed, "pdata_rva", 0), "geometry is invalid"),
        (lambda parsed: setattr(parsed, "pdata_rva", 0x2801),
         "geometry is invalid"),
    ),
)
def test_v3_rejects_free_floating_or_forged_pdata_inventory(mutation, match):
    parsed, report, manifest = _evidence()
    mutation(parsed)

    with pytest.raises(selection.VirtualizationSelectionError, match=match):
        _verify(parsed, report, manifest)


@pytest.mark.parametrize(
    ("pdata_raw", "match"),
    (
        (b"", "not file-backed"),
        (PDATA[:-1], "not file-backed"),
        (struct.pack("<III", 0x1000, 0x1000 + len(SOURCE) - 1, 0x2000),
         "do not match"),
        (struct.pack("<III", 0x1000, 0x1000 + len(SOURCE), 0x2004),
         "UNWIND_INFO|do not match"),
    ),
)
def test_v3_rejects_missing_truncated_or_forged_pdata_bytes(pdata_raw, match):
    parsed, report, manifest = _evidence()
    pdata = SimpleNamespace(**{
        **parsed.sections[2].__dict__,
        "raw": pdata_raw,
    })
    changed = SimpleNamespace(**{
        **parsed.__dict__,
        "sections": (*parsed.sections[:2], pdata),
    })

    with pytest.raises(selection.VirtualizationSelectionError, match=match):
        _verify(changed, report, manifest)


def test_v3_recomputes_canonical_suffix_after_synchronized_hash_changes():
    parsed, report, manifest = _evidence()
    noncanonical = BODY + b"\x00\x00"
    changed = SimpleNamespace(**{
        **parsed.__dict__,
        "sections": (
            SimpleNamespace(
                **{**parsed.sections[0].__dict__, "raw": noncanonical}),
            *parsed.sections[1:],
        ),
    })
    item = manifest["selections"][0]
    item["source_extent_sha256"] = hashlib.sha256(noncanonical).hexdigest()
    item["lifted_body_sha256"] = hashlib.sha256(BODY).hexdigest()

    with pytest.raises(
            selection.VirtualizationSelectionError,
            match="padding proof|canonical padding"):
        _verify(changed, report, manifest)


def test_v2_parser_remains_strictly_equal_extent_only():
    parsed, report, manifest = _evidence()
    item = manifest["selections"][0]
    item.pop("source_extent_sha256")
    item.pop("lifted_body_sha256")
    item.pop("padding_proof")
    item["original_bytes_sha256"] = hashlib.sha256(SOURCE).hexdigest()
    manifest["version"] = 2

    with pytest.raises(selection.VirtualizationSelectionError, match="version-2"):
        _verify(parsed, report, manifest)
