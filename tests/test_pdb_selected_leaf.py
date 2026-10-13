"""Exact-PDB selected leaf ranges must not be decoded twice."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import struct
from types import SimpleNamespace
from uuid import UUID

import pytest

from lifter import direct_control_flow as flow
from lifter import function_discovery
from lifter import pdb_coverage as coverage
from lifter import pdb_function_inventory as inventory


EXEC = 0x60000020


def _fixture(tmp_path: Path, *, selected_code: bytes = b"\xc3"):
    text = bytearray(b"\xcc" * 0x40)
    text[0] = 0xC3  # Retained PDATA function.
    text[0x20:0x20 + len(selected_code)] = selected_code
    image = tmp_path / "source-image.bin"
    image.write_bytes(b"exact source pin")
    parsed = SimpleNamespace(
        path=str(image),
        size_of_image=0x3000,
        sections=(SimpleNamespace(
            name=".text", rva=0x1000, virtual_size=len(text),
            raw=bytes(text), characteristics=EXEC,
        ),),
        runtime_functions=(SimpleNamespace(
            begin_rva=0x1000, end_rva=0x1001, unwind_info_rva=0x2000,
        ),),
        imports=(),
    )
    leaf = (0x1020, 0x1020 + len(selected_code))
    bound = inventory.BoundPdbInventory(
        image_sha256=sha256(image.read_bytes()).hexdigest(),
        pdb_sha256="b" * 64,
        helper_sha256="c" * 64,
        msdia_sha256="d" * 64,
        identity=inventory.CodeViewIdentity(UUID(int=1), 1),
        symbol_count=2,
        distinct_ranges=((0x1000, 0x1001), leaf),
        supplemental_ranges=(leaf,),
        range_multiplicities=((0x1000, 0x1001, 1), (*leaf, 1)),
    )
    spec = (SimpleNamespace(name="selected_leaf", rva=leaf[0], size=len(selected_code)),)
    return parsed, bound, spec


def _prove(monkeypatch, tmp_path, parsed, bound, spec):
    monkeypatch.setattr(inventory, "run_bound_inventory", lambda *_args: bound)
    # The synthetic file pins commit bytes; it is not a full PE export table.
    monkeypatch.setattr(function_discovery, "parse_pe_exports", lambda *_args: ())
    return coverage.prove_pdb_executable_coverage(
        parsed, Path(parsed.path), tmp_path / "source.pdb",
        tmp_path / "helper.exe", tmp_path / "msdia.dll", spec,
    )


def test_exact_pdb_selected_unframed_leaf_is_decoded_once_and_replays(
    monkeypatch, tmp_path
) -> None:
    parsed, bound, spec = _fixture(tmp_path)
    proof = _prove(monkeypatch, tmp_path, parsed, bound, spec)
    assert proof.inventory.supplemental_ranges == ((0x1020, 0x1021),)
    assert proof.direct_flow.coverage_gaps == ()
    assert proof.direct_flow.direct_reference_gate_passed
    assert (0x1020, 0x1021) not in {
        (item.begin_rva, item.end_rva)
        for item in proof.direct_flow.decoded_supplemental_ranges
    }
    assert proof.direct_flow.selected_functions[0].rva == 0x1020
    binding = coverage.bind_pdb_commit_proof(parsed, proof, spec)
    assert binding.supplemental_ranges == (
        (0x1001, 0x1020), (0x1021, 0x1040)
    )
    coverage.validate_pdb_commit_binding(parsed, spec, binding)
    parsed.sections[0].raw = parsed.sections[0].raw[:-1] + b"\x90"
    with pytest.raises(coverage.PdbCoverageError, match="source changed"):
        coverage.validate_pdb_commit_binding(parsed, spec, binding)


@pytest.mark.parametrize("bound_leaf", [
    (0x1020, 0x1022),  # Superset including selected RET and padding.
    (0x101F, 0x1021),  # Overlap through selected entry from the left.
])
def test_partial_pdb_overlap_with_selected_leaf_still_rejects(
    monkeypatch, tmp_path, bound_leaf
) -> None:
    parsed, bound, spec = _fixture(tmp_path)
    bound = replace(bound, distinct_ranges=((0x1000, 0x1001), bound_leaf),
                    supplemental_ranges=(bound_leaf,),
                    range_multiplicities=((0x1000, 0x1001, 1), (*bound_leaf, 1)))
    with pytest.raises(coverage.PdbCoverageError, match="overlaps a known function"):
        _prove(monkeypatch, tmp_path, parsed, bound, spec)


@pytest.mark.parametrize("selected_code,bound_leaf", [
    (b"\xcc\xc3", (0x1021, 0x1022)),  # PDB covers only the RET suffix.
    (b"\xc3\xcc", (0x1020, 0x1021)),  # PDB covers only the RET prefix.
])
def test_pdb_proper_subset_of_selected_extent_still_rejects(
    monkeypatch, tmp_path, selected_code, bound_leaf
) -> None:
    parsed, bound, spec = _fixture(tmp_path, selected_code=selected_code)
    bound = replace(bound, distinct_ranges=((0x1000, 0x1001), bound_leaf),
                    supplemental_ranges=(bound_leaf,),
                    range_multiplicities=((0x1000, 0x1001, 1), (*bound_leaf, 1)))
    with pytest.raises(coverage.PdbCoverageError, match="overlaps a known function"):
        _prove(monkeypatch, tmp_path, parsed, bound, spec)


def test_selected_leaf_interior_direct_branch_still_rejects(
    monkeypatch, tmp_path
) -> None:
    parsed, bound, spec = _fixture(tmp_path, selected_code=b"\x90\xc3")
    text = bytearray(parsed.sections[0].raw)
    text[:5] = b"\xe9" + struct.pack("<i", 0x1021 - 0x1005)
    parsed.sections[0].raw = bytes(text)
    parsed.runtime_functions = (SimpleNamespace(
        begin_rva=0x1000, end_rva=0x1005, unwind_info_rva=0x2000,
    ),)
    bound = replace(bound, distinct_ranges=((0x1000, 0x1005), (0x1020, 0x1022)),
                    range_multiplicities=((0x1000, 0x1005, 1), (0x1020, 0x1022, 1)))
    with pytest.raises(coverage.PdbCoverageError, match="enters selected.*interior"):
        _prove(monkeypatch, tmp_path, parsed, bound, spec)


def test_duplicate_bound_pdb_selected_leaf_still_rejects(
    monkeypatch, tmp_path
) -> None:
    parsed, bound, spec = _fixture(tmp_path)
    leaf = (0x1020, 0x1021)
    bound = replace(bound, supplemental_ranges=(leaf, leaf))
    with pytest.raises(coverage.PdbCoverageError, match="supplemental code ranges overlap"):
        _prove(monkeypatch, tmp_path, parsed, bound, spec)


def test_pdb_span_intersecting_pdata_is_not_filtered(
    monkeypatch, tmp_path
) -> None:
    parsed, bound, _spec = _fixture(tmp_path, selected_code=b"\x90\xc3")
    bound = replace(bound, distinct_ranges=((0x1000, 0x1002), (0x1020, 0x1022)),
                    supplemental_ranges=((0x1000, 0x1002), (0x1020, 0x1022)),
                    range_multiplicities=((0x1000, 0x1002, 1), (0x1020, 0x1022, 1)))
    spec = (SimpleNamespace(name="not_a_leaf", rva=0x1000, size=2),)
    with pytest.raises(coverage.PdbCoverageError, match="partially overlaps runtime function"):
        _prove(monkeypatch, tmp_path, parsed, bound, spec)


def test_raw_supplemental_exact_selected_leaf_still_rejects(tmp_path) -> None:
    parsed, _bound, spec = _fixture(tmp_path)
    with pytest.raises(flow.DirectControlFlowError, match="overlaps a known function"):
        flow.analyze_direct_control_flow(
            parsed, spec, production=False,
            _supplemental_code_ranges=((0x1020, 0x1021),),
        )
