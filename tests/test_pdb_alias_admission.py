"""Real helper-protocol aliases must not disappear before selected-leaf admission."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from lifter import function_discovery, pdb_coverage, pdb_function_inventory
from tests.test_pdb_function_inventory import HASH, fixture_image, fixture_parsed, helper_output


def _case(tmp_path: Path, monkeypatch, *, duplicate_leaf: bool = False,
          duplicate_pdata: bool = False):
    image = fixture_image()
    image[0x200:0x400] = b"\xCC" * 0x200
    image[0x200] = 0xC3
    image[0x220] = 0xC3
    image_path = tmp_path / "source.exe"
    image_path.write_bytes(image)
    parsed = fixture_parsed()
    parsed.path = str(image_path)
    parsed.sections[0].raw = bytes(image[0x200:0x400])
    parsed.sections[1].raw = bytes(image[0x400:0x600])
    parsed.runtime_functions = (SimpleNamespace(
        begin_rva=0x1000, end_rva=0x1001, unwind_info_rva=0x2800,
    ),)
    parsed.imports = ()
    rows = [(0x1000, 1), (0x1020, 1)]
    if duplicate_leaf:
        rows.append((0x1020, 1))
    if duplicate_pdata:
        rows.append((0x1000, 1))
    bound = pdb_function_inventory.bind_inventory(
        parsed, bytes(image), HASH, HASH, helper_output(*rows)
    )
    monkeypatch.setattr(pdb_function_inventory, "run_bound_inventory", lambda *_: bound)
    monkeypatch.setattr(function_discovery, "parse_pe_exports", lambda *_: ())
    selected = (SimpleNamespace(name="private_leaf", rva=0x1020, size=1),)
    return parsed, image_path, bound, selected


def _prove(parsed, image_path, selected):
    return pdb_coverage.prove_pdb_executable_coverage(
        parsed, image_path, Path("source.pdb"), Path("helper.exe"),
        Path("msdia.dll"), selected,
    )


def test_real_inventory_duplicate_selected_leaf_rejects(tmp_path, monkeypatch):
    parsed, image_path, bound, selected = _case(tmp_path, monkeypatch, duplicate_leaf=True)
    assert bound.symbol_count == 3
    assert bound.distinct_ranges == ((0x1000, 0x1001), (0x1020, 0x1021))
    assert bound.supplemental_ranges == ((0x1020, 0x1021),)
    assert bound.range_multiplicities == ((0x1000, 0x1001, 1), (0x1020, 0x1021, 2))
    with pytest.raises(pdb_coverage.PdbCoverageError, match="aliased PDB function range"):
        _prove(parsed, image_path, selected)


def test_real_inventory_duplicate_other_range_keeps_unique_leaf(tmp_path, monkeypatch):
    parsed, image_path, bound, selected = _case(tmp_path, monkeypatch, duplicate_pdata=True)
    proof = _prove(parsed, image_path, selected)
    assert bound.symbol_count == 3
    assert bound.supplemental_ranges == ((0x1020, 0x1021),)
    assert bound.range_multiplicities == ((0x1000, 0x1001, 2), (0x1020, 0x1021, 1))
    assert proof.direct_flow.coverage_gaps == ()
    assert proof.direct_flow.direct_reference_gate_passed
    assert proof.direct_flow.indirect_target_closure_proven is False


def test_real_inventory_unique_leaf_still_passes(tmp_path, monkeypatch):
    parsed, image_path, bound, selected = _case(tmp_path, monkeypatch)
    proof = _prove(parsed, image_path, selected)
    assert bound.symbol_count == 2
    assert bound.range_multiplicities == ((0x1000, 0x1001, 1), (0x1020, 0x1021, 1))
    assert proof.direct_flow.coverage_gaps == ()
    assert proof.direct_flow.direct_reference_gate_passed


def test_missing_alias_multiplicity_rejects_instead_of_assuming_unique(tmp_path, monkeypatch):
    parsed, image_path, bound, selected = _case(tmp_path, monkeypatch, duplicate_leaf=True)
    monkeypatch.setattr(pdb_function_inventory, "run_bound_inventory",
                        lambda *_: replace(bound, range_multiplicities=()))
    with pytest.raises(pdb_coverage.PdbCoverageError, match="alias multiplicity inventory is incomplete"):
        _prove(parsed, image_path, selected)


@pytest.mark.parametrize("rows,diagnostic", [
    (((0x1000, 0x1001, 1), (0x1020, 0x1021, 1)), "incomplete"),
    (((0x1000, 0x1001, 1), (0x1020, 0x1021, True)), "malformed"),
    (((0x1000, 0x1001, 1), (0x1021, 0x1022, 2)), "malformed"),
])
def test_forged_alias_multiplicity_rejects(tmp_path, monkeypatch, rows, diagnostic):
    parsed, image_path, bound, selected = _case(tmp_path, monkeypatch, duplicate_leaf=True)
    monkeypatch.setattr(pdb_function_inventory, "run_bound_inventory",
                        lambda *_: replace(bound, range_multiplicities=rows))
    with pytest.raises(pdb_coverage.PdbCoverageError, match=diagnostic):
        _prove(parsed, image_path, selected)


def test_forged_duplicate_distinct_leaf_cannot_overwrite_alias_count(tmp_path, monkeypatch):
    parsed, image_path, bound, selected = _case(tmp_path, monkeypatch, duplicate_leaf=True)
    pdata, leaf = bound.distinct_ranges
    forged = replace(
        bound,
        symbol_count=4,
        distinct_ranges=(pdata, leaf, leaf),
        range_multiplicities=((*pdata, 1), (*leaf, 2), (*leaf, 1)),
    )
    monkeypatch.setattr(pdb_function_inventory, "run_bound_inventory", lambda *_: forged)
    with pytest.raises(pdb_coverage.PdbCoverageError, match="alias multiplicity inventory is malformed"):
        _prove(parsed, image_path, selected)


@pytest.mark.parametrize("spans", [
    ((0x1020, 0x1021), (0x1000, 0x1001)),
    ((0x1000, 0x1001), (0x1000, 0x1002), (0x1020, 0x1021)),
])
def test_forged_noncanonical_distinct_ranges_reject(tmp_path, monkeypatch, spans):
    parsed, image_path, bound, selected = _case(tmp_path, monkeypatch)
    forged = replace(
        bound,
        symbol_count=len(spans),
        distinct_ranges=spans,
        range_multiplicities=tuple((*span, 1) for span in spans),
    )
    monkeypatch.setattr(pdb_function_inventory, "run_bound_inventory", lambda *_: forged)
    with pytest.raises(pdb_coverage.PdbCoverageError, match="alias multiplicity inventory is malformed"):
        _prove(parsed, image_path, selected)
