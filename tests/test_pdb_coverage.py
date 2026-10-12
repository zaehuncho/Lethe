"""Canonical executable-residual proof contracts."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import struct
from types import SimpleNamespace
from uuid import UUID

import pytest

from lifter import direct_control_flow as flow
from lifter import pdb_coverage as coverage
from lifter import pdb_function_inventory as inventory


EXEC = 0x60000020
READ = 0x40000040
NOP10 = bytes.fromhex("66660F1F840000000000")


def fixture(*, virtual_size: int = 0x80):
    text = bytearray(b"\xCC" * 0x80)
    text[0] = 0xC3  # selected PDATA function
    text[0x20] = 0xC3  # PDB-only function
    text[0x30:0x36] = b"\xFF\x25" + struct.pack("<i", 0x2000 - 0x1036)
    text[0x40:0x4A] = NOP10
    text[0x50:0x59] = b"\x48\x83\xE9\x10\xE9" + struct.pack("<i", 0x1000 - 0x1059)
    parsed = SimpleNamespace(
        sections=(
            SimpleNamespace(name=".text", rva=0x1000, virtual_size=virtual_size,
                            raw=bytes(text), characteristics=EXEC),
            SimpleNamespace(name=".idata", rva=0x2000, virtual_size=0x20,
                            raw=b"\0" * 0x20, characteristics=READ),
        ),
        runtime_functions=(SimpleNamespace(begin_rva=0x1000, end_rva=0x1001),),
        imports=(SimpleNamespace(funcs=(SimpleNamespace(iat_rva=0x2000),)),),
    )
    bound = inventory.BoundPdbInventory(
        image_sha256="a" * 64, pdb_sha256="b" * 64,
        helper_sha256="c" * 64,
        identity=inventory.CodeViewIdentity(UUID(int=1), 1),
        symbol_count=2,
        distinct_ranges=((0x1000, 0x1001), (0x1020, 0x1021)),
        supplemental_ranges=((0x1020, 0x1021),),
    )
    return parsed, bound


def prove(monkeypatch, parsed=None, bound=None):
    if parsed is None or bound is None:
        parsed, bound = fixture()
    monkeypatch.setattr(inventory, "run_bound_inventory", lambda *args: bound)
    spec = SimpleNamespace(name="selected", rva=0x1000, size=1)
    return coverage.prove_pdb_executable_coverage(
        parsed, Path("image.exe"), Path("image.pdb"),
        Path("helper.exe"), Path("msdia.dll"), (spec,)
    )


def test_canonical_residuals_are_decoded_and_direct_edges_checked(monkeypatch) -> None:
    result = prove(monkeypatch)
    assert result.direct_flow.coverage_gaps == ()
    assert result.direct_flow.direct_reference_gate_passed
    assert not result.direct_flow.indirect_target_closure_proven
    kinds = {token.kind for token in result.tokens}
    assert kinds == {
        "int3_padding", "canonical_nop10", "exact_import_jump", "this_adjustor"
    }
    assert len(result.direct_flow.decoded_supplemental_ranges) == 3
    adjustor = next(x for x in result.direct_flow.direct_transfers if x.source_rva == 0x1054)
    assert adjustor.target_rva == 0x1000
    assert not adjustor.source_has_runtime_function


def test_public_default_still_rejects_executable_gap() -> None:
    parsed, _ = fixture()
    with pytest.raises(flow.CoverageGapError):
        flow.analyze_direct_control_flow(
            parsed, (SimpleNamespace(name="selected", rva=0x1000, size=1),)
        )


@pytest.mark.parametrize("offset,value,match", [
    (0x0F, 0x90, "unclassified executable byte"),
    (0x43, 0xFF, "unclassified executable byte"),
    (0x51, 0x81, "unclassified executable byte"),
])
def test_noncanonical_residual_byte_rejects(monkeypatch, offset, value, match) -> None:
    parsed, bound = fixture()
    text = bytearray(parsed.sections[0].raw)
    text[offset] = value
    parsed.sections[0].raw = bytes(text)
    with pytest.raises(coverage.PdbCoverageError, match=match):
        prove(monkeypatch, parsed, bound)


def test_ff25_must_target_exact_normal_file_backed_iat(monkeypatch) -> None:
    parsed, bound = fixture()
    parsed.imports = ()
    with pytest.raises(coverage.PdbCoverageError, match="unproven FF25 import slot"):
        prove(monkeypatch, parsed, bound)
    parsed, bound = fixture()
    parsed.imports = (
        SimpleNamespace(funcs=(SimpleNamespace(iat_rva=0x2000),)),
        SimpleNamespace(funcs=(SimpleNamespace(iat_rva=0x2000),)),
    )
    with pytest.raises(coverage.PdbCoverageError, match="overlap"):
        prove(monkeypatch, parsed, bound)
    parsed, bound = fixture()
    parsed.sections[1].characteristics = EXEC
    with pytest.raises(coverage.PdbCoverageError, match="unproven FF25 import slot"):
        prove(monkeypatch, parsed, bound)


def test_adjustor_must_target_exact_function_entry(monkeypatch) -> None:
    parsed, bound = fixture()
    text = bytearray(parsed.sections[0].raw)
    text[0x55:0x59] = struct.pack("<i", 0x1001 - 0x1059)
    parsed.sections[0].raw = bytes(text)
    with pytest.raises(coverage.PdbCoverageError, match="misses a function entry"):
        prove(monkeypatch, parsed, bound)


def test_non_file_backed_virtual_tail_and_discardable_section_reject(monkeypatch) -> None:
    parsed, bound = fixture(virtual_size=0x90)
    with pytest.raises(coverage.PdbCoverageError, match="non-file-backed"):
        prove(monkeypatch, parsed, bound)
    parsed, bound = fixture()
    parsed.sections[0].characteristics |= 0x02000000
    with pytest.raises(coverage.PdbCoverageError, match="not retained"):
        prove(monkeypatch, parsed, bound)


def test_pdb_only_direct_jump_to_selected_interior_rejects(monkeypatch) -> None:
    parsed, bound = fixture()
    text = bytearray(parsed.sections[0].raw)
    text[0] = 0x90
    text[1] = 0xC3
    text[0x20:0x25] = b"\xE9" + struct.pack("<i", 0x1001 - 0x1025)
    parsed.sections[0].raw = bytes(text)
    parsed.runtime_functions = (SimpleNamespace(begin_rva=0x1000, end_rva=0x1002),)
    bound = replace(bound, distinct_ranges=((0x1000, 0x1002), (0x1020, 0x1025)),
                    supplemental_ranges=((0x1020, 0x1025),))
    monkeypatch.setattr(inventory, "run_bound_inventory", lambda *args: bound)
    with pytest.raises(coverage.PdbCoverageError, match="enters selected.*interior"):
        coverage.prove_pdb_executable_coverage(
            parsed, Path("image.exe"), Path("image.pdb"),
            Path("helper.exe"), Path("msdia.dll"),
            (SimpleNamespace(name="selected", rva=0x1000, size=2),),
        )


def test_raw_supplemental_overlap_or_invalid_type_rejects() -> None:
    parsed, _ = fixture()
    spec = (SimpleNamespace(name="selected", rva=0x1000, size=1),)
    with pytest.raises(flow.DirectControlFlowError, match="overlaps a known function"):
        flow.analyze_direct_control_flow(
            parsed, spec, production=False,
            _supplemental_code_ranges=((0x1000, 0x1001),),
        )
    with pytest.raises(flow.DirectControlFlowError, match="invalid supplemental"):
        flow.analyze_direct_control_flow(
            parsed, spec, production=False,
            _supplemental_code_ranges=((True, 0x1020),),
        )
