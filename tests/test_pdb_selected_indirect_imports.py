from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import struct

import pytest

from lifter import function_discovery
from lifter import native_tail_calls
from lifter import pdb_coverage as coverage
from lifter import pdb_function_inventory as inventory
from tests.test_pdb_coverage import fixture as base_fixture


def _call_iat(slot: int, *, ip: int = 0x1000, opcode: int = 0x15) -> bytes:
    return b"\xff" + bytes((opcode,)) + struct.pack("<i", slot - (ip + 6))


def _case(monkeypatch, tmp_path: Path, code: bytes, *, duplicate_iat: bool = False):
    parsed, bound = base_fixture()
    text = bytearray(parsed.sections[0].raw)
    text[:len(code)] = code
    parsed.sections[0].raw = bytes(text)
    parsed.runtime_functions = (SimpleNamespace(
        begin_rva=0x1000, end_rva=0x1000 + len(code),
        unwind_info_rva=0x3000, unwind_flags=0
    ),)
    parsed.size_of_image = 0x4000
    source = tmp_path / "source-image.bin"
    source.write_bytes(b"exact source image pin")
    parsed.path = str(source)
    imported = SimpleNamespace(
        iat_rva=0x2000, by_ordinal=False, ordinal=0, name="QExample"
    )
    dll = SimpleNamespace(name="Qt6Core.dll", funcs=(imported,))
    if duplicate_iat:
        parsed.imports = (dll, SimpleNamespace(
            name="Qt6Gui.dll",
            funcs=(SimpleNamespace(
                iat_rva=0x2000, by_ordinal=False, ordinal=0, name="QAlias"
            ),),
        ))
    else:
        parsed.imports = (dll,)
    selected_end = 0x1000 + len(code)
    bound = replace(
        bound,
        image_sha256=sha256(source.read_bytes()).hexdigest(),
        msdia_sha256="d" * 64,
        symbol_count=2,
        distinct_ranges=((0x1000, selected_end), (0x1020, 0x1021)),
        supplemental_ranges=((0x1020, 0x1021),),
        range_multiplicities=((0x1000, selected_end, 1), (0x1020, 0x1021, 1)),
    )
    monkeypatch.setattr(inventory, "run_bound_inventory", lambda *_args: bound)
    monkeypatch.setattr(function_discovery, "parse_pe_exports", lambda _parsed: ())
    spec = SimpleNamespace(name="selected", rva=0x1000, size=len(code))
    proof = coverage.prove_pdb_executable_coverage(
        parsed, source, tmp_path / "source.pdb", tmp_path / "helper.exe",
        tmp_path / "msdia.dll", (spec,),
    )
    return parsed, spec, proof


def _native_import_proof(
    call: coverage.SelectedIndirectImportCall,
    *,
    function_rva: int = 0x1000,
) -> native_tail_calls.VerifiedNativeImportCallProof:
    """Build an otherwise pinned dependency proof for one selected FF15 site."""
    return native_tail_calls.VerifiedNativeImportCallProof(
        function_rva=function_rva,
        call_rva=call.source_rva,
        iat_rva=call.iat_rva,
        module=call.module,
        symbol=call.symbol,
        dependency_sha256="a" * 64,
        export_rva=0x3000,
        export_ordinal=1,
        body_size=16,
        body_sha256="b" * 64,
    )


def test_selected_import_indirect_calls_are_exactly_bound(monkeypatch, tmp_path):
    parsed, spec, proof = _case(
        monkeypatch, tmp_path, _call_iat(0x2000) + b"\xc3"
    )
    assert proof.direct_flow.indirect_target_closure_proven is False
    calls = proof.selected_indirect_import_calls
    assert len(calls) == 1
    call = calls[0]
    assert call.function_name == "selected"
    assert call.source_rva == 0x1000
    assert call.iat_rva == 0x2000
    assert call.module == "Qt6Core.dll"
    assert call.symbol == "QExample"
    assert call.instruction_bytes_hex == _call_iat(0x2000).hex()
    assert call.reachable_from_selected_entry is True
    assert parsed.imports[0].funcs[0].iat_rva == call.iat_rva
    assert spec.name == call.function_name


def test_selected_import_inventory_is_empty_only_when_no_indirect_sites(monkeypatch, tmp_path):
    _parsed, _spec, proof = _case(monkeypatch, tmp_path, b"\xc3")
    assert proof.selected_indirect_import_calls == ()


@pytest.mark.parametrize("code", [
    b"\xff\xd0\xc3",                       # register target
    _call_iat(0x2010) + b"\xc3",            # unlisted IAT slot
    _call_iat(0x2000, opcode=0x25),           # indirect jump, not a call
    b"\xc3\xff\xd0",                       # unreachable dynamic call in selected extent
])
def test_selected_nonimport_or_unreachable_indirect_targets_fail_closed(
    monkeypatch, tmp_path, code
):
    with pytest.raises(coverage.PdbCoverageError, match="selected indirect"):
        _case(monkeypatch, tmp_path, code)


@pytest.mark.parametrize("second_slot", [0x2000, 0x2004])
def test_selected_import_call_rejects_aliased_or_overlapping_iat_inventory(
    monkeypatch, tmp_path, second_slot
):
    parsed, bound = base_fixture()
    text = bytearray(parsed.sections[0].raw)
    code = _call_iat(0x2000) + b"\xc3"
    text[:len(code)] = code
    parsed.sections[0].raw = bytes(text)
    parsed.runtime_functions = (SimpleNamespace(
        begin_rva=0x1000, end_rva=0x1000 + len(code),
        unwind_info_rva=0x3000, unwind_flags=0
    ),)
    imported = SimpleNamespace(
        iat_rva=0x2000, by_ordinal=False, ordinal=0, name="QExample"
    )
    parsed.imports = (
        SimpleNamespace(name="Qt6Core.dll", funcs=(imported,)),
        SimpleNamespace(name="Qt6Gui.dll", funcs=(SimpleNamespace(iat_rva=second_slot, by_ordinal=False, ordinal=0, name="QAlias"),)),
    )
    selected_end = 0x1000 + len(code)
    bound = replace(
        bound, symbol_count=2,
        distinct_ranges=((0x1000, selected_end), (0x1020, 0x1021)),
        supplemental_ranges=((0x1020, 0x1021),),
        range_multiplicities=((0x1000, selected_end, 1), (0x1020, 0x1021, 1)),
    )
    monkeypatch.setattr(inventory, "run_bound_inventory", lambda *_args: bound)
    spec = SimpleNamespace(name="selected", rva=0x1000, size=len(code))
    with pytest.raises(coverage.PdbCoverageError, match="overlap"):
        coverage.prove_pdb_executable_coverage(
            parsed, Path("image.exe"), Path("image.pdb"),
            Path("helper.exe"), Path("msdia.dll"), (spec,),
        )


@pytest.mark.parametrize("bad_value", [0, 1, None, "false"])
def test_source_import_ordinal_mode_must_be_an_exact_boolean(
    monkeypatch, tmp_path, bad_value
):
    parsed, _spec, _proof = _case(
        monkeypatch, tmp_path, _call_iat(0x2000) + b"\xc3"
    )
    parsed.imports[0].funcs[0].by_ordinal = bad_value
    with pytest.raises(coverage.PdbCoverageError, match="ordinal mode is malformed"):
        coverage._source_iat_imports(parsed)


def test_source_import_iat_slot_must_remain_exact_integer(monkeypatch, tmp_path):
    parsed, _spec, _proof = _case(
        monkeypatch, tmp_path, _call_iat(0x2000) + b"\xc3"
    )
    parsed.imports[0].funcs[0].iat_rva = True
    with pytest.raises(coverage.PdbCoverageError):
        coverage._source_iat_imports(parsed)



def test_selected_import_calls_are_replayed_and_bound(monkeypatch, tmp_path):
    parsed, spec, proof = _case(
        monkeypatch, tmp_path, _call_iat(0x2000) + b"\xc3"
    )
    binding = coverage.bind_pdb_commit_proof(parsed, proof, (spec,))
    assert binding.selected_indirect_import_calls == proof.selected_indirect_import_calls
    assert binding.selected_canonical_import_call_closure is None
    assert binding.to_dict()["selected_indirect_import_calls"][0]["iat_rva"] == 0x2000
    coverage.validate_pdb_commit_binding(parsed, (spec,), binding)

    forged = replace(binding, selected_indirect_import_calls=())
    forged = replace(forged, binding_sha256=coverage._binding_sha256(forged))
    with pytest.raises(coverage.PdbCoverageError, match="selected indirect import inventory changed"):
        coverage.validate_pdb_commit_binding(parsed, (spec,), forged)

    parsed.imports[0].funcs[0].iat_rva = 0x2008
    with pytest.raises(coverage.PdbCoverageError, match="source changed after preflight"):
        coverage.validate_pdb_commit_binding(parsed, (spec,), binding)


def test_selected_canonical_import_closure_binds_every_call_through_one_iat(
    monkeypatch, tmp_path
):
    """Two reachable calls may share a slot, but each physical call is bound."""
    code = (
        _call_iat(0x2000, ip=0x1000)
        + _call_iat(0x2000, ip=0x1006)
        + b"\xc3"
    )
    parsed, spec, proof = _case(monkeypatch, tmp_path, code)
    assert proof.direct_flow.indirect_target_closure_proven is False
    assert [item.source_rva for item in proof.selected_indirect_import_calls] == [
        0x1000,
        0x1006,
    ]
    native_proofs = tuple(
        _native_import_proof(item) for item in proof.selected_indirect_import_calls
    )

    binding = coverage.bind_pdb_commit_proof(
        parsed,
        proof,
        (spec,),
        native_import_call_proofs=native_proofs,
    )
    closure = binding.selected_canonical_import_call_closure
    assert isinstance(closure, coverage.SelectedCanonicalImportCallClosure)
    assert closure.calls == proof.selected_indirect_import_calls
    assert closure.native_import_call_proofs == native_proofs
    assert binding.to_dict()["selected_canonical_import_call_closure"] == closure.to_dict()
    assert binding.binding_sha256 == coverage._binding_sha256(binding)
    coverage.validate_pdb_commit_binding(parsed, (spec,), binding)
    coverage.validate_selected_canonical_import_call_closure(
        parsed,
        binding.direct_flow,
        binding.selected_indirect_import_calls,
        closure,
        native_import_call_proofs=closure.native_import_call_proofs,
    )


def test_selected_canonical_import_closure_rejects_reordered_manifest_proofs(
    monkeypatch, tmp_path
):
    """A semantically equal proof set still needs its bound canonical order."""
    code = (
        _call_iat(0x2000, ip=0x1000)
        + _call_iat(0x2000, ip=0x1006)
        + b"\xc3"
    )
    parsed, spec, proof = _case(monkeypatch, tmp_path, code)
    native_proofs = tuple(
        _native_import_proof(item) for item in proof.selected_indirect_import_calls
    )
    binding = coverage.bind_pdb_commit_proof(
        parsed,
        proof,
        (spec,),
        native_import_call_proofs=native_proofs,
    )
    closure = binding.selected_canonical_import_call_closure
    assert closure is not None
    reordered = tuple(reversed(closure.native_import_call_proofs))
    assert reordered != closure.native_import_call_proofs
    with pytest.raises(coverage.PdbCoverageError, match="canonical manifest proof tuple"):
        coverage.validate_selected_canonical_import_call_closure(
            parsed,
            binding.direct_flow,
            binding.selected_indirect_import_calls,
            closure,
            native_import_call_proofs=reordered,
        )


@pytest.mark.parametrize(
    ("kind", "mutate", "message"),
    [
        ("missing", lambda items: items[:1], "do not exactly match"),
        (
            "extra",
            lambda items: items + (replace(items[0], call_rva=0x1010),),
            "do not exactly match",
        ),
        (
            "duplicate",
            lambda items: items + (items[0],),
            "identity is duplicated",
        ),
        (
            "function",
            lambda items: (replace(items[0], function_rva=0x1001),) + items[1:],
            "do not exactly match",
        ),
        (
            "call",
            lambda items: (replace(items[0], call_rva=0x1001),) + items[1:],
            "do not exactly match",
        ),
        (
            "iat",
            lambda items: (replace(items[0], iat_rva=0x2008),) + items[1:],
            "do not exactly match",
        ),
        (
            "module",
            lambda items: (replace(items[0], module="Qt6Gui.dll"),) + items[1:],
            "do not exactly match",
        ),
        (
            "symbol",
            lambda items: (replace(items[0], symbol="QOther"),) + items[1:],
            "do not exactly match",
        ),
    ],
    ids=lambda item: item if isinstance(item, str) else None,
)
def test_selected_canonical_import_closure_rejects_nonexact_native_proofs(
    monkeypatch, tmp_path, kind, mutate, message
):
    del kind
    code = (
        _call_iat(0x2000, ip=0x1000)
        + _call_iat(0x2000, ip=0x1006)
        + b"\xc3"
    )
    parsed, spec, proof = _case(monkeypatch, tmp_path, code)
    native_proofs = tuple(
        _native_import_proof(item) for item in proof.selected_indirect_import_calls
    )
    with pytest.raises(coverage.PdbCoverageError, match=message):
        coverage.bind_pdb_commit_proof(
            parsed,
            proof,
            (spec,),
            native_import_call_proofs=mutate(native_proofs),
        )


def test_selected_canonical_import_closure_tamper_rejects_after_binding(
    monkeypatch, tmp_path
):
    parsed, spec, proof = _case(
        monkeypatch, tmp_path, _call_iat(0x2000) + b"\xc3"
    )
    native_proofs = tuple(
        _native_import_proof(item) for item in proof.selected_indirect_import_calls
    )
    binding = coverage.bind_pdb_commit_proof(
        parsed,
        proof,
        (spec,),
        native_import_call_proofs=native_proofs,
    )
    closure = binding.selected_canonical_import_call_closure
    assert closure is not None
    altered_proof = replace(closure.native_import_call_proofs[0], symbol="QOther")
    altered_closure = replace(
        closure, native_import_call_proofs=(altered_proof,)
    )
    forged = replace(
        binding,
        selected_canonical_import_call_closure=altered_closure,
    )
    forged = replace(forged, binding_sha256=coverage._binding_sha256(forged))
    with pytest.raises(coverage.PdbCoverageError, match="do not exactly match"):
        coverage.validate_pdb_commit_binding(parsed, (spec,), forged)


def test_selected_canonical_import_closure_requires_an_immutable_proof_tuple(
    monkeypatch, tmp_path
):
    parsed, spec, proof = _case(
        monkeypatch, tmp_path, _call_iat(0x2000) + b"\xc3"
    )
    native_proofs = [
        _native_import_proof(item) for item in proof.selected_indirect_import_calls
    ]
    with pytest.raises(coverage.PdbCoverageError, match="immutable"):
        coverage.bind_pdb_commit_proof(
            parsed,
            proof,
            (spec,),
            native_import_call_proofs=native_proofs,  # type: ignore[arg-type]
        )
