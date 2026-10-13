"""Held-out PDB preflight/commit binding contracts for source coverage."""
from __future__ import annotations

import copy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from uuid import UUID

import pytest

from lifter import function_discovery
from lifter import direct_control_flow as flow
from lifter import pdb_coverage as coverage
from lifter import pdb_function_inventory as inventory
from lifter import virtualization_plan as plan
from packer import virtualize
from tests import test_known_source_references as known
from tests import test_virtualization_materializer as fixtures


_INTERIOR_LEA = bytes.fromhex("488d05daffffffc3")
_ENTRY_JUMP = bytes.fromhex("e9dbffffff9090c3")


def _case(monkeypatch, tmp_path: Path, *, pdb_code: bytes = b"\x90" * 7 + b"\xc3"):
    image, selected = fixtures._parsed()
    text = bytearray(image.sections[0].raw)
    text.extend(b"\xcc" * (0x28 - len(text)))
    text[0x20:0x28] = pdb_code
    image.sections[0].raw = bytes(text)
    image.sections[0].virtual_size = len(text)
    image.runtime_functions = image.runtime_functions[:1]
    image.pdata_count = 1
    image.sections[1].raw = image.sections[1].raw[:12]
    image.sections[1].virtual_size = 12
    source = tmp_path / "source-image.bin"
    source.write_bytes(b"exact external PDB image pin")
    image.path = str(source)
    spec = (plan.FunctionSpec("probe", 0x1000, len(selected)),)
    bound = inventory.BoundPdbInventory(
        image_sha256=sha256(source.read_bytes()).hexdigest(),
        pdb_sha256="b" * 64,
        helper_sha256="c" * 64,
        msdia_sha256="d" * 64,
        identity=inventory.CodeViewIdentity(UUID(int=1), 1),
        symbol_count=2,
        distinct_ranges=((0x1000, 0x1000 + len(selected)), (0x1020, 0x1028)),
        supplemental_ranges=((0x1020, 0x1028),),
        range_multiplicities=((0x1000, 0x1000 + len(selected), 1), (0x1020, 0x1028, 1)),
    )
    # The external-file fixture pins bytes but is not a full PE header.
    monkeypatch.setattr(function_discovery, "parse_pe_exports", lambda _parsed: ())
    monkeypatch.setattr(inventory, "run_bound_inventory", lambda *args: bound)
    proof = coverage.prove_pdb_executable_coverage(
        image, source, tmp_path / "source.pdb", tmp_path / "helper.exe",
        tmp_path / "msdia.dll", spec,
    )
    manifest = known._manifest(image, len(selected))
    return image, spec, proof, manifest


def _bound_manifest(image, spec, proof, manifest):
    binding = coverage.bind_pdb_commit_proof(image, proof, spec)
    return replace(manifest, source_coverage_mode="pdb", pdb_commit_binding=binding)


def test_pdb_unframed_interior_reference_is_rechecked_at_low_level_commit(monkeypatch, tmp_path):
    image, spec, proof, manifest = _case(monkeypatch, tmp_path)
    pdb_manifest = _bound_manifest(image, spec, proof, manifest)
    before = copy.deepcopy(image)
    assert virtualize.apply_virtualization_manifest(
        image, pdb_manifest, acknowledge_no_interior_entries=True
    )
    assert image == before
    assert pdb_manifest.to_dict()["source_coverage_mode"] == "pdb"

    text = bytearray(image.sections[0].raw)
    text[0x20:0x28] = _INTERIOR_LEA
    image.sections[0].raw = bytes(text)
    mutated = copy.deepcopy(image)
    with pytest.raises(flow.DirectControlFlowError, match="known source reference"):
        flow.analyze_direct_control_flow(
            image, spec, production=False,
            _supplemental_code_ranges=pdb_manifest.pdb_commit_binding.supplemental_ranges,
        )
    # The selected extent is unchanged, but the nonselected PDB-only body is stale.
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="PDB source changed"):
        virtualize.apply_virtualization_manifest(
            image, pdb_manifest, acknowledge_no_interior_entries=True
        )
    assert image == mutated
    # Even if the parsed digest were falsely updated, the full supplemental
    # re-decode must still reject the selected-interior RIP reference.
    rebound = replace(
        pdb_manifest.pdb_commit_binding,
        source_parsed_sha256=coverage.parsed_source_sha256(image),
    )
    rebound = replace(rebound, binding_sha256=coverage._binding_sha256(rebound))
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="known source reference"):
        virtualize.apply_virtualization_manifest(
            image, replace(pdb_manifest, pdb_commit_binding=rebound),
            acknowledge_no_interior_entries=True,
        )
    assert image == mutated
    # This is the preserved legacy low-level gap; PDB mode is required to close it.
    assert virtualize.apply_virtualization_manifest(
        image, manifest, acknowledge_no_interior_entries=True
    )


@pytest.mark.parametrize("mutation", ["missing", "selected", "supplemental", "digest", "mode", "image"])
def test_pdb_omitted_or_altered_binding_rejects_without_source_mutation(
    monkeypatch, tmp_path, mutation
):
    image, spec, proof, manifest = _case(monkeypatch, tmp_path)
    pdb_manifest = _bound_manifest(image, spec, proof, manifest)
    before = copy.deepcopy(image)
    if mutation == "missing":
        pdb_manifest = replace(pdb_manifest, pdb_commit_binding=None)
    elif mutation == "selected":
        binding = replace(
            pdb_manifest.pdb_commit_binding,
            selected_functions=(("probe", 0x1001, 6, 6),),
        )
        pdb_manifest = replace(pdb_manifest, pdb_commit_binding=binding)
    elif mutation == "supplemental":
        binding = replace(pdb_manifest.pdb_commit_binding, supplemental_ranges=())
        pdb_manifest = replace(pdb_manifest, pdb_commit_binding=binding)
    elif mutation == "digest":
        binding = replace(pdb_manifest.pdb_commit_binding, pdb_sha256="e" * 64)
        pdb_manifest = replace(pdb_manifest, pdb_commit_binding=binding)
    elif mutation == "mode":
        pdb_manifest = replace(pdb_manifest, source_coverage_mode="legacy")
    elif mutation == "image":
        Path(image.path).write_bytes(b"different external source")
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="PDB|coverage mode"):
        virtualize.apply_virtualization_manifest(
            image, pdb_manifest, acknowledge_no_interior_entries=True
        )
    assert image == before


def test_exact_entry_from_pdb_only_code_is_accepted(monkeypatch, tmp_path):
    image, spec, proof, manifest = _case(monkeypatch, tmp_path, pdb_code=_ENTRY_JUMP)
    pdb_manifest = _bound_manifest(image, spec, proof, manifest)
    before = copy.deepcopy(image)
    result = virtualize.apply_virtualization_manifest(
        image, pdb_manifest, acknowledge_no_interior_entries=True
    )
    assert result.sections[0].raw[0] == 0xE9
    assert image == before


def test_pdb_binding_source_file_and_parsed_byte_pins_are_independent(monkeypatch, tmp_path):
    image, spec, proof, manifest = _case(monkeypatch, tmp_path)
    image.sections[0].raw = image.sections[0].raw[:-1] + b"\x90"
    with pytest.raises(coverage.PdbCoverageError, match="parsed source changed"):
        coverage.bind_pdb_commit_proof(image, proof, spec)
    image, spec, proof, manifest = _case(monkeypatch, tmp_path)
    Path(image.path).write_bytes(b"different source file")
    with pytest.raises(coverage.PdbCoverageError, match="source image changed"):
        coverage.bind_pdb_commit_proof(image, proof, spec)



def test_high_level_materializer_embeds_binding_and_replays_proof(monkeypatch, tmp_path):
    image, spec, proof, manifest = _case(monkeypatch, tmp_path)
    provenance = virtualize.StubVirtualizationProvenance(
        "a" * 64, "b" * 64, "c" * 64, 0x1000, 0, 0x1000
    )
    monkeypatch.setattr(
        virtualize, "_read_stub_provenance",
        lambda *_args, **_kwargs: (object(), 0x1000, "a" * 64, "b" * 64),
    )
    monkeypatch.setattr(
        virtualize, "_compile_manifest",
        lambda *_args, **_kwargs: (manifest, provenance),
    )
    before = copy.deepcopy(image)
    result = virtualize.materialize_selected_functions(
        image, spec,
        stub_bytes=b"synthetic stub handled by fixture",
        opcode_table=plan.OpcodeTable.canonical(),
        expected_handler_variant_sha256="c" * 64,
        page_master_key=bytes(32),
        acknowledge_no_interior_entries=True,
        pdb_coverage_proof=proof,
    )
    assert result.manifest.source_coverage_mode == "pdb"
    assert isinstance(result.manifest.pdb_commit_binding, coverage.PdbCommitBinding)
    assert result.stub is provenance
    assert image == before
