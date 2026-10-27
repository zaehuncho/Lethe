"""Experimental virtualization orchestration and build-provenance gates."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from daedalus import shuffle_opcodes
from lifter import direct_control_flow, function_discovery, virtualization_plan
from packer import (
    assemble, container, keyed_validation, orchestrator, payload, pe_analyze, report,
    virtualization_selection, virtualize,
)


def _write_candidate(tmp_path, *, rolling=True):
    stub = tmp_path / "lethe_stub_x64.dll"
    stub_bytes = b"fresh candidate stub bytes"
    stub.write_bytes(stub_bytes)
    generated = shuffle_opcodes.generate_shuffle(bytes.fromhex("11" * 32))
    manifest = {
        "schema": 1,
        "artifact": stub.name,
        "size_bytes": len(stub_bytes),
        "sha256": hashlib.sha256(stub_bytes).hexdigest(),
        "dvm_shuffle_seed": "11" * 32,
        "dvm_handler_variant_sha256": generated["handler_variant_sha256"],
        "dvm_rolling": rolling,
        "dvm_paged_runtime": True,
    }
    with open(str(stub) + ".manifest.json", "w", encoding="utf-8") as stream:
        json.dump(manifest, stream)
    return stub, stub_bytes, manifest


def test_candidate_manifest_uses_dll_adjacent_name_not_promoted_stem(tmp_path):
    stub, stub_bytes, _manifest = _write_candidate(tmp_path)
    promoted_name = stub.with_suffix(".manifest.json")
    promoted_name.write_text("not candidate provenance", encoding="utf-8")

    loaded, digest, table, handler_hash, rolling = (
        orchestrator._load_virtualization_build(
            str(stub), allow_unverified_stub_for_tests=True)
    )

    assert loaded == stub_bytes
    assert digest == hashlib.sha256(stub_bytes).hexdigest()
    assert len(table.entries) > 0
    assert handler_hash == _manifest["dvm_handler_variant_sha256"]
    assert rolling is True


def test_explicit_pdb_coverage_branch_is_bound_to_private_source_snapshot(
        monkeypatch, tmp_path):
    from lifter import pdb_coverage

    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    stub, _stub_bytes, _manifest = _write_candidate(tmp_path)
    pdb = tmp_path / "app.pdb"
    helper = tmp_path / "pdb_function_dump.exe"
    msdia = tmp_path / "msdia140.dll"
    for path in (pdb, helper, msdia):
        path.write_bytes(b"fixture")
    source_parsed = SimpleNamespace(is_dll=False)
    materialized_parsed = SimpleNamespace(is_dll=False, materialized=True)
    captures = {}
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")
    monkeypatch.setattr(pe_analyze, "analyze_pe", lambda _path: source_parsed)

    def fake_coverage(parsed, image, actual_pdb, actual_helper, actual_msdia,
                      specs, **kwargs):
        captures.update(parsed=parsed, image=image, pdb=actual_pdb,
                        helper=actual_helper, msdia=actual_msdia,
                        specs=specs, tail_policy=kwargs["tail_exit_policy"])
        coverage_proof = SimpleNamespace(
            inventory=SimpleNamespace(
                supplemental_ranges=((0x2000, 0x2010),),
                image_sha256="a" * 64, pdb_sha256="b" * 64,
                helper_sha256="c" * 64, msdia_sha256="d" * 64,
            ),
            residual_ranges=(object(),),
            direct_flow=SimpleNamespace(
                direct_transfers=(object(),), coverage_gaps=(),
                acknowledged_coverage_gaps=(), indirect_transfers=(),
                direct_reference_gate_passed=True,
                indirect_target_closure_proven=False,
            ),
        )
        captures["coverage_proof"] = coverage_proof
        return coverage_proof

    monkeypatch.setattr(pdb_coverage, "prove_pdb_executable_coverage", fake_coverage)
    monkeypatch.setattr(
        direct_control_flow, "analyze_direct_control_flow",
        lambda *_args, **_kwargs: pytest.fail("legacy proof used in PDB mode"),
    )
    def materialize_with_capture(_parsed, _specs, **kwargs):
        captures["materializer_pdb_proof"] = kwargs.get("pdb_coverage_proof")
        return SimpleNamespace(
            parsed=materialized_parsed,
            manifest=SimpleNamespace(
                functions=(object(),),
                native_import_call_proofs=(),
            ),
        )

    monkeypatch.setattr(virtualize, "materialize_selected_functions", materialize_with_capture)
    _patch_post_materialization_pipeline(monkeypatch, materialized_parsed, captures)
    progress = []
    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(output), is_dll=False, stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec("Init", 0x1000, 16),),
            virtualization_pdb_path=str(pdb),
            virtualization_dia_helper_path=str(helper),
            virtualization_msdia_path=str(msdia),
            acknowledge_unproven_indirect_targets=True,
            _allow_unverified_stub_for_tests=True,
        ),
        progress.append,
    )
    assert result.ok, result.error
    assert output.read_bytes() == b"candidate"
    assert captures["parsed"] is source_parsed
    assert captures["image"] != source and captures["image"].name.startswith(".")
    assert (captures["pdb"], captures["helper"], captures["msdia"]) == (
        pdb, helper, msdia)
    assert captures["specs"] == (virtualization_plan.FunctionSpec("Init", 0x1000, 16),)
    assert captures["materializer_pdb_proof"] is captures["coverage_proof"]
    assert any("PDB-bound virtualization control-flow proof" in x for x in progress)


@pytest.mark.parametrize("field,value,match", [
    ("virtualization_dia_helper_path", None, "three nonempty paths"),
    ("virtualization_gap_acknowledgements",
     (orchestrator.VirtualizationGapAcknowledgement(0x2000, 16, "manual"),),
     "no manual gap"),
])
def test_pdb_proof_option_misconfiguration_fails_before_pe_analysis(
        monkeypatch, tmp_path, field, value, match):
    source = tmp_path / "app.exe"
    source.write_bytes(b"fixture")
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")
    paths = {"virtualization_pdb_path": str(tmp_path / "app.pdb"),
             "virtualization_dia_helper_path": str(tmp_path / "helper.exe"),
             "virtualization_msdia_path": str(tmp_path / "msdia.dll")}
    paths[field] = value
    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(tmp_path / "out.exe"), stub_path="stub.dll",
            virtualization_specs=(orchestrator.VirtualizationSpec("Init", 0x1000, 16),),
            acknowledge_unproven_indirect_targets=True,
            **paths,
        ),
    )
    assert not result.ok and match in result.error
    assert source.read_bytes() == b"fixture"


def test_pdb_proof_cannot_alias_output_or_executable_input(monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "packed.exe"
    source.write_bytes(b"source")
    output.write_bytes(b"existing output")
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")
    options = orchestrator.PackOptions(
        output_path=str(output), stub_path="stub.dll",
        virtualization_specs=(orchestrator.VirtualizationSpec("Init", 0x1000, 16),),
        virtualization_pdb_path=str(output),
        virtualization_dia_helper_path=str(tmp_path / "helper.exe"),
        virtualization_msdia_path=str(tmp_path / "msdia.dll"),
        acknowledge_unproven_indirect_targets=True,
    )
    result = orchestrator.pack_file(str(source), options)
    assert not result.ok and "PDB must not alias input or output" in result.error
    assert output.read_bytes() == b"existing output"
    options.virtualization_pdb_path = str(tmp_path / "source.pdb")
    options.virtualization_dia_helper_path = str(source)
    result = orchestrator.pack_file(str(source), options)
    assert not result.ok and "DIA helper must not alias input or output" in result.error
    assert source.read_bytes() == b"source"


def test_promoted_stem_manifest_is_not_silently_used_for_candidate(tmp_path):
    stub = tmp_path / "lethe_stub_x64.dll"
    stub.write_bytes(b"stub")
    stub.with_suffix(".manifest.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="verified candidate"):
        orchestrator._load_virtualization_build(str(stub))


@pytest.mark.parametrize(
    "field, value, expected",
    [
        ("schema", 2, "schema"),
        ("artifact", "other.dll", "artifact"),
        ("size_bytes", 1, "size"),
        ("sha256", "00" * 32, "SHA-256"),
        ("dvm_shuffle_seed", "11" * 31, "32 bytes"),
        ("dvm_handler_variant_sha256", "00" * 32, "handler variants"),
        ("dvm_rolling", None, "boolean"),
        ("dvm_paged_runtime", False, "paging runtime"),
    ],
)
def test_candidate_manifest_rejects_invalid_provenance(
        tmp_path, field, value, expected):
    stub, _stub_bytes, manifest = _write_candidate(tmp_path)
    manifest[field] = value
    with open(str(stub) + ".manifest.json", "w", encoding="utf-8") as stream:
        json.dump(manifest, stream)

    with pytest.raises(ValueError, match=expected):
        orchestrator._load_virtualization_build(
            str(stub), allow_unverified_stub_for_tests=True)


def test_assembler_rejects_stub_changed_after_geometry_pin(tmp_path):
    stub, stub_bytes, _manifest = _write_candidate(tmp_path)
    pinned = hashlib.sha256(stub_bytes).hexdigest()
    stub.write_bytes(stub_bytes + b"changed")

    with pytest.raises(assemble.AssembleError, match="changed after virtualization"):
        assemble._load_stub(str(stub), expected_sha256=pinned)


def _patch_post_materialization_pipeline(monkeypatch, expected_parsed, captures):
    def fake_payload(parsed, _options, **kwargs):
        captures["payload_parsed"] = parsed
        captures["payload_master_key"] = kwargs.get("master_key")
        captures["payload_paged_vm"] = kwargs.get("paged_vm")
        return object()

    monkeypatch.setattr(
        payload, "build_payload",
        fake_payload,
    )

    def fake_assemble(parsed, _artifacts, output_path, **kwargs):
        captures["assembly_parsed"] = parsed
        captures["assembly_sha"] = kwargs.get("expected_stub_sha256")
        with open(output_path, "wb") as stream:
            stream.write(b"candidate")
        return SimpleNamespace(server_shard=None, output_path=output_path)

    monkeypatch.setattr("packer.assemble.build_output_pe", fake_assemble)
    monkeypatch.setattr(
        report, "validate_packed",
        lambda _path: report.ValidationResult(
            True, section_count=1, format_version=container.FORMAT_VERSION),
    )
    monkeypatch.setattr(
        keyed_validation, "validate_staged_output",
        lambda *_args, **_kwargs: keyed_validation.KeyedValidationResult(
            True, section_count=1),
    )
    monkeypatch.setattr(orchestrator, "_pe_content_id", lambda _path: "a" * 64)


def _terminal_tail_binding_fixture(
        *, target_flags=0, target_raw=True, target_rva=0x1100):
    source_rva = 0x1000
    source = b"\xE9" + (
        target_rva - (source_rva + 5)
    ).to_bytes(4, "little", signed=True)
    target = b"\xB8\x2D\x00\x00\x00\xC3"
    raw_target = target if target_raw else target[:-1]
    section_raw = (
        source
        + b"\x90" * (target_rva - source_rva - len(source))
        + raw_target
    )
    parsed = SimpleNamespace(
        is_dll=False,
        sections=(pe_analyze.ParsedSection(
            ".text", source_rva, len(section_raw), section_raw, 0x60000020,
        ),),
        runtime_functions=(pe_analyze.ParsedRuntimeFunction(
            target_rva, target_rva + len(target), 0x3000, target_flags,
        ),),
    )
    spec = virtualization_plan.FunctionSpec("terminal_tail", source_rva, len(source))
    approval = direct_control_flow.TailExitApproval(
        source_rva, source_rva, target_rva, "reviewed terminal tail",
    )
    policy = direct_control_flow.TailExitPolicy((approval,))
    selected = direct_control_flow.SelectedFunctionRange(
        spec.name, spec.rva, spec.size, spec.lifted_body_size,
    )
    flow = direct_control_flow.SelectedFunctionFlow(
        spec.name,
        spec.rva,
        spec.size,
        spec.body_size,
        (source_rva,),
        (approval,),
    )
    transfer = direct_control_flow.DirectControlTransfer(
        source_rva=source_rva,
        source_range_begin_rva=source_rva,
        source_has_runtime_function=False,
        kind="jump",
        target_rva=target_rva,
        source_selected_name=spec.name,
        target_selected_name=None,
        target_is_selected_entry=False,
        reachable_from_selected_entry=True,
    )
    proof = direct_control_flow.DirectControlFlowProof(
        version=direct_control_flow.PROOF_VERSION,
        selected_functions=(selected,),
        decoded_runtime_functions=(),
        direct_transfers=(transfer,),
        indirect_transfers=(),
        selected_flows=(flow,),
        coverage_gaps=(),
        acknowledged_coverage_gaps=(),
        direct_runtime_coverage_complete=True,
        direct_reference_gate_passed=True,
        indirect_target_closure_proven=False,
        limitations=(),
    )
    return parsed, (spec,), policy, proof, approval, target


def _bind_terminal_tail(parsed, specs, policy, proof):
    return orchestrator._bind_verified_tail_exit_specs(
        parsed,
        specs,
        tail_policy=policy,
        proof=proof,
        direct_control_flow=direct_control_flow,
        virtualization_plan=virtualization_plan,
    )


def test_tail_exit_binder_derives_target_identity_only_from_consumed_proof():
    parsed, specs, policy, proof, approval, target = _terminal_tail_binding_fixture()

    bound = _bind_terminal_tail(parsed, specs, policy, proof)

    assert bound[0].tail_exit == virtualization_plan.TailExitSpec(
        instruction_rva=approval.instruction_rva,
        target_rva=approval.target_rva,
        target_size=len(target),
        target_unwind_info_rva=0x3000,
        target_body_sha256=hashlib.sha256(target).hexdigest(),
    )
    assert specs[0].tail_exit is None


def test_tail_exit_binder_accepts_real_direct_control_flow_proof():
    parsed, specs, policy, _proof, approval, target = \
        _terminal_tail_binding_fixture(target_rva=0x1005)

    proof = direct_control_flow.analyze_direct_control_flow(
        parsed,
        specs,
        tail_exit_policy=policy,
        production=True,
    )
    bound = _bind_terminal_tail(parsed, specs, policy, proof)

    assert proof.selected_flows[0].approved_tail_exits == (approval,)
    assert bound[0].tail_exit is not None
    assert bound[0].tail_exit.target_rva == approval.target_rva
    assert bound[0].tail_exit.target_size == len(target)


def test_tail_exit_binder_rejects_unconsumed_or_raw_tail_request():
    parsed, specs, policy, proof, _approval, target = _terminal_tail_binding_fixture()
    unconsumed = direct_control_flow.DirectControlFlowProof(
        version=proof.version,
        selected_functions=proof.selected_functions,
        decoded_runtime_functions=proof.decoded_runtime_functions,
        direct_transfers=proof.direct_transfers,
        indirect_transfers=proof.indirect_transfers,
        selected_flows=(direct_control_flow.SelectedFunctionFlow(
            proof.selected_flows[0].name,
            proof.selected_flows[0].rva,
            proof.selected_flows[0].size,
            proof.selected_flows[0].lifted_body_size,
            proof.selected_flows[0].reachable_instruction_rvas,
            (),
        ),),
        coverage_gaps=proof.coverage_gaps,
        acknowledged_coverage_gaps=proof.acknowledged_coverage_gaps,
        direct_runtime_coverage_complete=proof.direct_runtime_coverage_complete,
        direct_reference_gate_passed=proof.direct_reference_gate_passed,
        indirect_target_closure_proven=proof.indirect_target_closure_proven,
        limitations=proof.limitations,
    )
    with pytest.raises(ValueError, match="was not consumed"):
        _bind_terminal_tail(parsed, specs, policy, unconsumed)

    raw_tail = virtualization_plan.FunctionSpec(
        specs[0].name,
        specs[0].rva,
        specs[0].size,
        tail_exit=virtualization_plan.TailExitSpec(
            instruction_rva=specs[0].rva,
            target_rva=0x1100,
            target_size=len(target),
            target_unwind_info_rva=0x3000,
            target_body_sha256=hashlib.sha256(target).hexdigest(),
        ),
    )
    with pytest.raises(ValueError, match="must be derived"):
        _bind_terminal_tail(parsed, (raw_tail,), policy, proof)


def test_tail_exit_binder_rejects_unsafe_target_pdata_or_body():
    parsed, specs, policy, proof, _approval, _target = _terminal_tail_binding_fixture(
        target_flags=1,
    )
    with pytest.raises(ValueError, match="handler-free primary"):
        _bind_terminal_tail(parsed, specs, policy, proof)

    parsed, specs, policy, proof, _approval, _target = _terminal_tail_binding_fixture(
        target_raw=False,
    )
    with pytest.raises(ValueError, match="not wholly file-backed"):
        _bind_terminal_tail(parsed, specs, policy, proof)


def test_core_derives_terminal_tail_spec_after_consumed_proof(
        monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    stub, _stub_bytes, _manifest = _write_candidate(tmp_path, rolling=True)
    source_parsed, specs, policy, proof, approval, target = \
        _terminal_tail_binding_fixture()
    materialized_parsed = SimpleNamespace(is_dll=False, materialized=True)
    captures = {}
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")
    monkeypatch.setattr(pe_analyze, "analyze_pe", lambda _path: source_parsed)

    def fake_proof(parsed, analyzed_specs, **kwargs):
        captures["proof_parsed"] = parsed
        captures["proof_specs"] = analyzed_specs
        captures["proof_tail_policy"] = kwargs["tail_exit_policy"]
        return proof

    monkeypatch.setattr(
        direct_control_flow, "analyze_direct_control_flow", fake_proof,
    )

    def fake_materialize(parsed, materialized_specs, **kwargs):
        captures["materialize_parsed"] = parsed
        captures["materialize_specs"] = materialized_specs
        captures["tail_exit_proof"] = kwargs["tail_exit_proof"]
        return SimpleNamespace(
            parsed=materialized_parsed,
            manifest=SimpleNamespace(
                functions=(object(),),
                native_import_call_proofs=(),
            ),
        )

    monkeypatch.setattr(virtualize, "materialize_selected_functions", fake_materialize)
    _patch_post_materialization_pipeline(monkeypatch, materialized_parsed, captures)

    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(output), is_dll=False, stub_path=str(stub),
            virtualization_specs=(orchestrator.VirtualizationSpec(
                specs[0].name, specs[0].rva, specs[0].size,
            ),),
            virtualization_tail_exit_approvals=(
                orchestrator.VirtualizationTailExitApproval(
                    approval.function_rva,
                    approval.instruction_rva,
                    approval.target_rva,
                    approval.rationale,
                ),
            ),
            acknowledge_unproven_indirect_targets=True,
            _allow_unverified_stub_for_tests=True,
        ),
    )

    assert result.ok, result.error
    assert captures["proof_parsed"] is source_parsed
    assert captures["proof_specs"] == specs
    assert captures["proof_tail_policy"] == policy
    assert captures["materialize_parsed"] is source_parsed
    assert captures["tail_exit_proof"] is proof
    assert captures["materialize_specs"][0].tail_exit == virtualization_plan.TailExitSpec(
        instruction_rva=approval.instruction_rva,
        target_rva=approval.target_rva,
        target_size=len(target),
        target_unwind_info_rva=0x3000,
        target_body_sha256=hashlib.sha256(target).hexdigest(),
    )


def test_core_materializes_before_payload_and_pins_exact_stub(
        monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    stub, stub_bytes, _manifest = _write_candidate(tmp_path, rolling=True)
    source_parsed = SimpleNamespace(is_dll=False)
    materialized_parsed = SimpleNamespace(is_dll=False, materialized=True)
    captures = {}
    progress = []
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")
    monkeypatch.setattr(pe_analyze, "analyze_pe", lambda _path: source_parsed)

    def fake_proof(parsed, specs, **kwargs):
        captures["proof_parsed"] = parsed
        captures["proof_specs"] = specs
        captures["proof_tail_policy"] = kwargs["tail_exit_policy"]
        captures["proof_gaps"] = kwargs["coverage_acknowledgements"]
        captures["proof_production"] = kwargs["production"]
        return SimpleNamespace(
            direct_transfers=(object(), object()),
            coverage_gaps=(object(),),
            acknowledged_coverage_gaps=(object(),),
            indirect_transfers=(object(),),
            direct_reference_gate_passed=True,
            indirect_target_closure_proven=False,
        )

    monkeypatch.setattr(
        direct_control_flow, "analyze_direct_control_flow", fake_proof)

    def fake_materialize(parsed, specs, **kwargs):
        captures["materialize_parsed"] = parsed
        captures["specs"] = specs
        captures["stub_bytes"] = kwargs["stub_bytes"]
        captures["handler_hash"] = kwargs["expected_handler_variant_sha256"]
        captures["page_master_key"] = kwargs["page_master_key"]
        captures["rolling"] = kwargs["rolling"]
        captures["rolling_seed"] = kwargs["rolling_seed"]
        captures["ack"] = kwargs["acknowledge_no_interior_entries"]
        return SimpleNamespace(
            parsed=materialized_parsed,
            manifest=SimpleNamespace(
                functions=(object(),),
                native_import_call_proofs=(),
            ),
        )

    monkeypatch.setattr(virtualize, "materialize_selected_functions", fake_materialize)
    _patch_post_materialization_pipeline(monkeypatch, materialized_parsed, captures)

    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(output),
            is_dll=False,
            stub_path=str(stub),
            virtualization_specs=(
                orchestrator.VirtualizationSpec("Init", 0x1000, 16),
            ),
            virtualization_gap_acknowledgements=(
                orchestrator.VirtualizationGapAcknowledgement(
                    0x2000, 16, "known linker padding"),
            ),
            acknowledge_unproven_indirect_targets=True,
            _allow_unverified_stub_for_tests=True,
        ),
        progress.append,
    )

    assert result.ok, result.error
    assert output.read_bytes() == b"candidate"
    assert captures["materialize_parsed"] is source_parsed
    assert captures["payload_parsed"] is materialized_parsed
    assert captures["assembly_parsed"] is materialized_parsed
    assert captures["stub_bytes"] == stub_bytes
    assert captures["handler_hash"] == _manifest["dvm_handler_variant_sha256"]
    assert captures["assembly_sha"] == hashlib.sha256(stub_bytes).hexdigest()
    assert captures["rolling"] is False
    assert captures["rolling_seed"] is None
    assert len(captures["page_master_key"]) == 32
    assert captures["payload_master_key"] == captures["page_master_key"]
    assert captures["payload_paged_vm"] is True
    assert captures["ack"] is True
    assert captures["proof_parsed"] is source_parsed
    assert captures["proof_specs"] == captures["specs"]
    assert captures["proof_production"] is True
    assert captures["proof_gaps"] == (
        direct_control_flow.CoverageGapAcknowledgement(
            0x2000, 16, "known linker padding"),
    )
    assert captures["proof_tail_policy"].approvals == ()
    assert any("2 direct transfer" in line and "1 coverage gap" in line
               and "1 indirect transfer" in line for line in progress)
    assert any("virtualized 1 selected function" in line for line in progress)
    assert any("rolling-capable VM stub verified" in line for line in progress)


def test_core_consumes_verified_manifest_as_current_direct_only_request(
        monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    manifest_path = tmp_path / "selection.json"
    source.write_bytes(b"source")
    manifest_path.write_text("{}", encoding="ascii")
    stub, _stub_bytes, _manifest = _write_candidate(tmp_path, rolling=True)
    source_parsed, expected_specs, expected_policy, proof, approval, target = \
        _terminal_tail_binding_fixture()
    materialized_parsed = SimpleNamespace(is_dll=False, materialized=True)
    current_report = object()
    captures = {}
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")
    monkeypatch.setattr(pe_analyze, "analyze_pe", lambda _path: source_parsed)
    monkeypatch.setattr(
        function_discovery, "discover_functions", lambda parsed: current_report)

    def fake_load(path, **kwargs):
        captures["manifest_path"] = path
        captures["manifest_parsed"] = kwargs["parsed"]
        captures["manifest_report"] = kwargs["report"]
        captures["source_sha256"] = kwargs["source_sha256"]
        return virtualization_selection.VerifiedSelection(
            functions=(virtualization_selection.SelectedFunction(
                expected_specs[0].name,
                expected_specs[0].rva,
                expected_specs[0].size,
            ),),
            gaps=(virtualization_selection.GapAcknowledgement(
                0x2000, 16, "reviewed linker padding"),),
            tail_exits=(virtualization_selection.TailExitApproval(
                approval.function_rva,
                approval.instruction_rva,
                approval.target_rva,
                approval.rationale,
            ),),
            acknowledge_unproven_indirect_targets=True,
        )

    monkeypatch.setattr(virtualization_selection, "load_and_verify", fake_load)

    def fake_proof(parsed, specs, **kwargs):
        captures["proof_specs"] = specs
        captures["proof_gaps"] = kwargs["coverage_acknowledgements"]
        captures["proof_tails"] = kwargs["tail_exit_policy"].approvals
        return proof

    monkeypatch.setattr(
        direct_control_flow, "analyze_direct_control_flow", fake_proof)
    def fake_materialize(parsed, specs, **kwargs):
        captures["materialize_specs"] = specs
        captures["tail_exit_proof"] = kwargs["tail_exit_proof"]
        return SimpleNamespace(
            parsed=materialized_parsed,
            manifest=SimpleNamespace(
                functions=(object(),),
                native_import_call_proofs=(),
            ),
        )

    monkeypatch.setattr(
        virtualize, "materialize_selected_functions", fake_materialize)
    _patch_post_materialization_pipeline(monkeypatch, materialized_parsed, captures)

    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(output), is_dll=False, stub_path=str(stub),
            virtualization_selection_manifest=str(manifest_path),
            _allow_unverified_stub_for_tests=True,
        ),
    )

    assert result.ok, result.error
    assert captures["manifest_path"] == str(manifest_path.resolve())
    assert captures["manifest_parsed"] is source_parsed
    assert captures["manifest_report"] is current_report
    assert captures["source_sha256"] == hashlib.sha256(b"source").hexdigest()
    assert captures["proof_specs"] == expected_specs
    assert captures["proof_gaps"] == (
        direct_control_flow.CoverageGapAcknowledgement(
            0x2000, 16, "reviewed linker padding"),
    )
    assert captures["proof_tails"] == expected_policy.approvals
    assert captures["tail_exit_proof"] is proof
    assert captures["materialize_specs"][0].tail_exit == virtualization_plan.TailExitSpec(
        instruction_rva=approval.instruction_rva,
        target_rva=approval.target_rva,
        target_size=len(target),
        target_unwind_info_rva=0x3000,
        target_body_sha256=hashlib.sha256(target).hexdigest(),
    )


def test_core_rejects_manifest_mixed_with_explicit_selection_before_snapshot(
        monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    output.write_bytes(b"previous")
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")

    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(output), is_dll=False, stub_path="fresh.dll",
            virtualization_selection_manifest="selection.json",
            virtualization_specs=(
                orchestrator.VirtualizationSpec("Init", 0x1000, 16),),
        ),
    )

    assert not result.ok
    assert "incompatible" in result.error
    assert output.read_bytes() == b"previous"


def test_core_virtualization_gate_failure_is_transactional(monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    output.write_bytes(b"previous")
    monkeypatch.delenv(orchestrator._VIRTUALIZATION_GATE, raising=False)

    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(output),
            is_dll=False,
            stub_path="fresh.dll",
            virtualization_specs=(
                orchestrator.VirtualizationSpec("Init", 0x1000, 16),
            ),
        ),
    )

    assert not result.ok
    assert "experimental virtualization acknowledgment" in result.error
    assert output.read_bytes() == b"previous"
    assert list(tmp_path.glob("*.pending")) == []


def test_core_requires_indirect_ack_before_analysis(monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    output.write_bytes(b"previous")
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")

    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(output),
            is_dll=False,
            stub_path="fresh.dll",
            virtualization_specs=(
                orchestrator.VirtualizationSpec("Init", 0x1000, 16),
            ),
        ),
    )

    assert not result.ok
    assert "indirect and address-taken target closure is unproven" in result.error
    assert output.read_bytes() == b"previous"


def test_core_default_production_proof_rejects_first_exact_gap(
        monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    output.write_bytes(b"previous")
    code = b"\xB8\x01\x00\x00\x00\xC3"
    section_raw = b"\xCC" * 0x10 + code
    parsed = SimpleNamespace(
        is_dll=False,
        sections=(SimpleNamespace(
            name=".text",
            rva=0x1000,
            virtual_size=len(section_raw),
            raw=section_raw,
            characteristics=0x60000020,
        ),),
        runtime_functions=(),
    )
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")
    monkeypatch.setattr(pe_analyze, "analyze_pe", lambda _path: parsed)

    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(output),
            is_dll=False,
            stub_path="not-reached.dll",
            virtualization_specs=(
                orchestrator.VirtualizationSpec("Init", 0x1010, len(code)),
            ),
            acknowledge_unproven_indirect_targets=True,
        ),
    )

    assert not result.ok
    assert "unacknowledged executable coverage gap 0x1000+0x10" in result.error
    assert output.read_bytes() == b"previous"
