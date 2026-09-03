"""Experimental virtualization orchestration and build-provenance gates."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from daedalus import shuffle_opcodes
from lifter import direct_control_flow
from packer import (
    assemble, container, keyed_validation, orchestrator, payload, pe_analyze, report,
    virtualize,
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
        orchestrator._load_virtualization_build(str(stub))
    )

    assert loaded == stub_bytes
    assert digest == hashlib.sha256(stub_bytes).hexdigest()
    assert len(table.entries) > 0
    assert handler_hash == _manifest["dvm_handler_variant_sha256"]
    assert rolling is True


def test_promoted_stem_manifest_is_not_silently_used_for_candidate(tmp_path):
    stub = tmp_path / "lethe_stub_x64.dll"
    stub.write_bytes(b"stub")
    stub.with_suffix(".manifest.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match=r"\.dll\.manifest\.json"):
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
        orchestrator._load_virtualization_build(str(stub))


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


def test_core_materializes_before_payload_and_pins_exact_stub(
        monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    stub, stub_bytes, _manifest = _write_candidate(tmp_path, rolling=False)
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
            manifest=SimpleNamespace(functions=(object(),)),
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
            virtualization_tail_exit_approvals=(
                orchestrator.VirtualizationTailExitApproval(
                    0x1000, 0x1004, 0x2000, "known tail target"),
            ),
            acknowledge_unproven_indirect_targets=True,
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
    assert captures["proof_tail_policy"].approvals == (
        direct_control_flow.TailExitApproval(
            0x1000, 0x1004, 0x2000, "known tail target"),
    )
    assert any("2 direct transfer" in line and "1 coverage gap" in line
               and "1 indirect transfer" in line for line in progress)
    assert any("virtualized 1 selected function" in line for line in progress)


def test_core_rejects_rolling_stub_for_production_paging(monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    stub, _stub_bytes, _manifest = _write_candidate(tmp_path, rolling=True)
    monkeypatch.setenv(orchestrator._VIRTUALIZATION_GATE, "1")
    monkeypatch.setattr(
        pe_analyze,
        "analyze_pe",
        lambda _path: SimpleNamespace(is_dll=False),
    )
    monkeypatch.setattr(
        direct_control_flow,
        "analyze_direct_control_flow",
        lambda *_args, **_kwargs: SimpleNamespace(
            direct_transfers=(),
            coverage_gaps=(),
            acknowledged_coverage_gaps=(),
            indirect_transfers=(),
        ),
    )
    result = orchestrator.pack_file(
        str(source),
        orchestrator.PackOptions(
            output_path=str(output),
            is_dll=False,
            stub_path=str(stub),
            virtualization_specs=(
                orchestrator.VirtualizationSpec("Init", 0x1000, 16),
            ),
            acknowledge_unproven_indirect_targets=True,
        ),
    )
    assert not result.ok
    assert "rolling stub builds are incompatible" in result.error


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
