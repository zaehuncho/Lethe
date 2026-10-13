"""Held-out PE metadata reference contracts for full selected source extent."""
from __future__ import annotations
import copy
import struct
from types import SimpleNamespace

import pytest
from lifter import direct_control_flow as flow, function_discovery as discovery
from lifter import virtualization_plan as plan
from packer import pe_analyze, virtualize
from tests.test_known_source_references import _image, _manifest
from tests import test_virtualization_materializer as materializer


@pytest.mark.parametrize('kind', ('export', 'oep', 'tls', 'guard_cf', 'guard_long_jump', 'guard_eh'))
@pytest.mark.parametrize('offset', (0, 1, 7))
def test_known_entry_target_must_not_enter_selected_interior(monkeypatch, kind, offset):
    image = _image(b'\x90')
    target = 0x1000 + offset
    if kind == 'export':
        image.export_directory_rva = 0x3000
        image.export_directory_size = 40
        monkeypatch.setattr(discovery, 'parse_pe_exports',
                            lambda _image: (discovery.ExportSymbol('alias', 1, target),))
    elif kind == 'oep':
        image.oep_rva = target
    elif kind == 'tls':
        image.tls = SimpleNamespace(callback_rvas=(target,), index_rva=0x4000,
                                    raw_start_rva=0, raw_end_rva=0)
    else:
        field = {'guard_cf': 'guard_cf_targets',
                 'guard_long_jump': 'guard_long_jump_targets',
                 'guard_eh': 'guard_eh_continuation_targets'}[kind]
        image.load_config = SimpleNamespace(directory_rva=0x3000, directory_size=64,
            guard_flags=0, **{field: (pe_analyze.ParsedGuardTarget(target),)})
    spec = plan.FunctionSpec('vm_probe', 0x1000, 7)
    before = copy.deepcopy(image)
    if offset == 1:
        with pytest.raises(flow.DirectControlFlowError, match='known source reference'):
            flow.analyze_direct_control_flow(image, (spec,), production=False)
    else:
        proof = flow.analyze_direct_control_flow(image, (spec,), production=False)
        assert proof.indirect_target_closure_proven is False
    assert image == before


@pytest.mark.parametrize('rva,size,rejected', ((0x1000,1,True),(0x1001,1,True),
                                            (0x0FFF,2,True),(0x0FFE,2,False),
                                            (0x1007,1,False)))
def test_metadata_storage_bytes_are_not_overwritten(rva, size, rejected):
    image = _image(b'\x90')
    image.rsrc_directory_rva = rva
    image.rsrc_directory_size = size
    spec = plan.FunctionSpec('vm_probe', 0x1000, 7)
    if rejected:
        with pytest.raises(flow.DirectControlFlowError, match='known source reference'):
            flow.analyze_direct_control_flow(image, (spec,), production=False)
    else:
        flow.analyze_direct_control_flow(image, (spec,), production=False)


def test_commit_rechecks_stale_entry_metadata_without_changing_source():
    image, selected = materializer._parsed()
    manifest = _manifest(image, len(selected))
    original = copy.deepcopy(image)
    assert virtualize.apply_virtualization_manifest(
        image, manifest, acknowledge_no_interior_entries=True)
    assert image == original
    image.oep_rva = 0x1001
    before = copy.deepcopy(image)
    with pytest.raises(virtualize.VirtualizationMaterializationError,
                       match='known source reference'):
        virtualize.apply_virtualization_manifest(
            image, manifest, acknowledge_no_interior_entries=True)
    assert image == before


def test_volatile_region_is_not_itself_a_byte_or_entry_reference():
    image = _image(b"\x90")
    raw = struct.pack("<IHHIIII", 24, 1, 1, 0, 0, 0, 0)
    volatile = SimpleNamespace(rva=0x3000, raw=raw, access_rvas=(),
                               info_ranges=((0x1000, 0x1000),))
    image.load_config = SimpleNamespace(directory_rva=0x3100,
        directory_size=0x100, guard_flags=0, volatile_metadata=volatile)
    spec = plan.FunctionSpec("vm_probe", 0x1000, 7)
    proof = flow.analyze_direct_control_flow(image, (spec,), production=False)
    assert proof.indirect_target_closure_proven is False
    volatile.access_rvas = (0x1001,)
    with pytest.raises(flow.DirectControlFlowError, match="volatile access target"):
        flow.analyze_direct_control_flow(image, (spec,), production=False)


def test_address_taken_iat_slot_checks_all_eight_bytes():
    image = _image(b"\x90")
    image.load_config = SimpleNamespace(directory_rva=0x3000,
        directory_size=0x40, guard_flags=0,
        guard_address_taken_iat_entries=(pe_analyze.ParsedGuardTarget(0x1000),))
    # The candidate starts four bytes into the declared 8-byte IAT slot.
    candidate = plan.FunctionSpec("overlap", 0x1004, 7)
    from lifter import source_references
    index = source_references.SourceReferenceIndex(
        source_references.metadata_references(image, exports=()))
    assert "Guard address-taken IAT target" in index.rejection(
        candidate.name, candidate.rva, candidate.size)


@pytest.mark.parametrize("interface", ("preflight", "discovery"))
@pytest.mark.parametrize("slot,rejected", (
    (0x0FF8, False), (0x0FF9, True), (0x1000, True),
    (0x1006, True), (0x1007, False),
))
def test_ordinary_import_iat_slot_checks_all_eight_bytes(interface, slot, rejected):
    image = _image(b"\x90")
    image.imports = (SimpleNamespace(funcs=(SimpleNamespace(iat_rva=slot),)),)
    if interface == "preflight":
        if rejected:
            with pytest.raises(flow.DirectControlFlowError,
                               match="ordinary import IAT slot"):
                flow.analyze_direct_control_flow(
                    image, (plan.FunctionSpec("probe", 0x1000, 7),),
                    production=False)
        else:
            flow.analyze_direct_control_flow(
                image, (plan.FunctionSpec("probe", 0x1000, 7),),
                production=False)
    else:
        report = discovery.discover_functions(image, exports=())
        candidate = next(item for item in report.candidates if item.rva == 0x1000)
        assert (candidate.direct_control_proof_status == "rejected") is rejected
        if rejected:
            assert "ordinary import IAT slot" in candidate.direct_control_rejection_reason
            assert candidate.direct_reference_gate_passed is False


def test_volatile_info_annotation_does_not_bind_padding_suffix(monkeypatch):
    from tests import test_padding_aware_extents as padding
    body = padding._asm("mov eax, 42; ret")
    source = body + b"\xCC"
    raw = struct.pack("<IHHIIII", 24, 1, 1, 0, 0, 0, 0)
    volatile = SimpleNamespace(rva=0x3000, raw=raw, access_rvas=(),
                               info_ranges=((0x1000, len(source)),))
    config = SimpleNamespace(
        directory_rva=0x3100, directory_size=0x100, guard_flags=0,
        guard_cf_function_table_rva=0, guard_cf_targets=(),
        guard_address_taken_iat_entry_table_rva=0,
        guard_address_taken_iat_entries=(),
        guard_long_jump_target_table_rva=0, guard_long_jump_targets=(),
        guard_eh_continuation_table_rva=0, guard_eh_continuation_targets=(),
        volatile_metadata=volatile,
    )
    image = padding._parsed(source, load_config=config)
    extent = SimpleNamespace(rva=0x1000, size=len(source),
                             lifted_body_size=len(body))
    assert discovery._padding_metadata_rejection(image, extent, (), (), ()) is None
    monkeypatch.setattr(discovery, "parse_pe_exports", lambda _image: ())
    spec = plan.FunctionSpec("vm_probe", 0x1000, len(source), len(body))
    virtualize._validate_padding_suffix_bindings(image, (spec,))
    volatile.access_rvas = (0x1000 + len(body),)
    assert "volatile access target" in discovery._padding_metadata_rejection(
        image, extent, (), (), ())
    with pytest.raises(virtualize.VirtualizationMaterializationError,
                       match="volatile access target"):
        virtualize._validate_padding_suffix_bindings(image, (spec,))


def _minimal_export_image(tmp_path, outside):
    path = tmp_path / "export-span.dll"
    header = bytearray(0x200)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    header[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", header, 0x84, 0x8664)
    struct.pack_into("<H", header, 0x94, 0xF0)
    struct.pack_into("<H", header, 0x98, 0x20B)
    struct.pack_into("<I", header, 0x98 + 0x6C, 1)
    struct.pack_into("<II", header, 0x98 + 0x70, 0x2000, 0x80)
    path.write_bytes(header)
    text = bytearray(0x20)
    edata = bytearray(0x80)
    fields = dict(address=0x2040, names=0x2048, ordinals=0x204C,
                  name=0x2060, module=0x2050)
    if outside is not None:
        fields[outside] = 0x1000
    struct.pack_into("<IIHHIIIIIII", edata, 0, 0, 0, 0, 0,
                     fields["module"], 1, 1, 1, fields["address"],
                     fields["names"], fields["ordinals"])
    edata[0x50:0x54] = b"lab\x00"
    edata[0x60:0x66] = b"alias\x00"
    struct.pack_into("<I", edata, 0x40, 0x1010)
    struct.pack_into("<I", edata, 0x48, fields["name"])
    struct.pack_into("<H", edata, 0x4C, 0)
    if outside == "address":
        struct.pack_into("<I", text, 0, 0x1010)
    elif outside == "names":
        struct.pack_into("<I", text, 0, 0x2060)
    elif outside == "ordinals":
        struct.pack_into("<H", text, 0, 0)
    elif outside == "name":
        text[:6] = b"alias\x00"
    elif outside == "module":
        text[:4] = b"lab\x00"
    sections = (
        pe_analyze.ParsedSection(".text", 0x1000, len(text), bytes(text), 0x60000020),
        pe_analyze.ParsedSection(".edata", 0x2000, len(edata), bytes(edata), 0x40000040),
    )
    return SimpleNamespace(
        path=str(path), image_base=0x140000000, size_of_image=0x3000,
        sections=sections, export_directory_rva=0x2000,
        export_directory_size=0x80, oep_rva=0, tls=None, imports=(),
        dir64_relocations=(), runtime_functions=(), pdata_rva=0, pdata_count=0,
        rsrc_directory_rva=0, rsrc_directory_size=0,
        delay_import_rva=0, delay_import_size=0, load_config=None,
    )


@pytest.mark.parametrize("outside", (None, "address", "names", "ordinals",
                                       "name", "module"))
def test_export_tables_outside_declared_span_fail_closed(tmp_path, outside):
    from lifter import source_references
    image = _minimal_export_image(tmp_path, outside)
    assert len(discovery.parse_pe_exports(image)) == 1
    if outside is None:
        refs = source_references.metadata_references(image)
        assert any(ref.kind == "export directory" and ref.target_rva == 0x2000
                   for ref in refs)
    else:
        with pytest.raises(source_references.SourceReferenceError,
                           match="export-table storage escapes"):
            source_references.metadata_references(image)


def test_unbounded_eh_language_data_cannot_be_overwritten_at_commit():
    from lifter import source_references
    image, _selected = materializer._parsed()
    code = bytes.fromhex("b82a000000c3")
    text = bytearray(b"\xCC" * 0x21)
    text[0x10:0x18] = bytes.fromhex("09000000") + struct.pack("<I", 0x1020)
    text[0x18:0x1E] = code
    text[0x20] = 0xC3
    image.sections[0].raw = bytes(text)
    image.sections[0].virtual_size = len(text)
    image.sections[1].raw = (
        struct.pack("<III", 0x1018, 0x101E, 0x3000)
        + struct.pack("<III", 0x1020, 0x1021, 0x1010))
    image.runtime_functions = (
        pe_analyze.ParsedRuntimeFunction(0x1018, 0x101E, 0x3000),
        pe_analyze.ParsedRuntimeFunction(0x1020, 0x1021, 0x1010, 1),
    )
    spec = plan.FunctionSpec("probe", 0x1018, len(code))
    assert pe_analyze._validate_runtime_function(
        0x1020, 0x1021, 0x1010, image.size_of_image,
        image.sections, set()) == (1, 0x1020)
    index = source_references.SourceReferenceIndex(
        source_references.metadata_references(image))
    assert "unbounded unwind handler data" in index.rejection(
        spec.name, spec.rva, spec.size)
    with pytest.raises(flow.DirectControlFlowError,
                       match="unbounded unwind handler data"):
        flow.analyze_direct_control_flow(image, (spec,), production=False)
    text_rva, data_rva = virtualize._next_generated_rvas(image, 1)
    manifest = plan.compile_virtualization_manifest(
        (spec,), plan.SectionImage.from_parsed_sections(image.sections),
        generated_text_rva=text_rva, generated_data_rva=data_rva,
        runtime_common_rva=text_rva,
        source_dir64_relocations=tuple(
            plan.SourceDir64Relocation(item.target_rva)
            for item in image.dir64_relocations),
        require_source_relocation_metadata=True,
        source_exception_metadata=plan.SourceExceptionMetadata(
            image.pdata_rva, tuple(plan.SourceRuntimeFunction(
                item.begin_rva, item.end_rva, item.unwind_info_rva,
                item.unwind_flags) for item in image.runtime_functions)),
        require_source_exception_metadata=True,
    )
    before = copy.deepcopy(image)
    with pytest.raises(virtualize.VirtualizationMaterializationError,
                       match="unbounded unwind handler data"):
        virtualize.apply_virtualization_manifest(
            image, manifest, acknowledge_no_interior_entries=True)
    assert image == before
