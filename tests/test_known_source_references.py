"""Public admission contracts for references to overwritten source code."""
from __future__ import annotations

import copy
import struct
from types import SimpleNamespace

import pytest
from iced_x86 import Decoder, Mnemonic
from keystone import KS_ARCH_X86, KS_MODE_64, Ks

from lifter import direct_control_flow as flow, function_discovery as discovery
from lifter import source_references, virtualization_plan as plan
from packer import pe_analyze, virtualize
from tests import test_function_discovery as fixtures
from tests import test_virtualization_materializer as materializer


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_SELECTED = bytes.fromhex("90b82a000000c3")


def _rip(template, target, source=0x1100):
    probe = bytes(_KS.asm(template.format(mem="[rip]"), addr=source)[0])
    displacement = target - source - len(probe)
    return bytes(_KS.asm(template.format(mem=f"[rip + {displacement}]"), addr=source)[0])


def _image(native):
    image = fixtures._parsed([(0x1000, _SELECTED, 0), (0x1100, native + b"\xc3", 0)])
    image.dir64_relocations = ()
    return image


def _admit(image, interface, reject):
    before = copy.deepcopy(image)
    if interface == "preflight":
        if reject:
            with pytest.raises(flow.DirectControlFlowError, match="source reference"):
                flow.analyze_direct_control_flow(image, (plan.FunctionSpec("probe", 0x1000, 7),), production=False)
        else:
            proof = flow.analyze_direct_control_flow(image, (plan.FunctionSpec("probe", 0x1000, 7),), production=False)
            assert proof.indirect_target_closure_proven is False
    else:
        report = discovery.discover_functions(image, exports=())
        candidate = next(x for x in report.candidates if x.rva == 0x1000)
        assert (candidate.direct_control_proof_status == "rejected") is reject
        assert candidate.indirect_target_closure_proven is False
        if reject:
            assert "source reference" in candidate.direct_control_rejection_reason
            assert candidate.direct_reference_gate_passed is False
    assert image == before


@pytest.mark.parametrize("interface", ["preflight", "discovery"])
@pytest.mark.parametrize("template,width", [
    ("movzx eax,byte ptr {mem}", 1),
    ("mov rax,qword ptr {mem}", 8),
    ("movdqu xmm0,xmmword ptr {mem}", 16),
    ("mov byte ptr {mem},1", 1),
    ("mov qword ptr {mem},rax", 8),
])
@pytest.mark.parametrize("offset", [-8, -1, 0, 5, 7])
def test_fixed_width_access_checks_entire_span(interface, template, width, offset):
    image = _image(_rip(template, 0x1000 + offset))
    _admit(image, interface, offset < 7 and offset + width > 0)


@pytest.mark.parametrize("interface", ["preflight", "discovery"])
@pytest.mark.parametrize("offset", [-1, 0, 1, 5, 7])
def test_lea_interior_or_unconsumed_entry_pointer_rejects(interface, offset):
    # LEA of an exact entry is not by itself a proof that arithmetic cannot
    # derive an interior target before an indirect call.
    _admit(_image(_rip("lea rax,{mem}", 0x1000 + offset)), interface, 0 <= offset < 7)


def _bounded_entry_call(branch_to_call):
    # An immediate LEA-to-CALL transfer preserves the selected entry. A
    # direct branch into CALL can bypass LEA and supply entry+1 in RAX.
    prefix = bytes(_KS.asm("sub rsp,0x28" +
                           ("; mov rax,rcx" if branch_to_call else ""),
                           addr=0x1100)[0])
    branch = bytes.fromhex("eb07") if branch_to_call else b""
    lea = _rip("lea rax,{mem}", 0x1000,
               source=0x1100 + len(prefix) + len(branch))
    assert len(lea) == 7
    suffix = bytes(_KS.asm("call rax; add rsp,0x28; ret",
                           addr=0x1100 + len(prefix) + len(branch) + len(lea))[0])
    return prefix + branch + lea + suffix


@pytest.mark.parametrize("interface", ["preflight", "discovery"])
@pytest.mark.parametrize("branch_to_call", [False, True])
def test_bounded_exact_entry_call_and_alternate_predecessor_agree(
        interface, branch_to_call):
    _admit(_image(_bounded_entry_call(branch_to_call)), interface, branch_to_call)


def test_unresolved_native_prefix_cannot_prove_exact_entry_call(monkeypatch):
    image = _image(_bounded_entry_call(False))
    original = discovery.jump_table.decode_function_body

    def unresolved_native(code, begin, end):
        if begin == 0x1100:
            raise discovery.jump_table.JumpTableUnresolved("fixture unscanned suffix")
        return original(code, begin, end)

    monkeypatch.setattr(discovery.jump_table, "decode_function_body", unresolved_native)
    report = discovery.discover_functions(image, exports=())
    selected = next(item for item in report.candidates if item.rva == 0x1000)
    assert selected.direct_control_proof_status == "rejected"
    assert "known source reference: RIP address" in selected.direct_control_rejection_reason
    with pytest.raises(flow.DirectControlFlowError):
        flow.analyze_direct_control_flow(
            image, (plan.FunctionSpec("probe", 0x1000, 7),), production=False)


def test_other_function_direct_edge_cannot_prove_local_exact_call():
    native = tuple(Decoder(64, _bounded_entry_call(False), ip=0x1100))
    call_rva = next(int(item.ip) for item in native if item.mnemonic == Mnemonic.CALL)
    other = tuple(Decoder(64, bytes(_KS.asm(f"jmp {call_rva}", addr=0x1200)[0]),
                          ip=0x1200))
    proven = source_references.proven_immediate_entry_calls((native, other))
    assert not proven
    assert source_references.SourceReferenceIndex(
        source_references.instruction_references(native),
        proven_entry_calls=proven,
    ).rejection("probe", 0x1000, 7) is not None


def test_known_address_entry_to_call_site_cannot_prove_local_exact_call():
    native = tuple(Decoder(64, _bounded_entry_call(False), ip=0x1100))
    call_rva = next(int(item.ip) for item in native if item.mnemonic == Mnemonic.CALL)
    proven = source_references.proven_immediate_entry_calls(
        (native,), known_entry_targets=(call_rva,))
    assert not proven
    assert source_references.SourceReferenceIndex(
        source_references.instruction_references(native),
        proven_entry_calls=proven,
    ).rejection("probe", 0x1000, 7) is not None


@pytest.mark.parametrize("interface", ["preflight", "discovery"])
@pytest.mark.parametrize("offset", [-1, 0, 1, 5, 7])
def test_dir64_values_not_just_slot_locations_participate(interface, offset):
    image = _image(b"\x90")
    image.sections.append(pe_analyze.ParsedSection(
        ".rdata", 0x4000, 8, struct.pack("<Q", image.image_base + 0x1000 + offset), 0x40000040))
    image.dir64_relocations = (pe_analyze.ParsedDir64Relocation(0x4000),)
    # A relocatable pointer value is available outside the decoded local
    # caller; exact-entry storage is not an indirect-target closure proof.
    _admit(image, interface, 0 <= offset < 7)


@pytest.mark.parametrize("interface", ["preflight", "discovery"])
@pytest.mark.parametrize("slots", [(0x4000, 0x4000), (0x4000, 0x4004), (True,), (0x4001,), (0,), ((1 << 32) - 7,)])
def test_invalid_unused_dir64_inventory_is_not_silently_ignored(interface, slots):
    image = _image(b"\x90")
    image.sections.append(pe_analyze.ParsedSection(".rdata", 0x4000, 8, bytes(8), 0x40000040))
    image.dir64_relocations = tuple(SimpleNamespace(target_rva=x) for x in slots)
    _admit(image, interface, True)


@pytest.mark.parametrize("template", ["xsave {mem}", "bt qword ptr {mem},rcx"])
@pytest.mark.parametrize("interface", ["preflight", "discovery"])
def test_ambiguous_access_span_is_fail_closed(template, interface):
    _admit(_image(_rip(template, 0x4000)), interface, True)


def test_supplemental_decoded_code_cannot_waive_known_reference():
    native = _rip("movzx eax,byte ptr {mem}", 0x1005)
    image = _image(native)
    image.runtime_functions = image.runtime_functions[:1]
    with pytest.raises(flow.DirectControlFlowError, match="known source reference"):
        flow.analyze_direct_control_flow(image, (plan.FunctionSpec("probe", 0x1000, 7),),
            production=False, _supplemental_code_ranges=((0x1100, 0x1100 + len(native) + 1),))


@pytest.mark.parametrize("interface", ["preflight", "discovery"])
def test_eip_relative_address_is_not_mistaken_for_rip_rva(interface):
    # 67 MOVZX EAX,byte ptr [EIP+disp32]. Actual VA zero-extension matters.
    _admit(_image(bytes.fromhex("670fb60500000000")), interface, True)


@pytest.mark.parametrize("template", ["lea rax,{mem}", "movzx eax,byte ptr {mem}"])
def test_selected_self_reference_has_no_native_only_waiver(template):
    code = _rip(template, 0x1001, source=0x1000) + b"\xc3"
    image = fixtures._parsed([(0x1000, code, 0)])
    with pytest.raises(flow.DirectControlFlowError, match="known source reference"):
        flow.analyze_direct_control_flow(image, (plan.FunctionSpec("self", 0x1000, len(code)),), production=False)


def test_heuristic_leaf_self_reference_participates_in_discovery():
    code = _rip("lea rax,{mem}", 0x1001, source=0x1000) + b"\xc3"
    image = fixtures._parsed([(0x1000, code, 0)])
    image.runtime_functions = ()
    image.pdata_rva = image.pdata_count = 0
    report = discovery.discover_functions(image, exports=(discovery.ExportSymbol("leaf", 1, 0x1000),))
    assert report.candidates[0].direct_control_proof_status == "rejected"
    assert "known source reference" in report.candidates[0].direct_control_rejection_reason


@pytest.mark.parametrize("kind", ["RIP", "DIR64"])
def test_trimmed_padding_bytes_are_still_overwritten(kind):
    image, selected = materializer._parsed()
    padded = selected + b"\xcc\xcc"
    image.sections[0].raw = padded + image.sections[0].raw[len(padded):]
    old = image.runtime_functions[0]
    image.runtime_functions = (pe_analyze.ParsedRuntimeFunction(0x1000, 0x1000 + len(padded), old.unwind_info_rva), image.runtime_functions[1])
    image.sections[1].raw = struct.pack("<III", 0x1000, 0x1000 + len(padded), 0x3000) + image.sections[1].raw[12:]
    if kind == "DIR64":
        image.sections[3].raw = struct.pack("<Q", image.image_base + 0x1000 + len(selected))
    else:
        native = _rip("movzx eax,byte ptr {mem}", 0x1000 + len(selected), source=0x1020) + b"\xc3"
        image.sections[0].raw = image.sections[0].raw[:0x20] + native
        image.sections[0].virtual_size = len(image.sections[0].raw)
        image.runtime_functions = (image.runtime_functions[0], pe_analyze.ParsedRuntimeFunction(0x1020, 0x1020 + len(native), 0x3010))
        image.sections[1].raw = image.sections[1].raw[:12] + struct.pack("<III", 0x1020, 0x1020 + len(native), 0x3010)
    with pytest.raises(flow.DirectControlFlowError, match="known source reference"):
        flow.analyze_direct_control_flow(image, (plan.FunctionSpec("padded", 0x1000, len(padded), len(selected)),), production=False)


def _manifest(image, size):
    text, data = virtualize._next_generated_rvas(image, 1)
    return plan.compile_virtualization_manifest(
        (plan.FunctionSpec("probe", 0x1000, size),),
        plan.SectionImage.from_parsed_sections(image.sections),
        generated_text_rva=text, generated_data_rva=data, runtime_common_rva=text,
        source_dir64_relocations=tuple(plan.SourceDir64Relocation(x.target_rva) for x in image.dir64_relocations),
        require_source_relocation_metadata=True,
        source_exception_metadata=plan.SourceExceptionMetadata(image.pdata_rva, tuple(
            plan.SourceRuntimeFunction(x.begin_rva, x.end_rva, x.unwind_info_rva, x.unwind_flags)
            for x in image.runtime_functions)),
        require_source_exception_metadata=True)


@pytest.mark.parametrize("kind", ["load", "store", "lea", "dir64"])
def test_low_level_commit_rechecks_external_native_bytes_and_pointer_values(kind):
    image, selected = materializer._parsed()
    template = {"load": "movzx eax,byte ptr {mem}", "store": "mov byte ptr {mem},1", "lea": "lea rax,{mem}"}.get(kind)
    if template:
        native = _rip(template, 0x4000, source=0x1020) + b"\xc3"
        image.sections[0].raw = image.sections[0].raw[:0x20] + native
        image.sections[0].virtual_size = len(image.sections[0].raw)
        old = image.runtime_functions[1]
        image.runtime_functions = (image.runtime_functions[0], pe_analyze.ParsedRuntimeFunction(
            old.begin_rva, old.begin_rva + len(native), old.unwind_info_rva))
        image.sections[1].raw = image.sections[1].raw[:12] + struct.pack("<III", 0x1020, 0x1020 + len(native), 0x3010)
    else:
        image.sections[3].raw = struct.pack("<Q", image.image_base + 0x4000)
    manifest = _manifest(image, len(selected))
    # A valid, unchanged source still commits. This does not execute the stub.
    assert virtualize.apply_virtualization_manifest(image, manifest, acknowledge_no_interior_entries=True)
    if template:
        replacement = _rip(template, 0x1001, source=0x1020) + b"\xc3"
        assert len(replacement) == len(native)
        image.sections[0].raw = image.sections[0].raw[:0x20] + replacement
    else:
        image.sections[3].raw = struct.pack("<Q", image.image_base + 0x1000)
    before = copy.deepcopy(image)
    with pytest.raises(virtualize.VirtualizationMaterializationError, match="known source reference"):
        virtualize.apply_virtualization_manifest(image, manifest, acknowledge_no_interior_entries=True)
    assert image == before
