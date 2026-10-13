"""Segment bases are not flat image RVAs; native source checks stay conservative."""
from __future__ import annotations

import copy
import struct

import pytest
from iced_x86 import Decoder, Register, Mnemonic
from lifter import direct_control_flow as flow, function_discovery as discovery
from lifter import virtualization_plan as plan, source_references
from packer import pe_analyze, virtualize
from tests.test_known_source_references import _admit, _image, _rip, _manifest
from tests import test_virtualization_materializer as materializer

_PREFIX = {'fs': 0x64, 'gs': 0x65, 'cs': 0x2e, 'ds': 0x3e, 'es': 0x26, 'ss': 0x36}
_REGISTER = {name: getattr(Register, name.upper()) for name in _PREFIX}
_ERROR = 'unbounded source reference: segment-relative memory operand'


def _seg_rip(template, segment, target, source=0x1100):
    # Force the literal prefix, including DS (which assemblers may omit).
    raw = bytes((_PREFIX[segment],)) + _rip(template, target, source + 1)
    decoded = Decoder(64, raw, ip=source).decode()
    assert decoded.segment_prefix == _REGISTER[segment]
    assert decoded.is_ip_rel_memory_operand and decoded.memory_base == Register.RIP
    assert decoded.ip_rel_memory_address == target
    return raw


@pytest.mark.parametrize('interface', ['preflight', 'discovery'])
@pytest.mark.parametrize('segment', ['fs', 'gs'])
@pytest.mark.parametrize('template', [
    'movzx eax,byte ptr {mem}', 'mov rax,qword ptr {mem}',
    'mov byte ptr {mem},1', 'movdqu xmm0,xmmword ptr {mem}',
    'btr qword ptr {mem},7',
])
@pytest.mark.parametrize('target', [0x805, 0x4000, 0x1000, 0x1001])
def test_unknown_segment_base_rejects_even_nominally_disjoint_native_reference(interface, segment, template, target):
    image = _image(_seg_rip(template, segment, target))
    before = copy.deepcopy(image)
    if interface == 'preflight':
        with pytest.raises(flow.DirectControlFlowError, match=_ERROR):
            flow.analyze_direct_control_flow(image, (plan.FunctionSpec('probe', 0x1000, 7),), production=False)
    else:
        report = discovery.discover_functions(image, exports=())
        candidate = next(c for c in report.candidates if c.rva == 0x1000)
        assert candidate.direct_control_proof_status == 'rejected'
        assert _ERROR in candidate.direct_control_rejection_reason
        assert candidate.direct_reference_gate_passed is False
        assert candidate.indirect_target_closure_proven is False
    assert image == before


@pytest.mark.parametrize('interface', ['preflight', 'discovery'])
@pytest.mark.parametrize('segment', ['cs', 'ds', 'es', 'ss'])
@pytest.mark.parametrize('template,width', [('movzx eax,byte ptr {mem}', 1), ('mov rax,qword ptr {mem}', 8)])
@pytest.mark.parametrize('target', [0x805, 0x1000, 0x1001, 0x1007])
def test_ignored_legacy_segments_keep_exact_flat_span_checks(interface, segment, template, width, target):
    raw = _seg_rip(template, segment, target)
    refs = source_references.instruction_references(Decoder(64, raw, ip=0x1100))
    assert len(refs) == 1 and refs[0].target_rva == target and refs[0].size == width
    _admit(_image(raw), interface, target < 0x1007 and target + width > 0x1000)


@pytest.mark.parametrize('interface', ['preflight', 'discovery'])
@pytest.mark.parametrize('segment', ['fs', 'gs'])
@pytest.mark.parametrize('target', [0x805, 0x1000, 0x1001, 0x1007])
def test_address_only_lea_does_not_add_segment_base_or_waive_interior_reference(interface, segment, target):
    raw = _seg_rip('lea rax,{mem}', segment, target)
    refs = source_references.instruction_references(Decoder(64, raw, ip=0x1100))
    assert len(refs) == 1 and refs[0].address_only and refs[0].target_rva == target
    _admit(_image(raw), interface, 0x1000 <= target < 0x1007)


@pytest.mark.parametrize('interface', ['preflight', 'discovery'])
@pytest.mark.parametrize('segment', ['fs', 'gs'])
@pytest.mark.parametrize('target', [0x1000, 0x4000])
def test_non_accessing_nop_is_not_reclassified_as_segment_memory(interface, segment, target):
    # Keystone's spelling emits reserved 0F18 /4, not canonical 0F1F /0.
    raw = bytes((_PREFIX[segment],)) + bytes.fromhex('0f1f05') + struct.pack('<i', target - 0x1100 - 8)
    decoded = Decoder(64, raw, ip=0x1100).decode()
    assert decoded.mnemonic == Mnemonic.NOP and decoded.ip_rel_memory_address == target
    assert source_references.instruction_references(Decoder(64, raw, ip=0x1100)) == ()
    _admit(_image(raw), interface, False)


@pytest.mark.parametrize('interface', ['preflight', 'discovery'])
@pytest.mark.parametrize('segment', ['fs', 'gs'])
def test_eip_address_size_rejection_precedence_is_unchanged(interface, segment):
    raw = bytes((_PREFIX[segment],)) + bytes.fromhex('670fb60500000000')
    image = _image(raw)
    if interface == 'preflight':
        with pytest.raises(flow.DirectControlFlowError, match='address-size-relative operand'):
            flow.analyze_direct_control_flow(image, (plan.FunctionSpec('probe', 0x1000, 7),), production=False)
    else:
        candidate = next(c for c in discovery.discover_functions(image, exports=()).candidates if c.rva == 0x1000)
        assert 'address-size-relative operand' in candidate.direct_control_rejection_reason


@pytest.mark.parametrize('segment', ['fs', 'gs'])
@pytest.mark.parametrize('template', ['movzx eax,byte ptr {mem}', 'mov byte ptr {mem},1'])
def test_low_level_commit_rechecks_segment_mutation_outside_selected_body(segment, template):
    image, selected = materializer._parsed()
    native = _seg_rip(template, 'cs', 0x4000, source=0x1020) + b'\xc3'
    image.sections[0].raw = image.sections[0].raw[:0x20] + native
    image.sections[0].virtual_size = len(image.sections[0].raw)
    old = image.runtime_functions[1]
    image.runtime_functions = (image.runtime_functions[0], pe_analyze.ParsedRuntimeFunction(
        old.begin_rva, old.begin_rva + len(native), old.unwind_info_rva))
    image.sections[1].raw = image.sections[1].raw[:12] + struct.pack('<III', 0x1020, 0x1020 + len(native), 0x3010)
    manifest = _manifest(image, len(selected))
    assert virtualize.apply_virtualization_manifest(image, manifest, acknowledge_no_interior_entries=True)
    replacement = _seg_rip(template, segment, 0x4000, source=0x1020) + b'\xc3'
    assert len(replacement) == len(native) and replacement[1:] == native[1:]
    image.sections[0].raw = image.sections[0].raw[:0x20] + replacement
    before = copy.deepcopy(image)
    with pytest.raises(virtualize.VirtualizationMaterializationError, match=_ERROR):
        virtualize.apply_virtualization_manifest(image, manifest, acknowledge_no_interior_entries=True)
    assert image == before


@pytest.mark.parametrize('segment', ['fs', 'gs'])
def test_pdb_supplement_has_no_segment_base_waiver(segment):
    native = _seg_rip('movzx eax,byte ptr {mem}', segment, 0x805)
    image = _image(native)
    image.runtime_functions = image.runtime_functions[:1]
    with pytest.raises(flow.DirectControlFlowError, match=_ERROR):
        flow.analyze_direct_control_flow(image, (plan.FunctionSpec('probe', 0x1000, 7),),
            production=False, _supplemental_code_ranges=((0x1100, 0x1100 + len(native) + 1),))


@pytest.mark.parametrize('segment', ['fs', 'gs'])
def test_segment_base_can_redirect_nominally_disjoint_read_into_changed_source_bytes(segment):
    # Owned Unicorn state, not the Windows host's thread/segment registers.
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_FS_BASE, UC_X86_REG_GS_BASE
    base = 0x140000000
    raw = _seg_rip('movzx eax,byte ptr {mem}', segment, 0x805)
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    machine.mem_map(base, 0x3000)
    machine.mem_write(base + 0x1000, bytes.fromhex('90b82a000000c3'))
    machine.mem_write(base + 0x1100, raw)
    machine.reg_write(UC_X86_REG_FS_BASE if segment == 'fs' else UC_X86_REG_GS_BASE, 0x800)
    machine.emu_start(base + 0x1100, base + 0x1100 + len(raw))
    assert machine.reg_read(UC_X86_REG_EAX) == 0
    machine.mem_write(base + 0x1005, b'\xcc')
    machine.emu_start(base + 0x1100, base + 0x1100 + len(raw))
    assert machine.reg_read(UC_X86_REG_EAX) == 204
