"""Bounded source outgoing spans: no silent eight-argument truncation."""
from __future__ import annotations

import struct
import pytest
from lifter import x64_lifter,virtualization_plan
from daedalus import daedalus_asm,daedalus_ref,daedalus_rolling,shuffle_opcodes
from tests.test_virtualization_plan import _asm


def prove(source):
    code=_asm(source)
    spans={}
    depth=x64_lifter.validate_materialized_stack_window(
        code,window_size=512,native_call_targets={0x4000},native_call_stack_bytes=spans)
    return code,depth,spans


@pytest.mark.parametrize('count',(4,5,8,9,10,16,31,32,62,63))
def test_static_source_frame_forwards_every_allocated_outgoing_slot(count):
    depth=((32+8*max(count-4,0)+7)//16)*16+8
    code,maximum,spans=prove(f'sub rsp,{depth}; call 0x4000; add rsp,{depth}; ret')
    assert maximum==depth and len(spans)==1
    assert tuple(spans.values())==(depth-32,)
    assembly=x64_lifter.lift_function(code,native_call_targets={0x4000},native_call_stack_bytes=spans)
    assert assembly.count('n_call_frame_span')==1
    # The VM consumes three operands; no fixed-eight array and no unallocated reads.
    instruction=next(i for i in x64_lifter.Decoder(64,code,ip=0x1000) if i.mnemonic==x64_lifter.Mnemonic.CALL)
    emitter=x64_lifter._Lifter(code,0x1000,native_call_targets={0x4000},native_call_stack_bytes=spans)
    emitter._marshal_win64_argv(instruction)
    assert emitter.a.lines==['  local_addr 32','  load64',
        '  push_imm64 0x0000000000000020','  add',f'  push_imm64 0x{depth-32:016X}']


@pytest.mark.parametrize('depth',(0,8,24,32,48,64,512,520))
def test_absent_misaligned_or_oversized_native_frames_fail_closed(depth):
    source=f'sub rsp,{depth}; call 0x4000; add rsp,{depth}; ret'
    with pytest.raises(x64_lifter.LiftUnsupported,match='outgoing frame|512-byte window'):
        prove(source)


def test_ambiguous_per_call_depth_is_not_replaced_with_a_maximum_cushion():
    source=('push rbp; mov rbp,rsp; test ecx,ecx; je small; '
            'sub rsp,0x30; jmp invoke; small:sub rsp,0x20; '
            'invoke:call 0x4000; mov rsp,rbp; pop rbp; ret')
    with pytest.raises(x64_lifter.LiftUnsupported,match='ambiguous native outgoing frame'):
        prove(source)


@pytest.mark.parametrize('slot',(0x20,0x28,0x38,0x40,0x48,0x50))
def test_pointer_escapes_in_the_entire_forwarded_span_are_rejected(slot):
    with pytest.raises(x64_lifter.LiftUnsupported,match='native source stack pointer escape'):
        prove(f'sub rsp,0x58; mov r10,rsp; mov [rsp+{slot}],r10; xor r10d,r10d; '
              'call 0x4000; add rsp,0x58; ret')


@pytest.mark.parametrize('size',(0,8,32,40,96,472,480))
def test_reference_span_exact_extent_and_register_positions(size):
    stack=struct.pack('<'+'Q'*(size//8),*range(5,5+size//8))
    program=daedalus_asm.assemble(f'.code\npush_imm64 8192\npush_imm64 {size}\npush_imm64 16384\nn_call_frame_span\nhalt\n')
    calls=[]
    def hook(vm,target,count,argv):
        calls.append((target,count,argv));return sum(argv)
    vm=daedalus_ref.RefVM(program[2:],b'',mem=stack,mem_base=8192,native_frame_hook=hook)
    for offset,value in ((8,1),(16,2),(64,3),(72,4)):
        vm.locals[offset:offset+8]=struct.pack('<Q',value)
    assert vm.run()==sum(range(1,5+size//8))
    assert calls==[(16384,4+size//8,list(range(1,5+size//8)))]


@pytest.mark.parametrize('address,size,target',((8192,1,16384),(8192,488,16384),
    (8192,2**64-8,16384),(2**64-8,8,16384),(8192,8,0),(0,8,16384)))
def test_reference_rejects_invalid_contract_before_call_or_state_change(address,size,target):
    program=daedalus_asm.assemble(f'.code\npush_imm64 {address}\npush_imm64 {size}\npush_imm64 {target}\nn_call_frame_span\nhalt\n')
    calls=[]
    vm=daedalus_ref.RefVM(program[2:],b'',mem=bytes(16),mem_base=8192,
        native_frame_hook=lambda *args:calls.append(args) or 0)
    before=bytes(vm.locals)
    with pytest.raises(daedalus_ref.DaedalusError):vm.run()
    assert not calls and bytes(vm.locals)==before
    assert vm.stack==[address,size,target]


@pytest.mark.parametrize('operands',((),(8192,),(8192,8)))
def test_reference_span_underflow_does_not_invoke_native(operands):
    source='.code\n'+''.join(f'push_imm64 {n}\n' for n in operands)+'n_call_frame_span\nhalt\n'
    program=daedalus_asm.assemble(source);calls=[]
    vm=daedalus_ref.RefVM(program[2:],b'',native_frame_hook=lambda *a:calls.append(a) or 0)
    with pytest.raises(daedalus_ref.DaedalusError,match='underflow'):vm.run()
    assert not calls and vm.stack==list(operands)


def test_old_runtime_opcode_mapping_is_rejected_not_assumed_span_capable():
    legacy=dict(daedalus_asm.OPCODES);legacy.pop('n_call_frame_span')
    with pytest.raises(virtualization_plan.VirtualizationPlanError,match='missing n_call_frame_span'):
        virtualization_plan.OpcodeTable.from_mapping(legacy,identity='legacy-fixed-eight')
    assert daedalus_asm.OPCODES['n_call_frame']==(0x3B,0,'none')
    assert daedalus_asm.OPCODES['n_call_frame_span']==(0x3C,0,'none')
    assert dict(shuffle_opcodes.CANONICAL_OPCODES)==daedalus_asm.OPCODES


@pytest.mark.parametrize('seed',(b'A'*32,b'B'*32))
def test_span_opcode_is_bound_into_shuffled_mapping_identity(seed):
    generated=shuffle_opcodes.generate_shuffle(seed)
    assert not shuffle_opcodes.verify_shuffle(generated)
    assert 'n_call_frame_span' in generated['real_map']
    assert generated['unmap'][generated['real_map']['n_call_frame_span']]==0x3C
