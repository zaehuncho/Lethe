"""Exact legacy CVTSI2SD; no rounded signed64 or FP-state admission."""
from __future__ import annotations

import random
import struct

import pytest

pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("unicorn")

from iced_x86 import Decoder, Mnemonic
from keystone import KS_ARCH_X86, KS_MODE_64, Ks

from daedalus import daedalus_asm
from daedalus.daedalus_ref import DaedalusError, RefVM
from lifter import oracle
from lifter import x64_lifter as lifter

K = Ks(KS_ARCH_X86, KS_MODE_64)


def asm(text, base=oracle.BASE):
    return bytes(K.asm(text, addr=base)[0])


def regs(**values):
    state = [0] * 16
    for name, value in values.items():
        state[lifter.GPR_NAMES.index(name)] = value & ((1 << 64) - 1)
    return state


def doubles(value):
    return int.from_bytes(struct.pack("<d", float(value)), "little")


def xmms():
    return [(0xFEDCBA9876543210 + n) << 64 | (0x123456789ABCDEF0 + n)
            for n in range(16)]


@pytest.mark.parametrize("destination,source", [(0, "eax"), (15, "r11d"), (7, "edi")])
@pytest.mark.parametrize("value", [0, 1, -1, -(1 << 31), (1 << 31) - 1,
                                   -(1 << 31) + 1, 16777217, -16777217])
def test_signed32_register_exact_preserves_source_flags_and_upper_lane(destination, source, value):
    state = [(n + 1) * 0x1020304050607 for n in range(16)]
    parent = {"eax": "rax", "r11d": "r11", "edi": "rdi"}[source]
    state[lifter.GPR_NAMES.index(parent)] = (0xAABBCCDD << 32) | (value & 0xFFFFFFFF)
    initial = xmms()
    native, lifted = oracle.check_xmm(asm(f"cvtsi2sd xmm{destination},{source}"),
                                       init=state, xmm_init=initial)
    assert native[0] == lifted[0] == state
    assert lifted[2][destination] == (initial[destination] & ~((1 << 64) - 1)) | doubles(value)


@pytest.mark.parametrize("pattern", range(32))
def test_signed32_all_integer_flag_patterns_unchanged(pattern):
    names = ("CF", "PF", "ZF", "SF", "OF")
    expected = {name: (pattern >> n) & 1 for n, name in enumerate(names)}
    mask = sum(value << oracle.FLAG_BIT[name] for name, value in expected.items())
    native, lifted = oracle.check_xmm(asm("cvtsi2sd xmm15,r11d"),
                                       init=regs(r11=0x1234567880000000),
                                       xmm_init=xmms(), initial_flags=mask)
    assert native[1] == lifted[1] == expected


@pytest.mark.parametrize("value", [0, 1, -1, -(1 << 31), (1 << 31) - 1,
                                   0xFFFFFFFF, (1 << 53), -(1 << 53),
                                   (1 << 53) - 1, -(1 << 53) + 1,
                                   1 << 54, -(1 << 54), 1 << 62, -(1 << 63),
                                   (1 << 63) - 1024])
def test_proven_exact_signed64_constants_construct_binary64(value):
    text = f"mov rax,0x{value & ((1 << 64) - 1):x}; cvtsi2sd xmm15,rax"
    before = xmms()
    native, lifted = oracle.check_xmm(asm(text), xmm_init=before)
    assert native[2][15] == lifted[2][15] == (before[15] & ~((1 << 64) - 1)) | doubles(value)


@pytest.mark.parametrize("source", [
    "mov eax,ecx; cvtsi2sd xmm0,rax",
    "mov r11d,ecx; mov rax,r11; cvtsi2sd xmm0,rax",
    "movsxd rax,ecx; cvtsi2sd xmm0,rax",
    "mov eax,ecx; cdqe; cvtsi2sd xmm0,rax",
    "movsx rax,cx; cvtsi2sd xmm0,rax",
    "movzx rax,cx; cvtsi2sd xmm0,rax",
    "xor rax,rax; cvtsi2sd xmm0,rax",
    "sub rax,rax; cvtsi2sd xmm0,rax",
])
@pytest.mark.parametrize("input_value", [0, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF])
def test_full_width_producer_provenance_matches_oracle(source, input_value):
    oracle.check_xmm(asm(source), init=regs(rcx=input_value), xmm_init=xmms())


@pytest.mark.parametrize("offset", [0, 1, 3, 7])
@pytest.mark.parametrize("value", [-(1 << 31), (1 << 31) - 1, -16777217])
def test_m32_exact_read_no_alignment_or_overread(offset, value):
    memory = b"\xA5" * offset + struct.pack("<i", value)
    before = xmms()
    native, lifted = oracle.check_xmm(asm(f"cvtsi2sd xmm15,dword ptr [rax+{offset}]"),
                                       init=regs(rax=oracle.MEM_BASE), xmm_init=before, mem=memory)
    assert native[2][15] == lifted[2][15] == (before[15] & ~((1 << 64) - 1)) | doubles(value)


def test_faulting_m32_read_precedes_destination_write():
    assembly = lifter.lift_function(asm("cvtsi2sd xmm15,dword ptr [rax]"))
    assert "load32" in assembly and "load128" not in assembly
    blob = daedalus_asm.assemble(assembly)
    size = int.from_bytes(blob[:2], "little")
    vm = RefVM(blob[2 + size:], blob[2:2 + size], mem=bytes(3), mem_base=oracle.MEM_BASE)
    vm.locals[:8] = oracle.MEM_BASE.to_bytes(8, "little")
    offset = lifter.XMM_OFF[lifter.Register.XMM15]
    sentinel = bytes.fromhex("00112233445566778899aabbccddeeff")
    vm.locals[offset:offset + 16] = sentinel
    with pytest.raises(DaedalusError):
        vm.run()
    assert vm.locals[offset:offset + 16] == sentinel


@pytest.mark.parametrize("image_base", [0, 0x180000000])
def test_rip_relative_signed32_rebases_and_reads_exact_width(image_base):
    code_rva, data_rva = 0x1000, 0x3000
    probe = asm("cvtsi2sd xmm15,dword ptr [rip]", code_rva)
    displacement = data_rva - code_rva - len(probe)
    code = asm(f"cvtsi2sd xmm15,dword ptr [rip+{displacement}]", code_rva)
    data = struct.pack("<i", -(1 << 31))
    sections = (
        oracle._OracleSection(".text", code_rva, len(code), code, 0x60000020),
        oracle._OracleSection(".data", data_rva, len(data), data, 0xC0000040),
    )
    before = xmms()
    native, lifted = oracle.check_xmm(
        code, mem=data, mem_base=image_base + data_rva, lift_base=code_rva,
        image_base=image_base, code_base=image_base + code_rva, xmm_init=before,
        image_sections=sections, selected_extents=((code_rva, len(code)),))
    assert lifted[2][15] == native[2][15] == (before[15] & ~((1 << 64) - 1)) | doubles(-(1 << 31))


@pytest.mark.parametrize("source", [
    "test ecx,ecx; jz other; mov eax,edx; jmp cvt; other: movsxd rax,r8d; cvt: cvtsi2sd xmm0,rax",
    "mov eax,ecx; again: cvtsi2sd xmm0,rax; inc eax; cmp eax,4; jb again",
    "mov eax,ecx; cmovne rax,rdx; cvtsi2sd xmm0,eax",
    "mov eax,ecx; mov rdx,rax; mov rax,r8; cvtsi2sd xmm0,rdx",
    "mov eax,ecx; cmovne eax,edx; cvtsi2sd xmm0,rax",
    "test ecx,ecx; jz other; mov rax,0x20000000000000; jmp cvt; other: mov rax,-0x20000000000000; cvt: cvtsi2sd xmm0,rax",
])
def test_cfg_exact_joins_copies_and_loops_admit(source):
    assert daedalus_asm.assemble(lifter.lift_function(asm(source)))


@pytest.mark.parametrize("value", [0, 1])
def test_taken_and_untaken_exact_branch_matches_oracle(value):
    source = "test ecx,ecx; jz other; mov eax,edx; jmp cvt; other: movsxd rax,r8d; cvt: cvtsi2sd xmm0,rax"
    oracle.check_xmm(asm(source), init=regs(rcx=value, rdx=0xFFFFFFFF, r8=0x80000000), xmm_init=xmms())


def test_loop_fixpoint_matches_oracle():
    source = "mov eax,1; again: cvtsi2sd xmm0,rax; inc eax; cmp eax,4; jb again"
    oracle.check_xmm(asm(source), xmm_init=xmms())


@pytest.mark.parametrize("source", [
    "cvtsi2sd xmm0,rax",
    "mov rax,0x20000000000001; cvtsi2sd xmm0,rax",
    "mov rax,-0x20000000000001; cvtsi2sd xmm0,rax",
    "mov rax,0x7FFFFFFFFFFFFFFF; cvtsi2sd xmm0,rax",
    "mov eax,1; mov ax,cx; cvtsi2sd xmm0,rax",
    "mov eax,1; mov al,cl; cvtsi2sd xmm0,rax",
    "mov eax,1; mov ah,cl; cvtsi2sd xmm0,rax",
    "mov eax,1; mov rax,r8; cvtsi2sd xmm0,rax",
    "mov eax,1; add rax,1; cvtsi2sd xmm0,rax",
    "mov eax,1; cmovne rax,r8; cvtsi2sd xmm0,rax",
    "mov edx,1; cmovne rax,rdx; cvtsi2sd xmm0,rax",
    "mov rax,0x40000000000000; cmovne eax,ecx; cvtsi2sd xmm0,rax",
    "test ecx,ecx; jz other; mov eax,edx; jmp cvt; other: mov rax,r8; cvt: cvtsi2sd xmm0,rax",
    "mov eax,1; test ecx,ecx; jz cvt; mov rax,0x20000000000001; cvt: cvtsi2sd xmm0,rax",
    "mov eax,1; again: cvtsi2sd xmm0,rax; inc rax; cmp rax,4; jb again",
    "jmp end; mov eax,1; cvtsi2sd xmm0,rax; end: nop",
    "mov eax,1; call qword ptr [rip+0x2ff5]; cvtsi2sd xmm0,rax",
    "jmp entry; inner: mov rax,r8; ret; entry: mov eax,1; call inner; cvtsi2sd xmm0,rax",
    "jmp entry; inner: cvtsi2sd xmm0,rax; ret; entry: mov eax,1; call inner",
])
def test_unsound_reaching_values_reject_before_emission(source):
    code = asm(source)
    sections = (
        oracle._OracleSection(".text", oracle.BASE, len(code), code, 0x60000020),
        oracle._OracleSection(".rdata", 0x4000, 8, bytes(8), 0x40000040),
    )
    with pytest.raises(lifter.LiftUnsupported, match="cvtsi2sd signed64 input is not proven exact"):
        lifter.lift_function(code, image_sections=sections,
                             selected_extents=((oracle.BASE, len(code)),))


def test_internal_callee_can_prove_own_local_input_but_return_summary_is_not_assumed():
    text = "jmp entry; inner: mov eax,ecx; cvtsi2sd xmm0,rax; ret; entry: call inner"
    assert daedalus_asm.assemble(lifter.lift_function(asm(text)))


@pytest.mark.parametrize("source", [
    "cvtsi2sd xmm0,qword ptr [rax]", "cvtsi2sd xmm0,dword ptr gs:[rax]",
    "cvtsi2sd xmm0,dword ptr [eax]", "vcvtsi2sd xmm0,xmm1,eax",
    "vcvtsi2sd xmm0,xmm1,rax",
])
def test_unmodeled_width_address_or_encoding_rejects(source):
    with pytest.raises(lifter.LiftUnsupported):
        lifter.lift_function(asm(source))


def test_seeded_random_signed32_register_and_memory_oracle():
    rng = random.Random(0xC7512D)
    for n in range(48):
        value = rng.randrange(-(1 << 31), 1 << 31)
        destination = rng.randrange(16)
        if n % 2:
            code = asm(f"mov eax,ecx; cvtsi2sd xmm{destination},rax")
            state, memory = regs(rcx=value & 0xFFFFFFFF), None
            expected = value & 0xFFFFFFFF
        else:
            code = asm(f"cvtsi2sd xmm{destination},dword ptr [rax]")
            state, memory = regs(rax=oracle.MEM_BASE), struct.pack("<i", value)
            expected = value
        before = xmms()
        native, lifted = oracle.check_xmm(code, init=state, xmm_init=before, mem=memory)
        assert native[2][destination] == lifted[2][destination] == (before[destination] & ~((1 << 64) - 1)) | doubles(expected)


def test_proof_does_not_admit_full_product_fp_sequence():
    # Actual OrionNative producer/conversion shape is exact, not its subsequent
    # rounded FP arithmetic or opaque import; nowMs arbitrary signed64 stays shut.
    prefix = asm("mov eax,ecx; cvtsi2sd xmm2,rax; mov eax,edx; cvtsi2sd xmm0,rax")
    conversions = [i.ip for i in Decoder(64, prefix, ip=oracle.BASE) if i.mnemonic == Mnemonic.CVTSI2SD]
    assert lifter._cvtsi2sd_exact_inputs(tuple(Decoder(64, prefix, ip=oracle.BASE)), oracle.BASE) == frozenset(conversions)
    with pytest.raises(lifter.LiftUnsupported):
        lifter.lift_function(prefix + asm("subsd xmm0,xmm2"))
