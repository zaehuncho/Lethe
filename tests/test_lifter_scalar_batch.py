"""Differential coverage for the common scalar x64 lifter batch."""
from __future__ import annotations

import random
import struct

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("unicorn")

from keystone import KS_ARCH_X86, KS_MODE_64, Ks  # noqa: E402
from lifter import oracle  # noqa: E402
from lifter import x64_lifter as L  # noqa: E402
from daedalus_ref import DaedalusError  # noqa: E402


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_FLAGS = ("CF", "PF", "ZF", "SF", "OF")
_MEM = bytes((index * 29 + 0x80) & 0xFF for index in range(256))
_STACK_BASE = oracle.STACK - 0x1000


def _asm(source: str) -> bytes:
    encoded, _ = _KS.asm(source, addr=oracle.BASE)
    return bytes(encoded)


def _init(**registers: int) -> list[int]:
    values = [0] * 16
    for name, value in registers.items():
        values[L.GPR_NAMES.index(name)] = value
    return values


def _incoming_flags(pattern: int) -> tuple[int, dict[str, int]]:
    values = {name: (pattern >> index) & 1 for index, name in enumerate(_FLAGS)}
    mask = sum(values[name] << oracle.FLAG_BIT[name] for name in _FLAGS)
    return mask, values


@pytest.mark.parametrize("pattern", range(32))
def test_all_incoming_flag_combinations_across_oracle_boundaries(pattern):
    mask, seeded = _incoming_flags(pattern)
    initial = _init(rax=0x1122334455667788, rbx=0x7FFFFFFFFFFFFFFF,
                    rcx=0, rdx=0x8877665544332211,
                    r8=0x8000000000000080, r9=0xFFFFFFFFFFFFFFFF,
                    r10=17, r11=19, r12=23, r13=29, r14=31)
    passive, _ = oracle.check(
        _asm("mov rax, rbx; not r8; lea r9, [r10+r11*2]"),
        init=initial, initial_flags=mask)
    # Independently assert the seed, so a shared all-zero initialization bug
    # cannot pass merely because the two engines agree with each other.
    assert passive[1] == seeded
    for width_regs in (("al", "bl", "r8b", "r9b"),
                       ("ax", "bx", "r8w", "r9w"),
                       ("eax", "ebx", "r8d", "r9d"),
                       ("rax", "rbx", "r8", "r9")):
        a, b, c, d = width_regs
        oracle.check(_asm(f"adc {a}, {b}; sbb {c}, {d}"),
                     init=initial, initial_flags=mask)
    oracle.check(_asm("inc rax; dec rbx"), init=initial, initial_flags=mask)
    zero, _ = oracle.check(
        _asm("shl eax, 0; sar r8b, cl; ror r9w, cl; shld r10d, r11d, 0"),
        init=initial, initial_flags=mask)
    assert zero[1] == seeded
    oracle.check(_asm("rol rax, 1; ror r8b, 1"),
                 init=initial, initial_flags=mask)
    selection, _ = oracle.check(
        _asm("setc al; setp dl; sets r9b; seto r10b; "
             "cmovl r11, r12; cmovg r13, r14"),
        init=initial, initial_flags=mask)
    assert selection[1] == seeded
    assert selection[0][L.GPR_NAMES.index("rax")] & 0xFF == seeded["CF"]
    assert selection[0][L.GPR_NAMES.index("rdx")] & 0xFF == seeded["PF"]
    assert selection[0][L.GPR_NAMES.index("r11")] == (23 if seeded["SF"] != seeded["OF"] else 19)
    assert selection[0][L.GPR_NAMES.index("r13")] == (31 if not seeded["ZF"] and seeded["SF"] == seeded["OF"] else 29)
    oracle.check(_asm("adc word ptr [rbx], ax; sbb dword ptr [rbx+4], r8d"),
                 init=_init(rbx=oracle.MEM_BASE, rax=0xFFFF, r8=0x80000000),
                 initial_flags=mask, mem=_MEM)
    function, _ = oracle.check_function(
        _asm("setc al; ret"), init=_init(rsp=oracle.STACK, rax=0x123400),
        initial_flags=mask)
    assert function[1] == seeded and function[0][0] == 0x123400 | seeded["CF"]
    xmm, _ = oracle.check_xmm(
        _asm("movdqa xmm0, xmm15; pxor xmm1, xmm1"), init=initial,
        xmm_init=[(index + 1) << 80 for index in range(16)], initial_flags=mask)
    assert xmm[1] == seeded and xmm[2][0] == 16 << 80 and xmm[2][1] == 0
    code_rva, data_rva = 0x1000, 0x3000
    encoded, _ = _KS.asm(
        f"mov rax, qword ptr [rip+{data_rva-code_rva-7}]; adc rax, rbx",
        addr=code_rva)
    relocated, _ = oracle.check_rip_data(
        bytes(encoded), struct.pack("<Q", 0xFFFFFFFFFFFFFFFD),
        code_rva=code_rva, data_rva=data_rva, runtime_image_base=0x180000000,
        init=_init(rbx=2), initial_flags=mask)
    assert relocated[0][0] == 0xFFFFFFFFFFFFFFFF + seeded["CF"] & ((1 << 64) - 1)


@pytest.mark.parametrize("value", [-1, 2, 0x200, 1 << 64, True, None, "1", 1.0])
def test_initial_flags_reject_unmodeled_bits_and_non_integer_values(value):
    code = _asm("nop")
    initial = _init(rsp=oracle.STACK)
    calls = (
        lambda: oracle.run_unicorn(code, initial, initial_flags=value),
        lambda: oracle.run_daedalus(code, initial, initial_flags=value),
        lambda: oracle.run_unicorn_xmm(code, initial, initial_flags=value),
        lambda: oracle.run_daedalus_xmm(code, initial, initial_flags=value),
        lambda: oracle.check(code, initial, initial_flags=value),
        lambda: oracle.check_xmm(code, initial, initial_flags=value),
        lambda: oracle.check_function(_asm("ret"), initial, initial_flags=value),
        lambda: oracle.check_rip_data(code, b"data", code_rva=0x1000,
            data_rva=0x3000, runtime_image_base=0x180000000,
            init=initial, initial_flags=value),
    )
    for call in calls:
        with pytest.raises(ValueError, match="initial_flags must contain only modeled"):
            call()


def test_default_incoming_flags_remain_explicit_zero():
    code = _asm("setc al; setp dl")
    initial = _init(rax=0xFF, rdx=0xFF)
    assert oracle.check(code, initial) == oracle.check(code, initial, initial_flags=0)
    assert oracle.check_xmm(code, initial) == oracle.check_xmm(code, initial, initial_flags=0)


_LOW8 = (
    ("al", "rax"), ("cl", "rcx"), ("dl", "rdx"), ("bl", "rbx"),
    ("spl", "rsp"), ("bpl", "rbp"), ("sil", "rsi"), ("dil", "rdi"),
    ("r8b", "r8"), ("r9b", "r9"), ("r10b", "r10"), ("r11b", "r11"),
    ("r12b", "r12"), ("r13b", "r13"), ("r14b", "r14"), ("r15b", "r15"),
)
_LOW16 = (
    ("ax", "rax"), ("cx", "rcx"), ("dx", "rdx"), ("bx", "rbx"),
    ("sp", "rsp"), ("bp", "rbp"), ("si", "rsi"), ("di", "rdi"),
    ("r8w", "r8"), ("r9w", "r9"), ("r10w", "r10"), ("r11w", "r11"),
    ("r12w", "r12"), ("r13w", "r13"), ("r14w", "r14"), ("r15w", "r15"),
)


@pytest.mark.parametrize("register,parent", _LOW8)
def test_low8_writes_preserve_parent_bits(register: str, parent: str) -> None:
    oracle.check(
        _asm(f"cmp rax, rax; mov {register}, 0xA5"),
        init=_init(**{parent: 0x1122334455667788}),
        flags=_FLAGS,
    )


@pytest.mark.parametrize("register,parent", _LOW16)
def test_low16_writes_preserve_parent_bits(register: str, parent: str) -> None:
    oracle.check(
        _asm(f"cmp rax, rax; mov {register}, 0xA5C3"),
        init=_init(**{parent: 0x1122334455667788}),
        flags=_FLAGS,
    )


@pytest.mark.parametrize(
    "source",
    (
        "mov al, 0x80; movzx ecx, al",
        "mov ax, 0xFEDC; movzx r8, ax",
        "mov al, 0x80; movsx ecx, al",
        "mov ax, 0x8001; movsx r8, ax",
        "movsxd r9, eax",
        "movzx ax, bl",
        "movsx cx, bl",
    ),
)
def test_extension_register_forms_and_aliases(source: str) -> None:
    oracle.check(
        _asm("cmp r14, r15; " + source),
        init=_init(
            rax=0xAABBCCDD80000001,
            rbx=0x11223344556677F1,
            rcx=0xFFEEDDCCBBAA9988,
            r8=0xDEADBEEFDEADBEEF,
            r9=0xFFFFFFFFFFFFFFFF,
            r14=0,
            r15=1,
        ),
        flags=_FLAGS,
    )


def test_extension_memory_forms_use_exact_widths() -> None:
    for instruction in (
        "movzx eax, byte ptr [rbx]",
        "movzx r8, word ptr [rbx+3]",
        "movsx ecx, byte ptr [rbx+7]",
        "movsx r9, word ptr [rbx+11]",
        "movsxd r10, dword ptr [rbx+17]",
    ):
        oracle.check(
            _asm(instruction),
            init=_init(rbx=oracle.MEM_BASE),
            flags=(),
            mem=_MEM,
        )


def test_narrow_mov_and_alu_forms_preserve_or_replace_exact_bits() -> None:
    cases = (
        ("add al, bl", _init(rax=0x11223344556677FF, rbx=1), _FLAGS),
        ("sub ax, bx", _init(rax=0x1122334455660000, rbx=1), _FLAGS),
        ("xor r8b, r9b", _init(r8=0xAA55AA55AA55AA55, r9=0xF0), _FLAGS),
        ("and r10w, 0x8001", _init(r10=0x123456789ABCFFFF), _FLAGS),
        ("or cx, -1", _init(rcx=0x8877665544332211), _FLAGS),
        ("cmp dl, bl", _init(rdx=0x80, rbx=0x7F), _FLAGS),
        ("test si, di", _init(rsi=0x8000, rdi=0xFFFF), _FLAGS),
        ("inc al", _init(rax=0x11223344556677FF), ("ZF", "SF", "OF")),
        ("dec ax", _init(rax=0x1122334455668000), ("ZF", "SF", "OF")),
        ("neg r11b", _init(r11=0xAABBCCDDEEFF0080), _FLAGS),
        ("not r12w", _init(r12=0x1122334455667788), ()),
    )
    for instruction, initial, flags in cases:
        oracle.check(_asm(instruction), init=initial, flags=flags)


def test_narrow_mov_memory_roundtrip() -> None:
    oracle.check(
        _asm("mov al, byte ptr [rbx+3]; mov word ptr [rbx+9], ax"),
        init=_init(rax=0x1122334455667788, rbx=oracle.MEM_BASE),
        flags=(),
        mem=_MEM,
    )


@pytest.mark.parametrize(
    "instruction",
    (
        "mov byte ptr [rbx+3], 0xA5",
        "mov word ptr [rbx+7], 0xBEEF",
        "mov dword ptr [rbx+11], 0x89ABCDEF",
        "mov qword ptr [rbx+24], 0x12345678",
    ),
)
def test_mov_immediate_to_memory_uses_decoded_destination_width(
    instruction: str,
) -> None:
    oracle.check(
        _asm("cmp r14, r15; " + instruction),
        init=_init(rbx=oracle.MEM_BASE, r14=0, r15=1),
        flags=_FLAGS,
        mem=_MEM,
    )


@pytest.mark.parametrize(
    "instruction,flags",
    (
        ("add byte ptr [rbx+1], al", _FLAGS),
        ("sub word ptr [rbx+5], 0x1234", _FLAGS),
        ("xor dword ptr [rbx+12], eax", _FLAGS),
        ("and qword ptr [rbx+24], rax", _FLAGS),
        ("or dword ptr [rbx+40], 0x10203040", _FLAGS),
        ("cmp qword ptr [rbx+48], rax", _FLAGS),
        ("test word ptr [rbx+60], ax", _FLAGS),
        ("inc byte ptr [rbx+72]", ("ZF", "SF", "OF")),
        ("dec word ptr [rbx+80]", ("ZF", "SF", "OF")),
        ("neg dword ptr [rbx+88]", _FLAGS),
        ("not qword ptr [rbx+96]", _FLAGS),
    ),
)
def test_scalar_memory_destination_rmw_forms(
    instruction: str, flags: tuple[str, ...]
) -> None:
    oracle.check(
        _asm("cmp r14, r15; " + instruction),
        init=_init(
            rax=0x8877665544332211,
            rbx=oracle.MEM_BASE,
            r14=0,
            r15=1,
        ),
        flags=flags,
        mem=_MEM,
    )


@pytest.mark.parametrize("instruction", ("adc dword ptr [rbx+112], eax", "sbb qword ptr [rbx+120], rax"))
@pytest.mark.parametrize("carry", (0, 1))
def test_adc_sbb_memory_destinations(instruction: str, carry: int) -> None:
    oracle.check(
        _asm("cmp r14, r15; " + instruction),
        init=_init(
            rax=0x80000000FFFFFFFF,
            rbx=oracle.MEM_BASE,
            r14=0 if carry else 1,
            r15=1 if carry else 0,
        ),
        flags=_FLAGS,
        mem=_MEM,
    )


def test_fuzz_scalar_memory_destinations_and_flags() -> None:
    rng = random.Random(0x5CA1A2)
    widths = (
        ("byte", "al"),
        ("word", "ax"),
        ("dword", "eax"),
        ("qword", "rax"),
    )
    binary = ("add", "sub", "xor", "and", "or", "adc", "sbb", "cmp", "test")
    unary = ("inc", "dec", "neg", "not")
    for _ in range(240):
        size, source = rng.choice(widths)
        offset = rng.randrange(0, len(_MEM) - 8)
        operation = rng.choice(binary + unary)
        if operation in unary:
            instruction = f"{operation} {size} ptr [rbx+{offset}]"
        else:
            instruction = f"{operation} {size} ptr [rbx+{offset}], {source}"
        carry = rng.randrange(2)
        initial = [rng.getrandbits(64) for _ in range(16)]
        initial[L.GPR_NAMES.index("rbx")] = oracle.MEM_BASE
        initial[L.GPR_NAMES.index("r14")] = 0 if carry else 1
        initial[L.GPR_NAMES.index("r15")] = 1 if carry else 0
        oracle.check(
            _asm("cmp r14, r15; " + instruction),
            init=initial,
            flags=_FLAGS,
            mem=_MEM,
        )


@pytest.mark.parametrize(
    "source",
    (
        "push rax; xor rax, rax; pop rcx",
        "push -1; pop r8",
        "push rsp; pop r9",
        "push qword ptr [rsp+16]; pop qword ptr [rsp+24]",
    ),
)
def test_push_pop_stack_semantics(source: str) -> None:
    stack = bytearray(0x2000)
    struct.pack_into("<Q", stack, 0x1010, 0xCAFEBABE11223344)
    oracle.check(
        _asm("cmp r14, r15; " + source),
        init=_init(
            rax=0x8877665544332211,
            rsp=oracle.STACK,
            r14=0,
            r15=1,
        ),
        flags=_FLAGS,
        mem=stack,
        mem_base=_STACK_BASE,
    )


def test_pop_rsp_uses_popped_value_after_increment() -> None:
    stack = bytearray(0x2000)
    struct.pack_into("<Q", stack, 0x1000, oracle.STACK + 0x80)
    oracle.check(
        _asm("pop rsp"),
        init=_init(rsp=oracle.STACK),
        flags=_FLAGS,
        mem=stack,
        mem_base=_STACK_BASE,
    )


def test_leave_restores_frame_pointer_and_stack_pointer() -> None:
    stack = bytearray(0x2000)
    frame = oracle.STACK + 0x100
    struct.pack_into("<Q", stack, frame - _STACK_BASE, 0x1122334455667788)
    oracle.check(
        _asm("cmp r14, r15; leave"),
        init=_init(rsp=oracle.STACK, rbp=frame, r14=0, r15=1),
        flags=_FLAGS,
        mem=stack,
        mem_base=_STACK_BASE,
    )


@pytest.mark.parametrize(
    "suffix",
    ("e", "ne", "b", "ae", "s", "ns", "o", "no", "p", "np", "be", "a", "l", "ge", "le", "g"),
)
def test_setcc_and_cmovcc_share_exact_condition_model(suffix: str) -> None:
    comparisons = (
        (0, 0),
        (0, 1),
        (1, 0),
        (0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
        (0x8000000000000000, 1),
    )
    for left, right in comparisons:
        oracle.check(
            _asm(f"cmp r14, r15; set{suffix} al; cmov{suffix} ecx, edx"),
            init=_init(
                rax=0x1122334455667788,
                rcx=0xAABBCCDD12345678,
                rdx=0x87654321,
                r14=left,
                r15=right,
            ),
            flags=_FLAGS,
        )


def test_setcc_memory_and_cmovcc_memory_sources() -> None:
    oracle.check(
        _asm("cmp r14, r15; setb byte ptr [rbx+5]; cmovb rax, qword ptr [rbx+16]"),
        init=_init(rbx=oracle.MEM_BASE, r14=0, r15=1),
        flags=_FLAGS,
        mem=_MEM,
    )
    oracle.check(
        _asm("cmp r14, r15; setb byte ptr [rbx+5]; cmovb rax, qword ptr [rbx+16]"),
        init=_init(
            rax=0x8877665544332211,
            rbx=oracle.MEM_BASE,
            r14=2,
            r15=1,
        ),
        flags=_FLAGS,
        mem=_MEM,
    )


@pytest.mark.parametrize(
    "instruction,initial",
    (
        ("xchg al, cl", _init(rax=0x1122334455667788, rcx=0x8877665544332211)),
        ("xchg ax, r8w", _init(rax=0x1122334455667788, r8=0x8877665544332211)),
        ("xchg eax, r9d", _init(rax=0xFFFFFFFF11223344, r9=0xAAAAAAAA55667788)),
        ("xchg rax, r10", _init(rax=0x1122334455667788, r10=0x8877665544332211)),
        ("xchg eax, eax", _init(rax=0xFFFFFFFF11223344)),
    ),
)
def test_xchg_register_forms_preserve_flags(instruction: str, initial: list[int]) -> None:
    oracle.check(_asm("cmp r14, r15; " + instruction), init=initial, flags=_FLAGS)


@pytest.mark.parametrize(
    "instruction,initial",
    (
        ("bswap eax", _init(rax=0xFFFFFFFF01020304)),
        ("bswap rax", _init(rax=0x0102030405060708)),
        ("bswap r8d", _init(r8=0xAABBCCDD80000001)),
        ("bswap r15", _init(r15=0xFF00AA5512345678)),
    ),
)
def test_bswap_32_and_64_preserve_flags(instruction: str, initial: list[int]) -> None:
    oracle.check(_asm("cmp r14, r15; " + instruction), init=initial, flags=_FLAGS)


@pytest.mark.parametrize(
    "width,dst,src,maximum,signbit",
    (
        (8, "al", "bl", 0xFF, 0x80),
        (16, "ax", "bx", 0xFFFF, 0x8000),
        (32, "eax", "ebx", 0xFFFFFFFF, 0x80000000),
        (64, "rax", "rbx", 0xFFFFFFFFFFFFFFFF, 0x8000000000000000),
    ),
)
def test_adc_sbb_boundaries(
    width: int, dst: str, src: str, maximum: int, signbit: int
) -> None:
    del width
    cases = (
        ("adc", maximum, 0, 1),
        ("adc", signbit - 1, 0, 1),
        ("adc", signbit, maximum, 1),
        ("sbb", 0, 0, 1),
        ("sbb", signbit, signbit - 1, 1),
        ("sbb", maximum, maximum, 0),
    )
    for mnemonic, left, right, carry in cases:
        initial = _init(
            rax=left,
            rbx=right,
            r14=0 if carry else 1,
            r15=1 if carry else 0,
        )
        oracle.check(
            _asm(f"cmp r14, r15; {mnemonic} {dst}, {src}"),
            init=initial,
            flags=_FLAGS,
        )


def test_adc_sbb_immediate_memory_and_flag_consumers() -> None:
    oracle.check(
        _asm("cmp r14, r15; adc eax, -1"),
        init=_init(rax=0, r14=0, r15=1),
        flags=_FLAGS,
    )
    oracle.check(
        _asm("cmp r14, r15; sbb rax, qword ptr [rbx+8]"),
        init=_init(rax=0x8000000000000000, rbx=oracle.MEM_BASE, r14=0, r15=1),
        flags=_FLAGS,
        mem=_MEM,
    )
    for mnemonic, left, right, carry in (
        ("adc", 0xFF, 0, 1),
        ("adc", 0x7F, 0, 1),
        ("sbb", 0, 0, 1),
        ("sbb", 0x80, 0x7F, 1),
    ):
        oracle.check(
            _asm(
                f"cmp r14, r15; {mnemonic} al, bl; "
                "setb cl; seto dl; jb carry; mov r12d, 1; jmp done; "
                "carry: mov r12d, 2; done: nop"
            ),
            init=_init(
                rax=left,
                rbx=right,
                r14=0 if carry else 1,
                r15=1 if carry else 0,
            ),
            flags=_FLAGS,
        )


def test_fuzz_adc_sbb_all_widths_aliases_and_flags() -> None:
    rng = random.Random(0xADC5BB)
    pools = (
        ("al", "cl", "dl", "bl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b"),
        ("ax", "cx", "dx", "bx", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w"),
        ("eax", "ecx", "edx", "ebx", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d"),
        ("rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13"),
    )
    for _ in range(300):
        pool = rng.choice(pools)
        destination = rng.choice(pool)
        source = destination if rng.random() < 0.2 else rng.choice(pool)
        carry = rng.randrange(2)
        initial = [rng.getrandbits(64) for _ in range(16)]
        initial[L.GPR_NAMES.index("r14")] = 0 if carry else 1
        initial[L.GPR_NAMES.index("r15")] = 1 if carry else 0
        mnemonic = rng.choice(("adc", "sbb"))
        oracle.check(
            _asm(f"cmp r14, r15; {mnemonic} {destination}, {source}"),
            init=initial,
            flags=_FLAGS,
        )


def test_fuzz_setcc_cmovcc_and_dirty_parent_aliases() -> None:
    rng = random.Random(0x5E7CC)
    suffixes = ("e", "ne", "b", "ae", "s", "ns", "o", "no", "p", "np", "be", "a", "l", "ge", "le", "g")
    for _ in range(180):
        suffix = rng.choice(suffixes)
        initial = [rng.getrandbits(64) for _ in range(16)]
        oracle.check(
            _asm(f"cmp r12, r13; set{suffix} r8b; cmov{suffix} r9d, r10d"),
            init=initial,
            flags=_FLAGS,
        )


@pytest.mark.parametrize(
    "source,reason",
    (
        ("xchg qword ptr [rbx], rax", "atomic"),
        ("lock add dword ptr [rbx], 1", "LOCK-prefixed"),
        ("movzx eax, byte ptr fs:[rbx]", "segment-overridden"),
    ),
)
def test_unsupported_scalar_forms_fail_closed(source: str, reason: str) -> None:
    with pytest.raises(L.LiftUnsupported, match=reason):
        L.lift_function(_asm(source), base=oracle.BASE)


def test_noncanonical_narrow_movsxd_encoding_fails_closed() -> None:
    # 63 /r without REX.W decodes as MOVSXD r32,r/m32 in iced-x86 even though
    # mainstream assemblers decline to emit the discouraged form.
    with pytest.raises(L.LiftUnsupported, match="64-bit destination"):
        L.lift_function(bytes.fromhex("63c3"), base=oracle.BASE)


_PACKED_COMPARE = (("pcmpeqb", 8, False), ("pcmpeqw", 16, False),
                   ("pcmpeqd", 32, False), ("pcmpgtb", 8, True),
                   ("pcmpgtw", 16, True), ("pcmpgtd", 32, True))


def _packed_compare_expected(left, right, width, greater):
    result, mask = 0, (1 << width) - 1
    for shift in range(0, 128, width):
        a, b = (left >> shift) & mask, (right >> shift) & mask
        if greater:
            # Independent signed conversion, rather than the lifter's bias.
            a = a - (1 << width) if a >> (width - 1) else a
            b = b - (1 << width) if b >> (width - 1) else b
        if a > b if greater else a == b:
            result |= mask << shift
    return result


@pytest.mark.parametrize("mnemonic,width,greater", _PACKED_COMPARE)
@pytest.mark.parametrize("destination,source", [(0, 15), (15, 0), (8, 9), (15, 15)])
def test_packed_integer_comparisons_register_edges_aliases_and_flags(
        mnemonic, width, greater, destination, source):
    rng = random.Random(0xC0A0 + width + destination)
    mask = (1 << width) - 1
    edge = (0, 1, mask, 1 << (width - 1), (1 << (width - 1)) - 1)
    repeat = lambda value: sum(value << shift for shift in range(0, 128, width))
    cases = [(repeat(a), repeat(b)) for a in edge for b in edge]
    cases += [(rng.getrandbits(128), rng.getrandbits(128)) for _ in range(32)]
    code = _asm(f"{mnemonic} xmm{destination}, xmm{source}")
    for index, (left, right) in enumerate(cases):
        xmms = [rng.getrandbits(128) for _ in range(16)]
        xmms[destination] = left
        if source != destination:
            xmms[source] = right
        bits, flags = _incoming_flags(index % 32)
        expected = _packed_compare_expected(xmms[destination], xmms[source], width, greater)
        native, _ = oracle.check_xmm(code, xmm_init=xmms, initial_flags=bits)
        assert native[2][destination] == expected and native[1] == flags
        assert all(native[2][reg] == xmms[reg] for reg in range(16) if reg != destination)


@pytest.mark.parametrize("mnemonic,width,greater", _PACKED_COMPARE)
def test_packed_integer_comparisons_aligned_memory_and_fault_guard(mnemonic, width, greater):
    rng = random.Random(0xA11C + width)
    code = _asm(f"{mnemonic} xmm15, xmmword ptr [rbx+16]")
    for index in range(32):
        left, right = rng.getrandbits(128), rng.getrandbits(128)
        xmms = [0] * 16; xmms[15] = left
        memory = bytes(16) + right.to_bytes(16, "little") + bytes(16)
        bits, flags = _incoming_flags(index)
        native, _ = oracle.check_xmm(code, init=_init(rbx=oracle.MEM_BASE),
            xmm_init=xmms, mem=memory, initial_flags=bits)
        assert native[2][15] == _packed_compare_expected(left, right, width, greater)
        assert native[1] == flags
    assert "load128a" in L.lift_function(code, base=oracle.BASE)
    # Unicorn does not reliably enforce legacy alignment exceptions. Assert
    # the VM's existing checked-load contract instead of inventing oracle parity.
    with pytest.raises(DaedalusError, match="align"):
        oracle.run_daedalus_xmm(code, init=_init(rbx=oracle.MEM_BASE+1),
                               mem=bytes(64), initial_flags=bits)


@pytest.mark.parametrize("source", [
    "pcmpeqb mm0, mm1", "pcmpgtw mm2, mm3",
    "vpcmpeqb xmm0, xmm1, xmm2", "vpcmpgtd ymm0, ymm1, ymm2",
    "pcmpeqq xmm0, xmm1", "pcmpgtq xmm0, xmm1",
])
def test_packed_comparison_non_sse2_surfaces_stay_closed(source):
    with pytest.raises(L.LiftUnsupported):
        L.lift_function(_asm(source), base=oracle.BASE)


@pytest.mark.parametrize("mnemonic,width,greater", _PACKED_COMPARE)
def test_packed_integer_compare_rip_data_relocates_and_bounds_full_operand(mnemonic, width, greater):
    code_rva, data_rva, image_base = 0x1000, 0x3000, 0x180000000
    placeholder = _asm(f"{mnemonic} xmm15, xmmword ptr [rip]")
    raw, _ = _KS.asm(f"{mnemonic} xmm15, xmmword ptr [rip+{data_rva-code_rva-len(placeholder)}]",
                     addr=code_rva)
    code = bytes(raw)
    left = int.from_bytes(bytes.fromhex("80ff7f000180ff7f10203040a0b0c0d0"), "little")
    right_bytes = bytes.fromhex("7fff8000017fff80102031409fb0c1d0")
    right = int.from_bytes(right_bytes, "little")
    text = oracle._OracleSection(".text", code_rva, len(code), code, 0x60000020)
    data = oracle._OracleSection(".rdata", data_rva, 16, right_bytes, 0x40000040)
    xmms = [0]*16; xmms[15] = left
    bits, flags = _incoming_flags(31)
    native, _ = oracle.check_xmm(code, xmm_init=xmms, mem=right_bytes,
        mem_base=image_base+data_rva, code_base=image_base+code_rva,
        lift_base=code_rva, image_base=image_base, image_sections=(text, data),
        selected_extents=((code_rva, len(code)),), initial_flags=bits)
    assert native[1] == flags
    assert native[2][15] == _packed_compare_expected(left, right, width, greater)
    for size, characteristics in ((15, 0x40000040), (16, 0x60000020), (16, 0x42000040)):
        bad = oracle._OracleSection(".bad", data_rva, size, right_bytes[:size], characteristics)
        with pytest.raises(L.LiftUnsupported):
            L.lift_function(code, base=code_rva, image_sections=(text, bad),
                            selected_extents=((code_rva, len(code)),))
