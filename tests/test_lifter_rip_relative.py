"""Bounded RIP-relative image-data lifting and fail-closed gates."""
from __future__ import annotations

from dataclasses import dataclass

import pytest


pytest.importorskip("iced_x86")
pytest.importorskip("keystone")
pytest.importorskip("unicorn")

from iced_x86 import Decoder, Register
from keystone import KS_ARCH_X86, KS_MODE_64, Ks
from lifter import oracle
from lifter import x64_lifter as lifter


_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_EXEC = 0x60000020
_READ = 0x40000040
_WRITE = 0x80000040
_READ_WRITE = 0xC0000040


@dataclass(frozen=True)
class _Section:
    name: str
    rva: int
    virtual_size: int
    raw: bytes
    characteristics: int


def _rip_instruction(source: str, *, instruction_rva: int, target_rva: int) -> bytes:
    probe, _ = _KS.asm(source.format(mem="[rip]"), addr=instruction_rva)
    displacement = target_rva - (instruction_rva + len(probe))
    sign = "+" if displacement >= 0 else "-"
    memory = f"[rip {sign} 0x{abs(displacement):X}]"
    encoded, _ = _KS.asm(source.format(mem=memory), addr=instruction_rva)
    result = bytes(encoded)
    decoded = next(iter(Decoder(64, result, ip=instruction_rva)))
    assert decoded.is_ip_rel_memory_operand
    assert decoded.ip_rel_memory_address == target_rva
    return result


def _program(parts: list[tuple[str, int | None]], *, code_rva: int) -> bytes:
    output = bytearray()
    for source, target in parts:
        if target is None:
            encoded, _ = _KS.asm(source, addr=code_rva + len(output))
            output += bytes(encoded)
        else:
            output += _rip_instruction(
                source,
                instruction_rva=code_rva + len(output),
                target_rva=target,
            )
    return bytes(output)


def _sections(code: bytes, data: bytes, *, code_rva=0x1000, data_rva=0x4000):
    return (
        _Section(".text", code_rva, len(code), code, _EXEC),
        _Section(".data", data_rva, len(data), data, _READ_WRITE),
    )


def test_decoder_targets_are_rvas_and_runtime_uses_relocated_image_base() -> None:
    code_rva = 0x1000
    data_rva = 0x4000
    parts = [
        ("mov al, byte ptr {mem}", data_rva),
        ("mov bx, word ptr {mem}", data_rva + 2),
        ("mov ecx, dword ptr {mem}", data_rva + 4),
        ("mov rdx, qword ptr {mem}", data_rva + 8),
        ("mov byte ptr {mem}, al", data_rva + 0x10),
        ("mov word ptr {mem}, bx", data_rva + 0x12),
        ("mov dword ptr {mem}, ecx", data_rva + 0x14),
        ("mov qword ptr {mem}, rdx", data_rva + 0x18),
        ("add byte ptr {mem}, 3", data_rva + 0x20),
        ("xor word ptr {mem}, 0x55", data_rva + 0x22),
        ("or dword ptr {mem}, 0x100", data_rva + 0x24),
        ("and qword ptr {mem}, -2", data_rva + 0x28),
        ("movzx r10d, byte ptr {mem}", data_rva),
        ("movsx r11, word ptr {mem}", data_rva + 2),
        ("movsxd r12, dword ptr {mem}", data_rva + 4),
        ("cmp rax, rax", None),
        ("cmovne r13, qword ptr {mem}", data_rva + 8),
        ("setne byte ptr {mem}", data_rva + 0x30),
        ("test rax, rax", None),
        ("lea r9, {mem}", data_rva + 0x40),
    ]
    code = _program(parts, code_rva=code_rva)
    data = bytes(range(0x80))
    init = [0] * 16
    init[4] = oracle.STACK

    references = lifter.validate_rip_relative_references(
        code,
        base=code_rva,
        image_sections=_sections(code, data),
        selected_extents=((code_rva, len(code)),),
    )
    assert len(references) == sum(target is not None for _source, target in parts)
    assert references[0].target_rva == data_rva
    assert references[0].size == 1
    assert references[0].access == "read"
    assert references[4].access == "write"
    assert references[8].access == "read_write"
    assert references[-1].access == "address"
    assert references[-1].address_only is True

    (native, _flags, native_data), (lifted, _lifted_flags, lifted_data) = (
        oracle.check_rip_data(
            code,
            data,
            code_rva=code_rva,
            data_rva=data_rva,
            runtime_image_base=0x000001A000000000,
            init=init,
        )
    )
    assert native == lifted
    assert native_data == lifted_data
    assert native[9] == 0x000001A000004040


def test_backward_rip_lea_rebases_from_source_rva() -> None:
    code_rva = 0x4000
    data_rva = 0x1000
    code = _program([("lea rax, {mem}", data_rva + 7)], code_rva=code_rva)
    data = bytes(0x20)
    (native, _flags, _memory), _ = oracle.check_rip_data(
        code,
        data,
        code_rva=code_rva,
        data_rva=data_rva,
        runtime_image_base=0x000001B000000000,
        flags=(),
    )
    assert native[0] == 0x000001B000001007


def test_rip_references_require_section_geometry() -> None:
    code = _program([("mov rax, qword ptr {mem}", 0x4000)], code_rva=0x1000)
    with pytest.raises(lifter.LiftUnsupported, match="section geometry"):
        lifter.lift_function(code, base=0x1000)


@pytest.mark.parametrize(
    ("section", "source", "target", "reason"),
    [
        (None, "mov eax, dword ptr {mem}", 0x200, "unmapped/header"),
        (_Section(".rdata", 0x4000, 8, bytes(8), _READ),
         "mov qword ptr {mem}, rax", 0x4000, "non-writable"),
        (_Section(".data", 0x4000, 8, bytes(8), _WRITE),
         "mov rax, qword ptr {mem}", 0x4000, "non-readable"),
        (_Section(".text2", 0x4000, 8, bytes(8), _EXEC),
         "mov rax, qword ptr {mem}", 0x4000, "executable bytes"),
        (_Section(".text2", 0x4000, 8, bytes(8), _EXEC),
         "lea rax, {mem}", 0x4000, "address-taken executable code"),
        (_Section(".reloc", 0x4000, 8, bytes(8), _READ | 0x02000000),
         "mov rax, qword ptr {mem}", 0x4000, "discardable"),
    ],
)
def test_rip_permissions_headers_and_executable_targets_fail_closed(
    section, source: str, target: int, reason: str
) -> None:
    code = _program([(source, target)], code_rva=0x1000)
    sections = [_Section(".text", 0x1000, len(code), code, _EXEC)]
    if section is not None:
        sections.append(section)
    with pytest.raises(lifter.LiftUnsupported, match=reason):
        lifter.lift_function(
            code,
            base=0x1000,
            image_sections=sections,
            selected_extents=((0x1000, len(code)),),
        )


def test_rip_span_must_fit_one_section_and_avoid_selected_extents() -> None:
    code = _program([("mov rax, qword ptr {mem}", 0x4004)], code_rva=0x1000)
    sections = (
        _Section(".text", 0x1000, len(code), code, _EXEC),
        _Section(".data", 0x4000, 8, bytes(8), _READ_WRITE),
        _Section(".next", 0x4008, 8, bytes(8), _READ_WRITE),
    )
    with pytest.raises(lifter.LiftUnsupported, match="cross-section"):
        lifter.lift_function(code, base=0x1000, image_sections=sections)

    code = _program([("lea rax, {mem}", 0x4004)], code_rva=0x1000)
    with pytest.raises(lifter.LiftUnsupported, match="overlaps selected extent"):
        lifter.lift_function(
            code,
            base=0x1000,
            image_sections=_sections(code, bytes(8)),
            selected_extents=((0x4000, 8),),
        )


def test_segment_override_precedes_rip_relative_emission() -> None:
    code = _program([("mov rax, qword ptr fs:{mem}", 0x4000)], code_rva=0x1000)
    with pytest.raises(lifter.LiftUnsupported, match="segment-overridden"):
        lifter.lift_function(
            code,
            base=0x1000,
            image_sections=_sections(code, bytes(8)),
        )


@pytest.mark.parametrize(
    "code",
    (
        bytes.fromhex("67 8B 05 00 00 00 00"),
        bytes.fromhex("67 8D 05 00 00 00 00"),
    ),
    ids=("mov-eip-relative", "lea-eip-relative"),
)
def test_address_size_overridden_eip_relative_forms_fail_before_emission(
    code: bytes,
) -> None:
    instruction = next(iter(Decoder(64, code, ip=0x1000)))
    assert instruction.is_ip_rel_memory_operand
    assert instruction.memory_base == Register.EIP

    with pytest.raises(
        lifter.LiftUnsupported,
        match="address-size-overridden EIP-relative memory operand at 0x1000",
    ):
        lifter.analyze_rip_relative_references(code, base=0x1000)
    with pytest.raises(
        lifter.LiftUnsupported,
        match="address-size-overridden EIP-relative memory operand at 0x1000",
    ):
        lifter.lift_function(
            code,
            base=0x1000,
            image_sections=_sections(code, bytes(8)),
            selected_extents=((0x1000, len(code)),),
        )


def test_rip_push_and_pop_data_forms_lift_with_bounded_geometry() -> None:
    code = _program(
        [
            ("push qword ptr {mem}", 0x4000),
            ("pop qword ptr {mem}", 0x4008),
            ("shld qword ptr {mem}, rax, 3", 0x4008),
        ],
        code_rva=0x1000,
    )
    assembly = lifter.lift_function(
        code,
        base=0x1000,
        image_sections=_sections(code, bytes(16)),
        selected_extents=((0x1000, len(code)),),
    )
    assert assembly.count(f"local_addr {lifter.IMAGE_BASE}") == 3


@pytest.mark.parametrize(
    "source",
    [
        "mov qword ptr {mem}, 7",
        "add rax, qword ptr {mem}",
        "sub qword ptr {mem}, 1",
        "xor rax, qword ptr {mem}",
        "and qword ptr {mem}, rax",
        "or rax, qword ptr {mem}",
        "adc qword ptr {mem}, rax",
        "sbb rax, qword ptr {mem}",
        "cmp qword ptr {mem}, rax",
        "test rax, qword ptr {mem}",
        "inc qword ptr {mem}",
        "dec qword ptr {mem}",
        "neg qword ptr {mem}",
        "not qword ptr {mem}",
        "sete byte ptr {mem}",
        "cmove rax, qword ptr {mem}",
        "mul qword ptr {mem}",
        "imul qword ptr {mem}",
        "imul rax, qword ptr {mem}",
        "imul rax, qword ptr {mem}, 7",
        "shld qword ptr {mem}, rax, 3",
        "shrd qword ptr {mem}, rax, cl",
    ],
)
def test_existing_scalar_rip_memory_routes_compile(source: str) -> None:
    code = _program([(source, 0x4000)], code_rva=0x1000)
    assembly = lifter.lift_function(
        code,
        base=0x1000,
        image_sections=_sections(code, bytes(16)),
        selected_extents=((0x1000, len(code)),),
    )
    assert f"local_addr {lifter.IMAGE_BASE}" in assembly


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("call qword ptr {mem}", "indirect / non-near call"),
        ("jmp qword ptr {mem}", "indirect / non-near branch"),
        ("movdqu xmm0, xmmword ptr {mem}", "register-only operands"),
        ("vmovdqu xmm0, xmmword ptr {mem}", "mnemonic"),
    ],
)
def test_indirect_control_and_xmm_memory_remain_rejected(source: str, reason: str) -> None:
    code = _program([(source, 0x4000)], code_rva=0x1000)
    with pytest.raises(lifter.LiftUnsupported, match=reason):
        lifter.lift_function(
            code,
            base=0x1000,
            image_sections=_sections(code, bytes(16)),
        )
