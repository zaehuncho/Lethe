"""Bounded bit-immediate spans do not waive source-byte overlap checks."""
from __future__ import annotations

import pytest
from iced_x86 import Decoder, OpKind
from tests.test_known_source_references import _admit, _image, _rip


@pytest.mark.parametrize("interface", ["preflight", "discovery"])
@pytest.mark.parametrize("mnemonic", ["bt", "btc", "btr", "bts"])
@pytest.mark.parametrize("bit", [0, 7, 63])
@pytest.mark.parametrize("target", [0x4000, 0x1001, 0xFF8, 0xFF9])
def test_in_operand_imm8_checks_full_qword_not_just_bit_byte(interface, mnemonic, bit, target):
    native = _rip(f"{mnemonic} qword ptr {{mem}},{bit}", target)
    instruction = Decoder(64, native, ip=0x1100).decode()
    assert instruction.op1_kind == OpKind.IMMEDIATE8
    assert instruction.immediate8 == bit
    assert instruction.ip_rel_memory_address == target
    _admit(_image(native), interface, target in (0x1001, 0xFF9))


@pytest.mark.parametrize("interface", ["preflight", "discovery"])
@pytest.mark.parametrize("mnemonic", ["bt", "btc", "btr", "bts"])
@pytest.mark.parametrize("offset", ["rcx", "64", "255"])
def test_register_and_unsupported_large_offsets_stay_fail_closed(interface, mnemonic, offset):
    native = _rip(f"{mnemonic} qword ptr {{mem}}," + ("rcx" if offset == "rcx" else "0"), 0x4000)
    if offset != "rcx":
        # Keystone rejects 255; test the actual encoded imm8, not an assembler
        # macro or altered displacement. Preserve the complete memory operand.
        assert native[-1] == 0
        native = native[:-1] + bytes((int(offset),))
        decoded = Decoder(64, native, ip=0x1100).decode()
        assert decoded.immediate8 == int(offset) and decoded.ip_rel_memory_address == 0x4000
    _admit(_image(native), interface, True)


@pytest.mark.parametrize("interface", ["preflight", "discovery"])
@pytest.mark.parametrize("width,bit,target,reject", [
    ("word", 15, 0xFFE, False), ("word", 15, 0xFFF, True),
    ("dword", 31, 0xFFC, False), ("dword", 31, 0xFFD, True),
    ("word", 16, 0x4000, True), ("dword", 32, 0x4000, True),
])
def test_operand_width_and_nonoverlap_boundary_are_exact(interface, width, bit, target, reject):
    _admit(_image(_rip(f"btr {width} ptr {{mem}},{bit}", target)), interface, reject)


@pytest.mark.parametrize("interface", ["preflight", "discovery"])
def test_exact_crt_instruction_remains_native_and_does_not_poison_other_function(interface):
    native = bytes.fromhex("480fba359e14000007")
    instruction = Decoder(64, native, ip=0x1B71).decode()
    assert instruction.ip_rel_memory_address == 0x3018
    # Encode that same bounded operation in the fixture's native source range.
    _admit(_image(_rip("btr qword ptr {mem},7", 0x3018)), interface, False)
