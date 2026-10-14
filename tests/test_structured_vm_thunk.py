"""Exact generated-thunk data islands are proved, never generic gap waivers."""

from dataclasses import FrozenInstanceError
import struct

import pytest

from lifter import structured_vm_thunk as proof, win64_thunk


def _code(*, rva=0x1000, common=0x5000, descriptor=0x140008000):
    code = bytearray(win64_thunk.THUNK_TEMPLATE)
    struct.pack_into("<i", code, 9, common - rva - 13)
    struct.pack_into("<Q", code, 15, descriptor)
    return bytes(code)


def test_exact_partition_and_entry_reachability():
    result = proof.decode_stack512_thunk(
        _code(), rva=0x1000, common_rva=0x5000, descriptor_va=0x140008000)
    assert result.data_island == (0x100F, 0x1017)
    assert result.end_rva == 0x102E
    assert len(result.instructions) == 12
    assert result.instruction_starts - result.reachable_starts == {0x1025, 0x1026}
    assert not set(range(*result.data_island)) & result.instruction_starts
    assert {ins.ip for ins in result.instructions} == result.instruction_starts
    with pytest.raises(FrozenInstanceError):
        result.data_island = (0, 8)


@pytest.mark.parametrize("descriptor", [
    1, 0xE8, 0xE8E8E8E8E8E8E8E8, 0xCCCCCCCCCCCCCCCC,
    0x140008000, 0x7FFF12340000, 0xFFFF_FFFF_FFFF_FFFF,
])
def test_pointer_bytes_cannot_invent_instructions(descriptor):
    result = proof.decode_stack512_thunk(
        _code(descriptor=descriptor), rva=0x1000, common_rva=0x5000,
        descriptor_va=descriptor)
    reference = proof.decode_stack512_thunk(
        _code(), rva=0x1000, common_rva=0x5000, descriptor_va=0x140008000)
    assert result.instruction_starts == reference.instruction_starts
    assert result.reachable_starts == reference.reachable_starts
    assert tuple(str(x) for x in result.instructions) == tuple(str(x) for x in reference.instructions)


@pytest.mark.parametrize("offset", [x for x in range(46) if x not in range(9, 13) and x not in range(15, 23)])
def test_every_nonrelocation_byte_is_template_bound(offset):
    changed = bytearray(_code())
    changed[offset] ^= 1
    with pytest.raises(proof.StructuredThunkError, match="template"):
        proof.decode_stack512_thunk(bytes(changed), rva=0x1000,
                                   common_rva=0x5000, descriptor_va=0x140008000)


@pytest.mark.parametrize("offset", list(range(9, 13)) + list(range(15, 23)))
def test_every_relocation_field_byte_is_target_bound(offset):
    changed = bytearray(_code())
    changed[offset] ^= 1
    with pytest.raises(proof.StructuredThunkError, match="target differs|pointer differs"):
        proof.decode_stack512_thunk(bytes(changed), rva=0x1000,
                                   common_rva=0x5000, descriptor_va=0x140008000)


@pytest.mark.parametrize("kwargs", [
    {"rva": True}, {"rva": 0}, {"rva": -1}, {"rva": 0xFFFF_FFFF},
    {"common_rva": False}, {"common_rva": 0}, {"common_rva": 0x1_0000_0000},
    {"common_rva": 0x1000}, {"common_rva": 0x100F}, {"common_rva": 0x1017},
    {"descriptor_va": True}, {"descriptor_va": 0}, {"descriptor_va": -1},
    {"descriptor_va": 0x1_0000_0000_0000_0000},
])
def test_exact_integer_address_contract(kwargs):
    args = {"rva": 0x1000, "common_rva": 0x5000, "descriptor_va": 0x140008000}
    args.update(kwargs)
    with pytest.raises(proof.StructuredThunkError):
        proof.decode_stack512_thunk(_code(), **args)


@pytest.mark.parametrize("code", [b"", _code()[:-1], _code() + b"\x90", bytearray(_code()), None])
def test_only_exact_immutable_code_bytes_accept(code):
    with pytest.raises(proof.StructuredThunkError, match="exact stack512"):
        proof.decode_stack512_thunk(code, rva=0x1000, common_rva=0x5000,
                                   descriptor_va=0x140008000)


@pytest.mark.parametrize("rva,common", [(0x5000, 0x1000), (1, 0x2000), (0x7FFF0000, 0x7FFE0000)])
def test_distinct_in_image_forward_and_backward_bridge(rva, common):
    result = proof.decode_stack512_thunk(
        _code(rva=rva, common=common), rva=rva, common_rva=common,
        descriptor_va=0x140008000)
    call = next(ins for ins in result.instructions if ins.ip == rva + 8)
    assert call.near_branch_target == common
