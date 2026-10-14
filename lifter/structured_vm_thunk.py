"""Decode only the maintained stack512 thunk's exact code/data partition.

This is a byte/CFG proof, not a PE, unwind, relocation, entry-closure or runtime
admission proof.  Its consumer must independently bind those facts to the
current image.  No caller-supplied range can turn arbitrary bytes into data.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

from iced_x86 import Decoder, FlowControl, Instruction, OpKind

from . import win64_thunk


class StructuredThunkError(ValueError):
    """The bytes do not prove the single supported thunk partition."""


@dataclass(frozen=True)
class StructuredThunkCode:
    rva: int
    end_rva: int
    instructions: tuple[Instruction, ...]
    instruction_starts: frozenset[int]
    data_island: tuple[int, int]
    reachable_starts: frozenset[int]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise StructuredThunkError(message)


def decode_stack512_thunk(
    code: bytes, *, rva: int, common_rva: int, descriptor_va: int,
) -> StructuredThunkCode:
    """Prove the exact 46-byte template, excluding its one skipped qword.

    Relative branch encodings are image-base invariant.  The only absolute VA
    lies at +15..+23, after EB08 at +13; those eight bytes never contribute an
    instruction or direct control edge.  The two fixed post-RET NOPs are decoded
    but are not reachable from the thunk entry.  An external bridge CALL is not
    a proof of the bridge's behavior or of arbitrary indirect-entry closure.
    """
    size = win64_thunk.THUNK_CODE_SIZE
    _require(type(code) is bytes and len(code) == size,
             "exact stack512 thunk bytes required")
    _require(type(rva) is int and 0 < rva and rva + size <= 0x1_0000_0000,
             "thunk RVA/extent is out of bounds")
    _require(type(common_rva) is int and 0 < common_rva < 0x1_0000_0000 and
             not rva <= common_rva < rva + size,
             "common bridge must be a distinct bounded RVA")
    _require(type(descriptor_va) is int and 0 < descriptor_va < 0x1_0000_0000_0000_0000,
             "descriptor VA is out of bounds")
    call_field = win64_thunk.THUNK_COMMON_REL32_OFFSET
    pointer = win64_thunk.THUNK_DESCRIPTOR_POINTER_OFFSET
    _require((size, call_field, pointer) == (46, 9, 15),
             "maintained thunk partition changed")
    displacement = struct.unpack_from("<i", code, call_field)[0]
    _require(rva + call_field + 4 + displacement == common_rva,
             "thunk common bridge target differs")
    _require(struct.unpack_from("<Q", code, pointer)[0] == descriptor_va,
             "thunk descriptor pointer differs")
    normalized = bytearray(code)
    normalized[call_field:call_field + 4] = b"\0" * 4
    normalized[pointer:pointer + 8] = b"\0" * 8
    _require(bytes(normalized) == win64_thunk.THUNK_TEMPLATE,
             "thunk is not the exact maintained template")
    island = (rva + pointer, rva + pointer + 8)
    instructions: list[Instruction] = []
    for begin, end in ((0, pointer), (pointer + 8, size)):
        segment = code[begin:end]
        decoded = tuple(Decoder(64, segment, ip=rva + begin))
        _require(decoded and all(not ins.is_invalid for ins in decoded) and
                 sum(ins.len for ins in decoded) == len(segment),
                 "thunk code partition is not exactly decodable")
        instructions.extend(decoded)
    expected = ((0, 1), (1, 7), (8, 5), (13, 2), (23, 4), (27, 2),
                (29, 7), (36, 1), (37, 1), (38, 1), (39, 5), (44, 2))
    _require(tuple((ins.ip - rva, ins.len) for ins in instructions) == expected,
             "thunk instruction boundaries differ")
    by_ip = {ins.ip: ins for ins in instructions}
    _require(len(by_ip) == len(instructions), "thunk instruction alias")
    starts = frozenset(by_ip)
    _require(all(not island[0] <= value < island[1] for value in starts),
             "thunk data island contains an instruction")
    reachable: set[int] = set()
    pending = [rva]
    while pending:
        ip = pending.pop()
        if ip in reachable:
            continue
        _require(ip in by_ip, "thunk flow enters data or an instruction interior")
        reachable.add(ip)
        ins = by_ip[ip]
        if ins.flow_control == FlowControl.NEXT:
            successors = (ins.next_ip,)
        elif ins.flow_control == FlowControl.CALL:
            _require(ins.ip == rva + 8 and ins.op_count == 1 and
                     ins.op_kind(0) == OpKind.NEAR_BRANCH64 and
                     ins.near_branch_target == common_rva,
                     "thunk has an unexpected call")
            successors = (ins.next_ip,)
        elif ins.flow_control == FlowControl.UNCONDITIONAL_BRANCH:
            _require(ins.ip == rva + 13 and ins.op_count == 1 and
                     ins.op_kind(0) == OpKind.NEAR_BRANCH64 and
                     ins.near_branch_target == island[1],
                     "thunk does not jump over its exact data island")
            successors = (ins.near_branch_target,)
        elif ins.flow_control == FlowControl.CONDITIONAL_BRANCH:
            _require(ins.ip == rva + 27 and ins.op_count == 1 and
                     ins.op_kind(0) == OpKind.NEAR_BRANCH64 and
                     ins.near_branch_target == rva + 39,
                     "thunk has an unexpected conditional branch")
            successors = (ins.next_ip, ins.near_branch_target)
        elif ins.flow_control == FlowControl.RETURN:
            _require(ins.ip == rva + 36, "thunk has an unexpected return")
            successors = ()
        elif ins.flow_control == FlowControl.INTERRUPT:
            _require(ins.ip == rva + 44, "thunk has an unexpected interrupt")
            successors = ()
        else:
            raise StructuredThunkError("thunk has unsupported control flow")
        _require(all(child in starts for child in successors),
                 "thunk flow leaves the exact code partition")
        pending.extend(successors)
    _require(starts - reachable == {rva + 37, rva + 38},
             "thunk reachability differs from the maintained epilogue")
    return StructuredThunkCode(rva, rva + size, tuple(instructions), starts,
                               island, frozenset(reachable))


__all__ = ["StructuredThunkError", "StructuredThunkCode", "decode_stack512_thunk"]
