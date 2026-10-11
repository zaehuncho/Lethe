"""Conservative recognition of compiler-emitted switch jump tables.

MSVC lays a ``switch`` dispatched through a computed jump as data-in-code: the
jump table's bytes sit inside the function's ``pdata`` extent, right after the
last real instruction.  A naive linear sweep decodes those table bytes as
instructions, mis-decodes, and either bails or -- worse -- fabricates bogus
control edges.  In the whole-image direct-control gate a single such function
used to poison the entire image, making selective virtualization of the DLL
impossible.

This module decodes one runtime-function extent, recognizes the compiler
jump-table shape, and returns the real code instructions with the table byte
ranges proven and excised as DATA.  It NEVER guesses a table's extent: a table
is delimited only from an in-range indexing instruction plus the bytes' own
self-consistency (every dword entry must resolve to an instruction start inside
the same function, and the delimited tables must tile the trailing data region
exactly).  Anything it cannot prove raises :class:`JumpTableUnresolved` so the
caller can bail that one function to native without touching the rest of the
image.

Supported MSVC x64 shapes (position-independent, image-base relative):

* single-level dword table::

      cmp   idx, N
      ja    default
      lea   base, [0]                     ; base := image base
      mov   ecx, [base + idx*4 + TBL]     ; TBL: dword offset table
      add   rcx, base
      jmp   rcx

* two-level byte-index + dword table (sparse switch)::

      cmp   idx, N
      ja    default
      lea   base, [0]
      movzx eax, byte ptr [base + idx + TBL_b]   ; TBL_b: byte index table
      mov   ecx, [base + eax*4 + TBL_d]           ; TBL_d: dword offset table
      add   rcx, base
      jmp   rcx

Both tables live inside the function extent; the dword entries are RVAs (offsets
from the image base) of case bodies inside the same function.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from iced_x86 import Decoder, FlowControl, OpKind, Register


# Alignment padding permitted between the last instruction and a table, or
# between two tables: exact INT3, single-byte NOP, and the two-byte NOP.
_PADDING_BYTES = frozenset({0x00, 0xCC, 0x90})
_SCALED_LOAD_STRIDES = frozenset({1, 4})
_MAX_TABLE_ENTRIES = 1 << 20


class JumpTableError(ValueError):
    """The extent cannot be decoded, even with jump-table recognition."""


class JumpTableUnresolved(JumpTableError):
    """A decode fault could not be proven to be a compiler jump table.

    Callers isolate the single function (bail it to native) rather than
    rejecting the whole image.
    """


@dataclass(frozen=True)
class DecodedFunctionBody:
    begin_rva: int
    end_rva: int
    # Real code instructions only, in ascending address order. Table bytes are
    # NOT present here -- they carry no instructions and no control edges.
    instructions: tuple
    instruction_starts: frozenset
    # Proven data-in-code byte ranges (the jump tables), sorted, disjoint.
    data_ranges: tuple
    # Case-body RVAs read out of the dword tables (intra-function switch
    # targets); useful for a computed-transfer lift and as a cross-check.
    switch_target_rvas: tuple
    has_indirect_dispatch: bool

    @property
    def has_data_in_code(self) -> bool:
        return bool(self.data_ranges)


def _decode_span(code: bytes, begin: int, span_begin: int, span_end: int):
    """Linear-decode [span_begin, span_end); return (instrs, landed_exactly)."""
    offset = span_begin - begin
    length = span_end - span_begin
    if length <= 0:
        return [], span_begin == span_end
    decoder = Decoder(64, code[offset:offset + length], ip=span_begin)
    instructions = []
    cursor = span_begin
    for instruction in decoder:
        if instruction.ip != cursor or instruction.code == 0 or instruction.len <= 0:
            return instructions, False
        instructions.append(instruction)
        cursor += instruction.len
    return instructions, (cursor == span_end)


def _scaled_index_table_refs(instructions, begin: int, end: int):
    """Forward scaled-index memory references whose displacement is in-extent.

    Returns a list of (instruction_ip, displacement_rva, stride).  Only
    references that point strictly ahead of the referencing instruction are
    considered -- a compiler places a function's jump table after the dispatch
    code, so a real table reference is always a forward reference.  This also
    excludes backward references fabricated by mis-decoding table bytes.
    """
    refs = []
    for instruction in instructions:
        for index in range(instruction.op_count):
            if instruction.op_kind(index) != OpKind.MEMORY:
                continue
            if instruction.memory_index == Register.NONE:
                continue
            scale = instruction.memory_index_scale
            if scale not in _SCALED_LOAD_STRIDES:
                continue
            disp = instruction.memory_displacement
            if begin <= disp < end and disp > instruction.ip:
                refs.append((instruction.ip, disp, scale))
    return refs


def _read_u32(code: bytes, begin: int, rva: int) -> int:
    return struct.unpack_from("<I", code, rva - begin)[0]


def _delimit_tables(code, begin, end, table_start, refs, code_starts):
    """Delimit each table in [table_start, end); prove they tile the region.

    ``refs`` are (ip, disp, stride) references from the clean code prefix whose
    ip < table_start.  Returns (data_ranges, switch_targets, resumed_instrs).
    Raises :class:`JumpTableUnresolved` on anything it cannot prove.
    """
    bases = sorted({disp for _ip, disp, _stride in refs})
    stride_by_base: dict[int, set] = {}
    for _ip, disp, stride in refs:
        stride_by_base.setdefault(disp, set()).add(stride)

    def next_base(base: int) -> int:
        higher = [other for other in bases if other > base]
        return min(higher) if higher else end

    # Pass 1: dword (stride 4) offset tables. Entries are case-body RVAs.
    dword_ranges = []
    dword_counts = {}
    for base in bases:
        if 4 not in stride_by_base[base]:
            continue
        limit = next_base(base)
        cursor = base
        count = 0
        while cursor + 4 <= limit and cursor + 4 <= end:
            target = _read_u32(code, begin, cursor)
            if not (begin <= target < end):
                break
            count += 1
            cursor += 4
            if count > _MAX_TABLE_ENTRIES:
                raise JumpTableUnresolved("dword jump table exceeds sanity bound")
        if count == 0:
            raise JumpTableUnresolved(
                f"dword table at 0x{base:X} has no in-extent entry")
        dword_counts[base] = count
        dword_ranges.append((base, base + 4 * count))

    if not dword_counts:
        raise JumpTableUnresolved(
            f"no dword offset table backing the switch at 0x{table_start:X}")
    max_dword_count = max(dword_counts.values())

    # Pass 2: byte index tables (stride 1). Each entry indexes a dword table.
    byte_ranges = []
    for base in bases:
        if stride_by_base[base] != {1}:
            continue
        limit = next_base(base)
        cursor = base
        count = 0
        while cursor < limit and cursor < end:
            if code[cursor - begin] >= max_dword_count:
                break
            count += 1
            cursor += 1
            if count > _MAX_TABLE_ENTRIES:
                raise JumpTableUnresolved("byte jump table exceeds sanity bound")
        if count == 0:
            raise JumpTableUnresolved(
                f"byte table at 0x{base:X} has no valid index entry")
        byte_ranges.append((base, base + count))

    ranges = sorted(dword_ranges + byte_ranges)

    # The tables must tile [table_start, data_end) contiguously; any gap must be
    # pure alignment padding. Overlap is a contradiction -> bail.
    covered = table_start
    for start, finish in ranges:
        if start < covered:
            raise JumpTableUnresolved(
                f"jump tables overlap near 0x{start:X}")
        if start > covered:
            gap = code[covered - begin:start - begin]
            if any(byte not in _PADDING_BYTES for byte in gap):
                raise JumpTableUnresolved(
                    f"non-padding bytes between tables at 0x{covered:X}")
        covered = finish
    data_end = covered

    # Code may resume after the tables (a table embedded before more code); it
    # must then decode cleanly to the extent end.
    resumed = []
    if data_end < end:
        resumed, ok = _decode_span(code, begin, data_end, end)
        if not ok:
            raise JumpTableUnresolved(
                f"bytes after tables [0x{data_end:X},0x{end:X}) are not code")
    elif data_end != end:
        raise JumpTableUnresolved("tables run past the function extent")

    # Final soundness check: every dword entry must resolve to a real
    # instruction start inside this function. Reinterpreting live code as a
    # jump table cannot satisfy this, so it proves the bytes are truly the
    # table and that we delimited the right regions.
    resumed_starts = {instruction.ip for instruction in resumed}
    valid_starts = code_starts | resumed_starts
    switch_targets = []
    for base, count in dword_counts.items():
        for index in range(count):
            target = _read_u32(code, begin, base + 4 * index)
            if target not in valid_starts:
                raise JumpTableUnresolved(
                    f"dword table entry 0x{base + 4 * index:X} -> 0x{target:X} "
                    "is not an instruction start")
            switch_targets.append(target)

    # Merge adjacent ranges for a tidy, minimal data-range set.
    merged = []
    for start, finish in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], finish))
        else:
            merged.append((start, finish))
    return tuple(merged), tuple(switch_targets), resumed


def decode_function_body(
    code: bytes, begin_rva: int, end_rva: int
) -> DecodedFunctionBody:
    """Decode one runtime-function extent, excising proven jump tables.

    A clean linear decode is not sufficient evidence of code: table RVAs can
    themselves be valid x64 opcodes. Forward table references preceding an
    indirect branch therefore use the same table proof even without a fault.
    Clean extents without that shape retain the linear fast path.

    A decode fault is also examined for a compiler jump-table shape. On
    success the code instructions are returned with the table byte ranges
    proven as data. On any doubt, :class:`JumpTableUnresolved` is raised.
    """
    if type(begin_rva) is not int or type(end_rva) is not int:
        raise JumpTableError("extent bounds must be integers")
    if end_rva <= begin_rva:
        raise JumpTableError("empty extent")
    if len(code) != end_rva - begin_rva:
        raise JumpTableError("code length does not match the extent")

    prefix, landed = _decode_span(code, begin_rva, begin_rva, end_rva)
    has_indirect_branch = any(
        instruction.flow_control == FlowControl.INDIRECT_BRANCH
        for instruction in prefix
    )
    refs = (
        _scaled_index_table_refs(prefix, begin_rva, end_rva)
        if not landed or has_indirect_branch else []
    )
    referenced_dispatch = False
    if refs:
        first_reference = min(ref[0] for ref in refs)
        first_table = min(ref[1] for ref in refs)
        referenced_dispatch = any(
            first_reference < instruction.ip < first_table
            and instruction.flow_control == FlowControl.INDIRECT_BRANCH
            for instruction in prefix
        )
    if landed and not referenced_dispatch:
        starts = frozenset(instruction.ip for instruction in prefix)
        has_indirect = any(
            instruction.flow_control
            in (FlowControl.INDIRECT_BRANCH, FlowControl.INDIRECT_CALL)
            for instruction in prefix
        )
        return DecodedFunctionBody(
            begin_rva=begin_rva,
            end_rva=end_rva,
            instructions=tuple(prefix),
            instruction_starts=starts,
            data_ranges=(),
            switch_target_rvas=(),
            has_indirect_dispatch=has_indirect,
        )

    # A fault or a referenced dispatch requires proof, not a successful sweep.
    if not refs:
        raise JumpTableUnresolved(
            f"decode fault in 0x{begin_rva:X}..0x{end_rva:X} with no in-extent "
            "jump-table reference")

    table_start = min(disp for _ip, disp, _stride in refs)
    # Real dispatch instructions precede the table; drop any reference whose
    # source lies at or after the table (those come from mis-decoded bytes).
    kept = [ref for ref in refs if ref[0] < table_start]
    if not kept:
        raise JumpTableUnresolved(
            f"jump-table reference at 0x{table_start:X} has no dispatch in code")

    code_instrs, landed_prefix = _decode_span(
        code, begin_rva, begin_rva, table_start)
    if not landed_prefix:
        raise JumpTableUnresolved(
            f"code prefix [0x{begin_rva:X},0x{table_start:X}) is not clean")
    code_starts = {instruction.ip for instruction in code_instrs}

    data_ranges, switch_targets, resumed = _delimit_tables(
        code, begin_rva, end_rva, table_start, kept, code_starts)

    all_instrs = tuple(sorted(
        (*code_instrs, *resumed), key=lambda instruction: instruction.ip))
    _validate_data_reachability(
        all_instrs, begin_rva, end_rva, data_ranges, switch_targets)
    starts = frozenset(instruction.ip for instruction in all_instrs)
    has_indirect = any(
        instruction.flow_control
        in (FlowControl.INDIRECT_BRANCH, FlowControl.INDIRECT_CALL)
        for instruction in all_instrs
    )
    return DecodedFunctionBody(
        begin_rva=begin_rva,
        end_rva=end_rva,
        instructions=all_instrs,
        instruction_starts=starts,
        data_ranges=data_ranges,
        switch_target_rvas=switch_targets,
        has_indirect_dispatch=has_indirect,
    )


def _validate_data_reachability(instructions, begin, end, data_ranges, targets):
    """Never excise bytes reached by a direct edge or reachable fallthrough.

    Case targets are extra roots; indirect dispatches reach their proven case
    targets. This is not an indirect-target closure proof or permission to
    virtualize a switch function. Unreachable alignment after a terminating
    instruction remains permitted.
    """
    by_rva = {instruction.ip: instruction for instruction in instructions}
    near = {OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64}

    def is_data(rva):
        return any(start <= rva < finish for start, finish in data_ranges)

    direct_flows = {
        FlowControl.CALL, FlowControl.UNCONDITIONAL_BRANCH,
        FlowControl.CONDITIONAL_BRANCH,
    }
    for instruction in instructions:
        if (instruction.flow_control in direct_flows
                and instruction.op_count and instruction.op_kind(0) in near
                and is_data(int(instruction.near_branch_target))):
            raise JumpTableUnresolved(
                f"direct edge at 0x{instruction.ip:X} enters jump-table data")

    pending = [begin, *targets]
    visited = set()
    fallthrough_flows = {
        FlowControl.NEXT, FlowControl.CALL, FlowControl.INDIRECT_CALL,
        FlowControl.CONDITIONAL_BRANCH,
    }
    while pending:
        rva = pending.pop()
        if not begin <= rva < end or rva in visited:
            continue
        if is_data(rva):
            raise JumpTableUnresolved(
                f"reachable fallthrough enters jump-table data at 0x{rva:X}")
        instruction = by_rva.get(rva)
        if instruction is None:
            raise JumpTableUnresolved(
                f"table proof reaches non-instruction RVA 0x{rva:X}")
        visited.add(rva)
        flow = instruction.flow_control
        if flow in direct_flows:
            if not instruction.op_count or instruction.op_kind(0) not in near:
                raise JumpTableUnresolved("table proof uses a non-near direct edge")
            pending.append(int(instruction.near_branch_target))
        if flow in fallthrough_flows:
            pending.append(instruction.ip + instruction.len)
        elif flow not in {
                FlowControl.UNCONDITIONAL_BRANCH, FlowControl.INDIRECT_BRANCH,
                FlowControl.RETURN, FlowControl.INTERRUPT, FlowControl.EXCEPTION}:
            raise JumpTableUnresolved(
                f"table proof uses unsupported control flow at 0x{rva:X}")


__all__ = [
    "DecodedFunctionBody",
    "JumpTableError",
    "JumpTableUnresolved",
    "decode_function_body",
]
