"""Prove bounded, state-neutral native tail thunks without rewriting them.

Only canonical E9 rel32 links and a terminal FF25 RIP-relative jump through an
exact normal-import IAT entry are modeled. A retained PDATA entry may terminate
the chain. No arbitrary native leaf, register jump, prefix or body is admitted.
"""
from __future__ import annotations

from typing import Any, Iterable, Sequence

from iced_x86 import Decoder, Mnemonic, OpKind

MAX_TAIL_INSTRUCTIONS = 16
_LIMIT = 0x1_0000_0000
_EXECUTE = 0x20000000
_DISCARDABLE = 0x02000000


def validated_import_iat_rvas(entries: tuple[int, ...]) -> frozenset[int]:
    """Validate the complete source inventory before discarding its ordering.

    Discovery and planning share this contract. In particular, converting to a
    set before checking would hide duplicate slots, including cross-DLL aliases.
    Geometry and file backing of a referenced slot are checked by the proof.
    """
    if not isinstance(entries, tuple):
        raise ValueError("source import IAT entries must be an immutable tuple")
    if any(type(rva) is not int or not 0 < rva < _LIMIT - 7 for rva in entries):
        raise ValueError("source import IAT entries must be valid eight-byte RVAs")
    ordered = sorted(entries)
    if any(right < left + 8 for left, right in zip(ordered, ordered[1:])):
        raise ValueError("source import IAT entries overlap")
    return frozenset(entries)


def _read(sections: Sequence[Any], rva: int, size: int, *, executable: bool) -> bytes | None:
    if not 0 < rva < rva + size <= _LIMIT:
        return None
    owners = [s for s in sections
              if s.rva <= rva and rva + size <= s.rva + len(s.raw)]
    if len(owners) != 1:
        return None
    owner = owners[0]
    if bool(owner.characteristics & _EXECUTE) != executable or owner.characteristics & _DISCARDABLE:
        return None
    start = rva - owner.rva
    return bytes(owner.raw[start:start + size])


def _overlaps(rva: int, size: int, ranges: Iterable[tuple[int, int]]) -> bool:
    return any(rva < end and begin < rva + size for begin, end in ranges)


def proven_tail_call_targets(
    code: bytes, *, base: int, sections: Sequence[Any],
    retained_entries: frozenset[int], runtime_ranges: Sequence[tuple[int, int]],
    selected_extents: Sequence[tuple[int, int]], import_iat_rvas: frozenset[int] = frozenset(),
) -> frozenset[int]:
    """Return only external CALL targets whose complete neutral chain is proven.

    The caller supplies source-validated runtime/import metadata. Every thunk
    instruction must remain outside *all* selected bytes and all runtime bodies;
    jumping to a retained runtime entry terminates before reading its body.
    The original chain and import slot stay native, so guard/dispatch code is
    never substituted and no source-stack pointer translation is inferred.
    """
    blocked = tuple((rva, rva + size) for rva, size in selected_extents)

    def prove(entry: int) -> bool:
        current, seen = entry, set()
        for _ in range(MAX_TAIL_INSTRUCTIONS):
            if current in seen or _overlaps(current, 1, blocked):
                return False
            if current in retained_entries:
                return True
            seen.add(current)
            raw = _read(sections, current, 5, executable=True)
            if raw is None:
                return False
            if raw[0] == 0xE9:
                if _overlaps(current, 5, blocked) or _overlaps(current, 5, runtime_ranges):
                    return False
                current += 5 + int.from_bytes(raw[1:], 'little', signed=True)
                if not 0 < current < _LIMIT:
                    return False
            elif raw[:2] == b'\xFF\x25':
                raw = _read(sections, current, 6, executable=True)
                if raw is None or _overlaps(current, 6, blocked) or _overlaps(current, 6, runtime_ranges):
                    return False
                slot = current + 6 + int.from_bytes(raw[2:], 'little', signed=True)
                return (slot in import_iat_rvas and
                        not _overlaps(slot, 8, blocked) and
                        _read(sections, slot, 8, executable=False) is not None)
            else:
                return False
        # Exactly sixteen neutral direct jumps may finish at a retained entry;
        # a seventeenth thunk or import instruction would exceed the bound.
        return current in retained_entries and not _overlaps(current, 1, blocked)

    targets = set()
    for instruction in Decoder(64, bytes(code), ip=base):
        offset = instruction.ip - base
        if (instruction.len == 5 and code[offset] == 0xE8 and
                instruction.mnemonic == Mnemonic.CALL and instruction.op_count == 1 and
                instruction.op_kind(0) == OpKind.NEAR_BRANCH64):
            target = int(instruction.near_branch_target)
            if target not in retained_entries and prove(target):
                targets.add(target)
    return frozenset(targets)
