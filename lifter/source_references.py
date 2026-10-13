"""Non-waivable negative facts about references to overwritten source bytes.

This is not indirect/address-taken closure. Only decoded RIP operands and
validated, file-backed DIR64 pointer values participate. An entry address may
remain a callable pointer; a direct memory access to entry bytes may not.
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
from typing import Any, Iterable

from iced_x86 import MemorySizeExt, Mnemonic, Register


class SourceReferenceError(ValueError):
    """A known source reference or its required inventory is unsafe."""


@dataclass(frozen=True, order=True)
class SourceReference:
    target_rva: int
    size: int
    source_rva: int
    kind: str
    address_only: bool = False


def instruction_references(instructions: Iterable[Any]) -> tuple[SourceReference, ...]:
    references = []
    for instruction in instructions:
        if not instruction.is_ip_rel_memory_operand or instruction.mnemonic == Mnemonic.NOP:
            continue
        # An EIP operand zero-extends the actual VA, not the decoder's RVA.
        # Do not mistake that address-size form for an ordinary RIP operand.
        if instruction.memory_base != Register.RIP:
            raise SourceReferenceError(
                f"unbounded source reference: address-size-relative operand at RVA 0x{instruction.ip:X}"
            )
        address_only = instruction.mnemonic == Mnemonic.LEA
        size = 1 if address_only else MemorySizeExt.size(instruction.memory_size)
        # Memory bit-string offsets can move the access outside the encoded
        # base/operand width. They need a separate bounded address proof.
        if size <= 0 or instruction.mnemonic in {
            Mnemonic.BT, Mnemonic.BTC, Mnemonic.BTR, Mnemonic.BTS,
        }:
            raise SourceReferenceError(
                f"unbounded source reference: memory span at RVA 0x{instruction.ip:X}"
            )
        references.append(SourceReference(
            int(instruction.ip_rel_memory_address), size, int(instruction.ip),
            "RIP address" if address_only else "RIP memory", address_only,
        ))
    return tuple(references)


def dir64_references(parsed: Any) -> tuple[SourceReference, ...]:
    # Partial analysis records may omit the inventory. This does not prove it
    # empty: the materializer independently requires complete source metadata.
    inventory = getattr(parsed, "dir64_relocations", ())
    if not isinstance(inventory, (tuple, list)):
        raise SourceReferenceError("source reference: DIR64 inventory must be a sequence")
    if not inventory:
        return ()
    base = getattr(parsed, "image_base", None)
    if type(base) is not int or not 0 <= base < 1 << 64:
        raise SourceReferenceError("source reference: DIR64s require a valid image base")
    slots = []
    for item in inventory:
        rva = getattr(item, "target_rva", None)
        if type(rva) is not int or not 0 < rva <= (1 << 32) - 8:
            raise SourceReferenceError("source reference: DIR64 has an invalid eight-byte slot")
        slots.append(rva)
    slots.sort()
    if any(right < left + 8 for left, right in zip(slots, slots[1:])):
        raise SourceReferenceError("source reference: DIR64 slots overlap or duplicate")
    references = []
    for rva in slots:
        matches = [s for s in parsed.sections
                   if s.rva <= rva and rva + 8 <= s.rva + len(s.raw)]
        if len(matches) != 1:
            raise SourceReferenceError(
                f"source reference: DIR64 at RVA 0x{rva:X} must be uniquely file-backed"
            )
        section = matches[0]
        offset = rva - section.rva
        target = int.from_bytes(section.raw[offset:offset + 8], "little") - base
        if 0 < target < 1 << 32:
            references.append(SourceReference(target, 1, rva, "DIR64 address", True))
    return tuple(references)


class SourceReferenceIndex:
    """Build once; query candidate extents without rescanning the image."""

    def __init__(self, references: Iterable[SourceReference]) -> None:
        self.references = tuple(sorted(references))
        self.starts = tuple(item.target_rva for item in self.references)
        self.max_size = max((item.size for item in self.references), default=1)

    def rejection(self, name: str, rva: int, size: int) -> str | None:
        start = bisect_left(self.starts, rva - self.max_size + 1)
        end = bisect_left(self.starts, rva + size)
        for item in self.references[start:end]:
            if item.target_rva + item.size <= rva:
                continue
            if item.address_only and item.target_rva == rva:
                continue
            return (
                f"known source reference: {item.kind} at RVA 0x{item.source_rva:X} "
                f"targets 0x{item.target_rva:X}+0x{item.size:X}, overlapping "
                f"overwritten function {name!r} 0x{rva:X}..0x{rva + size:X}"
            )
        return None

    def validate(self, selected: Iterable[Any]) -> None:
        for spec in selected:
            reason = self.rejection(spec.name, spec.rva, spec.size)
            if reason is not None:
                raise SourceReferenceError(reason)
