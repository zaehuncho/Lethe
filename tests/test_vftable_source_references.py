"""A validated exported MSVC vftable preserves exact selected entry addresses."""
from __future__ import annotations

import struct

import pytest

from lifter import direct_control_flow as flow
from lifter import function_discovery as discovery
from lifter import source_references
from lifter import virtualization_plan as plan
from packer import pe_analyze
from tests.test_known_source_references import _image


_BASE = 0x140000000
_VFTABLE = discovery.ExportSymbol("??_7Foo@@6B@", 1, 0x4010)
_EXEC = 0x60000020
_READ = 0x40000040


def _image_with_vftable(*, target: int = 0x1000, valid_rtti: bool = True):
    image = _image(b"\x90")
    text = image.sections[0]
    image.sections[0] = pe_analyze.ParsedSection(
        text.name, 0x1000, 7, text.raw[:7], _EXEC
    )
    image.runtime_functions = tuple(
        item for item in image.runtime_functions if item.begin_rva == 0x1000
    )
    image.pdata_count = len(image.runtime_functions)
    rdata = bytearray(b"\0" * 0xC0)

    def put(rva: int, raw: bytes) -> None:
        start = rva - 0x4000
        rdata[start:start + len(raw)] = raw

    # x64 COL immediately before the address point; all embedded COL links are
    # image-relative RVAs, while the preceding pointer and table entries are
    # ordinary DIR64 relocations.
    put(0x4008, struct.pack("<Q", _BASE + 0x4040))
    put(0x4040, struct.pack("<IIIIII", 1, 0, 0, 0x4060, 0x4080, 0x4040))
    type_name = b".?AVFoo@@" if valid_rtti else b".?AVOther@@"
    put(0x4060, struct.pack("<QQ", _BASE + 0x4000, 0) + type_name + b"\0")
    put(0x4080, struct.pack("<IIII", 0, 0, 1, 0x4090))
    put(0x4090, struct.pack("<I", 0x40A0))
    put(0x40A0, struct.pack("<IIiiiII", 0x4060, 0, 0, -1, 0, 0, 0x4080))
    put(0x4010, struct.pack("<Q", _BASE + target))

    image.sections.append(pe_analyze.ParsedSection(
        ".rdata", 0x4000, len(rdata), bytes(rdata), _READ
    ))
    image.export_directory_rva = 0x4100
    image.export_directory_size = 40
    image.dir64_relocations = tuple(
        pe_analyze.ParsedDir64Relocation(rva)
        for rva in (0x4008, 0x4010, 0x4060)
    )
    return image


def _patch_exports(monkeypatch):
    monkeypatch.setattr(discovery, "parse_pe_exports", lambda _image: (_VFTABLE,))


def test_validated_vftable_exact_entry_is_callable_but_closure_stays_unproven(monkeypatch):
    image = _image_with_vftable()
    _patch_exports(monkeypatch)

    proof = flow.analyze_direct_control_flow(
        image, (plan.FunctionSpec("selected", 0x1000, 7),), production=False
    )

    assert proof.direct_reference_gate_passed
    assert proof.indirect_target_closure_proven is False
    refs = source_references.dir64_references(
        image, known_function_entries=(0x1000,), exports=(_VFTABLE,)
    )
    vtable_ref = next(item for item in refs if item.source_rva == 0x4010)
    assert vtable_ref.kind == "DIR64 vftable function pointer"
    assert vtable_ref.metadata_entry is True


@pytest.mark.parametrize("target", (0x1001,))
def test_vftable_interior_or_unproven_target_stays_rejected(monkeypatch, target):
    image = _image_with_vftable(target=target)
    _patch_exports(monkeypatch)

    with pytest.raises(flow.DirectControlFlowError, match="DIR64 address"):
        flow.analyze_direct_control_flow(
            image, (plan.FunctionSpec("selected", 0x1000, 7),), production=False
        )


def test_non_vftable_pointer_to_exact_exported_entry_stays_rejected(monkeypatch):
    image = _image_with_vftable()
    rdata = bytearray(image.sections[-1].raw)
    rdata[0x20:0x28] = struct.pack("<Q", _BASE + 0x1000)
    image.sections[-1] = pe_analyze.ParsedSection(
        ".rdata", 0x4000, len(rdata), bytes(rdata), _READ
    )
    image.dir64_relocations += (pe_analyze.ParsedDir64Relocation(0x4020),)
    _patch_exports(monkeypatch)

    with pytest.raises(flow.DirectControlFlowError, match="DIR64 address"):
        flow.analyze_direct_control_flow(
            image, (plan.FunctionSpec("selected", 0x1000, 7),), production=False
        )


def test_invalid_rtti_cannot_turn_vtable_slot_into_entry_allowance(monkeypatch):
    image = _image_with_vftable(valid_rtti=False)
    _patch_exports(monkeypatch)

    with pytest.raises(flow.DirectControlFlowError, match="DIR64 address"):
        flow.analyze_direct_control_flow(
            image, (plan.FunctionSpec("selected", 0x1000, 7),), production=False
        )


def test_unrelocated_or_extended_type_descriptor_is_not_trusted(monkeypatch):
    image = _image_with_vftable()
    image.dir64_relocations = tuple(
        item for item in image.dir64_relocations if item.target_rva != 0x4060
    )
    _patch_exports(monkeypatch)

    with pytest.raises(flow.DirectControlFlowError, match="DIR64 address"):
        flow.analyze_direct_control_flow(
            image, (plan.FunctionSpec("selected", 0x1000, 7),), production=False
        )


def test_writable_file_backed_type_descriptor_is_accepted_only_as_rtti_identity(monkeypatch):
    image = _image_with_vftable()
    rdata = bytearray(image.sections[-1].raw)
    rdata[0x4C:0x50] = struct.pack("<I", 0x4860)
    rdata[0xA0:0xA4] = struct.pack("<I", 0x4860)
    image.sections[-1] = pe_analyze.ParsedSection(
        ".rdata", 0x4000, len(rdata), bytes(rdata), _READ
    )
    data = bytearray(b"\0" * 0x80)
    data[0x60:0x70] = struct.pack("<QQ", _BASE + 0x4000, 0)
    data[0x70:0x7A] = b".?AVFoo@@\0"
    image.sections.append(pe_analyze.ParsedSection(
        ".data", 0x4800, len(data), bytes(data), 0xC0000040
    ))
    image.dir64_relocations = tuple(
        item for item in image.dir64_relocations if item.target_rva != 0x4060
    ) + (pe_analyze.ParsedDir64Relocation(0x4860),)
    _patch_exports(monkeypatch)

    proof = flow.analyze_direct_control_flow(
        image, (plan.FunctionSpec("selected", 0x1000, 7),), production=False
    )

    assert proof.direct_reference_gate_passed
    assert proof.indirect_target_closure_proven is False


def test_type_descriptor_vftable_pointer_must_be_retained_read_only_data(monkeypatch):
    image = _image_with_vftable()
    rdata = bytearray(image.sections[-1].raw)
    rdata[0x60:0x68] = struct.pack("<Q", _BASE + 0x1000)
    image.sections[-1] = pe_analyze.ParsedSection(
        ".rdata", 0x4000, len(rdata), bytes(rdata), _READ
    )
    _patch_exports(monkeypatch)

    with pytest.raises(flow.DirectControlFlowError, match="DIR64 address"):
        flow.analyze_direct_control_flow(
            image, (plan.FunctionSpec("selected", 0x1000, 7),), production=False
        )


def test_unterminated_or_unbounded_table_does_not_admit_later_pointer(monkeypatch):
    image = _image_with_vftable()
    rdata = bytearray(image.sections[-1].raw)
    # The next relocation is not an exact function entry, so the callable
    # prefix ends. A later slot must not be reclassified across that gap.
    rdata[0x18:0x20] = struct.pack("<Q", _BASE + 0x4010)
    rdata[0x20:0x28] = struct.pack("<Q", _BASE + 0x1000)
    image.sections[-1] = pe_analyze.ParsedSection(
        ".rdata", 0x4000, len(rdata), bytes(rdata), _READ
    )
    image.dir64_relocations += (
        pe_analyze.ParsedDir64Relocation(0x4018),
        pe_analyze.ParsedDir64Relocation(0x4020),
    )
    _patch_exports(monkeypatch)

    with pytest.raises(flow.DirectControlFlowError, match="DIR64 address"):
        flow.analyze_direct_control_flow(
            image, (plan.FunctionSpec("selected", 0x1000, 7),), production=False
        )
