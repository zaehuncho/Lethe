"""Retained PDATA is extent metadata, not a native CALL parity proof."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from keystone import KS_ARCH_X86, KS_MODE_64, Ks

from lifter import function_discovery, virtualization_plan as plan

_KS = Ks(KS_ARCH_X86, KS_MODE_64)
_EXEC = 0x60000020


def _asm(source: str, rva: int) -> bytes:
    encoded, _ = _KS.asm(source, addr=rva)
    return bytes(encoded)


def _fixture():
    caller = _asm("sub rsp,0x28; call 0x1100; add rsp,0x28; ret", 0x1000)
    callee = _asm("mov eax,42; ret", 0x1100)
    raw = bytearray(b"\xCC" * 0x200)
    raw[:len(caller)] = caller
    raw[0x100:0x100 + len(callee)] = callee
    section = plan.SectionBytes(".text", 0x1000, len(raw), bytes(raw), _EXEC)
    records = (
        plan.SourceRuntimeFunction(0x1000, 0x1000 + len(caller), 0x3000),
        plan.SourceRuntimeFunction(0x1100, 0x1100 + len(callee), 0x3010),
    )
    return caller, section, records


def test_direct_pdata_call_rejects_with_or_without_section_geometry() -> None:
    caller, section, records = _fixture()
    spec = plan.FunctionSpec("caller", 0x1000, len(caller))
    metadata = plan.SourceExceptionMetadata(0x3000, records)
    for reader in (
        plan.SectionImage((section,)),
        SimpleNamespace(read_file_backed_executable=lambda rva, size: caller),
    ):
        with pytest.raises(plan.FunctionRejected, match="retained PDATA native CALL lacks physical return-slot"):
            plan.compile_virtualization_manifest(
                (spec,), reader, generated_text_rva=0x4000,
                generated_data_rva=0x5000, source_exception_metadata=metadata,
            )


def test_private_compile_entry_cannot_reinstate_retained_target() -> None:
    caller, section, _records = _fixture()
    spec = plan.FunctionSpec("caller", 0x1000, len(caller))
    with pytest.raises(plan.FunctionRejected, match="caller-supplied native CALL targets"):
        plan._compile_one(
            spec, plan.SectionImage((section,)), rolling=False,
            rolling_seed=None, opcode_table=plan.OpcodeTable.canonical(),
            image_sections=None, selected_extents=((0x1000, len(caller)),),
            native_call_targets=frozenset({0x1100}),
        )


def test_discovery_does_not_advertise_retained_pdata_caller() -> None:
    caller, section, records = _fixture()
    parsed = SimpleNamespace(
        path="retained-pdata.exe", image_base=0x140000000,
        size_of_image=0x5000, sections=(section,),
        pdata_rva=0x3000, pdata_count=len(records),
        runtime_functions=records,
    )
    report = function_discovery.discover_functions(parsed, exports=())
    selected = {item["rva"] for item in report.starter_selection_manifest()["functions"]}
    assert 0x1000 not in selected
    caller_status = next(item for item in report.candidates if item.rva == 0x1000)
    assert not caller_status.liftable
    assert "retained PDATA native CALL lacks physical return-slot" in caller_status.rejection_reason
