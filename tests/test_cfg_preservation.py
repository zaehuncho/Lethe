"""Guard CF preservation planning and immutable outer metadata emission."""

from __future__ import annotations

import struct
from dataclasses import replace
from types import SimpleNamespace

import pytest

from packer import assemble, cfg_preservation, container, pe_analyze


def _load_config(*, interior: bool = True, unsupported=()):
    targets = [
        pe_analyze.ParsedGuardTarget(0x1000, b"\0"),
        pe_analyze.ParsedGuardTarget(0x2000, b"\0"),
    ]
    if interior:
        targets.insert(1, pe_analyze.ParsedGuardTarget(0x1010, b"\0"))
    return pe_analyze.ParsedLoadConfig(
        directory_rva=0x3000,
        directory_size=320,
        declared_size=320,
        major_version=0,
        minor_version=0,
        guard_flags=0x10000500,
        security_cookie_rva=0x3400,
        guard_cf_check_function_pointer_rva=0x3410,
        guard_cf_dispatch_function_pointer_rva=0x3418,
        guard_cf_function_table_rva=0x3200,
        guard_cf_targets=tuple(targets),
        guard_address_taken_iat_entry_table_rva=0,
        guard_address_taken_iat_entries=(),
        guard_long_jump_target_table_rva=0,
        guard_long_jump_targets=(),
        guard_eh_continuation_table_rva=0,
        guard_eh_continuation_targets=(),
        dynamic_value_relocations_present=(
            "dynamic_value_relocations" in unsupported),
        chpe_metadata_present=("chpe_metadata" in unsupported),
        xfg_present=("xfg" in unsupported),
        unsupported_features=tuple(unsupported),
        raw=b"\0" * 320,
    )


def _parsed(*, interior: bool = True, unsupported=()):
    return SimpleNamespace(
        image_base=0x140000000,
        size_of_image=0x6000,
        section_alignment=0x1000,
        sections=(pe_analyze.ParsedSection(
            ".text", 0x1000, 0x1000, b"\xC3", 0x60000020),),
        oep_rva=0x1000,
        is_dll=False,
        dll_characteristics=0x4160,
        load_config=_load_config(interior=interior, unsupported=unsupported),
    )


def _manifest():
    return SimpleNamespace(functions=(SimpleNamespace(
        target_rva=0x1000,
        target_size=0x20,
        cfg_target_rvas=(),
        generated_executable_ranges=(SimpleNamespace(rva=0x5000, size=0x40),),
        capabilities={"direct_only_thunk": True},
    ),))


def _indirect_target_manifest():
    return SimpleNamespace(functions=(SimpleNamespace(
        target_rva=0x1000,
        target_size=0x20,
        cfg_target_rvas=(0x5000,),
        generated_executable_ranges=(SimpleNamespace(rva=0x5000, size=0x40),),
        capabilities={"direct_only_thunk": False},
    ),))


def test_cfg_plan_retains_source_entry_without_declaring_direct_only_thunk() -> None:
    plan = cfg_preservation.build_cfg_preservation_plan(_parsed(), _manifest())

    assert [target.rva for target in plan.source_targets] == [
        0x1000, 0x1010, 0x2000]
    assert [target.rva for target in plan.retained_source_targets] == [
        0x1000, 0x2000]
    assert [target.rva for target in plan.removed_tombstoned_interior_targets] == [
        0x1010]
    assert plan.generated_thunk_targets == ()
    assert [target.rva for target in plan.merged_declared_targets] == [
        0x1000, 0x2000]
    assert plan.preservation_supported is False
    assert any("tombstoned interiors" in blocker for blocker in plan.blockers)


def test_guard_cf_plan_claims_only_the_implemented_runtime_contract() -> None:
    plan = cfg_preservation.build_cfg_preservation_plan(
        _parsed(interior=False), _manifest())

    assert plan.live_load_config_emitted is True
    assert plan.guard_pointer_initialization_proven is True
    assert plan.runtime_target_registration_proven is True
    assert plan.preservation_supported is True
    assert plan.blockers == ()


def test_unsupported_source_features_are_preserved_as_precise_blockers() -> None:
    plan = cfg_preservation.build_cfg_preservation_plan(
        _parsed(interior=False, unsupported=(
            "dynamic_value_relocations", "chpe_metadata")),
        _manifest(),
    )
    assert plan.unsupported_source_features == (
        "dynamic_value_relocations", "chpe_metadata")
    assert "dynamic_value_relocations, chpe_metadata" in plan.blockers[-1]


def test_non_guard_source_does_not_invent_cfg_activation() -> None:
    parsed = SimpleNamespace(dll_characteristics=0, load_config=None)
    plan = cfg_preservation.build_cfg_preservation_plan(parsed, _manifest())

    assert plan.source_guard_cf_enabled is False
    assert plan.generated_thunk_targets == ()
    assert plan.preservation_supported is True
    assert plan.live_load_config_emitted is False


def test_present_non_guard_load_config_is_not_silently_dropped() -> None:
    load_config = replace(
        _load_config(interior=False),
        guard_flags=0,
        guard_cf_check_function_pointer_rva=0,
        guard_cf_dispatch_function_pointer_rva=0,
        guard_cf_function_table_rva=0,
        guard_cf_targets=(),
    )
    parsed = SimpleNamespace(dll_characteristics=0, load_config=load_config)

    plan = cfg_preservation.build_cfg_preservation_plan(parsed)

    assert plan.source_load_config_present is True
    assert plan.source_guard_cf_enabled is False
    assert plan.preservation_supported is True
    assert plan.live_load_config_emitted is True
    assert cfg_preservation.require_cfg_preservation_supported(parsed) == plan


def test_global_xfg_preserves_source_identity_for_direct_only_thunk() -> None:
    load_config = replace(
        _load_config(interior=False),
        xfg_present=True,
        guard_cf_targets=(
            pe_analyze.ParsedGuardTarget(0x1000, b"\0"),
            pe_analyze.ParsedGuardTarget(0x2000, b"\0"),
        ),
    )
    parsed = _parsed(interior=False)
    parsed.load_config = load_config

    plan = cfg_preservation.build_cfg_preservation_plan(parsed, _manifest())

    assert plan.preservation_supported is True
    assert plan.generated_thunk_targets == ()
    assert [target.rva for target in plan.merged_declared_targets] == [
        0x1000, 0x2000]
    assert plan.blockers == ()


def test_direct_only_xfg_retains_selected_source_metadata_byte_exact() -> None:
    source_targets = (
        pe_analyze.ParsedGuardTarget(0x1000, b"\x08"),
        pe_analyze.ParsedGuardTarget(0x2000, b"\x02"),
    )
    parsed = _parsed(interior=False)
    parsed.load_config = replace(
        parsed.load_config,
        xfg_present=True,
        guard_cf_targets=source_targets,
    )

    plan = cfg_preservation.build_cfg_preservation_plan(parsed, _manifest())

    assert plan.preservation_supported is True
    assert plan.source_targets == tuple(
        cfg_preservation.PlannedCfgTarget(target.rva, target.metadata, "source")
        for target in source_targets
    )
    assert plan.retained_source_targets == plan.source_targets
    assert plan.merged_declared_targets == plan.source_targets
    assert plan.generated_thunk_targets == ()


def test_global_xfg_crafted_generated_gfid_fails_closed() -> None:
    load_config = replace(
        _load_config(interior=False),
        xfg_present=True,
        guard_cf_targets=(
            pe_analyze.ParsedGuardTarget(0x1000, b"\0"),
            pe_analyze.ParsedGuardTarget(0x2000, b"\0"),
        ),
    )
    parsed = _parsed(interior=False)
    parsed.load_config = load_config

    plan = cfg_preservation.build_cfg_preservation_plan(
        parsed, _indirect_target_manifest())

    assert plan.preservation_supported is False
    assert [target.rva for target in plan.generated_thunk_targets] == [0x5000]
    assert any("8-byte XFG function hashes" in blocker for blocker in plan.blockers)


def test_direct_only_thunk_rejects_sideband_generated_cfg_inventory() -> None:
    parsed = _parsed(interior=False)
    parsed.generated_cfg_targets = (
        pe_analyze.ParsedGuardTarget(0x5000, b"\0"),
    )

    with pytest.raises(ValueError, match="direct-only.*generated CFG inventory"):
        cfg_preservation.build_cfg_preservation_plan(parsed, _manifest())


def test_suppressed_source_targets_are_preserved_by_outer_loader_metadata() -> None:
    load_config = replace(
        _load_config(interior=False),
        guard_cf_targets=(
            pe_analyze.ParsedGuardTarget(0x1000, b"\x01"),
            pe_analyze.ParsedGuardTarget(0x2000, b"\x02"),
        ),
    )
    parsed = _parsed(interior=False)
    parsed.load_config = load_config

    plan = cfg_preservation.build_cfg_preservation_plan(parsed)

    assert plan.preservation_supported is True
    assert [target.metadata for target in plan.merged_declared_targets] == [
        b"\x01", b"\x02"]


def test_default_assembler_rejects_unsupported_load_config_before_output(tmp_path) -> None:
    output = tmp_path / "must-not-exist.exe"
    artifacts = SimpleNamespace(is_dll=False)
    parsed = _parsed(
        interior=False, unsupported=("dynamic_value_relocations",))

    with pytest.raises(assemble.AssembleError, match="Guard CF preservation blocked") \
            as rejected:
        assemble.build_output_pe(
            parsed,
            artifacts,
            str(output),
        )

    assert rejected.value.preservation_plan.source_guard_cf_enabled is True
    assert rejected.value.preservation_plan.unsupported_source_features == (
        "dynamic_value_relocations",)
    assert output.exists() is False


def test_guard_cf_with_memory_guard_fails_before_stub_or_output(tmp_path) -> None:
    output = tmp_path / "must-not-exist.exe"
    artifacts = SimpleNamespace(
        is_dll=False, flags=container.FLAG_MEMGUARD)

    with pytest.raises(assemble.AssembleError, match="memory guard") as rejected:
        assemble.build_output_pe(
            _parsed(interior=False), artifacts, str(output))

    assert rejected.value.preservation_plan.source_guard_cf_enabled is True
    assert output.exists() is False


def test_live_load_config_merges_outer_targets_and_shadows_os_slots() -> None:
    parsed = _parsed(interior=False)
    source = bytearray(0x1000)
    for rva, value in (
        (0x3400, 0x1122334455667788),
        (0x3410, parsed.image_base + 0x2100),
        (0x3418, parsed.image_base + 0x2200),
    ):
        source[rva - 0x3000:rva - 0x3000 + 8] = value.to_bytes(8, "little")
    parsed.sections = [pe_analyze.ParsedSection(
        ".data", 0x3000, 0x1000, bytes(source), 0xC0000040)]
    plan = cfg_preservation.build_cfg_preservation_plan(
        parsed, _manifest())

    live = cfg_preservation.build_live_load_config(
        parsed, plan, section_rva=0x7000, image_base=parsed.image_base,
        outer_target_rvas=(0x8000,))

    assert live is not None
    table_va = int.from_bytes(live.data[128:136], "little")
    table_rva = table_va - parsed.image_base
    count = int.from_bytes(live.data[136:144], "little")
    assert count == 3
    table_offset = table_rva - live.section_rva
    entries = [
        int.from_bytes(live.data[table_offset + i * 5:table_offset + i * 5 + 4],
                       "little")
        for i in range(count)
    ]
    assert entries == [0x1000, 0x2000, 0x8000]
    assert [copy.source_rva for copy in live.runtime_slot_copies] == [
        0x3400, 0x3410, 0x3418]
    assert live.directory_rva == 0x7000
    assert live.directory_size == 320
    assert all(target >= 0x7000 for target in live.relocation_target_rvas)


def test_runtime_recipe_carries_slots_and_exact_target_flags() -> None:
    slots = (
        cfg_preservation.RuntimeSlotCopy(0x3400, 0x7200, "cookie"),
        cfg_preservation.RuntimeSlotCopy(0x3410, 0x7208, "check"),
    )
    targets = (
        cfg_preservation.PlannedCfgTarget(0x1000, b"\0", "source"),
        cfg_preservation.PlannedCfgTarget(0x2000, b"\x08", "source"),
    )

    live_data = bytearray(0x220)
    struct.pack_into("<Q", live_data, 0x80, 0x140000000 + 0x7100)
    live = cfg_preservation.LiveLoadConfigImage(
        image_base=0x140000000,
        section_rva=0x7000,
        directory_rva=0x7000,
        directory_size=0x140,
        data=bytes(live_data),
        relocation_target_rvas=(0x7080, 0x7200, 0x7208),
        runtime_slot_copies=slots,
    )
    blob = cfg_preservation.build_runtime_slot_blob(
        slots,
        targets,
        live_load_config=live,
        dll_characteristics=0x4160,
    )
    (
        magic,
        version,
        slot_count,
        target_count,
        relocation_count,
        dll_characteristics,
        directory_rva,
        directory_size,
        section_rva,
        section_size,
        section_characteristics,
        section_sha256,
    ) = cfg_preservation.RUNTIME_HEADER.unpack_from(blob)

    assert magic == cfg_preservation.RUNTIME_MAGIC
    assert version == cfg_preservation.RUNTIME_VERSION
    assert (slot_count, target_count) == (2, 2)
    assert relocation_count == 3
    assert dll_characteristics == 0x4160
    assert (directory_rva, directory_size) == (0x7000, 0x140)
    assert (section_rva, section_size, section_characteristics) == (
        0x7000,
        len(live_data),
        cfg_preservation.LIVE_SECTION_CHARACTERISTICS,
    )
    assert len(section_sha256) == 32 and any(section_sha256)
    target_offset = cfg_preservation.RUNTIME_HEADER.size + (
        slot_count * cfg_preservation.RUNTIME_ENTRY.size)
    assert cfg_preservation.RUNTIME_TARGET.unpack_from(blob, target_offset) == (
        0x1000, 0)
    assert cfg_preservation.RUNTIME_TARGET.unpack_from(
        blob, target_offset + cfg_preservation.RUNTIME_TARGET.size) == (
            0x2000, 0x08)
    relocation_offset = target_offset + (
        target_count * cfg_preservation.RUNTIME_TARGET.size
    )
    assert [
        cfg_preservation.RUNTIME_RELOCATION.unpack_from(
            blob,
            relocation_offset + index * cfg_preservation.RUNTIME_RELOCATION.size,
        )[0]
        for index in range(relocation_count)
    ] == [0x7080, 0x7200, 0x7208]
