"""Fail-closed source-link build primitives; no product or VM dependencies."""

from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from lifter import source_link_build as build
from lifter import win64_thunk, x64_lifter
from packer.pe_analyze import IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT


def missing_inputs(tmp_path: Path) -> build.SourceLinkInputs:
    missing = tmp_path / "missing"
    return build.SourceLinkInputs(
        image=missing, pdb=missing, helper_object=missing, link_map=missing,
        symbol="helper", abi="win64:u64(u64)", dia_helper=missing,
        abi_helper=missing, msdia=missing, dumpbin=missing,
        runtime_root=missing,
    )


def test_production_key_path_fails_before_emission(tmp_path):
    output = tmp_path / "output"
    with pytest.raises(build.SourceLinkError, match="production key provisioning"):
        build.emit_fixture(missing_inputs(tmp_path), output)
    assert not output.exists()


@pytest.mark.parametrize("key", [None, b"", b"a" * 31, b"a" * 33])
def test_fixture_key_must_be_explicit_32_bytes(tmp_path, key):
    output = tmp_path / "output"
    with pytest.raises(build.SourceLinkError, match="exactly 32 bytes"):
        build.emit_fixture(
            missing_inputs(tmp_path), output, key_mode="synthetic_fixture",
            synthetic_fixture_key=key,
        )
    assert not output.exists()


def test_map_symbol_requires_exact_object_owner():
    rows = (("helper", 0x140001000, "source.obj"),)
    assert build._unique_map_symbol(rows, "helper", "source.obj") == 0x140001000
    with pytest.raises(build.SourceLinkError, match="absent, duplicated"):
        build._unique_map_symbol(rows + rows, "helper", "source.obj")
    with pytest.raises(build.SourceLinkError, match="owned by another object"):
        build._unique_map_symbol(rows, "helper", "thunk.obj")


def test_map_parser_rejects_unbound_text():
    with pytest.raises(build.SourceLinkError, match="no object-bound symbols"):
        build._map_rows(b"not a linker MAP")


def test_non_fixture_manifest_rejected_before_pe_access(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema": 1, "mode": "production"}')
    missing = tmp_path / "missing"
    with pytest.raises(build.SourceLinkError, match="non-fixture"):
        build.verify_final(manifest, missing, missing, missing, missing, missing, missing)


def test_dynamic_stack_is_not_source_link_admissible():
    with pytest.raises(x64_lifter.LiftUnsupported, match="dynamic source stack pointer"):
        x64_lifter.validate_materialized_stack_window(
            bytes.fromhex("4829CCC3"), base=0x1000,
            window_size=win64_thunk.STACK_WINDOW_SIZE,
        )


def test_entry_thunk_is_symbol_parameterized():
    text = win64_thunk.render_entry_thunk("arbitrary_scalar", "arbitrary_descriptor")
    assert "arbitrary_scalar PROC FRAME" in text
    assert "EXTERN arbitrary_descriptor:BYTE" in text
    assert "vm_scalar" not in text


@pytest.mark.parametrize("label", ["source", "final"])
def test_xfg_source_or_final_fails_closed(label):
    parsed = SimpleNamespace(
        extended_dll_characteristics=IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT,
        load_config=SimpleNamespace(
            has_guard_cf=True, xfg_present=True, unsupported_features=(),
        ),
    )
    with pytest.raises(build.SourceLinkError, match=rf"{label} XFG"):
        build._require_supported_mitigations(parsed, label)


@pytest.mark.parametrize("label", ["source", "final"])
def test_typed_xfg_requires_actual_xfg_metadata(label):
    parsed = SimpleNamespace(
        extended_dll_characteristics=IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT,
        load_config=SimpleNamespace(
            has_guard_cf=True, xfg_present=False, unsupported_features=(),
        ),
    )
    with pytest.raises(build.SourceLinkError, match="requires XFG metadata"):
        build._require_supported_mitigations(parsed, label, typed_xfg=True)


def test_explicit_typed_xfg_still_rejects_unsupported_load_config():
    parsed = SimpleNamespace(
        extended_dll_characteristics=IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT,
        load_config=SimpleNamespace(
            has_guard_cf=True, xfg_present=True,
            unsupported_features=("dynamic_value_relocations",),
        ),
    )
    with pytest.raises(build.SourceLinkError, match="unsupported VM thunk features"):
        build._require_supported_mitigations(parsed, "source", typed_xfg=True)


@pytest.mark.parametrize("typed_xfg,linked_tag,gfid,verified,status", [
    (False, False, None, False, None),
    (True, False, "00", False, "cfg_only_no_linked_xfg_hash"),
    (True, True, "00", True, "linked_xfg_tag_and_gfid_verified_enforcement_unproven"),
    (True, True, "08", False, "selected_target_xfg_metadata_unverified"),
    (True, False, None, False, "selected_target_xfg_metadata_unverified"),
])
def test_selected_target_xfg_status_follows_linked_tag_and_gfid(
        typed_xfg, linked_tag, gfid, verified, status):
    assert build._selected_target_xfg_status(
        typed_xfg=typed_xfg, linked_tag=linked_tag, gfid_metadata=gfid,
    ) == (verified, status)


def test_typed_wrapper_source_is_five_argument_tail_call():
    source = build._render_typed_xfg_wrapper(
        "vm_scalar", "win64:u64(u64,u64,u64,u64,u64)"
    ).decode("ascii")
    assert "__declspec(dllexport) __declspec(noinline)" in source
    assert "uint64_t __cdecl vm_scalar_vm(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);" in source
    assert "return vm_scalar_vm(a0, a1, a2, a3, a4);" in source
    assert "selected_scalar" not in source


def test_typed_manifest_without_compiler_object_fails_before_final_pe(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema": 1, "mode": "synthetic_fixture_only", "typed_xfg_wrapper": true}')
    missing = tmp_path / "missing"
    with pytest.raises(build.SourceLinkError, match="compiler object is required"):
        build.verify_final(manifest, missing, missing, missing, missing, missing, missing)


@pytest.mark.parametrize("label", ["source", "final"])
def test_other_unsupported_load_config_fails_closed(label):
    parsed = SimpleNamespace(
        extended_dll_characteristics=IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT,
        load_config=SimpleNamespace(
            has_guard_cf=True, xfg_present=False,
            unsupported_features=("dynamic_value_relocations",),
        ),
    )
    with pytest.raises(build.SourceLinkError, match=rf"{label} load config"):
        build._require_supported_mitigations(parsed, label)


def test_runtime_header_change_is_bound_by_provenance(tmp_path):
    header = tmp_path / "stub" / "src" / "crypto.h"
    header.parent.mkdir(parents=True)
    header.write_bytes(b"#define FOO 1\n")
    original = build._source_tree_hashes(tmp_path, runtime=True)
    header.write_bytes(b"#define FOO 2\n")
    changed = build._source_tree_hashes(tmp_path, runtime=True)
    assert original["stub/src/crypto.h"] != changed["stub/src/crypto.h"]


def test_loaded_project_module_must_match_declared_source_tree(tmp_path, monkeypatch):
    foreign = tmp_path / "foreign" / "lifter" / "rogue.py"
    foreign.parent.mkdir(parents=True)
    foreign.write_bytes(b"# fake compiler module\n")
    monkeypatch.setitem(sys.modules, "lifter.rogue_proof", SimpleNamespace(__file__=str(foreign)))
    with pytest.raises(build.SourceLinkError, match="differs from runtime root"):
        build._bind_loaded_project_modules(Path(build.__file__).parents[1])


@pytest.mark.parametrize("encoded,width", [
    (0x1014, 4), (0x14, 4), (0x140001014, 8),
])
def test_literal_interior_aliases_reject_even_outside_code(encoded, width):
    raw = bytearray(64)
    raw[48:48 + width] = encoded.to_bytes(width, "little")
    parsed = SimpleNamespace(
        sections=(SimpleNamespace(rva=0x1000, raw=bytes(raw)),),
        image_base=0x140000000,
    )
    with pytest.raises(build.SourceLinkError, match="literal source helper interior alias"):
        build._reject_encoded_interior_aliases(parsed, 0x1010, 16)
