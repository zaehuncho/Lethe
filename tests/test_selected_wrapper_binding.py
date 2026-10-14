"""Mandatory consumed-wrapper API and conservative transformation contracts."""
from dataclasses import replace
import inspect
from pathlib import Path
import struct
from types import SimpleNamespace as NS

import pytest

from lifter import direct_control_flow as flow, win64_thunk
from lifter import product_fixture_link_verify as public
from lifter import selected_wrapper_binding as binding
from lifter import link_capture_final_callsites as conventional


def _object(symbol, code=b"\x33\xc0\xc3", *, target=None, flags=0x60000020):
    names = [symbol] + ([target] if target else [])
    codepos = 60
    reloc = codepos + len(code) if target else 0
    sympos = codepos + len(code) + (10 if target else 0)
    strings = bytearray(b"\0\0\0\0")
    fields = []
    for name in names:
        fields.append(b"\0\0\0\0" + struct.pack("<I", len(strings)))
        strings.extend(name.encode() + b"\0")
    struct.pack_into("<I", strings, 0, len(strings))
    raw = bytearray(sympos + 18 * len(names) + len(strings))
    struct.pack_into("<HHIIIHH", raw, 0, 0x8664, 1, 0, sympos, len(names), 0, 0)
    raw[20:28] = b".text\0\0\0"
    struct.pack_into("<III", raw, 36, len(code), codepos, reloc)
    struct.pack_into("<H", raw, 52, bool(target))
    struct.pack_into("<I", raw, 56, flags)
    raw[codepos:codepos + len(code)] = code
    if target:
        struct.pack_into("<IIH", raw, reloc, len(code) - 4, 1, 4)
    for index, field in enumerate(fields):
        pos = sympos + index * 18
        raw[pos:pos + 8] = field
        struct.pack_into("<IhHBB", raw, pos + 8, 0, 1 if index == 0 else 0, 0x20, 2, 0)
    raw[sympos + 18 * len(names):] = strings
    return bytes(raw)


def _inputs(prefix="policy_vm"):
    names = (prefix + "_wrapper.obj", prefix + ".obj", prefix + "_data.obj", *binding._RUNTIME_OBJECTS)
    return binding.SelectedWrapperLinkInputs(Path("original"), tuple(Path(n) for n in names))


def test_public_requires_selected_reference_inputs_before_any_io():
    param = inspect.signature(public.verify_product_fixture_final_link).parameters["selected_reference_inputs"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY and param.default is inspect.Parameter.empty
    with pytest.raises(TypeError, match="selected_reference_inputs"):
        public.verify_product_fixture_final_link(None, None, None, None, synthetic_fixture_key=b"x" * 32)
    with pytest.raises(public.ProductLinkProofError, match="exact selected wrapper"):
        public.verify_product_fixture_final_link(None, None, None, None,
            synthetic_fixture_key=b"x" * 32, selected_reference_inputs=None)


@pytest.mark.parametrize("bad", [None, {}, NS(), (Path("x"),),
    binding.SelectedWrapperLinkInputs(Path("x"), []),
    replace(_inputs(), generated_inputs=_inputs().generated_inputs[:-1]),
    replace(_inputs(), generated_inputs=(Path("same.obj"),) * 11),
    replace(_inputs(), native_initializer_object="init.obj"),
])
def test_untyped_or_ambiguous_required_inputs_reject(bad):
    with pytest.raises(binding.SelectedWrapperProofError):
        binding.validate_inputs(bad)


@pytest.mark.parametrize("prefix", ["policy_vm", "lease_vm"])
def test_exact_wrapper_object_tail_is_bound(prefix):
    code = (bytes.fromhex("0fb644242888442428") if prefix == "policy_vm" else b"") + b"\xe9\0\0\0\0"
    binding._wrapper_coff(_object("selected", code, target=prefix), "selected", prefix)


@pytest.mark.parametrize("change", ["body", "target", "reloc_kind", "reloc_field", "addend", "definition", "data_definition"])
def test_wrapper_coff_mutations_reject(change):
    raw = bytearray(_object("selected", b"\xe9\0\0\0\0", target="lease_vm"))
    if change == "body": raw[60] = 0xE8
    elif change == "target": raw[-9:-1] = b"evil____"
    elif change == "reloc_kind": struct.pack_into("<H", raw, 73, 5)
    elif change == "reloc_field": struct.pack_into("<I", raw, 65, 0)
    elif change == "addend": raw[61] = 1
    elif change == "definition": struct.pack_into("<I", raw, 83, 1)
    elif change == "data_definition": struct.pack_into("<I", raw, 56, 0x40000040)
    with pytest.raises((binding.SelectedWrapperProofError, ValueError)):
        binding._wrapper_coff(bytes(raw), "selected", "lease_vm")


@pytest.mark.parametrize("code", [b"\x33\xc0\xc3", b"\x31\xc0\xc3"])
def test_native_initializer_is_exact_noop(code):
    binding._native_initializer(_object("lease_vm_fixture_init", code), "lease_vm_fixture_init")


@pytest.mark.parametrize("code,flags", [(b"\xc3", 0x60000020), (b"\xb8\x01\0\0\0\xc3", 0x60000020),
    (b"\x33\xc0\xc3\x90", 0x60000020), (b"\x33\xc0\xc3", 0x40000040)])
def test_native_initializer_extra_behavior_or_noncode_reject(code, flags):
    with pytest.raises(ValueError):
        binding._native_initializer(_object("lease_vm_fixture_init", code, flags=flags), "lease_vm_fixture_init")


def _parsed_thunk():
    rva, common, descriptor, base = 0x1000, 0x2000, 0x4000, 0x140000000
    code = bytearray(win64_thunk.THUNK_TEMPLATE)
    struct.pack_into("<i", code, 9, common - rva - 13)
    struct.pack_into("<Q", code, 15, base + descriptor)
    parsed = NS(image_base=base, sections=[
        NS(name=".text", rva=rva, virtual_size=len(code), raw=bytes(code), characteristics=0x60000020),
        NS(name=".text2", rva=common, virtual_size=1, raw=b"\xc3", characteristics=0x60000020),
        NS(name=".xdata", rva=0x3000, virtual_size=12, raw=win64_thunk.THUNK_UNWIND_INFO, characteristics=0x40000040),
    ], runtime_functions=[NS(begin_rva=rva, end_rva=rva + 46, unwind_info_rva=0x3000),
        NS(begin_rva=common, end_rva=common + 1, unwind_info_rva=0x3000)],
        dir64_relocations=[NS(target_rva=rva + 15)], load_config=NS(guard_cf_targets=[]))
    return parsed, flow._EntryThunkRange(rva, common, descriptor)


def test_structured_thunk_metadata_preserves_exact_extent_and_code_starts():
    parsed, thunk = _parsed_thunk()
    result = flow._entry_thunk_decodes(parsed, flow._normalize_sections(parsed), (thunk,))
    decoded = result[(0x1000, 0x102E)]
    assert len(decoded.instructions) == 12
    assert not any(0x100F <= rva < 0x1017 for rva in decoded.starts)


@pytest.mark.parametrize("change", ["pdata", "unwind", "missing_reloc", "duplicate_reloc", "cross_left", "cross_right", "internal_guard"])
def test_structured_thunk_metadata_mutations_reject(change):
    parsed, thunk = _parsed_thunk()
    if change == "pdata": parsed.runtime_functions[0].end_rva -= 1
    elif change == "unwind": parsed.sections[2].raw = bytes(12)
    elif change == "missing_reloc": parsed.dir64_relocations = []
    elif change == "duplicate_reloc": parsed.dir64_relocations *= 2
    elif change == "cross_left": parsed.dir64_relocations.append(NS(target_rva=0x100E))
    elif change == "cross_right": parsed.dir64_relocations.append(NS(target_rva=0x1010))
    elif change == "internal_guard": parsed.load_config.guard_cf_targets = [NS(rva=0x1010)]
    with pytest.raises(flow.DirectControlFlowError):
        flow._entry_thunk_decodes(parsed, flow._normalize_sections(parsed), (thunk,))


def test_conventional_dir64_rejection_is_not_weakened_by_thunk_profile():
    parsed, _ = _parsed_thunk()
    with pytest.raises(conventional.FinalCallsiteError, match="DIR64"):
        conventional._reject_executable_dir64(parsed, flow._normalize_sections(parsed))


def test_incoming_branch_into_structured_data_island_rejects():
    parsed, thunk = _parsed_thunk()
    decoded = flow._entry_thunk_decodes(parsed, flow._normalize_sections(parsed), (thunk,))[(0x1000, 0x102E)]
    from iced_x86 import Decoder
    source = tuple(Decoder(64, b"\xe8" + struct.pack("<i", 0x100F - 0x2505), ip=0x2500))
    caller = flow._RuntimeDecode(0x2500, 0x2505, source, frozenset({0x2500}))
    with pytest.raises(flow.DirectControlFlowError, match="non-instruction"):
        flow._validate_direct_targets((decoded, caller), ())


def _debug_types(records):
    raw = bytearray(_object("unrelated", b"\x04\0\0\0" + records, flags=0x40000040))
    raw[20:28] = b".debug$T"
    return bytes(raw)


def test_inline_z7_type_record_is_not_a_type_server():
    binding._reject_other_typeservers(_debug_types(struct.pack("<HHI", 6, 0x1001, 0)), "ordinary_amd64_coff")


@pytest.mark.parametrize("leaf", [0x1515, 0x1501, 0x0016])
@pytest.mark.parametrize("path", [b"D:\\owned\\vc143.pdb", b"D:/owned/vc143.pdb", b"D:\\owned\\.\\vc143.pdb", b"D:\\OWNED~1\\vc143.pdb"])
def test_any_retained_type_server_including_alias_spelling_rejects(leaf, path):
    payload = struct.pack("<H", leaf) + b"x" * 16 + struct.pack("<I", 1) + path + b"\0"
    record = struct.pack("<H", len(payload)) + payload
    with pytest.raises(binding.SelectedWrapperProofError, match="type server"):
        binding._reject_other_typeservers(_debug_types(record), "ordinary_amd64_coff")


@pytest.mark.parametrize("record", [b"\0", b"\x06\0\x01", b"\x01\0\x01\x10", b"\xff\xff\x01\x10"])
def test_malformed_retained_type_record_rejects(record):
    with pytest.raises(binding.SelectedWrapperProofError):
        binding._reject_other_typeservers(_debug_types(record), "ordinary_amd64_coff")


def _entry():
    return binding._MaterializedWrapperEntry("selected", "lease_vm", 0x800, 5,
        0x1000, 0x2000, 0x4000, "a" * 64, "b" * 64, "c" * 64)


def _edge(source, target, kind="jump", reachable=False):
    return NS(source_rva=source, target_rva=target, kind=kind,
              reachable_from_selected_entry=reachable)


def test_only_exact_reachable_wrapper_tail_enters_thunk():
    edges = (_edge(0x800, 0x1000, reachable=True),
             _edge(0x100D, 0x1017), _edge(0x101B, 0x1027, "conditional_jump"))
    binding._thunk_direct_entries(NS(direct_transfers=edges), _entry())


@pytest.mark.parametrize("target", [0x1000, 0x1001, 0x100F, 0x1016, 0x1017, 0x1027, 0x102D])
def test_other_external_thunk_entries_reject(target):
    edges = (_edge(0x800, 0x1000, reachable=True), _edge(0x3000, target, "call"))
    with pytest.raises(binding.SelectedWrapperProofError):
        binding._thunk_direct_entries(NS(direct_transfers=edges), _entry())


def test_unreachable_or_nonjump_wrapper_tail_does_not_authorize_thunk():
    for edge in (_edge(0x800, 0x1000), _edge(0x800, 0x1000, "call", True)):
        with pytest.raises(binding.SelectedWrapperProofError):
            binding._thunk_direct_entries(NS(direct_transfers=(edge,)), _entry())


def _extra_section(name, data, flags=0x40000040):
    symbol = b"lease_vm_fixture_init\0"
    first, second = 100, 103
    sympos = second + len(data)
    raw = bytearray(sympos + 18 + 4 + len(symbol))
    struct.pack_into("<HHIIIHH", raw, 0, 0x8664, 2, 0, sympos, 1, 0, 0)
    raw[20:28] = b".text\0\0\0"
    struct.pack_into("<II", raw, 36, 3, first)
    struct.pack_into("<I", raw, 56, 0x60000020)
    raw[60:68] = name.ljust(8, b"\0")
    struct.pack_into("<II", raw, 76, len(data), second)
    struct.pack_into("<I", raw, 96, flags)
    raw[first:second] = b"\x33\xc0\xc3"
    raw[second:sympos] = data
    raw[sympos:sympos + 8] = b"\0" * 4 + struct.pack("<I", 4)
    struct.pack_into("<IhHBB", raw, sympos + 8, 0, 1, 0x20, 2, 0)
    struct.pack_into("<I", raw, sympos + 18, 4 + len(symbol))
    raw[sympos + 22:] = symbol
    return bytes(raw)


@pytest.mark.parametrize("name,data,flags", [
    (b".CRT$XCU", bytes(8), 0x40000040),
    (b".rdata", b"hidden", 0x40000040),
    (b".text$x", b"\xc3", 0x60000020),
    (b".drectve", b"/INCLUDE:hidden_startup_behavior", 0x00100A00),
    (b".drectve", b"/DEFAULTLIB:unknown", 0x00100A00),
    (b".chks64", bytes(8), 0x40000040),
    (b".gxfg$y", bytes(16), 0x40501040),
])
def test_native_initializer_hidden_runtime_or_directive_behavior_rejects(name, data, flags):
    with pytest.raises(ValueError):
        binding._native_initializer(_extra_section(name, data, flags), "lease_vm_fixture_init")


def test_retained_long_coff_section_name_cannot_hide_typeserver():
    payload = struct.pack("<HH", 22, 0x1515) + b"x" * 20
    raw = bytearray(_debug_types(payload))
    raw[20:28] = b"/4\0\0\0\0\0\0"
    symptr, count = struct.unpack_from("<II", raw, 8)
    strings = symptr + count * 18
    raw[strings:] = struct.pack("<I", 13) + b".debug$T\0"
    with pytest.raises(binding.SelectedWrapperProofError, match="type server"):
        binding._reject_other_typeservers(bytes(raw), "ordinary_amd64_coff")


def test_valid_long_non_debug_section_name_is_resolved_not_waived():
    raw = bytearray(_object("name"))
    raw[20:28] = b"/4\0\0\0\0\0\0"
    symptr, count = struct.unpack_from("<II", raw, 8)
    name = b".text$mn$00\0"
    raw[symptr + count * 18:] = struct.pack("<I", 4 + len(name)) + name
    assert binding._coff_section_names(bytes(raw), "ordinary_amd64_coff") == (b".text$mn$00",)
    binding._reject_other_typeservers(bytes(raw), "ordinary_amd64_coff")


@pytest.mark.parametrize("field", [b"/0", b"/3", b"/999999", b"/nope", b"//abcd"])
def test_long_section_malformed_or_out_of_bounds_offset_rejects(field):
    raw = bytearray(_object("name"))
    raw[20:28] = field.ljust(8, b"\0")
    with pytest.raises(binding.SelectedWrapperProofError):
        binding._coff_section_names(bytes(raw), "ordinary_amd64_coff")


def test_long_section_unterminated_string_rejects():
    raw = bytearray(_object("name"))
    raw[20:28] = b"/4\0\0\0\0\0\0"
    raw[-1] = 0x41
    with pytest.raises(binding.SelectedWrapperProofError, match="unterminated"):
        binding._coff_section_names(bytes(raw), "ordinary_amd64_coff")
