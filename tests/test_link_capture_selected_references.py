"""Fail-closed selected COFF references, aliases and omission contracts."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import struct

import pytest

from lifter import link_capture_selected_references as selected


SYMBOL = "?allowedRuntime@AutomationAccessPolicy@orion@@SA_N_N0000@Z"


def _coff(code: bytes = b"\xe8\0\0\0\0\xc3", *, kind: int = 4,
          flags: int = 0x60000020, addend: int = 0,
          defined: bool = False, directive: bytes | None = None) -> bytes:
    """One bounded AMD64 section and exact target symbol/relocation."""
    sections = 1 + (directive is not None)
    header_end = 20 + 40 * sections
    dataoff = header_end
    relocation_off = dataoff + len(code)
    directive_off = relocation_off + (0 if defined else 10)
    symptr = directive_off + (len(directive) if directive else 0)
    encoded = SYMBOL.encode("ascii") + b"\0"
    raw = bytearray(symptr + 18 + 4 + len(encoded))
    struct.pack_into("<HHIIIHH", raw, 0, 0x8664, sections, 0, symptr, 1, 0, 0)
    raw[20:28] = b".text\0\0\0"
    struct.pack_into("<III", raw, 20 + 16,
                     len(code), dataoff, 0 if defined else relocation_off)
    struct.pack_into("<H", raw, 20 + 32, 0 if defined else 1)
    struct.pack_into("<I", raw, 20 + 36, flags)
    raw[dataoff:dataoff + len(code)] = code
    if not defined:
        struct.pack_into("<IIH", raw, relocation_off, 1, 0, kind)
    if directive is not None:
        off = 60
        raw[off:off + 8] = b".drectve"
        struct.pack_into("<III", raw, off + 16,
                         len(directive), directive_off, 0)
        struct.pack_into("<I", raw, off + 36, 0x00100A00)
        raw[directive_off:directive_off + len(directive)] = directive
    raw[symptr:symptr + 8] = b"\0" * 4 + struct.pack("<I", 4)
    struct.pack_into("<IhHBB", raw, symptr + 8,
                     0, 1 if defined else 0, 0x20, 2, 0)
    string_start = symptr + 18
    struct.pack_into("<I", raw, string_start, 4 + len(encoded))
    raw[string_start + 4:] = encoded
    if addend:
        struct.pack_into("<i", raw, dataoff + 1, addend)
    return bytes(raw)


def _scan(raw: bytes):
    return selected._scan_object("caller.obj", raw, "ordinary_amd64_coff", SYMBOL,
                                 helper_name="helper.obj")


def test_exact_reachable_rel32_call_is_classified():
    report = _scan(_coff())
    assert len(report["references"]) == 1
    assert report["references"][0]["classification"] == (
        "decoded_call_rel32_zero_addend")
    assert report["definitions"] == []


@pytest.mark.parametrize("mutated,reason", [
    (_coff(kind=0x5), "zero-addend AMD64 REL32 E8"),
    (_coff(addend=1), "zero-addend AMD64 REL32 E8"),
    (_coff(code=b"\xe9\0\0\0\0\xc3"), "zero-addend AMD64 REL32 E8"),
    (_coff(flags=0x40000040), "non-executable or address-taken"),
    (_coff(code=b"\xeb\x05\xe8\0\0\0\0\xc3"),
     "zero-addend AMD64 REL32 E8"),
])
def test_wrong_kind_addend_branch_or_data_reference_reject(mutated, reason):
    with pytest.raises(selected.SelectedReferenceError, match=reason):
        _scan(mutated)


def test_decoded_call_must_be_reachable_from_section_entry():
    # The relocation targets the E8 displacement at offset three, but an
    # unconditional jump skips it. Linear decode alone would accept it.
    raw = bytearray(_coff(code=b"\xeb\x05\xe8\0\0\0\0\xc3"))
    struct.pack_into("<I", raw, 20 + 24, 68)
    struct.pack_into("<IIH", raw, 68, 3, 0, 4)
    with pytest.raises(selected.SelectedReferenceError,
                       match="unbounded branch|unreachable encoded bytes"):
        _scan(bytes(raw))


def test_linker_directive_alias_to_selected_symbol_rejects():
    body = b"/alternatename:?alternate=" + SYMBOL.encode("ascii")
    with pytest.raises(selected.SelectedReferenceError,
                       match="linker directive/alternate"):
        _scan(_coff(directive=body))


def test_weak_external_target_alias_rejects():
    raw = _coff()
    symptr = struct.unpack_from("<I", raw, 8)[0]
    old_strings = symptr + 18
    changed = bytearray(raw[:old_strings] + bytes(36) + raw[old_strings:])
    struct.pack_into("<I", changed, 12, 3)
    changed[symptr + 18:symptr + 26] = b"ALIAS\0\0\0"
    struct.pack_into("<IhHBB", changed, symptr + 26, 0, 0, 0, 105, 1)
    struct.pack_into("<I", changed, symptr + 36, 0)  # target symbol index
    with pytest.raises(selected.SelectedReferenceError, match="weak external"):
        _scan(bytes(changed))


def test_duplicate_or_competing_definition_rejects_at_capture_boundary(monkeypatch):
    source = {"source_body_and_abi_verified": True, "symbol": SYMBOL,
              "source_coff_sha256": sha256(_coff(defined=True)).hexdigest()}
    item = {"identity": "helper.obj", "kind": "ordinary_amd64_coff",
            "sha256": source["source_coff_sha256"]}
    monkeypatch.setattr(selected, "inspect_source", lambda _: source)
    monkeypatch.setattr(selected, "inspect_capture_inputs",
                        lambda _: {"inputs": [item], "link_rsp_sha256": "a" * 64, "switches": []})
    monkeypatch.setattr(selected, "_scan_inventory",
                        lambda *_: ([{"object": "helper.obj", "section": 1,
                                     "value": 0},
                                    {"object": "other.obj", "section": 1,
                                     "value": 0}], [{"object": "caller.obj"}], [],
                                   selected.Counter()))
    inputs = type("Inputs", (), {"symbol": SYMBOL,
                                  "helper_object": Path("helper.obj")})()
    with pytest.raises(selected.SelectedReferenceError,
                       match="competing definition"):
        selected.inspect_selected_capture(Path("capture"), inputs)


def test_original_object_omission_rejects_stale_or_other_input_delta(monkeypatch,
                                                                     tmp_path):
    old = _coff(defined=True)
    replacement = _coff(code=b"\xc3", defined=True)
    old_hash, new_hash = (sha256(x).hexdigest() for x in (old, replacement))
    original = {"selected_input_references_classified": True,
                "selected": SYMBOL, "helper_object": "helper.obj",
                "source_coff_sha256": old_hash,
                "capture_input_hashes": {"helper.obj": old_hash,
                                         "other.obj": "b" * 64}}
    item = {"identity": "helper.obj", "kind": "ordinary_amd64_coff",
            "sha256": new_hash}
    inventory = {"inputs": [item, {"identity": "other.obj",
                                   "sha256": "b" * 64,
                                   "kind": "ordinary_amd64_coff"}],
                 "link_rsp_sha256": "c" * 64}
    monkeypatch.setattr(selected, "inspect_capture_inputs", lambda _: inventory)
    monkeypatch.setattr(selected, "_capture_root", lambda _: tmp_path)
    monkeypatch.setattr(selected, "_capture_regular_file", lambda *_: replacement)
    result = selected.inspect_replacement_omission(original, tmp_path)
    assert result["original_helper_object_omission_proven"] is True
    assert result["production_admitted"] is False
    inventory["inputs"][0]["sha256"] = old_hash
    with pytest.raises(selected.SelectedReferenceError, match="not exact"):
        selected.inspect_replacement_omission(original, tmp_path)
    inventory["inputs"][0]["sha256"] = new_hash
    inventory["inputs"][1]["sha256"] = "d" * 64
    with pytest.raises(selected.SelectedReferenceError, match="non-helper"):
        selected.inspect_replacement_omission(original, tmp_path)


def test_selected_link_option_rejects_before_input_scan(monkeypatch):
    source = {"source_body_and_abi_verified": True, "symbol": SYMBOL,
              "source_coff_sha256": "a" * 64}
    monkeypatch.setattr(selected, "inspect_source", lambda _: source)
    monkeypatch.setattr(selected, "inspect_capture_inputs",
                        lambda _: {"switches": ["/INCLUDE:" + SYMBOL]})
    monkeypatch.setattr(selected, "_scan_inventory",
                        lambda *_: pytest.fail("must not scan admitted inputs"))
    inputs = type("Inputs", (), {"symbol": SYMBOL,
                                  "helper_object": Path("helper.obj")})()
    with pytest.raises(selected.SelectedReferenceError,
                       match="linker option"):
        selected.inspect_selected_capture(Path("capture"), inputs)
