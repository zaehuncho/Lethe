"""Captured link response parity is an input prerequisite, never admission."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import struct

import pefile
import pytest

from lifter import link_capture_response_pair as pair
from lifter.source_link_product_admission import ProductSourceInputs


def _sha(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _write_rsp(root: Path, tokens: list[str]) -> str:
    raw = ("\r\n".join('"' + token + '"' for token in tokens) + "\r\n").encode("utf-16")
    (root / "link.rsp").write_bytes(raw)
    return _sha(raw)


def _fixture(tmp_path):
    before, after = tmp_path / "before", tmp_path / "after"
    before.mkdir()
    after.mkdir()
    old, new, common, pdb = b"old-coff", b"new-coff", b"caller-coff", b"pdb-bytes"
    for root, helper in ((before, old), (after, new)):
        (root / "helper.obj").write_bytes(helper)
        (root / "caller.obj").write_bytes(common)
        (root / "vc143.pdb").write_bytes(pdb)
    opts = ["/out:.\\fixture.exe", "/MACHINE:X64", "/OPT:REF",
            "/pdbmap:C:\\build\\before\\vc143.pdb=.\\vc143.pdb",
            ".\\caller.obj", ".\\helper.obj"]
    before_sha = _write_rsp(before, opts)
    opts[3] = "/pdbmap:D:\\build\\after\\vc143.pdb=.\\vc143.pdb"
    after_sha = _write_rsp(after, opts)
    selected = {
        "selected_input_references_classified": True,
        "selected": "selected_helper", "helper_object": "helper.obj",
        "source_coff_sha256": _sha(old), "capture_rsp_sha256": before_sha,
        "capture_input_hashes": {"helper.obj": _sha(old), "caller.obj": _sha(common)},
    }
    omission = {
        "original_helper_object_omission_proven": True,
        "other_input_hashes_equal": True,
        "original_coff_sha256": _sha(old), "replacement_coff_sha256": _sha(new),
        "replacement_rsp_sha256": after_sha,
    }
    return before, after, selected, omission


def _inputs(before: Path) -> ProductSourceInputs:
    return ProductSourceInputs(*(before / name for name in (
        "source.exe", "source.pdb", "source.map", "helper.obj",
    )), "selected_helper", "win64:bool(bool)",
        before / "dia.exe", before / "msdia.dll", before / "typed.exe")


def _mock_fresh(monkeypatch, selected: dict, omission: dict) -> None:
    monkeypatch.setattr(pair, "inspect_selected_capture", lambda *_: dict(selected))
    monkeypatch.setattr(pair, "inspect_replacement_omission", lambda *_: dict(omission))


def test_same_link_profile_and_capture_payloads_pass(tmp_path, monkeypatch):
    before, after, selected, omission = _fixture(tmp_path)
    _mock_fresh(monkeypatch, selected, omission)
    proof = pair.inspect_response_pair(before, after, _inputs(before),
                                       expected_selected=selected,
                                       expected_omission=omission)
    assert proof["response_profile_equal_except_pdbmap_source_and_position"] is True
    assert proof["capture_pdbmap_option_position_proven"] is False
    assert proof["capture_pdbmap_source_path_proven"] is False
    assert proof["implicit_coff_directives_bound"] is False
    assert proof["response_option_semantics_proven"] is False
    assert proof["all_nonhelper_input_hashes_equal"] is True
    assert proof["distinct_inputs"] == 2
    assert proof["captured_pdbmap_payloads"] == {"vc143.pdb": _sha(b"pdb-bytes")}
    assert proof["final_image_reference_closure_proven"] is False
    assert proof["production_admitted"] is False


@pytest.mark.parametrize("mutate,reason", [
    (lambda x: x.__setitem__(2, "/OPT:NOREF"), "linker options differ"),
    (lambda x: x.insert(2, "/BREPRO"), "linker options differ"),
    (lambda x: x.__setitem__(4, ".\\helper.obj"), "material input order differs"),
    (lambda x: x.insert(1, "/INCLUDE:selected_helper"), "unsupported linker option"),
    (lambda x: x.insert(1, "/LTCG"), "unsupported linker option"),
    (lambda x: x.insert(1, "/DEFAULTLIB:extra.lib"), "unsupported linker option"),
])
def test_option_or_order_delta_rejects_even_with_updated_rsp_receipt(tmp_path,
                                                                     monkeypatch, mutate, reason):
    before, after, selected, omission = _fixture(tmp_path)
    tokens = ["/out:.\\fixture.exe", "/MACHINE:X64", "/OPT:REF",
              "/pdbmap:D:\\build\\after\\vc143.pdb=.\\vc143.pdb",
              ".\\caller.obj", ".\\helper.obj"]
    mutate(tokens)
    omission["replacement_rsp_sha256"] = _write_rsp(after, tokens)
    _mock_fresh(monkeypatch, selected, omission)
    with pytest.raises(pair.ResponsePairError, match=reason):
        pair.inspect_response_pair(before, after, _inputs(before))


def test_mutated_pdbmap_payload_or_material_input_rejects(tmp_path, monkeypatch):
    before, after, selected, omission = _fixture(tmp_path)
    _mock_fresh(monkeypatch, selected, omission)
    (after / "vc143.pdb").write_bytes(b"different-pdb")
    with pytest.raises(pair.ResponsePairError, match="PDBMAP payload differs|linker options differ"):
        pair.inspect_response_pair(before, after, _inputs(before))
    (after / "vc143.pdb").write_bytes(b"pdb-bytes")
    (after / "caller.obj").write_bytes(b"changed-caller")
    with pytest.raises(pair.ResponsePairError, match="replacement LINKREPRO material input changed"):
        pair.inspect_response_pair(before, after, _inputs(before))


def test_stale_or_forged_report_and_helper_rejects(tmp_path, monkeypatch):
    before, after, selected, omission = _fixture(tmp_path)
    _mock_fresh(monkeypatch, selected, omission)
    forged = dict(selected, selected="another_symbol")
    with pytest.raises(pair.ResponsePairError, match="stale or forged selected-reference report"):
        pair.inspect_response_pair(before, after, _inputs(before), expected_selected=forged)
    stale = dict(omission, replacement_rsp_sha256="0" * 64)
    with pytest.raises(pair.ResponsePairError, match="stale or forged omission report"):
        pair.inspect_response_pair(before, after, _inputs(before), expected_omission=stale)
    (after / "helper.obj").write_bytes(b"old-coff")
    with pytest.raises(pair.ResponsePairError, match="replacement LINKREPRO material input changed"):
        pair.inspect_response_pair(before, after, _inputs(before))


def test_pdbmap_source_and_position_are_explicitly_unproven(tmp_path, monkeypatch):
    before, after, selected, omission = _fixture(tmp_path)
    tokens = ["/out:.\\fixture.exe", "/MACHINE:X64", "/OPT:REF",
              ".\\caller.obj", ".\\helper.obj",
              "/pdbmap:C:\\unrelated\\not_in_any_obj.pdb=.\\vc143.pdb"]
    omission["replacement_rsp_sha256"] = _write_rsp(after, tokens)
    _mock_fresh(monkeypatch, selected, omission)
    proof = pair.inspect_response_pair(before, after, _inputs(before))
    assert proof["capture_pdbmap_source_path_proven"] is False
    assert proof["capture_pdbmap_option_position_proven"] is False
    assert proof["source_output_reference_equivalence_proven"] is False


def test_noncanonical_response_separator_rejects(tmp_path, monkeypatch):
    before, after, selected, omission = _fixture(tmp_path)
    raw = (after / "link.rsp").read_bytes().decode("utf-16")
    changed = raw.replace("\r\n", "\u2028").encode("utf-16")
    (after / "link.rsp").write_bytes(changed)
    omission["replacement_rsp_sha256"] = _sha(changed)
    _mock_fresh(monkeypatch, selected, omission)
    with pytest.raises(pair.ResponsePairError, match="line separators are unsupported"):
        pair.inspect_response_pair(before, after, _inputs(before))


def test_same_unknown_switch_is_only_report_consistency(tmp_path, monkeypatch):
    before, after, selected, omission = _fixture(tmp_path)
    for root, report in ((before, selected), (after, omission)):
        tokens = ["/out:.\\fixture.exe", "/MACHINE:X64",
                  "/MYSTERY:C:\\external\\input.bin", "/OPT:REF",
                  "/pdbmap:C:\\build\\vc143.pdb=.\\vc143.pdb",
                  ".\\caller.obj", ".\\helper.obj"]
        key = "capture_rsp_sha256" if root == before else "replacement_rsp_sha256"
        report[key] = _write_rsp(root, tokens)
    _mock_fresh(monkeypatch, selected, omission)
    proof = pair.inspect_response_pair(before, after, _inputs(before))
    assert proof["response_option_semantics_proven"] is False
    assert proof["external_default_library_resolution_bound"] is False
    assert proof["production_admitted"] is False


def _minimal_coff(value: bytes) -> bytes:
    return (struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0) +
            struct.pack("<8sIIIIIIHHI", b".text", 0, 0, len(value), 60,
                        0, 0, 0, 0, 0x60000020) + value)


def _ar_member(label: str, body: bytes) -> bytes:
    header = (label.encode("ascii").ljust(16, b" ") + b"0".ljust(12, b" ") +
              b"0".ljust(6, b" ") + b"0".ljust(6, b" ") +
              b"100644".ljust(8, b" ") +
              str(len(body)).encode("ascii").ljust(10, b" ") + b"`\n")
    return header + body + (b"\n" if len(body) & 1 else b"")


def _archive_with(old: bytes) -> bytes:
    first = _ar_member("/", struct.pack(">I", 0))
    second_size = 4 + 4 + 4
    placeholder = _ar_member("/", bytes(second_size))
    offset = 8 + len(first) + len(placeholder)
    second = _ar_member("/", struct.pack("<III", 1, offset, 0))
    assert len(second) == len(placeholder)
    return b"!<arch>\n" + first + second + _ar_member("helper.obj/", old)


def test_old_helper_inside_archive_rejects_before_profile_claim(tmp_path, monkeypatch):
    before, after, selected, _ = _fixture(tmp_path)
    old, new, caller = (_minimal_coff(value) for value in (b"\xc3", b"\x90", b"\x90\xc3"))
    archive = _archive_with(old)
    for root, helper in ((before, old), (after, new)):
        (root / "helper.obj").write_bytes(helper)
        (root / "caller.obj").write_bytes(caller)
        (root / "archive.lib").write_bytes(archive)
        tokens = ["/out:.\\fixture.exe", "/MACHINE:X64", "/OPT:REF",
                  "/pdbmap:C:\\build\\vc143.pdb=.\\vc143.pdb",
                  ".\\caller.obj", ".\\helper.obj", ".\\archive.lib"]
        _write_rsp(root, tokens)
    selected["source_coff_sha256"] = _sha(old)
    selected["capture_rsp_sha256"] = _sha((before / "link.rsp").read_bytes())
    selected["capture_input_hashes"] = {"helper.obj": _sha(old),
                                        "caller.obj": _sha(caller),
                                        "archive.lib": _sha(archive)}
    monkeypatch.setattr(pair, "inspect_selected_capture", lambda *_: selected)
    with pytest.raises(pair.ResponsePairError, match="original helper object remains in a captured archive"):
        pair.inspect_response_pair(before, after, _inputs(before))


@pytest.mark.parametrize("index,image", [(0, "OrionNative"), (1, "SecurityCore")])
def test_materialized_conventional_exe_dll_response_pair(index, image):
    root = os.environ.get("LETHE_CONVENTIONAL_RESPONSE_EVIDENCE")
    if not root:
        pytest.skip("opt-in source-augmented conventional LINKREPRO evidence unavailable")
    root = Path(root)
    receipt = json.loads((root / "materialized-response-pairs.json").read_text())[index]
    original = receipt["selected"]
    omission = receipt["omission"]
    before = Path(receipt["original_capture_path"])
    after = Path(receipt["replacement_capture_path"])
    extension = ".exe" if image == "OrionNative" else ".dll"
    built = Path(receipt["built_path"])
    assert built.name == image + extension
    assert built.is_file() and built.stat().st_size > 0
    assert _sha(built.read_bytes()) == receipt["built_pe_sha256"]
    pe = pefile.PE(str(built), fast_load=True)
    assert pe.FILE_HEADER.Machine == 0x8664
    assert bool(pe.FILE_HEADER.Characteristics & 0x2000) == (extension == ".dll")
    inputs = ProductSourceInputs(*(
        Path(receipt["source_inputs"][name]) for name in (
            "image", "pdb", "link_map", "helper_object",
        )), receipt["source_inputs"]["symbol"], receipt["source_inputs"]["abi"],
        *(Path(receipt["source_inputs"][name]) for name in (
            "dia_helper", "msdia", "typed_abi_helper",
        )))
    proof = pair.inspect_response_pair(before, after, inputs,
                                       expected_selected=original,
                                       expected_omission=omission)
    assert proof == receipt["paired"]
    assert proof["selected"] == original["selected"]
    assert proof["response_profile_equal_except_pdbmap_source_and_position"] is True
    assert proof["production_admitted"] is False
