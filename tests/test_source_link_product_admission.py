"""Negative and bounded positives for product-shaped source admission only."""

from __future__ import annotations

import struct
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from lifter import source_link_product_admission as admission


POLICY_BODY = bytes.fromhex(
    "84d27403b001c384c974114584c0750c4584c974ef443844242875e832c0c3"
)
LEASE_BODY = bytes.fromhex(
    "84c97503b001c384d274204d85c0781b488b442430492bc0493bc17f0e"
    "488b44242848394424380f9cc0c332c0c3"
)
POLICY_SYMBOL = "?allowedRuntime@AutomationAccessPolicy@orion@@SA_N_N0000@Z"
LEASE_SYMBOL = "?leaseFireAllowedScalar@orion@@YA_N_N0_J1111@Z"


@pytest.mark.parametrize("signature,args", [
    ("win64:bool(bool,bool,bool,bool,bool)", ("bool",) * 5),
    ("win64:bool(bool,bool,i64,i64,i64,i64,i64)",
     ("bool", "bool", "i64", "i64", "i64", "i64", "i64")),
])
def test_exact_typed_scalar_schema(signature, args):
    assert admission._typed_signature(signature) == args


@pytest.mark.parametrize("signature", [
    "win64:u64(bool)", "win64:bool()", "win64:bool(bool, bool)",
    "win64:bool(bool,u64)", "win64:bool(bool,ptr)",
    "win64:bool(bool,bool,bool,bool,bool,bool,bool,bool,bool)",
    "win64:bool(bool,...)", "win64:bool(i64) noexcept",
])
def test_non_exact_or_unsupported_abi_rejects(signature):
    with pytest.raises(admission.ProductSourceProofError):
        admission._typed_signature(signature)


@pytest.mark.parametrize("symbol", [POLICY_SYMBOL, LEASE_SYMBOL])
def test_exact_decorated_symbol_syntax(symbol):
    assert admission._DECORATED.fullmatch(symbol)


@pytest.mark.parametrize("symbol", [
    "plain_c", "?source@foo@@YA_N_N@Z\n/OUT:bad", "?bad-name@@YA_N_N@Z",
    "?foo@@YA_N_N@Z/../../bad",
])
def test_unbound_symbol_syntax_rejects(symbol):
    assert not admission._DECORATED.fullmatch(symbol)


@pytest.mark.parametrize("body,instructions,returns", [
    (POLICY_BODY, 14, 2), (LEASE_BODY, 18, 3),
])
def test_exact_product_shaped_branch_graph_lifts(body, instructions, returns):
    count, ret_count, digest = admission._bounded_branch_graph(body, 0x1000)
    assert (count, ret_count) == (instructions, returns)
    assert len(digest) == 64


@pytest.mark.parametrize("body,reason", [
    (POLICY_BODY[:3] + b"\x7f" + POLICY_BODY[4:], "instruction boundary"),
    (POLICY_BODY[:3] + b"\x01" + POLICY_BODY[4:], "instruction boundary"),
    (POLICY_BODY[:3] + b"\xfc" + POLICY_BODY[4:], "cyclic"),
    (b"\xc3\x90\xc3", "unreachable"),
    (b"\xe8\x00\x00\x00\x00\xc3", "call-free"),
    (b"\x48\x8b\x01\xc3", "non-RSP"),
    (b"\x48\x8d\x04\x24\xc3", "address formation"),
])
def test_bad_branch_or_pointer_graph_rejects(body, reason):
    with pytest.raises(admission.ProductSourceProofError, match=reason):
        admission._bounded_branch_graph(body, 0x1000)


def _coff_one(name: str, *, storage: int = 2, value: int = 0) -> bytes:
    encoded = name.encode("ascii") + b"\0"
    raw = bytearray(20 + 40 + 18 + 4 + len(encoded))
    struct.pack_into("<HHIIIHH", raw, 0, 0x8664, 1, 0, 60, 1, 0, 0)
    raw[60:68] = b"\0" * 4 + struct.pack("<I", 4)
    # COFF symbol fields are name[8], value[4], section[2], type[2], storage[1], aux[1].
    struct.pack_into("<IhHBB", raw, 68, value, 1, 0, storage, 0)
    struct.pack_into("<I", raw, 78, 4 + len(encoded))
    raw[82:] = encoded
    return bytes(raw)


def test_raw_coff_long_decorated_symbol_exact():
    assert admission._coff_defined_externals(_coff_one(POLICY_SYMBOL)) == (
        (POLICY_SYMBOL, 1, 0),
    )


@pytest.mark.parametrize("raw", [
    _coff_one(POLICY_SYMBOL, storage=105),
    _coff_one(POLICY_SYMBOL)[:-1],
    b"not a COFF object",
])
def test_raw_coff_weak_truncated_or_non_coff_rejects(raw):
    with pytest.raises(admission.ProductSourceProofError):
        admission._coff_defined_externals(raw)


def test_typed_dia_output_requires_exact_order_and_extent():
    valid = b"ABI_TYPED rva=00001000 size=31 argc=5 ret=bool " \
            b"args=bool,bool,bool,bool,bool callconv=0\n"
    args = ("bool",) * 5
    admission._validate_typed_output(valid, 0x1000, 31, args)
    for bad in (
        valid.replace(b"00001000", b"00001001"),
        valid.replace(b"size=31", b"size=32"),
        valid.replace(b"argc=5", b"argc=4"),
        valid.replace(b"bool,bool,bool,bool,bool", b"bool,bool,bool,i64,bool"),
        valid.replace(b"callconv=0", b"callconv=4"),
        valid + b"extra\n",
    ):
        with pytest.raises(admission.ProductSourceProofError):
            admission._validate_typed_output(bad, 0x1000, 31, args)


def test_guard_target_whole_span_not_just_entry():
    admission._require_no_guard_target_in_span((0x0FFF, 0x101F), 0x1000, 31)
    for target in (0x1000, 0x1001, 0x101E):
        with pytest.raises(admission.ProductSourceProofError, match="span contains"):
            admission._require_no_guard_target_in_span((target,), 0x1000, 31)


def test_executable_coff_relocations_reject():
    raw = bytearray(_coff_one(POLICY_SYMBOL))
    struct.pack_into("<I", raw, 20 + 36, 0x20000020)  # one executable .text
    admission._require_no_executable_relocations(bytes(raw))
    for offset, fmt, value in (
        (20 + 24, "<I", 100),  # relocation pointer, even with count zero
        (20 + 32, "<H", 1),    # count one, even with pointer zero
        (20 + 36, "<I", 0x21000020),  # relocation-overflow flag
    ):
        changed = bytearray(raw)
        struct.pack_into(fmt, changed, offset, value)
        with pytest.raises(admission.ProductSourceProofError, match="relocations"):
            admission._require_no_executable_relocations(bytes(changed))


def test_observed_child_reparse_component_rejects(tmp_path, monkeypatch):
    child = tmp_path / "junction"
    child.mkdir()
    subject = child / "input.bin"
    subject.write_bytes(b"input")
    original = Path.lstat

    def lstat(path):
        if Path(path) == child:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
        return original(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(admission.ProductSourceProofError, match="reparse component"):
        admission._reject_reparse_components(subject)


def test_typed_dia_invocation_passes_exact_decorated_symbol(tmp_path, monkeypatch):
    pdb, msdia, helper = (tmp_path / name for name in ("input.pdb", "msdia.dll", "helper.exe"))
    for path in (pdb, msdia, helper):
        path.write_bytes(b"pinned")
    seen = []

    def run(command, **kwargs):
        seen.append(tuple(command))
        return SimpleNamespace(returncode=29, stdout=b"", stderr=b"")

    monkeypatch.setattr(admission.subprocess, "run", run)
    inputs = admission.ProductSourceInputs(
        tmp_path / "input.exe", pdb, tmp_path / "input.map", tmp_path / "input.obj",
        POLICY_SYMBOL, "win64:bool(bool,bool,bool,bool,bool)",
        tmp_path / "inventory.exe", msdia, helper,
    )
    with pytest.raises(admission.ProductSourceProofError, match="decorated public identity"):
        admission._prove_dia_abi(inputs, 0x1000, 31, ("bool",) * 5)
    assert seen[0][-1] == POLICY_SYMBOL
