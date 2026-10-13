"""Fail-closed contracts for the opt-in exact helper fixture emitter."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from lifter import source_link_product_fixture as fixture
from lifter import source_link_product_admission as admission
from lifter import x64_lifter


KEY = b"F" * 32
POLICY = "?allowedRuntime@AutomationAccessPolicy@orion@@SA_N_N0000@Z"
LEASE = "?leaseFireAllowedScalar@orion@@YA_N_N0_J1111@Z"
POLICY_BODY = bytes.fromhex(
    "84d27403b001c384c974114584c0750c4584c974ef443844242875e832c0c3"
)


def _inputs(tmp_path: Path, symbol: str = POLICY, abi: str | None = None):
    return admission.ProductSourceInputs(
        tmp_path / "source.exe", tmp_path / "source.pdb", tmp_path / "source.map",
        tmp_path / "source.obj", symbol,
        abi or fixture._SPECS[POLICY].abi,
        tmp_path / "dia.exe", tmp_path / "msdia.dll", tmp_path / "typed.exe",
    )


@pytest.mark.parametrize("mode,key", [
    ("production", KEY), ("synthetic_fixture", None),
    ("synthetic_fixture", b"short"), ("synthetic_fixture", bytearray(KEY)),
])
def test_production_or_missing_exact_synthetic_key_rejects_before_output(tmp_path, mode, key):
    out = tmp_path / "out"
    with pytest.raises(fixture.ProductFixtureError):
        fixture.emit_product_fixture(_inputs(tmp_path), tmp_path / "header", out,
                                     key_mode=mode, synthetic_fixture_key=key)
    assert not out.exists()


@pytest.mark.parametrize("symbol,abi", [
    ("?unreviewed@orion@@YA_N_N@Z", fixture._SPECS[POLICY].abi),
    (POLICY, fixture._SPECS[LEASE].abi),
    (LEASE, fixture._SPECS[POLICY].abi),
    (POLICY, "win64:bool(bool,bool,bool,bool,ptr)"),
])
def test_only_two_exact_decorated_symbols_and_abis(tmp_path, symbol, abi):
    out = tmp_path / "out"
    with pytest.raises(fixture.ProductFixtureError, match="two exact reviewed"):
        fixture.emit_product_fixture(_inputs(tmp_path, symbol, abi), tmp_path / "header",
                                     out, key_mode="synthetic_fixture",
                                     synthetic_fixture_key=KEY)
    assert not out.exists()


def test_changed_or_wrong_header_fails_before_inspection(tmp_path, monkeypatch):
    header = tmp_path / "AutomationAccessPolicy.h"
    header.write_text("changed prototype\n")
    monkeypatch.setattr(fixture, "inspect_source", lambda _: pytest.fail("inspected"))
    out = tmp_path / "out"
    with pytest.raises(fixture.ProductFixtureError, match="header differs"):
        fixture.emit_product_fixture(_inputs(tmp_path), header, out,
                                     key_mode="synthetic_fixture",
                                     synthetic_fixture_key=KEY)
    assert not out.exists()


@pytest.mark.parametrize("reason", [
    "PDB function ABI differs", "non-RSP memory", "executable COFF relocation",
    "source PE lacks Guard CF", "unsupported stack frame", "XFG target ambiguity",
])
def test_underlying_source_abi_stack_reference_or_metadata_failure_propagates(
    tmp_path, monkeypatch, reason,
):
    monkeypatch.setattr(fixture, "_header_bytes", lambda *_: b"reviewed header")
    def reject(_):
        raise admission.ProductSourceProofError(reason)
    monkeypatch.setattr(fixture, "inspect_source", reject)
    out = tmp_path / "out"
    with pytest.raises(fixture.ProductFixtureError, match="exact source proof failed"):
        fixture.emit_product_fixture(_inputs(tmp_path), tmp_path / "header", out,
                                     key_mode="synthetic_fixture",
                                     synthetic_fixture_key=KEY)
    assert not out.exists()


def _proof(**updates):
    proof = {
        "symbol": POLICY, "abi": fixture._SPECS[POLICY].abi,
        "source_body_sha256": fixture._SPECS[POLICY].body_sha256,
        "source_body_and_abi_verified": True,
        "source_reference_closure_proven": False,
        "original_helper_object_omission_proven": False,
        "indirect_target_closure_proven": False,
        "xfg_enforcement_proven": False,
        "production_admitted": False,
    }
    proof.update(updates)
    return proof


@pytest.mark.parametrize("changed", [
    {"source_body_sha256": "0" * 64},
    {"source_body_and_abi_verified": False},
    {"source_reference_closure_proven": True},
    {"original_helper_object_omission_proven": True},
    {"indirect_target_closure_proven": True},
    {"xfg_enforcement_proven": True},
    {"production_admitted": True},
])
def test_source_proof_cannot_waive_final_link_or_admission(tmp_path, monkeypatch, changed):
    monkeypatch.setattr(fixture, "_header_bytes", lambda *_: b"reviewed header")
    monkeypatch.setattr(fixture, "inspect_source", lambda _: _proof(**changed))
    out = tmp_path / "out"
    with pytest.raises(fixture.ProductFixtureError, match="source proof differs"):
        fixture.emit_product_fixture(_inputs(tmp_path), tmp_path / "header", out,
                                     key_mode="synthetic_fixture",
                                     synthetic_fixture_key=KEY)
    assert not out.exists()


def test_source_pe_change_after_inspection_rejects(tmp_path, monkeypatch):
    image = tmp_path / "source.exe"
    image.write_bytes(b"changed")
    monkeypatch.setattr(fixture, "_header_bytes", lambda *_: b"reviewed header")
    monkeypatch.setattr(fixture, "inspect_source", lambda _: _proof(
        source_pe_sha256=sha256(b"original").hexdigest()))
    out = tmp_path / "out"
    with pytest.raises(fixture.ProductFixtureError, match="PE changed"):
        fixture.emit_product_fixture(_inputs(tmp_path), tmp_path / "header", out,
                                     key_mode="synthetic_fixture",
                                     synthetic_fixture_key=KEY)
    assert not out.exists()


def test_dynamic_stack_rejects_before_output(tmp_path, monkeypatch):
    image = tmp_path / "source.exe"
    image.write_bytes(b"test-pe")
    proof = _proof(source_pe_sha256=sha256(image.read_bytes()).hexdigest(),
                   rva=0x1000, size=len(POLICY_BODY))
    monkeypatch.setattr(fixture, "_header_bytes", lambda *_: b"reviewed header")
    monkeypatch.setattr(fixture, "inspect_source", lambda _: proof)
    monkeypatch.setattr(fixture, "analyze_pe", lambda _: SimpleNamespace(
        load_config=SimpleNamespace(xfg_present=True)))
    monkeypatch.setattr(fixture.pefile, "PE", lambda **_: SimpleNamespace(
        get_data=lambda rva, size: POLICY_BODY))
    def reject(*_, **__):
        raise x64_lifter.LiftUnsupported("dynamic source stack")
    monkeypatch.setattr(fixture.x64_lifter, "validate_materialized_stack_window", reject)
    out = tmp_path / "out"
    with pytest.raises(fixture.ProductFixtureError, match="dynamic source stack"):
        fixture.emit_product_fixture(_inputs(tmp_path), tmp_path / "header", out,
                                     key_mode="synthetic_fixture",
                                     synthetic_fixture_key=KEY)
    assert not out.exists()


def test_source_xfg_metadata_absent_rejects(tmp_path, monkeypatch):
    image = tmp_path / "source.exe"
    image.write_bytes(b"test-pe")
    proof = _proof(source_pe_sha256=sha256(image.read_bytes()).hexdigest())
    monkeypatch.setattr(fixture, "_header_bytes", lambda *_: b"reviewed header")
    monkeypatch.setattr(fixture, "inspect_source", lambda _: proof)
    monkeypatch.setattr(fixture, "analyze_pe", lambda _: SimpleNamespace(
        load_config=SimpleNamespace(xfg_present=False)))
    out = tmp_path / "out"
    with pytest.raises(fixture.ProductFixtureError, match="lacks required XFG"):
        fixture.emit_product_fixture(_inputs(tmp_path), tmp_path / "header", out,
                                     key_mode="synthetic_fixture",
                                     synthetic_fixture_key=KEY)
    assert not out.exists()


def test_nonempty_output_refuses_to_overwrite(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "existing.bin").write_bytes(b"preserve")
    with pytest.raises(fixture.ProductFixtureError):
        fixture.emit_product_fixture(_inputs(tmp_path), tmp_path / "header", out,
                                     key_mode="synthetic_fixture",
                                     synthetic_fixture_key=KEY)
    assert (out / "existing.bin").read_bytes() == b"preserve"
