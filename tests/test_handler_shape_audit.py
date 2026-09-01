"""Portable contracts and opt-in native gate for handler machine shapes."""
from __future__ import annotations

import os

import pytest

from daedalus import shuffle_opcodes
from tools import handler_shape_audit


_RUN_GATE = "LETHE_RUN_NATIVE_HANDLER_SHAPE"


def test_declared_handler_counts_only_claim_machine_distinct_forms() -> None:
    assert shuffle_opcodes.HANDLER_VARIANT_COUNTS["neg"] == 1
    assert all(count >= 1 for count in shuffle_opcodes.HANDLER_VARIANT_COUNTS.values())


def test_relocation_normalization_zeros_only_address_fields() -> None:
    body = bytes(range(24))
    normalized = handler_shape_audit._normalized_relocations(
        body,
        symbol_value=0x20,
        relocations=((0x24, 0x0004), (0x30, 0x000A)),
    )
    assert normalized[:4] == body[:4]
    assert normalized[4:8] == b"\0" * 4
    assert normalized[8:16] == body[8:16]
    assert normalized[16:18] == b"\0" * 2
    assert normalized[18:] == body[18:]


def test_unknown_relocation_type_fails_closed() -> None:
    with pytest.raises(handler_shape_audit.HandlerShapeAuditError, match="relocation"):
        handler_shape_audit._normalized_relocations(
            b"\x90" * 8,
            symbol_value=0,
            relocations=((0, 0xFFFF),),
        )


@pytest.mark.skipif(
    os.environ.get(_RUN_GATE) != "1",
    reason=f"set {_RUN_GATE}=1 to compile every handler shape with release MSVC",
)
def test_release_msvc_handler_shapes_are_distinct_and_deterministic() -> None:
    compiler = handler_shape_audit.find_msvc()
    if compiler is None:
        pytest.skip("release MSVC x64 compiler is unavailable")
    first = handler_shape_audit.run_audit(compiler)
    second = handler_shape_audit.run_audit(compiler)
    assert first["ok"] is True
    assert second["ok"] is True
    assert first["handler_code_sha256"] == second["handler_code_sha256"]
    assert first["handlers"] == second["handlers"]
    assert first["compiled_profiles"] == second["compiled_profiles"]
    assert all(item["distinct"] for item in first["handlers"])
    assert all(
        item["integrated_unique_variant_count"] == item["declared_variant_count"]
        for item in first["handlers"]
    )
