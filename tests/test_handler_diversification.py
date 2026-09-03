"""Per-build Daedalus native-handler diversification contracts."""
from __future__ import annotations

import random
from pathlib import Path

from daedalus import shuffle_opcodes


ROOT = Path(__file__).resolve().parents[1]
MASK64 = (1 << 64) - 1


def _variant_result(name: str, variant: int, a: int, b: int = 0) -> int:
    a &= MASK64
    b &= MASK64
    if name == "add":
        return (a + b) & MASK64 if variant == 0 else (a - ((~b + 1) & MASK64)) & MASK64
    if name == "sub":
        return (a - b) & MASK64 if variant == 0 else (a + ((~b + 1) & MASK64)) & MASK64
    if name == "xor":
        return a ^ b if variant == 0 else ((a | b) & ~(a & b)) & MASK64
    if name == "and":
        return a & b if variant == 0 else ~(~a | ~b) & MASK64
    if name == "or":
        return a | b if variant == 0 else ~(~a & ~b) & MASK64
    if name == "neg":
        return ((~a) + 1) & MASK64 if variant == 0 else (-a) & MASK64
    if name == "cmp_eq":
        return int(a == b) if variant == 0 else int((a ^ b) == 0)
    if name == "cmp_ne":
        return int(a != b) if variant == 0 else int((a ^ b) != 0)
    raise AssertionError(name)


def _canonical_result(name: str, a: int, b: int) -> int:
    return _variant_result(name, 0, a, b)


def test_handler_profile_is_deterministic_and_independently_hashed() -> None:
    seed = bytes.fromhex("23" * 32)
    first = shuffle_opcodes.generate_shuffle(seed)
    second = shuffle_opcodes.generate_shuffle(seed)
    assert first["handler_variants"] == second["handler_variants"]
    assert first["handler_variant_sha256"] == second["handler_variant_sha256"]
    assert first["handler_variant_sha256"] == shuffle_opcodes.handler_variant_sha256(
        first["handler_variants"]
    )
    assert not shuffle_opcodes.verify_shuffle(first)


def test_seed_population_produces_more_than_one_handler_profile() -> None:
    profiles = {
        tuple(shuffle_opcodes.generate_shuffle(bytes([seed]) * 32)["handler_variants"].items())
        for seed in range(1, 17)
    }
    assert len(profiles) > 1


def test_declared_variant_count_tracks_effective_native_shapes() -> None:
    # Both NEG source formulas compile to the same x64 NEG body under the
    # release optimizer. The compiled shape gate owns the evidence; generation
    # must not claim that source spelling as an additional native variant.
    assert shuffle_opcodes.HANDLER_VARIANT_COUNTS["neg"] == 1


def test_generated_artifacts_publish_exact_handler_profile() -> None:
    result = shuffle_opcodes.generate_shuffle(bytes.fromhex("42" * 32))
    header = shuffle_opcodes.emit_c_header(result)
    module = shuffle_opcodes.emit_py_dict(result, 0.25)
    assert (
        f'#define DVM_HANDLER_VARIANT_SHA256 "{result["handler_variant_sha256"]}"'
        in header
    )
    for name, variant in result["handler_variants"].items():
        assert f"DVM_HANDLER_VARIANT_{name.upper()}" in header
        assert f"'{name}': {variant}" in module
    assert f"HANDLER_VARIANT_SHA256 = {result['handler_variant_sha256']!r}" in module


def test_every_handler_formula_is_bit_exact_over_boundaries_and_fuzz() -> None:
    values = [
        0,
        1,
        2,
        (1 << 31) - 1,
        1 << 31,
        (1 << 63) - 1,
        1 << 63,
        MASK64 - 1,
        MASK64,
    ]
    rng = random.Random(0x4080)
    values.extend(rng.getrandbits(64) for _ in range(128))
    for name, count in shuffle_opcodes.HANDLER_VARIANT_COUNTS.items():
        for a in values:
            for b in values[::17]:
                expected = _canonical_result(name, a, b)
                for variant in range(count):
                    assert _variant_result(name, variant, a, b) == expected


def test_runtime_uses_generated_variants_and_exports_provenance() -> None:
    source = (ROOT / "stub/src/daedalus_vm.c").read_text(encoding="utf-8")
    build_script = (ROOT / "stub/build_stub.ps1").read_text(encoding="utf-8")
    assert "daedalus_handler_variant_sha256" in source
    assert "Generated native-handler provenance is missing or malformed" in build_script
    assert "dvm_handler_variant_sha256 = $HandlerVariantHash" in build_script
    for name in shuffle_opcodes.HANDLER_VARIANT_COUNTS:
        assert f"dvm_sem_{name}" in source
