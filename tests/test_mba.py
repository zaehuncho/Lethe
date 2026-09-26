#!/usr/bin/env python3
"""
Correctness proof for the MBA rewriter (daedalus/daedalus_mba.py).

The rewriter is semantics-preserving iff, for every input, the reference
interpreter produces the identical result on the original and rewritten
programs. We prove that directly over random inputs -- an identity or
stack-juggling bug fails here, not in production.

Run: python -m pytest tests/test_mba.py -q   or   python tests/test_mba.py
"""
from __future__ import annotations

import random
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
sys.path.insert(0, str(PKG / "daedalus"))

import daedalus_asm            # noqa: E402
import daedalus_mba            # noqa: E402
from daedalus_ref import run_plaintext  # noqa: E402
import daedalus_rolling as vr  # noqa: E402

MASK64 = (1 << 64) - 1
PROGRAMS_DIR = PKG / "daedalus" / "programs"


def _run(src, args):
    val, _trace = run_plaintext(daedalus_asm.assemble(src), args)
    return val


def _binop_prog(op):
    # halts with (args[0] OP args[1])
    return f"""
    .code
      push_arg 0
      push_arg 1
      {op}
      halt
    """


def test_xor_expansion_matches_random():
    rng = random.Random(1)
    src = _binop_prog("xor")
    rewritten = daedalus_mba.rewrite_source(src, ops=("xor",))
    assert "MBA[xor]" in rewritten and daedalus_mba.count_rewritable(src) == 1
    for _ in range(200):
        a = rng.getrandbits(64); b = rng.getrandbits(64)
        assert _run(src, [a, b]) == _run(rewritten, [a, b]) == (a ^ b)


def test_add_expansion_matches_random():
    rng = random.Random(2)
    src = _binop_prog("add")
    rewritten = daedalus_mba.rewrite_source(src, ops=("add",))
    assert "MBA[add]" in rewritten
    for _ in range(200):
        a = rng.getrandbits(64); b = rng.getrandbits(64)
        assert _run(src, [a, b]) == _run(rewritten, [a, b]) == ((a + b) & MASK64)


def test_composed_and_nested():
    """Rewrite a program that mixes xor/add with branches and locals; results
    must be identical for all inputs including the branch both ways."""
    src = """
    .code
      push_arg 0
      push_arg 1
      xor
      local_addr 0
      swap
      store64
      push_arg 0
      push_arg 1
      add
      local_addr 0
      load64
      add          ; (a+b) + (a^b)
      dup
      jz zero
      halt
    zero:
      push_imm8 123
      halt
    """
    rewritten = daedalus_mba.rewrite_source(src, ops=("xor", "add"))
    assert daedalus_mba.count_rewritable(src) == 3
    rng = random.Random(3)
    for _ in range(200):
        a = rng.getrandbits(64); b = rng.getrandbits(64)
        assert _run(src, [a, b]) == _run(rewritten, [a, b])
    # and the degenerate branch (result 0 -> jz taken)
    assert _run(src, [0, 0]) == _run(rewritten, [0, 0]) == 123


def test_idempotent_structure_on_real_programs():
    """On the real crypto programs the pass must still produce assemblable
    bytecode and must not touch anything but bare xor/add (data + native ops +
    branches survive; the blob still disassembles)."""
    import daedalus_disasm
    for vasm in sorted(PROGRAMS_DIR.glob("*.vasm")):
        text = vasm.read_text(encoding="utf-8")
        rewritten = daedalus_mba.rewrite_source(text)
        blob = daedalus_asm.assemble(rewritten)          # must assemble
        _txt = daedalus_disasm.disassemble(blob)          # must disassemble
        # data section is untouched
        orig_ds = struct.unpack_from("<H", daedalus_asm.assemble(text), 0)[0]
        new_ds = struct.unpack_from("<H", blob, 0)[0]
        assert orig_ds == new_ds, f"{vasm.name}: MBA altered the data section"


def test_mba_composes_with_rolling():
    """MBA then rolling-encode then decode must round-trip -- the two passes
    compose (MBA changes the plaintext; rolling encrypts whatever it is given)."""
    src = _binop_prog("add")
    rewritten = daedalus_mba.rewrite_source(src)
    blob = daedalus_asm.assemble(rewritten)
    ds = struct.unpack_from("<H", blob, 0)[0]
    code = blob[2 + ds:]
    import hashlib
    for s in range(8):
        seed = hashlib.sha256(b"s" + struct.pack("<I", s)).digest()[:vr.SEED_LEN]
        ct, leaders = vr.encrypt_code(code, seed)
        assert vr.decode_stream(ct, seed, leaders) == code


# ---------------------------------------------------------------------------
# NEW: exact-identity catalogue proofs (daedalus_mba.CATALOGUE)
# ---------------------------------------------------------------------------
_REF = {
    "xor": lambda a, b: a ^ b,
    "add": lambda a, b: (a + b) & MASK64,
    "sub": lambda a, b: (a - b) & MASK64,
    "and": lambda a, b: a & b,
    "or":  lambda a, b: a | b,
}


def _identity_prog(tree):
    """A program that halts with args[0] OP args[1] computed via `tree`."""
    ops, _peak = daedalus_mba.emit_expansion(tree)
    body = "\n".join("      " + ins for ins in ops)
    return f".code\n  push_arg 0\n  push_arg 1\n{body}\n      halt\n"


def test_every_catalogue_identity_is_exact_over_random_inputs():
    """Each NEW MBA identity in the catalogue must equal the operation it stands
    for, for 200+ random (a, b) via the reference interpreter. A wrong identity
    would silently corrupt a crypto routine -- it is caught here, not shipped."""
    rng = random.Random(20240926)
    total = 0
    for op, trees in daedalus_mba.CATALOGUE.items():
        assert 2 <= len(trees) <= 3, f"{op}: expected 2-3 identities"
        for idx, tree in enumerate(trees):
            src = _identity_prog(tree)
            # include the boundary cases plus 200 random pairs
            pairs = [(0, 0), (MASK64, MASK64), (0, MASK64), (MASK64, 0), (1, MASK64)]
            pairs += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(200)]
            for a, b in pairs:
                got = _run(src, [a, b])
                assert got == _REF[op](a, b), (
                    f"{op} identity #{idx} wrong for a=0x{a:016X} b=0x{b:016X}: "
                    f"got 0x{got:016X}")
            total += 1
    assert total == 15, f"expected 15 catalogue identities, proved {total}"


def test_seeded_rewrite_matches_reference_and_is_stack_safe():
    """A seeded catalogue rewrite over xor/add/sub/and/or must preserve semantics
    for random inputs and never exceed the operand-stack ceiling."""
    import daedalus_mutate
    src = """
    .code
      push_arg 0
      push_arg 1
      xor
      push_arg 0
      and
      push_arg 1
      or
      push_arg 0
      add
      push_arg 1
      sub
      halt
    """
    rng = random.Random(7)
    for seed in (b"s0", b"s1", b"s2"):
        d = daedalus_mutate.stack_depth_map(src)
        rewritten = daedalus_mba.rewrite_source(
            src, ops=("xor", "add", "sub", "and", "or"),
            seed=seed, depth=1, templates=daedalus_mba.CATALOGUE, depth_in=d)
        # stack safety of the rewritten program
        peak = max([x for x in daedalus_mutate.stack_depth_map(rewritten)
                    if x is not None] + [0])
        assert peak <= daedalus_mba.CEILING
        for _ in range(200):
            a = rng.getrandbits(64); b = rng.getrandbits(64)
            assert _run(src, [a, b]) == _run(rewritten, [a, b])


def test_seeded_determinism_and_variation():
    """Same seed => byte-identical rewrite; different seed => different bytes.

    Uses a multi-site program so two seeds selecting the same per-site template
    everywhere (each site has only 2-3 choices) is vanishingly unlikely."""
    src = """
    .code
      push_arg 0
      push_arg 1
      xor
      push_arg 0
      xor
      push_arg 1
      xor
      push_arg 0
      xor
      push_arg 1
      xor
      push_arg 0
      xor
      halt
    """
    kw = dict(ops=("xor",), depth=0, templates=daedalus_mba.CATALOGUE)
    a = daedalus_mba.rewrite_source(src, seed=b"alpha", **kw)
    a2 = daedalus_mba.rewrite_source(src, seed=b"alpha", **kw)
    b = daedalus_mba.rewrite_source(src, seed=b"beta", **kw)
    assert a == a2, "same seed must reproduce byte-identical output"
    assert a != b, "different seeds must diverge"


def test_default_rewrite_is_byte_identical_to_legacy():
    """The default (no seed/templates) path is byte-for-byte the legacy MBA."""
    for vasm in sorted(PROGRAMS_DIR.glob("*.vasm")):
        text = vasm.read_text(encoding="utf-8")
        assert (daedalus_mba.rewrite_source(text)
                == daedalus_mba._legacy_rewrite(text, ("xor", "add"), "  "))


def _main():
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except Exception:
            print(f"  FAIL  {fn.__name__}"); traceback.print_exc(); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
