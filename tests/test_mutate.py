#!/usr/bin/env python3
"""
Proofs for the T3 metamorphic transformation engine (daedalus/daedalus_mutate.py,
daedalus_junk.py, and the seeded daedalus_mba.py catalogue).

Every mutation must be behaviour-preserving. This is proven directly:

  * ORACLE -- short lifted x64 snippets, mutated between lift and assembly, still
    match Unicorn on all 16 GPRs + flags + memory (via lifter/oracle.check).
  * REFVM EQUIVALENCE -- pure-subset synthetic programs run identically
    (halt + final stack + locals + memory) plaintext vs mutated, and mutated vs
    mutated-then-rolling after decode.
  * STACK SAFETY -- the operand stack never exceeds 56; a near-full-stack region
    is left unmutated (fail-closed).
  * DETERMINISM -- same seed => identical bytes, different seeds differ; junk is
    code-only (data_size unchanged); every mutated program
    assembles + disassembles + rolling-round-trips.

Run: python -m pytest tests/test_mutate.py -q
"""
from __future__ import annotations

import random
import struct
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
sys.path.insert(0, str(PKG / "daedalus"))
sys.path.insert(0, str(PKG / "lifter"))

import daedalus_asm            # noqa: E402
import daedalus_disasm         # noqa: E402
import daedalus_mba            # noqa: E402
import daedalus_mutate as MU   # noqa: E402
import daedalus_rolling as vr  # noqa: E402
from daedalus_ref import RefVM, run_plaintext  # noqa: E402

MASK64 = (1 << 64) - 1
PROGRAMS_DIR = PKG / "daedalus" / "programs"
CEILING = MU.CEILING


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _assemble(src):
    return daedalus_asm.assemble(src)


def _split(blob):
    ds = struct.unpack_from("<H", blob, 0)[0]
    return blob[2:2 + ds], blob[2 + ds:]


def _full_state(src, args):
    """Run a pure-subset program to halt; return (halt, stack, locals)."""
    blob = _assemble(src)
    data, code = _split(blob)
    vm = RefVM(code, data, args)
    halt = vm.run()
    return halt, tuple(vm.stack), bytes(vm.locals)


def _peak_depth(src):
    depths = [d for d in MU.stack_depth_map(src) if d is not None]
    return max(depths) if depths else 0


# Pure-subset synthetic programs: (name, source, args)
_SYNTH = [
    ("bitmix",
     """
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
     """, [0x0123456789ABCDEF, 0xFEDCBA9876543210]),
    ("branchy",
     """
     .code
       push_arg 0
     loop:
       dup
       jz done
       push_imm8 1
       sub
       jmp loop
     done:
       push_arg 1
       push_arg 0
       add
       halt
     """, [6, 40]),
    ("callret",
     """
     .code
       push_arg 0
       push_arg 1
       call combine
       halt
     combine:
       dup
       add
       ret
     """, [11, 0]),
    ("locals",
     """
     .code
       local_addr 0
       push_arg 0
       push_arg 1
       xor
       store64
       local_addr 0
       load64
       push_arg 0
       and
       halt
     """, [0xAABBCCDD, 0x11223344]),
]

_DATA_PROG = """
.data
  tbl: db 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
.code
  data_addr 0
  load64
  push_arg 0
  xor
  push_arg 1
  add
  halt
"""

_SEEDS = [b"seed-alpha", b"seed-bravo", b"seed-charlie"]
_LEVELS = [1, 2, 3]


# ---------------------------------------------------------------------------
# 1. ORACLE: lifted x64, mutated between lift and assembly, matches Unicorn
# ---------------------------------------------------------------------------
def _oracle_module():
    pytest.importorskip("iced_x86")
    pytest.importorskip("unicorn")
    pytest.importorskip("keystone")
    import oracle
    return oracle


_ORACLE_SNIPPETS = [
    ("alu_regs", "add rax, rbx; sub rcx, rdx; xor rsi, rdi; and r8, r9; or r10, r11",
     dict(rax=10, rbx=5, rcx=99, rdx=7, rsi=0xF0, rdi=0x0F, r8=0xABCD, r9=0x1234,
          r10=1, r11=2), ("CF", "ZF", "SF", "OF")),
    ("alu_imm", "add rax, 0x100; xor rbx, 0x55; sub rcx, 1",
     dict(rax=0xFFFF, rbx=0x0F0F, rcx=0), ("CF", "ZF", "SF", "OF")),
    ("branch", "cmp rax, rbx; jl less; mov rcx, 100; jmp done; "
               "less: mov rcx, 200; done: nop",
     dict(rax=1, rbx=9), ()),
    ("width32", "mov eax, 0x10; add rax, 0x100; add eax, 1; xor ebx, eax",
     dict(rax=0xFFFFFFFF00000000), ("CF", "ZF", "SF", "OF")),
]


def _init_regs(oracle, **regs):
    import x64_lifter as L
    out = [0] * 16
    for name, val in regs.items():
        out[L.GPR_NAMES.index(name)] = val
    return out


@pytest.mark.parametrize("seed", _SEEDS)
@pytest.mark.parametrize("level", _LEVELS)
def test_oracle_lifted_snippets_match_unicorn(seed, level, monkeypatch):
    oracle = _oracle_module()
    import x64_lifter as L
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # Wrap lift_function so oracle.check exercises the mutated bytecode: the
    # oracle still runs Unicorn on the ORIGINAL x64 and the RefVM on the lifted +
    # mutated + assembled program, and asserts they agree on regs/flags/memory.
    original_lift = L.lift_function

    def mutated_lift(code, base=0x1000, optimize_flags=True, **kwargs):
        asm = original_lift(code, base=base, **kwargs)
        out = MU.mutate_source(asm, seed=seed, level=level)
        assert _peak_depth(out) <= CEILING, "mutated lift exceeded stack ceiling"
        return out

    monkeypatch.setattr(oracle.L, "lift_function", mutated_lift)

    for _name, src, regs, flags in _ORACLE_SNIPPETS:
        code, _ = ks.asm(src, addr=oracle.BASE)
        oracle.check(bytes(code), init=_init_regs(oracle, **regs), flags=flags)


def test_oracle_lifted_memory_ops_match_unicorn(monkeypatch):
    oracle = _oracle_module()
    import x64_lifter as L
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    mem = bytes((i * 37 + 11) & 0xFF for i in range(256))

    original_lift = L.lift_function

    def mutated_lift(code, base=0x1000, optimize_flags=True, **kwargs):
        asm = original_lift(code, base=base, **kwargs)
        return MU.mutate_source(asm, seed=b"mem-seed", level=3)

    monkeypatch.setattr(oracle.L, "lift_function", mutated_lift)
    src = "add rax, [rbx]; xor rcx, [rbx+8]; mov [rbx+16], rax; and rdx, [rbx+24]"
    code, _ = ks.asm(src, addr=oracle.BASE)
    init = _init_regs(oracle, rax=0x0102030405060708, rbx=oracle.MEM_BASE,
                      rcx=0xDEAD, rdx=0xFFFF)
    oracle.check(bytes(code), init=init, flags=("CF", "ZF", "SF", "OF"), mem=mem)


# ---------------------------------------------------------------------------
# 2. REFVM EQUIVALENCE on pure-subset synthetic programs
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("level", _LEVELS)
@pytest.mark.parametrize("seed", _SEEDS)
def test_refvm_equivalence_plaintext_vs_mutated(level, seed):
    for _name, src, args in _SYNTH:
        base = _full_state(src, args)
        mutated = MU.mutate_source(src, seed=seed, level=level)
        assert _full_state(mutated, args) == base, _name


def test_refvm_equivalence_random_inputs():
    rng = random.Random(1234)
    src = _SYNTH[0][1]
    for seed in _SEEDS:
        m = MU.mutate_source(src, seed=seed, level=3)
        for _ in range(200):
            a = rng.getrandbits(64); b = rng.getrandbits(64)
            assert run_plaintext(_assemble(src), [a, b])[0] == \
                run_plaintext(_assemble(m), [a, b])[0]


@pytest.mark.parametrize("level", _LEVELS)
def test_mutated_vs_mutated_plus_rolling(level):
    """A mutated program and its rolling-encoded form decode/execute identically."""
    for name, src, args in _SYNTH:
        mutated = MU.mutate_source(src, seed=b"roll", level=level)
        blob = _assemble(mutated)
        data, code = _split(blob)
        plain_val, plain_trace = run_plaintext(blob, args)
        for s in range(4):
            seed = struct.pack("<I", s) + b"\x00" * (vr.SEED_LEN - 4)
            ct, leaders = vr.encrypt_code(code, seed)
            assert vr.decode_stream(ct, seed, leaders) == code, name
            dec = vr.RollingDecoder(ct, seed, leaders)
            vm = RefVM(code, data, args, decoder=dec)
            assert vm.run() == plain_val, f"{name}: rolling halt @seed {s}"
            assert vm.trace == plain_trace, f"{name}: rolling trace @seed {s}"


# ---------------------------------------------------------------------------
# 3. STACK SAFETY
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("level", _LEVELS)
@pytest.mark.parametrize("seed", _SEEDS)
def test_stack_headroom_never_exceeds_ceiling(level, seed):
    for _name, src, _args in _SYNTH + [("data", _DATA_PROG, [1, 2])]:
        mutated = MU.mutate_source(src, seed=seed, level=level)
        assert _peak_depth(mutated) <= CEILING


def test_near_full_stack_region_left_unmutated():
    """A binary op executed with the operand stack near full cannot be expanded
    (its expansion would overflow), so it must be left bare -- fail-closed --
    while a shallow op in the same program is still expanded."""
    fillers = "\n".join("  push_imm8 1" for _ in range(54))
    pops = "\n".join("  pop" for _ in range(53))
    src = f"""
.code
  push_arg 0
  push_arg 1
  xor            ; SHALLOW (depth 2) -> expanded
  pop
  push_imm8 7
{fillers}
  xor            ; DEEP (depth 55) -> unsafe -> left bare
{pops}
  halt
"""
    # The original program legitimately runs the operand stack ~55 deep.
    assert _peak_depth(src) >= 55
    mutated = MU.mutate_source(src, seed=b"deep", level=1)
    # Exactly one xor (the shallow one) was expanded; the deep xor stays bare.
    assert mutated.count("MBA[xor]") == 1
    # A bare `xor` line survives (the deep, unmutated one).
    bare_xor = [l for l in mutated.splitlines() if l.split(";", 1)[0].strip() == "xor"]
    assert len(bare_xor) == 1, "the deep xor must remain unmutated"
    # And the mutated program is itself stack-safe and semantics-preserving.
    assert _peak_depth(mutated) <= CEILING
    assert run_plaintext(_assemble(src), [3, 4])[0] == \
        run_plaintext(_assemble(mutated), [3, 4])[0]


def test_unknown_depth_after_native_op_is_refused():
    """A site downstream of a native op (unknown stack effect) has depth None and
    must be left unmutated -- fail-closed."""
    src = """
.data
  n: db 0x4E, 0x00
.code
  data_addr 0
  n_getenv
  push_arg 0
  xor
  halt
"""
    depths = MU.stack_depth_map(src)
    # everything from the native op onward is unknown
    assert depths[-2] is None  # the xor before halt
    mutated = MU.mutate_source(src, seed=b"nat", level=3)
    assert "MBA[" not in mutated, "must not mutate downstream of an unknown depth"


# ---------------------------------------------------------------------------
# 4. DETERMINISM / REPRODUCIBILITY / CODE-ONLY
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("level", _LEVELS)
def test_same_seed_identical_different_seed_differs(level):
    src = _SYNTH[0][1]
    a = MU.mutate_source(src, seed=b"K1", level=level)
    a2 = MU.mutate_source(src, seed=b"K1", level=level)
    b = MU.mutate_source(src, seed=b"K2", level=level)
    assert a == a2, "same seed must reproduce byte-identical output"
    assert a != b, "different seeds must produce different output"


def test_level0_is_byte_identical_to_legacy_pipeline():
    """Default (level 0 / seed None) reproduces today's exact output, and a seed
    at level 0 changes nothing either."""
    for vasm in sorted(PROGRAMS_DIR.glob("*.vasm")):
        text = vasm.read_text(encoding="utf-8")
        legacy = daedalus_mba.rewrite_source(text)
        assert MU.mutate_source(text, seed=None, level=0) == legacy
        assert MU.mutate_source(text, seed=b"ignored", level=0) == legacy
    # and on synthetic programs too
    for _name, src, _args in _SYNTH:
        assert MU.mutate_source(src, seed=None, level=0) == \
            daedalus_mba.rewrite_source(src)


@pytest.mark.parametrize("level", _LEVELS)
@pytest.mark.parametrize("seed", _SEEDS)
def test_junk_is_code_only_data_size_unchanged(level, seed):
    orig_ds = struct.unpack_from("<H", _assemble(_DATA_PROG), 0)[0]
    mutated = MU.mutate_source(_DATA_PROG, seed=seed, level=level)
    new_ds = struct.unpack_from("<H", _assemble(mutated), 0)[0]
    assert new_ds == orig_ds, "mutation altered the data section"
    # data bytes themselves are byte-identical
    o_data, _ = _split(_assemble(_DATA_PROG))
    m_data, _ = _split(_assemble(mutated))
    assert o_data == m_data


@pytest.mark.parametrize("level", _LEVELS)
@pytest.mark.parametrize("seed", _SEEDS)
def test_every_mutated_program_assembles_disassembles_and_rolls(level, seed):
    for _name, src, _args in _SYNTH + [("data", _DATA_PROG, None)]:
        mutated = MU.mutate_source(src, seed=seed, level=level)
        blob = _assemble(mutated)                    # must assemble
        _txt = daedalus_disasm.disassemble(blob)      # must disassemble
        data, code = _split(blob)
        roll = vr.pack_rolling_blob(blob, b"\x01" * vr.SEED_LEN)
        r_seed, r_data, r_ct, leaders = vr.unpack_rolling_blob(roll)
        assert r_data == data
        assert vr.decode_stream(r_ct, r_seed, leaders) == code


def _main():
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            # skip parametrized (need pytest); run only zero-arg tests
            import inspect
            if inspect.signature(fn).parameters:
                continue
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except Exception:
            print(f"  FAIL  {fn.__name__}"); traceback.print_exc(); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
