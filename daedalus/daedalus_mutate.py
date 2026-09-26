#!/usr/bin/env python3
"""
daedalus_mutate.py -- per-build-seeded, behaviour-preserving mutation orchestrator
for Daedalus .vasm.

``mutate_source(text, seed, level)`` runs the three source-level passes in a
FIXED order -- substitution -> MBA -> junk -- each driven by its own
domain-tagged PRNG derived from the build seed, and each gated by a
stack-safety analysis so no transformed program can overflow the operand stack
where the original succeeded.

Design contracts
----------------
* DEFAULT (``seed=None`` / ``level=0``) reproduces today's output byte-for-byte.
  At level 0 mutate_source is exactly ``daedalus_mba.rewrite_source(text)`` (the
  legacy fixed expansion), so the release gate and every existing test are
  unaffected. This holds even when a seed is supplied but ``level`` is 0, which
  is what generate_programs relies on to stay byte-identical by default.

* DETERMINISM: the same seed yields byte-identical output; different seeds
  differ. All randomness derives from HKDF sub-seeds of the build seed through
  the ``metamorph_seed`` substrate (domains DOMAIN_MBA / DOMAIN_NOISE).

* COMPOSITION: mutate(source) -> assemble(shuffled) -> rolling(pack). This
  module never assembles or reorders; it only rewrites .vasm text.

Stack safety
------------
``stack_depth_map(text)`` computes, per .code instruction (in the canonical
enumeration shared with the passes), the operand-stack depth on entry, via a
control-flow fixpoint. Sites that are unreachable, ambiguous (two depths), or
downstream of an opcode with unknown stack effect (native ``n_*`` ops) get a
depth of ``None`` and are refused by every pass -- fail-closed.
"""
from __future__ import annotations

import hashlib
import random

import daedalus_mba
import daedalus_junk
from daedalus_mba import CEILING, iter_code_instructions

try:
    from metamorph_seed import MetamorphSeed, DOMAIN_MBA, DOMAIN_NOISE
except ImportError:  # pragma: no cover - metamorph_seed ships alongside
    MetamorphSeed = None
    DOMAIN_MBA = "mba/v1"
    DOMAIN_NOISE = "noise/v1"

__all__ = ["mutate_source", "stack_depth_map", "CEILING"]

# Per-mnemonic operand-stack delta (pop count negative, push positive). Native
# ``n_*`` ops are intentionally absent -> unknown delta -> downstream refused.
_DELTA = {
    "halt": -1, "nop": 0,
    "push_imm8": 1, "push_imm16": 1, "push_imm32": 1, "push_imm64": 1,
    "pop": -1, "dup": 1, "swap": 0,
    "add": -1, "sub": -1, "xor": -1, "and": -1, "or": -1,
    "shl": -1, "shr": -1, "mul": -1, "div": -1, "mod": -1,
    "neg": 0, "not": 0,
    "load8": 0, "load16": 0, "load32": 0, "load64": 0,
    "store8": -2, "store16": -2, "store32": -2, "store64": -2,
    "cmp_eq": -1, "cmp_lt": -1, "cmp_gt": -1, "cmp_ge": -1, "cmp_ne": -1,
    "jmp": 0, "jz": -1, "jnz": -1, "call": 0,
    "push_arg": 1, "local_addr": 1, "data_addr": 1,
    "ret": 0, "rot3": 0, "pick": 1,
}

_TARGET_OPS = {"jmp", "jz", "jnz", "call"}
_NO_FALLTHROUGH = {"jmp", "halt", "ret"}


def stack_depth_map(text: str):
    """Return a list ``depths`` where ``depths[k]`` is the operand-stack depth on
    entry to the k-th .code instruction (canonical enumeration), or ``None`` when
    the depth is unknown / unreachable / ambiguous.

    A forward control-flow fixpoint over the instruction graph. Edges:
      * fall-through to the next instruction (unless jmp/halt/ret);
      * branch/call target (jmp/jz/jnz/call), resolved by label;
      * a ``call`` also has a fall-through edge at the same depth (its callee is
        assumed operand-stack-balanced; a real imbalance surfaces as a depth
        conflict -> None, which is refused).
    An opcode with unknown delta (native ``n_*``) yields ``None`` downstream.
    Two conflicting depths at the same instruction collapse to ``None``.
    """
    instrs = []                 # (mnemonic, operand)
    label_to_ord = {}
    for _idx, label, mnem, operand in iter_code_instructions(text):
        if label is not None:                 # label sharing the instruction line
            label_to_ord[label] = len(instrs)
        instrs.append((mnem, operand))
    n = len(instrs)
    if n == 0:
        return []
    # A branch target may live on its own line (a bare ``name:``); bind those
    # standalone labels to the next instruction's ordinal.
    _resolve_standalone_labels(text, label_to_ord)

    depths = [None] * n
    UNKNOWN = object()
    state = {}          # ordinal -> int depth, or UNKNOWN
    work = [0]
    state[0] = 0
    while work:
        i = work.pop()
        d = state.get(i)
        if d is UNKNOWN or d is None:
            continue
        mnem, operand = instrs[i]
        delta = _DELTA.get(mnem) if not mnem.startswith("n_") else None
        d_out = None if delta is None else d + delta

        succ = []
        if mnem == "halt" or mnem == "ret":
            pass
        elif mnem == "jmp":
            t = label_to_ord.get(operand)
            if t is not None:
                succ.append((t, d_out))
        elif mnem in ("jz", "jnz"):
            if i + 1 < n:
                succ.append((i + 1, d_out))
            t = label_to_ord.get(operand)
            if t is not None:
                succ.append((t, d_out))
        elif mnem == "call":
            t = label_to_ord.get(operand)
            if t is not None:
                succ.append((t, d_out))
            if i + 1 < n:
                succ.append((i + 1, d_out))
        else:
            if i + 1 < n:
                succ.append((i + 1, d_out))

        for (s, ds) in succ:
            new = UNKNOWN if ds is None else ds
            if s not in state:
                state[s] = new
                work.append(s)
            elif state[s] is not UNKNOWN and state[s] != new:
                # conflicting depth (or now-unknown) -> collapse to UNKNOWN once
                state[s] = UNKNOWN
                work.append(s)

    for i in range(n):
        v = state.get(i, None)
        depths[i] = None if (v is None or v is UNKNOWN) else v
    return depths


def _resolve_standalone_labels(text, label_to_ord):
    """Map label-only lines to the ordinal of the next instruction.

    ``iter_code_instructions`` skips a bare ``name:`` line, so a branch target
    that lives on its own line would otherwise be missing from ``label_to_ord``.
    Walk the raw lines, remembering pending standalone labels, and bind them to
    the next real instruction's ordinal."""
    section = None
    ordinal = 0
    pending = []
    for raw in text.split("\n"):
        stripped = raw.split(";", 1)[0].strip()
        if not stripped:
            continue
        if stripped == ".data":
            section = "data"; continue
        if stripped == ".code":
            section = "code"; continue
        if section != "code":
            continue
        label, rest = daedalus_mba._split_label(stripped)
        parts = rest.split(None, 1)
        if not parts:
            # label-only line
            if label is not None:
                pending.append(label)
            continue
        # a real instruction at `ordinal`
        for p in pending:
            label_to_ord.setdefault(p, ordinal)
        pending = []
        if label is not None:
            label_to_ord.setdefault(label, ordinal)
        ordinal += 1


# --------------------------------------------------------------------------
# Per-pass PRNGs (domain-separated) and level policy.
# --------------------------------------------------------------------------
def _master_bytes(seed) -> bytes:
    if hasattr(seed, "master"):             # a MetamorphSeed
        return bytes(seed.master)
    if isinstance(seed, (bytes, bytearray)):
        return bytes(seed)
    if isinstance(seed, str):
        s = seed.strip()
        try:
            return bytes.fromhex(s)
        except ValueError:
            return s.encode("utf-8")
    if isinstance(seed, int):
        return seed.to_bytes(8, "big", signed=False)
    return repr(seed).encode("utf-8")


def _pass_rng(seed, domain: str, label: bytes) -> random.Random:
    """A deterministic PRNG for one pass, domain-separated from the build seed.

    When metamorph_seed is available the domain sub-seed comes from its HKDF
    hierarchy; otherwise a plain SHA-256 domain separation is used. Either way
    the result is a pure function of (seed, domain, label)."""
    master = _master_bytes(seed)
    if MetamorphSeed is not None:
        sub = MetamorphSeed(master).subseed(domain)
    else:  # pragma: no cover
        sub = hashlib.sha256(domain.encode("utf-8") + b"|" + master).digest()
    digest = hashlib.sha256(sub + b"|" + label).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _mba_seed(seed, domain: str = DOMAIN_MBA) -> bytes:
    master = _master_bytes(seed)
    if MetamorphSeed is not None:
        return MetamorphSeed(master).subseed(domain)
    return hashlib.sha256(domain.encode("utf-8") + b"|" + master).digest()  # pragma: no cover


_MBA_OPS = ("xor", "add", "sub", "and", "or")


def _recursion_depth(level: int) -> int:
    return 1 if level >= 3 else 0


def mutate_source(text: str, seed=None, level: int = 0) -> str:
    """Run substitution -> MBA -> junk over ``text`` in a fixed order.

    ``level`` (0..3+) scales intensity:
      0  -- no mutation; returns the legacy MBA output byte-for-byte identical to
            today's pipeline (regardless of ``seed``).
      1  -- seeded MBA catalogue only (depth 0).
      2  -- substitution + seeded MBA (depth 0) + stack-neutral junk.
      3+ -- substitution + seeded MBA with bounded recursion (depth 1) + junk.

    ``seed`` may be raw bytes, a hex/utf-8 string, an int, or a MetamorphSeed;
    per-pass PRNGs are domain-separated sub-seeds of it. Every pass is gated by a
    freshly computed ``stack_depth_map`` so no site can overflow the operand
    stack (ceiling ``CEILING`` == 56).
    """
    if level <= 0:
        # Byte-identical default: exactly the legacy fixed expansion.
        return daedalus_mba.rewrite_source(text)

    # Pass 1: instruction substitution (domain: noise, label 'subst').
    if level >= 2:
        rng = _pass_rng(seed, DOMAIN_NOISE, b"subst")
        d1 = stack_depth_map(text)
        text = daedalus_junk.substitute_source(text, rng, level, depth_in=d1)

    # Pass 2: MBA catalogue expansion (domain: mba).
    d2 = stack_depth_map(text)
    text = daedalus_mba.rewrite_source(
        text,
        ops=_MBA_OPS,
        seed=_mba_seed(seed),
        depth=_recursion_depth(level),
        templates=daedalus_mba.CATALOGUE,
        depth_in=d2,
    )

    # Pass 3: stack-neutral dead/junk insertion (domain: noise, label 'junk').
    if level >= 2:
        rng = _pass_rng(seed, DOMAIN_NOISE, b"junk")
        d3 = stack_depth_map(text)
        text = daedalus_junk.insert_junk(text, rng, level, depth_in=d3)

    return text


def main():  # pragma: no cover - thin CLI
    import argparse
    ap = argparse.ArgumentParser(description="Daedalus mutation orchestrator")
    ap.add_argument("input")
    ap.add_argument("--output", "-o")
    ap.add_argument("--seed", default=None)
    ap.add_argument("--level", type=int, default=0)
    args = ap.parse_args()
    text = open(args.input, encoding="utf-8").read()
    out = mutate_source(text, seed=args.seed, level=args.level)
    if args.output:
        open(args.output, "w", encoding="utf-8").write(out)
    else:
        import sys
        sys.stdout.write(out)


if __name__ == "__main__":
    main()
