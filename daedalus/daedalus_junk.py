#!/usr/bin/env python3
"""
daedalus_junk.py -- seeded instruction substitution and dead/junk insertion for
Daedalus .vasm.

Two source-level, semantics-preserving passes that raise static-analysis cost by
inflating and diversifying the instruction stream WITHOUT changing behaviour:

* ``substitute_source`` -- rewrites a handful of pure-ISA-subset instructions
  into equivalent multi-instruction sequences (an exact identity per template,
  e.g. ``not x == x ^ 0xFFFF...F``, ``neg x == (~x)+1``, ``dup == pick 0``,
  ``swap == swap;swap;swap``). Only instructions with statically-known, exact
  equivalents are touched. Labels are preserved on the first emitted instruction.

* ``insert_junk`` -- inserts provably STACK-NEUTRAL dead code (net operand-stack
  delta 0, no locals/data/memory writes) at instruction boundaries. It is
  code-only: the ``.data`` section, ``data_size`` and the container format are
  untouched.

Both passes are FAIL-CLOSED with respect to the operand stack: when a
per-instruction operand-stack-depth map (``depth_in=`` from
``daedalus_mutate.stack_depth_map``) is supplied, a site whose transformation
would push the stack past ``CEILING`` (56), or whose depth is unknown, is left
unchanged. Correctness is proven by tests/test_mutate.py against the reference
interpreter and (for lifted x64) the Unicorn oracle.
"""
from __future__ import annotations

from daedalus_mba import CEILING, MASK64, _split_label

__all__ = ["substitute_source", "insert_junk", "CEILING"]

# --------------------------------------------------------------------------
# Substitution templates. Each maps a no-operand mnemonic to (replacement,
# peak_delta) where ``replacement`` is an EXACT equivalent instruction sequence
# and ``peak_delta`` is how far above the site's entry depth the sequence peaks.
#
# Exactness (unsigned 64-bit):
#   dup  == pick 0                        (pick 0 copies TOS, identical to dup)
#   swap == swap; swap; swap              (swap is an involution: 3x == 1x)
#   not  == push 0xFFFF...F; xor          (~x == x ^ all-ones)
#   neg  == not; push_imm8 1; add         (-x == (~x) + 1  (mod 2^64))
# --------------------------------------------------------------------------
_SUBST = {
    "dup": (["pick 0"], 1),
    "swap": (["swap", "swap", "swap"], 0),
    "not": ([f"push_imm64 0x{MASK64:016X}", "xor"], 1),
    "neg": (["not", "push_imm8 1", "add"], 1),
}


def _subst_level_prob(level: int) -> float:
    if level < 2:
        return 0.0
    if level == 2:
        return 0.5
    return 0.8


def _junk_level_prob(level: int) -> float:
    if level < 2:
        return 0.0
    if level == 2:
        return 0.35
    return 0.6


# Stack-neutral junk snippets, each a function of a random 8-bit constant.
# Every snippet has net operand-stack delta 0 and writes no local/data/memory.
def _junk_snippets(rng):
    k = rng.randrange(0, 256)
    j = rng.randrange(0, 256)
    return [
        (["nop"], 0),
        ([f"push_imm8 {k}", "pop"], 1),
        ([f"push_imm8 {k}", f"push_imm8 {k}", "xor", "pop"], 2),   # k^k = 0
        ([f"push_imm8 {k}", f"push_imm8 {k}", "sub", "pop"], 2),   # k-k = 0
        ([f"push_imm8 {k}", f"push_imm8 {j}", "and", "pop"], 2),
    ]


def substitute_source(text: str, rng, level: int, *, depth_in=None,
                      indent="  ", ceiling=CEILING) -> str:
    """Replace pure-subset instructions with exact equivalent sequences.

    ``rng`` is a deterministic PRNG (a ``random.Random``). ``level`` scales the
    per-site substitution probability. ``depth_in`` is the operand-stack-depth
    map for stack-safety gating (a site whose peak would exceed ``ceiling``, or
    whose depth is unknown, is left unchanged). Only ``.code`` is touched; labels
    are preserved on the first emitted instruction.
    """
    prob = _subst_level_prob(level)
    if prob <= 0.0:
        return text

    out_lines = []
    section = None
    ordinal = -1
    for raw in text.split("\n"):
        stripped = raw.split(";", 1)[0].strip()
        if not stripped:
            out_lines.append(raw); continue
        if stripped == ".data":
            section = "data"; out_lines.append(raw); continue
        if stripped == ".code":
            section = "code"; out_lines.append(raw); continue
        if section != "code":
            out_lines.append(raw); continue

        label, rest = _split_label(stripped)
        parts = rest.split(None, 1)
        if not parts:
            out_lines.append(raw); continue
        mnem = parts[0].lower()
        operand = parts[1].strip() if len(parts) > 1 else None
        ordinal += 1

        if mnem in _SUBST and operand is None and rng.random() < prob:
            replacement, peak_delta = _SUBST[mnem]
            safe = True
            if depth_in is not None:
                d = depth_in[ordinal] if ordinal < len(depth_in) else None
                # `d` is depth before the op; every replacement peaks at
                # d + peak_delta.
                if d is None or d + peak_delta > ceiling:
                    safe = False
            if safe:
                first = True
                for ins in replacement:
                    if first and label is not None:
                        out_lines.append(f"{indent}{label}: {ins}")
                    else:
                        out_lines.append(f"{indent}{ins}")
                    first = False
                continue

        out_lines.append(raw)
    return "\n".join(out_lines)


def insert_junk(text: str, rng, level: int, *, depth_in=None,
                indent="  ", ceiling=CEILING) -> str:
    """Insert provably stack-neutral dead code at safe instruction boundaries.

    A junk block is emitted AFTER an instruction (never between a label and its
    instruction) when the instruction has a defined, reachable fall-through
    (i.e. it is not ``jmp``/``halt``/``ret``) and the block's peak stays within
    ``ceiling``. Every block has net operand-stack delta 0, so surrounding code's
    stack is untouched. Only ``.code`` is modified; ``.data`` is passed through.
    """
    from daedalus_mutate import stack_depth_map, _DELTA  # local: avoid cycle

    prob = _junk_level_prob(level)
    if prob <= 0.0:
        return text

    if depth_in is None:
        depth_in = stack_depth_map(text)

    _NO_FALLTHROUGH = {"jmp", "halt", "ret"}
    out_lines = []
    section = None
    ordinal = -1
    for raw in text.split("\n"):
        stripped = raw.split(";", 1)[0].strip()
        if not stripped:
            out_lines.append(raw); continue
        if stripped == ".data":
            section = "data"; out_lines.append(raw); continue
        if stripped == ".code":
            section = "code"; out_lines.append(raw); continue
        if section != "code":
            out_lines.append(raw); continue

        _label, rest = _split_label(stripped)
        parts = rest.split(None, 1)
        if not parts:
            out_lines.append(raw); continue
        mnem = parts[0].lower()
        ordinal += 1
        out_lines.append(raw)

        if mnem in _NO_FALLTHROUGH or mnem.startswith("n_"):
            continue
        if rng.random() >= prob:
            continue
        d = depth_in[ordinal] if ordinal < len(depth_in) else None
        delta = _DELTA.get(mnem)
        if d is None or delta is None:
            continue
        d_after = d + delta                 # operand depth after this instruction
        snippets = _junk_snippets(rng)
        block, peak_delta = rng.choice(snippets)
        if d_after + peak_delta > ceiling:
            continue
        for ins in block:
            out_lines.append(f"{indent}{ins}")

    return "\n".join(out_lines)
