#!/usr/bin/env python3
"""
daedalus_mba.py -- Mixed Boolean-Arithmetic (MBA) rewriter for Daedalus bytecode.

Solver-hostile arithmetic (NEXTGEN_PROTECTION_PLAN §6.2 / §4.2): replace simple
arithmetic opcodes with semantically-identical but algebraically-tangled
sequences over Z/2^64. A human reads `xor`; an automated simplifier
(angr/Triton/SiMBA/Arybo) sees `(a|b) - (a&b)` woven through the stack and must
prove the identity before it can fold anything.

This is a SOURCE-LEVEL (.vasm) pass: it rewrites standalone arithmetic
instructions into stack-juggling MBA expansions, then the normal assembler
recomputes all branch offsets -- so labels and control flow are untouched by
construction. It composes cleanly in front of the opcode shuffle and the rolling
encoder (both operate on the assembled wire bytes afterward).

Correctness is not argued -- it is PROVEN: tests/test_mba.py runs the reference
interpreter (daedalus_ref) on the original and rewritten programs over random
inputs and asserts identical results. An identity bug is caught by the oracle,
not shipped.

Two operating modes
-------------------
* DEFAULT (no ``seed``/``templates``): the historical fixed expansion of bare
  ``xor``/``add``. Byte-for-byte identical to the pre-metamorphism pipeline; the
  release gate depends on this being stable.

* SEEDED CATALOGUE (``seed=`` and/or ``templates=``): a per-build-seeded choice
  from a broadened catalogue of EXACT Z/2^64 identities for
  ``xor``/``add``/``sub``/``and``/``or`` (2-3 identities each), with optional
  bounded recursion (``depth=``). Each site's template is chosen by a
  deterministic PRNG derived from the build seed. When a per-instruction operand
  stack-depth map (``depth_in=``) is supplied, a site whose expansion would push
  the operand stack past ``CEILING`` (56, matching DVM_STACK_SIZE-8) is left
  UNMUTATED -- fail-closed, never overflow where the original succeeded.

Legacy identities (exact in Z/2^64), used by the DEFAULT mode:
    a ^ b = (a | b) - (a & b)
    a + b = (a ^ b) + ((a & b) << 1)

Stack discipline: each expansion consumes [.. a b] (b = TOS) and leaves
[.. result], juggling copies with `pick` and dropping the two originals with
`swap; pop; swap; pop`.
"""
from __future__ import annotations

import hashlib
import random
import re

# --------------------------------------------------------------------------
# Operand-stack ceiling. DVM_STACK_SIZE is 64; an 8-slot safety margin (the
# same 56 the T3 stack analysis uses) keeps a transformed program comfortably
# clear of the overflow-fail-closed boundary even in the deepest expansion.
# --------------------------------------------------------------------------
CEILING = 56
MASK64 = (1 << 64) - 1

# Each expansion assumes the operand stack is [.. a b] with b on top, and must
# leave [.. f(a,b)]. `pick N` copies stack[sp-1-N] to the top (pick 0 == dup).
#
# tail `swap pop swap pop` drops the two originals (a, b) left under the result:
#   [a b R] -swap-> [a R b] -pop-> [a R] -swap-> [R a] -pop-> [R]
_DROP_ORIGINALS = ["swap", "pop", "swap", "pop"]

_XOR_EXPANSION = [
    "pick 1", "pick 1", "or",      # [a b (a|b)]
    "pick 2", "pick 2", "and",     # [a b (a|b) (a&b)]
    "sub",                          # [a b (a^b)]
] + _DROP_ORIGINALS

_ADD_EXPANSION = [
    "pick 1", "pick 1", "xor",     # [a b (a^b)]
    "pick 2", "pick 2", "and",     # [a b (a^b) (a&b)]
    "push_imm8 1", "shl",          # [a b (a^b) ((a&b)<<1)]
    "add",                          # [a b (a+b)]
] + _DROP_ORIGINALS

EXPANSIONS = {
    "xor": _XOR_EXPANSION,
    "add": _ADD_EXPANSION,
}


# ==========================================================================
# Seeded catalogue: exact MBA identities as expression trees over a, b.
# ==========================================================================
# A tree node is a tuple:
#   ('a',) ('b',)              -- the two live operands ([.. a b], b = TOS)
#   ('const', v)              -- a 64-bit constant
#   ('not', X) ('neg', X)     -- unary
#   ('and'|'or'|'xor'|'add'|'sub'|'shl', L, R)  -- binary (computes L OP R)
#
# Every tree below is an EXACT identity over unsigned 64-bit arithmetic for the
# operation it is filed under. tests/test_mba.py proves each one against the
# reference interpreter over hundreds of random (a, b) pairs before it can ship.
A = ("a",)
B = ("b",)


def _c(v):
    return ("const", v & MASK64)


# xor(a, b)
_XOR_TREES = [
    # (a | b) - (a & b)
    ("sub", ("or", A, B), ("and", A, B)),
    # (a & ~b) | (~a & b)
    ("or", ("and", A, ("not", B)), ("and", ("not", A), B)),
    # (a + b) - 2*(a & b)
    ("sub", ("add", A, B), ("shl", ("and", A, B), _c(1))),
]

# add(a, b)
_ADD_TREES = [
    # (a ^ b) + 2*(a & b)
    ("add", ("xor", A, B), ("shl", ("and", A, B), _c(1))),
    # (a | b) + (a & b)
    ("add", ("or", A, B), ("and", A, B)),
    # (a - ~b) - 1     (since -~b == b + 1)
    ("sub", ("sub", A, ("not", B)), _c(1)),
]

# sub(a, b)
_SUB_TREES = [
    # a + ~b + 1
    ("add", ("add", A, ("not", B)), _c(1)),
    # (a ^ b) - 2*(~a & b)
    ("sub", ("xor", A, B), ("shl", ("and", ("not", A), B), _c(1))),
    # (a & ~b) - (~a & b)
    ("sub", ("and", A, ("not", B)), ("and", ("not", A), B)),
]

# and(a, b)
_AND_TREES = [
    # (a + b) - (a | b)
    ("sub", ("add", A, B), ("or", A, B)),
    # (a | b) - (a ^ b)
    ("sub", ("or", A, B), ("xor", A, B)),
    # ~(~a | ~b)      (De Morgan)
    ("not", ("or", ("not", A), ("not", B))),
]

# or(a, b)
_OR_TREES = [
    # (a & b) + (a ^ b)
    ("add", ("and", A, B), ("xor", A, B)),
    # (a + b) - (a & b)
    ("sub", ("add", A, B), ("and", A, B)),
    # ~(~a & ~b)      (De Morgan)
    ("not", ("and", ("not", A), ("not", B))),
]

# The per-op template catalogue. Keys are the bare mnemonics this pass expands.
CATALOGUE = {
    "xor": _XOR_TREES,
    "add": _ADD_TREES,
    "sub": _SUB_TREES,
    "and": _AND_TREES,
    "or": _OR_TREES,
}

# Human-readable identity strings (for reporting / test enumeration).
CATALOGUE_DOC = {
    "xor": ["(a|b) - (a&b)", "(a&~b) | (~a&b)", "(a+b) - 2*(a&b)"],
    "add": ["(a^b) + 2*(a&b)", "(a|b) + (a&b)", "(a - ~b) - 1"],
    "sub": ["a + ~b + 1", "(a^b) - 2*(~a&b)", "(a&~b) - (~a&b)"],
    "and": ["(a+b) - (a|b)", "(a|b) - (a^b)", "~(~a | ~b)"],
    "or":  ["(a&b) + (a^b)", "(a+b) - (a&b)", "~(~a & ~b)"],
}

_UNARY = frozenset({"not", "neg"})
_BINARY = frozenset({"and", "or", "xor", "add", "sub", "shl", "shr", "mul"})
_RECURSE_PROB = 0.5


class _Builder:
    """Emits stack code that evaluates an expression tree on top of [.. a b].

    Invariant: the two live operands ``a`` (2nd-from-top) and ``b`` (top) stay in
    place; everything is built above them by copying with ``pick``. ``depth`` is
    the running operand-stack height counted from the ``a,b`` pair (starts at 2).
    ``peak`` is the maximum height reached, so a caller can prove stack safety.
    """

    __slots__ = ("ops", "depth", "peak")

    def __init__(self) -> None:
        self.ops: list[str] = []
        self.depth = 2          # [a b]
        self.peak = 2

    def _adv(self, delta: int) -> None:
        self.depth += delta
        if self.depth > self.peak:
            self.peak = self.depth

    def emit(self, ins: str, delta: int) -> None:
        self.ops.append(ins)
        self._adv(delta)

    def push_a(self) -> None:
        # a sits 2nd from the top of the ORIGINAL pair, i.e. at pick (depth-1).
        self.emit(f"pick {self.depth - 1}", +1)

    def push_b(self) -> None:
        self.emit(f"pick {self.depth - 2}", +1)

    def push_const(self, v: int) -> None:
        v &= MASK64
        if v <= 0xFF:
            self.emit(f"push_imm8 {v}", +1)
        elif v <= 0xFFFF:
            self.emit(f"push_imm16 {v}", +1)
        else:
            self.emit(f"push_imm64 0x{v:016X}", +1)

    def binop(self, op: str) -> None:
        self.emit(op, -1)

    def unop(self, op: str) -> None:
        self.emit(op, 0)


def _emit_tree(builder: _Builder, node) -> None:
    tag = node[0]
    if tag == "a":
        builder.push_a()
    elif tag == "b":
        builder.push_b()
    elif tag == "const":
        builder.push_const(node[1])
    elif tag in _UNARY:
        _emit_tree(builder, node[1])
        builder.unop(tag)
    elif tag in _BINARY:
        _emit_tree(builder, node[1])
        _emit_tree(builder, node[2])
        builder.binop(tag)
    else:  # pragma: no cover - guards catalogue authoring mistakes
        raise ValueError(f"bad MBA tree node {node!r}")


def emit_expansion(tree):
    """Return (ops, peak) for a full expansion of `tree` over [.. a b].

    ``ops`` leaves exactly [.. result] on the stack (the two originals dropped).
    ``peak`` is the maximum operand-stack height counted from the a,b pair, i.e.
    the ABSOLUTE peak is ``(depth_before_op - 2) + peak``.
    """
    b = _Builder()
    _emit_tree(b, tree)
    # stack is now [a b result]; drop the two originals.
    b.emit("swap", 0)
    b.emit("pop", -1)
    b.emit("swap", 0)
    b.emit("pop", -1)
    return b.ops, b.peak


def _subst(node, a_sub, b_sub):
    tag = node[0]
    if tag == "a":
        return a_sub
    if tag == "b":
        return b_sub
    if tag == "const":
        return node
    if tag in _UNARY:
        return (tag, _subst(node[1], a_sub, b_sub))
    return (tag, _subst(node[1], a_sub, b_sub), _subst(node[2], a_sub, b_sub))


def _recurse(node, rng, depth, templates):
    tag = node[0]
    if tag in ("a", "b", "const"):
        return node
    if tag in _UNARY:
        return (tag, _recurse(node[1], rng, depth, templates))
    left = _recurse(node[1], rng, depth, templates)
    right = _recurse(node[2], rng, depth, templates)
    if depth > 0 and tag in templates and rng.random() < _RECURSE_PROB:
        return _build_tree(tag, left, right, rng, depth - 1, templates)
    return (tag, left, right)


def _build_tree(op, a_sub, b_sub, rng, depth, templates):
    tmpl = rng.choice(templates[op])
    tree = _subst(tmpl, a_sub, b_sub)
    if depth > 0:
        tree = _recurse(tree, rng, depth, templates)
    return tree


def _split_label(code_line: str):
    """Return (label_or_None, rest) for a .code line that may start `name:`."""
    m = re.match(r"^(\w+)\s*:\s*(.*)$", code_line)
    if m:
        return m.group(1), m.group(2).strip()
    return None, code_line.strip()


def iter_code_instructions(vasm_text: str):
    """Yield (line_index, label, mnemonic, operand) for each .code instruction.

    Canonical instruction enumeration shared by the stack-depth map and every
    mutation pass, so their per-instruction ordinals line up exactly. Label-only
    lines, comments, blanks and directives yield nothing (mirrors the assembler,
    which treats a bare ``name:`` as a label, not an instruction)."""
    section = None
    for idx, raw in enumerate(vasm_text.split("\n")):
        stripped = raw.split(";", 1)[0].strip()
        if not stripped:
            continue
        if stripped == ".data":
            section = "data"
            continue
        if stripped == ".code":
            section = "code"
            continue
        if section != "code":
            continue
        label, rest = _split_label(stripped)
        parts = rest.split(None, 1)
        if not parts:
            continue
        mnem = parts[0].lower()
        operand = parts[1].strip() if len(parts) > 1 else None
        yield idx, label, mnem, operand


def _seeded_rng(seed, salt: bytes = b"mba/v1") -> random.Random:
    """A deterministic PRNG from an arbitrary seed value."""
    if hasattr(seed, "subseed"):        # a MetamorphSeed instance
        raw = seed.subseed("mba/v1")
    elif isinstance(seed, (bytes, bytearray)):
        raw = bytes(seed)
    elif isinstance(seed, str):
        raw = seed.encode("utf-8")
    elif isinstance(seed, int):
        raw = seed.to_bytes(8, "big", signed=False)
    else:
        raw = repr(seed).encode("utf-8")
    digest = hashlib.sha256(salt + b"|" + raw).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _legacy_rewrite(vasm_text: str, ops, indent: str) -> str:
    """The historical fixed-expansion pass -- byte-identical to pre-metamorphism.
    Only bare `xor`/`add` (per `ops`) with no operand are touched."""
    ops = set(ops)
    out_lines = []
    section = None
    for raw in vasm_text.split("\n"):
        stripped = raw.split(";", 1)[0].strip()
        if not stripped:
            out_lines.append(raw)
            continue
        if stripped == ".data":
            section = "data"; out_lines.append(raw); continue
        if stripped == ".code":
            section = "code"; out_lines.append(raw); continue
        if section != "code":
            out_lines.append(raw)
            continue

        label, rest = _split_label(stripped)
        parts = rest.split(None, 1)
        mnem = parts[0].lower() if parts else ""
        operand = parts[1].strip() if len(parts) > 1 else None

        if mnem in ops and operand is None:
            expansion = EXPANSIONS[mnem]
            comment = f"{indent}; MBA[{mnem}]"
            out_lines.append(comment)
            first = True
            for ins in expansion:
                if first and label is not None:
                    out_lines.append(f"{indent}{label}: {ins}")
                    first = False
                else:
                    out_lines.append(f"{indent}{ins}")
                    first = False
        else:
            out_lines.append(raw)
    return "\n".join(out_lines)


def rewrite_source(vasm_text: str, ops=("xor", "add"), indent="  ", *,
                   seed=None, depth=0, templates=None, depth_in=None,
                   ceiling=CEILING) -> str:
    """Return `vasm_text` with standalone arithmetic ops expanded to MBA.

    DEFAULT (``seed is None and templates is None``): the legacy fixed expansion
    of bare ``xor``/``add`` -- byte-for-byte identical to the pre-metamorphism
    pipeline (the release gate relies on this).

    SEEDED (``seed`` and/or ``templates`` given): per-site template selection
    from the exact-identity catalogue. ``ops`` selects which mnemonics to expand
    (only those present in the catalogue can be), ``depth`` enables bounded
    recursive nesting, and ``depth_in`` (a per-instruction operand-stack-depth
    list from daedalus_mutate.stack_depth_map) makes each site fail-closed:
    a site with unknown depth, fewer than two operands, or an expansion peak
    above ``ceiling`` is left UNMUTATED.

    Only bare arithmetic instructions in the `.code` section are touched. A label
    that shared a line with a rewritten op is preserved on the first emitted
    instruction. Comments and `.data` are passed through verbatim.
    """
    if seed is None and templates is None and depth == 0:
        return _legacy_rewrite(vasm_text, ops, indent)

    if templates is None:
        templates = CATALOGUE
    ops = set(ops)
    rng = _seeded_rng(seed) if seed is not None else random.Random(0)

    out_lines = []
    section = None
    ordinal = -1
    for raw in vasm_text.split("\n"):
        stripped = raw.split(";", 1)[0].strip()
        if not stripped:
            out_lines.append(raw)
            continue
        if stripped == ".data":
            section = "data"; out_lines.append(raw); continue
        if stripped == ".code":
            section = "code"; out_lines.append(raw); continue
        if section != "code":
            out_lines.append(raw)
            continue

        label, rest = _split_label(stripped)
        parts = rest.split(None, 1)
        if not parts:                       # label-only line
            out_lines.append(raw)
            continue
        mnem = parts[0].lower()
        operand = parts[1].strip() if len(parts) > 1 else None
        ordinal += 1

        if mnem in ops and mnem in templates and operand is None:
            # Build the seeded expansion (consumes rng deterministically), then
            # accept it only if it is provably stack-safe.
            tree = _build_tree(mnem, A, B, rng, depth, templates)
            expansion, peak = emit_expansion(tree)
            safe = True
            if depth_in is not None:
                d_before = depth_in[ordinal] if ordinal < len(depth_in) else None
                if d_before is None or d_before < 2:
                    safe = False
                elif (d_before - 2) + peak > ceiling:
                    safe = False
            if safe:
                out_lines.append(f"{indent}; MBA[{mnem}]")
                first = True
                for ins in expansion:
                    if first and label is not None:
                        out_lines.append(f"{indent}{label}: {ins}")
                    else:
                        out_lines.append(f"{indent}{ins}")
                    first = False
                continue

        out_lines.append(raw)
    return "\n".join(out_lines)


def count_rewritable(vasm_text: str, ops=("xor", "add")) -> int:
    """How many standalone ops this pass would expand (for reporting/tests)."""
    ops = set(ops)
    n = 0
    for _idx, _label, mnem, operand in iter_code_instructions(vasm_text):
        if mnem in ops and operand is None:
            n += 1
    return n


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Daedalus MBA rewriter")
    ap.add_argument("input", help="input .vasm")
    ap.add_argument("--output", "-o")
    ap.add_argument("--ops", default="xor,add",
                    help="comma-separated ops to expand (default: xor,add)")
    args = ap.parse_args()
    ops = tuple(o.strip() for o in args.ops.split(",") if o.strip())
    text = open(args.input, encoding="utf-8").read()
    rewritten = rewrite_source(text, ops=ops)
    if args.output:
        open(args.output, "w", encoding="utf-8").write(rewritten)
    else:
        import sys
        sys.stdout.write(rewritten)


if __name__ == "__main__":
    main()
