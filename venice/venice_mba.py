#!/usr/bin/env python3
"""
venice_mba.py -- Mixed Boolean-Arithmetic (MBA) rewriter for Venice bytecode.

Solver-hostile arithmetic (NEXTGEN_PROTECTION_PLAN §6.2 / §4.2): replace simple
arithmetic opcodes with semantically-identical but algebraically-tangled
sequences over Z/2^64. A human reads `xor`; an automated simplifier
(angr/Triton/SiMBA/Arybo) sees `(a|b) - (a&b)` woven through the stack and must
prove the identity before it can fold anything.

This is a SOURCE-LEVEL (.vasm) pass: it rewrites standalone `xor` / `add`
instructions into stack-juggling MBA expansions, then the normal assembler
recomputes all branch offsets -- so labels and control flow are untouched by
construction. It composes cleanly in front of the opcode shuffle and the rolling
encoder (both operate on the assembled wire bytes afterward).

Correctness is not argued -- it is PROVEN: tests/test_mba.py runs the reference
interpreter (venice_ref) on the original and rewritten programs over random
inputs and asserts identical results. An identity bug is caught by the oracle,
not shipped.

Identities used (exact in Z/2^64):
    a ^ b = (a | b) - (a & b)
    a + b = (a ^ b) + ((a & b) << 1)

Stack discipline: each expansion consumes [.. a b] (b = TOS) and leaves
[.. result], juggling copies with `pick` and dropping the two originals with
`swap; pop; swap; pop`. Peak ABSOLUTE depth during an expansion is base+5 (e.g.
`[a b (a^b) a b]`), so an `xor`/`add` rewritten while the operand stack is
already at depth >= VVM_STACK_SIZE-5 (= 59) would overflow where the original
succeeded. This is FAIL-CLOSED (overflow -> exec returns -1, never a silent
wrong result) and the shipped crypto programs run far shallower, but keep this
5-slot headroom in mind before virtualizing deep-stack code.
"""
from __future__ import annotations

import re

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


def _split_label(code_line: str):
    """Return (label_or_None, rest) for a .code line that may start `name:`."""
    m = re.match(r"^(\w+)\s*:\s*(.*)$", code_line)
    if m:
        return m.group(1), m.group(2).strip()
    return None, code_line.strip()


def rewrite_source(vasm_text: str, ops=("xor", "add"), indent="  ") -> str:
    """Return `vasm_text` with standalone `xor`/`add` (per `ops`) expanded to MBA.

    Only bare arithmetic instructions in the `.code` section are touched. A label
    that shared a line with a rewritten op is preserved on the first emitted
    instruction. Comments and `.data` are passed through verbatim.
    """
    ops = set(ops)
    out_lines = []
    section = None
    for raw in vasm_text.split("\n"):
        # Preserve original line if it is a comment-only / blank / directive line.
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


def count_rewritable(vasm_text: str, ops=("xor", "add")) -> int:
    """How many standalone ops this pass would expand (for reporting/tests)."""
    ops = set(ops)
    n = 0
    section = None
    for raw in vasm_text.split("\n"):
        stripped = raw.split(";", 1)[0].strip()
        if stripped == ".data":
            section = "data"; continue
        if stripped == ".code":
            section = "code"; continue
        if section != "code" or not stripped:
            continue
        _label, rest = _split_label(stripped)
        parts = rest.split(None, 1)
        mnem = parts[0].lower() if parts else ""
        operand = parts[1].strip() if len(parts) > 1 else None
        if mnem in ops and operand is None:
            n += 1
    return n


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Venice MBA rewriter")
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
