# Lethe x64 → Daedalus lifter

Lifts selected x64 functions of a target binary into Daedalus VM bytecode, so the
packer can **virtualize the app's own functions** (not just the stub's hand-
authored programs). This is the hardest component of a virtualizing protector, so
it is built the safe way: a supported subset + a **hard bail-out** on anything
else + a **differential oracle** that proves every lift correct.

## Files
- `x64_lifter.py` — decode (iced-x86) → lift to Daedalus asm. `lift_function(code,
  base)` returns `.vasm` text or raises `LiftUnsupported`.
- `oracle.py` — `check(code, init, flags)`: run the x64 in **Unicorn** and the
  lifted bytecode in the **Daedalus reference interpreter**; the 16 GPRs + the
  requested flags must match, or it raises. Nothing lands without this.

## Fixed model (do NOT change without updating both sides)
- 16 GPRs → VM locals at offsets `0,8,…,120` (`REG_OFF`, order = `GPR_NAMES`).
- Flags `CF/ZF/SF/OF` → locals `128/136/144/152`.
- Scratch `SA/SB/SR` → `160/168/176` (operand a, b, result for flag math).
- Interpreter facts the lifting relies on: `cmp_lt/gt/ge` are **unsigned**;
  `shr` is **logical**; `store64` pops `[addr, val]`; shift counts mask by 63.

## Coverage (proven by the oracle)
- **Cut 1** — `mov, add, sub, and, or, xor, cmp, test, inc, dec, neg, not,
  shl, shr, jmp, jcc, ret, nop`, 64-bit register + immediate.
- **Cut 2** — 32-bit register operands (`eax..r15d`); reads mask low-32, writes
  zero-extend the parent; flags at bit 31.
- **Cut 3** — `lea` (address arithmetic), `imul` (2/3-operand, with the
  128-bit-product CF/OF), `sar`, `rol`/`ror`, and shift/rotate by `CL`.
- **Cut 4** — **memory operands**: `mov` load/store (32/64-bit) and ALU/`imul`
  with a memory **source**, over `[base + index*scale + disp]`. Verified against
  Unicorn on registers, flags, **and a shared memory region**.

Still **bails** (left native — correctness over coverage): `call`/`ret`,
`mul`/`div` and 1-operand `imul` (rdx:rax), ALU with a memory **dest**
(read-modify-write), `mov [mem], imm`, RIP-relative/segment memory, 8/16-bit
sub-registers, `movzx`/`movsx`, SIMD, string ops, indirect/external branches.

## Extending it (the fan-out contract)
To add an instruction:
1. Add a lifter branch in `_Lifter.lift()` and a helper if needed. Reuse
   `rd_reg/wr_reg`, `push_operand`, the `SA/SB/SR` scratch, and the `flags_*`
   emitters. Bail (`raise LiftUnsupported`) on any operand form you don't handle.
2. Add a directed `oracle.check(...)` test AND extend the fuzzer in
   `tests/test_lifter.py`. **A change is not done until the oracle passes** —
   especially flags. Flags are the #1 source of silent mis-lifts.
3. For undefined-flag cases (e.g. `shl` by n≠1 leaves OF undefined), restrict the
   test's `flags=(...)` to the defined ones.

## Next
`call`/`ret` with Win64-ABI glue (the last big lifter piece), then the runtime
C thunk below. ALU-with-memory-dest (read-modify-write) and `mov [mem], imm` are
small follow-ons. Each gated behind an oracle pass.

The oracle models a writable memory region: `oracle.check(code, init, flags,
mem=<initial bytes>)` maps it in both Unicorn and the reference VM (via the
additive `RefVM(mem=..., mem_base=...)` param) and compares the final bytes.

## Runtime integration (build-time C, not in this Python reference)
The packer replaces a lifted function with a thunk that loads the incoming
registers into the VM local frame, runs `daedalus_vm_exec` on the lifted (rolling+
shuffled) bytecode, and writes the result registers back per the Win64 ABI. That
glue is native and is validated by the existing stub round-trip harness.

## Dependencies (builder-side, test-only here)
`iced-x86` (decode), `unicorn` + `keystone` (oracle/tests). The tests
`importorskip` them, so the suite still runs where they're absent.
