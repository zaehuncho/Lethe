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
- `win64_thunk.py` — deterministic MASM entry-shim generator and fixed code,
  relocation, and unwind constants.
- `virtualization_plan.py` — builder-only explicit-function compiler. It accepts
  `(name, RVA, size)` specs plus strict section bytes, rejects partial or
  ambiguous functions, and emits a deterministic no-write placement manifest.
- `function_discovery.py` — read-only pdata/export discovery, optional exact
  MSVC MAP binding, lift diagnostics, direct-reference coverage gaps, and
  deterministic JSON/starter manifests. Export-only leaf sizing is deliberately
  heuristic, capped, labelled, and never selected for production automatically.
- `../tools/virtualization_report.py` — CLI renderer for that report; it does
  not invoke the packer or mutate the inspected image.

## Fixed model (do NOT change without updating both sides)
- 16 GPRs → VM locals at offsets `0,8,…,120` (`REG_OFF`, order = `GPR_NAMES`).
- Flags `CF/PF/ZF/SF/OF` → locals `128/232/136/144/152`.
- Scratch `SA/SB/SR` → `160/168/176` (operand a, b, result for flag math).
- Internal-call depth uses local `240`, 32 shadow return VAs use `248..503`,
  and the loader-relocated image base uses local `504`.
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
- **Cut 5** — low 8-bit (`AL/CL/DL/BL`, `SPL/BPL/SIL/DIL`, `R8B..R15B`) and
  16-bit (`AX..R15W`) register reads/writes; narrow writes preserve untouched
  parent bits while 32-bit writes still zero-extend. Adds `movzx`, `movsx`,
  64-bit-destination `movsxd`, non-parity `setcc`/`cmovcc`, register `xchg`,
  32/64-bit `bswap`, and exact `adc`/`sbb` CF/PF/ZF/SF/OF behavior. Scalar memory
  sources are supported where their decoded width exactly matches; `setcc`
  supports a byte memory destination, and memory `xchg` remains rejected.
- **Cut 6** — scalar memory destinations: immediate/register `mov` stores and
  ordinary non-LOCK `add/sub/xor/and/or/adc/sbb/cmp/test/inc/dec/neg/not`
  read-modify-write forms at 8/16/32/64 bits. Effective addresses are captured
  before source evaluation and the full register/flag/memory result is checked
  against Unicorn. `LOCK` and implicit-atomic memory `xchg` remain fail-closed.
- **Cut 7** — parity flag import/export and even-low-byte parity updates for
  arithmetic, logical, shift, compare, and test operations. This enables
  `jp`/`jnp`, `setp`/`setnp`, and `cmovp`/`cmovnp` with oracle coverage.
- **Cut 8** — Win64 stack-frame primitives: 64-bit register/immediate/memory
  `push`, register/memory `pop` (including architectural `pop rsp` ordering),
  and `leave`. The oracle can now map a caller stack region and compares both
  register and stack-memory effects.
- **Cut 9** — direct near `call` targets wholly inside one selected extent.
  Context-sensitive analysis gives every plain `ret` exactly one role: internal
  VM return or top-level native-thunk return. CALL writes the ASLR-correct next
  RIP to the architectural stack and a 32-frame VM-local shadow; internal RET
  validates that slot, restores RSP, then uses the Daedalus return stack. Nested
  and early-return paths are checked against Unicorn and the native C runtime.
- **Cut 10** — one-operand unsigned `mul` and signed `imul` at 8/16/32/64
  bits, including register and scalar-memory sources. The implicit
  `AX`/`DX:AX`/`EDX:EAX`/`RDX:RAX` products, narrow parent preservation,
  32-bit zero-extension, and defined `CF`/`OF` results are differential-checked
  against Unicorn. The packed native corpus exercises both 64-bit forms.
- **Cut 11** — 32/64-bit `shld` and `shrd` with register or ordinary memory
  destinations, register sources, and immediate/`CL` counts. Architectural
  count masking, zero-count flag preservation, 32-bit parent zero-extension,
  effective-address evaluation order, and every defined `CF/PF/ZF/SF/OF`
  result are differential-checked. The native Win64 entry-thunk test executes
  both operations through an actual generated selected-function thunk.
- **Cut 12** — legacy XMM0-XMM15 capture plus register-only `movd`, `movq`,
  `movaps`, `movups`, `movdqa`, `movdqu`, `pxor`, `xorps`, and `xorpd`. Each
  128-bit register occupies two 64-bit VM lanes. Directed and deterministic
  fuzz cases compare the full XMM/GPR/flags state against Unicorn. Native-frame
  and entry-thunk tests exercise plain and rolling bytecode drawn from this
  bounded subset; the real XFG DLL pack exercises XMM-shaped Win64 ABI values
  in eager mode. The memory-guard selected-function proof remains scalar. XMM
  memory operands and VEX/EVEX encodings remain fail-closed.
- **Cut 13** — bounded RIP-relative scalar data addressing. Iced decodes every
  source at its 32-bit RVA; the lift computes each effective address as runtime
  image base local `504` plus the decoded target RVA, so ASLR never bakes a
  preferred VA into bytecode. Existing scalar memory operations and `lea` may
  reference one mapped, non-executable section when the complete byte span has
  the required PE read/write permissions. Virtual zero-fill is valid. Header,
  gap, cross-section, discardable-section, executable-byte, address-taken-code,
  selected-extent, and unknown-layout references remain whole-function rejections. Manifest and
  discovery JSON record the instruction RVA, target RVA, span, and access kind.
  Differential tests use a deliberately nonpreferred runtime base; the native
  eager/memory-guard gate forces relocation of a `/DYNAMICBASE` fixture.


- **Cut 14** - legacy high-byte `AH/BH/CH/DH`, `CBW/CWDE/CDQE/CWD/CDQ/CQO`,
  two-/three-operand 16-bit `imul`, and register-target `bt/bts/btr/btc`.
  Ordinary register and memory `shl/shr/sar/rol/ror` now cover 8/16/32/64-bit
  destinations with the architectural five-/six-bit count mask, rotate-width
  reduction, zero-count behavior, and defined flag results. Dead-flag
  elimination is not enabled by the default lift path.

Still **bails** (left native — correctness over coverage): external, indirect,
recursive, over-depth, or context-ambiguous `call`/`ret` graphs; `ret imm16`,
`div`/`idiv` because the current thunk cannot deliver architectural `#DE`,
ALU with a memory **dest**
(read-modify-write) when LOCK-prefixed, unvalidated RIP-relative references,
RIP targets in headers/gaps/discardable sections/code/selected extents,
segment memory, 16-bit `shld`/`shrd`, memory-target `bt/bts/btr/btc` bit strings,
XMM memory forms,
SIMD/FP arithmetic, VEX/EVEX encodings, YMM/ZMM state, string ops, and
indirect/external branches.

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
The native VM exposes `daedalus_vm_exec_x64`, and `win64_thunk.py` emits a small
descriptor-selecting entry shim backed by `daedalus_x64_enter_common`. The bridge
captures the fixed 16-GPR + CF/PF/ZF/SF/OF frame, preserves the original entry RSP
for stack arguments, captures XMM0-XMM15 as two 64-bit lanes, restores the
Win64 nonvolatile GPRs and XMM6-XMM15, and has MASM unwind metadata.
The VM frame still exports CF/PF/ZF/SF/OF for lifted semantics, but physical Win64
return flags are ABI-volatile and are not restored by the legal
`add rsp,40; ret` epilogue. A nonzero VM HALT/status takes the generated
fail-fast path. Descriptor versions 3 (plain, 24 bytes) and 4 (paged, 40 bytes)
carry a separate loader-relocated image-base pointer. The bridge rejects a zero
base and imports it into VM local 504, so internal CALL return slots remain exact
after ASLR. Native/external calls still require a rigorously typed ABI bridge;
they are not routed through the legacy generic pointer-call opcode. Each
instruction addition remains oracle-gated.

The oracle models a writable memory region: `oracle.check(code, init, flags,
mem=<initial bytes>)` maps it in both Unicorn and the reference VM (via the
additive `RefVM(mem=..., mem_base=...)` param) and compares the final bytes.
`oracle.check_rip_data(...)` additionally separates source RVA from a relocated
runtime image base and proves the resolved registers, flags, and data bytes.

## Runtime integration (build-time C, not in this Python reference)
The next packer interface is:

```python
manifest = compile_virtualization_manifest(
    specs,  # explicit FunctionSpec(name, rva, size) allowlist only
    SectionImage.from_parsed_sections(parsed.sections),
    generated_text_rva=reserved_vtext_rva,
    generated_data_rva=reserved_vdata_rva,
    rolling=False,
    # Production supplies a sealer that returns
    # (authenticated_DVPG_v1_envelope, expected_program_id).
    program_sealer=seal_with_pack_master_key,
    opcode_table=OpcodeTable.from_mapping(
        generated_stub_opcode_map,
        identity=stub_build_id,
    ),
    require_shuffled_opcodes=True,
    expected_opcode_mapping_sha256=stub_exports[
        "daedalus_opcode_mapping_sha256"
    ],
    source_dir64_relocations=tuple(
        SourceDir64Relocation(rva) for rva in parsed_dir64_target_rvas
    ),
    require_source_relocation_metadata=True,
    source_exception_metadata=SourceExceptionMetadata(
        table_rva=parsed_exception_directory_rva,
        records=tuple(parsed_runtime_functions),
    ),
    require_source_exception_metadata=True,
    runtime_common_rva=(
        stub_graft_delta + stub_export_rvas["daedalus_x64_enter_common"]
    ),
)
```

The stub exports `daedalus_x64_enter_common`, `daedalus_opcode_mapping_sha256`,
and `daedalus_handler_variant_sha256`; these survive stripping. Production
materialization requires both hashes, the authenticated-paging capability, and
the numeric post-graft common-entry RVA to match the exact fresh build. Missing
provenance is a hard error. Production emits only the version-2 descriptor:
trusted envelope size, relocated envelope pointer, and an expected 16-byte
program identity. The VM authenticates metadata once, validates record geometry
again on each page open, and decrypts only through an invocation-local one-page
cache. The packer consumes this
manifest transactionally: verify the opcode-map hash against the stub build and
every original-byte hash; copy each program, unwind
blob, descriptor, and fixed 40-byte `thunk_template` at the declared RVAs; fill
its zeroed `REL32`/`DIR64` holes, including the descriptor's program pointer and
image-base pointer (using the recorded numeric common RVA, never a
PDB or link-map symbol); merge/register the emitted `RUNTIME_FUNCTION`
records; preserve every declared source CFG target; then apply each deterministic full-extent
`target_entry_patch` only after all validation succeeds. That replacement is an
`E9 rel32` entry followed by one-byte `INT3` tombstones at every remaining RVA,
so the original tail is scrubbed and an interior entry faults. A selected extent
under five bytes, a target-to-thunk displacement outside signed rel32 reach, or any
source DIR64 relocation target overlapping a selected extent is a hard bailout.
An explicit empty DIR64 metadata set is distinct from missing metadata. Rolling
containers and nonempty VM data regions are rejected for production-selected
functions; the raw program is never materialized beside its paged envelope.

The exception mutation plan is also all-or-nothing. Source AMD64
`RUNTIME_FUNCTION` records must arrive as an immutable tuple sorted by
`BeginAddress`, with non-overlapping code ranges and explicit unwind flags. A
record exactly matching a selected function is removed and replaced by the
generated thunk record. Partial overlaps and selected records using EHANDLER,
UHANDLER, or CHAININFO are rejected. Retained and generated records are merged
in address order into one deterministic table allocated inside the declared
generated-data reservation; each generated record and each function unwind plan
contains its final record RVA. The manifest carries the retained, removed,
generated, merged, and packed-table views so the materializer can replace the
exception directory without rediscovering policy.

Every external caller or branch must enter at the selected function's first
byte. An edge into any interior RVA could bypass the entry JMP and is therefore
outside this milestone's contract. The production transform remains explicit
selection only and has no partial-lift fallback; the separate discovery report's
bounded export-leaf heuristic is advisory and excluded from starter selection.
The materializer now merges unwind records and the loader registers the restored
exception table. Supported modern MSVC GuardCF inputs retain a live outer load
config, merged target tables/relocations, restored support slots, and runtime
target registration; unsupported load-config families fail closed. CET-specific
metadata remains future validation work. A selected function keeps its original
GFID and XFG hash identity at the source RVA. That RVA is patched with a direct
`E9 rel32` transfer, while the generated thunk is explicitly direct-only and is
never added to the Guard CF function table. Crafted manifests or sideband state
that attempt to declare a generated thunk GFID fail before materialization.

## Dependencies (builder-side, test-only here)
`iced-x86` (decode), `unicorn` + `keystone` (oracle/tests). The tests
`importorskip` them, so the suite still runs where they're absent.
