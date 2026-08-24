# Lethe — Next-Gen Protection Design & Roadmap

> Internal, build-time protection of Orion's **own** first-party x64 Windows
> binaries. Everything here is anti-reverse-engineering / anti-dump / anti-tamper
> of our own IP. **Hard constraints (non-negotiable):** stay Windows-Defender
> clean (no AV/EDR evasion, no anti-cheat interaction), no RWX pages, no
> self-modifying `.text`, kernel32-only freestanding no-CRT stub, and **never
> brick a paying customer** (the real license gate is server-side; a client-side
> crack of the decoy buys the attacker nothing).

This document is the synthesized output of a 12-lens ideation → novelty-triage →
adversarial red-team pass (97 raw ideas → 25 survivors, all 25 individually
attacked by a simulated senior reverse engineer and hardened against that
attack). The 11 ideas that were killed for brick-risk or AV-risk are recorded at
the bottom as guardrails — **do not resurrect them.**

---

## 1. The one finding that shapes everything

We red-teamed every technique against a top-tier analyst. The result was
strikingly consistent:

- Against **static analysis** (IDA/Ghidra/HexRays, offline lifters, file-only
  devirtualizers) — almost everything here **wins outright**.
- Against **in-process instrumentation** (x64dbg, Frida, Pin/DynamoRIO, hardware
  breakpoints, single-step) — most techniques win *if* we couple them to a
  tamper-reactive signal, because instrumentation perturbs state we can fold into
  keys.
- Against the **passive observer** — Intel Processor Trace / a thin hypervisor
  tracer, or simply *run the unmodified binary cleanly once and snapshot RAM* —
  most techniques only **survive weakened.** This adversary generates **zero
  in-process events**: no faults we can see, no branch to poison, no byte to
  hash-check, no timing to trip. And our own documented residual hands them the
  prize: after a clean run, keys and license logic in `.rdata`/`.data` sit
  **plaintext for the process lifetime**, and any executed code page is briefly
  plaintext+RX.

**Therefore the north star is not "stop execution being observed" — that's
impossible for code the CPU must run. It is:**

1. **Never let a whole secret exist at one instant.** No full key, no full
   bytecode blob, no full import map, no whole decrypted section — ever resident
   contiguously. Force the observer to *stitch* many time-sliced fragments.
2. **Fold the environment/trace into keys, not into branches.** A branch is one
   byte to NOP or one bit to pin. A summand inside HKDF has no NOP and no compare
   — a dirty read just derives the wrong key, downstream and silent.
3. **Make one clean trace non-general.** Path-/run-/build-dependent decode means
   the analyst's single recorded trace is valid only for that exact run, so they
   must re-capture per build and drive the live app to full coverage.
4. **Route detection to silent deception, never to a crash.** A crash is a
   breadcrumb straight to the check. A plausible wrong answer burns days and
   poisons the analyst's confidence in every "successful" unpack.

Every technique below is an application of one or more of these four to a
specific surface. That coherence — not any single trick — is what makes this
different from VMProtect/Themida (recognizable fixed VM, static across builds,
crash-on-detect) and gives the "how did they even think to couple *that* to the
key?" reaction.

---

## 2. Four shared primitives (build these once, reuse everywhere)

Implement these as the foundation; every track consumes them.

| # | Primitive | What it is | Consumed by |
|---|-----------|-----------|-------------|
| P1 | **Rolling state accumulator** | A 64-bit (+ SHA/ARX midstate) fold updated at the `vvm_push`/`vvm_pop` choke points and at each dispatched `opcode‖operand‖sp‖taken-edge`. The one keystream/decode seed. | VM decode, key binding, handler chaining, decode-of-dispatch |
| P2 | **Fine-grained crypto (memguard v3)** | Per-page AEAD + per-shard key assembly so no whole section/key/blob is ever resident; randomized short re-encrypt jitter; decoy resident pages. | Anti-dump, moving code, JIT secrets |
| P3 | **Environment-as-summand KDF** | `antidebug.c` reads (PEB, DR0-3, remote-debug flag, TLS-ran boolean, code-hash, quantized self-timing bucket) become HKDF `info` terms, not `if()`s. Baked expectations in `container.py`. | Anti-automation, tamper response, key binding |
| P4 | **Silent deception router** | A tamper/analysis signal selects *which cryptographically-valid blob/key/OEP* is used (real vs decoy) — both decrypt cleanly, so a false positive is survivable and a true positive is invisible. | All deception, tamper response |

**Also foundational (do first):**
- **Per-build seed** shared across `venice_asm.py` / `venice_vm.c` /
  `venice_disasm.py` / `shuffle_opcodes.py` so every build is structurally unique.
- **Differential harness**: assembler-simulated result vs interpreter result must
  match bit-exactly on a clean build, or the *pack* fails (never the customer).
  This is the safety net for every rolling/entangled scheme.
- **Universal kill-switches**: `--tamper-fold={off,env,timing}`,
  `--deception={off,on}`, per-feature flags in `PackInfo.flags`. Ship hardened
  builds only after AV-smoke + clean-VM A/B.

---

## 3. Track 1 — Venice VM overhaul (the centerpiece)

Goal: defeat automated lifters/devirtualizers and make the bytecode unliftable
statically and non-general dynamically. Ordered by build sequence.

### 1.1 Threaded, decode-fused dispatch — *kill the readable `switch()`*
Replace `vvm_run`'s `switch(op)` with **subroutine-threaded handler thunks**
(read-only, CFG-registered table) dispatched by computed-goto. The post-unmap
opcode index becomes a **jump target, not a readable integer** — no dispatcher
loop for VMHunt/back-edge heuristics to fingerprint. *Files:* `venice_vm.c`,
`venice_disasm.py` (matching emulator). *No ABI change.* Effort: **M**.

### 1.2 Path-Entangled Rolling Bytecode — *the blob is ciphertext that eats itself*
Wrap the single fetch site so each instruction is **JIT-decrypted from the
rolling accumulator (P1)** keyed on running ARX state + stack-top + the
actually-taken edge, then the consumed bytes are re-encrypted/zeroed behind PC.
`venice_asm.py` emits the pre-image-encrypted stream by **simulating the concrete
execution**; branch targets reseed from a per-target header constant so *legit*
branching decodes but forked/out-of-order exploration self-corrupts to zeros.
Keep `code[]` in a private **RW `VirtualAlloc` page** (data self-modification —
**not** `.text`, stays AV-clean).
- **Red-team hardening (mandatory):** a passive tracer captures at the one
  post-decrypt window. So (a) decrypt each *operand lazily inside its handler* —
  never a whole instruction at one site; (b) **fold an anti-instrumentation
  signal** (DR0-3, code-page self-CRC, trap-flag state, quantized RDTSC bucket)
  into the accumulator so a watchpoint/PAGE_GUARD/Stalker relocation perturbs it
  → the *next* decrypt yields garbage (the "eaten to zeros" property now works
  against the live tracer); (c) fold-in **output validation** so a corrupted run
  fails closed instead of leaking a clean trace.
*Files:* `venice_vm.c`, `venice_asm.py`, header `[u16 data_size]` reseed
constants. Effort: **L**. Risk: legit-run brittleness from timing/protection
mixing → gate those summands to quantized/robust bits + rely on the differential
harness.

### 1.3 Trace-Hashed Handler Chaining — *the next handler is a hash of how you got here*
Each handler ends with `next = handler_table[op] ^ mask(h)` where `h` is the P1
accumulator; on a genuinely executed path `h` cancels, on an assumed/forked path
it derails into a **decoy thunk**. *Hardening:* fold `crc32(thunk_bytes)` into
`h` so any 0xCC/inline hook on a handler entry corrupts `h` and derails —
punishes DBI/x64dbg directly. Inject **operand-dependent folds** into the
straight-line crypto handlers so even branch-free code can't be replayed from one
generic trace. *Files:* `venice_vm.c`, `venice_disasm.py`. Effort: **M**.

### 1.4 History-Keyed Decode & Overlapping Encoding — *one byte, two opcodes*
Promote `VVM_OPCODE_UNMAP` from const to **live-permuting**:
`decode = UNMAP[wire ^ acc ^ (acc>>29)]`, with a `VVM_RESYNC` op reseeding at loop
headers so iterations re-enter identically. Because the ISA already decodes
byte-by-byte, lay **overlapping/stride-permuted spans** where the same bytes are
a real KDF at one entry and a plausible-wrong KDF at offset+1. A static
byte→opcode assignment *provably does not exist.* *Hardening:* make the
overlapping decoy **actually execute** on real runs as a deception poison (so one
trace isn't self-evidently the real routine), and fuse the `acc`-mixed decode
into the computed-goto so no clean integer opcode ever materializes. *Files:*
`venice_vm.c`, `venice_asm.py` (becomes a forward simulator solving per wire
byte). Effort: **L**.

### 1.5 Image-Bound Opcode Semantics — *the ISA doesn't exist until the real image decrypts*
Materialize the opcode permutation via HKDF from the **code-hash-bound key** that
only exists after a `.text`-hash-verified section decrypt. *Hardening:* never let
the full 256-entry table be resident — use an **inline keyed PRP** (3-4 round
ARX/S-box) over the opcode byte at each dispatch, and **rotate it per basic
block** by mixing the VM PC into the HKDF info. A snapshot yields no table; the
analyst must enumerate all 256 inputs *per position.* *Files:* `venice_vm.c`,
`shuffle_opcodes.py` (emits HKDF seed, not a static array). Effort: **M**.

### 1.6 Reflective Microcode — *handlers are deliberately incomplete*
Move the meaning-bearing constants (which rotate, which fold, which mask) out of
handler C and into the **encrypted `data[]` blob**, resolved per-program.
*Hardening:* resolve params through the **rolling accumulator** (same
`VVM_FOLD` reads a different effective mixing each iteration), decrypt one param
at a time under P2 and re-encrypt immediately, and derive the param key partly
from the handler's own instruction bytes so an inline hook silently poisons the
values it's trying to read. *Files:* `venice_vm.c`, `venice_asm.py`,
`generate_programs.py`. Effort: **M**.

### 1.7 Defunctionalized CPS — *no call stack, no return opcode*
Build-time CPS transform: every call → `push cont-id; jump callee`, every return
→ `pop id; DISPATCH_CONT`. Delete `ret_stack[]`/`rsp`. *Hardening (required, or
it's a worse single chokepoint):* make the continuation id **opaque and
runtime-keyed** (MBA-mixed with the P1 accumulator) and keep the id→target table
under P2, never plaintext-resident. Ship **only** composed with 1.2/1.3, never on
the standalone "nothing to key on" claim. *Files:* `venice_asm.py`, `venice_vm.c`.
Effort: **M**. Note: 64-slot cap forbids deep recursion — add a build-time depth
check.

### 1.8 Self-Generating Inner VM — *the inner program is an output, not a file*
The outer program computes the inner VM's bytecode as **data**, then trampolines
(`VVM_N_CALL_PTR`, `venice_trampoline.asm`) into a nested `vvm_execute` under a
different HKDF-seeded ISA. The inner blob appears nowhere in the packed file.
*Hardening:* never materialize the whole inner program — **lazy keyed-stream
fetch** (rolling key) so at most one inner opcode is live; break determinism by
seeding the inner ISA from decrypted secret/license state so a dump doesn't
generalize across runs/builds; interleave inner/outer steps (mode flag) so "a
second `vvm_execute` call" isn't a clean breakpoint signal. *Files:*
`venice_vm.c`, `venice_asm.py`. Effort: **L**. Reserve for the crown-jewel
routine only (license decision + key derivation).

### 1.9 Per-Build & Runtime ISA Metamorphism — *superoperators cut mid-operation*
From one per-build seed: mint **superoperators** from frequent bigrams/trigrams
whose boundaries straddle semantic boundaries; randomize immediate
mask/rotation, branch encoding, stack-growth direction, accumulator slot; give
native crypto ops **N bit-identical variant bodies** chosen by low bits of the
rolling state. *Hardening:* the mandated bit-identical semantics guarantee an
output-lift always works, so **move the consumer into the VM** (AES-GCM decrypt
over VM-managed scattered state — no stable key-buffer breakpoint target) and
make a *subset* of variants **anti-debug-gated poison paths** (feeds deception).
*Files:* all three `venice_*` tools + `venice_vm.c`. Effort: **M**.

### 1.10 Execution- & Bytecode-Bound Key Binding — *the key is the fingerprint of the exact path walked*
Extend `crypto_derive_key` (already hashes stub `.text`) with two HKDF info
terms: a rolling fold over every dispatched `opcode‖operand‖sp` (the dynamic
trace) **and** the byte-exact Venice blob(s). Devirt-and-recompile changes the
blob; reorder/patch changes the trace; either → wrong key → GCM failure,
fail-closed. *Honest limit (documented):* the key must be build-time-predictable,
so the trace is recordable by an observer — this **kills the low-effort tamper
path** (naive NOP-and-rerun breaks loudly with the cause 3 layers upstream) but
does not stop an analyst who understands it. Its real teeth come from pairing
with 1.2 (rolling fetch forces the whole genuine VM to stay resident and executed
in-order, defeating "hash inert blob + run devirt'd native"). *Files:*
`crypto.c`/`crypto_derive_key`, `packer/container.py`, `venice_vm.c`. Effort:
**S** (mechanism) / **M** (paired). No new failure mode beyond existing code-hash
bind.

---

## 4. Track 2 — Anti-dump (kill "dumpable once in RAM")

### 2.1 Per-Page AEAD + keyless chained page keys — *THE residual fix*
Store guarded sections as independently `deflate + AES-256-GCM`'d **page-chunks**
(one tag per page, page RVA as AAD; a shared preset deflate dictionary recovers
cross-page redundancy). First fault decrypts **only the faulting page** — the
documented whole-section plaintext window **disappears** (bounded to the LRU
working set). Delete memguard's stored `keys[][32]`; derive
`page_key[i] = HKDF(section_master, SHA256(static_ciphertext_of_page[i-1]) ‖ i)`
— **no key table in any snapshot.** Extend cross-section: section N+1 subkey takes
`SHA256` of section N's **post-fixup plaintext**, cryptographically enforcing
decrypt order + reloc completeness.
- **Red-team hardening:** the chain input is on-disk, so it reduces to one secret
  `section_master`. Perform the per-page HKDF **inside Venice VM over scattered
  shards** so `section_master` never exists contiguously; mix a per-legit-fault
  **liveness counter** into the section→section subkey (keep a page-intrinsic
  fallback for correctness) so offline batch-decrypt of a cold section also
  requires having driven the prior section live.
- **ABI-BREAKING** — container format changes (per-page tag array). Bump
  `LETHE_FORMAT_VERSION`; land `container.py` + `pack_info.h` + `payload.py` +
  `assemble.py` + `memguard.c` **together**. *Files:* all of those. Effort: **L**.
  This is the highest-value single item in the whole plan.

### 2.2 Runtime dump-attempt detection & response
In the memguard VEH/sweeper: (1) detect a **monotone fast page-fault sweep** (N
sequential VAs within T µs) → drop working-set cap to 1 and re-encrypt behind the
reader; (2) **NOACCESS canary pages** interleaved among real guarded pages → any
canary fault, or a faulting RIP outside the legit code map, = injected scanner →
deception; (3) sweeper records `GetTickCount64`; a delta far beyond cadence but
below sleep scale = **external freeze** (MiniDumpWriteDump suspend) → re-encrypt
the whole working set + migrate `key_scatter` fragments so any mid-dump capture
is stale on resume. **Responses are re-encryption/migration only — never
key-poison** (avoids AV-scanner/RDP false-positive brick, per the killed
"fault-cadence poison" idea).
- **Honest limit:** a *passive external* `QueryWorkingSetEx`+`ReadProcessMemory`
  harvester generates no in-process events and is invisible to self-observation.
  Mitigate by **shrinking + de-correlating the residency window** (randomized
  short re-encrypt jitter + phase-randomized global tick), **decoy resident RX
  pages** holding mislabeled handlers, routing crypto/license/cold paths through
  the VM (a perfect page harvest yields the interpreter + rolling bytecode, not
  clean native), and moving `.rdata`/`.data` secrets to JIT-in-VM (see 2.4).
  Net: the **push-button suspend+dump path is fully closed**; the passive
  harvester is demoted to a multi-hour, coverage-limited, time-spliced campaign.
*Files:* `memguard.c`, `antidump.c`. Effort: **M**.

### 2.3 Import-graph deception & runtime IAT concealment
Derive the FNV offset-basis/prime **per build from the stub self-hash** so
precomputed API-name tables miss (forces live PEB-walk). After resolve, relocate
real pointers to a fresh region and write per-process XOR-recover **trampolines**
into the header IAT slots; scatter a chosen license/integrity subset into
`key_scatter` fragments reassembled per-call via `VVM_N_CALL_PTR`; the sweeper
periodically re-encrypts the exiled thunk region, which **roves to a new VA** on a
timer. Curate `stub_junk_imports.c` decoys into a coherent false narrative (a
registry-key trial dialog) so IDA's import view **tells a lie.** All targets
CFG-registered (`SetProcessValidCallTargets`), RX not RWX.
- **Hardening:** kill the single resolver choke (`pe_loader.c` writes every real
  `(slot,pointer)` in one pass) — for the protected subset store only fragments,
  reassemble **inside the VM at the call site**, re-scatter before return; derive
  the trampoline key from a **per-call nonce + caller return address** (lifted
  pointer non-replayable); resolve lazily on first real call interleaved with
  decoy resolutions; wrap the resolver in a VM-hosted BP/timing tripwire that
  diverts to the decoy graph. *Files:* `pe_loader.c`, `memguard.c`,
  `stub_junk_imports.c`, `venice_vm.c`. Effort: **L**.

### 2.4 Fiber-isolated crypto core + touch-and-scrub secrets
Run VM key-derivation/scatter on a **second fiber** whose private stack is flipped
RW immediately before `SwitchToFiber` and back to **PAGE_NOACCESS** after it
yields. For at-rest `.rdata`/`.data` secrets (`key_scatter` output,
`venice_str_data.h` strings, the bytecode blob): `get(scratch)→use→SecureZero`
discipline, stored XOR/AES-sealed, plaintext only for the microsecond of use. A
full-process dump **taken while parked contains no key material.**
- **Hardening:** keep the key **sharded** and fed incrementally into the AES key
  schedule inside the VM (no single watchpoint hit yields 32 bytes); on the RW
  flip, scan the resolved `SwitchToFiber`/`VirtualProtect` thunks + fiber entry
  for `0xCC` and check DR0-3 → **poison key** on a hit; plant a resident
  never-scrubbed **decoy key buffer** with plausible entropy; randomize per-build
  which handler assembles which shard. Verify the Qt payload doesn't itself
  `ConvertThreadToFiber` (else use a dedicated worker thread). *Files:* new
  `fiber_core.c`, `crypto.c`, `key_scatter.c`, `venice_vm.c`. Effort: **L**.

---

## 5. Track 3 — Deception (the "nasty": they win, and they're wrong)

> Every item here needs a hard kill-switch + zero-false-positive gating + a
> private crash/telemetry marker, and **must** be A/B'd on a clean Defender VM and
> across throttled/cloud/heterogeneous-core hosts before shipping. The decoy is
> only worthwhile because server-side enforcement makes a decoy crack worthless.

### 3.1 Authenticated Decoy Payload / "Judas Key" — *the crack works, the tag verifies, it's the wrong binary*
Which payload decrypts is chosen by which key the environment/CFI accumulator
(P3) assembles. Both decrypts are **cryptographically valid AES-GCM** — every
integrity check the analyst runs passes.
- **Hardening (kills the three cheap tells):** (i) don't ship a second full blob
  — ship the real payload + a **small encrypted delta**; the Judas path
  reconstructs `real XOR delta` (still one authentic GCM tag), killing the
  file-size tell and the second-ciphertext dump; (ii) synthesize the decoy at
  pack time by an **automated crippling pass over the real binary** (stub out
  licensed functions, keep symbol/section shape) so it's never byte-identical to
  the public trial → defeats content-diff attribution; (iii) make honest key
  material **destructive** — route the honest seed through the existing tripwires
  so any dirty run folds `secret_seed` irreversibly into the Judas constant *in
  place*, so forcing "the other branch" in a debugger can only ever yield Judas.
  The analyst must complete a provably-clean, tripwire-free run to get the real
  payload — exactly the state hardest to sustain while extracting. *Files:*
  `pe_loader.c` (replace `ExitProcess(1)` with Judas-derive), `packer/*`,
  `container.py`. Effort: **L**. **ABI touch** (delta blob descriptor).

### 3.2 Concealed Decoy OEP — *breakpoint the OEP, land in "trial expired"*
Point the statically-visible indirect OEP target at a **functional decoy license
routine**; compute the real OEP only inside the memguard VEH triggered by a benign
guarded-page access. Make `s_oep_key` a **capstone rolling digest** folded at each
honest milestone (envelope inflate, per-section ratchet, IAT resolve, antidump,
mitigation set) so a partial/lazy unpacker computes a wrong address; have each
deterministic tripwire deposit an expected share so NOP-ing any one lands in the
decoy.
- **Hardening (defeats Intel-PT "read the jump"):** drive the first N basic blocks
  of the real entry **through successive fault handlers (CPS-style)** — one block
  per VEH invocation, re-encrypted immediately — so no instant holds a large
  cleartext real-entry region and no PT packet points to a stable OEP. Make decoy
  and real path share identical initial blocks, diverging only after a
  milestone-digest-gated MBA branch. Fold the **exact guarded-page-fault count +
  milestone completion order** (a Merkle ratchet) into `s_oep_key` — deterministic
  and zero-FP for a clean customer, but any tracer that perturbs the fault ledger
  mis-keys into the decoy. **Never gate on wall-clock.** *Files:* `stub_main.c`,
  `memguard.c`, `pe_loader.c`. Effort: **L**.

### 3.3 Cipher-Collision Honeypot Page — *derive "the" key, get a clean fake license check*
For one memguard page, author real `P`, real `K_real`, decoy `D` (a fake license
routine that quietly passes). Store `C = P ^ K_real`; the **visible** scatter
machinery yields `K_guess = C ^ D` (computable at pack time). The obvious path
decrypts the page into a clean disassembly of `D`; the runtime uses `K_real` via
the genuine hidden path.
- **Hardening:** make selection **analysis-gated** — feed the scatter selector a
  bit from the anti-debug/inline-hook checks + code-hash. Clean run → `K_real` →
  `P`; instrumented/patched → `K_guess` → `D`, and it **continues into the
  fake-but-passing routine** with no crash. Now dynamic dumping *backfires*: the
  bytes the analyst breakpoints-and-dumps are `D`. Pack-time assert the honest
  path can never select `K_guess`. *Files:* `memguard.c`, `key_scatter.c`,
  `packer/payload.py`. Effort: **M**.

### 3.4 Self-Hash-Gated Predicates with decoy fold
`venice_asm.py` macro emits predicates `byte k of SHA256(runtime-decrypted
region) == C` feeding `JZ/JNZ`; the TRUE arm does the correct fold, the FALSE arm
(reachable only by forcing the edge) runs a **self-consistent wrong fold + decoy
scatter/OEP**. *Hardening:* both arms live and **input-dependent** (gate on a
per-shot BCrypt nonce, split the real key into complementary shares across both
arms) so an edge-trace can prune neither; include **runtime-decrypted bytes** in
the hashed range so `C` doesn't exist on disk (defeats offline hash-folding); make
the FALSE fold decrypt a **real small decoy payload** so a tamper-tripped analyst
sees a coherent "trial expired," not a garbage fault. The anti-patch canary
property is free (reuses the code-hash-bound key: can't 0xCC in-region without
breaking decryption). *Files:* `venice_asm.py`, `venice_vm.c`, `crypto.c`.
Effort: **M**.

### 3.5 Static Decoy Artifacts Bundle — *a dump full of mutually-corroborating lies*
(1) **The Pretty Key** — a per-build CSPRNG 32-byte const in `.rdata` positioned
to look like the live AES key (the real key is never contiguous —
`key_scatter` guarantees it). (2) **Confession Log** — a real no-CRT formatter
writing a self-consistent *wrong* ring buffer (`[lethe] OEP=…, key=…, antidbg
13/13`) whose fake OEP = decoy trampoline, fake key = Pretty Key. (3) **Live
Honeypot License** — a genuine caller for the junk imports
(`RegQueryValueExW` + constant-time compare) that always proceeds, giving decoy
imports **real call sites** (defeats the "unreferenced import descriptor =
decoy" heuristic). (4) **Decoy `PackInfo`** — a second GCM-valid `LETHE` recipe
at an attractive RVA a static unpacker latches onto (real loader uses an
unambiguous locator). **Note:** we ship a decoy *`LETHE`-magic PackInfo*, **not**
a decoy PE-header/IAT blob (that shape is a known Defender in-memory heuristic —
see guardrails). *Files:* `stub_junk_imports.c`, new `decoy_artifacts.c`,
`packer/assemble.py`. Effort: **M**.

### 3.6 Diffused / Delayed Tamper Response — *NOP the check, die 40s deep in Qt*
Give tripwires a **third outcome**: `arm_slow_poison()` XORs a small delta into
`key_scatter` shard state so a downstream constant faults deep in Qt/V4, spatially
and temporally divorced from the detection. Couple memguard's per-page CRC
aggregate into `key_scatter_migrate`'s pad selection so patching a guarded page
corrupts a **different** section's key later (Interlock Web). On a guarded-page
CRC mismatch, map a shipped **subtly-wrong decoy page** RX and continue.
- **Hardening (defeats PT-diff + write-watchpoint):** make detection→response
  **branchless** — `pad += f(PEB_byte, DR0|1|2|3, rdtsc_residual)` where clean =
  neutral, dirty = silent nonzero delta. No conditional to diff, no discrete
  arm-site store to trap. Route the delta through the **same code path/pages** as
  the periodic benign `key_scatter_migrate` (a watchpoint yields a firehose of
  legit hits). Ship the decoy page as an **encrypted delta**, not a plaintext
  twin. *Files:* `antidebug.c`, `key_scatter.c`, `memguard.c`. Effort: **M**.
  The sharpest residual: "it ran fine" is no longer a trustworthy success signal —
  the analyst can never accept an unpacked output without full independent
  verification.

---

## 6. Track 4 — Anti-automation (blow up symbolic/taint/trace/DBI)

### 4.1 Environment-Share KDF — *no `if(debugged)` to NOP*
Convert most `antidebug.c` checks/tripwires from `detect→wipe→exit` into **silent
HKDF summands** (P3): `share_i = HKDF(check_id, observed_word)` for
zero-legit-variance reads (PEB→BeingDebugged, DR0-3, remote-debug out-flag);
`aes_key_enc = key XOR code-hash-mask XOR env-share-mask`. Fold a **TLS-callback
ran+lock-held boolean** so headless entry-at-OEP emulators (angr/unicorn) that
skip TLS mis-key. Keep 2-3 loud early exits. *Hardening:* **rolling re-fold** the
same shares into scattered downstream derivations *and each memguard per-page
key* — so "run clean to OEP then attach/dump" fails (a later HW breakpoint mis-keys
the next page decrypt); add one quantized self-timed RDTSC-bucket shard XOR'd with
the DR read behind `--tamper-fold=timing`. *Files:* `antidebug.c`, `crypto.c`,
`container.py`. Effort: **M**.

### 4.2 Solver-Hostile Arithmetic Suite
In the VM key-derivation program: **MBA-expand** with identities whose
coefficient masks alias `PackInfo.kdf_salt`/`aes_key_enc` cells (exact only for
the true salt); **spill/reload** every intermediate via
`STORE/LOAD &locals[f(runtime_value)]` to force symbolic-store aliasing blowup;
route part of the mixing through a **quantized int8 32→32→32 MLP** (evaluated in
existing opcodes) — a dense arithmetic circuit SiMBA/Arybo/msynth can't fold.
*Hardening (turn "concretize and run" into a trap):* fold the **code-hash** and
the **AND of tripwire results** into the same MBA coefficients so they're exact
only when pristine+clean; under instrumentation the "quicksand" terms stop
canceling → a plausible-wrong salt → decoy key. Wipe intermediates (extend the
envelope wipe). *Files:* `venice_asm.py`, `generate_programs.py`. Effort: **M**.

### 4.3 Perjured Unwind — *structurally valid, semantically false `.pdata`*
A build pass synthesizes decoy `RUNTIME_FUNCTION`+`UNWIND_INFO` over the stub's
own code: lying prologue sizes, bogus frame register, `UNW_FLAG_CHAINED` pointing
mid-instruction, Begin/End that split one function into three. IDA/Ghidra/ML
function-boundary models **seed from `.pdata` and inherit poisoned function
lists.** *Hardening (defeats the strip attack):* **bind a hash of the exception
directory into the code-hash-bound key** so zeroing/editing `.pdata` → wrong key →
decrypt fails; choose decoy Begin addresses that start with real
`push rbp`/`sub rsp` byte shapes; keep a subset on a **genuinely-triggered**
exception path (correct for the CPU, poison for auto-unwinders) so they're not
"inert therefore strippable." *Files:* new `perjury_pass.py`, `assemble.py`,
`pe_loader.c` (register via existing `RtlAddFunctionTable`). Effort: **M**.
Honest scope: cheap AV-clean seed-poisoning of automated pipelines; an expert
presses `P` and moves on.

### 4.4 Exception/Unwind/APC-Threaded Dispatch — *the real edges live in a CONTEXT record*
For **coarse transitions only:** replace selected `VVM_JMP/JZ` with a controlled
fault whose target is encoded in the fault address (decoded by the memguard VEH);
end some blocks with `RaiseException` so `RtlDispatchException` picks the next
handler via crafted `UNWIND_INFO`; queue an unpack stage via `QueueUserAPC` +
alertable `SleepEx` (EXE path only, never under loader lock). No off-the-shelf
VMProtect/Themida lifter follows a fault into a VEH or an unwind language handler.
*Hardening (defeats passive PT):* **bind the fault-address→target decode to the
code-hash key + rolling VM state** so the resolved RIP is path/run-dependent (one
trace doesn't generalize; patching `.text` to observe breaks the decode); plant
**decoy fault sites** that resolve to poison unless a covert VM-state predicate
holds. *Files:* `venice_vm.c`, `memguard.c`, `pe_loader.c`, `perjury_pass.py`.
Effort: **L**. Scope to a handful of edges.

### 4.5 Emulation-Divergence & Spoof-Consistency Panel
Stop asking "am I debugged?" Ask questions where the **over-clean answer is
structurally impossible on real silicon**, routed into deception, never a key or a
crash: impossible `ProcessDebugObjectHandle` states; clean `BeingDebugged` +
dirty heap `ForceFlags`; self-relative warmup sign-bit; DTLB ~64-page capacity
cliff; CPUID per-leaf cost **dispersion** (emulators serve flat); RDTSCP
`TSC_AUX` vs pinned affinity; **three-clock** `QueryProcessCycleTime`/RDTSC/QPC
triangulation; exception-round-trip + VEH-chain canary timing. OR conservatively,
default "not detected" on ambiguity. *Hardening (kills the single OR-flag pin):*
mix a small **trust value** into the **scatter-index selection** (P4) so both real
and decoy blobs are valid AES-GCM under different indices — forcing any value just
picks a differently-scattered blob (survivable false positive, no brick); de-
converge in time (each check independently perturbs different scattered state at
staggered points). *Files:* new `divergence_panel.c`, `key_scatter.c`,
`memguard.c`. Effort: **M**.

### 4.6 Consensus / N-Version Key (folded, never compared)
Derive `K` structurally-divergent VVM implementations of `derive_key` +
a native-C recomputation; combine as `out_1 XOR (out_1^out_2^…^out_K)` into
`key_scatter_init` — agreement ⇒ zero extra term, disagreement ⇒ silent poison,
**no equality test to NOP.** *Hardening:* each path folds an **independent
environmental measurement** (code-hash, a tripwire result, RDTSC residue) that
cancels only on real hardware, so a devirtualizer that lifts one side runs the
analyst's instrumented environment into the **wrong** key; feed the consensus into
an **ephemeral per-page-rederived key** (P2). Honest: mainly denies the
"invert the compare" tamper foothold; native↔VM bit-exact agreement across MSVC
codegen is fragile — lean on the differential harness. *Files:*
`generate_programs.py`, `key_scatter.c`, `crypto.c`. Effort: **M**.

---

## 7. The "damn — how'd they think of this?" top picks

The ideas an expert reverse engineer would least expect, ranked by that reaction:

1. **Judas Key (3.1)** — the crack succeeds, the AES-GCM tag *verifies*, and it's
   the wrong binary. Nothing ever errored. Burns the "clean unpack = done"
   heuristic every automated unpacker relies on.
2. **Path-Entangled Rolling Bytecode (1.2)** — the data-stack *is* the keystream;
   a forked/instrumented run decrypts the wrong next instruction and the program
   eats itself to zeros. Self-poisoning against a live tracer.
3. **Cipher-Collision Honeypot Page (3.3)** — two valid keys collide on one
   ciphertext; the analyst derives "the" key, gets a beautiful clean license
   check that always passes, ships it, and it's a plant.
4. **Environment-Share KDF (4.1)** — there is no `if(being_debugged)` anywhere;
   the raw PEB/DR bytes are *summands inside HKDF*. Patching the check just
   derives the wrong key, with no branch to find.
5. **History-Keyed Overlapping Encoding (1.4)** — the same byte span is two
   different valid crypto routines at offset+0 and offset+1; a static one-byte-
   one-opcode assignment provably does not exist.
6. **Perjured Unwind (4.3)** — ship `.pdata` the CPU never reads at runtime but
   IDA/Ghidra/ML always trust: structurally valid, semantically false, hash-bound
   so it can't be stripped.
7. **Self-Generating Inner VM (1.8)** — the inner bytecode is an *output*, not a
   file; a lifter has literally nothing to lift.
8. **Concealed Decoy OEP smeared through fault handlers (3.2)** — the real entry
   never exists as a stable address in any snapshot or PT packet; it's executed
   one block per page-fault and re-encrypted behind itself.
9. **Delayed/branchless tamper poison (3.6)** — NOP the check, run fine, then die
   40 seconds later inside Qt with a call stack that has nothing to do with the
   packer.
10. **Per-page keyless key chain (2.1)** — no page-key table exists in any dump,
    because each key is a PRF of the previous page's *static ciphertext*, and
    forcing pages resident out of execution order decrypts them to garbage.
11. **Consensus key, never compared (4.6)** — the key is computed three ways in
    two worlds and XOR-folded; lift one side imperfectly and you mint a dead key
    with no comparison to invert.
12. **Emulation-Divergence panel → deception (4.5)** — don't detect the debugger;
    ask a question whose *too-clean* answer is impossible on real silicon, and
    route the liar into a decoy instead of crashing.

---

## 8. Phased roadmap

Each phase is self-contained, testable, and AV-smoke-gated. Early phases are
low-risk and non-ABI-breaking; brick-risk items are late and kill-switched.

### Phase 0 — Foundations (no attacker-visible change)
- Per-build seed plumbing across `venice_asm.py`/`venice_vm.c`/`venice_disasm.py`/
  `shuffle_opcodes.py`.
- **Differential harness** (assembler-sim vs interpreter, bit-exact or pack
  fails) — the safety net for every later phase.
- Kill-switch flags in `PackInfo.flags` + CLI (`--tamper-fold`, `--deception`).
- **Gate:** existing round-trip + ABI tests still green; no output change.

### Phase 1 — VM core hardening *(no ABI break)*
- 1.1 threaded dispatch → 1.2 rolling bytecode → 1.3 handler chaining → 1.4
  history-keyed/overlapping → 1.6 reflective microcode. Handler polymorphism +
  1.9 metamorphism ride along.
- **Gate:** round-trip parity on sample EXE/DLL; `venice_disasm.py` emulator
  matches; AV-smoke on clean Defender VM with `--anti-debug on`.

### Phase 2 — Anti-dump core *(ABI-BREAKING — bump `LETHE_FORMAT_VERSION`)*
- 2.1 per-page AEAD + chained keys **(lands with `container.py` + `pack_info.h` +
  `payload.py` + `assemble.py` + `memguard.c` together)** → 2.2 dump-attempt
  response → 2.4 fiber/JIT secrets → 2.3 IAT concealment.
- **Gate:** memguard round-trip; PE-sieve/Scylla produce garbage; suspend+
  MiniDumpWriteDump yields torn/stale dump; no RWX at any point; AV-smoke with
  `--memory-guard`.

### Phase 3 — Key entanglement *(brick-risk — kill-switched, heavy A/B)*
- 4.1 environment-share KDF → 1.10 execution/bytecode-bound key → 4.6 consensus
  key → 4.2 solver-hostile arithmetic.
- **Gate:** clean-VM A/B across throttled/cloud/heterogeneous-core hosts (this is
  where fleet-brick risk lives); every summand quantized/robust; `--tamper-fold`
  default `env`, `timing` opt-in only.

### Phase 4 — Deception layer *(highest care — server-enforcement makes decoys safe)*
- 3.5 static decoy artifacts → 3.4 self-hash predicates → 3.3 honeypot page →
  3.2 decoy OEP → 3.6 delayed poison → 3.1 Judas payload *(ABI touch: delta blob)*.
- **Gate:** decoy path exercised in tests; **prove the honest path can never
  select a decoy** on a clean run (pack-time assertion); private crash marker
  wired; AV-smoke (decoy artifacts must not trip heuristics).

### Phase 5 — Advanced dispatch & panels
- 4.5 divergence panel → 4.3 perjured unwind → 4.4 APC/exception-threaded
  dispatch → 1.7 CPS → 1.8 inner VM (crown-jewel routine only).
- **Gate:** coarse-edge count bounded; TTD/PT recovery still forced to per-build
  re-derivation; full regression + AV-smoke.

---

## 9. Guardrails — killed ideas (do NOT resurrect)

The triage/red-team pass **rejected** these for brick-risk or AV-risk. They are
listed so no future pass re-proposes them:

- **Any "fold wall-clock timing into the *key*" scheme** (timing-into-KDF,
  microarch-ratio-into-key, self-timing quine key select) — frequency scaling,
  thermal throttle, cloud/nested-virt, big.LITTLE core migration will brick
  paying customers un-debuggably. *Timing survives only as detection→deception
  (4.5) and as quantized robust summands, never as a deterministic key input.*
- **Decoy PE headers + fake IAT resident in memory** — a second
  `IMAGE_NT_HEADERS`+IAT-shaped blob is a known in-memory Defender/EDR heuristic.
  *We ship an `LETHE`-magic decoy `PackInfo` instead (3.5), which is not
  PE-header-shaped.*
- **Thread-race / N-body key smeared across decoy threads** — timing-gated
  rendezvous is a classic heisenbug on loaded/throttled/single-core VMs; the
  mandatory deterministic fallback nullifies the anti-DBI value anyway.
- **memguard fault-cadence poison-on-anomaly** — first-chance exception latency is
  legitimately inflated by AV real-time scanning, other VEH handlers, RDP/cloud →
  risks corrupting a customer. *Non-poison scanner *detection* is kept in 2.2.*
- **Deliberately executing authenticated-but-rejected GCM plaintext / off-by-one
  key poison (standalone)** — highest blast radius, fragile. *The safer
  delayed-poison-via-scatter spirit is retained in 3.6.*
- **Aliased-cell taint blowup** — sound alias handling cuts through it; not novel
  enough and risks corrupting real derivation.
- **"Dump Hole" (lift a real payload function to VVM)** — requires a full,
  validated x64→VVM lifter; a mis-lift corrupts a shipping function. *Anti-dump
  goal is better served by 2.1.*

**Universal rule:** any technique that diverges/poisons on detection ships behind
a hard kill-switch, with zero-false-positive gating, a private (not
customer-visible) marker, and mandatory clean-VM + hardware-fleet A/B before it's
enabled in a release build.

---

## 10. Honest posture

No packer is unbreakable, and this plan doesn't pretend otherwise. What it does:

- **Static-only analysis:** effectively defeated across the board (unliftable
  bytecode, no readable dispatcher, poisoned function seeds, ISA that doesn't
  exist until a correct decrypt).
- **Debugger / DBI (x64dbg, Frida, Pin):** defeated wherever we couple to a
  tamper-reactive fold — instrumentation mis-keys or diverts to deception.
- **The apex adversary — passive Intel-PT / hypervisor trace, or clean-run-then-
  snapshot:** *raised in cost, not eliminated.* We convert a **30-second
  push-button unpack** into a multi-hour, coverage-limited, per-build campaign
  requiring stealth tracing, live-driving the app to full coverage, and
  disambiguating deception from truth on every "successful" result — and even
  then the client-side prize is gated by server-side enforcement.

That combination — per-build uniqueness + whole-secret-never-resident +
fold-not-branch + silent deception — is what separates this from an off-the-shelf
protector, and it's what earns the "how did they even think to do that?" reaction
while staying entirely within the AV-clean, don't-brick-the-customer envelope.
