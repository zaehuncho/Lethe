# Lethe NG — Denial · Deception · Divergence

*Next-gen protection design & build roadmap. Internal, build-time PE protector for the owner's own x64 Windows binaries. AV-clean is a hard release gate; nothing here targets AV/EDR evasion or anti-cheat.*

---

## 0. Executive summary — the strategy in one breath

We red-teamed every technique below against a top-tier analyst. The verdicts collapsed into a single, uncomfortable, clarifying truth:

- Against **static / symbolic tooling** (IDA/Ghidra/HexRays, angr/Triton lifters, offline devirtualizers, Scylla/PE-sieve carving) — almost everything here **wins outright**.
- Against **in-process instrumentation** (x64dbg, Frida, Pin/DynamoRIO, hardware breakpoints, single-step) — most techniques win **because instrumentation perturbs state we fold into keys** rather than into branches.
- Against the **bare-metal passive observer** (Intel PT + one clean run + a RAM snapshot) — most techniques survive only **weakened**. This adversary emits *zero* in-process events, and our own documented residual hands them the prize: after a clean run, keys and license logic sit **plaintext in `.data`/`.rdata` for the process lifetime**, and any executed page is briefly plaintext+RX.

So the north star is **not** "stop the CPU being observed" — impossible for code that must run. It is a three-move doctrine, and every technique is an application of it:

1. **DENIAL — never let a whole secret exist at one instant.** No full key, no full bytecode blob, no full import map, no whole decrypted section, ever resident contiguously. Force the observer to *stitch* time-sliced fragments. This is the only move that beats the passive observer, and it is load-bearing under everything else.
2. **DECEPTION — when denial is bypassed or tamper is detected, feed a coherent WRONG answer, routed through cryptography, never a crash.** A crash is a breadcrumb to the check. An authenticating decoy burns days and poisons the analyst's confidence in every "successful" unpack.
3. **DIVERGENCE (per-build uniqueness) — make one clean trace non-general.** Path-, run-, and build-dependent decode means a single recorded trace is valid only for that exact run of that exact build. The same seed that makes each build unique also **fingerprints which build a leaked crack came from**.

The coherence of these three — not any single trick — is what separates Lethe NG from VMProtect/Themida (one recognizable fixed VM, static across builds, crash-on-detect) and from Denuvo (binary-lift virtualization, no source cooperation). The reaction we're engineering is *"how did they even think to couple **that** to the key?"*

**Honest posture, stated once, up front:** none of the clever key-folding, exception-weaponization, or trace-binding stops a patient human who runs the unmodified binary on real silicon and snapshots RAM. Only **DENIAL (SP2 below)** does. Deception and divergence are what convert "minutes with Scylla" into "days of bespoke, per-build, live-coverage tooling that yields a watermarked, downstream-poisoned artifact." That is the honest deliverable, and it is a large one.

---

## 1. Shared primitives — build once, reuse everywhere

These five primitives are consumed by nearly every technique. They map onto the existing `NEXTGEN_PROTECTION_PLAN.md` P1–P4 vocabulary; where a name already exists there, we keep it.

| # | Primitive | What it is | The red-team fix it embodies |
|---|-----------|-----------|------------------------------|
| **SP1** | **Rolling state accumulator (P1)** | A 64-bit value + a SHA/ARX midstate, folded at the `vvm_push`/`vvm_pop` choke points and at each dispatched `opcode‖operand‖sp‖taken-edge`. The single keystream/decode seed. | The one thing every "value-keyed" and "history-keyed" scheme reads from. |
| **SP2** | **Memguard v3 + VM-internal key schedule (P2)** | Per-page (and, on crown-jewel routines, per-basic-block) AEAD; **AES key expansion moved *inside* the Venice VM** so round keys are consumed fragment-wise and **no contiguous 32-byte key ever exists in a register or stack cell**; short randomized re-encrypt jitter; decoy resident pages. | **The single most-repeated red-team fix.** Kills `key_scatter_get()`'s contiguous reassembly (`key_scatter.c:175`) and the whole-section plaintext flash (`memguard.c:463`) — the two facts every "just snapshot the key/section" attack depends on. |
| **SP3** | **Environment-as-summand KDF (P3)** | `antidebug.c` signals (PEB.BeingDebugged, NtGlobalFlag bits, debug-object handle, TLS-ran boolean, code-hash, quantized self-timing bucket) become HKDF `info` terms, **not `if()`s**. Baked expectations live in `container.py`. | A branch is one byte to NOP; a summand inside HKDF has no NOP and no compare — a dirty read just derives the wrong key, silently, downstream. |
| **SP4** | **Silent deception router (P4)** | A tamper/analysis signal selects *which cryptographically-valid* blob/key/OEP is used (real vs decoy). Both authenticate, so a false positive is survivable and a true positive is invisible. | Turns every "detect → ExitProcess" into "detect → coherent wrong answer." |
| **SP5** | **Per-build seed + differential pack-time harness + kill-switches** | One seed threaded through `venice_asm.py` / `venice_vm.c` / `venice_disasm.py` / `shuffle_opcodes.py`. Assembler-simulated result must equal interpreter result **bit-exactly on a clean build or the *pack* fails — never the customer**. Universal flags: `--tamper-fold={off,env,timing}`, `--deception={off,on}`, per-feature bits in `PackInfo.flags`. | The safety net for every rolling/entangled/keyed scheme. No hardened build ships without AV-smoke + clean-VM A/B. |

### 1.1 The contiguous-key choke point (why SP2 is non-negotiable)

`key_scatter_get(uint8_t out_key[32])` reassembles all 8 fragments into one caller stack buffer (`key_scatter.c:175–205`). `mg_decrypt_section` then calls it (`memguard.c:426`), derives a section key, and — critically — `mz_uncompress`es the **entire** section into `S->va` as plaintext (`memguard.c:463`) before re-encrypting cold pages (`:477`). Every red-team attack that "survives weakened" cashes in one of these two moments. SP2 closes both:

- **VM-internal AES-256 key schedule.** Port `aes256_key_expand` / `aes256_encrypt_block` (`crypto.c:263,320`) into Venice native ops that read fragments directly from the scatter pages and expand round keys **without** ever assembling `out_key[32]`. `key_scatter_get` as a public "give me the whole key" primitive is deleted; only `key_scatter_feed_schedule()` (fragment → round-key word) survives.
- **Per-page GCM at pack time** (see §3.2): the compression unit becomes the page, so `mz_uncompress` never inflates a whole section, and the 32 KB deflate LZ77 back-window plaintext exposure disappears.

---

## 2. Container / ABI versioning strategy

Current: `LETHE_FORMAT_VERSION = 1`, `PackInfo` = 192 bytes with `reserved[24]`, `SectionDesc` = 52 bytes (`pack_info.h`). To avoid format thrash we **introduce `v2` once**, at the anti-dump phase, and make it carry *all* the optional regions later phases need (each gated by a `PackInfo.flags` bit, zero-default = absent):

- page-chunked section storage (per-page nonce/tag table) — **the breaking change**;
- an optional **expectations blob** (baked canonical constants, expected trace/cadence digests) for SP3-keyed techniques;
- an optional **decoy region** (dual ciphertext + decoy-OEP selector) for deception;
- an optional **gather-list** and **IAT-token** region for anti-automation.

Rule: **the page-chunk reformat and the memguard-v3 runtime must land in the same release** — a v2 stub cannot read v1 sections and vice-versa. Everything else is additive under `flags` and can land incrementally without a further bump. `pack_info.h` and `container.py` move in lockstep (the round-trip test asserts it; the `flags`-fits-AAD fence at `pack_info.h:88` still guards the AAD width).

---

## 3. Track 1 — Venice VM overhaul

Goal: make the bytecode **unliftable statically** and **non-general dynamically**, and put real semantics on the critical path so a wrong lift computes wrong answers rather than a dead key.

### 3.1 History-Keyed / Fixpoint Self-Decrypting Bytecode
*"There is no decodable program image at rest — each instruction's plaintext exists only along the one true trace, and a forward-dependency variant makes partial static decode provably underdetermined."*

**Mechanism (hardened).** `venice_asm.py` pre-encrypts `code[]` so each block's keystream folds the SP1 rolling ARX accumulator **plus the executed opcode/operand/result values** (past-and-value keyed). The fetch site in `vvm_run` (`venice_vm.c:93`) decrypts → executes → **re-seals behind `pc`**, so exactly one live instruction is ever clear. An escalation mode also mixes a *linear* function of a forward span at `i+δ`, kept XOR-linear/acyclic so the assembler solves the whole stream as one triangular system at build time, but any windowed static decoder faces bytes it has not yet decoded — *partial static decode is provably underdetermined.* **Hardened against the "trace the single fetch point" defeat by folding the decryptor's own environment into the history key:** (a) a running self-measurement (ARX over the live dispatch-loop `.text` bytes) + a coarse RDTSC-delta bucket enters each block's keystream, so any inline detour at the fetch point perturbs the key that decrypts the *next* instruction → downstream garbage routed to SP4 deception, not a clean crash; (b) the decrypt-execute-reseal is emitted across **several polymorphic, mutually code-hash-validating dispatch sites** that rotate, so one hook never sees the whole trace; (c) the remaining tape is periodically **re-keyed from the live accumulator**, so a paused/dumped tape cannot be resumed offline.

**Novel vs VMP/Themida/Denuvo.** Their bytecode is a static (at most XOR/renumbered) blob; standard self-decrypting code is defeated by tracing the one decrypt point. Here the keystream folds the *actual execution history*, and the forward-dependency variant makes "decode just the KDF region" mathematically impossible — plus observing the decrypt corrupts it.

**Touch.** `venice_vm.c` (fetch/reseal, multi-site dispatch), `venice_asm.py` (forward-simulating encoder + triangular solver), `venice_disasm.py` (matching emulator for the differential harness). `code[]` lives in a **private RW `VirtualAlloc` page** (data SMC — *not* `.text`, stays AV-clean).

**Container/ABI.** None (bytecode ships inside the stub as `venice_programs.h`, not in the container).

**Perf · correctness · AV.** Per-instruction hash is acceptable only on **short, near-straight-line crypto paths** (key derivation, shard fold, scatter) — keep programs straight-line. AV-clean (RW data SMC, no `.text` mutation, no RWX). Correctness is fully governed by the SP5 differential harness.

**Kill-switch / FP.** `--vm-tape={off,history,history+fwd}`. Timing/self-hash summands gate to quantized/robust bits; on any mixing that could FP, fall back to history-only. Fail-closed on corrupted decode.

**Effort. L.**

### 3.2 Stateful / Context-Dependent ISA
*"The same byte is a different opcode at every nesting depth and mode; there is no jump table to recover; and sampling a handler in isolation gives non-functional I/O because its output folds execution history."*

**Mechanism (hardened).** Add a decode-context stack (Dyck OPEN/CLOSE meta-prefixes with data-dependent pop counts) and a mode register, so `(address → instruction)` is no longer a function of address alone — linear-sweep and recursive-descent boundary recovery both produce garbage. Replace the readable `switch` (`venice_vm.c:98`) with a **chaotic closed-form successor** (per-build bijective ARX recurrence over GF(2⁶⁴)); there is no dispatch table to recover. **Hardened against the "function-boundary synthesis / memory-lift" bypass:** the accumulator is *not* injected-then-inverted (which cancels under trace simplification). Instead the section key is derived from `HKDF(inputs ‖ H(actual executed handler-sequence / path-tag))` — the output legitimately depends on the control-flow path, so black-box program-synthesis (Syntia/QSynth/Xyntia) has **no clean stateless function to converge on** and must reproduce the exact internal VM execution, i.e. truly devirtualize. Feed a coarse timing-gated quantity into the Dyck CLOSE pop-count so running under instrumentation silently corrupts the pushdown balance (wrong key, not a crash). Consume keys via SP2 so the memory-lift is a timing-race against the sweeper.

**Novel vs VMP/Themida/Denuvo.** Attacks four lifter assumptions at once — fixed instruction length, statically resolvable boundaries, an enumerable handler table, stateless-samplable handlers — and binds the answer to the path so synthesis is forced up to full devirtualization.

**Touch.** `venice_vm.c` (pushdown+mode decode, closed-form successor), `venice_asm.py`/`venice_disasm.py` (must simulate pushdown+mode — a balance bug bricks the crypto path, so the differential harness is mandatory and load-bearing). `crypto_derive_key` path (`crypto.c:474`) gains the path-tag HKDF term.

**Container/ABI.** `reserved[24]` gains a per-build ARX-successor seed reference (or it is folded from the existing per-build seed → no bump).

**Perf · correctness · AV.** AV-clean. Highest correctness risk in the track: an off-by-one in pop-count or mode balance mis-keys. Gate hard behind SP5.

**Kill-switch / FP.** `--vm-stateful={off,on}`; the path-tag term is disabled by `--tamper-fold=off`.

**Effort. M–L.**

### 3.3 Cross-Domain Seal + Self-Referential Integrity Fold
*"The VM MACs the native routine it is about to call, the native trampoline hashes the bytecode that called it, and the interpreter reads its own instructions as data — lift or breakpoint either side and the other's key term silently rots."*

**Mechanism (hardened).** Bidirectional seal at the `VVM_N_CALL_PTR` boundary (`venice_vm.c:452`, `venice_trampoline.asm`): the VM handler hashes the target native crypto's byte range into the value passed down, and the trampoline accumulates a rolling hash of the executing bytecode region into a shard the native key path consumes. Extend the existing one-shot code-hash binding to **byte granularity**: a handler folds computed addresses into `code[]` *as data* (defeating alias/points-to separation) and masks LOAD/STORE effective addresses with `(live_dispatch_checksum − expected)`, so a `0xCC` or inline patch corrupts memory access instead of tripping a detectable trap. **Hardened against the "snapshot the product / replay the constant seal terms" bypass:** (a) do not derive one resident section key — drive an SP2 per-page keystream so a snapshot at OEP yields only fragments; (b) make the seal **non-replayable** by folding in a value recoverable *only* from already-decrypted payload, so `key ⇐ seal ⇐ payload ⇐ key` is a true cycle a static "constant replay" cannot enter without first running it; (c) emit **many VM instances with per-section renumbered ISAs and distinct sealed cycles**, so one captured PT trace does not generalize across sections or builds.

**Novel vs VMP/Themida/Denuvo.** Off-the-shelf VMs trust their native handler table and treat bytecode as pure code. Making interpreter and handlers hold each other hostage — and making the interpreter's own program simultaneously code, integrity-witness, and key-input — defeats code/data separation and isolated tracer extraction of the native crypto.

**Touch.** `venice_vm.c`, `venice_trampoline.asm` (must preserve the x64 nonvolatile/shadow-space contract), `crypto.c` (native crypto byte-range hashing), `venice_asm.py` (relocation-stable folded ranges, rebaked per build).

**Container/ABI.** None (all runtime + per-build rebake).

**Perf · correctness · AV.** AV-clean. Folded ranges must be relocation-stable; the address-masking must never mask a legitimate access — exhaustive differential testing required.

**Kill-switch / FP.** `--vm-seal={off,on}`; byte-granular address masking behind its own flag for staged A/B.

**Effort. M.**

### 3.4 Logic Mortaring — source-annotated virtualization with secret-sharing
*"Denuvo's actual thesis minus the fragile binary lifter: the owner MARKS a load-bearing first-party function and it ships only as Venice bytecode — devirtualize it wrong and the app computes wrong answers, not a dead key."*

**Mechanism (hardened).** Do **not** lift a binary (brick-prone). Compile from **source**: an `ORNVM_VIRT` macro extracts an audited pure-integer/POD kernel into `venice_asm`, and payload call sites re-enter `venice_vm_exec` through a native→VM thunk, so genuine app output flows through the interpreter. **Hardened against both fatal bypasses the red-team found:** (1) **secret-share, don't N-version-vote** — the original "K implementations + a native path, XOR-combined" *requires a plaintext native participant that computes the answer*; instead each of K paths computes a random additive/XOR **share** `sᵢ`, with `V = ⊕sᵢ` only at the fold, so reading any single path (native included) yields noise while a wrong share still corrupts `V`; (2) **destroy purity / inflate the domain** — fold the code-hash-bound key, a wide slab of decrypted `.rdata`, and the live epoch/PRP state into the kernel, and have the VM read app state directly by pointer (`VVM_LOAD64` over live structs) rather than through one clean typed thunk, so `(visible-args → result)` is *not a learnable function* and I/O-sampling/synthesis cannot tabulate it. Rotate the opcode PRP on a coarse epoch cadence (the memguard sweeper) so a live interpreter snapshot goes stale; wrap the epoch swap in a seqlock.

**Novel vs VMP/Themida/Denuvo.** First mechanism here to put **real application output** on the protection critical path with **no native fallback** to auto-recover a bad lift — and it does so from source (Denuvo lifts binaries; VMP/Themida virtualize opaque blobs whose output is a key, not app state). Threshold sharing across structurally-divergent VM implementations is not something any shipping protector does.

**Touch.** New `packer/mortar.py` (source extraction + share generation) and a small build-system hook; `venice_asm.py`, `venice_vm.c` (native→VM thunk ABI, share-fold), `generate_programs.py`. First-party **source cooperation** required. A **bit-exact PACK-time differential gate** (the packer knows the secret state) fails the pack, never the customer.

**Container/ABI.** **BREAKING (v2):** mortared-function bytecode + share metadata become a new optional metadata region under a `flags` bit.

**Perf · correctness · AV.** AV-clean. This is the deepest integration and the biggest correctness surface: audited-pure kernels only; a divergent trace bricks the key, so the differential gate is existential. Scope to a handful of crown-jewel functions (license decision + key derivation) to bound perf.

**Kill-switch / FP.** `--mortar={off,on}`, per-function opt-in list. A function fails the pack (not the release) if its differential gate diverges.

**Effort. L.**

### 3.5 Cycle-Woven Correctness → demoted to an instrumentation tripwire (honest)
*"Lift the bytecode to clean IR all you want — you threw away the cycle counts the program needs to compute the right key."*

**Mechanism (hardened, honestly scoped).** `VVM_TSC_MARK` / `VVM_TSC_FOLD` quantize a basic block's measured cycle cost to a canonical per-block constant (min-of-N, coarse quantization) and mix it into SP1. **The red-team is right that as a *devirt-correctness* claim this is defeated** — the woven value must be a byte-exact canonical constant across all customer CPUs, so it is a build-time constant a single clean run logs, and the memory-dump path bypasses it entirely. **So we do not sell it as devirt-correctness.** We repurpose it as an asymmetric **deception selector (SP4)**: min-of-N cycle cost lands in band A on clean silicon and inflates past the quantization ceiling into band B under single-step/DBI/emulation; band A derives the real key, band B derives a *silently-wrong-but-structurally-valid* key that passes an early decoy GCM tag and corrupts far downstream. An analyst who traces under instrumentation captures the **decoy** constant; the real one requires a perfectly clean run.

**Novel vs VMP/Themida/Denuvo.** Microarchitectural timing as a *data operand* of a deception fork (not a patchable `if(timing)`), snapped so real silicon and VT-x customers stay correct while single-step/DBI diverge.

**Touch.** `venice_vm.c` (two opcodes), `venice_asm.py`, `container.py` (baked canonical band boundaries in the expectations blob).

**Container/ABI.** Expectations blob (v2 optional region).

**Perf · correctness · AV.** Only `rdtsc`/`lfence` — zero AV weight. **Honest brick risk:** the band must be byte-exact across E/P cores, AVX throttle, SMT, hypervisors; never weave into an unboundedly-preemptable block.

**Kill-switch / FP.** Ship **detection→deception first**; promote to a hard key summand *only* after fleet telemetry proves the band. Kill-switched behind the SP5 differential brick-harness.

**Effort. M.**

---

## 4. Track 2 — Anti-dump

Goal: kill "dumpable once in RAM." Every item here is an application of **DENIAL (SP2)**: shrink the plaintext window until the passive observer must stitch thousands of time-slices under live coverage.

### 4.1 Merkle-Linked Encrypted Basic Blocks
*"Each block's key is the hash of its actual predecessor's PLAINTEXT, so the CFG is a hash-linked list you can only unroll by genuinely executing it — and only one block is ever in the clear."*

**Mechanism (hardened).** Compile the mostly-static crown-jewel VVM program to independently AEAD-sealed basic blocks where block B's key = `HKDF(sha256(plaintext of the actually-taken predecessor) ‖ edge-tag ‖ image-bound key)`. The interpreter decrypts a block into one scrubbed scratch page, executes, re-seals/zeros it, then derives the next key from the block it just ran. **Hardened against the "read-only watchpoint on the scratch page harvests every block" attack:** (a) fold a **runtime integrity hash of the decrypt+dispatch code and anti-debug tripwire state** into each block's HKDF key, so any inline hook/DBI trampoline/`0xCC` on the path yields a wrong key → the chain forks into a **decoy block (SP4)** a trace-dumper cannot distinguish from real; (b) make a subset of crown-jewel edges **genuinely data-dependent on the server-side license secret** so those blocks have no local key and never decrypt offline (defeats coverage-driven harvesting for the highest-value paths); (c) shrink the plaintext window toward **sub-block / instruction granularity**, re-encrypting the just-executed slice before advancing, so a single snapshot exposes only a few instructions and a watchpoint must fire and be serviced thousands of times.

**Novel vs VMP/Themida/Denuvo.** One mechanism yields a **triple**: static CFG unrecoverable, anti-dump free (one block plaintext at a time), tamper self-punishing (patch A → B's key is wrong). No shipping protector chains block keys to predecessor *plaintext*.

**Touch.** New `stub/src/vvm_blocks.c` (block decrypt/execute/reseal), `venice_vm.c` (block-threaded fetch), `venice_asm.py` (block sealing + hash-chain, must match the runtime path exactly), `crypto.c` (reuse SHA256/HKDF).

**Container/ABI.** **BREAKING (v2):** per-block sealed blob is a new optional metadata region (`flags` bit). Must land with its runtime.

**Perf · correctness · AV.** AV-clean. Restricted to a **mostly-static CFG**; data-dependent/indirect edges need every predecessor key precomputed and can explode — keep to the crown-jewel routine. Instruction-granularity mode is a real fault-storm perf cost; opt-in.

**Kill-switch / FP.** `--merkle-blocks={off,block,subblock}`; server-secret edges behind `--merkle-server-edges` (needs the license channel live).

**Effort. M–L.**

### 4.2 Forward-Secure Section Ratchet + Per-Page Pad Hardening
*"By the time the app reaches OEP, the keys that decrypted every eager section have already ratcheted into oblivion, and each cold guarded page is a fresh one-time pad with no resident key table."*

**Mechanism (hardened).** Replace independent per-section keys with a one-way ratchet: decrypt section *n* with `kₙ`, then `kₙ₊₁ = HKDF(kₙ, gcm_tagₙ ‖ rvaₙ)` and wipe `kₙ` (and the master right after `k₁`). In memguard, rotate each page's pad to a fresh `BCryptGenRandom` draw on every re-encrypt and derive `pad[i] = HKDF(scattered_subkey, sha256(ciphertext(page i-1)) ‖ i)`, so the resident `keys[][32]` table disappears and a partial region grab decrypts zero pages. **Hardened, and honestly rescoped:** the red-team is right that forward-securing *keys* does nothing against a dumper that wants the *plaintext already resident at OEP* — so we **drop the "defeats OEP snapshot for eager sections" claim** and instead (a) move `scattered_subkey` and the pad-derivation HKDF **inside the Venice VM** (SP2) so no contiguous resident subkey exists and "decrypt a page" is a VM program, not a single native function a Frida hook can sit on; (b) mix a **per-activation nonce from the section ratchet** into `pad[i]` so a captured subkey + ciphertext chain cannot reproduce pads offline; (c) for genuinely sensitive guarded code, drop toward **instruction/basic-block granularity** so the resident-plaintext window a runtime tap depends on collapses.

**Novel vs VMP/Themida/Denuvo.** Packers keep a resident master because memguard re-decrypts later. Forward secrecy for eager sections + neighbor-chained rotating pads defeats OEP-snapshot re-derivation, two-time-pad correlation, and "lift the pad once, decrypt forever."

**Touch.** `memguard.c` (`mg_reencrypt_page`, `mg_activate_page`, the `keys[][32]` table), `crypto.c`/`lethe_derive_section_key` (`crypto.c:494` → ratchet), `pe_loader.c` (`decrypt_section` eager-section wipe), `venice_vm.c` (VM-hosted pad derivation).

**Container/ABI.** Ratchet itself is **runtime-only, no break** (container already stores per-section `gcm_tag`). Per-activation nonce is derived, not stored.

**Perf · correctness · AV.** AV-clean. SHA256+HKDF per page activation is fine for a 12-page working set. Neighbor-chaining means pages must decrypt in order — enforce it.

**Kill-switch / FP.** `--ratchet={off,sections,sections+pads}`. Fail-closed on chain break.

**Effort. M.**

### 4.3 Minimal / Moving Plaintext-Code Footprint
*"The module's own RX range never holds the cleartext section, the plaintext working set shrinks the harder you watch, and for crown-jewel pages the code never becomes executable at its real address at all."*

**Mechanism (hardened).** Rework `mg_decrypt_section` (`memguard.c:400`) to AES-GCM-inflate into a `VirtualLock`'d scratch, then walk it 4 KB at a time XOR-re-encrypting each cold page straight into `S->va` and `__stosb`-wiping the consumed scratch page — at most one plaintext page + shredded scratch ever exists (closes the `:463` whole-section flash **with no ABI break** on the compression side). Bracket the VEH with RDTSC/QPC and, when the profile matches single-step/DBI, drive `MEMGUARD_MAX_ACTIVE_PAGES` toward 1 and `MEMGUARD_IDLE_MS` toward 0 via a continuous control law (no branch to patch). **Hardened against the red-team's three hits:** (a) the deflate 32 KB LZ window still needs ~8 plaintext pages live during streaming → **re-chunk sections into independently GCM-tagged 4 KB units at pack time (compression unit = page)** so decrypt is per-page authenticated and the LZ-window exposure disappears (this is the ABI-breaking part, shared with §3.2/SP2); (b) the self-timed control law is blind to an out-of-process scraper → add a monitor thread polling `QueryWorkingSetEx` valid/shared bits to catch the working-set churn an external `ReadProcessMemory` sweep induces, feeding the same control law; (c) private unbacked RX arena is a **worse** PE-sieve/Moneta signature than image-backed RX → **block-level trampoline lifetime** (execute one basic block per fault, re-encrypt the arena slot on the next fault) collapses the external poller's race window toward zero, and **decoy arena slots** seeded with deception-valid-but-wrong leaf code tax the reassembly.

**Novel vs VMP/Themida/Denuvo.** Split-inflate + observation-adaptive residency + trampoline-arena execution together mean "dump the module's RX range" yields only ciphertext, and "the harder you watch, the less you see" is a real control law, not a slogan.

**Touch.** `memguard.c` (`mg_decrypt_section`, VEH control law, new working-set monitor thread, arena allocator), `container.py`/`pack_info.h` (page-chunked `SectionDesc`), `pe_loader.c` (arena targets must be CFG-valid, off any `.pdata` unwind path).

**Container/ABI.** **BREAKING (v2):** page-chunked section storage. **This is the anchor of the v2 bump; §3.2, §4.1, SP2 ride with it.**

**Perf · correctness · AV.** **Highest AV-risk item in the whole design** — private RX arena resembles shellcode. Mitigate with block-lifetime + image-backed-where-possible + heavy AV-smoke; restrict the arena to leaf pages off any unwind path (image `.pdata` is keyed to image RVAs). No RWX ever (write RW, flip RX).

**Kill-switch / FP.** `--footprint={split,adaptive,arena}` staged; the arena is the last and most-gated. Post-build unwind-simulation must prove no arena page sits on a live unwind path.

**Effort. L.**

### 4.4 At-Rest Secret Custody, Suspend Re-Key & Retaliatory Relocation
*"The honestly-documented residual — keys and license logic plaintext in `.data` for the process lifetime — gets no stable resident address; freeze the process to dump it and the key re-scatters, leaving decoy entropy that makes the analyst's own watchpoints fire forever on garbage."*

**Mechanism (hardened).** Store scatter seeds, license constants and decrypted strings **encrypted at rest**; a no-CRT accessor derives a field key, decrypts one field into a single scrubbed stack cache-line, uses it, `__stosb`-wipes it — a delimited dynamic extent, no fixed `.data` VA. A heartbeat thread compares `GetSystemTimePreciseAsFileTime` deltas to its own tick counter; a suspicious wall-clock-vs-TSC gap (external freeze for MiniDump) triggers `key_scatter_migrate` (`key_scatter.c:207`) + working-set re-encrypt on resume. On a high-confidence dump-witness, an off-cadence migrate overwrites vacated fragment pages with plausible high-entropy **decoy** bytes so page-guard/DR watchpoints keep firing on garbage. **Hardened against the fatal "breakpoint the consume site" attack:** the choke point is `key_scatter_get` reassembling the full key into one stack buffer — so (per SP2) **never materialize it**: feed fragments directly into the VM-hosted AES key schedule so no contiguous 32-byte plaintext ever exists; reach the accessor only via VM-dispatched (threaded) control flow so there is no single stable consume-site instruction to breakpoint, varied per build; gate the consume site behind the existing `check_hardware_breakpoints` tripwire (`antidebug.c:201`) + an accessor-local timing check so instrumenting it trips key-wipe.

**Novel vs VMP/Themida/Denuvo.** Everyone re-encrypts *code*; this closes the steady-state plaintext *data* target and weaponizes relocation into a noise source against the analyst's tooling.

**Touch.** New `stub/src/at_rest.c` (encrypted-field accessor), `key_scatter.c` (migrate/relocate), `antidebug.c` (heartbeat/suspend detection), `venice_vm.c` (VM-hosted schedule).

**Container/ABI.** Encrypted `.rdata` field table is a stub-build artifact; **no container break** (may use `reserved[]` for a salt).

**Perf · correctness · AV.** AV-clean (benign timing APIs). **FP risk:** a laptop sleep looks like an external freeze → **prefer reversible re-key over destructive poison**; gate the key-poison half on high-confidence-only signals.

**Kill-switch / FP.** `--at-rest={off,custody,custody+retaliate}`; retaliation off by default until confidence-gating is fleet-proven.

**Effort. M.**

### 4.5 Program-From-Payload (steganographic gather execution)
*"There is no bytecode section to find — the VM program is reassembled at runtime from bytes already living in the Qt app's own legitimate `.rdata`."*

**Mechanism (hardened).** At pack time (after `.rdata` is final) emit only a short encrypted **gather list** of `(rdata_offset, length)` tuples that reconstruct the bytecode from byte runs already present in the payload; the stub gather-copies them into scratch. The pack step verifies `reassembly == intended bytecode` before finalizing. **Hardened against "dump the reconstructed scratch buffer at the first VM fetch":** (a) **never materialize the whole program** — gather+decrypt **one instruction on demand** at fetch time (compose with the §3.1 tape so only the current instruction is clear, re-encrypted immediately); (b) bind gather offsets and per-instruction key to the SP1 rolling key + code-hash-bound key so a logged fetch stream is **single-run-only** and stub-`.text` tampering corrupts reconstruction; (c) deliberately source some gather runs from **`.rdata` bytes the Qt app itself reads at runtime**, so a scanner cannot page-mark those as VM data without breaking the live app — forcing per-access differentiation instead of a one-shot dump.

**Novel vs VMP/Themida/Denuvo.** Steganographic, data-driven execution: the protector's logic is *latent* in ordinary string/icon tables. Entropy scans and dump-and-diff recovery find nothing; sourcing from live-read `.rdata` makes the payload itself a shield.

**Touch.** New `packer/gather.py` (deterministic last-step gather-list builder + verify gate), `venice_vm.c` (on-demand gather fetch), `container.py`/`pack_info.h` (gather-list region).

**Container/ABI.** **BREAKING (v2):** encrypted gather-list region (`flags` bit). Packing must be the **deterministic last step** with a verify gate (no runtime brick).

**Perf · correctness · AV.** AV-clean. Build fragility is the cost: any `.rdata` change invalidates the list. Honest caveat: arbitrary opcode sequences rarely have long runs in `.rdata`, so most tuples are short — keep this scoped to a small crown-jewel program, not the whole VM.

**Kill-switch / FP.** `--gather={off,on}`; pack fails (never the customer) if verify ≠ intended bytecode.

**Effort. M–L.**

### 4.6 Import / Hook Analysis Defeat
*"Scylla rebuilds an import table of pure garbage, and the debugger-hide engine is detected not by any flag it spoofs but by the bytes it had to hook to spoof them."*

**Mechanism (hardened).** After FNV-hash/PEB import resolution (`pe_loader.c:325`), write `addr XOR mask` into each IAT slot where `mask = f(call-site page base)`, routing calls through a per-import RW→RX thunk that un-masks with the site-derived value — no resident slot holds a pointer into any export range, so Scylla/ImpREC auto-reconstruct resolves to nothing. Separately, hash the first bytes of the ntdll stubs a hider must inline-hook (`NtQueryInformationProcess`, `NtSetInformationThread`, the exception-dispatch stub) and route a hooked-stub result to **deception, never a key summand** (legit customer EDR also hooks ntdll). **Hardened against the two enumeration/observation oracles the red-team found:** (a) CFG-registered per-import thunks are a *static enumeration oracle* (GFIDS lists them all) → **collapse them into ONE CFG-registered dispatcher** that computes the target from an encrypted per-call token, so the import set is no longer statically countable; (b) a dynamic inter-module-transition trace records `{slot → real API}` regardless of masking → **make the resolved target unstable per call** (re-randomize `k` each invocation, rotate how many stolen prologue instructions run inside the dispatcher), **bind the mask to return-address + caller-page code-hash** so a lifted/replayed call site derives the wrong unmask and faults, route the real transition through the Venice `VVM_N_CALL_PTR` trampoline so every import appears to emanate from the single VM dispatch site, and **fold hot imports into Venice native ops** (already have SHA256/HKDF) so they never appear as inter-module calls at all.

**Novel vs VMP/Themida/Denuvo.** Defeats the address-in-export-range heuristic Scylla/ImpREC/IDA share *while calls keep working*, and detects the hider one layer beneath where it operates — by its own footprint, not by a flag it spoofs.

**Touch.** `pe_loader.c` (`resolve_imports`, IAT masking, single dispatcher), new `stub/src/iat_gate.c` (dispatcher + per-call token), `antidebug.c` (ntdll stub tomography → SP4), `venice_vm.c` (import-as-native-op).

**Container/ABI.** Per-import mask seed can be **derived from call-site page base (no stored data → no break)**; the single-dispatcher token table, if stored, is a v2 optional region.

**Perf · correctness · AV.** RW→RX thunks (no RWX) and self-ntdll reads are AV-clean. The mid-instruction relay resembles a hook trampoline → AV-smoke, and keep any `base+k` entry on **safe instruction boundaries** (length-disassemble or crash).

**Kill-switch / FP.** `--iat={masked,dispatcher,vm-native}` staged. ntdll tomography is deception-only and never bricks a legit-EDR customer.

**Effort. M.**

---

## 5. Track 3 — Deception

Goal: the analyst *wins, and is wrong.* Every item routes through cryptography so a false positive is survivable (the real license is server-side, so a customer never bricks) and a true positive is invisible.

### 5.1 Poisoned-Crack Family (running, authenticated, subtly-wrong builds)
*"Patch the stub and the GCM tag still verifies — no tamper error — because the wrong hash silently forks you onto a functional-but-sabotaged build that fails minutes later, deep in Qt, with no temporal link to the check you broke."*

**Mechanism (hardened).** Carry a decoy variant per protected section under a fixed fallback key: on the pristine-hash key's GCM auth failure (patched stub), **do not surface an error** — decrypt the decoy, which authenticates cleanly and yields a **watermarked/degraded** build. On a zero-FP detection, seed a poison value into `key_scatter` that only folds in on the Nth memguard fault or the second unsigned-Qt-DLL attach, so the failure surfaces far downstream and reads as a payload bug. **Hardened against "NOP the one `if(auth_fail)` fork / find the fixed fallback key blob":** replace the single-branch fork with a **keyless, branchless KDF-selected decode** — precompute a **poison dictionary** keyed by the hashes of the most common patch targets / known crack signatures, each entry a decoy ciphertext whose GCM tag is valid under the key derived from *that patched hash*. There is now no comparison, no second key path, no distinct fallback blob to NOP or find: a patched hash KDFs straight into an authenticating decoy, a pristine hash into the real one. Pair with §4.3 moving-code so no section is ever wholly plaintext at one snapshot instant, and spread the delayed-poison fold-in across many ordinary payload operations.

**Novel vs VMP/Themida/Denuvo.** AEAD auth-failure is normally a hard stop; weaponizing it into a **silent reward** — and doing so branchlessly via a hash-keyed decoy dictionary — makes the cracker ship a poisoned build and declare victory.

**Touch.** `pe_loader.c`/`memguard.c` (decode selection), `crypto.c` (hash-keyed KDF), `container.py`/`pack_info.h` (decoy dictionary region + per-section decoy ciphertext), `key_scatter.c` (delayed poison seed).

**Container/ABI.** **BREAKING (v2):** decoy region (`flags` bit); ~2× payload for dictionaried sections — scope to crown-jewel sections.

**Perf · correctness · AV.** AV-clean. Pristine customers always authenticate the real key first → **zero brick** for the fallback variant. Dictionary coverage is finite (anticipated patches only) — honest, but it removes the neutralize-one-branch bypass.

**Kill-switch / FP.** `--deception=off` disables all of it. Delayed-poison paths gate on **effectively-zero-FP signals only** (debug object / HW BP / named DBI — never timing).

**Effort. M.**

### 5.2 Coherent Decoy Everything
*"Every artifact the analyst reaches — the obvious key-shaped blob, the strings, the mostly-resident code, the unpacker their VirtualProtect breakpoint fires in — is a self-consistent lie that passes its own sanity check."*

**Mechanism (hardened).** Place a high-entropy decoy blob near the scatter buffer that **authenticates** (valid GCM under `HKDF(decoy_blob)`) to coherent fake config/license fields. Tamper-select a second `venice_strenc` string ciphertext that decrypts to a coherent false narrative (fake C2, fake ProductKey regpath, fake "valid until"). Keep build-verified-unreachable decoy code pages RX/resident 100% while real guarded pages are mostly NOACCESS, so a random snapshot is decoy-dominated. Add a **louder decoy unpacker** that is the first to `VirtualProtect` a buffer to RX (full AES-GCM decrypt of a decoy section, `CALL_PTR` into a meaningless checksum), plus a readable decoy jump-table that IDA reconstructs into a complete working interpreter for an ISA that computes nothing. **Hardened against "coverage/taint separates unreachable decoys":** the red-team's Intel-PT-coverage attack separates decoys precisely because they are *unreachable and unconsumed*. So make them **execute and be consumed on the real path** via a cancelling MBA identity — `real_key = f(real) ⊕ g(decoy) ⊕ g(decoy)`, the two `g(decoy)` terms emitted at separated program points so each taint-reaches the final key and each decoy page carries real coverage; make the perjured config **genuinely loaded** by branching real control flow on `(decoy_valid_until XOR correction)`. Then weaponize the **server-side dormancy** that already favors us: make the *only* license branch reachable without a valid account the **decoy** one, whose patch is build-verified not to affect OEP-key derivation — a cracker who NOPs it gets fake-success while the real key still derives.

**Novel vs VMP/Themida/Denuvo.** Standard decoys decrypt to garbage (an instant tell). Making every reachable artifact authenticate/compile/lift **cleanly to a wrong answer** turns the analyst's own sanity checks into positive reinforcement for the false trail — and braiding decoys into real dataflow defeats the coverage/taint counter.

**Touch.** `key_scatter.c` (honeypot blob), `venice_strenc.py`/`venice_str_data.h` (perjured strings), `memguard.c` (resident decoy pages), new `packer/decoys.py` (build-time verifier that no edge/reloc targets a real path *and* that decoy coverage/taint braids correctly), `venice_asm.py` (MBA cancel-identity).

**Container/ABI.** Decoy artifacts ride the v2 decoy region (shared with §5.1).

**Perf · correctness · AV.** AV-clean, mostly additive, near-zero brick risk (decoys build-verified off every real path — except the intentionally-braided ones, which the differential gate must prove neutral).

**Kill-switch / FP.** `--deception=off`. The braided-MBA and reachable-decoy-license paths behind their own sub-flags with mandatory pack-time neutrality proof.

**Effort. M.**

### 5.3 Invisible OEP Handoff + Judas Entry + Camouflaged Failure
*"Every tutorial says 'breakpoint the tail jump to OEP' — so there is no jump; and on tamper the entry silently resolves to the app's own trial-mode door while the decompiler confidently prints it as the real one."*

**Mechanism (hardened).** Delete the indirect call to OEP. Today `invoke_exe_oep()` computes `addr = s_oep ^ s_oep_key` and does `fn()` (`stub_main.c:46–52`). Replace with: build a `CONTEXT` (`Rip` materialized from the XOR'd `s_oep` at the last instant, inside a VEH) and resume via dynamically-resolved `RtlRestoreContext`/`NtContinue`, so the transition is a return-from-exception inside ntdll and the visible linear fallthrough is a fake validator ending at a decoy entry. Fold the aggregate tamper-witness into the `s_oep` XOR key so a clean run recovers the true OEP and any tamper recovers **the app's own trial/expired entry** (no synthetic decoy to author, indistinguishable by construction). Wrap the selector in an MBA identity tuned so HexRays' constant-folder simplifies to the **decoy** OEP. For zero-FP witnesses, feed the witness into the **GCM AAD** of a section subset so tamper fails with the exact generic "authentication failed" the loader already emits for a bad dump. **Hardened against "hook `NtContinue`, read `Context->Rip` on a clean run":** (a) do **not** put OEP in the resumed `Rip` — set it to a short springboard in already-executed stub code (or a `PAGE_NOACCESS` guard page); the true OEP is computed only inside the VEH/springboard and re-hidden immediately; (b) in that springboard, **scan for the exact attack** — check DR0-3 and the first bytes of the resolved `RtlRestoreContext`/`NtContinue`/springboard for hooks, and fold any hit into the `s_oep` witness, so breakpointing the resume primitive **is** a tamper event; (c) emit 2–3 **decoy `NtContinue` resumes first**, each with a `Rip` at the trial entry or a junk validator, so a naive export breakpoint fires repeatedly and no single `Context->Rip` is trustworthy.

**Novel vs VMP/Themida/Denuvo.** No protector ships the OEP handoff as an unwinder resume, uses the app's **genuine trial entry** as the honeypot, or makes the tamper response **collide with the boring corrupt-dump path** so the analyst blames their own tools.

**Touch.** `stub_main.c` (`stash_oep`/`invoke_exe_oep`/`invoke_dll_oep` → CONTEXT resume + springboard + BP-scan), `pe_loader.c` (`*out_oep`, the trial-entry RVA as second OEP), `crypto.c` (witness → AAD), `container.py`/`pack_info.h` (trial-OEP RVA + witness config).

**Container/ABI.** Trial-OEP RVA + selector config in `reserved[24]` or the v2 decoy region.

**Perf · correctness · AV.** `RtlRestoreContext`/`CONTEXT` are ubiquitous and AV-clean. The **DLL-main path is brittle** (springboard/CONTEXT resume is cleanest EXE-only) → keep DLL targets on a simpler variant. Springboard adds a few hundred bytes + one guard-fault of latency.

**Kill-switch / FP.** Hard-fail witnesses (trial-fold, AAD) must be **effectively zero-FP** or a paying customer boots into trial — gate behind the production-build flag with the other tripwires; `--deception=off` reverts to the plain indirect call.

**Effort. L.**

---

## 6. Track 4 — Anti-automation

Goal: blow up symbolic execution / taint / trace-based devirt / DBI / program-synthesis / LLM-assisted RE. Each folds analysis-hostility into **keys**, so there is nothing to NOP.

### 6.1 RNS-Encoded VM Stack (data-space residue obfuscation)
*"Every 64-bit stack value is secretly smeared across 3 coprime residue lanes, so a single logical variable has no single storage cell to taint."*

**Mechanism (hardened).** Carry each VVM stack slot as `(x mod m0, x mod m1, x mod m2)` with per-build code-hash-derived coprime moduli whose product exceeds 2⁶⁴. ADD/SUB/MUL are CRT-homomorphic lane-wise; CMP/JZ reconstruct via a Garner step; scope to the arithmetic-heavy key-derivation/shard-fold program where bitwise ops are rare. **Hardened against the "boundary-tap at the mandatory Garner reconstruction / recover moduli by GCD" attack:** (a) **fuse Garner into the consumer** — reconstruct directly into the byte-lane feed of the SHA256/XOR/scatter native op as one non-interruptible handler, so there is no plaintext register/slot to hook between join and consume; (b) **rolling moduli** — re-encode residues between segments with PC+code-hash-derived moduli so one triple recovery unlocks only one segment, paired with §3.1/§3.3 so the single readable switch (the actual tap point) is gone; (c) add a **4th redundant consistency lane** whose desync under single-stepping/patched handlers/forced reconstruction trips the SP4 key-wipe/deception path — instrumenting the boundary **poisons** the key instead of leaking it.

**Novel vs VMP/Themida/Denuvo.** Taint and value-set analysis assume one variable = one cell; RNS breaks that at the root, and SMT must carry 3 (now 4) modular constraints with a reduction per op. No protector represents VM stack values in a residue number system.

**Touch.** `venice_vm.c` (lane-wise arithmetic, fused Garner-to-consumer), `venice_asm.py`/`venice_disasm.py` (encode/decode residues, rolling moduli), `crypto.c` (moduli from code-hash).

**Container/ABI.** None (moduli derived from the per-build seed + code-hash).

**Perf · correctness · AV.** AV-clean, pure uint64 modular math (VM already has DIV/MOD). **A modulus/overflow bug silently mis-keys** → exhaustive encoded-vs-plain differential testing (SP5) required. Cost is constant-factor, honestly — its teeth are the fused boundary + consistency lane, not RNS alone.

**Kill-switch / FP.** `--rns={off,3lane,4lane}`; fail-closed on lane desync.

**Effort. M.**

### 6.2 Control-to-Data Key Laundering
*"The key byte is never a value the CPU adds or moves — it is reconstructed from WHICH of two identical-looking blocks ran."*

**Mechanism (hardened).** In the VVM key-derivation program no secret byte is consumed by an arithmetic opcode: each bit branches into one of two structurally identical micro-blocks that STORE the same constant to positionally different scattered cells, and reassembly reads the key from the **presence pattern** of which cells were written. Small crown-jewel scalars are materialized structurally as Church/unary loop trip counts, so the constant never exists as a findable immediate. **Hardened against the three red-team attacks (consumer-tap, write-address side channel, PDG slice):** (a) kill the **consumer tap** (the fatal one) — never let the full 32-byte key exist: virtualize AES key expansion inside the VVM (SP2) and feed round keys directly from the presence-pattern reconstruction; put scatter cells on memguard `PAGE_NOACCESS` pages touched only under the VEH, re-encrypt immediately after use; (b) blunt the **write-address trace** by switching from **positional to temporal** encoding — both micro-blocks write the *same* address at different times with an intervening re-encrypt, and randomize the store target each run via a CSPRNG-seeded permutation so the write-address trace is unstable across runs and the store offset is computed, not an immediate; (c) **decorrelate the branch predicate from raw key bits** — `predicate = MBA(keybit, per-build nonce)` — so slicing the condition yields an obfuscated expression, not the bit.

**Novel vs VMP/Themida/Denuvo.** Every serious protector still *moves* the secret value, so data-flow taint follows it. Re-expressing key material as **pure branch decisions with constant-valued stores** defeats dynamic taint (Triton/libdft/Pin) and backward data slicing by construction — and temporal-not-positional encoding closes the address side channel.

**Touch.** `venice_asm.py` (laundering codegen + MBA predicates), `venice_vm.c` (temporal store + VM AES schedule), `key_scatter.c` (presence-pattern reassembly).

**Container/ABI.** None.

**Perf · correctness · AV.** AV-clean, fully deterministic → zero brick risk, harness-validatable. **~8× bloat → restrict to a few key bytes.**

**Kill-switch / FP.** `--launder={off,on}`, per-byte budget.

**Effort. S–M.**

### 6.3 Analysis-Hostile Constructs Folded Into the Key
*"There is no branch to NOP and no crypto call to summarize away — the always-true fact, the unsatisfiable SAT instance, the unwidenable loop, and the aliased slice are all load-bearing inputs to the AES key."*

**Mechanism (hardened).** A suite of compute-or-die predicates folded into `key_scatter_init` input rather than branched on: entangled opaque predicates through one shared accumulator (globally inconsistent 10⁵ instructions downstream → defeats path-merging); number-theoretic (quadratic-residue/Pell) + tuned subset-sum/xor-SAT tarpits disguised as flat ADD/XOR/AND (SMT bit-blasts poorly, no SHA/AES to summarize); concretely-bounded popcount/Collatz loops (force interval/octagon widening to Top); load-bearing opaque-1 padding (backward slice/DCE can't prune without rotting the multiplier); runtime-keyed must-alias/may-alias interleave; an opaque-true edge into a reachable-but-never-taken VVM region as a symbolic/lift sink. **Hardened against "concrete-trace / observe-the-result" (its own axiom is the wedge — always-true ⇒ constant ⇒ zero runtime entropy):** break that axiom — make the folded value always-control-safe but **data-varying per run**, seeded from a quantity the analyst cannot replay: feed the predicate accumulator the stub's **code-hash + a section-content measurement**, so a key recorded under a DBI/instrumented image (which perturbs measured pages) derives a *different, wrong* key — the trace harness becomes a tripwire. Recompute the fold **lazily inside the memguard per-page fault path** so no assembled 32-byte key ever exists. And ship it **strictly paired with the anti-dump/moving-code layer** — alone it only defeats the static/symbolic attacker while observe-once-and-dump walks past it.

**Novel vs VMP/Themida/Denuvo.** Turns the analyzer's own *soundness* (path-merge, termination/widening, slicing, evaluation-order independence, SMT completeness) into the trap, and binds every construct's value into the key so cheap pattern-match-and-NOP fails.

**Touch.** `venice_asm.py` (predicate library — each numerically unit-tested at pack across environments or it universally bricks), `venice_vm.c` (lazy per-page fold), `key_scatter.c`, `crypto.c` (code-hash+section measurement seed).

**Container/ABI.** Baked per-environment predicate constants in the v2 expectations blob.

**Perf · correctness · AV.** AV-clean. The rewrite engine is the one costly piece — ship it last, gated. **Each predicate must be genuinely always-true across all customer environments (pack-time numeric unit tests) or it universally bricks.**

**Kill-switch / FP.** `--hostile={off,static,static+datavary}`; the data-varying seed behind `--tamper-fold`.

**Effort. M–L.**

### 6.4 Microarchitectural / Timing Fuse woven into the OEP unmask
*"There is no 'if debugger' branch to NOP — the measured cache/branch-predictor/clock texture, snapped to a canonical constant, IS an operand of the number that unmasks the entry point."*

**Mechanism (hardened, honestly scoped).** Harvest robust classification bits (each with a 5–10× margin so it quantizes identically across real CPUs): L2 eviction-set miss/hit sign, PHT branch-predictor convergence, TSC step-texture (GCD/zero-delta fraction), coarse TSC/QPC ratio bucket. Snap each to a stable canonical constant and XOR the descriptor into the CSPRNG key that unmasks `s_oep`. **The red-team is right that "canonical across all real CPUs" = a global constant a single native run harvests** — so we scope this as an **anti-automation multiplier, not a human-stopper**, and (a) **kill the extract-once-concretize-forever property**: feed the texture into the **memguard per-page/per-section key schedule, re-measured at intervals**, so concretizing one constant decrypts only the first page and later faults derive from a fresh measurement — forcing an emulator to model cache/PHT *continuously* (angr/Triton cannot); (b) **split into N independent fuses** gating different sections at staggered times, each XOR-fused with the code-hash-bound key, so one harvested descriptor never covers the whole binary; (c) route mismatch to **deception** (decoy OEP), per its own detection-first note.

**Novel vs VMP/Themida/Denuvo.** Converts timing *detection* from a patchable control-flow decision into a *data dependency* of the entry transfer; a wall-clock magnitude spoof or constant-increment `rdtsc` hook cannot reproduce the grain, and VT-x customers stay correct because texture rides the real core.

**Touch.** New `stub/src/uarch_fuse.c` (harvest routines), `stub_main.c` (`stash_oep` unmask), `memguard.c` (per-section re-measure), `container.py` (baked canonical bands).

**Container/ABI.** Canonical bands in the v2 expectations blob.

**Perf · correctness · AV.** Only `clflush`/`rdtsc`/`lfence`/loads — zero AV weight. **The descriptor must be byte-exact on 100% of customer silicon** → ship **detection→deception first**, promote to hard key only after fleet telemetry.

**Kill-switch / FP.** `--uarch-fuse={off,deception,key}`; `key` mode fleet-gated + kill-switched.

**Effort. M.**

### 6.5 Emulator / DBI Correctness-Gap Oracles (branchless, folded to deception)
*"No is-emulated test to invert — the emulator simply computes the wrong key, because it faked an instruction, a fault, a JIT product, or a speculation window that real silicon gets right."*

**Mechanism (hardened).** Fold known emulator/DBI gaps branchlessly into the KDF, routed to survivable deception on mismatch: a deliberately-faulting RDPMC read observed under the memguard VEH (raised? correct #GP code? fault-latency class?); DBI code-cache detection via noinline self-call timing + a `_ReturnAddress()`-vs-module-range provenance fold (Pin/DynamoRIO/Frida relocate off-image); a mixing-loop trip count read from `KUSER_SHARED_DATA` at `0x7FFE0000` (symbolic engines stub the page → unbounded); a CPUID-gated hardware AESENC round in the fold (incomplete AES-NI emulation mis-keys); a robust structural invariant of the payload's own Qt/V4 JIT cache (a stub-only emulation never produced it). **Hardened against "run native once, record the deterministic oracle outputs, constant-fold into the emulated env":** the exploited property is that oracle values feed a *static, capture-once* key — so **re-sample them continuously and bind them into memguard's per-page re-encryption keys** (the SEC_SPLIT path): a replayed constant key runs correctly through the first section decrypt but **diverges on every subsequent page fault**, because the live oracle feeds the moving-code page crypto a native-captured constant cannot reproduce under instrumentation. Make the deception N-of-M vote **re-sampled per page-fault epoch**, not once at arm.

**Novel vs VMP/Themida/Denuvo.** Protectors *detect* emulation with patchable flags; folding the **correctness gaps themselves** into key material leaves nothing to NOP — and per-page re-sampling defeats record-and-replay.

**Touch.** `memguard.c` (VEH observation of RDPMC #GP, per-page oracle binding), new `stub/src/emu_oracles.c`, `venice_vm.c` (AESENC fold, provenance fold), `crypto.c`.

**Container/ABI.** None (oracles are runtime); N-of-M vote config in the expectations blob.

**Perf · correctness · AV.** All AV-clean (no direct syscalls, no int3). **Spectre and the JIT invariant are fragile across microarch/updates** (see §8 moonshots — kept separate); the AES-NI path needs a CPUID fallback a spoofer could dodge → deception-route it.

**Kill-switch / FP.** `--emu-oracles={off,detect,key}`; fragile oracles opt-in and N-vote/deception-routed; kill-switched. FP risk on EDR/crash-reporter hosts that hook exceptions → deterministic fold-the-real-shard fallback.

**Effort. M–L.**

### 6.6 Checks-Pay-Into-Key (no branch, no self-consistent single-site patch)
*"The anti-debug checks stop being branches you can NOP — each pays a secret into the AES key, each is the integrity custodian of its neighbor, and the derivation folds the call-chain it was actually invoked through."*

**Mechanism (hardened).** For the deterministic true-negative subset (BeingDebugged byte `antidebug.c:137`, NtGlobalFlag bits `:146`, debug-object handle `:272`) replace detect→ExitProcess with a **fold**: honest arithmetic yields a baked contribution, a debugged machine yields garbage, and the section GCM key is correct **iff every folded check ran honestly**. Wire the 13 checks + 4 tripwires into a **ring** where `check_i` folds `HKDF(baseline_{i+1} XOR live_hash_of_check_{i+1})` — measurement and victim are different functions, so a single NOP corrupts via a sibling. Fold a base-normalized `VirtualQuery` proof-of-W^X of the stub's own sections and the ASLR-normalized return-address chain into the KDF info, so an RWX flip or extract-and-replay-in-Unicorn presents the wrong context. **Hardened against "stealth-spoof the three folded PEB signals, then read the derived key":** since the fold cannot beat runtime key-theft, **stop protecting a persistent plaintext key** — (a) keep the folded key inside the VM value-stack, derive per-section immediately before that section's GCM decrypt, scrub after (SP2); (b) bind the ring's neighbor-hashes into memguard page CRCs and rotate folded material per page; (c) against the stealth-spoof specifically, add **one contribution the PEB-spoofers don't cover** — a base-normalized, data-only self-hash of the code *surrounding* the BeingDebugged/NtGlobalFlag reads (spoofers zero the field values but don't synthesize a consistent self-hash of the surrounding check code), CFG/reloc-stable and rebaked per compile.

**Novel vs VMP/Themida/Denuvo.** Decouples the analyst's patch from its delayed, opaque consequence in a way the one-shot code-hash bind cannot (step-over never touches `.text`); the mutual-custody ring means there is no single site whose patch is self-consistent.

**Touch.** `antidebug.c` (check subset → fold, ring wiring), `crypto.c`/`crypto_derive_key` (`crypto.c:474`, ring digest as HKDF info), `venice_vm.c` (VM-hosted key), `container.py` (baked baselines).

**Container/ABI.** Baked per-check baselines + return-chain digest in the v2 expectations blob.

**Perf · correctness · AV.** Reuses the vetted AV-clean check set + HKDF → AV-clean. **Discipline:** fold ONLY rock-solid true-negatives — **never DR0-3 or the RDTSC gate** (those FP on legit environments; route them to deception). Keep ranges relocation/CFG-thunk stable; rebake the return-chain every compile; keep loud early-exit checks outside the ring.

**Kill-switch / FP.** `--tamper-fold={off,env}`; only the zero-FP subset ever enters the key.

**Effort. M.**

### 6.7 Session-Long Liveness & Cadence Gating
*"There is no startup gauntlet to snapshot past — a late key only derives if a set of lifecycle checkpoints each fired exactly the right number of times, if owner-placed sleepers ran mid-session, and if sealed code was materialized by genuine OS-driven execution."*

**Mechanism (hardened).** Maintain a scattered accumulator that deterministic events increment by distinct deltas (TLS callback ran, each section decrypt completed, each import-hash round, each in-ring tripwire) and derive a late/most-used-section key from the quorum — so OEP-only emulators that skip loader stages, or a "this check is redundant" patch, land on the wrong total. Defer sensitive sections behind OS-driven materialization: a real TLS callback under the loader lock (reserved static-TLS slot as a crypto invariant) and a self-queued `QueueUserAPC` decrypt delivered only at the Qt event loop's alertable wait. Gate specific live features on `HKDF(startup-milestone-ratchet-digest, feature_id)`. **Hardened against "native-run-and-dump satisfies all cadence, then hardcode the terminal constant":** (a) replace the one-shot quorum with a **rolling ratchet consumed at many points** — every section/feature decrypt XOR-advances the accumulator and re-derives, so a patched `accumulator = 0xKNOWN` satisfies one site and desynchronizes all later ones; make each delta a **hash of that stage's own `.text` bytes** so a patched-out "redundant" check changes its own contribution and can't be substituted by an integer; (b) **compose with memguard** on every ratchet-gated feature so no two features are simultaneously plaintext and an end-of-session dump captures only the last page; wipe the APC-delivered materialization key inside the alertable-wait servicing window so lazy end-of-session dumping misses it.

**Novel vs VMP/Themida/Denuvo.** Folds **control-flow cardinality and OS-callback delivery** (structural facts with nothing to spoof) rather than sensor values, and extends protection **past the boot window** so "the crack boots" becomes a false success signal.

**Touch.** `pe_loader.c` (TLS callback, section-decrypt counters — `invoke_tls_callbacks:495`, `setup_tls:518`), `stub_main.c` (APC at alertable wait), `crypto.c` (ratchet digest), new `stub/src/cadence.c`.

**Container/ABI.** Expected milestone deltas in the v2 expectations blob.

**Perf · correctness · AV.** AV-clean. **Discipline:** fold only **bit-deterministic counts** (never fault/sweeper counts); TLS callbacks must be O(1) loader-lock-safe no-ops; the APC needs a bounded alertable-`SleepEx` fallback; any gated feature must be fleet-proven invariant.

**Kill-switch / FP.** `--cadence={off,ratchet}`, per-feature gate kill-switches.

**Effort. M–L.**

### 6.8 Polymorphic Stub + Entangled Forensic Watermark
*"Every build's unpacker is a different program, and the per-build key constants that make it unique also fingerprint which build a leaked crack came from and localize the exact bytes the cracker neutralized."*

**Mechanism (hardened).** A packer-side **source-to-source** pass (from the per-build seed) regenerates the stub sources before compile: reorder independent startup checks, select among N semantically-equivalent check bodies, inject MBA-identity computations into `pe_loader` arithmetic, permute struct-field access, rotate which slot holds the accumulator — then **honestly recompile**, so the existing code-hash binding just tracks a different `.text`. Carve a documented sub-range of the MBA/consensus coefficient masks as a per-build (or per-channel) identifier that is **load-bearing in key derivation**, logged to a private ledger. **Hardened against "structural relocator + static MBA simplifiers (SiMBA/GAMBA) normalize N builds to one template" and "shed the stub via unpack-and-reship":** (a) keep every watermark/MBA coefficient **runtime-keyed** (never a static `.rdata` constant) — mixed with the SP1 accumulator and gated by an opaque predicate over the guarded-fault ledger — so no static simplifier sees a foldable constant and recovery is forced through the symbolic execution the other Track-4 items break; (b) close the **attribution gap** by entangling the build-id into a value the **payload** consumes at runtime (or watermarking the decrypted payload image benignly), so a dumped-and-rebuilt binary either inherits the fingerprint or is subtly broken; (c) make metamorphism perturb **dataflow shape** (superoperator minting, accumulator-slot rotation) not just syntax, so a normalizing decompiler cannot canonicalize builds back to one template.

**Novel vs VMP/Themida/Denuvo.** The 2000s polymorphic-engine idea done as a **source pass + honest recompile** stays Defender-clean (no machine-code SMC/RWX) and defeats loader-signaturing and cross-build IDA-script replay **in both directions**; entangling a **non-removable, runtime-keyed** watermark into the key turns each leak into attribution + next-build hardening.

**Touch.** New `packer/metamorph.py` (source pass) + `packer/watermark.py` (id ledger), all three `venice_*` tools, `pe_loader.c`/`antidebug.c` (variant bodies), payload-side watermark hook.

**Container/ABI.** Watermark is runtime-keyed (no stored constant → no break); payload-consumed id may need a small `reserved[]` field.

**Perf · correctness · AV.** **The entry needing the MOST AV vigilance** — the variant library + MBA must be hand-curated and **per-build AV-smoked**; every generated build must pass the SP5 round-trip harness.

**Kill-switch / FP.** `--metamorph={off,syntax,dataflow}`; watermark `--watermark={off,build,channel}`. No hardened build ships without the per-build AV-smoke farm green.

**Effort. M (per feature) / L (the AV-smoke farm).**

---

## 7. Track 5 — Moonshots / extras

Higher novelty or higher fragility; quarantined here with heavy kill-switches. Ship after the core.

### 7.1 Decompiler-Analysis Poison → repurposed as a decoy-path time-sink
*"You don't hide the code from HexRays — you make it formally refuse or lay out the wrong frame, using its own soundness requirements against it."*

**Mechanism (hardened).** Positive-SP trampoline (runtime-balanced but HexRays sees an unprovable delta and declines the routine with "positive sp"); perjured `UNWIND_INFO` (wrong alloc size / phantom saved regs → IDA/Ghidra place locals wrong); overlapping-instruction desync anchors **registered in the `/guard:cf` GFIDS table** so guard-aware disassembly trusts the mid-instruction landing; hash-bind the exception directory into the code-hash key so stripping/fixing `.pdata` breaks the unpack. **Hardened per the red-team's correctness catch:** these only poison *static* disassembly, and worse, with `/guard:cf` + the memguard VEH + a Qt payload that throws SEH/C++ exceptions through V4, `RtlVirtualUnwind` will consult `.pdata` for live frames — a poisoned frame on a real unwind path **crashes the shipped app**. So **do not use it as a wall on the real path.** Emit the poison **only on leaf, provably-non-throwing DECOY functions** that statically resemble the key path, so an analyst who trusts HexRays reads a coherent-but-wrong key schedule (feeds §5.2); keep the real crypto path clean of unwind poison; drop the `.pdata` hash-bind on real frames. Gate behind a build kill-switch and an **exhaustive post-build unwind-simulation** (`RtlVirtualUnwind` every poisoned frame from every RIP) that **fails the build** if any poisoned frame is reachable on a real unwind.

**Novel vs VMP/Themida/Denuvo.** Off-the-shelf protectors make pseudocode *ugly* (a heuristic); weaponizing balance-soundness, trusted unwind metadata, and the CFG guard table makes tools **structurally decline or confidently mislabel** — and, keyed to `.pdata`, it can't be stripped.

**Touch.** `venice_trampoline.asm` (positive-SP reconverge), new `packer/unwind_poison.py` (perjured `UNWIND_INFO` on decoy frames + post-build unwind simulator), `container.py` (decoy `.pdata`).

**Container/ABI.** Decoy `.pdata` rides the v2 decoy region.

**Perf · correctness · AV.** AV-clean. **Real brick risk** if any poisoned frame reaches a live unwind or the reconverge math is off by a slot → the post-build unwind simulator is existential.

**Kill-switch / FP.** `--unwind-poison={off,decoy}`; build fails if the simulator finds a reachable poisoned frame.

**Effort. M (fragile).**

### 7.2 Windows Exception-Dispatch Weaponization
*"The analyst's reflex — 'swallow all first-chance exceptions to survive the tripwires' — is exactly what disarms the real key, because the load-bearing crypto lives in the continue phase, the __except filter, and an exactly-once guard-page trip they never re-take."*

**Mechanism (hardened).** The first-chance VEH does only **decoy** key-shard work and continues; the **real** shard is folded in a **Vectored Continue Handler** the OS invokes only on the actual continue path a swallowed exception never reaches. Express a stub stage as a language `__try/__except` whose filter performs the key fold and returns its disposition from the result, so `RtlDispatchException` *is* the interpreter. Carry real control through a ladder of `PAGE_GUARD` scratch pages: the **exactly-once auto-clearing** trip advances a rolling accumulator (routed only to scatter-index selection, survivable), so a DBI/symbolic replay that re-touches the block does not re-fault and diverges. **Hardened against "faithfully replay everything with Intel PT + a clean snapshot, then dump the assembled shard":** bind the exception-assembled shard as a **rolling input into memguard's per-page key schedule** instead of a once-derived section key — the guard-page-ladder accumulator drives per-page derivation, the sweeper re-encrypts, and the secret exists only as a transient per-page value, defeating both the symbolic analyst *and* the native snapshotter; feed a coarse fault→continue latency band into the VCH so a JIT-recompiling recorder (TTD) lands out-of-band and diverges (Intel PT stays invisible to this, forcing the heavier hypervisor-snapshot route); make the one-shot rung produce state consumed later and never left resident.

**Novel vs VMP/Themida/Denuvo.** Continue handlers and `__except`-filter-as-oracle are almost unknown in protectors and **invert the analyst's exception-suppression instinct**; the guard-page ladder exploits a Windows paging quirk emulators model imprecisely.

**Touch.** `memguard.c` (reuse the VEH — `memguard_veh:521`; add VCH + per-page shard binding; the existing `mg_veh_path_hooked:268` decline-to-arm guard stays), new `stub/src/exc_weave.c`, `crypto.c` (`__C_specific_handler` resolved from ntdll for the freestanding `__except`).

**Container/ABI.** None (runtime).

**Perf · correctness · AV.** AV-clean (no int3, no direct syscalls). **Honest FP risk on EDR/crash-reporter hosts** that hook/swallow exceptions → keep opt-in with a **deterministic fold-the-real-shard fallback**; keep the latency band wide.

**Kill-switch / FP.** `--exc-weave={off,on}`; fallback path derives the real shard when the VCH doesn't fire.

**Effort. L (fragile).**

### 7.3 Experimental extras (opt-in, fleet-gated, off by default)

Pulled out of §6.5 and honestly quarantined because they are fragile across microarch/OS updates:

- **Spectre-v1 transient-domain key byte** — a key byte recovered by flush+reload so the value has **no committed data-flow edge** any taint/symbolic engine can model. *Real, but* fragile across microarch and mitigation state → **N-vote + deception-routed + kill-switched**; never a sole key summand. `--spectre-byte=off` default. Effort **M**, high maintenance.
- **Hardware AESENC round fold** — a CPUID-gated `AESENC` mixed into the KDF so incomplete AES-NI emulation mis-keys. Needs a CPUID fallback a spoofer could dodge → **deception-route** the fallback. `--aesni-fold={off,deception}`. Effort **S**.

Both live behind the SP5 differential harness and require fleet telemetry before any promotion from deception to hard-key.

---

## 8. Phased implementation roadmap

Ordered so early phases are low-risk and self-contained; later phases build on them. Each phase names its **deliverable · files · test + AV-smoke gate**. **ABI-breaking phases are marked and must land as one release** (stub + `container.py` + `pack_info.h` in lockstep, round-trip test asserting agreement).

### Phase 0 — Foundations *(no attacker-visible change, no ABI break)*
- **Deliverable:** SP1 rolling accumulator plumbed at `vvm_push`/`vvm_pop`; per-build seed threaded through all `venice_*` tools; SP5 differential pack-time harness (assembler vs interpreter, bit-exact or pack fails); kill-switch flags reserved in `PackInfo.flags`; SP4 deception-router skeleton (selects between two valid blobs).
- **Files:** `venice_vm.c`, `venice_asm.py`, `venice_disasm.py`, `shuffle_opcodes.py`, `container.py` (flag bits only), `pack_info.h` (flag bits, still 192 B).
- **Gate:** existing round-trip tests green; differential harness green on 100 random programs; AV-smoke unchanged (no behavior change); clean-VM A/B identical output.

### Phase 1 — VM core hardening *(no ABI break)*
- **Deliverable:** §3.1 history-keyed tape (RW page), §3.2 stateful/tableless dispatch (kills the readable `switch`), §3.3 cross-domain seal, §6.1 RNS stack, §6.2 control-to-data laundering. All runtime/bytecode-only (bytecode ships in `venice_programs.h`, not the container).
- **Files:** `venice_vm.c`, `venice_asm.py`, `venice_disasm.py`, `venice_trampoline.asm`, `crypto.c` (path-tag/seal HKDF terms).
- **Gate:** differential harness green per-build across 50 seeds; clean-VM A/B (key derivation still yields correct section keys → GCM decrypt succeeds); **AV-smoke on 20 seeds** (RW data SMC must not trip Defender); perf budget (crown-jewel VM path within N ms).

### Phase 2 — Anti-dump core *(ABI-BREAKING → bump to `LETHE_FORMAT_VERSION = 2`; MUST land together)*
- **Deliverable:** **SP2** (VM-internal AES key schedule; delete `key_scatter_get` contiguous reassembly), **page-chunked section storage** (per-page GCM units — the breaking change), §4.3 streaming split-inflate + observation-adaptive residency (+ working-set monitor thread), §4.2 forward-secure ratchet + neighbor-chained pads, §4.4 at-rest secret custody. Define the full **v2 container** here with all optional regions reserved under `flags` (expectations / decoy / gather / IAT-token) so later phases add data without another bump.
- **Files:** `memguard.c`, `key_scatter.c`, `crypto.c`, `pe_loader.c`, `venice_vm.c`, **`container.py` + `pack_info.h` (v2, lockstep)**, new `stub/src/at_rest.c`.
- **Gate:** **dump-resistance harness** — snapshot RAM at OEP and assert (a) no contiguous 32-byte key, (b) no whole section plaintext, (c) working-set ≤ cap; round-trip v2 test; perf budget (per-page crypto at 12-page WS); **AV-smoke heavy** (the private RX arena of §4.3 is the top risk — arena stays `--footprint=split` here, `arena` deferred to Phase 5 after its own AV soak).

### Phase 3 — Key entanglement *(brick-risk; kill-switched; heavy A/B; ABI-additive under v2 flags)*
- **Deliverable:** §6.6 checks-pay-into-key ring, SP3 environment-as-summand KDF, §6.3 analysis-hostile constructs (static first, then data-varying seed), §4.1 Merkle-linked blocks (per-block blob in a v2 optional region), §6.7 cadence/liveness ratchet.
- **Files:** `antidebug.c`, `crypto.c`/`crypto_derive_key`, `venice_vm.c`, new `stub/src/vvm_blocks.c` + `stub/src/cadence.c`, `container.py` (expectations blob populate — no layout change), `venice_asm.py`.
- **Gate:** **fleet-representative A/B** (10+ real CPU/OS/EDR configs must all derive the correct key — any FP is a customer brick); differential harness; `--tamper-fold=off` fallback verified; AV-smoke. **Only zero-FP true-negatives enter keys; DR0-3/RDTSC route to deception, never key.**

### Phase 4 — Deception layer *(highest care; server-enforcement makes decoys safe; ABI-additive under v2 decoy region)*
- **Deliverable:** §5.1 poisoned-crack (keyless KDF-selected decoy dictionary), §5.2 coherent decoy everything (with braided-MBA neutrality proof), §5.3 invisible OEP handoff + Judas trial entry + camouflaged GCM-AAD failure, §7.1 decompiler-poison on decoy frames.
- **Files:** `stub_main.c`, `pe_loader.c`, `memguard.c`, `crypto.c`, `key_scatter.c`, `venice_strenc.py`, new `packer/decoys.py` + `packer/unwind_poison.py` (with the existential post-build unwind simulator), `container.py` (decoy region populate).
- **Gate:** **pristine-customer A/B proves zero brick** (real license server-side; unmodified binary always authenticates the real path first); tamper A/B proves decoy authenticates + fails downstream with the generic message; **post-build unwind-simulation green** (no poisoned frame on any live unwind); AV-smoke.

### Phase 5 — Anti-automation panels + advanced dispatch *(mixed; some ABI-additive)*
- **Deliverable:** §6.4 uarch/timing fuse (deception mode), §6.5 emu/DBI correctness-gap oracles (per-page-bound), §3.5 cycle-woven (instrumentation-tripwire mode), §4.6 import/hook defeat (single dispatcher + VM-native imports), §4.5 program-from-payload (gather list — v2 gather region), §3.4 logic mortaring (source cooperation + native→VM thunk — v2 mortar region), §4.3 arena execution (promoted after its AV soak), §7.2 exception-dispatch weaponization.
- **Files:** new `stub/src/uarch_fuse.c` + `emu_oracles.c` + `exc_weave.c` + `iat_gate.c`, `pe_loader.c`, `memguard.c`, `venice_vm.c`, new `packer/gather.py` + `packer/mortar.py`, `container.py` (gather/mortar regions populate).
- **Gate:** per-item kill-switch verified; **fleet telemetry required before any fuse/oracle promotes from deception to hard key**; logic-mortaring PACK-time bit-exact differential gate green per function; gather verify gate green; **arena AV-soak** (private RX) green on the 20-seed farm; perf budget for fault-storm modes.

### Phase 6 — Polymorphic stub + forensic watermark + experimental extras *(ship last; MOST AV vigilance)*
- **Deliverable:** §6.8 source metamorphism (syntax → dataflow) + runtime-keyed non-removable watermark + payload-consumed build-id, §7.3 experimental extras (Spectre byte, AES-NI fold) — all off by default.
- **Files:** new `packer/metamorph.py` + `packer/watermark.py`, all `venice_*` tools, `pe_loader.c`/`antidebug.c` (variant bodies), payload watermark hook, `reserved[]` build-id field.
- **Gate:** **per-build AV-smoke farm** (every generated variant must be Defender-clean — this is the release blocker the whole product hinges on); SP5 round-trip on every seed; watermark attribution round-trip (leak a build → recover the id from the packed EXE **and** from a dumped-and-rebuilt copy); experimental extras stay `off` until fleet-gated.

### ABI-break summary
| Phase | Breaking? | What lands together |
|---|---|---|
| 0, 1 | No | Runtime/bytecode only |
| **2** | **Yes → `FORMAT_VERSION = 2`** | Page-chunked sections + memguard v3 + SP2; **defines all v2 optional regions** |
| 3, 4, 5 | Additive under v2 `flags` | Populate expectations / decoy / gather / mortar / IAT-token regions (no layout change) |
| 6 | No (runtime-keyed watermark) | `reserved[]` build-id only |

Only **Phase 2** bumps the container. If any later phase must change an *existing* v2 region's layout (rather than populate a reserved one), it bumps to v3 and lands its stub in lockstep — but the reserved-region strategy is designed to avoid that.

---

## 9. Guardrails — honest limits and AV red lines

- **The bare-metal passive observer still wins against everything except DENIAL (SP2).** State this in every design review. Deception (Track 3) and divergence (§6.8) convert their win into days of per-build, live-coverage, watermarked-artifact work — that is the deliverable, not "unbreakable."
- **Never fold a non-zero-FP signal into a hard key.** DR0-3, RDTSC timing, emulation oracles, uarch texture, cycle-woven bands → **deception only** until fleet telemetry proves byte-exactness; only BeingDebugged/NtGlobalFlag/debug-object (deterministic true-negatives) and bit-deterministic cadence counts ever enter a key, behind `--tamper-fold`.
- **AV red lines (do NOT cross):** no self-modifying `.text` (self-decrypting tape is RW *data* SMC), no RWX ever (write RW → flip RX), no `ThreadHideFromDebugger`/`int 2d`/`int 3`, no plaintext `GetProcAddress` name strings. The **private RX arena (§4.3)** and the **mid-instruction IAT relay (§4.6)** are the two constructs most likely to trip Defender → both are heavily AV-smoked and kill-switched; the **source-metamorphism farm (§6.8)** must AV-smoke *every* generated build.
- **`/guard:cf` is both requirement and attack surface.** Every indirect-call target (threaded thunks, arena slots, IAT dispatcher) must be GFIDS-registered — which enumerates them. Collapse enumerable N-thunk sets into single dispatchers (§4.6) so the guard table is not a free map of the protection.
- **Qt/V4 constraint:** process-wide `MicrosoftSignedOnly`/`ProhibitDynamicCode` are unusable (the app JITs and loads unsigned DLLs); SEH/C++ exceptions flow through V4, so **no perjured `.pdata` on a real unwind path** (§7.1 decoy-only + post-build unwind simulation).
- **Every keyed/entangled scheme ships behind the SP5 differential harness and a kill-switch, and fails the *pack*, never the customer.** A mis-fold that would brick a paying user must be caught at build time.

*End of design. This document is written to be implemented directly; each technique's file map, ABI note, and gate is load-bearing.*