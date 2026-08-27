# Lethe Next-Gen — Implementation Status

Tracks what is **built and verified** vs. **built, pending rig verification** vs.
**designed only**, against `NEXTGEN_PROTECTION_PLAN.md` (Fable base) and
`NEXTGEN_PROTECTION_PLAN_fable.md`. Honest by construction: "verified" means a
test in this repo proves it; "pending rig" means the code exists but needs MSVC
(`cl.exe` is not on the dev-box PATH) to compile/run.

---

## 🚀 SHIPPED & LIVE IN A REAL PACKED BINARY (2026-08-21)

The full chain is integrated, compiled, and proven on a real EXE:

- **Rolling bytecode integrated into `daedalus_vm.c`** — the dispatch loop
  reconstructs one instruction at a time from the history-keyed ciphertext
  (`ip` window + `dvm_rolling_fetch`); `daedalus_vm_exec` parses the self-describing
  `VR` container (seed + leaders embedded). Built with `-DDVM_ROLLING=ON` under
  `/W4 /WX` — clean.
- **`generate_programs.py` emits `VR` containers** — MBA rewrite → shuffle →
  rolling-encode, per-build derived seed. The two on-critical-path programs
  (`DVM_PROG_DERIVE_KEY`, `DVM_PROG_SHARD_XOR`) now ship as `MBA+rolling` and
  begin with `0x56 0x52` ('VR').
- **End-to-end proof:** `sample_exe.exe` packed with the rolling stub runs
  byte-identically (exit 42); the round-trip harness path holds; and a purpose-
  built **crackme** (`challenge.exe`) packs and runs correctly on all paths
  (GRANTED/DENIED/usage) while its strings vanish from the packed image
  (entropy 6.18→7.40/8). The Daedalus VM decodes rolling ciphertext at runtime to
  derive the real AES-256-GCM section key — a bug would brick it; it doesn't.

Deliverable: `tests/build/challenge.packed.exe` (rolling VM + MBA + per-build
shuffle + anti-debug + anti-dump + memory-guard). Build toolchain: MSVC 2022
(`cl.exe` found via `vcvars64.bat`), CMake, LIEF 1.0.

---

## ✅ Phase 0 foundations + Technique 1.2 (History-Keyed Rolling Bytecode) — pack-time half VERIFIED

The single highest-novelty VM technique from both design runs (rated N10). At
rest the Daedalus bytecode is ciphertext with no decodable image; each instruction's
plaintext exists only for the instant before it executes, reconstructed from a
keystream that folds the executing basic block's accumulator.

**v1 scheme:** per-basic-block resync — the accumulator is reseeded from
`(seed, block-leader-offset)` at every basic-block leader and chained over the
plaintext bytes inside the block. Provably **path-independent** (a block's
encryption depends only on the seed, its leader offset, and its own bytes), so
there is **zero data-dependent-branch miscompile risk** — the failure mode that
kills naive self-decrypting VMs.

### Files
| File | Role | Status |
|------|------|--------|
| `daedalus/daedalus_ref.py` | Reference interpreter (pure ISA subset) + basic-block decomposition | ✅ verified |
| `daedalus/daedalus_rolling.py` | Pack-time encoder + `RollingDecoder` + container format + SHA-256 primitives | ✅ verified |
| `stub/src/daedalus_rolling.{c,h}` | Runtime decoder (no-CRT, `crypto_sha256`), bit-exact mirror + self-test | ⏳ pending rig compile |
| `tests/test_rolling_bytecode.py` | Differential + self-poisoning harness | ✅ 8/8 pass |
| `stub/CMakeLists.txt` | `option(DVM_ROLLING … OFF)` gate | ✅ additive, default build unchanged |

### What the tests prove (`python -m pytest tests/test_rolling_bytecode.py -q` → 8 passed)
1. **Codec round-trip** — `decode(encrypt(code)) == code` for **all 8 real
   `.vasm` crypto programs** across **16 per-build seeds**. The runtime, walking
   the true path, always reconstructs exact plaintext.
2. **Interpreter equivalence** — for synthetic programs over the pure ISA subset
   (arithmetic, forward branches, loops, `call/ret`, locals), the reference VM
   yields the **identical halt value and identical dispatch trace** running
   plaintext vs. rolling ciphertext. Virtualization semantics are unchanged.
3. **Self-poisoning** — (a) decoding from a mid-block offset (wrong accumulator)
   faults or yields wrong bytes; (b) flipping one ciphertext byte avalanches
   through the rest of its block; (c) the wrong seed decodes garbage.
4. **Primitive vectors pinned** — `resync/keystream/fold` have fixed test vectors;
   `daedalus_rolling.c::dvm_rolling_selftest()` re-checks the same vectors in C.

### Primitives (bit-exact across Python `hashlib` and stub `crypto_sha256`)
```
resync(seed, leader)     = u64le( SHA256(seed16 ‖ 'R' ‖ u32le(leader))[0:8] )
keystream(seed, pc, acc) = SHA256(seed16 ‖ 'K' ‖ u32le(pc) ‖ u64le(acc))
fold(acc, plain, pc):
    for x in plain: acc = rotl64(acc ^ x, 7) + 0x9E3779B97F4A7C15   (mod 2^64)
    acc ^= u32(pc)
```
Pinned vectors: `resync(0..15, 0) = 0x0E17E9881DD39855`,
`fold(0,{01 02},0) = 0xB9F456792488C7E4`, `keystream[0:4]@pc0 = 26 19 83 B3`.

### Rolling container
`[2 'VR'][u16 data_size][data][u16 n_leaders][u32 leader…][code_ct]`
— the leaders are the one plaintext index the stub needs (it cannot decode
without them; it cannot decode a block without executing into it).

### Remaining to fully ship Technique 1.2 (all default-OFF, no ship-build impact)
1. **`daedalus_vm.c` dispatch integration** (behind `#ifdef DVM_ROLLING`): at the
   fetch site (`daedalus_vm.c:93`), call `dvm_rolling_fetch()` into a 9-byte
   scratch, point operand reads at the scratch, dispatch, advance. Loader learns
   the `VR` container (leaders + seed). *Not yet wired — keeps the tree pristine
   until compiled on the rig.*
2. **Rig build + differential parity**: `cmake -DDVM_ROLLING=ON`, run
   `dvm_rolling_selftest()` at stub init (must return 0), then round-trip a
   packed sample and confirm identical behavior to the plaintext-VM build.
3. **AV-smoke**: the rolling `code[]` lives in a private **RW `VirtualAlloc`**
   page (data self-modification — *not* `.text`, no RWX), so it stays AV-clean;
   confirm on a clean Defender VM.

### Hardened v2 (designed, not built)
Cross-block accumulator chaining; fold an anti-instrumentation signal
(DR0-3 / code-page self-CRC / quantized RDTSC) into the keystream so observing
the decode corrupts the *next* instruction (self-poisoning against a live
tracer, per the plan's §3.1 hardening); forward-dependency variant for
provably-underdetermined partial static decode.

---

## ✅ Technique 4.2 / 6.2 (Solver-Hostile MBA Arithmetic) — VERIFIED

A semantics-preserving `.vasm`→`.vasm` pass that rewrites bare `xor`/`add` into
mixed boolean-arithmetic expansions (`a^b = (a|b)-(a&b)`,
`a+b = (a^b)+((a&b)<<1)`) so an automated simplifier must prove the identity
before folding anything. Source-level, so the assembler recomputes all branch
offsets — control flow is untouched by construction. Composes in front of the
opcode shuffle and the rolling encoder.

| File | Role | Status |
|------|------|--------|
| `daedalus/daedalus_mba.py` | The rewriter (`rewrite_source`, `count_rewritable`) | ✅ verified |
| `tests/test_mba.py` | Correctness proof via the `daedalus_ref` oracle | ✅ 5/5 pass |

**What the tests prove:** xor/add expansions match native over **200+ random
64-bit input pairs each**; a composed program (xor+add+branches+locals) matches
for all inputs and both branch directions; the real crypto programs still
assemble+disassemble with the data section untouched; and **MBA∘rolling
round-trips** (the two passes compose). Correctness is proven, not argued — an
identity bug fails the oracle, not production.

---

## ⏭️ Next techniques (queued, same test-first discipline)

Ordered by impact-to-risk, each landing with its own differential/round-trip test:

1. **MBA per-site polymorphism** — multiple equivalent expansions per op, chosen
   per-build from the seed, so the same `xor` looks different at every site and
   every build (extends the verified pass; oracle-checked).
2. **Tableless / threaded dispatch** — replace the readable `switch` in
   `daedalus_vm.c` with a computed successor; kills VM-loop fingerprinting.
3. **Execution/bytecode-bound key** (Plan §1.10, F9) — extend `crypto_derive_key`
   with a trace-fold + blob-hash HKDF term; fail-closed anti-tamper.
4. **Per-page AEAD** (Plan §2.1) — THE anti-dump fix; **ABI-breaking**
   (`LETHE_FORMAT_VERSION` bump), lands `container.py`+`pack_info.h`+`memguard.c`
   together.

---

## ⚠️ Pre-existing, unrelated
`tests/test_stub_safety_contracts.py::test_cmake_sources_exist_and_bcrypt_is_a_static_system_import`
fails on a clean tree (HEAD `CMakeLists.txt:28` links `PRIVATE kernel32` only;
the test expects a static `bcrypt` link). This predates and is unrelated to the
rolling-bytecode work — the stub resolves `BCryptGenRandom` dynamically by
design. Not fixed here (fixing it by adding a static `bcrypt` link may contradict
the dynamic-resolution design; flagged for a separate decision).
