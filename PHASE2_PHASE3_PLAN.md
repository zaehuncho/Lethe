# Lethe — Phase 2 & Phase 3 Implementation Plan

**Status:** Plan only. Execute after the product is stable and tested.
**Prerequisite:** Phase 1 (packer) is shipped and hardened (7 red-team findings patched).
**Estimated total effort:** 2-3 weeks with agent parallelism.

---

## Phase 2: Compile-Time Obfuscation

**Goal:** Make the unpacked code harder to understand. Even if an attacker dumps the
running process (defeating Phase 1), they face obfuscated code, not clean MSVC output.

Three sub-phases, ordered by value/risk ratio. Each is independently useful; deploy
incrementally.

---

### 2A: String Encryption (MSVC-compatible, ~2 days)

**The problem:** SecurityManager.cpp contains ~35 analysis-tool names in plaintext
(`cheat engine`, `x64dbg`, `ida`, `ghidra`, ...), registry paths
(`SOFTWARE\Microsoft\Cryptography`), DPAPI entropy constants, license regex patterns,
and policy file names. LeaseGate.cpp has an embedded Ed25519 public key in base64.
All greppable in a memory dump.

**Approach:** C++20 `constexpr` string encryption. No compiler change — works with
MSVC cl.exe (C++20 is already enabled: `CMAKE_CXX_STANDARD 20`).

**Design:**

```
tools/security/obfuscation/
  obfs_string.h          constexpr XOR encryption + runtime decrypt macro
  obfs_config.h          per-module encryption key seeds (constexpr, compile-time only)
```

The macro:

```cpp
// Usage: OBFS("cheat engine") returns a temporary decrypted std::string_view.
// At compile time: string literal XOR'd with a constexpr key derived from
// __LINE__ + __COUNTER__ + a per-TU seed. Stored in .rdata as ciphertext.
// At runtime: decrypts to a stack buffer on first access, wipes after scope.

#define OBFS(s) ::orion::obfs::DecryptedString<sizeof(s)-1>( \
    ::orion::obfs::Encrypted<sizeof(s)-1, __LINE__ ^ __COUNTER__>{s})
```

Implementation:

```cpp
namespace orion::obfs {

template<size_t N, uint32_t Seed>
struct Encrypted {
    char data[N];
    constexpr Encrypted(const char (&str)[N+1]) {
        for (size_t i = 0; i < N; ++i)
            data[i] = str[i] ^ key_byte(Seed, i);
    }
    static constexpr char key_byte(uint32_t s, size_t i) {
        // LCG-derived per-byte key; deterministic but unique per call site
        uint32_t k = s ^ (uint32_t)i;
        k = k * 1103515245u + 12345u;
        return (char)(k >> 16);
    }
};

template<size_t N>
struct DecryptedString {
    char buf[N + 1];
    template<uint32_t Seed>
    explicit DecryptedString(const Encrypted<N, Seed>& enc) {
        for (size_t i = 0; i < N; ++i)
            buf[i] = enc.data[i] ^ Encrypted<N, Seed>::key_byte(Seed, i);
        buf[N] = '\0';
    }
    ~DecryptedString() { SecureZeroMemory(buf, sizeof(buf)); }
    operator const char*() const { return buf; }
    operator QString() const { return QString::fromUtf8(buf, (int)N); }
    operator QByteArray() const { return QByteArray(buf, (int)N); }
    operator QLatin1String() const { return QLatin1String(buf, (int)N); }
};

} // namespace orion::obfs
```

**Files to modify:**

| File | String count | Priority |
|------|-------------|----------|
| SecurityManager.cpp | ~35 tool names, ~10 registry/file paths, 5 constants | Critical |
| LeaseGate.cpp | 1 public key, ~8 state strings | Critical |
| LicenseClient.cpp | API endpoints, header names | High |
| OrionAppController.cpp | Various policy strings | Medium |
| AdminToolController.cpp | API endpoints, machine ID format | Medium |

**Verification:**
1. Build with MSVC — must compile clean with /W4 /WX.
2. `strings` on the compiled DLLs — encrypted strings must NOT appear in plaintext.
3. Runtime: all string comparisons and API calls still work (round-trip test the product).
4. Defender VM smoke test — string encryption does not trigger AV.

**Risk:** Low. Pure C++ constexpr, no compiler change, no build system change. Each
string can be converted independently. Rollback = remove the OBFS() wrapper.

---

### 2B: SecurityCore Obfuscation via clang-cl + OLLVM (~5 days)

**The problem:** Even with encrypted strings, the control flow of SecurityManager
(35 methods, 1234 LOC) and LeaseGate (17 methods, 168 LOC) is clean MSVC output.
An attacker can follow the logic in IDA/Ghidra straightforwardly.

**Approach:** Compile the `SecurityCore` shared library (6 .cpp files, 1804 LOC total)
with clang-cl + OLLVM obfuscation passes. The rest of the product stays on MSVC.

**Why only SecurityCore:** It's a separate CMake shared library target. The boundary
is clean (exported symbols, no header-only templates crossing the boundary). 1804 LOC
is small enough to validate thoroughly. The three highest-value targets are all in it:
SecurityManager, LeaseGate, Ed25519.

**clang-cl compatibility (verified):**
- Ed25519.cpp: No MSVC-only features. Clean under clang-cl.
- LeaseGate.cpp: No Q_OBJECT, no MSVC intrinsics. Clean.
- SecurityManager.cpp: Uses `__cpuid` (clang-cl supports it via `<intrin.h>`) and
  `#pragma comment(lib, ...)` (clang-cl supports this). Uses Q_OBJECT — Qt officially
  supports clang-cl; MOC output is standard C++.

**OLLVM fork selection:**

| Fork | LLVM ver | Status | Notes |
|------|----------|--------|-------|
| [heroims/obfuscator](https://github.com/heroims/obfuscator) | 16+ | Active | Most maintained |
| [AidIcHi/Pluto](https://github.com/AidIcHi/Pluto-Obfuscator) | 12-14 | Stale | Last commit 2023 |
| [61bcdefg/Hikari-LLVM15](https://github.com/61bcdefg/Hikari-LLVM15) | 15 | Semi-active | Fork of Hikari |

Recommendation: Use the most current maintained fork that targets the LLVM version
matching the installed clang-cl. If no fork matches, build LLVM from source with the
obfuscation passes cherry-picked.

**Obfuscation passes to enable:**

| Pass | Flag | Effect | Perf cost |
|------|------|--------|-----------|
| Control-flow flattening | `-mllvm -fla` | Replaces structured control flow with a switch-in-loop dispatcher | ~2-5x slower |
| Bogus control flow | `-mllvm -bcf` | Inserts opaque predicates + dead branches | ~1.5x larger |
| Instruction substitution | `-mllvm -sub` | Replaces simple ops (add/xor) with equivalent complex sequences | Negligible |
| String encryption | `-mllvm -sobf` | Encrypts string literals (overlaps with 2A; keep both for layering) | Negligible |

**Do NOT enable:**
- `-mllvm -split` (basic block splitting): marginal value, breaks some debuggers' DWARF.
- Any pass on non-SecurityCore targets: risk/reward wrong for 33K LOC of UI/network code.

**Build integration:**

```cmake
# In native_orion/CMakeLists.txt, conditional toolchain for SecurityCore only:

if(ORION_OBFUSCATE_SECURITY)
    # Find the obfuscating clang-cl
    set(OBFS_CLANG "C:/llvm-obfs/bin/clang-cl.exe" CACHE FILEPATH "Obfuscating clang-cl")

    set_target_properties(SecurityCore PROPERTIES
        C_COMPILER   "${OBFS_CLANG}"
        CXX_COMPILER "${OBFS_CLANG}"
    )
    # CMake doesn't support per-target compiler override natively.
    # Workaround: build SecurityCore as an ExternalProject with its own toolchain file.
    # See implementation section below.
endif()
```

**Practical integration (ExternalProject approach):**

Because CMake doesn't allow per-target compiler switching, SecurityCore must be built
as an ExternalProject:

1. Extract SecurityCore's CMakeLists.txt into `native_orion/security_core/CMakeLists.txt`
   with its own `project()` declaration.
2. The parent CMakeLists.txt adds it via `ExternalProject_Add()` with a clang-cl
   toolchain file that enables the OLLVM flags.
3. The parent links against the resulting `SecurityCore.dll` import library.
4. Non-obfuscated builds: SecurityCore stays inline in the parent project (no change).
   Gated by `ORION_OBFUSCATE_SECURITY`.

**Toolchain file (`native_orion/security_core/toolchain_obfs.cmake`):**

```cmake
set(CMAKE_C_COMPILER   "C:/llvm-obfs/bin/clang-cl.exe")
set(CMAKE_CXX_COMPILER "C:/llvm-obfs/bin/clang-cl.exe")
set(CMAKE_LINKER        "C:/llvm-obfs/bin/lld-link.exe")

# OLLVM passes
add_compile_options(
    -mllvm -fla          # control-flow flattening
    -mllvm -bcf          # bogus control flow
    -mllvm -sub          # instruction substitution
)
```

**Verification:**
1. SecurityCore.dll loads and all exports resolve.
2. Full product test suite passes (license activation, lease verification, machine ID).
3. Disassemble SecurityManager::machineId() in IDA — confirm flattened control flow.
4. Defender VM smoke test — obfuscated DLL must not trigger.
5. Performance: measure startup + license-check latency. SecurityCore is not hot-path
   (called once at startup, once per lease check), so 2-5x slowdown is acceptable.

**Risk:** Medium. clang-cl + Qt is well-supported but untested for this project.
The ExternalProject boundary adds build complexity. OLLVM forks can be flaky.
Mitigation: gate behind a build flag; non-obfuscated builds are always the fallback.

---

### 2C: Symbol and Export Stripping (~0.5 days)

**The problem:** Compiled DLLs contain named exports, PDB debug symbols, and RTTI
type names that reveal class/method names.

**Changes:**

1. **Strip PDB from release builds:** Already done (`/DEBUG:NONE` or no `/DEBUG` in
   Release config). Verify no `.pdb` ships.

2. **Export only required symbols:** SecurityCore.dll currently exports everything
   decorated with `__declspec(dllexport)` via `OrionExports.h`. Audit and reduce to
   the minimum API surface (the symbols OrionNative.exe actually imports).

3. **Disable RTTI for SecurityCore:** Add `/GR-` to SecurityCore compile flags. This
   removes `type_info` structures that contain plaintext class names. Verify that
   `dynamic_cast` and `typeid` are not used in SecurityCore (they're not — it's
   signal/slot, not polymorphic casts).

4. **Linker flag `/EMITPOGODB:NO`:** prevents PGO database embedding.

**Risk:** Low. Each change is a build flag.

---

## Phase 3: Code Virtualization

**Goal:** Critical functions never exist as native x86-64 in memory. Even after
unpacking and deobfuscation, an attacker sees only custom bytecode interpreted by the
Daedalus VM. This is the strongest client-side protection short of hardware enclaves.

---

### 3A: Daedalus VM v2 — Extend the Interpreter (~3 days)

**Current state:** 40 opcodes, pure stack machine, 64-slot stack, 256-byte locals,
11 native call-outs, no CALL/RET, no subroutines. 487 LOC. Two hand-encoded programs
(DERIVE_KEY 112B, SHARD_XOR 49B).

**What it lacks for general-purpose virtualization:**

| Category | Missing | Needed for |
|----------|---------|------------|
| Arithmetic | MUL, DIV, MOD, NEG, NOT, ROTL, ROTR | General computation |
| Comparison | GT, GE, LE, NE, signed variants | Conditionals beyond eq/lt |
| Control flow | CALL, RET, function table | Subroutine calls within bytecode |
| Data | PUSH_IMM16, PUSH_LOCAL (by index), LOAD/STORE 16-bit | Wider data access |
| Native | N_CALL_PTR (call arbitrary function pointer) | Qt/Win32 API access from VM |
| Stack | ROT3, OVER, PICK(n) | Complex expressions without excessive DUP/SWAP |
| Conversion | SIGN_EXTEND_8/16/32, TRUNC_8/16/32 | Signed/truncated arithmetic |

**Proposed opcode map (v2):**

```
0x00-0x07  (unchanged) HALT NOP PUSH_IMM8/32/64 POP DUP SWAP
0x08-0x0E  (unchanged) ADD SUB XOR AND OR SHL SHR
0x0F       MUL
0x10-0x15  (unchanged) LOAD8/32/64 STORE8/32/64
0x16-0x17  (unchanged) CMP_EQ CMP_LT
0x18-0x1A  (unchanged) JMP JZ JNZ
0x1B       CALL (u32 target; pushes return address)
0x1C-0x1E  (unchanged) PUSH_ARG LOCAL_ADDR DATA_ADDR
0x1F       RET (pops return address, jumps to it)
0x20-0x2A  (unchanged) native ops N_SHA256 ... N_XOR_CONST
0x2B       N_CALL_PTR (pop arg_count, pop func_ptr, pop args[], call, push result)
0x2C       DIV
0x2D       MOD
0x2E       NEG (unary negate top of stack)
0x2F       NOT (bitwise NOT top of stack)
0x30       CMP_GT
0x31       CMP_GE
0x32       CMP_NE
0x33       SIGN_EXTEND (pop width, sign-extend top of stack)
0x34       LOAD16 / STORE16
0x35       ROT3 (rotate top 3 stack elements)
0x36       PICK (u8 n: copy stack[sp-n] to top)
0x37       PUSH_IMM16
```

**N_CALL_PTR design (the key extension):**

This opcode lets virtualized code call any native function (Qt, Win32, CRT) without
adding a dedicated native op for each one. The caller pushes:
1. Arguments in order (left to right, matching x64 calling convention)
2. The argument count (u8)
3. The function pointer (u64)

The VM pops all of them, builds a stack frame matching the x64 ABI (first 4 args in
RCX/RDX/R8/R9, rest on stack), calls via an indirect `call` through a small ASM
trampoline, and pushes the u64 return value.

**Implementation:** The trampoline is a ~30-instruction x64 ASM routine
(`daedalus_trampoline.asm`) that:
- Receives (func_ptr, arg_count, args[]) from the C dispatcher
- Sets up the x64 shadow space + register args
- Issues `call [func_ptr]`
- Returns RAX

This is the bridge that lets VM bytecode call LoadLibraryA, QString::fromUtf8,
BCryptHashData, etc. without each needing a dedicated native opcode.

**Call stack:** Add a 32-deep return-address stack (separate from the operand stack)
for CALL/RET. Functions within the bytecode program can call each other. A stack
overflow returns -1 (fatal VM error, same as operand stack overflow).

**Files to modify:**
- `stub/src/daedalus_vm.h` — add new opcode constants, bump DVM version
- `stub/src/daedalus_vm.c` — add dispatch cases (~150 LOC)
- `stub/src/daedalus_trampoline.asm` — N_CALL_PTR x64 ABI bridge (~50 LOC)
- `stub/CMakeLists.txt` — add daedalus_trampoline.asm

**Verification:**
- Roundtrip: existing DERIVE_KEY and SHARD_XOR programs still work (backward compat).
- Unit test: write a test program exercising every new opcode, run it from a test
  harness (call `daedalus_vm_exec` from a C test, assert results).

---

### 3B: Daedalus Assembler — Human-Readable Bytecode (~2 days)

**The problem:** Current programs are hand-encoded hex blobs in `daedalus_programs.h`.
This doesn't scale beyond tiny programs. We need a text-based assembly language and
an assembler.

**Design:**

```
daedalus/
  daedalus_asm.py          assembler: .vasm text → binary blob (Python, build-time tool)
  daedalus_disasm.py       disassembler: binary → .vasm text (debugging aid)
  programs/              .vasm source files
    derive_key.vasm      existing program, ported from hand-encoded hex
    shard_xor.vasm       existing program, ported from hand-encoded hex
    (new programs added in 3C)
```

**Assembly syntax:**

```asm
; Daedalus Assembly — derive_key.vasm
; Lines starting with ; are comments. Labels end with :.
; Operands are decimal or 0x hex.

.data
    ; Data section: raw bytes, referenced by DATA_ADDR
    codehash_info: db 0xCF,0x99,0xA4,0x52,...   ; XOR'd "Lethe-v1"

.code
    ; Push image_base argument
    push_arg 1              ; image_base
    push_arg 0              ; pi
    load64                  ; pi->stub_text_rva (offset within PackInfo)
    ; ... etc

    push_imm8 32
    local_addr 0            ; &locals[0] = scratch for SHA-256 output
    n_sha256                ; SHA256(text_ptr, text_size, &locals[0])

    jnz error               ; if nonzero, fail

    ; HKDF
    push_imm8 32            ; out_len
    local_addr 32           ; &locals[32] = mask output
    ; ... etc

error:
    push_imm8 1
    halt

done:
    push_imm8 0
    halt
```

**Assembler features:**
- Labels with forward/backward references (resolved in two-pass assembly)
- `.data` section for inline byte arrays
- Named constants (`.const STACK_SIZE 64`)
- `#include` for shared definitions
- Output: the same `[u16 data_size][data][code]` binary format daedalus_vm_exec expects
- Optional: output as C header (`static const uint8_t PROG[] = { ... };`) for direct
  embedding in daedalus_programs.h

**Verification:**
- Assemble existing DERIVE_KEY and SHARD_XOR from .vasm source → compare output
  byte-for-byte against the current hand-encoded blobs.
- Disassemble the blobs → reassemble → byte-identical round-trip.

---

### 3C: Critical Function Virtualization (~5 days)

**The problem:** Which functions to virtualize, and how.

**Target selection criteria:**
1. High value to an attacker (license validation, HWID, signature verification)
2. Small enough to port (<200 LOC native)
3. Not performance-critical (called infrequently)
4. Deterministic (same inputs → same output; no UI, no threading)

**Selected targets (7 functions, ~400 LOC total):**

| Function | File | LOC | Why |
|----------|------|-----|-----|
| `SecurityManager::machineId()` | SecurityManager.cpp:280 | ~60 | HWID computation — clone/spoof target |
| `SecurityManager::validateLicenseKeyFormat()` | SecurityManager.cpp:375 | ~15 | License format regex — bypassed by patching |
| `SecurityManager::computeEntitlementBinding()` | SecurityManager.cpp:~825 | ~30 | Entitlement hash — forgery target |
| `SecurityManager::sealEntitlementCache()` | SecurityManager.cpp:~895 | ~40 | DPAPI seal — cache tampering target |
| `SecurityManager::unsealEntitlementCache()` | SecurityManager.cpp:~925 | ~40 | DPAPI unseal — cache tampering target |
| `LeaseGate::verifyLeaseSignature()` | LeaseGate.cpp:137 | ~30 | Ed25519 verify — lease forgery target |
| `LeaseGate::leaseVerifyPublicKey()` | LeaseGate.cpp:~85 | ~5 | Public key accessor — key swap target |

**Approach: Source-level port to Daedalus assembly.**

For each target function:
1. Read the C++ source.
2. Identify all external calls it makes (Qt APIs, Win32 APIs, Ed25519 functions).
3. Write equivalent logic in Daedalus assembly, using `n_call_ptr` for external calls.
4. The function's native body is replaced with a VM entry stub:

```cpp
// Original:
QString SecurityManager::machineId() const {
    // ... 60 lines of HWID computation ...
}

// After virtualization:
QString SecurityManager::machineId() const {
    // VM entry stub — the bytecode program does the real work
    uint64_t args[2];
    args[0] = (uint64_t)(uintptr_t)this;
    args[1] = (uint64_t)(uintptr_t)&result;
    daedalus_vm_exec(DVM_PROG_MACHINE_ID, DVM_PROG_MACHINE_ID_SIZE, args, 2);
    return result;
}
```

5. The bytecode is embedded as a static array in a header (generated by the assembler).

**External call resolution:**

Virtualized functions need to call Qt and Win32 APIs. These are resolved at startup
and passed to the bytecode as arguments or stored in a function-pointer table:

```cpp
struct VmExternals {
    void *GetComputerNameA;
    void *GetSystemFirmwareTable;
    void *RegOpenKeyExA;
    void *RegQueryValueExA;
    void *BCryptHashData;
    void *QString_fromUtf8;
    // ... etc
};
```

The VM entry stub passes a pointer to this table as an arg. The bytecode loads
function pointers from it and uses `n_call_ptr` to invoke them.

**Why not automate with an x86 lifter?**

An automated x86-64 → Daedalus lifter would be ideal but is a multi-month project:
- Reliable x86-64 disassembly (Zydis) is solved, but lifting to IR is not — x86
  has ~1500 instruction forms, flags register semantics, SIMD, etc.
- Open-source lifters exist (Remill, RetDec) but they're 100K+ LOC projects.
- For 7 functions totaling ~400 LOC, manual porting is faster and more reliable.

**Future (3E below):** if the target list grows beyond ~15 functions, invest in an
automated lifter. For now, manual port is the right call.

**Verification:**
- For each ported function: call the VM version and the original C++ version with
  identical inputs, assert identical outputs. Automate this as a test.
- Full product test: license activation, lease verification, HWID display — all
  must produce the same results as before.
- Dump test: attach a debugger, dump the process, confirm the 7 functions' original
  native code does not appear anywhere in the dump (only the VM entry stubs and the
  encrypted bytecode blobs).

---

### 3D: Packer Integration — Bytecode Protection (~1 day)

**The problem:** The bytecode programs are embedded as static arrays in the product
binary. An attacker could extract them, disassemble them (reverse the Daedalus ISA),
and read the logic. We need to protect the bytecode itself.

**Approach:** The bytecode is encrypted at build time and decrypted at runtime by the
packer stub, just like section data.

**Design:**
1. The Daedalus programs are stored in a dedicated `.vdata` section of the product binary.
2. At pack time, Lethe encrypts `.vdata` along with the other sections (AES-256-GCM
   with per-section subkey derivation — already implemented).
3. At runtime, the stub decrypts `.vdata` before the VM runs any program.
4. After all programs execute, the decrypted bytecode is wiped (same as other sections).

Alternatively (simpler, no new section):
1. The bytecode arrays live in `.rdata` (read-only data), which is already encrypted
   and decrypted by the packer.
2. No additional work needed — the packer already handles this.

**Recommendation:** Use the simpler approach. The bytecode is just const data in
`.rdata`; the packer encrypts it automatically. The only extra step: ensure the VM
entry stubs reference the bytecode AFTER the packer has decrypted the section (they
do — the stubs are called from the product's code, which runs after unpack).

**Bytecode obfuscation (defense-in-depth):**

Even encrypted, the bytecode runs through a public ISA (the Daedalus opcode set). An
attacker who reverse-engineers the VM interpreter can write a disassembler. Counter:

1. **Per-build opcode shuffling:** At build time, randomly permute the opcode
   assignments (e.g., ADD might be 0x1F in one build, 0x03 in another). The assembler
   and the VM interpreter are compiled with the same permutation table. An attacker's
   disassembler from build N is useless on build N+1.

2. **Handler duplication:** Each opcode has 2-4 handler implementations that produce
   the same result through different instruction sequences. The assembler randomly
   selects among them. Static pattern matching on the interpreter fails.

3. **Dummy opcodes:** 30% of the opcode space is filled with handlers that do plausible
   but meaningless work (push/pop/xor sequences that cancel out). The assembler inserts
   them as noise between real instructions.

**Implementation:** The permutation table is generated by the build script and
`#include`d by both `daedalus_vm.c` (C side) and `daedalus_asm.py` (Python side).

---

### 3E: Future — Automated x86-64 Lifter (separate project, weeks-months)

**When to build this:** When the target list exceeds ~15 functions, or when a function
is too complex to port manually (e.g., OrionAppController methods at 10K LOC).

**Architecture:**

```
lifter/
  lifter.py              main driver: ELF/PE → Daedalus bytecode
  disasm.py              x86-64 disassembly via Zydis (Python bindings or subprocess)
  ir.py                  intermediate representation (SSA-based)
  lift_x86.py            x86-64 → IR translation (~200 instruction forms, not all 1500)
  lower_daedalus.py        IR → Daedalus bytecode
  optimize.py            dead-code elimination, constant folding, register allocation
```

**Scope:** Only lift the ~200 x86-64 instruction forms that MSVC actually emits for
C++ code (no SIMD, no x87 FP, no legacy 16-bit). This covers: MOV, LEA, ADD, SUB,
IMUL, XOR, AND, OR, SHL, SHR, CMP, TEST, Jcc, CALL, RET, PUSH, POP, MOVZX, MOVSX,
CDQ, CMOV, SET, and their memory-operand variants.

**Key challenges:**
- **Flags register:** x86 sets FLAGS on most ALU ops; Daedalus has no flags. The lifter
  must synthesize flag values as explicit comparisons.
- **Memory addressing modes:** x86 has base+index*scale+disp; Daedalus has flat LOAD/STORE.
  The lifter must decompose complex addressing into arithmetic + load.
- **Calling convention:** The lifter must recognize and handle x64 ABI (shadow space,
  register args, stack args) when the lifted code calls native functions.
- **Function boundary detection:** For stripped binaries, function boundaries are
  heuristic. For our own builds (with symbols), this is trivial.

**Dependency:** Zydis (BSD-licensed, ~15K LOC C library, excellent x86 decoder).
Python bindings via `pyzydis` or subprocess `ZydisInfo`.

**Estimated effort:** 3-6 weeks for a working lifter covering the common instruction
subset. Ongoing maintenance as MSVC codegen evolves.

---

## Sequencing

```
Week 1:
  Day 1-2:  2A (string encryption)  — ship independently, immediate value
  Day 3:    2C (symbol stripping)   — build flags only
  Day 3-5:  3A (Daedalus VM v2)       — extend interpreter (parallel with 2B setup)

Week 2:
  Day 1-2:  3B (Daedalus assembler)   — port existing programs, validate
  Day 1-5:  2B (SecurityCore OLLVM) — build LLVM fork, integrate ExternalProject
                                      (parallel with 3B)
  Day 3-5:  3C (port first 3 functions: machineId, validateLicenseKey, leaseVerify)

Week 3:
  Day 1-2:  3C (port remaining 4 functions)
  Day 3:    3D (bytecode protection — opcode shuffle, dummy ops)
  Day 4-5:  Integration test, Defender VM smoke, full product regression
```

**Parallelism:** 2A and 3A are independent (different codebases). 2B and 3B are
independent. 3C depends on 3A + 3B. Everything converges in week 3 for integration.

---

## Risk Summary

| Risk | Impact | Mitigation |
|------|--------|------------|
| OLLVM fork doesn't compile with current LLVM | 2B blocked | Build from source; cherry-pick passes onto stock LLVM |
| clang-cl breaks Qt MOC for SecurityCore | 2B broken | Qt officially supports clang-cl; if it breaks, file upstream |
| Obfuscated SecurityCore triggers Defender | Ship blocker | A/B test: obfuscated vs. clean on Defender VM before commit |
| Manual Daedalus port introduces logic bugs | Silent failure | Dual-run test: VM output == native output for all inputs |
| N_CALL_PTR ABI mismatch | VM crash | Trampoline is small (~50 LOC asm), exhaustively testable |
| Opcode shuffle breaks backward compat | Old packed binaries fail | Shuffle is per-build; the packer embeds the VM interpreter, so the shuffle + bytecode are always matched |

---

## Files Created by This Plan

```
Phase 2A:
  tools/security/obfuscation/obfs_string.h
  tools/security/obfuscation/obfs_config.h
  (edits to SecurityManager.cpp, LeaseGate.cpp, LicenseClient.cpp, etc.)

Phase 2B:
  native_orion/security_core/CMakeLists.txt      (extracted sub-project)
  native_orion/security_core/toolchain_obfs.cmake
  (edits to native_orion/CMakeLists.txt)

Phase 3A:
  (edits to stub/src/daedalus_vm.h, daedalus_vm.c)
  stub/src/daedalus_trampoline.asm

Phase 3B:
  daedalus/daedalus_asm.py
  daedalus/daedalus_disasm.py
  daedalus/programs/derive_key.vasm
  daedalus/programs/shard_xor.vasm

Phase 3C:
  daedalus/programs/machine_id.vasm
  daedalus/programs/validate_license.vasm
  daedalus/programs/verify_lease.vasm
  daedalus/programs/entitlement_binding.vasm
  daedalus/programs/seal_cache.vasm
  daedalus/programs/unseal_cache.vasm
  daedalus/programs/lease_pubkey.vasm
  (edits to SecurityManager.cpp, LeaseGate.cpp — replace function bodies with VM stubs)

Phase 3D:
  daedalus/shuffle_opcodes.py
  (edits to daedalus_vm.c, daedalus_asm.py — conditional opcode table)
```
