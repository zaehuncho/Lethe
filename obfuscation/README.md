# Lethe obfuscation pass — custom compile-time code tangling

This is the **"OLLVM but everything custom"** layer of Lethe. The packer
(`../lethe.py`) hides the code until it is unpacked in RAM; this LLVM pass
plugin makes sure that **even after an analyst unpacks the binary, the machine
code has no readable structure**. It runs at *compile time*, in LLVM IR, so
there is no runtime unpack cost and nothing for a dumper to strip out.

Everything is driven by a **per-build seed**, so two builds of the same source
produce different dispatchers, different opaque predicates, different bogus
blocks, and a different subset of MBA rewrites. Off-the-shelf deobfuscators
target the *known* OLLVM patterns; these transforms are ours and per-build
randomized, so there is no matching tool and no build-to-build transfer.

## What it does (all semantics-preserving)

| Transform | Flag | What it emits |
|---|---|---|
| **Control-flow flattening** | `-lethe-flatten` | Collapses each function into a single `switch` dispatcher over a state variable, with **per-build-random** case constants. |
| **Opaque predicates** | `-lethe-opaque` | Rewrites `br Dest` into `br OPAQUE_TRUE, Dest, Bogus`. The predicate is provably true to us, opaque to a solver. |
| **MBA substitution** | `-lethe-mba` | Rewrites `add/sub/and/or/xor` into mixed boolean-arithmetic identities (the same ones `../daedalus/daedalus_mba.py` proves with an oracle). |
| **Bogus control flow** | `-lethe-bcf` | Splits blocks and adds opaque-guarded dead paths (extra fuel for the flattener). |

The MBA identities used (exact in Z/2ⁿ):

```
a + b = (a ^ b) + 2*(a & b)
a - b = (a ^ b) - 2*(~a & b)
a ^ b = (a | b) - (a & b)
a & b = (a | b) - (a ^ b)
a | b = (a & b) + (a ^ b)
```

**Note on opaque predicates:** the classic textbook predicate `7*y*y - 1 != x*x`
is only valid over the integers **Z** — under two's-complement wraparound mod 2ⁿ
it can become *false* and corrupt control flow. This pass deliberately does
**not** use it. It uses low-bit parity invariants that are exact for *every*
value in Z/2ⁿ (`x*(x+1)` is always even, `x|(x+1)` is always odd, …). See the
`emitOpaqueTrue()` comment in the source.

## Requirements

- **LLVM + Clang 17 or 18**, installed, with the CMake package files
  (`lib/cmake/llvm/LLVMConfig.cmake`). LLVM 15/16 mostly works too; LLVM ≥ 19/20
  needs the small API tweak flagged in the source (`registerOptimizerLastEPCallback`
  gained a 3rd parameter).
- **CMake ≥ 3.20**.
- Build the plugin with the **same toolchain/version** you will feed it to. A
  pass plugin resolves LLVM symbols against the loading `clang`/`opt` process, so
  a version or RTTI/Release-vs-Debug mismatch will fail to load.

## Build

```powershell
# from obfuscation\
cmake -S . -B build -G "Ninja" `
      -DCMAKE_BUILD_TYPE=Release `
      -DLLVM_DIR="C:/path/to/llvm/lib/cmake/llvm"
cmake --build build --config Release
# -> build\LetheObfuscation.dll   (Windows)
# -> build/LetheObfuscation.so    (Linux/macOS)
```

If you use the Visual Studio generator instead of Ninja:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 `
      -DLLVM_DIR="C:/path/to/llvm/lib/cmake/llvm"
cmake --build build --config Release
```

## Use it with clang / clang-cl

**Automatic (recommended)** — the plugin registers an *OptimizerLast* callback,
so simply loading it obfuscates every eligible function at `-O1`+:

```powershell
# clang-cl, MSVC-style flags
clang-cl /O2 -fpass-plugin=build\LetheObfuscation.dll /c mycode.c

# clang driver
clang -O2 -fpass-plugin=build/LetheObfuscation.so -c mycode.c
```

**Explicit by name** (older clangs without `-fpass-plugin`, or for `opt`):

```powershell
# via the clang cc1 loader
clang-cl /O2 -Xclang -load -Xclang build\LetheObfuscation.dll /c mycode.c

# run the pass by name on IR with opt
opt -load-pass-plugin=build/LetheObfuscation.dll `
    -passes="function(lethe-obf)" in.ll -o out.ll
```

Pass the tuning options through the compiler with `-mllvm`:

```powershell
clang-cl /O2 -fpass-plugin=build\LetheObfuscation.dll `
   -mllvm -lethe-obf-level=2 -mllvm -lethe-seed=0xDEADBEEF /c mycode.c
```

### Integrating into an MSVC / CMake project

Point the C/C++ compiler at `clang-cl` and add the plugin flags — the rest of
your MSVC build (linker, `.rsrc`, manifest, signing) is unchanged:

```powershell
cmake -S yourproject -B out `
   -T ClangCL `                                  # use the clang-cl toolset
   -DCMAKE_C_FLAGS="-fpass-plugin=C:/.../LetheObfuscation.dll" `
   -DCMAKE_CXX_FLAGS="-fpass-plugin=C:/.../LetheObfuscation.dll"
```

Then pack the resulting EXE/DLL with `../lethe.py` as usual. Obfuscation runs
first (compile time); packing runs last (post-link). They compose.

## The `LETHE_OBF_SEED` per-build seed

Everything random is derived from one seed. Set it **per release build** so each
shipped binary differs:

```powershell
$env:LETHE_OBF_SEED = git rev-parse HEAD    # any string: hashed with FNV-1a
$env:LETHE_OBF_LEVEL = "2"                   # 0=off, 1=default, 2, 3=max
clang-cl /O2 -fpass-plugin=build\LetheObfuscation.dll /c mycode.c
```

- Accepts a decimal, a `0x`-hex value, or **any string** (a git SHA, a build id)
  which is folded to 64 bits with FNV-1a — the same hash family Lethe's stub
  uses for import resolution.
- The seed is spread per function (seed XOR FNV-1a(function name)), so each
  function is tangled differently while the whole build stays **reproducible**
  from the seed alone — you can rebuild the exact same obfuscated binary for a
  crash repro.
- Precedence per knob: pass option (`-lethe-seed`, `-lethe-obf-level`) →
  environment variable → built-in default. With **no** seed set, the pass warns
  and uses a fixed fallback (reproducible, but every release would be identical —
  don't ship that way).

Disable per build with `LETHE_OBF_LEVEL=0`, or disable individual transforms
with `-mllvm -lethe-flatten=false` (likewise `-lethe-opaque`, `-lethe-mba`,
`-lethe-bcf`).

---

## Honest notes — read before you ship

1. **This was NOT compiled in the authoring environment.** There is no LLVM
   toolchain where it was written, so it has **not been built or run**. Treat it
   as a careful first draft: it needs a code review and a real LLVM 17/18 box to
   compile, and the transforms must be validated against an oracle (compile a
   test corpus with and without the plugin and assert identical output/exit
   codes — mirror what `../daedalus/tests/test_mba.py` does for the VM) before
   any of it goes near a shipping binary. The `// API NOTE` comments in the
   source mark the exact API calls to verify for your LLVM version.

2. **Heavy control-flow flattening can raise AV heuristic scores.** Flattened,
   dispatcher-heavy code looks like malware to some heuristic engines — and
   "persistent AV false positives" is a release blocker in Lethe's IP plan.
   **Measure it:** build with and without the plugin, and at each
   `LETHE_OBF_LEVEL`, then AV-smoke on a clean Windows Defender VM (the same gate
   the packer uses). Back the level off if Defender flags it.

3. **Always verify the obfuscated binary still RUNS — functionality first.**
   Obfuscation that changes behavior is worthless. After every build, run the
   binary's real test suite / smoke path and diff against the un-obfuscated
   build. Start at `LETHE_OBF_LEVEL=1`, confirm green, then raise it.

4. **Flattening interacts badly with some optimizations — run it late.** The
   plugin registers on the *OptimizerLast* extension point on purpose: it lets
   the optimizer clean up first and keeps later passes from simplifying the
   opaque predicates back out. If you invoke the pass manually, put it **at the
   end** of your pipeline. Flattening also demotes cross-block SSA values to the
   stack (required for correctness), which costs performance — don't apply it to
   hot paths without measuring.

### Additional caveats

- **Correctness-driven bail-outs:** flattening skips functions containing
  `switch`, `invoke`/EH pads, indirect/`callbr` branches, or blocks whose address
  is taken. This is intentional (correctness over coverage); those functions are
  left un-flattened but still get MBA/opaque/BCF where safe.
- **CFG + packing:** per Lethe's README, packing already drops Windows CFG
  enforcement on the packed payload; obfuscation doesn't change that trade-off,
  but don't expect CFG to protect obfuscated code.
- **Debuggability:** obfuscated + packed builds are effectively undebuggable and
  produce useless minidumps. Keep an un-obfuscated build of each release for your
  own crash triage — the same "pack last, after sign-off" discipline the packer
  follows.
