# Lethe release checklist

Use this checklist for a candidate intended to leave the development machine.
Passing it establishes a recorded release gate, not universal security or
compatibility.

The currently releasable envelope remains an unmanaged x64 EXE with anti-debug,
process hardening, and memory guard disabled. Guarded DLL packing now has native
dynamic/static consumer, TLS, unwind, export-suppression, attach-failure, and
unload/reload proof, but it remains behind the experimental CLI gate until every
required DLL matrix row is green. Server-shard mode remains experimental.

## 1. Establish provenance

- Start from the intended commit and record `git rev-parse HEAD`.
- Review `git status --short`; explain every tracked and untracked change.
- Use Python 3.12, VS2022 x64/MSVC, and the committed `uv.lock`.
- Do not release the inherited prebuilt while its manifest says
  `legacy-unverified`; replace it through the clean promotion flow below.
- Supply the full intended commit to the staging tool. Abbreviated commits,
  tracked changes, untracked files, a mismatched checkout, or an unlocked
  interpreter fail before any build starts.
- Keep builder tokens and PEM material in the shell's secret source. Do not put
  real values in `.env.example`, command history, manifests, or logs.

## 2. Run automated tests

```powershell
uv sync --frozen --group dev
uv run pytest -q -p no:cacheprovider `
  --ignore=tests/test_lifter.py `
  --ignore=tests/test_lifter_internal_calls.py `
  --ignore=tests/test_lifter_native_runtime.py `
  --ignore=tests/test_lifter_scalar_batch.py
uv run pytest tests/test_lifter.py tests/test_lifter_internal_calls.py `
  tests/test_lifter_native_runtime.py tests/test_lifter_scalar_batch.py `
  -q -p no:cacheprovider -p no:faulthandler
```

Record the command output and exact pass/skip counts. A skipped optional
dependency is not a validated subsystem.

Run the publication policy gate on the exact candidate commit:

```powershell
uv run python tools/release_check.py
```

## 3. Preflight the native candidate

Choose and record a hexadecimal opcode-shuffle seed so the candidate can be
reproduced during investigation. The preflight is read-only.

```powershell
$commit = (git rev-parse HEAD).Trim()
.\.venv\Scripts\python.exe .\tools\promote_stub.py `
  --source-commit $commit `
  --shuffle-seed <recorded-even-length-hex-seed> `
  --dry-run
```

The full staging run creates a new, previously nonexistent staging directory.
It performs a fresh VS2022 x64 Release build with `/W4 /WX /Brepro`, verifies
MSVC and the committed Python 3.12 lock, runs non-empty CTest, runs the complete
EXE/DLL round trip and native production corpus against one immutable stub
SHA-256, and evaluates the `all` production matrix.

```powershell
.\.venv\Scripts\python.exe .\tools\promote_stub.py `
  --source-commit $commit `
  --shuffle-seed <same-recorded-even-length-hex-seed> `
  --stage-dir .test-release-candidate
```

Each command result is stored under `evidence/` with the source commit and
artifact SHA-256. The candidate manifest is written atomically only after every
gate passes and hashes every evidence record. Failed gates leave diagnostics,
but no approved candidate manifest.

## 4. Validate the real application

- Pack the intended unmanaged x64 EXE with the freshly built stub via
  `--stub-path`.
- Exercise startup, shutdown, worker threads, exceptions, resources, updates,
  and application-specific workflows.
- Inspect the output's architecture, imports, section protections, signature
  state, and mitigation flags. Basic GuardCF tables, including exact
  suppressed/export-suppressed GFID metadata, must remain present and pass the
  native negative test. Unsupported load-config families, XFG metadata for
  generated thunks, and any unbound outer mitigation clone must fail the release
  matrix; a successful pack must never imply that CFG was silently removed.
- Test anti-debug on/off. Test memory guard only if it is part of the candidate.
- Retain an unpacked, symbolized canary for support and rollback.

## 5. Experimental feature containment

- Confirm the release command does not use `--enable-experimental-dll`,
  `--enable-experimental-server-shard`, `--memory-guard`, or
  `--anti-debug on`.
- Treat DLL native evidence as proof only for the declared guarded fixture
  envelope. Do not call DLL release-supported until generated-thunk XFG
  coverage, clean provenance, and the clean-VM matrix are green. Offset-root
  resources and DLL delay imports are covered only by the declared native
  fixtures and still require real-application validation.
- Do not ship server-shard mode until its backend contract, TLS policy, signed
  launcher, denial paths, and signed application launch pass an external
  end-to-end acceptance gate.

## 6. Stage, review, sign, and scan

- The staging tool and CI workflow never modify
  `stub/prebuilt/lethe_stub_x64.dll` or its tracked manifest. The legacy
  `build_stub.ps1 -Promote` switch fails closed.
- The complete `all` matrix must be green. A green EXE subset cannot bypass a
  red DLL lane, and `--validate-only` is never promotion evidence.
- Review the staged DLL, manifest, and hashed evidence as one indivisible unit.
- Publication remains a separate reviewed operation and is unavailable while
  any matrix row is blocked, partial, experimental, failing, or unverified.
- Pack the application, then Authenticode-sign the packed output and launcher.
- Verify signatures and timestamp chains on a clean machine.
- Run current Windows Defender scans and launch/runtime smoke tests on a clean VM.
- Canary the exact signed hashes before wider distribution.

## 7. Release record

Record source commit, lockfile hash, toolchain versions, shuffle seed, native
manifest, unsigned and signed artifact hashes, signing identity/timestamp,
automated test logs, functional owner approval, Defender evidence, and rollback
artifact. A changed hash requires repeating artifact-specific gates.
