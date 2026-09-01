# Lethe release checklist

Use this checklist to create and review a release candidate. Candidate staging
and production release are separate states: local staging proves one immutable
bundle, while only a later production-release attestation may authorize the
default bundled stub.

The currently releasable envelope remains an unmanaged x64 EXE with anti-debug,
process hardening, and memory guard disabled. Compatibility-preserving anti-dump
metadata sanitization is proven in the declared EXE/DLL corpus. Guarded DLL
packing now has native dynamic/static consumer, TLS, unwind, export-suppression,
attach-failure, and unload/reload proof, but it remains behind the experimental
CLI gate until every required DLL matrix row is green. Server-shard mode remains
experimental.

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

The publication policy gate validates the tracked default prebuilt, so it is
expected to remain red while that prebuilt is legacy or candidate-only. Run it
on the exact release commit; a pass means the candidate manifest and detached
release attestation verify under a pinned, non-revoked Ed25519 public key, all
hashed evidence is present, and an evidence-aware all-scope gate independently
matches the signed green result:

```powershell
uv run python tools/release_check.py
```

## 3. Preflight the native candidate

Choose and record an exact 64-lowercase-hex-character opcode-shuffle seed so the candidate can be
reproduced during investigation. The preflight is read-only.

```powershell
$commit = (git rev-parse HEAD).Trim()
.\.venv\Scripts\python.exe .\tools\promote_stub.py `
  --source-commit $commit `
  --shuffle-seed <recorded-64-hex-seed> `
  --dry-run
```

The full staging run creates a new, previously nonexistent staging directory.
It performs a fresh VS2022 x64 Release build with `/W4 /WX /Brepro`, verifies
MSVC and the committed Python 3.12 lock, runs non-empty CTest, then runs the
opt-in native runtime-hardening file, complete EXE/DLL round trip, and native
production corpus against one immutable stub SHA-256 before evaluating the
`all` production matrix. The hardening run inherits the normal process
environment, overrides only `LETHE_RUN_NATIVE_RUNTIME_STRESS=1` and
`LETHE_NATIVE_RUNTIME_STUB_PATH=<fresh-stub>`, and never serializes the inherited
environment into evidence. A green matrix is accepted.
A red matrix is accepted for candidate staging only when every blocker has the
exact id and status in the versioned candidate policy; unknown, changed,
evidence-missing, evidence-failed, or dirty-source blockers fail staging.
The current `lethe-native-candidate-v1` exception set is limited to:

- `mitigation.load_config_cfg_xfg=partial`
- `virtualization.selected_functions=partial`
- `hardening.process_policy=partial`
- `hardening.antidebug=experimental`
- `hardening.memory_guard_native=experimental`
- `provenance.fresh_native_stub=blocked`
- `release.clean_vm_matrix=unverified`

```powershell
.\.venv\Scripts\python.exe .\tools\promote_stub.py `
  --source-commit $commit `
  --shuffle-seed <same-recorded-64-hex-seed> `
  --stage-dir (Join-Path $env:TEMP "lethe-native-candidate-<unique>")
```

Keep the stage outside the Git checkout. Creating evidence beneath the checkout
would dirty the tree before the promoter's final provenance check.

Each command result is stored under `evidence/` with the source commit and
artifact SHA-256. The schema-2 candidate manifest is written atomically only
after every local verification passes and hashes every required evidence
record. It is marked `artifact_status=candidate-verified`,
`production_ready=false`, carries the complete remaining blocker list, and has
no `production_scope`. The manifest also binds the source, dependency locks,
toolchain record, candidate policy, promotion tool, and the candidate-time
production-matrix snapshot. Recorded commands use portable `repo://`,
`candidate://`, and `tool://` identities rather than machine-local paths.
Failed local gates or policy drift leave diagnostics but no verified manifest.
`evidence/runtime-hardening.json` is mandatory, must name the candidate artifact
hash, and must contain a complete non-skipped pytest pass.

## 4. Validate the real application

- Pack the intended unmanaged x64 EXE with the freshly built stub via
  `--stub-path`. Candidate status never authorizes implicit/default stub use.
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
- Review the staged DLL, schema-2 manifest, and hashed evidence directory as one
  indivisible unit. Moving only the DLL or manifest destroys the candidate
  evidence contract.
- Publication remains a separate reviewed operation and is unavailable while
  any matrix row is blocked, partial, experimental, failing, or unverified.
- Never copy a candidate DLL and manifest alone into `stub/prebuilt`. The
  default loader accepts only a valid detached `lethe_stub_x64.release.json`
  signed by a non-revoked key pinned in `packer/release_trust.json`. Candidate
  staging does not create that release attestation.
- Pack the application, then Authenticode-sign the packed output and launcher.
- Verify signatures and timestamp chains on a clean machine.
- Run current Windows Defender scans and launch/runtime smoke tests on a clean VM.
- Canary the exact signed hashes before wider distribution.

Create the production bundle only from the intact candidate directory and an
explicit external evidence manifest. Pin only the Ed25519 public key; keep the
private PEM outside the repository. The checked-in trust store intentionally
starts empty, so release is fail-closed until an owner-reviewed public key is
committed before candidate staging. The external manifest must bind the
candidate stub, candidate manifest, and source commit and contain exactly one
record for Authenticode, scanner, clean-VM, application, and production-native
evidence. It also declares one canonical subject registry containing at least
one PE32+ x64 EXE and one PE32+ x64 DLL. Every Authenticode, scanner,
application, and clean-VM record must cover that exact registry with
`subject_id`, `subject_kind`, `format`, `subject_path`, `subject_sha256`, and
`protected_with_stub_sha256`, plus the subject size, original-input hash,
pack-report hash, protection-profile hash, source commit, and candidate-manifest
hash. Scanner evidence requires current Microsoft Defender plus at least one
independent scanner; every subject must contain that exact engine set with tool,
version, definitions, scan time, output hash, and receipt hash. Each subject
requires at least two passing application workflows and all four clean-VM
cells: Windows 10 22H2 with VBS off, supported Windows 11 with VBS off,
supported Windows 11 with VBS/HVCI on, and Windows 11 with Hyper-V on. Each VM
cell records build, patch, architecture, Secure Boot, VBS/HVCI/Hyper-V state,
image and snapshot IDs, and runner hash. These records name the actual protected
outputs; they do not claim the unchanged candidate DLL was signed.

Scanner, clean-VM, and application records also carry detached Ed25519 provider
attestations. Provider public keys are pinned separately in
`packer/evidence_trust.json`, are authorized per evidence kind, and can be
revoked without changing the release-signing trust store. That policy also
pins nonempty Authenticode signer and timestamp-authority thumbprint allowlists.
Release keys and evidence-provider keys must be cryptographically disjoint;
one key cannot hold both roles. Its checked-in trust lists intentionally
start empty. Each provider signature binds the canonical evidence document and
all declared hashes. The evidence bundle must contain hash-addressed pack
reports, protection profiles, per-engine raw scanner output and receipts,
per-cell clean-VM result logs, and structured application workflow results and
logs. Missing, linked, escaped, forged, or changed backing files fail release.

```powershell
uv run python tools/release_stub.py `
  --candidate-dir <candidate-directory> `
  --external-evidence-manifest <external-evidence-manifest.json> `
  --private-key <external-ed25519-private.pem> `
  --private-key-password-file <external-password-file> `
  --output-dir <new-release-directory>
```

Use `--private-key-password-env <VARIABLE_NAME>` instead of the password file
when the release secret provider exports it. The release producer rejects a
dirty checkout, any code drift from the candidate source commit, a stale or red
current matrix, malformed external evidence, an unpinned/revoked key, and an
existing output directory. Before signing, it snapshots all candidate, matrix,
trust-store, and external-evidence inputs into an isolated directory. It then
rebuilds the native stub from a Git archive of the candidate commit with the
candidate's exact seed and toolchain and requires byte-for-byte identity. The
promotion configure evidence and rebuild must both contain exactly one
`-DDVM_ROLLING=ON` and one `-DDVM_ROLL_POISON=OFF`; the generated provenance,
candidate manifest, signed candidate identity, and release-rebuild evidence must
also bind `dvm_rolling=true`, `dvm_roll_poison=false`, and
`dvm_paged_runtime=true`. Conflicting or omitted
values invalidate the candidate. Rolling support serves internal VM programs,
while selected-function virtualization continues to use authenticated paging.
The candidate-bound native runtime record must name both the hardening stress
file and the selected-function virtualization E2E file. It must report at least
five passes with zero skips against the exact candidate hash; the E2E pair must
execute paged-v1 output in eager and memory-guard modes. Release replay repeats
that same command against the byte-identical rebuilt stub.
The candidate promoter, compatibility matrix, and dependency-lock hashes are read
back from that tracked Git commit rather than trusted from candidate snapshots.
The rebuilt bytes then rerun CTest, candidate-bound native runtime hardening,
EXE/DLL roundtrip, and the production corpus; portable command and output hashes
are included in the signed rebuild evidence. Before signing, Windows
`Get-AuthenticodeSignature` must independently report a valid signer and
timestamper for both snapshotted PE32+ x64 subjects. The release verifier also
requires bounded WIN_CERTIFICATE tables rather than accepting boolean claims.
Publication is an atomic new-directory swap. Verification replays the all-scope
production gate from the bundled release matrix and native evidence.

## 7. Release record

Record source commit, lockfile hash, toolchain versions, shuffle seed, native
manifest, unsigned and signed artifact hashes, signing identity/timestamp,
automated test logs, functional owner approval, Defender evidence, and rollback
artifact. A changed hash requires repeating artifact-specific gates.
