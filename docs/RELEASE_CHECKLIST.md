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
- The limited bundle helper requires ordinary, single-link input, output, stub,
  and manifest files. Source, candidate and destination paths must not traverse
  symlinks or junctions. Use independent copies instead of aliases. It pins the
  candidate's filesystem identity as well as its bytes across packing and never
  replaces an existing output directory on the supported Windows host.

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

The isolated scalar oracle covers every combination of incoming CF/PF/ZF/SF/OF
through register, XMM, memory, complete-function and relocated-data boundaries.
Its keyword-only `initial_flags` argument accepts only those arithmetic RFLAGS
bits; the default remains zero. The native frame harness independently replays
160 seeded cases in plain and rolling modes (320 executions), compares all GPRs,
XMM lanes and modeled flags, and checks preservation of unmodeled flag bits.
This is instruction/frame evidence, not real-application or general ISA approval.

The publication policy gate validates the tracked default prebuilt, so it is
expected to remain red while that prebuilt is legacy or candidate-only. Run it
on the exact release commit; a pass means the candidate manifest and detached
release attestation verify under a pinned, non-revoked Ed25519 public key, all
hashed evidence is present, and an evidence-aware all-scope gate independently
matches the signed green result:

```powershell
uv run python tools/release_check.py
```

### Captured-frame external calls

Run `tests/test_lifter_frame_call_native.py` with the native toolchain. Its own
C/MASM fixtures cover positional mixed single/double/integer and variadic
arguments, FP returns, the emitted bridge unwind record and Windows RtlVirtualUnwind
at a transient flag push,
volatile GPR/XMM/flag state, all 32 incoming flag patterns, dispatch admission
and denial, malformed call rejection, and rolling aligned 128-bit transfers.
The six frame-call nodes are mandatory source-compiled native primitive proof,
not executions of the candidate DLL. Other candidate-bound lanes retain their
artifact binding. The mandatory materialized FP-frame node packs and executes
generated EXE and DLL fixtures with eight mixed FP/integer positions and checks
original parity. Materialization rejects indexed or truncated RSP-based source
addresses: the static displacement alone does not bound a dynamic index. Fixed
stack offsets, incoming stack arguments and non-stack indexed addresses retain
their existing validation paths. The dispatch sentinel is not Windows CFG matrix evidence. No installed product
runs in this test. The lifter uses the new `n_call_frame` opcode; keep the
scalar-only `n_call_ptr` out of newly lifted call paths. Rebuild/stage a fresh
candidate after this ISA change and retain its new opcode fingerprint. Do not
reuse an older runtime mapping or infer product acceptance from these fixtures.

The stack-window proof tracks full-width register copies, constant adjustments,
fixed frame-pointer addresses and qword stack spills/reloads across control flow.
Indexed/truncated aliases, partial pointer spills, opaque pointer escapes and
other unmodeled pointer transfers fail closed. Source-derived pointers in the
captured volatile native-call registers or four outgoing stack positions require
a native-call pointer summary that is not yet implemented; those functions are
rejected, not rewritten. Ordinary incoming caller pointers are not relocated.
The materialized FP EXE/DLL regression also uses an RBP frame and a spilled/reloaded
source-stack pointer for outgoing stores, and a second virtualized function checks
an unchanged incoming caller output pointer plus its fifth stack argument.
Its third selected function executes legacy `CVTDQ2PD` in both self-aliasing
register and m64 forms. Eight directed signed-int32 pairs execute under 32 MXCSR
settings covering every rounding mode, FTZ, sticky status and masked/unmasked
exceptions; exact MXCSR preservation and four output doubles are asserted.
The eight-byte input ends at a PAGE_NOACCESS boundary, so an accidental m128
read faults rather than silently passing. The source-level plain/rolling frame
harness also includes this exact conversion in its all-incoming-flags replay.
General rounded conversions and floating-point arithmetic remain unsupported;
the exact int32-to-binary64 lift uses existing integer opcodes, not host FP state.
This is bounded admission evidence,
not a claim of arbitrary memory-safety analysis or general ISA support.

Read-only function discovery replays that same materialized-stack proof with
the thunk's actual window size, canonical lifted body and per-candidate proven
native-call targets before reporting `liftable=true` or emitting a starter
selection. Dynamic/oversized frames, unbalanced returns, out-of-window aliases
and unsupported native pointer escapes therefore appear as explicit lift
rejections rather than a starter selection that fails later during packing.
Instruction-specific failures retain their original diagnostic precedence.
Passing this preflight still does not prove indirect-target closure, whole-image
executable coverage, native application behavior or release readiness.

### Native debugger verdicts

The mandatory positive-debugger EXE node also checks its own debugger with a
benign unhandled continuable exception (`0xE04C5448`). The initial primary-thread
loader breakpoint alone is consumed. Application first- and second-chance
exceptions receive `DBG_EXCEPTION_NOT_HANDLED`, preserving Windows exception
dispatch; the unhandled fault oracle must exit with the exception code, and the
handled oracle must reach its SEH handler and exit 83, never sentinel 73.
Events from another PID, missing loader-breakpoint evidence, and a zero exit
after a second-chance exception fail validation.

The original 30-second deadline and three DLL-host repetitions stay unchanged.
A failed wait records the original Win32 error, owned-child process/main-thread
status, debugger presence and the last 32 events, even if status probes fail.
These read-only diagnostics do not retry a wait or turn a timeout into a pass.
Later passing runs do not explain an earlier timeout; rejected stages remain
rejected until their failure is understood rather than being overwritten.

The no-CRT DLL test host explicitly calls `ExitProcess(host_main())` only after
its unchanged load/call/unload or host-safe rejection checks. This matches
normal CRT process termination; returning from a custom PE entrypoint terminates
only its main thread and can leave other threads keeping the process alive.
The original twelve control/protected, debugged/nondebugged launches remain,
and all twelve repeat with a host-owned 60-second worker still outstanding.
Both groups retain the original 30-second process deadline and three repetitions.
The protected DLL does not terminate its host, and no process-exit call was added
to the protected runtime. The returning-entrypoint failure and controlled-worker
baseline/rollback remain recorded; this test-host correction is not general
custom-entrypoint DLL-host compatibility or real-product acceptance evidence.

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
frozen twenty-nine-node native hardening, selected-function, captured-call
frame, 128-bit memory, XFG,
and post-startup EXE export
replay, the complete nineteen-check EXE/DLL round trip, and native production
corpus against one immutable stub SHA-256 before evaluating the `all` production
matrix. The native replay
inherits the normal process environment, overrides
`LETHE_RUN_NATIVE_RUNTIME_STRESS=1`, `LETHE_RUN_NATIVE_VM_E2E=1`, and
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

### Replay the integer corpus against the verified candidate

After staging, run the six-function integer/SSE2 corpus with the intact candidate
bundle. This mode verifies the complete candidate before building or executing
the generated fixture, rechecks its artifact/manifest binding before packing,
and never enables the unverified-stub test override:

```powershell
$env:LETHE_RUN_NATIVE_VM_CORPUS = "1"
$env:LETHE_NATIVE_CORPUS_STUB_PATH = "C:\path\to\candidate\lethe_stub_x64.dll"
.\.venv\Scripts\python.exe -m pytest tests/test_native_virtualization_corpus.py `
  -q -p no:cacheprovider
```

The run exercises narrow extensions, SET/CMOV selection, ADC/SBB carry,
BSWAP/XCHG memory, MUL/IMUL wide arithmetic, and the six legacy SSE2 packed
byte/word/dword equality and signed-greater-than comparisons with the candidate's own opcode
mapping and rolling configuration. An empty, damaged, changed or unverified
explicit candidate fails; it never falls back to a freshly built test runtime.
Unset both variables afterward. With no candidate path, the opt-in test retains
its self-built non-rolling fixture mode. Fixture-only coverage/indirect-target
acknowledgements are not product approval or a general indirect-closure proof.

The packed comparisons accept XMM registers and aligned 128-bit memory sources;
MMX, VEX/EVEX, and the SSE4 quadword forms remain whole-function rejections.
Element masks and signed comparisons follow the
[Intel instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

## 4. Validate the real application

- Exercise closing the GUI while a file is still packing. Closing must remain
  responsive, cancel later queued files, and defer window destruction until the
  current pack and native worker cleanup finish. Cancellation does not interrupt
  the active `pack_file` transaction. Repeat closing must not destroy a running
  child QThread or start another batch. A successful UI-only Nuitka compilation
  proves the compiler recipe, not the signed resource closure or product runtime.
- Repeat the close/cancel check with Venice's actual QML window. Its close event
  must wait for worker cleanup without blocking the event loop. With post-pack
  validation enabled, a validator exception, absent output path, malformed result,
  or structural rejection must count as a failed/unverified file, never success.
  Validation selection is captured for the batch; changing a preset mid-pack must
  not weaken the current batch's check. Structural validation is not runtime proof.
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

- The constrained `lethe-limited-v1` helper admits exported EXEs only through a
  matching export-capable assembler/runtime (`lethe_exe_export_abi=1`). A
  structurally valid container does not prove application compatibility. Early
  original-dependency attach callbacks into the EXE remain unsupported. Do not
  distribute exported-EXE outputs produced by earlier versions of that helper
  without separately verified export-preservation and real-host runtime evidence.

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
- Record Defender service/antivirus state, engine version, and signature
  version/update time immediately before and after scanning. Both observations
  must show the service and antivirus enabled with unchanged engine and
  definitions. Record real-time protection state without requiring it for an
  on-demand scan. A silent `MpCmdRun` process with exit code zero is not sufficient
  scanner evidence, especially when the service is disabled or definitions are
  absent. Retain the actual per-file scan result and scan-tool output; do not
  infer a clean verdict from process status alone. See Microsoft's
  [MpCmdRun reference](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus).
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
tool version, engine version, definitions, scan time, output hash, and receipt
hash. Each subject
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

The production scanner document uses schema **2** and each scanner-registry
entry includes `engine_version`. Every per-run receipt uses schema **1**, kind
`lethe-scanner-receipt`, and the exact fields validated by
`packer/scanner_evidence.py`. Receipts bind the subject's before/after hash and
size, source commit, candidate manifest, protecting stub, scanner/tool/engine/
definitions identity, raw-output hash, and a completed clean zero-detection
result. Provider authentication remains mandatory; a receipt is not trusted
merely because it declares a clean verdict. Receipt parsing is limited to
64 KiB of duplicate-free, finite-number JSON and raw output to 16 MiB of
nonempty meaningful bytes. These are per-file validation limits, not a total
input-directory snapshot size limit.

Lethe's freshness policy requires canonical UTC timestamps at second precision.
Definitions must not be future-dated and must be at most 24 hours old at scan
completion. Defender's before observation, scan start, scan completion, after
observation, and collection are ordered. The before-to-start,
completion-to-after, and after-to-collection gaps are each at most five minutes;
scan duration itself is not limited to five minutes. An independent scanner
must collect within five minutes of completion. Collection must fall within
24 hours before signed release issuance, with at most five minutes of forward
clock skew. These windows are Lethe policy, not a claim about Microsoft defaults.

The signed production release **payload** also uses schema **2** and includes
`issued_at_utc`. The outer release envelope, provider envelopes, external
manifest, and per-run scanner receipts remain schema **1**. Legacy scanner
documents and release payloads are rejected rather than silently promoted.
Final verification repeats all receipt checks using the signed issuance before
publication; later installed-release verification uses that same issuance, not
the current date, so valid historical evidence does not expire merely with age.
Issuance more than five minutes ahead of the verifier's clock is rejected.

`packer.external_evidence_phase_b` is the evidence-only v2 preparation boundary.
It snapshots already-built candidate and EXE/DLL material once, requires an
explicit bytes-only candidate verifier, creates a CSPRNG challenge, ingests
strict duplicate-free detached receipts, and retains their exact canonical
payload, signature, subjects, and backings. Finalization reverifies complete
subject/role/scope coverage under current trust and requires an explicit
bytes-only Authenticode verifier whose hashes and signer/TSA pins match the
retained signed subjects. It never executes or recollects an artifact and never
reopens an accepted source path. Its publisher writes only retained bytes and
sets `release_authorized=false`; this foundation is not yet wired into
`tools/release_stub.py` and does not satisfy any external production-matrix row.

Phase C adds [durable prepared bundles](EXTERNAL_EVIDENCE_PHASE_C.md) for
multi-process evidence workflows. Reload requires an independently retained
context pin and revalidates exact retained material; persistence does not
renew challenge expiry or grant release authority.

Phase D adds [strict finalized-bundle reload and historical replay](EXTERNAL_EVIDENCE_PHASE_D.md).
It requires independently retained context and manifest hashes, current trust
bytes, and an explicit bytes-only Authenticode verifier. Current-time
reverification runs before an exact recorded-time replay. This remains
evidence-only, always leaves release authority false, and is not integrated
with `tools/release_stub.py`.

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
The candidate-bound native runtime record must name the frozen list of twenty-nine
node IDs spanning hardening stress, selected-function virtualization E2E,
plain and shuffled-rolling STORE128 atomic-fault checks, captured frame calls
and unwind recovery, XFG preflight, and post-startup EXE exports (one positive plus five directory/snapshot mutations).
The count-zero mutation may be rejected by Windows before the stub executes;
it is not proof that the stub's own verifier ran. The optional early-attach
characterization is excluded and does not establish support. The mandatory
terminal pytest summary must report exactly twenty-nine passes
with no other outcome against the exact candidate hash; the EXE E2E pair must
execute paged-v1 output in eager and memory-guard modes, and the DLL E2E node
must execute a source-bound schema-v3 selection with a canonical padded suffix.
Release replay repeats that same command against the byte-identical rebuilt stub.
The separate EXE/DLL round-trip record must contain exactly one terminal
`19/19 passed -- PASS` summary; reduced, duplicated, nested, or contradictory
summaries reject both candidate promotion and release replay.
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

Publishing that verified bundle into `stub/prebuilt` must retain both its
candidate `evidence/` files and its `release-evidence/` files, not only the DLL
and two manifests. The source-tree release check permits only the exact
candidate backing paths listed by the revalidated candidate manifest whose hash
matches the signed release payload. An unlisted file under `evidence/` is not
authorized merely because it shares that directory prefix. Missing or modified
candidate records still fail verification; unrelated source changes after
attestation remain forbidden.

## 7. Release record

### GUI build artifact acceptance

Use a previously nonexistent `-OutputDir` for each `gui/build_gui.ps1` run.
The build recipe refuses existing directories before starting Nuitka, preserving
old binaries and standalone dependency trees rather than accepting stale output
or letting the compiler clean a previous distribution. A failed build retains
its fresh directory for diagnosis; the next attempt needs another directory.

Successful compilation must produce `Lethe.exe` for onefile mode or
`app.dist/Lethe.exe` for `-NoOnefile`. The recipe binds the output directory's
filesystem identity, rejects linked output paths and hardlinked executables,
and structurally checks a bounded (at most 512 MiB) AMD64 PE32+ Windows GUI EXE
before reporting its exact size and SHA-256. Missing, malformed, wrong-kind,
or wrong-architecture outputs fail even if the compiler returns zero.
These checks are not runtime acceptance, a complete standalone dependency audit,
or production release authorization. Test the actual compiled GUI and its
packing workflow with the approved complete release bundle before distribution.
`-SkipStubCheck` with a missing stub remains a UI-only build and supplies no
packing or release evidence.

Record source commit, lockfile hash, toolchain versions, shuffle seed, native
manifest, unsigned and signed artifact hashes, signing identity/timestamp,
automated test logs, functional owner approval, Defender evidence, and rollback
artifact. A changed hash requires repeating artifact-specific gates.
