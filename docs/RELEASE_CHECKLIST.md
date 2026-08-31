# Lethe release checklist

Use this checklist for a candidate intended to leave the development machine.
Passing it establishes a recorded release gate, not universal security or
compatibility.

The release-supported payload is an unmanaged x64 EXE with anti-debug and
memory-guard disabled. DLL and server-shard modes are experimental and must not
be used in a release candidate.

## 1. Establish provenance

- Start from the intended commit and record `git rev-parse HEAD`.
- Review `git status --short`; explain every tracked and untracked change.
- Use Python 3.12, VS2022 x64/MSVC, and the committed `uv.lock`.
- Do not release the inherited prebuilt while its manifest says
  `legacy-unverified`; replace it through the clean promotion flow below.
- Keep builder tokens and PEM material in the shell's secret source. Do not put
  real values in `.env.example`, command history, manifests, or logs.

## 2. Run automated tests

```powershell
uv sync --frozen --group dev
uv run pytest -q -p no:cacheprovider --ignore=tests/test_lifter.py
uv run pytest tests/test_lifter.py -q -p no:cacheprovider -p no:faulthandler
```

Record the command output and exact pass/skip counts. A skipped optional
dependency is not a validated subsystem.

Run the publication policy gate on the exact candidate commit:

```powershell
uv run python tools/release_check.py
```

## 3. Build and test the native stub

Choose and record a hexadecimal opcode-shuffle seed so the candidate can be
reproduced during investigation.

```powershell
.\stub\build_stub.ps1 -Clean -Config Release `
  -ShuffleSeed <recorded-hex-seed>
.\tests\build_samples.ps1
.\tests\roundtrip.ps1 `
  -StubPath .\stub\build\Release\lethe_stub_x64.dll
```

Archive `lethe_stub_x64.dll.manifest.json` with the test evidence. Confirm the
manifest hash matches the DLL under test. Build the shard bootstrap separately:

```powershell
cmake -S bootstrap -B bootstrap/build -G "Visual Studio 17 2022" -A x64
cmake --build bootstrap/build --config Release
```

## 4. Validate the real application

- Pack the intended unmanaged x64 EXE with the freshly built stub via
  `--stub-path`.
- Exercise startup, shutdown, worker threads, exceptions, resources, updates,
  and application-specific workflows.
- Inspect the output's architecture, imports, section protections, signature
  state, and mitigation flags. Lethe currently drops CFG on the payload and stub.
- Test anti-debug on/off. Test memory guard only if it is part of the candidate.
- Retain an unpacked, symbolized canary for support and rollback.

## 5. Experimental feature containment

- Confirm the release command does not use `--enable-experimental-dll`,
  `--enable-experimental-server-shard`, `--memory-guard`, or
  `--anti-debug on`.
- Treat the DLL round-trip in CI as regression research, not evidence that DLLs
  are release-supported.
- Do not ship server-shard mode until its backend contract, TLS policy, signed
  launcher, denial paths, and signed application launch pass an external
  end-to-end acceptance gate.

## 6. Promote, sign, and scan

After the tree and candidate pass the prior gates:

```powershell
.\stub\build_stub.ps1 -Clean -Config Release `
  -ShuffleSeed <same-recorded-hex-seed> -Promote `
  -PythonExe .\.venv\Scripts\python.exe
```

- Review the prebuilt DLL and its provenance manifest as intentional changes.
- Pack the application, then Authenticode-sign the packed output and launcher.
- Verify signatures and timestamp chains on a clean machine.
- Run current Windows Defender scans and launch/runtime smoke tests on a clean VM.
- Canary the exact signed hashes before wider distribution.

## 7. Release record

Record source commit, lockfile hash, toolchain versions, shuffle seed, native
manifest, unsigned and signed artifact hashes, signing identity/timestamp,
automated test logs, functional owner approval, Defender evidence, and rollback
artifact. A changed hash requires repeating artifact-specific gates.
