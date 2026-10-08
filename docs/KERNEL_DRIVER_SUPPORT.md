# Kernel-driver readiness: inspection only

**Kernel packing and kernel virtualization are NOT IMPLEMENTED.** Lethe's native
runtime is a user-mode runtime, not a kernel driver runtime. The existing packer
rejection of native-subsystem driver images remains mandatory. Neither a `.sys`
extension nor successful static inspection makes an artifact suitable for this
runtime. VMProtect-equivalent coverage is not claimed.

## Compatibility target, not universal support

There is no claim that every `.sys` file can be transformed compatibly. A future
kernel implementation would need an explicit driver-model, architecture, OS,
HVCI and workload matrix, with unsupported inputs rejected rather than silently
processed. A filename extension or a successful structural report proves none
of those runtime properties. This report currently parses PE32+ and identifies
AMD64 candidates; it does not establish support for KMDF, WDM, minifilters,
boot-start drivers, ARM64, or any other kernel execution profile.

No exact driver project, release `.sys`, package, device description, or real
driver workflow has been supplied. This report does not discover or inspect
unrelated installed drivers. Provide the exact intended release artifact and
its source/build/package inputs before product-specific driver validation.

## Read-only report

Run from the checkout, substituting the exact artifact path:

```powershell
uv run python tools/kernel_driver_report.py C:\release\ProductDriver.sys
```

Report invocations emit one JSON document to standard output; `--help` instead
prints usage and exits with status 0 without inspecting an input. The report
reads one regular file; it does not write the file, load code, install services,
modify signing or boot settings, scan the host for drivers, or configure Driver
Verifier.

Exit statuses are deliberate:

| Exit | Meaning |
| --- | --- |
| 1 | Parsed structural report; blockers and/or unverified external gates remain. |
| 2 | Malformed, truncated, unsupported, oversized, inaccessible input or invalid CLI arguments. |

There is no production-success exit status in this version. `production_ready`,
`kernel_packing_supported`, and `kernel_virtualization_supported` always remain
false. `parsed: true` means only that this bounded parser accepted the structures
it examines, not that Windows will load the file or that every PE field is valid.

The report records:

- SHA-256 and byte size of the exact bytes read.
- Header-based candidacy: `.sys`, unmanaged AMD64 PE32+, executable image, native
  subsystem. This is not proof that a renamed native program is a real driver.
- Section file/virtual ranges, alignment, W+X permissions, declared and
  descriptor-derived IAT placement, NX-compatible and dynamic-base header flags.
- Normal and delayed import module names, with a non-exhaustive user-mode module
  check. This is not kernel DDI validation or a compatible-import allowlist.
- Bounded certificate-table entries. **Presence is not signature validation**;
  trust remains unverified, and catalog signatures are not examined.
- Unverified build/package, Microsoft signing, HVCI, Driver Verifier/HLK, real
  device workflows, and deployment/recovery evidence requirements.

Input handling uses Python's standard library. Limits are 256 MiB per file, 96
sections, 4,096 descriptors per import directory, 65,536 aggregate import thunks,
260-byte module names, 4,096-byte imported symbol names, and 1,024 certificate
entries. Ambiguous/overlapping/truncated ranges, unterminated imports, and
out-of-bounds references fail closed. No instruction decoding is performed.
The parser uses the [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
as its structural reference, including the certificate directory's file-offset
semantics rather than RVA semantics.

## Production evidence that static inspection does not replace

1. **Build and package:** supply the exact driver project, supported WDK/toolchain,
   reproducible release build, intended device/driver model, INF, catalog and
   installation files. Review the package using Microsoft's
   [driver package guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/creating-a-driver-package).
2. **Signing:** select an applicable Microsoft production signing route and verify
   the resulting file/package trust on each target system. Ordinary user-mode
   Authenticode is not a substitute for kernel signing requirements. A certificate
   table is not proof of trust, and absence of one does not establish whether a
   catalog signs the file. See Microsoft's [driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
   and [signing options](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings).
3. **Memory integrity/HVCI:** sections must avoid W+X and have page-aligned layout;
   driver code must use NX allocations and avoid dynamic kernel code or modifying
   executable system memory. Those behavioral properties are not proved by the
   NX header bit, this report, or static section flags. Test real workflows with
   HVCI enabled and retain applicable code-integrity test results. Microsoft's
   [memory-integrity compatibility guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/implement-hvci-compatible-code)
   explains the runtime and layout requirements.
4. **Correctness and compatibility:** on dedicated, recoverable test machines,
   collect applicable Driver Verifier, CodeQL/WDK and HLK results, tied to exact
   release hashes and target OS/hardware states. Exercise installation, update,
   removal, reboot, failure recovery, device/power transitions and the driver's
   actual IRQL/concurrency paths. Driver Verifier can intentionally bugcheck test
   machines; this report never runs it. See [Driver Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier)
   and the [Windows HLK](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/).

The new report is a validation input, not kernel execution support. It does not
change Lethe's user-mode release gates or make the current product production-ready.

## Regression tests

```powershell
uv run pytest -q tests/test_kernel_driver_report.py
```

Tests use generated, non-functional structural PE fixtures only; none is a
loadable test driver. They cover malformed/truncated inputs, strict bounds,
classification, imports, W+X/NX, certificate non-verification, and read-only JSON
CLI behavior. Nine public-analyzer admission cases also verify that native,
system-image, and WDM-driver headers remain rejected regardless of a `.sys`,
`.exe`, or `.dll` filename. Production driver runtime tests remain external and
unverified.
