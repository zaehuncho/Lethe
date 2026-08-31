<#
.SYNOPSIS
    Lethe end-to-end round-trip acceptance harness.

.DESCRIPTION
    1. Checks that prebuilt sample binaries exist (sample_exe.exe, sample_dll.dll,
       host.exe).  If missing, prints build instructions and exits with error.
    2. Packs sample_exe.exe, runs original vs packed, asserts identical stdout and
       exit code.
    3. Packs sample_dll.dll, loads original vs packed via host.exe, asserts
       identical stdout and exit code.
    4. Prints summary: N/N passed, overall PASS/FAIL.

.OUTPUTS
    Exit 0 = all tests passed.
    Exit 1 = one or more tests failed or a prerequisite was missing.
.PARAMETER StubPath
    Optional freshly built stub DLL; avoids relying on the tracked prebuilt in CI.
.PARAMETER PythonExe
    Python interpreter used to run lethe.py. Defaults to the locked virtual
    environment when present, otherwise the Python command on PATH.
#>
[CmdletBinding()]
param(
    [string]$StubPath = '',
    [string]$PythonExe = ''
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Paths -- packer root is one directory above $PSScriptRoot (tests/).
# ---------------------------------------------------------------------------
$TestsDir   = $PSScriptRoot
$PackerRoot = Split-Path $TestsDir -Parent
$BuildDir   = Join-Path $TestsDir 'build'
$Orionpack  = Join-Path $PackerRoot 'lethe.py'

if (-not $PythonExe) {
    $VenvPython = Join-Path $PackerRoot '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $VenvPython) {
        $PythonExe = $VenvPython
    } else {
        $PythonExe = 'python'
    }
}

if (-not (Get-Command -Name $PythonExe -ErrorAction SilentlyContinue)) {
    throw "Python interpreter not found: $PythonExe"
}

$OrigExe    = Join-Path $BuildDir 'sample_exe.exe'
$PackedExe  = Join-Path $BuildDir 'sample_exe.packed.exe'
$OrigDll    = Join-Path $BuildDir 'sample_dll.dll'
$PackedDll  = Join-Path $BuildDir 'sample_dll.packed.dll'
$HostExe    = Join-Path $BuildDir 'host.exe'

$script:Passed = 0
$script:Total  = 0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Report-Pass($msg) {
    $script:Passed++
    $script:Total++
    Write-Host "  [PASS] $msg" -ForegroundColor Green
}

function Report-Fail($msg) {
    $script:Total++
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
}

function Section($msg) {
    Write-Host ''
    Write-Host "== $msg ==" -ForegroundColor Cyan
}

# Run an executable via Start-Process, capturing stdout and stderr to temp
# files.  Returns a PSCustomObject with .Stdout, .Stderr, .ExitCode.
function Invoke-Captured {
    param(
        [string]$FilePath,
        [string[]]$Arguments = @()
    )
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        $procArgs = @{
            FilePath               = $FilePath
            Wait                   = $true
            NoNewWindow            = $true
            PassThru               = $true
            RedirectStandardOutput = $stdoutFile
            RedirectStandardError  = $stderrFile
        }
        if ($Arguments.Count -gt 0) {
            $procArgs['ArgumentList'] = $Arguments
        }
        $proc = Start-Process @procArgs
        $stdout = Get-Content -Path $stdoutFile -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content -Path $stderrFile -Raw -ErrorAction SilentlyContinue
        if ($stdout -eq $null) { $stdout = '' }
        if ($stderr -eq $null) { $stderr = '' }
        return [pscustomobject]@{
            Stdout   = $stdout
            Stderr   = $stderr
            ExitCode = $proc.ExitCode
        }
    }
    finally {
        Remove-Item -LiteralPath $stdoutFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Set working directory to the packer root.
# ---------------------------------------------------------------------------
Push-Location $PackerRoot

try {

Write-Host 'Lethe round-trip test' -ForegroundColor White
Write-Host "  packer root : $PackerRoot"
Write-Host "  build dir   : $BuildDir"

# ---------------------------------------------------------------------------
# Step 0 -- check that sample binaries exist.
# ---------------------------------------------------------------------------
Section 'Step 0: prerequisite check'

$missing = @()
if (-not (Test-Path -LiteralPath $OrigExe))  { $missing += 'tests/build/sample_exe.exe' }
if (-not (Test-Path -LiteralPath $OrigDll))   { $missing += 'tests/build/sample_dll.dll' }
if (-not (Test-Path -LiteralPath $HostExe))   { $missing += 'tests/build/host.exe' }

if ($missing.Count -gt 0) {
    Write-Host ''
    Write-Host 'ERROR: required sample binaries not found:' -ForegroundColor Red
    foreach ($m in $missing) {
        Write-Host "  - $m" -ForegroundColor Red
    }
    Write-Host ''
    Write-Host 'To build them, open an x64 Native Tools Command Prompt and run:' -ForegroundColor Yellow
    Write-Host "  cd $PackerRoot" -ForegroundColor Yellow
    Write-Host '  powershell -File tests\build_samples.ps1' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Or from PowerShell with MSVC on PATH:' -ForegroundColor Yellow
    Write-Host "  & `"$TestsDir\build_samples.ps1`"" -ForegroundColor Yellow
    exit 1
}

if ($StubPath -and -not (Test-Path -LiteralPath $StubPath)) {
    Write-Host "ERROR: requested stub not found: $StubPath" -ForegroundColor Red
    exit 1
}

Write-Host '  sample_exe.exe, sample_dll.dll, host.exe all present.'

# ---------------------------------------------------------------------------
# Step 1 -- EXE round-trip.
# ---------------------------------------------------------------------------
Section 'Step 1: EXE round-trip'

# 1a. Pack.
Write-Host '  Packing sample_exe.exe ...'
Remove-Item -LiteralPath $PackedExe -Force -ErrorAction SilentlyContinue
$packArgs = @(
    $Orionpack,
    $OrigExe,
    $PackedExe
)
if ($StubPath) { $packArgs += @('--stub-path', $StubPath) }
$packResult = Invoke-Captured -FilePath $PythonExe -Arguments $packArgs
if ($packResult.ExitCode -ne 0) {
    Report-Fail "lethe.py failed to pack EXE (exit $($packResult.ExitCode))"
    Write-Host "    stderr: $($packResult.Stderr.TrimEnd())" -ForegroundColor DarkGray
} elseif (-not (Test-Path -LiteralPath $PackedExe)) {
    Report-Fail 'packed EXE was not produced'
} else {
    Write-Host '  Packed EXE created.'

    # 1b. Run original.
    Write-Host '  Running original ...'
    $origRun = Invoke-Captured -FilePath $OrigExe
    Write-Host "    stdout: [$($origRun.Stdout.TrimEnd())]  exit=$($origRun.ExitCode)"

    # 1c. Run packed.
    Write-Host '  Running packed ...'
    $packedRun = Invoke-Captured -FilePath $PackedExe
    Write-Host "    stdout: [$($packedRun.Stdout.TrimEnd())]  exit=$($packedRun.ExitCode)"

    # 1d. Compare stdout.
    if ($origRun.Stdout -eq $packedRun.Stdout) {
        Report-Pass 'EXE stdout matches (original == packed)'
    } else {
        Report-Fail "EXE stdout mismatch`n    original: [$($origRun.Stdout.TrimEnd())]`n    packed:   [$($packedRun.Stdout.TrimEnd())]"
    }

    # 1e. Compare exit code.
    if ($origRun.ExitCode -eq $packedRun.ExitCode) {
        Report-Pass "EXE exit code matches (original=$($origRun.ExitCode), packed=$($packedRun.ExitCode))"
    } else {
        Report-Fail "EXE exit code mismatch (original=$($origRun.ExitCode), packed=$($packedRun.ExitCode))"
    }

    # 1f. Verify expected contract values.
    $expectedStdout = "Lethe sample_exe: tls=105 caught=-1`r`n"
    $expectedExit   = 42
    if ($origRun.Stdout -ne $expectedStdout) {
        Report-Fail "EXE stdout does not match expected contract`n    expected: [Lethe sample_exe: tls=105 caught=-1]`n    got:      [$($origRun.Stdout.TrimEnd())]"
    } else {
        Report-Pass 'EXE stdout matches expected contract'
    }
    if ($origRun.ExitCode -ne $expectedExit) {
        Report-Fail "EXE exit code does not match expected contract (expected=$expectedExit, got=$($origRun.ExitCode))"
    } else {
        Report-Pass "EXE exit code matches expected contract (exit=$expectedExit)"
    }
}

# Clean up packed EXE.
Remove-Item -LiteralPath $PackedExe -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Step 2 -- DLL round-trip.
# ---------------------------------------------------------------------------
Section 'Step 2: DLL round-trip'

# 2a. Pack.
Write-Host '  Packing sample_dll.dll ...'
Remove-Item -LiteralPath $PackedDll -Force -ErrorAction SilentlyContinue
$packDllArgs = @(
    $Orionpack,
    $OrigDll,
    $PackedDll,
    '--enable-experimental-dll'
)
if ($StubPath) { $packDllArgs += @('--stub-path', $StubPath) }
$packDllResult = Invoke-Captured -FilePath $PythonExe -Arguments $packDllArgs
if ($packDllResult.ExitCode -ne 0) {
    Report-Fail "lethe.py failed to pack DLL (exit $($packDllResult.ExitCode))"
    Write-Host "    stderr: $($packDllResult.Stderr.TrimEnd())" -ForegroundColor DarkGray
} elseif (-not (Test-Path -LiteralPath $PackedDll)) {
    Report-Fail 'packed DLL was not produced'
} else {
    Write-Host '  Packed DLL created.'

    # 2b. Run host.exe with original DLL.
    Write-Host '  Running host.exe with original DLL ...'
    $hostOrig = Invoke-Captured -FilePath $HostExe -Arguments @($OrigDll)
    Write-Host "    stdout: [$($hostOrig.Stdout.TrimEnd())]  exit=$($hostOrig.ExitCode)"

    # 2c. Run host.exe with packed DLL.
    Write-Host '  Running host.exe with packed DLL ...'
    $hostPacked = Invoke-Captured -FilePath $HostExe -Arguments @($PackedDll)
    Write-Host "    stdout: [$($hostPacked.Stdout.TrimEnd())]  exit=$($hostPacked.ExitCode)"

    # 2d. Compare stdout.
    if ($hostOrig.Stdout -eq $hostPacked.Stdout) {
        Report-Pass 'DLL stdout matches (original == packed)'
    } else {
        Report-Fail "DLL stdout mismatch`n    original: [$($hostOrig.Stdout.TrimEnd())]`n    packed:   [$($hostPacked.Stdout.TrimEnd())]"
    }

    # 2e. Compare exit code.
    if ($hostOrig.ExitCode -eq $hostPacked.ExitCode) {
        Report-Pass "DLL exit code matches (original=$($hostOrig.ExitCode), packed=$($hostPacked.ExitCode))"
    } else {
        Report-Fail "DLL exit code mismatch (original=$($hostOrig.ExitCode), packed=$($hostPacked.ExitCode))"
    }

    # 2f. Verify expected contract values.
    if ($hostOrig.Stdout -like '*PASS sample_dll_value=0xC0FFEE42*') {
        Report-Pass 'DLL stdout contains expected "PASS sample_dll_value=0xC0FFEE42"'
    } else {
        Report-Fail "DLL stdout does not contain expected marker`n    expected to contain: PASS sample_dll_value=0xC0FFEE42`n    got: [$($hostOrig.Stdout.TrimEnd())]"
    }
    if ($hostOrig.ExitCode -eq 0) {
        Report-Pass 'DLL exit code matches expected contract (exit=0)'
    } else {
        Report-Fail "DLL exit code does not match expected contract (expected=0, got=$($hostOrig.ExitCode))"
    }
    if ($hostOrig.Stdout -like '*TLS main=105 worker=105*' -and
        $hostPacked.Stdout -like '*TLS main=105 worker=105*') {
        Report-Pass 'DLL static TLS is isolated and initialized on a worker thread'
    } else {
        Report-Fail "DLL TLS worker contract failed`n    original: [$($hostOrig.Stdout.TrimEnd())]`n    packed:   [$($hostPacked.Stdout.TrimEnd())]"
    }
}

# Clean up packed DLL.
Remove-Item -LiteralPath $PackedDll -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '-------------------------------------------' -ForegroundColor White
if ($script:Total -eq 0) {
    Write-Host "  0/0 passed -- no tests ran" -ForegroundColor Yellow
    exit 1
} elseif ($script:Passed -eq $script:Total) {
    Write-Host "  $($script:Passed)/$($script:Total) passed -- PASS" -ForegroundColor Green
    exit 0
} else {
    $failed = $script:Total - $script:Passed
    Write-Host "  $($script:Passed)/$($script:Total) passed ($failed failed) -- FAIL" -ForegroundColor Red
    exit 1
}

} # end try
finally {
    Pop-Location
}
