<#
.SYNOPSIS
    Run Lethe's native EXE compatibility corpus and write JSON evidence.

.DESCRIPTION
    This harness is intentionally fail-closed. Every failed pack records both
    stdout and stderr so mitigation rejections and loader failures stay
    actionable. It exits nonzero until every declared corpus lane passes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StubPath,
    [string]$PythonExe = '',
    [string]$BuildDir = '',
    [string]$EvidencePath = '',
    [string]$SourceCommit = ''
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
$TestPacker = Join-Path $PSScriptRoot '_lethe_test_cli.py'
$BuildDir = if ($BuildDir) {
    [System.IO.Path]::GetFullPath($BuildDir)
} else {
    Join-Path $PSScriptRoot 'production-build'
}
$EvidencePath = if ($EvidencePath) {
    [System.IO.Path]::GetFullPath($EvidencePath)
} else {
    Join-Path $BuildDir 'production-evidence.json'
}
$StubPath = [System.IO.Path]::GetFullPath($StubPath)
if (-not $PythonExe) {
    $candidate = Join-Path $Root '.venv\Scripts\python.exe'
    $PythonExe = if (Test-Path -LiteralPath $candidate) { $candidate } else { 'python' }
}

function Invoke-Captured {
    param([string]$FilePath, [string[]]$Arguments = @())
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        $processArgs = @{
            FilePath = $FilePath
            Wait = $true
            NoNewWindow = $true
            PassThru = $true
            RedirectStandardOutput = $stdoutFile
            RedirectStandardError = $stderrFile
        }
        if ($Arguments.Count -gt 0) {
            $processArgs['ArgumentList'] = $Arguments
        }
        $process = Start-Process @processArgs
        [string]$stdout = Get-Content -LiteralPath $stdoutFile -Raw -ErrorAction SilentlyContinue
        [string]$stderr = Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue
        return [ordered]@{
            exit_code = $process.ExitCode
            stdout = if ($null -eq $stdout) { '' } else { $stdout }
            stderr = if ($null -eq $stderr) { '' } else { $stderr }
        }
    }
    finally {
        Remove-Item -LiteralPath $stdoutFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

function Add-Result {
    param(
        [string]$Id,
        [bool]$Passed,
        [string]$Detail,
        $Process = $null
    )
    $entry = [ordered]@{
        id = $Id
        status = if ($Passed) { 'passed' } else { 'failed' }
        detail = $Detail
    }
    if ($null -ne $Process) {
        $entry['exit_code'] = $Process.exit_code
        $entry['stdout'] = $Process.stdout
        $entry['stderr'] = $Process.stderr
    }
    $script:Results += [pscustomobject]$entry
    $label = if ($Passed) { 'PASS' } else { 'FAIL' }
    Write-Host "  [$label] $Id - $Detail"
    if (-not $Passed -and $null -ne $Process) {
        Write-Host "    stdout: $($Process.stdout.TrimEnd())"
        Write-Host "    stderr: $($Process.stderr.TrimEnd())"
    }
}

function Get-Probe {
    param([string]$Path)
    $result = Invoke-Captured -FilePath $PythonExe -Arguments @(
        (Join-Path $Root 'tools\pe_feature_probe.py'), $Path)
    if ($result.exit_code -ne 0) {
        throw "PE feature probe failed for $Path`nstdout: $($result.stdout)`nstderr: $($result.stderr)"
    }
    return $result.stdout | ConvertFrom-Json
}

function Get-ResourceProbe {
    param([string]$Path)
    $result = Invoke-Captured -FilePath $PythonExe -Arguments @(
        (Join-Path $Root 'tools\pe_resource_probe.py'), $Path)
    if ($result.exit_code -ne 0) {
        throw "resource geometry probe failed for $Path`nstdout: $($result.stdout)`nstderr: $($result.stderr)"
    }
    return $result.stdout | ConvertFrom-Json
}

if (-not (Test-Path -LiteralPath $StubPath)) {
    throw "stub does not exist: $StubPath"
}
$CoreExe = Join-Path $BuildDir 'compat_core_exe.exe'
$DelayExe = Join-Path $BuildDir 'compat_delay_exe.exe'
$Dependency = Join-Path $BuildDir 'compat_dependency.dll'
$GuardedDll = Join-Path $BuildDir 'sample_dll.dll'
$GuardedPackedDll = Join-Path $BuildDir 'sample_dll.production.packed.dll'
$DynamicHost = Join-Path $BuildDir 'host.exe'
$StaticHost = Join-Path $BuildDir 'static_host.exe'
$ReloadHost = Join-Path $BuildDir 'reload_host.exe'
$CfgSuppressionHost = Join-Path $BuildDir 'cfg_suppression_host.exe'
$PreexistingTlsHost = Join-Path $BuildDir 'preexisting_tls_host.exe'
$ResourceOffsetDll = Join-Path $BuildDir 'resource_offset_dll.dll'
$ResourceOffsetPackedDll = Join-Path $BuildDir 'resource_offset_dll.production.packed.dll'
$ResourceOffsetHost = Join-Path $BuildDir 'resource_offset_host.exe'
$DelayDll = Join-Path $BuildDir 'compat_delay_dll.dll'
$DelayPackedDll = Join-Path $BuildDir 'compat_delay_dll.production.packed.dll'
$DelayDllHost = Join-Path $BuildDir 'compat_delay_dll_host.exe'
$AuxiliaryDllCases = @(
    [pscustomobject]@{ Id='dll.noentry.runtime'; Dll='noentry_dll.dll'; Packed='noentry_dll.production.packed.dll'; Host='noentry_host.exe'; Marker='noentry_host: PASS' },
    [pscustomobject]@{ Id='dll.reject.runtime'; Dll='reject_dll.dll'; Packed='reject_dll.production.packed.dll'; Host='reject_host.exe'; Marker='reject_host: PASS' },
    [pscustomobject]@{ Id='dll.unwind.runtime'; Dll='unwind_dll.dll'; Packed='unwind_dll.production.packed.dll'; Host='unwind_host.exe'; Marker='unwind_host: PASS' },
    [pscustomobject]@{ Id='dll.tlsfree.runtime'; Dll='tlsfree_dll.dll'; Packed='tlsfree_dll.production.packed.dll'; Host='tlsfree_host.exe'; Marker='tlsfree_host: PASS' }
)
foreach ($required in @($CoreExe, $DelayExe, $Dependency, $GuardedDll,
                         $DynamicHost, $StaticHost, $ReloadHost,
                         $CfgSuppressionHost, $PreexistingTlsHost,
                         $ResourceOffsetDll, $ResourceOffsetHost,
                         $DelayDll, $DelayDllHost)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "native corpus artifact is missing: $required; run tests/build_production_corpus.ps1"
    }
}
foreach ($case in $AuxiliaryDllCases) {
    foreach ($file in @($case.Dll, $case.Host)) {
        if (-not (Test-Path -LiteralPath (Join-Path $BuildDir $file))) {
            throw "native corpus artifact is missing: $file; run tests/build_production_corpus.ps1"
        }
    }
}

$script:Results = @()
$ExpectedCore = "Lethe compat_core: resource=1 reloc=1 aslr=1`r`n"
$ExpectedDelay = "Lethe compat_exe: resource=1 delay=C0DEC0DE reloc=1 aslr=1`r`n"
$CorePacked = Join-Path $BuildDir 'compat_core_exe.packed.exe'
$DelayPacked = Join-Path $BuildDir 'compat_delay_exe.packed.exe'
Remove-Item -LiteralPath $CorePacked, $DelayPacked, $GuardedPackedDll `
    -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $ResourceOffsetPackedDll -Force `
    -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $DelayPackedDll -Force -ErrorAction SilentlyContinue

Push-Location $Root
try {
    $coreProbe = Get-Probe $CoreExe
    $coreShape =
        -not $coreProbe.has_load_config -and
        $coreProbe.resource_bytes -gt 0 -and
        $coreProbe.dir64_relocations -gt 0 -and
        $coreProbe.dynamic_base
    Add-Result 'exe.core.shape' $coreShape `
        'no load-config; resource, DIR64, and DYNAMICBASE are present'

    $coreOriginal = Invoke-Captured -FilePath $CoreExe
    Add-Result 'exe.core.original' `
        ($coreOriginal.exit_code -eq 0 -and $coreOriginal.stdout -eq $ExpectedCore) `
        'original core fixture contract' -Process $coreOriginal

    $corePack = Invoke-Captured -FilePath $PythonExe -Arguments @(
        $TestPacker, $CoreExe, $CorePacked,
        '--stub-path', $StubPath)
    $corePackPassed = $corePack.exit_code -eq 0 -and (Test-Path -LiteralPath $CorePacked)
    Add-Result 'exe.core.pack' $corePackPassed 'pack core fixture' -Process $corePack
    if ($corePackPassed) {
        $corePackedRun = Invoke-Captured -FilePath $CorePacked
        Add-Result 'exe.core.runtime' `
            ($corePackedRun.exit_code -eq $coreOriginal.exit_code -and
             $corePackedRun.stdout -eq $coreOriginal.stdout -and
             $corePackedRun.stderr -eq $coreOriginal.stderr) `
            'packed core fixture matches original' -Process $corePackedRun
    } else {
        Add-Result 'exe.core.runtime' $false 'not run because packing failed'
    }

    $delayProbe = Get-Probe $DelayExe
    $delayShape =
        $delayProbe.has_delay_imports -and
        $delayProbe.has_load_config -and
        $delayProbe.guard_cf_header -and
        $delayProbe.load_config.has_guard_cf -and
        $delayProbe.load_config.xfg_present
    Add-Result 'exe.delay.shape' $delayShape `
        'real delay-import directory and modern GuardCF/XFG load-config are present'

    $delayOriginal = Invoke-Captured -FilePath $DelayExe
    Add-Result 'exe.delay.original' `
        ($delayOriginal.exit_code -eq 0 -and $delayOriginal.stdout -eq $ExpectedDelay) `
        'original delay-import fixture contract' -Process $delayOriginal

    $delayPack = Invoke-Captured -FilePath $PythonExe -Arguments @(
        $TestPacker, $DelayExe, $DelayPacked,
        '--stub-path', $StubPath)
    $delayPackPassed = $delayPack.exit_code -eq 0 -and (Test-Path -LiteralPath $DelayPacked)
    Add-Result 'exe.delay.pack' $delayPackPassed `
        'pack guarded delay-import fixture without mitigation downgrade' -Process $delayPack
    if ($delayPackPassed) {
        $delayPackedRun = Invoke-Captured -FilePath $DelayPacked
        Add-Result 'exe.delay.runtime' `
            ($delayPackedRun.exit_code -eq $delayOriginal.exit_code -and
             $delayPackedRun.stdout -eq $delayOriginal.stdout -and
             $delayPackedRun.stderr -eq $delayOriginal.stderr) `
            'packed delay-import fixture matches original' -Process $delayPackedRun
    } else {
        Add-Result 'exe.delay.runtime' $false 'not run because packing failed'
    }

    $resourceProbe = Get-ResourceProbe $ResourceOffsetDll
    $resourceShape =
        $resourceProbe.resource_directory_offset -eq 0x40 -and
        $resourceProbe.resource_directory_rva -gt $resourceProbe.resource_rva -and
        $resourceProbe.resource_directory_size -gt 0
    Add-Result 'dll.resource.offset_root.shape' $resourceShape `
        'resource DataDirectory begins 0x40 bytes inside its owner section'
    $resourcePack = Invoke-Captured -FilePath $PythonExe -Arguments @(
        $TestPacker, $ResourceOffsetDll,
        $ResourceOffsetPackedDll, '--enable-experimental-dll',
        '--stub-path', $StubPath)
    $resourcePackPassed = $resourcePack.exit_code -eq 0 -and
        (Test-Path -LiteralPath $ResourceOffsetPackedDll)
    Add-Result 'dll.resource.offset_root.pack' $resourcePackPassed `
        'pack DLL without normalizing its resource directory root' `
        -Process $resourcePack
    if ($resourcePackPassed) {
        $packedResourceProbe = Get-ResourceProbe $ResourceOffsetPackedDll
        $resourceGeometryExact =
            $packedResourceProbe.resource_directory_rva -eq
                $resourceProbe.resource_directory_rva -and
            $packedResourceProbe.resource_directory_size -eq
                $resourceProbe.resource_directory_size -and
            $packedResourceProbe.resource_directory_offset -eq 0x40
        Add-Result 'dll.resource.offset_root.geometry' $resourceGeometryExact `
            'packed RESOURCE DataDirectory preserves exact source RVA and size'
        $resourceOriginal = Invoke-Captured -FilePath $ResourceOffsetHost `
            -Arguments @($ResourceOffsetDll)
        $resourcePacked = Invoke-Captured -FilePath $ResourceOffsetHost `
            -Arguments @($ResourceOffsetPackedDll)
        Add-Result 'dll.resource.offset_root.runtime' `
            ($resourceOriginal.exit_code -eq 0 -and
             $resourcePacked.exit_code -eq 0 -and
             $resourceOriginal.stdout -eq $resourcePacked.stdout -and
             $resourceOriginal.stderr -eq $resourcePacked.stderr -and
             $resourcePacked.stdout -like
                '*resource_offset_host: PASS FindResource/LoadResource*') `
            'FindResource/LoadResource matches the original offset-root DLL' `
            -Process $resourcePacked
    } else {
        Add-Result 'dll.resource.offset_root.geometry' $false `
            'not checked because packing failed'
        Add-Result 'dll.resource.offset_root.runtime' $false `
            'not run because packing failed'
    }

    $delayDllProbe = Get-Probe $DelayDll
    $delayDllShape =
        $delayDllProbe.has_delay_imports -and
        $delayDllProbe.has_load_config -and
        $delayDllProbe.guard_cf_header -and
        $delayDllProbe.load_config.has_guard_cf
    Add-Result 'dll.delay.shape' $delayDllShape `
        'guarded DLL has a real delay-import directory'
    $delayDllPack = Invoke-Captured -FilePath $PythonExe -Arguments @(
        $TestPacker, $DelayDll, $DelayPackedDll,
        '--enable-experimental-dll', '--stub-path', $StubPath)
    $delayDllPackPassed = $delayDllPack.exit_code -eq 0 -and
        (Test-Path -LiteralPath $DelayPackedDll)
    Add-Result 'dll.delay.pack' $delayDllPackPassed `
        'pack guarded delay-import DLL' -Process $delayDllPack
    if ($delayDllPackPassed) {
        $delayDllOriginal = Invoke-Captured -FilePath $DelayDllHost `
            -Arguments @($DelayDll)
        $delayDllPacked = Invoke-Captured -FilePath $DelayDllHost `
            -Arguments @($DelayPackedDll)
        Add-Result 'dll.delay.runtime' `
            ($delayDllOriginal.exit_code -eq 0 -and
             $delayDllPacked.exit_code -eq 0 -and
             $delayDllOriginal.stdout -eq $delayDllPacked.stdout -and
             $delayDllOriginal.stderr -eq $delayDllPacked.stderr -and
             $delayDllPacked.stdout -like
                '*compat_delay_dll_host: PASS first-call/unload cycles=8*') `
            'first delayed call and explicit dependency unload match across eight DLL reloads' `
            -Process $delayDllPacked
    } else {
        Add-Result 'dll.delay.runtime' $false `
            'not run because delay-import DLL packing failed'
    }

    $dllProbe = Get-Probe $GuardedDll
    $dllShape = $dllProbe.has_load_config -and $dllProbe.guard_cf_header -and
        $dllProbe.load_config.has_guard_cf
    Add-Result 'dll.guardcf.shape' $dllShape `
        'guarded DLL has active GuardCF load-config metadata'

    $dllPack = Invoke-Captured -FilePath $PythonExe -Arguments @(
        $TestPacker, $GuardedDll, $GuardedPackedDll,
        '--enable-experimental-dll', '--stub-path', $StubPath)
    $dllPackPassed = $dllPack.exit_code -eq 0 -and
        (Test-Path -LiteralPath $GuardedPackedDll)
    Add-Result 'dll.guardcf.pack' $dllPackPassed `
        'pack guarded DLL without stripping its load config' -Process $dllPack
    if ($dllPackPassed) {
        $dynamicOriginal = Invoke-Captured -FilePath $DynamicHost `
            -Arguments @($GuardedDll)
        $dynamicPacked = Invoke-Captured -FilePath $DynamicHost `
            -Arguments @($GuardedPackedDll)
        Add-Result 'dll.dynamic.runtime' `
            ($dynamicOriginal.exit_code -eq 0 -and
             $dynamicPacked.exit_code -eq 0 -and
             $dynamicOriginal.stdout -eq $dynamicPacked.stdout -and
             $dynamicOriginal.stderr -eq $dynamicPacked.stderr) `
            'dynamic host matches original DLL lifecycle' -Process $dynamicPacked

        $staticOriginal = Invoke-Captured -FilePath $StaticHost
        $staticDir = Join-Path $BuildDir (
            'production-static-' + [guid]::NewGuid().ToString('N'))
        try {
            New-Item -ItemType Directory -Path $staticDir | Out-Null
            $staticPackedHost = Join-Path $staticDir 'static_host.exe'
            $staticPackedDll = Join-Path $staticDir 'sample_dll.dll'
            Copy-Item -LiteralPath $StaticHost -Destination $staticPackedHost
            Copy-Item -LiteralPath $GuardedPackedDll -Destination $staticPackedDll
            $staticPacked = Invoke-Captured -FilePath $staticPackedHost
            Add-Result 'dll.static.runtime' `
                ($staticOriginal.exit_code -eq 0 -and
                 $staticPacked.exit_code -eq 0 -and
                 $staticOriginal.stdout -eq $staticPacked.stdout -and
                 $staticOriginal.stderr -eq $staticPacked.stderr) `
                'static-import host resolves packed exports before DllMain' `
                -Process $staticPacked
        }
        finally {
            Remove-Item -LiteralPath (Join-Path $staticDir 'static_host.exe'), `
                (Join-Path $staticDir 'sample_dll.dll') -Force `
                -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $staticDir -Force -ErrorAction SilentlyContinue
        }

        $reloadOriginal = Invoke-Captured -FilePath $ReloadHost `
            -Arguments @($GuardedDll)
        $reloadPacked = Invoke-Captured -FilePath $ReloadHost `
            -Arguments @($GuardedPackedDll)
        Add-Result 'dll.reload.runtime' `
            ($reloadOriginal.exit_code -eq 0 -and
             $reloadPacked.exit_code -eq 0 -and
             $reloadOriginal.stdout -eq $reloadPacked.stdout -and
             $reloadOriginal.stdout -like '*PASS cycles=8*') `
            'eight packed DLL load/call/unload cycles match original' `
            -Process $reloadPacked

        $cfgOriginal = Invoke-Captured -FilePath $CfgSuppressionHost `
            -Arguments @($GuardedDll)
        $cfgPacked = Invoke-Captured -FilePath $CfgSuppressionHost `
            -Arguments @($GuardedPackedDll)
        Add-Result 'dll.guardcf.suppression' `
            ($cfgOriginal.exit_code -eq -1073740791 -and
             $cfgPacked.exit_code -eq -1073740791 -and
             $cfgOriginal.stdout -eq $cfgPacked.stdout -and
             $cfgPacked.stdout -like '*cfg_suppression_host: armed*') `
            'requested export succeeds; unrequested suppressed target fail-fasts' `
            -Process $cfgPacked

        $preexistingOriginal = Invoke-Captured -FilePath $PreexistingTlsHost `
            -Arguments @($GuardedDll)
        $preexistingPacked = Invoke-Captured -FilePath $PreexistingTlsHost `
            -Arguments @($GuardedPackedDll)
        Add-Result 'dll.tls.preexisting' `
            ($preexistingOriginal.exit_code -eq 0 -and
             $preexistingPacked.exit_code -eq 0 -and
             $preexistingOriginal.stdout -eq $preexistingPacked.stdout -and
             $preexistingPacked.stdout -like '*main=105 pre=105 post=105 lifecycle=0*') `
            'pre-existing and post-load thread TLS semantics match original' `
            -Process $preexistingPacked

        foreach ($case in $AuxiliaryDllCases) {
            $auxOriginalDll = Join-Path $BuildDir $case.Dll
            $auxPackedDll = Join-Path $BuildDir $case.Packed
            $auxHost = Join-Path $BuildDir $case.Host
            $auxPack = Invoke-Captured -FilePath $PythonExe -Arguments @(
                $TestPacker, $auxOriginalDll, $auxPackedDll,
                '--enable-experimental-dll', '--stub-path', $StubPath)
            if ($auxPack.exit_code -ne 0 -or
                -not (Test-Path -LiteralPath $auxPackedDll)) {
                Add-Result $case.Id $false 'auxiliary DLL packing failed' `
                    -Process $auxPack
                continue
            }
            $auxOriginal = Invoke-Captured -FilePath $auxHost `
                -Arguments @($auxOriginalDll)
            $auxPacked = Invoke-Captured -FilePath $auxHost `
                -Arguments @($auxPackedDll)
            Add-Result $case.Id `
                ($auxOriginal.exit_code -eq 0 -and $auxPacked.exit_code -eq 0 -and
                 $auxOriginal.stdout -eq $auxPacked.stdout -and
                 $auxPacked.stdout -like "*$($case.Marker)*") `
                'auxiliary DLL lifecycle matches original' -Process $auxPacked
        }
    } else {
        foreach ($id in @('dll.dynamic.runtime', 'dll.static.runtime',
                          'dll.reload.runtime', 'dll.guardcf.suppression',
                          'dll.tls.preexisting')) {
            Add-Result $id $false 'not run because guarded DLL packing failed'
        }
        foreach ($case in $AuxiliaryDllCases) {
            Add-Result $case.Id $false 'not run because guarded DLL packing failed'
        }
    }
}
finally {
    Pop-Location
    Remove-Item -LiteralPath $CorePacked, $DelayPacked, $GuardedPackedDll `
        -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ResourceOffsetPackedDll -Force `
        -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $DelayPackedDll -Force `
        -ErrorAction SilentlyContinue
    foreach ($case in $AuxiliaryDllCases) {
        Remove-Item -LiteralPath (Join-Path $BuildDir $case.Packed) -Force `
            -ErrorAction SilentlyContinue
    }
}

$stubHash = (Get-FileHash -LiteralPath $StubPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host 'Collecting source provenance...'
if ($SourceCommit) {
    if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
        throw 'SourceCommit must be a full lowercase Git commit id'
    }
    $commit = $SourceCommit
    $dirty = $false
} else {
    $commit = (& git -C $Root rev-parse HEAD 2>$null).Trim()
    $dirty = [bool]((& git -C $Root status --porcelain --untracked-files=no 2>$null) |
        Select-Object -First 1)
}
$passed = @($script:Results | Where-Object { $_.status -eq 'passed' }).Count
$evidence = [pscustomobject][ordered]@{
    schema = 1
    source_commit = $commit
    tracked_source_dirty = $dirty
    stub_path = $StubPath
    stub_sha256 = $stubHash
    passed = $passed
    total = $script:Results.Count
    ready = $passed -eq $script:Results.Count
    tests = $script:Results
}
$evidenceDir = Split-Path $EvidencePath -Parent
if ($evidenceDir) {
    New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
}
Write-Host 'Writing machine-readable evidence...'
$evidence | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath $EvidencePath -Encoding utf8
Write-Host "Evidence: $EvidencePath"
Write-Host "$passed/$($script:Results.Count) compatibility checks passed"
exit $(if ($evidence.ready) { 0 } else { 1 })
