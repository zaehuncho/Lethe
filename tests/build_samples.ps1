<#
.SYNOPSIS
    Compile the Lethe round-trip sample binaries with MSVC (x64), using the
    same hardening spirit as the real Orion targets (/guard:cf, /DYNAMICBASE,
    /NXCOMPAT, /HIGHENTROPYVA).

.DESCRIPTION
    Produces, in -OutDir (default: <this dir>\build):
        sample_exe.exe   console EXE: imports + __declspec(thread) + C++ throw/catch
        sample_dll.dll   DLL with DllMain + exports for value and static TLS
        host.exe         dynamically loads a DLL and checks its lifecycle
        static_host.exe  imports sample_dll.dll before either DllMain executes
        reload_host.exe  repeats LoadLibrary/call/FreeLibrary in one process
        noentry_dll.dll   has no PE entry point; its host covers pre/post threads
        reject_dll.dll    rejects PROCESS_ATTACH; its host covers clean retries
        unwind_dll.dll    throws/catches across protected x64 unwind metadata
        resource_offset_dll.dll has a resource root at a nonzero section offset

    Finds cl.exe automatically: if already on PATH (running inside a Native Tools
    prompt) it is used as-is; otherwise vswhere locates the latest VS and
    vcvars64.bat is imported into this session.

.OUTPUTS
    Exit 0 = all three built.  Exit 3 = SKIP (no MSVC toolchain found -- not a
    failure, the harness treats this as "cannot build here").  Exit 1 = a
    compile/link actually failed.
#>
[CmdletBinding()]
param(
    [string]$OutDir = '',
    [ValidateSet('Release', 'Debug')]
    [string]$Config = 'Release'
)

$ErrorActionPreference = 'Stop'
$OutDir = if ($OutDir) { $OutDir } else { Join-Path $PSScriptRoot 'build' }
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
$SampleDir = Join-Path $PSScriptRoot 'sample'

function Write-Step($m) { Write-Host "[build_samples] $m" }

# --- locate the MSVC x64 toolchain ----------------------------------------
function Initialize-MsvcX64 {
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
        Write-Step 'cl.exe already on PATH (using current developer environment).'
        return $true
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        Write-Step "vswhere not found at $vswhere"
        return $false
    }
    $vsRoot = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null | Select-Object -First 1
    if (-not $vsRoot) {
        Write-Step 'vswhere found no VS install with the VC x64 toolset.'
        return $false
    }
    $vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path -LiteralPath $vcvars)) {
        Write-Step "vcvars64.bat not found under $vsRoot"
        return $false
    }
    Write-Step "Importing MSVC x64 environment from: $vcvars"
    # Run the batch file and copy the resulting environment into this session.
    & cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            Set-Item -Path ("Env:" + $matches[1]) -Value $matches[2] -ErrorAction SilentlyContinue
        }
    }
    return [bool](Get-Command cl.exe -ErrorAction SilentlyContinue)
}

if (-not (Initialize-MsvcX64)) {
    Write-Step 'SKIP: no MSVC (cl.exe) x64 toolchain available on this machine.'
    exit 3
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$ObjDir = Join-Path $OutDir 'obj'
New-Item -ItemType Directory -Force -Path $ObjDir | Out-Null

# Hardening flags shared with the real Orion binaries (plan: /guard:cf etc.).
$CommonC   = @('/nologo', '/W4', '/WX', '/Gy', '/guard:cf')
$OptC      = if ($Config -eq 'Release') { @('/O2', '/MD', '/DNDEBUG') } else { @('/Od', '/MDd', '/Zi') }
$LinkFlags = @('/DYNAMICBASE', '/NXCOMPAT', '/HIGHENTROPYVA', '/guard:cf')

function Invoke-Cl {
    # NB: do NOT name this parameter $Args -- that shadows PowerShell's automatic
    # $Args and the splat silently expands to nothing.
    param([string[]]$ClArgs, [string]$What)
    Write-Step "cl $What"
    & cl.exe @ClArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Step "FAIL: compiling/linking $What (cl exit $LASTEXITCODE)"
        exit 1
    }
}

Push-Location $OutDir
try {
    $exeSrc  = Join-Path $SampleDir 'sample_exe.c'
    $dllSrc  = Join-Path $SampleDir 'sample_dll.c'
    $hostSrc = Join-Path $SampleDir 'host.c'
    $staticHostSrc = Join-Path $SampleDir 'static_host.c'
    $reloadHostSrc = Join-Path $SampleDir 'reload_host.c'
    $cfgSuppressionHostSrc = Join-Path $SampleDir 'cfg_suppression_host.c'
    $noentryDllSrc = Join-Path $SampleDir 'noentry_dll.c'
    $noentryHostSrc = Join-Path $SampleDir 'noentry_host.c'
    $rejectDllSrc = Join-Path $SampleDir 'reject_dll.c'
    $rejectHostSrc = Join-Path $SampleDir 'reject_host.c'
    $unwindDllSrc = Join-Path $SampleDir 'unwind_dll.cpp'
    $unwindHostSrc = Join-Path $SampleDir 'unwind_host.c'
    $preexistingTlsHostSrc = Join-Path $SampleDir 'preexisting_tls_host.c'
    $tlsfreeDllSrc = Join-Path $SampleDir 'tlsfree_dll.c'
    $tlsfreeHostSrc = Join-Path $SampleDir 'tlsfree_host.c'
    $returnEntrySrc = Join-Path $SampleDir 'return_entry_exe.c'
    $resourceOffsetDllSrc = Join-Path $SampleDir 'resource_offset_dll.c'
    $resourceOffsetRcSrc = Join-Path $SampleDir 'resource_offset_dll.rc'
    $resourceOffsetHostSrc = Join-Path $SampleDir 'resource_offset_host.c'
    $resourceOffsetRes = Join-Path $ObjDir 'resource_offset_dll.res'

    # sample_exe.exe -- /TP forces C++ so throw/catch => real x64 SEH; /EHsc EH.
    Invoke-Cl -What 'sample_exe.exe' -ClArgs (
        $CommonC + $OptC + @('/TP', '/EHsc', "/Fo:$ObjDir\", "/Fe:sample_exe.exe", $exeSrc,
            '/link') + $LinkFlags)

    # sample_dll.dll -- /LD builds a DLL (compiled as C).
    Invoke-Cl -What 'sample_dll.dll' -ClArgs (
        $CommonC + $OptC + @('/LD', "/Fo:$ObjDir\", "/Fe:sample_dll.dll", $dllSrc,
            '/link') + $LinkFlags)

    Write-Step 'rc resource_offset_dll.res'
    & rc.exe /nologo "/fo$resourceOffsetRes" $resourceOffsetRcSrc
    if ($LASTEXITCODE -ne 0) {
        Write-Step "FAIL: compiling resource_offset_dll.rc (rc exit $LASTEXITCODE)"
        exit 1
    }
    Invoke-Cl -What 'resource_offset_dll.dll' -ClArgs (
        $CommonC + $OptC + @('/LD', "/Fo:$ObjDir\",
            "/Fe:resource_offset_dll.dll", $resourceOffsetDllSrc,
            $resourceOffsetRes, '/link') + $LinkFlags)
    $resourceShift = Join-Path $PSScriptRoot 'shift_resource_root.py'
    & python $resourceShift (Join-Path $OutDir 'resource_offset_dll.dll') `
        --shift 0x40
    if ($LASTEXITCODE -ne 0) {
        Write-Step "FAIL: shifting resource directory root (exit $LASTEXITCODE)"
        exit 1
    }

    # host.exe -- plain C console host.
    Invoke-Cl -What 'host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:host.exe", $hostSrc,
            '/link') + $LinkFlags)
    Invoke-Cl -What 'resource_offset_host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:resource_offset_host.exe",
            $resourceOffsetHostSrc, '/link') + $LinkFlags)

    # static_host.exe -- link against the fixture's import library. This host
    # proves Windows can resolve a packed DLL's exports before StubDllMain.
    Invoke-Cl -What 'static_host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:static_host.exe", $staticHostSrc,
            (Join-Path $OutDir 'sample_dll.lib'), '/link') + $LinkFlags)

    Invoke-Cl -What 'reload_host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:reload_host.exe", $reloadHostSrc,
            '/link') + $LinkFlags)

    Invoke-Cl -What 'cfg_suppression_host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:cfg_suppression_host.exe",
            $cfgSuppressionHostSrc, '/link') + $LinkFlags)
    $cfgPatch = Join-Path $PSScriptRoot 'enable_cfg_export_suppression.py'
    & python $cfgPatch (Join-Path $OutDir 'cfg_suppression_host.exe')
    if ($LASTEXITCODE -ne 0) {
        Write-Step "FAIL: enabling CFG export suppression (exit $LASTEXITCODE)"
        exit 1
    }

    Invoke-Cl -What 'noentry_dll.dll' -ClArgs (
        $CommonC + $OptC + @('/LD', '/GS-', "/Fo:$ObjDir\",
            "/Fe:noentry_dll.dll", $noentryDllSrc, '/link', '/NOENTRY') +
            $LinkFlags)
    Invoke-Cl -What 'noentry_host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:noentry_host.exe",
            $noentryHostSrc, '/link') + $LinkFlags)

    Invoke-Cl -What 'reject_dll.dll' -ClArgs (
        $CommonC + $OptC + @('/LD', "/Fo:$ObjDir\", "/Fe:reject_dll.dll",
            $rejectDllSrc, '/link') + $LinkFlags)
    Invoke-Cl -What 'reject_host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:reject_host.exe",
            $rejectHostSrc, '/link') + $LinkFlags)

    Invoke-Cl -What 'unwind_dll.dll' -ClArgs (
        $CommonC + $OptC + @('/TP', '/EHsc', '/LD', "/Fo:$ObjDir\",
            "/Fe:unwind_dll.dll", $unwindDllSrc, '/link') + $LinkFlags)
    Invoke-Cl -What 'unwind_host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:unwind_host.exe",
            $unwindHostSrc, '/link') + $LinkFlags)
    Invoke-Cl -What 'preexisting_tls_host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:preexisting_tls_host.exe",
            $preexistingTlsHostSrc, '/link') + $LinkFlags)
    Invoke-Cl -What 'tlsfree_dll.dll' -ClArgs (
        $CommonC + $OptC + @('/LD', "/Fo:$ObjDir\", "/Fe:tlsfree_dll.dll",
            $tlsfreeDllSrc, '/link') + $LinkFlags)
    Invoke-Cl -What 'tlsfree_host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:tlsfree_host.exe",
            $tlsfreeHostSrc, '/link') + $LinkFlags)
    Invoke-Cl -What 'return_entry_exe.exe' -ClArgs (
        @('/nologo', '/W4', '/WX', '/O2', '/GS-', '/guard:cf-', '/c',
          "/Fo:$ObjDir\return_entry_exe.obj", $returnEntrySrc))
    Write-Step 'link return_entry_exe.exe'
    & link.exe /NOLOGO /NODEFAULTLIB /SUBSYSTEM:CONSOLE /ENTRY:return_37 `
        /FIXED /NXCOMPAT `
        "/OUT:return_entry_exe.exe" "$ObjDir\return_entry_exe.obj" kernel32.lib
    if ($LASTEXITCODE -ne 0) {
        Write-Step "FAIL: linking return_entry_exe.exe (exit $LASTEXITCODE)"
        exit 1
    }

}
finally {
    Pop-Location
}

$built = @('sample_exe.exe', 'sample_dll.dll', 'host.exe', 'static_host.exe',
           'reload_host.exe', 'cfg_suppression_host.exe', 'noentry_dll.dll',
           'noentry_host.exe', 'reject_dll.dll', 'reject_host.exe',
           'unwind_dll.dll', 'unwind_host.exe', 'preexisting_tls_host.exe',
           'tlsfree_dll.dll', 'tlsfree_host.exe', 'return_entry_exe.exe',
           'resource_offset_dll.dll', 'resource_offset_host.exe') |
    ForEach-Object { Join-Path $OutDir $_ }
foreach ($b in $built) {
    if (-not (Test-Path -LiteralPath $b)) {
        Write-Step "FAIL: expected artifact missing: $b"
        exit 1
    }
}

Write-Step "OK: built the following in $OutDir"
$built | ForEach-Object { Write-Host "        $_" }
exit 0
