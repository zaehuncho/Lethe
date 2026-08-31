<#
.SYNOPSIS
    Compile the Lethe round-trip sample binaries with MSVC (x64), using the
    same hardening spirit as the real Orion targets (/guard:cf, /DYNAMICBASE,
    /NXCOMPAT, /HIGHENTROPYVA).

.DESCRIPTION
    Produces, in -OutDir (default: <this dir>\build):
        sample_exe.exe   console EXE: imports + __declspec(thread) + C++ throw/catch
        sample_dll.dll   DLL with DllMain + exports for value and static TLS
        host.exe         loads a DLL, asserts DllMain + loading/worker TLS

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
$CommonC   = @('/nologo', '/W3', '/Gy', '/guard:cf')
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

    # sample_exe.exe -- /TP forces C++ so throw/catch => real x64 SEH; /EHsc EH.
    Invoke-Cl -What 'sample_exe.exe' -ClArgs (
        $CommonC + $OptC + @('/TP', '/EHsc', "/Fo:$ObjDir\", "/Fe:sample_exe.exe", $exeSrc,
            '/link') + $LinkFlags)

    # sample_dll.dll -- /LD builds a DLL (compiled as C).
    Invoke-Cl -What 'sample_dll.dll' -ClArgs (
        $CommonC + $OptC + @('/LD', "/Fo:$ObjDir\", "/Fe:sample_dll.dll", $dllSrc,
            '/link') + $LinkFlags)

    # host.exe -- plain C console host.
    Invoke-Cl -What 'host.exe' -ClArgs (
        $CommonC + $OptC + @("/Fo:$ObjDir\", "/Fe:host.exe", $hostSrc,
            '/link') + $LinkFlags)
}
finally {
    Pop-Location
}

$built = @('sample_exe.exe', 'sample_dll.dll', 'host.exe') |
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
