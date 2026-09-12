<#
.SYNOPSIS
    Build the native EXE compatibility corpus with MSVC x64.

.DESCRIPTION
    Builds two intentionally different EXEs. The core fixture omits load-config
    so resources and DIR64/ASLR behavior can be isolated. The delay-load fixture
    uses current MSVC GuardCF/XFG metadata so preservation bugs cannot be hidden
    by weakening compiler or linker flags.
#>
[CmdletBinding()]
param(
    [string]$OutDir = ''
)

$ErrorActionPreference = 'Stop'
$OutDir = if ($OutDir) {
    [System.IO.Path]::GetFullPath($OutDir)
} else {
    Join-Path $PSScriptRoot 'production-build'
}
$SampleDir = Join-Path $PSScriptRoot 'sample'

function Write-Step($message) {
    Write-Host "[build_production_corpus] $message"
}

function Initialize-MsvcX64 {
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
        return $true
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        return $false
    }
    $vsRoot = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null | Select-Object -First 1
    if (-not $vsRoot) {
        return $false
    }
    $vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path -LiteralPath $vcvars)) {
        return $false
    }
    & cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            Set-Item -Path ("Env:" + $matches[1]) -Value $matches[2] -ErrorAction SilentlyContinue
        }
    }
    return [bool](Get-Command cl.exe -ErrorAction SilentlyContinue)
}

function Invoke-Tool {
    param(
        [string]$Name,
        [string[]]$ToolArgs
    )
    Write-Step "$Name $($ToolArgs -join ' ')"
    & $Name @ToolArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

if (-not (Initialize-MsvcX64)) {
    Write-Step 'SKIP: Visual Studio x64 C/C++ tools are unavailable.'
    exit 3
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$ObjDir = Join-Path $OutDir 'obj'
New-Item -ItemType Directory -Force -Path $ObjDir | Out-Null

$dependencySource = Join-Path $SampleDir 'compat_dependency.c'
$coreSource = Join-Path $SampleDir 'compat_core_exe.c'
$exeSource = Join-Path $SampleDir 'compat_exe.c'
$resourceSource = Join-Path $SampleDir 'compat_exe.rc'
$dependencyObject = Join-Path $ObjDir 'compat_dependency.obj'
$coreObject = Join-Path $ObjDir 'compat_core_exe.obj'
$exeObject = Join-Path $ObjDir 'compat_exe.obj'
$resourceObject = Join-Path $ObjDir 'compat_exe.res'
$dependencyDll = Join-Path $OutDir 'compat_dependency.dll'
$dependencyLib = Join-Path $OutDir 'compat_dependency.lib'
$coreExe = Join-Path $OutDir 'compat_core_exe.exe'
$delayExe = Join-Path $OutDir 'compat_delay_exe.exe'
$delayDllSource = Join-Path $SampleDir 'compat_delay_dll.c'
$delayDllHostSource = Join-Path $SampleDir 'compat_delay_dll_host.c'
$delayDllObject = Join-Path $ObjDir 'compat_delay_dll.obj'
$delayDllHostObject = Join-Path $ObjDir 'compat_delay_dll_host.obj'
$delayDll = Join-Path $OutDir 'compat_delay_dll.dll'
$delayDllLib = Join-Path $OutDir 'compat_delay_dll.lib'
$delayDllHost = Join-Path $OutDir 'compat_delay_dll_host.exe'

Invoke-Tool 'cl.exe' @(
    '/nologo', '/W4', '/WX', '/O2', '/MD', '/GS-', '/guard:cf-', '/c',
    "/Fo:$dependencyObject", $dependencySource)
Invoke-Tool 'link.exe' @(
    '/NOLOGO', '/DLL', '/DYNAMICBASE', '/NXCOMPAT', '/HIGHENTROPYVA',
    "/OUT:$dependencyDll", "/IMPLIB:$dependencyLib", $dependencyObject)

Invoke-Tool 'rc.exe' @('/nologo', "/fo$resourceObject", $resourceSource)
Invoke-Tool 'cl.exe' @(
    '/nologo', '/W4', '/WX', '/O2', '/GS-', '/guard:cf-', '/c',
    "/Fo:$coreObject", $coreSource)
Invoke-Tool 'link.exe' @(
    '/NOLOGO', '/NODEFAULTLIB', '/SUBSYSTEM:CONSOLE', '/ENTRY:compat_core_entry',
    '/DYNAMICBASE', '/NXCOMPAT', '/HIGHENTROPYVA', '/BASE:0x146000000',
    "/OUT:$coreExe", $coreObject, $resourceObject, 'kernel32.lib')

Invoke-Tool 'cl.exe' @(
    '/nologo', '/W4', '/WX', '/O2', '/MD', '/guard:cf', '/c',
    "/Fo:$exeObject", $exeSource)
Invoke-Tool 'link.exe' @(
    '/NOLOGO', '/DYNAMICBASE', '/NXCOMPAT', '/HIGHENTROPYVA', '/guard:cf',
    '/BASE:0x145000000', '/DELAYLOAD:compat_dependency.dll',
    "/OUT:$delayExe", "/LIBPATH:$OutDir", $exeObject, $resourceObject,
    'compat_dependency.lib', 'delayimp.lib')

Invoke-Tool 'cl.exe' @(
    '/nologo', '/W4', '/WX', '/O2', '/MD', '/guard:cf', '/c',
    "/Fo:$delayDllObject", $delayDllSource)
Invoke-Tool 'link.exe' @(
    '/NOLOGO', '/DLL', '/DYNAMICBASE', '/NXCOMPAT', '/HIGHENTROPYVA',
    '/guard:cf', '/DELAYLOAD:compat_dependency.dll', '/DELAY:UNLOAD',
    "/OUT:$delayDll", "/IMPLIB:$delayDllLib", "/LIBPATH:$OutDir",
    $delayDllObject, 'compat_dependency.lib', 'delayimp.lib')
Invoke-Tool 'cl.exe' @(
    '/nologo', '/W4', '/WX', '/O2', '/MD', '/guard:cf', '/c',
    "/Fo:$delayDllHostObject", $delayDllHostSource)
Invoke-Tool 'link.exe' @(
    '/NOLOGO', '/DYNAMICBASE', '/NXCOMPAT', '/HIGHENTROPYVA', '/guard:cf',
    "/OUT:$delayDllHost", $delayDllHostObject)

foreach ($artifact in @($dependencyDll, $dependencyLib, $coreExe, $delayExe,
                         $delayDll, $delayDllLib, $delayDllHost)) {
    if (-not (Test-Path -LiteralPath $artifact)) {
        throw "missing expected artifact: $artifact"
    }
}

$sampleBuilder = Join-Path $PSScriptRoot 'build_samples.ps1'
& powershell -NoProfile -ExecutionPolicy Bypass -File $sampleBuilder `
    -OutDir $OutDir -Config Release
if ($LASTEXITCODE -ne 0) {
    throw "guarded DLL corpus build failed with exit code $LASTEXITCODE"
}

Write-Step "OK: corpus built under $OutDir"
exit 0
