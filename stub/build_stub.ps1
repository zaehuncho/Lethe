<#
.SYNOPSIS
    Build the Lethe stub DLL (lethe_stub_x64.dll).
.DESCRIPTION
    Configures and builds the stub using CMake + VS2022 x64.
    On success copies the DLL to stub/prebuilt/lethe_stub_x64.dll
    (the post-build step in CMakeLists.txt handles the copy).
.PARAMETER Clean
    Remove the build directory before configuring.
.PARAMETER Config
    Build configuration: Release (default) or RelWithDebInfo.
#>
param(
    [switch]$Clean,
    [ValidateSet('Release','RelWithDebInfo')]
    [string]$Config = 'Release'
)

$ErrorActionPreference = 'Stop'

$StubDir  = $PSScriptRoot
$BuildDir = Join-Path $StubDir 'build'

if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "Cleaning $BuildDir ..."
    Remove-Item $BuildDir -Recurse -Force
}

if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

Write-Host "`n=== CMake Configure (VS2022 x64, $Config) ==="
cmake -S $StubDir -B $BuildDir `
      -G "Visual Studio 17 2022" `
      -A x64
if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake configure failed (exit $LASTEXITCODE)"
    exit 1
}

Write-Host "`n=== CMake Build ($Config) ==="
cmake --build $BuildDir --config $Config
if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake build failed (exit $LASTEXITCODE)"
    exit 1
}

$Prebuilt = Join-Path (Join-Path $StubDir 'prebuilt') 'lethe_stub_x64.dll'
if (Test-Path $Prebuilt) {
    $info = Get-Item $Prebuilt
    Write-Host "`nStub ready: $Prebuilt ($([math]::Round($info.Length / 1KB, 1)) KB)"
} else {
    Write-Error "Post-build copy failed - $Prebuilt not found"
    exit 1
}
