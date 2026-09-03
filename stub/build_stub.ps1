<#
.SYNOPSIS
    Build the Lethe stub DLL (lethe_stub_x64.dll).
.DESCRIPTION
    Configures and builds the stub using CMake + VS2022 x64. Ordinary builds
    remain in stub/build. This script never updates the tracked prebuilt.
.PARAMETER Clean
    Remove the build directory before configuring.
.PARAMETER Config
    Build configuration: Release (default) or RelWithDebInfo.
.PARAMETER Promote
    Retired compatibility switch. It fails closed and points to the staged
    release-candidate workflow.
.PARAMETER ShuffleSeed
    Optional hexadecimal opcode-shuffle seed for a reproducible release build.
#>
param(
    [switch]$Clean,
    [switch]$Promote,
    [ValidateSet('Release','RelWithDebInfo')]
    [string]$Config = 'Release',
    [string]$ShuffleSeed = ''
)

$ErrorActionPreference = 'Stop'

$StubDir  = $PSScriptRoot
$BuildDir = Join-Path $StubDir 'build'
$RepoDir  = Split-Path $StubDir -Parent

if ($ShuffleSeed -and $ShuffleSeed -notmatch '^[0-9A-Fa-f]+$') {
    throw 'ShuffleSeed must contain hexadecimal characters only.'
}
if ($Promote) {
    throw 'Direct prebuilt promotion is disabled. Use tools/promote_stub.py to produce a fully gated staging bundle; review and publication remain separate.'
}

$SourceCommit = (& git -C $RepoDir rev-parse HEAD 2>$null)
if (-not $SourceCommit) { $SourceCommit = 'unknown' }
$SourceDirty = [bool](& git -C $RepoDir status --porcelain --untracked-files=all 2>$null)

if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "Cleaning $BuildDir ..."
    Remove-Item $BuildDir -Recurse -Force
}

if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

Write-Host "`n=== CMake Configure (VS2022 x64, $Config) ==="
$CMakeArgs = @(
    '-S', $StubDir,
    '-B', $BuildDir,
    '-G', 'Visual Studio 17 2022',
    '-A', 'x64',
    "-DDVM_SHUFFLE_SEED=$ShuffleSeed"
)
& cmake @CMakeArgs
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

$Built = Join-Path (Join-Path $BuildDir $Config) 'lethe_stub_x64.dll'
if (-not (Test-Path -LiteralPath $Built)) {
    Write-Error "Build output missing: $Built"
    exit 1
}

$SeedFile = Join-Path $BuildDir 'daedalus_opcodes_shuffled.py'
$EffectiveSeed = ''
$HandlerVariantHash = ''
if (Test-Path -LiteralPath $SeedFile) {
    $SeedLine = Select-String -LiteralPath $SeedFile -Pattern '^BUILD_SEED\s*=\s*[''\"]([0-9a-fA-F]+)[''\"]' | Select-Object -First 1
    if ($SeedLine) { $EffectiveSeed = $SeedLine.Matches[0].Groups[1].Value }
    $HandlerHashLine = Select-String -LiteralPath $SeedFile -Pattern '^HANDLER_VARIANT_SHA256\s*=\s*[''\"]([0-9a-fA-F]{64})[''\"]' | Select-Object -First 1
    if ($HandlerHashLine) { $HandlerVariantHash = $HandlerHashLine.Matches[0].Groups[1].Value.ToLowerInvariant() }
}
if ($HandlerVariantHash -notmatch '^[0-9a-f]{64}$') {
    throw "Generated native-handler provenance is missing or malformed: $SeedFile"
}

$BuiltInfo = Get-Item -LiteralPath $Built
$CachePath = Join-Path $BuildDir 'CMakeCache.txt'
if (-not (Test-Path -LiteralPath $CachePath)) {
    throw "CMake cache missing after configure: $CachePath"
}
$CacheText = Get-Content -LiteralPath $CachePath -Raw
function Get-CMakeBool([string]$Name) {
    $Match = [regex]::Match(
        $CacheText,
        "(?m)^$([regex]::Escape($Name)):BOOL=(ON|OFF)\r?$")
    if (-not $Match.Success) {
        throw "CMake option $Name is missing from $CachePath"
    }
    return $Match.Groups[1].Value -eq 'ON'
}
$DvmRolling = Get-CMakeBool 'DVM_ROLLING'
$MemguardKalypso = Get-CMakeBool 'MEMGUARD_KALYPSO'
$NativeRoundtrip = 'not-run'
$ProvenanceStatus = if ($SourceCommit -eq 'unknown') {
    'partial'
} elseif ($SourceDirty) {
    'dirty'
} else {
    'clean'
}
$Manifest = [ordered]@{
    schema             = 1
    artifact           = 'lethe_stub_x64.dll'
    sha256             = (Get-FileHash -LiteralPath $Built -Algorithm SHA256).Hash.ToLowerInvariant()
    size_bytes         = $BuiltInfo.Length
    source_commit      = $SourceCommit.Trim()
    source_dirty       = $SourceDirty
    configuration      = $Config
    cmake_generator    = 'Visual Studio 17 2022'
    cmake_version      = ((& cmake --version | Select-Object -First 1) -replace '^cmake version\s+', '')
    python_version     = (& python --version 2>&1) -replace '^Python\s+', ''
    dvm_shuffle_seed   = $EffectiveSeed
    dvm_handler_variant_sha256 = $HandlerVariantHash
    dvm_rolling        = $DvmRolling
    dvm_paged_runtime  = $true
    memguard_kalypso   = $MemguardKalypso
    native_roundtrip   = $NativeRoundtrip
    validation_utc     = $null
    provenance_status  = $ProvenanceStatus
}
$ManifestPath = "$Built.manifest.json"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    $ManifestPath, (($Manifest | ConvertTo-Json) + [Environment]::NewLine), $Utf8NoBom)

Write-Host "`nStub ready: $Built ($([math]::Round($BuiltInfo.Length / 1KB, 1)) KB)"
Write-Host "Manifest:  $ManifestPath"
Write-Host 'Tracked prebuilt files were not modified.'
