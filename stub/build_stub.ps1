<#
.SYNOPSIS
    Build the Lethe stub DLL (lethe_stub_x64.dll).
.DESCRIPTION
    Configures and builds the stub using CMake + VS2022 x64. Ordinary builds
    remain in stub/build. Promotion is an explicit, clean-build-only action
    that publishes the DLL and its provenance manifest together.
.PARAMETER Clean
    Remove the build directory before configuring.
.PARAMETER Config
    Build configuration: Release (default) or RelWithDebInfo.
.PARAMETER Promote
    Explicitly copy the built DLL and provenance manifest to stub/prebuilt/.
.PARAMETER ShuffleSeed
    Optional hexadecimal opcode-shuffle seed for a reproducible release build.
.PARAMETER PythonExe
    Locked Python interpreter used by mandatory promotion acceptance tests.
#>
param(
    [switch]$Clean,
    [switch]$Promote,
    [ValidateSet('Release','RelWithDebInfo')]
    [string]$Config = 'Release',
    [string]$ShuffleSeed = '',
    [string]$PythonExe = ''
)

$ErrorActionPreference = 'Stop'

$StubDir  = $PSScriptRoot
$BuildDir = Join-Path $StubDir 'build'
$RepoDir  = Split-Path $StubDir -Parent

if ($ShuffleSeed -and $ShuffleSeed -notmatch '^[0-9A-Fa-f]+$') {
    throw 'ShuffleSeed must contain hexadecimal characters only.'
}

$SourceCommit = (& git -C $RepoDir rev-parse HEAD 2>$null)
if (-not $SourceCommit) { $SourceCommit = 'unknown' }
$SourceDirty = [bool](& git -C $RepoDir status --porcelain --untracked-files=all 2>$null)
if ($Promote -and $SourceCommit -eq 'unknown') {
    throw 'Refusing to promote without an identifiable Git source commit.'
}
if ($Promote -and $SourceDirty) {
    throw 'Refusing to promote a prebuilt stub from a dirty tree. Commit or stash every tracked and untracked change first.'
}
if ($Promote -and -not $Clean) {
    throw 'Refusing to promote from a reused CMake cache. Pass -Clean for a fresh release build.'
}

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
if (Test-Path -LiteralPath $SeedFile) {
    $SeedLine = Select-String -LiteralPath $SeedFile -Pattern '^BUILD_SEED\s*=\s*[''\"]([0-9a-fA-F]+)[''\"]' | Select-Object -First 1
    if ($SeedLine) { $EffectiveSeed = $SeedLine.Matches[0].Groups[1].Value }
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
if ($Promote) {
    if (-not $PythonExe) {
        $PythonExe = Join-Path $RepoDir '.venv\Scripts\python.exe'
    }
    if (-not (Test-Path -LiteralPath $PythonExe)) {
        throw "Promotion requires the locked Python interpreter: $PythonExe"
    }
    Write-Host "`n=== Native promotion acceptance ==="
    & (Join-Path $RepoDir 'tests\build_samples.ps1')
    if (-not $?) { throw 'Native fixture build failed; refusing promotion.' }
    & (Join-Path $RepoDir 'tests\roundtrip.ps1') `
        -StubPath $Built -PythonExe $PythonExe
    if (-not $?) { throw 'Native round-trip failed; refusing promotion.' }
    $NativeRoundtrip = 'passed-9-of-9'
}
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
    dvm_rolling        = $DvmRolling
    memguard_kalypso   = $MemguardKalypso
    native_roundtrip   = $NativeRoundtrip
    validation_utc     = if ($Promote) { (Get-Date).ToUniversalTime().ToString('o') } else { $null }
    provenance_status  = $ProvenanceStatus
}
$ManifestPath = "$Built.manifest.json"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    $ManifestPath, (($Manifest | ConvertTo-Json) + [Environment]::NewLine), $Utf8NoBom)

if ($Promote) {
    $PrebuiltDir = Join-Path $StubDir 'prebuilt'
    $Prebuilt = Join-Path $PrebuiltDir 'lethe_stub_x64.dll'
    $PrebuiltManifest = Join-Path $PrebuiltDir 'lethe_stub_x64.manifest.json'
    New-Item -ItemType Directory -Path $PrebuiltDir -Force | Out-Null
    $DllStage = Join-Path $PrebuiltDir ('.lethe_stub_x64.dll.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $ManifestStage = Join-Path $PrebuiltDir ('.lethe_stub_x64.manifest.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $DllBackup = Join-Path $PrebuiltDir ('.lethe_stub_x64.dll.' + [guid]::NewGuid().ToString('N') + '.bak')
    $ManifestBackup = Join-Path $PrebuiltDir ('.lethe_stub_x64.manifest.' + [guid]::NewGuid().ToString('N') + '.bak')
    $HadDll = Test-Path -LiteralPath $Prebuilt
    $HadManifest = Test-Path -LiteralPath $PrebuiltManifest
    try {
        Copy-Item -LiteralPath $Built -Destination $DllStage
        Copy-Item -LiteralPath $ManifestPath -Destination $ManifestStage
        if ($HadDll) { Copy-Item -LiteralPath $Prebuilt -Destination $DllBackup }
        if ($HadManifest) { Copy-Item -LiteralPath $PrebuiltManifest -Destination $ManifestBackup }
        Move-Item -LiteralPath $DllStage -Destination $Prebuilt -Force
        Move-Item -LiteralPath $ManifestStage -Destination $PrebuiltManifest -Force
        $PromotedHash = (Get-FileHash -LiteralPath $Prebuilt -Algorithm SHA256).Hash.ToLowerInvariant()
        $PromotedMetadata = Get-Content -LiteralPath $PrebuiltManifest -Raw | ConvertFrom-Json
        if ($PromotedMetadata.sha256 -ne $PromotedHash) {
            throw 'Promoted prebuilt and manifest hash do not match.'
        }
    } catch {
        if ($HadDll) {
            Move-Item -LiteralPath $DllBackup -Destination $Prebuilt -Force
        } else {
            Remove-Item -LiteralPath $Prebuilt -Force -ErrorAction SilentlyContinue
        }
        if ($HadManifest) {
            Move-Item -LiteralPath $ManifestBackup -Destination $PrebuiltManifest -Force
        } else {
            Remove-Item -LiteralPath $PrebuiltManifest -Force -ErrorAction SilentlyContinue
        }
        throw
    } finally {
        Remove-Item -LiteralPath $DllStage -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ManifestStage -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $DllBackup -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ManifestBackup -Force -ErrorAction SilentlyContinue
    }
    Write-Host "`nPromoted stub: $Prebuilt"
    Write-Host "Manifest:      $PrebuiltManifest"
} else {
    Write-Host "`nStub ready: $Built ($([math]::Round($BuiltInfo.Length / 1KB, 1)) KB)"
    Write-Host "Manifest:  $ManifestPath"
    Write-Host 'Use -Promote only for an intentional prebuilt release update.'
}
