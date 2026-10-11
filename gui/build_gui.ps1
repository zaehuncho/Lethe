<#
.SYNOPSIS
    Freeze the Lethe GUI (gui/app.py) into a single Lethe.exe with Nuitka.

.DESCRIPTION
    Produces a standalone, one-file Lethe.exe -- the clickable internal build
    tool. It embeds the packer library, its PE/crypto dependencies (LIEF +
    cryptography), the PySide6 runtime, and a complete approved release bundle
    with its public trust/matrix/evidence resources as exact bundled data.
    Lethe produces protected first-party binaries and is never shipped
    to customers, so freezing it is fine.

    Uses the project's Nuitka standalone build shape -- the same
    --standalone / --assume-yes-for-downloads / --windows-console-mode=disable
    spine, plus --onefile and the PySide6 plugin.

    ------------------------------------------------------------------------
    EXACT INVOCATION (what this script runs; paths shown relative to repo root
    Lethe):

        python -m nuitka ^
            --standalone ^
            --onefile ^
            --assume-yes-for-downloads ^
            --enable-plugin=pyside6 ^
            --windows-console-mode=disable ^
            --include-package=packer ^
            --include-package=lief ^
            --include-package=cryptography ^
            --include-module=tools.production_gate ^
            --include-data-files=<private-stage>/<resource>=<resource> ^
            --output-filename=Lethe.exe ^
            --output-dir=<packer>/build ^
            --remove-output ^
            gui/app.py

    Why the explicit --include-package flags: app.py imports the packer core
    lazily (on the worker thread), and the core imports LIEF / cryptography
    inside submodules. Nuitka's static import analysis can miss those deferred
    imports, so we force-include the whole packages.

    ------------------------------------------------------------------------
    STUB-PATH RESOLUTION REQUIREMENT (the assembler MUST honor this):

    The prebuilt native stub is bundled as DATA at the dist-relative path
    "stub/prebuilt/lethe_stub_x64.dll". At runtime pack_file()/assemble.py must
    locate it RELATIVE TO the packer package -- specifically, the PARENT of the
    `packer` package directory -- which resolves correctly in BOTH modes:

        # in packer/assemble.py (or wherever the stub is loaded):
        _here = os.path.dirname(os.path.abspath(__file__))   # .../packer
        _root = os.path.dirname(_here)                       # dist root (frozen)
                                                             #  OR Lethe (source)
        STUB_PATH = os.path.join(_root, "stub", "prebuilt", "lethe_stub_x64.dll")

      * Source run:  _root = Lethe, so the stub is found at
                     stub/prebuilt/lethe_stub_x64.dll.
      * Frozen one-file: Nuitka extracts everything to a temp dist dir; the
                     `packer` package lands at <dist>/packer and the bundled
                     data at <dist>/stub/prebuilt/lethe_stub_x64.dll, so the
                     same parent-of-package join lands on it.

    The DEST half of --include-data-files below is chosen to make that single
    resolution rule work unchanged in both cases. Do NOT resolve the stub from
    sys.argv[0]/sys.executable -- for one-file builds those point at the ORIGINAL
    exe, not the temp dist dir where the data actually lives.

.PARAMETER PythonExe
    Python interpreter to build with. Default: "python".

.PARAMETER OutputDir
    New output directory for this build. It must not already exist; previous
    builds are never cleaned or overwritten. Default: <packer>/build.
    Onefile output is Lethe.exe; standalone output is app.dist/Lethe.exe.

.PARAMETER StubPath
    Path to the canonical lethe_stub_x64.dll in a complete approved release
    bundle. Raw builds and unsigned candidates do not satisfy this contract.
    Default: <packer>/stub/prebuilt/lethe_stub_x64.dll.

.PARAMETER NoOnefile
    Build a --standalone .dist/ folder instead of a single .exe (faster to
    iterate; useful for debugging what got bundled).

.PARAMETER SkipStubCheck
    Build the UI only if the prebuilt stub is missing. This never relaxes
    verification for an existing stub; the UI-only build cannot pack.

.NOTES
    Toolchain (validate this exact combination before each release):
      * Python  : 3.12, matching pyproject.toml and uv.lock.
      * Nuitka  : >= 4.1.3.
      * MSVC    : Visual Studio 2022 C++ toolset (14.x); Nuitka auto-detects it
                  and, with --assume-yes-for-downloads, fetches ccache /
                  dependency-walker without prompting.
      * PySide6 : LGPL, the same Qt stack the app uses; --enable-plugin=pyside6
                  bundles the required Qt plugins.

    Install the locked build dependencies from the repository root first:
        uv sync --frozen --group gui-build

    Then use the virtual-environment interpreter:
        .\gui\build_gui.ps1 -PythonExe .\.venv\Scripts\python.exe

    First-time onefile Qt builds are large and can take several minutes.
#>
[CmdletBinding()]
param(
    [string]$PythonExe = "python",
    [string]$OutputDir,
    [string]$StubPath,
    [switch]$NoOnefile,
    [switch]$SkipStubCheck
)

$ErrorActionPreference = "Stop"

# --- resolve layout from the script location -------------------------------
$GuiDir     = $PSScriptRoot                              # gui
$PackerRoot = Split-Path $GuiDir -Parent                 # Lethe
$Entry      = Join-Path $GuiDir "app.py"
$InvocationRoot = (Get-Location).ProviderPath

function Get-InvocationPath([string]$Value) {
    if ($Value -match '^[A-Za-z]:(?![\\/])') {
        throw "Drive-relative paths are ambiguous: $Value"
    }
    if ($Value -match '^[\\/](?![\\/])') {
        return [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetPathRoot($InvocationRoot)) $Value.TrimStart([char[]]'\/')))
    }
    if ([System.IO.Path]::IsPathRooted($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $InvocationRoot $Value))
}

if (-not $OutputDir) { $OutputDir = Join-Path $PackerRoot "build" }
if (-not $StubPath)  { $StubPath  = Join-Path $PackerRoot "stub\prebuilt\lethe_stub_x64.dll" }
$OutputDir = Get-InvocationPath $OutputDir
$StubPath = Get-InvocationPath $StubPath
# Preserve PATH-based names such as python/python.exe; anchor explicit paths.
if ($PythonExe -match '[\\/]' -or [System.IO.Path]::IsPathRooted($PythonExe)) {
    $PythonExe = Get-InvocationPath $PythonExe
}

if (-not (Test-Path $Entry)) {
    throw "GUI entry script not found: $Entry"
}

# --- prebuilt stub (bundled as data) ---------------------------------------
$IncludeStub = $true
if (-not (Test-Path $StubPath)) {
    if ($SkipStubCheck) {
        Write-Warning "Prebuilt stub not found at: $StubPath"
        Write-Warning "Building WITHOUT the stub (-SkipStubCheck). The frozen exe cannot pack until the stub is bundled."
        $IncludeStub = $false
    } else {
        throw @"
Prebuilt native stub not found:
    $StubPath

Supply the canonical DLL in a complete, independently approved release bundle.
An ordinary native build or unsigned validation candidate is not sufficient.

Or re-run with -SkipStubCheck to freeze the UI without packing capability.
"@
    }
}

# Preflight with the existing release verifier, then consume only retained,
# hash-pinned data. No directory wildcard includes or key/signing discovery.
$BundleHelper = Join-Path $PackerRoot 'tools\gui_bundle.py'
$ResourcePlan = $null
if ($IncludeStub) {
    $ResourceStage = Join-Path ([System.IO.Path]::GetTempPath()) ("lethe-gui-bundle-" + [guid]::NewGuid().ToString('N'))
    $PlanOutput = & $PythonExe -B $BundleHelper prepare --stub-path $StubPath --output-dir $ResourceStage
    if ($LASTEXITCODE -ne 0) { throw 'GUI release resource preflight failed; compiler was not started.' }
    $ResourcePlan = ($PlanOutput -join "`n") | ConvertFrom-Json
}

function Assert-ResourcePlan {
    if ($null -ne $ResourcePlan) {
        & $PythonExe -B $BundleHelper validate --plan $ResourcePlan.plan_path --plan-sha256 $ResourcePlan.plan_sha256 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'GUI release resources changed or no longer verify.' }
    }
}

Assert-ResourcePlan
$OutputHelper = Join-Path $PackerRoot 'tools\gui_build_output.py'
$OutputStateJson = & $PythonExe -B $OutputHelper prepare --output-dir $OutputDir
if ($LASTEXITCODE -ne 0) { throw 'GUI output directory preflight failed; compiler was not started.' }
$OutputState = ($OutputStateJson -join "`n") | ConvertFrom-Json
if (-not $OutputState.identity) { throw 'GUI output directory identity was not returned.' }

# --- assemble the Nuitka command -------------------------------------------
# The DEST of --include-data-files ("stub/prebuilt/lethe_stub_x64.dll") is
# dist-root-relative on purpose -- see the STUB-PATH RESOLUTION note above.
$NuitkaArgs = @(
    "-m", "nuitka",
    "--standalone",
    "--assume-yes-for-downloads",
    "--enable-plugin=pyside6",
    "--windows-console-mode=disable",
    "--include-package=packer",         # force the lazily-imported core in
    "--include-package=lief",           # PE analysis (compiled extension)
    "--include-package=cryptography",   # AES-256-GCM / SHA-256 (compiled backend)
    "--include-module=tools.production_gate", # runtime release-evidence replay
    "--company-name=Orion",
    "--product-name=Lethe",
    "--file-description=Lethe x64 PE packer (internal build tool)",
    "--file-version=0.1.0",
    "--product-version=0.1.0",
    "--output-filename=Lethe.exe",
    "--output-dir=$OutputDir",
    "--remove-output"
)

if (-not $NoOnefile) {
    $NuitkaArgs += "--onefile"
}

if ($IncludeStub) {
    # Explicit per-file mapping preserves original .py evidence as DATA too.
    # The helper rejects pattern/separator characters and destination collisions.
    foreach ($Resource in $ResourcePlan.resources) {
        $DataSource = Join-Path $ResourcePlan.staged_root $Resource.destination
        $NuitkaArgs += "--include-data-files=$DataSource=$($Resource.destination)"
    }
}

$NuitkaArgs += $Entry

# --- run --------------------------------------------------------------------
Write-Host "Lethe GUI freeze" -ForegroundColor Cyan
Write-Host "  python     : $PythonExe"
Write-Host "  entry      : $Entry"
Write-Host "  output dir : $OutputDir"
Write-Host "  stub       : $(if ($IncludeStub) { $StubPath } else { '(omitted)' })"
Write-Host "  onefile    : $(-not $NoOnefile)"
Write-Host ""
Write-Host "> $PythonExe $($NuitkaArgs -join ' ')" -ForegroundColor DarkGray
Write-Host ""

Push-Location $PackerRoot
try {
    Assert-ResourcePlan
    & $PythonExe @NuitkaArgs
    $NuitkaExitCode = $LASTEXITCODE
    Assert-ResourcePlan
} finally {
    Pop-Location
}

if ($NuitkaExitCode -ne 0) {
    throw "Nuitka build failed with exit code $NuitkaExitCode"
}

$Layout = if ($NoOnefile) { 'standalone' } else { 'onefile' }
$BuildResultJson = & $PythonExe -B $OutputHelper verify --output-dir $OutputDir --identity $OutputState.identity --layout $Layout
if ($LASTEXITCODE -ne 0) { throw 'GUI build output verification failed; no successful build is reported.' }
$BuildResult = ($BuildResultJson -join "`n") | ConvertFrom-Json
Write-Host ""
Write-Host "OK  built: $($BuildResult.executable)" -ForegroundColor Green
Write-Host "  SHA-256    : $($BuildResult.sha256)"
Write-Host "  bytes      : $($BuildResult.size)"
Write-Host "  validation : structural artifact check; runtime acceptance is separate"
