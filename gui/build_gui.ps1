<#
.SYNOPSIS
    Freeze the Lethe GUI (gui/app.py) into a single Lethe.exe with Nuitka.

.DESCRIPTION
    Produces a standalone, one-file Lethe.exe -- the clickable internal build
    tool. It embeds the packer library, its PE/crypto dependencies (LIEF +
    cryptography), the PySide6 runtime, and the prebuilt native stub as bundled
    data. Lethe produces protected first-party binaries and is never shipped
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
            --include-data-files=<repo>/stub/prebuilt/lethe_stub_x64.dll=stub/prebuilt/lethe_stub_x64.dll ^
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
    Where Lethe.exe is written. Default: <packer>/build.

.PARAMETER StubPath
    Path to the prebuilt native stub to bundle.
    Default: <packer>/stub/prebuilt/lethe_stub_x64.dll.

.PARAMETER NoOnefile
    Build a --standalone .dist/ folder instead of a single .exe (faster to
    iterate; useful for debugging what got bundled).

.PARAMETER SkipStubCheck
    Build even if the prebuilt stub is missing (the resulting exe cannot pack
    until the stub is present -- for smoke-testing the freeze only).

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

if (-not $OutputDir) { $OutputDir = Join-Path $PackerRoot "build" }
if (-not $StubPath)  { $StubPath  = Join-Path $PackerRoot "stub\prebuilt\lethe_stub_x64.dll" }

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

Build it first (produces stub/prebuilt/lethe_stub_x64.dll), e.g.:
    stub/build_stub.ps1

Or re-run with -SkipStubCheck to freeze the UI without packing capability.
"@
    }
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

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
    # single argv token: "--include-data-files=<abs src>=stub/prebuilt/lethe_stub_x64.dll"
    $NuitkaArgs += "--include-data-files=$StubPath=stub/prebuilt/lethe_stub_x64.dll"
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
    & $PythonExe @NuitkaArgs
} finally {
    Pop-Location
}

if ($LASTEXITCODE -ne 0) {
    throw "Nuitka build failed with exit code $LASTEXITCODE"
}

$ExePath = Join-Path $OutputDir "Lethe.exe"
Write-Host ""
if (Test-Path $ExePath) {
    Write-Host "OK  built: $ExePath" -ForegroundColor Green
} else {
    Write-Warning "Nuitka reported success but Lethe.exe was not found in $OutputDir (a --standalone build lands in a .dist/ folder)."
}
