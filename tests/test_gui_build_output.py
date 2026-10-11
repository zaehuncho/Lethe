"""GUI output checks and real PowerShell recipe runs with a compiler double.

The synthetic PE fixture is never executed. These are artifact/recipe tests,
not Nuitka compilation, GUI smoke tests, or release approval.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tools import gui_build_output as build


ROOT = Path(__file__).resolve().parents[1]


def _pe() -> bytes:
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", image, 0x84, 0x8664, 1)
    struct.pack_into("<HH", image, 0x94, 0xF0, 0x22)
    struct.pack_into("<H", image, 0x98, 0x20B)
    struct.pack_into("<I", image, 0xA8, 0x1000)
    struct.pack_into("<Q", image, 0xB0, 0x140000000)
    struct.pack_into("<II", image, 0xB8, 0x1000, 0x200)
    struct.pack_into("<II", image, 0xD0, 0x2000, 0x200)
    struct.pack_into("<H", image, 0xDC, 2)
    struct.pack_into("<I", image, 0x104, 16)
    image[0x188:0x18D] = b".text"
    struct.pack_into("<IIII", image, 0x190, 1, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, 0x1AC, 0x60000020)
    image[0x200] = 0xC3
    return bytes(image)


def _artifact(tmp_path, layout="onefile"):
    root = tmp_path / "new output"
    prepared = build.prepare_output_directory(root)
    exe = root / ("Lethe.exe" if layout == "onefile" else "app.dist/Lethe.exe")
    exe.parent.mkdir(exist_ok=True)
    exe.write_bytes(_pe())
    return root, prepared["identity"], exe


@pytest.mark.parametrize("layout", ["onefile", "standalone"])
def test_expected_layout_returns_exact_snapshot_identity_size_and_digest(tmp_path, layout):
    root, identity, exe = _artifact(tmp_path, layout)
    before = exe.read_bytes()
    result = build.verify_build_output(root, identity=identity, layout=layout)
    assert result == {"schema": 1, "kind": "lethe-gui-build-output", "layout": layout,
                      "executable": str(exe), "size": len(before),
                      "sha256": hashlib.sha256(before).hexdigest(),
                      "output_identity": identity, "validation": "structural-only"}
    assert exe.read_bytes() == before


@pytest.mark.parametrize("existing", ["empty-directory", "directory-with-old-build", "file"])
def test_existing_output_is_preserved_and_never_reused(tmp_path, existing):
    root = tmp_path / "existing"
    if existing == "file":
        root.write_bytes(b"preserve-file")
    else:
        root.mkdir()
        if existing == "directory-with-old-build":
            (root / "Lethe.exe").write_bytes(b"preserve-old-build")
    before = root.stat()
    with pytest.raises(ValueError):
        build.prepare_output_directory(root)
    assert root.stat().st_ino == before.st_ino
    if existing == "file":
        assert root.read_bytes() == b"preserve-file"
    elif existing == "directory-with-old-build":
        assert (root / "Lethe.exe").read_bytes() == b"preserve-old-build"
    else:
        assert list(root.iterdir()) == []


def test_new_nested_output_is_allocated_once(tmp_path):
    root = tmp_path / "parent" / "child" / "new output"
    value = build.prepare_output_directory(root)
    assert value["output_dir"] == str(root) and value["identity"]
    assert list(root.iterdir()) == []
    with pytest.raises(ValueError, match="already exists"):
        build.prepare_output_directory(root)


@pytest.mark.parametrize("value", ["relative", "./relative", "C:relative"])
def test_ambiguous_directory_paths_reject(value):
    with pytest.raises(ValueError, match="absolute"):
        build.prepare_output_directory(value)


def test_parent_traversal_and_non_directory_ancestors_reject(tmp_path):
    with pytest.raises(ValueError, match="unambiguous"):
        build.prepare_output_directory(tmp_path / "parent" / ".." / "child")
    (tmp_path / "file").write_bytes(b"retain")
    with pytest.raises((ValueError, OSError)):
        build.prepare_output_directory(tmp_path / "file" / "child")
    assert (tmp_path / "file").read_bytes() == b"retain"


@pytest.mark.parametrize("linked_mode", ["symlink", "reparse"])
def test_linklike_directory_is_rejected_before_allocation(tmp_path, monkeypatch, linked_mode):
    root = tmp_path / "new"
    original = Path.lstat
    def linked(path):
        if path == tmp_path:
            return SimpleNamespace(st_mode=stat.S_IFLNK if linked_mode == "symlink" else stat.S_IFDIR,
                                   st_file_attributes=0x400 if linked_mode == "reparse" else 0)
        return original(path)
    monkeypatch.setattr(Path, "lstat", linked)
    with pytest.raises(ValueError, match="link or reparse"):
        build.prepare_output_directory(root)
    assert not root.exists()


def test_competing_allocation_never_reuses_winners_directory(tmp_path, monkeypatch):
    root = tmp_path / "new"
    original = Path.mkdir
    def raced(path, *args, **kwargs):
        if path == root:
            original(path)
            (path / "winner").write_bytes(b"preserve-winner")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "mkdir", raced)
    with pytest.raises(FileExistsError):
        build.prepare_output_directory(root)
    assert (root / "winner").read_bytes() == b"preserve-winner"


@pytest.mark.parametrize("identity", [None, True, "", "invalid", "0:0", "1:2:3"])
def test_invalid_output_identity_rejects(tmp_path, identity):
    root, _correct, _exe = _artifact(tmp_path)
    with pytest.raises(ValueError, match="invalid GUI output directory identity"):
        build.verify_build_output(root, identity=identity, layout="onefile")


def test_replaced_output_directory_is_rejected(tmp_path):
    root, identity, _exe = _artifact(tmp_path)
    retained = tmp_path / "retained-old-root"
    root.rename(retained)
    root.mkdir()
    (root / "Lethe.exe").write_bytes(_pe())
    with pytest.raises(ValueError, match="identity changed"):
        build.verify_build_output(root, identity=identity, layout="onefile")
    assert (retained / "Lethe.exe").read_bytes() == _pe()


def test_directory_change_during_verification_is_rejected(tmp_path, monkeypatch):
    root, identity, _exe = _artifact(tmp_path)
    original = build.snapshot_file
    def snapshot_then_replace(path, **kwargs):
        image = original(path, **kwargs)
        root.rename(tmp_path / "retained")
        root.mkdir()
        return image
    monkeypatch.setattr(build, "snapshot_file", snapshot_then_replace)
    with pytest.raises(ValueError, match="identity changed during verification"):
        build.verify_build_output(root, identity=identity, layout="onefile")


def test_standalone_parent_replacement_during_verification_is_rejected(tmp_path, monkeypatch):
    root, identity, exe = _artifact(tmp_path, "standalone")
    original = build.snapshot_file
    def snapshot_then_replace(path, **kwargs):
        image = original(path, **kwargs)
        exe.parent.rename(root / "retained.dist")
        exe.parent.mkdir()
        return image
    monkeypatch.setattr(build, "snapshot_file", snapshot_then_replace)
    with pytest.raises(ValueError, match="parent identity changed"):
        build.verify_build_output(root, identity=identity, layout="standalone")


@pytest.mark.parametrize("layout", ["onefile", "standalone"])
def test_missing_output_or_wrong_layout_is_not_success(tmp_path, layout):
    root = tmp_path / "new"
    identity = build.prepare_output_directory(root)["identity"]
    wrong = root / ("app.dist/Lethe.exe" if layout == "onefile" else "Lethe.exe")
    wrong.parent.mkdir(exist_ok=True)
    wrong.write_bytes(_pe())
    with pytest.raises((ValueError, OSError)):
        build.verify_build_output(root, identity=identity, layout=layout)
    assert wrong.read_bytes() == _pe()


@pytest.mark.parametrize("mutation", ["empty", "dos", "signature", "optional-truncated",
                                     "arch", "pe32", "dll", "not-executable", "console",
                                     "section-range", "entry-zero", "entry-outside-image",
                                     "entry-not-executable", "entry-zero-fill"])
def test_invalid_pe_kind_and_architecture_fail_without_changing_output(tmp_path, mutation):
    root, identity, exe = _artifact(tmp_path)
    data = bytearray(_pe())
    if mutation == "empty": data.clear()
    elif mutation == "dos": data[:2] = b"NO"
    elif mutation == "signature": data[0x80:0x84] = b"NOPE"
    elif mutation == "optional-truncated": del data[0x100:]
    elif mutation == "arch": struct.pack_into("<H", data, 0x84, 0x14C)
    elif mutation == "pe32": struct.pack_into("<H", data, 0x98, 0x10B)
    elif mutation == "dll": struct.pack_into("<H", data, 0x96, 0x2022)
    elif mutation == "not-executable": struct.pack_into("<H", data, 0x96, 0x20)
    elif mutation == "console": struct.pack_into("<H", data, 0xDC, 3)
    elif mutation == "section-range": struct.pack_into("<I", data, 0x19C, 0xFFFFFF00)
    elif mutation == "entry-zero": struct.pack_into("<I", data, 0xA8, 0)
    elif mutation == "entry-outside-image": struct.pack_into("<I", data, 0xA8, 0x3000)
    elif mutation == "entry-not-executable": struct.pack_into("<I", data, 0x1AC, 0x40000040)
    elif mutation == "entry-zero-fill":
        struct.pack_into("<I", data, 0xA8, 0x1300)
        struct.pack_into("<I", data, 0x190, 0x1000)
    exe.write_bytes(data)
    with pytest.raises(ValueError):
        build.verify_build_output(root, identity=identity, layout="onefile")
    assert exe.read_bytes() == bytes(data)


def test_real_hardlinked_executable_is_rejected(tmp_path):
    root, identity, exe = _artifact(tmp_path)
    os.link(exe, tmp_path / "owned-alias.exe")
    with pytest.raises(ValueError, match="hard-linked"):
        build.verify_build_output(root, identity=identity, layout="onefile")
    assert exe.read_bytes() == _pe()


def test_output_size_is_bounded_before_pe_parse(tmp_path, monkeypatch):
    root, identity, exe = _artifact(tmp_path)
    monkeypatch.setattr(build, "MAX_GUI_EXE_BYTES", 8)
    monkeypatch.setattr(build, "parse_pe_image", lambda *_a, **_kw: pytest.fail("parse preceded size bound"))
    with pytest.raises(ValueError, match="max_bytes"):
        build.verify_build_output(root, identity=identity, layout="onefile")
    assert exe.read_bytes() == _pe()


def test_unknown_layout_is_rejected(tmp_path):
    root, identity, _exe = _artifact(tmp_path)
    with pytest.raises(ValueError, match="layout"):
        build.verify_build_output(root, identity=identity, layout="unknown")


def test_cli_returns_json_on_success_and_nonzero_on_missing_output(tmp_path, capsys):
    root = tmp_path / "new"
    assert build.main(["prepare", "--output-dir", str(root)]) == 0
    identity = json.loads(capsys.readouterr().out)["identity"]
    args = ["verify", "--output-dir", str(root), "--identity", identity, "--layout", "onefile"]
    assert build.main(args) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "GUI build output verify failed:" in captured.err
    (root / "Lethe.exe").write_bytes(_pe())
    assert build.main(args) == 0
    assert json.loads(capsys.readouterr().out)["validation"] == "structural-only"


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell recipe")
@pytest.mark.parametrize("standalone", [False, True])
@pytest.mark.parametrize("case", ["success", "missing", "invalid", "compiler-error", "existing"])
def test_actual_powershell_recipe_with_compiler_double(tmp_path, case, standalone):
    ps = os.environ.get("LETHE_GUI_TEST_POWERSHELL",
                        str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"))
    assert Path(ps).is_file(), "PowerShell is required for Windows recipe coverage"
    payload = tmp_path / "structural-fixture.bin"
    payload.write_bytes(_pe())
    output = tmp_path / "gui output [literal]"
    if case == "existing":
        output.mkdir()
        (output / "Lethe.exe").write_bytes(b"preserve-original")
    script = tmp_path / "compiler-double.ps1"
    script.write_text('''param([string]$Recipe,[string]$OutputDir,[string]$StubPath,[string]$Case,[switch]$Standalone)
$ErrorActionPreference = 'Stop'
$BeforeLocation = (Get-Location).ProviderPath
$global:CompilerCalls = 0
function Invoke-LetheCompilerDouble {
    if ($args -contains 'nuitka') {
        $global:CompilerCalls += 1
        if ($Case -eq 'compiler-error') { $global:LASTEXITCODE = 17; return }
        if ($Case -eq 'success' -or $Case -eq 'invalid') {
            $DirectoryArg = @($args | Where-Object { $_ -like '--output-dir=*' })
            if ($DirectoryArg.Count -ne 1) { throw 'compiler output argument missing' }
            $Directory = $DirectoryArg[0].Substring('--output-dir='.Length)
            if ($args -notcontains '--onefile') { $Directory = Join-Path $Directory 'app.dist' }
            [System.IO.Directory]::CreateDirectory($Directory) | Out-Null
            $Bytes = if ($Case -eq 'success') { [System.IO.File]::ReadAllBytes($env:LETHE_GUI_TEST_PAYLOAD) } else { [byte[]]@(1,2,3) }
            [System.IO.File]::WriteAllBytes((Join-Path $Directory 'Lethe.exe'), $Bytes)
        }
        $global:LASTEXITCODE = 0
        return
    }
    & $env:LETHE_GUI_TEST_PYTHON @args
    $global:LASTEXITCODE = $LASTEXITCODE
}
try {
    & $Recipe -PythonExe Invoke-LetheCompilerDouble -OutputDir $OutputDir -StubPath $StubPath -SkipStubCheck -NoOnefile:$Standalone
    if ((Get-Location).ProviderPath -ne $BeforeLocation) { throw 'caller location changed' }
    Write-Output "RECIPE_ACCEPTED calls=$global:CompilerCalls location_restored=true"
    exit 0
} catch {
    if ((Get-Location).ProviderPath -ne $BeforeLocation) { Write-Output 'LOCATION_CHANGED'; exit 9 }
    Write-Output "RECIPE_REJECTED calls=$global:CompilerCalls location_restored=true reason=$($_.Exception.Message)"
    exit 2
}
''', encoding="utf-8")
    env = os.environ.copy()
    env.update(LETHE_GUI_TEST_PAYLOAD=str(payload), LETHE_GUI_TEST_PYTHON=sys.executable)
    command = [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script),
               "-Recipe", str(ROOT / "gui/build_gui.ps1"), "-OutputDir", str(output),
               "-StubPath", str(tmp_path / "missing-stub.dll"), "-Case", case]
    if standalone:
        command.append("-Standalone")
    result = subprocess.run(command, cwd=tmp_path, env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    log = result.stdout + result.stderr
    assert "location_restored=true" in log, log
    if case == "success":
        assert result.returncode == 0 and "RECIPE_ACCEPTED calls=1" in log, log
        expected = output / ("app.dist/Lethe.exe" if standalone else "Lethe.exe")
        assert "OK  built: " + str(expected) in log
        assert hashlib.sha256(_pe()).hexdigest() in log
        assert expected.read_bytes() == _pe()
    else:
        assert result.returncode == 2 and "OK  built:" not in log, log
        if case == "existing":
            assert "RECIPE_REJECTED calls=0" in log
            assert "GUI output directory preflight failed" in log
            assert (output / "Lethe.exe").read_bytes() == b"preserve-original"
        elif case == "compiler-error":
            assert "Nuitka build failed with exit code 17" in log
        else:
            assert "GUI build output verification failed" in log
