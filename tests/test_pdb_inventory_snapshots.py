"""DIA provenance must bind execution to the bytes that were hashed."""

from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from lifter import pdb_function_inventory as inv
from packer import pe_analyze
from test_pdb_function_inventory import fixture_image, fixture_parsed, helper_output


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    paths = [tmp_path / name for name in ("image.exe", "input.pdb", "helper.exe", "dia.dll")]
    contents = [bytes(fixture_image()), b"pinned PDB", b"pinned helper", b"pinned DIA"]
    for path, content in zip(paths, contents):
        path.write_bytes(content)
    parsed = fixture_parsed()
    parsed.path = str(paths[0])
    analyzed = []

    def analyze(path):
        analyzed.append(Path(path))
        return parsed

    monkeypatch.setattr(pe_analyze, "analyze_pe", analyze)
    if os.name != "nt":
        # DIA itself is Windows-only. Portable tests exercise snapshot routing;
        # the Windows-only test below independently exercises mandatory locks.
        @contextmanager
        def no_windows_locks(paths):
            yield
        monkeypatch.setattr(inv, "_seal_snapshot_paths", no_windows_locks, raising=False)
    return SimpleNamespace(paths=paths, contents=contents, parsed=parsed, analyzed=analyzed)


def terminal(output=None, *, returncode=0, stderr=b""):
    if output is None:
        output = helper_output((0x1000, 0x10), (0x1020, 2)).encode("ascii")
    return SimpleNamespace(returncode=returncode, stdout=output, stderr=stderr)


def run(fixture):
    return inv.run_bound_inventory(fixture.parsed, *fixture.paths)


def test_helper_and_analyzer_use_independent_exact_snapshot_files(inputs, monkeypatch):
    observed = []

    def helper(command, **kwargs):
        observed.extend(Path(item) for item in command)
        assert kwargs == {"capture_output": True, "timeout": 300, "check": False}
        assert [path.read_bytes() for path in observed] == [inputs.contents[i] for i in (2, 3, 1)]
        assert not set(observed) & set(inputs.paths)
        assert len({path.parent for path in observed}) == 1
        return terminal()

    monkeypatch.setattr(inv.subprocess, "run", helper)
    result = run(inputs)
    assert result.image_sha256 == sha256(inputs.contents[0]).hexdigest()
    assert result.pdb_sha256 == sha256(inputs.contents[1]).hexdigest()
    assert result.helper_sha256 == sha256(inputs.contents[2]).hexdigest()
    assert result.msdia_sha256 == sha256(inputs.contents[3]).hexdigest()
    assert len(inputs.analyzed) == 1 and inputs.analyzed[0] != inputs.paths[0]
    assert inputs.analyzed[0].parent == observed[0].parent
    assert all(not path.exists() for path in [*observed, *inputs.analyzed])
    assert not observed[0].parent.exists()


@pytest.mark.parametrize("source_index,command_index", [(1, 2), (2, 0), (3, 1)])
def test_transient_source_replacement_cannot_change_hashed_helper_inputs(
    inputs, monkeypatch, source_index, command_index
):
    """Pre/post hashes miss ABA replacements; the helper must read a snapshot."""
    original = inputs.paths[source_index]
    pinned = original.read_bytes()

    def helper(command, **kwargs):
        original.write_bytes(b"transient replacement with the same PDB identity")
        try:
            observed = Path(command[command_index]).read_bytes()
        finally:
            original.write_bytes(pinned)
        rva = 0x1020 if observed == pinned else 0x1030
        return terminal(helper_output((0x1000, 0x10), (rva, 2)).encode("ascii"))

    monkeypatch.setattr(inv.subprocess, "run", helper)
    result = run(inputs)
    assert result.supplemental_ranges == ((0x1020, 0x1022),)
    assert original.read_bytes() == pinned


def test_analyzer_reads_pinned_image_despite_transient_original_replacement(inputs, monkeypatch):
    original = inputs.paths[0]
    observed = []

    def analyze(path):
        original.write_bytes(b"transient different PE")
        try:
            observed.append(Path(path).read_bytes())
        finally:
            original.write_bytes(inputs.contents[0])
        return inputs.parsed

    monkeypatch.setattr(pe_analyze, "analyze_pe", analyze)
    monkeypatch.setattr(inv.subprocess, "run", lambda *a, **k: terminal())
    run(inputs)
    assert observed == [inputs.contents[0]]


@pytest.mark.parametrize("index,diagnostic", [
    (0, "PE changed during PDB inventory"), (1, "PDB changed during inventory"),
    (2, "DIA helper changed during inventory"), (3, "DIA runtime changed during inventory"),
])
def test_persistent_original_changes_still_fail_closed(inputs, monkeypatch, index, diagnostic):
    observed = []

    def helper(command, **kwargs):
        observed.extend(Path(item) for item in command)
        inputs.paths[index].write_bytes(b"changed source")
        return terminal()

    monkeypatch.setattr(inv.subprocess, "run", helper)
    with pytest.raises(inv.PdbInventoryError, match=diagnostic):
        run(inputs)
    assert all(path in inputs.paths or not path.exists() for path in observed)


@pytest.mark.parametrize("failure,diagnostic", [
    ("exit", "failed or emitted diagnostics"),
    ("stderr", "failed or emitted diagnostics"),
    ("nonascii", "not ASCII"),
    ("oversized", "failed or emitted diagnostics"),
    ("protocol", "invalid DIA"),
    ("timeout", "did not complete"),
    ("oserror", "did not complete"),
])
def test_failed_helper_releases_and_cleans_snapshots(inputs, monkeypatch, failure, diagnostic):
    observed = []

    def helper(command, **kwargs):
        observed.extend(Path(item) for item in command)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 300)
        if failure == "oserror":
            raise OSError("fixture launch failed")
        if failure == "exit":
            return terminal(returncode=1)
        if failure == "stderr":
            return terminal(stderr=b"DIA diagnostic")
        if failure == "nonascii":
            return terminal(b"\xff")
        if failure == "oversized":
            return terminal(b"x" * 16_000_001)
        return terminal(b"not the inventory protocol\n")

    monkeypatch.setattr(inv.subprocess, "run", helper)
    with pytest.raises(inv.PdbInventoryError, match=diagnostic):
        run(inputs)
    assert all(path in inputs.paths or not path.exists() for path in observed)
    if observed[0] not in inputs.paths:
        assert not observed[0].parent.exists()
    assert [path.read_bytes() for path in inputs.paths] == inputs.contents


@pytest.mark.skipif(os.name != "nt", reason="mandatory Windows share-mode sealing")
def test_windows_snapshots_deny_write_delete_and_replace_during_helper(inputs, monkeypatch):
    def helper(command, **kwargs):
        paths = [*map(Path, command), *inputs.analyzed]
        assert not set(paths) & set(inputs.paths)
        for index, path in enumerate(paths):
            with pytest.raises(PermissionError):
                path.write_bytes(b"snapshot tamper")
            with pytest.raises(PermissionError):
                path.unlink()
            other = path.parent / f"replacement-{index}.tmp"
            other.write_bytes(b"snapshot replacement")
            with pytest.raises(PermissionError):
                other.replace(path)
            other.unlink()
        parent = paths[0].parent
        moved = parent.with_name(parent.name + "-unexpected-rename")
        try:
            with pytest.raises(PermissionError):
                parent.rename(moved)
        finally:
            if moved.exists() and not parent.exists():
                moved.rename(parent)
        return terminal()

    monkeypatch.setattr(inv.subprocess, "run", helper)
    assert run(inputs).supplemental_ranges == ((0x1020, 0x1022),)


def test_parsed_geometry_mismatch_cleans_snapshots_without_running_helper(inputs, monkeypatch):
    def different(path):
        inputs.analyzed.append(Path(path))
        parsed = fixture_parsed()
        parsed.size_of_image += 0x1000
        return parsed

    monkeypatch.setattr(pe_analyze, "analyze_pe", different)
    monkeypatch.setattr(inv.subprocess, "run", lambda *a, **k: pytest.fail("helper must not run"))
    with pytest.raises(inv.PdbInventoryError, match="differs from current image"):
        run(inputs)
    assert all(path == inputs.paths[0] or not path.exists() for path in inputs.analyzed)


def test_snapshot_sealing_failure_cleans_prepared_files(inputs, monkeypatch):
    prepared = []

    @contextmanager
    def fail_to_seal(paths):
        prepared.extend(paths)
        raise inv.PdbInventoryError("fixture sealing failure")
        yield  # pragma: no cover - contextmanager protocol

    monkeypatch.setattr(inv, "_seal_snapshot_paths", fail_to_seal, raising=False)
    monkeypatch.setattr(inv.subprocess, "run", lambda *a, **k: pytest.fail("helper must not run"))
    with pytest.raises(inv.PdbInventoryError, match="sealing failure"):
        run(inputs)
    assert len(prepared) == 4 and all(not path.exists() for path in prepared)
    assert not prepared[0].parent.exists()
