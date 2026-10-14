"""Selected final-link direct calls are a narrow, fail-closed proof."""

from __future__ import annotations

from types import SimpleNamespace
import os
from pathlib import Path
import struct
import sys
import time

import pytest

from lifter import link_capture_final_callsites as final


def _response(icf: str = "/OPT:ICF") -> dict:
    return {"switches": ["/OUT:.\\unit.exe", "/MACHINE:X64",
                         "/OPT:REF", icf, "/BREPRO", "/DEBUG:FULL",
                         "/INCREMENTAL:NO", "/MAP", "/guard:cf",
                         "/pdb:.\\unit.pdb", "/implib:.\\unit.lib"]}


@pytest.mark.parametrize("icf", ["/OPT:ICF", "/OPT:NOICF"])
def test_exact_icf_mode_is_explicit(icf):
    final._required_response(_response(icf), "unit.exe")


@pytest.mark.parametrize("mutate", [
    lambda x: x.remove("/OPT:ICF"),
    lambda x: x.append("/OPT:NOICF"),
    lambda x: x.append("/OPT:REF"),
    lambda x: x.append("/OUT:.\\other.exe"),
    lambda x: x.remove("/BREPRO"),
    lambda x: x.append("/OPT:NOREF"),
    lambda x: x.append("/VERBOSE:ICF"),
])
def test_missing_or_ambiguous_link_mode_rejects(mutate):
    response = _response()
    mutate(response["switches"])
    with pytest.raises(final.FinalCallsiteError):
        final._required_response(response, "unit.exe")


def _coff(*, kind: int = 4, code: bytes = b"\xe8\0\0\0\0\xc3") -> bytes:
    """One AMD64 executable COMDAT with one primary and one relocation."""
    dataoff = 60
    reloff = dataoff + len(code)
    symptr = reloff + 10
    raw = bytearray(symptr + 18 + 4)
    struct.pack_into("<HHIIIHH", raw, 0, 0x8664, 1, 0, symptr, 1, 0, 0)
    raw[20:28] = b".text\0\0\0"
    struct.pack_into("<III", raw, 36, len(code), dataoff, reloff)
    struct.pack_into("<H", raw, 52, 1)
    struct.pack_into("<I", raw, 56, 0x60001020)
    raw[dataoff:dataoff + len(code)] = code
    struct.pack_into("<IIH", raw, reloff, 1, 0, kind)
    raw[symptr:symptr + 8] = b"primary\0"
    struct.pack_into("<IhHBB", raw, symptr + 8, 0, 1, 0x20, 2, 0)
    struct.pack_into("<I", raw, symptr + 18, 4)
    return bytes(raw)


def test_exact_primary_call_coff_parses():
    section = final._coff_primary(_coff(), "caller.obj", 1, 1)
    assert (section.primary, section.body, section.reloc_fields) == (
        "primary", b"\xe8\0\0\0\0\xc3", (1,))


@pytest.mark.parametrize("raw,reason", [
    (_coff(kind=5), "unsupported relocation"),
    (_coff(code=b"\xe9\0\0\0\0\xc3"), "omit selected E8"),
])
def test_unsupported_coff_rejects(raw, reason):
    with pytest.raises(final.FinalCallsiteError, match=reason):
        final._coff_primary(raw, "caller.obj", 1, 1)


def test_exact_discard_and_unknown_icf_log_forms():
    marker = b"(primary) from caller.obj"
    assert final._discarded(b'  Discarded "x" ' + marker + b"\r\n",
                            "primary", "caller.obj")
    assert not final._discarded(b"unrelated\r\n", "primary", "caller.obj")
    for log in (b"Selected symbol: " + marker,
                b"Folded " + marker,
                b'Discarded "x" ' + marker + b"\n" +
                b'Discarded "y" ' + marker):
        with pytest.raises(final.FinalCallsiteError):
            final._discarded(log, "primary", "caller.obj")


def _linked(monkeypatch, body: bytes, *, spans=None, rows=None,
            log: bytes = b""):
    section = final._coff_primary(_coff(), "caller.obj", 1, 1)
    parsed = SimpleNamespace(image_base=0x140000000)
    inventory = SimpleNamespace(inventory=SimpleNamespace(
        range_multiplicities=spans if spans is not None else
        [(0x1000, 0x1006, 1)]))
    monkeypatch.setattr(final.direct_control_flow, "_normalize_sections",
                        lambda *_: ())
    monkeypatch.setattr(final.direct_control_flow, "_read_executable",
                        lambda *_: body)
    return final._linked_callsite(
        section,
        rows if rows is not None else
        (("primary", 0x140001000, "caller.obj"),),
        inventory, parsed, 0x2000, log)


def test_output_call_masks_only_declared_rel32_bytes(monkeypatch):
    linked = b"\xe8" + struct.pack("<i", 0x2000 - 0x1005) + b"\xc3"
    ip, proof = _linked(monkeypatch, linked)
    assert (ip, proof["status"], proof["rel32_fields"]) == (
        0x1000, "retained_direct_call", 1)
    with pytest.raises(final.FinalCallsiteError, match="outside declared REL32"):
        _linked(monkeypatch, linked[:-1] + b"\x90")
    with pytest.raises(final.FinalCallsiteError, match="resolves away"):
        _linked(monkeypatch, b"\xe8" + struct.pack("<i", 0x2001 - 0x1005) + b"\xc3")
    with pytest.raises(final.FinalCallsiteError, match="missing or aliased"):
        _linked(monkeypatch, linked, spans=[(0x1000, 0x1006, 2)])
    with pytest.raises(final.FinalCallsiteError, match="MAP ownership"):
        _linked(monkeypatch, linked,
                rows=(("primary", 0x140001000, "other.obj"),))


def test_discarded_caller_must_be_absent_from_map(monkeypatch):
    log = b'Discarded "primary" (primary) from caller.obj\r\n'
    assert _linked(monkeypatch, b"", rows=(), log=log)[1]["status"] == (
        "ref_discarded")
    with pytest.raises(final.FinalCallsiteError, match="MAP ownership"):
        _linked(monkeypatch, b"", log=log)


def test_archive_member_basename_never_proves_explicit_caller(monkeypatch):
    raw = (b" 0001:00001000 primary 0000000140001000 f i "
           b"Other.lib:caller.obj\r\n")
    rows = final._strict_map_rows(raw)
    assert rows == (("primary", 0x140001000, "other.lib:caller.obj"),)
    linked = b"\xe8" + struct.pack("<i", 0x2000 - 0x1005) + b"\xc3"
    with pytest.raises(final.FinalCallsiteError, match="MAP ownership"):
        _linked(monkeypatch, linked, rows=rows)
    with pytest.raises(final.FinalCallsiteError, match="helper MAP owner"):
        final._require_explicit_helper_row(rows, "primary", 0x140001000,
                                           "caller.obj")


def test_archive_member_label_cannot_impersonate_explicit_map_owner():
    selected = {"helper_object": "helper.obj",
                "references": [{"object": "caller.obj"}]}
    inventory = {"inputs": [{"kind": "microsoft_coff_archive",
                             "members": [{"display_label": "path/caller.obj"}]}],
                 "implicit_libraries": []}
    with pytest.raises(final.FinalCallsiteError, match="aliases"):
        final._reject_archive_caller_label_aliases(inventory, selected)
    inventory["inputs"][0]["members"][0]["display_label"] = "other.obj"
    final._reject_archive_caller_label_aliases(inventory, selected)


def test_loader_relocation_in_executable_bytes_rejects():
    section = SimpleNamespace(rva=0x1000, mapped_end=0x2000,
                              characteristics=final.direct_control_flow.IMAGE_SCN_MEM_EXECUTE)
    safe = SimpleNamespace(dir64_relocations=(SimpleNamespace(target_rva=0x3000),))
    final._reject_executable_dir64(safe, (section,))
    unsafe = SimpleNamespace(dir64_relocations=(SimpleNamespace(target_rva=0x1800),))
    with pytest.raises(final.FinalCallsiteError, match="changes executable bytes"):
        final._reject_executable_dir64(unsafe, (section,))


def test_bounded_read_rejects_oversized_file_before_loading(tmp_path):
    path = tmp_path / "oversized.bin"
    path.write_bytes(b"X" * 4097)
    with pytest.raises(final.FinalCallsiteError, match="bounded file size"):
        final._read(path, "oversized", 4096)
    assert path.stat().st_size == 4097


@pytest.mark.parametrize("kind", ("stdout", "stderr"))
def test_linker_pipe_output_is_bounded_during_process(tmp_path, kind):
    code = ("import sys; "
            f"sys.{kind}.buffer.write(b'Z'*262144); sys.{kind}.flush()")
    result = final._run_bounded((sys.executable, "-c", code), tmp_path,
                                os.environ.copy(), limit=4096, timeout=10)
    assert result.status == "output_limit"
    assert len(result.stdout) + len(result.stderr) == 4096


def test_finished_parent_cannot_leave_pipe_holding_child(tmp_path):
    code = ("import subprocess,sys; "
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'], "
            "stdout=sys.stdout,stderr=sys.stderr);print('parent-exit',flush=True)")
    started = time.monotonic()
    result = final._run_bounded((sys.executable, "-c", code), tmp_path,
                                os.environ.copy(), limit=4096, timeout=5)
    assert result.status == "exited"
    assert result.stdout == b"parent-exit\r\n"
    assert time.monotonic() - started < 5


def test_replay_parent_cannot_overlap_inputs(tmp_path):
    capture = tmp_path / "capture"
    capture.mkdir()
    inside = capture / "inside"
    inside.mkdir()
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    with pytest.raises(final.FinalCallsiteError, match="overlaps"):
        final._validated_replay_parent(inside, (capture,))
    with pytest.raises(final.FinalCallsiteError, match="overlaps"):
        final._validated_replay_parent(tmp_path, (capture,))
    final._validated_replay_parent(sibling, (capture,))
    assert not list(inside.iterdir()) and not list(sibling.iterdir())


def test_captured_link_override_rejected_before_tool_resolution(monkeypatch,
                                                                 tmp_path):
    capture = tmp_path / "capture"
    capture.mkdir()
    monkeypatch.setattr(final, "_environment_profile",
                        lambda _: ("digest", (("link", "/force"),), True))
    with pytest.raises(final.FinalCallsiteError, match="LINK or _LINK_"):
        final._replay_environment(capture, tmp_path,
                                  Path(r"C:\Program Files\Microsoft Visual Studio\2022"
                                       r"\Community\VC\Tools\MSVC\14.44.35207"
                                       r"\bin\Hostx64\x64\link.exe"))


def test_projected_replay_ignores_ambient_path_and_comspec(monkeypatch, tmp_path):
    capture = Path(r"D:\codex-artifacts\lethe-crt-directive-parity-20261013"
                   r"\baseline_capture\SecurityCore")
    linker = Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community"
                  r"\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe")
    if not capture.is_dir() or not linker.is_file():
        pytest.skip("captured conventional linker replay is not installed")
    clean, receipt = final._replay_environment(capture, tmp_path, linker)
    monkeypatch.setenv("PATH", str(tmp_path / "spoof"))
    monkeypatch.setenv("COMSPEC", str(tmp_path / "cmd.exe"))
    spoofed, second = final._replay_environment(capture, tmp_path, linker)
    assert clean == spoofed and receipt == second
    assert spoofed["ComSpec"] == r"C:\Windows\System32\cmd.exe"
    assert str(tmp_path / "spoof") not in spoofed["Path"]


def test_bounded_replay_timeout_terminates_process(tmp_path):
    started = time.monotonic()
    result = final._run_bounded(
        (sys.executable, "-c", "import time;time.sleep(30)"),
        tmp_path, os.environ.copy(), limit=4096, timeout=0.2)
    assert result.status == "timeout"
    assert time.monotonic() - started < 5


@pytest.mark.parametrize("diagnostic", (
    b"warning LNK4099", b"WARNING LNK4099", b"Warning lnk4099",
    b"error LNK1104", b"ERROR LNK1104", b"eRrOr LnK1104",
))
def test_linker_warning_and_error_case_variants_reject(diagnostic):
    with pytest.raises(final.FinalCallsiteError, match="emitted diagnostics"):
        final._require_clean_linker_replay(final._ReplayProcess(
            0, b"Selected symbol:\r\n" + diagnostic + b"\r\n", b"", "exited"))
    final._require_clean_linker_replay(final._ReplayProcess(
        0, b"Selected symbol:\r\n", b"", "exited"))


@pytest.mark.parametrize("changed", (
    "image", "pdb", "link_map", "helper_object",
    "replay_pe", "replay_pdb", "replay_map", "log_path",
))
def test_post_dia_final_rehash_rejects_each_changed_artifact(tmp_path, changed):
    labels = ("image", "pdb", "link_map", "helper_object",
              "replay_pe", "replay_pdb", "replay_map", "log_path")
    paths = {name: tmp_path / (name + ".bin") for name in labels}
    for path in paths.values():
        path.write_bytes(b"baseline")
    digest = final._sha(b"baseline")
    source = SimpleNamespace(**{name: paths[name] for name in labels[:4]})
    proof = {name: digest for name in (
        "source_pe_sha256", "source_pdb_sha256", "source_map_sha256",
        "source_coff_sha256")}
    replay = {name: paths[name] for name in labels[4:]}
    replay.update(pe_sha256=digest, replay_pdb_sha256=digest,
                  map_sha256=digest, built_pdb_sha256=digest,
                  log_sha256=digest)
    final._final_source_and_replay_pins(source, proof, replay, digest)
    paths[changed].write_bytes(b"changed")
    with pytest.raises(final.FinalCallsiteError, match="changed during"):
        final._final_source_and_replay_pins(source, proof, replay, digest)


@pytest.mark.parametrize("field", (
    "source_pe_sha256", "source_pdb_sha256", "source_map_sha256",
    "source_coff_sha256",
))
def test_post_dia_replay_or_capture_digest_drift_rejects(tmp_path, field):
    paths = {name: tmp_path / (name + ".bin") for name in (
        "image", "pdb", "link_map", "helper_object", "replay_pe",
        "replay_pdb", "replay_map", "log_path")}
    for path in paths.values():
        path.write_bytes(b"baseline")
    digest = final._sha(b"baseline")
    proof = {key: digest for key in (
        "source_pe_sha256", "source_pdb_sha256", "source_map_sha256",
        "source_coff_sha256")}
    replay = {key: paths[key] for key in (
        "replay_pe", "replay_pdb", "replay_map", "log_path")}
    replay.update(pe_sha256=digest, replay_pdb_sha256=digest,
                  built_pdb_sha256=digest, map_sha256=digest,
                  log_sha256=digest)
    source = SimpleNamespace(**{key: paths[key] for key in (
        "image", "pdb", "link_map", "helper_object")})
    proof[field] = final._sha(b"altered before proof")
    with pytest.raises(final.FinalCallsiteError, match="provenance differs"):
        final._final_source_and_replay_pins(source, proof, replay, digest)
