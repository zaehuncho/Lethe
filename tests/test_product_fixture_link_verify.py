"""Fail-closed unit contracts for opt-in synthetic final-link replay."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from lifter import product_fixture_link_verify as proof


_VS_ROOT = Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community")
_VS_LINK = (_VS_ROOT / "VC" / "Tools" / "MSVC" / "14.44.35207" /
            "bin" / "Hostx64" / "x64" / "link.exe")
_VS_DEVCMD = _VS_ROOT / "Common7" / "Tools" / "VsDevCmd.bat"


def test_only_canonical_paired_visual_studio_tools_can_enter_cmd_script():
    assert proof._validated_tool_paths(_VS_LINK, _VS_DEVCMD) is None


@pytest.mark.parametrize("metachar", ["%TEMP%", "!TEMP!", "&", "^", "|", "<", ">"])
def test_cmd_expansion_and_metacharacters_reject_before_tool_read(metachar):
    link = Path(str(_VS_LINK).replace("\\Community\\", "\\Community" + metachar + "\\"))
    with pytest.raises(proof.ProductLinkProofError, match="unsafe or noncanonical"):
        proof._validated_tool_paths(link, _VS_DEVCMD)


@pytest.mark.parametrize("bad_link,bad_setup", [
    (Path(r"C:\relative\..\link.exe"), _VS_DEVCMD),
    (_VS_LINK, Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community%PATH%\Common7\Tools\VsDevCmd.bat")),
    (_VS_LINK, Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Other.bat")),
    (Path(r"C:\Impostor\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe"),
     Path(r"C:\Impostor\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat")),
    (Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx86\x86\link.exe"), _VS_DEVCMD),
])
def test_noncanonical_or_unpaired_tool_paths_reject(bad_link, bad_setup):
    with pytest.raises(proof.ProductLinkProofError):
        proof._validated_tool_paths(bad_link, bad_setup)


def _rsp(*, extra: str = "", dll: bool = False) -> bytes:
    target = "fixture.dll" if dll else "fixture.exe"
    options = [
        f"/out:.\\{target}", "/pdb:.\\fixture.pdb", "/INCREMENTAL:NO",
        "/DEBUG:FULL", "/MACHINE:X64", "/CETCOMPAT", "/GUARD:CF",
        "/GUARD:XFG", "/BREPRO", "/OPT:NOICF",
    ]
    if dll:
        options.append("/DLL")
    if extra:
        options.append(extra)
    options.append(".\\fixture.obj")
    return b"\xff\xfe" + ("\r\n".join(f'"{x}"' for x in options) + "\r\n").encode("utf-16le")


@pytest.mark.parametrize("extra,reason", [
    ("/FORCE", "unsupported linker option"),
    ("/ALTERNATENAME:a=b", "unsupported linker option"),
    ("/PDBALTPATH:forged", "unsupported linker option"),
    ("/OUT:.\\other.exe", "output/PDB target differs"),
    ("C:\\absolute.obj", "input escapes capture"),
    ("@other.rsp", "input escapes capture"),
])
def test_response_rejects_unsafe_or_ambiguous_option(extra, reason):
    with pytest.raises(proof.ProductLinkProofError, match=reason):
        proof._response(_rsp(extra=extra), "fixture.exe", "fixture.pdb")


@pytest.mark.parametrize("dll", [False, True])
def test_response_accepts_only_matching_fixture_kind(dll):
    image = "fixture.dll" if dll else "fixture.exe"
    assert proof._response(_rsp(dll=dll), image, "fixture.pdb") == ("fixture.obj",)
    other = "fixture.exe" if dll else "fixture.dll"
    with pytest.raises(proof.ProductLinkProofError, match="output/PDB target differs"):
        proof._response(_rsp(dll=dll), other, "fixture.pdb")


def test_response_rejects_dll_switch_on_exe():
    with pytest.raises(proof.ProductLinkProofError, match="required fixture"):
        proof._response(_rsp(extra="/DLL"), "fixture.exe", "fixture.pdb")


def _fixture(tmp_path: Path, monkeypatch, *, replay_bytes: bytes = b"MZfixture"):
    # The replay-core unit fixture uses temporary fake tools; the distinct
    # path-contract tests above and materialized integration exercise the real
    # CMD-tool validator rather than requiring VS to be installed for pytest.
    monkeypatch.setattr(proof, "_validated_tool_paths", lambda *_: None)
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / "link.rsp").write_bytes(_rsp())
    (capture / "fixture.obj").write_bytes(b"COFF fixture")
    (capture / "fixture.pdb").write_bytes(b"stale captured PDB")
    built = tmp_path / "fixture.exe"
    built.write_bytes(b"MZfixture")
    pdb = tmp_path / "fixture.pdb"
    pdb.write_bytes(b"PDB sidecar")
    link_map = tmp_path / "fixture.map"
    link_map.write_bytes(b"MAP sidecar")
    link_exe = tmp_path / "link.exe"
    link_exe.write_bytes(b"link tool")
    vsdevcmd = tmp_path / "VsDevCmd.bat"
    vsdevcmd.write_bytes(b"tool environment")
    replay = tmp_path / "replay"
    inputs = proof.ReplayInputs(capture, built, pdb, link_map, replay, link_exe, vsdevcmd)
    monkeypatch.setattr(proof, "_rsds", lambda _: ("guid", 1, "C:\\fixture.pdb"))

    def run(_cmd, *, cwd, capture_output, timeout, check):
        assert capture_output and timeout == 120 and check is False
        assert cwd == replay
        (replay / "fixture.exe").write_bytes(replay_bytes)
        (replay / "replay.stderr").write_bytes(b"")
        return SimpleNamespace(returncode=0, stderr=b"")

    monkeypatch.setattr(proof.subprocess, "run", run)
    return inputs


def test_replay_requires_actual_raw_pe_equality(tmp_path, monkeypatch):
    inputs = _fixture(tmp_path, monkeypatch)
    result = proof.replay_exact_pe(inputs, required_objects=("fixture.obj",))
    assert result["raw_pe_byte_equal"] is True
    assert result["built_pe_sha256"] == result["replay_pe_sha256"]
    assert result["pdb_raw_byte_equal_claimed"] is False
    assert result["map_raw_byte_equal_claimed"] is False
    assert result["source_reference_closure_proven"] is False
    assert result["production_admitted"] is False


def test_replay_rejects_bytes_different_even_if_process_exits_zero(tmp_path, monkeypatch):
    inputs = _fixture(tmp_path, monkeypatch, replay_bytes=b"MZchanged")
    with pytest.raises(proof.ProductLinkProofError, match="PE bytes differ"):
        proof.replay_exact_pe(inputs)


def test_replay_rejects_omitted_required_or_retained_forbidden_object(tmp_path, monkeypatch):
    inputs = _fixture(tmp_path, monkeypatch)
    with pytest.raises(proof.ProductLinkProofError, match="required VM object absent"):
        proof.replay_exact_pe(inputs, required_objects=("missing.obj",))
    assert not inputs.replay_dir.exists()
    with pytest.raises(proof.ProductLinkProofError, match="original helper object remains"):
        proof.replay_exact_pe(inputs, forbidden_object="fixture.obj")
    assert not inputs.replay_dir.exists()


def test_replay_rejects_tool_mutation_during_link(tmp_path, monkeypatch):
    inputs = _fixture(tmp_path, monkeypatch)
    old_run = proof.subprocess.run

    def changed_tool(*args, **kwargs):
        result = old_run(*args, **kwargs)
        inputs.link_exe.write_bytes(b"changed link tool")
        return result

    monkeypatch.setattr(proof.subprocess, "run", changed_tool)
    with pytest.raises(proof.ProductLinkProofError, match="tool changed during replay"):
        proof.replay_exact_pe(inputs)


def test_replay_rejects_existing_output_directory(tmp_path, monkeypatch):
    inputs = _fixture(tmp_path, monkeypatch)
    inputs.replay_dir.mkdir()
    (inputs.replay_dir / "stray").write_bytes(b"x")
    with pytest.raises(proof.ProductLinkProofError, match="must be empty"):
        proof.replay_exact_pe(inputs)
