"""The product-link inventory is syntactic evidence, never admission."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os
import struct

import pytest

from lifter import link_capture_diagnostic as diagnostic
from lifter.link_capture_diagnostic import (
    BIGOBJ_CLASS_ID,
    CaptureDiagnosticError,
    inspect_archive_bytes,
    inspect_capture_inputs,
    inspect_object_bytes,
)


def _section(name: bytes, data_offset: int, body: bytes, flags: int) -> bytes:
    assert len(name) <= 8
    return struct.pack("<8sIIIIIIHHI", name, 0, 0, len(body), data_offset,
                       0, 0, 0, 0, flags)


def _ordinary(*, count: int = 2, directive: bytes = b'/DEFAULTLIB:"fixture.lib" ') -> bytes:
    assert count >= 2
    header_end = 20 + 40 * count
    data = directive + b"\xc3"
    raw = bytearray(struct.pack("<HHIIIHH", 0x8664, count, 0, 0, 0, 0, 0))
    raw += _section(b".drectve", header_end, directive, 0x00100A00)
    raw += _section(b".text", header_end + len(directive), b"\xc3", 0x60000020)
    raw += _section(b".bss", 0, b"", 0xC0000080) * (count - 2)
    raw += data
    return bytes(raw)


def _bigobj() -> bytes:
    header = struct.pack("<HHHHI16sIIIIIII", 0, 0xFFFF, 2, 0x8664, 0,
                         BIGOBJ_CLASS_ID, 0, 0, 0, 0, 1, 0, 0)
    return header + _section(b".text", 96, b"\xc3", 0x60000020) + b"\xc3"


def _short_import() -> bytes:
    payload = b"Function\0FIXTURE.dll\0"
    return struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, 0x8664, 0,
                       len(payload), 0, 4) + payload


def _ar_member(label: str, body: bytes) -> bytes:
    field = label.encode("ascii").ljust(16, b" ")
    header = field + b"0".ljust(12, b" ") + b"0".ljust(6, b" ") + \
        b"0".ljust(6, b" ") + b"100644".ljust(8, b" ") + \
        str(len(body)).encode("ascii").ljust(10, b" ") + b"`\n"
    assert len(header) == 60
    return header + body + (b"\n" if len(body) & 1 else b"")


def _archive(*, longname: bool = False) -> bytes:
    bodies = (_short_import(), _short_import())
    first = _ar_member("/", struct.pack(">I", 0))
    second_payload_size = 4 + 4 * len(bodies) + 4
    second_placeholder = _ar_member("/", bytes(second_payload_size))
    long = _ar_member("//", b"dir\\same.obj/\n") if longname else b""
    next_offset = 8 + len(first) + len(second_placeholder) + len(long)
    offsets = []
    labels = ("/0", "/0") if longname else ("FIXTURE.dll/", "FIXTURE.dll/")
    members = []
    for label, body in zip(labels, bodies):
        member = _ar_member(label, body)
        offsets.append(next_offset)
        next_offset += len(member)
        members.append(member)
    second = _ar_member("/", struct.pack("<I", 2) +
                        b"".join(struct.pack("<I", off) for off in reversed(offsets)) +
                        struct.pack("<I", 0))
    assert len(second) == len(second_placeholder)
    return b"!<arch>\n" + first + second + long + b"".join(members)


def test_ordinary_large_section_count_preserves_directive_bytes() -> None:
    directive = b'/DEFAULTLIB:"fixture.lib" /FAILIFMISMATCH:"ABI=1" '
    report = inspect_object_bytes("large.obj", _ordinary(count=256, directive=directive))
    assert report["kind"] == "ordinary_amd64_coff"
    assert report["sections"] == 256
    assert report["directives"][0]["raw_hex"] == directive.hex()
    assert report["directives"][0]["owner"] == "large.obj"


def test_bigobj_class_id_and_executable_section() -> None:
    report = inspect_object_bytes("generated.obj", _bigobj())
    assert report["kind"] == "bigobj_amd64"
    assert report["executable_sections"] == 1
    bad = bytearray(_bigobj())
    bad[12] ^= 1
    with pytest.raises(CaptureDiagnosticError, match="bigobj class ID"):
        inspect_object_bytes("bad.obj", bytes(bad))


def test_short_import_bounds_and_names() -> None:
    report = inspect_object_bytes("input.lib@0x40", _short_import(), in_archive=True)
    assert report["kind"] == "short_import_v0"
    assert report["names"] == ["Function", "FIXTURE.dll"]
    with pytest.raises(CaptureDiagnosticError, match="short import must"):
        inspect_object_bytes("top.obj", _short_import())
    bad = bytearray(_short_import())
    bad[12] += 1
    with pytest.raises(CaptureDiagnosticError, match="size differs"):
        inspect_object_bytes("bad.lib@0x40", bytes(bad), in_archive=True)


@pytest.mark.parametrize("longname", [False, True])
def test_duplicate_archive_display_labels_have_distinct_offset_identities(longname: bool) -> None:
    report = inspect_archive_bytes("capture.lib", _archive(longname=longname))
    assert report["member_count"] == 2
    assert report["member_kinds"] == {"short_import_v0": 2}
    assert report["members"][0]["display_label"] == report["members"][1]["display_label"]
    assert report["members"][0]["identity"] != report["members"][1]["identity"]
    assert report["index"]["member_count"] == 2
    assert report["linker_extraction_proven"] is False


def test_mutated_archive_index_rejects() -> None:
    raw = bytearray(_archive())
    first_len = len(_ar_member("/", struct.pack(">I", 0)))
    second_payload = 8 + first_len + 60
    raw[second_payload + 4] ^= 1
    with pytest.raises(CaptureDiagnosticError, match="second archive member offsets"):
        inspect_archive_bytes("bad.lib", bytes(raw))


def test_truncated_object_section_and_relocation_bounds_reject() -> None:
    with pytest.raises(CaptureDiagnosticError, match="section bytes are out of bounds"):
        inspect_object_bytes("truncated.obj", _ordinary()[:-1])
    raw = bytearray(_ordinary())
    struct.pack_into("<H", raw, 20 + 32, 1)
    struct.pack_into("<I", raw, 20 + 24, len(raw) - 3)
    with pytest.raises(CaptureDiagnosticError, match="relocation table is out of bounds"):
        inspect_object_bytes("bad_reloc.obj", bytes(raw))


def test_capture_path_escape_and_ltcg_reject(tmp_path: Path) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / "good.obj").write_bytes(_ordinary())
    for token, message in (("..\\good.obj", "input escapes capture"),
                           (".\\good.obj", "LTCG/whole-archive")):
        switches = '"/LTCG"\n' if token.startswith(".\\") else ""
        (capture / "link.rsp").write_text(switches + f'"{token}"\n', encoding="utf-16")
        with pytest.raises(CaptureDiagnosticError, match=message):
            inspect_capture_inputs(capture)


def test_unlisted_implicit_archive_is_inventoried_without_admission(tmp_path: Path) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / "good.obj").write_bytes(_ordinary())
    (capture / "link.rsp").write_text('".\\good.obj"\r\n', encoding="utf-16", newline="")
    implicit = _archive()
    (capture / "implicit.lib").write_bytes(implicit)
    report = inspect_capture_inputs(capture)
    assert report["distinct_inputs"] == 1
    assert report["implicit_counts"]["libraries"] == 1
    assert report["implicit_counts"]["archive_members"] == 2
    assert report["implicit_libraries"][0]["name"] == "implicit.lib"
    assert report["capture_file_sha256"]["implicit.lib"] == sha256(implicit).hexdigest()
    assert report["capture_file_roles"]["implicit.lib"] == (
        "captured_implicit_possible_material_input")
    assert report["capture_file_roles"]["good.obj"] == "response_listed_material_input"
    assert report["all_captured_implicit_libraries_inventoried"] is True
    assert report["production_admitted"] is False


@pytest.mark.parametrize("suffix", ["obj", "res"])
def test_unlisted_material_or_redirected_implicit_archive_rejects(
        tmp_path: Path, suffix: str) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / "good.obj").write_bytes(_ordinary())
    (capture / "link.rsp").write_text('".\\good.obj"\r\n', encoding="utf-16", newline="")
    unexpected = capture / f"unlisted.{suffix}"
    unexpected.write_bytes(_ordinary())
    with pytest.raises(CaptureDiagnosticError, match="unlisted non-library"):
        inspect_capture_inputs(capture)
    unexpected.unlink()
    target = tmp_path / "archive.lib"
    target.write_bytes(_archive())
    try:
        (capture / "implicit.lib").symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Windows symlink privilege unavailable")
    with pytest.raises(CaptureDiagnosticError, match="reparse|regular|redirect"):
        inspect_capture_inputs(capture)


def test_case_colliding_capture_names_reject_even_on_case_insensitive_host(
        tmp_path: Path, monkeypatch) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / "good.obj").write_bytes(_ordinary())
    rsp = '".\\good.obj"\r\n'.encode("utf-16")
    (capture / "link.rsp").write_bytes(rsp)
    real_iterdir = Path.iterdir

    def duplicate_names(path):
        if path == capture:
            return iter((capture / "link.rsp", capture / "good.obj",
                         capture / "GOOD.OBJ"))
        return real_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", duplicate_names)
    with pytest.raises(CaptureDiagnosticError, match="case-ambiguous"):
        diagnostic._capture_other_files(capture, {"good.obj"}, sha256(rsp).hexdigest())


def test_directory_sibling_has_typed_inventory_failure(tmp_path: Path) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / "good.obj").write_bytes(_ordinary())
    (capture / "link.rsp").write_text('".\\good.obj"\r\n', encoding="utf-16", newline="")
    (capture / "implicit.lib").mkdir()
    with pytest.raises(CaptureDiagnosticError, match="redirected or unreadable"):
        inspect_capture_inputs(capture)


def test_oversized_captured_pdb_rejects_before_read(tmp_path: Path, monkeypatch) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / "good.obj").write_bytes(_ordinary())
    (capture / "link.rsp").write_text('".\\good.obj"\r\n', encoding="utf-16", newline="")
    with (capture / "output.pdb").open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    real_read = diagnostic._capture_regular_file

    def reject_pdb_read(root, name):
        if name == "output.pdb":
            pytest.fail("oversized PDB was read before size preflight")
        return real_read(root, name)

    monkeypatch.setattr(diagnostic, "_capture_regular_file", reject_pdb_read)
    with pytest.raises(CaptureDiagnosticError, match="byte count is unsupported"):
        inspect_capture_inputs(capture)


def test_only_archive_codeview_machine_neutral_coff_is_accepted() -> None:
    body = b"CodeView"
    raw = (struct.pack("<HHIIIHH", 0, 1, 0, 0, 0, 0, 0) +
           _section(b".debug$S", 60, body, 0x42000040) + body)
    item = inspect_object_bytes("debug.lib@0x80", raw, in_archive=True)
    assert item["kind"] == "neutral_debug_coff"
    assert item["executable_sections"] == 0
    with pytest.raises(CaptureDiagnosticError, match="ordinary AMD64"):
        inspect_object_bytes("top.obj", raw)
    mutated = bytearray(raw)
    struct.pack_into("<I", mutated, 20 + 36, 0x60000020)
    with pytest.raises(CaptureDiagnosticError, match="contains code"):
        inspect_object_bytes("debug.lib@0x80", bytes(mutated), in_archive=True)


@pytest.mark.parametrize("target, expected", [
    ("SecurityCore", {"libraries": 18, "archive_members": 16566,
                      "explicit_ordinary_amd64_coff": 10,
                      "member_short_import_v0": 16269,
                      "member_ordinary_amd64_coff": 297,
                      "directive_sections": 256}),
    ("OrionNative", {"libraries": 43, "archive_members": 70247,
                     "explicit_ordinary_amd64_coff": 54,
                     "explicit_bigobj_amd64": 1,
                     "member_short_import_v0": 69878,
                     "member_ordinary_amd64_coff": 368,
                     "member_bigobj_amd64": 1,
                     "opaque_resources": 1,
                     "directive_sections": 307}),
])
def test_real_conventional_profile_capture(target: str, expected: dict[str, int]) -> None:
    root = os.environ.get("LETHE_CONVENTIONAL_LINKREPRO")
    if not root:
        pytest.skip("external conventional product capture not present in this checkout")
    report = inspect_capture_inputs(Path(root) / target)
    for key, value in expected.items():
        assert report["counts"][key] == value
    assert report["status"] == "diagnostic_input_inventory_only"
    assert not report["linker_member_extraction_proven"]
    assert not report["direct_instruction_boundaries_proven"]
    assert not report["indirect_target_closure_proven"]
    assert not report["source_output_binding"]
    assert not report["final_image_reference_closure_proven"]
    assert not report["production_admitted"]


def test_real_capture_header_and_directive_mutations_reject_or_rebind() -> None:
    root = os.environ.get("LETHE_CONVENTIONAL_LINKREPRO")
    if not root:
        pytest.skip("external conventional product capture not present in this checkout")
    capture = Path(root) / "OrionNative"

    ordinary = (capture / "OrionAppController.obj").read_bytes()
    assert inspect_object_bytes("OrionAppController.obj", ordinary)["sections"] == 35800
    malformed = bytearray(ordinary)
    struct.pack_into("<H", malformed, 2, 0)
    with pytest.raises(CaptureDiagnosticError, match="section count"):
        inspect_object_bytes("OrionAppController.obj", bytes(malformed))

    entry = (capture / "Qt6EntryPoint.lib").read_bytes()
    members = inspect_archive_bytes("Qt6EntryPoint.lib", entry)["members"]
    assert len(members) == 1 and members[0]["kind"] == "bigobj_amd64"
    off = members[0]["header_offset"] + 60
    body = bytearray(entry[off:off + members[0]["bytes"]])
    body[12] ^= 1
    with pytest.raises(CaptureDiagnosticError, match="bigobj class ID"):
        inspect_object_bytes("Qt6EntryPoint.lib@offset", bytes(body), in_archive=True)

    imports = (capture / "advapi32.lib").read_bytes()
    import_member = next(m for m in inspect_archive_bytes("advapi32.lib", imports)["members"]
                         if m["kind"] == "short_import_v0")
    off = import_member["header_offset"] + 60
    body = bytearray(imports[off:off + import_member["bytes"]])
    body[12] ^= 1
    with pytest.raises(CaptureDiagnosticError, match="size differs"):
        inspect_object_bytes("advapi32.lib@offset", bytes(body), in_archive=True)

    helper = (capture / "AutomationAccessPolicy.obj").read_bytes()
    old = inspect_object_bytes("AutomationAccessPolicy.obj", helper)
    assert len(old["directives"]) == 1
    directive = old["directives"][0]
    assert helper[directive["data_offset"]:
                  directive["data_offset"] + directive["size"]].hex() == directive["raw_hex"]
    changed = bytearray(helper)
    changed[directive["data_offset"]] ^= 1
    new = inspect_object_bytes("AutomationAccessPolicy.obj", bytes(changed))
    assert new["directives"][0]["sha256"] != directive["sha256"]
