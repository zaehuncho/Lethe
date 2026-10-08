"""Non-executable structural fixtures for the read-only driver report."""
from __future__ import annotations

import hashlib
import json
import random
import struct
from pathlib import Path

import pytest

from tools import kernel_driver_report as driver

OPTIONAL = 0x98
SECTIONS = OPTIONAL + 240


def _u16(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", data, offset, value)


def _u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def _directory(data: bytearray, index: int, rva: int, size: int) -> None:
    struct.pack_into("<II", data, OPTIONAL + 112 + index * 8, rva, size)


def _fixture(*, imported: str | None = "ntoskrnl.exe", delayed: str | None = None,
             certificate: bool = False) -> bytearray:
    """Header/data bytes only; not a functional driver and never loaded."""
    data = bytearray(0xA00)
    data[:2] = b"MZ"
    _u32(data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 2, 0, 0, 0, 240, 0x0022)
    _u16(data, OPTIONAL, 0x20B)
    _u32(data, OPTIONAL + 16, 0x1000)
    struct.pack_into("<Q", data, OPTIONAL + 24, 0x140000000)
    _u32(data, OPTIONAL + 32, 0x1000)
    _u32(data, OPTIONAL + 36, 0x200)
    _u32(data, OPTIONAL + 56, 0x3000)
    _u32(data, OPTIONAL + 60, 0x200)
    _u16(data, OPTIONAL + 68, 1)
    _u16(data, OPTIONAL + 70, 0x0140)
    _u32(data, OPTIONAL + 108, 16)
    struct.pack_into("<8sIIIIIIHHI", data, SECTIONS,
                     b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", data, SECTIONS + 40,
                     b".rdata", 0x600, 0x2000, 0x600, 0x400, 0, 0, 0, 0, 0x40000040)
    for module, rva, raw, is_delay in ((imported, 0x2000, 0x400, False),
                                      (delayed, 0x2100, 0x500, True)):
        if module is None:
            continue
        _directory(data, 13 if is_delay else 1, rva, 64 if is_delay else 40)
        if is_delay:
            struct.pack_into("<IIIIIIII", data, raw,
                             1, rva + 0x40, 0, rva + 0x80, rva + 0x60, 0, 0, 0)
        else:
            struct.pack_into("<IIIII", data, raw, rva + 0x60, 0, 0, rva + 0x40, rva + 0x80)
            _directory(data, 12, rva + 0x80, 16)
        name = module.encode("ascii") + b"\0"
        data[raw + 0x40:raw + 0x40 + len(name)] = name
        struct.pack_into("<QQ", data, raw + 0x60, rva + 0xA0, 0)
        struct.pack_into("<QQ", data, raw + 0x80, rva + 0xA0, 0)
        data[raw + 0xA2:raw + 0xA7] = b"Test\0"
    if certificate:
        _directory(data, 4, len(data), 16)
        data.extend(struct.pack("<IHH", 12, 0x200, 2) + b"FAKE" + b"\0" * 4)
    return data


def _codes(result: dict) -> set[str]:
    return {entry["code"] for entry in result["blockers"]}


def test_candidate_has_hash_but_never_production_or_virtualization_claim() -> None:
    data = bytes(_fixture())
    result = driver.analyze_bytes(data, filename="fixture.sys")
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["classification"]["candidate"] is True
    assert result["classification"]["managed"] is False
    assert result["production_ready"] is False
    assert result["kernel_packing_supported"] is False
    assert result["kernel_virtualization_supported"] is False
    assert _codes(result) == {"kernel_packing_not_implemented"}
    assert all(gate["status"] == "unverified" for gate in result["external_gates"])
    assert result["imports"]["normal"] == ["ntoskrnl.exe"]
    assert result["imports"]["kernel_ddi_compatibility"] == "unverified"


@pytest.mark.parametrize("filename", ["fixture.exe", "fixture.dll", "fixture.sys.exe", "fixture"])
def test_extension_is_not_ignored(filename: str) -> None:
    result = driver.analyze_bytes(bytes(_fixture()), filename=filename)
    assert result["classification"]["candidate"] is False
    assert "not_amd64_native_driver_candidate" in _codes(result)


@pytest.mark.parametrize("offset,value", [(0x84, 0xAA64), (OPTIONAL + 68, 3), (0x96, 0)])
def test_non_driver_headers_are_not_supported(offset: int, value: int) -> None:
    data = _fixture()
    _u16(data, offset, value)
    assert not driver.analyze_bytes(bytes(data), filename="renamed.sys")["classification"]["candidate"]


def test_managed_image_is_not_driver_candidate() -> None:
    data = _fixture()
    _directory(data, 14, 0x2200, 72)
    result = driver.analyze_bytes(bytes(data), filename="managed.sys")
    assert result["classification"]["managed"] is True
    assert result["classification"]["candidate"] is False


def test_wx_and_nx_are_reported_as_static_blockers() -> None:
    data = _fixture()
    _u16(data, OPTIONAL + 70, 0x40)
    _u32(data, SECTIONS + 36, 0xE0000020)
    result = driver.analyze_bytes(bytes(data), filename="fixture.sys")
    assert {"nx_compat_absent", "writable_executable_section"} <= _codes(result)


def test_subpage_pe_layout_is_not_hvci_readiness() -> None:
    data = _fixture()
    _u32(data, OPTIONAL + 32, 0x200)
    assert "not_page_aligned" in _codes(driver.analyze_bytes(bytes(data), filename="fixture.sys"))


def test_executable_iat_is_reported() -> None:
    data = _fixture()
    _u32(data, SECTIONS + 40 + 36, 0x60000040)
    assert "executable_iat" in _codes(driver.analyze_bytes(bytes(data), filename="fixture.sys"))


def test_executable_descriptor_iat_is_reported_without_optional_iat_directory() -> None:
    data = _fixture()
    _directory(data, 12, 0, 0)
    _u32(data, SECTIONS + 40 + 36, 0x60000040)
    assert "executable_iat" in _codes(driver.analyze_bytes(bytes(data), filename="fixture.sys"))


@pytest.mark.parametrize("module", ["KERNEL32.dll", "ntdll.dll", "api-ms-win-core-file-l1-1-0.dll", "X:\\path\\kernel32.dll"])
def test_known_user_mode_normal_import_is_blocked(module: str) -> None:
    result = driver.analyze_bytes(bytes(_fixture(imported=module)), filename="fixture.sys")
    assert result["imports"]["known_user_mode"] == [module]
    assert "user_mode_imports" in _codes(result)


def test_delay_imports_are_inventoried_not_silently_skipped() -> None:
    result = driver.analyze_bytes(bytes(_fixture(delayed="user32.dll")), filename="fixture.sys")
    assert result["imports"]["delay"] == ["user32.dll"]
    assert {"user_mode_imports", "delay_imports_require_review"} <= _codes(result)


def test_certificate_payload_is_never_treated_as_verified_signature() -> None:
    result = driver.analyze_bytes(bytes(_fixture(certificate=True)), filename="fixture.sys")
    certificate = result["certificate_table"]
    assert certificate["present"] is True
    assert certificate["entries"] == [{"length": 12, "revision": 0x200, "type": 2}]
    assert certificate["signature_verified"] is False
    assert certificate["catalog_signature_checked"] is False
    assert certificate["trust_status"] == "unverified"
    assert result["production_ready"] is False


def test_absent_certificate_does_not_claim_no_catalog_signature() -> None:
    cert = driver.analyze_bytes(bytes(_fixture()), filename="fixture.sys")["certificate_table"]
    assert not cert["present"]
    assert cert["trust_status"] == "unverified"


@pytest.mark.parametrize("length", [0, 1, 63, 0x80, 0x97, 0x187, 0x1D7, 0x1FF, 0x9FF])
def test_truncation_fails_closed(length: int) -> None:
    with pytest.raises(driver.DriverReportError):
        driver.analyze_bytes(bytes(_fixture()[:length]), filename="fixture.sys")


@pytest.mark.parametrize("offset,value,error", [
    (0x3C, 0xFFFFFFF0, "PE/COFF"),
    (OPTIONAL + 108, 17, "data-directory count"),
    (OPTIONAL + 32, 0, "section alignment"),
    (OPTIONAL + 36, 3, "file alignment"),
    (OPTIONAL + 60, 0x100, "SizeOfHeaders"),
    (OPTIONAL + 56, 0x2000, "out-of-image"),
    (SECTIONS + 40 + 20, 0x200, "overlapping raw"),
    (SECTIONS + 40 + 12, 0x1000, "overlapping virtual"),
    (SECTIONS + 40 + 12, 0x2100, "SectionAlignment"),
    (SECTIONS + 16, 0x201, "FileAlignment"),
    (SECTIONS + 40 + 16, 0x100000, "out-of-image"),
    (0x40C, 0xFFFFFFF0, "outside the image"),
])
def test_malformed_ranges_fail_closed(offset: int, value: int, error: str) -> None:
    data = _fixture()
    _u32(data, offset, value)
    with pytest.raises(driver.DriverReportError, match=error):
        driver.analyze_bytes(bytes(data), filename="fixture.sys")


def test_import_lookup_can_fall_back_to_unbound_iat() -> None:
    data = _fixture()
    _u32(data, 0x400, 0)
    assert driver.analyze_bytes(bytes(data), filename="fixture.sys")["imports"]["normal"] == ["ntoskrnl.exe"]


def test_directory_cannot_extend_into_zero_fill() -> None:
    data = _fixture()
    _u32(data, SECTIONS + 40 + 8, 0x800)
    _directory(data, 1, 0x25F0, 40)
    with pytest.raises(driver.DriverReportError, match="file-backed"):
        driver.analyze_bytes(bytes(data), filename="fixture.sys")


def test_descriptor_must_have_terminator_inside_declared_directory() -> None:
    data = _fixture()
    _directory(data, 1, 0x2000, 20)
    with pytest.raises(driver.DriverReportError, match="descriptor terminator"):
        driver.analyze_bytes(bytes(data), filename="fixture.sys")


def test_module_string_bound_is_enforced() -> None:
    data = _fixture()
    _u32(data, 0x40C, 0x2300)
    data[0x700:0x900] = b"A" * 512
    with pytest.raises(driver.DriverReportError, match="exceeds its bound"):
        driver.analyze_bytes(bytes(data), filename="fixture.sys")


def test_thunk_symbol_pointer_and_ordinal_are_validated() -> None:
    for value in (0xFFFFFFFF, (1 << 63) | (1 << 32)):
        data = _fixture()
        struct.pack_into("<Q", data, 0x460, value)
        with pytest.raises(driver.DriverReportError):
            driver.analyze_bytes(bytes(data), filename="fixture.sys")


def test_thunk_aggregate_work_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(driver, "MAX_IMPORT_THUNKS", 1)
    with pytest.raises(driver.DriverReportError, match="work bound"):
        driver.analyze_bytes(bytes(_fixture()), filename="fixture.sys")


def test_certificate_bad_length_and_overlap_fail_closed() -> None:
    for offset, length in ((0x200, 16), (0xA00, 0x10000), (0xA00, 4)):
        data = _fixture(certificate=True)
        _directory(data, 4, offset, 16)
        if offset == 0xA00:
            _u32(data, offset, length)
        with pytest.raises(driver.DriverReportError, match="certificate"):
            driver.analyze_bytes(bytes(data), filename="fixture.sys")


def test_cli_read_only_json_nonzero_for_unverified(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "fixture.sys"
    original = bytes(_fixture())
    target.write_bytes(original)
    assert driver.main([str(target)]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["parsed"] is True and result["production_ready"] is False
    assert target.read_bytes() == original
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("arg", ["missing.sys", "--unknown"])
def test_cli_errors_are_json(tmp_path: Path, capsys: pytest.CaptureFixture[str], arg: str) -> None:
    argument = str(tmp_path / arg) if arg.endswith(".sys") else arg
    assert driver.main([argument]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["parsed"] is False and result["production_ready"] is False


def test_cli_does_not_sweep_directories(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert driver.main([str(tmp_path)]) == 2
    assert "regular file" in json.loads(capsys.readouterr().out)["error"]


def test_file_read_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "fixture.sys"
    target.write_bytes(bytes(_fixture()))
    monkeypatch.setattr(driver, "MAX_FILE_BYTES", 64)
    with pytest.raises(driver.DriverReportError, match="report limit"):
        driver.report(target)


def test_bounded_random_structural_mutations_never_claim_readiness() -> None:
    rng = random.Random(20261007)
    original = _fixture(certificate=True)
    for _ in range(300):
        data = bytearray(original)
        for _ in range(rng.randrange(1, 6)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            result = driver.analyze_bytes(bytes(data), filename="fixture.sys")
        except driver.DriverReportError:
            continue
        assert result["production_ready"] is False


@pytest.mark.parametrize("suffix", [".sys", ".exe", ".dll"])
@pytest.mark.parametrize("file_flags,dll_flags,subsystem,error", [
    pytest.param(0x0022, 0x0140, 1, "GUI/CUI", id="native-subsystem"),
    pytest.param(0x1022, 0x0140, 3, "kernel/system", id="system-image"),
    pytest.param(0x0022, 0x2140, 3, "WDM drivers", id="wdm-driver"),
])
def test_user_mode_admission_rejects_driver_markers_regardless_of_extension(
    tmp_path: Path, suffix: str, file_flags: int, dll_flags: int,
    subsystem: int, error: str,
) -> None:
    # Exercise the public analyzer, not only its private header helper. These
    # bytes are a nonfunctional structural fixture and are never loaded.
    from packer import pe_analyze

    data = _fixture()
    _u16(data, 0x96, file_flags)
    _u16(data, OPTIONAL + 70, dll_flags)
    _u16(data, OPTIONAL + 68, subsystem)
    path = tmp_path / ("structural-fixture-not-a-driver" + suffix)
    original = bytes(data)
    path.write_bytes(original)

    inspection = driver.report(path)
    assert inspection["parsed"] is True
    assert inspection["production_ready"] is False
    assert inspection["kernel_packing_supported"] is False
    with pytest.raises(pe_analyze.PEArchError, match=error):
        pe_analyze.analyze_pe(str(path))
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]
