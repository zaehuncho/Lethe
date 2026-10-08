"""Behavioral release-safety tests for output publication and validation."""
from __future__ import annotations

import os
import struct
from types import SimpleNamespace

import pytest

from packer import (
    assemble, container, keyed_validation, orchestrator, payload, pe_analyze,
    report,
)


def _patch_pipeline(monkeypatch, *, fail: bool,
                    server_shard: bytes | None = None) -> list[str]:
    stages: list[str] = []
    monkeypatch.setattr(pe_analyze, "analyze_pe", lambda _path: SimpleNamespace(is_dll=False))
    monkeypatch.setattr(payload, "build_payload", lambda *_args: object())

    def fake_assemble(_parsed, _artifacts, output_path, **_kwargs):
        stages.append(output_path)
        with open(output_path, "wb") as output:
            output.write(b"candidate")
        if fail:
            raise RuntimeError("assembly failed after staging")
        return SimpleNamespace(server_shard=server_shard, output_path=output_path)

    monkeypatch.setattr(assemble, "build_output_pe", fake_assemble)
    monkeypatch.setattr(
        report, "validate_packed",
        lambda _path: report.ValidationResult(
            True, section_count=1, format_version=container.FORMAT_VERSION))
    monkeypatch.setattr(
        keyed_validation, "validate_staged_output",
        lambda *_args, **_kwargs: keyed_validation.KeyedValidationResult(
            True, section_count=1))
    monkeypatch.setattr(orchestrator, "_pe_content_id", lambda _path: "a" * 64)
    return stages


def test_pack_rejects_same_input_output_without_modifying_source(tmp_path):
    source = tmp_path / "app.exe"
    source.write_bytes(b"source bytes")

    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(output_path=str(source)))

    assert not result.ok
    assert "same file" in result.error
    assert source.read_bytes() == b"source bytes"


def test_pack_rejects_hardlink_alias_without_modifying_source(tmp_path):
    source = tmp_path / "app.exe"
    alias = tmp_path / "alias.exe"
    source.write_bytes(b"source bytes")
    try:
        os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(output_path=str(alias)))

    assert not result.ok
    assert "same file" in result.error
    assert source.read_bytes() == b"source bytes"


@pytest.mark.parametrize("option", ["memory_guard", "process_hardening"])
def test_dll_rejects_process_global_runtime_options_before_analysis(
        monkeypatch, tmp_path, option):
    source = tmp_path / "plugin.dll"
    output = tmp_path / "plugin.packed.dll"
    source.write_bytes(b"source bytes")
    output.write_bytes(b"previous release")
    analyzed: list[str] = []
    monkeypatch.setattr(
        pe_analyze, "analyze_pe",
        lambda path: analyzed.append(path) or SimpleNamespace(is_dll=True))
    options = orchestrator.PackOptions(
        output_path=str(output), is_dll=True,
        **{option: True},
    )

    result = orchestrator.pack_file(str(source), options)

    assert not result.ok
    assert analyzed == []
    assert output.read_bytes() == b"previous release"
    assert list(tmp_path.glob("*.source")) == []


def test_failed_pack_preserves_existing_output_and_removes_unique_stage(
        monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    output.write_bytes(b"previous release")
    stages = _patch_pipeline(monkeypatch, fail=True)

    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(
            output_path=str(output), is_dll=False))

    assert not result.ok
    assert output.read_bytes() == b"previous release"
    assert len(stages) == 1
    assert not os.path.exists(stages[0])
    assert stages[0] != str(output)


def test_invalid_stage_is_not_uploaded_or_published_and_is_removed(
        monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    output.write_bytes(b"previous release")
    stages = _patch_pipeline(
        monkeypatch, fail=False, server_shard=b"s" * 32)
    monkeypatch.setattr(
        report, "validate_packed",
        lambda _path: report.ValidationResult(False, "corrupt PackInfo"))
    content_ids: list[str] = []
    monkeypatch.setattr(
        orchestrator, "_pe_content_id",
        lambda path: content_ids.append(path) or "a" * 64)
    uploads: list[dict] = []
    monkeypatch.setattr(
        orchestrator, "_upload_shard",
        lambda *_args, **kwargs: uploads.append(kwargs))

    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(
            output_path=str(output), is_dll=False,
            server_shard=True,
            shard_url=f"https://{orchestrator._SHARD_API_HOST}",
            shard_auth="build-token", shard_license_id="license-1",
            shard_hwid_hash="b" * 64))

    assert not result.ok
    assert "staged output failed structural validation" in result.error
    assert "corrupt PackInfo" in result.error
    assert output.read_bytes() == b"previous release"
    assert content_ids == []
    assert uploads == []
    assert len(stages) == 1
    assert not os.path.exists(stages[0])


def test_successful_pack_atomically_replaces_existing_output(monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    output.write_bytes(b"previous release")
    stages = _patch_pipeline(monkeypatch, fail=False)

    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(
            output_path=str(output), is_dll=False))

    assert result.ok
    assert output.read_bytes() == b"candidate"
    assert result.packed_size == len(b"candidate")
    assert len(stages) == 1 and not os.path.exists(stages[0])


def test_pack_uses_one_source_snapshot_and_removes_it(monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source A")
    stages = _patch_pipeline(monkeypatch, fail=False)
    analyzed: list[str] = []
    assembled: list[str] = []

    def fake_analyze(path):
        analyzed.append(path)
        assert path != str(source)
        assert open(path, "rb").read() == b"source A"
        return SimpleNamespace(is_dll=False)

    monkeypatch.setattr(pe_analyze, "analyze_pe", fake_analyze)
    original_assemble = assemble.build_output_pe

    def capture_assemble(parsed, artifacts, output_path, **kwargs):
        assembled.append(kwargs["input_path"])
        assert open(kwargs["input_path"], "rb").read() == b"source A"
        return original_assemble(parsed, artifacts, output_path, **kwargs)

    monkeypatch.setattr(assemble, "build_output_pe", capture_assemble)

    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(
            output_path=str(output), is_dll=False))

    assert result.ok
    assert analyzed == assembled
    assert len(stages) == 1
    assert list(tmp_path.glob("*.source")) == []


def test_source_replacement_during_pack_refuses_publication(monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source A")
    output.write_bytes(b"previous release")
    stages = _patch_pipeline(monkeypatch, fail=False)
    assembled_inputs: list[str] = []

    def mutate_after_snapshot(path):
        assert open(path, "rb").read() == b"source A"
        source.write_bytes(b"source B")
        return SimpleNamespace(is_dll=False)

    monkeypatch.setattr(pe_analyze, "analyze_pe", mutate_after_snapshot)
    original_assemble = assemble.build_output_pe

    def capture_assemble(parsed, artifacts, output_path, **kwargs):
        assembled_inputs.append(kwargs["input_path"])
        assert open(kwargs["input_path"], "rb").read() == b"source A"
        return original_assemble(parsed, artifacts, output_path, **kwargs)

    monkeypatch.setattr(assemble, "build_output_pe", capture_assemble)

    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(
            output_path=str(output), is_dll=False))

    assert not result.ok
    assert "source binary changed during packing" in result.error
    assert output.read_bytes() == b"previous release"
    assert len(assembled_inputs) == 1
    assert len(stages) == 1 and not os.path.exists(stages[0])
    assert list(tmp_path.glob("*.source")) == []


def test_keyed_invalid_stage_is_not_uploaded_or_published_and_is_removed(
        monkeypatch, tmp_path):
    source = tmp_path / "app.exe"
    output = tmp_path / "app.packed.exe"
    source.write_bytes(b"source")
    output.write_bytes(b"previous release")
    stages = _patch_pipeline(
        monkeypatch, fail=False, server_shard=b"s" * 32)
    monkeypatch.setattr(
        keyed_validation, "validate_staged_output",
        lambda *_args, **_kwargs: keyed_validation.KeyedValidationResult(
            False, "metadata envelope AES-GCM authentication failed"))
    content_ids: list[str] = []
    monkeypatch.setattr(
        orchestrator, "_pe_content_id",
        lambda path: content_ids.append(path) or "a" * 64)
    uploads: list[dict] = []
    monkeypatch.setattr(
        orchestrator, "_upload_shard",
        lambda *_args, **kwargs: uploads.append(kwargs))

    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(
            output_path=str(output), is_dll=False,
            server_shard=True,
            shard_url=f"https://{orchestrator._SHARD_API_HOST}",
            shard_auth="build-token", shard_license_id="license-1",
            shard_hwid_hash="b" * 64))

    assert not result.ok
    assert "staged output failed keyed validation" in result.error
    assert "AES-GCM authentication failed" in result.error
    assert output.read_bytes() == b"previous release"
    assert content_ids == []
    assert uploads == []
    assert len(stages) == 1
    assert not os.path.exists(stages[0])


def _minimal_packed_pe(*, live_offsets: tuple[int, ...],
                       decoy_offsets: tuple[int, ...]) -> bytes:
    """Build enough PE geometry for report.validate_packed behavioral tests."""
    blob = bytearray(0xE00)
    blob[:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x80)
    blob[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", blob, coff, 0x8664, 3, 0, 0, 0, 0xF0, 0x0022)
    optional = coff + 20
    struct.pack_into("<H", blob, optional, 0x20B)
    struct.pack_into("<I", blob, optional + 0x38, 0x8000)
    section_table = optional + 0xF0

    def section(index, name, virtual_size, rva, raw_size, raw_ptr, chars):
        off = section_table + index * 40
        blob[off:off + 8] = name.ljust(8, b"\0")
        struct.pack_into("<IIII", blob, off + 8,
                         virtual_size, rva, raw_size, raw_ptr)
        struct.pack_into("<I", blob, off + 36, chars)

    section(0, b".ldata", 0x400, 0x2000, 0x400, 0x200, 0xC0000040)
    section(1, b".ltext", 0x400, 0x3000, 0x400, 0x600, 0x60000020)
    section(2, b".rdata2", 0x400, 0x4000, 0x400, 0xA00, 0x40000040)

    info = container.PackInfo(
        original_image_base=0x140000000,
        original_size_of_image=0x2000,
        oep_rva=0x1000,
        is_dll=0,
        flags=0,
        section_count=1,
        meta_rva=0x4000,
        meta_stored_size=0x80,
        meta_uncompressed_size=0x100,
        meta_nonce=b"n" * 12,
        meta_tag=b"t" * 16,
        sections_off=0,
        imports_off=container.SECTIONDESC_SIZE,
        imports_size=4,
        relocs_off=container.SECTIONDESC_SIZE + 4,
        relocs_size=0,
        aes_key_enc=b"k" * 32,
        kdf_salt=b"s" * 16,
        stub_text_rva=0x3000,
        stub_text_size=0x100,
    ).pack()
    for offset in live_offsets + decoy_offsets:
        blob[offset:offset + len(info)] = info
    return bytes(blob)


def test_validator_ignores_read_only_decoy_and_accepts_one_live_container(tmp_path):
    packed = tmp_path / "packed.exe"
    packed.write_bytes(_minimal_packed_pe(live_offsets=(0x200,), decoy_offsets=(0xA80,)))

    result = report.validate_packed(str(packed))

    assert result.ok
    assert result.magic_offset == 0x200
    assert result.warnings == ["ignored 1 decoy PackInfo candidate(s)"]


def test_validator_rejects_decoy_only_container(tmp_path):
    packed = tmp_path / "packed.exe"
    packed.write_bytes(_minimal_packed_pe(live_offsets=(), decoy_offsets=(0xA80,)))

    result = report.validate_packed(str(packed))

    assert not result.ok
    assert "none is a structurally valid live container" in result.reason


def test_validator_rejects_ambiguous_live_containers(tmp_path):
    packed = tmp_path / "packed.exe"
    packed.write_bytes(_minimal_packed_pe(live_offsets=(0x200, 0x300), decoy_offsets=()))

    result = report.validate_packed(str(packed))

    assert not result.ok
    assert "ambiguous output" in result.reason


def _detection_header_fixture(*, offset=0x40, characteristics=0x0022):
    """Header-only bytes: not an executable image and never given to a PE parser."""
    blob = bytearray(offset + 24)
    blob[:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, offset)
    blob[offset:offset + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", blob, offset + 4,
                     0x8664, 1, 0, 0, 0, 0, characteristics)
    return bytes(blob)


def _detection_bad_fixture(case):
    blob = bytearray(_detection_header_fixture())
    if case == "empty":
        return b""
    if case == "short-dos":
        return bytes(blob[:0x3F])
    if case == "missing-mz":
        blob[:2] = b"ZZ"
    elif case in ("offset-zero", "offset-before-dos-end", "offset-at-eof",
                  "offset-past-eof", "offset-u32-max"):
        offset = {
            "offset-zero": 0,
            "offset-before-dos-end": 0x3F,
            "offset-at-eof": len(blob),
            "offset-past-eof": len(blob) + 1,
            "offset-u32-max": 0xFFFFFFFF,
        }[case]
        struct.pack_into("<I", blob, 0x3C, offset)
    elif case == "short-signature":
        return bytes(blob[:0x40 + 3])
    elif case == "signature-only":
        return bytes(blob[:0x40 + 4])
    elif case == "short-coff":
        return bytes(blob[:0x40 + 4 + 18])
    elif case == "one-characteristics-byte":
        return bytes(blob[:-1])
    elif case == "missing-pe":
        blob[0x40:0x44] = b"PE!!"
    else:
        raise AssertionError(case)
    return bytes(blob)


def _detection_forbid_native_parser(monkeypatch):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("header detection must stop before native PE parsing")

    monkeypatch.setattr(pe_analyze, "analyze_pe", unexpected)


@pytest.mark.parametrize("offset,characteristics,expected", [
    (0x40, 0x0022, False),
    (0x40, 0x2022, True),
    (0x80, 0x2000, True),
    (0x80, 0xDFFF, False),
    (0x1000, 0xFFFF, True),
    (0x1000, 0, False),
], ids=["exact-end-exe", "exact-end-dll", "dos-stub-dll",
        "unrelated-flags", "large-dos-stub-dll", "clear-flags-exe"])
def test_detect_is_dll_classifies_complete_headers_without_native_parser(
        monkeypatch, tmp_path, offset, characteristics, expected):
    _detection_forbid_native_parser(monkeypatch)
    source = tmp_path / ("misleading.exe" if expected else "misleading.dll")
    raw = _detection_header_fixture(offset=offset, characteristics=characteristics)
    source.write_bytes(raw)

    assert orchestrator.detect_is_dll(str(source)) is expected
    assert source.read_bytes() == raw


@pytest.mark.parametrize("case,reason", [
    ("empty", "truncated DOS header"),
    ("short-dos", "truncated DOS header"),
    ("missing-mz", "no DOS signature"),
    ("offset-zero", "overlaps DOS header"),
    ("offset-before-dos-end", "overlaps DOS header"),
    ("offset-at-eof", "truncated PE/COFF header"),
    ("offset-past-eof", "truncated PE/COFF header"),
    ("offset-u32-max", "truncated PE/COFF header"),
    ("short-signature", "truncated PE/COFF header"),
    ("signature-only", "truncated PE/COFF header"),
    ("short-coff", "truncated PE/COFF header"),
    ("one-characteristics-byte", "truncated PE/COFF header"),
    ("missing-pe", "no PE signature"),
])
def test_detect_is_dll_rejects_malformed_headers_as_value_error(
        monkeypatch, tmp_path, case, reason):
    _detection_forbid_native_parser(monkeypatch)
    source = tmp_path / "invalid.exe"
    raw = _detection_bad_fixture(case)
    source.write_bytes(raw)

    with pytest.raises(ValueError, match=reason) as caught:
        orchestrator.detect_is_dll(str(source))

    assert str(source) in str(caught.value)
    assert source.read_bytes() == raw


class _DetectionReadObserver:
    def __init__(self, source, reads, seeks, *, short_second=None):
        self.source = source
        self.reads = reads
        self.seeks = seeks
        self.short_second = short_second

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.source.close()

    def fileno(self):
        return self.source.fileno()

    def read(self, size=-1):
        assert 0 < size <= 0x40, "only fixed-size header reads are permitted"
        self.reads.append(size)
        raw = self.source.read(size)
        if len(self.reads) == 2 and self.short_second is not None:
            return raw[:self.short_second]
        return raw

    def seek(self, offset):
        self.seeks.append(offset)
        return self.source.seek(offset)


def _detection_observe_reads(monkeypatch, *, short_second=None):
    import builtins

    reads, seeks = [], []

    def opened(path, mode):
        return _DetectionReadObserver(
            builtins.open(path, mode), reads, seeks, short_second=short_second)

    monkeypatch.setattr(orchestrator, "open", opened, raising=False)
    return reads, seeks


def test_detect_is_dll_reads_at_most_88_bytes_without_reading_body(monkeypatch, tmp_path):
    _detection_forbid_native_parser(monkeypatch)
    source = tmp_path / "large-fixture.exe"
    source.write_bytes(_detection_header_fixture(offset=0x1000) + b"x" * (1024 * 1024))
    reads, _seeks = _detection_observe_reads(monkeypatch)

    assert orchestrator.detect_is_dll(str(source)) is False
    assert 0 < sum(reads) <= 88


def test_detect_is_dll_rejects_out_of_bounds_offset_before_seeking(monkeypatch, tmp_path):
    _detection_forbid_native_parser(monkeypatch)
    source = tmp_path / "invalid.exe"
    source.write_bytes(_detection_bad_fixture("offset-u32-max"))
    reads, seeks = _detection_observe_reads(monkeypatch)

    with pytest.raises(ValueError, match="truncated PE/COFF header"):
        orchestrator.detect_is_dll(str(source))

    assert reads == [0x40]
    assert seeks == []


@pytest.mark.parametrize("short_second", [0, 4, 23])
def test_detect_is_dll_handles_short_read_after_size_check(
        monkeypatch, tmp_path, short_second):
    _detection_forbid_native_parser(monkeypatch)
    source = tmp_path / "short-read.exe"
    raw = _detection_header_fixture()
    source.write_bytes(raw)
    _detection_observe_reads(monkeypatch, short_second=short_second)

    with pytest.raises(ValueError, match="truncated PE/COFF header"):
        orchestrator.detect_is_dll(str(source))

    assert source.read_bytes() == raw


def test_detect_is_dll_preserves_missing_file_os_error(monkeypatch, tmp_path):
    _detection_forbid_native_parser(monkeypatch)
    with pytest.raises(FileNotFoundError):
        orchestrator.detect_is_dll(str(tmp_path / "missing.exe"))


@pytest.mark.parametrize("case", ["empty", "one-characteristics-byte"])
def test_pack_file_reports_detection_value_error_and_removes_private_snapshot(
        monkeypatch, tmp_path, case):
    _detection_forbid_native_parser(monkeypatch)
    monkeypatch.delenv("LETHE_ENABLE_EXPERIMENTAL_VIRTUALIZATION", raising=False)
    source = tmp_path / "invalid.exe"
    output = tmp_path / "previous.exe"
    raw = _detection_bad_fixture(case)
    source.write_bytes(raw)
    output.write_bytes(b"previous release")

    result = orchestrator.pack_file(
        str(source), orchestrator.PackOptions(output_path=str(output)))

    assert result.ok is False
    assert result.error.startswith("ValueError:")
    assert "is not a valid PE" in result.error
    assert source.read_bytes() == raw
    assert output.read_bytes() == b"previous release"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["invalid.exe", "previous.exe"]


@pytest.mark.parametrize("case", ["empty", "one-characteristics-byte"])
def test_limited_inputs_wrap_detection_errors_before_native_preflight(
        monkeypatch, tmp_path, case):
    from tools import pack_limited_release as limited

    _detection_forbid_native_parser(monkeypatch)
    source = tmp_path / "invalid.exe"
    raw = _detection_bad_fixture(case)
    source.write_bytes(raw)

    with pytest.raises(limited.LimitedReleaseError, match="cannot inspect") as caught:
        limited._inputs(SimpleNamespace(exe=[str(source)], dll=[]))

    assert isinstance(caught.value.__cause__, ValueError)
    assert "is not a valid PE" in str(caught.value)
    assert source.read_bytes() == raw
    assert list(tmp_path.iterdir()) == [source]


@pytest.mark.parametrize("case", ["empty", "one-characteristics-byte"])
def test_limited_cli_renders_detection_failure_without_traceback(
        monkeypatch, tmp_path, capsys, case):
    from tools import pack_limited_release as limited

    _detection_forbid_native_parser(monkeypatch)
    source = tmp_path / "invalid.exe"
    raw = _detection_bad_fixture(case)
    source.write_bytes(raw)
    # Exercise the real input/error boundary only; no candidate admission,
    # signing, packing, or successful publication is mocked or claimed here.
    monkeypatch.setattr(limited, "build_bundle", limited._inputs)

    status = limited.main([
        "--stub-path", str(tmp_path / "unused-stub.dll"),
        "--output-dir", str(tmp_path / "unused-output"), "--exe", str(source),
    ])

    captured = capsys.readouterr()
    assert status == limited.EXIT_ERROR
    assert captured.out == ""
    assert "limited release: FAILED: cannot inspect" in captured.err
    assert "is not a valid PE" in captured.err
    assert "Traceback" not in captured.err
    assert source.read_bytes() == raw
    assert list(tmp_path.iterdir()) == [source]
