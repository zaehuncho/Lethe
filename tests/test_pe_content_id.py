"""Signing-stable build identifier used by the shard store and bootstrap."""

from __future__ import annotations

import builtins
import hashlib
import importlib
import os
import stat
import struct
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from packer import orchestrator
from packer.orchestrator import _pe_content_id
from packer.pe_content_id import pe_content_id, snapshot_file, validate_signing_delta


PE_CONTENT_ID_MODULE = importlib.import_module("packer.pe_content_id")


def _minimal_pe() -> bytearray:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    file_header = e_lfanew + 4
    optional_header = file_header + 20
    struct.pack_into("<H", data, file_header, 0x8664)
    struct.pack_into("<H", data, file_header + 2, 1)
    struct.pack_into("<H", data, file_header + 16, 0xF0)
    struct.pack_into("<H", data, optional_header, 0x20B)
    struct.pack_into("<I", data, optional_header + 0x3C, 0x200)
    struct.pack_into("<I", data, optional_header + 0x6C, 16)
    section = optional_header + 0xF0
    data[section:section + 5] = b".text"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    data[0x200:0x211] = b"signed-id-content"
    return data


def _certificate(payload: bytes = b"PKCS7") -> bytes:
    length = 8 + len(payload)
    record = struct.pack("<IHH", length, 0x0200, 0x0002) + payload
    return record + b"\x00" * ((-length) & 7)


def _signed(unsigned: bytes) -> bytes:
    signed = bytearray(unsigned)
    optional_header = 0x80 + 4 + 20
    struct.pack_into("<I", signed, optional_header + 0x40, 0x12345678)
    cert = _certificate()
    cert_off = (len(signed) + 7) & ~7
    signed.extend(b"\x00" * (cert_off - len(signed)))
    struct.pack_into(
        "<II", signed, optional_header + 0x70 + 4 * 8, cert_off, len(cert))
    signed.extend(cert)
    return bytes(signed)


def test_orchestrator_keeps_private_compatibility_alias():
    assert orchestrator._pe_content_id is pe_content_id


def test_content_id_ignores_checksum_and_authenticode_certificate(tmp_path):
    unsigned = _minimal_pe()
    unsigned_path = tmp_path / "unsigned.exe"
    unsigned_path.write_bytes(unsigned)
    expected = _pe_content_id(str(unsigned_path))

    signed = _signed(unsigned)
    signed_path = tmp_path / "signed.exe"
    signed_path.write_bytes(signed)

    assert _pe_content_id(str(signed_path)) == expected


def test_content_id_changes_when_executable_content_changes(tmp_path):
    original = _minimal_pe()
    original_path = tmp_path / "original.exe"
    original_path.write_bytes(original)

    changed = bytearray(original)
    changed[0x205] ^= 0xFF
    changed_path = tmp_path / "changed.exe"
    changed_path.write_bytes(changed)

    assert _pe_content_id(str(changed_path)) != _pe_content_id(str(original_path))


def test_content_id_rejects_out_of_range_certificate_table(tmp_path):
    malformed = _minimal_pe()
    optional_header = 0x80 + 4 + 20
    struct.pack_into("<II", malformed, optional_header + 0x70 + 4 * 8,
                     len(malformed) + 8, 32)
    path = tmp_path / "malformed.exe"
    path.write_bytes(malformed)

    with pytest.raises(ValueError, match="out-of-range certificate table"):
        _pe_content_id(str(path))


def test_content_id_rejects_non_amd64_image(tmp_path):
    image = _minimal_pe()
    struct.pack_into("<H", image, 0x80 + 4, 0xAA64)
    path = tmp_path / "arm64.exe"
    path.write_bytes(image)

    with pytest.raises(ValueError, match="not an AMD64 PE"):
        _pe_content_id(str(path))


def test_content_id_rejects_certificate_overlapping_text_section(tmp_path):
    image = _minimal_pe()
    optional_header = 0x80 + 4 + 20
    struct.pack_into(
        "<II", image, optional_header + 0x70 + 4 * 8, 0x200, 0x200)
    struct.pack_into("<IHH", image, 0x200, 0x200, 0x0200, 0x0002)
    path = tmp_path / "overlap.exe"
    path.write_bytes(image)

    with pytest.raises(ValueError, match="overlaps mapped PE bytes"):
        pe_content_id(path)


def test_signing_delta_accepts_only_terminal_authenticode_insertion(tmp_path):
    prepared = tmp_path / "prepared.exe"
    signed = tmp_path / "signed.exe"
    prepared.write_bytes(_minimal_pe())
    signed.write_bytes(_signed(prepared.read_bytes()))
    expected_id = pe_content_id(prepared)

    delta = validate_signing_delta(
        prepared,
        signed,
        expected_prepared_sha256=hashlib.sha256(prepared.read_bytes()).hexdigest(),
        expected_prepared_size=prepared.stat().st_size,
        expected_signing_stable_pe_id=expected_id,
        expected_subject_kind="exe",
    )

    assert delta.signing_stable_pe_id == expected_id
    assert delta.signed.sha256 == hashlib.sha256(signed.read_bytes()).hexdigest()
    assert pe_content_id(signed) == expected_id


def test_signing_delta_rejects_signer_alignment_insertion(tmp_path):
    prepared = tmp_path / "prepared-unaligned.exe"
    signed = tmp_path / "signed-unaligned.exe"
    prepared.write_bytes(_minimal_pe() + b"X")
    signed.write_bytes(_signed(prepared.read_bytes()))
    expected_id = pe_content_id(prepared)

    with pytest.raises(ValueError, match="8-byte aligned before signing"):
        validate_signing_delta(
            prepared,
            signed,
            expected_prepared_sha256=hashlib.sha256(prepared.read_bytes()).hexdigest(),
            expected_prepared_size=prepared.stat().st_size,
            expected_signing_stable_pe_id=expected_id,
            expected_subject_kind="exe",
        )


def test_signing_delta_rejects_non_signing_byte_change(tmp_path):
    prepared = tmp_path / "prepared.exe"
    signed = tmp_path / "signed.exe"
    prepared.write_bytes(_minimal_pe())
    changed = bytearray(_signed(prepared.read_bytes()))
    changed[0x205] ^= 0xFF
    signed.write_bytes(changed)

    with pytest.raises(ValueError, match="identity|outside signing fields"):
        validate_signing_delta(
            prepared,
            signed,
            expected_prepared_sha256=hashlib.sha256(prepared.read_bytes()).hexdigest(),
            expected_prepared_size=prepared.stat().st_size,
            expected_signing_stable_pe_id=pe_content_id(prepared),
            expected_subject_kind="exe",
        )


@pytest.mark.parametrize("operation", ("overwrite", "replace"))
def test_snapshot_blocks_or_rejects_same_size_mutation_after_final_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str,
):
    path = tmp_path / "racing.bin"
    replacement = tmp_path / "replacement.bin"
    path.write_bytes(b"original")
    replacement.write_bytes(b"replaced")
    original_fstat = PE_CONTENT_ID_MODULE.os.fstat
    calls = 0
    attempted = False
    blocked = False

    def racing_fstat(descriptor):
        nonlocal attempted, blocked, calls
        calls += 1
        if calls == 2:
            attempted = True
            try:
                if operation == "overwrite":
                    with builtins.open(path, "r+b", buffering=0) as writer:
                        writer.seek(0)
                        writer.write(b"mutated!")
                        os.fsync(writer.fileno())
                else:
                    os.replace(replacement, path)
            except OSError:
                blocked = True
        return original_fstat(descriptor)

    monkeypatch.setattr(PE_CONTENT_ID_MODULE.os, "fstat", racing_fstat)
    try:
        snapshot = snapshot_file(path)
    except ValueError as exc:
        assert attempted
        assert "changed while" in str(exc) or "cannot snapshot" in str(exc)
    else:
        assert attempted
        assert blocked
        assert snapshot.data == b"original"


class _IntegerSubclass(int):
    pass


@pytest.mark.parametrize("limit", [
    True, False, 0, -1, 1.0, "1", b"1", [], object(), _IntegerSubclass(1),
    sys.maxsize, sys.maxsize + 1, 10 ** 200,
])
def test_snapshot_rejects_invalid_limit_before_path_conversion_or_io(limit, monkeypatch):
    class UnusedPath:
        def __fspath__(self):
            raise AssertionError("path conversion preceded limit validation")

    def unexpected_io(*args, **kwargs):
        raise AssertionError("I/O preceded limit validation")

    monkeypatch.setattr(PE_CONTENT_ID_MODULE, "_reject_linklike_ancestors", unexpected_io)
    monkeypatch.setattr(PE_CONTENT_ID_MODULE, "_open_snapshot_stream", unexpected_io)
    with pytest.raises(ValueError, match="max_bytes must be an integer"):
        snapshot_file(UnusedPath(), max_bytes=limit)


@contextmanager
def _synthetic_snapshot_reader(monkeypatch, *, before_size, data, after_size=None, read_error=None):
    """Instrument a small held-handle fixture without allocating a large file."""
    state = SimpleNamespace(read_calls=[], fstat_calls=0, closed=False)

    def info(size):
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=size,
                               st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4)

    after_size = before_size if after_size is None else after_size

    class Reader:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            state.closed = True

        def fileno(self):
            return 101

        def read(self, *args):
            state.read_calls.append(args)
            if read_error is not None:
                raise read_error
            return data

    def held_fstat(descriptor):
        assert descriptor == 101
        state.fstat_calls += 1
        return info(before_size if state.fstat_calls == 1 else after_size)

    with monkeypatch.context() as patch:
        patch.setattr(PE_CONTENT_ID_MODULE, "_reject_linklike_ancestors", lambda *args: None)
        patch.setattr(PE_CONTENT_ID_MODULE, "_open_snapshot_stream", lambda *args: Reader())
        patch.setattr(PE_CONTENT_ID_MODULE.os, "fstat", held_fstat)
        patch.setattr(PE_CONTENT_ID_MODULE.os, "stat", lambda *args, **kwargs: info(after_size))
        yield state


@pytest.mark.parametrize("data,limit", [(b"", 1), (b"ab", 3), (b"abc", 3)])
def test_snapshot_bounded_read_accepts_empty_under_and_exact_boundary(tmp_path, data, limit):
    path = tmp_path / "small.bin"
    path.write_bytes(data)
    result = snapshot_file(path, max_bytes=limit)
    assert result.data == data
    assert result.size == len(data)
    assert result.sha256 == hashlib.sha256(data).hexdigest()


def test_snapshot_rejects_held_handle_oversize_without_read(monkeypatch):
    with _synthetic_snapshot_reader(monkeypatch, before_size=4, data=b"unused") as state:
        with pytest.raises(ValueError, match="exceeds max_bytes"):
            snapshot_file("synthetic.bin", max_bytes=3)
    assert state.read_calls == []
    assert state.fstat_calls == 1
    assert state.closed


def test_snapshot_bounded_read_uses_one_extra_byte(monkeypatch):
    with _synthetic_snapshot_reader(monkeypatch, before_size=3, data=b"abc") as state:
        result = snapshot_file("synthetic.bin", max_bytes=5)
    assert state.read_calls == [(6,)]
    assert result.data == b"abc"
    assert state.closed


def test_snapshot_detects_growth_from_bounded_read_before_snapshot_construction(monkeypatch):
    with _synthetic_snapshot_reader(monkeypatch, before_size=2, data=b"abcd") as state:
        with pytest.raises(ValueError, match="exceeds max_bytes.*while reading"):
            snapshot_file("synthetic.bin", max_bytes=3)
    assert state.read_calls == [(4,)]
    assert state.fstat_calls == 1
    assert state.closed


def test_snapshot_detects_growth_in_final_held_handle_size(monkeypatch):
    with _synthetic_snapshot_reader(monkeypatch, before_size=3, data=b"abc", after_size=4) as state:
        with pytest.raises(ValueError, match="grew beyond max_bytes"):
            snapshot_file("synthetic.bin", max_bytes=3)
    assert state.read_calls == [(4,)]
    assert state.fstat_calls == 2
    assert state.closed


def test_snapshot_preserves_fingerprint_rejection_within_byte_limit(monkeypatch):
    with _synthetic_snapshot_reader(monkeypatch, before_size=2, data=b"abc", after_size=3):
        with pytest.raises(ValueError, match="changed while being snapshotted"):
            snapshot_file("synthetic.bin", max_bytes=5)


def test_snapshot_largest_representable_limit_uses_sentinel_without_giant_allocation(monkeypatch):
    with _synthetic_snapshot_reader(monkeypatch, before_size=3, data=b"abc") as state:
        assert snapshot_file("synthetic.bin", max_bytes=sys.maxsize - 1).data == b"abc"
    assert state.read_calls == [(sys.maxsize,)]


@pytest.mark.parametrize("error", [OverflowError("synthetic read-size error"), MemoryError("synthetic allocation error")])
def test_snapshot_bounded_reader_resource_failure_is_a_validation_error(monkeypatch, error):
    with _synthetic_snapshot_reader(monkeypatch, before_size=3, data=b"", read_error=error) as state:
        with pytest.raises(ValueError, match="bounded read could not use max_bytes") as raised:
            snapshot_file("synthetic.bin", max_bytes=3)
    assert raised.value.__cause__ is error
    assert state.read_calls == [(4,)]
    assert state.closed


@pytest.mark.parametrize("kwargs", [{}, {"max_bytes": None}])
def test_snapshot_default_keeps_original_unsized_read(monkeypatch, kwargs):
    with _synthetic_snapshot_reader(monkeypatch, before_size=3, data=b"abc") as state:
        assert snapshot_file("synthetic.bin", **kwargs).data == b"abc"
    assert state.read_calls == [()]
    assert state.fstat_calls == 2
