"""Race-resistant signing-stable identity for AMD64 PE32+ images."""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


_IMAGE_FILE_DLL = 0x2000
_WIN_CERT_REVISION_1_0 = 0x0100
_WIN_CERT_REVISION_2_0 = 0x0200
_WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002


@dataclass(frozen=True)
class FileSnapshot:
    """Immutable bytes and filesystem identity captured from one held handle."""

    path: Path
    data: bytes
    sha256: str
    size: int
    device: int
    inode: int
    link_count: int
    mtime_ns: int
    ctime_ns: int

    @property
    def filesystem_identity(self) -> tuple[int, int] | None:
        if self.inode == 0:
            return None
        return self.device, self.inode


@dataclass(frozen=True)
class PEImageInfo:
    checksum_offset: int
    security_directory_offset: int
    certificate_offset: int
    certificate_size: int
    subject_kind: str


@dataclass(frozen=True)
class SigningDelta:
    prepared: FileSnapshot
    signed: FileSnapshot
    signing_stable_pe_id: str
    subject_kind: str


def _is_linklike(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())
    except OSError:
        return True


def _reject_linklike_ancestors(path: Path, what: str) -> None:
    current = path.absolute()
    while True:
        if _is_linklike(current):
            raise ValueError(f"{what} cannot traverse a link or junction")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _stat_fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_fingerprint(value: os.stat_result) -> tuple[int, ...]:
    if os.name == "nt":
        # CreateFileW keeps writers and renames out while the handle is held.
        # Windows can still report transient timestamp precision differences
        # between fstat() and stat() for a newly-created file.
        return value.st_dev, value.st_ino, value.st_size
    return _stat_fingerprint(value)


def _open_windows_snapshot_stream(path: Path, what: str):
    import ctypes
    import ctypes.wintypes
    import msvcrt

    generic_read = 0x80000000
    file_share_read = 0x00000001
    open_existing = 3
    file_attribute_reparse_point = 0x00000400
    file_flag_open_reparse_point = 0x00200000
    file_flag_sequential_scan = 0x08000000
    invalid_handle_value = ctypes.c_void_p(-1).value

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", ctypes.wintypes.DWORD),
            ("creation_time", ctypes.wintypes.FILETIME),
            ("last_access_time", ctypes.wintypes.FILETIME),
            ("last_write_time", ctypes.wintypes.FILETIME),
            ("volume_serial_number", ctypes.wintypes.DWORD),
            ("file_size_high", ctypes.wintypes.DWORD),
            ("file_size_low", ctypes.wintypes.DWORD),
            ("number_of_links", ctypes.wintypes.DWORD),
            ("file_index_high", ctypes.wintypes.DWORD),
            ("file_index_low", ctypes.wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.HANDLE,
    )
    create_file.restype = ctypes.wintypes.HANDLE
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = (
        ctypes.wintypes.HANDLE,
        ctypes.POINTER(ByHandleFileInformation),
    )
    get_information.restype = ctypes.wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (ctypes.wintypes.HANDLE,)
    close_handle.restype = ctypes.wintypes.BOOL

    handle = create_file(
        str(path),
        generic_read,
        file_share_read,
        None,
        open_existing,
        file_flag_open_reparse_point | file_flag_sequential_scan,
        None,
    )
    if handle == invalid_handle_value:
        error = ctypes.get_last_error()
        raise ValueError(f"cannot open {what}: Windows error {error}")
    owns_handle = True
    try:
        information = ByHandleFileInformation()
        if not get_information(handle, ctypes.byref(information)):
            error = ctypes.get_last_error()
            raise ValueError(f"cannot inspect {what}: Windows error {error}")
        if information.file_attributes & file_attribute_reparse_point:
            raise ValueError(f"{what} cannot be a reparse point")
        try:
            descriptor = msvcrt.open_osfhandle(
                int(handle), os.O_RDONLY | os.O_BINARY)
        except OSError as exc:
            raise ValueError(f"cannot adopt {what} handle: {exc}") from exc
        owns_handle = False
        try:
            return os.fdopen(descriptor, "rb", closefd=True)
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        if owns_handle:
            close_handle(handle)


def _open_posix_snapshot_stream(path: Path, what: str):
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open {what}: {exc}") from exc
    try:
        return os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise


def _open_snapshot_stream(path: Path, what: str):
    if os.name == "nt":
        return _open_windows_snapshot_stream(path, what)
    return _open_posix_snapshot_stream(path, what)


def snapshot_file(
    path: str | Path,
    *,
    what: str = "input file",
    reject_hardlinks: bool = False,
    max_bytes: int | None = None,
) -> FileSnapshot:
    """Copy one regular file through a held handle and detect concurrent mutation.

    An optional positive ``max_bytes`` bounds the read, including one extra
    byte to detect growth. The limit must be smaller than ``sys.maxsize`` so
    that sentinel read size is representable by Python; this is not a PE size
    policy. ``None`` preserves the original unbounded read behavior.
    """
    if max_bytes is not None and (
        type(max_bytes) is not int or not 1 <= max_bytes < sys.maxsize
    ):
        raise ValueError("max_bytes must be an integer from 1 through sys.maxsize - 1")
    raw_path = Path(path).absolute()
    _reject_linklike_ancestors(raw_path, what)
    try:
        with _open_snapshot_stream(raw_path, what) as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"{what} is not a regular file")
            if reject_hardlinks and before.st_nlink > 1:
                raise ValueError(f"{what} must not be hard-linked")
            if max_bytes is None:
                data = stream.read()
            else:
                if before.st_size > max_bytes:
                    raise ValueError(f"{what} exceeds max_bytes ({max_bytes})")
                try:
                    data = stream.read(max_bytes + 1)
                except (OverflowError, MemoryError) as exc:
                    raise ValueError(f"{what} bounded read could not use max_bytes ({max_bytes})") from exc
                if len(data) > max_bytes:
                    raise ValueError(f"{what} exceeds max_bytes ({max_bytes}) while reading")
            after = os.fstat(stream.fileno())
            if max_bytes is not None and after.st_size > max_bytes:
                raise ValueError(f"{what} grew beyond max_bytes ({max_bytes}) while reading")
            path_after = os.stat(raw_path, follow_symlinks=False)
            if (_stable_fingerprint(before) != _stable_fingerprint(after)
                    or _stable_fingerprint(after) != _stable_fingerprint(path_after)
                    or len(data) != after.st_size):
                raise ValueError(f"{what} changed while being snapshotted")
            snapshot = FileSnapshot(
                path=raw_path,
                data=data,
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
                device=after.st_dev,
                inode=after.st_ino,
                link_count=after.st_nlink,
                mtime_ns=after.st_mtime_ns,
                ctime_ns=after.st_ctime_ns,
            )
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"cannot snapshot {what}: {exc}") from exc
    return snapshot


def _ranges_intersect(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _validate_certificate_records(
    data: bytes,
    *,
    certificate_offset: int,
    certificate_size: int,
    label: str,
) -> None:
    end = certificate_offset + certificate_size
    cursor = certificate_offset
    records = 0
    while cursor < end:
        if end - cursor < 8:
            raise ValueError(f"{label} has a truncated WIN_CERTIFICATE header")
        length, revision, certificate_type = struct.unpack_from("<IHH", data, cursor)
        if length < 8 or length > end - cursor:
            raise ValueError(f"{label} has an invalid WIN_CERTIFICATE length")
        if revision not in {_WIN_CERT_REVISION_1_0, _WIN_CERT_REVISION_2_0}:
            raise ValueError(f"{label} has an invalid WIN_CERTIFICATE revision")
        if certificate_type != _WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            raise ValueError(f"{label} has an unsupported WIN_CERTIFICATE type")
        aligned_length = (length + 7) & ~7
        if cursor + aligned_length > end:
            raise ValueError(f"{label} has a truncated aligned WIN_CERTIFICATE")
        if any(data[cursor + length:cursor + aligned_length]):
            raise ValueError(f"{label} has nonzero WIN_CERTIFICATE alignment padding")
        cursor += aligned_length
        records += 1
    if cursor != end or records == 0:
        raise ValueError(f"{label} has a malformed WIN_CERTIFICATE table")


def parse_pe_image(data: bytes, *, label: str = "PE image") -> PEImageInfo:
    """Parse and structurally validate fields used for signing identity."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{label} is not a valid PE (missing DOS header)")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    file_header = e_lfanew + 4
    optional_header = file_header + 20
    if (e_lfanew + 24 > len(data)
            or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00"):
        raise ValueError(f"{label} is not a valid PE (missing PE signature)")

    machine, section_count = struct.unpack_from("<HH", data, file_header)
    optional_size = struct.unpack_from("<H", data, file_header + 16)[0]
    characteristics = struct.unpack_from("<H", data, file_header + 18)[0]
    optional_end = optional_header + optional_size
    if optional_end > len(data) or optional_size < 0x98:
        raise ValueError(f"{label} has a truncated PE32+ optional header")
    if machine != 0x8664:
        raise ValueError(f"{label} is not an AMD64 PE image")
    if struct.unpack_from("<H", data, optional_header)[0] != 0x20B:
        raise ValueError(f"{label} is not an x64 PE32+ image")
    if section_count < 1 or section_count > 96:
        raise ValueError(f"{label} has an invalid section count")

    section_table = optional_end
    section_table_end = section_table + section_count * 40
    if section_table_end > len(data):
        raise ValueError(f"{label} has a truncated section table")
    size_of_headers = struct.unpack_from("<I", data, optional_header + 0x3C)[0]
    if (size_of_headers < section_table_end or size_of_headers > len(data)
            or size_of_headers == 0):
        raise ValueError(f"{label} has an invalid SizeOfHeaders")

    checksum_offset = optional_header + 0x40
    number_of_dirs = struct.unpack_from("<I", data, optional_header + 0x6C)[0]
    if number_of_dirs <= 4:
        raise ValueError(f"{label} has no certificate-table directory entry")
    security_directory_offset = optional_header + 0x70 + (4 * 8)
    if security_directory_offset + 8 > optional_end:
        raise ValueError(f"{label} has a truncated certificate-table directory")

    mapped_file_ranges = [(0, size_of_headers)]
    for index in range(section_count):
        entry = section_table + index * 40
        raw_size, raw_offset = struct.unpack_from("<II", data, entry + 16)
        if raw_size == 0:
            continue
        raw_end = raw_offset + raw_size
        if raw_offset < size_of_headers or raw_end > len(data):
            raise ValueError(f"{label} section[{index}] has an invalid raw range")
        mapped_file_ranges.append((raw_offset, raw_end))

    certificate_offset, certificate_size = struct.unpack_from(
        "<II", data, security_directory_offset)
    if bool(certificate_offset) != bool(certificate_size):
        raise ValueError(f"{label} has an invalid certificate-table range")
    if certificate_offset:
        certificate_end = certificate_offset + certificate_size
        certificate_range = (certificate_offset, certificate_end)
        if certificate_offset & 7:
            raise ValueError(f"{label} certificate table is not 8-byte aligned")
        if certificate_end > len(data):
            raise ValueError(f"{label} has an out-of-range certificate table")
        if any(_ranges_intersect(certificate_range, mapped) for mapped in mapped_file_ranges):
            raise ValueError(f"{label} certificate table overlaps mapped PE bytes")
        if certificate_end != len(data):
            raise ValueError(f"{label} certificate table is not terminal")
        _validate_certificate_records(
            data,
            certificate_offset=certificate_offset,
            certificate_size=certificate_size,
            label=label,
        )

    return PEImageInfo(
        checksum_offset=checksum_offset,
        security_directory_offset=security_directory_offset,
        certificate_offset=certificate_offset,
        certificate_size=certificate_size,
        subject_kind="dll" if characteristics & _IMAGE_FILE_DLL else "exe",
    )


def _content_id_through(data: bytes, info: PEImageInfo, content_end: int) -> str:
    if content_end < info.security_directory_offset + 8 or content_end > len(data):
        raise ValueError("PE content identity boundary is invalid")
    after_security_directory = info.security_directory_offset + 8
    digest = hashlib.sha256()
    digest.update(data[:info.checksum_offset])
    digest.update(data[info.checksum_offset + 4:info.security_directory_offset])
    digest.update(data[after_security_directory:content_end])
    return digest.hexdigest()


def pe_content_id_from_bytes(data: bytes, *, label: str = "PE image") -> str:
    info = parse_pe_image(data, label=label)
    content_end = info.certificate_offset if info.certificate_offset else len(data)
    return _content_id_through(data, info, content_end)


def pe_content_id(path: str | Path) -> str:
    snapshot = snapshot_file(path, what="PE image")
    return pe_content_id_from_bytes(snapshot.data, label=str(path))


def validate_signing_delta_snapshots(
    prepared: FileSnapshot,
    signed: FileSnapshot,
    *,
    expected_prepared_sha256: str,
    expected_prepared_size: int,
    expected_signing_stable_pe_id: str,
    expected_subject_kind: str,
) -> SigningDelta:
    """Require that Authenticode insertion is the only prepared-to-signed delta."""
    if prepared.sha256 != expected_prepared_sha256:
        raise ValueError("prepared subject SHA-256 does not match challenge")
    if prepared.size != expected_prepared_size:
        raise ValueError("prepared subject size does not match challenge")
    prepared_info = parse_pe_image(prepared.data, label="prepared subject")
    signed_info = parse_pe_image(signed.data, label="signed subject")
    if prepared_info.subject_kind != expected_subject_kind:
        raise ValueError("prepared subject PE kind does not match challenge")
    if signed_info.subject_kind != expected_subject_kind:
        raise ValueError("signed subject PE kind does not match challenge")
    if prepared_info.certificate_offset or prepared_info.certificate_size:
        raise ValueError("prepared subject must not already contain a certificate")
    if not signed_info.certificate_offset or not signed_info.certificate_size:
        raise ValueError("signed subject has no terminal WIN_CERTIFICATE table")
    if prepared.size & 7:
        raise ValueError("prepared subject size must be 8-byte aligned before signing")

    prepared_stable_id = pe_content_id_from_bytes(
        prepared.data, label="prepared subject")
    if prepared_stable_id != expected_signing_stable_pe_id:
        raise ValueError("signing-stable PE identity does not match challenge")

    expected_certificate_offset = prepared.size
    if signed_info.certificate_offset != expected_certificate_offset:
        raise ValueError("certificate insertion is not immediately after prepared bytes")

    mutable_ranges = (
        (prepared_info.checksum_offset, prepared_info.checksum_offset + 4),
        (
            prepared_info.security_directory_offset,
            prepared_info.security_directory_offset + 8,
        ),
    )
    if (prepared_info.checksum_offset != signed_info.checksum_offset
            or prepared_info.security_directory_offset
                != signed_info.security_directory_offset):
        raise ValueError("signed subject moved mutable PE header fields")
    cursor = 0
    for start, end in mutable_ranges:
        if prepared.data[cursor:start] != signed.data[cursor:start]:
            raise ValueError("signed subject changed bytes outside signing fields")
        cursor = end
    if prepared.data[cursor:] != signed.data[cursor:prepared.size]:
        raise ValueError("signed subject changed bytes outside signing fields")
    signed_delta_id = _content_id_through(
        signed.data, signed_info, prepared.size)
    if signed_delta_id != expected_signing_stable_pe_id:
        raise ValueError("signed content identity does not match prepared subject")
    if pe_content_id_from_bytes(
            signed.data, label="signed subject") != expected_signing_stable_pe_id:
        raise ValueError("standalone signed PE identity does not match prepared subject")
    return SigningDelta(
        prepared=prepared,
        signed=signed,
        signing_stable_pe_id=prepared_stable_id,
        subject_kind=expected_subject_kind,
    )


def validate_signing_delta(
    prepared_path: str | Path,
    signed_path: str | Path,
    *,
    expected_prepared_sha256: str,
    expected_prepared_size: int,
    expected_signing_stable_pe_id: str,
    expected_subject_kind: str,
) -> SigningDelta:
    prepared = snapshot_file(
        prepared_path, what="prepared subject", reject_hardlinks=True)
    signed = snapshot_file(signed_path, what="signed subject", reject_hardlinks=True)
    return validate_signing_delta_snapshots(
        prepared,
        signed,
        expected_prepared_sha256=expected_prepared_sha256,
        expected_prepared_size=expected_prepared_size,
        expected_signing_stable_pe_id=expected_signing_stable_pe_id,
        expected_subject_kind=expected_subject_kind,
    )


__all__ = [
    "FileSnapshot",
    "PEImageInfo",
    "SigningDelta",
    "parse_pe_image",
    "pe_content_id",
    "pe_content_id_from_bytes",
    "snapshot_file",
    "validate_signing_delta",
    "validate_signing_delta_snapshots",
]
