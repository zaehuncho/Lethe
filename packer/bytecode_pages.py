"""Authenticated page envelopes for selected-function Daedalus programs.

This module is the pack-time half of ``stub/src/bytecode_pages.[ch]``.  It is
deliberately independent from the PE materializer: the envelope ABI and its
native reader can be proven before selected-function descriptors are upgraded
to point at sealed programs.

Format v1 is canonical.  All integer fields are little-endian and every offset
is relative to the beginning of the envelope::

    header[128]
    page_record[page_count]  # <plaintext_size, ciphertext_offset, tag[16]>
    ciphertext[plaintext_size]

The header authenticates a SHA-256 digest of the complete page table.  Each
page has an independent HKDF-SHA256-derived AES-256-GCM key and nonce, and its
AAD binds the layout, program identity, page index, length, and offset.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


MAGIC: Final = b"DVPG"
VERSION: Final = 1
FLAGS: Final = 0
HEADER_SIZE: Final = 128
RECORD_SIZE: Final = 24
MIN_PAGE_SIZE: Final = 256
MAX_PAGE_SIZE: Final = 4096
MAX_PAGE_COUNT: Final = 4096
MAX_PLAINTEXT_SIZE: Final = MAX_PAGE_SIZE * MAX_PAGE_COUNT
MASTER_KEY_SIZE: Final = 32
PROGRAM_ID_SIZE: Final = 16
SALT_SIZE: Final = 16
TAG_SIZE: Final = 16
NONCE_SIZE: Final = 12
MATERIAL_SIZE: Final = MASTER_KEY_SIZE + NONCE_SIZE

HKDF_INFO_META: Final = b"LetheDvmMetaKeyNonceV1"
HKDF_INFO_PAGE: Final = b"LetheDvmPageKeyNonceV1"
META_AAD_DOMAIN: Final = b"LetheDvmMetaAAD1"
PAGE_AAD_DOMAIN: Final = b"LetheDvmPageAAD1"

_HEADER = struct.Struct("<4sHHIIII16s16sIIII32s16s8s")
_RECORD = struct.Struct("<II16s")
_HEADER_PREFIX_SIZE: Final = 72
_METADATA_TAG_OFFSET: Final = 104

assert _HEADER.size == HEADER_SIZE
assert _RECORD.size == RECORD_SIZE
assert len(META_AAD_DOMAIN) == 16
assert len(PAGE_AAD_DOMAIN) == 16


class BytecodePageError(ValueError):
    """Base error for the authenticated bytecode-page format."""


class BytecodePageFormatError(BytecodePageError):
    """The envelope is non-canonical, truncated, or out of bounds."""


class BytecodePageAuthenticationError(BytecodePageError):
    """The metadata or a page failed authentication."""


@dataclass(frozen=True)
class PageRecord:
    plaintext_size: int
    ciphertext_offset: int
    tag: bytes


@dataclass(frozen=True)
class PageEnvelopeView:
    blob: bytes
    page_size: int
    plaintext_size: int
    page_count: int
    program_id: bytes
    salt: bytes
    table_offset: int
    data_offset: int
    table_size: int
    data_size: int
    table_sha256: bytes
    metadata_tag: bytes
    records: tuple[PageRecord, ...]


def _require_exact(value: bytes | bytearray | memoryview, size: int,
                   label: str) -> bytes:
    raw = bytes(value)
    if len(raw) != size:
        raise BytecodePageError(f"{label} must be exactly {size} bytes")
    return raw


def _valid_page_size(page_size: int) -> bool:
    return (
        isinstance(page_size, int)
        and MIN_PAGE_SIZE <= page_size <= MAX_PAGE_SIZE
        and page_size & (page_size - 1) == 0
    )


def _derive_material(master_key: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=MATERIAL_SIZE,
        salt=salt,
        info=info,
    ).derive(master_key)


def derive_metadata_key_nonce(
    master_key: bytes | bytearray | memoryview,
    salt: bytes | bytearray | memoryview,
    program_id: bytes | bytearray | memoryview,
) -> tuple[bytes, bytes]:
    key = _require_exact(master_key, MASTER_KEY_SIZE, "master key")
    checked_salt = _require_exact(salt, SALT_SIZE, "salt")
    checked_id = _require_exact(program_id, PROGRAM_ID_SIZE, "program id")
    material = _derive_material(
        key, checked_salt, HKDF_INFO_META + checked_id
    )
    return material[:MASTER_KEY_SIZE], material[MASTER_KEY_SIZE:]


def derive_page_key_nonce(
    master_key: bytes | bytearray | memoryview,
    salt: bytes | bytearray | memoryview,
    program_id: bytes | bytearray | memoryview,
    page_index: int,
) -> tuple[bytes, bytes]:
    key = _require_exact(master_key, MASTER_KEY_SIZE, "master key")
    checked_salt = _require_exact(salt, SALT_SIZE, "salt")
    checked_id = _require_exact(program_id, PROGRAM_ID_SIZE, "program id")
    if not isinstance(page_index, int) or not 0 <= page_index < MAX_PAGE_COUNT:
        raise BytecodePageError("page index is outside the derivation domain")
    material = _derive_material(
        key,
        checked_salt,
        HKDF_INFO_PAGE + checked_id + struct.pack("<I", page_index),
    )
    return material[:MASTER_KEY_SIZE], material[MASTER_KEY_SIZE:]


def _pack_header(
    *,
    page_size: int,
    plaintext_size: int,
    page_count: int,
    program_id: bytes,
    salt: bytes,
    table_offset: int,
    data_offset: int,
    table_size: int,
    data_size: int,
    table_sha256: bytes,
    metadata_tag: bytes,
) -> bytes:
    return _HEADER.pack(
        MAGIC,
        VERSION,
        HEADER_SIZE,
        FLAGS,
        page_size,
        plaintext_size,
        page_count,
        program_id,
        salt,
        table_offset,
        data_offset,
        table_size,
        data_size,
        table_sha256,
        metadata_tag,
        bytes(8),
    )


def _metadata_aad(header: bytes) -> bytes:
    canonical = bytearray(header)
    canonical[_METADATA_TAG_OFFSET:_METADATA_TAG_OFFSET + TAG_SIZE] = bytes(
        TAG_SIZE
    )
    return META_AAD_DOMAIN + canonical


def _page_aad(header: bytes, page_index: int, plaintext_size: int,
              ciphertext_offset: int) -> bytes:
    return (
        PAGE_AAD_DOMAIN
        + header[:_HEADER_PREFIX_SIZE]
        + struct.pack("<III", page_index, plaintext_size, ciphertext_offset)
    )


def seal_program(
    program: bytes | bytearray | memoryview,
    master_key: bytes | bytearray | memoryview,
    *,
    program_id: bytes | bytearray | memoryview,
    page_size: int = MAX_PAGE_SIZE,
    salt: bytes | bytearray | memoryview | None = None,
) -> bytes:
    """Seal one complete VM program into a canonical v1 page envelope.

    ``salt`` defaults to 16 CSPRNG bytes.  Supplying it is intended for
    reproducible builds and known-answer vectors; callers must not reuse the
    same master-key/salt/program-id tuple for different plaintext.
    """
    plaintext = bytes(program)
    key = _require_exact(master_key, MASTER_KEY_SIZE, "master key")
    checked_id = _require_exact(program_id, PROGRAM_ID_SIZE, "program id")
    checked_salt = os.urandom(SALT_SIZE) if salt is None else _require_exact(
        salt, SALT_SIZE, "salt"
    )
    if not _valid_page_size(page_size):
        raise BytecodePageError(
            f"page size must be a power of two from {MIN_PAGE_SIZE} through {MAX_PAGE_SIZE}"
        )
    if not plaintext:
        raise BytecodePageError("program must not be empty")
    if len(plaintext) > MAX_PLAINTEXT_SIZE:
        raise BytecodePageError("program exceeds the authenticated paging limit")
    page_count = (len(plaintext) + page_size - 1) // page_size
    if page_count > MAX_PAGE_COUNT:
        raise BytecodePageError("program requires too many authenticated pages")

    table_offset = HEADER_SIZE
    table_size = page_count * RECORD_SIZE
    data_offset = table_offset + table_size
    data_size = len(plaintext)
    header_without_hash = _pack_header(
        page_size=page_size,
        plaintext_size=len(plaintext),
        page_count=page_count,
        program_id=checked_id,
        salt=checked_salt,
        table_offset=table_offset,
        data_offset=data_offset,
        table_size=table_size,
        data_size=data_size,
        table_sha256=bytes(32),
        metadata_tag=bytes(TAG_SIZE),
    )

    records: list[bytes] = []
    ciphertexts: list[bytes] = []
    offset = data_offset
    for page_index in range(page_count):
        start = page_index * page_size
        page = plaintext[start:start + page_size]
        page_key, nonce = derive_page_key_nonce(
            key, checked_salt, checked_id, page_index
        )
        aad = _page_aad(header_without_hash, page_index, len(page), offset)
        sealed = AESGCM(page_key).encrypt(nonce, page, aad)
        ciphertext, tag = sealed[:-TAG_SIZE], sealed[-TAG_SIZE:]
        records.append(_RECORD.pack(len(page), offset, tag))
        ciphertexts.append(ciphertext)
        offset += len(ciphertext)

    table = b"".join(records)
    table_hash = hashlib.sha256(table).digest()
    unauthenticated_header = _pack_header(
        page_size=page_size,
        plaintext_size=len(plaintext),
        page_count=page_count,
        program_id=checked_id,
        salt=checked_salt,
        table_offset=table_offset,
        data_offset=data_offset,
        table_size=table_size,
        data_size=data_size,
        table_sha256=table_hash,
        metadata_tag=bytes(TAG_SIZE),
    )
    meta_key, meta_nonce = derive_metadata_key_nonce(
        key, checked_salt, checked_id
    )
    metadata_tag = AESGCM(meta_key).encrypt(
        meta_nonce, b"", _metadata_aad(unauthenticated_header)
    )
    assert len(metadata_tag) == TAG_SIZE
    header = _pack_header(
        page_size=page_size,
        plaintext_size=len(plaintext),
        page_count=page_count,
        program_id=checked_id,
        salt=checked_salt,
        table_offset=table_offset,
        data_offset=data_offset,
        table_size=table_size,
        data_size=data_size,
        table_sha256=table_hash,
        metadata_tag=metadata_tag,
    )
    return header + table + b"".join(ciphertexts)


def parse_envelope(blob: bytes | bytearray | memoryview) -> PageEnvelopeView:
    raw = bytes(blob)
    if len(raw) < HEADER_SIZE:
        raise BytecodePageFormatError("page envelope header is truncated")
    if len(raw) > HEADER_SIZE + MAX_PAGE_COUNT * RECORD_SIZE + MAX_PLAINTEXT_SIZE:
        raise BytecodePageFormatError("page envelope exceeds the format limit")
    (
        magic,
        version,
        header_size,
        flags,
        page_size,
        plaintext_size,
        page_count,
        program_id,
        salt,
        table_offset,
        data_offset,
        table_size,
        data_size,
        table_sha256,
        metadata_tag,
        reserved,
    ) = _HEADER.unpack_from(raw)
    if magic != MAGIC:
        raise BytecodePageFormatError("page envelope magic is invalid")
    if version != VERSION:
        raise BytecodePageFormatError("page envelope version is unsupported")
    if header_size != HEADER_SIZE:
        raise BytecodePageFormatError("page envelope header size is non-canonical")
    if flags != FLAGS:
        raise BytecodePageFormatError("page envelope flags are unsupported")
    if not _valid_page_size(page_size):
        raise BytecodePageFormatError("page envelope page size is invalid")
    if not 0 < plaintext_size <= MAX_PLAINTEXT_SIZE:
        raise BytecodePageFormatError("page envelope plaintext size is invalid")
    expected_count = (plaintext_size + page_size - 1) // page_size
    if page_count != expected_count or page_count > MAX_PAGE_COUNT:
        raise BytecodePageFormatError("page envelope page count is non-canonical")
    expected_table_size = page_count * RECORD_SIZE
    if table_offset != HEADER_SIZE or table_size != expected_table_size:
        raise BytecodePageFormatError("page envelope table geometry is non-canonical")
    if data_offset != table_offset + table_size or data_size != plaintext_size:
        raise BytecodePageFormatError("page envelope data geometry is non-canonical")
    if data_offset + data_size != len(raw):
        raise BytecodePageFormatError("page envelope length is non-canonical")
    if reserved != bytes(8):
        raise BytecodePageFormatError("page envelope reserved bytes are nonzero")

    records: list[PageRecord] = []
    offset = data_offset
    remaining = plaintext_size
    for page_index in range(page_count):
        record_offset = table_offset + page_index * RECORD_SIZE
        size, ciphertext_offset, tag = _RECORD.unpack_from(raw, record_offset)
        expected_size = min(page_size, remaining)
        if size != expected_size or ciphertext_offset != offset:
            raise BytecodePageFormatError(
                f"page record {page_index} geometry is non-canonical"
            )
        records.append(PageRecord(size, ciphertext_offset, tag))
        offset += size
        remaining -= size
    if remaining != 0 or offset != len(raw):
        raise BytecodePageFormatError("page record coverage is incomplete")
    return PageEnvelopeView(
        blob=raw,
        page_size=page_size,
        plaintext_size=plaintext_size,
        page_count=page_count,
        program_id=program_id,
        salt=salt,
        table_offset=table_offset,
        data_offset=data_offset,
        table_size=table_size,
        data_size=data_size,
        table_sha256=table_sha256,
        metadata_tag=metadata_tag,
        records=tuple(records),
    )


def _verify_metadata(view: PageEnvelopeView, master_key: bytes) -> None:
    table = view.blob[view.table_offset:view.data_offset]
    actual_hash = hashlib.sha256(table).digest()
    if not hmac.compare_digest(actual_hash, view.table_sha256):
        raise BytecodePageAuthenticationError(
            "page envelope metadata authentication failed"
        )
    meta_key, nonce = derive_metadata_key_nonce(
        master_key, view.salt, view.program_id
    )
    try:
        AESGCM(meta_key).decrypt(
            nonce,
            view.metadata_tag,
            _metadata_aad(view.blob[:HEADER_SIZE]),
        )
    except InvalidTag as exc:
        raise BytecodePageAuthenticationError(
            "page envelope metadata authentication failed"
        ) from exc


def _open_page(view: PageEnvelopeView, master_key: bytes,
               page_index: int) -> bytes:
    if not isinstance(page_index, int) or not 0 <= page_index < view.page_count:
        raise BytecodePageError("page index is outside the envelope")
    record = view.records[page_index]
    ciphertext = view.blob[
        record.ciphertext_offset:record.ciphertext_offset + record.plaintext_size
    ]
    page_key, nonce = derive_page_key_nonce(
        master_key, view.salt, view.program_id, page_index
    )
    aad = _page_aad(
        view.blob[:HEADER_SIZE],
        page_index,
        record.plaintext_size,
        record.ciphertext_offset,
    )
    try:
        return AESGCM(page_key).decrypt(
            nonce, ciphertext + record.tag, aad
        )
    except InvalidTag as exc:
        raise BytecodePageAuthenticationError(
            f"bytecode page {page_index} authentication failed"
        ) from exc


class AuthenticatedPageCache:
    """One-page plaintext cache with explicit wipe-on-evict semantics."""

    def __init__(self, blob: bytes | bytearray | memoryview,
                 master_key: bytes | bytearray | memoryview):
        key = _require_exact(master_key, MASTER_KEY_SIZE, "master key")
        self.view = parse_envelope(blob)
        _verify_metadata(self.view, key)
        self._page = bytearray(self.view.page_size)
        self._cached_index: int | None = None
        self._cached_size = 0

    def _wipe(self) -> None:
        self._page[:] = bytes(len(self._page))
        self._cached_index = None
        self._cached_size = 0

    def get_page(
        self,
        page_index: int,
        master_key: bytes | bytearray | memoryview,
    ) -> memoryview:
        key = _require_exact(master_key, MASTER_KEY_SIZE, "master key")
        if page_index == self._cached_index:
            return memoryview(self._page)[:self._cached_size]
        self._wipe()
        try:
            plaintext = _open_page(self.view, key, page_index)
        except Exception:
            self._wipe()
            raise
        self._page[:len(plaintext)] = plaintext
        self._cached_index = page_index
        self._cached_size = len(plaintext)
        return memoryview(self._page)[:self._cached_size]

    def read(
        self,
        offset: int,
        size: int,
        master_key: bytes | bytearray | memoryview,
    ) -> bytes:
        if not isinstance(offset, int) or not isinstance(size, int):
            raise BytecodePageError("read offset and size must be integers")
        if offset < 0 or size < 0 or offset + size > self.view.plaintext_size:
            raise BytecodePageError("bytecode read is outside the program")
        output = bytearray(size)
        consumed = 0
        while consumed < size:
            absolute = offset + consumed
            page_index = absolute // self.view.page_size
            within_page = absolute % self.view.page_size
            page = self.get_page(page_index, master_key)
            take = min(size - consumed, len(page) - within_page)
            output[consumed:consumed + take] = page[
                within_page:within_page + take
            ]
            consumed += take
        return bytes(output)

    def close(self) -> None:
        self._wipe()

    def __enter__(self) -> "AuthenticatedPageCache":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def open_program(
    blob: bytes | bytearray | memoryview,
    master_key: bytes | bytearray | memoryview,
) -> bytes:
    key = _require_exact(master_key, MASTER_KEY_SIZE, "master key")
    with AuthenticatedPageCache(blob, key) as cache:
        return cache.read(0, cache.view.plaintext_size, key)


__all__ = [
    "AuthenticatedPageCache",
    "BytecodePageAuthenticationError",
    "BytecodePageError",
    "BytecodePageFormatError",
    "HEADER_SIZE",
    "MAGIC",
    "MAX_PAGE_COUNT",
    "MAX_PAGE_SIZE",
    "MAX_PLAINTEXT_SIZE",
    "MIN_PAGE_SIZE",
    "PageEnvelopeView",
    "PageRecord",
    "RECORD_SIZE",
    "VERSION",
    "derive_metadata_key_nonce",
    "derive_page_key_nonce",
    "open_program",
    "parse_envelope",
    "seal_program",
]
