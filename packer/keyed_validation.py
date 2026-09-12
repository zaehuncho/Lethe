"""Keyed, non-executing validation of a freshly staged Lethe artifact.

``packer.report.validate_packed`` deliberately stops at PE/container structure.
This module is the builder-only cryptographic gate: it consumes the in-memory
``PayloadArtifacts`` that produced the staged file, authenticates and opens the
metadata and every protected section, and checks the emitted geometry against
those artifacts.  It never recovers a key from the output and never executes it.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
import zlib
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import container, report

_AES_KEY_SIZE = 32
_KDF_SALT_SIZE = 16
_SERVER_SHARD_SIZE = 32
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000
_U32_MAX = 0xFFFFFFFF


@dataclass(frozen=True)
class KeyedValidationResult:
    ok: bool
    reason: str = ""
    section_count: int = 0
    plaintext_bytes: int = 0

    def summary(self) -> str:
        if not self.ok:
            return f"invalid keyed container: {self.reason}"
        return (
            f"authenticated staged container: {self.section_count} protected "
            f"section(s), {self.plaintext_bytes:,} decrypted byte(s)"
        )


class _ValidationError(ValueError):
    pass


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise _ValidationError(reason)


def _same_bytes(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(bytes(left), bytes(right))


def _same_hash(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(
        hashlib.sha256(left).digest(), hashlib.sha256(right).digest())


def _read_raw_rva(data: bytes, layout, rva: int, size: int, label: str) -> bytes:
    _require(0 <= rva <= _U32_MAX and 0 < size <= _U32_MAX,
             f"{label} has invalid RVA/size")
    owner = layout.section_for_rva_range(rva, size, raw=True)
    _require(owner is not None, f"{label} is not fully file-backed")
    _require(bool(owner.characteristics & _SCN_MEM_READ),
             f"{label} is not in a readable PE section")
    _require(not (owner.characteristics & (_SCN_MEM_WRITE | _SCN_MEM_EXECUTE)),
             f"{label} is not in a read-only, non-executable PE section")
    file_offset = owner.raw_ptr + (rva - owner.rva)
    end = file_offset + size
    _require(end <= len(data), f"{label} runs past end of file")
    return data[file_offset:end]


def _read_mapped_rva(data: bytes, layout, rva: int, size: int,
                     label: str) -> bytes:
    _require(0 <= rva <= _U32_MAX and 0 < size <= _U32_MAX,
             f"{label} has invalid RVA/size")
    owner = layout.section_for_rva_range(rva, size, raw=False)
    _require(owner is not None, f"{label} is outside the mapped PE image")
    delta = rva - owner.rva
    file_backed = 0
    if delta < owner.raw_size:
        file_backed = min(size, owner.raw_size - delta)
    if file_backed:
        file_offset = owner.raw_ptr + delta
        prefix = data[file_offset:file_offset + file_backed]
        _require(len(prefix) == file_backed,
                 f"{label} file backing is truncated")
    else:
        prefix = b""
    return prefix + bytes(size - file_backed)


def _decompress_exact(compressed: bytes, expected_size: int,
                      label: str) -> bytes:
    _require(0 <= expected_size <= _U32_MAX,
             f"{label} has invalid uncompressed size")
    inflater = zlib.decompressobj()
    try:
        plain = inflater.decompress(compressed, expected_size + 1)
    except zlib.error as exc:
        raise _ValidationError(f"{label} is not a valid zlib stream") from exc
    _require(not inflater.unconsumed_tail,
             f"{label} expands beyond its declared size")
    _require(inflater.eof, f"{label} zlib stream is truncated")
    _require(not inflater.unused_data,
             f"{label} zlib stream has trailing data")
    _require(len(plain) == expected_size,
             f"{label} decompressed size does not match its descriptor")
    return plain


def _open_unit(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes,
               expected_size: int, aad: bytes, label: str) -> bytes:
    try:
        compressed = AESGCM(key).decrypt(
            bytes(nonce), bytes(ciphertext) + bytes(tag), aad)
    except (InvalidTag, ValueError) as exc:
        raise _ValidationError(f"{label} AES-GCM authentication failed") from exc
    return _decompress_exact(compressed, expected_size, label)


def _derive_key(master_key: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(), length=_AES_KEY_SIZE, salt=salt, info=info
    ).derive(master_key)


def _artifact_sections(artifacts):
    items = list(artifacts.stored_sections)
    sections = []
    for index, item in enumerate(items):
        try:
            desc = item.desc
            ciphertext = bytes(item.data)
        except (AttributeError, TypeError) as exc:
            raise _ValidationError(
                f"in-memory protected section {index} is malformed") from exc
        _require(isinstance(desc, container.SectionDesc),
                 f"in-memory protected section {index} has no SectionDesc")
        sections.append((desc, ciphertext))
    _require(sections, "in-memory payload has no protected sections")
    return sections


def _validate_non_overlapping(ranges, label: str) -> None:
    ordered = sorted(ranges)
    for index, (start, end) in enumerate(ordered):
        _require(0 <= start < end <= _U32_MAX + 1,
                 f"{label} has an invalid range")
        if index:
            _require(ordered[index - 1][1] <= start,
                     f"{label} ranges overlap")


def validate_staged_output(
        path: str, artifacts, *, server_shard: Optional[bytes] = None,
        expected_stub_text_rva: Optional[int] = None,
        expected_stub_text_size: Optional[int] = None,
        structural: Optional[report.ValidationResult] = None,
        ) -> KeyedValidationResult:
    """Authenticate and round-trip a staged file using builder-held material.

    Keys and shards are consumed only in memory.  Neither successful results nor
    failure text contains key material.  ``server_shard`` is required only for a
    server-sharded build so the embedded masked-key binding can also be checked.
    """
    try:
        master_key = bytes(artifacts.aes_key)
        salt = bytes(artifacts.kdf_salt)
        _require(len(master_key) == _AES_KEY_SIZE,
                 "in-memory AES master key has an invalid length")
        _require(len(salt) == _KDF_SALT_SIZE,
                 "in-memory KDF salt has an invalid length")
        shard = bytes(server_shard) if server_shard is not None else bytes(32)
        _require(len(shard) == _SERVER_SHARD_SIZE,
                 "in-memory server shard has an invalid length")

        if structural is None:
            structural = report.validate_packed(path)
        _require(structural.ok,
                 "structural validation must succeed before keyed validation")
        _require(structural.magic_offset >= 0,
                 "structural validation did not identify a live container")

        try:
            with open(path, "rb") as stream:
                data = stream.read()
        except OSError as exc:
            raise _ValidationError("cannot read staged output") from exc

        layout = report._parse_pe_layout(data)
        live = []
        cursor = 0
        while True:
            offset = data.find(container.MAGIC, cursor)
            if offset < 0:
                break
            cursor = offset + 1
            if offset + container.PACKINFO_SIZE > len(data):
                continue
            try:
                candidate = container.PackInfo.from_bytes(
                    data[offset:offset + container.PACKINFO_SIZE])
            except (ValueError, struct.error):
                continue
            if report._candidate_is_live(candidate, offset, layout):
                live.append((offset, candidate))
        _require(len(live) == 1,
                 "keyed validation requires exactly one live container")
        offset, info = live[0]
        _require(offset == structural.magic_offset,
                 "live container changed after structural validation")

        expected_sections = _artifact_sections(artifacts)
        expected_meta = artifacts.metadata
        scalar_pairs = (
            (info.flags, int(artifacts.flags), "flags"),
            (info.section_count, len(expected_sections), "section count"),
            (info.oep_rva, int(artifacts.oep_rva), "entry point"),
            (info.is_dll, int(artifacts.is_dll), "image type"),
            (info.original_image_base, int(artifacts.original_image_base),
             "original image base"),
            (info.original_size_of_image,
             int(artifacts.original_size_of_image), "original image size"),
            (info.pdata_rva, int(artifacts.pdata_rva), "exception table RVA"),
            (info.pdata_count, int(artifacts.pdata_count),
             "exception table count"),
            (info.meta_uncompressed_size,
             int(expected_meta.meta_uncompressed_size), "metadata plain size"),
        )
        for actual, expected, name in scalar_pairs:
            _require(actual == expected, f"staged {name} differs from build artifacts")
        _require(info.meta_uncompressed_size <= info.original_size_of_image,
                 "metadata plaintext exceeds the original image size bound")
        _require(_same_bytes(info.kdf_salt, salt),
                 "staged KDF salt differs from build artifacts")

        if expected_stub_text_rva is not None:
            _require(info.stub_text_rva == int(expected_stub_text_rva),
                     "staged stub text RVA differs from assembly result")
        if expected_stub_text_size is not None:
            _require(info.stub_text_size == int(expected_stub_text_size),
                     "staged stub text size differs from assembly result")

        stub_text = _read_mapped_rva(
            data, layout, info.stub_text_rva, info.stub_text_size, "stub text")
        text_hash = hashlib.sha256(stub_text).digest()
        mask = _derive_key(text_hash, salt, container.HKDF_INFO_CODEHASH)
        expected_masked_key = bytes(
            key_byte ^ mask_byte ^ shard_byte
            for key_byte, mask_byte, shard_byte in zip(master_key, mask, shard)
        )
        _require(_same_bytes(info.aes_key_enc, expected_masked_key),
                 "staged code-hash key binding does not match build artifacts")

        meta_ciphertext = _read_raw_rva(
            data, layout, info.meta_rva, info.meta_stored_size,
            "metadata ciphertext")
        meta_key = _derive_key(master_key, salt, container.HKDF_INFO_META)
        metadata_plain = _open_unit(
            meta_key, meta_ciphertext, info.meta_nonce, info.meta_tag,
            info.meta_uncompressed_size, container.build_metadata_aad(info),
            "metadata envelope")

        expected_descs = [desc for desc, _ciphertext in expected_sections]
        expected_plain, expected_offsets = container.build_metadata(
            container.pack_section_descs(expected_descs),
            bytes(artifacts.import_blob), bytes(artifacts.reloc_blob),
            bytes(artifacts.tls_blob),
            bytes(getattr(artifacts, "load_config_blob", b"")))
        _require(_same_hash(metadata_plain, expected_plain),
                 "metadata plaintext hash differs from build artifacts")
        _require(len(metadata_plain) == len(expected_plain),
                 "metadata plaintext size differs from build artifacts")
        _require(info.meta_stored_size == len(expected_meta.meta_stored),
                 "metadata ciphertext size differs from build artifacts")
        _require(_same_hash(meta_ciphertext, bytes(expected_meta.meta_stored)),
                 "metadata ciphertext hash differs from build artifacts")
        _require(_same_bytes(info.meta_nonce, expected_meta.meta_nonce),
                 "metadata nonce differs from build artifacts")
        _require(_same_bytes(info.meta_tag, expected_meta.meta_tag),
                 "metadata tag differs from build artifacts")

        export_range = None
        if info.dll_export_rva or info.dll_export_size:
            _require(bool(info.flags & container.FLAG_DLL_PRELOAD_IAT),
                     "export snapshot is present without the DLL preload flag")
            _require(info.dll_export_rva > 0 and info.dll_export_size >= 40,
                     "authenticated export snapshot geometry is invalid")
            export_bytes = _read_mapped_rva(
                data, layout, info.dll_export_rva, info.dll_export_size,
                "DLL export snapshot")
            _require(_same_bytes(
                hashlib.sha256(export_bytes).digest()[:16],
                info.dll_export_sha256_128),
                "DLL export snapshot hash differs from authenticated PackInfo")
            export_range = (
                info.dll_export_rva,
                info.dll_export_rva + info.dll_export_size,
            )
        else:
            _require(info.dll_export_rva == 0 and info.dll_export_size == 0 and
                     not any(info.dll_export_sha256_128),
                     "empty DLL export snapshot has nonzero authentication state")

        offset_pairs = (
            (info.sections_off, expected_offsets.sections_off, "sections"),
            (info.imports_off, expected_offsets.imports_off, "imports"),
            (info.imports_size, expected_offsets.imports_size, "imports size"),
            (info.relocs_off, expected_offsets.relocs_off, "relocations"),
            (info.relocs_size, expected_offsets.relocs_size,
             "relocations size"),
            (info.tls_off, expected_offsets.tls_off, "TLS"),
        )
        for actual, expected, name in offset_pairs:
            _require(actual == expected,
                     f"staged metadata {name} geometry differs from artifacts")

        desc_bytes = info.section_count * container.SECTIONDESC_SIZE
        _require(info.sections_off + desc_bytes <= len(metadata_plain),
                 "section descriptor table exceeds metadata")
        staged_descs = []
        for index in range(info.section_count):
            start = info.sections_off + index * container.SECTIONDESC_SIZE
            staged_descs.append(container.SectionDesc.from_bytes(
                metadata_plain[start:start + container.SECTIONDESC_SIZE]))

        stored_ranges = [(info.meta_rva,
                          info.meta_rva + info.meta_stored_size)]
        target_ranges = []
        total_plaintext = len(metadata_plain)
        for index, ((expected_desc, expected_ciphertext), staged_desc) in enumerate(
                zip(expected_sections, staged_descs)):
            _require(_same_bytes(staged_desc.pack(), expected_desc.pack()),
                     f"protected section {index} descriptor differs from artifacts")
            _require(staged_desc.stored_size == len(expected_ciphertext),
                     f"protected section {index} ciphertext size differs from artifacts")
            _require(staged_desc.stored_rva >= info.original_size_of_image,
                     f"protected section {index} storage overlaps original image")
            target_span = max(staged_desc.virtual_size,
                              staged_desc.uncompressed_size)
            _require(staged_desc.rva < info.original_size_of_image,
                     f"protected section {index} target begins outside original image")
            _require(staged_desc.rva + target_span <= info.original_size_of_image,
                     f"protected section {index} target exceeds original image")
            target_owner = layout.section_for_rva_range(
                staged_desc.rva, target_span, raw=False)
            _require(target_owner is not None,
                     f"protected section {index} target is not mapped")
            if target_owner.raw_size != 0:
                _require(export_range is not None,
                         f"protected section {index} target is not an empty placeholder")
                target_start = staged_desc.rva
                target_end = staged_desc.rva + target_span
                _require(
                    target_start <= export_range[0] and
                    export_range[1] <= target_end,
                    f"protected section {index} file backing is not the "
                    "authenticated DLL export snapshot")
                placeholder = bytearray(_read_mapped_rva(
                    data, layout, target_start, target_span,
                    f"protected section {index} placeholder"))
                export_start = export_range[0] - target_start
                export_end = export_range[1] - target_start
                placeholder[export_start:export_end] = bytes(
                    export_end - export_start)
                _require(not any(placeholder),
                         f"protected section {index} has unauthenticated "
                         "file-backed placeholder bytes")
            mapped_protection = target_owner.characteristics & (
                _SCN_MEM_READ | _SCN_MEM_WRITE | _SCN_MEM_EXECUTE)
            expected_protection = _SCN_MEM_READ | _SCN_MEM_WRITE
            if ((info.flags & container.FLAG_LOAD_CONFIG)
                    and staged_desc.characteristics & _SCN_MEM_EXECUTE):
                expected_protection = _SCN_MEM_READ | _SCN_MEM_EXECUTE
            _require(
                mapped_protection == expected_protection,
                f"protected section {index} placeholder protections are invalid")
            stored_ranges.append((staged_desc.stored_rva,
                                  staged_desc.stored_rva + staged_desc.stored_size))
            target_ranges.append((staged_desc.rva,
                                  staged_desc.rva + target_span))

            staged_ciphertext = _read_raw_rva(
                data, layout, staged_desc.stored_rva, staged_desc.stored_size,
                f"protected section {index} ciphertext")
            section_key = _derive_key(
                master_key, salt,
                container.HKDF_INFO_SECTION + struct.pack("<I", staged_desc.rva))
            plaintext = _open_unit(
                section_key, staged_ciphertext, staged_desc.gcm_nonce,
                staged_desc.gcm_tag, staged_desc.uncompressed_size,
                struct.pack("<I", staged_desc.rva),
                f"protected section {index}")
            _require(_same_hash(staged_ciphertext, expected_ciphertext),
                     f"protected section {index} ciphertext hash differs from artifacts")
            total_plaintext += len(plaintext)

        resource_bytes = bytes(getattr(artifacts, "rsrc_bytes", b""))
        resource_rva = int(getattr(artifacts, "rsrc_rva", 0))
        if resource_bytes:
            _require(0 < resource_rva < info.original_size_of_image,
                     "preserved resource RVA is outside the original image")
            _require(resource_rva + len(resource_bytes) <=
                     info.original_size_of_image,
                     "preserved resource data exceeds the original image")
            staged_resource = _read_raw_rva(
                data, layout, resource_rva, len(resource_bytes),
                "preserved resource data")
            _require(_same_hash(staged_resource, resource_bytes),
                     "preserved resource hash differs from build artifacts")
            target_ranges.append(
                (resource_rva, resource_rva + len(resource_bytes)))
            total_plaintext += len(resource_bytes)

        _validate_non_overlapping(stored_ranges, "stored payload")
        _validate_non_overlapping(target_ranges, "restored section")
        return KeyedValidationResult(
            True, section_count=info.section_count,
            plaintext_bytes=total_plaintext)
    except (_ValidationError, AttributeError, TypeError, ValueError,
            struct.error) as exc:
        reason = str(exc) or "unspecified keyed validation failure"
        return KeyedValidationResult(False, reason)


__all__ = ["KeyedValidationResult", "validate_staged_output"]
