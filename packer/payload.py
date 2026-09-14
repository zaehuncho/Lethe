"""Payload builder for the Lethe packer: compress + encrypt an analyzed PE
into the artifacts the assembler grafts into the output image.

Dependency
----------
Requires **cryptography** (``pip install cryptography``) for AES-256-GCM. Pure
build-time tooling; never shipped in the native stub.

Crypto / compression -- MUST match the C stub
---------------------------------------------
* One random **AES-256 master key** (32 B) is stored (masked) in the single
  ``PackInfo.aes_key_enc`` but NEVER encrypts anything directly. Each unit is
  encrypted under its own **HKDF-SHA256 subkey** derived from the master key, so
  leaking one subkey cannot decrypt the other units:
    - section subkey = ``HKDF(master, kdf_salt, info=b"Lethe-v1-section" ||
      <original section RVA as LE uint32>)``
    - metadata subkey = ``HKDF(master, kdf_salt, info=b"Lethe-v1-meta")``
  The stub recovers the master key (see below) then re-derives these subkeys with
  the SAME info labels + ``kdf_salt``. Each unit gets its own fresh random
  **12-byte nonce**; the **16-byte GCM tag** is stored *separately* (in
  ``SectionDesc.gcm_tag`` / ``meta_tag``), never appended to the stored
  ciphertext. ``AESGCM.encrypt`` returns ``ciphertext || tag``; we split the
  trailing 16 B off.
* Compression is **zlib (RFC 1950)** via the stdlib ``zlib`` module -- this is
  what the stub's bundled miniz ``mz_uncompress`` expects. Do **not** use
  ``lzma``: the stub cannot decode it.

Key masking split (why the RAW key is returned)
-----------------------------------------------
This module returns the **raw master key** + ``kdf_salt`` (the per-unit subkeys
are re-derived, never stored). It deliberately does NOT compute
``PackInfo.aes_key_enc``: that mask is
``key XOR HKDF-SHA256(SHA256(stub .text) || salt)`` and requires the *final
linked stub ``.text`` bytes*, which only the assembler has. The assembler owns
the XOR-masking (and ``stub_text_rva`` / ``stub_text_size``); we own the key
generation. Keeping these apart avoids importing stub artifacts here.

Assembler contract (IMPORTANT -- read before consuming ``PayloadArtifacts``)
---------------------------------------------------------------------------
Each ``SectionDesc.stored_rva`` records where that section's stored ciphertext
lives in the packed module -- but that RVA is only known once the assembler lays
out the appended payload region. And every ``SectionDesc`` (with its
``stored_rva``) is serialized *inside the encrypted metadata envelope*. So the
envelope cannot be finalized until layout is done. The required sequence is:

    parsed  = analyze_pe(path)
    art     = build_payload(parsed, options)          # envelope is PROVISIONAL

    # 1. Lay out the payload region. Place each section's ciphertext and set its
    #    stored_rva. (Place the metadata envelope LAST so section RVAs never
    #    depend on the envelope size.)
    for ss in art.stored_sections:
        ss.desc.stored_rva = <rva you placed ss.data at>

    # 2. Re-seal the envelope now that stored_rva values are final:
    aad_info = PackInfo(...)      # final critical geometry, including meta_rva
    env = art.reseal_metadata(aad_info)  # -> metadata, fresh nonce/tag

    # 3. Place env.meta_stored at the AAD-bound meta_rva; fill PackInfo:
    #      meta_rva, meta_stored_size=env.meta_stored_size,
    #      meta_uncompressed_size=env.meta_uncompressed_size,
    #      meta_nonce=env.meta_nonce, meta_tag=env.meta_tag,
    #      sections_off/imports_off/imports_size/relocs_off/relocs_size/tls_off
    #        = env.offsets.*
    # 4. section_count = art.section_count. (The SectionDesc[] is embedded in the
    #    sealed env.meta_stored -- there is no separate SectionDesc[] to write.)
    # 5. aes_key_enc = art.aes_key XOR HKDF(SHA256(stub .text)||art.kdf_salt);
    #    kdf_salt = art.kdf_salt.
    # 6. flags/oep_rva/is_dll/original_image_base/original_size_of_image/
    #    pdata_rva/pdata_count come straight off ``art``. Preserve
    #    ``art.rsrc_bytes`` PLAINTEXT at ``art.rsrc_rva``.

``build_payload`` creates one provisional v2 envelope using placeholder (0)
stored RVAs and metadata RVA. It is only *correct* once the assembler assigns
the final locations and re-seals with a matching PackInfo AAD context.
"""
from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass, replace
from typing import List, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:  # package import (normal case)
    from .container import (
        SectionDesc, MetadataOffsets, build_import_blob, build_tls_blob,
        build_metadata, pack_section_descs,
        FLAG_HAS_TLS, FLAG_HAS_EXCEPTIONS, FLAG_ANTIDEBUG, FLAG_MEMGUARD,
        FLAG_PAGED_DVM, FLAG_LOAD_CONFIG, FLAG_DLL_PRELOAD_IAT,
        FLAG_PROCESS_HARDENING,
    )
    from .pe_analyze import ParsedPE
except ImportError:  # pragma: no cover - allows standalone / importlib file loading
    from container import (  # type: ignore
        SectionDesc, MetadataOffsets, build_import_blob, build_tls_blob,
        build_metadata, pack_section_descs,
        FLAG_HAS_TLS, FLAG_HAS_EXCEPTIONS, FLAG_ANTIDEBUG, FLAG_MEMGUARD,
        FLAG_PAGED_DVM, FLAG_LOAD_CONFIG, FLAG_DLL_PRELOAD_IAT,
        FLAG_PROCESS_HARDENING,
    )
    from pe_analyze import ParsedPE  # type: ignore

__all__ = [
    "PayloadOptions",
    "StoredSection",
    "MetadataEnvelope",
    "PayloadArtifacts",
    "build_payload",
    "seal_metadata",
    "decrypt_unit",
]

AES_KEY_LEN = 32
KDF_SALT_LEN = 16
GCM_NONCE_LEN = 12
GCM_TAG_LEN = 16
# Must match stub/src/tls_anchor.h. The stub's PE TLS directory reserves this
# many loader-owned bytes per thread; larger original TLS templates cannot be
# represented safely and are rejected before an output artifact is written.
STUB_TLS_CAPACITY = 4096

# Canonical HKDF info labels live in container.py (mirrored byte-for-byte in the
# C stub's crypto.c). Import them — never define a second copy.
try:
    from . import container as _cnt
except ImportError:
    import container as _cnt  # type: ignore
HKDF_INFO_SECTION = _cnt.HKDF_INFO_SECTION
HKDF_INFO_META    = _cnt.HKDF_INFO_META

_RSRC_SECTION = ".rsrc"


# ---------------------------------------------------------------------------
# options
# ---------------------------------------------------------------------------


@dataclass
class PayloadOptions:
    """Payload-relevant knobs. The orchestrator's ``PackOptions`` is a superset
    and can be passed directly -- ``build_payload`` reads only these three
    attributes (falling back to these defaults if an attribute is absent)."""

    anti_debug: bool = False
    memory_guard: bool = False
    process_hardening: bool = False
    compression_level: int = 9


# ---------------------------------------------------------------------------
# artifact dataclasses
# ---------------------------------------------------------------------------


@dataclass
class StoredSection:
    """A protected section's on-disk artifact.

    ``data`` is the compressed-then-AES-GCM-encrypted ciphertext **without** the
    GCM tag (the tag is in ``desc.gcm_tag``). ``desc.stored_rva`` is a
    PLACEHOLDER (0) until the assembler assigns the RVA it places ``data`` at.
    """

    desc: SectionDesc
    data: bytes


@dataclass
class MetadataEnvelope:
    """The compressed+encrypted metadata blob and its PackInfo locators.

    ``meta_stored`` is ciphertext **without** the tag (``meta_tag`` holds it).
    """

    meta_stored: bytes
    meta_nonce: bytes
    meta_tag: bytes
    meta_uncompressed_size: int
    offsets: MetadataOffsets

    @property
    def meta_stored_size(self) -> int:
        return len(self.meta_stored)


@dataclass
class PayloadArtifacts:
    """Everything the assembler needs to emit the packed image.

    See the module docstring for the exact consumption sequence. In particular,
    ``metadata`` must be regenerated via :meth:`reseal_metadata` after the
    assembler sets every ``stored_sections[i].desc.stored_rva``.
    """

    # RAW master key; assembler XOR-masks it into PackInfo.aes_key_enc. Never
    # encrypts directly -- per-unit HKDF subkeys are derived from it (see module
    # docstring). The stub re-derives the subkeys after recovering this key.
    aes_key: bytes                      # 32 B master key
    kdf_salt: bytes                     # 16 B

    # protected sections (assembler assigns each desc.stored_rva during layout)
    stored_sections: List[StoredSection]

    # metadata envelope (PROVISIONAL until reseal_metadata after layout)
    metadata: MetadataEnvelope

    # PackInfo scalars carried through from the parse
    flags: int
    oep_rva: int
    is_dll: int                         # 0 / 1
    original_image_base: int
    original_size_of_image: int
    pdata_rva: int
    pdata_count: int

    # Resource owner section preserved PLAINTEXT by the assembler at rsrc_rva.
    # The PE directory may begin at a nonzero offset inside that section.
    rsrc_rva: int
    rsrc_bytes: bytes
    rsrc_directory_rva: int
    rsrc_directory_size: int

    # raw metadata inputs + params retained so the envelope can be re-sealed
    import_blob: bytes
    reloc_blob: bytes
    tls_blob: bytes
    compression_level: int
    load_config_blob: bytes = b""

    @property
    def section_count(self) -> int:
        return len(self.stored_sections)

    @property
    def section_descs(self) -> List[SectionDesc]:
        """The SectionDesc[] serialized into the metadata envelope (live objects;
        mutate ``.stored_rva`` then call :meth:`reseal_metadata`)."""
        return [ss.desc for ss in self.stored_sections]

    def reseal_metadata(self, aad_info: "_cnt.PackInfo") -> MetadataEnvelope:
        """Rebuild + re-encrypt the metadata envelope from the CURRENT
        ``stored_rva`` values (fresh nonce/tag). Call this after assigning every
        section's ``stored_rva`` and final metadata RVA. ``aad_info`` supplies
        the critical PackInfo geometry authenticated by format v2. Updates and
        returns ``self.metadata``."""
        meta_key = _derive_meta_key(self.aes_key, self.kdf_salt)
        self.metadata = seal_metadata(
            meta_key, self.section_descs, self.import_blob,
            self.reloc_blob, self.tls_blob, self.compression_level,
            aad_info=aad_info, load_config_blob=self.load_config_blob)
        return self.metadata


# ---------------------------------------------------------------------------
# crypto primitives (match the stub exactly)
# ---------------------------------------------------------------------------


def _compress_encrypt(key: bytes, plaintext: bytes, level: int,
                      aad: bytes | None = None,
                      ) -> Tuple[bytes, bytes, bytes]:
    """zlib-compress then AES-256-GCM encrypt ``plaintext``.

    Returns ``(ciphertext, nonce, tag)`` where ``ciphertext`` excludes the tag.
    ``aad`` is Additional Authenticated Data bound to this unit (e.g. the
    section RVA as a 4-byte LE uint32) -- must match what the stub passes to
    ``crypto_aes256gcm_decrypt``.
    """
    compressed = zlib.compress(plaintext, level)
    nonce = os.urandom(GCM_NONCE_LEN)
    ct_and_tag = AESGCM(key).encrypt(nonce, compressed, aad)
    return ct_and_tag[:-GCM_TAG_LEN], nonce, ct_and_tag[-GCM_TAG_LEN:]


def decrypt_unit(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes,
                 uncompressed_size: int, aad: bytes | None = None) -> bytes:
    """Reference inverse of :func:`_compress_encrypt` (mirrors the stub).

    Verifies the GCM tag and checks the decompressed length. Used by round-trip
    tests / self-checks; not needed to *produce* a package.
    """
    compressed = AESGCM(key).decrypt(nonce, bytes(ciphertext) + bytes(tag), aad)
    raw = zlib.decompress(compressed)
    if uncompressed_size is not None and len(raw) != uncompressed_size:
        raise ValueError(
            f"decompressed size {len(raw)} != expected {uncompressed_size}")
    return raw


# ---------------------------------------------------------------------------
# per-unit subkey derivation (match the stub exactly)
# ---------------------------------------------------------------------------


def _derive_section_key(master_key: bytes, salt: bytes, rva: int) -> bytes:
    """HKDF-SHA256 subkey for the section at ORIGINAL ``rva`` (the value also used
    as that section's GCM AAD): ``HKDF(master_key, salt,
    info=HKDF_INFO_SECTION || struct.pack("<I", rva))``. The stub re-derives the
    identical subkey from the recovered master key + ``kdf_salt``."""
    info = HKDF_INFO_SECTION + struct.pack("<I", rva)
    return HKDF(algorithm=SHA256(), length=AES_KEY_LEN, salt=salt,
               info=info).derive(master_key)


def _derive_meta_key(master_key: bytes, salt: bytes) -> bytes:
    """HKDF-SHA256 subkey for the metadata envelope:
    ``HKDF(master_key, salt, info=HKDF_INFO_META)``."""
    return HKDF(algorithm=SHA256(), length=AES_KEY_LEN, salt=salt,
               info=HKDF_INFO_META).derive(master_key)


# ---------------------------------------------------------------------------
# metadata envelope
# ---------------------------------------------------------------------------


def seal_metadata(meta_key: bytes, section_descs: List[SectionDesc],
                  import_blob: bytes, reloc_blob: bytes, tls_blob: bytes,
                  compression_level: int, *,
                  aad_info: "_cnt.PackInfo",
                  load_config_blob: bytes = b"") -> MetadataEnvelope:
    """Serialize ``[SectionDesc[]][imports][relocs][tls]``, then zlib-compress +
    AES-256-GCM encrypt it as one unit. ``meta_key`` is the metadata SUBKEY
    (``_derive_meta_key(master_key, kdf_salt)``) -- NOT the master key; callers
    derive it first. The ``section_descs`` are read at call time, so their
    ``stored_rva`` values are baked in -- assign them first.

    Format v2 authenticates the critical PackInfo geometry via the canonical
    ``container.build_metadata_aad`` serialization. ``aad_info`` carries the
    fields known before sealing; metadata sizes/offsets are filled from the
    bytes built here so callers cannot accidentally authenticate stale values.
    """
    if aad_info.section_count != len(section_descs):
        raise ValueError(
            "metadata AAD section_count does not match SectionDesc count")
    sections_blob = pack_section_descs(section_descs)
    meta_buf, offsets = build_metadata(
        sections_blob, import_blob, reloc_blob, tls_blob, load_config_blob)
    compressed = zlib.compress(meta_buf, compression_level)
    final_info = replace(
        aad_info,
        meta_stored_size=len(compressed),
        meta_uncompressed_size=len(meta_buf),
        sections_off=offsets.sections_off,
        imports_off=offsets.imports_off,
        imports_size=offsets.imports_size,
        relocs_off=offsets.relocs_off,
        relocs_size=offsets.relocs_size,
        tls_off=offsets.tls_off,
    )
    meta_aad = _cnt.build_metadata_aad(final_info)
    nonce = os.urandom(GCM_NONCE_LEN)
    sealed = AESGCM(meta_key).encrypt(nonce, compressed, meta_aad)
    ciphertext, tag = sealed[:-GCM_TAG_LEN], sealed[-GCM_TAG_LEN:]
    return MetadataEnvelope(
        meta_stored=ciphertext, meta_nonce=nonce, meta_tag=tag,
        meta_uncompressed_size=len(meta_buf), offsets=offsets)


# ---------------------------------------------------------------------------
# top-level builder
# ---------------------------------------------------------------------------


def _is_protected(section) -> bool:
    """Protect every section except .rsrc (plaintext) and empty /
    uninitialized-only sections (nothing on disk to store; the assembler's
    zero-filled placeholder covers them)."""
    if section.name == _RSRC_SECTION:
        return False
    return len(section.raw) > 0


def build_payload(
    parsed: ParsedPE,
    options,
    *,
    master_key: bytes | bytearray | memoryview | None = None,
    paged_vm: bool = False,
) -> PayloadArtifacts:
    """Compress + encrypt ``parsed`` into a :class:`PayloadArtifacts`.

    ``options`` exposes ``anti_debug``, ``memory_guard``,
    ``process_hardening`` and ``compression_level`` -- e.g.
    :class:`PayloadOptions` or the orchestrator's ``PackOptions``. Absent
    attributes fall back to the :class:`PayloadOptions` defaults.
    """
    anti_debug = bool(getattr(options, "anti_debug", False))
    memory_guard = bool(getattr(options, "memory_guard", False))
    process_hardening = bool(getattr(options, "process_hardening", False))
    level = int(getattr(options, "compression_level", 9))
    if not isinstance(paged_vm, bool):
        raise TypeError("paged_vm must be a boolean")
    requires_paged_vm = bool(getattr(parsed, "requires_paged_vm", False))
    if parsed.is_dll and memory_guard:
        raise ValueError(
            "memory guard is unsupported for DLLs because loader-lock teardown "
            "cannot safely establish vectored-handler rundown")
    if parsed.is_dll and process_hardening:
        raise ValueError(
            "process hardening is EXE-only and must not mutate a DLL host")
    if paged_vm != requires_paged_vm:
        raise ValueError(
            "paged_vm must match the materialized selected-function paging contract"
        )
    if paged_vm and master_key is None:
        raise ValueError(
            "paged VM payloads require the materializer's explicit master key"
        )

    if master_key is None:
        checked_master_key = os.urandom(AES_KEY_LEN)
    else:
        checked_master_key = bytes(master_key)
        if len(checked_master_key) != AES_KEY_LEN:
            raise ValueError("injected payload master key must be exactly 32 bytes")
    salt = os.urandom(KDF_SALT_LEN)

    # --- protected sections (each under its own HKDF-derived subkey) ---
    stored_sections: List[StoredSection] = []
    for sec in parsed.sections:
        if not _is_protected(sec):
            continue
        sec_aad = struct.pack("<I", sec.rva)
        section_key = _derive_section_key(checked_master_key, salt, sec.rva)
        ciphertext, nonce, tag = _compress_encrypt(
            section_key, sec.raw, level, aad=sec_aad)
        desc = SectionDesc(
            rva=sec.rva,
            virtual_size=sec.virtual_size,
            stored_size=len(ciphertext),
            uncompressed_size=len(sec.raw),
            stored_rva=0,                       # PLACEHOLDER -- assembler assigns
            characteristics=sec.characteristics,
            gcm_nonce=nonce,
            gcm_tag=tag,
        )
        stored_sections.append(StoredSection(desc=desc, data=ciphertext))

    # --- metadata blobs ---
    import_blob = build_import_blob(parsed.imports)
    if parsed.tls is not None:
        t = parsed.tls
        if t.raw_end_rva < t.raw_start_rva:
            raise ValueError("TLS raw-data range ends before it starts")
        tls_total_size = (t.raw_end_rva - t.raw_start_rva) + t.zero_fill
        if tls_total_size > STUB_TLS_CAPACITY:
            raise ValueError(
                f"TLS template is {tls_total_size} bytes; Lethe's "
                f"OS-managed TLS anchor supports at most {STUB_TLS_CAPACITY}"
            )
        tls_blob = build_tls_blob(
            t.index_rva, t.raw_start_rva, t.raw_end_rva, t.zero_fill,
            t.callback_rvas, characteristics=t.characteristics)
    else:
        tls_blob = b""
    reloc_blob = parsed.reloc_blob

    # --- flags ---
    flags = 0
    if parsed.tls is not None:
        flags |= FLAG_HAS_TLS
    if parsed.pdata_count > 0:
        flags |= FLAG_HAS_EXCEPTIONS
    if anti_debug:
        flags |= FLAG_ANTIDEBUG
    if memory_guard:
        flags |= FLAG_MEMGUARD
    if process_hardening:
        flags |= FLAG_PROCESS_HARDENING
    if paged_vm:
        flags |= FLAG_PAGED_DVM
    if parsed.load_config is not None:
        flags |= FLAG_LOAD_CONFIG
    if parsed.is_dll:
        flags |= FLAG_DLL_PRELOAD_IAT

    # --- provisional envelope (placeholder stored_rvas; assembler re-seals) ---
    meta_key = _derive_meta_key(checked_master_key, salt)
    provisional_info = _cnt.PackInfo(
        original_image_base=parsed.image_base,
        original_size_of_image=parsed.size_of_image,
        oep_rva=parsed.oep_rva,
        is_dll=1 if parsed.is_dll else 0,
        flags=flags,
        section_count=len(stored_sections),
        meta_rva=0,
        pdata_rva=parsed.pdata_rva,
        pdata_count=parsed.pdata_count,
    )
    metadata = seal_metadata(
        meta_key, [ss.desc for ss in stored_sections], import_blob, reloc_blob,
        tls_blob, level, aad_info=provisional_info)

    return PayloadArtifacts(
        aes_key=checked_master_key,
        kdf_salt=salt,
        stored_sections=stored_sections,
        metadata=metadata,
        flags=flags,
        oep_rva=parsed.oep_rva,
        is_dll=1 if parsed.is_dll else 0,
        original_image_base=parsed.image_base,
        original_size_of_image=parsed.size_of_image,
        pdata_rva=parsed.pdata_rva,
        pdata_count=parsed.pdata_count,
        rsrc_rva=parsed.rsrc_rva,
        rsrc_bytes=parsed.rsrc_bytes,
        rsrc_directory_rva=int(getattr(
            parsed, "rsrc_directory_rva",
            parsed.rsrc_rva if parsed.rsrc_bytes else 0)),
        rsrc_directory_size=int(getattr(
            parsed, "rsrc_directory_size",
            len(parsed.rsrc_bytes) if parsed.rsrc_bytes else 0)),
        import_blob=import_blob,
        reloc_blob=reloc_blob,
        tls_blob=tls_blob,
        compression_level=level,
    )
