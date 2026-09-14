"""
Lethe container ABI -- the single source of truth for the on-disk / in-image
format shared between the Python builder and the native C stub loader.

This module is the canonical Python mirror of ``stub/src/pack_info.h``. The two
MUST stay byte-for-byte identical; both carry size self-checks and the round-trip
tests assert they agree. Do not change one without the other.

Conventions
-----------
* All integers little-endian.
* ``*_rva`` fields are RVAs within the packed module (add the runtime image base
  to dereference).
* ``*_off`` fields are byte offsets within the *decrypted metadata buffer*.
* String-pool offsets are relative to the first byte of the string pool.

Layout at a glance
------------------
* ``PackInfo`` (192 bytes) is patched into the stub image in the clear. It holds
  the image params, OEP, key material, and the locator for the *metadata
  envelope*.
* The **metadata envelope** is ``[SectionDesc[]][import blob][reloc blob]
  [tls blob]`` zlib (deflate)-compressed then AES-256-GCM encrypted as ONE unit
  (this hides the import table). It lives at ``PackInfo.meta_rva`` and is
  authenticated by ``meta_nonce`` / ``meta_tag``.
* Each original section's bytes are zlib (deflate)-compressed then AES-256-GCM
  encrypted *individually* (own nonce/tag in its ``SectionDesc``) and stored at
  ``SectionDesc.stored_rva``.
* Compression is **zlib (deflate)** throughout. The stub decompresses with miniz
  ``mz_uncompress()``. Do not use lzma -- the stub cannot decode it.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import List, Tuple

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

MAGIC = b"LETHE01\x00"          # 8 bytes incl. trailing NUL; identifies PackInfo
FORMAT_VERSION = 2

# PackInfo.flags bits
FLAG_HAS_TLS        = 1 << 0
FLAG_HAS_EXCEPTIONS = 1 << 1
FLAG_ANTIDEBUG      = 1 << 2
FLAG_MEMGUARD       = 1 << 3
FLAG_PAGED_DVM      = 1 << 4
FLAG_LOAD_CONFIG    = 1 << 5
FLAG_DLL_PRELOAD_IAT = 1 << 6
FLAG_PROCESS_HARDENING = 1 << 7

LOAD_CONFIG_INDEX_MAGIC = b"LCFGIDX1"
_LOAD_CONFIG_INDEX = struct.Struct("<8sII")
LOAD_CONFIG_INDEX_SIZE = _LOAD_CONFIG_INDEX.size

# Import descriptor: a function is imported by ordinal when this bit is set in
# its ``id`` field (low 16 bits = ordinal); otherwise ``id`` is a string-pool
# offset to the function name.
IMPORT_BY_ORDINAL = 0x80000000   # LEGACY (v0 blob format); kept for reference only

# New (v1) import blob: ordinal detection is via the hint_or_ordinal field; hash-
# based resolution replaces plaintext string-pool lookups. The sentinel is 0xFFFF
# which collides with the (extremely rare) legitimate ordinal 65535 -- build_import_blob
# rejects that ordinal at pack time rather than silently misclassifying it.
IMPORT_HINT_BY_HASH = 0xFFFF     # hint_or_ordinal sentinel: resolve by FNV-1a hash


def _import_hash(s: str) -> int:
    """FNV-1a hash with avalanche mixing.

    Matches the C stub's ``import_hash()`` exactly (same offset basis, prime,
    and final XOR-shift).  Both sides MUST produce identical output for every
    input; change one => change the other.
    """
    h = 0x811c9dc5                         # FNV offset basis
    for c in s:
        h ^= ord(c) & 0xFF
        h = (h * 0x01000193) & 0xFFFFFFFF  # FNV prime, keep 32-bit
    h ^= (h >> 16)                         # avalanche
    return h & 0xFFFFFFFF

# HKDF-SHA256 ``info`` strings (domain separation) -- CANONICAL SOURCE OF TRUTH.
# assemble.py and payload.py import these; the native stub hard-codes the exact
# same byte strings. Changing any value here REQUIRES the identical change in
# stub/src, or the stub derives the wrong key and every AES-GCM auth fails.
HKDF_INFO_CODEHASH = b"\x8a\x3c\x01\xf7\x92\xb5\x6d\xe4\x11\x0a\x7f\x53"
HKDF_INFO_SECTION  = b"\x8a\x3c\x01\xf7\x92\xb5\x6d\xe4\x11\x0a\x7f\x53\x2e\x73"
HKDF_INFO_META     = b"\x8a\x3c\x01\xf7\x92\xb5\x6d\xe4\x11\x0a\x7f\x53\x2e\x6d"
HKDF_INFO_SHARD    = b"\x8a\x3c\x01\xf7\x92\xb5\x6d\xe4\x11\x0a\x7f\x53\x2e\x67"

# Canonical metadata AES-GCM AAD (format v2). The explicit domain prevents the
# same tag from being meaningful in another protocol; every integer is encoded
# little-endian at its declared PackInfo width. Keep metadata_aad.[ch] in the C
# loader byte-for-byte identical.
METADATA_AAD_DOMAIN = b"LETHE-META-AAD2\x00"
_METADATA_AAD = struct.Struct("<16sIIQ" + "I" * 19 + "16s")
METADATA_AAD_SIZE = _METADATA_AAD.size
assert len(METADATA_AAD_DOMAIN) == 16
assert METADATA_AAD_SIZE == 124

# ---------------------------------------------------------------------------
# PackInfo (fixed 192 bytes)
# ---------------------------------------------------------------------------
#
# magic(8s) format_ver(I) flags(I) original_image_base(Q)
# original_size_of_image(I) oep_rva(I) is_dll(I) section_count(I)
# meta_rva(I) meta_stored_size(I) meta_uncompressed_size(I)
# meta_nonce(12s) meta_tag(16s)
# sections_off(I) imports_off(I) imports_size(I) relocs_off(I) relocs_size(I)
# tls_off(I) pdata_rva(I) pdata_count(I)
# aes_key_enc(32s) kdf_salt(16s) stub_text_rva(I) stub_text_size(I)
# dll_export_rva(I) dll_export_size(I) dll_export_sha256_128(16s)
_PACKINFO = struct.Struct("<8sIIQIIIIIII12s16sIIIIIIII32s16sIIII16s")
PACKINFO_SIZE = _PACKINFO.size
assert PACKINFO_SIZE == 192, f"PackInfo must be 192 bytes, got {PACKINFO_SIZE}"


@dataclass
class PackInfo:
    original_image_base: int = 0
    original_size_of_image: int = 0
    oep_rva: int = 0
    is_dll: int = 0
    flags: int = 0
    section_count: int = 0
    # metadata envelope locator (module RVA + AES-GCM params)
    meta_rva: int = 0
    meta_stored_size: int = 0
    meta_uncompressed_size: int = 0
    meta_nonce: bytes = b"\x00" * 12
    meta_tag: bytes = b"\x00" * 16
    # offsets within the decrypted metadata buffer
    sections_off: int = 0
    imports_off: int = 0
    imports_size: int = 0
    relocs_off: int = 0
    relocs_size: int = 0
    tls_off: int = 0
    # exception table (module RVA into the restored .pdata section)
    pdata_rva: int = 0
    pdata_count: int = 0
    # key material + tamper-evident binding
    aes_key_enc: bytes = b"\x00" * 32
    kdf_salt: bytes = b"\x00" * 16
    stub_text_rva: int = 0
    stub_text_size: int = 0
    # The loader-visible export snapshot exists before DLL initialization.
    # Its truncated SHA-256 is authenticated by the metadata AAD and verified
    # by the stub before any protected source section is restored.
    dll_export_rva: int = 0
    dll_export_size: int = 0
    dll_export_sha256_128: bytes = b"\x00" * 16

    def pack(self) -> bytes:
        if len(self.aes_key_enc) != 32:
            raise ValueError("aes_key_enc must be 32 bytes")
        if len(self.meta_nonce) != 12:
            raise ValueError("meta_nonce must be 12 bytes")
        if len(self.meta_tag) != 16:
            raise ValueError("meta_tag must be 16 bytes")
        if len(self.kdf_salt) != 16:
            raise ValueError("kdf_salt must be 16 bytes")
        if len(self.dll_export_sha256_128) != 16:
            raise ValueError("dll_export_sha256_128 must be 16 bytes")
        return _PACKINFO.pack(
            MAGIC, FORMAT_VERSION, self.flags, self.original_image_base,
            self.original_size_of_image, self.oep_rva, self.is_dll,
            self.section_count, self.meta_rva, self.meta_stored_size,
            self.meta_uncompressed_size, self.meta_nonce, self.meta_tag,
            self.sections_off, self.imports_off, self.imports_size,
            self.relocs_off, self.relocs_size, self.tls_off,
            self.pdata_rva, self.pdata_count, self.aes_key_enc, self.kdf_salt,
            self.stub_text_rva, self.stub_text_size, self.dll_export_rva,
            self.dll_export_size, self.dll_export_sha256_128,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "PackInfo":
        (magic, ver, flags, imgbase, soi, oep, is_dll, sc, meta_rva,
         meta_stored, meta_uncomp, meta_nonce, meta_tag, sections_off,
         imports_off, imports_size, relocs_off, relocs_size, tls_off, pdata_rva,
         pdata_count, key, salt, st_rva, st_sz, export_rva, export_size,
         export_hash) = _PACKINFO.unpack(
            data[:PACKINFO_SIZE])
        if magic != MAGIC:
            raise ValueError("bad PackInfo magic")
        if ver != FORMAT_VERSION:
            raise ValueError(f"unsupported PackInfo format version {ver}")
        return cls(imgbase, soi, oep, is_dll, flags, sc, meta_rva, meta_stored,
                   meta_uncomp, meta_nonce, meta_tag, sections_off, imports_off,
                   imports_size, relocs_off, relocs_size, tls_off, pdata_rva,
                   pdata_count, key, salt, st_rva, st_sz, export_rva,
                   export_size, export_hash)


def build_metadata_aad(info: PackInfo) -> bytes:
    """Serialize the format-v2 metadata AES-GCM authentication context.

    Only fields available before metadata is opened are included. Crypto key
    bytes and nonce/tag are excluded. The stable stub code locator is included:
    it is known before sealing and also selects the bytes used by the independent
    code-hash/master-key binding, so there is no circular dependency.
    """
    if not isinstance(info, PackInfo):
        raise TypeError("metadata AAD requires a PackInfo instance")
    return _METADATA_AAD.pack(
        METADATA_AAD_DOMAIN,
        FORMAT_VERSION,
        info.flags,
        info.original_image_base,
        info.original_size_of_image,
        info.oep_rva,
        info.is_dll,
        info.section_count,
        info.meta_rva,
        info.meta_stored_size,
        info.meta_uncompressed_size,
        info.sections_off,
        info.imports_off,
        info.imports_size,
        info.relocs_off,
        info.relocs_size,
        info.tls_off,
        info.pdata_rva,
        info.pdata_count,
        info.stub_text_rva,
        info.stub_text_size,
        info.dll_export_rva,
        info.dll_export_size,
        info.dll_export_sha256_128,
    )


# ---------------------------------------------------------------------------
# SectionDesc (fixed 52 bytes)
# ---------------------------------------------------------------------------
#
# rva(I) virtual_size(I) stored_size(I) uncompressed_size(I) stored_rva(I)
# characteristics(I) gcm_nonce(12s) gcm_tag(16s)
_SECTIONDESC = struct.Struct("<IIIIII12s16s")
SECTIONDESC_SIZE = _SECTIONDESC.size
assert SECTIONDESC_SIZE == 52, f"SectionDesc must be 52 bytes, got {SECTIONDESC_SIZE}"


@dataclass
class SectionDesc:
    rva: int
    virtual_size: int
    stored_size: int          # compressed+encrypted byte count at stored_rva
    uncompressed_size: int
    stored_rva: int           # module RVA of the stored (compressed+enc) bytes
    characteristics: int      # IMAGE_SCN_* -> final page protection
    gcm_nonce: bytes = b"\x00" * 12
    gcm_tag: bytes = b"\x00" * 16

    def pack(self) -> bytes:
        if len(self.gcm_nonce) != 12:
            raise ValueError("gcm_nonce must be 12 bytes")
        if len(self.gcm_tag) != 16:
            raise ValueError("gcm_tag must be 16 bytes")
        return _SECTIONDESC.pack(self.rva, self.virtual_size, self.stored_size,
                                 self.uncompressed_size, self.stored_rva,
                                 self.characteristics, self.gcm_nonce,
                                 self.gcm_tag)

    @classmethod
    def from_bytes(cls, data: bytes) -> "SectionDesc":
        return cls(*_SECTIONDESC.unpack(data[:SECTIONDESC_SIZE]))


def pack_section_descs(descs: List[SectionDesc]) -> bytes:
    return b"".join(d.pack() for d in descs)


# ---------------------------------------------------------------------------
# Import blob (hash-based, v1)
# ---------------------------------------------------------------------------
#
# No plaintext function or DLL names are stored.  DLL resolution uses PEB
# InMemoryOrderModuleList (hash match) with XOR-encrypted name fallback for
# LoadLibraryA; function resolution walks the export directory by hash.
#
#   u32 enc_pool_size
#   u8  enc_pool[enc_pool_size]      XOR-encrypted DLL name fallback strings
#
#   ImportEntry[] (terminated by dll_name_hash == 0):
#     u32 dll_name_hash              FNV-1a of lowercase DLL name
#     u8  dll_name_xor_key           random byte; decrypt pool entry with XOR
#     u32 dll_name_enc_offset        offset into enc_pool of the XOR'd name
#     u32 func_count
#     FuncEntry[func_count]:
#       u32 iat_rva                  where the stub writes the resolved ptr
#       u16 hint_or_ordinal          0xFFFF = by-hash; else ordinal number
#       u32 func_name_hash           FNV-1a of function name (case-sensitive)
#       u32 preload_iat_rva          outer DLL IAT slot, zero for EXEs
#   u32 terminator (0)               marks end of DLL entries

@dataclass
class ImportFunc:
    iat_rva: int
    by_ordinal: bool = False
    ordinal: int = 0
    name: str = ""
    preload_iat_rva: int = 0


@dataclass
class ImportDll:
    name: str
    funcs: List[ImportFunc] = field(default_factory=list)


def build_import_blob(dlls: List[ImportDll]) -> bytes:
    """Serialize imports into the hash-based v1 blob consumed by the stub.

    DLL names are hashed (FNV-1a, lowercase) for PEB matching and XOR-encrypted
    into a fallback pool for LoadLibraryA.  Function names are hashed (FNV-1a,
    case-sensitive).  Ordinal imports store the ordinal directly.
    """
    enc_pool = bytearray()
    entries = bytearray()

    for d in dlls:
        # DLL name hash (lowercase, matching the stub's PEB walk)
        dll_hash = _import_hash(d.name.lower())
        if dll_hash == 0:
            dll_hash = 1                   # 0 is the terminator sentinel

        # XOR-encrypt the DLL name for LoadLibraryA fallback.  The NUL
        # terminator XOR'd with the key produces the key byte itself; since no
        # other plaintext byte is 0, the key byte uniquely marks the end of the
        # encrypted string.
        name_bytes = d.name.encode("ascii") + b"\x00"
        xor_key = os.urandom(1)[0] or 1   # ensure non-zero
        while xor_key == 0:               # belt-and-suspenders
            xor_key = os.urandom(1)[0]
        enc_offset = len(enc_pool)
        enc_pool.extend(b ^ xor_key for b in name_bytes)

        # ImportEntry header
        entries += struct.pack("<I", dll_hash)
        entries += struct.pack("<B", xor_key)
        entries += struct.pack("<I", enc_offset)
        entries += struct.pack("<I", len(d.funcs))

        for f in d.funcs:
            entries += struct.pack("<I", f.iat_rva)
            if f.by_ordinal:
                if not (0 <= f.ordinal <= 0xFFFF):
                    raise ValueError(
                        f"{d.name}: ordinal {f.ordinal} out of range for a "
                        f"PE u16 ordinal field")
                if f.ordinal == IMPORT_HINT_BY_HASH:
                    raise ValueError(
                        f"{d.name}: ordinal 0x{f.ordinal:04X} collides with the "
                        f"by-hash sentinel (IMPORT_HINT_BY_HASH); "
                        f"Lethe cannot import this function by ordinal")
                entries += struct.pack("<H", f.ordinal)
                entries += struct.pack("<I", 0)            # hash unused
            else:
                entries += struct.pack("<H", IMPORT_HINT_BY_HASH)
                entries += struct.pack("<I", _import_hash(f.name))
            entries += struct.pack("<I", f.preload_iat_rva)

    # Terminator
    entries += struct.pack("<I", 0)

    out = bytearray()
    out += struct.pack("<I", len(enc_pool))
    out += enc_pool
    out += entries
    return bytes(out)


def parse_import_blob(blob: bytes) -> List[ImportDll]:
    """Reference parser for the hash-based v1 import blob.

    DLL names are recovered from the XOR-encrypted pool.  Function names are
    NOT recoverable (hashed); by-name imports are returned with ``name=""``.
    Ordinal imports preserve their ordinal value.  Used by structural tests.
    """
    enc_pool_size = struct.unpack_from("<I", blob, 0)[0]
    enc_pool = blob[4:4 + enc_pool_size]
    pos = 4 + enc_pool_size

    dlls: List[ImportDll] = []
    while True:
        (dll_hash,) = struct.unpack_from("<I", blob, pos)
        if dll_hash == 0:
            break
        pos += 4
        (xor_key,) = struct.unpack_from("<B", blob, pos)
        pos += 1
        (enc_offset,) = struct.unpack_from("<I", blob, pos)
        pos += 4
        (func_count,) = struct.unpack_from("<I", blob, pos)
        pos += 4

        # Decrypt DLL name: scan for byte == xor_key (encrypted NUL)
        end = enc_offset
        while end < len(enc_pool) and enc_pool[end] != xor_key:
            end += 1
        dll_name = bytes(
            b ^ xor_key for b in enc_pool[enc_offset:end]
        ).decode("ascii")

        funcs: List[ImportFunc] = []
        for _ in range(func_count):
            (iat_rva,) = struct.unpack_from("<I", blob, pos)
            pos += 4
            (hint_or_ordinal,) = struct.unpack_from("<H", blob, pos)
            pos += 2
            (_func_hash,) = struct.unpack_from("<I", blob, pos)
            pos += 4
            (preload_iat_rva,) = struct.unpack_from("<I", blob, pos)
            pos += 4

            if hint_or_ordinal == IMPORT_HINT_BY_HASH:
                funcs.append(ImportFunc(
                    iat_rva, False, 0, "", preload_iat_rva))
            else:
                funcs.append(ImportFunc(
                    iat_rva, True, hint_or_ordinal, "", preload_iat_rva))

        dlls.append(ImportDll(dll_name, funcs))

    return dlls


def bind_preload_iat_rvas(blob: bytes, preload_iat_rvas: List[int]) -> bytes:
    """Bind authenticated source-import entries to outer DLL IAT slots."""
    out = bytearray(blob)
    if len(out) < 8:
        raise ValueError("import blob is truncated")
    enc_pool_size = struct.unpack_from("<I", out, 0)[0]
    if enc_pool_size > len(out) - 4:
        raise ValueError("import blob string pool is truncated")
    pos = 4 + enc_pool_size
    index = 0
    while True:
        if pos + 4 > len(out):
            raise ValueError("import blob terminator is missing")
        dll_hash = struct.unpack_from("<I", out, pos)[0]
        pos += 4
        if dll_hash == 0:
            if pos != len(out):
                raise ValueError("import blob has trailing bytes")
            break
        if pos + 9 > len(out):
            raise ValueError("import blob DLL entry is truncated")
        enc_offset = struct.unpack_from("<I", out, pos + 1)[0]
        func_count = struct.unpack_from("<I", out, pos + 5)[0]
        pos += 9
        if enc_offset >= enc_pool_size or func_count > (len(out) - pos) // 14:
            raise ValueError("import blob DLL entry is malformed")
        for _ in range(func_count):
            if index >= len(preload_iat_rvas):
                raise ValueError("preload IAT map has too few entries")
            preload_rva = int(preload_iat_rvas[index])
            if not 0 < preload_rva <= 0xFFFF_FFF7 or preload_rva % 8:
                raise ValueError("preload IAT map contains an invalid RVA")
            struct.pack_into("<I", out, pos + 10, preload_rva)
            pos += 14
            index += 1
    if index != len(preload_iat_rvas):
        raise ValueError("preload IAT map has too many entries")
    return bytes(out)


# ---------------------------------------------------------------------------
# TLS blob
# ---------------------------------------------------------------------------
#
#   u32 index_rva; u32 raw_start_rva; u32 raw_end_rva; u32 zero_fill;
#   u32 characteristics; u32 callback_count; u32 callbacks[callback_count]

def build_tls_blob(index_rva: int, raw_start_rva: int, raw_end_rva: int,
                   zero_fill: int, callback_rvas: List[int],
                   characteristics: int = 0) -> bytes:
    out = struct.pack("<IIIIII", index_rva, raw_start_rva, raw_end_rva,
                      zero_fill, characteristics, len(callback_rvas))
    out += b"".join(struct.pack("<I", r) for r in callback_rvas)
    return out


# ---------------------------------------------------------------------------
# Metadata envelope layout (pre compression/encryption)
# ---------------------------------------------------------------------------

@dataclass
class MetadataOffsets:
    sections_off: int
    imports_off: int
    imports_size: int
    relocs_off: int
    relocs_size: int
    tls_off: int
    load_config_off: int = 0
    load_config_size: int = 0


def build_metadata(section_descs_blob: bytes, import_blob: bytes,
                   reloc_blob: bytes, tls_blob: bytes,
                   load_config_blob: bytes = b"",
                   ) -> Tuple[bytes, MetadataOffsets]:
    """Lay out the metadata buffer: ``[SectionDesc[]][imports][relocs][tls]``,
    each 4-byte aligned. Returns (buffer, offsets); the offsets go into PackInfo.
    The caller zlib (deflate)-compresses then AES-GCM-encrypts the returned
    buffer as one unit and records ``meta_*`` in PackInfo. The stub decompresses
    with miniz ``mz_uncompress()``; do not use lzma -- the stub cannot decode it."""
    buf = bytearray()

    def align4() -> None:
        while len(buf) % 4:
            buf.append(0)

    sections_off = len(buf)
    buf += section_descs_blob
    align4()
    imports_off = len(buf)
    buf += import_blob
    align4()
    relocs_off = len(buf)
    buf += reloc_blob
    align4()
    tls_off = len(buf)
    buf += tls_blob
    load_config_off = 0
    load_config_size = 0
    if load_config_blob:
        align4()
        load_config_off = len(buf)
        load_config_size = len(load_config_blob)
        buf += load_config_blob
        align4()
        buf += _LOAD_CONFIG_INDEX.pack(
            LOAD_CONFIG_INDEX_MAGIC, load_config_off, load_config_size)
    return bytes(buf), MetadataOffsets(
        sections_off, imports_off, len(import_blob),
        relocs_off, len(reloc_blob), tls_off,
        load_config_off, load_config_size)


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    assert PACKINFO_SIZE == 192
    assert SECTIONDESC_SIZE == 52

    pi = PackInfo(original_image_base=0x140000000, original_size_of_image=0x9000,
                  oep_rva=0x1500, is_dll=0, flags=FLAG_HAS_TLS | FLAG_ANTIDEBUG,
                  section_count=3, meta_rva=0x8000, meta_stored_size=1234,
                  meta_uncompressed_size=4096, meta_nonce=b"\x11" * 12,
                  meta_tag=b"\x22" * 16, sections_off=0, imports_off=156,
                  imports_size=64, relocs_off=224, relocs_size=48, tls_off=272,
                  pdata_rva=0x7000, pdata_count=42, aes_key_enc=b"\x33" * 32,
                  kdf_salt=b"\x44" * 16, stub_text_rva=0x8800,
                  stub_text_size=0x600)
    assert PackInfo.from_bytes(pi.pack()) == pi

    sd = SectionDesc(0x1000, 0x2000, 900, 0x1800, 0x8100, 0x60000020,
                     b"\xAA" * 12, b"\xBB" * 16)
    assert SectionDesc.from_bytes(sd.pack()) == sd

    dlls = [
        ImportDll("KERNEL32.dll", [
            ImportFunc(0x2000, name="LoadLibraryA"),
            ImportFunc(0x2008, name="GetProcAddress"),
            ImportFunc(0x2010, by_ordinal=True, ordinal=17),
        ]),
        ImportDll("USER32.dll", [ImportFunc(0x2100, name="MessageBoxA")]),
    ]
    blob = build_import_blob(dlls)
    parsed = parse_import_blob(blob)
    # DLL names survive the XOR-encrypted round trip
    assert [d.name for d in parsed] == [d.name for d in dlls]
    # Function counts match
    assert [len(d.funcs) for d in parsed] == [len(d.funcs) for d in dlls]
    # Ordinal import preserved
    assert parsed[0].funcs[2].by_ordinal is True
    assert parsed[0].funcs[2].ordinal == 17
    # IAT RVAs preserved
    assert parsed[0].funcs[0].iat_rva == 0x2000
    assert parsed[1].funcs[0].iat_rva == 0x2100

    tls = build_tls_blob(0x3000, 0x3100, 0x3200, 64, [0x4000, 0x4008])
    meta, offs = build_metadata(pack_section_descs([sd]), build_import_blob(dlls),
                                b"\x00" * 12, tls)
    assert offs.sections_off == 0
    assert len(meta) >= SECTIONDESC_SIZE

    print(f"OK  PackInfo={PACKINFO_SIZE}B  SectionDesc={SECTIONDESC_SIZE}B  "
          f"metadata={len(meta)}B  offsets={offs}")
