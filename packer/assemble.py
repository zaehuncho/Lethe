"""
Lethe -- output PE assembler (the "back half" of the Python builder).

This module takes the analysis of the original PE (``ParsedPE`` from
``pe_analyze.py``) plus the encrypted payload artifacts (``PayloadArtifacts``
from ``payload.py``) and grafts a prebuilt native stub onto a brand-new PE that
runs the stub first, unpacks the original in memory, and jumps to its OEP.

It is deliberately low-level: the placeholder sections (``SizeOfRawData == 0`` but
``VirtualSize > 0``), the single-delta stub graft, the base-reloc / import
rewriting, and the code-hash key binding are all things LIEF's high-level
``Builder`` will not do for us, so the output image is laid out and serialized
from raw bytes here. LIEF is used only to *load and validate* the prebuilt stub
(as mandated), while every field extraction is done with a small, version-stable
raw PE reader so the assembler does not depend on any particular LIEF API shape.

==========================================================================
LAYOUT SCHEME (documented inline; see the module summary for the integrator)
==========================================================================

Output image RVA map (ImageBase == the ORIGINAL's ImageBase):

    [ headers ]                              RVA 0 .. SizeOfHeaders
    [ placeholder section per protected  ]   at each original section RVA
      original section: RawSize=0, VSize=original, chars = R/W
    [ .rsrc preserved as real bytes      ]   at the original .rsrc RVA
    ----- end of original image extent (original SizeOfImage) -------------
    [ grafted stub .text/.rdata/.data/.pdata/.reloc ]  shifted by one constant
      graft_delta = graft_base - min(stub section RVA); every stub RVA += delta
    [ payload section .rdata2 ]              per-section ciphertext + meta envelope

Because every grafted stub byte moves by the SAME ``graft_delta``, all
RIP-relative references inside the stub stay correct with no fixup; only the two
RVA-bearing tables need rewriting:
  * base relocations -- each block's PageRVA += graft_delta, and each DIR64
    target qword += value_fixup = (out_base + graft_delta) - stub_preferred_base
    (so the stored value equals the correct VA at the output preferred base, and
    the output reloc dir -- the STUB's relocs only -- lets ASLR fix it further).
  * imports -- each descriptor's OriginalFirstThunk/Name/FirstThunk += delta and
    each by-name ILT/IAT thunk RVA += delta.

The output header carries the stub's import, base-reloc, and minimal TLS-anchor
directories. The anchor lets Windows reserve a real static-TLS slot on every
thread; the stub fills that block from the encrypted original TLS recipe.
The original exception directory remains absent and is registered at runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
import time
import zlib
from dataclasses import dataclass, replace
from typing import Iterable, List, Optional, Tuple

# --- container ABI (import only; never edit) -------------------------------
if __package__:                         # normal: imported as ``packer.assemble``
    from . import cfg_preservation, container, dll_preload, pe_analyze
else:                                   # fallback: flat import / direct run
    import cfg_preservation  # type: ignore
    import container  # type: ignore
    import dll_preload  # type: ignore
    import pe_analyze  # type: ignore

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# PE constants (winnt.h)
# ---------------------------------------------------------------------------
IMAGE_FILE_MACHINE_AMD64            = 0x8664
IMAGE_FILE_EXECUTABLE_IMAGE         = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE      = 0x0020
IMAGE_FILE_DLL                      = 0x2000

IMAGE_NT_OPTIONAL_HDR64_MAGIC       = 0x20B
IMAGE_SIZEOF_OPTIONAL_HEADER64      = 0xF0   # 0x70 fixed + 16*8 data dirs

# DllCharacteristics
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE    = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT       = 0x0100
IMAGE_DLLCHARACTERISTICS_GUARD_CF        = 0x4000  # deliberately NOT set (§6)

# Section characteristics
IMAGE_SCN_CNT_CODE                  = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA      = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA    = 0x00000080
IMAGE_SCN_MEM_DISCARDABLE           = 0x02000000
IMAGE_SCN_MEM_EXECUTE               = 0x20000000
IMAGE_SCN_MEM_READ                  = 0x40000000
IMAGE_SCN_MEM_WRITE                 = 0x80000000

# Data-directory indices
DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION = 0, 1, 2, 3
DIR_SECURITY, DIR_BASERELOC, DIR_DEBUG = 4, 5, 6
DIR_TLS, DIR_LOAD_CONFIG, DIR_IAT, DIR_DELAY_IMPORT = 9, 10, 12, 13
NUM_DATA_DIRECTORIES = 16

# Base relocation types
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_DIR64    = 10

IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
MASK64 = (1 << 64) - 1

# HKDF ``info`` strings are defined in container.py (the canonical ABI source);
# use container.HKDF_INFO_CODEHASH / container.HKDF_INFO_SHARD here.

# MSVC-style DOS stub (0x40); the DOS header (0x40) is built by _dos_header().
# PE header starts at 0x80 (e_lfanew).
_DOS_STUB = bytes.fromhex(
    "0e1fba0e00b409cd21b8014ccd215468"
    "69732070726f6772616d2063616e6e6f"
    "742062652072756e20696e20444f5320"
    "6d6f64652e0d0d0a2400000000000000"
)
assert len(_DOS_STUB) == 0x40

_STUB_SECTION_NAMES = {
    ".text": ".ltext",
    ".rdata": ".lrdata",
    ".data": ".ldata",
    ".pdata": ".lpdata",
    ".reloc": ".lreloc",
    ".rsrc": ".lrsrc",
}


def _stub_section_name(original_name: str, used: set[str]) -> str:
    """Use stable, honest names for grafted Lethe runtime sections."""
    base = _STUB_SECTION_NAMES.get(original_name, ".lstub")
    if base not in used:
        return base
    for suffix in range(10):
        candidate = (base[:7] + str(suffix))[:8]
        if candidate not in used:
            return candidate
    raise AssembleError(f"could not assign a unique name for stub section {original_name!r}")


def _dos_header(e_lfanew: int) -> bytes:
    """A minimal, loader-accepted MZ header with e_lfanew at 0x3C."""
    h = bytearray(0x40)
    h[0x00:0x02] = b"MZ"
    struct.pack_into("<H", h, 0x02, 0x0090)   # e_cblp
    struct.pack_into("<H", h, 0x04, 0x0003)   # e_cp
    struct.pack_into("<H", h, 0x08, 0x0004)   # e_cparhdr
    struct.pack_into("<H", h, 0x0A, 0xFFFF)   # e_maxalloc
    struct.pack_into("<H", h, 0x10, 0x00B8)   # e_sp
    struct.pack_into("<H", h, 0x18, 0x0040)   # e_lfarlc
    struct.pack_into("<I", h, 0x3C, e_lfanew)
    return bytes(h)


# ---------------------------------------------------------------------------
# tolerant attribute access (the two sibling modules are built in parallel; the
# integrator reconciles minor field-name drift -- we try the likely spellings)
# ---------------------------------------------------------------------------
_MISSING = object()


def _get(obj, *names, default=_MISSING):
    """Return the first present attribute/key among ``names`` on ``obj``.

    REQUIRED fields (call WITHOUT ``default``): if none of ``names`` is present
    this raises ``ValueError`` naming the missing field, so a payload/pe_analyze
    field-name mismatch fails loudly here instead of silently substituting an
    empty value and masking the integration bug far downstream. Use this form
    for every critical input -- aes_key, kdf_salt, import_blob, reloc_blob,
    meta_ciphertext, section descriptors, etc.

    OPTIONAL fields (call WITH ``default=``): pass a default ONLY where absence
    is legitimate -- e.g. ``pdata_*`` (PE with no exception data), the
    optional-header fidelity scalars, or the ``.rsrc`` / ``sections`` presence
    probes.
    """
    for n in names:
        if isinstance(obj, dict):
            if n in obj:
                return obj[n]
        elif hasattr(obj, n):
            return getattr(obj, n)
    if default is _MISSING:
        raise ValueError(
            f"required field missing: expected one of {names!r} on "
            f"{type(obj).__name__}; integrator: align the field name with "
            f"pe_analyze/payload")
    return default


def _align_up(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def _merge_dir64_relocations(blob: bytes,
                             extra_target_rvas: Iterable[int]) -> bytes:
    """Canonicalize the stub relocation directory plus generated VA fields."""
    targets: set[int] = set()
    pos = 0
    while pos < len(blob):
        if len(blob) - pos < 8:
            raise AssembleError("stub relocation directory has a partial block")
        page_rva, block_size = struct.unpack_from("<II", blob, pos)
        if block_size < 8 or block_size % 4 or pos + block_size > len(blob):
            raise AssembleError("stub relocation directory has invalid geometry")
        for offset in range(pos + 8, pos + block_size, 2):
            entry, = struct.unpack_from("<H", blob, offset)
            kind, within_page = entry >> 12, entry & 0xFFF
            if kind == IMAGE_REL_BASED_ABSOLUTE:
                continue
            if kind != IMAGE_REL_BASED_DIR64:
                raise AssembleError(
                    f"unexpected base-reloc type {kind} while merging load config")
            targets.add(page_rva + within_page)
        pos += block_size

    for target in extra_target_rvas:
        if type(target) is not int or not 0 < target <= 0xFFFF_FFF8:
            raise AssembleError("load-config relocation target is outside RVA space")
        targets.add(target)

    by_page: dict[int, list[int]] = {}
    for target in sorted(targets):
        by_page.setdefault(target & ~0xFFF, []).append(target & 0xFFF)
    blocks = bytearray()
    for page_rva in sorted(by_page):
        entries = [IMAGE_REL_BASED_DIR64 << 12 | offset
                   for offset in by_page[page_rva]]
        if len(entries) & 1:
            entries.append(0)
        block_size = 8 + len(entries) * 2
        blocks += struct.pack("<II", page_rva, block_size)
        blocks += struct.pack(f"<{len(entries)}H", *entries)
    return bytes(blocks)


def _grafted_stub_guard_targets(stub: "_StubImage", img: "_Image", *,
                                graft_delta: int, image_base: int,
                                is_dll: bool) -> tuple[int, tuple[int, ...]]:
    """Return the output entry point and every OS-invoked stub TLS callback.

    Once GUARD_CF is asserted on the outer image, these entry paths belong in
    its GFID table alongside the protected image's eventual code targets.
    """
    entry_name = "StubDllMain" if is_dll else "StubExeEntry"
    entry_stub_rva = stub.find_export_rva(entry_name) or stub.entry_rva
    if not entry_stub_rva:
        raise AssembleError(f"stub has no {entry_name} entry point")

    def validate_target(output_rva: int, kind: str) -> None:
        if not 0 < output_rva < 0x1_0000_0000 or output_rva % 16:
            raise AssembleError(
                f"{kind} target RVA 0x{output_rva:X} is not a 16-byte-aligned RVA")
        source_rva = output_rva - graft_delta
        section = stub.section_containing(source_rva)
        if section is None or not (section.characteristics & IMAGE_SCN_MEM_EXECUTE):
            raise AssembleError(
                f"{kind} target RVA 0x{output_rva:X} is outside executable stub code")

    entry_rva = entry_stub_rva + graft_delta
    validate_target(entry_rva, entry_name)

    tls_stub_rva, tls_size = stub.dir(DIR_TLS)
    if not tls_stub_rva:
        return entry_rva, ()
    if tls_size < 40:
        raise AssembleError("stub TLS directory is smaller than IMAGE_TLS_DIRECTORY64")

    tls_output_rva = tls_stub_rva + graft_delta
    tls_directory = img.read(tls_output_rva, 40)
    callbacks_va, = struct.unpack_from("<Q", tls_directory, 24)
    if callbacks_va == 0:
        return entry_rva, ()
    if callbacks_va < image_base or callbacks_va - image_base >= 0x1_0000_0000:
        raise AssembleError("stub TLS callback array VA is outside output RVA space")
    callback_table_rva = callbacks_va - image_base

    callbacks: list[int] = []
    for index in range(64):
        callback_va, = struct.unpack(
            "<Q", img.read(callback_table_rva + index * 8, 8))
        if callback_va == 0:
            return entry_rva, tuple(callbacks)
        if callback_va < image_base or callback_va - image_base >= 0x1_0000_0000:
            raise AssembleError("stub TLS callback VA is outside output RVA space")
        callback_rva = callback_va - image_base
        validate_target(callback_rva, "stub TLS callback")
        callbacks.append(callback_rva)
    raise AssembleError("stub TLS callback array has no terminator within 64 entries")


class AssembleError(RuntimeError):
    """Raised for any unrecoverable layout / graft problem (caught upstream)."""

    def __init__(self, message: str, *, preservation_plan=None) -> None:
        self.preservation_plan = preservation_plan
        super().__init__(message)


# ---------------------------------------------------------------------------
# raw stub reader -- version-stable extraction from the prebuilt stub PE bytes
# ---------------------------------------------------------------------------
@dataclass
class _StubSection:
    name: str
    rva: int
    vsize: int
    raw_size: int
    raw_ptr: int
    characteristics: int
    content: bytes          # exactly raw_size bytes from the file


class _StubImage:
    """Minimal raw parse of the prebuilt stub PE (PE32+ only)."""

    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            raise AssembleError("stub is not a PE (missing MZ)")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise AssembleError("stub is not a PE (missing PE signature)")
        fh = e_lfanew + 4
        (machine, self.num_sections, _tds, _psym, _nsym,
         size_opt, _chars) = struct.unpack_from("<HHIIIHH", data, fh)
        if machine != IMAGE_FILE_MACHINE_AMD64:
            raise AssembleError("stub must be x64 (AMD64)")
        oh = fh + 20
        magic = struct.unpack_from("<H", data, oh)[0]
        if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            raise AssembleError("stub must be PE32+ (64-bit)")
        self.entry_rva = struct.unpack_from("<I", data, oh + 0x10)[0]
        self.image_base = struct.unpack_from("<Q", data, oh + 0x18)[0]
        self.num_dirs = struct.unpack_from("<I", data, oh + 0x6C)[0]
        dd_off = oh + 0x70
        self.data_dirs: List[Tuple[int, int]] = []
        for i in range(min(self.num_dirs, NUM_DATA_DIRECTORIES)):
            rva, size = struct.unpack_from("<II", data, dd_off + i * 8)
            self.data_dirs.append((rva, size))
        while len(self.data_dirs) < NUM_DATA_DIRECTORIES:
            self.data_dirs.append((0, 0))

        sec_off = oh + size_opt
        self.sections: List[_StubSection] = []
        for i in range(self.num_sections):
            base = sec_off + i * 40
            name = data[base:base + 8].rstrip(b"\x00").decode("latin-1")
            vsize, vrva, raw_size, raw_ptr = struct.unpack_from(
                "<IIII", data, base + 8)
            chars = struct.unpack_from("<I", data, base + 36)[0]
            content = data[raw_ptr:raw_ptr + raw_size] if raw_size else b""
            self.sections.append(_StubSection(
                name, vrva, vsize, raw_size, raw_ptr, chars, content))

    # -- helpers ------------------------------------------------------------
    def dir(self, index: int) -> Tuple[int, int]:
        return self.data_dirs[index]

    def section_containing(self, rva: int) -> Optional[_StubSection]:
        for s in self.sections:
            span = max(s.vsize, s.raw_size)
            if s.rva <= rva < s.rva + span:
                return s
        return None

    def rva_to_off(self, rva: int) -> int:
        s = self.section_containing(rva)
        if s is None:
            raise AssembleError(f"stub RVA 0x{rva:x} not in any section")
        return s.raw_ptr + (rva - s.rva)

    def read_at_rva(self, rva: int, n: int) -> bytes:
        off = self.rva_to_off(rva)
        return self.data[off:off + n]

    def cstr_at_rva(self, rva: int) -> str:
        off = self.rva_to_off(rva)
        end = self.data.index(b"\x00", off)
        return self.data[off:end].decode("latin-1")

    def find_export_rva(self, want: str) -> Optional[int]:
        exp_rva, exp_size = self.dir(DIR_EXPORT)
        if not exp_rva:
            return None
        d = self.read_at_rva(exp_rva, 40)
        num_funcs, num_names = struct.unpack_from("<II", d, 0x14)
        addr_funcs, addr_names, addr_ords = struct.unpack_from("<III", d, 0x1C)
        names = self.read_at_rva(addr_names, num_names * 4)
        ords_ = self.read_at_rva(addr_ords, num_names * 2)
        funcs = self.read_at_rva(addr_funcs, num_funcs * 4)
        for i in range(num_names):
            name_rva = struct.unpack_from("<I", names, i * 4)[0]
            if self.cstr_at_rva(name_rva) == want:
                ordinal = struct.unpack_from("<H", ords_, i * 2)[0]
                return struct.unpack_from("<I", funcs, ordinal * 4)[0]
        return None

    def find_packinfo_rva(self) -> int:
        """Scan writable sections for the PackInfo magic; return its stub RVA."""
        for s in self.sections:
            if not (s.characteristics & IMAGE_SCN_MEM_WRITE):
                continue
            idx = s.content.find(container.MAGIC)
            if idx != -1:
                return s.rva + idx
        # fall back to any section (some toolchains place it in .rdata-adjacent)
        for s in self.sections:
            idx = s.content.find(container.MAGIC)
            if idx != -1:
                return s.rva + idx
        raise AssembleError(
            "g_packinfo (PackInfo MAGIC) not found in the stub image -- is this "
            "the right prebuilt stub?")


# ---------------------------------------------------------------------------
# grafted image byte-store (random access by OUTPUT RVA, for the two fixups)
# ---------------------------------------------------------------------------
class _Image:
    """Sparse RVA-indexed byte store over the grafted stub section blocks."""

    def __init__(self):
        self._blocks: List[List] = []   # [rva, bytearray]

    def add(self, rva: int, data: bytes) -> None:
        self._blocks.append([rva, bytearray(data)])

    def _find(self, rva: int, n: int):
        for blk in self._blocks:
            base = blk[0]
            if base <= rva and rva + n <= base + len(blk[1]):
                return blk, rva - base
        raise AssembleError(
            f"fixup RVA 0x{rva:x}+{n} falls outside every grafted block")

    def read(self, rva: int, n: int) -> bytes:
        blk, off = self._find(rva, n)
        return bytes(blk[1][off:off + n])

    def write(self, rva: int, data: bytes) -> None:
        blk, off = self._find(rva, len(data))
        blk[1][off:off + len(data)] = data

    def contains(self, rva: int, n: int = 1) -> bool:
        try:
            self._find(rva, n)
            return True
        except AssembleError:
            return False

    def block_bytes(self, rva: int) -> bytes:
        for blk in self._blocks:
            if blk[0] == rva:
                return bytes(blk[1])
        raise AssembleError(f"no grafted block at RVA 0x{rva:x}")


# ---------------------------------------------------------------------------
# output section model
# ---------------------------------------------------------------------------
@dataclass
class _OutSection:
    name: str
    rva: int
    vsize: int
    characteristics: int
    raw: Optional[bytes]     # None => SizeOfRawData 0 (placeholder / BSS)


@dataclass
class AssembleResult:
    output_path: str
    size_of_image: int
    section_count: int
    graft_delta: int
    stub_text_rva: int
    stub_text_size: int
    payload_rva: int
    server_shard: Optional[bytes] = None


@dataclass(frozen=True)
class _FinalizedMetadata:
    """Complete metadata envelope committed atomically to payload artifacts."""

    meta_stored: bytes
    meta_nonce: bytes
    meta_tag: bytes
    meta_uncompressed_size: int
    offsets: "container.MetadataOffsets"

    @property
    def meta_stored_size(self) -> int:
        return len(self.meta_stored)


def _commit_finalized_metadata(artifacts, env: _FinalizedMetadata) -> None:
    """Publish one coherent final envelope or fail before PE serialization."""
    try:
        artifacts.metadata = env
    except Exception as exc:
        raise AssembleError(
            "payload artifacts cannot accept finalized metadata state; "
            "provide reseal_metadata(aad_info) or a writable metadata attribute"
        ) from exc
    if getattr(artifacts, "metadata", None) is not env:
        raise AssembleError(
            "payload artifacts did not retain the finalized metadata state"
        )


# ---------------------------------------------------------------------------
# metadata finalize -- bake the freshly-assigned stored_rva into the envelope
# ---------------------------------------------------------------------------
def _finalize_metadata(artifacts, descs: List["container.SectionDesc"],
                       level: int, aad_info: "container.PackInfo",
                       ) -> _FinalizedMetadata:
    """Produce the FINAL encrypted metadata envelope after the assembler has
    assigned every ``SectionDesc.stored_rva``.

    Returns a single immutable envelope and commits that same object to
    ``artifacts.metadata``. This keeps later keyed validation coherent with the
    exact bytes serialized into the staged PE.

    PRIMARY path: the payload exposes ``reseal_metadata(aad_info)`` -- the authoritative
    sealer. It re-serializes ``[SectionDesc[]][imports][relocs][tls]`` from the
    CURRENT (live) ``desc.stored_rva`` values and compresses+encrypts EXACTLY as
    the stub decodes (zlib/miniz + AES-256-GCM). We never second-guess its
    compression choice -- this is what keeps the envelope decodable by the stub.

    FALLBACK (only if that method is absent): rebuild with
    ``container.build_metadata`` and zlib + AES-GCM ourselves, using the raw
    sub-blobs the payload carried. Deliberately zlib -- NOT lzma: the stub's
    bundled miniz cannot decode lzma (per payload.py).
    """
    reseal = getattr(artifacts, "reseal_metadata", None)
    if callable(reseal):
        sealed = reseal(aad_info)             # reads the live desc.stored_rva
        env = _FinalizedMetadata(
            meta_stored=bytes(_get(sealed, "meta_stored", "meta_ciphertext")),
            meta_nonce=bytes(_get(sealed, "meta_nonce")),
            meta_tag=bytes(_get(sealed, "meta_tag")),
            meta_uncompressed_size=int(_get(
                sealed, "meta_uncompressed_size", "meta_uncomp_size")),
            offsets=_get(sealed, "offsets", "meta_offsets"),
        )
        _commit_finalized_metadata(artifacts, env)
        return env

    # --- fallback: seal it ourselves (zlib, matching the stub's miniz) -------
    raw_key = _get(artifacts, "aes_key", "key", "raw_key")
    if len(raw_key) != 32:
        raise AssembleError("payload AES key must be 32 bytes")
    kdf_salt = _get(artifacts, "kdf_salt", "salt")
    if len(kdf_salt) != 16:
        raise AssembleError("kdf_salt must be 16 bytes")
    meta_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=kdf_salt,
        info=container.HKDF_INFO_META).derive(raw_key)
    import_blob = _get(artifacts, "import_blob", "imports_blob")
    reloc_blob = _get(artifacts, "reloc_blob", "relocs_blob")
    tls_blob = _get(artifacts, "tls_blob")
    load_config_blob = _get(artifacts, "load_config_blob", default=b"")
    meta_plain, offsets = container.build_metadata(
        container.pack_section_descs(descs), import_blob, reloc_blob, tls_blob,
        load_config_blob)
    compressed = zlib.compress(meta_plain, max(0, min(9, level)))
    nonce = os.urandom(12)
    final_info = replace(
        aad_info,
        meta_stored_size=len(compressed),
        meta_uncompressed_size=len(meta_plain),
        sections_off=offsets.sections_off,
        imports_off=offsets.imports_off,
        imports_size=offsets.imports_size,
        relocs_off=offsets.relocs_off,
        relocs_size=offsets.relocs_size,
        tls_off=offsets.tls_off,
    )
    meta_aad = container.build_metadata_aad(final_info)
    out = AESGCM(meta_key).encrypt(nonce, compressed, meta_aad)
    env = _FinalizedMetadata(
        meta_stored=out[:-16],
        meta_nonce=nonce,
        meta_tag=out[-16:],
        meta_uncompressed_size=len(meta_plain),
        offsets=offsets,
    )
    _commit_finalized_metadata(artifacts, env)
    return env


# ---------------------------------------------------------------------------
# original optional-header fidelity (subsystem / stack / heap / versions)
# ---------------------------------------------------------------------------
@dataclass
class _OrigHeader:
    subsystem: int = 3                  # CUI fallback
    major_linker: int = 14
    minor_linker: int = 0
    major_os: int = 6
    minor_os: int = 0
    major_image: int = 0
    minor_image: int = 0
    major_subsystem: int = 6
    minor_subsystem: int = 0
    win32_version: int = 0
    stack_reserve: int = 0x100000
    stack_commit: int = 0x1000
    heap_reserve: int = 0x100000
    heap_commit: int = 0x1000
    loader_flags: int = 0
    export_rva: int = 0
    export_size: int = 0
    timestamp: int = 0
    dll_characteristics: int = 0x0160


def _read_original_header(input_path: Optional[str], parsed) -> _OrigHeader:
    """Copy behavioural optional-header scalars from the original PE so the packed
    image behaves identically (stack/heap sizes and subsystem especially -- the
    OS uses these BEFORE the stub runs). Prefer a raw read of the original file;
    fall back to any fields ``parsed`` exposes; then to safe defaults."""
    h = _OrigHeader()
    # fallbacks from parsed (if pe_analyze surfaced them)
    h.subsystem = _get(parsed, "subsystem", default=h.subsystem)
    h.export_rva = _get(parsed, "export_rva", "exports_rva", default=0)
    h.export_size = _get(parsed, "export_size", "exports_size", default=0)

    path = input_path or _get(parsed, "input_path", "path", default=None)
    if path and os.path.isfile(path):
        try:
            with open(path, "rb") as f:
                data = f.read()
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            oh = e_lfanew + 4 + 20
            fh = e_lfanew + 4
            h.timestamp = struct.unpack_from("<I", data, fh + 4)[0]
            if struct.unpack_from("<H", data, oh)[0] == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                h.major_linker, h.minor_linker = struct.unpack_from("<BB", data, oh + 2)
                h.dll_characteristics = struct.unpack_from("<H", data, oh + 0x46)[0]
                h.major_os, h.minor_os = struct.unpack_from("<HH", data, oh + 0x28)
                h.major_image, h.minor_image = struct.unpack_from("<HH", data, oh + 0x2C)
                h.major_subsystem, h.minor_subsystem = struct.unpack_from("<HH", data, oh + 0x30)
                h.win32_version = struct.unpack_from("<I", data, oh + 0x34)[0]
                h.subsystem = struct.unpack_from("<H", data, oh + 0x44)[0]
                h.stack_reserve = struct.unpack_from("<Q", data, oh + 0x48)[0]
                h.stack_commit = struct.unpack_from("<Q", data, oh + 0x50)[0]
                h.heap_reserve = struct.unpack_from("<Q", data, oh + 0x58)[0]
                h.heap_commit = struct.unpack_from("<Q", data, oh + 0x60)[0]
                h.loader_flags = struct.unpack_from("<I", data, oh + 0x68)[0]
                num_dirs = struct.unpack_from("<I", data, oh + 0x6C)[0]
                if num_dirs > DIR_EXPORT:
                    erva, esize = struct.unpack_from("<II", data, oh + 0x70 + DIR_EXPORT * 8)
                    if erva:
                        h.export_rva, h.export_size = erva, esize
        except (OSError, struct.error):
            pass  # keep parsed/defaults
    return h


# ---------------------------------------------------------------------------
# stub loading (LIEF mandated; guarded)
# ---------------------------------------------------------------------------
def _default_stub_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "stub", "prebuilt", "lethe_stub_x64.dll")


def _release_manifest_path(stub_path: str) -> str:
    stem, _extension = os.path.splitext(stub_path)
    return stem + ".manifest.json"


def _validate_release_stub_manifest(stub_path: str, blob: bytes) -> None:
    """Require integrity and clean-source provenance for the bundled stub."""
    manifest_path = _release_manifest_path(stub_path)
    try:
        with open(manifest_path, "r", encoding="utf-8-sig") as manifest_file:
            metadata = json.load(manifest_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AssembleError(
            f"release stub manifest is missing or invalid: {manifest_path}. "
            "Stage a clean, fully gated candidate with tools/promote_stub.py.") from exc

    digest = hashlib.sha256(blob).hexdigest()
    if metadata.get("schema") != 1:
        raise AssembleError("release stub manifest has an unsupported schema")
    if metadata.get("artifact") != os.path.basename(stub_path):
        raise AssembleError("release stub manifest names a different artifact")
    if metadata.get("size_bytes") != len(blob):
        raise AssembleError("release stub size does not match its manifest")
    if metadata.get("sha256") != digest:
        raise AssembleError("release stub SHA-256 does not match its manifest")
    if metadata.get("provenance_status") != "clean" or metadata.get("source_dirty") is not False:
        raise AssembleError(
            "bundled stub provenance is not release-approved (requires "
            "provenance_status='clean' and source_dirty=false). Build a fresh "
            "candidate and pass --stub-path for validation, or stage one with "
            "tools/promote_stub.py.")
    if metadata.get("native_roundtrip") != "passed-9-of-9":
        raise AssembleError(
            "bundled stub is missing the compatibility round-trip marker; "
            "stage it through tools/promote_stub.py.")

    actual = metadata.get("native_roundtrip_actual")
    if not isinstance(actual, dict):
        raise AssembleError("bundled stub has no actual native round-trip counts")
    passed = actual.get("passed")
    total = actual.get("total")
    if (type(passed) is not int or type(total) is not int or
            total < 1 or passed != total):
        raise AssembleError("bundled stub native round-trip is not a full N/N pass")
    if metadata.get("production_scope") != "all":
        raise AssembleError("bundled stub is not approved by the all-scope production gate")

    def valid_hex(value, length=None):
        return (isinstance(value, str) and value and
                (length is None or len(value) == length) and
                all(char in "0123456789abcdef" for char in value))

    seed = metadata.get("dvm_shuffle_seed")
    if not valid_hex(seed) or len(seed) % 2:
        raise AssembleError("bundled stub has no valid generated DVM shuffle seed")
    for field in (
            "dvm_opcode_mapping_sha256",
            "dvm_handler_variant_sha256",
            "dvm_python_map_sha256",
            "dvm_native_map_sha256"):
        if not valid_hex(metadata.get(field), 64):
            raise AssembleError(f"bundled stub has no valid {field}")


def _load_stub(stub_path: str, *, require_release_manifest: bool = False,
               expected_sha256: Optional[str] = None) -> _StubImage:
    if not os.path.isfile(stub_path):
        raise AssembleError(
            f"prebuilt stub not found: {stub_path}\n"
            "Build a validation stub with stub/build_stub.ps1 and pass it via "
            "--stub-path, or stage a release candidate with tools/promote_stub.py.")
    with open(stub_path, "rb") as stub_file:
        blob = stub_file.read()
    if expected_sha256 is not None:
        normalized = expected_sha256.strip().lower()
        if (len(normalized) != 64
                or any(char not in "0123456789abcdef" for char in normalized)):
            raise AssembleError("expected stub SHA-256 is malformed")
        if hashlib.sha256(blob).hexdigest() != normalized:
            raise AssembleError(
                "stub changed after virtualization geometry was computed")
    if require_release_manifest:
        _validate_release_stub_manifest(stub_path, blob)

    # Mandated: load + validate with LIEF. We keep the LIEF surface tiny (parse
    # only) and do field extraction with the version-stable raw reader below,
    # so we never depend on a specific LIEF API shape.
    try:
        import lief  # noqa: F401
    except ImportError as e:
        raise AssembleError(
            "LIEF is required to assemble the output PE (pip install lief). "
            "It is a build-time-only dependency.") from e
    parsed = lief.PE.parse(stub_path)
    if parsed is None:
        raise AssembleError(f"LIEF failed to parse the stub: {stub_path}")
    # Re-read after LIEF consumed the path and reject a concurrent replacement.
    with open(stub_path, "rb") as stub_file:
        parsed_blob = stub_file.read()
    if parsed_blob != blob:
        raise AssembleError("stub changed while it was being validated")
    return _StubImage(blob)


def _experimental_feature_enabled(name: str) -> bool:
    return os.environ.get(name) == "1"


def _require_experimental_runtime_paths(*, is_dll: bool, server_shard: bool) -> None:
    if is_dll and not _experimental_feature_enabled("LETHE_ENABLE_EXPERIMENTAL_DLL"):
        raise AssembleError(
            "DLL packing is experimental and disabled by default because its "
            "loader-lock runtime path is not release-approved. Use the explicit "
            "--enable-experimental-dll CLI acknowledgment (or set "
            "LETHE_ENABLE_EXPERIMENTAL_DLL=1 for direct API use).")
    if (server_shard and
            not _experimental_feature_enabled("LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD")):
        raise AssembleError(
            "server-shard packing is experimental and disabled by default until "
            "the bootstrap/server protocol and TLS pinning are release-approved. "
            "Use --enable-experimental-server-shard (or set "
            "LETHE_ENABLE_EXPERIMENTAL_SERVER_SHARD=1 for direct API use).")


# ---------------------------------------------------------------------------
# the assembler
# ---------------------------------------------------------------------------
def build_output_pe(parsed, artifacts, output_path: str, *,
                    input_path: Optional[str] = None,
                    options=None,
                    stub_path: Optional[str] = None,
                    expected_stub_sha256: Optional[str] = None) -> AssembleResult:
    """Assemble and write the packed output PE. Raises ``AssembleError`` on any
    unrecoverable problem (the orchestrator turns that into ``PackResult.ok=False``)."""
    # -- pull the semantic inputs (tolerant to field-name drift) -------------
    out_base = int(_get(parsed, "image_base", "imagebase", "original_image_base"))
    orig_soi = int(_get(parsed, "size_of_image", "sizeof_image",
                        "original_size_of_image"))
    is_dll = bool(_get(artifacts, "is_dll", default=_get(parsed, "is_dll",
                                                         default=False)))
    flags = int(_get(artifacts, "flags", default=0))
    server_shard_requested = bool(options and getattr(options, "server_shard", False))
    _require_experimental_runtime_paths(
        is_dll=is_dll, server_shard=server_shard_requested)

    cfg_plan = cfg_preservation.build_cfg_preservation_plan(parsed)
    if not cfg_plan.preservation_supported:
        raise AssembleError(
            str(cfg_preservation.CfgPreservationBlocked(cfg_plan)),
            preservation_plan=cfg_plan,
        )
    if (cfg_plan.source_guard_cf_enabled and
            flags & container.FLAG_MEMGUARD):
        raise AssembleError(
            "Guard CF preservation blocked: memory guard leaves executable "
            "pages unavailable during exact call-target registration",
            preservation_plan=cfg_plan,
        )

    resolved_stub_path = stub_path or _default_stub_path()
    stub = _load_stub(
        resolved_stub_path, require_release_manifest=(stub_path is None),
        expected_sha256=expected_stub_sha256)
    stub_packinfo_rva = stub.find_packinfo_rva()
    stub_packinfo_header = stub.read_at_rva(stub_packinfo_rva, 12)
    if len(stub_packinfo_header) != 12:
        raise AssembleError("stub PackInfo sentinel is truncated")
    stub_format = struct.unpack_from("<I", stub_packinfo_header, 8)[0]
    if stub_format != container.FORMAT_VERSION:
        raise AssembleError(
            f"stub container format v{stub_format} is incompatible with builder "
            f"format v{container.FORMAT_VERSION}; rebuild the stub from matching "
            "sources before packing")
    if is_dll:
        dll_preload_abi_rva = stub.find_export_rva("lethe_dll_preload_abi")
        if (dll_preload_abi_rva is None or
                stub.cstr_at_rva(dll_preload_abi_rva) != "1"):
            raise AssembleError(
                "DLL packing requires a stub with lethe_dll_preload_abi=1; "
                "rebuild the stub from matching sources")

    try:
        pe_analyze._validate_sections(
            _get(parsed, "sections"), orig_soi,
            int(_get(parsed, "section_alignment", default=0x1000)))
    except (AttributeError, TypeError, ValueError) as exc:
        raise AssembleError(
            f"source PE geometry is incompatible with fixed 0x1000 output "
            f"alignment: {exc}") from exc

    oep_rva = int(_get(artifacts, "oep_rva", default=_get(parsed, "oep_rva")))
    pdata_rva = int(_get(artifacts, "pdata_rva", default=_get(parsed, "pdata_rva",
                                                              default=0)))
    pdata_count = int(_get(artifacts, "pdata_count",
                           default=_get(parsed, "pdata_count", default=0)))
    raw_key = _get(artifacts, "aes_key", "key", "raw_key")
    kdf_salt = _get(artifacts, "kdf_salt", "salt")
    if len(kdf_salt) != 16:
        raise AssembleError("kdf_salt must be 16 bytes")
    level = int(_get(options, "compression_level", default=9)) if options else 9

    SA = 0x1000     # SectionAlignment (output; MSVC default)
    FA = 0x200      # FileAlignment    (output; MSVC default)

    orig = _read_original_header(input_path, parsed)

    # -- 1. graft geometry: one constant delta for the whole stub -----------
    stub_secs = [s for s in stub.sections]
    if not stub_secs:
        raise AssembleError("stub has no sections")
    min_stub_rva = min(s.rva for s in stub_secs)
    graft_base = _align_up(max(orig_soi, SA), SA)
    graft_delta = graft_base - min_stub_rva
    if graft_delta % SA != 0:
        raise AssembleError("graft delta is not section-aligned (internal)")

    text = next((s for s in stub_secs if s.name == ".text"), None)
    if text is None:
        text = next((s for s in stub_secs if s.characteristics & IMAGE_SCN_MEM_EXECUTE), None)
    if text is None:
        raise AssembleError("stub has no .text / executable section")
    stub_text_rva = text.rva + graft_delta
    stub_text_size = text.vsize or text.raw_size
    text_lo, text_hi = text.rva, text.rva + max(text.vsize, text.raw_size)

    # -- 2. lay grafted stub section bytes into the RVA-indexed image --------
    img = _Image()
    grafted: List[Tuple[_StubSection, int]] = []
    for s in stub_secs:
        g_rva = s.rva + graft_delta
        # in-memory content = raw bytes (fixups + g_packinfo live within raw)
        img.add(g_rva, s.content)
        grafted.append((s, g_rva))

    # -- 3. rewrite base relocations (PageRVA += delta; DIR64 value += fixup) -
    reloc_rva, reloc_size = stub.dir(DIR_BASERELOC)
    value_fixup = (out_base + graft_delta - stub.image_base) & MASK64
    if reloc_rva and reloc_size:
        g_reloc = reloc_rva + graft_delta
        reloc_bytes = img.read(g_reloc, reloc_size)   # snapshot to walk
        pos = 0
        while pos + 8 <= reloc_size:
            page_rva, block_size = struct.unpack_from("<II", reloc_bytes, pos)
            if block_size < 8:
                break
            nent = (block_size - 8) // 2
            for i in range(nent):
                entry = struct.unpack_from("<H", reloc_bytes, pos + 8 + i * 2)[0]
                typ, off = entry >> 12, entry & 0xFFF
                if typ == IMAGE_REL_BASED_ABSOLUTE:
                    continue
                if typ != IMAGE_REL_BASED_DIR64:
                    raise AssembleError(
                        f"unexpected base-reloc type {typ} in x64 stub "
                        f"(only DIR64/ABSOLUTE supported)")
                t_stub = page_rva + off
                if text_lo <= t_stub < text_hi:
                    raise AssembleError(
                        f"base relocation targets the stub .text at RVA "
                        f"0x{t_stub:x}; the code-hash key binding requires a "
                        f"reloc-free .text. INTEGRATOR: build the stub so .text "
                        f"has no absolute addressing (RIP-relative only).")
                g = t_stub + graft_delta
                v = struct.unpack_from("<Q", img.read(g, 8), 0)[0]
                img.write(g, struct.pack("<Q", (v + value_fixup) & MASK64))
            # patch this block's PageRVA in the OUTPUT reloc dir
            img.write(g_reloc + pos, struct.pack("<I", (page_rva + graft_delta) & 0xFFFFFFFF))
            pos += block_size

    # -- 4. rewrite imports (descriptor RVAs + by-name thunks += delta) ------
    import_rva, import_size = stub.dir(DIR_IMPORT)
    stub_import_descriptors: List[bytes] = []
    if import_rva and import_size:
        g_imp = import_rva + graft_delta
        pos = 0
        while True:
            desc = img.read(g_imp + pos, 20)
            oft, tds, fwd, name_rva, ft = struct.unpack("<IIIII", desc)
            if oft == 0 and name_rva == 0 and ft == 0:
                break
            if oft:
                img.write(g_imp + pos + 0, struct.pack("<I", oft + graft_delta))
            img.write(g_imp + pos + 12, struct.pack("<I", name_rva + graft_delta))
            if ft:
                img.write(g_imp + pos + 16, struct.pack("<I", ft + graft_delta))
            # fix by-name thunks in BOTH the ILT (oft) and the IAT (ft) arrays;
            # the loader may source names from either, and it overwrites the IAT
            # at load time so patching it is harmless when OFT is present.
            for arr_stub in {v for v in (oft, ft) if v}:
                t = arr_stub + graft_delta
                k = 0
                while True:
                    thunk = struct.unpack_from("<Q", img.read(t + k * 8, 8), 0)[0]
                    if thunk == 0:
                        break
                    if not (thunk & IMAGE_ORDINAL_FLAG64):
                        img.write(t + k * 8,
                                  struct.pack("<Q", (thunk + graft_delta) & MASK64))
                    k += 1
            stub_import_descriptors.append(img.read(g_imp + pos, 20))
            pos += 20

    # The TLS directory contains absolute VAs. Its pointer fields were adjusted
    # by the generic DIR64 loop above; only the data-directory RVA needs the
    # same single graft delta at serialization time.
    tls_rva, tls_size = stub.dir(DIR_TLS)
    if tls_rva and (flags & container.FLAG_HAS_TLS):
        source_tls = _get(parsed, "tls")
        source_tls_characteristics = int(
            _get(source_tls, "characteristics", default=0))
        img.write(tls_rva + graft_delta + 36,
                  struct.pack("<I", source_tls_characteristics))
    stub_entry_rva, stub_guard_targets = _grafted_stub_guard_targets(
        stub, img, graft_delta=graft_delta, image_base=out_base, is_dll=is_dll)

    # -- 5. code-hash key binding (over stub .text as laid in the OUTPUT) -----
    # .text is asserted reloc-free above, so its output bytes == the stub's raw
    # .text bytes; g_packinfo lives in .data, so hashing .text excludes it (no
    # circularity). Hash exactly [stub_text_rva, +stub_text_size) as the stub
    # will see it in memory (raw bytes zero-padded to VirtualSize).
    text_mem = bytearray(img.block_bytes(stub_text_rva))
    if len(text_mem) < stub_text_size:
        text_mem += b"\x00" * (stub_text_size - len(text_mem))
    text_hash = hashlib.sha256(bytes(text_mem[:stub_text_size])).digest()
    mask = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=bytes(kdf_salt),
                info=container.HKDF_INFO_CODEHASH).derive(text_hash)
    aes_key_enc = bytes(a ^ b for a, b in zip(raw_key, mask))

    # Server shard gate (Tier 3): XOR a random 32-byte shard into aes_key_enc.
    # The stub reads the 64-char hex shard from the NV_RT_GATE env var. Without
    # the shard the key is wrong and every GCM auth fails — hard online gate.
    server_shard = None
    if server_shard_requested:
        server_shard = os.urandom(32)
        aes_key_enc = bytes(a ^ b for a, b in zip(aes_key_enc, server_shard))

    # -- 6. placeholder sections (protected) + preserved .rsrc ---------------
    #    driven off the payload's per-section SectionDescs (rva/vsize/chars).
    protected = list(_iter_protected(artifacts))
    if not protected:
        raise AssembleError("payload exposed no protected sections")

    descs: List[container.SectionDesc] = [d for (_ct, d) in protected]
    (rsrc_rva, rsrc_bytes,
     rsrc_directory_rva, rsrc_directory_size) = _extract_rsrc(parsed)
    dll_export_snapshot = _dll_export_snapshot(parsed, orig) if is_dll else {}
    dll_export_rva = int(orig.export_rva) if dll_export_snapshot else 0
    dll_export_size = int(orig.export_size) if dll_export_snapshot else 0
    dll_export_hash = bytes(16)
    if dll_export_snapshot:
        snapshot_owner_rva, snapshot_owner = next(
            iter(dll_export_snapshot.items()))
        snapshot_offset = dll_export_rva - snapshot_owner_rva
        dll_export_span = snapshot_owner[
            snapshot_offset:snapshot_offset + dll_export_size]
        if len(dll_export_span) != dll_export_size:
            raise AssembleError("DLL export snapshot span is truncated")
        dll_export_hash = hashlib.sha256(dll_export_span).digest()[:16]

    # protected sections must fit their decrypted plaintext (uncompressed_size);
    # keyed by RVA so we can widen the matching original section's placeholder.
    uncomp_by_rva = {int(d.rva): int(d.uncompressed_size) for d in descs}

    # PLACEHOLDER SECTIONS. One zero-filled, committed R/W placeholder per ORIGINAL
    # section (except .rsrc, preserved below as real bytes). Driving this off the
    # full original section list -- not just the protected subset -- is essential:
    # payload.py does NOT store uninitialized/BSS sections (nothing on disk) and
    # relies on the assembler's zero-filled placeholder to back their RVA range.
    # The stub decrypts protected sections into their placeholders then
    # VirtualProtects to final perms (never W+X); BSS placeholders just stay zero.
    out_sections: List[_OutSection] = []
    parsed_sections = _get(parsed, "sections", default=None)
    if parsed_sections:
        for i, s in enumerate(parsed_sections):
            srva = int(_get(s, "rva", "virtual_address"))
            svsize = int(_get(s, "virtual_size", "vsize", default=0))
            sname = _sec_name(_get(s, "name", default="")) or f".pk{i:x}"
            if sname == ".rsrc" or (rsrc_bytes and srva == rsrc_rva):
                continue                         # preserved separately, real bytes
            vsize = max(svsize, uncomp_by_rva.get(srva, 0), 1)
            snapshot = dll_export_snapshot.get(srva)
            source_chars = int(_get(s, "characteristics", default=0))
            if (cfg_plan.source_guard_cf_enabled
                    and source_chars & IMAGE_SCN_MEM_EXECUTE):
                # The Windows image loader only applies GFID metadata to
                # executable image pages. Keep protected code RX during image
                # activation; the stub transiently switches it to RW while
                # restoring bytes and later returns it to RX without changing
                # the loader-created CFG bitmap.
                placeholder_chars = (
                    IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                    IMAGE_SCN_MEM_READ)
            elif snapshot is not None:
                placeholder_chars = (
                    IMAGE_SCN_CNT_INITIALIZED_DATA |
                    IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
            else:
                placeholder_chars = (
                    IMAGE_SCN_CNT_UNINITIALIZED_DATA |
                    IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
            out_sections.append(_OutSection(
                sname, srva, vsize,
                placeholder_chars, snapshot))
    else:
        _GENERIC_NAMES = [".text", ".rdata", ".data", ".bss",
                          ".tls", ".gfids", ".00cfg", ".idata"]
        for i, d in enumerate(descs):
            vsize = max(int(d.virtual_size), int(d.uncompressed_size), 1)
            gname = _GENERIC_NAMES[i] if i < len(_GENERIC_NAMES) else f".s{i:x}"
            out_sections.append(_OutSection(
                gname, int(d.rva), vsize,
                IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
                None))

    if rsrc_bytes:
        out_sections.append(_OutSection(
            ".rsrc", rsrc_rva, len(rsrc_bytes),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ, rsrc_bytes))

    # -- 7. grafted stub sections as output sections -------------------------
    used_names = {s.name for s in out_sections}
    for s, g_rva in grafted:
        raw = bytearray(img.block_bytes(g_rva))
        sn = _stub_section_name(s.name, used_names)
        used_names.add(sn)
        out_sections.append(_OutSection(
            sn, g_rva, s.vsize or len(s.content),
            s.characteristics, bytes(raw)))

    # -- 8. loader-visible load config, merged relocations, then payload ------
    # Windows consumes the output load config before our entry point. Keep its
    # directory and target tables live in the outer image, while an authenticated
    # inner recipe restores OS-populated guard slots after section decryption.
    layout_cursor = _align_up(
        max(g_rva + max(s.vsize, len(s.content)) for s, g_rva in grafted), SA)
    outer_import_dir = (
        (import_rva + graft_delta, import_size)
        if import_rva else (0, 0))
    if is_dll:
        if ".limp" in used_names:
            raise AssembleError("source PE uses reserved section name .limp")
        try:
            preload = dll_preload.build_dll_preload_image(
                stub_import_descriptors,
                _get(parsed, "imports", default=()) or (),
                section_rva=layout_cursor,
                image_size=orig_soi,
            )
        except (TypeError, ValueError, struct.error) as exc:
            raise AssembleError(
                f"could not emit DLL preload imports: {exc}") from exc
        try:
            artifacts.import_blob = container.bind_preload_iat_rvas(
                bytes(artifacts.import_blob), list(preload.preload_iat_rvas))
        except (AttributeError, TypeError, ValueError, struct.error) as exc:
            raise AssembleError(
                f"could not authenticate DLL preload IAT map: {exc}") from exc
        used_names.add(".limp")
        out_sections.append(_OutSection(
            ".limp", layout_cursor, len(preload.data),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
            IMAGE_SCN_MEM_WRITE,
            preload.data,
        ))
        outer_import_dir = (layout_cursor, preload.descriptor_size)
        layout_cursor = _align_up(layout_cursor + len(preload.data), SA)
    live_load_config = None
    load_config_dir = (0, 0)
    outer_dll_characteristics = orig.dll_characteristics
    if cfg_plan.source_guard_cf_enabled:
        outer_dll_characteristics |= IMAGE_DLLCHARACTERISTICS_GUARD_CF
    else:
        outer_dll_characteristics &= ~IMAGE_DLLCHARACTERISTICS_GUARD_CF
    if cfg_plan.source_load_config_present:
        try:
            live_load_config = cfg_preservation.build_live_load_config(
                parsed, cfg_plan, section_rva=layout_cursor,
                image_base=out_base,
                outer_target_rvas=(stub_entry_rva, *stub_guard_targets))
        except (TypeError, ValueError, struct.error) as exc:
            raise AssembleError(
                f"could not emit preserved load config: {exc}",
                preservation_plan=cfg_plan,
            ) from exc
        if live_load_config is None:
            raise AssembleError("load-config plan produced no live directory")
        if ".lcfg" in used_names:
            raise AssembleError("source PE uses reserved section name .lcfg")
        used_names.add(".lcfg")
        out_sections.append(_OutSection(
            ".lcfg", live_load_config.section_rva,
            len(live_load_config.data),
            cfg_preservation.LIVE_SECTION_CHARACTERISTICS,
            live_load_config.data,
        ))
        load_config_dir = (
            live_load_config.directory_rva,
            live_load_config.directory_size,
        )
        layout_cursor = _align_up(
            live_load_config.section_rva + len(live_load_config.data), SA)
        try:
            artifacts.load_config_blob = cfg_preservation.build_runtime_slot_blob(
                live_load_config.runtime_slot_copies,
                cfg_plan.merged_declared_targets,
                live_load_config=live_load_config,
                dll_characteristics=outer_dll_characteristics,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise AssembleError(
                "payload artifacts cannot carry authenticated load-config metadata"
            ) from exc
    else:
        try:
            artifacts.load_config_blob = b""
        except (AttributeError, TypeError) as exc:
            raise AssembleError(
                "payload artifacts cannot clear load-config metadata") from exc

    stub_reloc_blob = (
        img.read(reloc_rva + graft_delta, reloc_size)
        if reloc_rva and reloc_size else b"")
    extra_relocations = (
        live_load_config.relocation_target_rvas if live_load_config else ())
    merged_reloc_blob = _merge_dir64_relocations(
        stub_reloc_blob, extra_relocations)
    if extra_relocations:
        if ".lrel2" in used_names:
            raise AssembleError("source PE uses reserved section name .lrel2")
        used_names.add(".lrel2")
        reloc_output_rva = layout_cursor
        out_sections.append(_OutSection(
            ".lrel2", reloc_output_rva, len(merged_reloc_blob),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
            IMAGE_SCN_MEM_DISCARDABLE,
            merged_reloc_blob,
        ))
        reloc_output_dir = (reloc_output_rva, len(merged_reloc_blob))
        layout_cursor = _align_up(
            reloc_output_rva + len(merged_reloc_blob), SA)
    else:
        reloc_output_dir = (
            (reloc_rva + graft_delta, reloc_size)
            if reloc_rva else (0, 0))

    # The payload contains only data used by the runtime. We intentionally avoid
    # fake PackInfo records, fabricated application strings, and fingerprint
    # scrubbing: those mislead inspection tools without improving correctness.
    payload_rva = _align_up(layout_cursor, SA)
    payload = bytearray()

    def _emit(blob: bytes) -> int:
        while len(payload) % 16:            # 16-byte tidy alignment
            payload.append(0)
        at = payload_rva + len(payload)
        payload.extend(blob)
        return at

    # Real section ciphertext, 16-byte aligned by _emit.
    for (ct, d) in protected:
        d.stored_rva = _emit(ct)            # ASSIGN stored_rva into the LIVE desc

    # The metadata RVA is determined by already-emitted section ciphertext and
    # alignment, independent of metadata ciphertext length. Compute it before
    # sealing so format-v2 AAD authenticates the final locator too.
    meta_rva = payload_rva + _align_up(len(payload), 16)
    aad_info = container.PackInfo(
        original_image_base=out_base,
        original_size_of_image=orig_soi,
        oep_rva=oep_rva,
        is_dll=1 if is_dll else 0,
        flags=flags,
        section_count=len(descs),
        meta_rva=meta_rva,
        pdata_rva=pdata_rva,
        pdata_count=pdata_count,
        stub_text_rva=stub_text_rva,
        stub_text_size=stub_text_size,
        dll_export_rva=dll_export_rva,
        dll_export_size=dll_export_size,
        dll_export_sha256_128=dll_export_hash,
    )

    # Finalize AFTER stored_rva assignment. payload.reseal_metadata reads those
    # live descriptors and binds all critical PackInfo geometry into the AAD.
    metadata = _finalize_metadata(artifacts, descs, level, aad_info)
    meta_ct = metadata.meta_stored
    meta_nonce = metadata.meta_nonce
    meta_tag = metadata.meta_tag
    meta_stored_size = metadata.meta_stored_size
    meta_uncompressed_size = metadata.meta_uncompressed_size
    offsets = metadata.offsets
    emitted_meta_rva = _emit(meta_ct)
    if emitted_meta_rva != meta_rva:
        raise AssembleError("metadata RVA changed after AAD sealing")

    out_sections.append(_OutSection(
        ".rdata2", payload_rva, len(payload),
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ, bytes(payload)))

    # -- 9. build + patch PackInfo at g_packinfo's grafted RVA ---------------
    g_packinfo_rva = stub_packinfo_rva + graft_delta
    # guard: nothing (e.g., a reloc target) should live inside the 192-byte slot
    pi = container.PackInfo(
        original_image_base=out_base,
        original_size_of_image=orig_soi,
        oep_rva=oep_rva,
        is_dll=1 if is_dll else 0,
        flags=flags,
        section_count=len(descs),
        meta_rva=meta_rva,
        meta_stored_size=meta_stored_size,
        meta_uncompressed_size=meta_uncompressed_size,
        meta_nonce=meta_nonce,
        meta_tag=meta_tag,
        sections_off=offsets.sections_off,
        imports_off=offsets.imports_off,
        imports_size=offsets.imports_size,
        relocs_off=offsets.relocs_off,
        relocs_size=offsets.relocs_size,
        tls_off=offsets.tls_off,
        pdata_rva=pdata_rva,
        pdata_count=pdata_count,
        aes_key_enc=aes_key_enc,
        kdf_salt=bytes(kdf_salt),
        stub_text_rva=stub_text_rva,
        stub_text_size=stub_text_size,
        dll_export_rva=dll_export_rva,
        dll_export_size=dll_export_size,
        dll_export_sha256_128=dll_export_hash,
    )
    packinfo_bytes = pi.pack()
    # Keep the real magic intact for deterministic post-pack validation.
    _patch_into_out_sections(out_sections, g_packinfo_rva, packinfo_bytes)

    # -- 10. serialize the PE to disk ----------------------------------------
    out_sections.sort(key=lambda s: s.rva)
    _serialize(
        output_path, out_sections, out_base, SA, FA, orig, is_dll,
        entry_rva=stub_entry_rva,
        base_of_code=stub_text_rva,
        import_dir=outer_import_dir,
        reloc_dir=reloc_output_dir,
        tls_dir=(tls_rva + graft_delta, tls_size)
        if (tls_rva and (flags & container.FLAG_HAS_TLS)) else (0, 0),
        iat_dir=_grafted_dir(stub.dir(DIR_IAT), graft_delta),
        rsrc_dir=(rsrc_directory_rva, rsrc_directory_size)
        if rsrc_bytes else (0, 0),
        delay_import_dir=(
            int(_get(parsed, "delay_import_rva", default=0)),
            int(_get(parsed, "delay_import_size", default=0))),
        export_dir=(orig.export_rva, orig.export_size) if (is_dll and orig.export_rva) else (0, 0),
        load_config_dir=load_config_dir,
        guard_cf_enabled=cfg_plan.source_guard_cf_enabled,
    )

    size_of_image = _align_up(
        max(s.rva + s.vsize for s in out_sections), SA)
    return AssembleResult(output_path, size_of_image, len(out_sections),
                          graft_delta, stub_text_rva, stub_text_size, payload_rva,
                          server_shard=server_shard)


# ---------------------------------------------------------------------------
# small helpers used by build_output_pe
# ---------------------------------------------------------------------------
def _grafted_dir(d: Tuple[int, int], delta: int) -> Tuple[int, int]:
    rva, size = d
    return (rva + delta, size) if rva else (0, 0)


def _sec_name(name) -> str:
    """Normalize a section name (str or NUL-padded bytes) to a clean str."""
    if isinstance(name, bytes):
        return name.rstrip(b"\x00").decode("latin-1")
    return (name or "").rstrip("\x00")


def _iter_protected(artifacts) -> Iterable[Tuple[bytes, "container.SectionDesc"]]:
    """Yield (ciphertext_bytes, live SectionDesc) for each protected section.

    The real payload exposes ``stored_sections`` -- a list of ``StoredSection``
    objects with ``.desc`` (the live SectionDesc we mutate ``.stored_rva`` on,
    which ``reseal_metadata`` then re-reads) and ``.data`` (tag-less ciphertext).
    Also tolerates a plain list of ``(ciphertext, SectionDesc)`` tuples.
    """
    items = _get(artifacts, "stored_sections", "sections",
                 "protected_sections", "section_blobs")
    for it in items:
        if isinstance(it, (tuple, list)) and len(it) == 2:
            ct, d = it
        else:                                    # StoredSection(desc=, data=)
            d = _get(it, "desc", "section_desc", "descriptor")
            ct = _get(it, "data", "ciphertext", "stored", "blob")
        yield bytes(ct), d


def _extract_rsrc(parsed) -> Tuple[int, bytes, int, int]:
    """Return owner-section bytes plus exact RESOURCE directory geometry."""
    rva = _get(parsed, "rsrc_rva", default=None)
    data = _get(parsed, "rsrc_bytes", "rsrc_content", default=None)
    if rva is None or data is None:
        rsrc = _get(parsed, "rsrc", "resources", default=None)
        if rsrc is not None:
            rva = _get(rsrc, "rva", "virtual_address", default=None)
            data = _get(rsrc, "bytes", "content", "data", default=None)
    if rva is None or not data:
        return 0, b"", 0, 0
    section_rva = int(rva)
    section_bytes = bytes(data)
    directory_rva = int(_get(
        parsed, "rsrc_directory_rva", default=section_rva))
    directory_size = int(_get(
        parsed, "rsrc_directory_size", default=len(section_bytes)))
    section_end = section_rva + len(section_bytes)
    directory_end = directory_rva + directory_size
    if (directory_rva < section_rva or directory_size <= 0 or
            directory_end > section_end):
        raise AssembleError(
            "resource DataDirectory is outside its preserved owner section")
    return (section_rva, section_bytes, directory_rva, directory_size)


def _dll_export_snapshot(parsed, orig: _OrigHeader) -> dict[int, bytes]:
    """Build the minimal file-backed export bytes Windows needs before DllMain.

    A dependent image resolves a DLL's static imports *before* the dependency's
    entry point runs.  Protected sections are otherwise emitted as zero-backed
    placeholders, which made the original export directory unreadable until
    ``StubDllMain`` had already unpacked it.  Preserve only the authenticated
    source export-directory span at its original RVA; the normal section
    decrypt overwrites this sparse snapshot with the complete source bytes.

    PE export tables are self-referential.  Reject layouts whose name/function/
    ordinal arrays or strings escape the declared export directory instead of
    emitting a partial table that happens to work with ``GetProcAddress`` but
    fails when the Windows loader resolves a static consumer.
    """
    export_rva = int(orig.export_rva)
    export_size = int(orig.export_size)
    if export_rva == 0 and export_size == 0:
        return {}
    if export_rva <= 0 or export_size < 40:
        raise AssembleError(
            "DLL export directory must have a nonzero RVA and at least a "
            "40-byte IMAGE_EXPORT_DIRECTORY")
    export_end = export_rva + export_size
    if export_end > int(_get(parsed, "size_of_image", "sizeof_image")):
        raise AssembleError("DLL export directory escapes SizeOfImage")

    owner = None
    owner_raw = b""
    owner_rva = 0
    for section in _get(parsed, "sections", default=[]) or []:
        section_rva = int(_get(section, "rva", "virtual_address"))
        section_raw = bytes(_get(section, "raw", "content", "data", default=b""))
        if (section_rva <= export_rva and
                export_end <= section_rva + len(section_raw)):
            owner = section
            owner_raw = section_raw
            owner_rva = section_rva
            break
    if owner is None:
        raise AssembleError(
            "DLL export directory is not wholly file-backed by one source section")

    def export_slice(rva: int, size: int, what: str) -> bytes:
        if size < 0 or rva < export_rva or rva + size > export_end:
            raise AssembleError(
                f"DLL export {what} escapes the declared export-directory span")
        offset = rva - owner_rva
        return owner_raw[offset:offset + size]

    def export_cstr(rva: int, what: str) -> None:
        data = export_slice(rva, export_end - rva, what)
        if b"\x00" not in data:
            raise AssembleError(f"DLL export {what} is not NUL-terminated")

    directory = export_slice(export_rva, 40, "header")
    (module_name_rva, _ordinal_base, function_count, name_count,
     functions_rva, names_rva, ordinals_rva) = struct.unpack_from(
        "<IIIIIII", directory, 12)
    if function_count > export_size // 4 or name_count > export_size // 2:
        raise AssembleError("DLL export table count exceeds its declared span")
    export_cstr(module_name_rva, "module name")
    functions = export_slice(
        functions_rva, function_count * 4, "address table")
    names = export_slice(names_rva, name_count * 4, "name-pointer table")
    ordinals = export_slice(
        ordinals_rva, name_count * 2, "name-ordinal table")
    for index in range(name_count):
        ordinal = struct.unpack_from("<H", ordinals, index * 2)[0]
        if ordinal >= function_count:
            raise AssembleError("DLL export name ordinal exceeds address table")
        name_rva = struct.unpack_from("<I", names, index * 4)[0]
        export_cstr(name_rva, f"name[{index}]")
    for index in range(function_count):
        target_rva = struct.unpack_from("<I", functions, index * 4)[0]
        if export_rva <= target_rva < export_end:
            export_cstr(target_rva, f"forwarder[{index}]")

    sparse = bytearray(len(owner_raw))
    start = export_rva - owner_rva
    sparse[start:start + export_size] = owner_raw[start:start + export_size]
    return {owner_rva: bytes(sparse)}


def _patch_into_out_sections(out_sections: List[_OutSection], rva: int,
                             data: bytes) -> None:
    for s in out_sections:
        if s.raw is not None and s.rva <= rva and rva + len(data) <= s.rva + len(s.raw):
            buf = bytearray(s.raw)
            buf[rva - s.rva:rva - s.rva + len(data)] = data
            s.raw = bytes(buf)
            return
    raise AssembleError(
        f"g_packinfo target RVA 0x{rva:x} is not inside any writable output "
        f"section (expected the grafted .data)")


def _serialize(path, sections: List[_OutSection], image_base: int, SA: int,
               FA: int, orig: _OrigHeader, is_dll: bool, *, entry_rva: int,
               base_of_code: int, import_dir, reloc_dir, iat_dir, rsrc_dir,
               export_dir, tls_dir, load_config_dir=(0, 0),
               guard_cf_enabled: bool = False,
               delay_import_dir=(0, 0)) -> None:
    num_sections = len(sections)
    e_lfanew = 0x80
    headers_end = e_lfanew + 4 + 20 + IMAGE_SIZEOF_OPTIONAL_HEADER64 + num_sections * 40
    size_of_headers = _align_up(headers_end, FA)

    first_rva = min(s.rva for s in sections)
    if size_of_headers > first_rva:
        raise AssembleError(
            f"headers ({size_of_headers:#x}) overrun the first section RVA "
            f"({first_rva:#x}); too many sections for a single header page")

    # assign file offsets to sections that carry raw bytes (monotonic by RVA)
    file_cursor = size_of_headers
    raw_sizes, raw_ptrs = {}, {}
    for s in sections:
        if s.raw:
            rs = _align_up(len(s.raw), FA)
            raw_sizes[id(s)] = rs
            raw_ptrs[id(s)] = file_cursor
            file_cursor += rs
        else:
            raw_sizes[id(s)] = 0
            raw_ptrs[id(s)] = 0
    size_of_image = _align_up(max(s.rva + s.vsize for s in sections), SA)

    size_of_code = sum(raw_sizes[id(s)] for s in sections
                       if s.characteristics & IMAGE_SCN_CNT_CODE)
    size_of_idata = sum(raw_sizes[id(s)] for s in sections
                        if s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
    size_of_udata = sum(s.vsize for s in sections
                        if s.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)

    # ---- file header ----
    characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
    if is_dll:
        characteristics |= IMAGE_FILE_DLL
    file_header = struct.pack("<HHIIIHH", IMAGE_FILE_MACHINE_AMD64, num_sections,
                              orig.timestamp & 0xFFFFFFFF, 0, 0,
                              IMAGE_SIZEOF_OPTIONAL_HEADER64, characteristics)

    # ---- optional header (PE32+) ----
    oh = bytearray(IMAGE_SIZEOF_OPTIONAL_HEADER64)
    struct.pack_into("<H", oh, 0x00, IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    struct.pack_into("<BB", oh, 0x02, orig.major_linker & 0xFF, orig.minor_linker & 0xFF)
    struct.pack_into("<I", oh, 0x04, size_of_code)
    struct.pack_into("<I", oh, 0x08, size_of_idata)
    struct.pack_into("<I", oh, 0x0C, size_of_udata)
    struct.pack_into("<I", oh, 0x10, entry_rva)
    struct.pack_into("<I", oh, 0x14, base_of_code)
    struct.pack_into("<Q", oh, 0x18, image_base)
    struct.pack_into("<I", oh, 0x20, SA)
    struct.pack_into("<I", oh, 0x24, FA)
    struct.pack_into("<HH", oh, 0x28, orig.major_os, orig.minor_os)
    struct.pack_into("<HH", oh, 0x2C, orig.major_image, orig.minor_image)
    struct.pack_into("<HH", oh, 0x30, orig.major_subsystem, orig.minor_subsystem)
    struct.pack_into("<I", oh, 0x34, orig.win32_version)
    struct.pack_into("<I", oh, 0x38, size_of_image)
    struct.pack_into("<I", oh, 0x3C, size_of_headers)
    struct.pack_into("<I", oh, 0x40, 0)                 # CheckSum (computed last)
    struct.pack_into("<H", oh, 0x44, orig.subsystem)
    dll_chars = orig.dll_characteristics
    if guard_cf_enabled:
        dll_chars |= IMAGE_DLLCHARACTERISTICS_GUARD_CF
    else:
        dll_chars &= ~IMAGE_DLLCHARACTERISTICS_GUARD_CF
    struct.pack_into("<H", oh, 0x46, dll_chars)
    struct.pack_into("<Q", oh, 0x48, orig.stack_reserve)
    struct.pack_into("<Q", oh, 0x50, orig.stack_commit)
    struct.pack_into("<Q", oh, 0x58, orig.heap_reserve)
    struct.pack_into("<Q", oh, 0x60, orig.heap_commit)
    struct.pack_into("<I", oh, 0x68, orig.loader_flags)
    struct.pack_into("<I", oh, 0x6C, NUM_DATA_DIRECTORIES)

    dd = 0x70
    def _dir(index, pair):
        struct.pack_into("<II", oh, dd + index * 8, pair[0], pair[1])
    for i in range(NUM_DATA_DIRECTORIES):
        _dir(i, (0, 0))
    _dir(DIR_EXPORT, export_dir)      # original export dir (DLL only) -> live post-unpack
    _dir(DIR_IMPORT, import_dir)      # stub imports only
    _dir(DIR_RESOURCE, rsrc_dir)      # preserved resources
    _dir(DIR_BASERELOC, reloc_dir)    # stub relocs only (ASLR fixes the stub)
    _dir(DIR_TLS, tls_dir)            # OS-managed stub static-TLS anchor
    _dir(DIR_LOAD_CONFIG, load_config_dir)
    _dir(DIR_IAT, iat_dir)            # stub IAT (informational)
    _dir(DIR_DELAY_IMPORT, delay_import_dir)
    # EXCEPTION is registered by the loader. LOAD_CONFIG is loader-visible and
    # points at the immutable outer clone when the source carried one.

    # ---- section table ----
    sec_table = bytearray()
    for s in sections:
        name = s.name.encode("latin-1")[:8].ljust(8, b"\x00")
        sec_table += struct.pack(
            "<8sIIIIIIHHI", name, s.vsize, s.rva, raw_sizes[id(s)],
            raw_ptrs[id(s)], 0, 0, 0, 0, s.characteristics)

    # ---- assemble the file image ----
    out = bytearray()
    out += _dos_header(e_lfanew)
    out += _DOS_STUB
    assert len(out) == e_lfanew, f"DOS area {len(out):#x} != e_lfanew {e_lfanew:#x}"
    out += b"PE\x00\x00"
    out += file_header
    out += bytes(oh)
    out += sec_table
    out += b"\x00" * (size_of_headers - len(out))       # pad to SizeOfHeaders

    for s in sections:
        if s.raw:
            assert len(out) == raw_ptrs[id(s)], "section file offset drift"
            out += s.raw
            out += b"\x00" * (raw_sizes[id(s)] - len(s.raw))

    # ---- PE checksum (over the finished file, with the field zeroed) -------
    checksum_off = e_lfanew + 4 + 20 + 0x40
    struct.pack_into("<I", out, checksum_off, _pe_checksum(out, checksum_off))

    out_dir = os.path.dirname(os.path.abspath(path))
    prefix = f".{os.path.basename(path)}."
    fd, tmp = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=out_dir)
    try:
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(out)
        os.replace(tmp, path)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _pe_checksum(data: bytes, checksum_off: int) -> int:
    """Standard PE image checksum (16-bit ones'-complement sum + file length).

    The 4-byte CheckSum field itself is treated as zero -- that is both 16-bit
    words at ``checksum_off`` and ``checksum_off + 2``.
    """
    total = 0
    n = len(data)
    for i in range(0, n & ~1, 2):
        if i == checksum_off or i == checksum_off + 2:
            continue                     # 4-byte CheckSum field reads as 0
        total += data[i] | (data[i + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
    if n & 1:                            # trailing odd byte, if any
        total += data[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + n) & 0xFFFFFFFF


# public alias
assemble = build_output_pe
