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
import os
import struct
import time
import zlib
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

# --- container ABI (import only; never edit) -------------------------------
try:                                    # normal: imported as ``packer.assemble``
    from . import container
except ImportError:                     # fallback: flat import / direct run
    import container  # type: ignore

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
DIR_TLS, DIR_LOAD_CONFIG, DIR_IAT = 9, 10, 12
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

_FINGERPRINT_STRINGS = [
    b"lethe_stub_x64.dll",
    b"lethe_stub_x64",
    b"StubDllMain",
    b"StubExeEntry",
    # MSVC toolchain residue that clusters samples during triage
    b"RSDS",                              # PDB CodeView signature
    b".pdb",
    b"vcruntime140",
    b"Microsoft Visual C++ Runtime",
    b"api-ms-win-",                       # API-set fingerprints if any leaked in
]

# Pool of plausible-looking alt section names picked per-build. The map above
# was a fixed rewrite; we now randomize from this list so section-name-based
# clustering ("packer XYZ always calls its data section .data0") stops working.
_STUB_ALT_NAME_POOL = {
    ".text":  [".text0", ".text2", ".code", ".textbss", ".xtext"],
    ".rdata": [".rdata0", ".rdata2", ".const", ".rdata_e", ".rodata"],
    ".data":  [".data0", ".data2", ".bss2", ".gfids", ".00cfg"],
    ".pdata": [".pdata0", ".pdata2", ".xdata", ".eh_frame"],
    ".reloc": [".reloc0", ".reloc2", ".fixups", ".rlc"],
    ".rsrc":  [".rsrc0", ".rsrc2", ".res"],
}


# ---------------------------------------------------------------------------
# Polymorphism helpers (per-build randomization -- kills static tool signatures)
#
# NONE of these bytes are ever read by the stub at runtime. They exist purely to
# poison static analysis: pattern scanners, `strings`, IDA/Ghidra initial passes,
# and LLM-based RE assistants (all of which lean on structural fingerprints).
#
# Runtime invariants preserved:
#  * Decoys live in the appended payload section only -- never in .text (whose
#    hash binds the master key) and never inside the real PackInfo slot.
#  * Every stored_rva is assigned by the emitter AFTER padding is placed, so
#    the encrypted metadata envelope always points at the correct ciphertext.
#  * The real PackInfo has its LETHE01 magic destroyed at output time (existing
#    behaviour); only the decoys carry intact magic, so a `grep LETHE01`
#    finds only chaff.
# ---------------------------------------------------------------------------
def _rand_int(nbytes: int) -> int:
    return int.from_bytes(os.urandom(nbytes), "little")


def _rand_range(lo: int, hi: int) -> int:
    """Uniform-ish int in [lo, hi]. os.urandom-backed; not for cryptographic use."""
    if hi <= lo:
        return lo
    span = hi - lo + 1
    return lo + (_rand_int(4) % span)


def _rand_padding(min_bytes: int, max_bytes: int) -> bytes:
    """High-entropy filler of a random length -- indistinguishable from ciphertext
    to a byte-histogram scanner. Kept short in aggregate so packed size stays sane."""
    return os.urandom(_rand_range(min_bytes, max_bytes))


# Plausible-looking strings that make `strings <bin>` output resemble a normal
# Windows application, not a packer. Pooled + randomly sampled per build so no
# fixed string set fingerprints Lethe. Every entry is NUL-terminated to look
# like a real C string.
_DECOY_STRING_POOL = [
    b"Failed to initialize graphics subsystem\x00",
    b"Configuration file not found\x00",
    b"OpenGL 4.5 or later required\x00",
    b"D3D11 device creation failed (0x%08x)\x00",
    b"Unable to open registry key HKLM\\Software\\%s\x00",
    b"Warning: legacy mode is deprecated\x00",
    b"Loading plugin: %s (v%d.%d.%d)\x00",
    b"Session cache hit rate: %.1f%%\x00",
    b"Received signal %d, shutting down\x00",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\x00",
    b"[%04d-%02d-%02d %02d:%02d:%02d] %s\x00",
    b"connect() timed out after %d ms\x00",
    b"resource temporarily unavailable\x00",
    b"IPC channel closed unexpectedly\x00",
    b"invalid utf-8 sequence at offset %zu\x00",
    b"cache miss for key '%s' bucket %u\x00",
    b"assertion failed: %s (%s:%d)\x00",
    b"C:\\Users\\build\\AppData\\Local\\Temp\\_build_manifest.txt\x00",
    b"C:\\Program Files\\Common Files\\Microsoft Shared\\VC\\redist\\x64\\\x00",
    b"D:\\a\\_work\\1\\s\\src\\core\\pipeline\\stream.cpp\x00",
    b"kernel32.dll\x00",             # already imported elsewhere, adds noise
    b"advapi32.dll\x00",
    b"shell32.dll\x00",
    b"user32.dll\x00",
    b"ole32.dll\x00",
    b"CoCreateInstance\x00",
    b"RegOpenKeyExW\x00",
    b"CreateWindowExW\x00",
    b"GetSystemMetrics\x00",
    b"IsWow64Process\x00",
]


def _build_decoy_strings_blob(min_count: int = 12, max_count: int = 20) -> bytes:
    """Concatenate a random subset of the pool with random inter-string padding."""
    count = _rand_range(min_count, min(max_count, len(_DECOY_STRING_POOL)))
    # unbiased selection without a random.sample import
    pool = list(_DECOY_STRING_POOL)
    picked: List[bytes] = []
    for _ in range(count):
        if not pool:
            break
        idx = _rand_int(2) % len(pool)
        picked.append(pool.pop(idx))
    buf = bytearray()
    for s in picked:
        buf.extend(s)
        # 0-3 extra NULs / low bytes between strings -- typical for aligned data
        buf.extend(bytes(_rand_range(0, 3)))
    return bytes(buf)


def _build_decoy_packinfo() -> bytes:
    """A fake PackInfo with intact LETHE01 magic and internally-plausible fields.

    The real PackInfo's magic is scrubbed at output time (existing behaviour), so
    a scanner grepping for the LETHE01 pattern in the packed binary finds only
    decoys. Each decoy parses cleanly through container.PackInfo.from_bytes but
    the RVAs point at random offsets, so any attempt to follow them yields
    garbage. Every field is fresh entropy, so decoys cluster to no fixed pattern
    across builds."""
    pi = container.PackInfo(
        original_image_base=0x140000000 | (_rand_int(2) << 16),
        original_size_of_image=0x2000 + (_rand_int(2) & 0xFFFF0),
        oep_rva=0x1000 + (_rand_int(2) & 0xFFF0),
        is_dll=_rand_int(1) & 1,
        flags=_rand_int(4) & 0x0F,       # only real bits are 0x01..0x08
        section_count=_rand_range(1, 12),
        meta_rva=_rand_int(4) & 0xFFFFF,
        meta_stored_size=_rand_int(3) & 0xFFFFF,
        meta_uncompressed_size=_rand_int(3) & 0xFFFFF,
        meta_nonce=os.urandom(12),
        meta_tag=os.urandom(16),
        sections_off=_rand_int(2) & 0xFFF,
        imports_off=_rand_int(2) & 0xFFFF,
        imports_size=_rand_int(2) & 0xFFF,
        relocs_off=_rand_int(2) & 0xFFFF,
        relocs_size=_rand_int(2) & 0xFFF,
        tls_off=_rand_int(2) & 0xFFFF,
        pdata_rva=_rand_int(3) & 0xFFFFF,
        pdata_count=_rand_int(1),
        aes_key_enc=os.urandom(32),
        kdf_salt=os.urandom(16),
        stub_text_rva=_rand_int(3) & 0xFFFFF,
        stub_text_size=_rand_int(2) & 0xFFFF,
    )
    return pi.pack()


def _pick_alt_name(orig_name: str, used: set) -> str:
    """Pick a plausible alt name for a grafted stub section, avoiding collisions."""
    pool = _STUB_ALT_NAME_POOL.get(orig_name)
    if not pool:
        return orig_name[:4] + "2"
    # Try random pool entries first, then fall back to a mangled default
    order = list(pool)
    # cheap fisher-yates-ish shuffle using os.urandom
    for i in range(len(order) - 1, 0, -1):
        j = _rand_int(2) % (i + 1)
        order[i], order[j] = order[j], order[i]
    for cand in order:
        if cand not in used:
            return cand
    return orig_name[:4] + "2"


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


class AssembleError(RuntimeError):
    """Raised for any unrecoverable layout / graft problem (caught upstream)."""


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


# ---------------------------------------------------------------------------
# metadata finalize -- bake the freshly-assigned stored_rva into the envelope
# ---------------------------------------------------------------------------
def _finalize_metadata(artifacts, descs: List["container.SectionDesc"],
                       level: int) -> Tuple[bytes, bytes, bytes, int, int,
                                            container.MetadataOffsets]:
    """Produce the FINAL encrypted metadata envelope after the assembler has
    assigned every ``SectionDesc.stored_rva``.

    Returns (meta_ct, meta_nonce, meta_tag, meta_stored_size,
             meta_uncompressed_size, offsets).

    PRIMARY path: the payload exposes ``reseal_metadata()`` -- the authoritative
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
        env = reseal()                        # reads the live desc.stored_rva
        offsets = _get(env, "offsets", "meta_offsets")
        meta_ct = bytes(_get(env, "meta_stored", "meta_ciphertext"))
        return (meta_ct,
                bytes(_get(env, "meta_nonce")),
                bytes(_get(env, "meta_tag")),
                len(meta_ct),
                int(_get(env, "meta_uncompressed_size", "meta_uncomp_size")),
                offsets)

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
    meta_plain, offsets = container.build_metadata(
        container.pack_section_descs(descs), import_blob, reloc_blob, tls_blob)
    compressed = zlib.compress(meta_plain, max(0, min(9, level)))
    nonce = os.urandom(12)
    flags = int(getattr(artifacts, "flags", 0))
    meta_aad = struct.pack("<I", flags)
    out = AESGCM(meta_key).encrypt(nonce, compressed, meta_aad)
    return (out[:-16], nonce, out[-16:], len(out) - 16, len(meta_plain), offsets)


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


def _load_stub(stub_path: str) -> _StubImage:
    if not os.path.isfile(stub_path):
        raise AssembleError(
            f"prebuilt stub not found: {stub_path}\n"
            "The integrator must build it first (stub/build_stub.ps1 -> "
            "stub/prebuilt/lethe_stub_x64.dll) before packing.")
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
    with open(stub_path, "rb") as f:
        return _StubImage(f.read())


# ---------------------------------------------------------------------------
# the assembler
# ---------------------------------------------------------------------------
def build_output_pe(parsed, artifacts, output_path: str, *,
                    input_path: Optional[str] = None,
                    options=None,
                    stub_path: Optional[str] = None) -> AssembleResult:
    """Assemble and write the packed output PE. Raises ``AssembleError`` on any
    unrecoverable problem (the orchestrator turns that into ``PackResult.ok=False``)."""
    stub = _load_stub(stub_path or _default_stub_path())

    # -- pull the semantic inputs (tolerant to field-name drift) -------------
    out_base = int(_get(parsed, "image_base", "imagebase", "original_image_base"))
    orig_soi = int(_get(parsed, "size_of_image", "sizeof_image",
                        "original_size_of_image"))
    is_dll = bool(_get(artifacts, "is_dll", default=_get(parsed, "is_dll",
                                                         default=False)))
    flags = int(_get(artifacts, "flags", default=0))
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
            pos += 20

    # The TLS directory contains absolute VAs. Its pointer fields were adjusted
    # by the generic DIR64 loop above; only the data-directory RVA needs the
    # same single graft delta at serialization time.
    tls_rva, tls_size = stub.dir(DIR_TLS)

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
    if options and getattr(options, 'server_shard', False):
        server_shard = os.urandom(32)
        aes_key_enc = bytes(a ^ b for a, b in zip(aes_key_enc, server_shard))

    # -- 6. placeholder sections (protected) + preserved .rsrc ---------------
    #    driven off the payload's per-section SectionDescs (rva/vsize/chars).
    protected = list(_iter_protected(artifacts))
    if not protected:
        raise AssembleError("payload exposed no protected sections")

    descs: List[container.SectionDesc] = [d for (_ct, d) in protected]
    rsrc_rva, rsrc_bytes = _extract_rsrc(parsed)

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
            out_sections.append(_OutSection(
                sname, srva, vsize,
                IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
                None))
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
        for fp in _FINGERPRINT_STRINGS:
            idx = 0
            while True:
                idx = raw.find(fp, idx)
                if idx == -1:
                    break
                raw[idx:idx + len(fp)] = b"\x00" * len(fp)
                idx += len(fp)
        sn = s.name or ".stub"
        if sn in used_names:
            sn = _pick_alt_name(sn, used_names)
        used_names.add(sn)
        out_sections.append(_OutSection(
            sn, g_rva, s.vsize or len(s.content),
            s.characteristics, bytes(raw)))

    # -- 8. payload section: per-section ciphertext + sealed meta envelope ---
    # Interleaved with per-build polymorphism: random-length padding + decoy
    # PackInfo blobs (intact LETHE01 magic) + decoy strings. The stub never
    # reads any of these -- section stored_rva / meta_rva are the only pointers
    # into this region and both are assigned by _emit() AFTER padding lands, so
    # every real reference stays consistent. See "Polymorphism helpers" above.
    payload_end = max(g_rva + max(s.vsize, len(s.content))
                      for s, g_rva in grafted)
    payload_rva = _align_up(payload_end, SA)
    payload = bytearray()

    def _emit(blob: bytes) -> int:
        while len(payload) % 16:            # 16-byte tidy alignment
            payload.append(0)
        at = payload_rva + len(payload)
        payload.extend(blob)
        return at

    # LEADING chaff: random padding + 2-4 decoy PackInfos + decoy strings.
    # Scanners hit these before any real ciphertext, get plausible parses, waste
    # time following invalid RVAs.
    _emit(_rand_padding(96, 384))
    for _ in range(_rand_range(2, 4)):
        _emit(_build_decoy_packinfo())
        _emit(_rand_padding(32, 160))
    _emit(_build_decoy_strings_blob())
    _emit(_rand_padding(32, 128))

    # REAL section ciphertext with small random gaps between blobs. Gaps stay
    # small so packed size overhead is bounded (~< 4 KiB per protected section).
    for (ct, d) in protected:
        _emit(_rand_padding(16, 96))
        d.stored_rva = _emit(ct)            # ASSIGN stored_rva into the LIVE desc

    # PRE-METADATA chaff: additional padding + one more decoy PackInfo so an
    # analyst working outward from the ciphertext region hits it before finding
    # the real envelope.
    _emit(_rand_padding(48, 192))
    _emit(_build_decoy_packinfo())
    _emit(_rand_padding(32, 128))

    # finalize the envelope AFTER stored_rva assignment (payload.reseal_metadata
    # reads those same live desc objects; see _finalize_metadata).
    (meta_ct, meta_nonce, meta_tag, meta_stored_size,
     meta_uncompressed_size, offsets) = _finalize_metadata(artifacts, descs, level)
    meta_rva = _emit(meta_ct)

    # TRAILING chaff: more decoys after the real envelope.
    _emit(_rand_padding(64, 256))
    for _ in range(_rand_range(1, 3)):
        _emit(_build_decoy_packinfo())
        _emit(_rand_padding(32, 160))
    _emit(_build_decoy_strings_blob())

    out_sections.append(_OutSection(
        ".rdata2", payload_rva, len(payload),
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ, bytes(payload)))

    # -- 9. build + patch PackInfo at g_packinfo's grafted RVA ---------------
    g_packinfo_rva = stub.find_packinfo_rva() + graft_delta
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
    )
    packinfo_bytes = pi.pack()
    # Destroy the LETHE01 magic on the REAL PackInfo. The stub never validates
    # the magic (g_packinfo is a direct global); it existed only for the builder's
    # scanner. Combined with the decoy PackInfos scattered in the payload, this
    # inverts the analyst's search: `grep LETHE01` hits only decoys, and none of
    # them parse to a working image. The scrub bytes are pure entropy so a
    # per-build memcmp-fingerprint on the wiped region also produces no signal.
    packinfo_bytes = os.urandom(8) + packinfo_bytes[8:]
    _patch_into_out_sections(out_sections, g_packinfo_rva, packinfo_bytes)

    # -- 10. serialize the PE to disk ----------------------------------------
    out_sections.sort(key=lambda s: s.rva)
    _serialize(
        output_path, out_sections, out_base, SA, FA, orig, is_dll,
        entry_rva=(stub.find_export_rva("StubDllMain" if is_dll else "StubExeEntry")
                   or stub.entry_rva) + graft_delta,
        base_of_code=stub_text_rva,
        import_dir=(import_rva + graft_delta, import_size) if import_rva else (0, 0),
        reloc_dir=(reloc_rva + graft_delta, reloc_size) if reloc_rva else (0, 0),
        tls_dir=(tls_rva + graft_delta, tls_size) if tls_rva else (0, 0),
        iat_dir=_grafted_dir(stub.dir(DIR_IAT), graft_delta),
        rsrc_dir=(rsrc_rva, len(rsrc_bytes)) if rsrc_bytes else (0, 0),
        export_dir=(orig.export_rva, orig.export_size) if (is_dll and orig.export_rva) else (0, 0),
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


def _extract_rsrc(parsed) -> Tuple[int, bytes]:
    """Return (rsrc_rva, rsrc_bytes) or (0, b'') when the PE has no resources."""
    rva = _get(parsed, "rsrc_rva", default=None)
    data = _get(parsed, "rsrc_bytes", "rsrc_content", default=None)
    if rva is None or data is None:
        rsrc = _get(parsed, "rsrc", "resources", default=None)
        if rsrc is not None:
            rva = _get(rsrc, "rva", "virtual_address", default=None)
            data = _get(rsrc, "bytes", "content", "data", default=None)
    if rva is None or not data:
        return 0, b""
    return int(rva), bytes(data)


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
               export_dir, tls_dir) -> None:
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
    # Preserve original DllCharacteristics with only GUARD_CF cleared (§6)
    dll_chars = orig.dll_characteristics & ~IMAGE_DLLCHARACTERISTICS_GUARD_CF
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
    _dir(DIR_IAT, iat_dir)            # stub IAT (informational)
    # EXCEPTION(3) and LOAD_CONFIG(10) intentionally left zero.

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

    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(out)
    os.replace(tmp, path)


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
