"""Lethe ABI cross-check: ``packer/container.py`` vs ``stub/src/pack_info.h``.

``container.py`` (the Python builder's view of the format) and ``pack_info.h``
(the native C stub's view) MUST stay byte-for-byte identical -- the builder writes
the struct with ``struct.pack`` and the stub reads the identical C layout out of
its own image. This module parses the C header and asserts it agrees with the
Python module on: the magic, format version, flag bits, the by-hash marker,
the two fixed struct sizes, and the *field-width sequence* of ``PackInfo`` /
``SectionDesc`` (so a reordered or resized field is caught here rather than at
runtime in the loader).

These are the "additional unit tests" for the packer; they have no third-party
dependencies and pass NOW (both files already exist). The primary,
gate-registered container tests live at repo root in
``tests/test_lethe_container.py``.

Run: ``python -m pytest tools/security/packer/tests/test_lethe_container_abi.py``
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest


PACKER_ROOT = Path(__file__).resolve().parents[1]   # tools/security/packer
CONTAINER_PATH = PACKER_ROOT / "packer" / "container.py"
HEADER_PATH = PACKER_ROOT / "stub" / "src" / "pack_info.h"

if not CONTAINER_PATH.is_file():  # pragma: no cover - ships with repo
    pytest.skip(f"container.py missing at {CONTAINER_PATH}", allow_module_level=True)

_SPEC = importlib.util.spec_from_file_location("lethe_container_abi", CONTAINER_PATH)
container = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = container  # required so @dataclass can resolve annotations
_SPEC.loader.exec_module(container)


# ---------------------------------------------------------------------------
# tiny C-header parsing helpers (regex-level; the header is stable + simple)
# ---------------------------------------------------------------------------

_CTYPE_SIZE = {"uint8_t": 1, "uint16_t": 2, "uint32_t": 4, "uint64_t": 8}
# struct format char -> byte width, for the fixed-width codes container.py uses
_FMT_SIZE = {"B": 1, "H": 2, "I": 4, "Q": 8}


def _header_text():
    if not HEADER_PATH.is_file():
        pytest.skip(f"pack_info.h missing at {HEADER_PATH}")
    return HEADER_PATH.read_text(encoding="utf-8", errors="replace")


def _define(text, name):
    """Return the raw token of ``#define <name> <token>`` (first hit)."""
    m = re.search(rf"#define\s+{re.escape(name)}\s+([^\s/]+)", text)
    assert m, f"#define {name} not found in pack_info.h"
    return m.group(1)


def _define_int(text, name):
    tok = _define(text, name).rstrip("uUlL")
    return int(tok, 0)


def _struct_body(text, name):
    m = re.search(rf"typedef\s+struct\s+{name}\s*\{{(.*?)\}}\s*{name}\s*;",
                  text, re.DOTALL)
    assert m, f"struct {name} not found in pack_info.h"
    return m.group(1)


def _field_widths(struct_body):
    """Ordered list of (name, byte_width) for the fields in a struct body."""
    widths = []
    for ctype, name, arr in re.findall(
        r"\b(uint8_t|uint16_t|uint32_t|uint64_t)\s+(\w+)\s*(?:\[(\d+)\])?\s*;",
        struct_body,
    ):
        count = int(arr) if arr else 1
        widths.append((name, _CTYPE_SIZE[ctype] * count))
    return widths


def _py_struct_widths(fmt):
    """Byte widths implied by a struct format string, in order (skip the '<')."""
    widths = []
    for count, code in re.findall(r"(\d*)([BHIQs])", fmt):
        n = int(count) if count else 1
        widths.append(n if code == "s" else _FMT_SIZE[code] * n)
    return widths


# ---------------------------------------------------------------------------
# constant agreement
# ---------------------------------------------------------------------------

def test_header_magic_matches_container():
    text = _header_text()
    # LETHE_MAGIC is the 7 visible chars; container.MAGIC is those + trailing NUL.
    magic_str = _define(text, "LETHE_MAGIC").strip('"')
    assert magic_str.encode("ascii") + b"\x00" == container.MAGIC
    assert _define_int(text, "LETHE_MAGIC_LEN") == len(container.MAGIC) == 8


def test_header_format_version_matches_container():
    assert _define_int(_header_text(), "LETHE_FORMAT_VERSION") == container.FORMAT_VERSION


def test_header_flag_bits_match_container():
    text = _header_text()
    assert _define_int(text, "LETHE_FLAG_HAS_TLS") == container.FLAG_HAS_TLS
    assert _define_int(text, "LETHE_FLAG_HAS_EXCEPTIONS") == container.FLAG_HAS_EXCEPTIONS
    assert _define_int(text, "LETHE_FLAG_ANTIDEBUG") == container.FLAG_ANTIDEBUG
    assert _define_int(text, "LETHE_FLAG_MEMGUARD") == container.FLAG_MEMGUARD


def test_header_hash_marker_matches_container():
    assert _define_int(_header_text(), "LETHE_IMPORT_BY_HASH") == container.IMPORT_HINT_BY_HASH


# ---------------------------------------------------------------------------
# struct size + field-layout agreement
# ---------------------------------------------------------------------------

def test_header_compile_time_size_guards_match_container():
    text = _header_text()
    m_pi = re.search(r"sizeof\(PackInfo\)\s*==\s*(\d+)", text)
    m_sd = re.search(r"sizeof\(SectionDesc\)\s*==\s*(\d+)", text)
    assert m_pi and int(m_pi.group(1)) == container.PACKINFO_SIZE == 192
    assert m_sd and int(m_sd.group(1)) == container.SECTIONDESC_SIZE == 52


def test_packinfo_field_widths_sum_to_192():
    widths = _field_widths(_struct_body(_header_text(), "PackInfo"))
    assert sum(w for _n, w in widths) == 192


def test_sectiondesc_field_widths_sum_to_52():
    widths = _field_widths(_struct_body(_header_text(), "SectionDesc"))
    assert sum(w for _n, w in widths) == 52


@pytest.mark.parametrize("struct_name", ["PackInfo", "SectionDesc"])
def test_c_field_widths_match_python_struct_format(struct_name):
    """The strongest drift guard: the ordered field-width sequence parsed from
    the C header must equal the width sequence implied by container.py's own
    ``struct.Struct`` format. A reordered/resized field breaks this."""
    attr = {"PackInfo": "_PACKINFO", "SectionDesc": "_SECTIONDESC"}[struct_name]
    py_struct = getattr(container, attr, None)
    if py_struct is None:  # pragma: no cover - private attr renamed
        pytest.skip(f"container.{attr} not exposed; width cross-check skipped")

    c_widths = [w for _n, w in _field_widths(_struct_body(_header_text(), struct_name))]
    py_widths = _py_struct_widths(py_struct.format)
    assert c_widths == py_widths, (
        f"{struct_name} layout drift:\n  C : {c_widths}\n  py: {py_widths}"
    )


# ---------------------------------------------------------------------------
# complementary container invariants (beyond the repo-root round-trip file)
# ---------------------------------------------------------------------------

def test_metadata_envelope_is_one_contiguous_unit():
    """The envelope is compressed+encrypted as ONE unit, so build_metadata must
    hand back a single buffer whose declared sub-regions all fit inside it."""
    sd = container.SectionDesc(0x1000, 0x2000, 10, 0x2000, 0x9000, 0x40000040,
                               b"\x00" * 12, b"\x00" * 16)
    sd_blob = container.pack_section_descs([sd])
    imp = container.build_import_blob([
        container.ImportDll("bcrypt.dll", [container.ImportFunc(0x40, name="BCryptEncrypt")]),
    ])
    reloc = b"\x00" * 8            # a minimal (empty-ish) reloc run
    tls = container.build_tls_blob(0, 0, 0, 0, [])
    buf, offs = container.build_metadata(sd_blob, imp, reloc, tls)
    for off, size in (
        (offs.sections_off, len(sd_blob)),
        (offs.imports_off, offs.imports_size),
        (offs.relocs_off, offs.relocs_size),
        (offs.tls_off, len(tls)),
    ):
        assert 0 <= off <= len(buf)
        assert off + size <= len(buf)


def test_hash_based_blob_dll_names_survive_round_trip():
    """DLL names are XOR-encrypted (not hashed) so they can be recovered for
    LoadLibraryA fallback.  Verify the parse recovers them."""
    dlls = [
        container.ImportDll("KERNEL32.dll", [
            container.ImportFunc(0x10, name="GetTickCount"),
            container.ImportFunc(0x18, name="ExitProcess"),
        ]),
    ]
    blob = container.build_import_blob(dlls)
    parsed = container.parse_import_blob(blob)
    assert [d.name for d in parsed] == ["KERNEL32.dll"]
    assert len(parsed[0].funcs) == 2
    # No plaintext function name should appear in the blob
    assert b"GetTickCount" not in blob
    assert b"ExitProcess" not in blob


def test_is_dll_flag_survives_round_trip():
    pi = container.PackInfo(is_dll=1, oep_rva=0x1234, section_count=1)
    assert container.PackInfo.from_bytes(pi.pack()).is_dll == 1
