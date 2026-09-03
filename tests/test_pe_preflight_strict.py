from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("lief")
from packer import assemble, container, pe_analyze  # noqa: E402
from tools import handler_shape_audit  # noqa: E402


def _section(name: str, rva: int, virtual_size: int, raw: bytes = b"",
             characteristics: int = 0):
    return pe_analyze.ParsedSection(
        name, rva, virtual_size, raw, characteristics)


def _reloc_block(page_rva: int, *entries: int) -> bytes:
    body = b"".join(struct.pack("<H", entry) for entry in entries)
    while (8 + len(body)) % 4:
        body += b"\0\0"
    return struct.pack("<II", page_rva, 8 + len(body)) + body


def test_data_directory_distinguishes_absent_from_malformed() -> None:
    class Binary:
        def __init__(self, directory):
            self.directory = directory

        def data_directory(self, _dtype):
            return self.directory

    assert pe_analyze._data_dir(Binary(None), "TLS_TABLE") == (0, 0)
    assert pe_analyze._data_dir(
        Binary(SimpleNamespace(rva=0, size=0)), "TLS_TABLE") == (0, 0)

    with pytest.raises(ValueError, match="presence disagree"):
        pe_analyze._data_dir(
            Binary(SimpleNamespace(rva=0x1000, size=0)), "TLS_TABLE")


def test_data_directory_api_failure_is_not_reported_as_absent() -> None:
    class BrokenBinary:
        def data_directory(self, _dtype):
            raise RuntimeError("parser failure")

    with pytest.raises(ValueError, match="cannot read PE data directory"):
        pe_analyze._data_dir(BrokenBinary(), "TLS_TABLE")


def test_directory_slice_requires_every_requested_byte() -> None:
    sections = [_section(".x", 0x1000, 0x1000, b"A" * 16)]
    assert pe_analyze._slice_at_rva(
        sections, 0x1008, 8, what="test") == b"A" * 8
    with pytest.raises(ValueError, match="not file-backed"):
        pe_analyze._slice_at_rva(sections, 0x1008, 9, what="test")


@pytest.mark.parametrize(
    "blob, error",
    [
        (b"\0" * 7, "trailing partial block"),
        (struct.pack("<IIH", 0x1000, 10, 0), "malformed base relocation block"),
        (_reloc_block(0x1001, 0), "malformed base relocation block"),
        (_reloc_block(0x1000, 3 << 12), "unsupported AMD64"),
        (_reloc_block(0x3000, 10 << 12), "outside SizeOfImage"),
        (_reloc_block(0x1000, 0xA100, 0xA100), "duplicate DIR64"),
    ],
)
def test_relocation_preflight_rejects_malformed_blobs(
        blob: bytes, error: str) -> None:
    sections = [_section(".text", 0x1000, 0x1000)]
    with pytest.raises(ValueError, match=error):
        pe_analyze._validate_relocations(blob, 0x3000, sections)


def test_relocation_preflight_accepts_dir64_and_absolute_padding() -> None:
    sections = [_section(".text", 0x1000, 0x1000)]
    blob = _reloc_block(0x1000, 0xA100, 0)
    pe_analyze._validate_relocations(blob, 0x3000, sections)


def test_relocation_target_in_virtual_hole_is_rejected() -> None:
    sections = [
        _section(".one", 0x1000, 0x1000),
        _section(".two", 0x3000, 0x1000),
    ]
    with pytest.raises(ValueError, match="not contained"):
        pe_analyze._validate_relocations(
            _reloc_block(0x2000, 10 << 12), 0x5000, sections)


def test_exception_table_requires_complete_sorted_runtime_functions() -> None:
    valid = struct.pack("<III", 0x1000, 0x1100, 0x2000)
    assert pe_analyze._validate_pdata(valid, 0x2800, 0x3000) == 1

    with pytest.raises(ValueError, match="multiple"):
        pe_analyze._validate_pdata(valid + b"\0", 0x2800, 0x3000)
    with pytest.raises(ValueError, match="unsorted or overlap"):
        pe_analyze._validate_pdata(valid + valid, 0x2800, 0x3000)
    with pytest.raises(ValueError, match="malformed RUNTIME_FUNCTION"):
        pe_analyze._validate_pdata(
            struct.pack("<III", 0x1100, 0x1000, 0x2000),
            0x2800,
            0x3000,
        )


def test_aslr_contract_rejects_missing_or_contradictory_relocations() -> None:
    with pytest.raises(ValueError, match="DYNAMIC_BASE"):
        pe_analyze._validate_aslr_contract(0, 0x40, b"")
    with pytest.raises(ValueError, match="RELOCS_STRIPPED"):
        pe_analyze._validate_aslr_contract(1, 0, b"relocs")

    pe_analyze._validate_aslr_contract(0, 0x40, b"relocs")
    pe_analyze._validate_aslr_contract(1, 0, b"")


def test_user_mode_contract_rejects_non_gui_cui_and_driver_images() -> None:
    executable = 0x0002
    pe_analyze._validate_user_mode_contract(executable, 0, 2)
    pe_analyze._validate_user_mode_contract(executable, 0, 3)

    with pytest.raises(pe_analyze.PEArchError, match="not an executable"):
        pe_analyze._validate_user_mode_contract(0, 0, 3)
    with pytest.raises(pe_analyze.PEArchError, match="kernel/system"):
        pe_analyze._validate_user_mode_contract(executable | 0x1000, 0, 3)
    with pytest.raises(pe_analyze.PEArchError, match="WDM drivers"):
        pe_analyze._validate_user_mode_contract(executable, 0x2000, 3)
    for subsystem in (1, 10, 11, 12, 13, 16):
        with pytest.raises(pe_analyze.PEArchError, match="GUI/CUI"):
            pe_analyze._validate_user_mode_contract(executable, 0, subsystem)


def test_fixed_output_geometry_rejects_low_alignment_and_shared_pages() -> None:
    rw = 0x40000000 | 0x80000000
    sections = [
        _section(".text", 0x1000, 0x800, characteristics=rw),
        _section(".data", 0x1800, 0x800, characteristics=rw),
    ]
    with pytest.raises(ValueError, match="SectionAlignment"):
        pe_analyze._validate_sections(sections, 0x3000, 0x200)
    with pytest.raises(ValueError, match="page-sharing"):
        pe_analyze._validate_sections(sections, 0x3000, 0x1000)


def test_fixed_output_geometry_accepts_page_separated_sections() -> None:
    rw = 0x40000000 | 0x80000000
    pe_analyze._validate_sections(
        [
            _section(".text", 0x2000, 0x801, characteristics=rw),
            _section(".data", 0x4000, 0x400, characteristics=rw),
        ],
        0x6000,
        0x2000,
    )


def test_assembler_revalidates_geometry_before_layout(monkeypatch, tmp_path) -> None:
    stub_header = container.MAGIC + struct.pack("<I", container.FORMAT_VERSION)
    stub = SimpleNamespace(
        find_packinfo_rva=lambda: 0x2000,
        read_at_rva=lambda _rva, _size: stub_header,
    )
    monkeypatch.setattr(assemble, "_load_stub", lambda *_args, **_kwargs: stub)
    parsed = SimpleNamespace(
        image_base=0x140000000,
        size_of_image=0x3000,
        is_dll=False,
        oep_rva=0x1000,
        section_alignment=0x1000,
        sections=[
            _section(".text", 0x1000, 0x800,
                     characteristics=0x40000000 | 0x80000000),
            _section(".data", 0x1800, 0x800,
                     characteristics=0x40000000 | 0x80000000),
        ],
    )
    output = tmp_path / "must-not-exist.exe"

    with pytest.raises(assemble.AssembleError, match="page-sharing"):
        assemble.build_output_pe(
            parsed, SimpleNamespace(is_dll=False, flags=0), str(output))
    assert not output.exists()


@pytest.mark.parametrize(
    "section,error",
    [
        (_section(".wx", 0x1000, 0x1000, b"\xC3",
                  0x20000000 | 0x40000000 | 0x80000000),
         "writable and executable"),
        (_section(".xzero", 0x1000, 0x1000, b"",
                  0x20000000 | 0x40000000),
         "raw-empty"),
        (_section(".rzero", 0x1000, 0x1000, b"", 0x40000000),
         "raw-empty"),
    ],
)
def test_section_permission_fidelity_rejects_unsupported_sources(
        section, error) -> None:
    with pytest.raises(ValueError, match=error):
        pe_analyze._validate_sections([section], 0x3000, 0x1000)


@pytest.mark.parametrize(
    "section,error",
    [
        (_section(".wx", 0x1000, 0x1000, b"\xC3",
                  0x20000000 | 0x40000000 | 0x80000000),
         "writable and executable"),
        (_section(".xzero", 0x1000, 0x1000, b"",
                  0x20000000 | 0x40000000),
         "raw-empty"),
    ],
)
def test_assembler_permission_rejection_writes_no_output(
        monkeypatch, tmp_path, section, error) -> None:
    stub_header = container.MAGIC + struct.pack("<I", container.FORMAT_VERSION)
    monkeypatch.setattr(
        assemble,
        "_load_stub",
        lambda *_args, **_kwargs: SimpleNamespace(
            find_packinfo_rva=lambda: 0x2000,
            read_at_rva=lambda _rva, _size: stub_header,
        ),
    )
    output = tmp_path / "must-not-exist.exe"
    parsed = SimpleNamespace(
        image_base=0x140000000,
        size_of_image=0x3000,
        is_dll=False,
        oep_rva=0x1000,
        section_alignment=0x1000,
        sections=[section],
    )

    with pytest.raises(assemble.AssembleError, match=error):
        assemble.build_output_pe(
            parsed, SimpleNamespace(is_dll=False, flags=0), str(output))
    assert not output.exists()


def test_native_low_alignment_image_is_rejected_before_packing(tmp_path) -> None:
    compiler = handler_shape_audit.find_msvc()
    if compiler is None:
        pytest.skip("MSVC x64 compiler is unavailable")

    source = tmp_path / "low_alignment.c"
    image = tmp_path / "low_alignment.exe"
    source.write_text(
        "int mainCRTStartup(void) { return 0; }\n",
        encoding="ascii",
    )
    command = compiler.invoke(
        [
            "/nologo", "/O2", "/GS-", "/Zl", str(source),
            f"/Fe:{image}", "/link", "/NOLOGO", "/NODEFAULTLIB",
            "/ENTRY:mainCRTStartup", "/SUBSYSTEM:CONSOLE", "/MACHINE:X64",
            "/DYNAMICBASE:NO", "/FIXED", "/ALIGN:512",
        ],
        work=tmp_path,
    )
    built = subprocess.run(
        command, cwd=tmp_path, capture_output=True, text=True,
        check=False, timeout=60,
    )
    assert built.returncode == 0, built.stdout + built.stderr

    parsed = __import__("lief").parse(str(image))
    assert parsed is not None
    assert int(parsed.optional_header.section_alignment) == 0x200
    with pytest.raises(ValueError, match="SectionAlignment 0x200"):
        pe_analyze.analyze_pe(str(image))
