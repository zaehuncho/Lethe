"""Tests for packer/report.py: entropy, section parsing, structural validation."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packer import container, report  # noqa: E402

STUB = ROOT / "stub" / "prebuilt" / "lethe_stub_x64.dll"
_needs_stub = pytest.mark.skipif(not STUB.is_file(), reason="prebuilt stub not present")


def test_entropy_bounds():
    assert report.shannon_entropy(b"") == 0.0
    assert report.shannon_entropy(b"\x00" * 4096) == 0.0
    assert report.shannon_entropy(b"A" * 100) == 0.0
    # every byte value equally often -> exactly 8 bits/byte
    uniform = bytes(range(256)) * 16
    assert report.shannon_entropy(uniform) == pytest.approx(8.0, abs=1e-9)
    # a fair coin over two symbols -> exactly 1 bit/byte
    assert report.shannon_entropy(b"\x00\x01" * 128) == pytest.approx(1.0, abs=1e-9)


@_needs_stub
def test_section_report_on_real_pe():
    secs = report.section_report(str(STUB))
    assert secs, "a real DLL must have sections"
    for s in secs:
        assert 0.0 <= s.entropy <= 8.0
        assert len(s.flags) == 3
    text = next((s for s in secs if s.name.startswith(".text")), None)
    assert text is not None and text.executable


def test_section_report_rejects_non_pe(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a pe at all" * 10)
    with pytest.raises(ValueError):
        report.section_report(str(junk))


def test_validate_rejects_non_pe(tmp_path):
    junk = tmp_path / "x.bin"
    junk.write_bytes(b"\x00" * 500)
    res = report.validate_packed(str(junk))
    assert not res.ok
    assert "not a PE" in res.reason


@_needs_stub
def test_validate_bare_stub_is_not_a_packed_output():
    # The raw stub embeds the magic + format version but section_count == 0,
    # so it must be reported as "not a packed output", never as valid.
    res = report.validate_packed(str(STUB))
    assert not res.ok
    assert res.section_count == 0


@_needs_stub
def test_validate_reports_missing_container(tmp_path):
    # A valid PE with the Lethe magic scrubbed out -> "no Lethe container".
    data = bytearray(STUB.read_bytes())
    idx = data.find(container.MAGIC)
    assert idx >= 0
    data[idx:idx + len(container.MAGIC)] = b"\x00" * len(container.MAGIC)
    scrubbed = tmp_path / "no_container.dll"
    scrubbed.write_bytes(bytes(data))
    res = report.validate_packed(str(scrubbed))
    assert not res.ok
    assert "no Lethe container" in res.reason


@_needs_stub
def test_format_report_smoke():
    txt = report.format_report(str(STUB))
    assert "Sections" in txt and ".text" in txt
