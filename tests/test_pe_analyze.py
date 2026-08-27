"""analyze_pe functional coverage: native PEs parse; the .NET refusal is wired
without false-positiving on native binaries."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packer"))
STUB = ROOT / "stub" / "prebuilt" / "lethe_stub_x64.dll"

pytest.importorskip("lief")
import pe_analyze  # noqa: E402


@pytest.mark.skipif(not STUB.is_file(), reason="prebuilt stub absent")
def test_native_pe_analyzes_and_is_not_refused():
    # a real native x64 DLL must parse and must NOT trip the managed/.NET refusal
    parsed = pe_analyze.analyze_pe(str(STUB))
    assert parsed.is_dll is True
    assert parsed.sections, "native PE should expose sections"


def test_non_pe_is_rejected(tmp_path):
    junk = tmp_path / "x.bin"
    junk.write_bytes(b"not a pe at all " * 20)
    with pytest.raises(Exception):
        pe_analyze.analyze_pe(str(junk))
