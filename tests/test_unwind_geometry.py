from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("lief")
from packer import pe_analyze  # noqa: E402


IMAGE_SIZE = 0x4000
PDATA_RVA = 0x2800
TEXT_RVA = 0x1000
XDATA_RVA = 0x2000


def _section(name: str, rva: int, raw: bytes):
    return pe_analyze.ParsedSection(name, rva, len(raw), raw, 0)


def _sections(xdata: bytes):
    return [
        _section(".text", TEXT_RVA, b"\x90" * 0x400),
        _section(".xdata", XDATA_RVA, xdata),
    ]


def _runtime(begin: int = TEXT_RVA, end: int = TEXT_RVA + 0x100,
             unwind: int = XDATA_RVA) -> bytes:
    return struct.pack("<III", begin, end, unwind)


def _validate(xdata: bytes, pdata: bytes | None = None) -> int:
    return pe_analyze._validate_pdata(
        pdata or _runtime(), PDATA_RVA, IMAGE_SIZE, _sections(xdata))


def test_accepts_file_backed_v1_v2_and_v3_headers() -> None:
    assert _validate(bytes((1, 0, 0, 0))) == 1
    # v2 short-form UWOP_EPILOG followed by its alignment slot.
    assert _validate(bytes((2, 0, 1, 0, 1, 0x16, 0, 0))) == 1
    assert _validate(bytes((3, 0, 0, 0))) == 1


def test_rejects_unaligned_table_and_unwind_rvas() -> None:
    with pytest.raises(ValueError, match="unaligned directory"):
        pe_analyze._validate_pdata(_runtime(), PDATA_RVA + 1, IMAGE_SIZE)
    with pytest.raises(ValueError, match="unaligned unwind"):
        pe_analyze._validate_pdata(
            _runtime(unwind=XDATA_RVA + 1), PDATA_RVA, IMAGE_SIZE)


def test_rejects_overlapping_runtime_functions() -> None:
    pdata = (_runtime(end=TEXT_RVA + 0x100) +
             _runtime(begin=TEXT_RVA + 0x80, end=TEXT_RVA + 0x180))
    with pytest.raises(ValueError, match="unsorted or overlap"):
        _validate(bytes((1, 0, 0, 0)), pdata)


@pytest.mark.parametrize(
    "xdata,error",
    [
        (b"\x01\x00\x00", "not file-backed"),
        (bytes((0, 0, 0, 0)), "unsupported version"),
        (bytes((1 | (8 << 3), 0, 0, 0)), "reserved flags"),
        (bytes((1 | (4 << 3) | (1 << 3), 0, 0, 0)),
         "CHAININFO cannot carry"),
        # UWOP_ALLOC_LARGE opinfo=1 consumes three slots, not one.
        (bytes((1, 1, 1, 0, 1, 0x11, 0, 0)), "truncated unwind-code"),
        (bytes((1, 0, 1, 0, 0, 0x06, 0, 0)), "invalid UWOP_EPILOG"),
        # v3: one prolog offset, then an incomplete five-byte ALLOC_HUGE WOD.
        (bytes((3, 0, 1, 1, 0, 1)), "truncated WOD"),
    ],
)
def test_rejects_malformed_unwind_headers_and_codes(
        xdata: bytes, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        _validate(xdata)


def test_handler_rva_must_be_present_and_file_backed() -> None:
    handler_header = bytes((1 | (1 << 3), 0, 0, 0))
    with pytest.raises(ValueError, match="unwind handler target"):
        _validate(handler_header + struct.pack("<I", 0x3800))
    assert _validate(handler_header + struct.pack("<I", TEXT_RVA)) == 1


def test_chained_runtime_function_must_be_complete_and_acyclic() -> None:
    chain_header = bytes((1 | (4 << 3), 0, 0, 0))
    with pytest.raises(ValueError, match="chained RUNTIME_FUNCTION"):
        _validate(chain_header + b"\0" * 8)

    self_chain = chain_header + _runtime()
    with pytest.raises(ValueError, match="chained unwind cycle"):
        _validate(self_chain)


def test_v3_epilog_descriptors_and_wod_offsets_are_bounded() -> None:
    # One epilog, no prolog operations, but its descriptor is absent.
    with pytest.raises(ValueError, match="truncated epilog descriptor"):
        _validate(bytes((3, 0, 0, 0x20)))

    # Full epilog descriptor points its WOD list beyond the payload pool.
    payload = bytes((0x08, 0x10, 0, 4, 0, 0, 0, 0x04))
    header = bytes((3, 0, len(payload) // 2, 0x20))
    with pytest.raises(ValueError, match="WOD is outside payload"):
        _validate(header + payload)
