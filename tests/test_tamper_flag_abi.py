"""T5 tamper-monitor parity + wiring test (pure Python; no native toolchain).

Covers the build-time-visible contract for the OPT-IN runtime tamper monitor
(LETHE_FLAG_TAMPER_MONITOR):

  * the flag bit is 0x100, agrees byte-for-byte between ``packer/container.py`` and
    ``stub/src/pack_info.h``, and is DISTINCT (no bit overlap) from every other
    FLAG_*;
  * the container ABI is otherwise unchanged (PackInfo 192 B, SectionDesc 52 B,
    FORMAT_VERSION 2);
  * ``payload.build_payload`` sets the bit iff ``tamper_monitor`` is requested and
    clears it otherwise, and rejects ``is_dll + tamper_monitor`` (fail closed);
  * the orchestrator rejects ``is_dll + tamper_monitor`` up front;
  * ``report``'s structural validator whitelists the bit;
  * the self-integrity CRC contract vector (zlib.crc32) the native monitor must
    reproduce is pinned and matches the C source constants;
  * the ``--tamper-monitor`` CLI flag threads into ``PackOptions``.

Run: ``uv run pytest tests/test_tamper_flag_abi.py -q``
"""
from __future__ import annotations

import inspect
import re
import sys
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import lethe  # noqa: E402
from packer import container, orchestrator, payload, report  # noqa: E402

HEADER_PATH = ROOT / "stub" / "src" / "pack_info.h"
SRC = ROOT / "stub" / "src"

# The self-integrity CRC contract: the native monitor hashes the stub .text with
# mz_crc32 (zlib CRC-32); this vector is the fixed reference both sides reproduce.
CRC_CONTRACT_INPUT = b"LETHE-TAMPERGUARD-CRC32-CONTRACT-V1"
CRC_CONTRACT_VALUE = 0x83048D49


# ---------------------------------------------------------------------------
# tiny C-header parsing helpers (regex-level; the header is stable + simple)
# ---------------------------------------------------------------------------

def _header_text() -> str:
    if not HEADER_PATH.is_file():
        pytest.skip(f"pack_info.h missing at {HEADER_PATH}")
    return HEADER_PATH.read_text(encoding="utf-8", errors="replace")


def _define_int(text: str, name: str) -> int:
    m = re.search(rf"#define\s+{re.escape(name)}\s+([^\s/]+)", text)
    assert m, f"#define {name} not found in pack_info.h"
    return int(m.group(1).rstrip("uUlL"), 0)


def _container_flags() -> dict[str, int]:
    return {
        name: value
        for name, value in vars(container).items()
        if name.startswith("FLAG_") and isinstance(value, int)
    }


# ---------------------------------------------------------------------------
# flag bit: value, header agreement, distinctness
# ---------------------------------------------------------------------------

def test_flag_bit_value_and_header_agreement():
    assert container.FLAG_TAMPER_MONITOR == 0x100
    text = _header_text()
    assert _define_int(text, "LETHE_FLAG_TAMPER_MONITOR") == 0x100
    assert (_define_int(text, "LETHE_FLAG_TAMPER_MONITOR")
            == container.FLAG_TAMPER_MONITOR)
    # single-bit flag, the next free bit after PROCESS_HARDENING (0x80)
    assert container.FLAG_TAMPER_MONITOR == container.FLAG_PROCESS_HARDENING << 1
    assert bin(container.FLAG_TAMPER_MONITOR).count("1") == 1


def test_flag_bit_is_distinct_from_every_other_flag():
    flags = _container_flags()
    assert "FLAG_TAMPER_MONITOR" in flags
    bit = flags["FLAG_TAMPER_MONITOR"]
    for name, value in flags.items():
        if name == "FLAG_TAMPER_MONITOR":
            continue
        assert value != bit, f"{name} duplicates FLAG_TAMPER_MONITOR"
        assert value & bit == 0, f"{name} overlaps FLAG_TAMPER_MONITOR bit"


def test_every_container_flag_matches_the_header():
    """Whole-set parity so a future flag cannot silently diverge from the C side."""
    text = _header_text()
    name_map = {
        "FLAG_HAS_TLS": "LETHE_FLAG_HAS_TLS",
        "FLAG_HAS_EXCEPTIONS": "LETHE_FLAG_HAS_EXCEPTIONS",
        "FLAG_ANTIDEBUG": "LETHE_FLAG_ANTIDEBUG",
        "FLAG_MEMGUARD": "LETHE_FLAG_MEMGUARD",
        "FLAG_PAGED_DVM": "LETHE_FLAG_PAGED_DVM",
        "FLAG_LOAD_CONFIG": "LETHE_FLAG_LOAD_CONFIG",
        "FLAG_DLL_PRELOAD_IAT": "LETHE_FLAG_DLL_PRELOAD_IAT",
        "FLAG_PROCESS_HARDENING": "LETHE_FLAG_PROCESS_HARDENING",
        "FLAG_TAMPER_MONITOR": "LETHE_FLAG_TAMPER_MONITOR",
    }
    for py_name, c_name in name_map.items():
        assert getattr(container, py_name) == _define_int(text, c_name), py_name


# ---------------------------------------------------------------------------
# container ABI invariants must be UNCHANGED (only a new flag bit was added)
# ---------------------------------------------------------------------------

def test_container_abi_is_unchanged():
    assert container.PACKINFO_SIZE == 192
    assert container.SECTIONDESC_SIZE == 52
    assert container.FORMAT_VERSION == 2
    text = _header_text()
    assert _define_int(text, "LETHE_FORMAT_VERSION") == 2
    m_pi = re.search(r"sizeof\(PackInfo\)\s*==\s*(\d+)", text)
    m_sd = re.search(r"sizeof\(SectionDesc\)\s*==\s*(\d+)", text)
    assert m_pi and int(m_pi.group(1)) == 192
    assert m_sd and int(m_sd.group(1)) == 52


def test_packinfo_round_trip_still_192_bytes_with_flag_set():
    pi = container.PackInfo(flags=container.FLAG_TAMPER_MONITOR, section_count=1)
    blob = pi.pack()
    assert len(blob) == 192
    assert container.PackInfo.from_bytes(blob).flags & container.FLAG_TAMPER_MONITOR


# ---------------------------------------------------------------------------
# build_payload: sets / clears the bit per option
# ---------------------------------------------------------------------------

def _minimal_parsed(is_dll: bool = False):
    return SimpleNamespace(
        is_dll=is_dll,
        requires_paged_vm=False,
        sections=[],
        imports=[],
        tls=None,
        pdata_count=0,
        pdata_rva=0,
        reloc_blob=b"",
        image_base=0x140000000,
        size_of_image=0x2000,
        oep_rva=0x1000,
        load_config=None,
        rsrc_rva=0,
        rsrc_bytes=b"",
    )


def test_build_payload_sets_flag_when_requested():
    art = payload.build_payload(_minimal_parsed(), SimpleNamespace(tamper_monitor=True))
    assert art.flags & container.FLAG_TAMPER_MONITOR


def test_build_payload_clears_flag_by_default():
    art = payload.build_payload(_minimal_parsed(), SimpleNamespace())
    assert not (art.flags & container.FLAG_TAMPER_MONITOR)
    art2 = payload.build_payload(
        _minimal_parsed(), SimpleNamespace(tamper_monitor=False))
    assert not (art2.flags & container.FLAG_TAMPER_MONITOR)


def test_build_payload_rejects_dll_plus_tamper_monitor():
    with pytest.raises(ValueError, match="EXE-only"):
        payload.build_payload(
            _minimal_parsed(is_dll=True), SimpleNamespace(tamper_monitor=True))


def test_orchestrator_rejects_dll_plus_tamper_monitor_up_front():
    # The explicit "up front" DLL rejection lives in pack_file beside the
    # memory_guard / process_hardening guards.
    src = inspect.getsource(orchestrator.pack_file)
    assert "eff.tamper_monitor" in src
    assert re.search(r"is_dll\s+and\s+eff\.tamper_monitor", src)
    assert "EXE-only" in src
    # PackOptions carries the opt-in, default OFF, beside memory_guard.
    assert orchestrator.PackOptions().tamper_monitor is False


# ---------------------------------------------------------------------------
# report structural validation whitelists the bit
# ---------------------------------------------------------------------------

def test_report_structural_validator_accepts_the_bit():
    src = inspect.getsource(report._candidate_is_live)
    allowed = src[src.index("allowed_flags"):src.index("if info.flags & ~allowed_flags")]
    assert "container.FLAG_TAMPER_MONITOR" in allowed
    # The whitelist union computed the same way must contain the bit, so a
    # PackInfo carrying it is not rejected by ``info.flags & ~allowed_flags``.
    allowed_flags = (
        container.FLAG_HAS_TLS | container.FLAG_HAS_EXCEPTIONS
        | container.FLAG_ANTIDEBUG | container.FLAG_MEMGUARD
        | container.FLAG_PAGED_DVM | container.FLAG_LOAD_CONFIG
        | container.FLAG_DLL_PRELOAD_IAT | container.FLAG_PROCESS_HARDENING
        | container.FLAG_TAMPER_MONITOR
    )
    assert allowed_flags & container.FLAG_TAMPER_MONITOR
    assert container.FLAG_TAMPER_MONITOR & ~allowed_flags == 0


# ---------------------------------------------------------------------------
# CRC self-integrity contract vector
# ---------------------------------------------------------------------------

def test_crc32_contract_vector_is_pinned():
    # zlib.crc32 IS the algorithm the C monitor uses (mz_crc32, poly 0xEDB88320,
    # init 0). Pin the exact reference value the native self-integrity CRC must
    # reproduce for this input.
    assert (zlib.crc32(CRC_CONTRACT_INPUT) & 0xFFFFFFFF) == CRC_CONTRACT_VALUE
    assert len(CRC_CONTRACT_INPUT) == 35


def test_c_side_pins_the_same_crc_contract_vector():
    tg_h = (SRC / "tamperguard.h").read_text(encoding="utf-8")
    m_in = re.search(r'#define\s+TG_CRC_CONTRACT_INPUT\s+"([^"]*)"', tg_h)
    m_val = re.search(r"#define\s+TG_CRC_CONTRACT_VALUE\s+0x([0-9A-Fa-f]+)u?", tg_h)
    assert m_in, "TG_CRC_CONTRACT_INPUT not found in tamperguard.h"
    assert m_val, "TG_CRC_CONTRACT_VALUE not found in tamperguard.h"
    assert m_in.group(1).encode("ascii") == CRC_CONTRACT_INPUT
    assert int(m_val.group(1), 16) == CRC_CONTRACT_VALUE
    # The monitor uses the zlib CRC (mz_crc32) and enforces the vector at install.
    tg_c = (SRC / "tamperguard.c").read_text(encoding="utf-8")
    assert "mz_crc32" in tg_c
    assert "TG_CRC_CONTRACT_VALUE" in tg_c


# ---------------------------------------------------------------------------
# CLI wiring: --tamper-monitor threads into PackOptions
# ---------------------------------------------------------------------------

def test_cli_tamper_monitor_defaults_off():
    args = lethe.build_parser().parse_args(["input.exe"])
    assert args.tamper_monitor is False
    assert orchestrator.PackOptions().tamper_monitor is False


def test_cli_tamper_monitor_threads_into_pack_options(monkeypatch, tmp_path):
    dummy = tmp_path / "in.exe"
    dummy.write_bytes(b"MZ\x00\x00")
    captured = {}

    def fake_pack_file(input_path, options, progress=None):
        captured["options"] = options
        return SimpleNamespace(
            input_path=input_path, output_path="o.exe", ok=True, error=None,
            original_size=1, packed_size=1, ratio=1.0, elapsed_ms=1.0,
            build_id="a" * 64)

    monkeypatch.setattr(orchestrator, "pack_file", fake_pack_file)

    assert lethe.main([str(dummy), "--tamper-monitor"]) == lethe.EXIT_OK
    assert captured["options"].tamper_monitor is True

    captured.clear()
    assert lethe.main([str(dummy)]) == lethe.EXIT_OK
    assert captured["options"].tamper_monitor is False
