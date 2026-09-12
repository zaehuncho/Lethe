from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOADER = (ROOT / "stub" / "src" / "pe_loader.c").read_text(encoding="utf-8")


def test_native_relocation_parser_is_fail_closed() -> None:
    function = re.search(
        r"static int apply_relocs\(.*?^}\n",
        LOADER,
        re.MULTILINE | re.DOTALL,
    )
    assert function
    source = function.group(0)

    assert "if (size - pos < 8)" in source
    assert "(page_rva & 0xFFFu) != 0" in source
    assert "(block_size & 3u) != 0" in source
    assert re.search(r"target_off \+ 8 > image_size\)\s*return 1", source)
    assert "else if (type != RELOC_ABSOLUTE)" in source


def test_native_relocation_addition_checks_both_overflow_directions() -> None:
    assert "value > UINT64_MAX - add" in LOADER
    assert "value < subtract" in LOADER


def test_nonzero_delta_without_original_relocations_fails() -> None:
    assert re.search(
        r"reloc_delta != 0 && cpi->relocs_size == 0\)\s*goto fail",
        LOADER,
    )


def test_relocation_blob_is_parsed_even_when_delta_is_zero() -> None:
    relocation_stage = re.search(
        r"/\* 7\. apply base relocations \*/(.*?)/\* Tripwire:",
        LOADER,
        re.DOTALL,
    )
    assert relocation_stage
    source = relocation_stage.group(1)
    assert "cpi->relocs_size > 0 &&" in source
    assert "apply_relocs(" in source
    assert "if (reloc_delta != 0)" not in source
