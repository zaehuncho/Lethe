from __future__ import annotations

import hashlib
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from packer import bytecode_pages as pages


ROOT = Path(__file__).resolve().parents[1]
MASTER_KEY = bytes(range(32))
PROGRAM_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
SALT = bytes.fromhex("f0e0d0c0b0a090807060504030201000")
PROGRAM = bytes((index * 73 + 19) & 0xFF for index in range(777))
PAGED_VM_VALUE = 0x8877665544332211


def _envelope() -> bytes:
    return pages.seal_program(
        PROGRAM,
        MASTER_KEY,
        program_id=PROGRAM_ID,
        page_size=256,
        salt=SALT,
    )


def _changed(blob: bytes, offset: int, value: int | None = None) -> bytes:
    result = bytearray(blob)
    result[offset] = result[offset] ^ 1 if value is None else value
    return bytes(result)


def _paged_vm_program() -> bytes:
    code = (
        b"\x1d\x00\x00"
        + b"\x01" * 250
        + b"\x04"
        + struct.pack("<Q", PAGED_VM_VALUE)
        + b"\x15\x02\x00\x00"
    )
    program = b"\x00\x00" + code
    assert program[255] == 0x04
    assert program[256:264] == struct.pack("<Q", PAGED_VM_VALUE)
    return program


def test_v1_known_answer_and_derived_material_are_stable() -> None:
    envelope = _envelope()
    assert len(envelope) == 1001
    assert hashlib.sha256(envelope).hexdigest() == (
        "5ec4f726a805521d96d9b6a3d7fb0cfa"
        "810e6e5f5f87e7623ece2629998c8287"
    )
    key, nonce = pages.derive_page_key_nonce(
        MASTER_KEY, SALT, PROGRAM_ID, 0
    )
    assert key.hex() == (
        "602b9eae9ccb37ad8f00c0bec05a6452"
        "a78f56f59dd375d8148e1e488abc57c0"
    )
    assert nonce.hex() == "692914317d9e8e2b18c92680"
    meta_key, meta_nonce = pages.derive_metadata_key_nonce(
        MASTER_KEY, SALT, PROGRAM_ID
    )
    assert meta_key.hex() == (
        "9b68e372c9d3be9d8b1e5f4f51a1f7b6"
        "373d1c3fa6965960980a17f4606a59c6"
    )
    assert meta_nonce.hex() == "bc5153ca1d9c7bd7294361e3"


def test_round_trip_crosses_page_boundaries() -> None:
    envelope = _envelope()
    view = pages.parse_envelope(envelope)
    assert view.page_size == 256
    assert view.page_count == 4
    assert [record.plaintext_size for record in view.records] == [
        256, 256, 256, 9
    ]
    assert pages.open_program(envelope, MASTER_KEY) == PROGRAM
    with pages.AuthenticatedPageCache(envelope, MASTER_KEY) as cache:
        assert cache.read(250, 30, MASTER_KEY) == PROGRAM[250:280]
        assert cache.read(255, 514, MASTER_KEY) == PROGRAM[255:769]


def test_page_material_is_unique_per_page_and_program() -> None:
    pairs = {
        pages.derive_page_key_nonce(MASTER_KEY, SALT, PROGRAM_ID, index)
        for index in range(4)
    }
    assert len(pairs) == 4
    other = pages.derive_page_key_nonce(
        MASTER_KEY, SALT, bytes(reversed(PROGRAM_ID)), 0
    )
    assert other not in pairs


def test_cache_wipes_previous_page_and_close_wipes_all_plaintext() -> None:
    envelope = _envelope()
    cache = pages.AuthenticatedPageCache(envelope, MASTER_KEY)
    first = bytes(cache.get_page(0, MASTER_KEY))
    assert first == PROGRAM[:256]
    assert any(cache._page)
    last = bytes(cache.get_page(3, MASTER_KEY))
    assert last == PROGRAM[768:]
    assert cache._page[9:] == bytes(247)
    cache.close()
    assert cache._page == bytes(256)
    assert cache._cached_index is None
    assert cache._cached_size == 0


@pytest.mark.parametrize(
    "mutator",
    [
        lambda blob: _changed(blob, 0),
        lambda blob: _changed(blob, 4, 2),
        lambda blob: _changed(blob, 6, 0),
        lambda blob: _changed(blob, 8, 1),
        lambda blob: _changed(blob, 12, 3),
        lambda blob: _changed(blob, 20, 3),
        lambda blob: _changed(blob, 56, 0),
        lambda blob: _changed(blob, 64),
        lambda blob: _changed(blob, 120, 1),
        lambda blob: blob + b"\0",
    ],
)
def test_noncanonical_envelope_geometry_is_rejected(mutator) -> None:
    with pytest.raises(pages.BytecodePageFormatError):
        pages.parse_envelope(mutator(_envelope()))


@pytest.mark.parametrize("cut", [0, 1, 64, 127, 128, 223, 500, 1000])
def test_truncation_is_rejected_before_page_access(cut: int) -> None:
    with pytest.raises(pages.BytecodePageFormatError):
        pages.parse_envelope(_envelope()[:cut])


def test_record_length_and_offset_must_be_canonical() -> None:
    envelope = _envelope()
    bad_length = bytearray(envelope)
    struct.pack_into("<I", bad_length, pages.HEADER_SIZE, 255)
    with pytest.raises(pages.BytecodePageFormatError, match="record 0"):
        pages.parse_envelope(bad_length)
    bad_offset = bytearray(envelope)
    struct.pack_into("<I", bad_offset, pages.HEADER_SIZE + 4, 225)
    with pytest.raises(pages.BytecodePageFormatError, match="record 0"):
        pages.parse_envelope(bad_offset)


@pytest.mark.parametrize(
    "offset",
    [24, 40, 72, 104, pages.HEADER_SIZE + 8],
)
def test_authenticated_metadata_tamper_is_rejected(offset: int) -> None:
    with pytest.raises(pages.BytecodePageAuthenticationError):
        pages.AuthenticatedPageCache(_changed(_envelope(), offset), MASTER_KEY)


def test_wrong_key_is_indistinguishable_from_metadata_tamper() -> None:
    wrong = bytes([MASTER_KEY[0] ^ 1]) + MASTER_KEY[1:]
    with pytest.raises(
        pages.BytecodePageAuthenticationError,
        match="metadata authentication failed",
    ):
        pages.AuthenticatedPageCache(_envelope(), wrong)


def test_ciphertext_tamper_wipes_cache_and_rejects_page() -> None:
    envelope = _envelope()
    view = pages.parse_envelope(envelope)
    changed = _changed(envelope, view.data_offset + 300)
    cache = pages.AuthenticatedPageCache(changed, MASTER_KEY)
    assert bytes(cache.get_page(0, MASTER_KEY)) == PROGRAM[:256]
    with pytest.raises(
        pages.BytecodePageAuthenticationError,
        match="page 1 authentication failed",
    ):
        cache.get_page(1, MASTER_KEY)
    assert cache._page == bytes(view.page_size)
    assert cache._cached_index is None


def test_page_reads_are_strictly_bounded() -> None:
    cache = pages.AuthenticatedPageCache(_envelope(), MASTER_KEY)
    for offset, size in [(-1, 1), (0, -1), (778, 0), (770, 8)]:
        with pytest.raises(pages.BytecodePageError, match="outside"):
            cache.read(offset, size, MASTER_KEY)
    with pytest.raises(pages.BytecodePageError, match="outside"):
        cache.get_page(4, MASTER_KEY)


@pytest.mark.parametrize("page_size", [0, 128, 257, 8192])
def test_builder_rejects_invalid_page_sizes(page_size: int) -> None:
    with pytest.raises(pages.BytecodePageError, match="page size"):
        pages.seal_program(
            PROGRAM,
            MASTER_KEY,
            program_id=PROGRAM_ID,
            page_size=page_size,
            salt=SALT,
        )


def _visual_studio_available() -> bool:
    if shutil.which("cl.exe"):
        return True
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return False
    result = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


@pytest.mark.skipif(os.name != "nt", reason="the production stub is Windows-only")
def test_native_runtime_matches_python_and_rejects_tamper(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake plus the Visual Studio x64 toolchain are required")

    envelope_path = tmp_path / "program.dvpg"
    plaintext_path = tmp_path / "program.bin"
    envelope_path.write_bytes(_envelope())
    plaintext_path.write_bytes(PROGRAM)

    source_dir = ROOT / "stub/src"
    harness = ROOT / "stub/tests/bytecode_pages_test.c"
    cmake_source = f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_bytecode_pages_native C)
set(CMAKE_C_STANDARD 11)
add_executable(bytecode_pages_test
    "{harness.as_posix()}"
    "{(source_dir / 'bytecode_pages.c').as_posix()}"
    "{(source_dir / 'crypto.c').as_posix()}"
    "{(source_dir / 'daedalus_vm.c').as_posix()}"
)
target_include_directories(bytecode_pages_test PRIVATE "{source_dir.as_posix()}")
target_compile_definitions(bytecode_pages_test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(bytecode_pages_test PRIVATE bcrypt)
if(MSVC)
    target_compile_options(bytecode_pages_test PRIVATE /W4 /WX /O2)
endif()
"""
    (tmp_path / "CMakeLists.txt").write_text(cmake_source, encoding="utf-8")
    build = tmp_path / "build"
    configured = subprocess.run(
        [
            "cmake",
            "-S",
            str(tmp_path),
            "-B",
            str(build),
            "-G",
            "Visual Studio 17 2022",
            "-A",
            "x64",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert configured.returncode == 0, configured.stdout + configured.stderr
    compiled = subprocess.run(
        ["cmake", "--build", str(build), "--config", "Release"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executable = build / "Release/bytecode_pages_test.exe"
    result = subprocess.run(
        [
            str(executable),
            str(envelope_path),
            str(plaintext_path),
            MASTER_KEY.hex(),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "authenticated bytecode page vectors: PASS" in result.stdout


@pytest.mark.skipif(os.name != "nt", reason="the production stub is Windows-only")
def test_native_paged_vm_cross_page_execution_and_tamper(tmp_path: Path) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake plus the Visual Studio x64 toolchain are required")

    program = _paged_vm_program()
    vm_program_id = bytes.fromhex("fedcba98765432100123456789abcdef")
    envelope = pages.seal_program(
        program,
        MASTER_KEY,
        program_id=vm_program_id,
        page_size=256,
        salt=SALT,
    )
    envelope_path = tmp_path / "paged-vm.dvpg"
    envelope_path.write_bytes(envelope)

    source_dir = ROOT / "stub/src"
    harness = ROOT / "stub/tests/daedalus_paged_vm_test.c"
    cmake_source = f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_paged_vm_native C)
set(CMAKE_C_STANDARD 11)
add_executable(daedalus_paged_vm_test
    "{harness.as_posix()}"
    "{(source_dir / 'bytecode_pages.c').as_posix()}"
    "{(source_dir / 'crypto.c').as_posix()}"
    "{(source_dir / 'daedalus_vm.c').as_posix()}"
    "{(source_dir / 'key_scatter.c').as_posix()}"
)
target_include_directories(daedalus_paged_vm_test PRIVATE "{source_dir.as_posix()}")
target_compile_definitions(daedalus_paged_vm_test PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX DVM_PAGED_RUNTIME)
target_link_libraries(daedalus_paged_vm_test PRIVATE bcrypt)
if(MSVC)
    target_compile_options(daedalus_paged_vm_test PRIVATE /W4 /WX /O2)
endif()
"""
    (tmp_path / "CMakeLists.txt").write_text(cmake_source, encoding="utf-8")
    build = tmp_path / "build"
    configured = subprocess.run(
        [
            "cmake",
            "-S",
            str(tmp_path),
            "-B",
            str(build),
            "-G",
            "Visual Studio 17 2022",
            "-A",
            "x64",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert configured.returncode == 0, configured.stdout + configured.stderr
    compiled = subprocess.run(
        ["cmake", "--build", str(build), "--config", "Release"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executable = build / "Release/daedalus_paged_vm_test.exe"
    result = subprocess.run(
        [
            str(executable),
            str(envelope_path),
            MASTER_KEY.hex(),
            vm_program_id.hex(),
            f"{PAGED_VM_VALUE:x}",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "paged VM cross-page execution and tamper vectors: PASS" in result.stdout
