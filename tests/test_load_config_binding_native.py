"""Native verification of authenticated outer load-config bindings."""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from packer import cfg_preservation


ROOT = Path(__file__).resolve().parents[1]
_PREFERRED_BASE = 0x140000000
_SECTION_RVA = 0x1000
_TABLE_RVA = 0x1150
_CHECK_SHADOW_RVA = 0x1160
_CAST_SHADOW_RVA = 0x1168
_MEMCPY_SHADOW_RVA = 0x1170
_PACKED_SIZE = 0x3000


def _visual_studio_available() -> bool:
    if shutil.which("cl.exe"):
        return True
    vswhere = Path(os.environ.get("ProgramFiles(x86)", "")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if not vswhere.is_file():
        return False
    probe = subprocess.run(
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
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _c_bytes(value: bytes) -> str:
    return ", ".join(f"0x{item:02X}" for item in value)


def _binding_fixture() -> tuple[bytes, bytes]:
    data = bytearray(0x180)
    struct.pack_into("<Q", data, 128, _PREFERRED_BASE + _TABLE_RVA)
    struct.pack_into("<Q", data, 136, 1)
    struct.pack_into("<I", data, 144, 0x13000500)
    struct.pack_into("<Q", data, 304, _PREFERRED_BASE + _CAST_SHADOW_RVA)
    struct.pack_into("<Q", data, 312, _PREFERRED_BASE + _MEMCPY_SHADOW_RVA)
    struct.pack_into("<IB", data, _TABLE_RVA - _SECTION_RVA, 0x2000, 0)
    struct.pack_into(
        "<Q", data, _CHECK_SHADOW_RVA - _SECTION_RVA,
        _PREFERRED_BASE + 0x2200)
    struct.pack_into(
        "<Q", data, _CAST_SHADOW_RVA - _SECTION_RVA,
        _PREFERRED_BASE + 0x2300)
    struct.pack_into(
        "<Q", data, _MEMCPY_SHADOW_RVA - _SECTION_RVA,
        0x7FFA123456781234)
    slots = (
        cfg_preservation.RuntimeSlotCopy(
            0x2100, _CHECK_SHADOW_RVA, "GuardCFCheckFunctionPointer"),
        cfg_preservation.RuntimeSlotCopy(
            0x2110, _CAST_SHADOW_RVA,
            "CastGuardOsDeterminedFailureMode"),
        cfg_preservation.RuntimeSlotCopy(
            0x2118, _MEMCPY_SHADOW_RVA, "GuardMemcpyFunctionPointer"),
    )
    targets = (
        cfg_preservation.PlannedCfgTarget(0x2000, b"\0", "source"),
    )
    live = cfg_preservation.LiveLoadConfigImage(
        image_base=_PREFERRED_BASE,
        section_rva=_SECTION_RVA,
        directory_rva=_SECTION_RVA,
        directory_size=0x140,
        data=bytes(data),
        relocation_target_rvas=(
            _SECTION_RVA + 128,
            _SECTION_RVA + 304,
            _SECTION_RVA + 312,
            _CHECK_SHADOW_RVA,
            _CAST_SHADOW_RVA,
        ),
        runtime_slot_copies=slots,
    )
    recipe = cfg_preservation.build_runtime_slot_blob(
        slots,
        targets,
        live_load_config=live,
        dll_characteristics=0x4160,
    )
    return bytes(data), recipe


@pytest.mark.skipif(os.name != "nt", reason="the production loader is Windows-only")
def test_native_outer_load_config_binding_rejects_all_critical_tamper(
    tmp_path: Path,
) -> None:
    if not shutil.which("cmake") or not _visual_studio_available():
        pytest.skip("CMake + the Visual Studio x64 toolchain are required")

    section_data, recipe = _binding_fixture()
    harness = f"""
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>
#include "load_config_binding.h"

#define PACKED_SIZE 0x{_PACKED_SIZE:X}u
#define PE_OFFSET 0x80u
#define OPTIONAL_OFFSET 0x98u
#define SECTION_TABLE_OFFSET 0x188u
#define SECTION_RVA 0x{_SECTION_RVA:X}u

static uint8_t image[PACKED_SIZE];
static const uint8_t section_template[] = {{ {_c_bytes(section_data)} }};
static const uint8_t recipe[] = {{ {_c_bytes(recipe)} }};

int crypto_sha256(const void *data, size_t len, uint8_t out[32])
{{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    NTSTATUS status;
    if (len > 0xFFFFFFFFu)
        return 1;
    status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status >= 0)
        status = BCryptHash(algorithm, NULL, 0, (PUCHAR)data,
                            (ULONG)len, out, 32);
    if (algorithm)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    return status < 0;
}}

static void put16(uint8_t *out, uint16_t value)
{{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
}}

static void put32(uint8_t *out, uint32_t value)
{{
    unsigned int i;
    for (i = 0; i < 4u; ++i)
        out[i] = (uint8_t)(value >> (i * 8u));
}}

static void put64(uint8_t *out, uint64_t value)
{{
    unsigned int i;
    for (i = 0; i < 8u; ++i)
        out[i] = (uint8_t)(value >> (i * 8u));
}}

static uint64_t get64(const uint8_t *in)
{{
    uint64_t value = 0;
    unsigned int i;
    for (i = 0; i < 8u; ++i)
        value |= (uint64_t)in[i] << (i * 8u);
    return value;
}}

static void reset_image(void)
{{
    uint8_t *optional = image + OPTIONAL_OFFSET;
    uint8_t *section = image + SECTION_TABLE_OFFSET;
    memset(image, 0, sizeof(image));
    image[0] = 'M';
    image[1] = 'Z';
    put32(image + 0x3C, PE_OFFSET);
    image[PE_OFFSET] = 'P';
    image[PE_OFFSET + 1u] = 'E';
    put16(image + PE_OFFSET + 4u, 0x8664u);
    put16(image + PE_OFFSET + 6u, 1u);
    put16(image + PE_OFFSET + 20u, 0xF0u);
    put16(optional, 0x20Bu);
    put16(optional + 0x46u, 0x4160u);
    put32(optional + 0x6Cu, 16u);
    put32(optional + 0xC0u, SECTION_RVA);
    put32(optional + 0xC4u, 0x140u);
    memcpy(section, ".lcfg", 5u);
    put32(section + 8u, (uint32_t)sizeof(section_template));
    put32(section + 12u, SECTION_RVA);
    put32(section + 36u, 0x40000040u);
    memcpy(image + SECTION_RVA, section_template, sizeof(section_template));
    put64(image + SECTION_RVA + 128u,
          (uint64_t)(uintptr_t)(image + 0x{_TABLE_RVA:X}u));
    put64(image + SECTION_RVA + 304u,
          (uint64_t)(uintptr_t)(image + 0x{_CAST_SHADOW_RVA:X}u));
    put64(image + SECTION_RVA + 312u,
          (uint64_t)(uintptr_t)(image + 0x{_MEMCPY_SHADOW_RVA:X}u));
    put64(image + 0x{_CHECK_SHADOW_RVA:X}u,
          UINT64_C(0x7FFA111122223333));
    put64(image + 0x{_CAST_SHADOW_RVA:X}u,
          UINT64_C(0x7FFA444455556666));
    put64(image + 0x{_MEMCPY_SHADOW_RVA:X}u,
          UINT64_C(0x7FFA777788889999));
    put64(image + 0x2100u, UINT64_C(0xAAAAAAAAAAAAAAAA));
    put64(image + 0x2110u, UINT64_C(0xBBBBBBBBBBBBBBBB));
    put64(image + 0x2118u, UINT64_C(0xCCCCCCCCCCCCCCCC));
}}

static int accepted(void)
{{
    return lethe_load_config_binding_verify(
        image, (uint32_t)sizeof(image), recipe, (uint32_t)sizeof(recipe)) == 0;
}}

static int rejected_without_writes(uint32_t index,
                                   uint32_t source_rva,
                                   uint32_t shadow_rva)
{{
    uint8_t forged[sizeof(recipe)];
    uint8_t before[sizeof(image)];
    uint32_t entry_offset = 80u + index * 8u;
    reset_image();
    memcpy(forged, recipe, sizeof(forged));
    put32(forged + entry_offset, source_rva);
    put32(forged + entry_offset + 4u, shadow_rva);
    memcpy(before, image, sizeof(before));
    if (lethe_load_config_slots_restore_verified(
            image, 0x2800u, PACKED_SIZE,
            forged, (uint32_t)sizeof(forged)) == 0)
        return 0;
    return memcmp(image, before, sizeof(image)) == 0;
}}

int main(void)
{{
    reset_image();
    if (!accepted()) return 10;
    if (lethe_load_config_slots_restore_verified(
            image, 0x2800u, PACKED_SIZE,
            recipe, (uint32_t)sizeof(recipe)) != 0) return 11;
    if (get64(image + 0x2100u) != UINT64_C(0x7FFA111122223333)) return 12;
    if (get64(image + 0x2110u) != UINT64_C(0x7FFA444455556666)) return 13;
    if (get64(image + 0x2118u) != UINT64_C(0x7FFA777788889999)) return 14;
    image[0x{_MEMCPY_SHADOW_RVA:X}u] ^= 0x5Au;
    if (!accepted()) return 15;

    if (!rejected_without_writes(2u, 0x2800u,
                                 0x{_MEMCPY_SHADOW_RVA:X}u)) return 30;
    if (!rejected_without_writes(2u, 0x2118u, PACKED_SIZE)) return 31;
    if (!rejected_without_writes(2u, 0x2100u,
                                 0x{_MEMCPY_SHADOW_RVA:X}u)) return 32;
    if (!rejected_without_writes(2u, 0x2118u,
                                 0x{_CHECK_SHADOW_RVA:X}u)) return 33;
    if (!rejected_without_writes(2u, 0x{_CHECK_SHADOW_RVA:X}u,
                                 0x{_MEMCPY_SHADOW_RVA:X}u)) return 34;
    if (!rejected_without_writes(2u, 0x2118u, 0x2100u)) return 35;
    if (!rejected_without_writes(2u, 0x2118u, 0x2118u)) return 36;

    reset_image();
    image[SECTION_RVA + 144u] ^= 1u;
    if (accepted()) return 20;
    reset_image();
    image[SECTION_RVA + 128u] ^= 1u;
    if (accepted()) return 21;
    reset_image();
    image[0x{_TABLE_RVA:X}u] ^= 1u;
    if (accepted()) return 22;
    reset_image();
    image[OPTIONAL_OFFSET + 0xC0u] ^= 1u;
    if (accepted()) return 23;
    reset_image();
    image[OPTIONAL_OFFSET + 0xC4u] ^= 1u;
    if (accepted()) return 24;
    reset_image();
    image[OPTIONAL_OFFSET + 0x46u] ^= 1u;
    if (accepted()) return 25;
    reset_image();
    image[SECTION_TABLE_OFFSET + 36u] ^= 1u;
    if (accepted()) return 26;
    return 0;
}}
"""
    (tmp_path / "harness.c").write_text(harness, encoding="utf-8")
    module = (ROOT / "stub/src/load_config_binding.c").as_posix()
    include = (ROOT / "stub/src").as_posix()
    (tmp_path / "CMakeLists.txt").write_text(
        f"""
cmake_minimum_required(VERSION 3.20)
project(lethe_load_config_binding_native C)
add_executable(load_config_binding harness.c "{module}")
target_include_directories(load_config_binding PRIVATE "{include}")
target_compile_definitions(load_config_binding PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(load_config_binding PRIVATE /W4 /WX /O2)
target_link_libraries(load_config_binding PRIVATE bcrypt)
""".lstrip(),
        encoding="utf-8",
    )
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
    ran = subprocess.run(
        [str(build / "Release/load_config_binding.exe")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ran.returncode == 0, ran.stdout + ran.stderr
