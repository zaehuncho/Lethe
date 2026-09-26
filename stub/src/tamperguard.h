/*
 * Lethe stub -- tamperguard.h
 *
 * Declarations for the OPT-IN runtime tamper-resistance monitor
 * (LETHE_FLAG_TAMPER_MONITOR). The authoritative, frozen signatures live in
 * stub_hooks.h (the loader<->module boundary); this header re-exposes them for
 * the module's own translation unit and documents the module-local contract.
 *
 * The monitor is EXE-only, default-OFF, and fail-closed. See tamperguard.c for
 * the design (interval, checks, guard-page layout, wipe/termination path).
 *
 * Freestanding / no-CRT: Win32 (kernel32) + bcrypt (via crypto.c) + MSVC
 * intrinsics only. No CRT, no static writable secrets.
 */
#ifndef LETHE_TAMPERGUARD_H
#define LETHE_TAMPERGUARD_H

#include <stdint.h>
#include "pack_info.h"
#include "stub_hooks.h"   /* frozen: tamperguard_install / tamperguard_shutdown */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CRC-32 contract vector.
 *
 * The self-integrity monitor hashes the stub's own .text with mz_crc32() -- the
 * standard zlib CRC-32 (polynomial 0xEDB88320, init 0), byte-for-byte identical
 * to Python's zlib.crc32(). tamperguard_install() runs this vector as a startup
 * self-test and refuses to arm (fail closed) on any divergence, and the pack-time
 * parity test (tests/test_tamper_flag_abi.py) pins the SAME vector against
 * zlib.crc32 so a CRC-implementation drift is caught in CI on both sides.
 *
 *   input  = "LETHE-TAMPERGUARD-CRC32-CONTRACT-V1"   (35 bytes, no NUL)
 *   crc32  = 0x83048D49
 */
#define TG_CRC_CONTRACT_INPUT  "LETHE-TAMPERGUARD-CRC32-CONTRACT-V1"
#define TG_CRC_CONTRACT_VALUE  0x83048D49u

#ifdef __cplusplus
}
#endif

#endif /* LETHE_TAMPERGUARD_H */
