/*
 * daedalus_rolling.h -- runtime decoder for history-keyed self-decrypting Daedalus
 * bytecode. Mirror of daedalus/daedalus_rolling.py (the
 * pack-time encoder + SP5 differential oracle). The primitives here MUST stay
 * bit-exact with that file; test_rolling_bytecode.py::test_primitive_vectors_stable
 * pins the vectors, and dvm_rolling_selftest() below re-checks them in C.
 *
 * v1 scheme: per-basic-block resync. The accumulator is reseeded from
 * (seed, block-leader-offset) at every basic-block leader and chained over the
 * plaintext bytes of the instructions inside the block. One plaintext
 * instruction is reconstructed at a time, immediately before dispatch; nothing
 * behind the PC stays clear. See the .py for the full rationale.
 *
 * Freestanding / no-CRT: uses crypto_sha256 (crypto.h) only; no libc.
 *
 * This header + daedalus_rolling.c are compiled into the stub ONLY when
 * DVM_ROLLING is defined. With it undefined the file is inert and the default
 * build is byte-identical to today.
 */
#ifndef ORION_DAEDALUS_ROLLING_H
#define ORION_DAEDALUS_ROLLING_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DVM_ROLL_MAGIC0 'V'
#define DVM_ROLL_MAGIC1 'R'
#define DVM_ROLL_SEED_LEN 16
#define DVM_ROLL_MAX_INSTR 9   /* push_imm64 = opcode + 8 operand bytes */

/*
 * Runtime rolling-decode context. `ct` is the ciphertext code stream (the wire
 * bytes AFTER any opcode shuffle, then rolling-encrypted). `leaders` is the
 * baked, sorted array of basic-block leader offsets (the one plaintext index
 * the stub needs -- it cannot decode without it).
 */
typedef struct VvmRolling {
    const uint8_t *ct;
    uint32_t       ct_len;
    uint8_t        seed[DVM_ROLL_SEED_LEN];
    const uint8_t *leaders;    /* packed little-endian u32[n_leaders], possibly
                                * unaligned inside the embedded blob -> read
                                * byte-wise */
    uint16_t       n_leaders;
    uint64_t       acc;        /* live basic-block accumulator */
} VvmRolling;

/* Initialize a context over a rolling container's code region. `leaders` points
 * at a packed little-endian u32 array (read byte-wise; no alignment required). */
void dvm_rolling_init(VvmRolling *r, const uint8_t *code_ct, uint32_t ct_len,
                      const uint8_t seed[DVM_ROLL_SEED_LEN],
                      const uint8_t *leaders, uint16_t n_leaders);

/*
 * Reconstruct the one instruction at `pc` into out_plain[0..*out_len-1]
 * (out_plain must be >= DVM_ROLL_MAX_INSTR bytes). Reseeds the accumulator when
 * pc is a leader, then folds this instruction's plaintext so the next fetch in
 * the block chains. Returns 0 on success, -1 on a structural fault (bad opcode
 * or truncation -- e.g. a mid-block start, a byte flip, or the wrong seed),
 * matching daedalus_vm_exec's -1 discipline.
 *
 * *out_len receives the instruction length (1 + operand width).
 */
int dvm_rolling_fetch(VvmRolling *r, uint32_t pc,
                      uint8_t out_plain[DVM_ROLL_MAX_INSTR], uint32_t *out_len);

/* Primitives (exposed for the self-test / future callers). */
uint64_t dvm_roll_resync(const uint8_t seed[DVM_ROLL_SEED_LEN], uint32_t leader);
uint64_t dvm_roll_fold(uint64_t acc, const uint8_t *plain, uint32_t len,
                       uint32_t pc);

/*
 * Compile-time-optional self-check: recomputes the pinned vectors and returns 0
 * iff the C primitives agree bit-exactly with the Python oracle. Call once at
 * stub init under DVM_ROLLING to fail fast on a port regression.
 */
int dvm_rolling_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* ORION_DAEDALUS_ROLLING_H */
