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
#define DVM_ROLL_MAGIC1_V2 'S'  /* v2 container is 'VS' (v1 stays 'VR')        */
#define DVM_ROLL_SEED_LEN 16
#define DVM_ROLL_MAX_INSTR 9   /* push_imm64 = opcode + 8 operand bytes */

/* v2 compile cap on basic-block leaders (= chain slots). A container with more
 * leaders than this fails closed at init rather than truncating the chain. */
#define DVM_ROLL_MAX_LEADERS 128u

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
#ifdef DVM_ROLLING_V2
    /* v2 whole-program chaining state. Purely additive: with DVM_ROLLING_V2
     * undefined this struct (and its layout) is byte-identical to v1. */
    int            v2;                          /* 1 => 'VS' chained container   */
    uint8_t        whiten[DVM_ROLL_SEED_LEN];   /* effective seed = seed ^ whiten*/
    uint64_t       chain[DVM_ROLL_MAX_LEADERS]; /* per-leader chain (over CT)    */
#endif
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

#ifdef DVM_ROLLING_V2
/*
 * v2 primitives (bit-exact mirror of daedalus_rolling.py chain_digest / resync2).
 *   dvm_roll_chain(seed, prev, ct_block, len): domain tag 'C'. Byte-loop-folds
 *     the ciphertext block into a 64-bit accumulator seeded with prev_chain, then
 *     binds it with one SHA256(seed ‖ 'C' ‖ u64le(prev) ‖ u64le(fold_acc)).
 *   dvm_roll_resync2(eff_seed, leader, chain): v1 resync plus the chain, i.e.
 *     u64le(SHA256(eff ‖ 'R' ‖ u32le(leader) ‖ u64le(chain))[0:8]). `eff_seed`
 *     is the effective seed (seed XOR whiten).
 */
uint64_t dvm_roll_chain(const uint8_t seed[DVM_ROLL_SEED_LEN],
                        uint64_t prev_chain,
                        const uint8_t *ct_block, uint32_t block_len);
uint64_t dvm_roll_resync2(const uint8_t seed[DVM_ROLL_SEED_LEN],
                          uint32_t leader, uint64_t chain);

/*
 * Initialize a v2 (chained) context over a 'VS' container's code region. Computes
 * the effective seed (seed XOR whiten) and precomputes the whole-program chain
 * from the ciphertext + leaders WITHOUT decoding. Returns 0 on success, -1 on a
 * structural fault (n_leaders over DVM_ROLL_MAX_LEADERS). `whiten` is 16 bytes
 * (dvm_prepare passes a zero whiten for embedded programs).
 */
int dvm_rolling_init_v2(VvmRolling *r, const uint8_t *code_ct, uint32_t ct_len,
                        const uint8_t seed[DVM_ROLL_SEED_LEN],
                        const uint8_t whiten[DVM_ROLL_SEED_LEN],
                        const uint8_t *leaders, uint16_t n_leaders);

/* v2 counterpart of dvm_rolling_fetch: reseeds a leader from resync2(eff_seed,
 * pc, chain[leader_index]) so a ciphertext tamper avalanches across every later
 * block. Same -1 fail-closed discipline as dvm_rolling_fetch. */
int dvm_rolling_fetch_v2(VvmRolling *r, uint32_t pc,
                         uint8_t out_plain[DVM_ROLL_MAX_INSTR],
                         uint32_t *out_len);
#endif /* DVM_ROLLING_V2 */

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
