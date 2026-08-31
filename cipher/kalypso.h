/*
 * kalypso.h -- Kalypso: sound per-build stream cipher (C port).
 *
 * Core is ChaCha20 (proven rotations 16/12/8/7, 20 rounds) -- soundness proven
 * bit-exact against RFC 8439 and the `cryptography` library in
 * tests/test_kalypso.py and the C KAT below.
 *
 * ARCHITECTURE: this is the INNER keyed diffusion layer. AES-256-GCM remains the
 * OUTER authenticated gate. Kalypso never stands alone as the gate.
 *
 * Freestanding: 32-bit add/rotate/xor only. No tables (side-channel friendly),
 * no CRT. Per-build params (sigma, word-perm) come from the builder; the core
 * here takes them as inputs so the stub needs no SHA at cipher time.
 */
#ifndef KALYPSO_H
#define KALYPSO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KALYPSO_STD_SIGMA "expand 32-byte k"   /* 16 bytes, RFC 8439 constant */

/*
 * One 64-byte keystream block (RFC 8439 ChaCha layout).
 *   key[32], nonce[12], counter (u32), rounds (even; 20 = ChaCha20),
 *   sigma[16] (domain constant), out[64].
 */
void kalypso_chacha_block(const uint8_t key[32], uint32_t counter,
                     const uint8_t nonce[12], int rounds,
                     const uint8_t sigma[16], uint8_t out[64]);

/*
 * Stream encrypt/decrypt (symmetric). `word_perm` is a 16-entry permutation of
 * 0..15 applied to each block's output words (pass NULL or identity for
 * canonical ChaCha20). counter0 is the starting block counter.
 */
void kalypso_crypt(const uint8_t key[32], int rounds, const uint8_t sigma[16],
              const uint8_t word_perm[16], const uint8_t nonce[12],
              uint32_t counter0, const uint8_t *in, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KALYPSO_H */
