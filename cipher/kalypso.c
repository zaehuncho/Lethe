/*
 * kalypso.c -- Kalypso core (C). See kalypso.h.
 * Mirror of cipher/kalypso.py; soundness proven bit-exact against RFC 8439.
 */
#include "kalypso.h"

static uint32_t rotl32(uint32_t v, int c)
{
    c &= 31;                 /* future-proof: rotate-by-0/32 would be shift UB */
    if (c == 0) return v;
    return (v << c) | (v >> (32 - c));
}

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* ChaCha quarter-round (proven rotations 16/12/8/7). */
#define QR(x, a, b, c, d)                                    \
    do {                                                     \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 16); \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 12); \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 8);  \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 7);  \
    } while (0)

void kalypso_chacha_block(const uint8_t key[32], uint32_t counter,
                     const uint8_t nonce[12], int rounds,
                     const uint8_t sigma[16], uint8_t out[64])
{
    uint32_t state[16], x[16];
    int i;

    state[0] = rd32le(sigma + 0);
    state[1] = rd32le(sigma + 4);
    state[2] = rd32le(sigma + 8);
    state[3] = rd32le(sigma + 12);
    for (i = 0; i < 8; i++)
        state[4 + i] = rd32le(key + 4 * i);
    state[12] = counter;
    state[13] = rd32le(nonce + 0);
    state[14] = rd32le(nonce + 4);
    state[15] = rd32le(nonce + 8);

    for (i = 0; i < 16; i++)
        x[i] = state[i];

    for (i = 0; i < rounds / 2; i++) {
        /* column round */
        QR(x, 0, 4, 8, 12); QR(x, 1, 5, 9, 13);
        QR(x, 2, 6, 10, 14); QR(x, 3, 7, 11, 15);
        /* diagonal round */
        QR(x, 0, 5, 10, 15); QR(x, 1, 6, 11, 12);
        QR(x, 2, 7, 8, 13); QR(x, 3, 4, 9, 14);
    }

    for (i = 0; i < 16; i++)
        wr32le(out + 4 * i, x[i] + state[i]);
}

void kalypso_crypt(const uint8_t key[32], int rounds, const uint8_t sigma[16],
              const uint8_t word_perm[16], const uint8_t nonce[12],
              uint32_t counter0, const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t blk[64], ks[64];
    uint32_t counter = counter0;
    size_t off = 0;
    int i, use_perm = 0;

    if (word_perm) {
        for (i = 0; i < 16; i++) {
            if (word_perm[i] != (uint8_t)i) { use_perm = 1; break; }
        }
    }

    while (off < len) {
        size_t n = len - off;
        if (n > 64) n = 64;
        kalypso_chacha_block(key, counter, nonce, rounds, sigma, blk);
        if (use_perm) {
            /* reorder the 16 output words per the per-build permutation.
             * Mask each index to 0..15: derive_params always yields a valid
             * permutation, but a hand-supplied word_perm must never read past
             * the 64-byte block (defense-in-depth against a bad caller). */
            for (i = 0; i < 16; i++) {
                uint32_t w = rd32le(blk + 4 * (word_perm[i] & 15));
                wr32le(ks + 4 * i, w);
            }
        } else {
            for (i = 0; i < 64; i++) ks[i] = blk[i];
        }
        for (i = 0; i < (int)n; i++)
            out[off + i] = in[off + i] ^ ks[i];
        off += n;
        counter++;
    }
}

/* ---- optional standalone KAT (compile with -DKALYPSO_KAT_MAIN) --------------- */
#ifdef KALYPSO_KAT_MAIN
#include <stdio.h>
#include <string.h>

static int hexcmp(const uint8_t *got, const char *hex, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%02x", &v);
        if (got[i] != (uint8_t)v) return 0;
    }
    return 1;
}

int main(void)
{
    /* RFC 8439 s2.3.2 block-function known-answer test */
    uint8_t key[32], nonce[12], out[64];
    int i, fails = 0;
    const char *KAT =
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e";

    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
    memset(nonce, 0, 12);
    nonce[3] = 0x09; nonce[7] = 0x4a;

    kalypso_chacha_block(key, 1, nonce, 20, (const uint8_t *)KALYPSO_STD_SIGMA, out);
    if (hexcmp(out, KAT, 64)) {
        printf("PASS  RFC 8439 2.3.2 block KAT\n");
    } else {
        printf("FAIL  RFC 8439 2.3.2 block KAT\n"); fails++;
    }

    /* stream round-trip: decrypt(encrypt(x)) == x */
    {
        uint8_t pt[200], ct[200], rt[200];
        for (i = 0; i < 200; i++) pt[i] = (uint8_t)(i * 7 + 1);
        kalypso_crypt(key, 20, (const uint8_t *)KALYPSO_STD_SIGMA, 0, nonce, 5, pt, ct, 200);
        kalypso_crypt(key, 20, (const uint8_t *)KALYPSO_STD_SIGMA, 0, nonce, 5, ct, rt, 200);
        if (memcmp(pt, rt, 200) == 0 && memcmp(pt, ct, 200) != 0)
            printf("PASS  stream round-trip + actually-encrypts\n");
        else { printf("FAIL  stream round-trip\n"); fails++; }
    }

    /* memguard hot-path shape: rounds=12, canonical sigma, zero nonce/counter,
     * per-page 32B key, IN-PLACE on a 4096B page -> must be a correct involution
     * (encrypt then the identical call decrypts back), and must actually change
     * the buffer. Mirrors mg_xor_page()'s kalypso_crypt() call exactly. */
    {
        uint8_t page[4096], orig[4096], key32[32], nz[12];
        int changed;
        for (i = 0; i < 32; i++) key32[i] = (uint8_t)(i * 3 + 1);
        for (i = 0; i < 12; i++) nz[i] = 0;
        for (i = 0; i < 4096; i++) { page[i] = (uint8_t)(i * 7 + 5); orig[i] = page[i]; }
        kalypso_crypt(key32, 12, (const uint8_t *)KALYPSO_STD_SIGMA, 0, nz, 0, page, page, 4096);
        changed = memcmp(page, orig, 4096) != 0;
        kalypso_crypt(key32, 12, (const uint8_t *)KALYPSO_STD_SIGMA, 0, nz, 0, page, page, 4096);
        if (changed && memcmp(page, orig, 4096) == 0)
            printf("PASS  memguard-shape rounds=12 in-place involution\n");
        else { printf("FAIL  memguard-shape involution\n"); fails++; }
    }

    printf("%s\n", fails ? "SOME TESTS FAILED" : "ALL C KAT TESTS PASSED");
    return fails ? 1 : 0;
}
#endif
