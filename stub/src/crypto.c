/*
 * Lethe stub crypto -- pure-C implementations of crypto.h.
 *
 * SHA-256 (FIPS 180-4), HMAC-SHA256, HKDF-SHA256 (RFC 5869), AES-256 (FIPS 197),
 * and AES-256-GCM decrypt (NIST SP 800-38D) are implemented here from scratch so
 * the stub imports NO system crypto (bcrypt.dll) for its unpack path -- there is
 * no BCryptDecrypt / BCryptHash to inline-hook. The only entropy call
 * (crypto_csprng) resolves BCryptGenRandom dynamically at runtime; the name is
 * assembled on the stack so it is not a static import either.
 *
 * Freestanding / no-CRT: byte loops, small fixed stack buffers, xzero/xcopy and
 * the SecureZeroMemory macro only. All key material is volatile-wiped after use.
 */
#include "crypto.h"

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#include "venice_vm.h"
#include "venice_programs.h"

#define LETHE_RNG_SYSTEM_PREFERRED 0x00000002u

static void xzero(void *p, size_t n)
{
    volatile uint8_t *d = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++) d[i] = 0;
}

static void xcopy(uint8_t *dst, const uint8_t *src, size_t n)
{
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
}

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

typedef struct {
    uint32_t st[8];
    uint8_t  buf[64];
    uint64_t total;
    size_t   n;
} sha256_ctx;

static uint32_t ror32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static void sha256_compress(uint32_t st[8], const uint8_t b[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)b[i * 4] << 24) | ((uint32_t)b[i * 4 + 1] << 16) |
               ((uint32_t)b[i * 4 + 2] << 8) | (uint32_t)b[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = st[0], b0 = st[1], c = st[2], d = st[3];
    uint32_t e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint32_t maj = (a & b0) ^ (a & c) ^ (b0 & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b0; b0 = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b0; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
    xzero(w, sizeof(w));
}

static void sha256_init(sha256_ctx *c)
{
    c->st[0] = 0x6a09e667; c->st[1] = 0xbb67ae85;
    c->st[2] = 0x3c6ef372; c->st[3] = 0xa54ff53a;
    c->st[4] = 0x510e527f; c->st[5] = 0x9b05688c;
    c->st[6] = 0x1f83d9ab; c->st[7] = 0x5be0cd19;
    c->total = 0;
    c->n = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *p, size_t len)
{
    c->total += len;
    while (len) {
        size_t take = 64 - c->n;
        if (take > len) take = len;
        xcopy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == 64) { sha256_compress(c->st, c->buf); c->n = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->total * 8;
    c->buf[c->n++] = 0x80;
    if (c->n > 56) {
        while (c->n < 64) c->buf[c->n++] = 0;
        sha256_compress(c->st, c->buf);
        c->n = 0;
    }
    while (c->n < 56) c->buf[c->n++] = 0;
    for (int i = 0; i < 8; i++)
        c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_compress(c->st, c->buf);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c->st[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->st[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->st[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->st[i]);
    }
}

int crypto_sha256(const void *data, size_t len, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)data, len);
    sha256_final(&c, out);
    xzero(&c, sizeof(c));
    return 0;
}

static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    uint8_t k[64], ipad[64], opad[64], inner[32];
    sha256_ctx c;

    xzero(k, sizeof(k));
    if (key_len > 64) {
        if (crypto_sha256(key, key_len, k)) return 1;
    } else {
        xcopy(k, key, key_len);
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, msg_len);
    sha256_final(&c, inner);

    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);

    xzero(k, sizeof(k));
    xzero(ipad, sizeof(ipad));
    xzero(opad, sizeof(opad));
    xzero(inner, sizeof(inner));
    xzero(&c, sizeof(c));
    return 0;
}

int crypto_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len)
{
    if (info_len > 256) return 1;
    if (out_len > 255u * 32) return 1;

    uint8_t prk[32];
    if (hmac_sha256(salt, salt_len, ikm, ikm_len, prk)) return 1;

    uint8_t t[32];
    uint8_t buf[32 + 256 + 1];
    size_t  t_len = 0, done = 0;
    uint8_t counter = 1;

    while (done < out_len) {
        size_t p = 0;
        xcopy(buf + p, t, t_len);       p += t_len;
        xcopy(buf + p, info, info_len); p += info_len;
        buf[p++] = counter;
        if (hmac_sha256(prk, 32, buf, p, t)) {
            xzero(prk, sizeof(prk));
            xzero(t, sizeof(t));
            xzero(buf, sizeof(buf));
            return 1;
        }
        t_len = 32;

        size_t n = (out_len - done < 32) ? (out_len - done) : 32;
        xcopy(out + done, t, n);
        done += n;
        counter++;
    }
    xzero(prk, sizeof(prk));
    xzero(t, sizeof(t));
    xzero(buf, sizeof(buf));
    return 0;
}

static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t AES_RCON[8] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40
};

typedef struct { uint32_t rk[60]; } aes256_ctx;

static uint32_t aes_subword(uint32_t w)
{
    return ((uint32_t)AES_SBOX[(w >> 24) & 0xff] << 24) |
           ((uint32_t)AES_SBOX[(w >> 16) & 0xff] << 16) |
           ((uint32_t)AES_SBOX[(w >> 8) & 0xff] << 8) |
           (uint32_t)AES_SBOX[w & 0xff];
}

static uint32_t aes_rotword(uint32_t w)
{
    return (w << 8) | (w >> 24);
}

static void aes256_key_expand(aes256_ctx *ctx, const uint8_t key[32])
{
    uint32_t *w = ctx->rk;
    for (int i = 0; i < 8; i++)
        w[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
               ((uint32_t)key[4 * i + 2] << 8) | (uint32_t)key[4 * i + 3];
    for (int i = 8; i < 60; i++) {
        uint32_t t = w[i - 1];
        if (i % 8 == 0)
            t = aes_subword(aes_rotword(t)) ^ ((uint32_t)AES_RCON[i / 8] << 24);
        else if (i % 8 == 4)
            t = aes_subword(t);
        w[i] = w[i - 8] ^ t;
    }
}

static uint8_t aes_xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

static void aes_add_round_key(uint8_t s[16], const uint32_t *rk, int round)
{
    for (int c = 0; c < 4; c++) {
        uint32_t w = rk[round * 4 + c];
        s[4 * c + 0] ^= (uint8_t)(w >> 24);
        s[4 * c + 1] ^= (uint8_t)(w >> 16);
        s[4 * c + 2] ^= (uint8_t)(w >> 8);
        s[4 * c + 3] ^= (uint8_t)(w);
    }
}

static void aes_sub_bytes(uint8_t s[16])
{
    for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
}

static void aes_shift_rows(uint8_t s[16])
{
    uint8_t t;
    t = s[1];  s[1] = s[5];  s[5] = s[9];   s[9] = s[13];  s[13] = t;
    t = s[2];  s[2] = s[10]; s[10] = t;     t = s[6];      s[6] = s[14];  s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3];   s[3] = t;
}

static void aes_mix_columns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = s[4 * c + 0], a1 = s[4 * c + 1];
        uint8_t a2 = s[4 * c + 2], a3 = s[4 * c + 3];
        s[4 * c + 0] = (uint8_t)(aes_xtime(a0) ^ (aes_xtime(a1) ^ a1) ^ a2 ^ a3);
        s[4 * c + 1] = (uint8_t)(a0 ^ aes_xtime(a1) ^ (aes_xtime(a2) ^ a2) ^ a3);
        s[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ aes_xtime(a2) ^ (aes_xtime(a3) ^ a3));
        s[4 * c + 3] = (uint8_t)((aes_xtime(a0) ^ a0) ^ a1 ^ a2 ^ aes_xtime(a3));
    }
}

static void aes256_encrypt_block(const aes256_ctx *ctx, const uint8_t in[16],
                                 uint8_t out[16])
{
    uint8_t s[16];
    xcopy(s, in, 16);
    aes_add_round_key(s, ctx->rk, 0);
    for (int round = 1; round < 14; round++) {
        aes_sub_bytes(s);
        aes_shift_rows(s);
        aes_mix_columns(s);
        aes_add_round_key(s, ctx->rk, round);
    }
    aes_sub_bytes(s);
    aes_shift_rows(s);
    aes_add_round_key(s, ctx->rk, 14);
    xcopy(out, s, 16);
    xzero(s, sizeof(s));
}

static void ghash_mul(uint8_t X[16], const uint8_t H[16])
{
    uint8_t Z[16], V[16];
    xzero(Z, 16);
    xcopy(V, H, 16);
    for (int i = 0; i < 128; i++) {
        if ((X[i >> 3] >> (7 - (i & 7))) & 1)
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        uint8_t lsb = V[15] & 1;
        for (int j = 15; j > 0; j--)
            V[j] = (uint8_t)((V[j] >> 1) | (V[j - 1] << 7));
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xe1;
    }
    xcopy(X, Z, 16);
}

static void ghash_block(uint8_t X[16], const uint8_t H[16], const uint8_t blk[16])
{
    for (int i = 0; i < 16; i++) X[i] ^= blk[i];
    ghash_mul(X, H);
}

int crypto_aes256gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t tag[16], uint8_t *out_pt,
                             const void *aad, size_t aad_len)
{
    aes256_ctx aes;
    aes256_key_expand(&aes, key);

    uint8_t H[16], zero[16];
    xzero(zero, 16);
    aes256_encrypt_block(&aes, zero, H);

    uint8_t J0[16];
    xcopy(J0, nonce, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    uint8_t S[16];
    xzero(S, 16);

    const uint8_t *ap = (const uint8_t *)aad;
    size_t i = 0;
    while (i + 16 <= aad_len) { ghash_block(S, H, ap + i); i += 16; }
    if (i < aad_len) {
        uint8_t blk[16];
        xzero(blk, 16);
        xcopy(blk, ap + i, aad_len - i);
        ghash_block(S, H, blk);
    }
    i = 0;
    while (i + 16 <= ct_len) { ghash_block(S, H, ct + i); i += 16; }
    if (i < ct_len) {
        uint8_t blk[16];
        xzero(blk, 16);
        xcopy(blk, ct + i, ct_len - i);
        ghash_block(S, H, blk);
    }

    uint8_t lb[16];
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits  = (uint64_t)ct_len * 8;
    for (int k = 0; k < 8; k++) lb[k]     = (uint8_t)(aad_bits >> (56 - 8 * k));
    for (int k = 0; k < 8; k++) lb[8 + k] = (uint8_t)(ct_bits  >> (56 - 8 * k));
    ghash_block(S, H, lb);

    uint8_t ekj0[16];
    aes256_encrypt_block(&aes, J0, ekj0);

    uint8_t diff = 0;
    for (int k = 0; k < 16; k++) diff |= (uint8_t)((S[k] ^ ekj0[k]) ^ tag[k]);

    uint8_t ctr[16], ks[16];
    int rc = 1;
    if (diff == 0) {
        xcopy(ctr, J0, 16);
        size_t off = 0;
        while (off < ct_len) {
            for (int b = 15; b >= 12; b--) { if (++ctr[b]) break; }
            aes256_encrypt_block(&aes, ctr, ks);
            size_t n = ct_len - off;
            if (n > 16) n = 16;
            for (size_t j = 0; j < n; j++) out_pt[off + j] = ct[off + j] ^ ks[j];
            off += n;
        }
        rc = 0;
    }

    xzero(&aes, sizeof(aes));
    xzero(H, sizeof(H));
    xzero(ekj0, sizeof(ekj0));
    xzero(J0, sizeof(J0));
    xzero(S, sizeof(S));
    xzero(ctr, sizeof(ctr));
    xzero(ks, sizeof(ks));
    return rc;
}

typedef LONG (WINAPI *LETHE_GenRandom_fn)(PVOID, PUCHAR, ULONG, ULONG);

/* Red-team pass 2026-08-06 found that the previous stack-by-byte assembly of
 * "bcrypt.dll" / "BCryptGenRandom" was coalesced by MSVC's optimizer into a
 * memcpy from an .rdata constant -- the plaintext ended up visible in the
 * shipped stub. venice_strings.h's vstr_dec uses a `volatile uint8_t *` write,
 * which the optimizer can't hoist into an .rdata copy: only the XOR-encrypted
 * bytes appear in the shipped image, plaintext lives on the stack transiently
 * and is wiped before the function returns. */
#include "venice_strings.h"
#include "venice_str_data.h"

int crypto_csprng(void *buf, size_t len)
{
    char dll[VSTR_BCRYPT_DLL_LEN + 1];
    char fn[VSTR_BCRYPT_GENRANDOM_LEN + 1];

    vstr_dec(_vs_bcrypt_dll, dll, VSTR_BCRYPT_DLL_LEN,
             VSTR_BCRYPT_DLL_KEY, VSTR_BCRYPT_DLL_MUL);
    vstr_dec(_vs_bcrypt_genrandom, fn, VSTR_BCRYPT_GENRANDOM_LEN,
             VSTR_BCRYPT_GENRANDOM_KEY, VSTR_BCRYPT_GENRANDOM_MUL);

    HMODULE h = LoadLibraryA(dll);
    LETHE_GenRandom_fn gen = h ? (LETHE_GenRandom_fn)GetProcAddress(h, fn) : NULL;

    /* Wipe the decrypted names off the stack before returning, so a live
     * memory dump of the running stub after crypto_csprng finishes doesn't
     * still expose them. */
    vstr_zero(dll, sizeof(dll));
    vstr_zero(fn,  sizeof(fn));

    if (!gen) return 1;
    LONG st = gen(NULL, (PUCHAR)buf, (ULONG)len, LETHE_RNG_SYSTEM_PREFERRED);
    return (st >= 0) ? 0 : 1;
}

int crypto_derive_key(const PackInfo *pi, const void *image_base,
                      uint8_t out_key[32])
{
    uint64_t vm_args[3];
    vm_args[0] = (uint64_t)(uintptr_t)pi;
    vm_args[1] = (uint64_t)(uintptr_t)image_base;
    vm_args[2] = (uint64_t)(uintptr_t)out_key;
    return venice_vm_exec(VVM_PROG_DERIVE_KEY, VVM_PROG_DERIVE_KEY_SIZE,
                          vm_args, 3);
}

static const uint8_t HKDF_INFO_SECTION[] = {
    0x8a,0x3c,0x01,0xf7,0x92,0xb5,0x6d,0xe4,0x11,0x0a,0x7f,0x53,0x2e,0x73
};
#define HKDF_INFO_SECTION_LEN 14
static const uint8_t HKDF_INFO_META[] = {
    0x8a,0x3c,0x01,0xf7,0x92,0xb5,0x6d,0xe4,0x11,0x0a,0x7f,0x53,0x2e,0x6d
};
#define HKDF_INFO_META_LEN    14

int lethe_derive_section_key(const uint8_t master_key[32],
                             const uint8_t salt[16],
                             uint32_t section_rva,
                             uint8_t out_key[32])
{
    uint8_t info[HKDF_INFO_SECTION_LEN + 4];
    xcopy(info, HKDF_INFO_SECTION, HKDF_INFO_SECTION_LEN);
    info[HKDF_INFO_SECTION_LEN + 0] = (uint8_t)(section_rva        & 0xFF);
    info[HKDF_INFO_SECTION_LEN + 1] = (uint8_t)((section_rva >>  8) & 0xFF);
    info[HKDF_INFO_SECTION_LEN + 2] = (uint8_t)((section_rva >> 16) & 0xFF);
    info[HKDF_INFO_SECTION_LEN + 3] = (uint8_t)((section_rva >> 24) & 0xFF);
    int ok = crypto_hkdf_sha256(master_key, 32, salt, 16,
                                info, sizeof(info), out_key, 32);
    SecureZeroMemory(info, sizeof(info));
    return ok;
}

int lethe_derive_meta_key(const uint8_t master_key[32],
                          const uint8_t salt[16],
                          uint8_t out_key[32])
{
    return crypto_hkdf_sha256(master_key, 32, salt, 16,
                              HKDF_INFO_META, HKDF_INFO_META_LEN,
                              out_key, 32);
}

void orion_secure_wipe(void *ptr, size_t len)
{
    SecureZeroMemory(ptr, len);
}
