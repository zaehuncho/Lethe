/*
 * Lethe stub -- key_scatter.c
 *
 * Implements key_scatter.h: split the 32-byte runtime AES key into 8 x 4-byte
 * fragments, each XOR-masked with a per-fragment pad and buried at a random
 * offset inside its own page of random noise. The descriptor table (page
 * pointer + offset + pad per fragment) is itself kept XOR-encrypted at rest
 * with a random table key, so a static scan of this module's data does not
 * reveal where the fragments live.
 *
 * Threat model note: get() only reads the (encrypted) global table into a local
 * copy -- it never mutates globals -- so concurrent get() calls from the
 * memguard VEH are safe. init()/migrate()/destroy() mutate globals and are only
 * driven single-threaded by the loader before control reaches the target code.
 *
 * Freestanding / no-CRT context (mirrors crypto.c / pe_loader.c): Win32 +
 * bcrypt + MSVC intrinsics only. No libc, no static writable payload beyond the
 * fixed globals below.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#include "key_scatter.h"
#include "crypto.h"

#include "stub_intrin.h"

#define FRAGMENT_COUNT   8u
#define FRAGMENT_SIZE    4u      /* 8 x 4 = 32 bytes                       */
#define KS_PAGE_MIN      4096u  /* minimum allocation (one OS page)         */
#define KS_PAGE_MAX      65536u /* upper bound — 16 pages at most           */
#define KS_TABLE_KEY_LEN 16u

typedef struct FragDesc {
    uint8_t *page;      /* VirtualAlloc'd page                              */
    uint32_t page_size; /* actual allocation size (varies per fragment)     */
    uint32_t offset;    /* random offset within page where fragment lives  */
    uint32_t xor_pad;   /* XOR encryption pad for this fragment            */
} FragDesc;

static FragDesc     g_frags[FRAGMENT_COUNT];
static uint8_t      g_table_key[KS_TABLE_KEY_LEN];
static volatile LONG g_initialized = 0;

#define KS_TABLE_BYTES (FRAGMENT_COUNT * sizeof(FragDesc))

/* ---- tiny local helpers (no CRT) ---------------------------------------- */

static void ks_zero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    size_t i;
    if (p && n) {
        for (i = 0; i < n; ++i) vp[i] = 0;
    }
}

static void ks_copy(void *dst, const void *src, size_t n)
{
    if (dst && src && n) {
        __movsb((unsigned char *)dst, (const unsigned char *)src, n);
    }
}

static int ks_rand(void *buf, size_t len)
{
    return crypto_csprng(buf, len);
}

static int ks_is_init(void)
{
    return g_initialized != 0;
}

static void ks_table_crypt(FragDesc *tbl)
{
    uint8_t *b = (uint8_t *)tbl;
    size_t i;
    for (i = 0; i < KS_TABLE_BYTES; i++) {
        b[i] = (uint8_t)(b[i] ^ g_table_key[i & (KS_TABLE_KEY_LEN - 1u)]);
    }
}

static void ks_raw_free_all(void)
{
    uint32_t i;
    for (i = 0; i < FRAGMENT_COUNT; i++) {
        if (g_frags[i].page) {
            uint32_t sz = g_frags[i].page_size ? g_frags[i].page_size : KS_PAGE_MIN;
            ks_zero(g_frags[i].page, sz);
            VirtualFree(g_frags[i].page, 0, MEM_RELEASE);
        }
    }
    ks_zero(g_frags, sizeof(g_frags));
    ks_zero(g_table_key, sizeof(g_table_key));
}

/* ---- public API --------------------------------------------------------- */

int key_scatter_init(uint8_t key[32])
{
    uint32_t i, j;

    if (!key) {
        return 1;
    }
    if (ks_is_init()) {
        return 1;
    }

    ks_zero(g_frags, sizeof(g_frags));

    if (ks_rand(g_table_key, KS_TABLE_KEY_LEN)) {
        ks_zero(g_table_key, sizeof(g_table_key));
        return 1;
    }

    for (i = 0; i < FRAGMENT_COUNT; i++) {
        uint8_t *page;
        uint32_t off = 0, pad = 0, alloc_size = 0;

        if (ks_rand(&alloc_size, sizeof(alloc_size))) {
            ks_raw_free_all();
            return 1;
        }
        alloc_size = KS_PAGE_MIN +
                     (alloc_size % (KS_PAGE_MAX - KS_PAGE_MIN + 1u));
        alloc_size = (alloc_size + (KS_PAGE_MIN - 1u)) & ~(KS_PAGE_MIN - 1u);

        page = (uint8_t *)VirtualAlloc(NULL, alloc_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!page) {
            ks_raw_free_all();
            return 1;
        }
        g_frags[i].page = page;
        g_frags[i].page_size = alloc_size;

        if (ks_rand(page, alloc_size)) {
            ks_raw_free_all();
            return 1;
        }
        if (ks_rand(&off, sizeof(off))) {
            ks_raw_free_all();
            return 1;
        }
        off = off % (alloc_size - FRAGMENT_SIZE + 1u);
        if (ks_rand(&pad, sizeof(pad))) {
            ks_raw_free_all();
            return 1;
        }
        for (j = 0; j < FRAGMENT_SIZE; j++) {
            uint8_t kb = key[i * FRAGMENT_SIZE + j];
            uint8_t pb = (uint8_t)((pad >> (8u * j)) & 0xFFu);
            page[off + j] = (uint8_t)(kb ^ pb);
        }
        g_frags[i].offset  = off;
        g_frags[i].xor_pad = pad;
    }

    ks_zero(key, 32);
    ks_table_crypt(g_frags);
    InterlockedExchange(&g_initialized, 1);
    return 0;
}

int key_scatter_get(uint8_t out_key[32])
{
    FragDesc local[FRAGMENT_COUNT];
    uint32_t i, j;

    if (!out_key || !ks_is_init()) {
        return 1;
    }

    ks_copy(local, g_frags, KS_TABLE_BYTES);
    ks_table_crypt(local);

    for (i = 0; i < FRAGMENT_COUNT; i++) {
        volatile const uint8_t *src;
        uint32_t pad = local[i].xor_pad;

        if (!local[i].page) {
            ks_zero(out_key, 32);
            ks_zero(local, sizeof(local));
            return 1;
        }
        src = (volatile const uint8_t *)(local[i].page + local[i].offset);
        for (j = 0; j < FRAGMENT_SIZE; j++) {
            uint8_t pb = (uint8_t)((pad >> (8u * j)) & 0xFFu);
            out_key[i * FRAGMENT_SIZE + j] = (uint8_t)(src[j] ^ pb);
        }
    }

    ks_zero(local, sizeof(local));
    return 0;
}

void key_scatter_migrate(void)
{
    uint8_t tmp[32];

    if (!ks_is_init()) {
        return;
    }
    if (key_scatter_get(tmp) != 0) {
        ks_zero(tmp, sizeof(tmp));
        return;
    }
    key_scatter_destroy();
    (void)key_scatter_init(tmp);
    ks_zero(tmp, sizeof(tmp));
}

void key_scatter_destroy(void)
{
    FragDesc local[FRAGMENT_COUNT];
    uint32_t i;

    if (!ks_is_init()) {
        ks_zero(g_frags, sizeof(g_frags));
        ks_zero(g_table_key, sizeof(g_table_key));
        return;
    }

    ks_copy(local, g_frags, KS_TABLE_BYTES);
    ks_table_crypt(local);
    for (i = 0; i < FRAGMENT_COUNT; i++) {
        if (local[i].page) {
            uint32_t sz = local[i].page_size ? local[i].page_size : KS_PAGE_MIN;
            ks_zero(local[i].page, sz);
            VirtualFree(local[i].page, 0, MEM_RELEASE);
        }
    }

    ks_zero(local, sizeof(local));
    ks_zero(g_frags, sizeof(g_frags));
    ks_zero(g_table_key, sizeof(g_table_key));
    InterlockedExchange(&g_initialized, 0);
}
