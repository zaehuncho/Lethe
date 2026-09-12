/*
 * Lethe stub -- key_scatter.c
 *
 * The scattered key is protected by a process-local SRW lock. Readers hold a
 * shared lease for the complete descriptor-copy/page-read interval; migration,
 * revocation, and destruction hold the exclusive lease. State is published as
 * unavailable before any backing page is wiped or released.
 *
 * Freestanding / no-CRT: Win32 + crypto_csprng + MSVC intrinsics only.
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
#define FRAGMENT_SIZE    4u
#define KS_PAGE_MIN      4096u
#define KS_PAGE_MAX      65536u
#define KS_TABLE_KEY_LEN 16u

#define KS_STATE_EMPTY   0
#define KS_STATE_READY   1
#define KS_STATE_REVOKED 2

typedef struct FragDesc {
    uint8_t *page;
    uint32_t page_size;
    uint32_t offset;
    uint32_t xor_pad;
    uint32_t locked;
} FragDesc;

#define KS_TABLE_BYTES (FRAGMENT_COUNT * sizeof(FragDesc))

static SRWLOCK       g_key_lock = SRWLOCK_INIT;
static FragDesc      g_frags[FRAGMENT_COUNT];
static uint8_t       g_table_key[KS_TABLE_KEY_LEN];
static volatile LONG g_state = KS_STATE_EMPTY;

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

static LONG ks_state(void)
{
    return InterlockedCompareExchange(&g_state, KS_STATE_EMPTY, KS_STATE_EMPTY);
}

static void ks_table_crypt(FragDesc *table,
                           const uint8_t table_key[KS_TABLE_KEY_LEN])
{
    uint8_t *bytes = (uint8_t *)table;
    size_t i;
    for (i = 0; i < KS_TABLE_BYTES; ++i) {
        bytes[i] = (uint8_t)(bytes[i] ^
            table_key[i & (KS_TABLE_KEY_LEN - 1u)]);
    }
}

static void ks_free_plain(FragDesc table[FRAGMENT_COUNT])
{
    uint32_t i;
    for (i = 0; i < FRAGMENT_COUNT; ++i) {
        if (table[i].page) {
            uint32_t size = table[i].page_size;
            if (size >= KS_PAGE_MIN && size <= KS_PAGE_MAX) {
                ks_zero(table[i].page, size);
            }
            if (table[i].locked && table[i].page_size >= FRAGMENT_SIZE &&
                table[i].offset <= table[i].page_size - FRAGMENT_SIZE) {
                VirtualUnlock(table[i].page + table[i].offset, FRAGMENT_SIZE);
            }
            VirtualFree(table[i].page, 0, MEM_RELEASE);
        }
    }
    ks_zero(table, KS_TABLE_BYTES);
}

static int ks_build_encrypted(const uint8_t key[32],
                              FragDesc table[FRAGMENT_COUNT],
                              uint8_t table_key[KS_TABLE_KEY_LEN])
{
    uint32_t i, j;

    ks_zero(table, KS_TABLE_BYTES);
    ks_zero(table_key, KS_TABLE_KEY_LEN);
    if (ks_rand(table_key, KS_TABLE_KEY_LEN) != 0) {
        return 1;
    }

    for (i = 0; i < FRAGMENT_COUNT; ++i) {
        uint8_t *page;
        uint32_t offset = 0;
        uint32_t pad = 0;
        uint32_t allocation_size = 0;

        if (ks_rand(&allocation_size, sizeof(allocation_size)) != 0) {
            ks_free_plain(table);
            ks_zero(table_key, KS_TABLE_KEY_LEN);
            return 1;
        }
        allocation_size = KS_PAGE_MIN +
            (allocation_size % (KS_PAGE_MAX - KS_PAGE_MIN + 1u));
        allocation_size = (allocation_size + (KS_PAGE_MIN - 1u)) &
            ~(KS_PAGE_MIN - 1u);

        page = (uint8_t *)VirtualAlloc(NULL, allocation_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!page) {
            ks_free_plain(table);
            ks_zero(table_key, KS_TABLE_KEY_LEN);
            return 1;
        }
        table[i].page = page;
        table[i].page_size = allocation_size;

        if (ks_rand(page, allocation_size) != 0 ||
            ks_rand(&offset, sizeof(offset)) != 0 ||
            ks_rand(&pad, sizeof(pad)) != 0) {
            ks_free_plain(table);
            ks_zero(table_key, KS_TABLE_KEY_LEN);
            return 1;
        }
        offset %= allocation_size - FRAGMENT_SIZE + 1u;
        for (j = 0; j < FRAGMENT_SIZE; ++j) {
            uint8_t key_byte = key[i * FRAGMENT_SIZE + j];
            uint8_t pad_byte = (uint8_t)((pad >> (8u * j)) & 0xFFu);
            page[offset + j] = (uint8_t)(key_byte ^ pad_byte);
        }
        table[i].offset = offset;
        table[i].xor_pad = pad;
        /* Only the one or two hardware pages containing the fragment need to
           be resident. Lock before the descriptor can ever be published. */
        if (!VirtualLock(page + offset, FRAGMENT_SIZE)) {
            ks_free_plain(table);
            ks_zero(table_key, KS_TABLE_KEY_LEN);
            return 1;
        }
        table[i].locked = 1u;
    }

    ks_table_crypt(table, table_key);
    return 0;
}

static int ks_snapshot_plain_locked(FragDesc local[FRAGMENT_COUNT])
{
    uint32_t i;

    ks_copy(local, g_frags, KS_TABLE_BYTES);
    ks_table_crypt(local, g_table_key);
    for (i = 0; i < FRAGMENT_COUNT; ++i) {
        if (!local[i].page ||
            local[i].page_size < KS_PAGE_MIN ||
            local[i].page_size > KS_PAGE_MAX ||
            (local[i].page_size & (KS_PAGE_MIN - 1u)) != 0 ||
            local[i].offset > local[i].page_size - FRAGMENT_SIZE ||
            local[i].locked != 1u) {
            ks_zero(local, KS_TABLE_BYTES);
            return 1;
        }
    }
    return 0;
}

static int ks_read_locked(uint8_t out_key[32])
{
    FragDesc local[FRAGMENT_COUNT];
    uint32_t i, j;

    if (ks_snapshot_plain_locked(local) != 0) {
        ks_zero(out_key, 32u);
        return 1;
    }
    for (i = 0; i < FRAGMENT_COUNT; ++i) {
        volatile const uint8_t *source = local[i].page + local[i].offset;
        uint32_t pad = local[i].xor_pad;
        for (j = 0; j < FRAGMENT_SIZE; ++j) {
            uint8_t pad_byte = (uint8_t)((pad >> (8u * j)) & 0xFFu);
            out_key[i * FRAGMENT_SIZE + j] =
                (uint8_t)(source[j] ^ pad_byte);
        }
    }
    ks_zero(local, KS_TABLE_BYTES);
    return 0;
}

static void ks_release_ready_locked(LONG next_state)
{
    FragDesc local[FRAGMENT_COUNT];

    ks_copy(local, g_frags, KS_TABLE_BYTES);
    ks_table_crypt(local, g_table_key);

    /* Publish unavailability while every prior reader is excluded. */
    InterlockedExchange(&g_state, next_state);
    ks_zero(g_frags, KS_TABLE_BYTES);
    ks_zero(g_table_key, KS_TABLE_KEY_LEN);
    ks_free_plain(local);
}

int key_scatter_init(uint8_t key[32])
{
    FragDesc new_table[FRAGMENT_COUNT];
    uint8_t new_table_key[KS_TABLE_KEY_LEN];
    int result = 1;

    if (!key) {
        return 1;
    }

    ks_zero(new_table, sizeof(new_table));
    ks_zero(new_table_key, sizeof(new_table_key));

    AcquireSRWLockExclusive(&g_key_lock);
    if (ks_state() == KS_STATE_EMPTY &&
        ks_build_encrypted(key, new_table, new_table_key) == 0) {
        ks_copy(g_frags, new_table, KS_TABLE_BYTES);
        ks_copy(g_table_key, new_table_key, KS_TABLE_KEY_LEN);
        InterlockedExchange(&g_state, KS_STATE_READY);
        ks_zero(key, 32u);
        result = 0;
    }
    ks_zero(new_table, KS_TABLE_BYTES);
    ks_zero(new_table_key, KS_TABLE_KEY_LEN);
    ReleaseSRWLockExclusive(&g_key_lock);
    return result;
}

int key_scatter_get(uint8_t out_key[32])
{
    int result;

    if (!out_key) {
        return 1;
    }
    AcquireSRWLockShared(&g_key_lock);
    if (ks_state() != KS_STATE_READY) {
        ks_zero(out_key, 32u);
        result = 1;
    } else {
        result = ks_read_locked(out_key);
    }
    ReleaseSRWLockShared(&g_key_lock);
    return result;
}

void key_scatter_migrate(void)
{
    uint8_t key[32];
    FragDesc old_table[FRAGMENT_COUNT];
    FragDesc new_table[FRAGMENT_COUNT];
    uint8_t new_table_key[KS_TABLE_KEY_LEN];
    int new_table_built = 0;
    int committed = 0;

    ks_zero(key, sizeof(key));
    ks_zero(old_table, sizeof(old_table));
    ks_zero(new_table, sizeof(new_table));
    ks_zero(new_table_key, sizeof(new_table_key));

    AcquireSRWLockExclusive(&g_key_lock);
    if (ks_state() != KS_STATE_READY || ks_read_locked(key) != 0)
        goto migrate_done;
    if (ks_build_encrypted(key, new_table, new_table_key) != 0)
        goto migrate_done;
    new_table_built = 1;
    if (ks_snapshot_plain_locked(old_table) != 0)
        goto migrate_done;

    InterlockedExchange(&g_state, KS_STATE_EMPTY);
    ks_zero(g_frags, KS_TABLE_BYTES);
    ks_zero(g_table_key, KS_TABLE_KEY_LEN);
    ks_copy(g_frags, new_table, KS_TABLE_BYTES);
    ks_copy(g_table_key, new_table_key, KS_TABLE_KEY_LEN);
    ks_free_plain(old_table);
    InterlockedExchange(&g_state, KS_STATE_READY);
    committed = 1;

migrate_done:
    ReleaseSRWLockExclusive(&g_key_lock);

    ks_zero(key, sizeof(key));
    if (new_table_built && !committed) {
        ks_table_crypt(new_table, new_table_key);
        ks_free_plain(new_table);
    }
    ks_zero(new_table, sizeof(new_table));
    ks_zero(new_table_key, sizeof(new_table_key));
}

void key_scatter_destroy(void)
{
    LONG state;

    AcquireSRWLockExclusive(&g_key_lock);
    state = ks_state();
    if (state == KS_STATE_READY) {
        ks_release_ready_locked(KS_STATE_EMPTY);
    } else {
        ks_zero(g_frags, KS_TABLE_BYTES);
        ks_zero(g_table_key, KS_TABLE_KEY_LEN);
    }
    ReleaseSRWLockExclusive(&g_key_lock);
}

void key_scatter_invalidate(void)
{
    AcquireSRWLockExclusive(&g_key_lock);
    if (ks_state() == KS_STATE_READY) {
        ks_release_ready_locked(KS_STATE_REVOKED);
    } else {
        InterlockedExchange(&g_state, KS_STATE_REVOKED);
        ks_zero(g_frags, KS_TABLE_BYTES);
        ks_zero(g_table_key, KS_TABLE_KEY_LEN);
    }
    ReleaseSRWLockExclusive(&g_key_lock);
}
