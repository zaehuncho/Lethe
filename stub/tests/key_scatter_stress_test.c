#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "key_scatter.h"

#define READER_COUNT 8u
#define MIGRATION_COUNT 96u
#define REINIT_COUNT 96u

static const uint8_t g_expected_key[32] = {
    0x03, 0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34,
    0x3b, 0x42, 0x49, 0x50, 0x57, 0x5e, 0x65, 0x6c,
    0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4,
    0xab, 0xb2, 0xb9, 0xc0, 0xc7, 0xce, 0xd5, 0xdc
};

static volatile LONG g_stop = 0;
static volatile LONG g_failed = 0;
static volatile LONG g_successful_reads = 0;
static volatile LONG g_rejected_reads = 0;

int crypto_csprng(void *buffer, size_t length)
{
    if (!buffer || length == 0 || length > ULONG_MAX)
        return 1;
    return BCryptGenRandom(NULL, (PUCHAR)buffer, (ULONG)length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : 1;
}

static int is_all_zero(const uint8_t *buffer, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) {
        if (buffer[i] != 0)
            return 0;
    }
    return 1;
}

static DWORD WINAPI reader_thread(void *unused)
{
    (void)unused;
    while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        uint8_t actual[32];
        int result;

        memset(actual, 0xa5, sizeof(actual));
        result = key_scatter_get(actual);
        if (result == 0) {
            if (memcmp(actual, g_expected_key, sizeof(actual)) != 0) {
                InterlockedExchange(&g_failed, 1);
                return 1;
            }
            InterlockedIncrement(&g_successful_reads);
        } else {
            if (!is_all_zero(actual, sizeof(actual))) {
                InterlockedExchange(&g_failed, 1);
                return 1;
            }
            InterlockedIncrement(&g_rejected_reads);
        }
        SecureZeroMemory(actual, sizeof(actual));
        SwitchToThread();
    }
    return 0;
}

static int initialize_expected_key(void)
{
    uint8_t key[32];
    memcpy(key, g_expected_key, sizeof(key));
    return key_scatter_init(key);
}

int main(void)
{
    HANDLE readers[READER_COUNT];
    uint8_t output[32];
    uint8_t rejected_key[32];
    uint32_t i;
    DWORD wait_result;

    if (initialize_expected_key() != 0)
        return 10;

    for (i = 0; i < READER_COUNT; ++i) {
        readers[i] = CreateThread(NULL, 0, reader_thread, NULL, 0, NULL);
        if (!readers[i]) {
            InterlockedExchange(&g_stop, 1);
            return 11;
        }
    }

    for (i = 0; i < MIGRATION_COUNT && g_failed == 0; ++i) {
        key_scatter_migrate();
        memset(output, 0, sizeof(output));
        if (key_scatter_get(output) != 0 ||
            memcmp(output, g_expected_key, sizeof(output)) != 0) {
            InterlockedExchange(&g_failed, 1);
            break;
        }
    }

    for (i = 0; i < REINIT_COUNT && g_failed == 0; ++i) {
        key_scatter_destroy();
        if (initialize_expected_key() != 0) {
            InterlockedExchange(&g_failed, 1);
            break;
        }
    }

    key_scatter_invalidate();
    memset(output, 0xa5, sizeof(output));
    memcpy(rejected_key, g_expected_key, sizeof(rejected_key));
    if (key_scatter_get(output) == 0 || !is_all_zero(output, sizeof(output)) ||
        key_scatter_init(rejected_key) == 0 ||
        memcmp(rejected_key, g_expected_key, sizeof(rejected_key)) != 0) {
        InterlockedExchange(&g_failed, 1);
    }

    key_scatter_destroy();
    memset(output, 0xa5, sizeof(output));
    if (key_scatter_get(output) == 0 || !is_all_zero(output, sizeof(output)))
        InterlockedExchange(&g_failed, 1);

    InterlockedExchange(&g_stop, 1);
    wait_result = WaitForMultipleObjects(
        READER_COUNT, readers, TRUE, 30000u);
    for (i = 0; i < READER_COUNT; ++i)
        CloseHandle(readers[i]);
    if (wait_result < WAIT_OBJECT_0 ||
        wait_result >= WAIT_OBJECT_0 + READER_COUNT)
        return 12;
    if (g_failed != 0 || g_successful_reads == 0 || g_rejected_reads == 0)
        return 13;

    printf("key scatter concurrency: PASS (%ld success, %ld revoked)\n",
        g_successful_reads, g_rejected_reads);
    return 0;
}
