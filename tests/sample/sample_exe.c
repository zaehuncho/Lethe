/*
 * sample_exe.c -- Lethe round-trip acceptance target (console EXE).
 *
 * Deliberately compiled AS C++ (cl /TP /EHsc, see build_samples.ps1) so the
 * throw/catch below lowers to real x64 SEH / unwind data (.pdata + .xdata) --
 * that exercises the packer's RtlAddFunctionTable path. The __declspec(thread)
 * global exercises the packer's TLS handling (IMAGE_TLS_DIRECTORY: index, raw
 * data, zero-fill, callback list). Together these cover plan Verification #2's
 * "a __declspec(thread), a C++ throw/catch (to exercise TLS + x64 SEH)".
 *
 * Contract for the harness (roundtrip.ps1):
 *   stdout (exactly):  Lethe sample_exe: tls=105 caught=-1
 *   exit code:         42
 * Both the original and the packed build MUST produce identical stdout + code.
 */
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

/* __declspec(thread) => the linker emits an IMAGE_TLS_DIRECTORY the packer must
 * preserve and re-initialize per plan runtime step 5. */
__declspec(thread) int g_tls_counter = 100;
__declspec(thread) int g_tls_callback_cookie = 7;
__declspec(thread) __declspec(align(64)) unsigned char g_tls_aligned[64];

static volatile LONG g_tls_process_attach_count = 0;
static volatile LONG g_tls_thread_attach_count = 0;
static volatile LONG g_tls_thread_detach_count = 0;
static volatile LONG g_tls_callback_error = 0;

static VOID NTAPI sample_tls_callback(PVOID module, DWORD reason,
                                      PVOID reserved)
{
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        if (g_tls_callback_cookie != 7)
            InterlockedExchange(&g_tls_callback_error, 1);
        g_tls_callback_cookie = 8;
        InterlockedIncrement(&g_tls_process_attach_count);
    } else if (reason == DLL_THREAD_ATTACH) {
        if (g_tls_callback_cookie != 7)
            InterlockedExchange(&g_tls_callback_error, 1);
        g_tls_callback_cookie = 8;
        InterlockedIncrement(&g_tls_thread_attach_count);
    } else if (reason == DLL_THREAD_DETACH) {
        if (g_tls_callback_cookie != 9)
            InterlockedExchange(&g_tls_callback_error, 1);
        InterlockedIncrement(&g_tls_thread_detach_count);
    }
}

#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK const g_sample_tls_callback = sample_tls_callback;
#pragma comment(linker, "/INCLUDE:g_sample_tls_callback")

typedef struct tls_worker_result {
    int counter;
    int callback_cookie;
    int aligned;
} tls_worker_result;

static DWORD WINAPI run_tls_lifecycle_fixture(LPVOID parameter)
{
    tls_worker_result *result = (tls_worker_result *)parameter;
    g_tls_counter += 5;
    result->counter = g_tls_counter;
    result->callback_cookie = g_tls_callback_cookie;
    result->aligned = (((uintptr_t)&g_tls_aligned[0] & 63u) == 0u);
    g_tls_callback_cookie = 9;
    return 0;
}

/* Force a real C++ throw so the optimizer cannot fold the try/catch away. */
static int risky(int n)
{
    if (n < 0) {
        throw n;                 /* unwinds via x64 SEH -> needs restored .pdata */
    }
    return n * 2;
}

int main(void)
{
    tls_worker_result worker_result = {0, 0};
    HANDLE worker;

    /* Import #1: GetTickCount (KERNEL32). Called only to force a genuine import
     * table entry; its value is NON-deterministic so it is never printed. */
    volatile DWORD warm = GetTickCount();
    (void)warm;

    g_tls_counter += 5;          /* touch TLS: 100 -> 105 */

    worker = CreateThread(NULL, 0, run_tls_lifecycle_fixture,
                          &worker_result, 0, NULL);
    if (!worker) {
        printf("Lethe sample_exe: CreateThread failed=%lu\n",
               (unsigned long)GetLastError());
        return 43;
    }
    if (WaitForSingleObject(worker, 5000) != WAIT_OBJECT_0) {
        CloseHandle(worker);
        return 44;
    }
    CloseHandle(worker);
    if (g_tls_callback_error != 0 || g_tls_process_attach_count != 1 ||
        g_tls_thread_attach_count != 1 || g_tls_thread_detach_count != 1 ||
        g_tls_callback_cookie != 8 || worker_result.counter != 105 ||
        worker_result.callback_cookie != 8 || !worker_result.aligned ||
        ((uintptr_t)&g_tls_aligned[0] & 63u) != 0u)
        return 45;

    int caught = 0;
    try {
        int a = risky(3);        /* 6 */
        int b = risky(-1);       /* throws -1 */
        (void)a;
        (void)b;
    } catch (int code) {
        caught = code;           /* -1 */
    }

    /* Import #2: printf (UCRT, dynamic under /MD). Deterministic line the
     * harness byte-compares between original and packed. */
    printf("Lethe sample_exe: tls=%d caught=%d\n", g_tls_counter, caught);

    return 42;                   /* known exit code the harness asserts */
}
