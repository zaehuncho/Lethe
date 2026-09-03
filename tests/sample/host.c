/*
 * host.c -- loads a DLL (original or Lethe-packed), resolves the export,
 * calls it, and asserts both the value and that DllMain ran. This is the
 * consumer side of plan Verification #4 / §7.
 *
 * Usage:  host.exe <path-to-dll>
 * Exit:   0 = PASS; 2 = bad args; 3 = LoadLibrary failed;
 *         4 = GetProcAddress failed; 5 = DllMain did not run;
 *         6 = unexpected export value; 7 = TLS fixture failed.
 *
 * On success prints a deterministic line the harness can also match:
 *   host: PASS sample_dll_value=0xC0FFEE42, DllMain ran
 */
#include <windows.h>
#include <stdio.h>

typedef unsigned int (*sample_fn)(void);

typedef struct tls_worker_ctx {
    sample_fn fn;
    sample_fn alignment_fn;
    unsigned int value;
    unsigned int aligned;
} tls_worker_ctx;

static DWORD WINAPI run_tls_fixture(LPVOID param)
{
    tls_worker_ctx *ctx = (tls_worker_ctx *)param;
    ctx->value = ctx->fn();
    ctx->aligned = ctx->alignment_fn();
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("host: usage: host.exe <dll>\n");
        return 2;
    }

    /* LoadLibrary runs DllMain(DLL_PROCESS_ATTACH) to completion before it
     * returns. For a packed DLL that is the stub DllMain, which unpacks the
     * image and then dispatches the original DllMain. */
    HMODULE h = LoadLibraryA(argv[1]);
    if (!h) {
        printf("host: FAIL LoadLibrary(%s) err=%lu\n", argv[1],
               (unsigned long)GetLastError());
        return 3;
    }

    sample_fn fn = (sample_fn)(void *)GetProcAddress(h, "sample_dll_value");
    sample_fn tls_fn =
        (sample_fn)(void *)GetProcAddress(h, "sample_dll_tls_value");
    sample_fn tls_lifecycle_fn =
        (sample_fn)(void *)GetProcAddress(h, "sample_dll_tls_lifecycle_ok");
    sample_fn tls_alignment_fn =
        (sample_fn)(void *)GetProcAddress(h, "sample_dll_tls_alignment_ok");
    if (!fn || !tls_fn || !tls_lifecycle_fn || !tls_alignment_fn) {
        printf("host: FAIL GetProcAddress(sample export) err=%lu\n",
               (unsigned long)GetLastError());
        FreeLibrary(h);
        return 4;
    }

    unsigned int v = fn();
    unsigned int main_tls = tls_fn();
    tls_worker_ctx tls_ctx = { tls_fn, tls_alignment_fn, 0u, 0u };
    HANDLE worker = CreateThread(NULL, 0, run_tls_fixture, &tls_ctx, 0, NULL);
    int rc;
    if (!worker) {
        printf("host: FAIL CreateThread err=%lu\n", (unsigned long)GetLastError());
        rc = 7;
    } else if (WaitForSingleObject(worker, 5000) != WAIT_OBJECT_0) {
        printf("host: FAIL TLS worker timeout\n");
        CloseHandle(worker);
        /* Do not FreeLibrary while a timed-out worker may still be executing
         * inside the DLL. Returning from main lets process teardown terminate
         * all workers before loader detach notifications run. */
        return 7;
    } else if (v == 0xDEAD0000u) {
        printf("host: FAIL DllMain did not run (export returned 0x%08X)\n", v);
        rc = 5;
    } else if (v != 0xC0FFEE42u) {
        printf("host: FAIL unexpected export value 0x%08X (want 0xC0FFEE42)\n", v);
        rc = 6;
    } else if (main_tls != 105u || tls_ctx.value != 105u ||
               tls_alignment_fn() != 1u || tls_ctx.aligned != 1u) {
        printf("host: FAIL static TLS main=%u worker=%u (want 105/105)\n",
               main_tls, tls_ctx.value);
        rc = 7;
    } else if (tls_lifecycle_fn() != 1u) {
        printf("host: FAIL TLS callback lifecycle was incomplete\n");
        rc = 7;
    } else {
        printf("host: PASS sample_dll_value=0x%08X, DllMain ran, "
               "TLS main=%u worker=%u callbacks=PASS\n",
               v, main_tls, tls_ctx.value);
        rc = 0;
    }

    if (worker)
        CloseHandle(worker);
    FreeLibrary(h);
    return rc;
}
