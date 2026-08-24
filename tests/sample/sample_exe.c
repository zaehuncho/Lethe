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
#include <windows.h>

/* __declspec(thread) => the linker emits an IMAGE_TLS_DIRECTORY the packer must
 * preserve and re-initialize per plan runtime step 5. */
__declspec(thread) int g_tls_counter = 100;

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
    /* Import #1: GetTickCount (KERNEL32). Called only to force a genuine import
     * table entry; its value is NON-deterministic so it is never printed. */
    volatile DWORD warm = GetTickCount();
    (void)warm;

    g_tls_counter += 5;          /* touch TLS: 100 -> 105 */

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
