/*
 * static_host.c -- verifies that a packed DLL is usable by a native static
 * import consumer.  Windows resolves these imports before the dependency's
 * DllMain runs, which exercises Lethe's pre-entry export-directory snapshot.
 */
#include <windows.h>
#include <stdio.h>

__declspec(dllimport) unsigned int sample_dll_value(void);
__declspec(dllimport) unsigned int sample_dll_tls_value(void);
__declspec(dllimport) unsigned int sample_dll_tls_alignment_ok(void);

int main(void)
{
    unsigned int value = sample_dll_value();
    unsigned int tls_value = sample_dll_tls_value();

    if (value != 0xC0FFEE42u || tls_value != 105u ||
        sample_dll_tls_alignment_ok() != 1u) {
        printf("static_host: FAIL value=0x%08X tls=%u\n", value, tls_value);
        return 1;
    }

    printf("static_host: PASS value=0x%08X tls=%u\n", value, tls_value);
    return 0;
}
