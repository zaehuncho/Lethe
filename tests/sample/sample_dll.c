/*
 * sample_dll.c -- Lethe DLL round-trip target (plan Verification #4, §7).
 *
 * Has a DllMain that sets an in-image marker on DLL_PROCESS_ATTACH, plus a
 * thread-local counter exercised from both the loading thread and a new worker.
 * This proves the packed DLL's stub DllMain unpacked the image, dispatched the
 * original DllMain, and initialized static TLS for DLL_THREAD_ATTACH before an
 * export runs on that worker.
 * (per plan §7: the OS runs DllMain to completion before LoadLibrary returns).
 *
 * Compiled as C (cl default for .c). x64 has no name decoration for a cdecl
 * __declspec(dllexport), so the export is visible as "sample_dll_value".
 */
#include <windows.h>

/* Set by DllMain(DLL_PROCESS_ATTACH); read by the export. If the export sees
 * anything other than this marker, DllMain did not run. */
static volatile LONG g_dllmain_marker = 0;
__declspec(thread) static unsigned int g_tls_counter = 100u;

#define ORION_DLLMAIN_MARKER  0x5A5Au

BOOL APIENTRY DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)hinst;
    (void)reserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_dllmain_marker = ORION_DLLMAIN_MARKER;
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

/*
 * The single exported function. Returns the known-good value 0xC0FFEE42 only
 * when DllMain has run; otherwise returns 0xDEAD0000 so the host can tell
 * "DllMain never ran" apart from "wrong value".
 */
static unsigned int sample_dll_value_impl(void)
{
    if (g_dllmain_marker != ORION_DLLMAIN_MARKER) {
        return 0xDEAD0000u;      /* DllMain did NOT run */
    }
    return 0xC0FFEE42u;          /* known-good; also proves DllMain ran */
}

/* Keep one absolute function pointer in the executable section. The loader's
 * relocation directory must patch this DIR64 target after decrypting code; the
 * memory-guard path must defer that patch until its first-touch decrypt. */
typedef unsigned int (*sample_value_fn)(void);
#pragma section(".xreloc", execute, read)
__declspec(allocate(".xreloc"))
static sample_value_fn const g_code_relocated_fn = sample_dll_value_impl;

__declspec(dllexport) unsigned int sample_dll_value(void)
{
    return g_code_relocated_fn();
}

/* Each newly attached thread must observe the initializer (100), independently
 * increment it, and return 105. Seeing 110 on the worker would prove that the
 * loader incorrectly shared the loading thread's TLS block. */
__declspec(dllexport) unsigned int sample_dll_tls_value(void)
{
    g_tls_counter += 5u;
    return g_tls_counter;
}
