/*
 * sample_dll.c -- Lethe DLL round-trip target (plan Verification #4, §7).
 *
 * Has a DllMain marker, a real TLS callback, and thread-local state exercised
 * from both the loading thread and a worker created after LoadLibrary. This
 * proves the packed DLL dispatches PROCESS_ATTACH once, initializes the new
 * thread before THREAD_ATTACH, and delivers THREAD_DETACH after its work.
 * (per plan §7: the OS runs DllMain to completion before LoadLibrary returns).
 *
 * Compiled as C (cl default for .c). x64 has no name decoration for a cdecl
 * __declspec(dllexport), so the export is visible as "sample_dll_value".
 */
#include <windows.h>
#include <stdint.h>

/* Set by DllMain(DLL_PROCESS_ATTACH); read by the export. If the export sees
 * anything other than this marker, DllMain did not run. */
static volatile LONG g_dllmain_marker = 0;
__declspec(thread) static unsigned int g_tls_counter = 100u;
__declspec(thread) static unsigned int g_tls_callback_cookie = 7u;
__declspec(thread) __declspec(align(64)) static unsigned char g_tls_aligned[64];

static volatile LONG g_tls_process_attach_count = 0;
static volatile LONG g_tls_thread_attach_count = 0;
static volatile LONG g_tls_thread_detach_count = 0;
static volatile LONG g_tls_callback_error = 0;

#define ORION_DLLMAIN_MARKER  0x5A5Au

static VOID NTAPI sample_dll_tls_callback(PVOID module, DWORD reason,
                                          PVOID reserved)
{
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        if (g_tls_callback_cookie != 7u)
            InterlockedExchange(&g_tls_callback_error, 1);
        g_tls_callback_cookie = 8u;
        InterlockedIncrement(&g_tls_process_attach_count);
    } else if (reason == DLL_THREAD_ATTACH) {
        if (g_tls_callback_cookie != 7u)
            InterlockedExchange(&g_tls_callback_error, 1);
        g_tls_callback_cookie = 8u;
        InterlockedIncrement(&g_tls_thread_attach_count);
    } else if (reason == DLL_THREAD_DETACH) {
        if (g_tls_callback_cookie != 9u)
            InterlockedExchange(&g_tls_callback_error, 1);
        InterlockedIncrement(&g_tls_thread_detach_count);
    }
}

#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK const g_sample_dll_tls_callback = sample_dll_tls_callback;
#pragma comment(linker, "/INCLUDE:g_sample_dll_tls_callback")

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
    if (g_tls_callback_cookie != 8u)
        InterlockedExchange(&g_tls_callback_error, 1);
    g_tls_counter += 5u;
    g_tls_callback_cookie = 9u;
    return g_tls_counter;
}

__declspec(dllexport) unsigned int sample_dll_tls_lifecycle_ok(void)
{
    return g_tls_callback_error == 0 &&
           g_tls_process_attach_count == 1 &&
           g_tls_thread_attach_count == 1 &&
           g_tls_thread_detach_count == 1;
}

__declspec(dllexport) unsigned int sample_dll_tls_alignment_ok(void)
{
    return ((uintptr_t)&g_tls_aligned[0] & 63u) == 0u;
}
