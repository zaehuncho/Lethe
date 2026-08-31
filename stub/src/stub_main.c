#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <stdint.h>

#include "pack_info.h"
#include "pe_loader.h"
#include "stub_hooks.h"
#include "key_scatter.h"
#include "crypto.h"

/*
 * The PackInfo sentinel that the builder scans for by magic bytes.
 * Placed in .data (writable, initialized) so find_packinfo_rva() finds
 * it among writable sections. The builder overwrites the full 192 bytes
 * after locating the magic. volatile prevents the compiler from eliding
 * or reordering accesses.
 */
volatile PackInfo g_packinfo = {
    { 'L','E','T','H','E','0','1','\0' },
    LETHE_FORMAT_VERSION
    /* remaining fields zero-initialized */
};

typedef void  (__cdecl *ExeEntry_t)(void);
typedef BOOL  (WINAPI  *DllMain_t)(HINSTANCE, DWORD, LPVOID);

static volatile int       s_unpacked = 0;
static volatile void     *s_oep      = NULL;
static volatile uintptr_t s_oep_key  = 0;
static volatile uint32_t  s_pdata_rva   = 0;
static volatile uint32_t  s_pdata_count = 0;

__declspec(noinline) static void stash_oep(void *raw)
{
    volatile uintptr_t k = 0;
    crypto_csprng((void *)&k, sizeof(k));
    s_oep_key = k;
    s_oep = (void *)((uintptr_t)raw ^ k);
}

__declspec(noinline) static void invoke_exe_oep(void)
{
    volatile uintptr_t addr = (uintptr_t)s_oep ^ s_oep_key;
    volatile ExeEntry_t fn = (ExeEntry_t)(void *)addr;
    if ((GetCurrentProcessId() | 1) != 0)
        fn();
}

__declspec(noinline) static BOOL invoke_dll_oep(HINSTANCE h, DWORD r,
                                                LPVOID res)
{
    volatile uintptr_t addr = (uintptr_t)s_oep ^ s_oep_key;
    volatile DllMain_t fn = (DllMain_t)(void *)addr;
    if ((GetCurrentProcessId() | 1) != 0)
        return fn(h, r, res);
    return FALSE;
}

__declspec(dllexport)
void __cdecl StubExeEntry(void)
{
    void *base = (void *)GetModuleHandleW(NULL);
    int antidebug_on = (g_packinfo.flags & LETHE_FLAG_ANTIDEBUG) != 0;

    if (antidebug_on) {
        if (antidbg_check_extended(base, g_packinfo.stub_text_rva,
                                   g_packinfo.stub_text_size))
            ExitProcess(0);
    }

    void *oep_tmp = NULL;
    if (pe_loader_run(base, &g_packinfo, &oep_tmp) != 0)
        ExitProcess(1);

    s_pdata_rva   = g_packinfo.pdata_rva;
    s_pdata_count = g_packinfo.pdata_count;
    {
        volatile uint8_t *p = (volatile uint8_t *)&g_packinfo;
        int j; for (j = 0; j < (int)sizeof(g_packinfo); j++) p[j] = 0;
    }
    stash_oep(oep_tmp);

    /* Tripwire: scattered RDTSC timing check before OEP transfer */
    if (antidebug_on)
        antidbg_tripwire_rdtsc();

    invoke_exe_oep();
    ExitProcess(0);
}

__declspec(dllexport)
BOOL WINAPI StubDllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    /* hInst IS the correct base address of the loaded DLL. */
    void *base = (void *)hInst;

    if (reason == DLL_PROCESS_ATTACH) {
        int antidebug_on = (g_packinfo.flags & LETHE_FLAG_ANTIDEBUG) != 0;

        if (antidebug_on) {
            if (antidbg_check_extended(base, g_packinfo.stub_text_rva,
                                       g_packinfo.stub_text_size))
                return FALSE;   /* fail the load, don't kill the host */
        }

        void *oep_tmp = NULL;
        if (pe_loader_run(base, &g_packinfo, &oep_tmp) != 0)
            return FALSE;

        s_pdata_rva   = g_packinfo.pdata_rva;
        s_pdata_count = g_packinfo.pdata_count;
        {
            volatile uint8_t *p = (volatile uint8_t *)&g_packinfo;
            int j; for (j = 0; j < (int)sizeof(g_packinfo); j++) p[j] = 0;
        }
        stash_oep(oep_tmp);
        s_unpacked = 1;

        /* Tripwire: scattered RDTSC timing check before OEP transfer */
        if (antidebug_on)
            antidbg_tripwire_rdtsc();

        if (!oep_tmp)
            return TRUE;   /* no DllMain (entry point 0) — load succeeds */
        return invoke_dll_oep(hInst, reason, reserved);
    }

    if (reason == DLL_PROCESS_DETACH && s_unpacked) {
        BOOL result = TRUE;
        if (s_oep)
            result = invoke_dll_oep(hInst, reason, reserved);
        pe_loader_tls_thread_free();
        memguard_shutdown();
        if (s_pdata_rva && s_pdata_count) {
            RtlDeleteFunctionTable(
                (PRUNTIME_FUNCTION)((uint8_t *)hInst + s_pdata_rva));
        }
        key_scatter_destroy();
        s_unpacked = 0;
        s_oep = NULL;
        s_oep_key = 0;
        return result;
    }

    if (reason == DLL_THREAD_ATTACH && s_unpacked) {
        if (pe_loader_tls_thread_init() != 0)
            return FALSE;
        if (s_oep)
            return invoke_dll_oep(hInst, reason, reserved);
        return TRUE;
    }

    if (reason == DLL_THREAD_DETACH && s_unpacked) {
        BOOL result = TRUE;
        if (s_oep)
            result = invoke_dll_oep(hInst, reason, reserved);
        pe_loader_tls_thread_free();
        return result;
    }

    return TRUE;
}
