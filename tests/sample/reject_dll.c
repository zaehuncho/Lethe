#include <windows.h>

__declspec(thread) static unsigned int g_reject_tls = 7u;
static HANDLE g_detach_semaphore = NULL;

static VOID NTAPI reject_tls_callback(PVOID module, DWORD reason, PVOID reserved)
{
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        ++g_reject_tls;
}

#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK const g_reject_tls_callback = reject_tls_callback;
#pragma comment(linker, "/INCLUDE:g_reject_tls_callback")

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
    char semaphore_name[128];
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DWORD length = GetEnvironmentVariableA(
            "LETHE_REJECT_SEMAPHORE", semaphore_name,
            (DWORD)sizeof(semaphore_name));
        if (length > 0 && length < (DWORD)sizeof(semaphore_name))
            g_detach_semaphore = OpenSemaphoreA(
                SEMAPHORE_MODIFY_STATE, FALSE, semaphore_name);
        return FALSE;
    }
    if (reason == DLL_PROCESS_DETACH && g_detach_semaphore) {
        ReleaseSemaphore(g_detach_semaphore, 1, NULL);
        CloseHandle(g_detach_semaphore);
        g_detach_semaphore = NULL;
    }
    return TRUE;
}
