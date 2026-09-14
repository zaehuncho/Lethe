#include <windows.h>

static volatile LONG g_disable_ok = 0;
static volatile LONG g_thread_notifications = 0;

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        if (DisableThreadLibraryCalls(module))
            InterlockedExchange(&g_disable_ok, 1);
    } else if (reason == DLL_THREAD_ATTACH || reason == DLL_THREAD_DETACH) {
        InterlockedIncrement(&g_thread_notifications);
    }
    return TRUE;
}

__declspec(dllexport) unsigned int tlsfree_status(void)
{
    return g_disable_ok == 1 && g_thread_notifications == 0 ? 1u : 0u;
}
