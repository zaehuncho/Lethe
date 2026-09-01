#include <windows.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <delayimp.h>
#pragma warning(pop)

__declspec(dllimport) unsigned int compat_delay_value(void);

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}

__declspec(dllexport) unsigned int compat_delay_dll_value(void)
{
    return compat_delay_value();
}

__declspec(dllexport) BOOL compat_delay_dll_unload(void)
{
    return __FUnloadDelayLoadedDLL2("compat_dependency.dll");
}
