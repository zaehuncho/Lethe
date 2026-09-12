#include <windows.h>

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}

__declspec(dllexport) unsigned int resource_offset_value(void)
{
    return 0x52535243u;
}
