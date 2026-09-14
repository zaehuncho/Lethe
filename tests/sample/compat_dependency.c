#include <windows.h>

BOOL APIENTRY DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}

__declspec(dllexport) unsigned int compat_delay_value(void)
{
    return 0xC0DEC0DEu;
}
