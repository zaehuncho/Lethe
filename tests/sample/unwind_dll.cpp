#include <windows.h>

static __declspec(noinline) int throw_and_catch(int value)
{
    try {
        throw value + 11;
    } catch (int caught) {
        return caught * 3;
    }
}

extern "C" __declspec(dllexport) unsigned int unwind_value(void)
{
    return (unsigned int)throw_and_catch(13);
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}
