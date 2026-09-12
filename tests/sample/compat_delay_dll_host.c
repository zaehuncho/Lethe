#include <windows.h>
#include <stdio.h>

typedef unsigned int (*value_fn)(void);
typedef BOOL (*unload_fn)(void);

int main(int argc, char **argv)
{
    unsigned int iteration;
    if (argc != 2)
        return 2;
    for (iteration = 0; iteration < 8u; ++iteration) {
        HMODULE module;
        value_fn value;
        unload_fn unload;
        if (GetModuleHandleW(L"compat_dependency.dll") != NULL)
            return 3;
        module = LoadLibraryA(argv[1]);
        if (module == NULL)
            return 4;
        value = (value_fn)(void *)GetProcAddress(
            module, "compat_delay_dll_value");
        unload = (unload_fn)(void *)GetProcAddress(
            module, "compat_delay_dll_unload");
        if (value == NULL || unload == NULL)
            return 5;
        if (GetModuleHandleW(L"compat_dependency.dll") != NULL)
            return 6;
        if (value() != 0xC0DEC0DEu)
            return 7;
        if (GetModuleHandleW(L"compat_dependency.dll") == NULL)
            return 8;
        if (!unload())
            return 9;
        if (GetModuleHandleW(L"compat_dependency.dll") != NULL)
            return 10;
        if (!FreeLibrary(module))
            return 11;
    }
    printf("compat_delay_dll_host: PASS first-call/unload cycles=8\n");
    return 0;
}
