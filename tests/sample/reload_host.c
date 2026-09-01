/* Repeatedly load, call, and unload a DLL in one process. */
#include <windows.h>
#include <stdio.h>

typedef unsigned int (*sample_fn)(void);

int main(int argc, char **argv)
{
    unsigned int iteration;
    if (argc != 2) {
        printf("reload_host: usage: reload_host.exe <dll>\n");
        return 2;
    }

    for (iteration = 0; iteration < 8u; ++iteration) {
        HMODULE module = LoadLibraryA(argv[1]);
        sample_fn value;
        if (!module) {
            printf("reload_host: FAIL load=%u err=%lu\n", iteration,
                   (unsigned long)GetLastError());
            return 3;
        }
        value = (sample_fn)(void *)GetProcAddress(module, "sample_dll_value");
        if (!value || value() != 0xC0FFEE42u) {
            printf("reload_host: FAIL call=%u err=%lu\n", iteration,
                   (unsigned long)GetLastError());
            FreeLibrary(module);
            return 4;
        }
        if (!FreeLibrary(module)) {
            printf("reload_host: FAIL free=%u err=%lu\n", iteration,
                   (unsigned long)GetLastError());
            return 5;
        }
    }

    printf("reload_host: PASS cycles=8\n");
    return 0;
}
