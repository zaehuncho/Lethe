#include <windows.h>
#include <stdio.h>

typedef unsigned int (*unwind_fn)(void);

int main(int argc, char **argv)
{
    unsigned int iteration;
    if (argc != 2)
        return 2;
    for (iteration = 0; iteration < 8u; ++iteration) {
        HMODULE module = LoadLibraryA(argv[1]);
        unwind_fn function;
        if (!module)
            return 3;
        function = (unwind_fn)(void *)GetProcAddress(module, "unwind_value");
        if (!function || function() != 72u) {
            FreeLibrary(module);
            return 4;
        }
        if (!FreeLibrary(module))
            return 5;
    }
    printf("unwind_host: PASS caught=72 cycles=8\n");
    return 0;
}
