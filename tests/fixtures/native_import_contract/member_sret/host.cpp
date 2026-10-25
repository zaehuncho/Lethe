#include "member_abi.h"

#include <windows.h>
#include <cstdio>

int main(int argc, char** argv)
{
    if (argc != 2) {
        return 2;
    }
    for (int cycle = 0; cycle != 3; ++cycle) {
        HMODULE module = LoadLibraryA(argv[1]);
        if (module == nullptr) {
            return 3;
        }
        auto function = reinterpret_cast<xfg_member_invoke_fn>(
            GetProcAddress(module, "xfg_member_invoke")
        );
        if (function == nullptr) {
            FreeLibrary(module);
            return 4;
        }
        int ok = function();
        if (!FreeLibrary(module)) {
            return 5;
        }
        if (!ok) {
            return 6;
        }
    }
    std::puts("XFG_MEMBER_IMPORT passed=true");
    return 0;
}
