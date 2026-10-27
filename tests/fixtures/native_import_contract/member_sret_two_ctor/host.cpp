#include "member_abi.h"

#include <cstdio>
#include <windows.h>

int main(int argc, char** argv) {
    if (argc != 2) {
        return 2;
    }
    HMODULE module = LoadLibraryA(argv[1]);
    if (!module) {
        return 3;
    }
    auto function = reinterpret_cast<xfg_member_two_invoke_fn>(
        GetProcAddress(module, "xfg_member_two_invoke")
    );
    if (!function) {
        FreeLibrary(module);
        return 4;
    }
    int result = function();
    FreeLibrary(module);
    if (!result) {
        return 5;
    }
    std::puts("XFG_MEMBER_TWO_CTOR passed=true");
    return 0;
}
