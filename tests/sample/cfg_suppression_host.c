/* Prove Guard CF export suppression remains live after DLL unpacking. */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef unsigned int (*sample_fn)(void);

static int same_ascii(const char *left, const char *right)
{
    while (*left && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

static sample_fn find_export_without_getprocaddress(
    HMODULE module, const char *wanted)
{
    const unsigned char *base = (const unsigned char *)(const void *)module;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)(const void *)base;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_EXPORT_DIRECTORY *exports;
    const DWORD *names;
    const DWORD *functions;
    const WORD *ordinals;
    DWORD index;

    if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    nt = (const IMAGE_NT_HEADERS64 *)(const void *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return NULL;
    exports = (const IMAGE_EXPORT_DIRECTORY *)(const void *)(
        base + nt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (const DWORD *)(const void *)(base + exports->AddressOfNames);
    functions = (const DWORD *)(const void *)(base + exports->AddressOfFunctions);
    ordinals = (const WORD *)(const void *)(base + exports->AddressOfNameOrdinals);
    for (index = 0; index < exports->NumberOfNames; ++index) {
        const char *name = (const char *)(const void *)(base + names[index]);
        if (same_ascii(name, wanted)) {
            WORD ordinal = ordinals[index];
            if (ordinal >= exports->NumberOfFunctions)
                return NULL;
            return (sample_fn)(uintptr_t)(base + functions[ordinal]);
        }
    }
    return NULL;
}

__declspec(noinline) static unsigned int guarded_call(sample_fn function)
{
    return function();
}

int main(int argc, char **argv)
{
    HMODULE module;
    sample_fn requested;
    sample_fn suppressed;
    unsigned int unexpected;

    if (argc != 2)
        return 2;
    module = LoadLibraryA(argv[1]);
    if (!module)
        return 3;
    requested = (sample_fn)(void *)GetProcAddress(module, "sample_dll_value");
    if (!requested || guarded_call(requested) != 0xC0FFEE42u)
        return 4;
    suppressed = find_export_without_getprocaddress(
        module, "sample_dll_tls_lifecycle_ok");
    if (!suppressed)
        return 5;

    printf("cfg_suppression_host: armed\n");
    fflush(stdout);
    unexpected = guarded_call(suppressed);
    printf("cfg_suppression_host: FAIL target returned %u\n", unexpected);
    FreeLibrary(module);
    return 9;
}
