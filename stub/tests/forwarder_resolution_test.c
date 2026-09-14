#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

FARPROC lethe_test_resolve_forwarder(const char *forwarder,
                                     uint32_t forwarder_size);

static int starts_with_api_set(const char *value, uint32_t length)
{
    static const char api_prefix[] = "api-";
    static const char ext_prefix[] = "ext-";
    const char *prefix;
    uint32_t i;

    if (length < 4u)
        return 0;
    prefix = (value[0] == 'a' || value[0] == 'A')
           ? api_prefix : ext_prefix;
    for (i = 0; i < 4u; ++i) {
        char current = value[i];
        if (current >= 'A' && current <= 'Z')
            current = (char)(current + ('a' - 'A'));
        if (current != prefix[i])
            return 0;
    }
    return 1;
}

static int expect_rejected(const char *value, uint32_t size)
{
    return lethe_test_resolve_forwarder(value, size) == NULL;
}

int main(void)
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const uint8_t *base = (const uint8_t *)(const void *)kernel32;
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_DATA_DIRECTORY *directory;
    const IMAGE_EXPORT_DIRECTORY *exports;
    const uint32_t *functions;
    const uint32_t *names;
    const uint16_t *name_ordinals;
    uint64_t export_end;
    uint32_t i;
    uint32_t api_set_count = 0;
    uint32_t ordinal_count = 0;
    char ordinal_forwarder[64];
    char unterminated[] = {
        'k','e','r','n','e','l','3','2','.','S','l','e','e','p'
    };
    char long_module[270];

    if (kernel32 == NULL)
        return 10;
    dos = (const IMAGE_DOS_HEADER *)(const void *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 11;
    nt = (const IMAGE_NT_HEADERS64 *)(const void *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 12;
    directory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory->VirtualAddress == 0u || directory->Size == 0u)
        return 13;
    export_end = (uint64_t)directory->VirtualAddress + directory->Size;
    exports = (const IMAGE_EXPORT_DIRECTORY *)(const void *)(
        base + directory->VirtualAddress);
    functions = (const uint32_t *)(const void *)(base + exports->AddressOfFunctions);
    names = (const uint32_t *)(const void *)(base + exports->AddressOfNames);
    name_ordinals = (const uint16_t *)(const void *)(
        base + exports->AddressOfNameOrdinals);

    for (i = 0; i < exports->NumberOfNames; ++i) {
        uint32_t function_index = name_ordinals[i];
        uint32_t function_rva;
        const char *name;
        const char *forwarder;
        uint32_t forwarder_bound;
        uint32_t forwarder_length;
        FARPROC expected;
        FARPROC actual;

        if (function_index >= exports->NumberOfFunctions)
            return 14;
        function_rva = functions[function_index];
        if ((uint64_t)function_rva < directory->VirtualAddress ||
            (uint64_t)function_rva >= export_end)
            continue;
        forwarder_bound = (uint32_t)(export_end - function_rva);
        forwarder = (const char *)(const void *)(base + function_rva);
        for (forwarder_length = 0; forwarder_length < forwarder_bound;
             ++forwarder_length) {
            if (forwarder[forwarder_length] == '\0')
                break;
        }
        if (forwarder_length == forwarder_bound ||
            !starts_with_api_set(forwarder, forwarder_length))
            continue;

        name = (const char *)(const void *)(base + names[i]);
        expected = GetProcAddress(kernel32, name);
        actual = lethe_test_resolve_forwarder(forwarder, forwarder_bound);
        if (expected == NULL || actual != expected) {
            printf("api-set mismatch: %s -> %s\n", name, forwarder);
            return 20;
        }
        printf("api-set resolved: %s -> %s\n", name, forwarder);
        ++api_set_count;
        break;
    }

    if (api_set_count == 0u)
        return 21;

    for (i = 0; i < exports->NumberOfNames; ++i) {
        uint32_t function_index = name_ordinals[i];
        uint32_t exported_ordinal;
        const char *name;
        FARPROC expected;
        FARPROC actual;

        if (function_index >= exports->NumberOfFunctions)
            continue;
        exported_ordinal = exports->Base + function_index;
        if (exported_ordinal == 0u || exported_ordinal > 65535u)
            continue;
        name = (const char *)(const void *)(base + names[i]);
        expected = GetProcAddress(kernel32, name);
        if (expected == NULL)
            continue;
        if (sprintf_s(ordinal_forwarder, sizeof(ordinal_forwarder),
                      "kernel32.#%lu", (unsigned long)exported_ordinal) < 0)
            return 30;
        actual = lethe_test_resolve_forwarder(
            ordinal_forwarder, (uint32_t)sizeof(ordinal_forwarder));
        if (actual != expected)
            continue;
        printf("ordinal resolved: %s -> #%lu\n",
               name, (unsigned long)exported_ordinal);
        ++ordinal_count;
        break;
    }

    if (ordinal_count == 0u)
        return 31;
    if (!expect_rejected("kernel32.", (uint32_t)sizeof("kernel32.")) ||
        !expect_rejected(".Sleep", (uint32_t)sizeof(".Sleep")) ||
        !expect_rejected("kernel32.#", (uint32_t)sizeof("kernel32.#")) ||
        !expect_rejected("kernel32.#0", (uint32_t)sizeof("kernel32.#0")) ||
        !expect_rejected("kernel32.#65536",
                         (uint32_t)sizeof("kernel32.#65536")) ||
        !expect_rejected("kernel32.#1x", (uint32_t)sizeof("kernel32.#1x")) ||
        !expect_rejected(unterminated, (uint32_t)sizeof(unterminated)))
        return 40;

    for (i = 0; i < (uint32_t)sizeof(long_module); ++i)
        long_module[i] = 'a';
    long_module[256] = '.';
    long_module[257] = 'X';
    long_module[258] = '\0';
    if (!expect_rejected(long_module, (uint32_t)sizeof(long_module)))
        return 41;

    printf("forwarder parser negatives: PASS\n");
    return 0;
}
