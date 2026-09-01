#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "stub_hooks.h"

#define TEST_IMAGE_SIZE 0x4000u
#define TEST_PAGE_SIZE  0x1000u
#define TEST_META_RVA   0x2000u
#define TEST_META_SIZE  0x0380u

typedef BOOL (WINAPI *RealVirtualProtectFn)(
    LPVOID, SIZE_T, DWORD, PDWORD);
typedef SIZE_T (WINAPI *RealVirtualQueryFn)(
    LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);

static RealVirtualProtectFn g_real_virtual_protect;
static RealVirtualQueryFn g_real_virtual_query;
static unsigned int g_protect_calls;
static unsigned int g_fail_protect_call;
static unsigned int g_query_mode;

enum {
    QUERY_REAL = 0u,
    QUERY_FAIL = 1u,
    QUERY_WRONG_PROTECTION = 2u
};

BOOL WINAPI lethe_test_virtual_protect(
    LPVOID address, SIZE_T size, DWORD protection, PDWORD old_protection)
{
    ++g_protect_calls;
    if (g_fail_protect_call != 0u &&
            g_protect_calls == g_fail_protect_call) {
        return FALSE;
    }
    return g_real_virtual_protect(
        address, size, protection, old_protection);
}

SIZE_T WINAPI lethe_test_virtual_query(
    LPCVOID address, PMEMORY_BASIC_INFORMATION information, SIZE_T size)
{
    SIZE_T result;
    if (g_query_mode == QUERY_FAIL)
        return 0;
    result = g_real_virtual_query(address, information, size);
    if (result == sizeof(*information) &&
            g_query_mode == QUERY_WRONG_PROTECTION) {
        information->Protect = PAGE_READWRITE;
    }
    return result;
}

static int resolve_real_apis(void)
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32)
        return 1;
    g_real_virtual_protect = (RealVirtualProtectFn)(uintptr_t)GetProcAddress(
        kernel32, "VirtualProtect");
    g_real_virtual_query = (RealVirtualQueryFn)(uintptr_t)GetProcAddress(
        kernel32, "VirtualQuery");
    return (!g_real_virtual_protect || !g_real_virtual_query) ? 1 : 0;
}

static void reset_faults(unsigned int fail_protect_call,
                         unsigned int query_mode)
{
    g_protect_calls = 0u;
    g_fail_protect_call = fail_protect_call;
    g_query_mode = query_mode;
}

static int set_real_protection(void *address, SIZE_T size, DWORD protection)
{
    DWORD old_protection = 0;
    return g_real_virtual_protect(
        address, size, protection, &old_protection) ? 0 : 1;
}

static int real_protection_is(const void *address, DWORD expected)
{
    MEMORY_BASIC_INFORMATION information;
    if (g_real_virtual_query(address, &information, sizeof(information)) !=
            sizeof(information)) {
        return 0;
    }
    return information.State == MEM_COMMIT && information.Protect == expected;
}

static int reset_headers(uint8_t *image)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    if (set_real_protection(
            image, TEST_PAGE_SIZE, PAGE_READWRITE) != 0) {
        return 1;
    }
    memset(image, 0, TEST_PAGE_SIZE);
    memset(image + sizeof(IMAGE_DOS_HEADER), 0xA5,
           0x80u - sizeof(IMAGE_DOS_HEADER));

    dos = (IMAGE_DOS_HEADER *)image;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;
    nt = (IMAGE_NT_HEADERS64 *)(image + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfHeaders = TEST_PAGE_SIZE;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1234u;
    nt->OptionalHeader.CheckSum = 0xAABBCCDDu;
    nt->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x2100u;
    nt->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0x80u;
    return set_real_protection(image, TEST_PAGE_SIZE, PAGE_READONLY);
}

static int header_is_intact(const uint8_t *image)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)image;
    const IMAGE_NT_HEADERS64 *nt =
        (const IMAGE_NT_HEADERS64 *)(image + dos->e_lfanew);
    return nt->OptionalHeader.AddressOfEntryPoint == 0x1234u &&
        nt->OptionalHeader.CheckSum == 0xAABBCCDDu &&
        nt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0x2100u &&
        image[sizeof(IMAGE_DOS_HEADER)] == 0xA5u;
}

static int header_is_wiped(const uint8_t *image)
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)image;
    const IMAGE_NT_HEADERS64 *nt =
        (const IMAGE_NT_HEADERS64 *)(image + dos->e_lfanew);
    return nt->OptionalHeader.AddressOfEntryPoint == 0u &&
        nt->OptionalHeader.CheckSum == 0u &&
        nt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0u &&
        image[sizeof(IMAGE_DOS_HEADER)] == 0u;
}

static int reset_metadata(uint8_t *image)
{
    uint8_t *metadata = image + TEST_META_RVA;
    if (set_real_protection(
            metadata, TEST_PAGE_SIZE, PAGE_READWRITE) != 0) {
        return 1;
    }
    memset(metadata, 0x5A, TEST_META_SIZE);
    return set_real_protection(metadata, TEST_PAGE_SIZE, PAGE_READONLY);
}

static int metadata_is(const uint8_t *image, uint8_t value)
{
    const uint8_t *metadata = image + TEST_META_RVA;
    SIZE_T index;
    for (index = 0; index < TEST_META_SIZE; ++index) {
        if (metadata[index] != value)
            return 0;
    }
    return 1;
}

static int test_headers(uint8_t *image)
{
    if (reset_headers(image) != 0)
        return 10;
    reset_faults(0u, QUERY_REAL);
    if (antidump_erase_headers(image, 0) != 0 ||
            !header_is_wiped(image) ||
            !real_protection_is(image, PAGE_READONLY)) {
        return 11;
    }

    if (reset_headers(image) != 0)
        return 12;
    reset_faults(1u, QUERY_REAL);
    if (antidump_erase_headers(image, 0) == 0 ||
            !header_is_intact(image) ||
            !real_protection_is(image, PAGE_READONLY)) {
        return 13;
    }

    if (reset_headers(image) != 0)
        return 14;
    reset_faults(2u, QUERY_REAL);
    if (antidump_erase_headers(image, 0) == 0 ||
            !header_is_wiped(image) ||
            !real_protection_is(image, PAGE_READWRITE)) {
        return 15;
    }

    if (reset_headers(image) != 0)
        return 16;
    reset_faults(0u, QUERY_WRONG_PROTECTION);
    if (antidump_erase_headers(image, 0) == 0 ||
            !header_is_wiped(image) ||
            !real_protection_is(image, PAGE_READONLY)) {
        return 17;
    }

    if (reset_headers(image) != 0)
        return 18;
    reset_faults(0u, QUERY_FAIL);
    if (antidump_erase_headers(image, 0) == 0 ||
            !real_protection_is(image, PAGE_READONLY)) {
        return 19;
    }
    return 0;
}

static int test_metadata(uint8_t *image)
{
    PackInfo info;
    memset(&info, 0, sizeof(info));
    info.meta_rva = TEST_META_RVA;
    info.meta_stored_size = TEST_META_SIZE;

    if (reset_metadata(image) != 0)
        return 20;
    reset_faults(0u, QUERY_REAL);
    if (antidump_harden(image, &info) != 0 ||
            !metadata_is(image, 0u) ||
            !real_protection_is(
                image + TEST_META_RVA, PAGE_READONLY)) {
        return 21;
    }

    if (reset_metadata(image) != 0)
        return 22;
    reset_faults(1u, QUERY_REAL);
    if (antidump_harden(image, &info) == 0 ||
            !metadata_is(image, 0x5Au) ||
            !real_protection_is(
                image + TEST_META_RVA, PAGE_READONLY)) {
        return 23;
    }

    if (reset_metadata(image) != 0)
        return 24;
    reset_faults(2u, QUERY_REAL);
    if (antidump_harden(image, &info) == 0 ||
            !metadata_is(image, 0u) ||
            !real_protection_is(
                image + TEST_META_RVA, PAGE_READWRITE)) {
        return 25;
    }

    if (reset_metadata(image) != 0)
        return 26;
    reset_faults(0u, QUERY_WRONG_PROTECTION);
    if (antidump_harden(image, &info) == 0 ||
            !metadata_is(image, 0u) ||
            !real_protection_is(
                image + TEST_META_RVA, PAGE_READONLY)) {
        return 27;
    }
    return 0;
}

int main(void)
{
    uint8_t *image;
    int result;
    if (resolve_real_apis() != 0)
        return 2;
    image = (uint8_t *)VirtualAlloc(
        NULL, TEST_IMAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!image)
        return 3;

    result = test_headers(image);
    if (result == 0)
        result = test_metadata(image);
    reset_faults(0u, QUERY_REAL);
    if (set_real_protection(image, TEST_IMAGE_SIZE, PAGE_READWRITE) != 0 &&
            result == 0) {
        result = 4;
    }
    VirtualFree(image, 0, MEM_RELEASE);
    if (result != 0)
        return result;
    puts("anti-dump fault injection: PASS");
    return 0;
}
