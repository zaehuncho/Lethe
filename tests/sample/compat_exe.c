#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

extern IMAGE_DOS_HEADER __ImageBase;
__declspec(dllimport) unsigned int compat_delay_value(void);

#define COMPAT_PREFERRED_BASE ((uintptr_t)0x0000000145000000ull)
#define COMPAT_RESOURCE_ID 201

static unsigned int relocation_target(void)
{
    return 0x51A7C0DEu;
}

typedef unsigned int (*relocation_fn)(void);
#pragma section(".xreloc", execute, read)
__declspec(allocate(".xreloc"))
static relocation_fn const g_relocated_call = relocation_target;

static int resource_contract(void)
{
    static const char marker[] = "LETHE_COMPAT_RESOURCE_V1";
    HRSRC resource = FindResourceW(
        (HMODULE)&__ImageBase,
        MAKEINTRESOURCEW(COMPAT_RESOURCE_ID),
        MAKEINTRESOURCEW(10));
    HGLOBAL loaded;
    const void *bytes;
    DWORD size;

    if (resource == NULL)
        return 0;
    size = SizeofResource((HMODULE)&__ImageBase, resource);
    if (size < sizeof(marker) - 1u)
        return 0;
    loaded = LoadResource((HMODULE)&__ImageBase, resource);
    if (loaded == NULL)
        return 0;
    bytes = LockResource(loaded);
    return bytes != NULL && memcmp(bytes, marker, sizeof(marker) - 1u) == 0;
}

int main(void)
{
    int resource_ok = resource_contract();
    unsigned int delayed = compat_delay_value();
    int relocation_ok = g_relocated_call() == 0x51A7C0DEu;
    int aslr_ok = (uintptr_t)&__ImageBase != COMPAT_PREFERRED_BASE;

    printf(
        "Lethe compat_exe: resource=%d delay=%08X reloc=%d aslr=%d\n",
        resource_ok,
        delayed,
        relocation_ok,
        aslr_ok);
    return resource_ok && delayed == 0xC0DEC0DEu && relocation_ok && aslr_ok
        ? 0
        : 31;
}
