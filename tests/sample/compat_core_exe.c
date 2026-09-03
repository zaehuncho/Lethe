#include <stdint.h>
#include <windows.h>

extern IMAGE_DOS_HEADER __ImageBase;

#define COMPAT_PREFERRED_BASE ((uintptr_t)0x0000000146000000ull)
#define COMPAT_RESOURCE_ID 201

static DWORD relocation_target(void)
{
    return 0x51A7C0DEu;
}

typedef DWORD (*relocation_fn)(void);
#pragma section(".xreloc", execute, read)
__declspec(allocate(".xreloc"))
static relocation_fn const g_relocated_call = relocation_target;

static BOOL bytes_equal(const BYTE *left, const BYTE *right, SIZE_T size)
{
    SIZE_T index;
    for (index = 0; index < size; ++index) {
        if (left[index] != right[index])
            return FALSE;
    }
    return TRUE;
}

static BOOL resource_contract(void)
{
    static const BYTE marker[] = "LETHE_COMPAT_RESOURCE_V1";
    HMODULE module = (HMODULE)&__ImageBase;
    HRSRC resource = FindResourceW(
        module,
        MAKEINTRESOURCEW(COMPAT_RESOURCE_ID),
        MAKEINTRESOURCEW(10));
    HGLOBAL loaded;
    const BYTE *bytes;
    DWORD size;

    if (resource == NULL)
        return FALSE;
    size = SizeofResource(module, resource);
    if (size < sizeof(marker) - 1u)
        return FALSE;
    loaded = LoadResource(module, resource);
    if (loaded == NULL)
        return FALSE;
    bytes = (const BYTE *)LockResource(loaded);
    return bytes != NULL && bytes_equal(bytes, marker, sizeof(marker) - 1u);
}

void compat_core_entry(void)
{
    static const char prefix[] = "Lethe compat_core: resource=";
    static const char reloc_label[] = " reloc=";
    static const char aslr_label[] = " aslr=";
    static const char newline[] = "\r\n";
    static const char zero[] = "0";
    static const char one[] = "1";
    BOOL resource_ok = resource_contract();
    BOOL relocation_ok = g_relocated_call() == 0x51A7C0DEu;
    BOOL aslr_ok = (uintptr_t)&__ImageBase != COMPAT_PREFERRED_BASE;
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    DWORD total_written = 0;

    WriteFile(output, prefix, (DWORD)(sizeof(prefix) - 1u), &written, NULL);
    total_written += written;
    WriteFile(output, resource_ok ? one : zero, 1u, &written, NULL);
    total_written += written;
    WriteFile(output, reloc_label, (DWORD)(sizeof(reloc_label) - 1u), &written, NULL);
    total_written += written;
    WriteFile(output, relocation_ok ? one : zero, 1u, &written, NULL);
    total_written += written;
    WriteFile(output, aslr_label, (DWORD)(sizeof(aslr_label) - 1u), &written, NULL);
    total_written += written;
    WriteFile(output, aslr_ok ? one : zero, 1u, &written, NULL);
    total_written += written;
    WriteFile(output, newline, (DWORD)(sizeof(newline) - 1u), &written, NULL);
    total_written += written;
    ExitProcess(resource_ok && relocation_ok && aslr_ok && total_written == 46u
        ? 0u
        : 30u);
}
