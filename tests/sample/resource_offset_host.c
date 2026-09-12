#include <windows.h>
#include <stdio.h>

typedef unsigned int (*value_fn)(void);

static BOOL equal_bytes(const BYTE *left, const BYTE *right, DWORD size)
{
    DWORD index;
    for (index = 0; index < size; ++index) {
        if (left[index] != right[index])
            return FALSE;
    }
    return TRUE;
}

int main(int argc, char **argv)
{
    static const BYTE marker[] = "LETHE_DLL_OFFSET_RESOURCE_V1";
    HMODULE module;
    HRSRC resource;
    HGLOBAL loaded;
    const BYTE *bytes;
    DWORD size;
    value_fn value;
    int result = 0;

    if (argc != 2)
        return 2;
    module = LoadLibraryA(argv[1]);
    if (module == NULL)
        return 3;
    resource = FindResourceW(
        module, MAKEINTRESOURCEW(301), MAKEINTRESOURCEW(10));
    if (resource == NULL) {
        result = 4;
        goto done;
    }
    size = SizeofResource(module, resource);
    if (size < sizeof(marker) - 1u) {
        result = 5;
        goto done;
    }
    loaded = LoadResource(module, resource);
    if (loaded == NULL) {
        result = 6;
        goto done;
    }
    bytes = (const BYTE *)LockResource(loaded);
    if (bytes == NULL ||
            !equal_bytes(bytes, marker, (DWORD)(sizeof(marker) - 1u))) {
        result = 7;
        goto done;
    }
    value = (value_fn)(void *)GetProcAddress(module, "resource_offset_value");
    if (value == NULL || value() != 0x52535243u) {
        result = 8;
        goto done;
    }
    printf("resource_offset_host: PASS FindResource/LoadResource size=%lu\n",
           (unsigned long)size);

done:
    FreeLibrary(module);
    return result;
}
