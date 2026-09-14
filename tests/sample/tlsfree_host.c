#include <windows.h>
#include <stdio.h>

typedef unsigned int (*status_fn)(void);

static DWORD WINAPI empty_worker(LPVOID parameter)
{
    (void)parameter;
    return 0;
}

int main(int argc, char **argv)
{
    unsigned int iteration;
    if (argc != 2)
        return 2;
    for (iteration = 0; iteration < 4u; ++iteration) {
        HMODULE module = LoadLibraryA(argv[1]);
        status_fn status;
        HANDLE workers[2];
        if (!module)
            return 3;
        status = (status_fn)(void *)GetProcAddress(module, "tlsfree_status");
        if (!status)
            return 4;
        workers[0] = CreateThread(NULL, 0, empty_worker, NULL, 0, NULL);
        workers[1] = CreateThread(NULL, 0, empty_worker, NULL, 0, NULL);
        if (!workers[0] || !workers[1] ||
            WaitForMultipleObjects(2, workers, TRUE, 5000) != WAIT_OBJECT_0)
            return 5;
        CloseHandle(workers[0]);
        CloseHandle(workers[1]);
        if (status() != 1u)
            return 6;
        if (!FreeLibrary(module))
            return 7;
    }
    printf("tlsfree_host: PASS DisableThreadLibraryCalls cycles=4\n");
    return 0;
}
