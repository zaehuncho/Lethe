#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    unsigned int iteration;
    char semaphore_name[96];
    HANDLE semaphore;
    if (argc != 2)
        return 2;
    if (sprintf_s(semaphore_name, sizeof(semaphore_name),
                  "Local\\LetheRejectDetach_%lu",
                  (unsigned long)GetCurrentProcessId()) < 0)
        return 3;
    semaphore = CreateSemaphoreA(NULL, 0, 100, semaphore_name);
    if (!semaphore ||
        !SetEnvironmentVariableA("LETHE_REJECT_SEMAPHORE", semaphore_name))
        return 4;
    for (iteration = 0; iteration < 8u; ++iteration) {
        HMODULE module = LoadLibraryA(argv[1]);
        if (module) {
            FreeLibrary(module);
            return 5;
        }
        if (GetLastError() != ERROR_DLL_INIT_FAILED)
            return 6;
        if (WaitForSingleObject(semaphore, 5000) != WAIT_OBJECT_0)
            return 7;
        if (WaitForSingleObject(semaphore, 0) != WAIT_TIMEOUT)
            return 8;
    }
    SetEnvironmentVariableA("LETHE_REJECT_SEMAPHORE", NULL);
    CloseHandle(semaphore);
    printf("reject_host: PASS rejected=8 detach=8 clean-retries=PASS\n");
    return 0;
}
