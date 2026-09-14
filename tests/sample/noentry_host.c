#include <windows.h>
#include <stdio.h>

typedef unsigned int (*noentry_fn)(void);

typedef struct worker_ctx {
    HANDLE start;
    noentry_fn function;
    unsigned int value;
} worker_ctx;

static DWORD WINAPI run_worker(LPVOID parameter)
{
    worker_ctx *ctx = (worker_ctx *)parameter;
    if (ctx->start && WaitForSingleObject(ctx->start, 5000) != WAIT_OBJECT_0)
        return 1;
    ctx->value = ctx->function();
    return 0;
}

int main(int argc, char **argv)
{
    unsigned int iteration;
    if (argc != 2)
        return 2;
    for (iteration = 0; iteration < 8u; ++iteration) {
        HANDLE start = CreateEventW(NULL, TRUE, FALSE, NULL);
        worker_ctx before = { start, NULL, 0u };
        worker_ctx after = { NULL, NULL, 0u };
        HANDLE pre_worker;
        HANDLE post_worker;
        HMODULE module;
        noentry_fn function;
        if (!start)
            return 3;
        pre_worker = CreateThread(NULL, 0, run_worker, &before, 0, NULL);
        if (!pre_worker) {
            CloseHandle(start);
            return 4;
        }
        module = LoadLibraryA(argv[1]);
        if (!module) {
            TerminateThread(pre_worker, 1);
            CloseHandle(pre_worker);
            CloseHandle(start);
            return 5;
        }
        function = (noentry_fn)(void *)GetProcAddress(module, "noentry_value");
        if (!function) {
            TerminateThread(pre_worker, 1);
            CloseHandle(pre_worker);
            CloseHandle(start);
            FreeLibrary(module);
            return 6;
        }
        before.function = function;
        after.function = function;
        SetEvent(start);
        post_worker = CreateThread(NULL, 0, run_worker, &after, 0, NULL);
        if (!post_worker ||
            WaitForSingleObject(pre_worker, 5000) != WAIT_OBJECT_0 ||
            WaitForSingleObject(post_worker, 5000) != WAIT_OBJECT_0 ||
            before.value != 0x4E4F454Eu || after.value != 0x4E4F454Eu) {
            if (post_worker)
                CloseHandle(post_worker);
            CloseHandle(pre_worker);
            CloseHandle(start);
            FreeLibrary(module);
            return 7;
        }
        CloseHandle(post_worker);
        CloseHandle(pre_worker);
        CloseHandle(start);
        if (!FreeLibrary(module))
            return 8;
    }
    printf("noentry_host: PASS cycles=8 pre/post-workers=PASS\n");
    return 0;
}
