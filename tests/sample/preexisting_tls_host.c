#include <windows.h>
#include <stdio.h>

typedef unsigned int (*sample_fn)(void);

typedef struct tls_ctx {
    HANDLE start;
    sample_fn function;
    unsigned int value;
} tls_ctx;

static DWORD WINAPI run_tls(LPVOID parameter)
{
    tls_ctx *ctx = (tls_ctx *)parameter;
    if (ctx->start && WaitForSingleObject(ctx->start, 5000) != WAIT_OBJECT_0)
        return 1;
    ctx->value = ctx->function();
    return 0;
}

int main(int argc, char **argv)
{
    HANDLE start;
    HANDLE pre_worker;
    HANDLE post_worker;
    tls_ctx before;
    tls_ctx after;
    HMODULE module;
    sample_fn tls_function;
    sample_fn lifecycle_function;
    unsigned int main_value;
    unsigned int lifecycle;
    if (argc != 2)
        return 2;
    start = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!start)
        return 3;
    before.start = start;
    before.function = NULL;
    before.value = 0;
    pre_worker = CreateThread(NULL, 0, run_tls, &before, 0, NULL);
    if (!pre_worker)
        return 4;
    module = LoadLibraryA(argv[1]);
    if (!module)
        return 5;
    tls_function = (sample_fn)(void *)GetProcAddress(module, "sample_dll_tls_value");
    lifecycle_function = (sample_fn)(void *)GetProcAddress(
        module, "sample_dll_tls_lifecycle_ok");
    if (!tls_function || !lifecycle_function)
        return 6;
    main_value = tls_function();
    before.function = tls_function;
    SetEvent(start);
    after.start = NULL;
    after.function = tls_function;
    after.value = 0;
    post_worker = CreateThread(NULL, 0, run_tls, &after, 0, NULL);
    if (!post_worker || WaitForSingleObject(pre_worker, 5000) != WAIT_OBJECT_0 ||
        WaitForSingleObject(post_worker, 5000) != WAIT_OBJECT_0)
        return 7;
    lifecycle = lifecycle_function();
    printf("preexisting_tls_host: main=%u pre=%u post=%u lifecycle=%u\n",
           main_value, before.value, after.value, lifecycle);
    CloseHandle(post_worker);
    CloseHandle(pre_worker);
    CloseHandle(start);
    FreeLibrary(module);
    return main_value == 105u && before.value == 105u &&
           after.value == 105u && lifecycle == 0u ? 0 : 8;
}
