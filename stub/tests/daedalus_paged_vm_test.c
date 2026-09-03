#define _CRT_SECURE_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bytecode_pages.h"
#include "daedalus_vm.h"
#include "key_scatter.h"

typedef struct WorkerInput {
    const uint8_t *envelope;
    uint32_t envelope_size;
    const uint8_t *program_id;
    uint64_t expected_rax;
    volatile LONG *failed;
} WorkerInput;

uint64_t daedalus_trampoline_call(void *function, int argument_count,
                                  const uint64_t *arguments)
{
    (void)function;
    (void)argument_count;
    (void)arguments;
    return 0;
}

static int read_file(const char *path, uint8_t **out, size_t *out_size)
{
    FILE *file = NULL;
    long length;
    uint8_t *buffer;

    if (fopen_s(&file, path, "rb") != 0 || file == NULL)
        return 0;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 0;
    }
    length = ftell(file);
    if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 0;
    }
    buffer = (uint8_t *)malloc((size_t)length);
    if (buffer == NULL) {
        fclose(file);
        return 0;
    }
    if (fread(buffer, 1, (size_t)length, file) != (size_t)length) {
        SecureZeroMemory(buffer, (size_t)length);
        free(buffer);
        fclose(file);
        return 0;
    }
    fclose(file);
    *out = buffer;
    *out_size = (size_t)length;
    return 1;
}

static int nibble(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int decode_hex(const char *hex, uint8_t *output, size_t output_size)
{
    size_t i;
    if (strlen(hex) != output_size * 2u)
        return 0;
    for (i = 0; i < output_size; ++i) {
        int high = nibble(hex[i * 2u]);
        int low = nibble(hex[i * 2u + 1u]);
        if (high < 0 || low < 0)
            return 0;
        output[i] = (uint8_t)((high << 4) | low);
    }
    return 1;
}

static void fill_context(DaedalusX64Context *context)
{
    uint32_t i;
    for (i = 0; i < DVM_X64_GPR_COUNT; ++i)
        context->gpr[i] = UINT64_C(0x1111111111111111) * (i + 1u);
    context->rflags = UINT64_C(0x202);
}

static int expect_failure_unchanged(const uint8_t *envelope,
                                    uint32_t envelope_size,
                                    const uint8_t program_id[16])
{
    DaedalusX64Context context;
    DaedalusX64Context original;
    fill_context(&context);
    original = context;
    if (daedalus_vm_exec_x64_paged(
            envelope, envelope_size, program_id, &context,
            (const uint8_t *)(uintptr_t)UINT64_C(0x180000000)) == 0)
        return 0;
    return memcmp(&context, &original, sizeof(context)) == 0;
}

static DWORD WINAPI execute_worker(void *opaque)
{
    WorkerInput *input = (WorkerInput *)opaque;
    uint32_t iteration;
    for (iteration = 0; iteration < 32u; ++iteration) {
        DaedalusX64Context context;
        fill_context(&context);
        if (daedalus_vm_exec_x64_paged(
                input->envelope, input->envelope_size,
                input->program_id, &context,
                (const uint8_t *)(uintptr_t)UINT64_C(0x180000000)) != 0 ||
            context.gpr[0] != input->expected_rax) {
            InterlockedExchange(input->failed, 1);
            return 1;
        }
    }
    return 0;
}

static int run_tests(uint8_t *envelope, uint32_t envelope_size,
                     const uint8_t key[32], const uint8_t program_id[16],
                     uint64_t expected_rax)
{
    uint8_t key_copy[32];
    uint8_t wrong_key[32];
    uint8_t wrong_id[16];
    uint8_t *changed;
    DvmPageEnvelopeView view;
    DaedalusX64Context context;
    WorkerInput input;
    HANDLE workers[4];
    volatile LONG failed = 0;
    uint32_t i;

    if (dvm_page_envelope_parse(envelope, envelope_size, &view) != DVM_PAGE_OK ||
        view.page_size != 256u || view.page_count < 2u ||
        memcmp(view.program_id, program_id, sizeof(wrong_id)) != 0)
        return 10;

    memcpy(wrong_key, key, sizeof(wrong_key));
    wrong_key[0] ^= 0x80u;
    if (key_scatter_init(wrong_key) != 0 ||
        !expect_failure_unchanged(envelope, envelope_size, program_id))
        return 11;
    key_scatter_destroy();

    memcpy(key_copy, key, sizeof(key_copy));
    if (key_scatter_init(key_copy) != 0)
        return 12;
    fill_context(&context);
    if (daedalus_vm_exec_x64_paged(
            envelope, envelope_size, program_id, &context,
            (const uint8_t *)(uintptr_t)UINT64_C(0x180000000)) != 0 ||
        context.gpr[0] != expected_rax)
        return 13;

    memcpy(wrong_id, program_id, sizeof(wrong_id));
    wrong_id[0] ^= 1u;
    if (!expect_failure_unchanged(envelope, envelope_size, wrong_id))
        return 14;
    if (!expect_failure_unchanged(envelope, envelope_size - 1u, program_id))
        return 15;

    changed = (uint8_t *)malloc(envelope_size);
    if (changed == NULL)
        return 16;
    memcpy(changed, envelope, envelope_size);
    changed[24] ^= 1u;
    if (!expect_failure_unchanged(changed, envelope_size, program_id))
        return 17;
    memcpy(changed, envelope, envelope_size);
    changed[view.table_offset + 8u] ^= 1u;
    if (!expect_failure_unchanged(changed, envelope_size, program_id))
        return 18;
    memcpy(changed, envelope, envelope_size);
    changed[view.data_offset + view.page_size] ^= 1u;
    if (!expect_failure_unchanged(changed, envelope_size, program_id))
        return 19;
    SecureZeroMemory(changed, envelope_size);
    free(changed);

    input.envelope = envelope;
    input.envelope_size = envelope_size;
    input.program_id = program_id;
    input.expected_rax = expected_rax;
    input.failed = &failed;
    for (i = 0; i < 4u; ++i) {
        workers[i] = CreateThread(NULL, 0, execute_worker, &input, 0, NULL);
        if (workers[i] == NULL)
            return 20;
    }
    if (WaitForMultipleObjects(4u, workers, TRUE, 30000u) != WAIT_OBJECT_0)
        return 21;
    for (i = 0; i < 4u; ++i)
        CloseHandle(workers[i]);
    key_scatter_destroy();
    return failed == 0 ? 0 : 22;
}

int main(int argc, char **argv)
{
    uint8_t *envelope = NULL;
    size_t envelope_size = 0;
    uint8_t key[32];
    uint8_t program_id[16];
    uint64_t expected_rax;
    int result;

    if (argc != 5 || !decode_hex(argv[2], key, sizeof(key)) ||
        !decode_hex(argv[3], program_id, sizeof(program_id)) ||
        sscanf_s(argv[4], "%llx", &expected_rax) != 1 ||
        !read_file(argv[1], &envelope, &envelope_size) ||
        envelope_size > UINT32_MAX)
        return 2;
    result = run_tests(
        envelope, (uint32_t)envelope_size, key, program_id, expected_rax);
    key_scatter_destroy();
    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(program_id, sizeof(program_id));
    SecureZeroMemory(envelope, envelope_size);
    free(envelope);
    if (result != 0)
        fprintf(stderr, "paged VM native test failed: %d\n", result);
    else
        puts("paged VM cross-page execution and tamper vectors: PASS");
    return result;
}
