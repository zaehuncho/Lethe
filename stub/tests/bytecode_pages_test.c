#define _CRT_SECURE_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bytecode_pages.h"

int key_scatter_init(uint8_t key[32])
{
    SecureZeroMemory(key, 32);
    return 0;
}

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

static int decode_key(const char *hex, uint8_t key[32])
{
    size_t i;
    if (strlen(hex) != 64)
        return 0;
    for (i = 0; i < 32; ++i) {
        int high = nibble(hex[i * 2]);
        int low = nibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0)
            return 0;
        key[i] = (uint8_t)((high << 4) | low);
    }
    return 1;
}

static int all_zero(const uint8_t *data, size_t size)
{
    size_t i;
    uint8_t value = 0;
    for (i = 0; i < size; ++i)
        value |= data[i];
    return value == 0;
}

static int run_tests(uint8_t *envelope, size_t envelope_size,
                     const uint8_t *expected, size_t expected_size,
                     uint8_t key[32])
{
    DvmPageEnvelopeView view;
    DvmPageCache cache;
    const uint8_t *page;
    uint32_t page_size;
    uint8_t *output;
    uint8_t *changed;
    uint8_t wrong_key[32];
    size_t tail;

    if (dvm_page_envelope_parse(envelope, envelope_size, &view) != DVM_PAGE_OK)
        return 10;
    if (view.plaintext_size != expected_size || view.page_count < 2)
        return 11;
    if (dvm_page_cache_init(&cache, envelope, envelope_size, key) != DVM_PAGE_OK)
        return 12;
    output = (uint8_t *)malloc(expected_size);
    if (output == NULL)
        return 13;
    if (dvm_page_cache_read(&cache, key, 0, output,
                            (uint32_t)expected_size) != DVM_PAGE_OK ||
        memcmp(output, expected, expected_size) != 0) {
        free(output);
        return 14;
    }
    if (dvm_page_cache_open(&cache, key, 0, &page, &page_size) != DVM_PAGE_OK ||
        page_size != view.page_size)
        return 15;
    if (dvm_page_cache_open(&cache, key, view.page_count - 1u,
                            &page, &page_size) != DVM_PAGE_OK)
        return 16;
    tail = (size_t)view.page_size - page_size;
    if (tail != 0 && !all_zero(cache.page + page_size, tail))
        return 17;

    memcpy(wrong_key, key, sizeof(wrong_key));
    wrong_key[0] ^= 0x80u;
    if (dvm_page_cache_init(&cache, envelope, envelope_size, wrong_key) !=
        DVM_PAGE_ERROR_AUTHENTICATION)
        return 18;
    SecureZeroMemory(wrong_key, sizeof(wrong_key));

    changed = (uint8_t *)malloc(envelope_size);
    if (changed == NULL)
        return 19;
    memcpy(changed, envelope, envelope_size);
    changed[view.table_offset + 8u] ^= 1u;
    if (dvm_page_cache_init(&cache, changed, envelope_size, key) !=
        DVM_PAGE_ERROR_AUTHENTICATION)
        return 20;

    memcpy(changed, envelope, envelope_size);
    changed[view.data_offset] ^= 1u;
    if (dvm_page_cache_init(&cache, changed, envelope_size, key) != DVM_PAGE_OK)
        return 21;
    if (dvm_page_cache_open(&cache, key, 0, &page, &page_size) !=
        DVM_PAGE_ERROR_AUTHENTICATION)
        return 22;
    if (!all_zero(cache.page, sizeof(cache.page)))
        return 23;

    memcpy(changed, envelope, envelope_size);
    if (dvm_page_cache_init(&cache, changed, envelope_size, key) != DVM_PAGE_OK)
        return 24;
    changed[view.table_offset + 4u] ^= 0x80u;
    if (dvm_page_cache_open(&cache, key, 0, &page, &page_size) !=
        DVM_PAGE_ERROR_FORMAT)
        return 25;
    if (!all_zero(cache.page, sizeof(cache.page)))
        return 26;

    memcpy(changed, envelope, envelope_size);
    changed[24] ^= 1u;
    if (dvm_page_cache_init(&cache, changed, envelope_size, key) !=
        DVM_PAGE_ERROR_AUTHENTICATION)
        return 27;
    if (dvm_page_envelope_parse(envelope, envelope_size - 1u, &view) !=
        DVM_PAGE_ERROR_FORMAT)
        return 28;

    dvm_page_cache_wipe(&cache);
    if (cache.view.blob != NULL || cache.cached_size != 0 ||
        cache.cached_index != DVM_PAGE_NO_CACHE ||
        !all_zero(cache.page, sizeof(cache.page)))
        return 29;

    SecureZeroMemory(output, expected_size);
    SecureZeroMemory(changed, envelope_size);
    free(output);
    free(changed);
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t *envelope = NULL;
    uint8_t *expected = NULL;
    size_t envelope_size = 0;
    size_t expected_size = 0;
    uint8_t key[32];
    int result;

    if (argc != 4 || !decode_key(argv[3], key) ||
        !read_file(argv[1], &envelope, &envelope_size) ||
        !read_file(argv[2], &expected, &expected_size))
        return 2;
    if (expected_size > UINT32_MAX) {
        result = 3;
    } else {
        result = run_tests(envelope, envelope_size, expected, expected_size,
                           key);
    }
    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(envelope, envelope_size);
    SecureZeroMemory(expected, expected_size);
    free(envelope);
    free(expected);
    if (result != 0)
        fprintf(stderr, "bytecode page native test failed: %d\n", result);
    else
        puts("authenticated bytecode page vectors: PASS");
    return result;
}
