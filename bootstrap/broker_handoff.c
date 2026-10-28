#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#include "broker_binding.h"
#include "broker_handoff.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

#define BROKER_EXE_NAME "OrionActivate.exe"

static int is_regular_file_handle(HANDLE file)
{
    FILE_ATTRIBUTE_TAG_INFO attributes;
    ZeroMemory(&attributes, sizeof(attributes));
    return file != INVALID_HANDLE_VALUE
        && GetFileInformationByHandleEx(file, FileAttributeTagInfo,
                                        &attributes, sizeof(attributes))
        && (attributes.FileAttributes
            & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
}

static int hex_equal_lower(const char *left, const char *right)
{
    return left && right && strlen(left) == 64 && strlen(right) == 64
        && memcmp(left, right, 64) == 0;
}

int lethe_sha256_file_handle(HANDLE file, char output_hex[65])
{
    static const char hex[] = "0123456789abcdef";
    BYTE buffer[64 * 1024];
    BYTE digest[32];
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    LARGE_INTEGER saved = {0};
    LARGE_INTEGER zero = {0};
    DWORD read = 0;
    int ok = 0;

    if (!output_hex || !is_regular_file_handle(file)
        || !SetFilePointerEx(file, zero, &saved, FILE_CURRENT)
        || !SetFilePointerEx(file, zero, NULL, FILE_BEGIN)) {
        return 0;
    }
    ZeroMemory(output_hex, 65);
    ZeroMemory(digest, sizeof(digest));
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0
        || BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) != 0) {
        goto cleanup;
    }
    for (;;) {
        read = 0;
        if (!ReadFile(file, buffer, sizeof(buffer), &read, NULL)) goto cleanup;
        if (read == 0) break;
        if (BCryptHashData(hash, buffer, read, 0) != 0) goto cleanup;
    }
    if (BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0) goto cleanup;
    for (DWORD i = 0; i < sizeof(digest); ++i) {
        output_hex[i * 2] = hex[(digest[i] >> 4) & 0x0f];
        output_hex[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    output_hex[64] = '\0';
    ok = 1;

cleanup:
    SetFilePointerEx(file, saved, NULL, FILE_BEGIN);
    SecureZeroMemory(buffer, sizeof(buffer));
    SecureZeroMemory(digest, sizeof(digest));
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!ok) SecureZeroMemory(output_hex, 65);
    return ok;
}

int lethe_current_process_elevated(int *elevated)
{
    HANDLE token = NULL;
    TOKEN_ELEVATION state;
    DWORD returned = 0;
    int ok = 0;
    if (!elevated || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    ZeroMemory(&state, sizeof(state));
    if (GetTokenInformation(token, TokenElevation, &state, sizeof(state), &returned)
        && returned == sizeof(state)) {
        *elevated = state.TokenIsElevated ? 1 : 0;
        ok = 1;
    }
    CloseHandle(token);
    return ok;
}

int lethe_launch_sibling_broker(const char *install_directory)
{
    char broker_path[MAX_PATH] = {0};
    char digest[65] = {0};
    char command[MAX_PATH + 3] = {0};
    HANDLE broker = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION process = {0};
    STARTUPINFOA startup = {0};
    DWORD exit_code = 1;
    int elevated = 0;
    int result = 0;

    if (!install_directory || !*install_directory || !lethe_current_process_elevated(&elevated)) {
        return 0;
    }
    if (snprintf(broker_path, sizeof(broker_path), "%s\\%s", install_directory,
                 BROKER_EXE_NAME) < 0) {
        return 0;
    }
    broker = CreateFileA(broker_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
                             | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (broker == INVALID_HANDLE_VALUE || !is_regular_file_handle(broker)
        || !lethe_sha256_file_handle(broker, digest)
        || !hex_equal_lower(digest, LETHE_ORION_ACTIVATE_SHA256_HEX)) {
        goto cleanup;
    }
    if (snprintf(command, sizeof(command), "\"%s\"", broker_path) < 0) goto cleanup;
    startup.cb = sizeof(startup);
    if (!CreateProcessA(broker_path, command, NULL, NULL, FALSE,
                        elevated ? CREATE_NEW_PROCESS_GROUP : 0,
                        NULL, install_directory, &startup, &process)) {
        goto cleanup;
    }
    CloseHandle(process.hThread);
    process.hThread = NULL;
    if (WaitForSingleObject(process.hProcess, INFINITE) != WAIT_OBJECT_0
        || !GetExitCodeProcess(process.hProcess, &exit_code)) {
        goto cleanup;
    }
    result = exit_code == 0;

cleanup:
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (broker != INVALID_HANDLE_VALUE) CloseHandle(broker);
    SecureZeroMemory(command, sizeof(command));
    SecureZeroMemory(digest, sizeof(digest));
    SecureZeroMemory(broker_path, sizeof(broker_path));
    return result;
}
