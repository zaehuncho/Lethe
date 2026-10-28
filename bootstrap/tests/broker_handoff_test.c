#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "broker_binding.h"
#include "broker_handoff.h"

int main(void)
{
    /* SHA-256("abc") anchors the file-handle hashing regression vector. */
    char path[MAX_PATH] = {0};
    char digest[65] = {0};
    DWORD path_length = GetTempPathA((DWORD)sizeof(path), path);
    HANDLE file;
    DWORD written = 0;
    int elevated = 0;

    if (path_length == 0 || path_length >= sizeof(path)
        || snprintf(path + path_length, sizeof(path) - path_length,
                    "lethe-broker-handoff-test.bin") < 0) {
        return 1;
    }
    file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (file == INVALID_HANDLE_VALUE) return 1;
    if (!WriteFile(file, "abc", 3, &written, NULL) || written != 3
        || !lethe_sha256_file_handle(file, digest)
        || strcmp(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != 0
        || !lethe_current_process_elevated(&elevated)
        || strncmp(LETHE_ORION_ACTIVATE_SHA256_MARKER, "ORION_ACTIVATE_SHA256:", 22) != 0) {
        CloseHandle(file);
        DeleteFileA(path);
        return 1;
    }
    CloseHandle(file);
    DeleteFileA(path);
    return 0;
}
