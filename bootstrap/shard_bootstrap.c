/*
 * Lethe V3 shard bootstrap — a pipe-only child launcher.
 *
 * This executable is staged as OrionNative.exe beside OrionNative.packed.exe.
 * It intentionally does NOT read a DPAPI session, make a network request, parse
 * a shard, set an environment variable, or write a cache.  The signed broker
 * has already verified the device-bound HPKE grant and supplies exactly one
 * sealed-to-EOF VSG3 frame on this process's stdin.  The bootstrap only forwards
 * that inherited pipe to the packed child while holding the packed file open
 * deny-write/deny-delete through the child's lifetime.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string.h>

#include "broker_binding.h"
#include "broker_handoff.h"

#pragma comment(lib, "shlwapi.lib")

#define PACKED_EXE_NAME "OrionNative.packed.exe"

/* This public release-integrity marker must be emitted verbatim in the final
 * bootstrap.  The volatile reads below keep it out of compile-time folding;
 * the release wrapper then requires exactly one canonical copy and compares
 * its digest with the manifest-covered broker bytes. */
#pragma section(".rdata$VSB", read)
__declspec(allocate(".rdata$VSB"))
static const volatile char s_broker_binding_marker[] =
    LETHE_ORION_ACTIVATE_SHA256_MARKER;

static int broker_binding_marker_is_present(void)
{
    volatile const char *marker = s_broker_binding_marker;
    size_t index;

    /* The direct-launch handoff performs the real digest comparison in
     * broker_handoff.c. Keep the configured raw digest in this compilation
     * contract as well, so the V3 source profile binds both representations. */
    if (LETHE_ORION_ACTIVATE_SHA256_HEX[0] == '\0')
        return 0;
    for (index = 0; index < 86u; ++index) {
        if (marker[index] == '\0')
            return 0;
    }
    return marker[86] == '\0';
}

static int is_regular_file_handle(HANDLE file)
{
    FILE_ATTRIBUTE_TAG_INFO attributes;
    ZeroMemory(&attributes, sizeof(attributes));
    if (file == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandleEx(file, FileAttributeTagInfo,
                                      &attributes, sizeof(attributes)))
        return 0;
    return (attributes.FileAttributes &
            (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    char exeDir[MAX_PATH] = {0};
    char packedPath[MAX_PATH] = {0};
    char command[MAX_PATH + 3] = {0};
    HANDLE packedFile = INVALID_HANDLE_VALUE;
    HANDLE stdinPipe = INVALID_HANDLE_VALUE;
    HANDLE nullOutput = INVALID_HANDLE_VALUE;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    PROCESS_INFORMATION process;
    SIZE_T attributesSize = 0;
    int elevated = 0;
    int result = 1;
    ZeroMemory(&process, sizeof(process));

    {
        DWORD exeLength = GetModuleFileNameA(NULL, exeDir, MAX_PATH);
        if (exeLength == 0 || exeLength >= MAX_PATH || !PathRemoveFileSpecA(exeDir)) {
            MessageBoxA(NULL, "Failed to resolve the Venice launch directory.",
                        "Venice Launch Error", MB_ICONERROR);
            goto cleanup;
        }
    }

    if (!lethe_current_process_elevated(&elevated)
        || (elevated != 0 && elevated != 1)) {
        MessageBoxA(NULL, "Venice could not verify the launch context.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    /* There are only two legal entry paths. The broker uses an inherited,
     * closed pipe; a direct bootstrap start first verifies the sibling broker's
     * configured SHA-256 and delegates to it. It never accepts a shard from a
     * console, command line, environment, cache, or file. */
    stdinPipe = GetStdHandle(STD_INPUT_HANDLE);
    if (stdinPipe == INVALID_HANDLE_VALUE || stdinPipe == NULL
        || GetFileType(stdinPipe) != FILE_TYPE_PIPE) {
        if (!lethe_launch_sibling_broker(exeDir)) {
            MessageBoxA(NULL, "Venice must be started by its verified launcher.",
                        "Venice Launch Error", MB_ICONERROR);
        } else {
            result = 0;
        }
        goto cleanup;
    }
    if (!SetHandleInformation(stdinPipe, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        MessageBoxA(NULL, "Venice could not prepare the verified launch path.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    /* Keep the generated marker in this binary. The release packer compares it
     * against the exact manifest-covered OrionActivate.exe it stages. */
    if (!broker_binding_marker_is_present()) {
        goto cleanup;
    }
    {
        int pathChars = snprintf(packedPath, sizeof(packedPath), "%s\\%s",
                                 exeDir, PACKED_EXE_NAME);
        if (pathChars < 0 || (size_t)pathChars >= sizeof(packedPath)) {
            MessageBoxA(NULL, "Venice launch path is too long.",
                        "Venice Launch Error", MB_ICONERROR);
            goto cleanup;
        }
    }

    /* Keep a deny-write/deny-delete handle through CreateProcess + wait. The
     * broker has already manifest-verified the same file under its own lock;
     * this second lock closes the bootstrap-to-packed-child swap window. */
    packedFile = CreateFileA(packedPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                                 FILE_FLAG_SEQUENTIAL_SCAN,
                             NULL);
    if (packedFile == INVALID_HANDLE_VALUE || !is_regular_file_handle(packedFile)) {
        MessageBoxA(NULL, "The protected Venice application is missing or unsafe. Reinstall Venice.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    {
        SECURITY_ATTRIBUTES inheritable;
        ZeroMemory(&inheritable, sizeof(inheritable));
        inheritable.nLength = sizeof(inheritable);
        inheritable.bInheritHandle = TRUE;
        nullOutput = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &inheritable, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (nullOutput == INVALID_HANDLE_VALUE) {
            MessageBoxA(NULL, "Venice could not prepare the protected runtime.",
                        "Venice Launch Error", MB_ICONERROR);
            goto cleanup;
        }
    }

    /* Limit child inheritance to the VSG3 stdin pipe and NUL output.  The packed
     * stub reads exactly 40 bytes then demands EOF, so it cannot accept an env
     * replacement, command-line secret, file cache, or a second pipe record. */
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributesSize);
    if (attributesSize == 0) goto cleanup;
    attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, attributesSize);
    if (!attributes ||
        !InitializeProcThreadAttributeList(attributes, 1, 0, &attributesSize))
        goto cleanup;
    {
        HANDLE allowed[2] = {stdinPipe, nullOutput};
        if (!UpdateProcThreadAttribute(attributes, 0,
                                       PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                       allowed, sizeof(allowed), NULL, NULL))
            goto cleanup;
    }
    {
        int chars = snprintf(command, sizeof(command), "\"%s\"", packedPath);
        if (chars < 0 || (size_t)chars >= sizeof(command)) goto cleanup;
    }
    {
        STARTUPINFOEXA startup;
        ZeroMemory(&startup, sizeof(startup));
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startup.StartupInfo.wShowWindow = SW_SHOW;
        startup.StartupInfo.hStdInput = stdinPipe;
        startup.StartupInfo.hStdOutput = nullOutput;
        startup.StartupInfo.hStdError = nullOutput;
        startup.lpAttributeList = attributes;
        if (!CreateProcessA(packedPath, command, NULL, NULL, TRUE,
                            EXTENDED_STARTUPINFO_PRESENT, NULL, exeDir,
                            &startup.StartupInfo, &process)) {
            MessageBoxA(NULL, "Venice could not start the protected application.",
                        "Venice Launch Error", MB_ICONERROR);
            goto cleanup;
        }
    }

    if (WaitForSingleObject(process.hProcess, INFINITE) != WAIT_OBJECT_0) {
        MessageBoxA(NULL, "Venice lost contact with the protected application.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }
    {
        DWORD exitCode = 1;
        if (!GetExitCodeProcess(process.hProcess, &exitCode)) goto cleanup;
        result = (int)exitCode;
    }

cleanup:
    if (attributes) {
        DeleteProcThreadAttributeList(attributes);
        HeapFree(GetProcessHeap(), 0, attributes);
    }
    if (packedFile != INVALID_HANDLE_VALUE) CloseHandle(packedFile);
    if (nullOutput != INVALID_HANDLE_VALUE) CloseHandle(nullOutput);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (process.hThread) CloseHandle(process.hThread);
    SecureZeroMemory(command, sizeof(command));
    SecureZeroMemory(packedPath, sizeof(packedPath));
    SecureZeroMemory(exeDir, sizeof(exeDir));
    return result;
}
