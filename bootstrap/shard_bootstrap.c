/*
 * Lethe shard bootstrap — tiny launcher shim.
 *
 * This exe sits next to the packed OrionNative.exe. On launch it:
 *   1. SHA-256 hashes the packed exe to get the build_id
 *   2. Reads the license key from settings.json
 *   3. Computes the HWID (matches SecurityManager::machineId)
 *   4. POSTs to the shard gate Worker (/api/shard/fetch)
 *   5. Sets NV_RT_GATE env var
 *   6. Spawns the packed exe (inherits env, forwards exit code)
 *
 * Compiled with CRT (not freestanding) — this is a build tool, not the stub.
 * Links: kernel32 bcrypt winhttp advapi32 shlwapi
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#define SHARD_HOST      L"api.zaeorion.com"
#define SHARD_PATH      L"/api/shard/fetch"
#define PACKED_EXE_NAME "OrionNative.exe"
#define SETTINGS_FILE   "settings.json"

static int sha256_file(const char *path, char *hex_out)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    int ret = -1;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        goto done;
    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) != 0)
        goto done;

    BYTE buf[65536];
    DWORD bytesRead;
    while (ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL) && bytesRead > 0) {
        if (BCryptHashData(hash, buf, bytesRead, 0) != 0)
            goto done;
    }

    BYTE digest[32];
    if (BCryptFinishHash(hash, digest, 32, 0) != 0)
        goto done;

    for (int i = 0; i < 32; i++)
        sprintf(hex_out + i * 2, "%02x", digest[i]);
    hex_out[64] = '\0';
    ret = 0;

done:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(hFile);
    return ret;
}

static int read_license_key(const char *dir, char *key_out, size_t key_max)
{
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\%s", dir, SETTINGS_FILE);

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    LARGE_INTEGER size;
    GetFileSizeEx(hFile, &size);
    if (size.QuadPart > 1024 * 1024) { CloseHandle(hFile); return -1; }

    char *data = (char *)malloc((size_t)size.QuadPart + 1);
    if (!data) { CloseHandle(hFile); return -1; }

    DWORD bytesRead;
    ReadFile(hFile, data, (DWORD)size.QuadPart, &bytesRead, NULL);
    CloseHandle(hFile);
    data[bytesRead] = '\0';

    const char *needle = "\"license_key\"";
    char *pos = strstr(data, needle);
    if (!pos) { free(data); return -1; }
    pos += strlen(needle);
    while (*pos && (*pos == ' ' || *pos == ':' || *pos == '\t')) pos++;
    if (*pos != '"') { free(data); return -1; }
    pos++;
    char *end = strchr(pos, '"');
    if (!end || (size_t)(end - pos) >= key_max) { free(data); return -1; }

    memcpy(key_out, pos, (size_t)(end - pos));
    key_out[end - pos] = '\0';
    free(data);
    return 0;
}

static int compute_hwid(char *hwid_out, size_t hwid_max)
{
    (void)hwid_max;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return -1;
    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }

    /* Component 1: hostname (matches QSysInfo::machineHostName) */
    char computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD compSize = sizeof(computer);
    if (GetComputerNameA(computer, &compSize))
        BCryptHashData(hash, (PUCHAR)computer, compSize, 0);
    BCryptHashData(hash, (PUCHAR)"|", 1, 0);

    /* Component 2: SMBIOS UUID from firmware (matches QSysInfo::machineUniqueId).
       GetSystemFirmwareTable('RSMB') returns the raw SMBIOS table; the UUID is
       in the System Information structure (type 1) at offset 0x08, 16 bytes. */
    {
        DWORD smbiosSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
        if (smbiosSize > 0 && smbiosSize < 65536) {
            BYTE *smbios = (BYTE *)malloc(smbiosSize);
            if (smbios && GetSystemFirmwareTable('RSMB', 0, smbios, smbiosSize) == smbiosSize) {
                DWORD offset = 8;  /* skip RawSMBIOSData header */
                while (offset + 4 < smbiosSize) {
                    BYTE type = smbios[offset];
                    BYTE len  = smbios[offset + 1];
                    if (type == 1 && len >= 0x19 && offset + 0x18 < smbiosSize) {
                        BCryptHashData(hash, smbios + offset + 0x08, 16, 0);
                        break;
                    }
                    /* skip to next structure: past formatted area + string table */
                    DWORD next = offset + len;
                    while (next + 1 < smbiosSize &&
                           !(smbios[next] == 0 && smbios[next + 1] == 0))
                        next++;
                    next += 2;
                    if (next <= offset + len) break;
                    offset = next;
                }
            }
            free(smbios);
        }
    }
    BCryptHashData(hash, (PUCHAR)"|", 1, 0);

    /* Component 3: Windows MachineGuid from registry (per-install, survives reboots;
       matches SecurityManager::registryValueMachineGuid) */
    {
        HKEY key = NULL;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                          "SOFTWARE\\Microsoft\\Cryptography",
                          0, KEY_READ | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS) {
            char guid[256] = {0};
            DWORD guidSize = sizeof(guid);
            if (RegQueryValueExA(key, "MachineGuid", NULL, NULL,
                                 (LPBYTE)guid, &guidSize) == ERROR_SUCCESS && guidSize > 0) {
                BCryptHashData(hash, (PUCHAR)guid, guidSize - 1, 0);
            }
            RegCloseKey(key);
        }
    }

    BYTE digest[32];
    BCryptFinishHash(hash, digest, 32, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    for (int i = 0; i < 32; i++)
        sprintf(hwid_out + i * 2, "%02x", digest[i]);
    hwid_out[64] = '\0';
    return 0;
}

static int fetch_shard(const char *build_id, const char *license_key,
                       const char *hwid, char *shard_out)
{
    char body[512];
    snprintf(body, sizeof(body),
             "{\"build_id\":\"%s\",\"license_key\":\"%s\",\"hwid\":\"%s\"}",
             build_id, license_key, hwid);

    HINTERNET session = WinHttpOpen(L"OrionBootstrap/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return -1;

    HINTERNET connect = WinHttpConnect(session, SHARD_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connect) { WinHttpCloseHandle(session); return -1; }

    HINTERNET request = WinHttpOpenRequest(connect, L"POST", SHARD_PATH,
                                           NULL, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           WINHTTP_FLAG_SECURE);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return -1;
    }

    const wchar_t *headers = L"Content-Type: application/json\r\n";
    DWORD bodyLen = (DWORD)strlen(body);
    if (!WinHttpSendRequest(request, headers, (DWORD)-1, body, bodyLen, bodyLen, 0) ||
        !WinHttpReceiveResponse(request, NULL)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return -1;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        NULL, &statusCode, &statusSize, NULL);

    char response[1024] = {0};
    DWORD totalRead = 0;
    DWORD bytesRead;
    while (WinHttpReadData(request, response + totalRead,
                           sizeof(response) - totalRead - 1, &bytesRead) && bytesRead > 0) {
        totalRead += bytesRead;
        if (totalRead >= sizeof(response) - 1) break;
    }
    response[totalRead] = '\0';

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    if (statusCode != 200) return (int)statusCode;

    const char *shard_key = "\"shard\"";
    char *pos = strstr(response, shard_key);
    if (!pos) return -2;
    pos += strlen(shard_key);
    while (*pos && (*pos == ' ' || *pos == ':')) pos++;
    if (*pos != '"') return -2;
    pos++;
    char *end = strchr(pos, '"');
    if (!end || (end - pos) != 64) return -2;
    memcpy(shard_out, pos, 64);
    shard_out[64] = '\0';

    SecureZeroMemory(response, sizeof(response));
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    char exeDir[MAX_PATH];
    GetModuleFileNameA(NULL, exeDir, MAX_PATH);
    PathRemoveFileSpecA(exeDir);

    char packedPath[MAX_PATH];
    snprintf(packedPath, sizeof(packedPath), "%s\\%s", exeDir, PACKED_EXE_NAME);

    if (GetFileAttributesA(packedPath) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxA(NULL, "OrionNative.exe not found next to bootstrap.",
                    "Orion Launch Error", MB_ICONERROR);
        return 1;
    }

    char buildId[65];
    if (sha256_file(packedPath, buildId) != 0) {
        MessageBoxA(NULL, "Failed to compute build hash.",
                    "Orion Launch Error", MB_ICONERROR);
        return 1;
    }

    char licenseKey[256] = {0};
    if (read_license_key(exeDir, licenseKey, sizeof(licenseKey)) != 0) {
        MessageBoxA(NULL, "License key not found in settings.json.\n"
                    "Please activate Orion first.",
                    "Orion Launch Error", MB_ICONERROR);
        return 1;
    }

    char hwid[65];
    if (compute_hwid(hwid, sizeof(hwid)) != 0) {
        MessageBoxA(NULL, "Failed to compute hardware ID.",
                    "Orion Launch Error", MB_ICONERROR);
        return 1;
    }

    char shard[65];
    int fetchResult = fetch_shard(buildId, licenseKey, hwid, shard);
    if (fetchResult != 0) {
        char msg[256];
        if (fetchResult == 403)
            snprintf(msg, sizeof(msg), "License validation failed (403).\nPlease check your license.");
        else if (fetchResult == 429)
            snprintf(msg, sizeof(msg), "Too many launch attempts. Please try again later.");
        else if (fetchResult == 404)
            snprintf(msg, sizeof(msg), "Build not recognized by server (404).");
        else
            snprintf(msg, sizeof(msg), "Failed to contact license server (error %d).\n"
                     "Please check your internet connection.", fetchResult);
        MessageBoxA(NULL, msg, "Orion Launch Error", MB_ICONERROR);
        SecureZeroMemory(shard, sizeof(shard));
        SecureZeroMemory(licenseKey, sizeof(licenseKey));
        return 1;
    }

    SetEnvironmentVariableA("NV_RT_GATE", shard);
    SecureZeroMemory(shard, sizeof(shard));
    SecureZeroMemory(licenseKey, sizeof(licenseKey));

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    ZeroMemory(&pi, sizeof(pi));

    char cmdLine[MAX_PATH + 3];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", packedPath);

    if (!CreateProcessA(packedPath, cmdLine, NULL, NULL, FALSE,
                        0, NULL, exeDir, &si, &pi)) {
        SetEnvironmentVariableA("NV_RT_GATE", NULL);
        MessageBoxA(NULL, "Failed to launch OrionNative.exe.",
                    "Orion Launch Error", MB_ICONERROR);
        return 1;
    }

    SetEnvironmentVariableA("NV_RT_GATE", NULL);

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exitCode;
}
