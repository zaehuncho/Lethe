/*
 * Lethe shard bootstrap — tiny launcher shim.
 *
 * This executable sits next to protected.exe. On launch it:
 *   1. Computes the signing-stable PE content ID used as build_id
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
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#define SHARD_HOST      L"shard.example.invalid"
#define SHARD_PATH      L"/api/shard/fetch"
#define PACKED_EXE_NAME "protected.exe"
#define SETTINGS_FILE   "settings.json"

static int read_exact_at(HANDLE file, ULONGLONG offset, void *buf, DWORD size)
{
    LARGE_INTEGER pos;
    DWORD bytes_read = 0;
    pos.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(file, pos, NULL, FILE_BEGIN)) return -1;
    if (!ReadFile(file, buf, size, &bytes_read, NULL) || bytes_read != size)
        return -1;
    return 0;
}

static int hash_file_range(HANDLE file, BCRYPT_HASH_HANDLE hash,
                           ULONGLONG offset, ULONGLONG length)
{
    BYTE buf[65536];
    LARGE_INTEGER pos;
    pos.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(file, pos, NULL, FILE_BEGIN)) return -1;

    while (length > 0) {
        DWORD want = (length > sizeof(buf)) ? (DWORD)sizeof(buf) : (DWORD)length;
        DWORD bytes_read = 0;
        if (!ReadFile(file, buf, want, &bytes_read, NULL) || bytes_read != want)
            return -1;
        if (BCryptHashData(hash, buf, bytes_read, 0) != 0)
            return -1;
        length -= bytes_read;
    }
    return 0;
}

/* SHA-256 over the PE while excluding the mutable checksum, certificate-table
 * directory entry, and Authenticode certificate bytes. This content ID is
 * stable before/after signing and matches packer.orchestrator._pe_content_id. */
static int pe_content_id(HANDLE hFile, char *hex_out)
{
    LARGE_INTEGER file_size_li;
    IMAGE_DOS_HEADER dos;
    DWORD signature = 0;
    IMAGE_FILE_HEADER file_header;
    IMAGE_OPTIONAL_HEADER64 optional_header;
    BYTE digest[32] = {0};
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    int ret = -1;

    if (!GetFileSizeEx(hFile, &file_size_li) || file_size_li.QuadPart <= 0)
        goto done;
    if (read_exact_at(hFile, 0, &dos, sizeof(dos)) != 0 ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
        goto done;

    ULONGLONG nt_off = (ULONGLONG)(DWORD)dos.e_lfanew;
    if (read_exact_at(hFile, nt_off, &signature, sizeof(signature)) != 0 ||
        signature != IMAGE_NT_SIGNATURE)
        goto done;
    if (read_exact_at(hFile, nt_off + sizeof(signature), &file_header,
                      sizeof(file_header)) != 0)
        goto done;
    if (file_header.Machine != IMAGE_FILE_MACHINE_AMD64)
        goto done;

    ULONGLONG optional_off = nt_off + sizeof(signature) + sizeof(file_header);
    size_t security_member_off = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
        IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY);
    if (file_header.SizeOfOptionalHeader < security_member_off +
            sizeof(IMAGE_DATA_DIRECTORY) ||
        file_header.SizeOfOptionalHeader > sizeof(optional_header))
        goto done;
    ZeroMemory(&optional_header, sizeof(optional_header));
    if (read_exact_at(hFile, optional_off, &optional_header,
                      file_header.SizeOfOptionalHeader) != 0 ||
        optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        optional_header.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY)
        goto done;

    ULONGLONG checksum_off = optional_off +
        offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum);
    ULONGLONG security_dir_off = optional_off + security_member_off;
    ULONGLONG after_security_dir = security_dir_off + sizeof(IMAGE_DATA_DIRECTORY);
    ULONGLONG cert_off = optional_header.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    ULONGLONG cert_size = optional_header.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    ULONGLONG file_size = (ULONGLONG)file_size_li.QuadPart;
    ULONGLONG cert_end = cert_off + cert_size;

    if ((cert_off == 0) != (cert_size == 0)) goto done;
    if (checksum_off + sizeof(DWORD) > security_dir_off ||
        after_security_dir > file_size)
        goto done;
    if (cert_off && (cert_off < after_security_dir || cert_end < cert_off ||
                     cert_end > file_size))
        goto done;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        goto done;
    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) != 0)
        goto done;

    if (hash_file_range(hFile, hash, 0, checksum_off) != 0 ||
        hash_file_range(hFile, hash, checksum_off + sizeof(DWORD),
                        security_dir_off - checksum_off - sizeof(DWORD)) != 0)
        goto done;
    if (cert_off) {
        if (hash_file_range(hFile, hash, after_security_dir,
                            cert_off - after_security_dir) != 0 ||
            hash_file_range(hFile, hash, cert_end, file_size - cert_end) != 0)
            goto done;
    } else if (hash_file_range(hFile, hash, after_security_dir,
                               file_size - after_security_dir) != 0) {
        goto done;
    }

    if (BCryptFinishHash(hash, digest, 32, 0) != 0)
        goto done;

    for (int i = 0; i < 32; i++)
        sprintf(hex_out + i * 2, "%02x", digest[i]);
    hex_out[64] = '\0';
    ret = 0;

done:
    SecureZeroMemory(digest, sizeof(digest));
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ret;
}

static int read_license_key(const char *dir, char *key_out, size_t key_max)
{
    char path[MAX_PATH] = {0};
    HANDLE hFile = INVALID_HANDLE_VALUE;
    char *data = NULL;
    size_t dataSize = 0;
    int result = -1;
    LARGE_INTEGER size = {0};

    if (!dir || !key_out || key_max < 2) return -1;
    SecureZeroMemory(key_out, key_max);
    int pathChars = snprintf(path, sizeof(path), "%s\\%s", dir, SETTINGS_FILE);
    if (pathChars < 0 || (size_t)pathChars >= sizeof(path)) goto done;

    hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto done;

    if (!GetFileSizeEx(hFile, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 1024 * 1024) goto done;
    dataSize = (size_t)size.QuadPart + 1;

    data = (char *)malloc(dataSize);
    if (!data) goto done;
    ZeroMemory(data, dataSize);

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, data, (DWORD)size.QuadPart, &bytesRead, NULL) ||
        bytesRead != (DWORD)size.QuadPart) goto done;
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;
    data[bytesRead] = '\0';

    const char *needle = "\"license_key\"";
    char *pos = strstr(data, needle);
    if (!pos) goto done;
    pos += strlen(needle);
    while (*pos && (*pos == ' ' || *pos == ':' || *pos == '\t')) pos++;
    if (*pos != '"') goto done;
    pos++;
    char *end = strchr(pos, '"');
    if (!end || (size_t)(end - pos) >= key_max) goto done;

    memcpy(key_out, pos, (size_t)(end - pos));
    key_out[end - pos] = '\0';
    result = 0;

done:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (data) {
        SecureZeroMemory(data, dataSize);
        free(data);
    }
    SecureZeroMemory(path, sizeof(path));
    if (result != 0) SecureZeroMemory(key_out, key_max);
    return result;
}

static int compute_hwid(char *hwid_out, size_t hwid_max)
{
    if (!hwid_out || hwid_max < 65) return -1;

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
    if (BCryptFinishHash(hash, digest, 32, 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return -1;
    }
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
    char body[768] = {0};
    char response[1024] = {0};
    HINTERNET session = NULL;
    HINTERNET connect = NULL;
    HINTERNET request = NULL;
    int result = -1;

    if (!build_id || !license_key || !hwid || !shard_out)
        goto done;
    SecureZeroMemory(shard_out, 65);

    const unsigned char *license_char = (const unsigned char *)license_key;
    if (!*license_char) goto done;
    for (; *license_char; ++license_char) {
        if (*license_char < 0x21 || *license_char > 0x7e ||
            *license_char == '"' || *license_char == '\\')
            goto done;
    }

    int body_chars = snprintf(
        body, sizeof(body),
        "{\"build_id\":\"%s\",\"license_key\":\"%s\",\"hwid\":\"%s\"}",
        build_id, license_key, hwid);
    if (body_chars < 0 || (size_t)body_chars >= sizeof(body)) goto done;

    session = WinHttpOpen(L"LetheShardBootstrap/0.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) goto done;
    if (!WinHttpSetTimeouts(session, 10000, 10000, 15000, 15000)) goto done;

    connect = WinHttpConnect(session, SHARD_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connect) goto done;

    request = WinHttpOpenRequest(connect, L"POST", SHARD_PATH,
                                 NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 WINHTTP_FLAG_SECURE);
    if (!request) goto done;
    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY,
                          &redirect_policy, sizeof(redirect_policy))) goto done;

    const wchar_t *headers = L"Content-Type: application/json\r\n";
    DWORD bodyLen = (DWORD)body_chars;
    if (!WinHttpSendRequest(request, headers, (DWORD)-1, body, bodyLen, bodyLen, 0) ||
        !WinHttpReceiveResponse(request, NULL)) goto done;

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (!WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             NULL, &statusCode, &statusSize, NULL)) goto done;

    DWORD totalRead = 0;
    for (;;) {
        DWORD bytesRead = 0;
        DWORD capacity = (DWORD)(sizeof(response) - totalRead - 1);
        if (capacity == 0) {
            result = -2;
            goto done;
        }
        if (!WinHttpReadData(request, response + totalRead, capacity, &bytesRead))
            goto done;
        if (bytesRead == 0) break;
        totalRead += bytesRead;
    }
    response[totalRead] = '\0';

    if (statusCode != 200) {
        result = statusCode ? (int)statusCode : -1;
        goto done;
    }

    const char *shard_key = "\"shard\"";
    char *pos = strstr(response, shard_key);
    if (!pos) {
        result = -2;
        goto done;
    }
    pos += strlen(shard_key);
    while (*pos && (*pos == ' ' || *pos == ':')) pos++;
    if (*pos != '"') {
        result = -2;
        goto done;
    }
    pos++;
    char *end = strchr(pos, '"');
    if (!end || (end - pos) != 64) {
        result = -2;
        goto done;
    }
    for (char *p = pos; p < end; ++p) {
        if (!isxdigit((unsigned char)*p)) {
            result = -2;
            goto done;
        }
    }
    memcpy(shard_out, pos, 64);
    shard_out[64] = '\0';
    result = 0;

done:
    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    if (session) WinHttpCloseHandle(session);
    if (result != 0 && shard_out) SecureZeroMemory(shard_out, 65);
    SecureZeroMemory(body, sizeof(body));
    SecureZeroMemory(response, sizeof(response));
    return result;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    char exeDir[MAX_PATH] = {0};
    char packedPath[MAX_PATH] = {0};
    char cmdLine[MAX_PATH + 3] = {0};
    char buildId[65] = {0};
    char launchBuildId[65] = {0};
    char licenseKey[256] = {0};
    char hwid[65] = {0};
    char shard[65] = {0};
    HANDLE packedFile = INVALID_HANDLE_VALUE;
    BOOL gateSet = FALSE;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    int result = 1;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    ZeroMemory(&pi, sizeof(pi));

    DWORD exeLength = GetModuleFileNameA(NULL, exeDir, MAX_PATH);
    if (exeLength == 0 || exeLength >= MAX_PATH || !PathRemoveFileSpecA(exeDir)) {
        MessageBoxA(NULL, "Failed to resolve bootstrap directory.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }
    int pathChars = snprintf(
        packedPath, sizeof(packedPath), "%s\\%s", exeDir, PACKED_EXE_NAME);
    if (pathChars < 0 || (size_t)pathChars >= sizeof(packedPath)) {
        MessageBoxA(NULL, "Packed executable path is too long.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    /* Keep a deny-write/deny-delete handle open from content-ID calculation
     * through CreateProcess. This closes the hash-to-execution pathname swap. */
    packedFile = CreateFileA(packedPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (packedFile == INVALID_HANDLE_VALUE) {
        MessageBoxA(NULL, "protected.exe not found next to bootstrap.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    if (pe_content_id(packedFile, buildId) != 0) {
        MessageBoxA(NULL, "Failed to compute build content ID.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    if (read_license_key(exeDir, licenseKey, sizeof(licenseKey)) != 0) {
        MessageBoxA(NULL, "License key not found in settings.json.\n"
                    "Please activate the protected application first.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    if (compute_hwid(hwid, sizeof(hwid)) != 0) {
        MessageBoxA(NULL, "Failed to compute hardware ID.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }

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
        MessageBoxA(NULL, msg, "Lethe Launch Error", MB_ICONERROR);
        SecureZeroMemory(msg, sizeof(msg));
        goto cleanup;
    }

    /* Re-hash the same locked handle after the network round trip. */
    if (pe_content_id(packedFile, launchBuildId) != 0 ||
        memcmp(buildId, launchBuildId, sizeof(buildId)) != 0) {
        MessageBoxA(NULL, "Packed executable changed before launch.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    if (!SetEnvironmentVariableA("NV_RT_GATE", shard)) {
        MessageBoxA(NULL, "Failed to prepare the runtime gate.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }
    gateSet = TRUE;
    SecureZeroMemory(shard, sizeof(shard));
    SecureZeroMemory(licenseKey, sizeof(licenseKey));

    int commandChars = snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", packedPath);
    if (commandChars < 0 || (size_t)commandChars >= sizeof(cmdLine)) {
        MessageBoxA(NULL, "Packed executable command line is too long.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    if (!CreateProcessA(packedPath, cmdLine, NULL, NULL, FALSE,
                        0, NULL, exeDir, &si, &pi)) {
        MessageBoxA(NULL, "Failed to launch protected.exe.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    CloseHandle(packedFile);
    packedFile = INVALID_HANDLE_VALUE;
    SetEnvironmentVariableA("NV_RT_GATE", NULL);
    gateSet = FALSE;

    if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
        MessageBoxA(NULL, "Failed while waiting for protected.exe.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
        MessageBoxA(NULL, "Failed to read protected.exe exit status.",
                    "Lethe Launch Error", MB_ICONERROR);
        goto cleanup;
    }
    result = (int)exitCode;

cleanup:
    if (gateSet) SetEnvironmentVariableA("NV_RT_GATE", NULL);
    if (packedFile != INVALID_HANDLE_VALUE) CloseHandle(packedFile);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    SecureZeroMemory(shard, sizeof(shard));
    SecureZeroMemory(licenseKey, sizeof(licenseKey));
    SecureZeroMemory(hwid, sizeof(hwid));
    SecureZeroMemory(buildId, sizeof(buildId));
    SecureZeroMemory(launchBuildId, sizeof(launchBuildId));
    SecureZeroMemory(cmdLine, sizeof(cmdLine));
    return result;
}
