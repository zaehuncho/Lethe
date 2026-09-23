/*
 * Lethe shard bootstrap — tiny launcher shim.
 *
 * This executable is shipped as OrionNative.exe beside OrionNative.packed.exe.
 * On launch it:
 *   1. Computes the signing-stable PE content ID used as build_id
 *   2. Reads a DPAPI-protected customer session written by the signed launcher
 *   3. Uses the exact persisted machine_id from /api/activate (no second HWID derivation)
 *   4. POSTs to /api/shard/retrieve with the revocable customer bearer
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
#include <wincrypt.h>
#include <shlwapi.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")

#define SHARD_HOST      L"api.zaeorion.com"
#define SHARD_PATH      L"/api/shard/retrieve"
#define PACKED_EXE_NAME "OrionNative.packed.exe"
#define SESSION_FILE    "NexusVision\\Orion Native\\.vault\\shard_session.dat"

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

static int json_string_field(const char *json, const char *field,
                             char *out, size_t out_size)
{
    char needle[96] = {0};
    if (!json || !field || !out || out_size < 2) return -1;
    if (snprintf(needle, sizeof(needle), "\"%s\"", field) < 0) return -1;
    const char *pos = strstr(json, needle);
    if (!pos) return -1;
    pos += strlen(needle);
    while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
    if (*pos++ != '"') return -1;
    const char *end = strchr(pos, '"');
    if (!end || end == pos || (size_t)(end - pos) >= out_size) return -1;
    for (const char *p = pos; p < end; ++p) {
        if ((unsigned char)*p < 0x21 || (unsigned char)*p > 0x7e ||
            *p == '\\') return -1;
    }
    memcpy(out, pos, (size_t)(end - pos));
    out[end - pos] = '\0';
    return 0;
}

static int is_hex_string(const char *value, size_t exact_length)
{
    if (!value || strlen(value) != exact_length) return 0;
    for (size_t i = 0; i < exact_length; ++i)
        if (!isxdigit((unsigned char)value[i])) return 0;
    return 1;
}

/* The signed outer launcher writes this record only after /api/activate. The
 * bootstrap never derives a second HWID and never reads a plaintext license key. */
static int read_session_credential(char *token, size_t token_size,
                                   char *token_id, size_t token_id_size,
                                   char *machine_id, size_t machine_id_size)
{
    char local_appdata[MAX_PATH] = {0};
    char path[MAX_PATH * 2] = {0};
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE *encrypted = NULL;
    DATA_BLOB input = {0};
    DATA_BLOB output = {0};
    LARGE_INTEGER size = {0};
    int result = -1;

    if (!token || !token_id || !machine_id) return -1;
    SecureZeroMemory(token, token_size);
    SecureZeroMemory(token_id, token_id_size);
    SecureZeroMemory(machine_id, machine_id_size);
    DWORD chars = GetEnvironmentVariableA(
        "LOCALAPPDATA", local_appdata, (DWORD)sizeof(local_appdata));
    if (chars == 0 || chars >= sizeof(local_appdata)) goto done;
    int path_chars = snprintf(path, sizeof(path), "%s\\%s", local_appdata, SESSION_FILE);
    if (path_chars < 0 || (size_t)path_chars >= sizeof(path))
        goto done;

    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) goto done;
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 16 * 1024) goto done;
    encrypted = (BYTE *)malloc((size_t)size.QuadPart);
    if (!encrypted) goto done;
    DWORD bytes_read = 0;
    if (!ReadFile(file, encrypted, (DWORD)size.QuadPart, &bytes_read, NULL) ||
        bytes_read != (DWORD)size.QuadPart) goto done;
    input.pbData = encrypted;
    input.cbData = bytes_read;
    if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL,
                            CRYPTPROTECT_UI_FORBIDDEN, &output)) goto done;
    if (!output.pbData || output.cbData == 0 || output.cbData > 4096) goto done;

    char json[4097] = {0};
    memcpy(json, output.pbData, output.cbData);
    if (json_string_field(json, "token", token, token_size) != 0 ||
        json_string_field(json, "token_id", token_id, token_id_size) != 0 ||
        json_string_field(json, "machine_id", machine_id, machine_id_size) != 0 ||
        !is_hex_string(machine_id, 64)) {
        SecureZeroMemory(json, sizeof(json));
        goto done;
    }
    SecureZeroMemory(json, sizeof(json));
    result = 0;

done:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (output.pbData) {
        SecureZeroMemory(output.pbData, output.cbData);
        LocalFree(output.pbData);
    }
    if (encrypted) {
        SecureZeroMemory(encrypted, (size_t)size.QuadPart);
        free(encrypted);
    }
    SecureZeroMemory(local_appdata, sizeof(local_appdata));
    SecureZeroMemory(path, sizeof(path));
    if (result != 0) {
        SecureZeroMemory(token, token_size);
        SecureZeroMemory(token_id, token_id_size);
        SecureZeroMemory(machine_id, machine_id_size);
    }
    return result;
}

/* [SERVER-SHARD blocker #5, Codex finding #1] Issuer-SPKI certificate pin for the
 * shard-retrieve TLS call. This is the SAME issuer-key pin set the Venice license
 * client and OrionActivate broker enforce (see native_orion/src/PinnedSpki.h in
 * the NexusVision repo). This is a SEPARATE repo and C, so the hex values are
 * duplicated here by hand — KEEP THEM BYTE-IDENTICAL to PinnedSpki.h if the pin
 * set is ever rotated. Pinning the stable INTERMEDIATE key (not the rotating
 * leaf) survives Cloudflare's ~90-day leaf renewals yet fails CLOSED against a
 * rogue/edge MITM cert. WinHTTP's normal hostname+chain validation still runs
 * first; this narrows the trusted CA set. */
static const char *const kApiPinnedSpki[] = {
    "908769e8d34477cc2cba0632c88605b22d7294c0840f78596d247c645b1afc0e", /* GTS WE1 */
    "be1efc292835472e0d6aa183575d30fdc4dbf551f7050519a0258d6bddd6fc46", /* GTS WE2 */
    "9847e5653e5e9e847516e5cb818606aa7544a19be67fd7366d506988e8d84347", /* GTS Root R4 */
    "3586d4ecf070578cbd27aedce20b964e48bc149faeb9dad72f46b857869172b8", /* LE E5 */
    "d016e1fe311948aca64f2de44ce86c9a51ca041df6103bb52a88eb3f761f57d7", /* LE E6 */
    "cbbc559b44d524d6a132bdac672744da3407f12aae5d5f722c5f6c7913871c75", /* LE E7 */
    "885bf0572252c6741dc9a52f5044487fef2a93b811cdedfad7624cc283b7cdd5", /* LE E8 */
    "f1440a9b76e1e41e53a4cb461329bf6337b419726be513e42e19f1c691c5d4b2", /* LE E9 */
    "2bbad93ab5c79279ec121507f272cbe0c6647a3aae52e22f388afab426b4adba", /* LE R10 */
    "6ddac18698f7f1f7e1c69b9bce420d974ac6f94ca8b2c761701623f99c767dc7", /* LE R11 */
    "919c0df7a787b597ed056ace654b1de9c0387acf349f73734a4fd7b58cf612a4", /* LE R12 */
    "025490860b498ab73c6a12f27a49ad5fe230fafe3ac8f6112c9b7d0aad46941d", /* LE R13 */
    "f1647a5ee3efac54c892e930584fe47979b7acd1c76c1271bca1c5076d869888", /* LE R14 */
};

static int spki_sha256_hex(const unsigned char *der, DWORD len, char out[65])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    unsigned char digest[32];
    static const char *hexchars = "0123456789abcdef";
    int ok = 0;
    if (!der || len == 0) return 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0 &&
        BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) == 0 &&
        BCryptHashData(hash, (PUCHAR)der, len, 0) == 0 &&
        BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
        DWORD i;
        for (i = 0; i < sizeof(digest); ++i) {
            out[i * 2]     = hexchars[(digest[i] >> 4) & 0x0f];
            out[i * 2 + 1] = hexchars[digest[i] & 0x0f];
        }
        out[64] = '\0';
        ok = 1;
    }
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    SecureZeroMemory(digest, sizeof(digest));
    return ok;
}

static int cert_spki_pinned(PCCERT_CONTEXT cert)
{
    DWORD der = 0;
    unsigned char *blob = NULL;
    char hex[65];
    size_t i;
    int matched = 0;
    if (!cert || !cert->pCertInfo) return 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                             &cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL,
                             NULL, &der) || der == 0)
        return 0;
    blob = (unsigned char *)malloc(der);
    if (!blob) return 0;
    if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                            &cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL,
                            blob, &der) &&
        spki_sha256_hex(blob, der, hex)) {
        for (i = 0; i < sizeof(kApiPinnedSpki) / sizeof(kApiPinnedSpki[0]); ++i) {
            if (strcmp(hex, kApiPinnedSpki[i]) == 0) { matched = 1; break; }
        }
    }
    free(blob);
    return matched;
}

/* Returns 1 iff SOME cert in the server's verified chain carries a pinned issuer
 * SPKI. FAILS CLOSED (0) on any read/build failure or no match. */
static int verify_server_spki_pin(HINTERNET request)
{
    PCCERT_CONTEXT leaf = NULL;
    DWORD leaf_size = sizeof(leaf);
    PCCERT_CHAIN_CONTEXT chain = NULL;
    CERT_CHAIN_PARA chain_para;
    int matched = 0;

    if (!WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                            &leaf, &leaf_size) || !leaf)
        return 0;

    ZeroMemory(&chain_para, sizeof(chain_para));
    chain_para.cbSize = sizeof(chain_para);
    if (CertGetCertificateChain(NULL, leaf, NULL, leaf->hCertStore, &chain_para,
                                0, NULL, &chain) &&
        chain && chain->cChain > 0 && chain->rgpChain[0]) {
        DWORD e;
        const CERT_SIMPLE_CHAIN *simple = chain->rgpChain[0];
        for (e = 0; e < simple->cElement; ++e) {
            if (cert_spki_pinned(simple->rgpElement[e]->pCertContext)) {
                matched = 1;
                break;
            }
        }
    }
    if (chain) CertFreeCertificateChain(chain);
    CertFreeCertificateContext(leaf);
    return matched;
}

static int fetch_shard(const char *build_id, const char *token,
                       const char *token_id, const char *machine_id,
                       char *shard_out, char *error_out, size_t error_size)
{
    char body[768] = {0};
    char response[1024] = {0};
    char header_utf8[768] = {0};
    wchar_t headers[768] = {0};
    HINTERNET session = NULL;
    HINTERNET connect = NULL;
    HINTERNET request = NULL;
    int result = -1;

    if (!build_id || !token || !token_id || !machine_id || !shard_out ||
        !error_out || error_size < 2)
        goto done;
    SecureZeroMemory(shard_out, 65);
    SecureZeroMemory(error_out, error_size);

    const unsigned char *token_char = (const unsigned char *)token;
    if (!*token_char) goto done;
    for (; *token_char; ++token_char) {
        if (*token_char < 0x21 || *token_char > 0x7e ||
            *token_char == '"' || *token_char == '\\')
            goto done;
    }

    int body_chars = snprintf(
        body, sizeof(body),
        "{\"build_id\":\"%s\",\"machine_id\":\"%s\"}",
        build_id, machine_id);
    if (body_chars < 0 || (size_t)body_chars >= sizeof(body)) goto done;
    int header_chars = snprintf(
        header_utf8, sizeof(header_utf8),
        "Content-Type: application/json\r\n"
        "Authorization: Bearer %s\r\n"
        "X-Orion-Token-Id: %s\r\n",
        token, token_id);
    if (header_chars < 0 || (size_t)header_chars >= sizeof(header_utf8)) goto done;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, header_utf8, -1,
                            headers, (int)(sizeof(headers) / sizeof(headers[0]))) <= 0)
        goto done;

    session = WinHttpOpen(L"LetheShardBootstrap/0.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) goto done;
    if (!WinHttpSetTimeouts(session, 10000, 10000, 15000, 15000)) goto done;
    DWORD secure_protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
    secure_protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
    if (!WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS,
                          &secure_protocols, sizeof(secure_protocols))) goto done;

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

    DWORD bodyLen = (DWORD)body_chars;
    if (!WinHttpSendRequest(request, headers, (DWORD)-1, body, bodyLen, bodyLen, 0) ||
        !WinHttpReceiveResponse(request, NULL)) goto done;

    /* [Codex finding #1] Enforce the issuer-SPKI pin BEFORE reading the body. A
     * pin failure aborts (fail closed) — no shard is parsed off an unpinned TLS
     * session. */
    if (!verify_server_spki_pin(request)) goto done;

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
        if (json_string_field(response, "error", error_out, error_size) != 0)
            snprintf(error_out, error_size, "http_%lu", statusCode);
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
    SecureZeroMemory(header_utf8, sizeof(header_utf8));
    SecureZeroMemory(headers, sizeof(headers));
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
    char token[256] = {0};
    char tokenId[96] = {0};
    char machineId[65] = {0};
    char shard[65] = {0};
    char shardError[96] = {0};
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
        MessageBoxA(NULL, "The protected Venice application is missing. Reinstall Venice.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    if (pe_content_id(packedFile, buildId) != 0) {
        MessageBoxA(NULL, "Venice could not validate this installation. Reinstall Venice.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    if (read_session_credential(token, sizeof(token), tokenId, sizeof(tokenId),
                                machineId, sizeof(machineId)) != 0) {
        MessageBoxA(NULL, "Connect Discord at zaeorion.com/connect, then reopen Venice.\n\n"
                    "A fresh install needs the signed Venice activation broker before "
                    "server-shard mode can ship.",
                    "Venice Sign-In Required", MB_ICONINFORMATION);
        goto cleanup;
    }

    int fetchResult = -1;
    for (;;) {
        fetchResult = fetch_shard(buildId, token, tokenId, machineId,
                                  shard, shardError, sizeof(shardError));
        if (fetchResult == 0) break;
        char msg[256];
        if (strcmp(shardError, "machine_mismatch") == 0)
            snprintf(msg, sizeof(msg), "This subscription is linked to another PC.\n"
                     "Use /hwid_reset in Discord, then select Retry.");
        else if (strcmp(shardError, "build_revoked") == 0 ||
                 strcmp(shardError, "build_expired") == 0 ||
                 strcmp(shardError, "build_not_found") == 0)
            snprintf(msg, sizeof(msg), "This Venice build is no longer available.\n"
                     "Update Venice before trying again.");
        else if (strcmp(shardError, "rate_limited") == 0)
            snprintf(msg, sizeof(msg), "Too many launch attempts.\n"
                     "Wait one minute, then select Retry.");
        else if (strcmp(shardError, "license_revoked") == 0 ||
                 strcmp(shardError, "license_inactive") == 0 ||
                 strcmp(shardError, "license_expired") == 0 ||
                 strcmp(shardError, "subscription_required") == 0 ||
                 strcmp(shardError, "token_expired") == 0 ||
                 strcmp(shardError, "invalid_token") == 0 ||
                 strcmp(shardError, "missing_token") == 0)
            snprintf(msg, sizeof(msg), "Your Venice access is not active.\n"
                     "Subscribe at zaeorion.com or open a Discord ticket.");
        else
            snprintf(msg, sizeof(msg), "Can't reach Venice servers.\n"
                     "Check your connection, then select Retry.");
        int choice = MessageBoxA(NULL, msg, "Venice Launch Error",
                                 MB_ICONERROR | MB_RETRYCANCEL);
        SecureZeroMemory(msg, sizeof(msg));
        if (choice != IDRETRY) goto cleanup;
    }

    /* Re-hash the same locked handle after the network round trip. */
    if (pe_content_id(packedFile, launchBuildId) != 0 ||
        memcmp(buildId, launchBuildId, sizeof(buildId)) != 0) {
        MessageBoxA(NULL, "Venice changed before launch. Reinstall Venice.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    if (!SetEnvironmentVariableA("NV_RT_GATE", shard)) {
        MessageBoxA(NULL, "Venice could not prepare the protected runtime.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }
    gateSet = TRUE;
    SecureZeroMemory(shard, sizeof(shard));
    SecureZeroMemory(token, sizeof(token));

    int commandChars = snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", packedPath);
    if (commandChars < 0 || (size_t)commandChars >= sizeof(cmdLine)) {
        MessageBoxA(NULL, "Venice command line is too long.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    if (!CreateProcessA(packedPath, cmdLine, NULL, NULL, FALSE,
                        0, NULL, exeDir, &si, &pi)) {
        MessageBoxA(NULL, "Venice could not start the protected application.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    CloseHandle(packedFile);
    packedFile = INVALID_HANDLE_VALUE;
    SetEnvironmentVariableA("NV_RT_GATE", NULL);
    gateSet = FALSE;

    if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
        MessageBoxA(NULL, "Venice lost contact with the protected application.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
        MessageBoxA(NULL, "Venice could not read the application exit status.",
                    "Venice Launch Error", MB_ICONERROR);
        goto cleanup;
    }
    result = (int)exitCode;

cleanup:
    if (gateSet) SetEnvironmentVariableA("NV_RT_GATE", NULL);
    if (packedFile != INVALID_HANDLE_VALUE) CloseHandle(packedFile);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    SecureZeroMemory(shard, sizeof(shard));
    SecureZeroMemory(token, sizeof(token));
    SecureZeroMemory(tokenId, sizeof(tokenId));
    SecureZeroMemory(machineId, sizeof(machineId));
    SecureZeroMemory(shardError, sizeof(shardError));
    SecureZeroMemory(buildId, sizeof(buildId));
    SecureZeroMemory(launchBuildId, sizeof(launchBuildId));
    SecureZeroMemory(cmdLine, sizeof(cmdLine));
    return result;
}
