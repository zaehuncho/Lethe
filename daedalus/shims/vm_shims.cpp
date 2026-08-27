/*
 * vm_shims.cpp -- Daedalus VM shim implementations.
 *
 * Flat C ABI wrappers around Win32 + Qt + project APIs, callable from
 * Daedalus bytecode via N_CALL_PTR.  Links against:
 *   Qt6::Core, Qt6::Network, crypt32.lib, advapi32.lib
 */

#include "vm_shims.h"

#include <windows.h>
#include <wincrypt.h>

#include <QByteArray>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QSysInfo>

#include "Ed25519.h"   // orion::ed25519Verify

#include <cstring>
#include <cstdlib>

/* -----------------------------------------------------------------------
 * Identity shims
 * --------------------------------------------------------------------- */

extern "C" int vm_get_hostname(char *buf, uint32_t bufsize)
{
    if (!buf || bufsize == 0)
        return 0;

    DWORD size = static_cast<DWORD>(bufsize);
    if (!GetComputerNameA(buf, &size))
        return 0;

    return static_cast<int>(size);
}

extern "C" int vm_get_machine_guid(char *buf, uint32_t bufsize)
{
    if (!buf || bufsize == 0)
        return 0;

    HKEY hKey = nullptr;
    LONG rc = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography",
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &hKey);
    if (rc != ERROR_SUCCESS)
        return 0;

    wchar_t wbuf[128];
    DWORD wbufSize = sizeof(wbuf);
    DWORD type = 0;
    rc = RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type,
                          reinterpret_cast<LPBYTE>(wbuf), &wbufSize);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS || type != REG_SZ)
        return 0;

    /* Convert wide string to UTF-8 via Qt for reliability. */
    QByteArray utf8 = QString::fromWCharArray(wbuf).toUtf8();
    if (utf8.isEmpty())
        return 0;

    uint32_t copyLen = static_cast<uint32_t>(utf8.size());
    if (copyLen >= bufsize)
        copyLen = bufsize - 1;

    std::memcpy(buf, utf8.constData(), copyLen);
    buf[copyLen] = '\0';

    return static_cast<int>(copyLen);
}

extern "C" int vm_get_machine_unique_id(uint8_t *buf, uint32_t bufsize)
{
    if (!buf || bufsize == 0)
        return 0;

    QByteArray id = QSysInfo::machineUniqueId();
    if (id.isEmpty())
        return 0;

    uint32_t copyLen = static_cast<uint32_t>(id.size());
    if (copyLen > bufsize)
        copyLen = bufsize;

    std::memcpy(buf, id.constData(), copyLen);
    return static_cast<int>(copyLen);
}

extern "C" int vm_get_username(char *buf, uint32_t bufsize)
{
    if (!buf || bufsize == 0)
        return 0;

    /* Primary: Win32 GetUserNameA. */
    DWORD size = static_cast<DWORD>(bufsize);
    if (GetUserNameA(buf, &size)) {
        /* size includes the null terminator; return chars without it. */
        return (size > 0) ? static_cast<int>(size - 1) : 0;
    }

    /* Fallback 1: %USERNAME% */
    const char *env = std::getenv("USERNAME");
    if (!env || *env == '\0') {
        /* Fallback 2: %USER% (POSIX-ish) */
        env = std::getenv("USER");
    }
    if (!env || *env == '\0')
        return 0;

    uint32_t len = static_cast<uint32_t>(std::strlen(env));
    if (len >= bufsize)
        len = bufsize - 1;

    std::memcpy(buf, env, len);
    buf[len] = '\0';
    return static_cast<int>(len);
}

/* -----------------------------------------------------------------------
 * Hashing shims
 * --------------------------------------------------------------------- */

extern "C" int vm_sha256_self_exe(uint8_t out[32])
{
    if (!out)
        return 1;

    QString path = QCoreApplication::applicationFilePath();
    if (path.isEmpty())
        return 1;

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return 1;

    QCryptographicHash hash(QCryptographicHash::Sha256);

    /* Stream in 64 KiB chunks to keep memory bounded. */
    constexpr qint64 kChunk = 65536;
    while (!file.atEnd()) {
        QByteArray chunk = file.read(kChunk);
        if (chunk.isEmpty())
            break;
        hash.addData(chunk);
    }
    file.close();

    QByteArray digest = hash.result();
    if (digest.size() != 32)
        return 1;

    std::memcpy(out, digest.constData(), 32);
    return 0;
}

extern "C" int vm_sha256_buf(const void *data, uint32_t len, uint8_t out[32])
{
    if (!out)
        return 1;
    if (!data && len > 0)
        return 1;

    QByteArray digest = QCryptographicHash::hash(
        QByteArrayView(static_cast<const char *>(data), static_cast<qsizetype>(len)),
        QCryptographicHash::Sha256);

    if (digest.size() != 32)
        return 1;

    std::memcpy(out, digest.constData(), 32);
    return 0;
}

/* -----------------------------------------------------------------------
 * DPAPI shims
 * --------------------------------------------------------------------- */

extern "C" int vm_dpapi_protect(const uint8_t *in, uint32_t in_len,
                                const uint8_t *entropy, uint32_t ent_len,
                                uint8_t *out, uint32_t out_max)
{
    if (!in || !out || out_max == 0)
        return -1;

    DATA_BLOB plainBlob;
    plainBlob.pbData = const_cast<BYTE *>(in);
    plainBlob.cbData = static_cast<DWORD>(in_len);

    DATA_BLOB entropyBlob;
    DATA_BLOB *pEntropy = nullptr;
    if (entropy && ent_len > 0) {
        entropyBlob.pbData = const_cast<BYTE *>(entropy);
        entropyBlob.cbData = static_cast<DWORD>(ent_len);
        pEntropy = &entropyBlob;
    }

    DATA_BLOB cipherBlob;
    std::memset(&cipherBlob, 0, sizeof(cipherBlob));

    BOOL ok = CryptProtectData(
        &plainBlob,
        nullptr,          /* description */
        pEntropy,
        nullptr,          /* reserved */
        nullptr,          /* prompt struct */
        CRYPTPROTECT_UI_FORBIDDEN,
        &cipherBlob);

    if (!ok)
        return -1;

    int result;
    if (cipherBlob.cbData <= out_max) {
        std::memcpy(out, cipherBlob.pbData, cipherBlob.cbData);
        result = static_cast<int>(cipherBlob.cbData);
    } else {
        result = -1;
    }

    LocalFree(cipherBlob.pbData);
    return result;
}

extern "C" int vm_dpapi_unprotect(const uint8_t *in, uint32_t in_len,
                                  const uint8_t *entropy, uint32_t ent_len,
                                  uint8_t *out, uint32_t out_max)
{
    if (!in || !out || out_max == 0)
        return -1;

    DATA_BLOB cipherBlob;
    cipherBlob.pbData = const_cast<BYTE *>(in);
    cipherBlob.cbData = static_cast<DWORD>(in_len);

    DATA_BLOB entropyBlob;
    DATA_BLOB *pEntropy = nullptr;
    if (entropy && ent_len > 0) {
        entropyBlob.pbData = const_cast<BYTE *>(entropy);
        entropyBlob.cbData = static_cast<DWORD>(ent_len);
        pEntropy = &entropyBlob;
    }

    DATA_BLOB plainBlob;
    std::memset(&plainBlob, 0, sizeof(plainBlob));

    BOOL ok = CryptUnprotectData(
        &cipherBlob,
        nullptr,          /* description out */
        pEntropy,
        nullptr,          /* reserved */
        nullptr,          /* prompt struct */
        CRYPTPROTECT_UI_FORBIDDEN,
        &plainBlob);

    if (!ok)
        return -1;

    int result;
    if (plainBlob.cbData <= out_max) {
        std::memcpy(out, plainBlob.pbData, plainBlob.cbData);
        result = static_cast<int>(plainBlob.cbData);
    } else {
        result = -1;
    }

    if (plainBlob.pbData) {
        SecureZeroMemory(plainBlob.pbData, plainBlob.cbData);
        LocalFree(plainBlob.pbData);
    }
    return result;
}

/* -----------------------------------------------------------------------
 * Encoding shims
 * --------------------------------------------------------------------- */

extern "C" int vm_base64url_decode(const char *in, uint32_t in_len,
                                   uint8_t *out, uint32_t out_max)
{
    if (!in || !out || out_max == 0)
        return -1;

    QByteArray encoded = QByteArray::fromRawData(in, static_cast<int>(in_len));
    QByteArray decoded = QByteArray::fromBase64(
        encoded,
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    if (decoded.isEmpty() && in_len > 0)
        return -1;

    uint32_t copyLen = static_cast<uint32_t>(decoded.size());
    if (copyLen > out_max)
        return -1;

    std::memcpy(out, decoded.constData(), copyLen);
    return static_cast<int>(copyLen);
}

/* -----------------------------------------------------------------------
 * Crypto shims
 * --------------------------------------------------------------------- */

extern "C" int vm_ed25519_verify(const uint8_t pk[32], const uint8_t *msg,
                                 uint32_t msg_len, const uint8_t sig[64])
{
    if (!pk || !sig)
        return 0;
    if (!msg && msg_len > 0)
        return 0;

    QByteArray pubKey = QByteArray::fromRawData(
        reinterpret_cast<const char *>(pk), 32);
    QByteArray message = QByteArray::fromRawData(
        reinterpret_cast<const char *>(msg),
        static_cast<int>(msg_len));
    QByteArray signature = QByteArray::fromRawData(
        reinterpret_cast<const char *>(sig), 64);

    return orion::ed25519Verify(pubKey, message, signature) ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * VmExternals init
 * --------------------------------------------------------------------- */

extern "C" void vm_externals_init(VmExternals *ext)
{
    if (!ext)
        return;

    ext->get_hostname         = vm_get_hostname;
    ext->get_machine_guid     = vm_get_machine_guid;
    ext->get_machine_unique_id = vm_get_machine_unique_id;
    ext->get_username          = vm_get_username;
    ext->sha256_self_exe       = vm_sha256_self_exe;
    ext->sha256_buf            = vm_sha256_buf;
    ext->dpapi_protect         = vm_dpapi_protect;
    ext->dpapi_unprotect       = vm_dpapi_unprotect;
    ext->base64url_decode      = vm_base64url_decode;
    ext->ed25519_verify        = vm_ed25519_verify;
}
