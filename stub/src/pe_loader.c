#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stddef.h>

#include "pe_loader.h"
#include "crypto.h"
#include "stub_hooks.h"
#include "key_scatter.h"
#include "tls_anchor.h"
#include "miniz.h"
#include "venice_vm.h"
#include "venice_programs.h"

#include "stub_intrin.h"

#define RELOC_ABSOLUTE 0
#define RELOC_DIR64    10
#define RELOC_FILTER_ALL      0
#define RELOC_FILTER_EXEC     1
#define RELOC_FILTER_NONEXEC  2

/* ---- helpers (no CRT) --------------------------------------------------- */

static void pl_zero(void *p, size_t n)
{
    volatile uint8_t *d = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++) d[i] = 0;
}

static DWORD chars_to_prot(uint32_t c)
{
    int x = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
    int w = (c & IMAGE_SCN_MEM_WRITE)   != 0;
    if (x)      return PAGE_EXECUTE_READ;   /* never RWX — drop W when X */
    if (w)      return PAGE_READWRITE;
    return PAGE_READONLY;
}

/* ---- decrypt + decompress one section ----------------------------------- */

static int decrypt_section(const uint8_t key[32], uint8_t *base,
                           const SectionDesc *sd, uint32_t target_bound,
                           uint32_t stored_bound)
{
    uint8_t *scratch;
    mz_ulong dlen;
    int rc;

    if (sd->stored_size == 0 || sd->uncompressed_size == 0)
        return 0;
    if (sd->uncompressed_size > sd->virtual_size)
        return 1;
    /* L1: the inflate target must lie within the original image region, and the
       stored ciphertext must lie within the full packed image (it lives in the
       grafted payload section beyond original_size_of_image). */
    if ((uint64_t)sd->rva + sd->virtual_size > target_bound)
        return 1;
    if ((uint64_t)sd->stored_rva + sd->stored_size > stored_bound)
        return 1;

    scratch = (uint8_t *)VirtualAlloc(NULL, sd->stored_size,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!scratch)
        return 1;
    VirtualLock(scratch, sd->stored_size);

    {
        uint32_t rva_aad = sd->rva;
        rc = crypto_aes256gcm_decrypt(key, sd->gcm_nonce,
                                      base + sd->stored_rva, sd->stored_size,
                                      sd->gcm_tag, scratch,
                                      &rva_aad, sizeof(rva_aad));
    }
    if (rc != 0) {
        VirtualFree(scratch, 0, MEM_RELEASE);
        return 1;
    }

    dlen = (mz_ulong)sd->uncompressed_size;
    rc = mz_uncompress((unsigned char *)(base + sd->rva), &dlen,
                       (const unsigned char *)scratch, (mz_ulong)sd->stored_size);

    pl_zero(scratch, sd->stored_size);
    VirtualFree(scratch, 0, MEM_RELEASE);

    return (rc == MZ_OK && dlen == (mz_ulong)sd->uncompressed_size) ? 0 : 1;
}

/* Best-effort wipe of the stored ciphertext in the payload section. */
static void wipe_stored(uint8_t *base, const SectionDesc *sd)
{
    DWORD old = 0, tmp = 0;
    uint8_t *p;
    if (sd->stored_size == 0)
        return;
    p = base + sd->stored_rva;
    if (!VirtualProtect(p, sd->stored_size, PAGE_READWRITE, &old))
        return;
    __stosb(p, 0, sd->stored_size);
    VirtualProtect(p, sd->stored_size, old, &tmp);
}

/* ---- hash-based import resolution --------------------------------------- */

/* FNV-1a hash with avalanche mixing.  MUST match the Python builder's
   _import_hash() in container.py exactly (same offset basis, prime, and
   final XOR-shift).  Changing either side without the other will silently
   break every packed binary. */
static uint32_t import_hash(const char *s)
{
    uint32_t h = 0x811c9dc5u;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x01000193u;
    }
    h ^= h >> 16;
    return h;
}

/* Hash a Unicode module name from the PEB, lowered to ASCII.  System module
   names (kernel32.dll, ntdll.dll, ...) are pure ASCII; the low byte of each
   WCHAR is the character, the high byte is zero. */
static uint32_t hash_unicode_lower(const wchar_t *s, uint32_t char_count)
{
    uint32_t h = 0x811c9dc5u;
    uint32_t i;
    for (i = 0; i < char_count; i++) {
        uint8_t c = (uint8_t)s[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= c;
        h *= 0x01000193u;
    }
    h ^= h >> 16;
    return h;
}

/* Walk PEB -> Ldr -> InMemoryOrderModuleList to find a loaded module whose
   BaseDllName hashes (lowered) to target_hash.  Returns DllBase or NULL. */
static void *find_module_by_hash(uint32_t target_hash)
{
    uint8_t *peb, *ldr;
    LIST_ENTRY *head, *cur;

    peb = (uint8_t *)__readgsqword(0x60);          /* x64 PEB */
    if (!peb) return NULL;
    ldr = *(uint8_t **)(peb + 0x18);               /* PEB.Ldr */
    if (!ldr) return NULL;
    head = (LIST_ENTRY *)(ldr + 0x20);              /* InMemoryOrderModuleList */
    cur = head->Flink;

    while (cur != head) {
        /* cur = &entry->InMemoryOrderLinks (offset 0x10 in LDR_DATA_TABLE_ENTRY).
           DllBase is at entry + 0x30; BaseDllName.Length at entry + 0x58;
           BaseDllName.Buffer at entry + 0x60 (UNICODE_STRING on x64). */
        uint8_t *entry = (uint8_t *)cur - 0x10;
        void    *dll_base = *(void **)(entry + 0x30);
        uint16_t name_len = *(uint16_t *)(entry + 0x58);   /* bytes */
        wchar_t *name_buf = *(wchar_t **)(entry + 0x60);

        if (dll_base && name_buf && name_len > 0) {
            uint32_t h = hash_unicode_lower(name_buf,
                                            name_len / sizeof(wchar_t));
            if (h == 0) h = 1;             /* match builder's zero-avoidance */
            if (h == target_hash)
                return dll_base;
        }
        cur = cur->Flink;
    }
    return NULL;
}

/* Forward declaration: resolve_export and resolve_forwarder are mutually
   recursive (a named export may forward to another DLL). */
static FARPROC resolve_export(void *mod_base, uint32_t func_hash,
                               uint16_t ordinal, int by_hash, int depth);

/* Resolve a PE export forwarder string ("DLL.FuncName" or "DLL.#ordinal"). */
static FARPROC resolve_forwarder(const char *fwd, int depth)
{
    char dll_lower[260];
    const char *dot;
    int dll_len, i;
    uint32_t dll_hash;
    void *mod;
    FARPROC result = NULL;

    if (depth > 5 || !fwd)
        return NULL;

    /* Locate the '.' separator */
    dot = fwd;
    while (*dot && *dot != '.') dot++;
    if (!*dot) return NULL;

    dll_len = (int)(dot - fwd);
    if (dll_len <= 0 || dll_len >= 250) return NULL;

    /* Lowercase DLL name + append ".dll" for PEB matching */
    for (i = 0; i < dll_len; i++) {
        char c = fwd[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        dll_lower[i] = c;
    }
    dll_lower[dll_len]   = '.';
    dll_lower[dll_len+1] = 'd';
    dll_lower[dll_len+2] = 'l';
    dll_lower[dll_len+3] = 'l';
    dll_lower[dll_len+4] = '\0';

    dll_hash = import_hash(dll_lower);
    if (dll_hash == 0) dll_hash = 1;
    mod = find_module_by_hash(dll_hash);

    if (!mod) {
        /* Try without .dll extension */
        dll_lower[dll_len] = '\0';
        dll_hash = import_hash(dll_lower);
        if (dll_hash == 0) dll_hash = 1;
        mod = find_module_by_hash(dll_hash);
    }

    if (!mod) {
        /* Last resort: LoadLibraryA (handles API-set redirection) */
        dll_lower[dll_len]   = '.';
        dll_lower[dll_len+1] = 'd';
        dll_lower[dll_len+2] = 'l';
        dll_lower[dll_len+3] = 'l';
        dll_lower[dll_len+4] = '\0';
        mod = (void *)LoadLibraryA(dll_lower);
    }

    __stosb((uint8_t *)dll_lower, 0, sizeof(dll_lower));   /* wipe */
    if (!mod) return NULL;

    /* Parse the function part after the dot */
    {
        const char *func = dot + 1;
        if (*func == '#') {
            uint16_t ord = 0;
            func++;
            while (*func >= '0' && *func <= '9') {
                ord = (uint16_t)(ord * 10 + (*func - '0'));
                func++;
            }
            result = resolve_export(mod, 0, ord, 0, depth);
        } else {
            result = resolve_export(mod, import_hash(func), 0, 1, depth);
        }
    }
    return result;
}

/* Walk a module's export directory to resolve a function by name hash or by
   ordinal.  Handles forwarder exports (recursion capped at depth 5). */
static FARPROC resolve_export(void *mod_base, uint32_t func_hash,
                               uint16_t ordinal, int by_hash, int depth)
{
    uint8_t *base = (uint8_t *)mod_base;
    uint32_t e_lfanew, export_rva, export_size;
    IMAGE_EXPORT_DIRECTORY *exp;
    uint32_t *funcs;
    uint32_t func_rva = 0;

    if (!base || depth > 5)
        return NULL;

    /* DOS / PE header validation */
    if (*(uint16_t *)base != 0x5A4D)           return NULL;   /* "MZ" */
    e_lfanew = *(uint32_t *)(base + 0x3C);
    if (*(uint32_t *)(base + e_lfanew) != 0x00004550)  return NULL;   /* "PE\0\0" */

    /* PE32+ data directory[0] = export table.  Optional header starts at
       e_lfanew + 4 (sig) + 20 (COFF) = e_lfanew + 0x18.  DataDirectory[0]
       is at optional_header + 0x70 = e_lfanew + 0x88. */
    export_rva  = *(uint32_t *)(base + e_lfanew + 0x88);
    export_size = *(uint32_t *)(base + e_lfanew + 0x8C);
    if (export_rva == 0)
        return NULL;

    exp   = (IMAGE_EXPORT_DIRECTORY *)(base + export_rva);
    funcs = (uint32_t *)(base + exp->AddressOfFunctions);

    if (by_hash) {
        uint32_t *names = (uint32_t *)(base + exp->AddressOfNames);
        uint16_t *ords  = (uint16_t *)(base + exp->AddressOfNameOrdinals);
        uint32_t i;
        int found = 0;
        for (i = 0; i < exp->NumberOfNames; i++) {
            const char *name = (const char *)(base + names[i]);
            if (import_hash(name) == func_hash) {
                uint32_t idx = ords[i];
                if (idx >= exp->NumberOfFunctions) return NULL;
                func_rva = funcs[idx];
                found = 1;
                break;
            }
        }
        if (!found) return NULL;
    } else {
        /* Ordinal resolution */
        uint32_t idx = (uint32_t)ordinal - exp->Base;
        if (idx >= exp->NumberOfFunctions) return NULL;
        func_rva = funcs[idx];
    }

    if (func_rva == 0)
        return NULL;

    /* Forwarder: the function RVA falls inside the export directory itself */
    if (func_rva >= export_rva && func_rva < export_rva + export_size)
        return resolve_forwarder((const char *)(base + func_rva), depth + 1);

    return (FARPROC)(base + func_rva);
}

/* ---- import resolution (public entry) ----------------------------------- */

static int resolve_imports(uint8_t *base, const uint8_t *blob, uint32_t blob_size,
                           uint32_t image_size)
{
    uint32_t pos = 0;
    uint32_t enc_pool_size;
    const uint8_t *enc_pool;

    if (blob_size < 8)
        return 0;   /* no imports */

    /* Encrypted string pool (XOR'd DLL name fallback for LoadLibraryA) */
    enc_pool_size = *(const uint32_t *)(blob + pos);
    pos += 4;
    if (enc_pool_size > blob_size - pos)
        return 1;
    enc_pool = blob + pos;
    pos += enc_pool_size;

    /* Import entries, terminated by dll_name_hash == 0 */
    while (1) {
        uint32_t dll_hash, enc_offset, func_count;
        uint8_t  xor_key;
        void    *hmod;
        uint32_t f;

        if (pos + 4 > blob_size)
            return 1;
        dll_hash = *(const uint32_t *)(blob + pos);
        if (dll_hash == 0)
            break;                         /* terminator */
        pos += 4;

        /* Entry header: u8 xor_key, u32 enc_offset, u32 func_count = 9 B */
        if (pos + 9 > blob_size)
            return 1;
        xor_key    = *(blob + pos);                        pos += 1;
        enc_offset = *(const uint32_t *)(blob + pos);      pos += 4;
        func_count = *(const uint32_t *)(blob + pos);      pos += 4;

        /* 1. PEB walk: find already-loaded module by hash */
        hmod = find_module_by_hash(dll_hash);

        if (!hmod) {
            /* 2. Fallback: decrypt DLL name, LoadLibraryA, wipe */
            char dll_name[260];
            uint32_t name_len = 0, j;

            if (enc_offset >= enc_pool_size)
                return 1;

            /* Scan for end marker (byte == xor_key, i.e. encrypted NUL) */
            while (enc_offset + name_len < enc_pool_size &&
                   enc_pool[enc_offset + name_len] != xor_key)
                name_len++;

            if (name_len == 0 || name_len >= sizeof(dll_name))
                return 1;

            for (j = 0; j < name_len; j++)
                dll_name[j] = (char)(enc_pool[enc_offset + j] ^ xor_key);
            dll_name[name_len] = '\0';

            hmod = (void *)LoadLibraryA(dll_name);
            __stosb((uint8_t *)dll_name, 0, sizeof(dll_name));

            if (!hmod)
                return 1;
        }

        /* 3. Resolve each function via export-directory walk */
        for (f = 0; f < func_count; f++) {
            uint32_t iat_rva, func_name_hash;
            uint16_t hint_or_ordinal;
            FARPROC  proc;

            if (pos + 10 > blob_size)      /* u32 + u16 + u32 = 10 */
                return 1;
            iat_rva         = *(const uint32_t *)(blob + pos);  pos += 4;
            hint_or_ordinal = *(const uint16_t *)(blob + pos);  pos += 2;
            func_name_hash  = *(const uint32_t *)(blob + pos);  pos += 4;

            if ((uint64_t)iat_rva + 8 > image_size)
                return 1;

            if (hint_or_ordinal == LETHE_IMPORT_BY_HASH) {
                proc = resolve_export(hmod, func_name_hash, 0, 1, 0);
            } else {
                proc = resolve_export(hmod, 0, hint_or_ordinal, 0, 0);
            }

            if (!proc)
                return 1;

            *(uint64_t *)(base + iat_rva) = (uint64_t)(uintptr_t)proc;
        }
    }
    return 0;
}

/* ---- base relocations --------------------------------------------------- */

static int reloc_target_matches_filter(uint64_t target_off,
                                       const SectionDesc *secs,
                                       uint32_t sec_count, int filter)
{
    uint32_t i;
    if (filter == RELOC_FILTER_ALL)
        return 1;
    for (i = 0; i < sec_count; ++i) {
        uint64_t begin = secs[i].rva;
        uint64_t end = begin + secs[i].virtual_size;
        if (target_off >= begin && target_off + 8u <= end) {
            int is_exec =
                (secs[i].characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            return filter == RELOC_FILTER_EXEC ? is_exec : !is_exec;
        }
    }
    /* Header relocations are never guarded, so they belong to the eager pass. */
    return filter == RELOC_FILTER_NONEXEC;
}

static int apply_relocs(uint8_t *base, const uint8_t *data, uint32_t size,
                        int64_t delta, uint32_t image_size,
                        const SectionDesc *secs, uint32_t sec_count,
                        int filter)
{
    uint32_t pos = 0;
    while (pos + 8 <= size) {
        uint32_t page_rva   = *(const uint32_t *)(data + pos);
        uint32_t block_size = *(const uint32_t *)(data + pos + 4);
        uint32_t entry_count, i;
        const uint16_t *entries;

        if (block_size < 8 || block_size > size - pos ||
            ((block_size - 8u) & 1u) != 0)
            return 1;

        entry_count = (block_size - 8) / 2;
        entries = (const uint16_t *)(data + pos + 8);

        for (i = 0; i < entry_count; i++) {
            uint16_t type   = entries[i] >> 12;
            uint16_t offset = entries[i] & 0x0FFF;

            if (type == RELOC_DIR64) {
                uint64_t target_off = (uint64_t)page_rva + offset;
                if (target_off + 8 > image_size)
                    continue;
                if (!reloc_target_matches_filter(target_off, secs, sec_count,
                                                 filter))
                    continue;
                int64_t *target = (int64_t *)(base + target_off);
                *target += delta;
            }
            /* RELOC_ABSOLUTE (0) is padding — skip. */
        }
        pos += block_size;
    }
    return pos == size ? 0 : 1;
}

/* ---- TLS ---------------------------------------------------------------- */

static uint8_t *s_tls_base      = NULL;
static uint32_t s_tls_raw_start = 0;
static uint32_t s_tls_raw_size  = 0;
static uint32_t s_tls_total_size = 0;
static DWORD    s_tls_slot      = 0;
static int      s_tls_active    = 0;

static int invoke_tls_callbacks(uint8_t *base, const uint8_t *blob,
                               uint32_t blob_size, uint32_t image_size)
{
    uint32_t cb_count, i;
    const uint32_t *cb_rvas;

    if (blob_size < 20)
        return 1;
    cb_count = *(const uint32_t *)(blob + 16);
    if (blob_size < 20 + (uint64_t)cb_count * 4)
        return 1;
    cb_rvas = (const uint32_t *)(blob + 20);

    for (i = 0; i < cb_count; i++) {
        if (cb_rvas[i] >= image_size)
            return 1;
        PIMAGE_TLS_CALLBACK cb =
            (PIMAGE_TLS_CALLBACK)(base + cb_rvas[i]);
        cb(base, DLL_PROCESS_ATTACH, NULL);
    }
    return 0;
}

static int setup_tls(uint8_t *base, const uint8_t *blob,
                     uint32_t blob_size, uint32_t image_size,
                     int is_dll)
{
    uint32_t index_rva, raw_start, raw_end, zero_fill, cb_count;
    uint32_t raw_size, total_size;
    const uint32_t *cb_rvas;
    void **tls_array;
    uint8_t *tls_data;
    DWORD tls_slot;

    (void)is_dll;

    if (blob_size < 20)
        return 1;

    index_rva = *(const uint32_t *)(blob);
    raw_start = *(const uint32_t *)(blob + 4);
    raw_end   = *(const uint32_t *)(blob + 8);
    zero_fill = *(const uint32_t *)(blob + 12);
    cb_count  = *(const uint32_t *)(blob + 16);

    if (blob_size < 20 + (uint64_t)cb_count * 4)
        return 1;
    cb_rvas   = (const uint32_t *)(blob + 20);

    if (raw_end < raw_start)
        return 1;
    if ((uint64_t)index_rva + 4 > image_size)
        return 1;

    raw_size = raw_end - raw_start;

    /* FIX 2: compute the TLS block size in 64-bit. total_size is uint32_t, so
       raw_size + zero_fill could wrap on a hostile/corrupt zero_fill, making
       HeapAlloc undersize the buffer that __movsb(raw_size) below then
       overflows. Reject anything larger than the image (a sane cap) before we
       allocate. After the check the sum fits in uint32_t. */
    {
        uint64_t total = (uint64_t)raw_size + zero_fill;
        if (total > image_size || total > ORION_STUB_TLS_CAPACITY)
            return 1;
        total_size = (uint32_t)total;
    }

    if (raw_size > 0 && (uint64_t)raw_start + raw_size > image_size)
        return 1;

    /* The grafted stub's TLS directory makes Windows reserve this slot and a
     * 4 KiB block on every thread. Never scan beyond the loader-owned vector:
     * TLS_MINIMUM_AVAILABLE applies to TlsAlloc slots, not this static array. */
    tls_slot = lethe_stub_tls_index();
    tls_array = (void **)__readgsqword(0x58);
    if (!tls_array || !tls_array[tls_slot])
        return 1;
    tls_data = (uint8_t *)tls_array[tls_slot];
    __stosb(tls_data, 0, ORION_STUB_TLS_CAPACITY);
    if (raw_size > 0)
        __movsb(tls_data, base + raw_start, raw_size);

    *(DWORD *)(base + index_rva) = tls_slot;
    tls_array[tls_slot] = tls_data;

    s_tls_base      = base;
    s_tls_raw_start = raw_start;
    s_tls_raw_size  = raw_size;
    s_tls_total_size = total_size;
    s_tls_slot      = tls_slot;
    s_tls_active    = 1;
    return 0;
}

/* ---- diagnostic (stripped in non-debug builds) -------------------------- */

#ifdef LETHE_DIAG
static void diag_hex(char *buf, int *pos, uint64_t v)
{
    static const char hex[] = "0123456789ABCDEF";
    int i;
    for (i = 60; i >= 0; i -= 4) {
        uint8_t nibble = (uint8_t)((v >> i) & 0xF);
        if (nibble || *pos > 0 || i == 0)
            buf[(*pos)++] = hex[nibble];
    }
    if (*pos == 0) buf[(*pos)++] = '0';
}

static void diag_write(int step)
{
    HANDLE h = CreateFileA("lethe_diag.txt", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[16];
        DWORD w;
        int len = 0;
        buf[len++] = '0' + (step / 10) % 10;
        buf[len++] = '0' + step % 10;
        buf[len++] = '\r';
        buf[len++] = '\n';
        WriteFile(h, buf, (DWORD)len, &w, NULL);
        CloseHandle(h);
    }
}

static void diag_dump(int step, uint64_t a, uint64_t b, uint64_t c)
{
    HANDLE h = CreateFileA("lethe_diag.txt", FILE_APPEND_DATA, 0, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[128];
        DWORD w;
        int len = 0;
        buf[len++] = 'S'; buf[len++] = '=';
        buf[len++] = '0' + (step / 10) % 10;
        buf[len++] = '0' + step % 10;
        buf[len++] = ' '; buf[len++] = 'A'; buf[len++] = '=';
        diag_hex(buf, &len, a);
        buf[len++] = ' '; buf[len++] = 'B'; buf[len++] = '=';
        diag_hex(buf, &len, b);
        buf[len++] = ' '; buf[len++] = 'C'; buf[len++] = '=';
        diag_hex(buf, &len, c);
        buf[len++] = '\r'; buf[len++] = '\n';
        WriteFile(h, buf, (DWORD)len, &w, NULL);
        CloseHandle(h);
    }
}
#define DIAG(n) diag_write(n)
#define DIAG3(n, a, b, c) diag_dump(n, (uint64_t)(a), (uint64_t)(b), (uint64_t)(c))
#else
#define DIAG(n) ((void)0)
#define DIAG3(n, a, b, c) ((void)0)
#endif

/* ---- main loader entry -------------------------------------------------- */

int pe_loader_run(void *image_base, volatile PackInfo *pi, void **out_oep)
{
    uint8_t *base = (uint8_t *)image_base;
    const PackInfo *cpi = (const PackInfo *)pi;
    uint8_t key[32];
    uint8_t *meta_dec  = NULL;   /* decrypted (still compressed) metadata */
    uint8_t *meta_buf  = NULL;   /* decompressed metadata                */
    SectionDesc *secs;
    mz_ulong dlen;
    int mg_want, mg_ok = 0;
    int64_t reloc_delta;
    uint32_t i;
    int rc;

    *out_oep = NULL;
    DIAG(1);

    /* The packed image is larger than the original: stub sections and the payload
       section are grafted beyond original_size_of_image. Read the PACKED image's
       SizeOfImage from its PE header so we can bounds-check those regions.
       PE32+: e_lfanew + 4 (sig) + 20 (COFF) + 56 (OptHdr.SizeOfImage). */
    uint32_t packed_image_size;
    {
        uint32_t e_lfanew = *(const uint32_t *)(base + 0x3C);
        packed_image_size = *(const uint32_t *)(base + e_lfanew + 0x50);
    }
    reloc_delta = (int64_t)(uintptr_t)base -
                  (int64_t)cpi->original_image_base;

    /* L6: crypto_derive_key hashes [base + stub_text_rva, stub_text_size] to
       bind the key to the stub's own code. The stub .text lives in the grafted
       region, so validate against packed_image_size (not original). */
    if ((uint64_t)cpi->stub_text_rva + cpi->stub_text_size > packed_image_size)
        return 1;

    /* 1. derive the code-hash-bound AES key. */
    if (crypto_derive_key(cpi, image_base, key))
        return 1;

    /* Server shard gate: the launcher passes a 32-byte shard (hex-encoded,
       64 hex chars) via the NV_RT_GATE environment variable. The builder XOR'd
       this shard 1:1 into aes_key_enc at pack time, so without it the derived
       key is wrong and every GCM auth check will fail. If the env var is absent
       the key stays as-is. */
    {
        /* Shard fetch/hex-decode/XOR/wipe/unset now lives in Venice VM bytecode
           (VVM_PROG_SHARD_XOR); the VM performs the GetEnvironmentVariableA,
           hex decode, in-place key XOR, SetEnvironmentVariableA(NULL) and local
           wipe via native ops. See venice_programs.h. */
        uint64_t shard_args[1];
        shard_args[0] = (uint64_t)(uintptr_t)key;
        venice_vm_exec(VVM_PROG_SHARD_XOR, VVM_PROG_SHARD_XOR_SIZE,
                       shard_args, 1);
    }

    /* Scatter the key across random pages and zero the contiguous copy. */
    if (key_scatter_init(key))   /* zeros `key` on success */
        goto fail;
    DIAG(2);

    /* 2. decrypt the metadata envelope (lives in the grafted payload section) */
    if (cpi->meta_stored_size == 0 || cpi->meta_uncompressed_size == 0)
        goto fail;
    if ((uint64_t)cpi->meta_rva + cpi->meta_stored_size > packed_image_size)
        goto fail;
    DIAG(21);

    meta_dec = (uint8_t *)VirtualAlloc(NULL, cpi->meta_stored_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!meta_dec)
        goto fail;
    /* Swap-hardening: pin the metadata scratch so decrypted secrets never reach
       the pagefile. Best-effort; VirtualFree(MEM_RELEASE) unlocks on free. */
    VirtualLock(meta_dec, cpi->meta_stored_size);
    DIAG3(22, (uintptr_t)base, cpi->meta_rva, (uintptr_t)cpi);

    {
        uint8_t master[32];
        uint8_t skey[32];
        uint32_t meta_aad = cpi->flags;
        if (key_scatter_get(master) != 0) {
            pl_zero(master, sizeof(master));
            goto fail;
        }
        if (lethe_derive_meta_key(master, cpi->kdf_salt, skey) != 0) {
            pl_zero(master, sizeof(master));
            goto fail;
        }
        pl_zero(master, sizeof(master));
        rc = crypto_aes256gcm_decrypt(skey, cpi->meta_nonce,
                                      base + cpi->meta_rva, cpi->meta_stored_size,
                                      cpi->meta_tag, meta_dec,
                                      &meta_aad, sizeof(meta_aad));
        pl_zero(skey, sizeof(skey));
    }
    DIAG(23);
    if (rc != 0)
        goto fail;
    DIAG(3);

    /* 3. decompress metadata */
    meta_buf = (uint8_t *)VirtualAlloc(NULL, cpi->meta_uncompressed_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!meta_buf)
        goto fail;
    /* Swap-hardening: pin the decompressed metadata (the SectionDesc table with
       per-section GCM nonces/tags plus the import/reloc/TLS blobs -- the whole
       unpack recipe) out of the pagefile. Best-effort; freed with MEM_RELEASE. */
    VirtualLock(meta_buf, cpi->meta_uncompressed_size);

    dlen = (mz_ulong)cpi->meta_uncompressed_size;
    rc = mz_uncompress((unsigned char *)meta_buf, &dlen,
                       (const unsigned char *)meta_dec,
                       (mz_ulong)cpi->meta_stored_size);
    pl_zero(meta_dec, cpi->meta_stored_size);
    VirtualFree(meta_dec, 0, MEM_RELEASE);
    meta_dec = NULL;

    if (rc != MZ_OK || dlen != (mz_ulong)cpi->meta_uncompressed_size)
        goto fail;
    DIAG(4);

    /* 4. locate the sub-blobs inside the decompressed metadata */
    {
        uint32_t meta_sz = cpi->meta_uncompressed_size;
        if ((uint64_t)cpi->sections_off +
            (uint64_t)cpi->section_count * sizeof(SectionDesc) > meta_sz)
            goto fail;
        if (cpi->imports_size > 0 &&
            (uint64_t)cpi->imports_off + cpi->imports_size > meta_sz)
            goto fail;
        if (cpi->relocs_size > 0 &&
            (uint64_t)cpi->relocs_off + cpi->relocs_size > meta_sz)
            goto fail;
        if ((cpi->flags & LETHE_FLAG_HAS_TLS) &&
            (uint64_t)cpi->tls_off + 20 > meta_sz)
            goto fail;
    }
    secs = (SectionDesc *)(meta_buf + cpi->sections_off);

    /* 5. decrypt + decompress each protected section. The AES key lives only as
       scattered fragments now: reassemble it into a short-lived local for each
       section, zero that local immediately, and migrate the fragments to fresh
       pages between sections so the key never rests contiguously for long. */
    mg_want = memguard_enabled(cpi);
    for (i = 0; i < cpi->section_count; i++) {
        uint8_t master[32];
        uint8_t skey[32];
        int drc;

        if (mg_want && (secs[i].characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;   /* memguard owns executable sections */

        if (key_scatter_get(master) != 0) {
            pl_zero(master, sizeof(master));
            goto fail;
        }
        if (lethe_derive_section_key(master, cpi->kdf_salt,
                                     secs[i].rva, skey) != 0) {
            pl_zero(master, sizeof(master));
            goto fail;
        }
        pl_zero(master, sizeof(master));
        drc = decrypt_section(skey, base, &secs[i],
                              cpi->original_size_of_image, packed_image_size);
        pl_zero(skey, sizeof(skey));
        key_scatter_migrate();   /* move fragments between sections */

        if (drc != 0) {
            uint32_t j;
            for (j = 0; j < i; j++) {
                if (mg_want && (secs[j].characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;
                pl_zero(base + secs[j].rva, secs[j].virtual_size);
            }
            goto fail;
        }
        wipe_stored(base, &secs[i]);
    }
    DIAG(5);

    /* Tripwire: scattered PEB.BeingDebugged check after section decryption */
    if (cpi->flags & LETHE_FLAG_ANTIDEBUG)
        antidbg_tripwire_peb();

    /* 5a. early header erasure: destroy PE signatures + section table NOW,
       before imports/relocs/TLS/VirtualProtect.  All subsequent steps use the
       decrypted metadata blob (meta_buf) or PackInfo/SectionDesc fields, never
       the in-memory PE headers.  Without this, a single breakpoint anywhere in
       steps 6-12 yields a perfect dump: all sections plaintext + intact PE
       headers.  Payload envelope wipe stays in antidump_harden (step 12). */
    antidump_erase_headers(image_base, cpi->is_dll);

    /* 5b. mid-unpack anti-debug re-check: catch debuggers attached after startup */
    if (cpi->flags & LETHE_FLAG_ANTIDEBUG) {
        if (antidbg_check_extended(base, cpi->stub_text_rva,
                                   cpi->stub_text_size)) {
            /* Wipe decrypted sections before exit */
            for (i = 0; i < cpi->section_count; i++) {
                if (mg_want && (secs[i].characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;
                pl_zero(base + secs[i].rva, secs[i].virtual_size);
            }
            key_scatter_destroy();
            pl_zero(key, sizeof(key));
            pl_zero(meta_buf, cpi->meta_uncompressed_size);
            VirtualFree(meta_buf, 0, MEM_RELEASE);
            ExitProcess(0);
        }
    }

    /* 5c. pre-import hardening: pin DLL search order + process mitigations
       BEFORE any LoadLibraryA so injection/planting is blocked during
       import resolution. Deferred to post-import (step 12) because
       SetDefaultDllDirectories restricts the search paths that
       resolve_imports' LoadLibraryA needs. */
    /* antidump_harden_early(cpi->is_dll); -- moved to after resolve_imports */

    /* 6. resolve imports */
    if (cpi->imports_size > 0) {
        if (resolve_imports(base, meta_buf + cpi->imports_off,
                            cpi->imports_size,
                            cpi->original_size_of_image) != 0)
            goto fail;
    }
    DIAG(6);

    /* Tripwire: scattered NtGlobalFlag check after import resolution */
    if (cpi->flags & LETHE_FLAG_ANTIDEBUG)
        antidbg_tripwire_ntgf();

    /* 7. apply base relocations */
    if (cpi->relocs_size > 0) {
        if (reloc_delta != 0) {
            if (apply_relocs(base, meta_buf + cpi->relocs_off,
                             cpi->relocs_size, reloc_delta,
                             cpi->original_size_of_image, secs,
                             cpi->section_count,
                             mg_want ? RELOC_FILTER_NONEXEC :
                                       RELOC_FILTER_ALL) != 0)
                goto fail;
        }
    }
    DIAG(7);

    /* Tripwire: scattered HW breakpoint check after relocation */
    if (cpi->flags & LETHE_FLAG_ANTIDEBUG)
        antidbg_tripwire_hwbp();

    /* 8. TLS */
    if (cpi->flags & LETHE_FLAG_HAS_TLS) {
        uint32_t tls_blob_size = cpi->meta_uncompressed_size - cpi->tls_off;
        if (setup_tls(base, meta_buf + cpi->tls_off,
                      tls_blob_size, cpi->original_size_of_image,
                      cpi->is_dll) != 0)
            goto fail;
    }
    DIAG(8);

    /* 9. x64 exception table (.pdata) */
    if ((cpi->flags & LETHE_FLAG_HAS_EXCEPTIONS) &&
        cpi->pdata_rva && cpi->pdata_count) {
        if (!RtlAddFunctionTable(
                (PRUNTIME_FUNCTION)(base + cpi->pdata_rva),
                cpi->pdata_count,
                (DWORD64)(uintptr_t)base))
            goto fail;
    }
    DIAG(9);

    /* 10. memguard install (or fallback to eager decrypt).
       On success memguard OWNS the scattered key (its VEH reassembles it on
       demand), so we must NOT destroy it below. On failure we eager-decrypt the
       executable sections here (using the scattered key) and the scatter is torn
       down after this step like the non-memguard case. */
    if (mg_want) {
        const uint8_t *reloc_blob = cpi->relocs_size > 0
                                  ? meta_buf + cpi->relocs_off : NULL;
        int reloc_ready = memguard_set_relocs(reloc_blob, cpi->relocs_size,
                                              reloc_delta) == 0;
        mg_ok = reloc_ready &&
                (memguard_install(image_base, cpi, secs) == 0);
        if (!mg_ok) {
            memguard_discard_pending_relocs();
            for (i = 0; i < cpi->section_count; i++) {
                uint8_t master[32];
                uint8_t skey[32];
                int drc;
                if (!(secs[i].characteristics & IMAGE_SCN_MEM_EXECUTE))
                    continue;
                if (key_scatter_get(master) != 0) {
                    pl_zero(master, sizeof(master));
                    goto fail;
                }
                if (lethe_derive_section_key(master, cpi->kdf_salt,
                                             secs[i].rva, skey) != 0) {
                    pl_zero(master, sizeof(master));
                    goto fail;
                }
                pl_zero(master, sizeof(master));
                drc = decrypt_section(skey, base, &secs[i],
                                      cpi->original_size_of_image,
                                      packed_image_size);
                pl_zero(skey, sizeof(skey));
                if (drc != 0)
                    goto fail;
                wipe_stored(base, &secs[i]);
            }
            /* The first relocation pass deliberately skipped encrypted code.
             * Once eager fallback has materialized it, relocate only those
             * executable targets. Reapplying non-executable targets would
             * double-add the image delta. */
            if (cpi->relocs_size > 0 && reloc_delta != 0) {
                if (apply_relocs(base, meta_buf + cpi->relocs_off,
                                 cpi->relocs_size, reloc_delta,
                                 cpi->original_size_of_image, secs,
                                 cpi->section_count,
                                 RELOC_FILTER_EXEC) != 0)
                    goto fail;
            }
        }
    }

    /* Tear down the scattered key once it is no longer needed. Only a
       successfully installed memguard (mg_ok) keeps it -- its VEH reassembles
       the key on demand for the process lifetime. In every other case (no
       memguard, or memguard install failed and we eager-decrypted above) every
       section is already plaintext, so wipe the fragments now. */
    if (!mg_ok)
        key_scatter_destroy();

    /* 11. set final page protections. FIX 4: check the VirtualProtect result.
       A failure on an executable section would leave that code RW (never made
       RX) and it would fault under DEP on the first execution -- treat that as
       fatal. A failure on a non-executable section is non-fatal (the data is
       still accessible): record it in diag and continue. */
    for (i = 0; i < cpi->section_count; i++) {
        DWORD old = 0;
        int is_exec = (secs[i].characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if (mg_ok && is_exec)
            continue;   /* memguard set these to NOACCESS */
        if (!VirtualProtect(base + secs[i].rva, secs[i].virtual_size,
                            chars_to_prot(secs[i].characteristics), &old)) {
            if (is_exec)
                goto fail;   /* code stuck non-executable -> DEP fault on run */
            DIAG3(101, i, secs[i].rva, secs[i].virtual_size);  /* non-fatal */
            continue;
        }
        if (is_exec)
            FlushInstructionCache(GetCurrentProcess(),
                                  base + secs[i].rva, secs[i].virtual_size);
    }
    DIAG(10);

    /* 11b. TLS callbacks: invoked AFTER final page protections so code
       sections are RX (not RW) when callbacks execute. */
    if (cpi->flags & LETHE_FLAG_HAS_TLS) {
        uint32_t tls_blob_size = cpi->meta_uncompressed_size - cpi->tls_off;
        if (invoke_tls_callbacks(base, meta_buf + cpi->tls_off,
                                 tls_blob_size,
                                 cpi->original_size_of_image) != 0)
            goto fail;
    }
    DIAG(11);

    /* 12. anti-dump: wipe metadata envelope (headers already erased at 5a) */
    antidump_harden(image_base, cpi);
    DIAG(12);

    /* 13. cleanup */
    pl_zero(key, sizeof(key));
    pl_zero(meta_buf, cpi->meta_uncompressed_size);
    VirtualFree(meta_buf, 0, MEM_RELEASE);

    if (cpi->oep_rva == 0 || (uint64_t)cpi->oep_rva >= cpi->original_size_of_image) {
        *out_oep = NULL;
    } else {
        *out_oep = base + cpi->oep_rva;
    }
    DIAG(13);
    return 0;

fail:
    pl_zero(key, sizeof(key));
    if (mg_ok) {
        /* Later failures (for example TLS callback setup) can occur after the
         * guard owns both the key and relocation recipe. Tear it down before
         * wiping the scattered key so no live VEH observes freed state. */
        memguard_shutdown();
        mg_ok = 0;
    } else {
        memguard_discard_pending_relocs();
    }
    key_scatter_destroy();
    if (meta_dec)  { pl_zero(meta_dec,  cpi->meta_stored_size);
                     VirtualFree(meta_dec,  0, MEM_RELEASE); }
    if (meta_buf)  { pl_zero(meta_buf,  cpi->meta_uncompressed_size);
                     VirtualFree(meta_buf,  0, MEM_RELEASE); }
    return 1;
}

/* ---- DLL TLS per-thread ------------------------------------------------- */

int pe_loader_tls_thread_init(void)
{
    void **tls_array;
    uint8_t *tls_data;

    if (!s_tls_active || s_tls_total_size == 0)
        return 0;

    tls_array = (void **)__readgsqword(0x58);
    if (!tls_array)
        return 0;

    if (s_tls_total_size > ORION_STUB_TLS_CAPACITY)
        return 1;
    if (!tls_array[s_tls_slot])
        return 1;
    tls_data = (uint8_t *)tls_array[s_tls_slot];
    __stosb(tls_data, 0, ORION_STUB_TLS_CAPACITY);
    if (s_tls_raw_size > 0)
        __movsb(tls_data, s_tls_base + s_tls_raw_start, s_tls_raw_size);
    return 0;
}

void pe_loader_tls_thread_free(void)
{
    void **tls_array;

    if (!s_tls_active)
        return;

    tls_array = (void **)__readgsqword(0x58);
    if (!tls_array)
        return;

    if (tls_array[s_tls_slot])
        __stosb((uint8_t *)tls_array[s_tls_slot], 0,
                ORION_STUB_TLS_CAPACITY);
}
