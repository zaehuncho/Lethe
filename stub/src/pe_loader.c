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
#include "metadata_aad.h"
#include "crypto.h"
#include "stub_hooks.h"
#include "key_scatter.h"
#include "tls_anchor.h"
#include "miniz.h"
#include "daedalus_vm.h"
#include "daedalus_programs.h"
#include "load_config_binding.h"

#include "stub_intrin.h"

/* Compile-time-only fault seams used by the native hardening stress harness.
 * Ordinary builds have the exact Win32 calls and no test state or ABI. */
#if defined(LETHE_PE_LOADER_TEST_FAIL_VIRTUAL_LOCK)
#define VirtualLock(address, size) ((void)(address), (void)(size), FALSE)
#endif
#if defined(LETHE_PE_LOADER_TEST_FAIL_WIPE_RESTORE)
#define PL_WIPE_RESTORE(address, size, protection, old_protection) \
    ((void)(address), (void)(size), (void)(protection), \
     (void)(old_protection), FALSE)
#else
#define PL_WIPE_RESTORE(address, size, protection, old_protection) \
    VirtualProtect((address), (size), (protection), (old_protection))
#endif

#define RELOC_ABSOLUTE 0
#define RELOC_DIR64    10
#define RELOC_FILTER_ALL      0
#define RELOC_FILTER_EXEC     1
#define RELOC_FILTER_NONEXEC  2

#define LCFG_INDEX_SIZE       16u
#define LCFG_RUNTIME_HDR_SIZE LETHE_LCFG_RUNTIME_HEADER_SIZE
#define LCFG_RUNTIME_ENTRY_SIZE LETHE_LCFG_RUNTIME_ENTRY_SIZE
#define LCFG_RUNTIME_TARGET_SIZE LETHE_LCFG_RUNTIME_TARGET_SIZE
#define LCFG_RUNTIME_RELOCATION_SIZE LETHE_LCFG_RUNTIME_RELOCATION_SIZE
#define LCFG_RUNTIME_VERSION LETHE_LCFG_RUNTIME_VERSION

#ifndef CFG_CALL_TARGET_VALID_XFG
#define CFG_CALL_TARGET_VALID_XFG 0x00000008u
#endif

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

static int validate_section_desc(const SectionDesc *sd,
                                 uint32_t target_bound,
                                 uint32_t stored_bound)
{
    if (!sd || sd->rva == 0 || sd->virtual_size == 0 ||
        sd->stored_rva == 0 || sd->stored_size == 0 ||
        sd->uncompressed_size == 0)
        return 1;
    if (sd->uncompressed_size > sd->virtual_size)
        return 1;
    if ((uint64_t)sd->rva + sd->virtual_size > target_bound)
        return 1;
    if ((uint64_t)sd->stored_rva + sd->stored_size > stored_bound)
        return 1;
    return 0;
}

static int decrypt_section(const uint8_t key[32], uint8_t *base,
                           const SectionDesc *sd, uint32_t target_bound,
                           uint32_t stored_bound)
{
    uint8_t *scratch;
    mz_ulong dlen;
    DWORD target_old = 0;
    DWORD ignored = 0;
    int target_writable = 0;
    int scratch_locked = 0;
    int rc;

    if (validate_section_desc(sd, target_bound, stored_bound) != 0)
        return 1;

    if (sd->characteristics & IMAGE_SCN_MEM_EXECUTE) {
        if (!VirtualProtect(base + sd->rva, sd->virtual_size,
                            PAGE_READWRITE, &target_old))
            return 1;
        target_writable = 1;
    }

    scratch = (uint8_t *)VirtualAlloc(NULL, sd->stored_size,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!scratch) {
        if (target_writable)
            VirtualProtect(base + sd->rva, sd->virtual_size,
                           target_old, &ignored);
        return 1;
    }
    if (!VirtualLock(scratch, sd->stored_size)) {
        VirtualFree(scratch, 0, MEM_RELEASE);
        if (target_writable)
            VirtualProtect(base + sd->rva, sd->virtual_size,
                           target_old, &ignored);
        return 1;
    }
    scratch_locked = 1;

    {
        uint32_t rva_aad = sd->rva;
        rc = crypto_aes256gcm_decrypt(key, sd->gcm_nonce,
                                      base + sd->stored_rva, sd->stored_size,
                                      sd->gcm_tag, scratch,
                                      &rva_aad, sizeof(rva_aad));
    }
    if (rc != 0) {
        pl_zero(scratch, sd->stored_size);
        if (scratch_locked)
            VirtualUnlock(scratch, sd->stored_size);
        VirtualFree(scratch, 0, MEM_RELEASE);
        if (target_writable)
            VirtualProtect(base + sd->rva, sd->virtual_size,
                           target_old, &ignored);
        return 1;
    }

    dlen = (mz_ulong)sd->uncompressed_size;
    rc = mz_uncompress((unsigned char *)(base + sd->rva), &dlen,
                       (const unsigned char *)scratch, (mz_ulong)sd->stored_size);

    pl_zero(scratch, sd->stored_size);
    if (scratch_locked)
        VirtualUnlock(scratch, sd->stored_size);
    VirtualFree(scratch, 0, MEM_RELEASE);

    if (rc != MZ_OK || dlen != (mz_ulong)sd->uncompressed_size) {
        if (target_writable)
            VirtualProtect(base + sd->rva, sd->virtual_size,
                           target_old, &ignored);
        return 1;
    }
    return 0;
}

static int pl_all_zero(const uint8_t *p, size_t n)
{
    uint8_t accumulator = 0;
    size_t i;
    for (i = 0; i < n; ++i)
        accumulator |= p[i];
    return accumulator == 0;
}

static int verify_dll_export_snapshot(
    const uint8_t *base, uint32_t packed_image_size, const PackInfo *pi)
{
    uint8_t actual_hash[32];
    uint8_t difference = 0;
    uint32_t e_lfanew;
    uint32_t export_rva;
    uint32_t export_size;
    uint16_t optional_size;
    size_t i;
    int rc;

    if (!(pi->flags & LETHE_FLAG_DLL_PRELOAD_IAT)) {
        return (pi->dll_export_rva == 0 && pi->dll_export_size == 0 &&
                pl_all_zero(pi->dll_export_sha256_128,
                            sizeof(pi->dll_export_sha256_128))) ? 0 : 1;
    }

    if (pi->dll_export_rva == 0 || pi->dll_export_size == 0) {
        return (pi->dll_export_rva == 0 && pi->dll_export_size == 0 &&
                pl_all_zero(pi->dll_export_sha256_128,
                            sizeof(pi->dll_export_sha256_128))) ? 0 : 1;
    }
    if (pi->dll_export_size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
        (uint64_t)pi->dll_export_rva + pi->dll_export_size >
            pi->original_size_of_image ||
        (uint64_t)pi->dll_export_rva + pi->dll_export_size > packed_image_size)
        return 1;

    /* Bind the loader-visible PE directory to the authenticated PackInfo.
       Windows has already consumed this directory for static consumers. */
    if (packed_image_size < 0x40u)
        return 1;
    e_lfanew = *(const uint32_t *)(base + 0x3cu);
    if ((uint64_t)e_lfanew + 24u + 120u > packed_image_size ||
        *(const uint32_t *)(base + e_lfanew) != IMAGE_NT_SIGNATURE ||
        *(const uint16_t *)(base + e_lfanew + 24u) !=
            IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 1;
    optional_size = *(const uint16_t *)(base + e_lfanew + 20u);
    if (optional_size < 120u)
        return 1;
    export_rva = *(const uint32_t *)(base + e_lfanew + 24u + 112u);
    export_size = *(const uint32_t *)(base + e_lfanew + 24u + 116u);
    if (export_rva != pi->dll_export_rva ||
        export_size != pi->dll_export_size)
        return 1;

    rc = crypto_sha256(base + pi->dll_export_rva,
                       pi->dll_export_size, actual_hash);
    if (rc != 0) {
        pl_zero(actual_hash, sizeof(actual_hash));
        return 1;
    }
    for (i = 0; i < sizeof(pi->dll_export_sha256_128); ++i) {
        difference = (uint8_t)(
            difference |
            (uint8_t)(actual_hash[i] ^ pi->dll_export_sha256_128[i]));
    }
    pl_zero(actual_hash, sizeof(actual_hash));
    return difference == 0 ? 0 : 1;
}

/* Mandatory wipe of consumed section ciphertext in the payload section. */
static int wipe_stored(uint8_t *base, const SectionDesc *sd)
{
    DWORD old = 0, tmp = 0;
    uint8_t *p;
    if (sd->stored_size == 0)
        return 1;
    p = base + sd->stored_rva;
    if (!VirtualProtect(p, sd->stored_size, PAGE_READWRITE, &old))
        return 1;
    __stosb(p, 0, sd->stored_size);
    return PL_WIPE_RESTORE(p, sd->stored_size, old, &tmp) ? 0 : 1;
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

            if (pos + 14 > blob_size)      /* u32 + u16 + u32 + u32 */
                return 1;
            iat_rva         = *(const uint32_t *)(blob + pos);  pos += 4;
            hint_or_ordinal = *(const uint16_t *)(blob + pos);  pos += 2;
            func_name_hash  = *(const uint32_t *)(blob + pos);  pos += 4;
            pos += 4; /* preload_iat_rva: DLL pre-entry path only */

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

static int load_config_recipe(const PackInfo *pi, const uint8_t *metadata,
                               uint32_t metadata_size,
                               const uint8_t **out_recipe,
                               uint32_t *out_slot_count,
                               uint32_t *out_target_count,
                               uint32_t *out_relocation_count,
                               uint32_t *out_recipe_size)
{
    const uint8_t *index;
    const uint8_t *recipe;
    uint32_t recipe_off;
    uint32_t recipe_size;
    uint32_t version;
    uint32_t slot_count;
    uint32_t target_count;
    uint32_t relocation_count;
    uint64_t expected_size;

    if (!pi || !metadata || !out_recipe || !out_slot_count ||
        !out_target_count || !out_relocation_count || !out_recipe_size ||
        metadata_size < LCFG_INDEX_SIZE)
        return 1;
    index = metadata + metadata_size - LCFG_INDEX_SIZE;
    if (index[0] != 'L' || index[1] != 'C' || index[2] != 'F' ||
        index[3] != 'G' || index[4] != 'I' || index[5] != 'D' ||
        index[6] != 'X' || index[7] != '1')
        return 1;
    recipe_off = *(const uint32_t *)(const void *)(index + 8);
    recipe_size = *(const uint32_t *)(const void *)(index + 12);
    if (recipe_size < LCFG_RUNTIME_HDR_SIZE ||
        (uint64_t)recipe_off + recipe_size > metadata_size - LCFG_INDEX_SIZE)
        return 1;
    recipe = metadata + recipe_off;
    if (recipe[0] != 'L' || recipe[1] != 'C' || recipe[2] != 'F' ||
        recipe[3] != 'G' || recipe[4] != 'R' || recipe[5] != 'T' ||
        recipe[6] != '1' || recipe[7] != '\0')
        return 1;
    version = *(const uint32_t *)(const void *)(recipe + 8);
    slot_count = *(const uint32_t *)(const void *)(recipe + 12);
    target_count = *(const uint32_t *)(const void *)(recipe + 16);
    relocation_count = *(const uint32_t *)(const void *)(recipe + 20);
    expected_size = LCFG_RUNTIME_HDR_SIZE +
                    (uint64_t)slot_count * LCFG_RUNTIME_ENTRY_SIZE +
                    (uint64_t)target_count * LCFG_RUNTIME_TARGET_SIZE +
                    (uint64_t)relocation_count * LCFG_RUNTIME_RELOCATION_SIZE;
    if (version != LCFG_RUNTIME_VERSION || expected_size != recipe_size)
        return 1;
    *out_recipe = recipe;
    *out_slot_count = slot_count;
    *out_target_count = target_count;
    *out_relocation_count = relocation_count;
    *out_recipe_size = recipe_size;
    return 0;
}

static int verify_outer_load_config_binding(uint8_t *base,
                                            uint32_t packed_size,
                                            const PackInfo *pi,
                                            const uint8_t *metadata,
                                            uint32_t metadata_size)
{
    const uint8_t *recipe;
    uint32_t slot_count;
    uint32_t target_count;
    uint32_t relocation_count;
    uint32_t recipe_size;

    if (!(pi->flags & LETHE_FLAG_LOAD_CONFIG))
        return 0;
    if (load_config_recipe(pi, metadata, metadata_size, &recipe,
                           &slot_count, &target_count, &relocation_count,
                           &recipe_size) != 0)
        return 1;
    (void)slot_count;
    (void)target_count;
    (void)relocation_count;
    return lethe_load_config_binding_verify(
        base, packed_size, recipe, recipe_size);
}

static int restore_load_config_slots(uint8_t *base, uint32_t packed_size,
                                     const PackInfo *pi,
                                     const uint8_t *metadata,
                                     uint32_t metadata_size)
{
    const uint8_t *recipe;
    uint32_t slot_count;
    uint32_t target_count;
    uint32_t relocation_count;
    uint32_t recipe_size;

    if (!(pi->flags & LETHE_FLAG_LOAD_CONFIG))
        return 0;
    if (load_config_recipe(pi, metadata, metadata_size, &recipe,
                           &slot_count, &target_count, &relocation_count,
                           &recipe_size) != 0)
        return 1;
    (void)target_count;
    (void)relocation_count;

    return lethe_load_config_slots_restore_verified(
        base, pi->original_size_of_image, packed_size, recipe, recipe_size);
}

static int register_load_config_targets(uint8_t *base,
                                        const PackInfo *pi,
                                        const uint8_t *metadata,
                                        uint32_t metadata_size)
{
    typedef BOOL (WINAPI *SetValidTargetsFn)(
        HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);
    const uint8_t *recipe;
    const uint8_t *targets;
    void *kernelbase;
    SetValidTargetsFn set_valid_targets;
    uint32_t slot_count;
    uint32_t target_count;
    uint32_t relocation_count;
    uint32_t recipe_size;
    uint32_t i;

    if (!(pi->flags & LETHE_FLAG_LOAD_CONFIG))
        return 0;
    if (load_config_recipe(pi, metadata, metadata_size, &recipe,
                           &slot_count, &target_count, &relocation_count,
                           &recipe_size) != 0)
        return 0x1001;
    (void)relocation_count;
    (void)recipe_size;
    kernelbase = find_module_by_hash(0xBD6D247Au); /* hash("kernelbase.dll") */
    if (!kernelbase)
        return 0x1002;
    set_valid_targets = (SetValidTargetsFn)(uintptr_t)GetProcAddress(
        (HMODULE)kernelbase, "SetProcessValidCallTargets");
    if (!set_valid_targets)
        return 0x1003;
    targets = recipe + LCFG_RUNTIME_HDR_SIZE +
              (uint64_t)slot_count * LCFG_RUNTIME_ENTRY_SIZE;
    for (i = 0; i < target_count; ++i) {
        const uint8_t *entry = targets + i * LCFG_RUNTIME_TARGET_SIZE;
        uint32_t target_rva = *(const uint32_t *)(const void *)entry;
        uint8_t metadata_flags = entry[4];
        uintptr_t page_rva;
        CFG_CALL_TARGET_INFO info;
        if (target_rva == 0 || target_rva >= pi->original_size_of_image ||
            (metadata_flags & 0xF4u) != 0)
            return 0x2000 | (int)(i & 0x0FFFu);
        /* Suppressed and export-suppressed GFIDs were installed from the
           byte-exact outer table by the Windows image loader. Re-registering
           either as VALID would silently destroy that policy. */
        if (metadata_flags & 0x03u)
            continue;
        page_rva = (uintptr_t)target_rva & ~(uintptr_t)0xFFFu;
        info.Offset = (ULONG_PTR)(target_rva - (uint32_t)page_rva);
        info.Flags = CFG_CALL_TARGET_VALID;
        if (metadata_flags & 0x08u)
            info.Flags |= CFG_CALL_TARGET_VALID_XFG;
        if (!set_valid_targets(
                GetCurrentProcess(), base + page_rva, 0x1000u, 1u, &info))
            return (int)(0x40000000u | ((i & 0xFFu) << 16) |
                         (GetLastError() & 0xFFFFu));
    }
    return 0;
}

typedef struct PreloadedIatEntry {
    uint32_t iat_rva;
    uint64_t value;
} PreloadedIatEntry;

/* Walk the authenticated import recipe while the Windows-populated source IAT
 * is still present. The outer packed-DLL import table points FirstThunk at the
 * source slots, so this captures loader-resolved addresses without calling
 * LoadLibrary/GetProcAddress from StubDllMain. A second pass fills the exact-
 * sized VirtualAlloc buffer after the first pass proves the geometry. */
static int walk_preloaded_iat(uint8_t *base, const uint8_t *blob,
                              uint32_t blob_size, uint32_t source_image_size,
                              uint32_t packed_image_size,
                              PreloadedIatEntry *entries, uint32_t capacity,
                              uint32_t *out_count)
{
    uint32_t pos, enc_pool_size, count = 0;

    if (!base || !blob || !out_count || blob_size < 8)
        return 1;
    enc_pool_size = *(const uint32_t *)blob;
    if (enc_pool_size > blob_size - 4u)
        return 1;
    pos = 4u + enc_pool_size;

    for (;;) {
        uint32_t dll_hash, enc_offset, func_count, f;
        if (pos + 4u > blob_size)
            return 1;
        dll_hash = *(const uint32_t *)(blob + pos);
        pos += 4u;
        if (dll_hash == 0) {
            if (pos != blob_size)
                return 1;
            *out_count = count;
            return 0;
        }
        if (pos + 9u > blob_size)
            return 1;
        pos += 1u; /* xor key */
        enc_offset = *(const uint32_t *)(blob + pos);
        pos += 4u;
        func_count = *(const uint32_t *)(blob + pos);
        pos += 4u;
        if (enc_offset >= enc_pool_size || func_count > (blob_size - pos) / 14u)
            return 1;
        if (func_count > UINT32_MAX - count)
            return 1;

        for (f = 0; f < func_count; ++f) {
            uint32_t iat_rva = *(const uint32_t *)(blob + pos);
            uint32_t preload_iat_rva = *(const uint32_t *)(blob + pos + 10u);
            uint64_t value;
            pos += 14u;
            if ((iat_rva & 7u) != 0u ||
                (uint64_t)iat_rva + sizeof(uint64_t) > source_image_size ||
                (preload_iat_rva & 7u) != 0u ||
                preload_iat_rva < source_image_size ||
                (uint64_t)preload_iat_rva + sizeof(uint64_t) >
                    packed_image_size)
                return (int)(0x10000u | (count & 0xFFFFu));
            value = *(const uint64_t *)(base + preload_iat_rva);
            if (value == 0)
                return (int)(0x20000u | (count & 0xFFFFu));
            if (entries) {
                if (count >= capacity)
                    return 1;
                entries[count].iat_rva = iat_rva;
                entries[count].value = value;
            }
            ++count;
        }
    }
}

static int snapshot_preloaded_iat(uint8_t *base, const uint8_t *blob,
                                  uint32_t blob_size,
                                  uint32_t source_image_size,
                                  uint32_t packed_image_size,
                                  PreloadedIatEntry **out_entries,
                                  uint32_t *out_count)
{
    PreloadedIatEntry *entries;
    uint32_t count = 0, filled = 0;
    size_t allocation_size;
    int walk_rc;

    if (!out_entries || !out_count)
        return 1;
    *out_entries = NULL;
    *out_count = 0;
    walk_rc = walk_preloaded_iat(base, blob, blob_size, source_image_size,
                                 packed_image_size,
                                 NULL, 0, &count);
    if (walk_rc != 0)
        return walk_rc;
    if (count == 0)
        return 0;
    if ((size_t)count > SIZE_MAX / sizeof(*entries))
        return 1;
    allocation_size = (size_t)count * sizeof(*entries);
    entries = (PreloadedIatEntry *)VirtualAlloc(
        NULL, allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!entries)
        return 1;
    walk_rc = walk_preloaded_iat(base, blob, blob_size, source_image_size,
                                 packed_image_size,
                                 entries, count, &filled);
    if (walk_rc != 0 || filled != count) {
        pl_zero(entries, allocation_size);
        VirtualFree(entries, 0, MEM_RELEASE);
        return walk_rc != 0 ? walk_rc : 1;
    }
    *out_entries = entries;
    *out_count = count;
    return 0;
}

static void restore_preloaded_iat(uint8_t *base, PreloadedIatEntry **entries,
                                  uint32_t *count)
{
    uint32_t i;
    size_t allocation_size;
    PreloadedIatEntry *snapshot;

    if (!entries || !count || !*entries)
        return;
    snapshot = *entries;
    allocation_size = (size_t)*count * sizeof(*snapshot);
    for (i = 0; i < *count; ++i)
        *(uint64_t *)(base + snapshot[i].iat_rva) = snapshot[i].value;
    pl_zero(snapshot, allocation_size);
    VirtualFree(snapshot, 0, MEM_RELEASE);
    *entries = NULL;
    *count = 0;
}

static void discard_preloaded_iat(PreloadedIatEntry **entries,
                                  uint32_t *count)
{
    size_t allocation_size;
    if (!entries || !count || !*entries)
        return;
    allocation_size = (size_t)*count * sizeof(**entries);
    pl_zero(*entries, allocation_size);
    VirtualFree(*entries, 0, MEM_RELEASE);
    *entries = NULL;
    *count = 0;
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
    while (pos < size) {
        uint32_t page_rva, block_size;
        uint32_t entry_count, i;
        const uint16_t *entries;

        if (size - pos < 8)
            return 1;
        page_rva   = *(const uint32_t *)(data + pos);
        block_size = *(const uint32_t *)(data + pos + 4);
        if ((page_rva & 0xFFFu) != 0 || block_size < 8 ||
            block_size > size - pos || (block_size & 3u) != 0)
            return 1;

        entry_count = (block_size - 8) / 2;
        entries = (const uint16_t *)(data + pos + 8);

        for (i = 0; i < entry_count; i++) {
            uint16_t type   = entries[i] >> 12;
            uint16_t offset = entries[i] & 0x0FFF;

            if (type == RELOC_DIR64) {
                uint64_t target_off = (uint64_t)page_rva + offset;
                if (target_off + 8 > image_size)
                    return 1;
                if (!reloc_target_matches_filter(target_off, secs, sec_count,
                                                 filter))
                    continue;
                {
                    uint64_t *target = (uint64_t *)(base + target_off);
                    uint64_t value = *target;
                    if (delta >= 0) {
                        uint64_t add = (uint64_t)delta;
                        if (value > UINT64_MAX - add)
                            return 1;
                        value += add;
                    } else {
                        uint64_t subtract = (uint64_t)(-(delta + 1)) + 1u;
                        if (value < subtract)
                            return 1;
                        value -= subtract;
                    }
                    *target = value;
                }
            } else if (type != RELOC_ABSOLUTE) {
                return 1;
            }
        }
        pos += block_size;
    }
    return 0;
}

/* RtlAddFunctionTable trusts its caller's table geometry. Keep malformed
   authenticated metadata from becoming a deferred fault in the OS unwinder. */
static int validate_pdata_geometry(const uint8_t *base, uint32_t pdata_rva,
                                   uint32_t pdata_count,
                                   uint32_t image_size)
{
    uint64_t table_size = (uint64_t)pdata_count * 12u;
    uint64_t table_end = (uint64_t)pdata_rva + table_size;
    uint32_t previous_end = 0;
    uint32_t i;

    if (pdata_rva == 0 || pdata_count == 0 || (pdata_rva & 3u) != 0)
        return 1;
    if (table_size > UINT32_MAX || table_end > image_size ||
        table_end > UINT32_MAX)
        return 1;

    for (i = 0; i < pdata_count; ++i) {
        const uint32_t *entry =
            (const uint32_t *)(const void *)(base + pdata_rva + i * 12u);
        uint32_t begin = entry[0];
        uint32_t end = entry[1];
        uint32_t unwind_rva = entry[2];
        uint8_t version_and_flags;
        uint8_t version;
        uint8_t flags;
        uint8_t allowed_flags;

        if (begin == 0 || begin >= end || end > image_size ||
            (i != 0 && begin < previous_end))
            return 1;
        if (unwind_rva == 0 || (unwind_rva & 3u) != 0 ||
            (uint64_t)unwind_rva + 4u > image_size)
            return 1;

        version_and_flags = base[unwind_rva];
        version = version_and_flags & 7u;
        flags = version_and_flags >> 3;
        if (version < 1 || version > 3)
            return 1;
        allowed_flags = version == 3 ? 0x0Fu : 0x07u;
        if ((flags & (uint8_t)~allowed_flags) != 0 ||
            ((flags & 0x04u) != 0 && (flags & 0x03u) != 0))
            return 1;
        previous_end = end;
    }
    return 0;
}

/* ---- TLS ---------------------------------------------------------------- */

typedef struct ProtectedTlsRecipe {
    uint32_t raw_size;
    uint32_t total_size;
    uint32_t callback_count;
    uint32_t allocation_size;
    uint8_t payload[1];
} ProtectedTlsRecipe;

typedef struct TlsThreadState {
    uint32_t magic;
    uint32_t initialized;
    uint32_t attach_delivered;
    uint32_t detach_delivered;
} TlsThreadState;

#define TLS_THREAD_STATE_MAGIC 0x534C544Cu

static uint8_t            *s_tls_base = NULL;
static ProtectedTlsRecipe *s_tls_recipe = NULL;
static DWORD               s_tls_slot = 0;
static int                 s_tls_active = 0;
static int                 s_tls_is_dll = 0;
static int                 s_tls_process_attached = 0;

static uint32_t *tls_recipe_callbacks(ProtectedTlsRecipe *recipe)
{
    return (uint32_t *)(void *)recipe->payload;
}

static uint8_t *tls_recipe_template(ProtectedTlsRecipe *recipe)
{
    return recipe->payload + (uint64_t)recipe->callback_count * 4u;
}

static uint8_t *tls_current_storage(void)
{
    void **tls_array = (void **)__readgsqword(0x58);
    if (!tls_array)
        return NULL;
    return (uint8_t *)tls_array[s_tls_slot];
}

static TlsThreadState *tls_current_state(uint8_t *storage)
{
    return (TlsThreadState *)(void *)(storage + ORION_STUB_TLS_CAPACITY);
}

static int tls_initialize_current(void)
{
    ProtectedTlsRecipe *recipe = s_tls_recipe;
    uint8_t *storage;
    TlsThreadState *state;

    if (!s_tls_active || !recipe ||
        recipe->total_size > ORION_STUB_TLS_CAPACITY)
        return 1;
    storage = tls_current_storage();
    if (!storage)
        return 1;
    state = tls_current_state(storage);
    if (state->magic == TLS_THREAD_STATE_MAGIC && state->initialized)
        return 0;

    pl_zero(storage, ORION_STUB_TLS_ALLOCATION_SIZE);
    if (recipe->raw_size > 0)
        __movsb(storage, tls_recipe_template(recipe), recipe->raw_size);
    state = tls_current_state(storage);
    state->magic = TLS_THREAD_STATE_MAGIC;
    state->initialized = 1;
    return 0;
}

static void tls_invoke_callbacks(DWORD reason)
{
    ProtectedTlsRecipe *recipe = s_tls_recipe;
    uint32_t *callback_rvas;
    uint32_t i;

    if (!s_tls_active || !recipe)
        return;
    callback_rvas = tls_recipe_callbacks(recipe);
    for (i = 0; i < recipe->callback_count; i++) {
        PIMAGE_TLS_CALLBACK cb =
            (PIMAGE_TLS_CALLBACK)(s_tls_base + callback_rvas[i]);
        cb(s_tls_base, reason, NULL);
    }
}

static void tls_release_state(void)
{
    ProtectedTlsRecipe *recipe = s_tls_recipe;
    uint8_t *storage = s_tls_active ? tls_current_storage() : NULL;

    s_tls_active = 0;
    s_tls_process_attached = 0;
    s_tls_is_dll = 0;
    s_tls_recipe = NULL;
    s_tls_base = NULL;
    s_tls_slot = 0;
    if (storage)
        pl_zero(storage, ORION_STUB_TLS_ALLOCATION_SIZE);
    if (recipe) {
        pl_zero(recipe, recipe->allocation_size);
        VirtualFree(recipe, 0, MEM_RELEASE);
    }
}

static int tls_process_attach(void)
{
    if (!s_tls_active || !s_tls_recipe)
        return 1;
    if (s_tls_process_attached)
        return 0;
    if (tls_initialize_current() != 0)
        return 1;
    s_tls_process_attached = 1;
    tls_invoke_callbacks(DLL_PROCESS_ATTACH);
    return 0;
}

static void tls_thread_attach(void)
{
    uint8_t *storage;
    TlsThreadState *state;

    if (!s_tls_process_attached || tls_initialize_current() != 0)
        return;
    storage = tls_current_storage();
    if (!storage)
        return;
    state = tls_current_state(storage);
    if (state->attach_delivered)
        return;
    state->attach_delivered = 1;
    tls_invoke_callbacks(DLL_THREAD_ATTACH);
}

static void tls_thread_detach(void)
{
    uint8_t *storage;
    TlsThreadState *state;

    if (!s_tls_process_attached)
        return;
    storage = tls_current_storage();
    if (!storage)
        return;
    state = tls_current_state(storage);
    if (state->magic != TLS_THREAD_STATE_MAGIC || !state->initialized ||
        !state->attach_delivered || state->detach_delivered)
        return;
    state->detach_delivered = 1;
    tls_invoke_callbacks(DLL_THREAD_DETACH);
    pl_zero(storage, ORION_STUB_TLS_ALLOCATION_SIZE);
}

static void tls_process_detach(void)
{
    if (!s_tls_active)
        return;
    if (s_tls_process_attached) {
        s_tls_process_attached = 0;
        tls_invoke_callbacks(DLL_PROCESS_DETACH);
    }
    tls_release_state();
}

static int setup_tls(uint8_t *base, const uint8_t *blob,
                     uint32_t blob_size, uint32_t image_size,
                     uint32_t packed_image_size,
                     int is_dll)
{
    uint32_t index_rva, raw_start, raw_end, zero_fill, characteristics, cb_count;
    uint32_t raw_size, total_size;
    const uint32_t *cb_rvas;
    ProtectedTlsRecipe *recipe;
    uint64_t recipe_size;
    DWORD tls_slot;
    uint32_t i;

    if (blob_size < 24)
        return 101;

    index_rva = *(const uint32_t *)(blob);
    raw_start = *(const uint32_t *)(blob + 4);
    raw_end   = *(const uint32_t *)(blob + 8);
    zero_fill = *(const uint32_t *)(blob + 12);
    characteristics = *(const uint32_t *)(blob + 16);
    cb_count  = *(const uint32_t *)(blob + 20);

    if (blob_size < 24 + (uint64_t)cb_count * 4)
        return 102;
    cb_rvas   = (const uint32_t *)(blob + 24);

    if (s_tls_active || s_tls_recipe)
        return 103;

    if (raw_end < raw_start)
        return 104;
    if ((characteristics & ~0x00F00000u) != 0 ||
        ((characteristics >> 20) & 0xFu) == 0xFu)
        return 105;
    if ((uint64_t)index_rva + 4 > image_size)
        return 106;

    raw_size = raw_end - raw_start;

    /* FIX 2: compute the TLS block size in 64-bit. total_size is uint32_t, so
       raw_size + zero_fill could wrap on a hostile/corrupt zero_fill, making
       HeapAlloc undersize the buffer that __movsb(raw_size) below then
       overflows. Reject anything larger than the image (a sane cap) before we
       allocate. After the check the sum fits in uint32_t. */
    {
        uint64_t total = (uint64_t)raw_size + zero_fill;
        if (total > image_size || total > ORION_STUB_TLS_CAPACITY)
            return 107;
        total_size = (uint32_t)total;
    }

    if (raw_size > 0 && (uint64_t)raw_start + raw_size > image_size)
        return 108;

    {
        uint32_t e_lfanew;
        uint32_t tls_rva;
        if (packed_image_size < 0x40u)
            return 109;
        e_lfanew = *(const uint32_t *)(base + 0x3cu);
        if ((uint64_t)e_lfanew + 24u + 112u + 11u * 8u > packed_image_size)
            return 110;
        tls_rva = *(const uint32_t *)(base + e_lfanew + 24u + 112u +
                                      IMAGE_DIRECTORY_ENTRY_TLS * 8u);
        if (tls_rva == 0 || (uint64_t)tls_rva +
                sizeof(IMAGE_TLS_DIRECTORY64) > packed_image_size ||
            *(const uint32_t *)(base + tls_rva + 36u) != characteristics)
            return 111;
    }

    for (i = 0; i < cb_count; i++) {
        if (cb_rvas[i] == 0 || cb_rvas[i] >= image_size)
            return 112;
    }

    recipe_size = offsetof(ProtectedTlsRecipe, payload) +
                  (uint64_t)cb_count * 4u + raw_size;
    if (recipe_size > UINT32_MAX)
        return 113;
    recipe = (ProtectedTlsRecipe *)VirtualAlloc(
        NULL, (SIZE_T)recipe_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!recipe)
        return 114;
    recipe->raw_size = raw_size;
    recipe->total_size = total_size;
    recipe->callback_count = cb_count;
    recipe->allocation_size = (uint32_t)recipe_size;
    if (cb_count > 0)
        __movsb((uint8_t *)tls_recipe_callbacks(recipe),
                (const uint8_t *)cb_rvas, (size_t)cb_count * 4u);
    if (raw_size > 0)
        __movsb(tls_recipe_template(recipe), base + raw_start, raw_size);

    /* The grafted stub's TLS directory makes Windows reserve this slot and a
     * 4 KiB block on every thread. Never scan beyond the loader-owned vector:
     * TLS_MINIMUM_AVAILABLE applies to TlsAlloc slots, not this static array. */
    tls_slot = lethe_stub_tls_index();
    s_tls_base = base;
    s_tls_recipe = recipe;
    s_tls_slot = tls_slot;
    s_tls_is_dll = is_dll != 0;
    s_tls_process_attached = 0;
    s_tls_active = 1;
    if (tls_initialize_current() != 0) {
        tls_release_state();
        return 115;
    }
    *(DWORD *)(base + index_rva) = tls_slot;
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
    int meta_dec_locked = 0;
    int meta_buf_locked = 0;
    SectionDesc *secs;
    mz_ulong dlen;
    int mg_want, mg_ok = 0;
    int pdata_registered = 0;
    int64_t reloc_delta;
    uint32_t i;
    int rc;
    PreloadedIatEntry *preloaded_iat = NULL;
    uint32_t preloaded_iat_count = 0;

    if (!image_base || !pi || !out_oep)
        return 1;
    *out_oep = NULL;
    if (cpi->magic[0] != 'L' || cpi->magic[1] != 'E' ||
        cpi->magic[2] != 'T' || cpi->magic[3] != 'H' ||
        cpi->magic[4] != 'E' || cpi->magic[5] != '0' ||
        cpi->magic[6] != '1' || cpi->magic[7] != '\0' ||
        cpi->format_ver != LETHE_FORMAT_VERSION)
        return 1;
    if (cpi->flags & ~(LETHE_FLAG_HAS_TLS | LETHE_FLAG_HAS_EXCEPTIONS |
                       LETHE_FLAG_ANTIDEBUG | LETHE_FLAG_MEMGUARD |
                       LETHE_FLAG_PAGED_DVM | LETHE_FLAG_LOAD_CONFIG |
                       LETHE_FLAG_DLL_PRELOAD_IAT |
                       LETHE_FLAG_PROCESS_HARDENING))
        return 1;
    if (!!(cpi->flags & LETHE_FLAG_DLL_PRELOAD_IAT) != !!cpi->is_dll)
        return 1;
    if (cpi->is_dll &&
        (cpi->flags & (LETHE_FLAG_MEMGUARD |
                       LETHE_FLAG_PROCESS_HARDENING)))
        return 1;
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
        /* Shard fetch/hex-decode/XOR/wipe/unset now lives in Daedalus VM bytecode
           (DVM_PROG_SHARD_XOR); the VM performs the GetEnvironmentVariableA,
           hex decode, in-place key XOR, SetEnvironmentVariableA(NULL) and local
           wipe via native ops. See daedalus_programs.h. */
        uint64_t shard_args[1];
        shard_args[0] = (uint64_t)(uintptr_t)key;
        daedalus_vm_exec(DVM_PROG_SHARD_XOR, DVM_PROG_SHARD_XOR_SIZE,
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
    /* Swap-hardening is a security contract: never continue if the decrypted
       metadata scratch cannot be pinned out of the pagefile. */
    if (!VirtualLock(meta_dec, cpi->meta_stored_size))
        goto fail;
    meta_dec_locked = 1;
    DIAG3(22, (uintptr_t)base, cpi->meta_rva, (uintptr_t)cpi);

    {
        uint8_t master[32];
        uint8_t skey[32];
        uint8_t meta_aad[LETHE_METADATA_AAD_SIZE];
        if (lethe_metadata_aad_build(cpi, meta_aad) != 0)
            goto fail;
        if (key_scatter_get(master) != 0) {
            pl_zero(meta_aad, sizeof(meta_aad));
            pl_zero(master, sizeof(master));
            goto fail;
        }
        if (lethe_derive_meta_key(master, cpi->kdf_salt, skey) != 0) {
            pl_zero(meta_aad, sizeof(meta_aad));
            pl_zero(master, sizeof(master));
            goto fail;
        }
        pl_zero(master, sizeof(master));
        rc = crypto_aes256gcm_decrypt(skey, cpi->meta_nonce,
                                      base + cpi->meta_rva, cpi->meta_stored_size,
                                      cpi->meta_tag, meta_dec,
                                      meta_aad, sizeof(meta_aad));
        pl_zero(meta_aad, sizeof(meta_aad));
        pl_zero(skey, sizeof(skey));
    }
    DIAG(23);
    if (rc != 0)
        goto fail;
    if (verify_dll_export_snapshot(base, packed_image_size, cpi) != 0)
        goto fail;
    DIAG(3);

    /* 3. decompress metadata */
    meta_buf = (uint8_t *)VirtualAlloc(NULL, cpi->meta_uncompressed_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!meta_buf)
        goto fail;
    /* The decompressed recipe contains all section tags and loader metadata;
       pinning it is mandatory rather than a silent best-effort downgrade. */
    if (!VirtualLock(meta_buf, cpi->meta_uncompressed_size))
        goto fail;
    meta_buf_locked = 1;

    dlen = (mz_ulong)cpi->meta_uncompressed_size;
    rc = mz_uncompress((unsigned char *)meta_buf, &dlen,
                       (const unsigned char *)meta_dec,
                       (mz_ulong)cpi->meta_stored_size);
    pl_zero(meta_dec, cpi->meta_stored_size);
    VirtualUnlock(meta_dec, cpi->meta_stored_size);
    meta_dec_locked = 0;
    VirtualFree(meta_dec, 0, MEM_RELEASE);
    meta_dec = NULL;

    if (rc != MZ_OK || dlen != (mz_ulong)cpi->meta_uncompressed_size)
        goto fail;
    DIAG(4);

    /* 4. locate the sub-blobs inside the decompressed metadata */
    {
        uint32_t meta_sz = cpi->meta_uncompressed_size;
        if (cpi->section_count == 0 ||
            (uint64_t)cpi->sections_off +
            (uint64_t)cpi->section_count * sizeof(SectionDesc) > meta_sz)
            goto fail;
        if (cpi->imports_size > 0 &&
            (uint64_t)cpi->imports_off + cpi->imports_size > meta_sz)
            goto fail;
        if (cpi->relocs_size > 0 &&
            (uint64_t)cpi->relocs_off + cpi->relocs_size > meta_sz)
            goto fail;
        if ((cpi->flags & LETHE_FLAG_HAS_TLS) &&
            (uint64_t)cpi->tls_off + 24 > meta_sz)
            goto fail;
    }
    secs = (SectionDesc *)(meta_buf + cpi->sections_off);
    for (i = 0; i < cpi->section_count; ++i) {
        if (validate_section_desc(&secs[i], cpi->original_size_of_image,
                                  packed_image_size) != 0)
            goto fail;
    }
    /* The .lcfg clone is necessarily loader-visible before our entry point.
       Bind its relocation-normalized bytes and governing PE header fields to
       the authenticated metadata before restoring any protected section or
       consuming loader-populated shadow slots. */
    if (verify_outer_load_config_binding(
            base, packed_image_size, cpi, meta_buf,
            cpi->meta_uncompressed_size) != 0)
        goto fail;
    DIAG3(45, cpi->sections_off, cpi->imports_off, cpi->imports_size);

    /* The outer import table has already made Windows resolve every protected
       DLL import into its source IAT slot. Capture those values before section
       decryption overwrites the sparse placeholders. */
    if ((cpi->flags & LETHE_FLAG_DLL_PRELOAD_IAT) && cpi->imports_size > 0) {
        int snapshot_rc = snapshot_preloaded_iat(
                base, meta_buf + cpi->imports_off, cpi->imports_size,
                cpi->original_size_of_image, packed_image_size,
                &preloaded_iat,
                &preloaded_iat_count);
        if (snapshot_rc != 0) {
            DIAG3(46, cpi->imports_off, cpi->imports_size,
                  (uint32_t)snapshot_rc);
            goto fail;
        }
    }
    DIAG3(47, preloaded_iat_count, 0, 0);

    /* 5. decrypt + decompress each protected section. The AES key lives only as
       scattered fragments now: reassemble it into a short-lived local for each
       section, zero that local immediately, and migrate the fragments to fresh
       pages between sections so the key never rests contiguously for long. */
    mg_want = memguard_enabled(cpi);
    for (i = 0; i < cpi->section_count; i++) {
        uint8_t master[32];
        uint8_t skey[32];
        int drc;

        DIAG3(41, i, secs[i].rva, secs[i].characteristics);

        if (mg_want && (secs[i].characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;   /* memguard owns executable sections */

        if (key_scatter_get(master) != 0) {
            DIAG3(42, i, 0, 0);
            pl_zero(master, sizeof(master));
            goto fail;
        }
        if (lethe_derive_section_key(master, cpi->kdf_salt,
                                     secs[i].rva, skey) != 0) {
            DIAG3(43, i, secs[i].rva, 0);
            pl_zero(master, sizeof(master));
            goto fail;
        }
        pl_zero(master, sizeof(master));
        drc = decrypt_section(skey, base, &secs[i],
                              cpi->original_size_of_image, packed_image_size);
        DIAG3(44, i, (uint32_t)drc, secs[i].rva);
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
        if (wipe_stored(base, &secs[i]) != 0)
            goto fail;
    }
    DIAG(5);

    if (cpi->flags & LETHE_FLAG_DLL_PRELOAD_IAT)
        restore_preloaded_iat(base, &preloaded_iat, &preloaded_iat_count);

    /* Tripwire: scattered PEB.BeingDebugged check after section decryption */
    if ((cpi->flags & LETHE_FLAG_ANTIDEBUG) && antidbg_tripwire_peb())
        goto fail;

    /* 5a. early header sanitization. Keep the live MZ/PE/section-table chain:
       FindResource, GetModuleInformation, NTDLL static-TLS work, and DLL export
       resolution all parse it after startup. The hook still removes the DOS
       stub/Rich bytes, original entry point, checksum, and consumed directory
       entries; payload-envelope wiping remains in step 12. */
    if (antidump_erase_headers(image_base, cpi->is_dll) != 0)
        goto fail;

    /* 5b. mid-unpack anti-debug re-check: catch debuggers attached after startup */
    if (cpi->flags & LETHE_FLAG_ANTIDEBUG) {
        if (antidbg_check_extended(base, cpi->stub_text_rva,
                                   cpi->stub_text_size))
            goto fail;
    }

    /* Apply authenticated host-wide mitigations before resolving any protected
       EXE import. This makes SetDefaultDllDirectories govern the first
       LoadLibraryA call instead of only later application loads. DLL inputs are
       rejected above because these policies are process-global. */
    if ((cpi->flags & LETHE_FLAG_PROCESS_HARDENING) &&
        antidump_harden_early(cpi->is_dll) != 0)
        goto fail;

    /* 6. resolve imports */
    if (cpi->imports_size > 0 &&
        !(cpi->flags & LETHE_FLAG_DLL_PRELOAD_IAT)) {
        if (resolve_imports(base, meta_buf + cpi->imports_off,
                            cpi->imports_size,
                            cpi->original_size_of_image) != 0)
            goto fail;
    }
    DIAG(6);

    /* Tripwire: scattered NtGlobalFlag check after import resolution */
    if ((cpi->flags & LETHE_FLAG_ANTIDEBUG) && antidbg_tripwire_ntgf())
        goto fail;

    /* 7. apply base relocations */
    if (reloc_delta != 0 && cpi->relocs_size == 0)
        goto fail;
    if (cpi->relocs_size > 0 &&
        apply_relocs(base, meta_buf + cpi->relocs_off,
                     cpi->relocs_size, reloc_delta,
                     cpi->original_size_of_image, secs,
                     cpi->section_count,
                     mg_want ? RELOC_FILTER_NONEXEC :
                               RELOC_FILTER_ALL) != 0)
        goto fail;
    DIAG(7);

    /* Windows initialized the immutable outer load-config slots before entry.
       Section restoration overwrote the original compiler slots, so copy the
       loader-selected values back using the authenticated metadata recipe. */
    if (restore_load_config_slots(base, packed_image_size, cpi,
                                  meta_buf,
                                  cpi->meta_uncompressed_size) != 0)
        goto fail;
    DIAG(71);

    /* Tripwire: scattered HW breakpoint check after relocation */
    if ((cpi->flags & LETHE_FLAG_ANTIDEBUG) &&
        antidbg_tripwire_debug_port())
        goto fail;

    /* 8. TLS */
    if (cpi->flags & LETHE_FLAG_HAS_TLS) {
        uint32_t tls_blob_size = cpi->meta_uncompressed_size - cpi->tls_off;
        int tls_rc = setup_tls(base, meta_buf + cpi->tls_off,
                               tls_blob_size, cpi->original_size_of_image,
                               packed_image_size, cpi->is_dll);
        if (tls_rc != 0) {
            DIAG3(81, (uint32_t)tls_rc, tls_blob_size,
                  cpi->original_size_of_image);
            goto fail;
        }
    }
    DIAG(8);

    /* 9. x64 exception table (.pdata) */
    if (cpi->flags & LETHE_FLAG_HAS_EXCEPTIONS) {
        if (validate_pdata_geometry(base, cpi->pdata_rva, cpi->pdata_count,
                                    cpi->original_size_of_image) != 0)
            goto fail;
        if (!RtlAddFunctionTable(
                (PRUNTIME_FUNCTION)(base + cpi->pdata_rva),
                cpi->pdata_count,
                (DWORD64)(uintptr_t)base))
            goto fail;
        pdata_registered = 1;
    } else if (cpi->pdata_rva || cpi->pdata_count) {
        goto fail;
    }
    DIAG(9);

    /* 10. Mandatory authenticated memguard install. On success memguard owns
       the scattered key because its VEH reassembles it on demand. A requested
       guard that cannot stage relocations, lock key pages, register its VEH, or
       arm every executable section fails startup; it never downgrades to eager
       plaintext execution. */
    if (mg_want) {
        const uint8_t *reloc_blob = cpi->relocs_size > 0
                                  ? meta_buf + cpi->relocs_off : NULL;
        if (memguard_set_relocs(reloc_blob, cpi->relocs_size,
                                reloc_delta) != 0) {
            memguard_discard_pending_relocs();
            goto fail;
        }
        if (memguard_install(image_base, cpi, secs) != 0) {
            memguard_discard_pending_relocs();
            goto fail;
        }
        mg_ok = 1;
    }

    /* Memguard and authenticated VM pages both reconstruct the same pack
       master key after loader return. Keep fragments only when either feature
       is authenticated in PackInfo and actually needs them. */
    if (!mg_ok && !(cpi->flags & LETHE_FLAG_PAGED_DVM))
        key_scatter_destroy();

    /* 11. Set every authenticated final page protection. Any failure is fatal:
       continuing could leave a restored data page writable or executable with
       permissions broader than the source section requested. */
    for (i = 0; i < cpi->section_count; i++) {
        DWORD old = 0;
        DWORD final_protection;
        int is_exec = (secs[i].characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if (mg_ok && is_exec)
            continue;   /* memguard set these to NOACCESS */
        final_protection = chars_to_prot(secs[i].characteristics);
        if ((cpi->flags & LETHE_FLAG_LOAD_CONFIG) && is_exec)
            final_protection |= PAGE_TARGETS_NO_UPDATE;
        if (!VirtualProtect(base + secs[i].rva, secs[i].virtual_size,
                            final_protection, &old))
            goto fail;
        if (is_exec)
            FlushInstructionCache(GetCurrentProcess(),
                                  base + secs[i].rva, secs[i].virtual_size);
    }
    DIAG(10);

    /* PAGE_TARGETS_NO_UPDATE preserves any loader GFID state that survives the
       transient restore. Reassert the exact authenticated target inventory for
       hosts where the RX->RW transition invalidated those bitmap entries. */
    rc = register_load_config_targets(base, cpi, meta_buf,
                                      cpi->meta_uncompressed_size);
    if (rc != 0) {
        DIAG3(102, (uint32_t)rc, 0, 0);
        goto fail;
    }
    DIAG(101);

    /* 11b. Wipe the authenticated metadata recipe before invoking protected
       code. If page-protection acquisition/restoration fails, reject startup
       before a TLS callback can observe a partially initialized lifecycle. */
    if (antidump_harden(image_base, cpi) != 0)
        goto fail;
    DIAG(12);

    /* 12. TLS process attach: invoked exactly once AFTER final page
       protections so callback code is RX and the persisted recipe no longer
       depends on the soon-to-be-freed metadata envelope. */
    if (cpi->flags & LETHE_FLAG_HAS_TLS) {
        if (tls_process_attach() != 0)
            goto fail;
    }
    DIAG(11);

    /* 13. cleanup */
    pl_zero(key, sizeof(key));
    pl_zero(meta_buf, cpi->meta_uncompressed_size);
    VirtualUnlock(meta_buf, cpi->meta_uncompressed_size);
    meta_buf_locked = 0;
    VirtualFree(meta_buf, 0, MEM_RELEASE);

    if (cpi->oep_rva == 0 || (uint64_t)cpi->oep_rva >= cpi->original_size_of_image) {
        *out_oep = NULL;
    } else {
        *out_oep = base + cpi->oep_rva;
    }
    DIAG(13);
    /* The registration now belongs to the successful module lifecycle.
       Packed DLL detach removes it; EXE teardown releases it with the process. */
    return 0;

fail:
    pl_zero(key, sizeof(key));
    discard_preloaded_iat(&preloaded_iat, &preloaded_iat_count);
    tls_release_state();
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
                     if (meta_dec_locked)
                         VirtualUnlock(meta_dec, cpi->meta_stored_size);
                     VirtualFree(meta_dec,  0, MEM_RELEASE); }
    if (meta_buf)  { pl_zero(meta_buf,  cpi->meta_uncompressed_size);
                     if (meta_buf_locked)
                         VirtualUnlock(meta_buf, cpi->meta_uncompressed_size);
                     VirtualFree(meta_buf,  0, MEM_RELEASE); }
    if (pdata_registered) {
        RtlDeleteFunctionTable(
            (PRUNTIME_FUNCTION)(base + cpi->pdata_rva));
        pdata_registered = 0;
    }
    return 1;
}

/* ---- OS TLS anchor dispatch -------------------------------------------- */

void pe_loader_tls_anchor_dispatch(void *image_base, DWORD reason,
                                   void *reserved)
{
    /* Runs under the process loader lock. This path only reads published
       state, touches the OS-owned static TLS block, invokes the protected
       callbacks, and uses the already-resolved VirtualFree teardown primitive.
       It must never load modules, use the CRT/process heap, wait, or spawn. */
    (void)reserved;
    if (!s_tls_active || image_base != s_tls_base)
        return;

    switch (reason) {
    case DLL_THREAD_ATTACH:
        tls_thread_attach();
        break;
    case DLL_THREAD_DETACH:
        /* The real Windows detach order is DllMain followed by TLS callbacks.
         * StubDllMain mirrors that order for protected DLL callbacks. */
        if (!s_tls_is_dll)
            tls_thread_detach();
        break;
    case DLL_PROCESS_DETACH:
        if (!s_tls_is_dll)
            tls_process_detach();
        break;
    case DLL_PROCESS_ATTACH:
    default:
        /* The OS reaches the anchor before unpack. pe_loader_run performs the
         * protected PROCESS_ATTACH after imports, unwind, and RX protections. */
        break;
    }
}

void pe_loader_tls_dll_detach(DWORD reason, void *reserved)
{
    (void)reserved;
    if (!s_tls_active || !s_tls_is_dll)
        return;
    if (reason == DLL_THREAD_DETACH)
        tls_thread_detach();
    else if (reason == DLL_PROCESS_DETACH)
        tls_process_detach();
}
