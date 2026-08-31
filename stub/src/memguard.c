/*
 * Lethe stub -- memguard.c
 *
 * Implements memguard_enabled() and memguard_install() from stub_hooks.h: the
 * OPT-IN (LETHE_FLAG_MEMGUARD) Vectored-Exception-Handler on-demand decryptor.
 * Off by default; enabled per-image by the builder's --memory-guard flag.
 *
 * GOAL: at ANY instant, a memory snapshot of the process holds at most a small,
 * bounded working set of plaintext code pages -- never the whole program.
 *
 * -------------------------------------------------------------------------
 * v2 SCHEME -- per-page working set with LRU + periodic re-encryption
 * -------------------------------------------------------------------------
 * The container format still stores each guarded (executable) section as ONE
 * AES-256-GCM blob (compressed then encrypted as a unit; the GCM tag covers the
 * whole section). So the *initial* decrypt of a section is necessarily whole
 * section -- that is the real cryptographic gate. Everything after that is
 * managed at PAGE granularity with a cheap, reversible per-page XOR cipher:
 *
 *   Section states:  SEC_ENCRYPTED -> SEC_SPLIT
 *   Page states:     PG_UNINIT -> PG_XOR_ENC <-> PG_ACTIVE
 *
 * memguard_install():
 *   - Snapshots the per-section AES descriptors into an OWN VirtualAlloc'd
 *     region (the loader's decrypted metadata scratch is wiped after load).
 *   - Allocates a per-PAGE metadata table + a random 32-byte XOR key per page
 *     in a VirtualLock'd region flanked by NOACCESS guard pages ("guard the
 *     guard").
 *   - Registers a FIRST-chance VEH (index 1) so it runs before debugger handlers.
 *   - Verifies the ntdll exception-dispatch path is not inline-hooked; if it is,
 *     it declines to arm (returns failure -> loader eager-decrypts) rather than
 *     risk a bypassed VEH crashing the host.
 *   - Marks every guarded section PAGE_NOACCESS.
 *   - Spawns a background sweeper thread that re-encrypts idle pages.
 *
 * On the FIRST fault into a guarded section (SEC_ENCRYPTED), the VEH:
 *   1. AES-256-GCM decrypts + inflates the WHOLE section into its VA.
 *   2. Computes a CRC32 baseline of every page's plaintext.
 *   3. Immediately XOR-re-encrypts every page EXCEPT the faulting one and marks
 *      the whole section NOACCESS -> only the faulting page is left plaintext.
 *   4. Brings the faulting page up: RX + added to the working set (evicting the
 *      LRU page first if the set is full). Marks the section SEC_SPLIT.
 *
 * On any later fault into a SEC_SPLIT section, the page is PG_XOR_ENC: the VEH
 * XOR-decrypts just that one page (no AES, no inflate -- the hot path), verifies
 * its CRC32 against the baseline (tamper check), sets it RX, and adds it to the
 * working set (evicting the LRU page if full).
 *
 * Working set cap (MEMGUARD_MAX_ACTIVE_PAGES): when full, the least-recently
 * activated page is XOR-re-encrypted and set NOACCESS before a new page is
 * decrypted. A sweeper thread additionally re-encrypts any active page idle for
 * more than MEMGUARD_IDLE_MS so the steady-state plaintext footprint decays even
 * without new faults.
 *
 * Re-encryption uses XOR with the page's random 32-byte key (repeating pad), not
 * AES: a page fault cannot afford AES. Speed over strength here is the accepted
 * tradeoff -- the AES-256-GCM section decrypt is the cryptographic gate; the XOR
 * layer only bounds how much plaintext a snapshot can scrape between faults.
 *
 * -------------------------------------------------------------------------
 * RESIDUAL LIMITATION
 * -------------------------------------------------------------------------
 * The whole-section AES decrypt+inflate (step 1 above) briefly materializes the
 * entire section in plaintext before step 3 re-encrypts the cold pages. That
 * window is short (a single inflate + XOR sweep) and occurs once per section on
 * its first touch -- it is inherent to a per-section GCM tag. Steady state after
 * that touch is bounded by the working set. True per-page AES would need per-page
 * GCM tags (a container/ABI change) and is out of scope here.
 *
 * Freestanding / no-CRT: Win32 (kernel32) + MSVC intrinsics + the parallel
 * crypto.c (pure C crypto + dynamic BCryptGenRandom) / miniz.c symbols.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <intrin.h>
#include <stddef.h>
#include <stdint.h>

#include "stub_hooks.h"
#include "crypto.h"       /* crypto_derive_key, crypto_aes256gcm_decrypt */
#include "key_scatter.h"  /* key_scatter_get (scattered key; fallback to derive) */
#include "miniz.h"        /* mz_uncompress, mz_crc32, mz_ulong, MZ_OK        */
#ifdef MEMGUARD_KALYPSO
#include "kalypso.h"  /* Kalypso hot-path cipher (replaces XOR pad)  */
#endif

#include "stub_intrin.h"

/* --- tunables ------------------------------------------------------------ */
#define MEMGUARD_MAX_ACTIVE_PAGES 12     /* plaintext working-set cap        */
#define MEMGUARD_IDLE_MS          50u    /* re-encrypt after this much idle  */
#define MEMGUARD_SWEEP_MS         100u   /* sweeper cadence                  */
#define MG_PAGE_SIZE              4096u  /* x64 page (named MG_* to be safe)  */

/* Section state (managed under g_lock). */
#define SEC_ENCRYPTED  0L   /* stored bytes still AES-encrypted; pages NOACCESS */
#define SEC_SPLIT      1L   /* section inflated + broken into XOR-guarded pages  */

/* Per-page state. */
#define PG_UNINIT      0L   /* section not yet decrypted (initial)              */
#define PG_XOR_ENC     1L   /* page XOR-encrypted in place; NOACCESS            */
#define PG_ACTIVE      2L   /* page plaintext + RX; in the working set          */

typedef struct GuardPage {
    uint8_t      *va;          /* page base (image_base + rva + page*4096)      */
    uint64_t      last_access; /* GetTickCount64() at last activation           */
    uint32_t      size;        /* valid bytes in this page (<= MG_PAGE_SIZE)    */
    uint32_t      sec_index;   /* owning section index                          */
    uint32_t      crc;         /* CRC32 of plaintext (baseline, set at split)   */
    volatile LONG state;       /* PG_UNINIT / PG_XOR_ENC / PG_ACTIVE            */
} GuardPage;

typedef struct GuardSection {
    uint8_t      *va;               /* image_base + rva (decrypt target)        */
    uint8_t      *stored;           /* image_base + stored_rva (ciphertext src) */
    uint32_t      virtual_size;
    uint32_t      stored_size;      /* compressed+encrypted byte count          */
    uint32_t      uncompressed_size;
    uint32_t      first_page;       /* index of this section's first GuardPage   */
    uint32_t      page_count;
    uint32_t      characteristics;  /* reserved; guarded set is exec -> RX       */
    volatile LONG state;            /* SEC_ENCRYPTED / SEC_SPLIT                 */
    uint8_t       nonce[12];
    uint8_t       tag[16];
} GuardSection;

typedef struct MemGuardCtx {
    void            *image_base;
    const PackInfo  *pi;            /* persistent PackInfo (not wiped)          */
    void            *veh;           /* AddVectoredExceptionHandler handle       */
    GuardSection    *secs;          /* -> inside the guarded region             */
    GuardPage       *pages;         /* -> inside the guarded region             */
    uint8_t        (*keys)[32];     /* per-page XOR keys, inside guarded region  */
    void            *region_base;   /* VirtualAlloc base (leading guard page)   */
    HANDLE           reenc_thread;  /* sweeper thread                           */
    SIZE_T           region_total;  /* full reservation byte count              */
    SIZE_T           data_bytes;    /* committed middle byte count              */
    uint32_t         sec_count;
    uint32_t         page_count;
    int              active_count;
    volatile LONG    shutting_down;
    int              active[MEMGUARD_MAX_ACTIVE_PAGES]; /* global page indices  */
    uint8_t          kdf_salt[16];  /* snapshot — g_packinfo is wiped post-load */
    uint8_t         *reloc_blob;    /* OWN copy of the original reloc directory  */
    uint32_t         reloc_size;
    int64_t          reloc_delta;   /* actual_base - preferred_image_base        */
} MemGuardCtx;

/* Single packed module per process -> one global context + one lock. */
static MemGuardCtx * volatile g_ctx = NULL;
static CRITICAL_SECTION       g_lock;
static volatile LONG          g_lock_ready = 0;

/* memguard_shutdown(): optional clean teardown (stops the sweeper thread,
 * removes the VEH, wipes + frees the guarded region). No hook drives it today;
 * process exit tears everything down otherwise. Declared here to keep it a
 * referenced external symbol. */
void memguard_shutdown(void);

/* ---- no-CRT helpers ----------------------------------------------------- */

static void mg_zero(void *p, SIZE_T n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    SIZE_T i;
    if (p && n) {
        for (i = 0; i < n; ++i) vp[i] = 0;
    }
}

static void mg_copy(void *d, const void *s, SIZE_T n)
{
    if (d && s && n) {
        __movsb((unsigned char *)d, (const unsigned char *)s, n);
    }
}

static void mg_apply_relocs_in_range(const MemGuardCtx *ctx,
                                     uint8_t *sec_va, uint32_t sec_vsize)
{
    const uint8_t *blob, *end;
    uint8_t *base;
    int64_t delta;
    uint32_t sec_rva, sec_end_rva;
    if (!ctx->reloc_blob || !ctx->reloc_size || ctx->reloc_delta == 0)
        return;
    blob  = ctx->reloc_blob;
    end   = blob + ctx->reloc_size;
    base  = (uint8_t *)ctx->image_base;
    delta = ctx->reloc_delta;
    sec_rva     = (uint32_t)(sec_va - base);
    sec_end_rva = sec_rva + sec_vsize;
    while (blob + 8 <= end) {
        uint32_t page_rva   = *(const uint32_t *)blob;
        uint32_t block_size = *(const uint32_t *)(blob + 4);
        uint32_t count, j;
        const uint16_t *entries;
        if (block_size < 8 || blob + block_size > end) break;
        count   = (block_size - 8) / 2;
        entries = (const uint16_t *)(blob + 8);
        for (j = 0; j < count; ++j) {
            uint16_t entry  = entries[j];
            uint8_t  type   = (uint8_t)(entry >> 12);
            uint32_t offset = entry & 0x0FFF;
            uint32_t rva    = page_rva + offset;
            if (type == 10 && rva >= sec_rva && rva + 8 <= sec_end_rva) {
                uint64_t *slot = (uint64_t *)(base + rva);
                *slot += (uint64_t)delta;
            }
        }
        blob += block_size;
    }
}

static SIZE_T mg_align8(SIZE_T n)
{
    return (n + (SIZE_T)7u) & ~(SIZE_T)7u;
}

static SIZE_T mg_align_page(SIZE_T n)
{
    return (n + (SIZE_T)(MG_PAGE_SIZE - 1u)) & ~(SIZE_T)(MG_PAGE_SIZE - 1u);
}

static int mg_rand(void *buf, SIZE_T len)
{
    return crypto_csprng(buf, (size_t)len);
}

static uint32_t mg_crc32(const void *p, uint32_t n)
{
    return (uint32_t)mz_crc32((mz_ulong)MZ_CRC32_INIT,
                              (const unsigned char *)p, (size_t)n);
}

/* Reversible per-page hot-path cipher. Encrypt and decrypt are the same
 * operation (symmetric stream), so every call site is unchanged.
 *
 * MEMGUARD_KALYPSO: use Kalypso (ChaCha12 core) keyed by the page's
 * random 32-byte key, replacing the old repeating-XOR pad (which a single known
 * page of plaintext trivially breaks). The AES-256-GCM section decrypt remains
 * the cryptographic gate; this layer only bounds how much plaintext a snapshot
 * can scrape between faults, so 12 rounds (fast + sound) is the right point.
 * Each page has a unique random key, so a fixed zero nonce/counter is safe (no
 * two pages share a keystream, and a code page's plaintext is constant). Falls
 * back to the repeating-XOR pad when the define is off (kill-switch). */
static void mg_xor_page(uint8_t *p, const uint8_t *key, uint32_t n)
{
#ifdef MEMGUARD_KALYPSO
    static const uint8_t zero_nonce[12] = { 0 };
    kalypso_crypt(key, 12, (const uint8_t *)KALYPSO_STD_SIGMA, 0, zero_nonce, 0, p, p, n);
#else
    uint32_t i;
    for (i = 0; i < n; ++i) {
        p[i] = (uint8_t)(p[i] ^ key[i & 31u]);
    }
#endif
}

/* ---- anti-hook on the exception dispatch path (requirement 7) ----------- */

/* Heuristic: does a function entry look like an inline hook (jmp/push-ret/mov
 * rax,imm64;jmp rax trampolines)? The real KiUserExceptionDispatcher /
 * RtlDispatchException prologues do not begin with any of these. */
static int mg_bytes_look_hooked(const uint8_t *p)
{
    if (!p) {
        return 0;
    }
    if (p[0] == 0xE9) return 1;                              /* jmp rel32       */
    if (p[0] == 0xEB) return 1;                              /* jmp rel8        */
    if (p[0] == 0x68) return 1;                              /* push imm32; ret */
    if (p[0] == 0xFF && (p[1] == 0x25 || p[1] == 0xE0)) return 1; /* jmp [rip]/jmp rax */
    if (p[0] == 0x48 && p[1] == 0xB8) return 1;             /* mov rax, imm64  */
    if (p[0] == 0x49 && p[1] == 0xBB) return 1;             /* mov r11, imm64  */
    return 0;
}

static int mg_veh_path_hooked(void)
{
    union { FARPROC f; const uint8_t *b; } u;   /* pun avoids fnptr->data cast */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return 0;   /* can't locate ntdll -> don't block install */
    }
    {
        char nm1[] = {'K','i','U','s','e','r','E','x','c','e','p','t','i','o','n',
                      'D','i','s','p','a','t','c','h','e','r','\0'};
        u.f = GetProcAddress(ntdll, nm1);
        SecureZeroMemory(nm1, sizeof(nm1));
    }
    if (mg_bytes_look_hooked(u.b)) {
        return 1;
    }
    {
        char nm2[] = {'R','t','l','D','i','s','p','a','t','c','h',
                      'E','x','c','e','p','t','i','o','n','\0'};
        u.f = GetProcAddress(ntdll, nm2);
        SecureZeroMemory(nm2, sizeof(nm2));
    }
    if (mg_bytes_look_hooked(u.b)) {
        return 1;
    }
    return 0;
}

/* ---- page (de)activation (all callers hold g_lock) ---------------------- */

/*
 * Re-encrypt an ACTIVE page back to XOR_ENC + NOACCESS.
 * Ordering is chosen so no thread can execute stale/garbage bytes:
 *   1. NOACCESS  -- fences out any concurrent access (faulters block on g_lock).
 *   2. READWRITE -- writable but non-executable (DEP), touched only by us.
 *   3. XOR       -- scramble in place.
 *   4. NOACCESS  -- final resting protection.
 * Does NOT touch the active[] set; the caller manages that.
 */
static void mg_reencrypt_page(MemGuardCtx *ctx, uint32_t gp)
{
    GuardPage *g = &ctx->pages[gp];
    DWORD old = 0;

    if (g->state != PG_ACTIVE) {
        return;
    }
    /* Flip the state first (still under g_lock): the lock-free fast path in the
     * VEH must never see PG_ACTIVE once the page is about to go NOACCESS, or a
     * faulter could spin re-faulting until we finish. Only the locked path acts
     * on the bytes, and it is blocked on g_lock until we return. */
    g->state = PG_XOR_ENC;
    VirtualProtect(g->va, MG_PAGE_SIZE, PAGE_NOACCESS,  &old);
    VirtualProtect(g->va, MG_PAGE_SIZE, PAGE_READWRITE, &old);
    mg_xor_page(g->va, ctx->keys[gp], g->size);
    VirtualProtect(g->va, MG_PAGE_SIZE, PAGE_NOACCESS,  &old);
}

/* Evict the least-recently-activated page from the working set. */
static void mg_evict_lru(MemGuardCtx *ctx)
{
    int i, lru = 0;
    uint64_t best;

    if (ctx->active_count <= 0) {
        return;
    }
    best = ctx->pages[ctx->active[0]].last_access;
    for (i = 1; i < ctx->active_count; ++i) {
        uint64_t la = ctx->pages[ctx->active[i]].last_access;
        if (la < best) {
            best = la;
            lru = i;
        }
    }
    mg_reencrypt_page(ctx, (uint32_t)ctx->active[lru]);
    ctx->active[lru] = ctx->active[ctx->active_count - 1];
    ctx->active_count--;
}

/*
 * Bring a PG_XOR_ENC page up to plaintext + RX and into the working set.
 * Hot path: XOR + CRC + two VirtualProtects, no allocation, no AES, no inflate.
 * Returns 0 on success, nonzero on failure (leaves the page dark on failure).
 */
static int mg_activate_page(MemGuardCtx *ctx, uint32_t gp)
{
    GuardPage *g = &ctx->pages[gp];
    DWORD old = 0;
    uint32_t crc;

    if (g->state == PG_ACTIVE) {
        return 0;   /* already resident (raced with another thread) */
    }
    if (ctx->active_count >= MEMGUARD_MAX_ACTIVE_PAGES) {
        mg_evict_lru(ctx);
    }

    /* Page is NOACCESS. Make it writable (non-executable under DEP) to decrypt. */
    if (!VirtualProtect(g->va, MG_PAGE_SIZE, PAGE_READWRITE, &old)) {
        return -1;
    }
    mg_xor_page(g->va, ctx->keys[gp], g->size);   /* XOR-decrypt in place */

    /* Integrity check: recovered plaintext must match the split-time baseline. */
    crc = mg_crc32(g->va, g->size);
    if (crc != g->crc) {
        mg_xor_page(g->va, ctx->keys[gp], g->size);           /* restore ct */
        VirtualProtect(g->va, MG_PAGE_SIZE, PAGE_NOACCESS, &old);
        return -1;
    }

    if (!VirtualProtect(g->va, MG_PAGE_SIZE, PAGE_EXECUTE_READ, &old)) {
        mg_xor_page(g->va, ctx->keys[gp], g->size);           /* restore ct */
        VirtualProtect(g->va, MG_PAGE_SIZE, PAGE_NOACCESS, &old);
        return -1;
    }
    FlushInstructionCache(GetCurrentProcess(), g->va, g->size);

    g->state = PG_ACTIVE;
    g->last_access = GetTickCount64();
    ctx->active[ctx->active_count++] = (int)gp;
    return 0;
}

/*
 * First-touch of a guarded section: AES-256-GCM decrypt + inflate the whole
 * section, compute a per-page CRC32 baseline, XOR-re-encrypt every page except
 * the faulting one, and bring the faulting page up. Marks the section SEC_SPLIT
 * once the pages are laid out. Runs under g_lock inside the VEH.
 * Returns 0 on success.
 */
static int mg_decrypt_section(MemGuardCtx *ctx, GuardSection *S,
                              uint32_t active_local)
{
    uint8_t   key[32];
    void     *scratch;
    DWORD     old = 0;
    mz_ulong  dlen;
    uint32_t  k, gp_active;
    uint64_t  now;
    int       rc;

    if (S->stored_size == 0 || S->uncompressed_size == 0) {
        return -1;
    }
    if (S->uncompressed_size > S->virtual_size) {
        return -1;
    }

    scratch = VirtualAlloc(NULL, S->stored_size, MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE);
    if (!scratch) {
        return -1;
    }
    VirtualLock(scratch, S->stored_size);

    /* Prefer the scattered key the loader left alive; else re-derive it. */
    if (key_scatter_get(key) != 0 &&
        crypto_derive_key(ctx->pi, ctx->image_base, key) != 0) {
        mg_zero(key, sizeof(key));
        VirtualFree(scratch, 0, MEM_RELEASE);
        return -1;
    }

    {
        uint8_t skey[32];
        uint32_t rva_aad = (uint32_t)((uint8_t *)S->va -
                                      (uint8_t *)ctx->image_base);
        if (lethe_derive_section_key(key, ctx->kdf_salt,
                                     rva_aad, skey) != 0) {
            mg_zero(key, sizeof(key));
            VirtualFree(scratch, 0, MEM_RELEASE);
            return -1;
        }
        mg_zero(key, sizeof(key));
        rc = crypto_aes256gcm_decrypt(skey, S->nonce, S->stored, S->stored_size,
                                      S->tag, (uint8_t *)scratch,
                                      &rva_aad, sizeof(rva_aad));
        mg_zero(skey, sizeof(skey));
    }
    if (rc != 0) {
        mg_zero(scratch, S->stored_size);
        VirtualFree(scratch, 0, MEM_RELEASE);
        return -1;
    }

    /* Whole section RW (non-executable under DEP) so we can inflate into it. */
    if (!VirtualProtect(S->va, S->virtual_size, PAGE_READWRITE, &old)) {
        mg_zero(scratch, S->stored_size);
        VirtualFree(scratch, 0, MEM_RELEASE);
        return -1;
    }

    dlen = (mz_ulong)S->uncompressed_size;
    rc = mz_uncompress((unsigned char *)S->va, &dlen,
                       (const unsigned char *)scratch, (mz_ulong)S->stored_size);
    mg_zero(scratch, S->stored_size);
    VirtualFree(scratch, 0, MEM_RELEASE);

    if (rc != MZ_OK || dlen != (mz_ulong)S->uncompressed_size) {
        VirtualProtect(S->va, S->virtual_size, PAGE_NOACCESS, &old);
        return -1;
    }

    mg_apply_relocs_in_range(ctx, S->va, S->uncompressed_size);

    /* Baseline every page's CRC, then immediately re-encrypt cold pages so the
     * whole-section plaintext window is as short as possible. */
    for (k = 0; k < S->page_count; ++k) {
        uint32_t gp = S->first_page + k;
        GuardPage *g = &ctx->pages[gp];
        g->crc = mg_crc32(g->va, g->size);
        if (k != active_local) {
            mg_xor_page(g->va, ctx->keys[gp], g->size);
            g->state = PG_XOR_ENC;
        }
    }

    /* Darken the whole section; the faulting page's plaintext survives (it was
     * not XORed) but is momentarily NOACCESS until we set it RX below. */
    VirtualProtect(S->va, S->virtual_size, PAGE_NOACCESS, &old);
    S->state = SEC_SPLIT;

    /* Bring the faulting page into the working set. */
    now = GetTickCount64();
    gp_active = S->first_page + active_local;
    {
        GuardPage *ga = &ctx->pages[gp_active];
        if (ctx->active_count >= MEMGUARD_MAX_ACTIVE_PAGES) {
            mg_evict_lru(ctx);
        }
        if (!VirtualProtect(ga->va, MG_PAGE_SIZE, PAGE_EXECUTE_READ, &old)) {
            /* Fall back: re-encrypt it so nothing plaintext lingers. Section is
             * already SEC_SPLIT, so a retry will route through mg_activate_page. */
            mg_xor_page(ga->va, ctx->keys[gp_active], ga->size);
            VirtualProtect(ga->va, MG_PAGE_SIZE, PAGE_NOACCESS, &old);
            ga->state = PG_XOR_ENC;
            return -1;
        }
        FlushInstructionCache(GetCurrentProcess(), ga->va, ga->size);
        ga->state = PG_ACTIVE;
        ga->last_access = now;
        ctx->active[ctx->active_count++] = (int)gp_active;
    }
    return 0;
}

/*
 * First-chance Vectored Exception Handler. Only acts on ACCESS_VIOLATIONs whose
 * faulting address lies inside a guarded, not-yet-resident page; everything else
 * is passed through (EXCEPTION_CONTINUE_SEARCH) so real faults are never masked.
 */
static LONG NTAPI memguard_veh(PEXCEPTION_POINTERS ep)
{
    MemGuardCtx *ctx = g_ctx;
    EXCEPTION_RECORD *er;
    ULONG_PTR fault;
    uint32_t i;

    if (!ctx || !ep || !ep->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    er = ep->ExceptionRecord;
    if (er->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
        er->NumberParameters < 2) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    fault = (ULONG_PTR)er->ExceptionInformation[1]; /* faulting VA */

    for (i = 0; i < ctx->sec_count; ++i) {
        GuardSection *S = &ctx->secs[i];
        ULONG_PTR lo = (ULONG_PTR)S->va;
        ULONG_PTR hi = lo + S->virtual_size;
        uint32_t local, gp;
        LONG result;

        if (fault < lo || fault >= hi) {
            continue;
        }

        local = (uint32_t)((fault - lo) / MG_PAGE_SIZE);
        gp = S->first_page + local;

        /* Fast path: already resident (benign race with another thread). */
        if (ctx->pages[gp].state == PG_ACTIVE) {
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        EnterCriticalSection(&g_lock);
        if (ctx->pages[gp].state == PG_ACTIVE) {
            result = EXCEPTION_CONTINUE_EXECUTION;
        } else if (S->state != SEC_SPLIT) {
            result = (mg_decrypt_section(ctx, S, local) == 0)
                         ? EXCEPTION_CONTINUE_EXECUTION
                         : EXCEPTION_CONTINUE_SEARCH;
        } else {
            result = (mg_activate_page(ctx, gp) == 0)
                         ? EXCEPTION_CONTINUE_EXECUTION
                         : EXCEPTION_CONTINUE_SEARCH;
        }
        LeaveCriticalSection(&g_lock);
        return result;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * Background sweeper: periodically re-encrypt working-set pages that have been
 * idle for more than MEMGUARD_IDLE_MS, so plaintext decays even without new
 * faults. A hot page that keeps executing without faulting will be re-encrypted
 * here and immediately re-faulted back in by the VEH (correct, just a little
 * churn) -- re-encryption sets NOACCESS first, so no thread ever executes the
 * scrambled bytes.
 */
static DWORD WINAPI memguard_reencrypt_thread(LPVOID param)
{
    MemGuardCtx *ctx = (MemGuardCtx *)param;
    if (!ctx) {
        return 0;
    }
    while (!ctx->shutting_down) {
        uint64_t now;
        int i;

        Sleep(MEMGUARD_SWEEP_MS);
        if (ctx->shutting_down) {
            break;
        }
        now = GetTickCount64();

        EnterCriticalSection(&g_lock);
        i = 0;
        while (i < ctx->active_count) {
            int gp = ctx->active[i];
            if (now - ctx->pages[gp].last_access > (uint64_t)MEMGUARD_IDLE_MS) {
                mg_reencrypt_page(ctx, (uint32_t)gp);
                ctx->active[i] = ctx->active[ctx->active_count - 1];
                ctx->active_count--;   /* re-check the swapped-in slot */
            } else {
                ++i;
            }
        }
        LeaveCriticalSection(&g_lock);
    }
    return 0;
}

/* Zero + unlock + release the guarded region. ctx lives INSIDE it, so capture
 * the fields we need before wiping. */
static void mg_free_region(MemGuardCtx *ctx)
{
    void   *rb = ctx->region_base;
    uint8_t *data = (uint8_t *)ctx;   /* ctx == committed-region start */
    SIZE_T  db = ctx->data_bytes;

    if (db) {
        mg_zero(data, db);
        VirtualUnlock(data, db);
    }
    if (rb) {
        VirtualFree(rb, 0, MEM_RELEASE);
    }
}

static uint8_t  *s_pending_reloc_blob  = NULL;
static uint32_t  s_pending_reloc_size  = 0;
static int64_t   s_pending_reloc_delta = 0;

void memguard_discard_pending_relocs(void)
{
    if (s_pending_reloc_blob) {
        mg_zero(s_pending_reloc_blob, s_pending_reloc_size);
        VirtualFree(s_pending_reloc_blob, 0, MEM_RELEASE);
        s_pending_reloc_blob = NULL;
    }
    s_pending_reloc_size  = 0;
    s_pending_reloc_delta = 0;
}

int memguard_set_relocs(const uint8_t *reloc_blob, uint32_t reloc_size,
                        int64_t delta)
{
    memguard_discard_pending_relocs();
    if (!reloc_blob || !reloc_size || delta == 0)
        return 0;
    s_pending_reloc_blob = (uint8_t *)VirtualAlloc(NULL, reloc_size,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!s_pending_reloc_blob)
        return 1;
    mg_copy(s_pending_reloc_blob, reloc_blob, reloc_size);
    s_pending_reloc_size  = reloc_size;
    s_pending_reloc_delta = delta;
    return 0;
}

static void mg_free_owned_relocs(MemGuardCtx *ctx)
{
    if (ctx && ctx->reloc_blob) {
        mg_zero(ctx->reloc_blob, ctx->reloc_size);
        VirtualFree(ctx->reloc_blob, 0, MEM_RELEASE);
        ctx->reloc_blob = NULL;
        ctx->reloc_size = 0;
        ctx->reloc_delta = 0;
    }
}

/* stub_hooks.h: reads flags bit3. */
int memguard_enabled(const PackInfo *pi)
{
    return (pi && (pi->flags & LETHE_FLAG_MEMGUARD)) ? 1 : 0;
}

/*
 * Install the guard. Returns 0 on success; nonzero on any failure (loader then
 * falls back to eager decryption of all sections).
 */
int memguard_install(void *image_base, const PackInfo *pi,
                     const SectionDesc *secs)
{
    MemGuardCtx *ctx;
    uint8_t     *region, *data;
    SIZE_T       off_secs, off_pages, off_keys, data_bytes, reserve_total;
    uint32_t     sec_count = 0, page_count = 0, i, j, gp;
    DWORD        old = 0;

    if (!image_base || !pi || !secs || !memguard_enabled(pi)) {
        return 1;
    }
    if (g_ctx) {
        return 1; /* install exactly once */
    }

    /* Count guarded (executable, non-empty) sections and their total pages. */
    for (i = 0; i < pi->section_count; ++i) {
        if ((secs[i].characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            secs[i].virtual_size != 0) {
            ++sec_count;
            page_count += (secs[i].virtual_size + MG_PAGE_SIZE - 1u) / MG_PAGE_SIZE;
        }
    }
    if (sec_count == 0) {
        /* Decline the install so the loader tears down the scattered key and
         * any staged relocation recipe instead of leaking no-op state. */
        return 1;
    }

    /* If the exception dispatch path is inline-hooked, an installed VEH could be
     * bypassed -> arming NOACCESS would then crash on the first code fault.
     * Decline to arm and let the loader eager-decrypt (contracted fallback). */
    if (mg_veh_path_hooked()) {
        return 1;
    }

    if (!g_lock_ready) {
        InitializeCriticalSection(&g_lock);
        g_lock_ready = 1;
    }

    /* Region layout: [ctx][secs[]][pages[]][keys[]], carved from one block. */
    off_secs   = mg_align8(sizeof(MemGuardCtx));
    off_pages  = mg_align8(off_secs  + (SIZE_T)sec_count  * sizeof(GuardSection));
    off_keys   = mg_align8(off_pages + (SIZE_T)page_count * sizeof(GuardPage));
    data_bytes = off_keys + (SIZE_T)page_count * 32u;

    /* Guard the guard: reserve [guard page][data...][guard page]; commit + lock
     * only the middle. The flanking pages stay reserved (any touch faults). */
    reserve_total = (SIZE_T)MG_PAGE_SIZE + mg_align_page(data_bytes) +
                    (SIZE_T)MG_PAGE_SIZE;
    region = (uint8_t *)VirtualAlloc(NULL, reserve_total, MEM_RESERVE,
                                     PAGE_NOACCESS);
    if (!region) {
        return 1;
    }
    data = (uint8_t *)VirtualAlloc(region + MG_PAGE_SIZE, data_bytes,
                                   MEM_COMMIT, PAGE_READWRITE);
    if (!data) {
        VirtualFree(region, 0, MEM_RELEASE);
        return 1;
    }
    VirtualLock(data, data_bytes);   /* best-effort: keep keys out of the pagefile */

    ctx = (MemGuardCtx *)data;       /* committed memory is zero-filled */
    ctx->image_base   = image_base;
    ctx->pi           = pi;
    mg_copy(ctx->kdf_salt, pi->kdf_salt, sizeof(ctx->kdf_salt));
    ctx->veh          = NULL;
    ctx->secs         = (GuardSection *)(data + off_secs);
    ctx->pages        = (GuardPage *)(data + off_pages);
    ctx->keys         = (uint8_t (*)[32])(data + off_keys);
    ctx->region_base  = region;
    ctx->reenc_thread = NULL;
    ctx->region_total = reserve_total;
    ctx->data_bytes   = data_bytes;
    ctx->sec_count    = sec_count;
    ctx->page_count   = page_count;
    ctx->active_count = 0;
    ctx->shutting_down = 0;
    ctx->reloc_blob   = s_pending_reloc_blob;
    ctx->reloc_size   = s_pending_reloc_size;
    ctx->reloc_delta  = s_pending_reloc_delta;
    s_pending_reloc_blob  = NULL;
    s_pending_reloc_size  = 0;
    s_pending_reloc_delta = 0;

    /* One random 32-byte XOR key per guarded page (bulk fill). */
    if (mg_rand(ctx->keys, (SIZE_T)page_count * 32u) != 0) {
        mg_free_owned_relocs(ctx);
        mg_zero(data, data_bytes);
        VirtualUnlock(data, data_bytes);
        VirtualFree(region, 0, MEM_RELEASE);
        return 1;
    }

    /* Snapshot section descriptors + fill per-page metadata. */
    j = 0;
    gp = 0;
    for (i = 0; i < pi->section_count; ++i) {
        const SectionDesc *sd = &secs[i];
        GuardSection *S;
        uint32_t vs, pc, k;

        if (!(sd->characteristics & IMAGE_SCN_MEM_EXECUTE) ||
            sd->virtual_size == 0) {
            continue;
        }
        vs = sd->virtual_size;
        S = &ctx->secs[j++];
        S->state            = SEC_ENCRYPTED;
        S->va               = (uint8_t *)image_base + sd->rva;
        S->stored           = (uint8_t *)image_base + sd->stored_rva;
        S->virtual_size     = vs;
        S->stored_size      = sd->stored_size;
        S->uncompressed_size = sd->uncompressed_size;
        S->characteristics  = sd->characteristics;
        mg_copy(S->nonce, sd->gcm_nonce, sizeof(S->nonce));
        mg_copy(S->tag,   sd->gcm_tag,   sizeof(S->tag));

        pc = (vs + MG_PAGE_SIZE - 1u) / MG_PAGE_SIZE;
        S->first_page = gp;
        S->page_count = pc;
        for (k = 0; k < pc; ++k) {
            GuardPage *g = &ctx->pages[gp];
            uint32_t off = k * MG_PAGE_SIZE;
            g->va         = S->va + off;
            g->size       = (vs - off < MG_PAGE_SIZE) ? (vs - off) : MG_PAGE_SIZE;
            g->sec_index  = (uint32_t)(j - 1u);
            g->crc        = 0;
            g->last_access = 0;
            g->state      = PG_UNINIT;
            ++gp;
        }
    }

    /* Publish, then register the first-chance VEH BEFORE arming NOACCESS. */
    g_ctx = ctx;
    ctx->veh = AddVectoredExceptionHandler(1 /* first */, memguard_veh);
    if (!ctx->veh) {
        g_ctx = NULL;
        mg_free_owned_relocs(ctx);
        mg_zero(data, data_bytes);
        VirtualUnlock(data, data_bytes);
        VirtualFree(region, 0, MEM_RELEASE);
        return 1;
    }

    /* Arm: mark each guarded section PAGE_NOACCESS. */
    for (j = 0; j < ctx->sec_count; ++j) {
        GuardSection *S = &ctx->secs[j];
        if (!VirtualProtect(S->va, S->virtual_size, PAGE_NOACCESS, &old)) {
            uint32_t m;
            for (m = 0; m < j; ++m) {
                DWORD t = 0;
                VirtualProtect(ctx->secs[m].va, ctx->secs[m].virtual_size,
                               PAGE_READWRITE, &t);
            }
            RemoveVectoredExceptionHandler(ctx->veh);
            g_ctx = NULL;
            mg_free_owned_relocs(ctx);
            mg_zero(data, data_bytes);
            VirtualUnlock(data, data_bytes);
            VirtualFree(region, 0, MEM_RELEASE);
            return 1;
        }
    }

    /* Start the idle-page sweeper for EXEs. A DLL cannot safely wait for its
     * worker during DLL_PROCESS_DETACH: the worker's DLL_THREAD_DETACH also
     * needs the loader lock, so joining it from DllMain deadlocks FreeLibrary.
     * DLLs retain the strict LRU working-set cap without the periodic sweep. */
    if (!pi->is_dll) {
        ctx->reenc_thread = CreateThread(NULL, 0, memguard_reencrypt_thread,
                                         ctx, 0, NULL);
    }
    return 0;
}

/*
 * Optional clean teardown. Stops the sweeper, removes the VEH, and wipes +
 * frees the guarded region (page keys included). Safe to call once; a no-op if
 * memguard was never installed.
 */
void memguard_shutdown(void)
{
    MemGuardCtx *ctx = g_ctx;
    if (!ctx) {
        memguard_discard_pending_relocs();
        return;
    }
    InterlockedExchange(&ctx->shutting_down, 1);
    if (ctx->reenc_thread) {
        WaitForSingleObject(ctx->reenc_thread, INFINITE);
        CloseHandle(ctx->reenc_thread);
        ctx->reenc_thread = NULL;
    }
    if (ctx->veh) {
        RemoveVectoredExceptionHandler(ctx->veh);
        ctx->veh = NULL;
    }
    mg_free_owned_relocs(ctx);
    g_ctx = NULL;
    mg_free_region(ctx);   /* wipes ctx too -- do not touch ctx afterwards */

    if (g_lock_ready) {
        DeleteCriticalSection(&g_lock);
        g_lock_ready = 0;
    }
    memguard_discard_pending_relocs();
}
