/*
 * Lethe stub -- tamperguard.c
 *
 * Implements the OPT-IN runtime tamper-resistance monitor from stub_hooks.h:
 * tamperguard_install(image_base, pi) / tamperguard_shutdown(). Gated by
 * LETHE_FLAG_TAMPER_MONITOR (default OFF; builder --tamper-monitor), EXE-only,
 * and fail-closed.
 *
 * -------------------------------------------------------------------------
 * WHY
 * -------------------------------------------------------------------------
 * Today Lethe's anti-tamper signals fire ONCE, during unpack. An analyst who
 * attaches a debugger, sets a hardware breakpoint, or patches a code page AFTER
 * the OEP is reached slips past the startup gate. This module adds a single
 * background worker that re-runs the periodic-safe subset of the existing checks
 * on a jittered interval, plus continuous self/VM-page integrity, and terminates
 * deterministically (after wiping key material) on any detection. A clean run is
 * a pure no-op: it never modifies executable bytes, never touches OEP execution,
 * and never false-positives on an unobserved process.
 *
 * -------------------------------------------------------------------------
 * WHAT RUNS EACH TICK (all AV-benign, all fail-closed)
 * -------------------------------------------------------------------------
 *   1. antidbg_run_runtime_battery(seed)   -- CheckRemoteDebuggerPresent,
 *      NtQIP(ProcessDebugPort / ProcessDebugObjectHandle), RDTSC timing gate
 *      (the periodic-safe subset reused from antidebug.c; order rotated by seed).
 *   2. memguard_verify_active_pages()       -- recompute the CRC32 of every
 *      resident (PG_ACTIVE) guarded page vs its split-time baseline (VM-page
 *      integrity), under memguard's own lock.
 *   3. tg_check_hw_breakpoints()            -- DR0-DR3 hardware-breakpoint probe
 *      of the OEP thread via GetThreadContext(THREAD_GET_CONTEXT). (This probe
 *      lives here, not in antidebug.c, because the antidebug release contract
 *      forbids a self-GetThreadContext in that translation unit.)
 *   4. tg_check_self_integrity()            -- CRC32 of the stub's own .text
 *      region (the loader/monitor code an attacker would patch to defeat this
 *      monitor) vs a baseline captured at install.
 *
 * -------------------------------------------------------------------------
 * TERMINATION / WIPE PATH (fail closed)
 * -------------------------------------------------------------------------
 * On ANY positive result the worker: (a) revokes the scattered master-key
 * fragments, (b) wipes g_packinfo's key material, (c) tears down memguard (which
 * wipes the per-page keys), then (d) TerminateProcess, with __fastfail as a
 * last resort. The master-key wipe happens FIRST, so even if a later step races
 * a faulting thread the secret is already gone before the process dies.
 *
 * -------------------------------------------------------------------------
 * GUARD-PAGE LAYOUT (mirrors memguard.c's "guard the guard")
 * -------------------------------------------------------------------------
 * The monitor context lives in a private region reserved as
 * [ NOACCESS guard page ][ committed + VirtualLock'd data ][ NOACCESS guard
 * page ]: only the middle is committed and locked (so it never hits the
 * pagefile), and any stray touch of a flanking page faults. On shutdown the data
 * is zeroed, unlocked, and released; the worker is signalled and joined first so
 * it never dereferences freed state.
 *
 * -------------------------------------------------------------------------
 * GUARDRAILS
 * -------------------------------------------------------------------------
 * No ThreadHideFromDebugger, no int 2d / int 3, no self-modifying .text, no RWX.
 * This is tamper DETECTION that fails closed, not AV/EDR evasion.
 *
 * Freestanding / no-CRT: Win32 (kernel32) + crypto.c (bcrypt CSPRNG + secure
 * wipe) + miniz (mz_crc32) + MSVC intrinsics only.
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

#include "tamperguard.h"
#include "stub_hooks.h"    /* antidbg_run_runtime_battery, memguard_* */
#include "crypto.h"        /* crypto_csprng, orion_secure_wipe        */
#include "key_scatter.h"   /* key_scatter_invalidate                  */
#include "miniz.h"         /* mz_crc32, MZ_CRC32_INIT, mz_ulong       */

#include "stub_intrin.h"

/* Per-build seed, derived from DVM_SHUFFLE_SEED by CMake (TAMPER_SEED). Mixed
 * with runtime CSPRNG entropy at install so the sampling cadence is neither
 * predictable across runs nor identical between two copies of the same build. */
#ifndef LETHE_TAMPER_SEED
#define LETHE_TAMPER_SEED 0xA5F00D1Eu
#endif

#define TG_PAGE_SIZE          4096u

/* Jittered sampling interval bounds (milliseconds). Cheap enough to be
 * imperceptible, frequent enough to bound an attacker's undetected window. */
#define TG_INTERVAL_MIN_MS    500u
#define TG_INTERVAL_MAX_MS    1500u

typedef struct TamperCtx {
    void          *image_base;
    const uint8_t *self_base;     /* image_base + stub_text_rva (RX, reloc-free) */
    uint32_t       self_size;     /* stub_text_size                             */
    uint32_t       self_crc;      /* baseline CRC32 of the stub .text           */
    uint32_t       seed;          /* build seed XOR runtime entropy             */
    HANDLE         worker;        /* monitor thread                             */
    HANDLE         stop_evt;      /* manual-reset shutdown signal               */
    HANDLE         oep_thread;    /* duplicated handle to the OEP thread (DR)    */
    void          *region_base;   /* VirtualAlloc reservation (leading guard)   */
    SIZE_T         region_total;  /* full reservation byte count                */
    SIZE_T         data_bytes;    /* committed + locked middle byte count       */
} TamperCtx;

/* One packed module per process -> one monitor. */
static TamperCtx * volatile g_tg = NULL;

/* Loader's persistent PackInfo sentinel (defined in stub_main.c); wiped on a
 * fail-closed termination so a resumed/dumped process finds no key. */
extern volatile PackInfo g_packinfo;

/* ---- no-CRT helpers ----------------------------------------------------- */

static void tg_zero(void *p, SIZE_T n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    SIZE_T i;
    if (p && n) {
        for (i = 0; i < n; ++i) vp[i] = 0;
    }
}

static SIZE_T tg_align_page(SIZE_T n)
{
    SIZE_T mask = (SIZE_T)TG_PAGE_SIZE - 1u;
    return (n + mask) & ~mask;
}

static uint32_t tg_crc32(const void *p, uint32_t n)
{
    return (uint32_t)mz_crc32((mz_ulong)MZ_CRC32_INIT,
                              (const unsigned char *)p, (size_t)n);
}

/* ---- individual checks -------------------------------------------------- */

/* CRC32 of the stub's own .text vs the install-time baseline. The .text is the
 * loader/monitor code itself; patching it (e.g. NOP'ing this monitor's exit) is
 * exactly what this catches. Returns nonzero on mismatch. */
static int tg_check_self_integrity(const TamperCtx *ctx)
{
    if (!ctx->self_base || ctx->self_size == 0u) {
        return 0;   /* no region to hash -> nothing to verify */
    }
    return tg_crc32(ctx->self_base, ctx->self_size) != ctx->self_crc ? 1 : 0;
}

/* DR0-DR3 hardware-breakpoint probe of the OEP thread. A non-suspending read is
 * used deliberately: it never disturbs the host and cannot false-positive (a
 * clean thread reports zeroed debug registers). Returns nonzero if any of the
 * four address registers is set. */
static int tg_check_hw_breakpoints(const TamperCtx *ctx)
{
    CONTEXT c;
    if (!ctx->oep_thread) {
        return 0;
    }
    tg_zero(&c, sizeof(c));
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(ctx->oep_thread, &c)) {
        return 0;   /* cannot read -> do not false-positive */
    }
    if (c.Dr0 || c.Dr1 || c.Dr2 || c.Dr3) {
        return 1;
    }
    return 0;
}

/* Run one full battery tick. Returns nonzero on the first detection. */
static int tg_run_checks(const TamperCtx *ctx, uint32_t tick)
{
    uint32_t seed = ctx->seed ^ (tick * 0x9E3779B9u);

    if (antidbg_run_runtime_battery(seed)) {
        return 1;
    }
    if (memguard_verify_active_pages()) {
        return 1;
    }
    if (tg_check_hw_breakpoints(ctx)) {
        return 1;
    }
    if (tg_check_self_integrity(ctx)) {
        return 1;
    }
    return 0;
}

/* ---- fail-closed termination -------------------------------------------- */

/* Destroy remaining sensitive material, then terminate deterministically. Never
 * returns. The master-key wipe is first so the secret is gone before any later
 * step can race a faulting thread. */
static void tg_fail_closed(void)
{
    /* (a) revoke the scattered master-key fragments. */
    key_scatter_invalidate();
    /* (b) wipe the code-hash-bound key + salt in the persistent PackInfo. */
    orion_secure_wipe((void *)(uintptr_t)g_packinfo.aes_key_enc,
                      sizeof(g_packinfo.aes_key_enc));
    orion_secure_wipe((void *)(uintptr_t)g_packinfo.kdf_salt,
                      sizeof(g_packinfo.kdf_salt));
    /* (c) tear down memguard: wipes the per-page keys + guarded region. */
    memguard_shutdown();
    /* (d) deterministic termination; __fastfail if the kernel refuses. */
    (void)TerminateProcess(GetCurrentProcess(), (UINT)ERROR_INVALID_DATA);
    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
}

/* ---- worker ------------------------------------------------------------- */

/* Pseudo-random jittered interval in [TG_INTERVAL_MIN_MS, TG_INTERVAL_MAX_MS].
 * Deterministic given (seed, tick) but unpredictable to an observer without the
 * seed, so the cadence cannot be trivially paused between fixed ticks. */
static DWORD tg_next_interval(const TamperCtx *ctx, uint32_t tick)
{
    uint32_t j = ctx->seed ^ (tick * 2654435761u);
    j ^= j >> 13;
    j *= 0x5BD1E995u;
    j ^= j >> 15;
    return (DWORD)(TG_INTERVAL_MIN_MS +
                   (j % (TG_INTERVAL_MAX_MS - TG_INTERVAL_MIN_MS + 1u)));
}

static DWORD WINAPI tg_worker(LPVOID param)
{
    TamperCtx *ctx = (TamperCtx *)param;
    uint32_t tick = 0;

    for (;;) {
        DWORD wait_ms = tg_next_interval(ctx, tick);
        DWORD w = WaitForSingleObject(ctx->stop_evt, wait_ms);
        if (w != WAIT_TIMEOUT) {
            /* Signalled (clean shutdown) or the wait failed: stop the worker. */
            return 0;
        }
        if (tg_run_checks(ctx, tick)) {
            tg_fail_closed();   /* never returns */
        }
        ++tick;
    }
}

/* ---- install / shutdown ------------------------------------------------- */

int tamperguard_install(void *image_base, const PackInfo *pi)
{
    TamperCtx *ctx;
    uint8_t   *region, *data;
    SIZE_T     data_bytes, reserve_total;
    uint32_t   rt_entropy = 0;

    if (!image_base || !pi || !(pi->flags & LETHE_FLAG_TAMPER_MONITOR)) {
        return 1;
    }
    if (pi->is_dll) {
        return 1;   /* EXE-only: a DLL cannot safely own a monitor thread */
    }
    if (g_tg) {
        return 1;   /* install exactly once */
    }

    /* CRC contract self-test: refuse to arm if the CRC implementation ever
     * diverges from the pinned zlib.crc32 vector (fail closed). */
    if (tg_crc32((const uint8_t *)TG_CRC_CONTRACT_INPUT,
                 (uint32_t)(sizeof(TG_CRC_CONTRACT_INPUT) - 1u))
            != TG_CRC_CONTRACT_VALUE) {
        return 1;
    }

    /* Region: [guard page][committed+locked data][guard page]. */
    data_bytes    = tg_align_page(sizeof(TamperCtx));
    reserve_total = (SIZE_T)TG_PAGE_SIZE + data_bytes + (SIZE_T)TG_PAGE_SIZE;

    region = (uint8_t *)VirtualAlloc(NULL, reserve_total, MEM_RESERVE,
                                     PAGE_NOACCESS);
    if (!region) {
        return 1;
    }
    data = (uint8_t *)VirtualAlloc(region + TG_PAGE_SIZE, data_bytes,
                                   MEM_COMMIT, PAGE_READWRITE);
    if (!data) {
        VirtualFree(region, 0, MEM_RELEASE);
        return 1;
    }
    if (!VirtualLock(data, data_bytes)) {
        tg_zero(data, data_bytes);
        VirtualFree(region, 0, MEM_RELEASE);
        return 1;
    }

    ctx = (TamperCtx *)data;   /* committed memory is zero-filled */
    ctx->image_base   = image_base;
    ctx->self_base    = (const uint8_t *)image_base + pi->stub_text_rva;
    ctx->self_size    = pi->stub_text_size;
    ctx->self_crc     = tg_crc32(ctx->self_base, ctx->self_size);
    ctx->region_base  = region;
    ctx->region_total = reserve_total;
    ctx->data_bytes   = data_bytes;

    if (crypto_csprng(&rt_entropy, sizeof(rt_entropy)) != 0) {
        rt_entropy = (uint32_t)GetTickCount64();
    }
    ctx->seed = (uint32_t)LETHE_TAMPER_SEED ^ rt_entropy;

    /* Duplicate the current (OEP) thread handle for the DR probe. Optional: a
     * failure just makes the hardware-breakpoint check a no-op. */
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                         GetCurrentProcess(), &ctx->oep_thread,
                         THREAD_GET_CONTEXT, FALSE, 0)) {
        ctx->oep_thread = NULL;
    }

    ctx->stop_evt = CreateEventW(NULL, TRUE /* manual reset */, FALSE, NULL);
    if (!ctx->stop_evt) {
        if (ctx->oep_thread) {
            CloseHandle(ctx->oep_thread);
        }
        tg_zero(data, data_bytes);
        VirtualUnlock(data, data_bytes);
        VirtualFree(region, 0, MEM_RELEASE);
        return 1;
    }

    /* Publish before starting the worker so the worker sees a complete ctx. */
    g_tg = ctx;

    ctx->worker = CreateThread(NULL, 0, tg_worker, ctx, 0, NULL);
    if (!ctx->worker) {
        g_tg = NULL;
        CloseHandle(ctx->stop_evt);
        if (ctx->oep_thread) {
            CloseHandle(ctx->oep_thread);
        }
        tg_zero(data, data_bytes);
        VirtualUnlock(data, data_bytes);
        VirtualFree(region, 0, MEM_RELEASE);
        return 1;
    }

    return 0;
}

void tamperguard_shutdown(void)
{
    TamperCtx *ctx = g_tg;
    HANDLE worker, stop_evt, oep_thread;
    void  *region;
    SIZE_T data_bytes;

    if (!ctx) {
        return;
    }
    g_tg = NULL;

    worker     = ctx->worker;
    stop_evt   = ctx->stop_evt;
    oep_thread = ctx->oep_thread;
    region     = ctx->region_base;
    data_bytes = ctx->data_bytes;

    /* Signal + join the worker before freeing the region it reads. */
    if (stop_evt) {
        SetEvent(stop_evt);
    }
    if (worker) {
        (void)WaitForSingleObject(worker, 5000);
        CloseHandle(worker);
    }
    if (stop_evt) {
        CloseHandle(stop_evt);
    }
    if (oep_thread) {
        CloseHandle(oep_thread);
    }

    /* ctx lives INSIDE the region: wipe, unlock, release. */
    tg_zero((void *)ctx, data_bytes);
    VirtualUnlock((void *)ctx, data_bytes);
    if (region) {
        VirtualFree(region, 0, MEM_RELEASE);
    }
}
