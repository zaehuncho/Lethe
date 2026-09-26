/*
 * Lethe stub hook interface -- the frozen boundary between the core loader
 * (stub_main.c / pe_loader.c) and the anti-analysis modules (antidebug.c /
 * antidump.c / memguard.c). Do NOT change these signatures without updating
 * both sides.
 *
 * The loader OWNS the call sites; the anti-analysis modules OWN the
 * implementations. All functions must be robust: they run in a bare loader
 * context (no CRT guarantees) and must never crash the host process.
 */
#ifndef LETHE_STUB_HOOKS_H
#define LETHE_STUB_HOOKS_H

#include "pack_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Gated debugger / analysis-environment detection.
 *
 * Returns nonzero if a debugger or analysis environment is detected, else 0.
 * Called early by the loader (before decryption). When it returns nonzero the
 * loader performs a CLEAN early exit (ExitProcess), never a crash. Must honor
 * LETHE_FLAG_ANTIDEBUG: if the flag is clear the loader will not call this, but
 * the implementation should still be self-contained. Keep the checks cheap and
 * AV-benign (PEB->BeingDebugged, NtGlobalFlag, CheckRemoteDebuggerPresent, one
 * RDTSC timing gate). Do NOT use ThreadHideFromDebugger, int 2d/int 3 tricks,
 * API-name hashing, or self-modifying code.
 */
int  antidbg_check(void);

/*
 * Extended anti-debug entry. The image/text parameters are retained for ABI
 * stability; current MSVC padding makes byte-pattern INT3 scans unsound, so it
 * delegates to the layered checks in antidbg_check().
 */
int  antidbg_check_extended(const void *image_base, uint32_t text_rva,
                            uint32_t text_size);

/*
 * Scattered anti-debug tripwires (defense-in-depth).
 *
 * Each performs a SINGLE lightweight anti-debug check using a different
 * technique and independently wipes key material (g_packinfo.aes_key_enc and
 * kdf_salt), then returns detection to the EXE/DLL-aware caller. Designed to
 * run at multiple points during the unpack flow so patching the main
 * antidbg_check() prologue alone does NOT defeat all detection.
 *
 * Each call site must be gated by (flags & LETHE_FLAG_ANTIDEBUG).
 */
int antidbg_tripwire_peb(void);    /* PEB->BeingDebugged              */
int antidbg_tripwire_ntgf(void);   /* PEB->NtGlobalFlag heap bits     */
int antidbg_tripwire_rdtsc(void);  /* RDTSC timing gate               */
int antidbg_tripwire_hwbp(void);   /* Hardware breakpoints (DR0-DR3)  */

/*
 * Periodic-safe anti-debug battery for the runtime tamper monitor.
 *
 * Re-runs ONLY the subset of the existing antidebug checks that stay correct
 * when invoked repeatedly long after startup (i.e. that catch attach-after-start
 * without false-positiving on a clean process): CheckRemoteDebuggerPresent, the
 * NtQIP ProcessDebugPort / ProcessDebugObjectHandle kernel queries, and the
 * RDTSC timing gate. It does NOT re-read the process-creation-time PEB/heap
 * flags (those describe how the process was launched, not a live attach).
 *
 * ``seed`` rotates the check order per invocation so a single patched prologue
 * cannot silently defeat the whole battery across ticks. Returns nonzero on
 * confident detection (and, like the tripwires, destroys the key material first
 * so a resumed process finds nothing to lift); 0 on a clean tick. AV-benign;
 * never crashes, never calls ExitProcess/TerminateProcess itself.
 */
int antidbg_run_runtime_battery(uint32_t seed);

/*
 * Post-load hardening (late phase).
 *
 * Called by the loader AFTER the image is fully unpacked (sections decrypted,
 * imports/relocs/TLS/exceptions applied, final page protections set) and just
 * before control transfers to the original entry point.
 *
 * PE headers are already sanitized by antidump_erase_headers() (called
 * immediately after section decryption, before imports).  This late call
 * performs only:
 *   1. Payload envelope wipe -- zero the compressed/encrypted metadata envelope
 *      (the unpack recipe) so a memory snapshot reveals no second copy.
 *      (Per-section stored ciphertext is wiped by the loader as it decrypts
 *      each non-guarded section; guarded sections are left for memguard.)
 *
 * Called exactly once. Returns nonzero if the envelope cannot be wiped and its
 * prior page protection restored and verified; the loader then fails closed.
 * NOTE: must not wipe anything the running program still needs (e.g. the .rsrc
 * or the restored .pdata registered with RtlAddFunctionTable).
 */
int antidump_harden(void *image_base, const PackInfo *pi);

/*
 * Early header sanitization.
 *
 * Called by the loader immediately after section decryption -- before import
 * resolution, relocations, TLS, or final page protections -- to clear the DOS
 * stub/Rich bytes, original entry point, checksum, and consumed directories.
 * The MZ/PE chain and section table remain valid because Windows resource,
 * module-introspection, and export APIs continue to parse them after startup.
 *
 * Import resolution, relocations, and TLS all consume the decrypted metadata
 * blob, never the in-memory PE headers, so sanitization at this point is safe.
 * The payload envelope wipe remains in antidump_harden (it is independent of
 * the dump-readiness window).
 */
int antidump_erase_headers(void *image_base, int is_dll);

/*
 * Explicit irreversible process hardening.
 *
 * Called only when authenticated LETHE_FLAG_PROCESS_HARDENING is set, after
 * fallback imports are loaded. For an EXE it verifies mitigation policy and
 * pins default DLL search directories. DLLs are rejected because these are
 * process-global host mutations. Returns nonzero on missing/failed policy.
 */
int antidump_harden_early(int is_dll);

/*
 * Returns nonzero iff the memory guard is requested for this image
 * (PackInfo.flags & LETHE_FLAG_MEMGUARD).
 */
int  memguard_enabled(const PackInfo *pi);

/*
 * Hand the relocation data to memguard BEFORE memguard_install(). memguard
 * makes its own copy (the caller's metadata buffer is freed after load).
 * delta = actual_base - preferred_image_base (same delta apply_relocs uses).
 * Safe to call with no relocation work (no-op). Returns zero when the
 * relocation recipe is safely staged, nonzero when its private allocation
 * fails. The loader must not arm memguard after a nonzero result.
 */
int  memguard_set_relocs(const uint8_t *reloc_blob, uint32_t reloc_size,
                         int64_t delta);

/* Wipe and release a staged relocation recipe that memguard_install() did not
 * consume. Idempotent; used by every loader-failure path. */
void memguard_discard_pending_relocs(void);

/*
 * Install the memory guard (on-demand page decryption).
 *
 * Marks guarded (executable) sections PAGE_NOACCESS and registers a Vectored
 * Exception Handler that decrypts a page on first access. Activated native
 * pages remain immutable RX for the module lifetime; VM bytecode uses the
 * separately authenticated one-page cache when bounded plaintext is required.
 *
 * CONTRACT: when memguard is enabled, the loader MUST NOT eagerly decrypt the
 * guarded executable sections -- memguard owns their contents and decrypts
 * them lazily. Non-executable sections are still eagerly decrypted by the
 * loader as usual. ``secs`` points at the already-decoded
 * SectionDesc[pi->section_count] (from the decrypted metadata buffer); memguard
 * needs their per-section nonce/tag to decrypt pages on demand.
 *
 * Returns 0 on success; nonzero on failure. An authenticated request is
 * mandatory, so the loader fails startup instead of exposing eager plaintext.
 */
int  memguard_install(void *image_base, const PackInfo *pi,
                      const SectionDesc *secs);

/*
 * Clean teardown: stop the sweeper, remove the VEH, wipe + free the
 * guarded region. Safe to call once; no-op if memguard was never installed.
 * Called by the DLL stub on DLL_PROCESS_DETACH.
 */
void memguard_shutdown(void);

/*
 * Continuous self-integrity check for the runtime tamper monitor.
 *
 * Under the existing memguard lock, recompute the CRC32 of every currently
 * PG_ACTIVE (plaintext, immutable-RX) guarded page and compare it against the
 * split-time baseline captured when the section was first faulted in. Returns
 * nonzero if ANY active page's plaintext no longer matches its baseline (a
 * patched code page), else 0. A no-op returning 0 when memguard is not
 * installed. Does not mutate the page-state machine; read-only verification.
 */
int memguard_verify_active_pages(void);

/*
 * Runtime tamper-resistance monitor (opt-in, LETHE_FLAG_TAMPER_MONITOR).
 *
 * Installed by the loader at the tls_process_attach step (EXE only), after every
 * final page protection is set and the metadata envelope is wiped. Spawns a
 * single background worker that, on a jittered interval, re-runs the
 * periodic-safe anti-debug battery (antidbg_run_runtime_battery), the memguard
 * self-integrity check (memguard_verify_active_pages), a hardware-breakpoint
 * (DR0-DR3) probe, and a CRC self-check of the stub's own .text. Any positive
 * result FAILS CLOSED: it wipes the remaining key material and terminates the
 * process deterministically. A clean run is a pure no-op that never touches OEP
 * execution. Its context lives in a VirtualLock'd, guard-page-flanked region.
 *
 * Returns 0 on success (monitor armed); nonzero on failure. The loader treats an
 * authenticated tamper-monitor request as best-effort defense-in-depth layered
 * over the mandatory checks, but installs it fail-closed like memguard.
 */
int  tamperguard_install(void *image_base, const PackInfo *pi);

/*
 * Clean teardown: signal + join the worker, remove state, wipe + free the
 * guard-page-flanked context. Safe to call once; no-op if never installed.
 */
void tamperguard_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* LETHE_STUB_HOOKS_H */
