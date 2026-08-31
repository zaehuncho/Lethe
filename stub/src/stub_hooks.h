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
 * Extended anti-debug: runs all checks from antidbg_check() PLUS an INT3
 * (0xCC) scan of the stub's own .text section. Needs the image base and
 * stub .text bounds from PackInfo. Called after g_packinfo is located.
 */
int  antidbg_check_extended(const void *image_base, uint32_t text_rva,
                            uint32_t text_size);

/*
 * Scattered anti-debug tripwires (defense-in-depth).
 *
 * Each performs a SINGLE lightweight anti-debug check using a different
 * technique and independently wipes key material (g_packinfo.aes_key_enc,
 * kdf_salt) + calls ExitProcess on detection. Designed to be called at
 * multiple points during the unpack flow so that patching the main
 * antidbg_check() prologue alone does NOT defeat all detection.
 *
 * Each call site must be gated by (flags & LETHE_FLAG_ANTIDEBUG).
 */
void antidbg_tripwire_peb(void);    /* PEB->BeingDebugged              */
void antidbg_tripwire_ntgf(void);   /* PEB->NtGlobalFlag heap bits     */
void antidbg_tripwire_rdtsc(void);  /* RDTSC timing gate               */
void antidbg_tripwire_hwbp(void);   /* Hardware breakpoints (DR0-DR3)  */

/*
 * Post-load hardening (late phase).
 *
 * Called by the loader AFTER the image is fully unpacked (sections decrypted,
 * imports/relocs/TLS/exceptions applied, final page protections set) and just
 * before control transfers to the original entry point.
 *
 * PE headers are already destroyed by antidump_erase_headers() (called
 * immediately after section decryption, before imports).  This late call
 * performs only:
 *   1. Payload envelope wipe -- zero the compressed/encrypted metadata envelope
 *      (the unpack recipe) so a memory snapshot reveals no second copy.
 *      (Per-section stored ciphertext is wiped by the loader as it decrypts
 *      each non-guarded section; guarded sections are left for memguard.)
 *
 * Must tolerate being called exactly once and must never fail the process.
 * NOTE: must not wipe anything the running program still needs (e.g. the .rsrc
 * or the restored .pdata registered with RtlAddFunctionTable).
 */
void antidump_harden(void *image_base, const PackInfo *pi);

/*
 * Early header erasure.
 *
 * Called by the loader immediately after section decryption -- before import
 * resolution, relocations, TLS, or final page protections -- to destroy the
 * in-memory PE headers (MZ/PE signatures, section table, DOS stub, Rich
 * header) while sections are still RW.  This closes the window where a
 * breakpoint between section decryption and the late antidump_harden call
 * could yield a clean dump with intact PE headers + all plaintext sections.
 *
 * Import resolution, relocations, and TLS all consume the decrypted metadata
 * blob, never the in-memory PE headers, so erasure at this point is safe.
 * The payload envelope wipe remains in antidump_harden (it is independent of
 * the dump-readiness window).
 */
void antidump_erase_headers(void *image_base, int is_dll);

/*
 * Early pre-import hardening.
 *
 * Called by the loader BEFORE resolve_imports() so the process-mitigation
 * policies (extension-point disable, image-load hardening) and DLL search-
 * order pinning are in place BEFORE any LoadLibraryA calls. This prevents
 * injection via AppInit_DLLs or DLL-planting during import resolution.
 *
 * For a packed EXE: sets mitigation policies + pins DLL search order.
 * For a packed DLL: pins DLL search order only (must not impose process-
 * wide mitigations on the host).
 */
void antidump_harden_early(int is_dll);

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
 * consume. Idempotent; used by every eager-fallback and loader-failure path. */
void memguard_discard_pending_relocs(void);

/*
 * Install the memory guard (on-demand page decryption).
 *
 * Marks guarded (executable) sections PAGE_NOACCESS and registers a Vectored
 * Exception Handler that decrypts a page on first access (and may re-encrypt
 * cold pages) so that only the active working set is ever plaintext.
 *
 * CONTRACT: when memguard is enabled, the loader MUST NOT eagerly decrypt the
 * guarded executable sections -- memguard owns their contents and decrypts
 * them lazily. Non-executable sections are still eagerly decrypted by the
 * loader as usual. ``secs`` points at the already-decoded
 * SectionDesc[pi->section_count] (from the decrypted metadata buffer); memguard
 * needs their per-section nonce/tag to decrypt pages on demand.
 *
 * Returns 0 on success; nonzero on failure, in which case the loader falls back
 * to eager decryption of all sections.
 */
int  memguard_install(void *image_base, const PackInfo *pi,
                      const SectionDesc *secs);

/*
 * Clean teardown: stop the sweeper, remove the VEH, wipe + free the
 * guarded region. Safe to call once; no-op if memguard was never installed.
 * Called by the DLL stub on DLL_PROCESS_DETACH.
 */
void memguard_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* LETHE_STUB_HOOKS_H */
