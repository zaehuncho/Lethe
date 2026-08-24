/*
 * Lethe stub -- antidump.c
 *
 * Two-phase antidump hardening (stub_hooks.h):
 *
 * PHASE 1 -- antidump_erase_headers() [EARLY, right after section decryption]:
 *   In-memory PE header erasure -- destroy MZ / "PE\0\0" signatures, the
 *   AddressOfEntryPoint, the consumed data-directory entries, the whole
 *   section table, and the DOS stub + Rich header (a linker/toolchain
 *   fingerprint) so header-driven dumpers (PE-sieve / Scylla / naive MZ+PE
 *   scanners) cannot rebuild the image. Called BEFORE imports/relocs/TLS/
 *   VirtualProtect so headers are gone before the image is in a dumpable
 *   state with plaintext sections. A packed DLL keeps its 64-byte DOS header
 *   + NT signature + export directory so post-unpack GetProcAddress still
 *   resolves.
 *
 * PHASE 2 -- antidump_harden() [LATE, after full unpack]:
 *   1. Payload wipe -- zero the compressed+encrypted metadata envelope
 *      ([base+meta_rva, meta_stored_size]). That envelope holds the entire
 *      SectionDesc table (per-section stored_rva / nonce / tag map), the import
 *      blob, the reloc blob and the TLS blob -- i.e. the whole unpack "recipe."
 *      Destroying it denies a dumper the map needed to locate or decrypt any
 *      leftover stored section bytes.
 *
 * Separately, antidump_harden_early() handles pre-import hardening:
 *   Anti-injection (packed EXE only) -- best-effort SetProcessMitigationPolicy:
 *   extension-point disable (blocks AppInit_DLLs / global SetWindowsHookEx
 *   hooks / Winsock LSP / IME injection) and image-load hardening
 *   (NoRemoteImages + PreferSystem32Images). Deliberately NOT
 *   MicrosoftSignedOnly or ProhibitDynamicCode: either would break THIS
 *   product -- the payload loads its own unsigned Qt DLLs, memguard remaps
 *   pages RX on demand for the process lifetime, and the payload's QML/V4
 *   engine JITs. Resolved dynamically; failures ignored so the binary still
 *   runs on OSes lacking a given policy. Skipped for a packed DLL (must not
 *   impose process-wide policy on an unwitting host process).
 *
 * Freestanding / no-CRT: Win32 (kernel32) + __stosb intrinsic only. No CRT.
 *
 * =========================================================================
 * SEAM NOTE (per-section stored-byte wipe) -- read before integrating:
 *   The hook contract also lists "zero each section's [base+stored_rva,
 *   stored_size]". That wipe requires the decoded SectionDesc[] array, which
 *   lives in the loader's decrypted-metadata scratch (PackInfo.sections_off is
 *   an offset INTO that buffer, not a module RVA) -- and antidump_harden's
 *   frozen signature receives only (image_base, pi), NOT secs. We therefore
 *   destroy the metadata ENVELOPE here (step 2), which removes the map that
 *   makes leftover stored bytes usable, and delegate the optional per-section
 *   zeroing to the LOADER, which holds secs in its decrypt loop and can zero
 *   each NON-guarded section's stored bytes right after decrypting it.
 *
 *   CRITICAL memguard interaction: when LETHE_FLAG_MEMGUARD is set, the loader
 *   must NOT wipe guarded (executable) sections' stored bytes -- memguard.c
 *   decrypts them lazily from [base+stored_rva] on page-fault. Wiping the
 *   metadata envelope here is safe for memguard: memguard snapshots the
 *   SectionDesc fields it needs into its own storage at install time and reads
 *   ciphertext from stored_rva (a different region), never from meta_rva.
 * =========================================================================
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <intrin.h>
#include "stub_intrin.h"
#include <stdint.h>

#include "stub_hooks.h"

/* No-CRT zero fill: rep stosb, never elided, no memset dependency. */
static void ad_zero(void *p, SIZE_T n)
{
    if (p && n) {
        __stosb((unsigned char *)p, 0, n);
    }
}

/* Zero a single optional-header data-directory entry (VA + size). */
static void ad_clear_dir(IMAGE_NT_HEADERS64 *nt, unsigned idx)
{
    if (idx < nt->OptionalHeader.NumberOfRvaAndSizes) {
        nt->OptionalHeader.DataDirectory[idx].VirtualAddress = 0;
        nt->OptionalHeader.DataDirectory[idx].Size = 0;
    }
}

/*
 * Step 1: erase the in-memory PE headers.
 *
 * We deliberately DO NOT touch data directories the running program (or the OS)
 * may still need in memory:
 *   - Export (0):    a packed DLL's GetProcAddress reads it live post-unpack.
 *   - Resource (2):  runtime FindResource/LoadResource + .rsrc must stay usable.
 *   - Exception (3): left intact (harmless; we register .pdata via
 *                    RtlAddFunctionTable, but leaving the dir costs nothing).
 *   - Security (4) / BaseReloc (5) / LoadConfig (10): left intact (low value to
 *                    wipe, some are consulted by the OS/runtime).
 * We DO clear directories that are fully consumed by unpack and never re-read:
 *   Import (1), Debug (6), TLS (9), Bound Import (11), IAT (12).
 */
static void erase_headers(void *image_base, int is_dll)
{
    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER *)image_base;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sections;
    DWORD  size_of_headers;
    WORD   number_of_sections;
    WORD   size_of_optional;
    DWORD  e_lfanew_orig;
    DWORD  old_prot = 0, tmp_prot = 0;

    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return;
    }
    nt = (IMAGE_NT_HEADERS64 *)((uint8_t *)image_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }
    e_lfanew_orig = (DWORD)dos->e_lfanew;   /* capture before the DOS wipe below */

    size_of_headers   = nt->OptionalHeader.SizeOfHeaders;
    number_of_sections = nt->FileHeader.NumberOfSections;
    size_of_optional  = nt->FileHeader.SizeOfOptionalHeader;
    sections = (IMAGE_SECTION_HEADER *)((uint8_t *)&nt->OptionalHeader +
                                        size_of_optional);

    if (size_of_headers == 0) {
        size_of_headers = 0x1000;
    }

    if (!VirtualProtect(image_base, size_of_headers, PAGE_READWRITE, &old_prot)) {
        return;
    }

    ad_clear_dir(nt, IMAGE_DIRECTORY_ENTRY_IMPORT);
    ad_clear_dir(nt, IMAGE_DIRECTORY_ENTRY_DEBUG);
    ad_clear_dir(nt, IMAGE_DIRECTORY_ENTRY_TLS);
    ad_clear_dir(nt, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
    ad_clear_dir(nt, IMAGE_DIRECTORY_ENTRY_IAT);

    nt->OptionalHeader.AddressOfEntryPoint     = 0;
    nt->OptionalHeader.CheckSum                = 0;
    nt->OptionalHeader.SizeOfCode              = 0;
    nt->OptionalHeader.SizeOfInitializedData   = 0;
    nt->OptionalHeader.SizeOfUninitializedData = 0;
    nt->OptionalHeader.BaseOfCode              = 0;

    if (number_of_sections) {
        ad_zero(sections,
                (SIZE_T)number_of_sections * sizeof(IMAGE_SECTION_HEADER));
    }

    nt->FileHeader.NumberOfSections   = 0;

    /*
     * Wipe the DOS stub + Rich header: the "This program cannot be run in DOS
     * mode" stub and the MSVC Rich header (a linker/toolchain-version
     * fingerprint analysts use to cluster samples). Neither is referenced at
     * runtime. For a DLL keep the 64-byte DOS header intact (the MZ -> PE ->
     * export walk GetProcAddress performs still needs e_magic + e_lfanew); for
     * an EXE nothing walks it, so wipe from the image base. Guarded so a
     * pathological e_lfanew <= sizeof(DOS header) never underflows the span.
     */
    if (e_lfanew_orig > sizeof(IMAGE_DOS_HEADER)) {
        SIZE_T dos_keep = is_dll ? sizeof(IMAGE_DOS_HEADER) : 0;
        ad_zero((uint8_t *)image_base + dos_keep,
                (SIZE_T)e_lfanew_orig - dos_keep);
    }

    /*
     * For DLLs, preserve the MZ → PE → optional header path:
     * GetProcAddress walks DOS.e_lfanew → NT signature → data
     * directory[0] (export) to resolve exports.  Destroying any
     * link in that chain breaks all post-unpack GetProcAddress calls.
     */
    if (!is_dll) {
        nt->FileHeader.SizeOfOptionalHeader = 0;
        nt->Signature = 0;
        dos->e_magic  = 0;
        dos->e_lfanew = 0;
    }

    VirtualProtect(image_base, size_of_headers, old_prot, &tmp_prot);
}

/*
 * Step 2: wipe the compressed+encrypted metadata envelope. This is the primary
 * "consumed payload" region addressable from PackInfo alone.
 */
static void wipe_metadata_envelope(void *image_base, const PackInfo *pi)
{
    uint8_t *meta;
    DWORD old_prot = 0, tmp_prot = 0;

    if (!pi->meta_rva || !pi->meta_stored_size) {
        return;
    }
    meta = (uint8_t *)image_base + pi->meta_rva;

    if (!VirtualProtect(meta, pi->meta_stored_size, PAGE_READWRITE, &old_prot)) {
        return; /* best-effort */
    }
    ad_zero(meta, pi->meta_stored_size);
    VirtualProtect(meta, pi->meta_stored_size, old_prot, &tmp_prot);
}

/*
 * Step 3: best-effort anti-injection via SetProcessMitigationPolicy.
 *
 * Enables ONLY mitigations that are safe for a normal desktop app that loads its
 * own (non-Microsoft) DLLs and may JIT:
 *   - Extension-point disable: blocks legacy AppInit_DLLs, global
 *     SetWindowsHookEx hooks, Winsock LSPs and IME injection.
 *   - Image-load policy: NoRemoteImages (no DLLs from UNC/remote paths) +
 *     PreferSystem32Images (defeats app-dir planting of system DLLs).
 *
 * Deliberately NOT enabled (they would break this product, not harden it):
 *   - Signature policy / MicrosoftSignedOnly -> blocks the payload's own Qt
 *     DLLs and plugins (not Microsoft-signed): app fails to start.
 *   - Dynamic-code prohibit -> breaks memguard's on-demand RX remap and the
 *     payload's QML/V4 JIT for the whole process lifetime.
 *
 * SetProcessMitigationPolicy is resolved dynamically so the packed binary still
 * loads on OSes predating a given policy (missing export -> skip, never a hard
 * static-import load failure). Policy buffers are each a single DWORD of flags
 * (a union over a bitfield struct, both 4 bytes), so passing the DWORD is
 * ABI-identical and avoids depending on the SDK's _WIN32_WINNT gate for the
 * PROCESS_MITIGATION_* struct types. All calls are best-effort; failures ignored.
 */
#define AD_POLICY_EXTENSION_POINT_DISABLE  6u   /* ProcessExtensionPointDisablePolicy */
#define AD_POLICY_IMAGE_LOAD               10u  /* ProcessImageLoadPolicy             */
#define AD_EXT_DISABLE_EXTENSION_POINTS    0x1u /* DisableExtensionPoints             */
#define AD_IMG_NO_REMOTE_IMAGES            0x1u /* NoRemoteImages       (bit 0)       */
#define AD_IMG_PREFER_SYSTEM32             0x4u /* PreferSystem32Images (bit 2)       */

typedef BOOL (WINAPI *SetProcMitigation_t)(DWORD, PVOID, SIZE_T);

static void harden_process_mitigations(void)
{
    HMODULE k32;
    SetProcMitigation_t set_policy;
    DWORD flags;

    k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) {
        return;
    }
    {
        char nm[] = {'S','e','t','P','r','o','c','e','s','s',
                     'M','i','t','i','g','a','t','i','o','n',
                     'P','o','l','i','c','y','\0'};
        set_policy = (SetProcMitigation_t)GetProcAddress(k32, nm);
        SecureZeroMemory(nm, sizeof(nm));
    }
    if (!set_policy) {
        return;
    }

    flags = AD_EXT_DISABLE_EXTENSION_POINTS;
    set_policy(AD_POLICY_EXTENSION_POINT_DISABLE, &flags, sizeof(flags));

    flags = AD_IMG_NO_REMOTE_IMAGES | AD_IMG_PREFER_SYSTEM32;
    set_policy(AD_POLICY_IMAGE_LOAD, &flags, sizeof(flags));
}

/*
 * Step 4: pin the DLL search order so resolve_imports' LoadLibraryA calls
 * cannot be hijacked via app-directory planting of system DLL names.
 * SetDefaultDllDirectories restricts the default search to SYSTEM32 +
 * APPLICATION_DIR (the folder containing the packed PE). Resolved
 * dynamically; harmless no-op on pre-Win8.
 */
#define AD_LOAD_LIBRARY_SEARCH_SYSTEM32       0x00000800u
#define AD_LOAD_LIBRARY_SEARCH_APPLICATION_DIR 0x00000200u

typedef BOOL (WINAPI *SetDefaultDllDirs_t)(DWORD);

static void harden_dll_search_order(void)
{
    HMODULE k32;
    SetDefaultDllDirs_t fn;

    k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) return;

    {
        char nm[] = {'S','e','t','D','e','f','a','u','l','t',
                     'D','l','l','D','i','r','e','c','t','o',
                     'r','i','e','s','\0'};
        fn = (SetDefaultDllDirs_t)GetProcAddress(k32, nm);
        SecureZeroMemory(nm, sizeof(nm));
    }
    if (!fn) return;

    fn(AD_LOAD_LIBRARY_SEARCH_SYSTEM32 | AD_LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
}

/* Early header erasure: called right after section decryption, before
   imports/relocs/TLS/VirtualProtect so headers are gone before the image
   reaches a "ready to dump" state. */
void antidump_erase_headers(void *image_base, int is_dll)
{
    if (!image_base)
        return;
    erase_headers(image_base, is_dll);
}

/* Early hook: called before resolve_imports. */
void antidump_harden_early(int is_dll)
{
    if (!is_dll)
        harden_process_mitigations();
    harden_dll_search_order();
}

/* Public hook (post-unpack). Headers already erased by
   antidump_erase_headers(); only the payload envelope wipe remains. */
void antidump_harden(void *image_base, const PackInfo *pi)
{
    if (!image_base || !pi) {
        return;
    }
    wipe_metadata_envelope(image_base, pi);
}
