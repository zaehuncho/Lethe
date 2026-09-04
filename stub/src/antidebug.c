/*
 * Lethe stub -- antidebug.c
 *
 * Implements antidbg_check() from stub_hooks.h: gated, AV-benign debugger /
 * analysis-environment detection. Called EARLY by the loader (before
 * decryption) only when LETHE_FLAG_ANTIDEBUG is set. On a nonzero return the
 * loader performs a CLEAN ExitProcess -- this module never crashes and never
 * takes any action itself, EXCEPT that on detection it first destroys the key
 * material in g_packinfo (see wipe_master_key) so an analyst who NOPs the
 * loader's ExitProcess and resumes finds no key to lift.
 *
 * Freestanding / no-CRT context: the stub links only kernel32. This
 * file uses Win32 (kernel32) + ntdll (dynamically resolved) + MSVC intrinsics
 * (__readgsqword, __rdtsc, _mm_lfence) only. No CRT calls, no static writable
 * data, no allocations. All sensitive string literals (ntdll / API / module /
 * process names) are XOR-obfuscated in daedalus_str_data.h and decrypted onto a
 * short-lived stack buffer that is wiped after use, so none are greppable in
 * the shipped binary.
 *
 * Checks (all AV-benign), in the order antidbg_check() runs them (cheapest and
 * highest-signal first, timing gates last):
 *   1.  PEB->BeingDebugged              (PEB + 0x02, via gs:[0x60])
 *   2.  PEB->NtGlobalFlag heap bits     (PEB + 0xBC, mask 0x70)
 *   3.  PEB->ProcessHeap Flags/ForceFlags (heap debug bits)
 *   4.  CheckRemoteDebuggerPresent(GetCurrentProcess())
 *   5.  NtQueryInformationProcess(ProcessDebugPort)        [dynamic resolve]
 *   6.  NtQueryInformationProcess(ProcessDebugObjectHandle)[dynamic resolve]
 *   7.  DBI / instrumentation modules   (Frida/Pin/DynamoRIO/x64dbg/ScyllaHide)
 *   8.  Parent process is a known debugger (NtQIP(ProcessBasicInformation) ->
 *       parent PID -> QueryFullProcessImageNameA -> basename match)
 *   9.  RDTSC timing gate around a trivial op          (min-of-N)
 *   10. RDTSC timing gate around a GetTickCount64 call  (min-of-N)
 *   11. QueryPerformanceCounter wall-clock gate         (min-of-N)
 *   12. RDTSC vs QPC crosscheck (catches a spoofed/hooked single clock)
 *
 * DELIBERATELY EXCLUDED (AV red flags):
 *   NtSetInformationThread(ThreadHideFromDebugger), int 2d / int 3 tricks,
 *   API-name hashing, self-modifying code.
 *
 * REMOVED (unavoidable false positive with MSVC): an INT3 (0xCC) scan of the
 * stub's own .text. MSVC Release pads the gaps between functions with 0xCC
 * (int3), so the shipped stub legitimately contains hundreds of 0xCC bytes and
 * the ">2 means a breakpoint" heuristic fired on every default-packed binary.
 * It was also low value: debuggers set breakpoints in the TARGET code, not in
 * the packer stub. antidbg_check_extended() therefore no longer scans .text.
 *
 * DELIBERATELY EXCLUDED (false-positives on Hyper-V hosts):
 *   KUSER_SHARED_DATA KdDebuggerEnabled, NtQuerySystemInformation
 *   SystemKernelDebuggerInformation -- both report a kernel debugger as present
 *   when the Hyper-V hypervisor is active (Windows 11 default), causing every
 *   packed binary to exit on the developer's machine.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <intrin.h>
#include <stdint.h>

#include "stub_hooks.h"
#include "key_scatter.h"
#include "daedalus_strings.h"
#include "daedalus_str_data.h"

/*
 * x64 PEB layout offsets (stable across all shipping Windows x64):
 *   gs:[0x60]      -> PEB*
 *   PEB + 0x002    -> UCHAR  BeingDebugged
 *   PEB + 0x0BC    -> ULONG  NtGlobalFlag
 */
#define PEB_BEINGDEBUGGED_OFF   0x002u
#define PEB_NTGLOBALFLAG_OFF    0x0BCu

/*
 * Heap-debug bits that the loader sets in NtGlobalFlag when a process is
 * created under a debugger:
 *   FLG_HEAP_ENABLE_TAIL_CHECK   0x10
 *   FLG_HEAP_ENABLE_FREE_CHECK   0x20
 *   FLG_HEAP_VALIDATE_PARAMETERS 0x40
 */
#define NTGLOBALFLAG_HEAP_DEBUG_BITS  0x70u

/*
 * ---- Timing-gate tuning ---------------------------------------------------
 *
 * Every timing gate takes the MINIMUM elapsed count across several tight
 * iterations. A random preemption / context switch inflates at most one
 * iteration, so the minimum stays small under normal execution; an active
 * single-stepping / breakpoint debugger inflates EVERY iteration, so the
 * minimum blows past the threshold.
 */

/* (10) Trivial-op RDTSC gate. lfence-serialized rdtsc around one un-elidable
 *      volatile op costs ~50-150 cycles on real hardware. 200,000 cycles
 *      (~80us at ~2.5GHz) is a ~1000x margin against cloud/VM/scheduling
 *      jitter while staying far below the cost of a debugger single-stepping
 *      (each step is a usermode<->debugger round-trip, typically 1e5-1e7
 *      cycles). TIGHTENED from the former 0x100000 (1,048,576) threshold,
 *      which a lightweight stepping debugger could slip under. */
#define RDTSC_ITERATIONS     8
#define RDTSC_WINDOWS        3
#define RDTSC_THRESHOLD      200000ull

/* (11) RDTSC gate around a real API call (GetTickCount64 -- reads
 *      KUSER_SHARED_DATA, no syscall, so it is cheap on real hardware). This
 *      is an INDEPENDENT code path from the trivial-op gate: a debugger that
 *      special-cases the tight loop still balloons an API it traces into. The
 *      threshold is looser because an API call legitimately costs more than a
 *      register add. */
#define RDTSC_API_ITERATIONS 8
#define RDTSC_API_THRESHOLD  500000ull

/* (12) QueryPerformanceCounter wall-clock gate: an independent clock source, so
 *      it survives a spoof that only touches RDTSC. ~20k volatile adds run in
 *      well under 1ms on real hardware; keep the MIN of QPC_RUNS runs and flag
 *      only if the fastest still exceeds 50ms -- an enormous margin that a
 *      single-stepping debugger (seconds) blows past. */
#define QPC_RUNS             5
#define QPC_WORKLOAD_ITERS   20000
#define QPC_ELAPSED_US_MAX   50000ull

/* (13) RDTSC vs QPC crosscheck. Measure the same code twice, once with a small
 *      and once with an 8x workload, timing each with BOTH clocks. On honest
 *      hardware the tsc/qpc ratio is a machine constant independent of interval
 *      length and jitter, so tsc_a*qpc_b == tsc_b*qpc_a. A clock that has been
 *      hooked/virtualized to defeat timing gates (constant delta, clamped
 *      delta, or a single spoofed source) breaks the identity because the two
 *      workloads differ 8x. Flag only a >4x divergence. */
#define XCHK_ITERS_A         40000
#define XCHK_ITERS_B         320000
#define XCHK_RUNS            5
#define XCHK_TOLERANCE       4ull

/* Read PEB->BeingDebugged. Returns 1 if a debugger flag is set, else 0. */
static int check_being_debugged(const uint8_t *peb)
{
    if (!peb) {
        return 0;
    }
    return peb[PEB_BEINGDEBUGGED_OFF] != 0 ? 1 : 0;
}

/* Read PEB->NtGlobalFlag and test the heap-debug bits. */
static int check_ntglobalflag(const uint8_t *peb)
{
    uint32_t flags;
    if (!peb) {
        return 0;
    }
    flags = *(const uint32_t *)(peb + PEB_NTGLOBALFLAG_OFF);
    return (flags & NTGLOBALFLAG_HEAP_DEBUG_BITS) != 0 ? 1 : 0;
}

/*
 * PEB->ProcessHeap flags check. Under a debugger the process heap is created
 * with HEAP_TAIL_CHECKING_ENABLED (0x20) and HEAP_FREE_CHECKING_ENABLED
 * (0x40). Read PEB->ProcessHeap (offset 0x30) then Heap->Flags (offset 0x70 on
 * x64) and Heap->ForceFlags (0x74).
 */
#define PEB_PROCESSHEAP_OFF  0x030u
#define HEAP_FLAGS_OFF       0x070u
#define HEAP_FORCEFLAGS_OFF  0x074u
#define HEAP_DEBUG_FLAGS     0x70u  /* TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMS */

static int check_heap_flags(const uint8_t *peb)
{
    const uint8_t *heap;
    uint32_t flags, forceflags;
    if (!peb)
        return 0;
    heap = *(const uint8_t **)(peb + PEB_PROCESSHEAP_OFF);
    if (!heap)
        return 0;
    flags      = *(const uint32_t *)(heap + HEAP_FLAGS_OFF);
    forceflags = *(const uint32_t *)(heap + HEAP_FORCEFLAGS_OFF);
    if ((flags & HEAP_DEBUG_FLAGS) || forceflags != 0)
        return 1;
    return 0;
}

/* CheckRemoteDebuggerPresent against our own process. */
static int check_remote_debugger(void)
{
    BOOL present = FALSE;
    /* GetCurrentProcess() returns the (-1) pseudo-handle -- no leak. */
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present) && present) {
        return 1;
    }
    return 0;
}

/*
 * ---- ntdll / NtQueryInformationProcess ------------------------------------
 * Resolved dynamically (GetModuleHandleW + GetProcAddress) from obfuscated
 * strings so neither "ntdll.dll" nor "NtQueryInformationProcess" appears in the
 * import table or as a greppable literal.
 */
typedef LONG (NTAPI *NtQueryInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

#define PROCESSDEBUGPORT_CLASS          7      /* ProcessDebugPort */
#define PROCESSDEBUGOBJECTHANDLE_CLASS  0x1Eu  /* ProcessDebugObjectHandle */
#define PROCESSBASICINFORMATION_CLASS   0      /* ProcessBasicInformation */

static NtQueryInformationProcess_t resolve_nqip(void)
{
    HMODULE ntdll;
    NtQueryInformationProcess_t fn;

    {
        wchar_t _ntdll[10];
        vstr_dec_w(_vs_ntdll_w, _ntdll, VSTR_NTDLL_W_LEN, VSTR_NTDLL_W_KEY, VSTR_NTDLL_W_MUL);
        ntdll = GetModuleHandleW(_ntdll);
        vstr_zero(_ntdll, sizeof(_ntdll));
    }
    if (!ntdll)
        return NULL;
    {
        char _nqip[26];
        vstr_dec(_vs_nqip, _nqip, VSTR_NQIP_LEN, VSTR_NQIP_KEY, VSTR_NQIP_MUL);
        fn = (NtQueryInformationProcess_t)GetProcAddress(ntdll, _nqip);
        vstr_zero(_nqip, sizeof(_nqip));
    }
    return fn;
}

/*
 * NtQueryInformationProcess(ProcessDebugPort): kernel-level debugger detection
 * that catches debuggers hiding from PEB flags (e.g. ScyllaHide can zero
 * PEB->BeingDebugged but the debug port still reveals the debugger).
 */
static int check_debug_port(void)
{
    NtQueryInformationProcess_t fn = resolve_nqip();
    ULONG_PTR port = 0;
    LONG st;
    if (!fn)
        return 0;
    st = fn(GetCurrentProcess(), PROCESSDEBUGPORT_CLASS,
            &port, sizeof(port), NULL);
    if (st >= 0 && port != 0)
        return 1;
    return 0;
}

/*
 * NtQueryInformationProcess(ProcessDebugObjectHandle): the kernel creates a
 * debug object when a debugger attaches. Even if the debugger hides PEB flags
 * and closes the debug port, the object handle persists. Catches
 * ScyllaHide/TitanHide scenarios where ProcessDebugPort is spoofed.
 */
static int check_debug_object(void)
{
    NtQueryInformationProcess_t fn = resolve_nqip();
    HANDLE obj = NULL;
    LONG st;
    if (!fn)
        return 0;
    st = fn(GetCurrentProcess(), PROCESSDEBUGOBJECTHANDLE_CLASS,
            &obj, sizeof(obj), NULL);
    /* success + valid handle = a debug object exists (STATUS_PORT_NOT_SET,
       0xC0000353, is the no-debugger case and is negative). */
    if (st >= 0 && obj != NULL)
        return 1;
    return 0;
}

/*
 * ---- DBI / instrumentation framework detection ----------------------------
 * Dynamic binary instrumentation engines (Frida, Intel Pin, DynamoRIO) and
 * hook-based analysis tools (ScyllaHide, x64dbg helpers) load a signature DLL
 * into the target. None of these names collide with legitimate software, so a
 * present-module hit is high-signal and false-positive-free. Names are
 * decrypted onto the stack and wiped immediately.
 */
static int daedalus_module_present(const uint8_t *enc, int len,
                                 uint8_t key, uint8_t mul)
{
    char nm[24];   /* longest name ("HookLibraryx64.dll") is 18 + NUL */
    HMODULE h;
    vstr_dec(enc, nm, len, key, mul);
    h = GetModuleHandleA(nm);
    vstr_zero(nm, sizeof(nm));
    return h != NULL ? 1 : 0;
}

static int check_instrumentation(void)
{
    if (daedalus_module_present(_vs_frida_agent,  VSTR_FRIDA_AGENT_LEN,  VSTR_FRIDA_AGENT_KEY,  VSTR_FRIDA_AGENT_MUL))  return 1;
    if (daedalus_module_present(_vs_frida_gadget, VSTR_FRIDA_GADGET_LEN, VSTR_FRIDA_GADGET_KEY, VSTR_FRIDA_GADGET_MUL)) return 1;
    if (daedalus_module_present(_vs_dynamorio,    VSTR_DYNAMORIO_LEN,    VSTR_DYNAMORIO_KEY,    VSTR_DYNAMORIO_MUL))    return 1;
    if (daedalus_module_present(_vs_pinvm,        VSTR_PINVM_LEN,        VSTR_PINVM_KEY,        VSTR_PINVM_MUL))        return 1;
    if (daedalus_module_present(_vs_x64dbg_dll,   VSTR_X64DBG_DLL_LEN,  VSTR_X64DBG_DLL_KEY,   VSTR_X64DBG_DLL_MUL))   return 1;
    if (daedalus_module_present(_vs_x32dbg_dll,   VSTR_X32DBG_DLL_LEN,  VSTR_X32DBG_DLL_KEY,   VSTR_X32DBG_DLL_MUL))   return 1;
    if (daedalus_module_present(_vs_hooklib,      VSTR_HOOKLIB_LEN,      VSTR_HOOKLIB_KEY,      VSTR_HOOKLIB_MUL))      return 1;
    return 0;
}

/*
 * ---- Parent process check -------------------------------------------------
 * A process launched under a debugger inherits that debugger as its parent.
 * NtQueryInformationProcess(ProcessBasicInformation) gives the parent PID;
 * QueryFullProcessImageNameA gives its path; we compare the basename (case-
 * insensitively) against a set of known debugger executables. (Catches
 * "launched under debugger"; attach-after-start is caught by the port/object
 * checks above.)
 */

/* x64 PROCESS_BASIC_INFORMATION (locally defined; winternl.h is not pulled in
 * by WIN32_LEAN_AND_MEAN). InheritedFromUniqueProcessId sits at offset 0x28. */
typedef struct _PBI_LOCAL {
    LONG      ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PBI_LOCAL;

/* Case-insensitive ASCII compare (no CRT). Returns 1 on equal. */
static int ci_ascii_eq(const char *a, const char *b)
{
    for (;;) {
        char ca = *a++;
        char cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 0x20);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 0x20);
        if (ca != cb) return 0;
        if (ca == 0)  return 1;
    }
}

/* Pointer to the filename component of a path (after the last \ or /). */
static const char *basename_of(const char *path)
{
    const char *base = path;
    const char *p;
    for (p = path; *p != 0; ++p) {
        if (*p == '\\' || *p == '/')
            base = p + 1;
    }
    return base;
}

/* Decrypt one obfuscated debugger basename and compare it to `base`. */
static int name_is_debugger(const char *base, const uint8_t *enc, int len,
                            uint8_t key, uint8_t mul)
{
    char nm[24];   /* longest name ("ollydbg.exe") is 11 + NUL */
    int r;
    vstr_dec(enc, nm, len, key, mul);
    r = ci_ascii_eq(base, nm);
    vstr_zero(nm, sizeof(nm));
    return r;
}

static int check_parent_process(void)
{
    NtQueryInformationProcess_t fn = resolve_nqip();
    PBI_LOCAL pbi;
    LONG st;
    DWORD ppid;
    HANDLE hp;
    char  path[MAX_PATH];
    DWORD sz = MAX_PATH;
    const char *base;
    int hit = 0;

    if (!fn)
        return 0;

    pbi.InheritedFromUniqueProcessId = 0;
    st = fn(GetCurrentProcess(), PROCESSBASICINFORMATION_CLASS,
            &pbi, sizeof(pbi), NULL);
    if (st < 0)
        return 0;

    ppid = (DWORD)pbi.InheritedFromUniqueProcessId;
    if (ppid == 0)
        return 0;

    /* PROCESS_QUERY_LIMITED_INFORMATION is enough for QueryFullProcessImageName
       and is grantable even for cross-integrity parents. Failure -> no hit. */
    hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if (!hp)
        return 0;

    if (QueryFullProcessImageNameA(hp, 0, path, &sz) && sz > 0) {
        base = basename_of(path);
        if      (name_is_debugger(base, _vs_x64dbg_exe,  VSTR_X64DBG_EXE_LEN,  VSTR_X64DBG_EXE_KEY,  VSTR_X64DBG_EXE_MUL))  hit = 1;
        else if (name_is_debugger(base, _vs_x32dbg_exe,  VSTR_X32DBG_EXE_LEN,  VSTR_X32DBG_EXE_KEY,  VSTR_X32DBG_EXE_MUL))  hit = 1;
        else if (name_is_debugger(base, _vs_x96dbg_exe,  VSTR_X96DBG_EXE_LEN,  VSTR_X96DBG_EXE_KEY,  VSTR_X96DBG_EXE_MUL))  hit = 1;
        else if (name_is_debugger(base, _vs_ollydbg_exe, VSTR_OLLYDBG_EXE_LEN, VSTR_OLLYDBG_EXE_KEY, VSTR_OLLYDBG_EXE_MUL)) hit = 1;
        else if (name_is_debugger(base, _vs_windbg_exe,  VSTR_WINDBG_EXE_LEN,  VSTR_WINDBG_EXE_KEY,  VSTR_WINDBG_EXE_MUL))  hit = 1;
        else if (name_is_debugger(base, _vs_devenv_exe,  VSTR_DEVENV_EXE_LEN,  VSTR_DEVENV_EXE_KEY,  VSTR_DEVENV_EXE_MUL))  hit = 1;
        else if (name_is_debugger(base, _vs_ida_exe,     VSTR_IDA_EXE_LEN,     VSTR_IDA_EXE_KEY,     VSTR_IDA_EXE_MUL))     hit = 1;
        else if (name_is_debugger(base, _vs_ida64_exe,   VSTR_IDA64_EXE_LEN,   VSTR_IDA64_EXE_KEY,   VSTR_IDA64_EXE_MUL))   hit = 1;
    }

    CloseHandle(hp);
    vstr_zero(path, sizeof(path));
    return hit;
}

/*
 * (10) Trivial-op RDTSC gate. Keep the smallest delta across N iterations; flag
 *      only if that minimum exceeds RDTSC_THRESHOLD.
 */
static int rdtsc_window_is_slow(void)
{
    uint64_t best = ~0ull;
    int i;

    for (i = 0; i < RDTSC_ITERATIONS; ++i) {
        uint64_t t0, t1, delta;
        volatile int trivial = i;

        _mm_lfence();
        t0 = __rdtsc();
        _mm_lfence();

        trivial = trivial + 1;   /* the trivial, un-elidable operation */

        _mm_lfence();
        t1 = __rdtsc();
        _mm_lfence();

        delta = t1 - t0;
        if (delta < best)
            best = delta;
    }

    return best > RDTSC_THRESHOLD ? 1 : 0;
}

static int check_rdtsc_timing(void)
{
    int window;
    for (window = 0; window < RDTSC_WINDOWS; ++window) {
        if (!rdtsc_window_is_slow())
            return 0;
    }
    return 1;
}

/*
 * (11) RDTSC gate around a GetTickCount64 call -- a second, independent timing
 *      probe over a different code path (an actual imported API rather than a
 *      register op). Min-of-N; flag only above RDTSC_API_THRESHOLD.
 */
static int check_rdtsc_api_timing(void)
{
    uint64_t best = ~0ull;
    int i;

    for (i = 0; i < RDTSC_API_ITERATIONS; ++i) {
        uint64_t t0, t1, delta;

        _mm_lfence();
        t0 = __rdtsc();
        _mm_lfence();

        (void)GetTickCount64();  /* imported call -> not elided; balloons if traced */

        _mm_lfence();
        t1 = __rdtsc();
        _mm_lfence();

        delta = t1 - t0;
        if (delta < best)
            best = delta;
    }

    return best > RDTSC_API_THRESHOLD ? 1 : 0;
}

/*
 * (12) QueryPerformanceCounter wall-clock gate. Independent clock source from
 *      RDTSC. Min-of-QPC_RUNS to shrug off a stray preemption; flag only if the
 *      fastest run's elapsed microseconds exceed QPC_ELAPSED_US_MAX.
 */
static int check_qpc_timing(void)
{
    LARGE_INTEGER f;
    uint64_t freq, best_us = ~0ull;
    int r;

    if (!QueryPerformanceFrequency(&f) || f.QuadPart == 0)
        return 0;   /* no usable QPC -> cannot judge, do not false-positive */
    freq = (uint64_t)f.QuadPart;

    for (r = 0; r < QPC_RUNS; ++r) {
        LARGE_INTEGER q0, q1;
        volatile uint64_t sink = 0;
        uint64_t us;
        int i;

        QueryPerformanceCounter(&q0);
        for (i = 0; i < QPC_WORKLOAD_ITERS; ++i)
            sink += (uint64_t)i;
        QueryPerformanceCounter(&q1);

        us = ((uint64_t)(q1.QuadPart - q0.QuadPart) * 1000000ull) / freq;
        if (us < best_us)
            best_us = us;
    }

    return best_us > QPC_ELAPSED_US_MAX ? 1 : 0;
}

/*
 * (13) RDTSC vs QPC crosscheck. See the XCHK_* comment above for the theory.
 *      The QPC and TSC brackets cannot be sampled atomically: a preemption in
 *      either narrow outer-bracket gap can inflate only QPC and make one honest
 *      sample look divergent. Require every repeated sample to diverge; any
 *      consistent sample makes this heuristic inconclusive rather than turning
 *      ordinary scheduler jitter into a loader rejection.
 */
static int check_timing_crosscheck(void)
{
    typedef struct TimingProduct {
        uint64_t low;
        uint64_t high;
    } TimingProduct;
    LARGE_INTEGER f;
    int run;

    if (!QueryPerformanceFrequency(&f) || f.QuadPart == 0)
        return 0;

    for (run = 0; run < XCHK_RUNS; ++run) {
        LARGE_INTEGER a0, a1, b0, b1;
        uint64_t ta0, ta1, tb0, tb1;
        uint64_t tsc_a, tsc_b, qpc_a, qpc_b;
        TimingProduct cross1, cross2, smaller, larger, scaled;
        uint64_t scale_carry;
        volatile uint64_t sink = 0;
        int i;

        QueryPerformanceCounter(&a0);
        _mm_lfence(); ta0 = __rdtsc(); _mm_lfence();
        for (i = 0; i < XCHK_ITERS_A; ++i)
            sink += (uint64_t)i;
        _mm_lfence(); ta1 = __rdtsc(); _mm_lfence();
        QueryPerformanceCounter(&a1);

        QueryPerformanceCounter(&b0);
        _mm_lfence(); tb0 = __rdtsc(); _mm_lfence();
        for (i = 0; i < XCHK_ITERS_B; ++i)
            sink += (uint64_t)i;
        _mm_lfence(); tb1 = __rdtsc(); _mm_lfence();
        QueryPerformanceCounter(&b1);

        tsc_a = ta1 - ta0;
        tsc_b = tb1 - tb0;
        qpc_a = (uint64_t)(a1.QuadPart - a0.QuadPart);
        qpc_b = (uint64_t)(b1.QuadPart - b0.QuadPart);
        if (tsc_a == 0 || tsc_b == 0 || qpc_a == 0 || qpc_b == 0)
            return 0;

        cross1.low = _umul128(tsc_a, qpc_b, &cross1.high);
        cross2.low = _umul128(tsc_b, qpc_a, &cross2.high);
        if (cross1.high < cross2.high ||
            (cross1.high == cross2.high && cross1.low < cross2.low)) {
            smaller = cross1;
            larger = cross2;
        } else {
            smaller = cross2;
            larger = cross1;
        }
        if (smaller.high == 0 && smaller.low == 0)
            return 0;
        scaled.low = _umul128(
            smaller.low, XCHK_TOLERANCE, &scale_carry);
        if (smaller.high > (~0ull - scale_carry) / XCHK_TOLERANCE)
            return 0;
        scaled.high = smaller.high * XCHK_TOLERANCE + scale_carry;
        if (larger.high < scaled.high ||
            (larger.high == scaled.high && larger.low <= scaled.low))
            return 0;
    }
    return 1;
}

/*
 * The loader's PackInfo sentinel (defined in stub_main.c). On detection we
 * destroy the key material here, BEFORE the loader's ExitProcess, so that an
 * analyst who patches out the exit and resumes finds only zeros in .data.
 */
extern volatile PackInfo g_packinfo;

static void wipe_master_key(void)
{
    /* aes_key_enc is the code-hash-bound, shard-XOR'd master key; kdf_salt is
       required to re-derive it. Destroy both. The (uintptr_t) launder yields a
       clean void* (drops the volatile qualifier without a C4090 diagnostic);
       SecureZeroMemory / RtlSecureZeroMemory is a FORCEINLINE volatile byte
       loop in winnt.h, so the wipe is never elided and needs no CRT/import. */
    key_scatter_invalidate();
    SecureZeroMemory((void *)(uintptr_t)g_packinfo.aes_key_enc,
                     sizeof(g_packinfo.aes_key_enc));
    SecureZeroMemory((void *)(uintptr_t)g_packinfo.kdf_salt,
                     sizeof(g_packinfo.kdf_salt));
}

/*
 * ---- Scattered tripwire checks (defense-in-depth) -------------------------
 *
 * Each tripwire uses a DIFFERENT anti-debug technique and independently wipes
 * key material + returns detection to its caller. Called at multiple points
 * during the unpack flow (pe_loader.c, stub_main.c) so that NOP'ing the main
 * antidbg_check() prologue ("xor eax,eax; ret") does NOT defeat all detection.
 *
 * __declspec(noinline) prevents MSVC from merging or inlining the call sites;
 * each tripwire must be a distinct call target to force an attacker to find and
 * patch every one individually.
 */

/* Tripwire 1: PEB->BeingDebugged (placed after section decryption). */
__declspec(noinline) int antidbg_tripwire_peb(void)
{
    const uint8_t *peb = (const uint8_t *)__readgsqword(0x60);
    if (peb && peb[PEB_BEINGDEBUGGED_OFF] != 0) {
        wipe_master_key();
        return 1;
    }
    return 0;
}

/* Tripwire 2: NtGlobalFlag heap-debug bits (placed after import resolution). */
__declspec(noinline) int antidbg_tripwire_ntgf(void)
{
    const uint8_t *peb = (const uint8_t *)__readgsqword(0x60);
    if (peb) {
        uint32_t flags = *(const uint32_t *)(peb + PEB_NTGLOBALFLAG_OFF);
        if (flags & NTGLOBALFLAG_HEAP_DEBUG_BITS) {
            wipe_master_key();
            return 1;
        }
    }
    return 0;
}

/* Tripwire 3: RDTSC timing gate (placed before OEP transfer in stub_main). */
__declspec(noinline) int antidbg_tripwire_rdtsc(void)
{
    if (check_rdtsc_timing()) {
        wipe_master_key();
        return 1;
    }
    return 0;
}

/* Tripwire 4: kernel debug-port recheck (placed after relocation). */
__declspec(noinline) int antidbg_tripwire_debug_port(void)
{
    if (check_debug_port()) {
        wipe_master_key();
        return 1;
    }
    return 0;
}

/*
 * Public hook. Returns nonzero only on confident detection. Runs the layered
 * checks cheapest-first and short-circuits on the first hit; on any hit it
 * destroys the key material before returning so the loader's clean exit leaves
 * nothing to recover.
 */
int antidbg_check(void)
{
    const uint8_t *peb = (const uint8_t *)__readgsqword(0x60);
    int detected = 0;

    if      (check_being_debugged(peb))     detected = 1;
    else if (check_ntglobalflag(peb))       detected = 1;
    else if (check_heap_flags(peb))         detected = 1;
    else if (check_remote_debugger())       detected = 1;
    else if (check_debug_port())            detected = 1;
    else if (check_debug_object())          detected = 1;
    else if (check_instrumentation())       detected = 1;
    else if (check_parent_process())        detected = 1;
    else if (check_rdtsc_timing())          detected = 1;
    else if (check_rdtsc_api_timing())      detected = 1;
    else if (check_qpc_timing())            detected = 1;
    else if (check_timing_crosscheck())     detected = 1;

    if (detected) {
        wipe_master_key();
        return 1;
    }
    return 0;
}

/*
 * Extended check. Historically this added an INT3 (0xCC) self-scan of the
 * stub's .text on top of antidbg_check(); that scan was removed because MSVC
 * Release inter-function padding (0xCC) made it fire on every packed binary
 * (see the file header). The signature is frozen (stub_hooks.h), and the
 * loader / stub_main.c still call this with the stub .text bounds, so the
 * parameters are retained but intentionally unused. It now runs exactly the
 * same checks as antidbg_check() (which includes the key wipe on detection).
 */
int antidbg_check_extended(const void *image_base, uint32_t text_rva,
                           uint32_t text_size)
{
    (void)image_base;
    (void)text_rva;
    (void)text_size;
    return antidbg_check();
}
