/*
 * stub_junk_imports.c -- decoy imports for anti-fingerprinting.
 *
 * These entries are DELIBERATELY NEVER CALLED. Their sole job is to appear in
 * the packed binary's DIR_IMPORT so the import graph looks like a normal
 * Windows application (user32/advapi32/ole32/shell32/gdi32/shlwapi) rather
 * than a bare packer stub whose only imports are the kernel32 primitives the
 * unpack path actually uses. This poisons:
 *
 *   * Static tooling (IDA/Ghidra): the "what does this program do" first pass
 *     is heavily import-graph driven -- a stub-only kernel32 import list is a
 *     dead giveaway; a plausible mixed-DLL import list is not.
 *   * LLM-assisted RE: import-graph shortcuts are one of the strongest cues an
 *     LLM uses to classify a binary. Filling that channel with red herrings
 *     forces it back onto expensive code analysis.
 *
 * Mechanism (no source-level function declarations required):
 *   * ``#pragma comment(lib, "<system>.lib")`` tells the linker to search that
 *     import library for unresolved symbols.
 *   * ``#pragma comment(linker, "/INCLUDE:__imp_<Name>")`` forces the linker
 *     to reference the ``__imp_<Name>`` mangled entry (the standard x64 name
 *     for an unbound IAT slot); resolving that reference pulls the export
 *     into the packed binary's import table.
 *
 * The Windows loader resolves every DIR_IMPORT entry at load time; the IAT
 * slots stay dormant because nothing in our code calls them. Zero runtime cost.
 *
 * Compile-time only. Freestanding-safe: no code executes here, so /NOENTRY
 * and /NODEFAULTLIB are unaffected. If the SDK ever renames or removes an
 * export below, LINK fails at that entry; swap or drop, do not disable.
 */

/* --- import libraries the linker should search for the /INCLUDE symbols --- */
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
/* shlwapi omitted: the Path*W entry points are declared in shlwapi.h but not
 * exported from every SDK's shlwapi.lib on modern Win10+ (path-cch.lib took
 * over some of the work). Sticking to the always-present system libs keeps
 * the stub link deterministic across SDK installs. */

/* --- forced-reference imports (x64 __imp_ prefix, single underscore) ------
 *
 * Ordering below groups by DLL so the descriptor slice for each library is
 * contiguous when a scanner clusters by name -- looks natural.
 */

/* user32.dll */
#pragma comment(linker, "/INCLUDE:__imp_GetSystemMetrics")
#pragma comment(linker, "/INCLUDE:__imp_MessageBoxW")
#pragma comment(linker, "/INCLUDE:__imp_GetDesktopWindow")
#pragma comment(linker, "/INCLUDE:__imp_IsWindow")
#pragma comment(linker, "/INCLUDE:__imp_LoadCursorW")

/* advapi32.dll */
#pragma comment(linker, "/INCLUDE:__imp_RegOpenKeyExW")
#pragma comment(linker, "/INCLUDE:__imp_RegCloseKey")
#pragma comment(linker, "/INCLUDE:__imp_RegQueryValueExW")
#pragma comment(linker, "/INCLUDE:__imp_OpenProcessToken")
#pragma comment(linker, "/INCLUDE:__imp_GetTokenInformation")

/* ole32.dll */
#pragma comment(linker, "/INCLUDE:__imp_CoInitializeEx")
#pragma comment(linker, "/INCLUDE:__imp_CoUninitialize")
#pragma comment(linker, "/INCLUDE:__imp_CoCreateInstance")

/* shell32.dll */
#pragma comment(linker, "/INCLUDE:__imp_SHGetKnownFolderPath")
#pragma comment(linker, "/INCLUDE:__imp_ShellExecuteW")

/* gdi32.dll */
#pragma comment(linker, "/INCLUDE:__imp_CreateCompatibleDC")
#pragma comment(linker, "/INCLUDE:__imp_DeleteDC")
#pragma comment(linker, "/INCLUDE:__imp_GetDeviceCaps")

/* Extra padding from libs already loaded, to keep the descriptor count
 * respectable after dropping shlwapi. */
/* user32.dll (more) */
#pragma comment(linker, "/INCLUDE:__imp_GetForegroundWindow")
#pragma comment(linker, "/INCLUDE:__imp_GetWindowRect")
/* advapi32.dll (more) */
#pragma comment(linker, "/INCLUDE:__imp_CryptAcquireContextW")
#pragma comment(linker, "/INCLUDE:__imp_CryptReleaseContext")

/* Placeholder symbol so the translation unit exports at least one name -- some
 * MSVC configurations warn on a source file with zero symbols. Not called. */
const unsigned int g_stub_junk_import_anchor = 0u;
