// Name-free DIA function inventory for exact PE RSDS-bound coverage analysis.
// Build with the Visual Studio DIA SDK: cl /EHsc /W4 pdb_function_dump.cpp
//   /link diaguids.lib ole32.lib oleaut32.lib
#define NOMINMAX
#include <windows.h>
#include <dia2.h>
#include <cstdio>

using DllGetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**);

static void print_guid(const GUID& g) {
    std::printf("{%08lX-%04hX-%04hX-%02hhX%02hhX-", g.Data1, g.Data2,
                g.Data3, g.Data4[0], g.Data4[1]);
    for (int i = 2; i < 8; ++i) std::printf("%02hhX", g.Data4[i]);
    std::printf("}");
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) return 2;
    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) return 3;
    HMODULE module = LoadLibraryW(argv[1]);
    if (!module) return 4;
    const auto get_class = reinterpret_cast<DllGetClassObjectFn>(
        GetProcAddress(module, "DllGetClassObject"));
    if (!get_class) return 5;
    IClassFactory* factory = nullptr;
    if (FAILED(get_class(CLSID_DiaSource, IID_IClassFactory,
                         reinterpret_cast<void**>(&factory)))) return 6;
    IDiaDataSource* source = nullptr;
    const HRESULT create = factory->CreateInstance(
        nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void**>(&source));
    factory->Release();
    if (FAILED(create)) return 7;
    if (FAILED(source->loadDataFromPdb(argv[2]))) return 8;
    IDiaSession* session = nullptr;
    if (FAILED(source->openSession(&session))) return 9;
    IDiaSymbol* global = nullptr;
    if (FAILED(session->get_globalScope(&global))) return 10;
    GUID guid{};
    DWORD age = 0, machine = 0;
    if (FAILED(global->get_guid(&guid)) || FAILED(global->get_age(&age)) ||
        FAILED(global->get_machineType(&machine)) || age == 0 ||
        machine != IMAGE_FILE_MACHINE_AMD64) return 11;
    IDiaEnumSymbols* symbols = nullptr;
    if (FAILED(global->findChildren(SymTagFunction, nullptr, nsNone, &symbols)))
        return 12;
    LONG expected = 0;
    if (FAILED(symbols->get_Count(&expected)) || expected <= 0 ||
        expected > 250000) return 13;
    std::printf("PDB_IDENTITY guid=");
    print_guid(guid);
    std::printf(" age=%lu machine=%04lX\n", age, machine);
    unsigned emitted = 0;
    IDiaSymbol* symbol = nullptr;
    ULONG fetched = 0;
    for (LONG index = 0; index < expected; ++index) {
        if (symbols->Next(1, &symbol, &fetched) != S_OK || fetched != 1)
            return 14;
        DWORD rva = 0;
        ULONGLONG length = 0;
        if (FAILED(symbol->get_relativeVirtualAddress(&rva)) ||
            FAILED(symbol->get_length(&length)) || rva == 0 || length == 0 ||
            length > 0xFFFFFFFFull) return 15;
        std::printf("FUNCTION rva=%08lX size=%llu\n", rva, length);
        ++emitted;
        symbol->Release();
        symbol = nullptr;
        fetched = 0;
    }
    if (symbols->Next(1, &symbol, &fetched) != S_FALSE) return 16;
    std::printf("FUNCTION_SUMMARY emitted=%u\n", emitted);
    symbols->Release();
    global->Release();
    session->Release();
    source->Release();
    FreeLibrary(module);
    CoUninitialize();
    return std::fflush(stdout) == 0 ? 0 : 17;
}
