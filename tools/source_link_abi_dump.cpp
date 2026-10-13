// Experimental source-link ABI probe: one exact named DIA function.
// Build: cl /EHsc /W4 /WX /I"<DIA SDK include>" this.cpp
//        /link /LIBPATH:"<DIA SDK lib/amd64>" diaguids.lib ole32.lib oleaut32.lib
#define NOMINMAX
#include <windows.h>
#include <dia2.h>
#include <cvconst.h>
#include <cstdio>

using DllGetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**);

static bool base_u64(IDiaSymbol* symbol) {
    DWORD tag = 0, base = 0;
    ULONGLONG size = 0;
    return SUCCEEDED(symbol->get_symTag(&tag)) && tag == SymTagBaseType &&
           SUCCEEDED(symbol->get_baseType(&base)) && base == btUInt &&
           SUCCEEDED(symbol->get_length(&size)) && size == 8;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 4) return 2;
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
    BSTR name = SysAllocString(argv[3]);
    if (!name) return 11;
    IDiaEnumSymbols* functions = nullptr;
    const HRESULT search = global->findChildren(
        SymTagFunction, name, nsCaseSensitive, &functions);
    SysFreeString(name);
    if (FAILED(search) || !functions) return 12;
    LONG count = 0;
    if (FAILED(functions->get_Count(&count)) || count != 1) return 13;
    IDiaSymbol* function = nullptr;
    ULONG fetched = 0;
    if (functions->Next(1, &function, &fetched) != S_OK || fetched != 1) return 14;
    DWORD rva = 0;
    ULONGLONG length = 0;
    if (FAILED(function->get_relativeVirtualAddress(&rva)) ||
        FAILED(function->get_length(&length)) || !rva || !length) return 15;
    IDiaSymbol* function_type = nullptr;
    if (FAILED(function->get_type(&function_type)) || !function_type) return 16;
    DWORD tag = 0, convention = 0;
    if (FAILED(function_type->get_symTag(&tag)) || tag != SymTagFunctionType ||
        FAILED(function_type->get_callingConvention(&convention)) ||
        convention != CV_CALL_NEAR_C) return 17;
    IDiaSymbol* result_type = nullptr;
    if (FAILED(function_type->get_type(&result_type)) || !result_type ||
        !base_u64(result_type)) return 18;
    IDiaEnumSymbols* arguments = nullptr;
    if (FAILED(function_type->findChildren(
            SymTagFunctionArgType, nullptr, nsNone, &arguments)) || !arguments)
        return 19;
    LONG argc_type = 0;
    if (FAILED(arguments->get_Count(&argc_type)) || argc_type < 0 ||
        argc_type > 8) return 20;
    for (LONG index = 0; index < argc_type; ++index) {
        IDiaSymbol* argument = nullptr;
        fetched = 0;
        if (arguments->Next(1, &argument, &fetched) != S_OK || fetched != 1)
            return 21;
        IDiaSymbol* type = nullptr;
        if (FAILED(argument->get_type(&type)) || !type || !base_u64(type))
            return 22;
        type->Release();
        argument->Release();
    }
    std::printf("ABI_U64 rva=%08lX size=%llu argc=%ld callconv=%lu\n",
        rva, length, argc_type, convention);
    arguments->Release();
    result_type->Release();
    function_type->Release();
    function->Release();
    functions->Release();
    global->Release();
    session->Release();
    source->Release();
    FreeLibrary(module);
    CoUninitialize();
    return std::fflush(stdout) == 0 ? 0 : 23;
}
