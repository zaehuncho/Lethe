// Exact DIA scalar ABI probe for the opt-in product-shaped source-link lane.
#define NOMINMAX
#include <windows.h>
#include <dia2.h>
#include <cvconst.h>
#include <cstdio>
#include <cstring>
#include <cwchar>

using DllGetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**);

static const char* scalar_type(IDiaSymbol* original) {
    IDiaSymbol* current = original;
    for (int depth = 0; depth < 4; ++depth) {
        DWORD tag = 0;
        if (FAILED(current->get_symTag(&tag))) return nullptr;
        if (tag == SymTagBaseType) {
            DWORD base = 0;
            ULONGLONG length = 0;
            if (FAILED(current->get_baseType(&base)) ||
                FAILED(current->get_length(&length))) return nullptr;
            if (base == btBool && length == 1) return "bool";
            if (base == btInt && length == 8) return "i64";
            return nullptr;
        }
        if (tag != SymTagTypedef) return nullptr;
        IDiaSymbol* next = nullptr;
        if (FAILED(current->get_type(&next)) || !next) return nullptr;
        if (current != original) current->Release();
        current = next;
    }
    if (current != original) current->Release();
    return nullptr;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 6) return 2;
    wchar_t* end = nullptr;
    const unsigned long rva = std::wcstoul(argv[3], &end, 16);
    if (!rva || !end || *end) return 3;
    end = nullptr;
    const unsigned long size = std::wcstoul(argv[4], &end, 10);
    if (!size || size > 512 || !end || *end) return 4;
    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) return 5;
    HMODULE module = LoadLibraryW(argv[1]);
    if (!module) return 6;
    const auto get_class = reinterpret_cast<DllGetClassObjectFn>(
        GetProcAddress(module, "DllGetClassObject"));
    if (!get_class) return 7;
    IClassFactory* factory = nullptr;
    if (FAILED(get_class(CLSID_DiaSource, IID_IClassFactory,
                         reinterpret_cast<void**>(&factory)))) return 8;
    IDiaDataSource* source = nullptr;
    const HRESULT create = factory->CreateInstance(
        nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void**>(&source));
    factory->Release();
    if (FAILED(create)) return 9;
    if (FAILED(source->loadDataFromPdb(argv[2]))) return 10;
    IDiaSession* session = nullptr;
    if (FAILED(source->openSession(&session))) return 11;
    IDiaSymbol* function = nullptr;
    if (FAILED(session->findSymbolByRVA(rva, SymTagFunction, &function)) ||
        !function) return 12;
    DWORD actual_rva = 0;
    ULONGLONG actual_size = 0;
    if (FAILED(function->get_relativeVirtualAddress(&actual_rva)) ||
        FAILED(function->get_length(&actual_size)) ||
        actual_rva != rva || actual_size != size) return 13;
    // DIA Function::name is an undecorated display name. Bind the *decorated*
    // public-symbol identity at this exact RVA, rejecting aliases and wrong
    // names even when the function extent and type are otherwise identical.
    IDiaSymbol* global = nullptr;
    if (FAILED(session->get_globalScope(&global)) || !global) return 24;
    IDiaEnumSymbols* public_symbols = nullptr;
    if (FAILED(global->findChildren(SymTagPublicSymbol, nullptr, nsNone,
                                    &public_symbols)) || !public_symbols) return 25;
    LONG public_count = 0;
    if (FAILED(public_symbols->get_Count(&public_count)) ||
        public_count < 1 || public_count > 250000) return 26;
    LONG matching_entry_count = 0;
    for (LONG index = 0; index < public_count; ++index) {
        IDiaSymbol* candidate = nullptr;
        ULONG fetched = 0;
        if (public_symbols->Next(1, &candidate, &fetched) != S_OK || fetched != 1)
            return 27;
        DWORD candidate_rva = 0;
        if (SUCCEEDED(candidate->get_relativeVirtualAddress(&candidate_rva)) &&
            candidate_rva == rva) {
            BSTR decorated = nullptr;
            if (FAILED(candidate->get_name(&decorated)) || !decorated)
                return 28;
            const bool same = std::wcscmp(decorated, argv[5]) == 0;
            SysFreeString(decorated);
            if (!same) return 29;
            ++matching_entry_count;
        }
        candidate->Release();
    }
    if (matching_entry_count != 1) return 30;
    public_symbols->Release();
    global->Release();
    IDiaSymbol* function_type = nullptr;
    if (FAILED(function->get_type(&function_type)) || !function_type) return 14;
    DWORD tag = 0, convention = 0;
    if (FAILED(function_type->get_symTag(&tag)) || tag != SymTagFunctionType ||
        FAILED(function_type->get_callingConvention(&convention)) ||
        convention != CV_CALL_NEAR_C) return 15;
    IDiaSymbol* object_pointer = nullptr;
    if (SUCCEEDED(function_type->get_objectPointerType(&object_pointer)) &&
        object_pointer) return 16; // hidden this pointer is not supported
    IDiaSymbol* result = nullptr;
    if (FAILED(function_type->get_type(&result)) || !result) return 17;
    const char* return_kind = scalar_type(result);
    if (!return_kind || std::strcmp(return_kind, "bool") != 0) return 18;
    IDiaEnumSymbols* arguments = nullptr;
    if (FAILED(function_type->findChildren(SymTagFunctionArgType, nullptr,
                                           nsNone, &arguments)) || !arguments)
        return 19;
    LONG count = 0;
    if (FAILED(arguments->get_Count(&count)) || count < 1 || count > 8) return 20;
    const char* types[8] = {};
    for (LONG index = 0; index < count; ++index) {
        IDiaSymbol* argument = nullptr;
        ULONG fetched = 0;
        if (arguments->Next(1, &argument, &fetched) != S_OK || fetched != 1)
            return 21;
        IDiaSymbol* type = nullptr;
        if (FAILED(argument->get_type(&type)) || !type ||
            !(types[index] = scalar_type(type))) return 22;
        type->Release();
        argument->Release();
    }
    std::printf("ABI_TYPED rva=%08lX size=%llu argc=%ld ret=bool args=",
                rva, actual_size, count);
    for (LONG index = 0; index < count; ++index)
        std::printf("%s%s", index ? "," : "", types[index]);
    std::printf(" callconv=%lu\n", convention);
    arguments->Release();
    result->Release();
    function_type->Release();
    function->Release();
    session->Release();
    source->Release();
    FreeLibrary(module);
    CoUninitialize();
    return std::fflush(stdout) == 0 ? 0 : 23;
}
