#include <windows.h>
int wmain(int argc,wchar_t** argv){if(argc!=2)return 90;HMODULE module=LoadLibraryExW(argv[1],nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);if(!module)return 91;auto f=reinterpret_cast<int(*)()>(GetProcAddress(module,"fixture_run"));if(!f){FreeLibrary(module);return 92;}int result=f();if(!FreeLibrary(module))return 93;return result;}
