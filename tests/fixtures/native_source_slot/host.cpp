#include <windows.h>
int wmain(int argc,wchar_t** argv){if(argc!=2)return 90;HMODULE m=LoadLibraryW(argv[1]);if(!m)return 91;
 auto f=reinterpret_cast<int(*)()>(GetProcAddress(m,"fixture_run"));if(!f){FreeLibrary(m);return 92;}
 int result=f();if(!FreeLibrary(m))return 93;return result;}
