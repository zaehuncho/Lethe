#include <windows.h>
#include <stdint.h>
extern uintptr_t outer_call(void);

static char *append(char *p,const char *s){while(*s)*p++=*s++;return p;}
__declspec(dllexport) int fixture_run(void){
 char b[128];char *p=b;DWORD count;
 uintptr_t got=outer_call();
 uintptr_t delta=got-(uintptr_t)&fixture_run;
 static const char digits[]="0123456789abcdef";
 p=append(p,"IMPORT_OPAQUE_RETURN_SLOT delta=");
 for(int i=15;i>=0;--i)*p++=digits[(delta>>(i*4))&15];
 *p++='\n';
 WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),b,(DWORD)(p-b),&count,0);
 return 0;
}
#ifdef BUILD_DLL
BOOL WINAPI DllMain(HINSTANCE m,DWORD reason,LPVOID reserved){(void)m;(void)reason;(void)reserved;return TRUE;}
#else
void fixture_entry(void){ExitProcess((UINT)fixture_run());}
#endif
