typedef unsigned long DWORD;
typedef unsigned __int64 U64;
__declspec(dllimport) void* __stdcall GetStdHandle(DWORD);
__declspec(dllimport) int __stdcall WriteFile(void*,const void*,DWORD,DWORD*,void*);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);
extern U64 vm_fp_probe(void);
static char* append(char* p,const char* s){while(*s)*p++=*s++;return p;}
static char* hex64(char* p,U64 value){static const char h[]="0123456789abcdef";int i;for(i=15;i>=0;--i)*p++=h[(unsigned int)(value>>(i*4))&15u];return p;}
__declspec(dllexport) int fixture_run(void){char b[128];char* p=b;DWORD count;U64 value=vm_fp_probe();int ok=(value==0xBFF0000000000000ULL);p=append(p,"IMPORT_FP_SPAN bits=");p=hex64(p,value);p=append(p,ok?" passed=true\n":" passed=false\n");WriteFile(GetStdHandle((DWORD)-11),b,(DWORD)(p-b),&count,0);return ok?0:7;}
#ifdef BUILD_DLL
int __stdcall DllMain(void* module,DWORD reason,void* reserved){(void)module;(void)reason;(void)reserved;return 1;}
#else
void fixture_entry(void){ExitProcess((unsigned int)fixture_run());}
#endif
