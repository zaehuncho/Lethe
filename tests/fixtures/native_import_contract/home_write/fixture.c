typedef unsigned long DWORD;
__declspec(dllimport) void* __stdcall GetStdHandle(DWORD);
__declspec(dllimport) int __stdcall WriteFile(void*,const void*,DWORD,DWORD*,void*);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);
extern unsigned int vm_probe(void);
static char* append(char* p,const char* s){while(*s)*p++=*s++;return p;}
static char* number(char* p,unsigned int n){char t[12];unsigned int k=0;do{t[k++]=(char)('0'+n%10);n/=10;}while(n);while(k)*p++=t[--k];return p;}
__declspec(dllexport) int fixture_run(void){char b[128];char* p=b;DWORD count;unsigned int v=vm_probe();int ok=(v==42);p=append(p,"IMPORT_HOME value=");p=number(p,v);p=append(p,ok?" passed=true\n":" passed=false\n");WriteFile(GetStdHandle((DWORD)-11),b,(DWORD)(p-b),&count,0);return ok?0:7;}
#ifdef BUILD_DLL
int __stdcall DllMain(void* module,DWORD reason,void* reserved){(void)module;(void)reason;(void)reserved;return 1;}
#else
void fixture_entry(void){ExitProcess((unsigned int)fixture_run());}
#endif
