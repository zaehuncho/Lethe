OPTION CASEMAP:NONE
PUBLIC helper_home_write
PUBLIC DllMain
.code
helper_home_write PROC
 mov dword ptr [rsp+8],42
 xor eax,eax
 ret
helper_home_write ENDP
DllMain PROC
 mov eax,1
 ret
DllMain ENDP
END
