OPTION CASEMAP:NONE
PUBLIC helper_leaf
PUBLIC DllMain
.code
helper_leaf PROC
 mov eax,ecx
 ret
helper_leaf ENDP
DllMain PROC
 mov eax,1
 ret
DllMain ENDP
END