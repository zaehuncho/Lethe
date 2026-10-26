OPTION CASEMAP:NONE
PUBLIC helper_fp
PUBLIC DllMain
.code
helper_fp PROC
 addsd xmm0,xmm1
 ret
helper_fp ENDP
DllMain PROC
 mov eax,1
 ret
DllMain ENDP
END
