OPTION CASEMAP:NONE
PUBLIC helper_probe
PUBLIC DllMain
.code
helper_probe PROC
 mov rax,qword ptr [rsp]
 movzx eax,byte ptr [rax]
 ret
helper_probe ENDP
DllMain PROC
 mov eax,1
 ret
DllMain ENDP
END
