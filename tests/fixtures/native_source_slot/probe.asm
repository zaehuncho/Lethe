OPTION CASEMAP:NONE
EXTERN __imp_GetTickCount:QWORD
PUBLIC vm_probe
PUBLIC outer_call
.data
PUBLIC reference_slot
reference_slot QWORD outer_call
.code
outer_call PROC FRAME
 sub rsp,28h
 .allocstack 28h
 .endprolog
 lea rcx,[rsp-38h]
 mov qword ptr [rcx],12345678h
 call vm_probe
 add rsp,28h
 ret
outer_call ENDP
vm_probe PROC FRAME
 push rbx
 .pushreg rbx
 sub rsp,20h
 .allocstack 20h
 .endprolog
 mov rbx,rcx
 call qword ptr [__imp_GetTickCount]
 mov rax,[rbx]
 add rsp,20h
 pop rbx
 ret
vm_probe ENDP
END
