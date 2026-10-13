OPTION CASEMAP:NONE
PUBLIC vm_probe
EXTERN __imp_helper_home_write:QWORD
.data
PUBLIC reference_slot
reference_slot QWORD retained_anchor
.code
vm_probe PROC FRAME
 sub rsp,28h
 .allocstack 28h
 .endprolog
 xor eax,eax
 mov qword ptr [rsp],rax
 call qword ptr [__imp_helper_home_write]
 mov eax,dword ptr [rsp]
 add rsp,28h
 ret
vm_probe ENDP
retained_anchor PROC FRAME
 .endprolog
 xor eax,eax
 ret
retained_anchor ENDP
END
