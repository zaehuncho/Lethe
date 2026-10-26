OPTION CASEMAP:NONE
PUBLIC vm_fp_probe
EXTERN __imp_helper_fp:QWORD
.data
PUBLIC reference_slot
reference_slot QWORD retained_anchor
.code
vm_fp_probe PROC FRAME
 sub rsp,28h
 .allocstack 28h
 .endprolog
 mov rax,03FF4000000000000h
 movq xmm0,rax
 mov rax,0C002000000000000h
 movq xmm1,rax
 call qword ptr [__imp_helper_fp]
 movq rax,xmm0
 add rsp,28h
 ret
vm_fp_probe ENDP
retained_anchor PROC FRAME
 .endprolog
 xor eax,eax
 ret
retained_anchor ENDP
END
