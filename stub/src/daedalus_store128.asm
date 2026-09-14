; One-instruction unaligned 128-bit memory-store boundary for DVM_STORE128.
; RCX = destination, RDX = low 64 bits, R8 = high 64 bits.

OPTION CASEMAP:NONE

PUBLIC dvm_store128_unaligned

.code

dvm_store128_unaligned PROC
    movq        xmm0, rdx
    movq        xmm1, r8
    punpcklqdq  xmm0, xmm1
    movdqu      XMMWORD PTR [rcx], xmm0
    ret
dvm_store128_unaligned ENDP

END
