; One-instruction 128-bit memory boundaries for Daedalus XMM transfers.
; Store: RCX = destination, RDX = low 64 bits, R8 = high 64 bits.
; Load:  RCX = source, RDX = &low, R8 = &high.

OPTION CASEMAP:NONE

PUBLIC dvm_store128_unaligned
PUBLIC dvm_load128_aligned
PUBLIC dvm_store128_aligned

.code

dvm_store128_unaligned PROC
    movq        xmm0, rdx
    movq        xmm1, r8
    punpcklqdq  xmm0, xmm1
    movdqu      XMMWORD PTR [rcx], xmm0
    ret
dvm_store128_unaligned ENDP

dvm_load128_aligned PROC
    movdqa      xmm0, XMMWORD PTR [rcx]
    movq        rax, xmm0
    mov         QWORD PTR [rdx], rax
    psrldq      xmm0, 8
    movq        rax, xmm0
    mov         QWORD PTR [r8], rax
    ret
dvm_load128_aligned ENDP

dvm_store128_aligned PROC
    movq        xmm0, rdx
    movq        xmm1, r8
    punpcklqdq  xmm0, xmm1
    movdqa      XMMWORD PTR [rcx], xmm0
    ret
dvm_store128_aligned ENDP

END
