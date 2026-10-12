; Win64 captured-frame external-call bridge.
PUBLIC daedalus_trampoline_frame
PUBLIC daedalus_trampoline_frame_span
.code

; void daedalus_trampoline_frame(void *func, DaedalusX64Context *ctx,
;                                const uint64_t argv[8]);
; Positional Win64 scalar/pointer/float/double arguments, NOT vectorcall or
; arbitrary arity. XMM0..5, volatile GPRs and arithmetic flags round-trip.
; Keeping the virtual RAX value also lets the real GuardCF dispatch thunk
; inspect its target; func is then the dispatch pointer, not a bypass target.
daedalus_trampoline_frame PROC FRAME
    push rbp
    .pushreg rbp
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 72
    .allocstack 72
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    mov rax, [r14+32]
    mov [rsp+32], rax
    mov rax, [r14+40]
    mov [rsp+40], rax
    mov rax, [r14+48]
    mov [rsp+48], rax
    mov rax, [r14+56]
    mov [rsp+56], rax
    mov rcx, [r14]
    mov rdx, [r14+8]
    mov r8, [r14+16]
    mov r9, [r14+24]
    mov r10, [r13+80]
    mov r11, [r13+88]
    movdqu xmm0, [r13+136]
    movdqu xmm1, [r13+152]
    movdqu xmm2, [r13+168]
    movdqu xmm3, [r13+184]
    movdqu xmm4, [r13+200]
    movdqu xmm5, [r13+216]
    mov rax, [r13]
    ; A stable RBP frame also unwinds during the transient flag PUSH/POP.
    push qword ptr [r13+128]
    popfq
    call r12
    ; No flag-modifying instruction precedes the return-state snapshot.
    pushfq
    pop qword ptr [r13+128]
    mov [r13], rax
    mov [r13+8], rcx
    mov [r13+16], rdx
    mov [r13+64], r8
    mov [r13+72], r9
    mov [r13+80], r10
    mov [r13+88], r11
    movdqu [r13+136], xmm0
    movdqu [r13+152], xmm1
    movdqu [r13+168], xmm2
    movdqu [r13+184], xmm3
    movdqu [r13+200], xmm4
    movdqu [r13+216], xmm5
    add rsp, 72
    pop r14
    pop r13
    pop r12
    pop rbp
    ret
daedalus_trampoline_frame ENDP

; Bounded-span ABI: (func, ctx, argv[argc], argc).
daedalus_trampoline_frame_span PROC FRAME
    push rbp
    .pushreg rbp
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 520
    .allocstack 520
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    ; R9D is argc (4..64), checked before the interpreter calls us.
    ; 32 shadow bytes + 60 qwords = 512, plus 8 alignment bytes = 520.
    mov ecx, 4
span_copy:
    cmp ecx, r9d
    jae span_copy_done
    mov rax, [r14+rcx*8]
    mov [rsp+rcx*8], rax
    inc ecx
    jmp span_copy
span_copy_done:
    mov rcx, [r14]
    mov rdx, [r14+8]
    mov r8, [r14+16]
    mov r9, [r14+24]
    mov r10, [r13+80]
    mov r11, [r13+88]
    movdqu xmm0, [r13+136]
    movdqu xmm1, [r13+152]
    movdqu xmm2, [r13+168]
    movdqu xmm3, [r13+184]
    movdqu xmm4, [r13+200]
    movdqu xmm5, [r13+216]
    mov rax, [r13]
    ; A stable RBP frame also unwinds during the transient flag PUSH/POP.
    push qword ptr [r13+128]
    popfq
    call r12
    ; No flag-modifying instruction precedes the return-state snapshot.
    pushfq
    pop qword ptr [r13+128]
    mov [r13], rax
    mov [r13+8], rcx
    mov [r13+16], rdx
    mov [r13+64], r8
    mov [r13+72], r9
    mov [r13+80], r10
    mov [r13+88], r11
    movdqu [r13+136], xmm0
    movdqu [r13+152], xmm1
    movdqu [r13+168], xmm2
    movdqu [r13+184], xmm3
    movdqu [r13+200], xmm4
    movdqu [r13+216], xmm5
    add rsp, 520
    pop r14
    pop r13
    pop r12
    pop rbp
    ret
daedalus_trampoline_frame_span ENDP

END
