; venice_trampoline.asm -- MASM x64 trampoline for Venice VM N_CALL_PTR opcode.
;
; uint64_t venice_trampoline_call(void *func, int argc, const uint64_t *argv);
;
; Calls an arbitrary C function pointer with up to 8 scalar/pointer arguments
; using the Microsoft x64 calling convention (RCX, RDX, R8, R9, stack).
;
; On entry (caller's x64 fastcall):
;   RCX = func_ptr       the function to call
;   EDX = argc            argument count (0-8)
;   R8  = argv            pointer to uint64_t array of arguments
;
; Returns RAX from the called function.

PUBLIC venice_trampoline_call
.code

venice_trampoline_call PROC FRAME

    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 72
    .allocstack 72
    .endprolog

    ; Stash our own parameters into non-volatile registers.
    mov     r12, rcx            ; r12 = func_ptr
    mov     r13d, edx           ; r13d = argc
    mov     r14, r8             ; r14 = argv

    ; Load register arguments and stack arguments from argv based on argc.
    test    r13d, r13d
    jz      do_call             ; argc == 0 -> no args

    mov     rcx, [r14]          ; arg 0
    cmp     r13d, 1
    je      do_call

    mov     rdx, [r14 + 8]     ; arg 1
    cmp     r13d, 2
    je      do_call

    mov     r8, [r14 + 16]     ; arg 2
    cmp     r13d, 3
    je      do_call

    mov     r9, [r14 + 24]     ; arg 3
    cmp     r13d, 4
    jle     do_call

    ; Stack arguments (above 32-byte shadow space).
    mov     rax, [r14 + 32]    ; arg 4
    mov     [rsp + 32], rax
    cmp     r13d, 5
    je      do_call

    mov     rax, [r14 + 40]    ; arg 5
    mov     [rsp + 40], rax
    cmp     r13d, 6
    je      do_call

    mov     rax, [r14 + 48]    ; arg 6
    mov     [rsp + 48], rax
    cmp     r13d, 7
    je      do_call

    mov     rax, [r14 + 56]    ; arg 7
    mov     [rsp + 56], rax

do_call:
    call    r12                 ; call func_ptr; result in RAX

    ; Tear down.
    add     rsp, 72
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

venice_trampoline_call ENDP

END
