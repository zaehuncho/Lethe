; Common Win64 entry bridge for generated Daedalus function shims.
;
; Generated shim contract (see lifter/win64_thunk.py):
;   pushfq
;   sub  rsp, 32                 ; aligned call + Win64 shadow space
;   call daedalus_x64_enter_common
;   jmp  SHORT resume            ; exact two-byte instruction
;   dq   OFFSET descriptor       ; read through return_address + 2
;
; At common entry the original target-function RSP is [rsp + 48]:
; return-to-shim (8) + shadow (32) + saved RFLAGS (8). The bridge captures all
; GPRs before using a scratch register and stores that original RSP in the VM
; context, so [rsp+40] stack arguments and RSP-relative loads retain x64 entry
; semantics. The API commits its context only after a successful HALT.
;
; On success, volatile GPRs come from the VM, RAX is the function return, and
; Win64 nonvolatiles are restored from private copies. Physical return RFLAGS
; are ABI-volatile; the VM frame retains them only for lifted semantics. On failure,
; the context is still the original capture, GPRs are restored for a controlled
; bridge exit, and status=1 is written into the shim's first shadow slot. The shim owns the final
; legal epilogue or fail-fast path, keeping normal CET call/return pairing.

EXTERN daedalus_vm_exec_x64_paged:PROC
IFDEF DVM_PLAIN_DESCRIPTOR_TEST_ONLY
EXTERN daedalus_vm_exec_x64:PROC
ENDIF
PUBLIC daedalus_x64_enter_common

DVM_DESCRIPTOR_VERSION_PLAIN EQU 3
DVM_DESCRIPTOR_VERSION_PAGED EQU 4

FRAME_SIZE          EQU 248
CTX                 EQU 40
CTX_RAX             EQU CTX + 0
CTX_RCX             EQU CTX + 8
CTX_RDX             EQU CTX + 16
CTX_RBX             EQU CTX + 24
CTX_RSP             EQU CTX + 32
CTX_RBP             EQU CTX + 40
CTX_RSI             EQU CTX + 48
CTX_RDI             EQU CTX + 56
CTX_R8              EQU CTX + 64
CTX_R9              EQU CTX + 72
CTX_R10             EQU CTX + 80
CTX_R11             EQU CTX + 88
CTX_R12             EQU CTX + 96
CTX_R13             EQU CTX + 104
CTX_R14             EQU CTX + 112
CTX_R15             EQU CTX + 120
CTX_RFLAGS          EQU CTX + 128

SAVE_RBX            EQU 176
SAVE_RBP            EQU 184
SAVE_RSI            EQU 192
SAVE_RDI            EQU 200
SAVE_R12            EQU 208
SAVE_R13            EQU 216
SAVE_R14            EQU 224
SAVE_R15            EQU 232

COMMON_RETURN       EQU FRAME_SIZE
SHIM_STATUS         EQU FRAME_SIZE + 8
SHIM_SAVED_RFLAGS   EQU FRAME_SIZE + 40
ORIGINAL_ENTRY_RSP  EQU FRAME_SIZE + 48

.code

daedalus_x64_enter_common PROC FRAME
    sub     rsp, FRAME_SIZE
    .allocstack FRAME_SIZE
    .endprolog

    ; Capture every incoming GPR before clobbering any scratch register.
    mov     [rsp + CTX_RAX], rax
    mov     [rsp + CTX_RCX], rcx
    mov     [rsp + CTX_RDX], rdx
    mov     [rsp + CTX_RBX], rbx
    mov     [rsp + CTX_RBP], rbp
    mov     [rsp + CTX_RSI], rsi
    mov     [rsp + CTX_RDI], rdi
    mov     [rsp + CTX_R8], r8
    mov     [rsp + CTX_R9], r9
    mov     [rsp + CTX_R10], r10
    mov     [rsp + CTX_R11], r11
    mov     [rsp + CTX_R12], r12
    mov     [rsp + CTX_R13], r13
    mov     [rsp + CTX_R14], r14
    mov     [rsp + CTX_R15], r15

    lea     rax, [rsp + ORIGINAL_ENTRY_RSP]
    mov     [rsp + CTX_RSP], rax
    mov     rax, [rsp + SHIM_SAVED_RFLAGS]
    mov     [rsp + CTX_RFLAGS], rax

    ; Private copies guarantee the bridge preserves Win64 nonvolatiles even if
    ; lifted bytecode writes their VM slots.
    mov     [rsp + SAVE_RBX], rbx
    mov     [rsp + SAVE_RBP], rbp
    mov     [rsp + SAVE_RSI], rsi
    mov     [rsp + SAVE_RDI], rdi
    mov     [rsp + SAVE_R12], r12
    mov     [rsp + SAVE_R13], r13
    mov     [rsp + SAVE_R14], r14
    mov     [rsp + SAVE_R15], r15

    ; The exact return address is the two-byte short jump. Its following qword
    ; is the generated function's descriptor pointer.
    mov     r11, [rsp + COMMON_RETURN]
    mov     r11, [r11 + 2]
    test    r11, r11
    jz      dvm_enter_failed
    cmp     DWORD PTR [r11], DVM_DESCRIPTOR_VERSION_PAGED
    je      dvm_enter_paged
IFDEF DVM_PLAIN_DESCRIPTOR_TEST_ONLY
    cmp     DWORD PTR [r11], DVM_DESCRIPTOR_VERSION_PLAIN
    jne     dvm_enter_failed

    mov     edx, DWORD PTR [r11 + 4] ; program_size
    mov     rcx, QWORD PTR [r11 + 8] ; program
    lea     r8, [rsp + CTX]
    mov     r9, QWORD PTR [r11 + 16] ; loader-relocated image base
    test    r9, r9
    jz      dvm_enter_failed
    call    daedalus_vm_exec_x64
    jmp     dvm_check_result
ELSE
    jmp     dvm_enter_failed
ENDIF

dvm_enter_paged:
    mov     edx, DWORD PTR [r11 + 4] ; envelope_size (trusted outer section)
    mov     rcx, QWORD PTR [r11 + 8] ; authenticated page envelope
    lea     r8, [r11 + 16]           ; descriptor-bound expected program_id
    lea     r9, [rsp + CTX]
    mov     rax, QWORD PTR [r11 + 32] ; fifth arg: loader-relocated image base
    test    rax, rax
    jz      dvm_enter_failed
    mov     QWORD PTR [rsp + 32], rax
    call    daedalus_vm_exec_x64_paged

dvm_check_result:
    test    eax, eax
    jne     dvm_enter_failed

    mov     DWORD PTR [rsp + SHIM_STATUS], 0
    jmp     dvm_restore_context

dvm_enter_failed:
    ; daedalus_vm_exec_x64 commits nothing on failure, so CTX still contains
    ; the exact incoming volatile register values and the saved flags stay put.
    mov     DWORD PTR [rsp + SHIM_STATUS], 1

dvm_restore_context:
    ; VM-produced volatile state is observable on success. On failure these are
    ; the original captured values. RSP is restored structurally below.
    mov     rax, [rsp + CTX_RAX]
    mov     rcx, [rsp + CTX_RCX]
    mov     rdx, [rsp + CTX_RDX]
    mov     r8,  [rsp + CTX_R8]
    mov     r9,  [rsp + CTX_R9]
    mov     r10, [rsp + CTX_R10]

    mov     rbx, [rsp + SAVE_RBX]
    mov     rbp, [rsp + SAVE_RBP]
    mov     rsi, [rsp + SAVE_RSI]
    mov     rdi, [rsp + SAVE_RDI]
    mov     r12, [rsp + SAVE_R12]
    mov     r13, [rsp + SAVE_R13]
    mov     r14, [rsp + SAVE_R14]
    mov     r15, [rsp + SAVE_R15]

    mov     r11, [rsp + CTX_R11]
    add     rsp, FRAME_SIZE
    ret
daedalus_x64_enter_common ENDP

END
