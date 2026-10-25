OPTION CASEMAP:NONE

PUBLIC xfg_copy_config
PUBLIC DllMain

.code
xfg_copy_config PROC
    mov rax, [rdx]
    mov [rcx], rax
    mov rax, [rdx+8]
    mov [rcx+8], rax
    mov rax, [rdx+16]
    mov [rcx+16], rax
    mov rax, [rdx+24]
    mov [rcx+24], rax
    mov rax, [rdx+32]
    mov [rcx+32], rax
    mov rax, [rdx+40]
    mov [rcx+40], rax
    mov rax, [rdx+48]
    mov [rcx+48], rax
    mov rax, rcx
    ret
xfg_copy_config ENDP

DllMain PROC
    mov eax, 1
    ret
DllMain ENDP
END
