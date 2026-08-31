; Lethe stub -- x64 stack probe for freestanding (no CRT) builds.
;
; MSVC emits `call __chkstk` before any function whose locals exceed one
; page (4096 bytes).  The routine probes each page between the current
; stack pointer and [RSP - RAX] so the kernel commits the guard pages
; in order, preventing a silent skip over the guard.
;
; Calling convention (compiler-internal, NOT standard):
;   RAX = bytes the caller wants to allocate on the stack.
;   RAX is preserved across the call.  No other register is clobbered.
;   After return the caller does `sub rsp, rax`.

_TEXT SEGMENT

PUBLIC __chkstk
__chkstk PROC
    cmp     rax, 1000h          ; <= 4096?  nothing to probe
    jbe     cs_done

    push    rcx
    push    rax                 ; preserve original RAX

    mov     rcx, rsp
    add     rcx, 18h            ; 2 pushes (16) + return addr (8)

cs_loop:
    sub     rcx, 1000h          ; step one page
    test    dword ptr [rcx], ecx ; read-only touch: commit the page
    sub     rax, 1000h
    cmp     rax, 1000h
    ja      cs_loop

    pop     rax
    pop     rcx
cs_done:
    ret
__chkstk ENDP

_TEXT ENDS
END
