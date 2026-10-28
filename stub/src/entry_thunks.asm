; CFG function-table RVAs encode four flag bits in their low nibble.  The
; packer therefore needs the exported loader entry points to be 16-byte aligned.
; Keep tiny assembly thunks at exact aligned addresses and tail-jump to the C
; implementations without changing the x64 calling convention or return edge.

EXTERN StubExeEntryImpl:PROC
EXTERN StubDllMainImpl:PROC

PUBLIC StubExeEntry
PUBLIC StubDllMain

; The default MASM .code segment has byte contribution alignment when the
; linker merges it with C objects.  Give this contribution an explicit section
; alignment so its first exported thunk remains CFG-addressable after linking.
_TEXT SEGMENT ALIGN(16) 'CODE'

ALIGN 16
StubExeEntry PROC
    jmp StubExeEntryImpl
StubExeEntry ENDP

ALIGN 16
StubDllMain PROC
    jmp StubDllMainImpl
StubDllMain ENDP

_TEXT ENDS

END
