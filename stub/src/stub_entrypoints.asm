; Stable, 16-byte-aligned OS and CFG entry veneers.
; The grafted outer image declares these RVAs in its Guard CF table. Keeping
; alignment in MASM avoids relying on compiler function-layout heuristics.

OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

EXTERN StubExeEntryImpl:PROC
EXTERN StubDllMainImpl:PROC
EXTERN lethe_stub_tls_callback_impl:PROC

PUBLIC StubExeEntry
PUBLIC StubDllMain
PUBLIC lethe_stub_tls_callback

.code

ALIGN 16
StubExeEntry PROC
    jmp StubExeEntryImpl
StubExeEntry ENDP

ALIGN 16
StubDllMain PROC
    jmp StubDllMainImpl
StubDllMain ENDP

ALIGN 16
lethe_stub_tls_callback PROC
    jmp lethe_stub_tls_callback_impl
lethe_stub_tls_callback ENDP

END
