"""Generate a Win64 entry shim for one bounded-stack Daedalus function.

The generated shim contains no program-specific logic. It preserves the exact
target-function entry state, calls the shared MASM bridge, and embeds a pointer
to a ``DaedalusX64Descriptor`` immediately after a two-byte short jump. The
common bridge reads that descriptor without consuming any target GPR.  The
planning layer proves all reachable source-stack depths fit the 512-byte
private window above the bridge's saved return and context.
"""

from __future__ import annotations

import re


_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Fixed encodings emitted by MASM for the template below. The planning layer
# uses these offsets before any output PE exists. Native thunk tests compile the
# same template in both rolling modes.
STACK_WINDOW_SIZE = 512
THUNK_CODE_SIZE = 46
THUNK_COMMON_REL32_OFFSET = 9
THUNK_DESCRIPTOR_POINTER_OFFSET = 15
THUNK_PROLOG_SIZE = 8
THUNK_UNWIND_INFO = bytes.fromhex("010803000801440001020000")
THUNK_TEMPLATE = bytes.fromhex(
    "9c"                    # pushfq
    "4881ec20020000"      # sub rsp, 544 = 512-byte source window + shadow
    "e800000000"            # call rel32 (hole at +9)
    "eb08"                  # jump over descriptor pointer
    "0000000000000000"      # descriptor VA (hole at +15)
    "833c2400"              # cmp dword ptr [rsp], 0
    "750A"                  # jne failure epilogue
    "4881c428020000c39090"        # success: add rsp,552; ret; fixed padding
    "b907000000cd29"        # failure: FAST_FAIL_FATAL_APP_EXIT
)

if len(THUNK_TEMPLATE) != THUNK_CODE_SIZE:  # import-time ABI guard
    raise RuntimeError("Win64 thunk template size drift")


# A tail-only shim is distinct from the ordinary return shim.  Status 2 is
# emitted only by a planner-proven terminal E9 body and is consumed after the
# common bridge has returned normally (so its CET call/return pair remains
# intact).  The generated E9 target is a fixed, planner-proven relative branch;
# no target address is carried in a volatile register.  ``lea`` is flag-neutral
# and ``popfq`` restores the VM-produced source flags immediately before that
# branch, which preserves the original caller-to-target shadow-stack pairing.
#
# There are three unwindable stack states: the ordinary shim frame through the
# LEA, the one-byte POPFQ state with only the saved flags on the stack, and the
# final direct E9 at the original source RSP.  Materialization emits separate
# PDATA records for those exact ranges using the offset constants below.
TAIL_THUNK_CODE_SIZE = 64
TAIL_THUNK_COMMON_REL32_OFFSET = THUNK_COMMON_REL32_OFFSET
TAIL_THUNK_DESCRIPTOR_POINTER_OFFSET = THUNK_DESCRIPTOR_POINTER_OFFSET
TAIL_THUNK_PROLOG_SIZE = THUNK_PROLOG_SIZE
TAIL_THUNK_UNWIND_INFO = THUNK_UNWIND_INFO
TAIL_THUNK_POPFQ_UNWIND_INFO = bytes.fromhex("0100010000020000")
TAIL_THUNK_JUMP_UNWIND_INFO = bytes.fromhex("01000000")
TAIL_THUNK_TAIL_STATUS_OFFSET = 37
TAIL_THUNK_FAILURE_OFFSET = 43
TAIL_THUNK_TAIL_RESTORE_OFFSET = 50
TAIL_THUNK_PRIMARY_END_OFFSET = 58
TAIL_THUNK_POPFQ_OFFSET = 58
TAIL_THUNK_POPFQ_END_OFFSET = 59
TAIL_THUNK_JUMP_OFFSET = 59
TAIL_THUNK_TARGET_REL32_OFFSET = 60
TAIL_THUNK_JUMP_END_OFFSET = 64
TAIL_THUNK_TEMPLATE = bytes.fromhex(
    "9c"                    # pushfq
    "4881ec20020000"        # sub rsp, 544
    "e800000000"            # call rel32 (hole at +9)
    "eb08"                  # jump over descriptor pointer
    "0000000000000000"      # descriptor VA (hole at +15)
    "833c2400"              # cmp dword ptr [rsp], 0
    "7508"                  # jne tail-status check
    "4881c428020000c3"      # normal: add rsp,552; ret
    "833c2402"              # cmp dword ptr [rsp], 2 (authenticated tail)
    "7407"                  # je authenticated tail epilogue
    "b907000000cd29"        # failure: FAST_FAIL_FATAL_APP_EXIT
    "488da42420020000"      # lea rsp, [rsp+544] -> saved VM RFLAGS
    "9d"                    # popfq
    "e900000000"            # jmp rel32 retained native tail target (hole +60)
)

if len(TAIL_THUNK_TEMPLATE) != TAIL_THUNK_CODE_SIZE:  # import-time ABI guard
    raise RuntimeError("Win64 tail thunk template size drift")


def _symbol(value: str, label: str) -> str:
    if not _SYMBOL.fullmatch(value):
        raise ValueError(f"invalid MASM {label}: {value!r}")
    return value


def render_entry_thunk(function_symbol: str, descriptor_symbol: str) -> str:
    """Return MASM source for a CET-balanced, unwindable function-entry shim.

    The descriptor must remain within image relocation reach as a normal qword
    ``OFFSET`` relocation. VM-produced RFLAGS remain available in the VM frame
    for lifted semantics, but Win64 makes physical return flags volatile and the
    legal epilogue does not attempt to export them. A VM/runtime failure is a
    fail-fast termination, never a silent return of the original RAX.
    """
    function_symbol = _symbol(function_symbol, "function symbol")
    descriptor_symbol = _symbol(descriptor_symbol, "descriptor symbol")
    resume = f"{function_symbol}_resume"
    failed = f"{function_symbol}_failed"

    return f"""; Generated by lifter/win64_thunk.py -- do not hand-edit.
OPTION CASEMAP:NONE
EXTERN daedalus_x64_enter_common_stack512:PROC
EXTERN {descriptor_symbol}:BYTE
PUBLIC {function_symbol}

.code

{function_symbol} PROC FRAME
    pushfq
    .allocstack 8
    sub     rsp, 544
    .allocstack 544
    .endprolog

    call    daedalus_x64_enter_common_stack512
    jmp     SHORT {resume}
    dq      OFFSET {descriptor_symbol}

{resume}:
    cmp     DWORD PTR [rsp], 0
    jne     {failed}
    add     rsp, 552
    ret
    nop
    nop

{failed}:
    mov     ecx, 7              ; FAST_FAIL_FATAL_APP_EXIT
    int     29h
{function_symbol} ENDP

END
"""


def render_tail_entry_thunk(
    function_symbol: str,
    descriptor_symbol: str,
    tail_target_symbol: str | None = None,
) -> str:
    """Return the dedicated CET-balanced shim for a proven terminal E9 tail.

    The common bridge returns to this shim normally.  Only a descriptor-v5,
    authenticated program may report status ``2``; the shim then restores the
    source flags and directly jumps to the planner-bound retained target.  The
    target returns directly to the original caller, never to this shim.
    """
    function_symbol = _symbol(function_symbol, "function symbol")
    descriptor_symbol = _symbol(descriptor_symbol, "descriptor symbol")
    if tail_target_symbol is not None:
        tail_target_symbol = _symbol(tail_target_symbol, "tail target symbol")
    resume = f"{function_symbol}_resume"
    tail_check = f"{function_symbol}_tail_check"
    tail_restore = f"{function_symbol}_tail_restore"
    tail_popfq = f"{function_symbol}_tail_popfq"
    tail_jump = f"{function_symbol}_tail_jump"
    failed = f"{function_symbol}_failed"
    tail_jump_source = (
        f"    jmp     {tail_target_symbol}"
        if tail_target_symbol is not None
        else "    db      0E9h, 0, 0, 0, 0 ; rel32 patched by materializer"
    )

    return f"""; Generated by lifter/win64_thunk.py -- do not hand-edit.
OPTION CASEMAP:NONE
EXTERN daedalus_x64_enter_common_stack512:PROC
EXTERN {descriptor_symbol}:BYTE
PUBLIC {function_symbol}

.code

{function_symbol} PROC FRAME
    pushfq
    .allocstack 8
    sub     rsp, 544
    .allocstack 544
    .endprolog

    call    daedalus_x64_enter_common_stack512
    jmp     SHORT {resume}
    dq      OFFSET {descriptor_symbol}

{resume}:
    cmp     DWORD PTR [rsp], 0
    jne     {tail_check}
    add     rsp, 552
    ret

{tail_check}:
    cmp     DWORD PTR [rsp], 2
    je      {tail_restore}

{failed}:
    mov     ecx, 7              ; FAST_FAIL_FATAL_APP_EXIT
    int     29h

{tail_restore}:
    lea     rsp, [rsp + 544]
{tail_popfq}:
    popfq
{tail_jump}:
{tail_jump_source}
{function_symbol} ENDP

END
"""


def render_entry_thunk_bytes() -> bytes:
    """Return the fixed machine template with REL32/DIR64 fields zeroed."""
    return THUNK_TEMPLATE


def render_tail_entry_thunk_bytes() -> bytes:
    """Return the fixed tail-shim template with REL32/DIR64 fields zeroed."""
    return TAIL_THUNK_TEMPLATE


__all__ = [
    "STACK_WINDOW_SIZE",
    "THUNK_CODE_SIZE",
    "THUNK_COMMON_REL32_OFFSET",
    "THUNK_DESCRIPTOR_POINTER_OFFSET",
    "THUNK_PROLOG_SIZE",
    "THUNK_TEMPLATE",
    "THUNK_UNWIND_INFO",
    "render_entry_thunk",
    "render_entry_thunk_bytes",
    "TAIL_THUNK_CODE_SIZE",
    "TAIL_THUNK_COMMON_REL32_OFFSET",
    "TAIL_THUNK_DESCRIPTOR_POINTER_OFFSET",
    "TAIL_THUNK_PROLOG_SIZE",
    "TAIL_THUNK_UNWIND_INFO",
    "TAIL_THUNK_POPFQ_UNWIND_INFO",
    "TAIL_THUNK_JUMP_UNWIND_INFO",
    "TAIL_THUNK_TAIL_STATUS_OFFSET",
    "TAIL_THUNK_TAIL_RESTORE_OFFSET",
    "TAIL_THUNK_PRIMARY_END_OFFSET",
    "TAIL_THUNK_POPFQ_OFFSET",
    "TAIL_THUNK_POPFQ_END_OFFSET",
    "TAIL_THUNK_JUMP_OFFSET",
    "TAIL_THUNK_TARGET_REL32_OFFSET",
    "TAIL_THUNK_JUMP_END_OFFSET",
    "TAIL_THUNK_FAILURE_OFFSET",
    "TAIL_THUNK_TEMPLATE",
    "render_tail_entry_thunk",
    "render_tail_entry_thunk_bytes",
]
