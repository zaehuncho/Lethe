"""Conditional pointer provenance must retain both architectural outcomes."""
from __future__ import annotations

import pytest

pytest.importorskip('iced_x86')
pytest.importorskip('keystone')

from lifter import x64_lifter
from lifter import win64_thunk
from tests.test_virtualization_plan import _asm, _compile, plan as virtualization_plan

_CONDITIONS = ('e', 'ne', 'b', 'ae', 's', 'ns', 'o', 'no',
               'p', 'np', 'be', 'a', 'l', 'ge', 'le', 'g')
_WINDOW = win64_thunk.STACK_WINDOW_SIZE


@pytest.mark.parametrize('condition', _CONDITIONS)
@pytest.mark.parametrize('source_kind', ('register', 'spill'))
def test_all_conditions_preserve_two_bounded_source_aliases(condition, source_kind):
    source = 'r11' if source_kind == 'register' else 'qword ptr [rsp+0x20]'
    code = _asm(
        'sub rsp, 0x48; lea r10, [rsp+8]; lea r11, [rsp+0x10]; '
        'mov qword ptr [r10], 17; mov qword ptr [r11], 23; '
        'mov [rsp+0x20], r11; test rcx, rcx; '
        f'cmov{condition} r10, {source}; '
        'mov rax, [r10]; add rsp, 0x48; ret'
    )
    assert x64_lifter.validate_materialized_stack_window(code, window_size=_WINDOW) == 0x48
    assert len(_compile(code).functions) == 1


@pytest.mark.parametrize('condition', _CONDITIONS)
@pytest.mark.parametrize('unsafe_outcome', ('taken', 'not_taken'))
def test_each_condition_rejects_the_unsafe_outcome_after_selection(condition, unsafe_outcome):
    old, new = ('rsp', '[rsp-8]') if unsafe_outcome == 'taken' else ('[rsp-8]', 'rsp')
    old_setup = f'mov r10, {old}' if old == 'rsp' else f'lea r10, {old}'
    new_setup = f'mov r11, {new}' if new == 'rsp' else f'lea r11, {new}'
    code = _asm(f'{old_setup}; {new_setup}; cmov{condition} r10, r11; '
                'mov rax, [r10-0x1F9]; ret')
    # One outcome starts at -505 (valid), the other at -513 (out of window).
    # A blanket CMOV rejection or dropping either alternative does not pass.
    with pytest.raises(x64_lifter.LiftUnsupported, match='exceeds 512-byte window'):
        x64_lifter.validate_materialized_stack_window(code, window_size=_WINDOW)
    with pytest.raises(virtualization_plan.FunctionRejected, match='exceeds 512-byte window'):
        _compile(code)


@pytest.mark.parametrize(('source', 'maximum'), [
    ('mov r10, rsp; cmovz rax, r10; ret', 0),
    ('lea r10, [rsp-0x100]; lea r11, [rsp-0x20]; '
     'cmovne r10, r11; mov rax, [r10]; ret', 0),
    ('mov r10, rsp; cmovne r10, rcx; mov rax, [r10+0x28]; ret', 0),
    ('mov r10, rcx; cmovne r10, rsp; mov rax, [r10+0x28]; ret', 0),
    ('mov r10, rsp; cmovz r10, r10; mov rax, [r10]; ret', 0),
    ('sub rsp, 0x40; lea r10, [rsp+8]; lea r11, [rsp+0x10]; '
     'mov [r10], r11; cmovz r10, qword ptr [r10]; '
     'mov rax, [r10+8]; add rsp, 0x40; ret', 0x40),
    ('mov r14, rsp; lea r15, [rsp-0x30]; cmovle r14, r15; mov rax, [r14]; ret', 0),
    ('nop; nop; cmovz eax, ecx; ret', 0),
    ('nop; nop; cmovne ax, cx; ret', 0),
    ('sub rsp, 0x28; lea r10, [rsp+8]; mov [rsp+0x10], r10; '
     'mov r11, rcx; cmovz r11, qword ptr [rsp+0x10]; '
     'mov rax, [r11]; add rsp, 0x28; ret', 0x28),
    ('mov r10, rsp; lea r11, [rsp-8]; again: cmovz r10, r11; '
     'test rcx, rcx; jnz again; mov rax, [r10]; ret', 0),
    ('mov r10, rsp; call inner; mov rax, [r10+0x28]; ret; '
     'inner: lea r11, [rsp+0x18]; cmovz r10, r11; ret', 8),
    ('push rbp; mov rbp, rsp; sub rsp, 0x40; lea r10, [rbp-0x10]; '
     'lea r11, [rbp+0x30]; cmovns r10, r11; mov rax, [r10]; '
     'add rsp, 0x40; pop rbp; ret', 0x48),
])
def test_bounded_conditional_aliases_keep_frames_spills_and_opaque_inputs(source, maximum):
    code = _asm(source)
    assert x64_lifter.validate_materialized_stack_window(code, window_size=_WINDOW) == maximum
    assert len(_compile(code).functions) == 1


@pytest.mark.parametrize('source', [
    'mov r10, rsp; cmovz r10, rcx; mov rax, [r10-0x208]; ret',
    'mov r10, rcx; cmovz r10, rsp; mov rax, [r10-0x208]; ret',
    'sub rsp, 0x28; mov r10, rsp; mov [rsp+8], r10; '
    'cmovz r11, qword ptr [rsp+8]; mov rax, [r11-0x208]; add rsp, 0x28; ret',
    'mov rcx, 1; test rcx, rcx; cmove r10, qword ptr [rsp-0x208]; ret',
    'mov r10, rsp; cmove eax, r10d; ret',
    'mov r10, rsp; cmove r10d, ecx; ret',
    'mov r10, rsp; cmove r10w, cx; ret',
    'mov r10, rsp; cmove rsp, r10; ret',
    'mov r10, rsp; cmove esp, r10d; ret',
    'mov r10, rsp; cmove sp, r10w; ret',
    'mov r10, rsp; cmove rax, r10; mov [rcx], rax; ret',
    'sub rsp, 0x28; mov r10, rsp; mov [rsp+8], r10; mov [rcx], rax; '
    'cmovg r11, qword ptr [rsp+8]; mov rax, [r11]; add rsp, 0x28; ret',
    'sub rsp, 0x28; mov r10, rsp; mov [rsp+8], r10; '
    'mov byte ptr [rsp+8], 1; cmove r11, qword ptr [rsp+8]; add rsp, 0x28; ret',
    'cmove r10, qword ptr [rsp+rcx*8]; ret',
    'mov r10, rsp; lea r11, [rsp-0x200]; cmove r10, r11; sub r10, 1; ret',
    'mov r10, rsp; again: lea r11, [r10-8]; cmovne r10, r11; '
    'test rcx, rcx; jne again; ret',
    'sub rsp, 0x28; mov r10, rsp; mov [rsp+8], r10; '
    'cmove ax, word ptr [rsp+8]; add rsp, 0x28; ret',
])
def test_conditional_aliases_do_not_open_partial_dynamic_or_escaping_pointers(source):
    code = _asm(source)
    with pytest.raises(x64_lifter.LiftUnsupported, match='source stack|RSP'):
        x64_lifter.validate_materialized_stack_window(code, window_size=_WINDOW)
    with pytest.raises(virtualization_plan.FunctionRejected, match='source stack|RSP'):
        _compile(code)


@pytest.mark.parametrize('old_is_stack', (False, True))
@pytest.mark.parametrize('outgoing_spill', (False, True))
def test_conditional_alias_native_escape_is_rejected_on_either_outcome(old_is_stack, outgoing_spill):
    old = 'mov r11, rsp' if old_is_stack else 'mov r11, rcx'
    source = 'rcx' if old_is_stack else 'rsp'
    outgoing = 'mov [rsp+0x20], r11; mov r11d, 0; ' if outgoing_spill else ''
    code = _asm(f'sub rsp, 0x38; {old}; cmovz r11, {source}; '
                f'{outgoing}call 0x4000; add rsp, 0x38; ret')
    with pytest.raises(x64_lifter.LiftUnsupported, match='native source stack pointer escape'):
        x64_lifter.validate_materialized_stack_window(
            code, window_size=_WINDOW, native_call_targets={0x4000})
