"""Strict bounded call-site proof for the synthetic typed-XFG source-link lane."""

import struct

import pytest

from lifter import source_link_build as build


CALLER_VA = 0x140001000
SLOT_VA = 0x140007000
DISPATCH_VA = 0x1400051D0
HASH = bytes.fromhex("70f1df7a08a79d81")


def _caller(*, prefix: bytes = b"", pointer: bytes | None = None,
            store: bytes = bytes.fromhex("48895c2430"),
            r10: bytes | None = None, arg2: bytes = bytes.fromhex("baa5000000"),
            call: bytes | None = None, prologue: bool = True) -> bytes:
    head = bytes.fromhex("4883ec38") if prologue else b""
    before = len(head) + len(prefix)
    pointer = pointer or (bytes.fromhex("488b05") + struct.pack(
        "<i", SLOT_VA - (CALLER_VA + before + 7)
    ))
    r10 = r10 or bytes.fromhex("49ba") + HASH
    middle = (pointer + store + r10 + arg2
              + bytes.fromhex("48c744242055000000")
              + bytes.fromhex("41b942000000")
              + bytes.fromhex("41b876080000")
              + bytes.fromhex("b934120000"))
    call = call or (bytes.fromhex("ff15") + struct.pack(
        "<i", DISPATCH_VA - (CALLER_VA + before + len(middle) + 6)
    ))
    return head + prefix + middle + call + bytes.fromhex("4883c438c3")


def _prove(encoded: bytes) -> bytes:
    return build._validated_typed_xfg_callsite(
        encoded, caller_va=CALLER_VA, slot_va=SLOT_VA,
        dispatch_va=DISPATCH_VA,
    )


def test_exact_live_register_and_rip_dispatch_template():
    assert _prove(_caller()) == HASH


@pytest.mark.parametrize("name,change", (
    ("clobbered_rax", {"store": bytes.fromhex("31c0909090")}),
    ("clobbered_r10", {"arg2": bytes.fromhex("4531d29090")}),
    ("alternate_pointer_addressing", {
        "pointer": bytes.fromhex("48a1") + SLOT_VA.to_bytes(8, "little"),
    }),
    ("alternate_dispatch_addressing", {
        "call": bytes.fromhex("48a1") + DISPATCH_VA.to_bytes(8, "little"),
    }),
))
def test_register_clobber_and_non_rip_forms_reject(name, change):
    with pytest.raises(build.SourceLinkError, match="unique live pointer/hash/dispatch"):
        _prove(_caller(**change))


def test_direct_branch_into_template_interior_rejects():
    # Short jump from the caller prelude to the second instruction, bypassing
    # the RAX definition while leaving all template bytes otherwise intact.
    prefix = bytes.fromhex("eb05")
    with pytest.raises(build.SourceLinkError, match="branches into live"):
        _prove(_caller(prefix=prefix))


def test_second_indirect_call_rejects():
    extra = bytes.fromhex("ff10")  # call qword [rax]
    with pytest.raises(build.SourceLinkError, match="unbounded indirect transfer"):
        _prove(_caller(prefix=extra))


def test_xbegin_abort_target_cannot_enter_after_pointer_definition():
    # On a transactional abort, XBEGIN jumps directly to the saved-RBX store
    # and leaves RAX holding an abort status, not the selected pointer.
    prefix = bytes.fromhex("c7f807000000")
    with pytest.raises(build.SourceLinkError, match="unsupported control flow"):
        _prove(_caller(prefix=prefix))


def test_call_to_template_begin_changes_stack_and_rejects():
    with pytest.raises(build.SourceLinkError, match="branches into live"):
        _prove(_caller(prefix=bytes.fromhex("e800000000")))


def test_jump_to_template_without_prologue_rejects():
    with pytest.raises(build.SourceLinkError, match="exact Win64 stack prologue"):
        _prove(_caller(prefix=bytes.fromhex("eb00"), prologue=False))


def test_restored_frame_cannot_jump_to_template():
    with pytest.raises(build.SourceLinkError, match="without Win64 frame"):
        _prove(_caller(prefix=bytes.fromhex("4883c438eb00")))
