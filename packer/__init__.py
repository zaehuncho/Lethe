"""Lethe -- custom x64 PE packer / protector (build-time tooling only).

Public API: :func:`packer.orchestrator.pack_file` with
:class:`packer.orchestrator.PackOptions` / :class:`packer.orchestrator.PackResult`.

The container ABI (:mod:`packer.container`) is the byte-exact mirror of
``stub/src/pack_info.h`` and is the single source of truth for the on-disk /
in-image format used by both the Python builder and the native C loader stub.

This package is an internal build tool: it *produces* protected binaries and is
never shipped to customers.
"""

__version__ = "0.1.0"
