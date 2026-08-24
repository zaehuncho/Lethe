#!/usr/bin/env python3
"""Venice -- QML entry point for the Lethe PE packer front-end.

Run from source, either from the packer directory::

    python gui/venice.py

or from the project root::

    python gui/venice.py

This creates a ``QApplication`` (QML apps do not use widgets), instantiates
:class:`~venice_backend.VeniceBackend`, exposes it to QML as the ``venice``
context property and loads ``qml/Main.qml`` next to this script.
"""
from __future__ import annotations

import os
import signal
import sys

# --- import bootstrap ------------------------------------------------------
# venice.py lives at gui/venice.py. Put both this dir (so
# ``venice_backend`` imports) and the packer root (so ``packer.orchestrator``
# resolves inside the worker) on sys.path, regardless of the launch cwd.
_GUI_DIR = os.path.dirname(os.path.abspath(__file__))
_PACKER_ROOT = os.path.dirname(_GUI_DIR)  # Lethe
if _GUI_DIR not in sys.path:
    sys.path.insert(0, _GUI_DIR)
if _PACKER_ROOT not in sys.path:
    sys.path.insert(0, _PACKER_ROOT)

# --- PySide6 import guard --------------------------------------------------
try:
    from PySide6.QtCore import QUrl
    from PySide6.QtQml import QQmlApplicationEngine
    from PySide6.QtWidgets import QApplication
    # QtQuick must be imported before the engine loads any QML so its types are
    # registered with the QML type system.
    import PySide6.QtQuick  # noqa: F401
    from PySide6.QtQuickControls2 import QQuickStyle
except ImportError as exc:  # pragma: no cover - environment without PySide6
    sys.stderr.write(
        "Venice requires PySide6 (LGPL).\n"
        f"  import error: {exc}\n"
        "  install it with:  python -m pip install PySide6\n"
    )
    sys.exit(1)

from venice_backend import VeniceBackend


def main(argv: "list[str] | None" = None) -> int:
    # Let Ctrl+C in the launching terminal terminate the app normally.
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    QQuickStyle.setStyle("Basic")
    QApplication.setApplicationName("Venice")
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationDisplayName("Venice")

    engine = QQmlApplicationEngine()

    backend = VeniceBackend()
    engine.rootContext().setContextProperty("venice", backend)

    qml_path = os.path.join(_GUI_DIR, "qml", "Main.qml")
    engine.load(QUrl.fromLocalFile(qml_path))

    if not engine.rootObjects():
        sys.stderr.write(f"Venice: failed to load QML from {qml_path}\n")
        return 1

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
