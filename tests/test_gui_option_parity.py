"""Keep both graphical front ends wired to core protection options."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_widgets_gui_forwards_process_hardening() -> None:
    source = (ROOT / "gui" / "app.py").read_text(encoding="utf-8")

    assert "self.process_hardening_cb = QCheckBox(" in source
    assert '"process_hardening": self.process_hardening_cb.isChecked()' in source
    assert 'process_hardening=self._opts["process_hardening"]' in source
    assert "self.process_hardening_cb.setEnabled(not running)" in source


def test_qml_gui_forwards_and_persists_process_hardening() -> None:
    backend = (ROOT / "gui" / "venice_backend.py").read_text(encoding="utf-8")
    qml = (ROOT / "gui" / "qml" / "Main.qml").read_text(encoding="utf-8")

    assert "processHardeningChanged = Signal()" in backend
    assert "processHardening = Property(" in backend
    assert 'self._options.get("process_hardening", False)' in backend
    assert '"process_hardening": self._process_hardening' in backend
    assert '"process_hardening" in cfg' in backend
    assert "checked: venice.processHardening" in qml
    assert "venice.processHardening = checked" in qml
