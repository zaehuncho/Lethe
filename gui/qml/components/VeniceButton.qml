import QtQuick
import QtQuick.Controls
import "../Theme.js" as Theme

// Reusable Venice button. Subclasses Controls.Button so `text`, `enabled` and
// the `clicked()` signal come for free; adds the gold `accent` variant and the
// full hover/press/disabled color story with smooth 150ms transitions.
Button {
    id: control

    property bool accent: false
    // Optional glyph prepended to the label. NOT named `icon`: Controls.Button
    // already declares a FINAL `icon` grouped property (for image icons), which
    // a subclass cannot override.
    property string glyph: ""

    hoverEnabled: true
    topPadding: 8
    bottomPadding: 8
    leftPadding: 16
    rightPadding: 16

    font.family: Theme.fontUi
    font.pixelSize: Theme.body      // 13
    font.weight: Font.Medium        // ~500

    contentItem: Text {
        text: control.glyph.length > 0 ? (control.glyph + "  " + control.text)
                                       : control.text
        font: control.font
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
        color: !control.enabled ? Theme.text_disabled
             : control.accent    ? Theme.accent_text
                                  : Theme.text_primary
    }

    background: Rectangle {
        radius: 6
        border.width: 1
        color: {
            if (!control.enabled)
                return Theme.bg_surface;
            if (control.accent)
                return control.down ? Theme.accent_press
                     : control.hovered ? Theme.accent_hover
                     : Theme.accent;
            // neutral variant: subtle lift on hover, subtle sink on press
            return control.down ? Qt.darker(Theme.bg_elevated, 1.15)
                 : control.hovered ? Qt.lighter(Theme.bg_elevated, 1.18)
                 : Theme.bg_elevated;
        }
        border.color: {
            if (!control.enabled)
                return Theme.border;
            if (control.accent)
                return control.hovered ? Theme.accent_hover : Theme.accent;
            return Theme.border;
        }

        Behavior on color { ColorAnimation { duration: 150 } }
        Behavior on border.color { ColorAnimation { duration: 150 } }
    }
}
