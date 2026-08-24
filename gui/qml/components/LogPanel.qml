import QtQuick
import QtQuick.Controls
import "../Theme.js" as Theme

// Read-only, selectable, monospace activity log. `logText` is the whole log as
// one accumulated string (bind it to venice.logText). Auto-tails to the newest
// line as content streams in.
Rectangle {
    id: root

    property string logText: ""

    color: Theme.bg_surface
    radius: 6
    border.color: Theme.border
    border.width: 1
    clip: true

    ScrollView {
        anchors.fill: parent
        anchors.margins: 8
        ScrollBar.vertical.policy: ScrollBar.AsNeeded
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

        TextArea {
            id: area
            text: root.logText
            readOnly: true
            selectByMouse: true
            wrapMode: TextArea.Wrap
            textFormat: TextArea.PlainText
            color: Theme.text_secondary
            placeholderText: "Progress and results appear here."
            placeholderTextColor: Theme.text_disabled
            font.family: Theme.fontMono
            font.pixelSize: Theme.mono

            // strip the default control chrome; the wrapping Rectangle is the frame
            background: Rectangle { color: "transparent" }

            // auto-scroll: moving the cursor to the tail makes the enclosing
            // ScrollView keep the newest line in view as the log grows.
            onTextChanged: area.cursorPosition = area.length
        }
    }
}
