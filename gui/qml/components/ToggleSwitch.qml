import QtQuick
import QtQuick.Layouts
import "../Theme.js" as Theme

// Custom pill toggle: a 36x20 track with a 16px white knob, plus a label and an
// optional description to its right.
//
// CONTROLLED COMPONENT: this does NOT mutate `checked` on click. The parent
// binds `checked: venice.<prop>` and reacts to `onToggled` by flipping the real
// backend property; the binding then redraws the switch. Mutating `checked`
// locally would break that binding and desync the toggle from the backend.
Item {
    id: root

    property bool checked: false            // the switch state (parent-bound)
    property string text: ""                // primary label
    property string description: ""         // optional sub-label
    signal toggled(bool checked)            // requested new value

    implicitWidth: 220
    implicitHeight: row.implicitHeight
    opacity: enabled ? 1.0 : 0.5
    Behavior on opacity { NumberAnimation { duration: 150 } }

    RowLayout {
        id: row
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        spacing: 12

        // ---- track + knob ----
        Rectangle {
            id: track
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 1
            implicitWidth: 36
            implicitHeight: 20
            radius: height / 2
            color: root.checked ? Theme.accent : Theme.bg_elevated
            border.width: 1
            border.color: root.checked ? Theme.accent : Theme.border

            Behavior on color { ColorAnimation { duration: 150 } }
            Behavior on border.color { ColorAnimation { duration: 150 } }

            Rectangle {
                id: knob
                width: 16
                height: 16
                radius: 8
                y: (parent.height - height) / 2
                x: root.checked ? parent.width - width - 2 : 2
                color: "#FFFFFF"
                border.width: root.checked ? 0 : 1
                border.color: Theme.text_disabled

                Behavior on x { NumberAnimation { duration: 150; easing.type: Easing.OutCubic } }
                Behavior on border.color { ColorAnimation { duration: 150 } }
            }
        }

        // ---- label + description ----
        ColumnLayout {
            id: textCol
            Layout.fillWidth: true
            spacing: 2

            Text {
                text: root.text
                visible: root.text.length > 0
                color: Theme.text_primary
                font.family: Theme.fontUi
                font.pixelSize: Theme.body
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }
            Text {
                text: root.description
                visible: root.description.length > 0
                color: Theme.text_secondary
                font.family: Theme.fontUi
                font.pixelSize: Theme.caption
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }
        }
    }

    MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: root.toggled(!root.checked)
    }
}
