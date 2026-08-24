import QtQuick
import QtQuick.Layouts
import "../Theme.js" as Theme

Rectangle {
    id: root

    property string value: ""
    property string label: ""
    property color valueColor: Theme.text_primary
    property int entranceDelay: 0

    readonly property color accentRgb: Theme.accent

    implicitWidth: 140
    implicitHeight: 92
    radius: 10
    color: hoverHandler.hovered
           ? Qt.lighter(Theme.bg_surface, 1.08)
           : Theme.bg_surface
    border.width: 1
    border.color: hoverHandler.hovered
                  ? Qt.rgba(accentRgb.r, accentRgb.g, accentRgb.b, 0.45)
                  : Theme.border

    Behavior on color { ColorAnimation { duration: 200 } }
    Behavior on border.color { ColorAnimation { duration: 200 } }

    HoverHandler { id: hoverHandler }

    Rectangle {
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.topMargin: 10
        anchors.bottomMargin: 10
        anchors.leftMargin: 1
        width: 3
        radius: 2
        color: Theme.accent
        opacity: hoverHandler.hovered ? 0.9 : 0.4
        Behavior on opacity { NumberAnimation { duration: 200 } }
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        anchors.leftMargin: 18
        anchors.rightMargin: 14
        spacing: 8

        Text {
            Layout.fillWidth: true
            text: root.label.toUpperCase()
            color: Theme.text_secondary
            font.family: Theme.fontUi
            font.pixelSize: 10
            font.weight: Font.DemiBold
            font.letterSpacing: 1.2
            elide: Text.ElideRight
        }

        Text {
            Layout.fillWidth: true
            text: root.value
            color: root.valueColor
            font.family: Theme.fontUi
            font.pixelSize: 24
            font.weight: Font.Bold
            elide: Text.ElideRight
            Behavior on color { ColorAnimation { duration: 200 } }
        }
    }

    opacity: 0
    Component.onCompleted: entranceTimer.start()
    Timer {
        id: entranceTimer
        interval: root.entranceDelay
        onTriggered: root.opacity = 1
    }
    Behavior on opacity { NumberAnimation { duration: 450; easing.type: Easing.OutCubic } }
}
