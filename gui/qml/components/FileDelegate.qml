import QtQuick
import QtQuick.Layouts
import "../Theme.js" as Theme

// One row in the file ListView, rendered as a rounded card (not a table row).
// Left: a type-coded icon chip (gold accent for EXE, blue for DLL). Center:
// filename, an indeterminate progress shimmer while packing, and arch + size
// beneath. Right: a status cell that changes with model.status. A "x" remove
// affordance fades in on hover; a done file reveals its output in Explorer.
Item {
    id: delegate

    // gold as a color so translucent tints can be derived from its channels
    readonly property color accentColor: Theme.accent

    width: ListView.view ? ListView.view.width : 0
    height: 68                                   // 64px card + 4px gap below

    Rectangle {
        id: card
        anchors.fill: parent
        anchors.bottomMargin: 4
        radius: 6
        color: hover.hovered ? Theme.bg_elevated : Theme.bg_surface
        border.width: 1
        border.color: delegate.ListView.isCurrentItem ? Theme.accent : Theme.border

        Behavior on color { ColorAnimation { duration: 150 } }
        Behavior on border.color { ColorAnimation { duration: 150 } }

        HoverHandler { id: hover }

        // selected-row accent bar
        Rectangle {
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.margins: 1
            width: 3
            radius: 2
            color: Theme.accent
            visible: delegate.ListView.isCurrentItem
        }

        // row click: select, and reveal the output when a file is done
        MouseArea {
            anchors.fill: parent
            cursorShape: (model.status === "done" && model.outputPath)
                         ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: {
                delegate.ListView.view.currentIndex = index;
                if (model.status === "done" && model.outputPath)
                    venice.openOutputFile(index);
            }
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 12
            anchors.rightMargin: 8
            spacing: 12

            // ---- type-coded icon chip ----
            Rectangle {
                Layout.alignment: Qt.AlignVCenter
                implicitWidth: 36
                implicitHeight: 36
                radius: 8
                color: Theme.bg_elevated

                // left accent: gold for EXE, blue for DLL (inset to clear corners)
                Rectangle {
                    anchors.left: parent.left
                    anchors.top: parent.top
                    anchors.bottom: parent.bottom
                    anchors.topMargin: 6
                    anchors.bottomMargin: 6
                    width: 2
                    radius: 1
                    color: model.fileType === "DLL" ? Theme.info : Theme.accent
                }

                Text {
                    anchors.centerIn: parent
                    text: model.fileType
                    color: Theme.text_secondary
                    font.family: Theme.fontUi
                    font.pixelSize: 10
                    font.weight: Font.Bold
                }
            }

            // ---- name + progress + metadata ----
            ColumnLayout {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignVCenter
                spacing: 4

                Text {
                    Layout.fillWidth: true
                    text: model.filename
                    color: Theme.text_primary
                    font.family: Theme.fontUi
                    font.pixelSize: Theme.body
                    font.weight: Font.DemiBold
                    elide: Text.ElideMiddle
                }

                // indeterminate progress shimmer -- only while packing
                Rectangle {
                    id: progressTrack
                    Layout.fillWidth: true
                    implicitHeight: 2
                    radius: 1
                    clip: true
                    visible: model.status === "packing"
                    color: Qt.rgba(delegate.accentColor.r, delegate.accentColor.g,
                                   delegate.accentColor.b, 0.2)

                    Rectangle {
                        id: shimmer
                        height: parent.height
                        width: Math.max(24, progressTrack.width * 0.3)
                        radius: 1
                        color: Theme.accent

                        SequentialAnimation {
                            running: model.status === "packing"
                            loops: Animation.Infinite
                            NumberAnimation {
                                target: shimmer
                                property: "x"
                                from: -shimmer.width
                                to: progressTrack.width
                                duration: 1000
                                easing.type: Easing.InOutQuad
                            }
                        }
                    }
                }

                RowLayout {
                    spacing: 6

                    // arch badge
                    Rectangle {
                        implicitHeight: 18
                        implicitWidth: archText.implicitWidth + 12
                        radius: 4
                        color: Theme.bg_elevated
                        border.width: 1
                        border.color: Theme.border
                        Text {
                            id: archText
                            anchors.centerIn: parent
                            text: model.arch
                            color: Theme.text_secondary
                            font.family: Theme.fontUi
                            font.pixelSize: 10
                            font.weight: Font.DemiBold
                        }
                    }

                    Text {
                        text: model.humanSize
                        color: Theme.text_secondary
                        font.family: Theme.fontUi
                        font.pixelSize: Theme.caption
                        Layout.leftMargin: 2
                    }
                }
            }

            // ---- status cell ----
            Text {
                id: statusLabel
                Layout.alignment: Qt.AlignVCenter
                Layout.maximumWidth: 240
                horizontalAlignment: Text.AlignRight
                elide: Text.ElideRight
                font.family: Theme.fontUi
                font.pixelSize: Theme.caption
                color: Theme.statusColor(model.status)
                text: {
                    switch (model.status) {
                    case "packing":
                        return "Packing…";
                    case "done":
                        return "✓ " + (model.ratio * 100).toFixed(1)
                               + "% · " + model.elapsed + " ms";
                    case "error":
                        return "✗ " + model.statusText;
                    default:
                        return "Ready";
                    }
                }

                // subtle opacity pulse while a file is actively packing
                SequentialAnimation {
                    running: model.status === "packing"
                    loops: Animation.Infinite
                    NumberAnimation { target: statusLabel; property: "opacity"; to: 0.45; duration: 700; easing.type: Easing.InOutSine }
                    NumberAnimation { target: statusLabel; property: "opacity"; to: 1.0;  duration: 700; easing.type: Easing.InOutSine }
                    onRunningChanged: if (!running) statusLabel.opacity = 1.0
                }
            }

            // ---- remove ("x") -- fades in on hover ----
            Item {
                Layout.alignment: Qt.AlignVCenter
                implicitWidth: 24
                implicitHeight: 24
                opacity: hover.hovered ? 1.0 : 0.0
                Behavior on opacity { NumberAnimation { duration: 120 } }

                Rectangle {
                    anchors.fill: parent
                    radius: 4
                    color: removeMa.containsMouse ? Theme.bg_input : "transparent"

                    Text {
                        anchors.centerIn: parent
                        text: "×"          // multiplication sign as a clean "x"
                        color: removeMa.containsMouse ? Theme.error : Theme.text_secondary
                        font.pixelSize: 16
                    }

                    MouseArea {
                        id: removeMa
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: venice.fileModel.removeFile(index)
                    }
                }
            }
        }
    }
}
