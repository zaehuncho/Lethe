import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "Theme.js" as Theme
import "components"

ApplicationWindow {
    id: window

    title: "Venice"
    visible: true
    width: 1080
    height: 740
    minimumWidth: 900
    minimumHeight: 620
    color: Theme.bg_base
    font.family: Theme.fontUi

    readonly property color accentRgb: Theme.accent

    component SectionLabel: Text {
        property string label: ""
        text: label.toUpperCase()
        color: Theme.text_secondary
        font.family: Theme.fontUi
        font.pixelSize: 10
        font.weight: Font.DemiBold
        font.letterSpacing: 1
    }

    component ThinRule: Rectangle {
        Layout.fillWidth: true
        implicitHeight: 1
        color: Theme.border
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // ═══════════════════════════════════════════════════════ HEADER
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 64
            color: Theme.bg_surface

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                spacing: 14

                Item {
                    Layout.alignment: Qt.AlignVCenter
                    implicitWidth: 44
                    implicitHeight: 44

                    Rectangle {
                        anchors.centerIn: parent
                        width: 56; height: 56; radius: 28
                        color: Qt.rgba(window.accentRgb.r, window.accentRgb.g,
                                       window.accentRgb.b, 0.06)
                    }

                    Rectangle {
                        id: brandMark
                        anchors.centerIn: parent
                        width: 40; height: 40; radius: 10
                        color: Qt.rgba(window.accentRgb.r, window.accentRgb.g,
                                       window.accentRgb.b, 0.10)
                        border.width: 1
                        border.color: Qt.rgba(window.accentRgb.r, window.accentRgb.g,
                                              window.accentRgb.b, 0.30)

                        Text {
                            anchors.centerIn: parent
                            text: "◆"
                            color: Theme.accent
                            font.pixelSize: 18
                        }

                        SequentialAnimation on border.color {
                            loops: Animation.Infinite
                            ColorAnimation {
                                to: Qt.rgba(window.accentRgb.r, window.accentRgb.g,
                                            window.accentRgb.b, 0.55)
                                duration: 2500
                                easing.type: Easing.InOutSine
                            }
                            ColorAnimation {
                                to: Qt.rgba(window.accentRgb.r, window.accentRgb.g,
                                            window.accentRgb.b, 0.20)
                                duration: 2500
                                easing.type: Easing.InOutSine
                            }
                        }
                    }
                }

                Column {
                    spacing: 1
                    Text {
                        text: "Venice"
                        color: Theme.accent
                        font.family: Theme.fontUi
                        font.pixelSize: 20
                        font.weight: Font.Bold
                        font.letterSpacing: 0.5
                    }
                    Text {
                        text: "PE Packer"
                        color: Theme.text_secondary
                        font.family: Theme.fontUi
                        font.pixelSize: 11
                        font.letterSpacing: 2
                    }
                }

                Item { Layout.fillWidth: true }

                Rectangle {
                    Layout.alignment: Qt.AlignVCenter
                    implicitHeight: 24
                    implicitWidth: versionText.implicitWidth + 20
                    radius: height / 2
                    color: Theme.bg_elevated
                    border.width: 1
                    border.color: Theme.border
                    Text {
                        id: versionText
                        anchors.centerIn: parent
                        text: "v1.0"
                        color: Theme.text_secondary
                        font.family: Theme.fontUi
                        font.pixelSize: 10
                        font.weight: Font.DemiBold
                        font.letterSpacing: 0.5
                    }
                }
            }

            Rectangle {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                height: 1
                gradient: Gradient {
                    orientation: Gradient.Horizontal
                    GradientStop { position: 0.0; color: "transparent" }
                    GradientStop { position: 0.25; color: Qt.rgba(window.accentRgb.r, window.accentRgb.g, window.accentRgb.b, 0.4) }
                    GradientStop { position: 0.5; color: Theme.accent }
                    GradientStop { position: 0.75; color: Qt.rgba(window.accentRgb.r, window.accentRgb.g, window.accentRgb.b, 0.4) }
                    GradientStop { position: 1.0; color: "transparent" }
                }
            }

            Rectangle {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.bottomMargin: -4
                height: 4
                gradient: Gradient {
                    GradientStop { position: 0.0; color: Qt.rgba(0, 0, 0, 0.18) }
                    GradientStop { position: 1.0; color: "transparent" }
                }
            }
        }

        // ═══════════════════════════════════════════════════ CONTENT
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.margins: 16
            spacing: 14

            // ──────────────────────────────────── stats row
            RowLayout {
                Layout.fillWidth: true
                spacing: 12

                StatCard {
                    Layout.fillWidth: true; Layout.preferredWidth: 1
                    label: "Files Queued"
                    value: venice.fileModel.count
                    entranceDelay: 0
                }
                StatCard {
                    Layout.fillWidth: true; Layout.preferredWidth: 1
                    label: "Total Size"
                    value: venice.totalSize
                    entranceDelay: 70
                }
                StatCard {
                    Layout.fillWidth: true; Layout.preferredWidth: 1
                    label: "Status"
                    value: venice.isPacking ? "Packing"
                         : (venice.doneCount > 0 ? "Complete" : "Ready")
                    valueColor: venice.isPacking ? Theme.warning
                              : (venice.doneCount > 0 ? Theme.success : Theme.text_primary)
                    entranceDelay: 140
                }
                StatCard {
                    Layout.fillWidth: true; Layout.preferredWidth: 1
                    label: "Completed"
                    value: venice.isPacking
                           ? (venice.doneCount + "/" + venice.totalJobs)
                           : "—"
                    entranceDelay: 210
                }
            }

            // ═══════════════════════════ main + log (resizable)
            SplitView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                orientation: Qt.Vertical

                handle: Rectangle {
                    implicitHeight: 6
                    color: SplitHandle.pressed ? Theme.accent
                         : SplitHandle.hovered ? Theme.border_focus
                         : "transparent"
                    Behavior on color { ColorAnimation { duration: 120 } }
                }

                // ────────────────────── files + options
                Item {
                    SplitView.fillHeight: true
                    SplitView.minimumHeight: 220

                    RowLayout {
                        anchors.fill: parent
                        spacing: 12

                        // ──── LEFT: file list card ────
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            radius: 10
                            color: Theme.bg_surface
                            border.width: 1
                            border.color: Theme.border
                            clip: true

                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 0

                                RowLayout {
                                    Layout.fillWidth: true
                                    Layout.topMargin: 10
                                    Layout.leftMargin: 12
                                    Layout.rightMargin: 12
                                    Layout.bottomMargin: 8
                                    spacing: 8

                                    VeniceButton {
                                        text: "Add Files"
                                        glyph: "+"
                                        enabled: !venice.isPacking
                                        onClicked: venice.browseFiles()
                                    }
                                    VeniceButton {
                                        text: "Remove"
                                        enabled: !venice.isPacking && fileList.currentIndex >= 0 && fileList.count > 0
                                        onClicked: venice.fileModel.removeFile(fileList.currentIndex)
                                    }
                                    VeniceButton {
                                        text: "Clear"
                                        enabled: !venice.isPacking && fileList.count > 0
                                        onClicked: venice.fileModel.clear()
                                    }
                                    VeniceButton {
                                        text: "Report"
                                        enabled: fileList.count > 0 && fileList.currentIndex >= 0
                                        onClicked: venice.showReport(fileList.currentIndex)
                                    }

                                    Item { Layout.fillWidth: true }

                                    Text {
                                        text: fileList.count + (fileList.count === 1 ? " file" : " files")
                                        color: Theme.text_secondary
                                        font.family: Theme.fontUi
                                        font.pixelSize: Theme.caption
                                    }
                                }

                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.leftMargin: 12
                                    Layout.rightMargin: 12
                                    implicitHeight: 1
                                    color: Theme.border
                                }

                                Item {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true

                                    ListView {
                                        id: fileList
                                        anchors.fill: parent
                                        anchors.margins: 6
                                        clip: true
                                        spacing: 0
                                        currentIndex: -1
                                        model: venice.fileModel
                                        delegate: FileDelegate {}
                                        boundsBehavior: Flickable.StopAtBounds
                                        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                                        add: Transition {
                                            NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 220; easing.type: Easing.OutCubic }
                                            NumberAnimation { property: "scale"; from: 0.97; to: 1; duration: 220; easing.type: Easing.OutCubic }
                                        }
                                        remove: Transition {
                                            NumberAnimation { property: "opacity"; from: 1; to: 0; duration: 160 }
                                        }
                                        displaced: Transition {
                                            NumberAnimation { properties: "y"; duration: 200; easing.type: Easing.OutCubic }
                                        }

                                        Keys.onDeletePressed:
                                            if (!venice.isPacking && currentIndex >= 0)
                                                venice.fileModel.removeFile(currentIndex)
                                    }

                                    Column {
                                        id: emptyState
                                        anchors.centerIn: parent
                                        spacing: 14
                                        visible: fileList.count === 0
                                        opacity: 0
                                        scale: 0.95

                                        Behavior on opacity { NumberAnimation { duration: 300; easing.type: Easing.OutCubic } }
                                        Behavior on scale { NumberAnimation { duration: 300; easing.type: Easing.OutCubic } }

                                        onVisibleChanged: {
                                            if (visible) { opacity = 1.0; scale = 1.0; }
                                            else { opacity = 0.0; scale = 0.95; }
                                        }
                                        Component.onCompleted: if (visible) { opacity = 1.0; scale = 1.0; }

                                        Item {
                                            anchors.horizontalCenter: parent.horizontalCenter
                                            width: 72; height: 72

                                            Rectangle {
                                                id: outerRing
                                                anchors.fill: parent
                                                radius: width / 2
                                                color: "transparent"
                                                border.width: 1.5
                                                border.color: Theme.border

                                                SequentialAnimation on opacity {
                                                    loops: Animation.Infinite
                                                    NumberAnimation { to: 0.35; duration: 2200; easing.type: Easing.InOutSine }
                                                    NumberAnimation { to: 1.0; duration: 2200; easing.type: Easing.InOutSine }
                                                }
                                            }

                                            Rectangle {
                                                anchors.centerIn: parent
                                                width: 46; height: 46; radius: 12
                                                color: Qt.rgba(window.accentRgb.r, window.accentRgb.g,
                                                               window.accentRgb.b, 0.06)
                                                border.width: 1
                                                border.color: Qt.rgba(window.accentRgb.r, window.accentRgb.g,
                                                                      window.accentRgb.b, 0.20)

                                                Text {
                                                    anchors.centerIn: parent
                                                    text: "↓"
                                                    color: Theme.accent
                                                    font.pixelSize: 22
                                                    font.weight: Font.Light
                                                }
                                            }
                                        }

                                        Text {
                                            anchors.horizontalCenter: parent.horizontalCenter
                                            text: "Drop PE files here"
                                            color: Theme.text_secondary
                                            font.family: Theme.fontUi
                                            font.pixelSize: 14
                                        }
                                        Text {
                                            anchors.horizontalCenter: parent.horizontalCenter
                                            text: "or click Add Files to get started"
                                            color: Theme.text_disabled
                                            font.family: Theme.fontUi
                                            font.pixelSize: 12
                                        }
                                    }

                                    DropArea {
                                        id: dropArea
                                        anchors.fill: parent
                                        onDropped: function(drop) { venice.addDroppedUrls(drop.urls) }
                                    }

                                    Rectangle {
                                        anchors.fill: parent
                                        anchors.margins: 4
                                        radius: 8
                                        color: Qt.rgba(window.accentRgb.r, window.accentRgb.g,
                                                       window.accentRgb.b, 0.04)
                                        border.color: Theme.accent
                                        border.width: 2
                                        visible: opacity > 0.01
                                        opacity: dropArea.containsDrag ? 1.0 : 0.0
                                        Behavior on opacity { NumberAnimation { duration: 150 } }
                                    }
                                }
                            }
                        }

                        // ──── RIGHT: settings panel ────
                        Rectangle {
                            Layout.preferredWidth: 260
                            Layout.minimumWidth: 240
                            Layout.fillHeight: true
                            radius: 10
                            color: Theme.bg_surface
                            border.width: 1
                            border.color: Theme.border
                            clip: true

                            Flickable {
                                anchors.fill: parent
                                anchors.margins: 14
                                contentHeight: settingsCol.implicitHeight
                                boundsBehavior: Flickable.StopAtBounds
                                ScrollBar.vertical: ScrollBar {
                                    policy: parent.contentHeight > parent.height
                                            ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff
                                }

                                ColumnLayout {
                                    id: settingsCol
                                    width: parent.width
                                    spacing: 10

                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 8

                                        Rectangle {
                                            implicitWidth: 4
                                            implicitHeight: 16
                                            radius: 2
                                            color: Theme.accent
                                        }

                                        Text {
                                            text: "SETTINGS"
                                            color: Theme.text_secondary
                                            font.family: Theme.fontUi
                                            font.pixelSize: 11
                                            font.weight: Font.Bold
                                            font.letterSpacing: 1.5
                                        }
                                    }

                                    ThinRule {}

                                    SectionLabel { label: "Presets" }

                                    Flow {
                                        Layout.fillWidth: true
                                        spacing: 6
                                        Repeater {
                                            model: venice.presetNames
                                            VeniceButton {
                                                text: modelData
                                                enabled: !venice.isPacking
                                                onClicked: venice.applyPreset(modelData)
                                            }
                                        }
                                    }

                                    ThinRule {}

                                    SectionLabel { label: "Output" }

                                    Rectangle {
                                        Layout.fillWidth: true
                                        implicitHeight: 34
                                        radius: 6
                                        color: Theme.bg_input
                                        border.width: 1
                                        border.color: Theme.border
                                        Text {
                                            anchors.fill: parent
                                            anchors.leftMargin: 10
                                            anchors.rightMargin: 10
                                            verticalAlignment: Text.AlignVCenter
                                            text: venice.outputDirectory !== "" ? venice.outputDirectory
                                                                                : "Beside input file"
                                            color: venice.outputDirectory !== "" ? Theme.text_primary
                                                                                 : Theme.text_secondary
                                            elide: Text.ElideMiddle
                                            font.family: Theme.fontUi
                                            font.pixelSize: Theme.caption
                                        }
                                    }

                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 8
                                        VeniceButton {
                                            text: "Browse"
                                            Layout.fillWidth: true
                                            enabled: !venice.isPacking
                                            onClicked: venice.browseOutputDir()
                                        }
                                        VeniceButton {
                                            text: "Reset"
                                            Layout.fillWidth: true
                                            enabled: !venice.isPacking && venice.outputDirectory !== ""
                                            onClicked: venice.resetOutputDir()
                                        }
                                    }

                                    ThinRule {}

                                    SectionLabel { label: "Protection" }

                                    Rectangle {
                                        Layout.fillWidth: true
                                        radius: 8
                                        color: Theme.bg_input
                                        border.width: 1
                                        border.color: Theme.border
                                        implicitHeight: protectionCol.implicitHeight + 20

                                        ColumnLayout {
                                            id: protectionCol
                                            anchors.left: parent.left
                                            anchors.right: parent.right
                                            anchors.verticalCenter: parent.verticalCenter
                                            anchors.leftMargin: 12
                                            anchors.rightMargin: 12
                                            spacing: 10

                                            ToggleSwitch {
                                                Layout.fillWidth: true
                                                text: "Anti-debug"
                                                checked: venice.antiDebug
                                                enabled: !venice.isPacking
                                                onToggled: function(checked) { venice.antiDebug = checked }
                                            }

                                            Rectangle {
                                                Layout.fillWidth: true
                                                implicitHeight: 1
                                                color: Theme.border
                                            }

                                            ToggleSwitch {
                                                Layout.fillWidth: true
                                                text: "Memory guard"
                                                description: "opt-in — test against AV first"
                                                checked: venice.memoryGuard
                                                enabled: !venice.isPacking
                                                onToggled: function(checked) { venice.memoryGuard = checked }
                                            }

                                            Rectangle {
                                                Layout.fillWidth: true
                                                implicitHeight: 1
                                                color: Theme.border
                                            }

                                            ToggleSwitch {
                                                Layout.fillWidth: true
                                                text: "Validate output"
                                                description: "structural round-trip check (no run)"
                                                checked: venice.validateAfterPack
                                                enabled: !venice.isPacking
                                                onToggled: function(checked) { venice.validateAfterPack = checked }
                                            }
                                        }
                                    }

                                    ThinRule {}

                                    RowLayout {
                                        Layout.fillWidth: true
                                        SectionLabel { label: "Compression" }
                                        Item { Layout.fillWidth: true }
                                        Text {
                                            text: Math.round(levelSlider.value)
                                            color: Theme.accent
                                            font.family: Theme.fontUi
                                            font.pixelSize: Theme.body
                                            font.weight: Font.Bold
                                        }
                                    }

                                    Slider {
                                        id: levelSlider
                                        Layout.fillWidth: true
                                        from: 0; to: 9; stepSize: 1
                                        snapMode: Slider.SnapAlways
                                        value: venice.compressionLevel
                                        enabled: !venice.isPacking
                                        onMoved: venice.compressionLevel = value

                                        background: Rectangle {
                                            x: levelSlider.leftPadding
                                            y: levelSlider.topPadding + levelSlider.availableHeight / 2 - height / 2
                                            width: levelSlider.availableWidth
                                            height: 4; radius: 2
                                            color: Theme.border

                                            Rectangle {
                                                width: levelSlider.visualPosition * parent.width
                                                height: parent.height; radius: 2
                                                color: Theme.accent
                                            }
                                        }
                                        handle: Rectangle {
                                            x: levelSlider.leftPadding + levelSlider.visualPosition * (levelSlider.availableWidth - width)
                                            y: levelSlider.topPadding + levelSlider.availableHeight / 2 - height / 2
                                            width: 16; height: 16; radius: 8
                                            color: levelSlider.pressed ? Theme.accent_press : "#FFFFFF"
                                            border.color: Theme.accent
                                            border.width: 2
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // ────────────────────── activity log
                Item {
                    SplitView.preferredHeight: 140
                    SplitView.minimumHeight: 80

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 6

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8

                            Rectangle {
                                implicitWidth: 4
                                implicitHeight: 12
                                radius: 2
                                color: Theme.accent
                                opacity: 0.5
                            }

                            SectionLabel { label: "Activity Log" }
                            Item { Layout.fillWidth: true }
                            Text {
                                text: {
                                    var t = venice.logText;
                                    var n = (t.length === 0) ? 0 : t.split("\n").length;
                                    return n + (n === 1 ? " line" : " lines");
                                }
                                color: Theme.text_secondary
                                font.family: Theme.fontUi
                                font.pixelSize: Theme.caption
                            }
                        }

                        LogPanel {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            logText: venice.logText
                        }
                    }
                }
            }

            // ═══════════════════════════════════════ ACTION BAR
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 1
                color: Qt.rgba(window.accentRgb.r, window.accentRgb.g,
                               window.accentRgb.b, 0.15)
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.preferredHeight: 48
                spacing: 14

                Text {
                    Layout.fillWidth: !venice.isPacking
                    Layout.alignment: Qt.AlignVCenter
                    elide: Text.ElideRight
                    color: Theme.text_secondary
                    font.family: Theme.fontUi
                    font.pixelSize: Theme.caption
                    text: venice.isPacking
                          ? ("Packing " + Math.min(venice.doneCount + 1, venice.totalJobs)
                             + " of " + venice.totalJobs + "…")
                          : (fileList.count === 0
                             ? "No files queued"
                             : fileList.count + (fileList.count === 1 ? " file ready" : " files ready"))
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter
                    implicitHeight: 6
                    radius: 3
                    color: Theme.bg_elevated
                    visible: venice.isPacking

                    Rectangle {
                        width: parent.width * venice.packProgress
                        height: parent.height; radius: 3
                        color: Theme.accent
                        Behavior on width { NumberAnimation { duration: 250; easing.type: Easing.OutCubic } }
                    }
                }

                VeniceButton {
                    Layout.preferredWidth: 140
                    Layout.preferredHeight: 38
                    Layout.alignment: Qt.AlignVCenter
                    accent: !venice.isPacking
                    glyph: venice.isPacking ? "" : "▶"
                    text: venice.isPacking ? "Cancel" : "Pack"
                    enabled: venice.isPacking || fileList.count > 0
                    onClicked: venice.isPacking ? venice.cancelPacking() : venice.packAll()

                    font.pixelSize: 14
                    font.weight: Font.DemiBold
                }
            }
        }
    }
}
