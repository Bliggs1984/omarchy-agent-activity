import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

// Agent Activity: which AI agents are running, what each one has started,
// and what it costs. All the work happens in scan.py; this file only draws.
Panel {
  id: root
  moduleName: "io.github.bliggs1984.agent-activity"
  ipcTarget: "agent-activity"
  manageIpc: true

  readonly property string pluginDir: decodeURIComponent(String(Qt.resolvedUrl(".")).replace(/^file:\/\//, "")).replace(/\/$/, "")
  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  property var snapshot: ({ agents: [], cpu: 0, mem: 0, busy: 0 })
  property double nowSec: Date.now() / 1000
  readonly property var agents: snapshot.agents || []
  readonly property int busy: Number(snapshot.busy) || 0
  readonly property bool showCount: setting("showCount", true) !== false

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: {
    nowSec = Date.now() / 1000
    if (scanner.running) scanner.write(opened ? "open\n" : "closed\n")
    if (opened) Qt.callLater(function() { if (panel.loadedContent) panel.loadedContent.forceActiveFocus() })
  }

  // ---- Scanner -------------------------------------------------------------
  Process {
    id: scanner
    command: ["python3", root.pluginDir + "/scan.py"]
    running: root.pluginDir !== ""
    stdinEnabled: true
    stdout: SplitParser {
      onRead: function(line) {
        var v = Model.parse(line)
        if (v) root.snapshot = v
      }
    }
    onStarted: if (root.opened) write("open\n")
    onExited: restartTimer.restart()
  }

  // If the scanner ever dies, try again after a pause rather than in a loop.
  Timer {
    id: restartTimer
    interval: 10000
    onTriggered: if (!scanner.running) scanner.running = true
  }

  // Ages tick once a second, only while the panel is open.
  Timer {
    interval: 1000
    repeat: true
    running: root.opened
    onTriggered: root.nowSec = Date.now() / 1000
  }

  // ---- Bar button ----------------------------------------------------------
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "󰘚"
    labelText: root.showCount && root.busy > 0 ? String(root.busy) : ""
    foreground: root.agents.length > 0 ? root.barForeground : Qt.darker(root.barForeground, 1.55)
    onPressed: function(buttonCode) { root.toggle() }
  }

  // ---- Panel ---------------------------------------------------------------
  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(Style.space(420))
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(620))

    content: PanelKeyCatcher {
      implicitHeight: column.implicitHeight
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Flickable {
        id: flick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: flick.width
          spacing: Style.space(12)

          PanelHero {
            width: parent.width
            title: "Agent activity"
            meta: root.agents.length === 0
              ? "No agents running"
              : root.agents.length + (root.agents.length === 1 ? " agent · " : " agents · ")
                + root.busy + (root.busy === 1 ? " task · " : " tasks · ")
                + Model.pct(root.snapshot.cpu) + " CPU · " + Model.mem(root.snapshot.mem)
            foreground: root.foreground
            fontFamily: root.fontFamily
            iconComponent: Component {
              Text {
                textFormat: Text.PlainText
                text: button.text
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.display
              }
            }
          }

          Text {
            visible: root.agents.length === 0
            width: parent.width
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            text: "Start Claude Code, Codex or another agent and its commands will show up here."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
          }

          Repeater {
            model: root.agents
            AgentCard {
              required property var modelData
              width: column.width
              agent: modelData
            }
          }
        }
      }
    }
  }

  // ---- Pieces --------------------------------------------------------------
  component AgentCard: Column {
    id: card
    property var agent: ({})
    readonly property color tint: Model.agentColor(agent.name, root.foreground)
    // Brighter the harder the agent works: the Windows widget's glow, minus the GPU.
    readonly property real heat: Math.min(1, (Number(agent.cpu) || 0) / 25)
    spacing: Style.space(4)

    PanelSeparator { foreground: root.foreground }

    RowLayout {
      width: parent.width
      spacing: Style.space(8)

      Item {
        Layout.preferredWidth: Style.space(10)
        Layout.preferredHeight: Style.space(10)
        Layout.alignment: Qt.AlignVCenter
        Rectangle {   // glow
          anchors.centerIn: parent
          width: parent.width * (1.4 + card.heat)
          height: width
          radius: width / 2
          color: card.tint
          opacity: 0.12 + 0.3 * card.heat
        }
        Rectangle {
          anchors.fill: parent
          radius: width / 2
          color: card.tint
          opacity: 0.55 + 0.45 * card.heat
        }
      }

      PlainText {
        text: card.agent.name || ""
        color: root.foreground
        font.pixelSize: Style.font.body
        font.bold: true
      }

      PlainText {
        Layout.fillWidth: true
        text: card.agent.label || ""
        color: root.foreground
        opacity: 0.8
        font.pixelSize: Style.font.body
        elide: Text.ElideRight
      }

      Gauges { cpu: card.agent.cpu; memMb: card.agent.mem; color: card.tint }
    }

    PlainText {
      x: Style.space(18)
      width: parent.width - x
      text: (card.agent.host || "") + " · running " + Model.age(card.agent.started, root.nowSec)
        + ((card.agent.mcp || []).length > 0 ? " · MCP: " + card.agent.mcp.join(", ") : "")
      color: root.dim
      font.pixelSize: Style.font.caption
      elide: Text.ElideRight
    }

    Repeater {
      model: card.agent.tasks || []
      TaskRow {
        required property var modelData
        x: Style.space(18)
        width: card.width - x
        task: modelData
        tint: card.tint
      }
    }

    PlainText {
      visible: (card.agent.tasks || []).length === 0
      x: Style.space(18)
      text: "Idle"
      color: root.dim
      font.pixelSize: Style.font.bodySmall
    }

    PlainText {
      visible: (Number(card.agent.hidden) || 0) > 0
      x: Style.space(18)
      text: "+" + card.agent.hidden + " more"
      color: root.dim
      font.pixelSize: Style.font.caption
    }
  }

  component TaskRow: RowLayout {
    id: row
    property var task: ({})
    property color tint: root.foreground
    readonly property bool done: task.done === true
    spacing: Style.space(8)
    opacity: done ? 0.5 : 1

    PlainText {
      text: row.done ? "✓" : "›"
      color: row.done ? root.dim : row.tint
      font.pixelSize: Style.font.bodySmall
    }

    PlainText {
      Layout.fillWidth: true
      text: (row.task.text || "") + (row.task.proc ? " · " + row.task.proc : "")
      color: root.foreground
      font.pixelSize: Style.font.bodySmall
      elide: Text.ElideRight
    }

    PlainText {
      text: row.done ? "done" : Model.age(row.task.started, root.nowSec)
      color: root.dim
      font.pixelSize: Style.font.caption
    }

    Gauges { visible: !row.done; cpu: row.task.cpu; memMb: row.task.mem; color: row.tint; small: true }
  }

  // A chip that fills from the bottom for CPU, and a memory stick whose four
  // chips light up for RAM, each with its number.
  component Gauges: Row {
    id: g
    property real cpu: 0
    property real memMb: 0
    property color color: root.foreground
    property bool small: false
    readonly property int cpuSteps: Model.cpuLevel(cpu)
    readonly property int memSteps: Model.memLevel(memMb)
    readonly property real unit: Style.space(small ? 9 : 11)
    spacing: Style.space(4)

    Item {
      width: g.unit; height: g.unit
      anchors.verticalCenter: parent.verticalCenter
      Rectangle {
        anchors.fill: parent
        color: "transparent"
        border.width: Math.max(1, Style.space(1))
        border.color: root.dim
        radius: Style.space(2)
      }
      Rectangle {
        anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom
        anchors.margins: Style.space(2)
        height: (parent.height - Style.space(4)) * g.cpuSteps / 4
        color: g.color
        radius: Style.space(1)
      }
    }
    PlainText {
      width: Style.space(g.small ? 30 : 34)
      text: Model.pct(g.cpu)
      color: root.foreground
      font.pixelSize: Style.font.caption
      anchors.verticalCenter: parent.verticalCenter
    }

    Row {
      spacing: Style.space(1)
      anchors.verticalCenter: parent.verticalCenter
      Repeater {
        model: 4
        Rectangle {
          required property int index
          width: Style.space(g.small ? 3 : 4)
          height: g.unit * 0.8
          radius: Style.space(1)
          color: index < g.memSteps ? g.color : "transparent"
          border.width: Math.max(1, Style.space(1))
          border.color: index < g.memSteps ? g.color : root.dim
        }
      }
    }
    PlainText {
      width: Style.space(g.small ? 40 : 44)
      text: Model.mem(g.memMb)
      color: root.foreground
      font.pixelSize: Style.font.caption
      horizontalAlignment: Text.AlignRight
      anchors.verticalCenter: parent.verticalCenter
    }
  }

  component PlainText: Text {
    textFormat: Text.PlainText
    font.family: root.fontFamily
  }
}
