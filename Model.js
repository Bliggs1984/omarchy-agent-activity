.pragma library

// Pure helpers for Panel.qml, kept here so they are easy to test.

function parse(line) {
  try {
    var v = JSON.parse(String(line))
    if (!v || !Array.isArray(v.agents)) return null
    return v
  } catch (e) {
    return null
  }
}

function pct(v) {
  v = Number(v) || 0
  if (v <= 0) return "0%"
  if (v < 10) return v.toFixed(1) + "%"
  return Math.round(v) + "%"
}

function mem(mb) {
  mb = Number(mb) || 0
  if (mb >= 1024) return (mb / 1024).toFixed(mb >= 10240 ? 0 : 1) + " GB"
  return Math.round(mb) + " MB"
}

function age(startedSec, nowSec) {
  var s = Math.max(0, Math.round(nowSec - startedSec))
  if (s < 60) return s + "s"
  var m = Math.floor(s / 60)
  if (m < 60) return m + "m"
  var h = Math.floor(m / 60)
  if (h < 24) return h + "h " + (m % 60) + "m"
  return Math.floor(h / 24) + "d " + (h % 24) + "h"
}

// Four steps, matching the Windows widget. CPU is % of the whole machine.
function cpuLevel(v) {
  v = Number(v) || 0
  return v >= 40 ? 4 : v >= 15 ? 3 : v >= 4 ? 2 : v >= 0.5 ? 1 : 0
}

function memLevel(mb) {
  mb = Number(mb) || 0
  return mb >= 8192 ? 4 : mb >= 2048 ? 3 : mb >= 500 ? 2 : mb >= 100 ? 1 : 0
}

var COLORS = {
  "Claude Code": "#d97757",
  "Codex": "#10a37f",
  "Gemini CLI": "#4f8cf6",
  "OpenCode": "#e0af68",
  "Kimi Code": "#9d7cd8",
  "Copilot CLI": "#6e7cf0",
  "Aider": "#4fd6be",
  "Qwen Code": "#7c6af7"
}

function agentColor(name, fallback) {
  return COLORS[name] || fallback
}
