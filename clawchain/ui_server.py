from __future__ import annotations

from base64 import b64decode, b64encode
from contextlib import redirect_stdout
from datetime import datetime
import sqlite3
import time
from io import StringIO
import json
import os
import re
from hashlib import sha256
from os import urandom
from pathlib import Path
import shlex
import shutil
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import agent_proxy_cli
from .agent_proxy import AgentProxyPaths, TransparentAgentProxy
from . import codex_rollout
from .host_monitor import aggregate_running_agents, detect_running_agents, list_known_agents
from .platform_support import (
    codex_command_matches,
    codex_env_path,
    codex_launcher_path,
    is_windows,
    monitored_handoff_path,
    script_command_display,
    script_command_parts,
)
from .risk_catalog import render_risk_filter_options, risk_label, risk_restorable, risk_class
from .runtime.recovery import RecoveryCatalogStore
from .runtime import recovery as recovery_runtime
from .system import ClawChainPaths

UI_DEFAULT_ACCOUNT_ID = "local-operator"
UI_DEFAULT_PASSWORD = "local-operator"
UI_BUILD_LABEL = "ClawChain UI Build 2026-03-22A"


def render_index_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ClawChain Console</title>
  <style>
    :root {
      --bg: #eef3fb;
      --panel: rgba(255,255,255,0.62);
      --panel-strong: rgba(255,255,255,0.8);
      --line: rgba(109,130,166,0.18);
      --line-strong: rgba(109,130,166,0.3);
      --ink: #0f1728;
      --muted: #5e6a80;
      --accent: #0a84ff;
      --accent-2: #19a974;
      --warn: #ff9f0a;
      --danger: #ff5f57;
      --glow: rgba(10,132,255,0.16);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "SF Pro Display", "SF Pro Text", "Helvetica Neue", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 15% 18%, rgba(89,168,255,0.22) 0%, transparent 26%),
        radial-gradient(circle at 82% 12%, rgba(25,169,116,0.14) 0%, transparent 24%),
        radial-gradient(circle at 55% 90%, rgba(255,159,10,0.12) 0%, transparent 26%),
        linear-gradient(180deg, #f6f9ff 0%, #edf2fb 42%, #e8eef9 100%);
      min-height: 100vh;
    }
    .shell {
      max-width: 1440px;
      margin: 0 auto;
      padding: 28px 20px 64px;
    }
    .workspace {
      display: grid;
      grid-template-columns: 220px minmax(0, 1fr);
      gap: 20px;
      align-items: start;
    }
    .nav-rail {
      position: sticky;
      top: 22px;
      padding: 22px;
    }
    .content-stack {
      display: grid;
      gap: 18px;
    }
    .nav-button {
      width: 100%;
      justify-content: flex-start;
      text-align: left;
    }
    .nav-button.active {
      background: linear-gradient(180deg, #172338, #101827);
      color: white;
      border-color: rgba(15,23,40,0.9);
    }
    .view-hidden { display: none !important; }
    .hero {
      display: grid;
      grid-template-columns: 1.5fr 1fr;
      gap: 20px;
      margin-bottom: 22px;
    }
    .card {
      position: relative;
      background: linear-gradient(180deg, var(--panel-strong), var(--panel));
      border: 1px solid var(--line);
      border-radius: 24px;
      padding: 20px;
      box-shadow:
        0 18px 48px rgba(37, 57, 88, 0.12),
        inset 0 1px 0 rgba(255,255,255,0.82);
      backdrop-filter: blur(18px) saturate(150%);
      -webkit-backdrop-filter: blur(18px) saturate(150%);
      opacity: 0;
      transform: translateY(16px);
      animation: riseIn 420ms ease forwards;
      overflow: hidden;
    }
    .card::before {
      content: "";
      position: absolute;
      inset: 0;
      background:
        linear-gradient(135deg, rgba(255,255,255,0.26), transparent 42%),
        radial-gradient(circle at 100% 0%, rgba(10,132,255,0.08), transparent 28%);
      pointer-events: none;
    }
    .card:nth-of-type(2) { animation-delay: 60ms; }
    .card:nth-of-type(3) { animation-delay: 120ms; }
    .card:nth-of-type(4) { animation-delay: 180ms; }
    h1,h2,h3 { margin: 0 0 10px; }
    h1 {
      font-size: 38px;
      line-height: 1.02;
      letter-spacing: -0.04em;
      font-weight: 700;
    }
    h2 {
      font-size: 18px;
      letter-spacing: -0.02em;
      font-weight: 600;
    }
    .sub { color: var(--muted); line-height: 1.6; max-width: 64ch; }
    .toolbar, .row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }
    .toolbar { margin-top: 16px; }
    .stack { display: grid; gap: 14px; }
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin-top: 8px;
    }
    .metric {
      padding: 14px;
      border-radius: 18px;
      border: 1px solid rgba(109,130,166,0.14);
      background: rgba(255,255,255,0.54);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.72);
    }
    .metric-label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 6px;
    }
    .metric-value {
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.04em;
    }
    .hero-glow {
      position: relative;
      overflow: hidden;
    }
    .hero-glow::after {
      content: "";
      position: absolute;
      width: 280px;
      height: 280px;
      right: -80px;
      top: -120px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(10,132,255,0.18) 0%, rgba(10,132,255,0.0) 72%);
      pointer-events: none;
    }
    input, select, button {
      border-radius: 14px;
      border: 1px solid var(--line);
      padding: 10px 12px;
      font: inherit;
      background: rgba(255,255,255,0.82);
      color: var(--ink);
      transition: transform 160ms ease, box-shadow 160ms ease, border-color 160ms ease, background 160ms ease;
    }
    input, select { min-width: 150px; }
    input:focus, select:focus {
      outline: none;
      border-color: rgba(10,132,255,0.45);
      box-shadow: 0 0 0 4px var(--glow);
      background: rgba(255,255,255,0.94);
    }
    button {
      cursor: pointer;
      background: linear-gradient(180deg, #172338, #101827);
      color: white;
      border-color: rgba(15,23,40,0.9);
      box-shadow: 0 10px 24px rgba(15,23,40,0.16);
    }
    button.secondary {
      background: rgba(255,255,255,0.56);
      color: var(--ink);
      border-color: var(--line-strong);
      box-shadow: none;
    }
    button.warn {
      background: linear-gradient(180deg, #ffb340, #ff9500);
      border-color: rgba(255,149,0,0.9);
      color: #2a1900;
    }
    button.good {
      background: linear-gradient(180deg, #2ac897, #16a36e);
      border-color: rgba(25,169,116,0.9);
    }
    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 14px 28px rgba(15,23,40,0.18);
    }
    button:active {
      transform: translateY(0);
    }
    button:disabled {
      cursor: not-allowed;
      opacity: 0.45;
      transform: none;
      box-shadow: none;
    }
    .history-item.restored {
      opacity: 0.74;
      border-color: rgba(25,169,116,0.24);
      background: linear-gradient(180deg, rgba(248,252,249,0.96), rgba(238,247,242,0.88));
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0,1fr));
      gap: 16px;
      margin-top: 18px;
    }
    .session-card-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 14px;
      margin-top: 12px;
    }
    .session-card {
      text-align: left;
      width: 100%;
      padding: 16px;
      border-radius: 20px;
      border: 1px solid rgba(109,130,166,0.16);
      background: rgba(255,255,255,0.72);
      color: var(--ink);
      box-shadow:
        inset 0 1px 0 rgba(255,255,255,0.78),
        0 10px 24px rgba(37,57,88,0.08);
    }
    .session-card.active {
      border-color: rgba(10,132,255,0.34);
      box-shadow:
        inset 0 1px 0 rgba(255,255,255,0.86),
        0 0 0 4px rgba(10,132,255,0.10),
        0 16px 28px rgba(10,132,255,0.10);
    }
    .session-card.flash-good {
      animation: monitoredPulse 900ms ease;
    }
    .session-card.new {
      border-color: rgba(255,159,10,0.28);
      box-shadow:
        inset 0 1px 0 rgba(255,255,255,0.86),
        0 0 0 4px rgba(255,159,10,0.08),
        0 16px 28px rgba(255,159,10,0.10);
    }
    .alert-stack {
      display: grid;
      gap: 10px;
      margin-top: 12px;
    }
    .alert-card {
      border-radius: 18px;
      border: 1px solid rgba(255,159,10,0.18);
      background: linear-gradient(180deg, rgba(255,255,255,0.92), rgba(255,248,236,0.88));
      padding: 14px;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.8);
    }
    .detail-grid {
      display: grid;
      grid-template-columns: 1.2fr 1fr;
      gap: 16px;
      margin-top: 12px;
    }
    .detail-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(109,130,166,0.14);
    }
    .detail-pane {
      border-radius: 18px;
      border: 1px solid rgba(109,130,166,0.14);
      background: rgba(255,255,255,0.74);
      padding: 14px;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.78);
    }
    .list { display: grid; gap: 10px; margin-top: 12px; }
    .timeline { display: grid; gap: 12px; margin-top: 12px; }
    .timeline-item {
      display: grid;
      grid-template-columns: 18px 1fr;
      gap: 12px;
      align-items: start;
    }
    .timeline-rail {
      position: relative;
      min-height: 100%;
    }
    .timeline-rail::before {
      content: "";
      position: absolute;
      left: 8px;
      top: 0;
      bottom: -16px;
      width: 2px;
      background: linear-gradient(180deg, rgba(10,132,255,0.34), rgba(109,130,166,0.06));
    }
    .timeline-dot {
      position: relative;
      width: 18px;
      height: 18px;
      border-radius: 999px;
      border: 2px solid rgba(10,132,255,0.28);
      background: rgba(255,255,255,0.86);
      box-shadow: 0 0 0 6px rgba(10,132,255,0.08);
      z-index: 1;
    }
    .timeline-dot.warn {
      border-color: rgba(255,159,10,0.34);
      box-shadow: 0 0 0 6px rgba(255,159,10,0.10);
    }
    .timeline-card {
      border-radius: 18px;
      border: 1px solid rgba(109,130,166,0.14);
      background: rgba(255,255,255,0.76);
      padding: 14px;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.72);
    }
    .item {
      border: 1px solid rgba(109,130,166,0.14);
      border-radius: 18px;
      padding: 14px;
      background: rgba(255,255,255,0.72);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.7);
      opacity: 0;
      transform: translateY(10px) scale(0.995);
      animation: itemIn 300ms ease forwards;
    }
    .item.live {
      border-color: rgba(10,132,255,0.24);
      box-shadow:
        0 0 0 1px rgba(10,132,255,0.08),
        0 12px 24px rgba(10,132,255,0.08);
    }
    .meta { color: var(--muted); font-size: 13px; line-height: 1.45; }
    .pill {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      background: rgba(108,129,164,0.12);
      color: #304056;
      border: 1px solid rgba(108,129,164,0.14);
    }
    .pill.good { background: rgba(25,169,116,0.12); color: #136746; border-color: rgba(25,169,116,0.14); }
    .pill.warn { background: rgba(255,159,10,0.14); color: #8a5800; border-color: rgba(255,159,10,0.16); }
    .mono { font-family: "SF Mono", "IBM Plex Mono", "SFMono-Regular", monospace; }
    .section-head {
      display: flex; justify-content: space-between; align-items: center;
      border-bottom: 1px solid rgba(109,130,166,0.14); padding-bottom: 10px; margin-bottom: 12px;
    }
    .wide { margin-top: 20px; }
    .segmented {
      display: inline-flex;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 3px;
      gap: 4px;
      background: rgba(255,255,255,0.72);
    }
    .toggle {
      border: 0;
      background: transparent;
      color: var(--muted);
      padding: 7px 12px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 600;
      box-shadow: none;
    }
    .toggle.active {
      background: linear-gradient(180deg, #172338, #101827);
      color: #fffaf2;
    }
    .statusbar {
      position: sticky; bottom: 16px; margin-top: 20px;
      border: 1px solid rgba(255,255,255,0.1); border-radius: 18px;
      padding: 12px 14px; background: rgba(16,24,39,0.88); color: #f7fbff;
      box-shadow: 0 12px 36px rgba(15,23,40,0.18);
    }
    .toast-stack {
      position: fixed;
      top: 18px;
      right: 18px;
      display: grid;
      gap: 10px;
      z-index: 60;
      width: min(360px, calc(100vw - 24px));
    }
    .toast {
      border-radius: 18px;
      padding: 14px 16px;
      border: 1px solid rgba(255,255,255,0.18);
      background: rgba(16,24,39,0.9);
      color: #f8fbff;
      box-shadow: 0 18px 40px rgba(15,23,40,0.22);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      animation: toastIn 220ms ease forwards;
    }
    .toast.good { background: rgba(18,95,69,0.92); }
    .toast.warn { background: rgba(120,74,0,0.92); }
    .modal-backdrop {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(15,23,40,0.38);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      z-index: 40;
      padding: 20px;
    }
    .modal-backdrop.open {
      display: flex;
    }
    .modal {
      width: min(520px, 100%);
      border-radius: 24px;
      border: 1px solid rgba(255,255,255,0.2);
      background: linear-gradient(180deg, rgba(255,255,255,0.95), rgba(239,245,255,0.88));
      box-shadow: 0 28px 64px rgba(15,23,40,0.22);
      padding: 22px;
      animation: riseIn 180ms ease forwards;
    }
    .statusbar.flash {
      animation: statusFlash 680ms ease;
    }
    .section-quiet {
      position: relative;
      overflow: hidden;
    }
    .section-quiet::after {
      content: "";
      position: absolute;
      inset: 0;
      background: linear-gradient(110deg, transparent 0%, rgba(255,255,255,0.28) 45%, transparent 100%);
      transform: translateX(-120%);
      animation: panelSweep 1.1s ease;
      pointer-events: none;
    }
    .empty { color: var(--muted); font-style: italic; }
    .history-item.warn {
      border-left: 5px solid var(--warn);
    }
    .history-item.good {
      border-left: 5px solid var(--accent-2);
    }
    .result-panel {
      border: 1px solid rgba(109,130,166,0.16);
      border-radius: 18px;
      padding: 14px;
      background: linear-gradient(180deg, rgba(255,255,255,0.92), rgba(240,246,255,0.84));
      display: grid;
      gap: 6px;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.8);
    }
    @keyframes riseIn {
      from { opacity: 0; transform: translateY(16px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes itemIn {
      from { opacity: 0; transform: translateY(10px) scale(0.995); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    @keyframes statusFlash {
      0% { box-shadow: 0 0 0 0 rgba(255,250,242,0.0); }
      25% { box-shadow: 0 0 0 6px rgba(255,250,242,0.18); }
      100% { box-shadow: 0 0 0 0 rgba(255,250,242,0.0); }
    }
    @keyframes panelSweep {
      from { transform: translateX(-120%); }
      to { transform: translateX(120%); }
    }
    @keyframes toastIn {
      from { opacity: 0; transform: translateY(-8px) scale(0.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    @keyframes monitoredPulse {
      0% { box-shadow: 0 0 0 0 rgba(25,169,116,0); }
      20% { box-shadow: 0 0 0 8px rgba(25,169,116,0.14); }
      100% { box-shadow: 0 0 0 0 rgba(25,169,116,0); }
    }
    @media (max-width: 980px) {
      .hero, .grid { grid-template-columns: 1fr; }
      .metric-grid { grid-template-columns: 1fr; }
      .workspace, .hero, .detail-grid, .session-card-grid { grid-template-columns: 1fr; }
      .nav-rail { position: static; }
    }
  
    .hero-shell { padding: 44px 28px; position: relative; overflow: hidden; }
    .hero-shell::before { content: ''; position: absolute; inset: auto 10% -40% 10%; height: 180px; background: radial-gradient(circle, rgba(54,124,255,0.22), rgba(54,124,255,0)); pointer-events: none; }
    .hero-kicker { font-size: 11px; letter-spacing: 0.24em; text-transform: uppercase; color: rgba(42,92,185,0.72); margin-bottom: 10px; }
    .hero-title { font-size: 82px; line-height: 0.96; letter-spacing: -0.1em; margin: 0 0 14px; font-weight: 780; background: linear-gradient(180deg, #09111f 0%, #11336a 44%, #2f7cff 100%); -webkit-background-clip: text; color: transparent; }
    .hero-copy { margin: 0 auto 24px; max-width: 820px; font-size: 16px; color: rgba(39,58,92,0.84); }
    .hero-metrics { max-width: 960px; margin: 0 auto 20px; }
    .hero-toolbar { position: relative; z-index: 1; }

    .modal-shell.hidden { display:none; }
    .modal-shell { position:fixed; inset:0; z-index:60; }
    .modal-backdrop { position:absolute; inset:0; background:rgba(6,10,18,0.55); backdrop-filter: blur(10px); }
    .modal-card { position:relative; max-width:860px; margin:6vh auto; background:rgba(250,252,255,0.92); border:1px solid rgba(140,160,190,0.24); border-radius:28px; padding:24px; box-shadow:0 24px 80px rgba(20,40,90,0.20); }

</style>
</head>
<body>
  <div class="shell">
    <div class="hero">
      <section class="card hero-glow hero-shell" style="grid-column: 1 / -1; text-align:center;">
        <div class="hero-kicker">Adaptive Safety Runtime</div>
        <h1 class="hero-title">ClawChain</h1>
        <div class="sub hero-copy">A high-trust control plane for local agent runtimes. ClawChain tracks live sessions, captures dangerous operations, preserves recovery evidence through git and snapshot sources, and keeps verifiable proof anchored for later audit and restore.</div>
        <div class="metric-grid hero-metrics">
          <div class="metric"><div class="metric-label">Monitored</div><div class="metric-value" id="monitoredCount">0</div></div>
          <div class="metric"><div class="metric-label">Running</div><div class="metric-value" id="runningCount">0</div></div>
          <div class="metric"><div class="metric-label">Needs Attention</div><div class="metric-value" id="unmanagedCount">0</div></div>
        </div>
        <div class="toolbar hero-toolbar" style="justify-content:center;">
          <input id="rootDir" placeholder="root dir (optional)" style="display:none;">
          <button class="secondary" onclick="refreshAll()">Refresh</button>
        </div>
      </section>
    </div>

    <div class="workspace">
      <aside class="card nav-rail">
        <h2>Navigator</h2>
        <div class="stack">
          <button class="secondary nav-button active" id="nav-dashboard" onclick="setView('dashboard')">Dashboard</button>
          <button class="secondary nav-button" id="nav-history" onclick="setView('history')">Dangerous History</button>
          <button class="secondary nav-button" id="nav-detail" onclick="setView('detail')">Session Detail</button>
        </div>
        <div class="meta" style="margin-top:14px; line-height:1.6;">Browse live sessions on the dashboard, inspect one session in detail, and use the history view for cross-session recovery lookup.</div>
      </aside>
      <div class="content-stack">
        <section class="card wide" id="sessionExplorerSection" data-view="dashboard">
          <div class="section-head">
            <h2>Session Explorer</h2>
            <span class="mono" id="sessionExplorerLabel">0 sessions</span>
          </div>
          <div class="session-card-grid" id="sessionCardGrid"></div>
        </section>

        <section class="card wide" id="liveActivitySection" data-view="dashboard">
          <div class="section-head">
            <h2>Live Activity</h2>
            <div class="row">
              <button class="secondary" onclick="loadActivity()">Refresh Activity</button>
            </div>
          </div>
          <div class="timeline" id="activityList"></div>
        </section>

        <section class="card wide view-hidden" id="sessionDetailSection" data-view="detail">
          <div class="section-head">
            <h2>Session Detail</h2>
            <span class="mono" id="sessionDetailLabel">none selected</span>
          </div>
          <div class="detail-head" style="display:block;">
            <div id="sessionDetailMeta">Select a session card to inspect its live activity and dangerous operations.</div>
            <div class="row" id="sessionDetailAction" style="margin-top:14px;"></div>
          </div>
          <div class="detail-grid">
            <div class="detail-pane">
              <h3>Dangerous Operations</h3>
              <div class="list" id="sessionHistoryList"></div>
            </div>
            <div class="detail-pane">
              <h3>Live Activity</h3>
              <div class="timeline" id="sessionActivityList"></div>
            </div>
          </div>
        </section>

        <section class="card wide view-hidden" id="historySection" data-view="history">
          <div class="section-head">
            <h2>Dangerous Operation History</h2>
            <div class="row">
              <input id="historySession" placeholder="session name or id">
<select id="historyRisk">__RISK_OPTIONS__</select>
              <input id="historyLimit" placeholder="limit" value="20">
              <button class="secondary" onclick="setView('history'); loadHistory()">Query</button>
            </div>
          </div>
          <div class="list" id="historyList"></div>
        </section>

        <section class="card wide view-hidden" id="restoreSection" data-view="history">
          <div class="section-head">
            <h2>Restore Result</h2>
            <span class="mono" id="restoreResultLabel">waiting</span>
          </div>
          <div class="result-panel" id="restoreResult">
            <div class="empty">No restore has been triggered from the UI yet.</div>
          </div>
        </section>
      </div>
    </div>


    <div class="modal-shell hidden" id="handoffModal">
      <div class="modal-backdrop" onclick="closeHandoffModal()"></div>
      <div class="modal-card">
        <div class="section-head">
          <h2>Enter Controlled Session</h2>
          <button class="secondary" onclick="closeHandoffModal()">Close</button>
        </div>
        <div class="sub" id="handoffMeta">Prepare a safe monitored handoff script. It will create or enter a controlled session without closing your current terminal.</div>
        <div class="row" style="margin:12px 0;">
          <button class="secondary" onclick="copyHandoffCommand()">Copy Command</button>
          <button class="secondary" onclick="copyHandoffScript()">Copy Script</button>
        </div>
        <div class="meta" id="handoffPath"></div>
        <textarea id="handoffScript" style="width:100%; min-height:260px; margin-top:12px;"></textarea>
      </div>
    </div>

    <div class="statusbar mono" id="statusBar">ClawChain UI ready.</div>
  </div>
  <div class="toast-stack" id="toastStack"></div>

  <script>
    const UI_ACCOUNT_ID = 'local-operator';
    const UI_PASSWORD = 'local-operator';
    let currentSessionFilter = 'all';
    let currentView = 'dashboard';
    let selectedSessionRef = '';
    let cachedSessionCards = [];
    let flashSessionRef = '';
    let refreshInFlight = false;
    let detailEditSessionRef = '';
        async function api(path, options={}) {
      const res = await fetch(path, {
        headers: {"Content-Type": "application/json"},
        ...options
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      return data;
    }

    function setStatus(text) {
      const bar = document.getElementById("statusBar");
      bar.textContent = text;
      bar.classList.remove('flash');
      void bar.offsetWidth;
      bar.classList.add('flash');
    }

    function pushToast(text, tone='good') {
      const stack = document.getElementById('toastStack');
      const node = document.createElement('div');
      node.className = `toast ${tone}`;
      node.innerHTML = `<strong>${escapeHtml(text)}</strong>`;
      stack.prepend(node);
      window.setTimeout(() => {
        node.style.opacity = '0';
        node.style.transform = 'translateY(-6px) scale(0.98)';
      }, 3200);
      window.setTimeout(() => node.remove(), 3600);
    }


    let handoffCommand = '';
    let handoffScriptBody = '';

    function openHandoffModal(payload) {
      handoffCommand = String(payload.handoff_command || '');
      handoffScriptBody = String(payload.script_body || '');
      document.getElementById('handoffMeta').textContent = payload.message || 'Prepared monitored handoff.';
      document.getElementById('handoffPath').textContent = payload.script_path ? `script: ${payload.script_path}` : '';
      document.getElementById('handoffScript').value = handoffScriptBody || handoffCommand || '';
      document.getElementById('handoffModal').classList.remove('hidden');
    }

    function closeHandoffModal() {
      document.getElementById('handoffModal').classList.add('hidden');
    }

    async function copyHandoffCommand() {
      if (!handoffCommand) return;
      await navigator.clipboard.writeText(handoffCommand);
      pushToast('Handoff command copied.', 'good');
    }

    async function copyHandoffScript() {
      const value = handoffScriptBody || document.getElementById('handoffScript').value;
      if (!value) return;
      await navigator.clipboard.writeText(value);
      pushToast('Handoff script copied.', 'good');
    }

    function escapeHtml(text) {
      return String(text ?? "").replace(/[&<>"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[ch]));
    }

    function renderItems(containerId, items, render) {
      const root = document.getElementById(containerId);
      if (!items.length) {
        root.innerHTML = '<div class="empty">none</div>';
        return;
      }
      root.innerHTML = items.map(render).join("");
      root.classList.remove('section-quiet');
      void root.offsetWidth;
      root.classList.add('section-quiet');
    }

    function renderSessionCards(cards) {
      document.getElementById('sessionExplorerLabel').textContent = `${cards.length} sessions`;
      renderItems('sessionCardGrid', cards, item => `
        <div class="session-card ${selectedSessionRef === item.session_ref ? 'active' : ''} ${String(item.status || '') === 'unmanaged' ? 'new' : ''} ${flashSessionRef === item.session_ref ? 'flash-good' : ''} ${String(item.live_state || '') === 'offline' ? 'offline' : 'live'}">
          <button class="secondary" style="width:100%; text-align:left;" onclick="selectSessionCard('${escapeHtml(item.session_ref)}')">
            <div class="row" style="justify-content:space-between; align-items:center; margin-bottom:8px;">
              <strong>${escapeHtml(item.agent_id || '-')}</strong>
              <div class="row">
                <span class="pill ${String(item.live_state || '') === 'offline' ? 'warn' : 'good'}">${String(item.live_state || '') === 'offline' ? 'offline' : 'running'}</span>
                <span class="pill ${String(item.status || '') === 'monitored' ? 'good' : (String(item.status || '') === 'pending' ? 'warn' : '')}">${escapeHtml(item.status || 'unmanaged')}</span>
              </div>
            </div>
            <div class="meta">session</div>
            <div class="mono" style="font-size:12px; margin-bottom:8px;">${escapeHtml(item.session_id || '-')}</div>
            <div class="meta" style="margin-bottom:8px;">name</div>
            <div style="font-weight:600; margin-bottom:8px;">${escapeHtml(item.session_name || item.title || 'session')}</div>
            <div class="meta" style="margin-top:10px;">started ${escapeHtml(item.started_at || '-')}</div>
            <div class="meta">last update ${escapeHtml(item.last_seen_label || '-')}</div>
          </button>
        </div>
      `);
    }

    function updateToggleGroup(prefix, active) {
      document.querySelectorAll(`[id^="${prefix}"]`).forEach(node => node.classList.remove('active'));
      const selected = document.getElementById(`${prefix}${active}`);
      if (selected) selected.classList.add('active');
    }

    function setView(view) {
      currentView = view;
      try { window.localStorage.setItem('clawchain-current-view', view); } catch (_) {}
      document.querySelectorAll('[data-view]').forEach(node => {
        const nodeView = String(node.getAttribute('data-view') || '');
        node.classList.toggle('view-hidden', nodeView !== view);
      });
      document.querySelectorAll('.nav-button').forEach(node => node.classList.remove('active'));
      const active = document.getElementById(`nav-${view}`);
      if (active) active.classList.add('active');
    }

    function setSessionFilter(mode) {
      currentSessionFilter = mode;
      updateToggleGroup('sessionFilter-', mode);
      refreshAll();
    }

    async function loadAgents() {
      const select = document.getElementById('agent');
      if (!select) return;
      const data = await api('/api/agents');
      const current = select.value;
      select.innerHTML = '<option value="all">all agents</option>' + data.agents.map(a =>
        `<option value="${escapeHtml(a.agent_id)}">${escapeHtml(a.agent_id)}</option>`
      ).join("");
      select.value = current || 'all';
    }

    async function refreshAll(options={}) {
      if (refreshInFlight) return;
      refreshInFlight = true;
      try {
      const agent = document.getElementById('agent')?.value || 'all';
      const rootDir = document.getElementById('rootDir').value.trim();
      const params = new URLSearchParams({account: UI_ACCOUNT_ID, agent});
      if (rootDir) params.set('root_dir', rootDir);
      const data = await api(`/api/sessions?${params.toString()}`);
      cachedSessionCards = data.session_cards || [];
      renderSessionCards(cachedSessionCards);
      data.running.filter(item => {
        if (currentSessionFilter === 'all') return true;
        if (currentSessionFilter === 'monitored') return String(item.status || '').startsWith('monitored');
        if (currentSessionFilter === 'unmanaged') return String(item.status || '') === 'unmanaged';
        return true;
      });
      document.getElementById('monitoredCount').textContent = String(data.monitored.length);
      document.getElementById('runningCount').textContent = String(data.running.length);
      document.getElementById('unmanagedCount').textContent = String(data.unmanaged.length);
      if (!options.quiet) setStatus(`Refreshed sessions for ${UI_ACCOUNT_ID}.`);
      if (currentView === 'detail' && selectedSessionRef && detailEditSessionRef !== selectedSessionRef) {
        await loadSessionDetail(selectedSessionRef, {quiet: true});
      }
      } finally {
        refreshInFlight = false;
      }
    }

    async function joinMonitor(sessionFingerprint, sessionName) {
      const rootDir = document.getElementById('rootDir').value.trim();
      const result = await api('/api/join-monitor', {
        method: 'POST',
        body: JSON.stringify({
          account: UI_ACCOUNT_ID,
          password: UI_PASSWORD,
          session_fingerprint: sessionFingerprint,
          session_name: sessionName || 'session',
          root_dir: rootDir || null,
          no_start_service: false,
        })
      });
      const prepared = Array.isArray(result.prepared) ? result.prepared : [];
      const primary = prepared.length ? prepared[0] : null;
      if (primary && primary.session_id) {
        selectedSessionRef = String(primary.session_id);
      }
      pushToast(result.message || 'Monitor join complete.', result.ok ? 'good' : 'warn');
      if (result.ok) {
        pushToast('This session stays in its current terminal. New dangerous operations will now be captured in place.', 'good');
      }
      await refreshAll();
      await loadHistory();
      await loadActivity();
      if (selectedSessionRef) await loadSessionDetail(selectedSessionRef, {quiet: true});
    }

    function startSessionNameEdit(sessionRef) {
      detailEditSessionRef = sessionRef;
      const editor = document.getElementById('sessionNameEditor');
      const input = document.getElementById('sessionNameInput');
      if (!editor || !input) return;
      editor.classList.remove('hidden');
      input.focus();
      input.select();
    }

    function cancelSessionNameEdit() {
      detailEditSessionRef = "";
      const nameEditor = document.getElementById('sessionNameEditor');
      if (nameEditor) nameEditor.classList.add('hidden');
    }

    async function renameSession(sessionRef) {
      const rootDir = document.getElementById('rootDir').value.trim();
      const input = document.getElementById('sessionNameInput');
      const sessionName = (input?.value || "").trim();
      if (!sessionName) return;
      const result = await api('/api/rename-session', {
        method: "POST",
        body: JSON.stringify({
          account: UI_ACCOUNT_ID,
          session_ref: sessionRef,
          session_name: sessionName,
          root_dir: rootDir || null,
        })
      });
      pushToast(result.message || "Name updated.", "good");
      detailEditSessionRef = "";
      await refreshAll();
      await loadSessionDetail(sessionRef);
    }

    async function copyResumeCommand(commandText) {
      if (!commandText || commandText === '-') return;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(commandText);
          pushToast('Monitored resume command copied.', 'good');
          return;
        }
      } catch (err) {}
      const input = document.createElement('textarea');
      input.value = commandText;
      input.setAttribute('readonly', 'true');
      input.style.position = 'fixed';
      input.style.opacity = '0';
      document.body.appendChild(input);
      input.focus();
      input.select();
      let copied = false;
      try {
        copied = document.execCommand('copy');
      } catch (err) {
        copied = false;
      }
      document.body.removeChild(input);
      if (copied) {
        pushToast('Monitored resume command copied.', 'good');
        return;
      }
      window.prompt('Copy this monitored resume command:', commandText);
      pushToast('Copy the monitored resume command from the prompt.', 'warn');
    }

    async function archiveSession(sessionRef) {
      const rootDir = document.getElementById('rootDir').value.trim();
      const result = await api('/api/archive-session', {
        method: 'POST',
        body: JSON.stringify({
          account: UI_ACCOUNT_ID,
          session_ref: sessionRef,
          root_dir: rootDir || null,
        })
      });
      pushToast(result.message || 'Session archived.', 'good');
      if (selectedSessionRef === sessionRef) {
        selectedSessionRef = '';
        document.getElementById('sessionDetailLabel').textContent = 'none selected';
        document.getElementById('sessionDetailMeta').textContent = 'Select a session card to inspect its live activity and dangerous operations.';
        document.getElementById('sessionHistoryList').innerHTML = '<div class="empty">none</div>';
        document.getElementById('sessionActivityList').innerHTML = '<div class="empty">none</div>';
        document.getElementById('sessionDetailAction').innerHTML = '';
      }
      await refreshAll();
    }

    async function loadHistory(options={}) {
      const params = new URLSearchParams({account: UI_ACCOUNT_ID});
      const rootDir = document.getElementById('rootDir').value.trim();
      if (rootDir) params.set('root_dir', rootDir);
      const session = document.getElementById('historySession').value.trim();
      const risk = document.getElementById('historyRisk').value.trim();
      const limit = document.getElementById('historyLimit').value.trim();
      if (session) params.set('session', session);
      if (risk) params.set('risk', risk);
      if (limit) params.set('limit', limit);
      const data = await api(`/api/history?${params.toString()}`);
      renderItems('historyList', data.items, item => `
        <div class="item history-item ${String(item.risk_reason || '').includes('delete') ? 'warn' : 'good'} ${item.restored ? 'restored' : ''}">
          <div><strong>[${item.index}] ${escapeHtml(item.summary)}</strong></div>
          <div class="row" style="margin:8px 0 6px;">
            <span class="pill">${escapeHtml(item.session_name || item.session_id)}</span>
            <span class="pill warn">${escapeHtml(item.risk_label || item.risk_reason)}</span>
            <span class="pill">${escapeHtml(item.time_label)}</span>
            <span class="pill good">${escapeHtml(item.recovery_count)} recovery</span>
            <span class="pill ${item.risk_class === 'restorable' ? 'good' : 'warn'}">${escapeHtml(item.risk_class || 'audit-only')}</span><span class="pill ${item.restored ? 'good' : ''}">${escapeHtml(item.restored_label || 'available')}</span>
            ${String(item.source || '').includes('fallback') ? '<span class="pill warn">fallback log</span>' : ''}
          </div>
          <div class="meta">impact set ${escapeHtml(item.impact_set_id || '-')}</div>
        </div>
      `);
      if (!options.quiet) setStatus(`Loaded ${data.items.length} dangerous operations.`);
    }

    async function loadActivity(options={}) {
      const params = new URLSearchParams({account: UI_ACCOUNT_ID});
      const rootDir = document.getElementById('rootDir').value.trim();
      if (rootDir) params.set('root_dir', rootDir);
      const data = await api(`/api/activity?${params.toString()}`);
      renderItems('activityList', data.items, item => `
        <div class="timeline-item">
          <div class="timeline-rail">
            <div class="timeline-dot ${String(item.headline || '').includes('dangerous') ? 'warn' : ''}"></div>
          </div>
          <div class="timeline-card">
            <div><strong>${escapeHtml(item.headline)}</strong></div>
            <div class="meta">${escapeHtml(item.detail || '-')}</div>
          </div>
        </div>
      `);
      if (!options.quiet) setStatus(`Loaded ${data.items.length} live activity items.`);
    }

    function describeControlState(detail) {
      const state = String(detail?.control_state || detail?.status || 'unmanaged');
      const captureMode = String(detail?.capture_mode || '');
      if (captureMode === 'rollout-observed') return 'This session is being monitored in place. ClawChain is watching the live Codex rollout stream, so dangerous operations can be captured without opening another terminal.';
      if (state === 'pending') return 'Prepared for monitoring. Run the generated safe handoff command in a terminal; it will keep your shell open and print how to attach.';
      if (state === 'routed') return 'This session is routed through ClawChain. Use the attach command below to enter the controlled terminal.';
      if (state === 'attached') return 'This controlled session is live and currently attached through tmux.';
      return 'This session is currently outside the monitor. Prepare a monitored handoff to bring it into the controlled chain.';
    }

    async function loadSessionDetail(sessionRef, options={}) {
      if (!sessionRef) return;
      const rootDir = document.getElementById("rootDir").value.trim();
      const params = new URLSearchParams({account: UI_ACCOUNT_ID, session_ref: sessionRef});
      if (rootDir) params.set("root_dir", rootDir);
      const data = await api(`/api/session-detail?${params.toString()}`);
      document.getElementById("sessionDetailLabel").textContent = data.detail?.title || sessionRef;
      const rawName = String(data.detail?.session_name || data.detail?.title || "session");
      const rawSessionRef = String(data.detail?.session_ref || sessionRef);
      const rawSessionId = String(data.detail?.session_id || rawSessionRef);
      const detailName = escapeHtml(rawName);
      const detailSessionId = escapeHtml(rawSessionId);
      const detailStatus = String(data.detail?.status || "");
      const statusTone = detailStatus === "monitored" ? "good" : (detailStatus === "pending" ? "warn" : "");
      const jsSessionId = JSON.stringify(rawSessionId);
      const jsSessionRef = JSON.stringify(rawSessionRef);
      document.getElementById("sessionDetailMeta").innerHTML = `
        <div class="stack">
          <div class="meta">${escapeHtml(data.detail?.agent_id || "-")}</div>
          <div class="meta">
            <strong>Name:</strong>
            <span id="sessionNameLabel">${detailName}</span>
            ${detailStatus !== "unmanaged" ? `<button class="secondary" onclick='startSessionNameEdit(${jsSessionRef})'>✎</button>` : ``}
          </div>
          ${detailStatus !== "unmanaged" ? `<div id="sessionNameEditor" class="hidden row" style="gap:10px;">
            <input id="sessionNameInput" value="${detailName}" placeholder="session name">
            <button class="secondary" onclick='renameSession(${jsSessionRef})'>Confirm</button>
            <button class="secondary" onclick="cancelSessionNameEdit()">Cancel</button>
          </div>` : ``}
          <div class="meta mono">
            <strong>Session:</strong>
            <span id="sessionIdLabel">${detailSessionId}</span>
          </div>
          <div class="row">
            <span class="pill">started ${escapeHtml(data.detail?.started_at || "-")}</span>
            <span class="pill">last update ${escapeHtml(data.detail?.last_seen_label || "-")}</span>
            <span class="pill ${statusTone}">${escapeHtml(data.detail?.status || "-")}</span>
          </div>
        </div>`;
      const action = document.getElementById("sessionDetailAction");
      const stateTone = data.detail?.control_state === "attached" ? "good" : (data.detail?.control_state === "routed" ? "" : "warn");
      action.innerHTML = [
        `<span class="pill ${stateTone}">${escapeHtml(data.detail?.control_state || data.detail?.status || "-")}</span>`,
        `<span class="meta" style="min-width:280px; flex:1 1 280px;">${escapeHtml(describeControlState(data.detail))}</span>`,
        data.detail?.can_prepare ? `<button class="good" onclick='joinMonitor(${jsSessionRef}, ${JSON.stringify(rawName)})'>Join Monitor</button>` : "",
        data.detail?.resume_command ? `<button class="secondary" onclick='copyResumeCommand(${JSON.stringify(String(data.detail?.resume_command || ''))})'>Copy Resume Command</button>` : "",
        detailStatus !== "unmanaged" ? `<button class="secondary" onclick='archiveSession(${jsSessionId})'>Archive</button>` : "",
        `<button class="secondary" onclick='downloadProofLog(${jsSessionId})'>Download Proof Log</button>`
      ].join("");
      renderItems("sessionHistoryList", data.history || [], item => `
        <div class="item history-item ${String(item.risk_reason || "").includes("delete") ? "warn" : "good"} ${item.restored ? "restored" : ""}">
          <div><strong>[${item.index}] ${escapeHtml(item.summary)}</strong></div>
          <div class="meta">${escapeHtml(item.time_label)} | ${escapeHtml(item.risk_label || item.risk_reason)}</div>
          <div class="row" style="margin-top:10px;">
            <button class="good" ${item.restore_disabled ? "disabled" : ""} onclick='restoreItem(${item.index}, ${JSON.stringify(String(item.session_id || ""))}, ${JSON.stringify(String(item.impact_set_id || ""))}, ${JSON.stringify(String(item.config_path || ""))})'>${item.restore_disabled ? (item.risk_class === "audit-only" ? "Audit Only" : (String(item.source || "").includes("fallback") ? "No Snapshot" : (item.restored ? "Restored" : "Unavailable"))) : "Restore"}</button>
          </div>
        </div>
      `);
      renderItems("sessionActivityList", data.activity || [], item => `
        <div class="timeline-item">
          <div class="timeline-rail">
            <div class="timeline-dot ${String(item.headline || "").includes("dangerous") ? "warn" : ""}"></div>
          </div>
          <div class="timeline-card">
            <div><strong>${escapeHtml(item.headline)}</strong></div>
            <div class="meta">${escapeHtml(item.detail || "-")}</div>
          </div>
        </div>
      `);
    }

    async function selectSessionCard(sessionRef) {
      selectedSessionRef = sessionRef;
      setView('detail');
      renderSessionCards(cachedSessionCards);
      await loadSessionDetail(sessionRef);
    }

    async function downloadProofLog(sessionRef) {
      const rootDir = document.getElementById('rootDir')?.value.trim() || '';
      const data = await api('/api/export-proof-log', {
        method: 'POST',
        body: JSON.stringify({
          account: UI_ACCOUNT_ID,
          session_ref: sessionRef,
          root_dir: rootDir || null,
        })
      });
      const bytes = Uint8Array.from(atob(data.download_b64), c => c.charCodeAt(0));
      const blob = new Blob([bytes], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = data.file_name || `${sessionRef}-proof-log.json`;
      pushToast('Readable proof log downloaded. Local encrypted archive also updated.', 'good');
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setStatus(`Proof log downloaded. Encrypted archive updated: ${data.archive_path || '-'}`);
    }


    async function restoreItem(index, sessionId, impactSetId, configPath) {
      const root_dir = document.getElementById('rootDir').value.trim();
      const historyEl = Array.from(document.querySelectorAll('#historyList .item'))[index - 1];
      const summary = historyEl?.querySelector('strong')?.textContent || `operation #${index}`;
      const meta = historyEl?.querySelector('.meta')?.textContent || '';
      const ok = confirm(`Restore ${summary}?\nSession: ${sessionId}\n${meta}`);
      if (!ok) return;
      const data = await api('/api/restore', {
        method: 'POST',
        body: JSON.stringify({
          account: UI_ACCOUNT_ID,
          root_dir: root_dir || null,
          session_id: sessionId,
          impact_set_id: impactSetId || null,
          config_path: configPath || null,
          pick: index,
          approve: true
        })
      });
      const result = document.getElementById('restoreResult');
      const label = document.getElementById('restoreResultLabel');
      label.textContent = data.ok ? 'completed' : 'failed';
      result.innerHTML = `
        <div><strong>${escapeHtml(data.operation_summary || summary)}</strong></div>
        <div class="meta">session=${escapeHtml(sessionId)} | impact_set=${escapeHtml(data.impact_set_id || '-')}</div>
        <div class="meta">scope=${escapeHtml((data.restored_scope_summary || []).join(', ') || '-')}</div>
      `;
      setStatus(`Restore finished: ${data.operation_summary || 'ok'}`);
      await loadActivity();
      await loadHistory();
      await refreshAll();
    }

    async function boot() {
      try {
        await loadAgents();
        await api('/api/deploy', {
          method: 'POST',
          body: JSON.stringify({
            account: UI_ACCOUNT_ID,
            password: UI_PASSWORD,
            no_start_service: true
          })
        });
        const savedView = (() => { try { return window.localStorage.getItem('clawchain-current-view') || 'dashboard'; } catch (_) { return 'dashboard'; } })();
        setView(savedView);
        await refreshAll({quiet: true});
        if ((cachedSessionCards || []).length) {
          selectedSessionRef = cachedSessionCards[0].session_ref;
        }
        await Promise.all([
          loadActivity({quiet: true}),
          loadHistory({quiet: true}),
          selectedSessionRef ? loadSessionDetail(selectedSessionRef, {quiet: true}) : Promise.resolve(),
        ]);
        setStatus(`ClawChain dashboard ready.`);
        setInterval(() => { refreshAll({quiet: true}).catch(err => setStatus(`Session refresh failed: ${err.message}`)); }, 4000);
        setInterval(() => { loadActivity({quiet: true}).catch(err => setStatus(`Activity refresh failed: ${err.message}`)); }, 5000);
        setInterval(() => { loadHistory({quiet: true}).catch(err => setStatus(`History refresh failed: ${err.message}`)); }, 6000);
      } catch (err) {
        setStatus(`UI bootstrap failed: ${err.message}`);
      }
    }
    boot();
  </script>
</body>
</html>""".replace("__BUILD_LABEL__", UI_BUILD_LABEL).replace("__RISK_OPTIONS__", render_risk_filter_options())


def _parse_root_dir(raw: str | None) -> Path | None:
    if not raw:
        return None
    return Path(raw).expanduser()


def _resolve_ui_account_id(raw: str | None) -> str:
    return str(raw or UI_DEFAULT_ACCOUNT_ID)


def _resolve_ui_password(raw: str | None) -> str:
    return str(raw or UI_DEFAULT_PASSWORD)


def _parse_iso_timestamp_ms(raw: str | None) -> int:
    return codex_rollout.parse_iso_timestamp_ms(raw)


def _codex_rollout_paths(session_id: str) -> list[Path]:
    return codex_rollout.codex_rollout_paths(session_id)


def _normalize_codex_rollout_tool_call(tool_name: str, arguments_text: str) -> tuple[str | None, dict[str, object]]:
    return codex_rollout.normalize_rollout_tool_call(tool_name, arguments_text)


def _collect_codex_rollout_dangerous_history(*, session_id: str, session_name: str, config_path: str | None = None, limit: int = 50) -> list[dict[str, object]]:
    if not session_id:
        return []
    rows: list[dict[str, object]] = []
    for rollout_path in _codex_rollout_paths(session_id):
        meta = codex_rollout.read_rollout_session_meta(rollout_path)
        items, _offset, _cwd = codex_rollout.read_rollout_updates(
            rollout_path,
            start_offset=0,
            default_cwd=meta.cwd if meta is not None else None,
        )
        for item in items:
            if item.kind != "function_call" or not item.tool_name:
                continue
            params = dict(item.params or {})
            risky, risk_reason = recovery_runtime.looks_like_risky_action(tool_name=item.tool_name, params=params)
            if not risky:
                continue
            cmd_text = str(params.get("cmd") or params.get("command") or params.get("path") or "").strip()
            if not cmd_text:
                continue
            target_path = codex_rollout.extract_risky_target_path(cmd_text, default_cwd=item.cwd)
            target_root = Path(target_path).name if target_path else _extract_risky_target_root(cmd_text)
            rows.append({
                "session_id": session_id,
                "session_name": session_name,
                "impact_set_id": None,
                "time_label": agent_proxy_cli._format_ts_label(item.timestamp_ms),
                "created_ts_ms": item.timestamp_ms,
                "risk_reason": risk_reason,
                "target_root": target_root,
                "summary": _compact_risky_summary(cmd_text=cmd_text, risk_reason=risk_reason, target_root=target_root),
                "risk_label": risk_label(risk_reason),
                "risk_class": risk_class(risk_reason),
                "restorable": False,
                "recovery_count": 0,
                "config_path": config_path,
                "restored": False,
                "restored_count": 0,
                "restored_label": "unavailable",
                "restored_ts_ms": None,
                "restored_ts_label": None,
                "restore_disabled": True,
                "evidence": {},
                "source": "codex-rollout-fallback",
                "target_path": target_path or None,
            })
    deduped: list[dict[str, object]] = []
    for item in rows:
        deduped = _merge_history_rows(base=deduped, extra=[item])
    deduped.sort(key=lambda row: int(row.get("created_ts_ms") or 0), reverse=True)
    return deduped[: max(limit, 0)]


_HISTORY_DUP_WINDOW_MS = 15_000


def _history_identity_value(value: object) -> str:
    return str(value or "").strip().lower()


def _history_is_fallback(item: dict[str, object]) -> bool:
    return str(item.get("source") or "").endswith("fallback")


def _history_target_parts(item: dict[str, object]) -> set[str]:
    target = str(item.get("target_root") or "").strip()
    if not target:
        return set()
    parts = {target.lower()}
    try:
        path = Path(target)
        parts.update(str(part).strip().lower() for part in path.parts if str(part).strip())
        name = path.name.strip().lower()
        if name:
            parts.add(name)
    except Exception:
        pass
    return parts


def _history_fallback_scope_matches(fallback: dict[str, object], preferred: dict[str, object]) -> bool:
    if not _history_is_fallback(fallback) or _history_is_fallback(preferred):
        return False
    fallback_target = _history_identity_value(fallback.get("target_root"))
    if not fallback_target:
        return False
    return fallback_target in _history_target_parts(preferred)


def _history_scope_merged(preferred: dict[str, object], secondary: dict[str, object]) -> dict[str, object]:
    if not _history_fallback_scope_matches(secondary, preferred):
        return preferred
    merged = dict(preferred)
    if secondary.get("target_root"):
        merged["target_root"] = secondary.get("target_root")
    if secondary.get("summary"):
        merged["summary"] = secondary.get("summary")
    return merged


def _history_rows_equivalent(left: dict[str, object], right: dict[str, object], *, window_ms: int = _HISTORY_DUP_WINDOW_MS) -> bool:
    if _history_identity_value(left.get("session_id")) != _history_identity_value(right.get("session_id")):
        return False
    if _history_identity_value(left.get("risk_reason")) != _history_identity_value(right.get("risk_reason")):
        return False
    left_target = _history_identity_value(left.get("target_root"))
    right_target = _history_identity_value(right.get("target_root"))
    left_summary = _history_identity_value(left.get("summary"))
    right_summary = _history_identity_value(right.get("summary"))
    scope_match = (
        (left_target and right_target and left_target == right_target)
        or (left_summary and right_summary and left_summary == right_summary)
        or _history_fallback_scope_matches(left, right)
        or _history_fallback_scope_matches(right, left)
    )
    if not scope_match:
        return False
    left_ts = int(left.get("created_ts_ms") or 0)
    right_ts = int(right.get("created_ts_ms") or 0)
    return abs(left_ts - right_ts) <= max(window_ms, 0)


def _history_row_rank(item: dict[str, object]) -> tuple[int, int, int]:
    recovery_count = int(item.get("recovery_count") or 0)
    has_impact_set = 1 if str(item.get("impact_set_id") or "").strip() else 0
    is_fallback = 0 if str(item.get("source") or "").endswith("fallback") else 1
    return (recovery_count, has_impact_set, is_fallback)


def _merge_history_rows(*, base: list[dict[str, object]], extra: list[dict[str, object]]) -> list[dict[str, object]]:
    merged = list(base)
    for candidate in extra:
        replacement_index = None
        for index, current in enumerate(merged):
            if not _history_rows_equivalent(current, candidate):
                continue
            if _history_row_rank(candidate) > _history_row_rank(current):
                merged_candidate = _history_scope_merged(candidate, current)
                replacement_index = index
                candidate = merged_candidate
            else:
                merged[index] = _history_scope_merged(current, candidate)
                replacement_index = -1
            break
        if replacement_index is None:
            merged.append(candidate)
        elif replacement_index >= 0:
            merged[replacement_index] = candidate
    return merged


def _readonly_impact_set_records(path: Path) -> list[object]:
    if not path.exists():
        return []
    rows: list[object] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                payload = str(line or "").strip()
                if not payload:
                    continue
                rows.append(recovery_runtime.recovery_impact_set_record_from_dict(json.loads(payload)))
    except Exception:
        return []
    return rows


def _session_event_chain_state(*, event_store_path: Path, session_id: str) -> tuple[int, str | None]:
    next_index = 0
    last_hash: str | None = None
    if not event_store_path.exists():
        return next_index, last_hash
    try:
        with event_store_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                payload = str(line or "").strip()
                if not payload:
                    continue
                row = json.loads(payload)
                if str(row.get("session_id") or "") != session_id:
                    continue
                try:
                    event_index = int(row.get("event_index") or 0)
                except (TypeError, ValueError):
                    continue
                next_index = max(next_index, event_index + 1)
                last_hash = str(row.get("event_hash") or "").strip() or last_hash
    except Exception:
        return 0, None
    return next_index, last_hash


def _path_identity_value(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    normalized = os.path.normcase(os.path.normpath(text))
    return normalized.lower()


def _backfill_codex_rollout_recovery(*, row: dict[str, object]) -> bool:
    if str(row.get("agent_id") or "") != "codex":
        return False
    session_id = str(row.get("session_id") or "").strip()
    config_path = Path(str(row.get("config_path") or "")).expanduser()
    if not session_id or not config_path.exists():
        return False
    try:
        stored = agent_proxy_cli.load_agent_proxy_config(config_path)
    except Exception:
        return False
    base_dir = Path(str(getattr(stored, "base_dir", "") or "")).expanduser()
    if not base_dir:
        return False
    runtime_local = base_dir / "runtime" / "local"
    impact_catalog_path = runtime_local / "recovery-impact-sets.jsonl"
    event_store_path = runtime_local / "events.jsonl"
    existing = _readonly_impact_set_records(impact_catalog_path)
    try:
        proxy = TransparentAgentProxy.create(stored.to_proxy_config())
    except Exception:
        return False
    changed = False
    try:
        next_index, parent_hash = _session_event_chain_state(
            event_store_path=event_store_path,
            session_id=session_id,
        )
        proxy._session_next_index[session_id] = next_index
        proxy._session_last_hash[session_id] = parent_hash
        for rollout_path in _codex_rollout_paths(session_id):
            meta = codex_rollout.read_rollout_session_meta(rollout_path)
            items, _offset, _cwd = codex_rollout.read_rollout_updates(
                rollout_path,
                start_offset=0,
                default_cwd=meta.cwd if meta is not None else None,
            )
            for item in items:
                if item.kind != "function_call" or not item.tool_name:
                    continue
                params = dict(item.params or {})
                risky, risk_reason = recovery_runtime.looks_like_risky_action(tool_name=item.tool_name, params=params)
                if not risky:
                    continue
                cmd_text = str(params.get("cmd") or params.get("command") or params.get("path") or "").strip()
                target_path_text = codex_rollout.extract_risky_target_path(cmd_text, default_cwd=item.cwd)
                if not target_path_text:
                    continue
                target_path = Path(target_path_text)
                if any(
                    record.session_id == session_id
                    and record.risk_reason == risk_reason
                    and _path_identity_value(record.target_root) == _path_identity_value(target_path)
                    for record in existing
                ):
                    continue
                protection, event, _receipt = proxy.system.plan_recovery(
                    session_id=session_id,
                    run_id=stored.default_run_id,
                    event_index=next_index,
                    timestamp_ms=item.timestamp_ms or int(time.time() * 1000),
                    actor_id="codex-rollout-backfill",
                    target_path=target_path,
                    tool_name=item.tool_name,
                    params=params,
                    parent_event_hash=parent_hash,
                    sources=("git",),
                )
                if protection is None:
                    continue
                if event is not None:
                    next_index += 1
                    parent_hash = event.event_hash
                record = proxy.system.record_recovery_impact_set(
                    session_id=session_id,
                    target_root=target_path,
                    risk_reason=risk_reason,
                    protections=(protection,),
                )
                if record is not None:
                    existing.append(record)
                    changed = True
        if changed:
            proxy._session_next_index[session_id] = next_index
            proxy._session_last_hash[session_id] = parent_hash
            proxy.system.flush()
            proxy.system.poll_anchor_submissions()
    finally:
        proxy.close()
    return changed


def _collect_codex_sqlite_dangerous_history(*, session_id: str, session_name: str, config_path: str | None = None, limit: int = 50) -> list[dict[str, object]]:
    if not session_id:
        return []
    rows: list[dict[str, object]] = []
    db_path = Path.home() / ".codex" / "logs_1.sqlite"
    if db_path.exists():
        try:
            con = sqlite3.connect(str(db_path))
            con.row_factory = sqlite3.Row
            sql_rows = con.execute(
                "select ts, feedback_log_body from logs where thread_id = ? order by ts desc, id desc limit ?",
                (session_id, max(limit * 6, 60)),
            ).fetchall()
        except sqlite3.Error:
            sql_rows = []
        finally:
            try:
                con.close()
            except Exception:
                pass
        for row in sql_rows:
            message = str(row["feedback_log_body"] or "")
            if not message.startswith('ToolCall: '):
                continue
            tool_payload = message[len('ToolCall: '):].strip()
            tool_name, _, payload_text = tool_payload.partition(' ')
            params: dict[str, object]
            try:
                params = json.loads(payload_text.strip()) if payload_text.strip() else {}
            except json.JSONDecodeError:
                continue
            normalized_tool = 'system.run' if tool_name == 'exec_command' else tool_name
            risky, risk_reason = recovery_runtime.looks_like_risky_action(tool_name=normalized_tool, params=params)
            if not risky:
                continue
            cmd_text = str(params.get('cmd') or params.get('command') or '').strip()
            target_path = codex_rollout.extract_risky_target_path(cmd_text, default_cwd=str(params.get("cwd") or "") or None)
            target_root = Path(target_path).name if target_path else _extract_risky_target_root(cmd_text)
            ts_ms = int(row['ts'] or 0) * 1000
            rows.append({
                'session_id': session_id,
                'session_name': session_name,
                'impact_set_id': None,
                'time_label': agent_proxy_cli._format_ts_label(ts_ms),
                'created_ts_ms': ts_ms,
                'risk_reason': risk_reason,
                'target_root': target_root,
                'summary': _compact_risky_summary(cmd_text=cmd_text, risk_reason=risk_reason, target_root=target_root),
                'risk_label': risk_label(risk_reason),
                'risk_class': risk_class(risk_reason),
                'restorable': False,
                'recovery_count': 0,
                'config_path': config_path,
                'restored': False,
                'restored_count': 0,
                'restored_label': 'unavailable',
                'restored_ts_ms': None,
                'restored_ts_label': None,
                'restore_disabled': True,
                'evidence': {},
                'source': 'codex-log-fallback',
                'target_path': target_path or None,
            })
            if len(rows) >= limit:
                break
    rows = _merge_history_rows(
        base=rows,
        extra=_collect_codex_rollout_dangerous_history(
            session_id=session_id,
            session_name=session_name,
            config_path=config_path,
            limit=max(limit * 3, 20),
        ),
    )
    rows.sort(key=lambda item: int(item.get("created_ts_ms") or 0), reverse=True)
    return rows[: max(limit, 0)]


def _extract_risky_target_root(cmd_text: str) -> str:
    return codex_rollout.extract_risky_target_root(cmd_text)


def _compact_risky_summary(*, cmd_text: str, risk_reason: str, target_root: str) -> str:
    summary = agent_proxy_cli._natural_language_operation_summary(
        risk_reason=str(risk_reason or ''),
        target_root=str(target_root or '-'),
    )
    text = str(summary or '').strip()
    if text and text != '-':
        return text
    compact = str(cmd_text or '').strip()
    return compact[:160] if compact else 'dangerous operation'


def _system_proof_key_path(*, account_id: str, root_dir: Path | None = None) -> Path:
    root = (root_dir or (Path.home() / '.clawchain-agent' / account_id)).expanduser()
    secure_dir = root / '_internal'
    secure_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(secure_dir, 0o700)
    except Exception:
        pass
    return secure_dir / 'proof-log.key'


def _load_or_create_system_proof_key(*, account_id: str, root_dir: Path | None = None) -> bytes:
    key_path = _system_proof_key_path(account_id=account_id, root_dir=root_dir)
    if key_path.exists():
        data = key_path.read_bytes()
        if len(data) == 32:
            return data
    key = AESGCM.generate_key(bit_length=256)
    key_path.write_bytes(key)
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    return key


def _proof_archive_root(*, account_id: str, base_dir: Path | None = None, root_dir: Path | None = None) -> Path:
    if base_dir is not None:
        archive_root = base_dir / "_internal" / "proof-archives"
    else:
        archive_root = agent_proxy_cli._default_account_root(account_id, root_dir=root_dir) / "_internal" / "proof-archives"
    archive_root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(archive_root, 0o700)
    except Exception:
        pass
    return archive_root


def _cleanup_plaintext_proof_exports(*, account_id: str, base_dir: Path | None = None, root_dir: Path | None = None) -> list[str]:
    roots = [agent_proxy_cli._default_account_root(account_id, root_dir=root_dir)]
    if base_dir is not None:
        roots.append(base_dir)
    removed: list[str] = []
    seen: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob('*-proof-log.json'):
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            try:
                path.unlink()
                removed.append(key)
            except OSError:
                continue
    return removed


def _store_encrypted_proof_archive(*, account_id: str, plaintext: bytes, archive_path: Path, root_dir: Path | None = None) -> dict[str, object]:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(archive_path.parent, 0o700)
    except Exception:
        pass
    key = _load_or_create_system_proof_key(account_id=account_id, root_dir=root_dir)
    nonce = urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    payload = {
        'format': 'clawchain-proof-log-archive.v1',
        'algorithm': 'AES-256-GCM',
        'stored_at': agent_proxy_cli._format_ts_label(int(time.time() * 1000)),
        'nonce_b64': b64encode(nonce).decode('ascii'),
        'ciphertext_b64': b64encode(ciphertext).decode('ascii'),
        'plaintext_sha256': sha256(plaintext).hexdigest(),
    }
    archive_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    try:
        os.chmod(archive_path, 0o600)
    except Exception:
        pass
    return {'archive_locator': str(archive_path), 'plaintext_sha256': payload['plaintext_sha256']}


def _monitored_resume_command(row: dict[str, object] | None, running_item: dict[str, object] | None = None) -> str | None:
    session_id = str((row or {}).get('session_id') or _immutable_session_id(running_item or {}) or '').strip()
    if not session_id or session_id.startswith('proc:') or session_id.startswith('path:'):
        return None
    config_path = Path(str((row or {}).get('config_path') or '')).expanduser()
    if config_path.exists():
        launcher_path = codex_launcher_path(config_path.parent)
        if launcher_path.exists():
            return script_command_display(launcher_path, "resume", session_id, keep_open=is_windows())
    return f"codex resume {shlex.quote(session_id)}"


def _attach_command_for_row(row: dict[str, object] | None, running_item: dict[str, object] | None = None) -> str | None:
    existing = str((row or {}).get("attach_command") or "").strip()
    if existing:
        return existing
    agent_id = str((row or {}).get("agent_id") or (running_item or {}).get("agent_id") or "")
    if is_windows() and agent_id == "codex":
        return _monitored_resume_command(row, running_item)
    controlled = _resolve_controlled_session_name(row)
    return f"tmux attach -t {controlled}" if controlled else None


def export_readable_proof_log(*, account_id: str, session_ref: str, password: str = "", root_dir: Path | None = None) -> dict[str, object]:
    detail_payload = build_session_detail_payload(account_id=account_id, session_ref=session_ref, root_dir=root_dir)
    detail = dict(detail_payload.get("detail") or {})
    session_id = str(detail.get("session_id") or session_ref)
    history = list(detail_payload.get("history") or [])
    activity = list(detail_payload.get("activity") or [])
    proof_cards: list[dict[str, object]] = []
    try:
        entries = agent_proxy_cli._collect_registry_review_entries(account_id=account_id, root_dir=root_dir)
    except TypeError:
        entries = agent_proxy_cli._collect_registry_review_entries(account_id=account_id)
    for row in entries:
        if str(row.get("session_id") or "") == session_id:
            proof_cards.append(agent_proxy_cli._build_proof_card(row))
    export_payload = {
        "format": "clawchain-proof-log.v2",
        "exported_at": agent_proxy_cli._format_ts_label(int(time.time() * 1000)),
        "account_id": account_id,
        "session": detail,
        "session_dangerous_operations": history,
        "session_live_activity": activity,
        "proof_cards": proof_cards,
        "security_model": {
            "download_gate": "ClawChain stores an encrypted local proof archive automatically and decrypts to plaintext only for user downloads.",
            "tamper_resistance": "Receipts, submissions, and anchor references provide the integrity chain. Use `clawchain.agent_proxy_cli verify` and `integrity-check` to validate evidence and anchors.",
            "recovery_storage": "Recovery uses snapshot-first storage. snapshot_paths and vault_root identify the local recovery material for each dangerous operation.",
        },
    }
    registry_rows = _active_registry_rows(account_id, root_dir=root_dir)
    matched = next((row for row in registry_rows if str(row.get("session_id") or "") == session_id or str(row.get("session_fingerprint") or "") == session_ref), None)
    base_dir = None
    if matched:
        config_path = str(matched.get("config_path") or "")
        if config_path:
            try:
                stored = agent_proxy_cli.load_agent_proxy_config(Path(config_path))
                base_dir = Path(str(getattr(stored, "base_dir", ""))).expanduser()
            except Exception:
                base_dir = None
    removed_plaintext_exports = _cleanup_plaintext_proof_exports(account_id=account_id, base_dir=base_dir, root_dir=root_dir)
    file_name = f"{session_id}-proof-log.json"
    archived_name = f"{session_id}-proof-log.enc.json"
    archive_root = _proof_archive_root(account_id=account_id, base_dir=base_dir, root_dir=root_dir)
    archive_path = archive_root / archived_name
    serialized = json.dumps(export_payload, ensure_ascii=False, indent=2) + "\n"
    archive_payload = _store_encrypted_proof_archive(account_id=account_id, plaintext=serialized.encode("utf-8"), archive_path=archive_path, root_dir=root_dir)
    return {
        "ok": True,
        "session_id": session_id,
        "file_name": file_name,
        "file_path": None,
        "plaintext_persisted": False,
        "archive_path": str(archive_path),
        "archive_locator": archive_payload.get("archive_locator"),
        "cleanup_removed": removed_plaintext_exports,
        "download_b64": b64encode(serialized.encode("utf-8")).decode("ascii"),
        "anchor_references": [card.get("anchor_reference") for card in proof_cards if card.get("anchor_reference")],
        "git_sources": sorted({src for card in proof_cards for src in card.get("git_source", [])}),
        "snapshot_paths": [src for card in proof_cards for src in card.get("snapshot_paths", [])],
    }


def export_encrypted_proof_log(*, account_id: str, session_ref: str, password: str = "", root_dir: Path | None = None) -> dict[str, object]:
    return export_readable_proof_log(
        account_id=account_id,
        session_ref=session_ref,
        root_dir=root_dir,
    )


def _tmux_bin() -> str | None:
    if is_windows():
        return None
    return shutil.which("tmux")


def _tmux_session_exists(session_name: str | None) -> bool:
    if not session_name:
        return False
    tmux_bin = _tmux_bin()
    if not tmux_bin:
        return False
    probe = subprocess.run([tmux_bin, "has-session", "-t", session_name], capture_output=True, text=True, check=False)
    return probe.returncode == 0


def _tmux_session_attached(session_name: str | None) -> bool:
    if not session_name:
        return False
    tmux_bin = _tmux_bin()
    if not tmux_bin:
        return False
    probe = subprocess.run([tmux_bin, "list-clients", "-t", session_name], capture_output=True, text=True, check=False)
    return probe.returncode == 0 and bool(probe.stdout.strip())

def _tmux_session_names() -> list[str]:
    tmux_bin = _tmux_bin()
    if not tmux_bin:
        return []
    probe = subprocess.run([tmux_bin, "ls"], capture_output=True, text=True, check=False)
    if probe.returncode != 0:
        return []
    names: list[str] = []
    for line in probe.stdout.splitlines():
        name = line.split(":", 1)[0].strip()
        if name:
            names.append(name)
    return names


def _resolve_controlled_session_name(row: dict[str, object] | None) -> str:
    if row is None:
        return ""
    controlled = str(row.get("controlled_session_name") or "").strip()
    if controlled:
        return controlled
    session_id = str(row.get("session_id") or "").strip()
    fingerprint = str(row.get("session_fingerprint") or "").strip()
    exact_candidates = [
        session_id.replace(":", "-").replace("/", "-").replace(" ", "-")[:48],
        fingerprint.replace(":", "-").replace("/", "-").replace(" ", "-")[:48],
    ]
    names = _tmux_session_names()
    for candidate in exact_candidates:
        if candidate and candidate in names:
            return candidate
    for fragment in (session_id, fingerprint):
        if not fragment:
            continue
        short = fragment[:12]
        for name in names:
            if fragment in name or short in name:
                return name
    return ""



def _control_state_from_registry(row: dict[str, object] | None) -> str:
    if row is None:
        return "unmanaged"
    capture_mode = str(row.get("capture_mode") or "")
    controlled_session_name = _resolve_controlled_session_name(row)
    if _tmux_session_exists(controlled_session_name):
        return "attached" if _tmux_session_attached(controlled_session_name) else "routed"
    if capture_mode in {"pending-handoff", "pending-relaunch"}:
        return "pending"
    if capture_mode == "tmux-routed":
        return "attached" if _tmux_session_attached(controlled_session_name) else "routed"
    if capture_mode in {"launcher-routed", "rollout-observed"}:
        return "routed"
    if _tmux_session_exists(controlled_session_name):
        return "attached" if _tmux_session_attached(controlled_session_name) else "routed"
    return "pending"


def _build_handoff_script(*, item: dict[str, object], prepared_item: dict[str, object]) -> tuple[str, str] | tuple[None, None]:
    launcher_path = str(prepared_item.get("launcher_path") or "")
    session_id = str(prepared_item.get("session_id") or prepared_item.get("session_name") or item.get("session_fingerprint") or "session")
    if not launcher_path or not session_id:
        return None, None
    command_text = str(item.get("command_text") or item.get("sample_process_summary") or "")
    try:
        tokens = shlex.split(command_text)
    except ValueError:
        tokens = command_text.split()
    while tokens and not codex_command_matches(tokens[0]):
        tokens = tokens[1:]
    forwarded = tokens[1:] if tokens else []
    base_dir = Path(str((prepared_item.get("prepared_payload") or {}).get("artifacts", {}).get("base_dir") or (prepared_item.get("prepared_payload") or {}).get("base_dir") or "")).expanduser()
    if not base_dir:
        return None, None
    script_path = monitored_handoff_path(base_dir)
    pids = [str(int(pid)) for pid in item.get("pids", []) if pid is not None]
    command = script_command_display(launcher_path, *forwarded, keep_open=is_windows())
    tmux_bin = _tmux_bin()
    controlled_session_name = str(prepared_item.get("controlled_session_name") or session_id).replace(":", "-").replace("/", "-").replace(" ", "-")[:48] or "clawchain-session"
    if is_windows():
        lines = [
            "@echo off",
            "setlocal EnableExtensions",
            "echo [clawchain] Preparing controlled session handoff...",
            "echo [clawchain] This script will not close your current terminal.",
            "",
        ]
        if pids:
            lines.append("REM Stop the currently running native session if it is still active.")
            for pid in pids:
                lines.append(f"taskkill /PID {pid} /T /F >NUL 2>&1")
            lines.extend(["timeout /t 1 /nobreak >NUL", ""])
        lines.extend(
            [
                "echo [clawchain] Launching the controlled session in a new terminal window...",
                f'start "" {command}',
                "echo [clawchain] Controlled session launched in a new terminal window.",
                "echo [clawchain] Re-enter later with:",
                f"echo {command}",
            ]
        )
        script_path.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
        prepared_item["attach_command"] = command
        prepared_item["controlled_session_name"] = ""
        return str(script_path), script_command_display(script_path)
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "echo '[clawchain] Preparing controlled session handoff...'",
        "echo '[clawchain] This script will not close your current terminal.'",
        "",
    ]
    if pids:
        lines.append("# Stop the currently running native session if it is still active.")
        for pid in pids:
            lines.append(f"kill -TERM {pid} 2>/dev/null || true")
        lines.append("sleep 1")
        lines.append("")
    if tmux_bin:
        lines.extend([
            f"TMUX_BIN={shlex.quote(tmux_bin)}",
            f"SESSION_NAME={shlex.quote(controlled_session_name)}",
            f"LAUNCH_CMD={shlex.quote(command)}",
            '"$TMUX_BIN" kill-session -t "$SESSION_NAME" 2>/dev/null || true',
            '"$TMUX_BIN" new-session -d -s "$SESSION_NAME" "$LAUNCH_CMD"',
            'echo "[clawchain] Controlled session started in tmux."',
            'echo "[clawchain] Attach with:"',
            'echo "tmux attach -t $SESSION_NAME"',
            'if [ "${CLAWCHAIN_NO_ATTACH:-0}" = "1" ]; then',
            '  echo "[clawchain] Background route complete. Attach later if needed."',
            '  exit 0',
            'fi',
            'echo "[clawchain] Attaching now. Detach with Ctrl-b d when done."',
            '"$TMUX_BIN" attach -t "$SESSION_NAME"',
            'echo "[clawchain] Detached from controlled session. Your current terminal remains open."',
        ])
        prepared_item["attach_command"] = f"tmux attach -t {controlled_session_name}"
        prepared_item["controlled_session_name"] = controlled_session_name
    else:
        lines.extend([
            "echo '[clawchain] tmux is not available; starting controlled session in this terminal.'",
            command,
        ])
    script_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    script_path.chmod(script_path.stat().st_mode | 0o111)
    return str(script_path), script_command_display(script_path)


def _upgrade_legacy_handoff_script(*, script_path: str | None, controlled_session_name: str | None = None) -> tuple[str | None, str | None]:
    if not script_path:
        return None, None
    path = Path(script_path).expanduser()
    if not path.exists():
        return None, None
    if is_windows():
        preferred = monitored_handoff_path(path.parent)
        if preferred.exists():
            return str(preferred), script_command_display(preferred)
        if path.suffix.lower() == ".cmd":
            return str(path), script_command_display(path)
        return None, None
    body = path.read_text(encoding="utf-8")
    if 'This script will not close your current terminal.' in body:
        return str(path), script_command_display(path)
    command = None
    for line in body.splitlines():
        line = line.strip()
        if line.startswith('exec '):
            command = line[len('exec '):].strip()
            break
    if not command:
        return str(path), script_command_display(path)
    tmux_bin = _tmux_bin()
    session_name = str(controlled_session_name or path.parent.name or 'clawchain-session').replace(':', '-').replace('/', '-').replace(' ', '-')[:48] or 'clawchain-session'
    lines = [
        '#!/usr/bin/env bash',
        'set -euo pipefail',
        '',
        "echo '[clawchain] Preparing controlled session handoff...'",
        "echo '[clawchain] This script will not close your current terminal.'",
        '',
    ]
    if tmux_bin:
        lines.extend([
            f'TMUX_BIN={shlex.quote(tmux_bin)}',
            f'SESSION_NAME={shlex.quote(session_name)}',
            f'LAUNCH_CMD={shlex.quote(command)}',
            '"$TMUX_BIN" kill-session -t "$SESSION_NAME" 2>/dev/null || true',
            '"$TMUX_BIN" new-session -d -s "$SESSION_NAME" "$LAUNCH_CMD"',
            'echo "[clawchain] Controlled session started in tmux."',
            'echo "[clawchain] Attach with:"',
            'echo "tmux attach -t $SESSION_NAME"',
            'if [ "${CLAWCHAIN_NO_ATTACH:-0}" = "1" ]; then',
            '  echo "[clawchain] Background route complete. Attach later if needed."',
            '  exit 0',
            'fi',
            'echo "[clawchain] Attaching now. Detach with Ctrl-b d when done."',
            '"$TMUX_BIN" attach -t "$SESSION_NAME"',
            'echo "[clawchain] Detached from controlled session. Your current terminal remains open."',
        ])
    else:
        lines.extend([
            "echo '[clawchain] tmux is not available; starting controlled session in this terminal.'",
            command,
        ])
    path.write_text("\n".join(lines) + "\n", encoding='utf-8')
    path.chmod(path.stat().st_mode | 0o111)
    return str(path), script_command_display(path)






def _auto_route_monitored_session(row: dict[str, object] | None) -> None:
    if str(os.environ.get("CLAWCHAIN_UI_AUTO_ROUTE") or "").strip().lower() not in {"1", "true", "yes"}:
        return
    if row is None:
        return
    if str(row.get("agent_id") or "") != "codex":
        return
    controlled = _resolve_controlled_session_name(row)
    if controlled and _tmux_session_exists(controlled):
        return
    script_path = str(row.get("handoff_script_path") or "")
    if not script_path:
        return
    path = Path(script_path).expanduser()
    if not path.exists():
        return
    env = os.environ.copy()
    env["CLAWCHAIN_NO_ATTACH"] = "1"
    subprocess.run(script_command_parts(path), env=env, capture_output=True, text=True, check=False, timeout=10)


def _is_concrete_session_id(value: str | None) -> bool:
    token = str(value or "").strip()
    return bool(token) and not token.startswith("proc:") and not token.startswith("path:")


def _restore_monitored_codex_row_from_disk(*, account_id: str, session_id: str, root_dir: Path | None = None) -> dict[str, object] | None:
    token = str(session_id or '').strip()
    if not token or token.startswith('proc:') or token.startswith('path:'):
        return None
    base_root = root_dir.expanduser() if root_dir is not None else (Path.home() / '.clawchain-agent')
    base_dir = base_root / account_id / 'codex' / token
    config_path = base_dir / 'agent-proxy.config.json'
    if not config_path.exists():
        return None
    launcher_path = codex_launcher_path(base_dir)
    handoff_script = monitored_handoff_path(base_dir)
    controlled_session_name = token.replace(':', '-').replace('/', '-').replace(' ', '-')[:48] or 'codex-session'
    resume_command = script_command_display(launcher_path, "resume", token, keep_open=is_windows()) if launcher_path.exists() else f"codex resume {shlex.quote(token)}"
    row = {
        'agent_id': 'codex',
        'session_id': token,
        'session_name': token,
        'session_fingerprint': f'resume:{token}',
        'path_hint': None,
        'config_path': str(config_path),
        'session_state': 'monitored',
        'capture_mode': 'rollout-observed',
        'attach_command': resume_command if is_windows() else f'tmux attach -t {controlled_session_name}',
        'controlled_session_name': controlled_session_name,
        'handoff_command': script_command_display(handoff_script) if handoff_script.exists() else None,
        'handoff_script_path': str(handoff_script) if handoff_script.exists() else None,
        'last_seen_ts_ms': int(time.time() * 1000),
    }
    agent_proxy_cli._upsert_session_registry(account_id, row, root_dir=root_dir)
    return row


def _promote_registry_session_identity(
    *,
    account_id: str,
    registry_rows: list[dict[str, object]],
    matched: dict[str, object] | None,
    item: dict[str, object],
    root_dir: Path | None = None,
) -> dict[str, object] | None:
    if matched is None:
        return None
    live_session_id = _immutable_session_id(item)
    if not _is_concrete_session_id(live_session_id):
        return matched
    current_session_id = str(matched.get("session_id") or "")
    if _is_concrete_session_id(current_session_id):
        return matched
    rows = agent_proxy_cli._load_session_registry(account_id, root_dir=root_dir)
    updated_row = {
        **matched,
        "session_id": live_session_id,
        "session_fingerprint": item.get("session_fingerprint") or matched.get("session_fingerprint"),
        "path_hint": item.get("path_hint") or matched.get("path_hint"),
        "last_seen_ts_ms": int(__import__("time").time() * 1000),
    }
    rewritten = []
    replaced = False
    for row in rows:
        same_old = str(row.get("session_id") or "") == current_session_id or str(row.get("session_fingerprint") or "") == str(matched.get("session_fingerprint") or "")
        if same_old and not replaced:
            rewritten.append(updated_row)
            replaced = True
        else:
            rewritten.append(row)
    if not replaced:
        rewritten.append(updated_row)
    agent_proxy_cli._write_session_registry(account_id, rewritten, root_dir=root_dir)
    for index, row in enumerate(list(registry_rows)):
        same_old = str(row.get("session_id") or "") == current_session_id or str(row.get("session_fingerprint") or "") == str(matched.get("session_fingerprint") or "")
        if same_old:
            registry_rows[index] = updated_row
            break
    else:
        registry_rows.append(updated_row)
    return updated_row


def _ensure_codex_runtime_upgrade(*, row: dict[str, object]) -> dict[str, object]:
    if str(row.get('agent_id') or '') != 'codex':
        return row
    config_path = Path(str(row.get('config_path') or '')).expanduser()
    if not config_path.exists():
        return row
    try:
        stored = agent_proxy_cli.load_agent_proxy_config(config_path)
    except Exception:
        return row
    base_dir = Path(str(getattr(stored, 'base_dir', '') or '')).expanduser()
    if not base_dir:
        return row
    env_path = codex_env_path(base_dir)
    if env_path.exists():
        try:
            env_text = env_path.read_text(encoding='utf-8')
            if 'CLAWCHAIN_AGENT_PROXY_CONFIG=' in env_text:
                return row
        except Exception:
            pass
    session_id = str(row.get('session_id') or getattr(stored, 'default_session_id', '') or 'codex-session')
    run_id = str(getattr(stored, 'default_run_id', '') or 'codex-run')
    workspace_root = None
    path_hint = str(row.get('path_hint') or getattr(stored, 'path_hint', '') or '').strip()
    if path_hint and path_hint != '-':
        workspace_root = Path(path_hint).expanduser()
    try:
        artifacts = agent_proxy_cli.bootstrap_codex_cli_integration(
            account_id=str(getattr(stored, 'account_id', '') or ''),
            password=str(getattr(stored, 'password', '') or ''),
            workspace_root=workspace_root,
            base_dir=base_dir,
            session_id=session_id,
            run_id=run_id,
            start_service=False,
            git_context_mode=str(getattr(stored, 'git_context_mode', 'bind-existing-git') or 'bind-existing-git'),
        )
    except Exception:
        return row
    updated = dict(row)
    updated['config_path'] = str(artifacts.config_path)
    launcher_path = codex_launcher_path(base_dir)
    handoff_script = monitored_handoff_path(base_dir)
    updated['attach_command'] = updated.get('attach_command') or (
        script_command_display(launcher_path, "resume", session_id, keep_open=True)
        if is_windows() and session_id and launcher_path.exists()
        else (f"tmux attach -t {session_id}" if session_id else None)
    )
    if handoff_script.exists():
        updated['handoff_script_path'] = str(handoff_script)
        updated['handoff_command'] = script_command_display(handoff_script)
    return updated


def _active_registry_rows(account_id: str, *, root_dir: Path | None = None) -> list[dict[str, object]]:
    rows = [
        row for row in agent_proxy_cli._load_session_registry(account_id, root_dir=root_dir)
        if not bool(row.get("archived"))
    ]
    return [_ensure_codex_runtime_upgrade(row=row) for row in rows]


def _archive_registry_session(*, account_id: str, session_ref: str, root_dir: Path | None = None) -> bool:
    rows = agent_proxy_cli._load_session_registry(account_id, root_dir=root_dir)
    updated = []
    changed = False
    for row in rows:
        if str(row.get("session_id") or "") == session_ref or str(row.get("session_fingerprint") or "") == session_ref:
            updated.append({**row, "archived": True})
            changed = True
        else:
            updated.append(row)
    if changed:
        agent_proxy_cli._write_session_registry(account_id, updated, root_dir=root_dir)
    return changed


def perform_archive_session(*, account_id: str, session_ref: str, root_dir: Path | None = None) -> dict[str, object]:
    changed = _archive_registry_session(account_id=account_id, session_ref=session_ref, root_dir=root_dir)
    return {
        "ok": changed,
        "message": "Session moved to archive." if changed else "Session not found.",
    }

def build_sessions_payload(*, account_id: str, agent_filter: str = "all", root_dir: Path | None = None) -> dict[str, object]:
    registry_rows = _active_registry_rows(account_id, root_dir=root_dir)
    sessions = agent_proxy_cli._coalesce_supervise_sessions(
        sessions=aggregate_running_agents(detect_running_agents(agent_filter=agent_filter))
    )
    unmanaged = [
        item for item in sessions
        if agent_proxy_cli._registry_lookup(registry_rows=registry_rows, item=item) is None
    ]
    running = []
    session_cards: list[dict[str, object]] = []
    for item in sessions:
        matched = agent_proxy_cli._registry_lookup(registry_rows=registry_rows, item=item)
        if matched is None and str(item.get("agent_id") or "") == "codex":
            restored = _restore_monitored_codex_row_from_disk(
                account_id=account_id,
                session_id=_immutable_session_id(item),
                root_dir=root_dir,
            )
            if restored is not None:
                registry_rows = _active_registry_rows(account_id, root_dir=root_dir)
                matched = restored
        matched = _promote_registry_session_identity(account_id=account_id, registry_rows=registry_rows, matched=matched, item=item, root_dir=root_dir)
        _auto_route_monitored_session(matched)
        control_state = _control_state_from_registry(matched)
        ui_status = _ui_status(control_state, live=True, matched=matched is not None)
        started_at = str(item.get("started_at") or "-")
        last_seen_ts_ms = int((matched or {}).get("last_seen_ts_ms") or 0)
        last_seen_label = agent_proxy_cli._format_ts_label(last_seen_ts_ms) if last_seen_ts_ms else started_at
        capture_mode = str((matched or {}).get("capture_mode") or ("pending-handoff" if matched is None else "launcher-routed"))
        running.append({
            "agent_id": item.get("agent_id"),
            "session_fingerprint": item.get("session_fingerprint"),
            "path_hint": item.get("path_hint"),
            "started_at": started_at,
            "status": ui_status,
        })
        handoff_script_path, handoff_command = _upgrade_legacy_handoff_script(
            script_path=(matched or {}).get("handoff_script_path"),
            controlled_session_name=_resolve_controlled_session_name(matched),
        )
        session_cards.append({
            "key": str(item.get("session_fingerprint") or item.get("agent_id") or "running"),
            "session_ref": str((matched or {}).get("session_id") or _immutable_session_id(item) or item.get("session_fingerprint") or ""),
            "session_id": (matched or {}).get("session_id") or _immutable_session_id(item),
            "session_name": (matched or {}).get("session_name") or str(item.get("session_fingerprint") or item.get("agent_id") or "session"),
            "session_fingerprint": item.get("session_fingerprint"),
            "path_hint": item.get("path_hint"),
            "started_at": started_at,
            "last_seen_label": last_seen_label,
            "last_seen_ts_ms": last_seen_ts_ms or None,
            "agent_id": item.get("agent_id"),
            "status": ui_status,
            "control_state": control_state,
            "capture_mode": capture_mode,
            "attach_command": _attach_command_for_row(matched, item),
            "handoff_command": handoff_command or (matched or {}).get("handoff_command"),
            "handoff_script_path": handoff_script_path or (matched or {}).get("handoff_script_path"),
            "title": (matched or {}).get("session_name") or item.get("agent_id"),
            "live": True,
            "monitored": matched is not None,
            "can_prepare": bool(item.get("path_hint")) or str(item.get("agent_id") or "") == "codex",
            "live_state": "running",
        })
    live_monitored_ids = {str(card.get("session_id") or "") for card in session_cards if card.get("session_id")}
    for row in registry_rows:
        session_id = str(row.get("session_id") or "")
        if session_id and session_id in live_monitored_ids:
            continue
        last_seen_ts_ms = int(row.get("last_seen_ts_ms") or 0)
        handoff_script_path, handoff_command = _upgrade_legacy_handoff_script(
            script_path=row.get("handoff_script_path"),
            controlled_session_name=_resolve_controlled_session_name(row),
        )
        session_cards.append({
            "key": f"registry:{session_id or row.get('session_name') or row.get('agent_id')}",
            "session_ref": session_id,
            "session_id": row.get("session_id"),
            "session_name": row.get("session_name") or session_id or row.get("agent_id"),
            "session_fingerprint": row.get("session_fingerprint"),
            "path_hint": row.get("path_hint"),
            "started_at": "-",
            "last_seen_label": agent_proxy_cli._format_ts_label(last_seen_ts_ms) if last_seen_ts_ms else "-",
            "last_seen_ts_ms": last_seen_ts_ms or None,
            "agent_id": row.get("agent_id"),
            "status": _ui_status(_control_state_from_registry(row), live=False, matched=True),
            "control_state": _control_state_from_registry(row),
            "capture_mode": str(row.get("capture_mode") or "unknown"),
            "attach_command": _attach_command_for_row(row),
            "handoff_command": handoff_command or row.get("handoff_command"),
            "handoff_script_path": handoff_script_path or row.get("handoff_script_path"),
            "title": row.get("session_name") or session_id or row.get("agent_id"),
            "live": False,
            "monitored": True,
            "can_prepare": False,
            "live_state": "offline",
        })
    session_cards = _dedupe_session_cards(session_cards)
    config_path = agent_proxy_cli._default_account_config_path(account_id, root_dir=root_dir)
    service = {"label": "not-configured"}
    if config_path.exists():
        status_payload = invoke_cli_json(["service-status", str(config_path)])
        if status_payload.get("ok"):
            service = {"label": f"running={bool(status_payload.get('running'))} ping_ok={bool(status_payload.get('ping_ok'))}"}
        else:
            service = {"label": f"not-running ({status_payload.get('reason') or 'unknown'})"}
    return {
        "ok": True,
        "monitoring_status": agent_proxy_cli._summarize_monitoring_status(sessions),
        "monitored": [{"agent_id": row.get("agent_id"), "session_id": row.get("session_id"), "session_name": row.get("session_name") or row.get("session_id"), "path_hint": row.get("path_hint")} for row in registry_rows],
        "running": running,
        "unmanaged": [{"agent_id": item.get("agent_id"), "session_fingerprint": item.get("session_fingerprint"), "path_hint": item.get("path_hint"), "started_at": item.get("started_at")} for item in session_cards if item.get("live") and not item.get("monitored")],
        "session_cards": session_cards,
        "service": service,
    }

def _load_json_rows(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    if isinstance(payload, list):
        return [dict(row) for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        return [dict(row) for row in payload["rows"] if isinstance(row, dict)]
    return []


def _build_recovery_event_index(*, event_store_path: Path, session_id: str) -> dict[str, object]:
    verified_ids: set[str] = set()
    completed_ids: set[str] = set()
    failed_ids: set[str] = set()
    latest_ts_by_id: dict[str, int] = {}
    latest_success_ts_by_id: dict[str, int] = {}
    latest_failed_ts_by_id: dict[str, int] = {}
    latest_dangerous: dict[str, object] | None = None
    last_invoke: dict[str, object] | None = None
    for event in agent_proxy_cli._load_session_events(event_store_path=event_store_path, session_id=session_id):
        event_type = str(event.get("event_type") or "")
        payload = dict(event.get("payload", {}))
        timestamp_ms = int(event.get("timestamp_ms") or 0)
        if event_type == "ToolInvocationRequested":
            last_invoke = event
            continue
        if event_type == "RecoveryPlanned":
            latest_dangerous = {
                "timestamp_ms": timestamp_ms,
                "headline": f"{session_id}: dangerous command",
                "detail": agent_proxy_cli._command_summary_from_invoke(last_invoke or event),
            }
        recovery_id = str(payload.get("recovery_id") or "")
        if not recovery_id:
            continue
        latest_ts_by_id[recovery_id] = max(timestamp_ms, latest_ts_by_id.get(recovery_id, 0))
        if event_type == "RecoveryVerified" and bool(payload.get("verified", True)):
            verified_ids.add(recovery_id)
            latest_success_ts_by_id[recovery_id] = max(timestamp_ms, latest_success_ts_by_id.get(recovery_id, 0))
        elif event_type == "RecoveryCompleted":
            completed_ids.add(recovery_id)
            latest_success_ts_by_id[recovery_id] = max(timestamp_ms, latest_success_ts_by_id.get(recovery_id, 0))
        elif event_type == "RecoveryFailed":
            failed_ids.add(recovery_id)
            latest_failed_ts_by_id[recovery_id] = max(timestamp_ms, latest_failed_ts_by_id.get(recovery_id, 0))
    return {
        "verified_ids": verified_ids,
        "completed_ids": completed_ids,
        "failed_ids": failed_ids,
        "latest_ts_by_id": latest_ts_by_id,
        "latest_success_ts_by_id": latest_success_ts_by_id,
        "latest_failed_ts_by_id": latest_failed_ts_by_id,
        "latest_dangerous": latest_dangerous,
    }


def _build_evidence_payload(*, config_file: Path, recovery_ids: tuple[str, ...]) -> dict[str, object]:
    try:
        stored = agent_proxy_cli.load_agent_proxy_config(config_file)
    except Exception:  # noqa: BLE001
        return {}
    base_dir = getattr(stored, "base_dir", None)
    if not base_dir:
        return {}
    base_path = Path(str(base_dir)).expanduser()
    proxy_paths = AgentProxyPaths.from_base_dir(base_path)
    chain_paths = ClawChainPaths.from_root(
        proxy_paths.runtime_root,
        remote_root=proxy_paths.evidence_root,
        vault_root=proxy_paths.vault_root,
    )
    locator_rows = RecoveryCatalogStore(chain_paths.recovery_catalog_path).read_all()
    locator_by_id = {row.recovery_id: row for row in locator_rows}
    selected_locators = [locator_by_id[rid] for rid in recovery_ids if rid in locator_by_id]
    source_kinds = sorted({row.source_kind for row in selected_locators})
    snapshot_locations = [
        str(chain_paths.vault_root / row.recovery_id)
        for row in selected_locators
        if row.source_kind == "snapshot"
    ]
    git_recovery_ids = [row.recovery_id for row in selected_locators if row.source_kind == "git"]
    receipt_rows = _load_json_rows(chain_paths.receipt_store_path)
    submission_rows = _load_json_rows(chain_paths.submission_store_path)
    def _related(rows: list[dict[str, object]]) -> list[dict[str, object]]:
        out = []
        wanted = set(recovery_ids)
        for row in rows:
            subject_id = str(row.get("subject_id") or "")
            event_ids = {str(item) for item in row.get("event_ids", []) if item is not None}
            if subject_id in wanted or wanted.intersection(event_ids):
                out.append(row)
        return out
    related_receipts = _related(receipt_rows)
    related_submissions = _related(submission_rows)
    latest_receipt = related_receipts[-1] if related_receipts else (receipt_rows[-1] if receipt_rows else {})
    latest_submission = related_submissions[-1] if related_submissions else (submission_rows[-1] if submission_rows else {})
    metadata = dict(latest_receipt.get("metadata") or {})
    return {
        "config_path": str(config_file),
        "base_dir": str(base_path),
        "runtime_root": str(proxy_paths.runtime_root),
        "vault_root": str(proxy_paths.vault_root),
        "remote_root": str(proxy_paths.evidence_root),
        "recovery_catalog_path": str(chain_paths.recovery_catalog_path),
        "impact_catalog_path": str(chain_paths.recovery_impact_set_catalog_path),
        "receipt_store_path": str(chain_paths.receipt_store_path),
        "submission_store_path": str(chain_paths.submission_store_path),
        "source_kinds": source_kinds,
        "git_recovery_ids": git_recovery_ids,
        "snapshot_locations": snapshot_locations,
        "anchor_mode": latest_receipt.get("anchor_mode") or latest_submission.get("anchor_mode"),
        "anchor_backend": latest_receipt.get("anchor_backend") or latest_submission.get("anchor_backend"),
        "anchor_reference": latest_receipt.get("anchor_reference") or latest_submission.get("anchor_reference"),
        "encrypted_bundle_ref": metadata.get("encrypted_bundle_ref"),
    }


def build_history_payload(
    *,
    account_id: str,
    session_query: str | None = None,
    risk_filter: str | None = None,
    limit: int = 20,
    root_dir: Path | None = None,
) -> dict[str, object]:
    since_ms = None
    registry_rows = _active_registry_rows(account_id, root_dir=root_dir)
    if session_query is not None:
        needle = session_query.strip().lower()
        target_rows = [
            row for row in registry_rows
            if needle and (
                needle in str(row.get("session_id") or "").lower()
                or needle in str(row.get("session_name") or "").lower()
            )
        ]
    else:
        target_rows = [row for row in registry_rows if str(row.get("agent_id") or "") == "codex"]
    for row in target_rows:
        _backfill_codex_rollout_recovery(row=row)
    try:
        entries = agent_proxy_cli._collect_registry_review_entries(account_id=account_id, root_dir=root_dir)
    except TypeError:
        entries = agent_proxy_cli._collect_registry_review_entries(account_id=account_id)
    if session_query is not None:
        needle = session_query.strip().lower()
        if needle:
            entries = [
                row for row in entries
                if needle in str(row.get("session_id") or "").lower()
                or needle in str(row.get("session_name") or "").lower()
            ]
    entries = agent_proxy_cli._filter_registry_entries(
        entries=entries,
        risk_filter=risk_filter,
        since_ms=since_ms,
        limit=limit,
    )
    items = []
    for index, item in enumerate(entries, start=1):
        config_path = item.get("config_path")
        event_index = {
            "verified_ids": set(),
            "completed_ids": set(),
            "failed_ids": set(),
            "latest_ts_by_id": {},
            "latest_success_ts_by_id": {},
            "latest_failed_ts_by_id": {},
        }
        evidence = {}
        if config_path:
            config_file = Path(str(config_path))
            if config_file.exists():
                try:
                    stored = agent_proxy_cli.load_agent_proxy_config(config_file)
                    base_dir = getattr(stored, "base_dir", None)
                    if base_dir:
                        event_index = _build_recovery_event_index(
                            event_store_path=Path(str(base_dir)).expanduser() / "runtime" / "local" / "events.jsonl",
                            session_id=str(item.get("session_id") or ""),
                        )
                    evidence = _build_evidence_payload(
                        config_file=config_file,
                        recovery_ids=tuple(item.get("recovery_ids", ()) or ()),
                    )
                except Exception:  # noqa: BLE001
                    pass
        recovery_ids = tuple(item.get("recovery_ids", ()) or ())
        restored_ids = event_index["verified_ids"] | event_index["completed_ids"]
        failed_ids = event_index["failed_ids"]
        restored_count = sum(1 for rid in recovery_ids if rid in restored_ids)
        restored = restored_count > 0
        failed_count = sum(1 for rid in recovery_ids if rid in failed_ids)
        restore_failed = failed_count > 0 and not restored
        restored_ts_ms = max((int(event_index["latest_success_ts_by_id"].get(rid, 0)) for rid in recovery_ids), default=0)
        risk_reason = str(item.get("risk_reason") or "")
        risk_is_restorable = risk_restorable(risk_reason)
        items.append({
            "index": index,
            "session_id": item.get("session_id"),
            "session_name": item.get("session_name"),
            "impact_set_id": item.get("impact_set_id"),
            "time_label": agent_proxy_cli._format_ts_label(item.get("created_ts_ms")),
            "created_ts_ms": item.get("created_ts_ms"),
            "risk_reason": item.get("risk_reason"),
            "risk_label": risk_label(risk_reason),
            "risk_class": risk_class(risk_reason),
            "restorable": risk_is_restorable,
            "target_root": item.get("target_root"),
            "summary": agent_proxy_cli._natural_language_operation_summary(
                risk_reason=str(item.get("risk_reason") or ""),
                target_root=str(item.get("target_root") or ""),
            ),
            "recovery_count": len(recovery_ids),
            "config_path": item.get("config_path"),
            "restored": restored,
            "restored_count": restored_count,
            "restored_label": "restored" if restored else ("failed" if restore_failed else "available"),
            "restored_ts_ms": restored_ts_ms or None,
            "restored_ts_label": agent_proxy_cli._format_ts_label(restored_ts_ms) if restored_ts_ms else None,
            "restore_disabled": restored or (not risk_is_restorable) or len(recovery_ids) == 0,
            "evidence": evidence,
        })
    deduped_items: list[dict[str, object]] = []
    for item in items:
        deduped_items = _merge_history_rows(base=deduped_items, extra=[item])
    items = deduped_items
    registry_rows = _active_registry_rows(account_id, root_dir=root_dir)
    fallback_rows: list[dict[str, object]] = []
    if session_query is not None:
        needle = session_query.strip()
        target_rows = [
            row for row in registry_rows
            if needle and (needle == str(row.get('session_id') or '') or needle.lower() == str(row.get('session_name') or '').lower())
        ]
    else:
        target_rows = [row for row in registry_rows if str(row.get('agent_id') or '') == 'codex']
    for row in target_rows:
        session_id = str(row.get('session_id') or '')
        if not session_id or str(row.get('agent_id') or '') != 'codex':
            continue
        fallback_rows.extend(_collect_codex_sqlite_dangerous_history(
            session_id=session_id,
            session_name=str(row.get('session_name') or session_id),
            config_path=str(row.get('config_path') or '') or None,
            limit=max(limit, 20),
        ))
    items = _merge_history_rows(base=items, extra=fallback_rows)
    items.sort(key=lambda item: int(item.get('created_ts_ms') or 0), reverse=True)
    for index, item in enumerate(items, start=1):
        item['index'] = index
    return {"ok": True, "items": items[: max(limit, 0)]}


def build_activity_payload(*, account_id: str, root_dir: Path | None = None, limit: int = 12, session_id: str | None = None) -> dict[str, object]:
    registry_rows = _active_registry_rows(account_id, root_dir=root_dir)
    if session_id is not None:
        registry_rows = [row for row in registry_rows if str(row.get("session_id") or "") == session_id]
    items: list[dict[str, object]] = []
    for row in registry_rows:
        config_path = row.get("config_path")
        session_key = str(row.get("session_id") or "")
        if not config_path or not session_key:
            continue
        config_file = Path(str(config_path))
        if not config_file.exists():
            continue
        latest_item = None
        try:
            stored = agent_proxy_cli.load_agent_proxy_config(config_file)
            if stored.base_dir:
                event_index = _build_recovery_event_index(
                    event_store_path=Path(stored.base_dir).expanduser() / "runtime" / "local" / "events.jsonl",
                    session_id=session_key,
                )
                latest_dangerous = event_index.get("latest_dangerous")
                if latest_dangerous is not None:
                    latest_item = {
                        "timestamp_ms": int(latest_dangerous.get("timestamp_ms") or 0),
                        "headline": f"{row.get('session_name') or session_key}: dangerous command",
                        "detail": str(latest_dangerous.get("detail") or ""),
                    }
                latest_restore_ts = max(event_index.get("latest_success_ts_by_id", {}).values(), default=0)
                if latest_restore_ts and (latest_item is None or latest_restore_ts > int(latest_item.get("timestamp_ms") or 0)):
                    latest_item = {
                        "timestamp_ms": latest_restore_ts,
                        "headline": f"{row.get('session_name') or session_key}: restore verified",
                        "detail": "recovery path verified",
                    }
                latest_failed_ts = max(event_index.get("latest_failed_ts_by_id", {}).values(), default=0)
                if latest_failed_ts and (latest_item is None or latest_failed_ts > int(latest_item.get("timestamp_ms") or 0)):
                    latest_item = {
                        "timestamp_ms": latest_failed_ts,
                        "headline": f"{row.get('session_name') or session_key}: restore failed",
                        "detail": "recovery execution failed; retry is still available",
                    }
        except Exception:  # noqa: BLE001
            pass
        capture_mode = str(row.get("capture_mode") or "")
        pending_item = None
        if capture_mode in {"pending-relaunch", "pending-handoff"}:
            pending_item = {
                "timestamp_ms": int(row.get("last_seen_ts_ms") or 0),
                "headline": f"{row.get('session_name') or session_key}: waiting for controlled entry",
                "detail": "run the monitored handoff command to start dangerous-command capture",
            }
        chosen = latest_item
        if pending_item and (chosen is None or int(pending_item.get("timestamp_ms") or 0) > int(chosen.get("timestamp_ms") or 0)):
            chosen = pending_item
        if chosen is not None:
            items.append(chosen)
    if session_id is not None and not items:
        registry_rows = _active_registry_rows(account_id, root_dir=root_dir)
        matched = next((row for row in registry_rows if str(row.get('session_id') or '') == session_id and str(row.get('agent_id') or '') == 'codex'), None)
        if matched is not None:
            fallback = _collect_codex_sqlite_dangerous_history(
                session_id=session_id,
                session_name=str(matched.get('session_name') or session_id),
                config_path=str(matched.get('config_path') or '') or None,
                limit=1,
            )
            if fallback:
                item = fallback[0]
                items.append({
                    'timestamp_ms': int(item.get('created_ts_ms') or 0),
                    'headline': f"{matched.get('session_name') or session_id}: dangerous command",
                    'detail': str(item.get('summary') or item.get('target_root') or '-'),
                })
    items.sort(key=lambda item: int(item.get("timestamp_ms") or 0), reverse=True)
    return {"ok": True, "items": items[: max(limit, 0)]}


def build_session_detail_payload(*, account_id: str, session_ref: str, root_dir: Path | None = None) -> dict[str, object]:
    registry_rows = _active_registry_rows(account_id, root_dir=root_dir)
    sessions = agent_proxy_cli._coalesce_supervise_sessions(
        sessions=aggregate_running_agents(detect_running_agents(agent_filter="all"))
    )
    matched_registry = next((row for row in registry_rows if str(row.get("session_id") or "") == session_ref or str(row.get("session_fingerprint") or "") == session_ref), None)
    if matched_registry is None:
        restored = _restore_monitored_codex_row_from_disk(account_id=account_id, session_id=session_ref, root_dir=root_dir)
        if restored is not None:
            registry_rows = _active_registry_rows(account_id, root_dir=root_dir)
            matched_registry = restored
    matched_running = next((
        item for item in sessions
        if str(item.get("session_fingerprint") or "") == session_ref
        or _immutable_session_id(item) == session_ref
        or str((agent_proxy_cli._registry_lookup(registry_rows=registry_rows, item=item) or {}).get("session_id") or "") == session_ref
    ), None)
    matched_registry = _promote_registry_session_identity(account_id=account_id, registry_rows=registry_rows, matched=matched_registry, item=matched_running or {}, root_dir=root_dir)
    _auto_route_monitored_session(matched_registry)
    title = (matched_registry or {}).get("session_name") or _display_session_id((matched_running or {})) or session_ref
    history_items: list[dict[str, object]] = []
    activity_items: list[dict[str, object]] = []
    detail_evidence: dict[str, object] = {}
    session_id = str((matched_registry or {}).get("session_id") or "")
    if session_id:
        history_items = build_history_payload(account_id=account_id, session_query=session_id, limit=50, root_dir=root_dir).get("items", [])
        activity_items = build_activity_payload(account_id=account_id, root_dir=root_dir, limit=20, session_id=session_id).get("items", [])
    if history_items:
        detail_evidence = dict(history_items[0].get("evidence") or {})
    elif matched_registry:
        config_path = str((matched_registry or {}).get("config_path") or "")
        if config_path:
            detail_evidence = _build_evidence_payload(config_file=Path(config_path), recovery_ids=())
    started_at = str((matched_running or {}).get("started_at") or "-")
    last_seen_ts_ms = int((matched_registry or {}).get("last_seen_ts_ms") or 0)
    detail_handoff_script_path, detail_handoff_command = _upgrade_legacy_handoff_script(
        script_path=(matched_registry or {}).get("handoff_script_path"),
        controlled_session_name=_resolve_controlled_session_name(matched_registry),
    )
    return {
        "ok": True,
        "detail": {
            "title": title,
            "session_ref": session_ref,
            "session_name": (matched_registry or {}).get("session_name") or title,
            "session_id": session_id or (_immutable_session_id(matched_running or {}) or None),
            "session_fingerprint": (matched_registry or {}).get("session_fingerprint") or (matched_running or {}).get("session_fingerprint"),
            "path_hint": (matched_registry or {}).get("path_hint") or (matched_running or {}).get("path_hint"),
            "started_at": started_at,
            "last_seen_label": agent_proxy_cli._format_ts_label(last_seen_ts_ms) if last_seen_ts_ms else started_at,
            "capture_mode": str((matched_registry or {}).get("capture_mode") or ("pending-handoff" if matched_registry is None else "launcher-routed")),
            "control_state": _control_state_from_registry(matched_registry),
            "attach_command": _attach_command_for_row(matched_registry, matched_running),
            "resume_command": _monitored_resume_command(matched_registry, matched_running),
            "handoff_command": detail_handoff_command or (matched_registry or {}).get("handoff_command"),
            "handoff_script_path": detail_handoff_script_path or (matched_registry or {}).get("handoff_script_path"),
            "agent_id": (matched_registry or {}).get("agent_id") or (matched_running or {}).get("agent_id"),
            "status": _ui_status(_control_state_from_registry(matched_registry), live=matched_running is not None, matched=matched_registry is not None),
            "can_prepare": bool((matched_running or {}).get("path_hint")) or str((matched_registry or {}).get("agent_id") or (matched_running or {}).get("agent_id") or "") == "codex",
            "evidence": detail_evidence,
        },
        "history": history_items,
        "activity": activity_items,
    }

def invoke_cli_json(argv: list[str]) -> dict[str, object]:
    stdout = StringIO()
    with redirect_stdout(stdout):
        exit_code = agent_proxy_cli.main(argv)
    raw = stdout.getvalue().strip()
    if raw:
        try:
            payload = json.loads(raw)
        except Exception:  # noqa: BLE001
            payload = {"ok": exit_code == 0, "raw": raw}
    else:
        payload = {"ok": exit_code == 0}
    payload.setdefault("exit_code", exit_code)
    return payload




def _immutable_session_id(item: dict[str, object]) -> str:
    fingerprint = str(item.get("session_fingerprint") or "").strip()
    if fingerprint.startswith("resume:"):
        return fingerprint.split(":", 1)[1]
    if fingerprint:
        return fingerprint
    return str(item.get("agent_id") or "session")


def _display_session_id(row: dict[str, object]) -> str:
    session_id = str(row.get("session_id") or "").strip()
    if session_id:
        return session_id
    fingerprint = str(row.get("session_fingerprint") or "").strip()
    if fingerprint.startswith("resume:"):
        return fingerprint.split(":", 1)[1]
    return fingerprint or "-"


def _ui_status(control_state: str, *, live: bool, matched: bool) -> str:
    if not matched:
        return "unmanaged"
    if control_state in {"attached", "routed"}:
        return "monitored"
    if control_state == "pending":
        return "pending" if live else "prepared"
    return "monitored" if live else "prepared"


def _sortable_session_ts(row: dict[str, object]) -> int:
    raw = row.get("last_seen_ts_ms")
    if raw:
        try:
            return int(raw)
        except Exception:
            pass
    started = str(row.get("started_at") or "").strip()
    if not started or started == "-":
        return 0
    try:
        import time as _time
        return int(_time.mktime(_time.strptime(started, "%a %b %d %H:%M:%S %Y")) * 1000)
    except Exception:
        return 0

def _dedupe_session_cards(cards: list[dict[str, object]]) -> list[dict[str, object]]:
    chosen: dict[str, dict[str, object]] = {}
    for row in cards:
        key = str(row.get("session_id") or row.get("session_fingerprint") or row.get("key") or "")
        if not key:
            key = str(row.get("key") or id(row))
        current = chosen.get(key)
        if current is None:
            chosen[key] = row
            continue
        current_score = (
            1 if current.get("live") else 0,
            1 if current.get("path_hint") else 0,
            1 if current.get("monitored") else 0,
            _sortable_session_ts(current),
        )
        new_score = (
            1 if row.get("live") else 0,
            1 if row.get("path_hint") else 0,
            1 if row.get("monitored") else 0,
            _sortable_session_ts(row),
        )
        if new_score > current_score:
            chosen[key] = row
    rows = list(chosen.values())
    rows.sort(key=lambda row: (not bool(row.get("live")), -_sortable_session_ts(row), str(row.get("session_name") or "")))
    return rows

def perform_prepare_monitor_script(
    *,
    account_id: str,
    password: str,
    session_fingerprint: str,
    session_name: str | None = None,
    agent_filter: str = "all",
    root_dir: Path | None = None,
    no_start_service: bool = False,
) -> dict[str, object]:
    sessions = agent_proxy_cli._coalesce_supervise_sessions(
        sessions=aggregate_running_agents(detect_running_agents(agent_filter=agent_filter))
    )
    picked = next((item for item in sessions if str(item.get("session_fingerprint") or "") == session_fingerprint or _immutable_session_id(item) == session_fingerprint), None)
    if picked is None:
        return {"ok": False, "error": f"session not found: {session_fingerprint}"}
    chosen_name = session_name.strip() if session_name else ""
    if not chosen_name:
        chosen_name = f"{picked['agent_id']}-{str(picked.get('session_fingerprint') or 'session').replace(':', '-')}"
    git_context_mode = agent_proxy_cli._auto_select_git_context_mode(item=picked)
    prepared = agent_proxy_cli._prepare_detected_sessions(
        sessions=[picked],
        account_id=account_id,
        password=password,
        root_dir=root_dir,
        no_start_service=no_start_service,
        git_context_mode=git_context_mode,
        session_id_override=_immutable_session_id(picked),
    )
    for result in prepared:
        result["session_name"] = chosen_name
        result["capture_mode"] = "pending-handoff" if no_start_service else "rollout-observed"
        script_path, handoff_command = _build_handoff_script(item=picked, prepared_item=result)
        if script_path:
            result["handoff_script_path"] = script_path
            result["handoff_command"] = handoff_command
    now_ms = int(__import__("time").time() * 1000)
    for result in prepared:
        result["last_seen_ts_ms"] = now_ms
    agent_proxy_cli._persist_prepared_sessions(
        account_id=account_id,
        prepared=prepared,
        root_dir=root_dir,
        fallback_items={
            str(result.get("session_id") or ""): {
                "agent_id": picked.get("agent_id"),
                "session_name": chosen_name,
                "session_fingerprint": picked.get("session_fingerprint"),
                "path_hint": picked.get("path_hint"),
                "capture_mode": result.get("capture_mode"),
                "handoff_command": result.get("handoff_command"),
                "handoff_script_path": result.get("handoff_script_path"),
            }
            for result in prepared
        },
    )
    primary = prepared[0] if prepared else {}
    script_path = primary.get("handoff_script_path")
    handoff_command = primary.get("handoff_command")
    if not script_path or not handoff_command:
        reason = str(primary.get("reason") or "handoff_unavailable")
        reason_map = {
            "path_hint_unavailable": "This session does not expose enough context to prepare a monitored handoff script yet.",
            "handoff_unavailable": "ClawChain could not generate a controlled handoff script for this session.",
        }
        return {
            "ok": True,
            "message": reason_map.get(reason, reason_map["handoff_unavailable"]),
            "prepared": prepared,
            "script_path": None,
            "handoff_command": None,
            "script_body": None,
            "reason": reason,
        }
    return {
        "ok": True,
        "message": f"Prepared monitored handoff for {chosen_name}.",
        "prepared": prepared,
        "script_path": script_path,
        "handoff_command": handoff_command,
        "script_body": Path(script_path).read_text(encoding="utf-8"),
    }


def perform_rename_session(
    *,
    account_id: str,
    session_ref: str,
    session_name: str,
    root_dir: Path | None = None,
) -> dict[str, object]:
    registry_rows = agent_proxy_cli._load_session_registry(account_id, root_dir=root_dir)
    updated = False
    for row in registry_rows:
        if str(row.get("session_id") or "") == session_ref or str(row.get("session_fingerprint") or "") == session_ref:
            row["session_name"] = session_name.strip() or str(row.get("session_name") or row.get("session_id") or "session")
            row["last_seen_ts_ms"] = int(__import__("time").time() * 1000)
            updated = True
            break
    if not updated:
        return {"ok": False, "error": f"session not found: {session_ref}"}
    agent_proxy_cli._write_session_registry(account_id, registry_rows, root_dir=root_dir)
    return {"ok": True, "message": f"Session renamed to {session_name}"}


def perform_update_session_id(
    *,
    account_id: str,
    session_ref: str,
    session_id: str,
    root_dir: Path | None = None,
) -> dict[str, object]:
    registry_rows = agent_proxy_cli._load_session_registry(account_id, root_dir=root_dir)
    updated = False
    for row in registry_rows:
        if str(row.get("session_id") or "") == session_ref or str(row.get("session_fingerprint") or "") == session_ref:
            row["session_id"] = session_id.strip() or str(row.get("session_id") or row.get("session_fingerprint") or "session")
            row["last_seen_ts_ms"] = int(__import__("time").time() * 1000)
            updated = True
            break
    if not updated:
        return {"ok": False, "error": f"session not found: {session_ref}"}
    agent_proxy_cli._write_session_registry(account_id, registry_rows, root_dir=root_dir)
    return {"ok": True, "message": f"Session updated to {session_id}"}


def perform_onboard(
    *,
    account_id: str,
    password: str,
    session_fingerprint: str,
    session_name: str | None = None,
    agent_filter: str = "all",
    root_dir: Path | None = None,
    no_start_service: bool = False,
) -> dict[str, object]:
    sessions = agent_proxy_cli._coalesce_supervise_sessions(
        sessions=aggregate_running_agents(detect_running_agents(agent_filter=agent_filter))
    )
    picked = next((item for item in sessions if str(item.get("session_fingerprint") or "") == session_fingerprint or _immutable_session_id(item) == session_fingerprint), None)
    if picked is None:
        return {"ok": False, "error": f"session not found: {session_fingerprint}"}
    chosen_name = session_name.strip() if session_name else ""
    if not chosen_name:
        chosen_name = f"{picked['agent_id']}-{str(picked.get('session_fingerprint') or 'session').replace(':', '-')}"
    git_context_mode = agent_proxy_cli._auto_select_git_context_mode(item=picked)
    prepared = agent_proxy_cli._prepare_detected_sessions(
        sessions=[picked],
        account_id=account_id,
        password=password,
        root_dir=root_dir,
        no_start_service=no_start_service,
        git_context_mode=git_context_mode,
        session_id_override=_immutable_session_id(picked),
    )
    for result in prepared:
        result["session_name"] = chosen_name
        result["capture_mode"] = "pending-handoff" if no_start_service else "rollout-observed"
        if str(picked.get("agent_id")) == "codex" and result.get("prepared_payload") is not None:
            script_path, handoff_command = _build_handoff_script(item=picked, prepared_item=result)
            if script_path:
                result["handoff_script_path"] = script_path
                result["handoff_command"] = handoff_command
    agent_proxy_cli._persist_prepared_sessions(
        account_id=account_id,
        prepared=prepared,
        root_dir=root_dir,
        fallback_items={
            str(result.get("session_id") or ""): {
                "agent_id": picked.get("agent_id"),
                "session_name": chosen_name,
                "session_fingerprint": picked.get("session_fingerprint"),
                "path_hint": picked.get("path_hint"),
                "capture_mode": result.get("capture_mode"),
            }
            for result in prepared
        },
    )
    return {
        "ok": True,
        "message": f"Session {chosen_name} entered monitoring without reopening terminals.",
        "prepared": prepared,
    }


def _auto_session_name(item: dict[str, object], existing_names: set[str]) -> str:
    base = str(item.get("path_hint") or "").strip()
    if base:
        candidate = Path(base).name or Path(base).parent.name or "session"
    else:
        candidate = str(item.get("session_fingerprint") or item.get("agent_id") or "session")
    candidate = candidate.replace(":", "-").replace("/", "-").replace(" ", "-").strip("-") or "session"
    original = candidate
    suffix = 2
    while candidate in existing_names:
        candidate = f"{original}-{suffix}"
        suffix += 1
    existing_names.add(candidate)
    return candidate


def perform_auto_onboard(
    *,
    account_id: str,
    password: str,
    agent_filter: str = "all",
    root_dir: Path | None = None,
    no_start_service: bool = False,
) -> dict[str, object]:
    registry_rows = agent_proxy_cli._load_session_registry(account_id, root_dir=root_dir)
    sessions = agent_proxy_cli._coalesce_supervise_sessions(
        sessions=aggregate_running_agents(detect_running_agents(agent_filter=agent_filter))
    )
    unmanaged = [
        item for item in sessions
        if agent_proxy_cli._registry_lookup(registry_rows=registry_rows, item=item) is None
    ]
    if not unmanaged:
        return {"ok": True, "count": 0, "prepared": [], "message": "No unmanaged sessions detected."}
    existing_names = {
        str(row.get("session_name") or row.get("session_id") or "")
        for row in registry_rows
        if str(row.get("session_name") or row.get("session_id") or "")
    }
    prepared_all: list[dict[str, object]] = []
    fallback_items: dict[str, dict[str, object]] = {}
    for item in unmanaged:
        chosen_name = _auto_session_name(item, existing_names)
        git_context_mode = agent_proxy_cli._auto_select_git_context_mode(item=item)
        prepared = agent_proxy_cli._prepare_detected_sessions(
            sessions=[item],
            account_id=account_id,
            password=password,
            root_dir=root_dir,
            no_start_service=no_start_service,
            git_context_mode=git_context_mode,
            session_id_override=_immutable_session_id(item),
        )
        for result in prepared:
            result["session_name"] = chosen_name
            result["capture_mode"] = "pending-handoff" if no_start_service else "rollout-observed"
            if str(item.get("agent_id")) == "codex" and result.get("prepared_payload") is not None:
                script_path, handoff_command = _build_handoff_script(item=item, prepared_item=result)
                if script_path:
                    result["handoff_script_path"] = script_path
                    result["handoff_command"] = handoff_command
            prepared_all.append(result)
            fallback_items[str(result.get("session_id") or "")] = {
                "agent_id": item.get("agent_id"),
                "session_name": chosen_name,
                "session_fingerprint": item.get("session_fingerprint"),
                "path_hint": item.get("path_hint"),
                "capture_mode": result.get("capture_mode"),
            }
    agent_proxy_cli._persist_prepared_sessions(
        account_id=account_id,
        prepared=prepared_all,
        root_dir=root_dir,
        fallback_items=fallback_items,
    )
    return {
        "ok": True,
        "count": len(prepared_all),
        "prepared": prepared_all,
        "message": f"Automatically enrolled {len(prepared_all)} session(s).",
    }


def perform_join_monitor(*, account_id: str, password: str, session_fingerprint: str, session_name: str | None = None, agent_filter: str = 'all', root_dir: Path | None = None, no_start_service: bool = False) -> dict[str, object]:
    result = perform_onboard(
        account_id=account_id,
        password=password,
        session_fingerprint=session_fingerprint,
        session_name=session_name,
        agent_filter=agent_filter,
        root_dir=root_dir,
        no_start_service=no_start_service,
    )
    prepared = list(result.get('prepared') or [])
    primary = prepared[0] if prepared else {}
    result['joined'] = bool(prepared)
    script_path = str(primary.get('handoff_script_path') or '')
    if script_path and Path(script_path).exists():
        result['script_path'] = script_path
        result['handoff_command'] = primary.get('handoff_command')
        result['script_body'] = Path(script_path).read_text(encoding='utf-8')
    if primary.get('attach_command'):
        result['attach_command'] = primary.get('attach_command')
    if not result.get('ok'):
        registry_rows = agent_proxy_cli._load_session_registry(account_id, root_dir=root_dir)
        matched = next((row for row in registry_rows if str(row.get('session_id') or '') == session_fingerprint or str(row.get('session_fingerprint') or '') == session_fingerprint), None)
        if matched is not None:
            result = {
                'ok': True,
                'joined': True,
                'prepared': prepared,
                'message': f"Session {matched.get('session_name') or matched.get('session_id') or session_fingerprint} is already monitored.",
                'attach_command': matched.get('attach_command'),
                'handoff_command': matched.get('handoff_command'),
                'script_path': matched.get('handoff_script_path'),
            }
    result['message'] = result.get('message') or ('Joined monitor.' if result.get('joined') else 'Monitor join unavailable.')
    return result



class ClawChainUIHandler(BaseHTTPRequestHandler):
    server_version = "ClawChainUI/0.1"

    def _send_json(self, payload: dict[str, object], *, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=True, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/":
            self._send_html(render_index_html())
            return
        if parsed.path == "/api/agents":
            self._send_json({
                "ok": True,
                "agents": [{"agent_id": row.agent_id, "display_name": row.display_name} for row in list_known_agents()],
            })
            return
        if parsed.path == "/api/sessions":
            account_id = _resolve_ui_account_id((query.get("account") or [None])[0])
            root_dir = _parse_root_dir((query.get("root_dir") or [None])[0])
            agent_filter = (query.get("agent") or ["all"])[0]
            payload = build_sessions_payload(
                account_id=account_id,
                agent_filter=agent_filter,
                root_dir=root_dir,
            )
            self._send_json(payload)
            return
        if parsed.path == "/api/history":
            account_id = _resolve_ui_account_id((query.get("account") or [None])[0])
            try:
                limit = int((query.get("limit") or ["20"])[0])
            except ValueError:
                self._send_json({"ok": False, "error": "limit must be an integer"}, status=400)
                return
            try:
                payload = build_history_payload(
                    account_id=account_id,
                    session_query=(query.get("session") or [None])[0],
                    risk_filter=(query.get("risk") or [None])[0],
                    limit=limit,
                    root_dir=_parse_root_dir((query.get("root_dir") or [None])[0]),
                )
            except Exception as exc:  # noqa: BLE001
                self._send_json({"ok": False, "error": str(exc)}, status=400)
                return
            self._send_json(payload)
            return
        if parsed.path == "/api/activity":
            account_id = _resolve_ui_account_id((query.get("account") or [None])[0])
            try:
                limit = int((query.get("limit") or ["12"])[0])
            except ValueError:
                self._send_json({"ok": False, "error": "limit must be an integer"}, status=400)
                return
            payload = build_activity_payload(
                account_id=account_id,
                root_dir=_parse_root_dir((query.get("root_dir") or [None])[0]),
                limit=limit,
            )
            self._send_json(payload)
            return
        if parsed.path == "/api/session-detail":
            account_id = _resolve_ui_account_id((query.get("account") or [None])[0])
            session_ref = (query.get("session_ref") or [""])[0]
            if not session_ref:
                self._send_json({"ok": False, "error": "session_ref is required"}, status=400)
                return
            payload = build_session_detail_payload(
                account_id=account_id,
                session_ref=session_ref,
                root_dir=_parse_root_dir((query.get("root_dir") or [None])[0]),
            )
            self._send_json(payload)
            return
        self._send_json({"ok": False, "error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        raw_len = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(raw_len) or b"{}")
        if parsed.path == "/api/deploy":
            account_id = _resolve_ui_account_id(payload.get("account"))
            password = _resolve_ui_password(payload.get("password"))
            argv = [
                "deploy",
                account_id,
                password,
                "--no-start-service" if bool(payload.get("no_start_service", True)) else "",
            ]
            root_dir = payload.get("root_dir")
            if root_dir:
                argv.extend(["--root-dir", str(root_dir)])
            argv = [part for part in argv if part]
            self._send_json(invoke_cli_json(argv))
            return
        if parsed.path == "/api/prepare-monitor-script":
            account_id = _resolve_ui_account_id(payload.get("account"))
            password = _resolve_ui_password(payload.get("password"))
            session_fingerprint = str(payload.get("session_fingerprint") or "")
            if not session_fingerprint:
                self._send_json({"ok": False, "error": "session_fingerprint is required"}, status=400)
                return
            result = perform_prepare_monitor_script(
                account_id=account_id,
                password=password,
                session_fingerprint=session_fingerprint,
                session_name=(payload.get("session_name") or None),
                agent_filter=str(payload.get("agent") or "all"),
                root_dir=_parse_root_dir(payload.get("root_dir")),
                no_start_service=bool(payload.get("no_start_service", False)),
            )
            self._send_json(result, status=200 if result.get("ok") else 400)
            return
        if parsed.path == "/api/join-monitor":
            account_id = _resolve_ui_account_id(payload.get("account"))
            password = _resolve_ui_password(payload.get("password"))
            session_fingerprint = str(payload.get("session_fingerprint") or "")
            if not session_fingerprint:
                self._send_json({"ok": False, "error": "session_fingerprint is required"}, status=400)
                return
            result = perform_join_monitor(
                account_id=account_id,
                password=password,
                session_fingerprint=session_fingerprint,
                session_name=(payload.get("session_name") or None),
                agent_filter=str(payload.get("agent") or "all"),
                root_dir=_parse_root_dir(payload.get("root_dir")),
                no_start_service=bool(payload.get("no_start_service", False)),
            )
            self._send_json(result, status=200 if result.get("ok") else 400)
            return

        if parsed.path == "/api/onboard":
            account_id = _resolve_ui_account_id(payload.get("account"))
            password = _resolve_ui_password(payload.get("password"))
            session_fingerprint = str(payload.get("session_fingerprint") or "")
            if not session_fingerprint:
                self._send_json({"ok": False, "error": "session_fingerprint is required"}, status=400)
                return
            result = perform_onboard(
                account_id=account_id,
                password=password,
                session_fingerprint=session_fingerprint,
                session_name=(payload.get("session_name") or None),
                agent_filter=str(payload.get("agent") or "all"),
                root_dir=_parse_root_dir(payload.get("root_dir")),
                no_start_service=bool(payload.get("no_start_service", False)),
            )
            self._send_json(result, status=200 if result.get("ok") else 400)
            return
        if parsed.path == "/api/archive-session":
            account_id = _resolve_ui_account_id(payload.get("account"))
            session_ref = str(payload.get("session_ref") or "")
            if not session_ref:
                self._send_json({"ok": False, "error": "session_ref is required"}, status=400)
                return
            result = perform_archive_session(
                account_id=account_id,
                session_ref=session_ref,
                root_dir=_parse_root_dir(payload.get("root_dir")),
            )
            self._send_json(result, status=200 if result.get("ok") else 404)
            return
        if parsed.path == "/api/rename-session":
            account_id = _resolve_ui_account_id(payload.get("account"))
            session_ref = str(payload.get("session_ref") or "")
            session_name = str(payload.get("session_name") or "")
            if not session_ref or not session_name.strip():
                self._send_json({"ok": False, "error": "session_ref and session_name are required"}, status=400)
                return
            result = perform_rename_session(
                account_id=account_id,
                session_ref=session_ref,
                session_name=session_name,
                root_dir=_parse_root_dir(payload.get("root_dir")),
            )
            self._send_json(result, status=200 if result.get("ok") else 400)
            return
        if parsed.path == "/api/auto-monitor":
            account_id = _resolve_ui_account_id(payload.get("account"))
            password = _resolve_ui_password(payload.get("password"))
            result = perform_auto_onboard(
                account_id=account_id,
                password=password,
                agent_filter=str(payload.get("agent") or "all"),
                root_dir=_parse_root_dir(payload.get("root_dir")),
                no_start_service=bool(payload.get("no_start_service", False)),
            )
            self._send_json(result, status=200 if result.get("ok") else 400)
            return
        if parsed.path == "/api/update-session-id":
            account_id = _resolve_ui_account_id(payload.get("account"))
            session_ref = str(payload.get("session_ref") or "")
            session_id = str(payload.get("session_id") or "")
            if not session_ref or not session_id.strip():
                self._send_json({"ok": False, "error": "session_ref and session_id are required"}, status=400)
                return
            result = perform_update_session_id(
                account_id=account_id,
                session_ref=session_ref,
                session_id=session_id,
                root_dir=_parse_root_dir(payload.get("root_dir")),
            )
            self._send_json(result, status=200 if result.get("ok") else 400)
            return
        if parsed.path == "/api/export-proof-log":
            account_id = _resolve_ui_account_id(payload.get("account"))
            session_ref = str(payload.get("session_ref") or "")
            if not session_ref:
                self._send_json({"ok": False, "error": "session_ref is required"}, status=400)
                return
            result = export_readable_proof_log(
                account_id=account_id,
                session_ref=session_ref,
                root_dir=_parse_root_dir(payload.get("root_dir")),
            )
            self._send_json(result, status=200 if result.get("ok") else 400)
            return
        if parsed.path == "/api/restore":
            account_id = _resolve_ui_account_id(payload.get("account"))
            session_id = str(payload.get("session_id") or "")
            pick = payload.get("pick")
            impact_set_id = str(payload.get("impact_set_id") or "")
            root_dir = _parse_root_dir(payload.get("root_dir"))
            if not session_id or pick is None:
                self._send_json({"ok": False, "error": "session_id and pick are required"}, status=400)
                return
            registry_rows = _active_registry_rows(account_id, root_dir=root_dir)
            explicit_config_path = str(payload.get("config_path") or "")
            matched_row = next((row for row in registry_rows if str(row.get("session_id") or "") == session_id), None)
            config_path = Path(explicit_config_path) if explicit_config_path else Path(str((matched_row or {}).get("config_path") or agent_proxy_cli._default_account_config_path(account_id, root_dir=root_dir)))
            if not config_path.exists():
                self._send_json({"ok": False, "error": "session config not found"}, status=404)
                return
            if impact_set_id:
                argv = [
                    "recover-impact-set-latest",
                    str(config_path),
                    session_id,
                    "--impact-set-id",
                    impact_set_id,
                ]
            else:
                argv = [
                    "restore",
                    "--config",
                    str(config_path),
                    "--session",
                    session_id,
                    "--pick",
                    str(int(pick)),
                ]
            if bool(payload.get("approve", True)):
                argv.append("--approve")
            self._send_json(invoke_cli_json(argv))
            return
        self._send_json({"ok": False, "error": "not found"}, status=404)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return None


def main(argv: list[str] | None = None) -> int:
    args = list(argv or [])
    host = "127.0.0.1"
    port = 8765
    index = 0
    while index < len(args):
        if args[index] == "--host" and index + 1 < len(args):
            host = str(args[index + 1]); index += 2; continue
        if args[index] == "--port" and index + 1 < len(args):
            port = int(args[index + 1]); index += 2; continue
        print(f"unknown option: {args[index]}")
        return 2
    server = ThreadingHTTPServer((host, port), ClawChainUIHandler)
    print(f"[clawchain] UI available at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()


__all__ = [
    "build_activity_payload",
    "build_history_payload",
    "build_session_detail_payload",
    "build_sessions_payload",
    "ClawChainUIHandler",
    "invoke_cli_json",
    "perform_auto_onboard",
    "main",
    "perform_onboard",
    "render_index_html",
]
