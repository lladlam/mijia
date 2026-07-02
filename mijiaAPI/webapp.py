import base64
import binascii
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from secrets import compare_digest
from typing import Any, Optional
from urllib import parse

import requests

from .apis import get_default_auth_path, mijiaAPI
from .devices import get_device_info, mijiaDevice
from .errors import APIError, DeviceActionError, DeviceGetError, DeviceSetError, LoginError
from .logger import logger


INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Mijia Web Console</title>
  <style>
    :root {
      --bg: #0e1116;
      --panel: rgba(255, 255, 255, 0.05);
      --panel-strong: rgba(255, 255, 255, 0.08);
      --line: rgba(255, 255, 255, 0.12);
      --text: #f3f5f7;
      --muted: #9fa8b3;
      --accent: #d2f268;
      --accent-soft: rgba(210, 242, 104, 0.12);
      --danger: #ff8c82;
      --radius: 22px;
      --shadow: 0 20px 50px rgba(0, 0, 0, 0.35);
      --mono: "Cascadia Code", "SFMono-Regular", Consolas, monospace;
      --serif: "Georgia", "Times New Roman", serif;
      --sans: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: var(--sans);
      background:
        radial-gradient(circle at top left, rgba(210, 242, 104, 0.12), transparent 32%),
        radial-gradient(circle at top right, rgba(104, 167, 242, 0.08), transparent 28%),
        linear-gradient(180deg, #0b0f14 0%, #11161d 100%);
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
      background-size: 28px 28px;
      mask-image: linear-gradient(180deg, rgba(0, 0, 0, 0.7), transparent);
    }

    .page {
      width: min(1480px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 28px 0 48px;
    }

    .hero {
      display: grid;
      grid-template-columns: 1.3fr 0.9fr;
      gap: 18px;
      margin-bottom: 18px;
    }

    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      backdrop-filter: blur(16px);
    }

    .hero-main,
    .hero-side,
    .section {
      padding: 24px;
    }

    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      letter-spacing: 0.08em;
      text-transform: uppercase;
      font-size: 12px;
    }

    h1, h2, h3 {
      margin: 0;
      font-family: var(--serif);
      font-weight: 600;
      letter-spacing: 0.01em;
    }

    h1 {
      font-size: clamp(34px, 6vw, 64px);
      line-height: 0.98;
      margin-top: 18px;
      max-width: 10ch;
    }

    .hero-copy {
      margin-top: 16px;
      max-width: 58ch;
      color: var(--muted);
      line-height: 1.75;
      font-size: 15px;
    }

    .hero-meta {
      margin-top: 22px;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }

    .stat {
      padding: 14px 16px;
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .stat-label {
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 6px;
    }

    .stat-value {
      font-size: 19px;
      font-family: var(--mono);
    }

    .hero-side {
      display: flex;
      flex-direction: column;
      gap: 14px;
      justify-content: space-between;
      min-height: 100%;
    }

    .side-title {
      font-size: 18px;
      margin-bottom: 10px;
    }

    .side-copy {
      color: var(--muted);
      line-height: 1.7;
      font-size: 14px;
    }

    .actions {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .pill,
    button,
    select,
    input,
    textarea {
      font: inherit;
    }

    button,
    .pill {
      border: 0;
      cursor: pointer;
      border-radius: 999px;
      padding: 12px 16px;
      transition: transform 0.18s ease, opacity 0.18s ease, background 0.18s ease;
    }

    button:hover,
    .pill:hover {
      transform: translateY(-1px);
    }

    .primary {
      background: var(--accent);
      color: #10140b;
      font-weight: 600;
    }

    .secondary {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }

    .danger {
      background: rgba(255, 140, 130, 0.12);
      color: var(--danger);
      border: 1px solid rgba(255, 140, 130, 0.18);
    }

    .layout {
      display: grid;
      grid-template-columns: 360px minmax(0, 1fr);
      gap: 18px;
      align-items: start;
    }

    .sidebar,
    .content {
      display: flex;
      flex-direction: column;
      gap: 18px;
    }

    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: start;
      gap: 12px;
      margin-bottom: 18px;
    }

    .section-copy {
      color: var(--muted);
      line-height: 1.65;
      max-width: 52ch;
      font-size: 14px;
    }

    .login-wrap {
      display: grid;
      grid-template-columns: 1fr 260px;
      gap: 18px;
      align-items: center;
    }

    .qr-box {
      min-height: 260px;
      border-radius: 24px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px dashed rgba(255, 255, 255, 0.16);
      display: grid;
      place-items: center;
      overflow: hidden;
    }

    .qr-box img {
      width: 100%;
      height: auto;
      display: block;
      background: white;
    }

    .status-banner {
      padding: 14px 16px;
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.09);
      color: var(--muted);
      line-height: 1.65;
    }

    .status-banner.ok {
      color: var(--accent);
      background: rgba(210, 242, 104, 0.08);
      border-color: rgba(210, 242, 104, 0.18);
    }

    .status-banner.error {
      color: var(--danger);
      background: rgba(255, 140, 130, 0.08);
      border-color: rgba(255, 140, 130, 0.18);
    }

    .stack {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .search {
      width: 100%;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px;
      padding: 13px 14px;
      outline: none;
    }

    .search::placeholder {
      color: #7f8893;
    }

    .device-list,
    .scene-list,
    .prop-list,
    .action-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .quick-remote-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }

    .remote-shell {
      position: relative;
      overflow: hidden;
      border-radius: 28px;
      padding: 22px;
      margin-bottom: 18px;
      background:
        radial-gradient(circle at top left, rgba(210, 242, 104, 0.14), transparent 34%),
        radial-gradient(circle at bottom right, rgba(84, 126, 255, 0.10), transparent 38%),
        linear-gradient(180deg, rgba(255, 255, 255, 0.06), rgba(255, 255, 255, 0.03));
      border: 1px solid rgba(255, 255, 255, 0.1);
    }

    .remote-screen {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 14px;
      margin-bottom: 16px;
    }

    .remote-display {
      min-height: 180px;
      padding: 18px;
      border-radius: 24px;
      background:
        linear-gradient(180deg, rgba(9, 13, 17, 0.96), rgba(16, 24, 30, 0.9));
      border: 1px solid rgba(210, 242, 104, 0.14);
      box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.03);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    .remote-eyebrow {
      color: var(--accent);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .remote-temp {
      display: flex;
      align-items: end;
      gap: 10px;
      font-family: var(--serif);
      line-height: 0.9;
    }

    .remote-temp-value {
      font-size: clamp(56px, 8vw, 94px);
    }

    .remote-temp-unit {
      margin-bottom: 10px;
      font-size: 18px;
      color: var(--muted);
    }

    .remote-status-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }

    .remote-chip {
      padding: 12px 14px;
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .remote-chip-label {
      margin-bottom: 6px;
      color: var(--muted);
      font-size: 12px;
    }

    .remote-chip-value {
      font-family: var(--mono);
      font-size: 15px;
    }

    .remote-ops {
      display: grid;
      gap: 14px;
    }

    .remote-power {
      min-height: 88px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 17px;
      font-weight: 600;
      border-radius: 24px;
    }

    .remote-power.off {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text);
    }

    .remote-temp-pad {
      display: grid;
      grid-template-columns: 1fr 132px 1fr;
      gap: 10px;
      align-items: stretch;
    }

    .remote-pad-btn {
      min-height: 88px;
      border-radius: 24px;
      font-size: 30px;
      font-weight: 400;
    }

    .remote-pad-center {
      border-radius: 24px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      display: grid;
      place-items: center;
      text-align: center;
      padding: 8px;
    }

    .remote-pad-label {
      color: var(--muted);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .remote-pad-value {
      font-family: var(--serif);
      font-size: 32px;
      margin-top: 6px;
    }

    .remote-sections {
      display: grid;
      gap: 14px;
    }

    .remote-section {
      padding: 16px;
      border-radius: 22px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .remote-section-title {
      margin-bottom: 12px;
      color: var(--muted);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .remote-choice-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(124px, 1fr));
      gap: 10px;
    }

    .remote-choice {
      min-height: 64px;
      padding: 10px 12px;
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.05);
      color: var(--text);
      border: 1px solid rgba(255, 255, 255, 0.08);
      text-align: left;
    }

    .remote-choice.active {
      background: rgba(210, 242, 104, 0.14);
      border-color: rgba(210, 242, 104, 0.38);
      color: var(--accent);
    }

    .remote-choice-value {
      display: block;
      font-family: var(--mono);
      font-size: 12px;
      opacity: 0.82;
      margin-bottom: 6px;
    }

    .remote-choice-label {
      display: block;
      font-size: 14px;
      line-height: 1.3;
    }

    .remote-toggle-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(148px, 1fr));
      gap: 10px;
    }

    .remote-toggle {
      min-height: 60px;
      padding: 12px 14px;
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: var(--text);
      text-align: left;
    }

    .remote-toggle.active {
      background: rgba(210, 242, 104, 0.14);
      border-color: rgba(210, 242, 104, 0.38);
      color: var(--accent);
    }

    .remote-toggle-title {
      display: block;
      font-size: 14px;
      margin-bottom: 6px;
    }

    .remote-toggle-state {
      display: block;
      font-size: 12px;
      color: inherit;
      opacity: 0.86;
    }

    .toolbar-compact {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
    }

    .toolbar-label {
      color: var(--muted);
      font-size: 13px;
    }

    .device-card,
    .scene-card,
    .prop-card,
    .action-card {
      border-radius: 18px;
      padding: 16px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .device-card.active {
      border-color: rgba(210, 242, 104, 0.4);
      background: rgba(210, 242, 104, 0.08);
    }

    .device-top,
    .scene-top,
    .prop-top {
      display: flex;
      justify-content: space-between;
      align-items: start;
      gap: 12px;
      margin-bottom: 10px;
    }

    .device-name,
    .scene-name,
    .prop-name {
      font-size: 16px;
    }

    .muted {
      color: var(--muted);
    }

    .tiny {
      font-size: 12px;
      line-height: 1.6;
    }

    .mono {
      font-family: var(--mono);
    }

    .tags {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 12px;
    }

    .tag {
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.06);
      color: var(--muted);
      font-size: 12px;
    }

    .two-col {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 18px;
    }

    .prop-controls {
      margin-top: 14px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
    }

    .field,
    .select,
    .number {
      width: 100%;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 14px;
      padding: 12px 14px;
      outline: none;
    }

    .checkbox-line {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-top: 14px;
      padding: 12px 14px;
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .empty {
      padding: 26px 18px;
      border-radius: 18px;
      border: 1px dashed rgba(255, 255, 255, 0.14);
      color: var(--muted);
      text-align: center;
      line-height: 1.7;
    }

    .toolbar {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
    }

    .hidden {
      display: none !important;
    }

    @media (max-width: 1100px) {
      .hero,
      .layout,
      .login-wrap,
      .two-col {
        grid-template-columns: 1fr;
      }
      .remote-screen {
        grid-template-columns: 1fr;
      }
      .remote-temp-pad {
        grid-template-columns: 1fr 110px 1fr;
      }
      .page {
        width: min(100vw - 20px, 1480px);
      }
    }
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <div class="panel hero-main">
        <div class="eyebrow">Mijia Local Console</div>
        <h1>本地端口打开后，直接在网页里控制米家设备。</h1>
        <div class="hero-copy">
          这个页面运行在你的本机，只封装当前仓库已有的米家 API 能力。首次使用先扫码登录，登录后可查看设备、执行场景、读取属性并直接控制空调等常见设备。
        </div>
        <div class="hero-meta">
          <div class="stat">
            <div class="stat-label">本地地址</div>
            <div class="stat-value mono" id="metaOrigin">-</div>
          </div>
          <div class="stat">
            <div class="stat-label">认证状态</div>
            <div class="stat-value" id="metaAuth">检查中</div>
          </div>
          <div class="stat">
            <div class="stat-label">设备数量</div>
            <div class="stat-value mono" id="metaDeviceCount">-</div>
          </div>
        </div>
      </div>
      <div class="panel hero-side">
        <div>
          <h2 class="side-title">当前服务</h2>
          <div class="side-copy" id="serverInfo">
            正在初始化本地服务状态。
          </div>
        </div>
        <div class="actions">
          <button class="primary" id="refreshAllBtn">刷新全部</button>
          <button class="secondary" id="showLoginBtn">扫码登录</button>
        </div>
      </div>
    </section>

    <div class="layout">
      <aside class="sidebar">
        <section class="panel section" id="loginSection">
          <div class="section-header">
            <div>
              <h2>扫码登录</h2>
              <div class="section-copy">点击开始后，会生成米家 App 扫码二维码。登录成功后会自动保存认证信息，下次打开优先复用。</div>
            </div>
          </div>
          <div class="login-wrap">
            <div class="stack">
              <div class="toolbar">
                <button class="primary" id="startLoginBtn">开始扫码</button>
                <a class="pill secondary hidden" id="openQrLink" target="_blank" rel="noreferrer">打开二维码原图</a>
              </div>
              <div class="status-banner" id="loginStatus">尚未开始登录。</div>
            </div>
            <div class="qr-box" id="qrBox">
              <div class="muted tiny">二维码将显示在这里</div>
            </div>
          </div>
        </section>

        <section class="panel section">
          <div class="section-header">
            <div>
              <h2>设备列表</h2>
              <div class="section-copy">先选择设备，再在右侧查看可读属性、可写属性和动作。空调类设备通常会显示开关、模式、温度、风速等常见项。</div>
            </div>
          </div>
          <input class="search" id="deviceSearch" placeholder="搜索设备名 / 型号 / 房间">
          <div class="device-list" id="deviceList">
            <div class="empty">登录后会加载设备列表。</div>
          </div>
        </section>
      </aside>

      <main class="content">
        <section class="panel section">
          <div class="section-header">
            <div>
              <h2>场景</h2>
              <div class="section-copy">这里可以直接运行米家手动场景，适合“回家模式”“睡眠模式”“关闭所有空调”等预设操作。</div>
            </div>
          </div>
          <div class="scene-list" id="sceneList">
            <div class="empty">登录后会加载场景列表。</div>
          </div>
        </section>

        <section class="panel section" id="deviceDetailSection">
          <div class="section-header">
            <div>
              <h2 id="detailTitle">设备详情</h2>
              <div class="section-copy" id="detailCopy">选择左侧设备后，这里会显示属性和动作。</div>
            </div>
            <div class="toolbar">
              <div class="toolbar-compact hidden" id="pollToolbar">
                <span class="toolbar-label">轮询刷新</span>
                <select class="select" id="pollIntervalSelect" style="width: 110px; padding: 10px 12px;">
                  <option value="3000">3 秒</option>
                  <option value="5000" selected>5 秒</option>
                  <option value="10000">10 秒</option>
                  <option value="15000">15 秒</option>
                </select>
                <button class="secondary" id="togglePollBtn">开启轮询</button>
              </div>
              <button class="secondary hidden" id="refreshDeviceBtn">刷新当前设备</button>
            </div>
          </div>
          <div>
            <h3 style="margin-bottom: 12px;">主动遥控器</h3>
            <div class="quick-remote-grid" id="quickRemotePanel">
              <div class="empty" style="grid-column: 1 / -1;">尚未选择设备。</div>
            </div>
          </div>
          <div class="two-col">
            <div>
              <h3 style="margin-bottom: 12px;">属性</h3>
              <div class="prop-list" id="propList">
                <div class="empty">尚未选择设备。</div>
              </div>
            </div>
            <div>
              <h3 style="margin-bottom: 12px;">动作</h3>
              <div class="action-list" id="actionList">
                <div class="empty">尚未选择设备。</div>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  </div>

  <script>
    const state = {
      status: null,
      devices: [],
      scenes: [],
      selectedDid: null,
      selectedDetail: null,
      loginSessionId: null,
      loginPollTimer: null,
      devicePollTimer: null,
      pollEnabled: false,
      pollMs: 5000,
      postChangeRefreshToken: 0,
      detailRequestToken: 0,
    };

    const els = {
      metaOrigin: document.getElementById("metaOrigin"),
      metaAuth: document.getElementById("metaAuth"),
      metaDeviceCount: document.getElementById("metaDeviceCount"),
      serverInfo: document.getElementById("serverInfo"),
      loginStatus: document.getElementById("loginStatus"),
      qrBox: document.getElementById("qrBox"),
      openQrLink: document.getElementById("openQrLink"),
      startLoginBtn: document.getElementById("startLoginBtn"),
      refreshAllBtn: document.getElementById("refreshAllBtn"),
      showLoginBtn: document.getElementById("showLoginBtn"),
      deviceSearch: document.getElementById("deviceSearch"),
      deviceList: document.getElementById("deviceList"),
      sceneList: document.getElementById("sceneList"),
      detailTitle: document.getElementById("detailTitle"),
      detailCopy: document.getElementById("detailCopy"),
      quickRemotePanel: document.getElementById("quickRemotePanel"),
      propList: document.getElementById("propList"),
      actionList: document.getElementById("actionList"),
      refreshDeviceBtn: document.getElementById("refreshDeviceBtn"),
      pollToolbar: document.getElementById("pollToolbar"),
      pollIntervalSelect: document.getElementById("pollIntervalSelect"),
      togglePollBtn: document.getElementById("togglePollBtn"),
      loginSection: document.getElementById("loginSection"),
    };

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"]/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
      }[char]));
    }

    async function api(path, options = {}) {
      const response = await fetch(path, {
        headers: { "Content-Type": "application/json" },
        ...options,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.error || data.message || "请求失败");
      }
      return data;
    }

    function setBanner(message, type = "") {
      els.loginStatus.textContent = message;
      els.loginStatus.className = "status-banner" + (type ? " " + type : "");
    }

    function setQr(url, linkUrl) {
      if (!url) {
        els.qrBox.innerHTML = '<div class="muted tiny">二维码将显示在这里</div>';
        els.openQrLink.classList.add("hidden");
        els.openQrLink.removeAttribute("href");
        return;
      }
      els.qrBox.innerHTML = `<img src="${escapeHtml(url)}" alt="米家登录二维码">`;
      els.openQrLink.href = linkUrl || url;
      els.openQrLink.classList.remove("hidden");
    }

    function updateMeta() {
      els.metaOrigin.textContent = window.location.origin;
      els.metaAuth.textContent = state.status?.authenticated ? "已登录" : "未登录";
      els.metaDeviceCount.textContent = String(state.devices.length || 0);
      const authPath = state.status?.auth_path || "生产模式已隐藏";
      const authText = state.status?.authenticated ? "当前认证可用。" : "当前未登录或认证失效。";
      const modeText = state.status?.production_mode ? "生产模式" : "开发模式";
      els.serverInfo.innerHTML = `
        ${authText}<br>
        认证文件: <span class="mono">${escapeHtml(authPath)}</span><br>
        服务模式: <span class="mono">${escapeHtml(modeText)}</span><br>
        本地接口: <span class="mono">${escapeHtml(window.location.origin)}</span>
      `;
    }

    function renderDevices() {
      const keyword = els.deviceSearch.value.trim().toLowerCase();
      const list = state.devices.filter((item) => {
        const haystack = `${item.name} ${item.model} ${item.home_name || ""}`.toLowerCase();
        return !keyword || haystack.includes(keyword);
      });

      if (!list.length) {
        els.deviceList.innerHTML = `<div class="empty">${state.status?.authenticated ? "没有匹配设备。" : "登录后会加载设备列表。"}</div>`;
        return;
      }

      els.deviceList.innerHTML = list.map((item) => `
        <button class="device-card secondary ${item.did === state.selectedDid ? "active" : ""}" data-did="${escapeHtml(item.did)}">
          <div class="device-top">
            <div>
              <div class="device-name">${escapeHtml(item.name)}</div>
              <div class="tiny muted mono">${escapeHtml(item.model)}</div>
            </div>
            <div class="tag">${item.isOnline ? "在线" : "离线"}</div>
          </div>
          <div class="tiny muted">家庭: ${escapeHtml(item.home_name || item.home_id || "-")}</div>
          <div class="tiny muted mono">did: ${escapeHtml(item.did)}</div>
        </button>
      `).join("");

      document.querySelectorAll("[data-did]").forEach((button) => {
        button.addEventListener("click", () => selectDevice(button.dataset.did));
      });
    }

    function renderScenes() {
      if (!state.scenes.length) {
        els.sceneList.innerHTML = `<div class="empty">${state.status?.authenticated ? "当前没有可用场景。" : "登录后会加载场景列表。"}</div>`;
        return;
      }
      els.sceneList.innerHTML = state.scenes.map((scene) => `
        <div class="scene-card">
          <div class="scene-top">
            <div>
              <div class="scene-name">${escapeHtml(scene.name)}</div>
              <div class="tiny muted">家庭: ${escapeHtml(scene.home_name || scene.home_id || "-")}</div>
            </div>
            <button class="primary run-scene-btn" data-scene-id="${escapeHtml(scene.scene_id)}">运行场景</button>
          </div>
          <div class="tiny muted mono">scene_id: ${escapeHtml(scene.scene_id)}</div>
        </div>
      `).join("");

      document.querySelectorAll(".run-scene-btn").forEach((button) => {
        button.addEventListener("click", async () => {
          try {
            button.disabled = true;
            await api("/api/scenes/run", {
              method: "POST",
              body: JSON.stringify({ scene_id: button.dataset.sceneId }),
            });
            setBanner("场景执行成功。", "ok");
          } catch (error) {
            setBanner(error.message, "error");
          } finally {
            button.disabled = false;
          }
        });
      });
    }

    function buildInput(prop) {
      const value = prop.current_value;

      if (prop.type === "bool") {
        return `
          <label class="checkbox-line">
            <span>${value ? "已开启" : "已关闭"}</span>
            <input type="checkbox" class="prop-bool" data-prop="${escapeHtml(prop.name)}" ${value ? "checked" : ""}>
          </label>
        `;
      }

      if (prop.value_list && prop.value_list.length) {
        const options = prop.value_list.map((item) => `
          <option value="${escapeHtml(item.value)}" ${String(item.value) === String(value) ? "selected" : ""}>
            ${escapeHtml(item.value)} · ${escapeHtml(item.desc_zh_cn || item.description)}
          </option>
        `).join("");
        return `
          <div class="prop-controls">
            <select class="select prop-select" data-prop="${escapeHtml(prop.name)}">${options}</select>
            <button class="primary prop-save-btn" data-prop="${escapeHtml(prop.name)}">设置</button>
          </div>
        `;
      }

      if (prop.type === "int" || prop.type === "uint" || prop.type === "float") {
        const step = Array.isArray(prop.range) && prop.range.length >= 3 ? prop.range[2] : (prop.type === "float" ? "0.1" : "1");
        const min = Array.isArray(prop.range) && prop.range.length >= 1 ? `min="${prop.range[0]}"` : "";
        const max = Array.isArray(prop.range) && prop.range.length >= 2 ? `max="${prop.range[1]}"` : "";
        return `
          <div class="prop-controls">
            <input class="number prop-input" type="number" ${min} ${max} step="${step}" value="${value ?? ""}" data-prop="${escapeHtml(prop.name)}">
            <button class="primary prop-save-btn" data-prop="${escapeHtml(prop.name)}">设置</button>
          </div>
        `;
      }

      return `
        <div class="prop-controls">
          <input class="field prop-input" type="text" value="${escapeHtml(value ?? "")}" data-prop="${escapeHtml(prop.name)}">
          <button class="primary prop-save-btn" data-prop="${escapeHtml(prop.name)}">设置</button>
        </div>
      `;
    }

    function buildQuickRemoteInput(prop) {
      const value = prop.current_value;

      if (prop.type === "bool") {
        return `
          <label class="checkbox-line">
            <span>${value ? "已开启" : "已关闭"}</span>
            <input type="checkbox" class="quick-bool" data-prop="${escapeHtml(prop.name)}" ${value ? "checked" : ""}>
          </label>
        `;
      }

      if (prop.value_list && prop.value_list.length) {
        const options = prop.value_list.map((item) => `
          <option value="${escapeHtml(item.value)}" ${String(item.value) === String(value) ? "selected" : ""}>
            ${escapeHtml(item.value)} · ${escapeHtml(item.desc_zh_cn || item.description)}
          </option>
        `).join("");
        return `
          <div class="prop-controls">
            <select class="select quick-select" data-prop="${escapeHtml(prop.name)}">${options}</select>
            <button class="primary quick-save-btn" data-prop="${escapeHtml(prop.name)}">设置</button>
          </div>
        `;
      }

      if (prop.type === "int" || prop.type === "uint" || prop.type === "float") {
        const step = Array.isArray(prop.range) && prop.range.length >= 3 ? prop.range[2] : (prop.type === "float" ? "0.1" : "1");
        const min = Array.isArray(prop.range) && prop.range.length >= 1 ? `min="${prop.range[0]}"` : "";
        const max = Array.isArray(prop.range) && prop.range.length >= 2 ? `max="${prop.range[1]}"` : "";
        return `
          <div class="prop-controls">
            <input class="number quick-input" type="number" ${min} ${max} step="${step}" value="${value ?? ""}" data-prop="${escapeHtml(prop.name)}">
            <button class="primary quick-save-btn" data-prop="${escapeHtml(prop.name)}">设置</button>
          </div>
        `;
      }

      return `
        <div class="prop-controls">
          <input class="field quick-input" type="text" value="${escapeHtml(value ?? "")}" data-prop="${escapeHtml(prop.name)}">
          <button class="primary quick-save-btn" data-prop="${escapeHtml(prop.name)}">设置</button>
        </div>
      `;
    }

    function getQuickRemoteProps(detail) {
      const preferredOrder = [
        "on",
        "mode",
        "target-temperature",
        "fan-level",
        "fan-percent",
        "vertical-swing",
        "wind-direction",
        "vertical-position",
        "eco",
        "heater",
        "dryer",
        "sleep-mode",
        "favorite-on",
      ];
      const propertyMap = new Map((detail.properties || []).map((item) => [item.name, item]));
      return preferredOrder
        .map((name) => propertyMap.get(name))
        .filter((item) => item && item.writable);
    }

    function getProp(detail, name) {
      return (detail?.properties || []).find((item) => item.name === name);
    }

    function getValueLabel(prop, fallback = "-") {
      if (!prop) return fallback;
      if (prop.current_error) return prop.current_error;
      if (prop.value_list && prop.value_list.length) {
        const match = prop.value_list.find((item) => String(item.value) === String(prop.current_value));
        if (match) {
          return match.desc_zh_cn || match.description || String(prop.current_value);
        }
      }
      if (prop.type === "bool") {
        return prop.current_value ? "开启" : "关闭";
      }
      if (prop.current_value === undefined || prop.current_value === null || prop.current_value === "") {
        return fallback;
      }
      return String(prop.current_value);
    }

    function formatTemperatureValue(prop) {
      if (!prop || prop.current_value === undefined || prop.current_value === null || prop.current_error) {
        return "--";
      }
      const numeric = Number(prop.current_value);
      if (Number.isNaN(numeric)) {
        return String(prop.current_value);
      }
      return Number.isInteger(numeric) ? String(numeric) : numeric.toFixed(1);
    }

    function getDisplayName(prop, fallback) {
      if (!prop) return fallback;
      const desc = prop.description || fallback || prop.name;
      return desc.split("/").pop().trim() || fallback || prop.name;
    }

    function hasRemoteProfile(detail) {
      return Boolean(getProp(detail, "on") && (getProp(detail, "target-temperature") || getProp(detail, "mode")));
    }

    async function setSteppedProperty(propName, delta) {
      const prop = state.selectedDetail?.properties?.find((item) => item.name === propName);
      if (!prop) return;
      const base = Number(prop.current_value);
      if (Number.isNaN(base)) {
        throw new Error(`属性 ${propName} 当前值不可用于步进调整`);
      }
      const step = Array.isArray(prop.range) && prop.range.length >= 3 ? Number(prop.range[2]) : 1;
      const min = Array.isArray(prop.range) && prop.range.length >= 1 ? Number(prop.range[0]) : undefined;
      const max = Array.isArray(prop.range) && prop.range.length >= 2 ? Number(prop.range[1]) : undefined;
      let nextValue = base + delta * (Number.isNaN(step) ? 1 : step);
      if (min !== undefined) nextValue = Math.max(min, nextValue);
      if (max !== undefined) nextValue = Math.min(max, nextValue);
      if (prop.type === "int" || prop.type === "uint") {
        nextValue = Math.round(nextValue);
      } else if (prop.type === "float") {
        nextValue = Number(nextValue.toFixed(1));
      }
      await savePropertyValue(propName, nextValue, `已调整 ${propName}。`);
    }

    function renderQuickRemote(detail) {
      if (!detail) {
        els.quickRemotePanel.innerHTML = `<div class="empty" style="grid-column: 1 / -1;">尚未选择设备。</div>`;
        return;
      }

      if (hasRemoteProfile(detail)) {
        const powerProp = getProp(detail, "on");
        const modeProp = getProp(detail, "mode");
        const targetTempProp = getProp(detail, "target-temperature");
        const fanProp = getProp(detail, "fan-level") || getProp(detail, "fan-percent");
        const swingProp = getProp(detail, "vertical-swing");
        const windProp = getProp(detail, "wind-direction");
        const ecoProp = getProp(detail, "eco");
        const heaterProp = getProp(detail, "heater");
        const dryerProp = getProp(detail, "dryer");
        const sleepProp = getProp(detail, "sleep-mode");
        const currentTempProp = getProp(detail, "temperature");

        const modeButtons = modeProp?.value_list?.length ? modeProp.value_list.map((item) => `
          <button
            class="remote-choice ${String(item.value) === String(modeProp.current_value) ? "active" : ""}"
            data-remote-prop="${escapeHtml(modeProp.name)}"
            data-remote-value="${escapeHtml(item.value)}"
          >
            <span class="remote-choice-value">${escapeHtml(item.value)}</span>
            <span class="remote-choice-label">${escapeHtml(item.desc_zh_cn || item.description || item.value)}</span>
          </button>
        `).join("") : `<div class="empty">当前设备未提供模式枚举。</div>`;

        const fanButtons = fanProp?.value_list?.length ? fanProp.value_list.map((item) => `
          <button
            class="remote-choice ${String(item.value) === String(fanProp.current_value) ? "active" : ""}"
            data-remote-prop="${escapeHtml(fanProp.name)}"
            data-remote-value="${escapeHtml(item.value)}"
          >
            <span class="remote-choice-value">${escapeHtml(item.value)}</span>
            <span class="remote-choice-label">${escapeHtml(item.desc_zh_cn || item.description || item.value)}</span>
          </button>
        `).join("") : `<div class="empty">当前设备未提供风速枚举。</div>`;

        const toggleProps = [swingProp, windProp ? null : null, ecoProp, heaterProp, dryerProp, sleepProp]
          .filter(Boolean);

        const boolToggles = [swingProp, ecoProp, heaterProp, dryerProp, sleepProp]
          .filter((item) => item && item.type === "bool")
          .map((prop) => `
            <button
              class="remote-toggle ${prop.current_value ? "active" : ""}"
              data-remote-prop="${escapeHtml(prop.name)}"
              data-remote-bool="${prop.current_value ? "false" : "true"}"
            >
              <span class="remote-toggle-title">${escapeHtml(getDisplayName(prop, prop.name))}</span>
              <span class="remote-toggle-state">${prop.current_value ? "已开启" : "已关闭"}</span>
            </button>
          `).join("");

        const windChoices = windProp?.value_list?.length ? `
          <div class="remote-section">
            <div class="remote-section-title">${escapeHtml(getDisplayName(windProp, "风感"))}</div>
            <div class="remote-choice-grid">
              ${windProp.value_list.map((item) => `
                <button
                  class="remote-choice ${String(item.value) === String(windProp.current_value) ? "active" : ""}"
                  data-remote-prop="${escapeHtml(windProp.name)}"
                  data-remote-value="${escapeHtml(item.value)}"
                >
                  <span class="remote-choice-value">${escapeHtml(item.value)}</span>
                  <span class="remote-choice-label">${escapeHtml(item.desc_zh_cn || item.description || item.value)}</span>
                </button>
              `).join("")}
            </div>
          </div>
        ` : "";

        els.quickRemotePanel.innerHTML = `
          <div class="remote-shell" style="grid-column: 1 / -1;">
            <div class="remote-screen">
              <div class="remote-display">
                <div>
                  <div class="remote-eyebrow">AC Remote</div>
                  <div class="tiny muted" style="margin-top: 8px;">${escapeHtml(detail.name)}</div>
                </div>
                <div class="remote-temp">
                  <div class="remote-temp-value">${escapeHtml(formatTemperatureValue(targetTempProp))}</div>
                  <div class="remote-temp-unit">°C</div>
                </div>
                <div class="remote-status-grid">
                  <div class="remote-chip">
                    <div class="remote-chip-label">当前模式</div>
                    <div class="remote-chip-value">${escapeHtml(getValueLabel(modeProp))}</div>
                  </div>
                  <div class="remote-chip">
                    <div class="remote-chip-label">风速</div>
                    <div class="remote-chip-value">${escapeHtml(getValueLabel(fanProp))}</div>
                  </div>
                  <div class="remote-chip">
                    <div class="remote-chip-label">开关状态</div>
                    <div class="remote-chip-value">${escapeHtml(getValueLabel(powerProp))}</div>
                  </div>
                  <div class="remote-chip">
                    <div class="remote-chip-label">环境温度</div>
                    <div class="remote-chip-value">${escapeHtml(formatTemperatureValue(currentTempProp))}°C</div>
                  </div>
                </div>
              </div>
              <div class="remote-ops">
                <button
                  class="remote-power ${powerProp?.current_value ? "primary" : "secondary off"}"
                  data-remote-prop="on"
                  data-remote-bool="${powerProp?.current_value ? "false" : "true"}"
                >
                  ${powerProp?.current_value ? "关闭空调" : "开启空调"}
                </button>
                <div class="remote-temp-pad">
                  <button class="secondary remote-pad-btn" data-remote-step="target-temperature" data-remote-delta="-1">-</button>
                  <div class="remote-pad-center">
                    <div class="remote-pad-label">设定温度</div>
                    <div class="remote-pad-value">${escapeHtml(formatTemperatureValue(targetTempProp))}°</div>
                  </div>
                  <button class="primary remote-pad-btn" data-remote-step="target-temperature" data-remote-delta="1">+</button>
                </div>
              </div>
            </div>
            <div class="remote-sections">
              <div class="remote-section">
                <div class="remote-section-title">${escapeHtml(getDisplayName(modeProp, "模式"))}</div>
                <div class="remote-choice-grid">${modeButtons}</div>
              </div>
              <div class="remote-section">
                <div class="remote-section-title">${escapeHtml(getDisplayName(fanProp, "风速"))}</div>
                <div class="remote-choice-grid">${fanButtons}</div>
              </div>
              ${windChoices}
              <div class="remote-section">
                <div class="remote-section-title">快捷开关</div>
                <div class="remote-toggle-grid">
                  ${boolToggles || '<div class="empty" style="grid-column: 1 / -1;">当前设备没有可显示的快捷开关。</div>'}
                </div>
              </div>
            </div>
          </div>
        `;
        return;
      }

      const quickProps = getQuickRemoteProps(detail);
      if (!quickProps.length) {
        els.quickRemotePanel.innerHTML = `<div class="empty" style="grid-column: 1 / -1;">当前设备没有可生成的快捷遥控项。</div>`;
        return;
      }

      els.quickRemotePanel.innerHTML = quickProps.map((prop) => `
        <div class="prop-card">
          <div class="prop-top">
            <div>
              <div class="prop-name">${escapeHtml(prop.name)}</div>
              <div class="tiny muted">${escapeHtml(prop.description || "无描述")}</div>
            </div>
            <div class="tag">${escapeHtml(prop.rw || "-")}</div>
          </div>
          <div class="tags">
            <div class="tag">当前值: ${escapeHtml(prop.current_error ? prop.current_error : prop.current_value)}</div>
          </div>
          ${buildQuickRemoteInput(prop)}
        </div>
      `).join("");
    }

    function renderPollingState() {
      if (!state.selectedDetail) {
        els.pollToolbar.classList.add("hidden");
        return;
      }
      els.pollToolbar.classList.remove("hidden");
      els.pollIntervalSelect.value = String(state.pollMs);
      els.togglePollBtn.textContent = state.pollEnabled ? "关闭轮询" : "开启轮询";
    }

    function stopDevicePolling() {
      if (state.devicePollTimer) {
        clearInterval(state.devicePollTimer);
        state.devicePollTimer = null;
      }
    }

    function startDevicePolling() {
      stopDevicePolling();
      if (!state.pollEnabled || !state.selectedDid) {
        return;
      }
      state.devicePollTimer = setInterval(async () => {
        if (!state.selectedDid || !state.status?.authenticated) {
          return;
        }
        try {
          await loadDeviceDetail(state.selectedDid, { silent: true });
        } catch (error) {
          console.error(error);
        }
      }, state.pollMs);
    }

    function schedulePostChangeRefresh() {
      const token = ++state.postChangeRefreshToken;
      setTimeout(async () => {
        if (token !== state.postChangeRefreshToken || !state.selectedDid) {
          return;
        }
        try {
          await loadDeviceDetail(state.selectedDid, { silent: true });
        } catch (error) {
          console.error(error);
        }
      }, 1800);
    }

    async function savePropertyValue(propName, value, successMessage) {
      await api("/api/device/property", {
        method: "POST",
        body: JSON.stringify({
          did: state.selectedDid,
          prop_name: propName,
          value,
        }),
      });
      setBanner(successMessage || `已设置 ${propName}。`, "ok");
      await loadDeviceDetail(state.selectedDid, { silent: true });
      schedulePostChangeRefresh();
    }

    function renderDetail() {
      const detail = state.selectedDetail;
      if (!detail) {
        els.detailTitle.textContent = "设备详情";
        els.detailCopy.textContent = "选择左侧设备后，这里会显示属性和动作。";
        els.quickRemotePanel.innerHTML = `<div class="empty" style="grid-column: 1 / -1;">尚未选择设备。</div>`;
        els.propList.innerHTML = `<div class="empty">尚未选择设备。</div>`;
        els.actionList.innerHTML = `<div class="empty">尚未选择设备。</div>`;
        els.refreshDeviceBtn.classList.add("hidden");
        renderPollingState();
        return;
      }

      els.refreshDeviceBtn.classList.remove("hidden");
      els.detailTitle.textContent = detail.name;
      els.detailCopy.textContent = `${detail.model} | did: ${detail.did}`;
      renderQuickRemote(detail);
      renderPollingState();

      const props = detail.properties || [];
      if (!props.length) {
        els.propList.innerHTML = `<div class="empty">该设备没有可展示的属性。</div>`;
      } else {
        els.propList.innerHTML = props.map((prop) => `
          <div class="prop-card">
            <div class="prop-top">
              <div>
                <div class="prop-name">${escapeHtml(prop.name)}</div>
                <div class="tiny muted">${escapeHtml(prop.description || "无描述")}</div>
              </div>
              <div class="tag">${escapeHtml(prop.rw || "-")}</div>
            </div>
            <div class="tiny muted mono">
              type: ${escapeHtml(prop.type || "-")}
              ${Array.isArray(prop.range) ? ` | range: ${escapeHtml(prop.range.join(" / "))}` : ""}
            </div>
            <div class="tags">
              <div class="tag">当前值: ${escapeHtml(prop.current_error ? prop.current_error : prop.current_value)}</div>
            </div>
            ${prop.writable ? buildInput(prop) : '<div class="tiny muted" style="margin-top: 14px;">此属性只读，不能在网页中设置。</div>'}
          </div>
        `).join("");
      }

      const actions = detail.actions || [];
      if (!actions.length) {
        els.actionList.innerHTML = `<div class="empty">该设备没有可执行动作。</div>`;
      } else {
        els.actionList.innerHTML = actions.map((action) => `
          <div class="action-card">
            <div class="prop-top">
              <div>
                <div class="prop-name">${escapeHtml(action.name)}</div>
                <div class="tiny muted">${escapeHtml(action.description || "无描述")}</div>
              </div>
              <button class="primary action-run-btn" data-action="${escapeHtml(action.name)}">执行</button>
            </div>
          </div>
        `).join("");
      }

      document.querySelectorAll(".prop-save-btn").forEach((button) => {
        button.addEventListener("click", () => saveProperty(button.dataset.prop));
      });

      document.querySelectorAll(".prop-bool").forEach((input) => {
        input.addEventListener("change", () => saveProperty(input.dataset.prop, input.checked));
      });

      document.querySelectorAll(".quick-save-btn").forEach((button) => {
        button.addEventListener("click", () => saveQuickProperty(button.dataset.prop));
      });

      document.querySelectorAll(".quick-bool").forEach((input) => {
        input.addEventListener("change", () => savePropertyValue(input.dataset.prop, input.checked, `已设置 ${input.dataset.prop}。`));
      });

      document.querySelectorAll("[data-remote-prop][data-remote-value]").forEach((button) => {
        button.addEventListener("click", () => {
          const propName = button.getAttribute("data-remote-prop");
          const prop = state.selectedDetail?.properties?.find((item) => item.name === propName);
          if (!prop) return;
          let value = button.getAttribute("data-remote-value");
          if (prop.type === "int" || prop.type === "uint") value = Number.parseInt(value, 10);
          if (prop.type === "float") value = Number.parseFloat(value);
          savePropertyValue(propName, value, `已设置 ${propName}。`);
        });
      });

      document.querySelectorAll("[data-remote-prop][data-remote-bool]").forEach((button) => {
        button.addEventListener("click", () => {
          const propName = button.getAttribute("data-remote-prop");
          const value = button.getAttribute("data-remote-bool") === "true";
          savePropertyValue(propName, value, `已设置 ${propName}。`);
        });
      });

      document.querySelectorAll("[data-remote-step]").forEach((button) => {
        button.addEventListener("click", async () => {
          try {
            const propName = button.getAttribute("data-remote-step");
            const delta = Number.parseInt(button.getAttribute("data-remote-delta"), 10) || 0;
            await setSteppedProperty(propName, delta);
          } catch (error) {
            setBanner(error.message, "error");
          }
        });
      });

      document.querySelectorAll(".action-run-btn").forEach((button) => {
        button.addEventListener("click", () => runAction(button.dataset.action));
      });
    }

    function parseInputValue(prop) {
      if (prop.type === "bool") {
        const input = document.querySelector(`.prop-bool[data-prop="${CSS.escape(prop.name)}"]`);
        return input.checked;
      }

      if (prop.value_list && prop.value_list.length) {
        const input = document.querySelector(`.prop-select[data-prop="${CSS.escape(prop.name)}"]`);
        const raw = input.value;
        if (prop.type === "int" || prop.type === "uint") return Number.parseInt(raw, 10);
        if (prop.type === "float") return Number.parseFloat(raw);
        return raw;
      }

      const input = document.querySelector(`.prop-input[data-prop="${CSS.escape(prop.name)}"]`);
      const raw = input.value;
      if (prop.type === "int" || prop.type === "uint") return Number.parseInt(raw, 10);
      if (prop.type === "float") return Number.parseFloat(raw);
      return raw;
    }

    async function saveProperty(propName, manualValue) {
      const prop = state.selectedDetail?.properties?.find((item) => item.name === propName);
      if (!prop) return;
      try {
        const value = manualValue !== undefined ? manualValue : parseInputValue(prop);
        await savePropertyValue(propName, value, `已设置 ${propName}。`);
      } catch (error) {
        setBanner(error.message, "error");
      }
    }

    function parseQuickInputValue(prop) {
      if (prop.type === "bool") {
        const input = document.querySelector(`.quick-bool[data-prop="${CSS.escape(prop.name)}"]`);
        return input.checked;
      }

      if (prop.value_list && prop.value_list.length) {
        const input = document.querySelector(`.quick-select[data-prop="${CSS.escape(prop.name)}"]`);
        const raw = input.value;
        if (prop.type === "int" || prop.type === "uint") return Number.parseInt(raw, 10);
        if (prop.type === "float") return Number.parseFloat(raw);
        return raw;
      }

      const input = document.querySelector(`.quick-input[data-prop="${CSS.escape(prop.name)}"]`);
      const raw = input.value;
      if (prop.type === "int" || prop.type === "uint") return Number.parseInt(raw, 10);
      if (prop.type === "float") return Number.parseFloat(raw);
      return raw;
    }

    async function saveQuickProperty(propName) {
      const prop = state.selectedDetail?.properties?.find((item) => item.name === propName);
      if (!prop) return;
      try {
        const value = parseQuickInputValue(prop);
        await savePropertyValue(propName, value, `已设置 ${propName}。`);
      } catch (error) {
        setBanner(error.message, "error");
      }
    }

    async function runAction(actionName) {
      try {
        await api("/api/device/action", {
          method: "POST",
          body: JSON.stringify({
            did: state.selectedDid,
            action_name: actionName,
          }),
        });
        setBanner(`已执行动作 ${actionName}。`, "ok");
        await loadDeviceDetail(state.selectedDid, { silent: true });
        schedulePostChangeRefresh();
      } catch (error) {
        setBanner(error.message, "error");
      }
    }

    async function selectDevice(did) {
      state.selectedDid = did;
      renderDevices();
      await loadDeviceDetail(did);
      startDevicePolling();
    }

    async function loadStatus() {
      state.status = await api("/api/status");
      updateMeta();
    }

    async function loadDevices() {
      if (!state.status?.authenticated) {
        state.devices = [];
        renderDevices();
        return;
      }
      const data = await api("/api/devices");
      state.devices = data.devices || [];
      renderDevices();
      updateMeta();
    }

    async function loadScenes() {
      if (!state.status?.authenticated) {
        state.scenes = [];
        renderScenes();
        return;
      }
      const data = await api("/api/scenes");
      state.scenes = data.scenes || [];
      renderScenes();
    }

    async function loadDeviceDetail(did, options = {}) {
      if (!did) return;
      const requestToken = ++state.detailRequestToken;
      const data = await api(`/api/device/detail?did=${encodeURIComponent(did)}`);
      if (requestToken !== state.detailRequestToken) {
        return;
      }
      state.selectedDetail = data.device;
      renderDetail();
      if (!options.silent && state.pollEnabled) {
        setBanner("设备状态已轮询刷新。", "ok");
      }
    }

    async function refreshAll() {
      try {
        await loadStatus();
        await Promise.all([loadDevices(), loadScenes()]);
        if (state.selectedDid) {
          const exists = state.devices.find((item) => item.did === state.selectedDid);
          if (exists) {
            await loadDeviceDetail(state.selectedDid);
            startDevicePolling();
          } else {
            state.selectedDid = null;
            state.selectedDetail = null;
            stopDevicePolling();
            renderDetail();
          }
        } else {
          stopDevicePolling();
          renderDetail();
        }
        if (state.status?.authenticated) {
          setBanner("认证有效，设备数据已刷新。", "ok");
        }
      } catch (error) {
        setBanner(error.message, "error");
      }
    }

    async function startLogin() {
      try {
        setBanner("正在创建二维码，请稍候...");
        const data = await api("/api/login/start", {
          method: "POST",
          body: JSON.stringify({}),
        });

        if (data.authenticated) {
          setBanner("当前认证仍然有效，无需重新扫码。", "ok");
          setQr(null);
          await refreshAll();
          return;
        }

        state.loginSessionId = data.session_id;
        setQr(data.qr_url, data.login_url);
        setBanner("请使用米家 App 扫描二维码，网页会自动轮询登录结果。");
        startLoginPolling();
      } catch (error) {
        setBanner(error.message, "error");
      }
    }

    function stopLoginPolling() {
      if (state.loginPollTimer) {
        clearInterval(state.loginPollTimer);
        state.loginPollTimer = null;
      }
    }

    function startLoginPolling() {
      stopLoginPolling();
      state.loginPollTimer = setInterval(checkLoginStatus, 2000);
      checkLoginStatus();
    }

    async function checkLoginStatus() {
      if (!state.loginSessionId) return;
      try {
        const data = await api(`/api/login/status?session_id=${encodeURIComponent(state.loginSessionId)}`);
        const status = data.status;
        if (status === "waiting") {
          setBanner("二维码已生成，等待扫码确认...");
          return;
        }
        if (status === "success") {
          stopLoginPolling();
          setBanner("登录成功，正在刷新设备列表。", "ok");
          setQr(null);
          state.loginSessionId = null;
          await refreshAll();
          return;
        }
        if (status === "error" || status === "timeout" || status === "expired") {
          stopLoginPolling();
          setBanner(data.message || "登录失败，请重试。", "error");
        }
      } catch (error) {
        stopLoginPolling();
        setBanner(error.message, "error");
      }
    }

    els.startLoginBtn.addEventListener("click", startLogin);
    els.refreshAllBtn.addEventListener("click", refreshAll);
    els.showLoginBtn.addEventListener("click", () => {
      els.loginSection.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    els.deviceSearch.addEventListener("input", renderDevices);
    els.pollIntervalSelect.addEventListener("change", () => {
      state.pollMs = Number.parseInt(els.pollIntervalSelect.value, 10) || 5000;
      startDevicePolling();
      if (state.selectedDid && state.pollEnabled) {
        setBanner(`轮询间隔已设置为 ${Math.round(state.pollMs / 1000)} 秒。`, "ok");
      }
    });
    els.togglePollBtn.addEventListener("click", () => {
      state.pollEnabled = !state.pollEnabled;
      renderPollingState();
      startDevicePolling();
      setBanner(state.pollEnabled ? "已开启设备轮询刷新。" : "已关闭设备轮询刷新。", "ok");
    });
    els.refreshDeviceBtn.addEventListener("click", async () => {
      if (state.selectedDid) {
        await loadDeviceDetail(state.selectedDid);
        setBanner("当前设备已刷新。", "ok");
      }
    });

    refreshAll();
  </script>
</body>
</html>
"""

LEGACY_WEB_DISABLED_MESSAGE = (
    "旧网页控制台已被安全策略禁用。"
    "请改用 `python -m mijiaAPI web` 启动零知识 API 服务，不再允许旧 Web 明文认证模式。"
)


@dataclass
class LoginTask:
    session_id: str
    status: str
    qr_url: str
    login_url: str
    lp_url: str
    headers: dict[str, str]
    created_at: float = field(default_factory=time.time)
    message: str = ""
    session: requests.Session = field(default_factory=requests.Session)


@dataclass(frozen=True)
class WebSecurityConfig:
    production_mode: bool = False
    basic_auth_username: str = ""
    basic_auth_password: str = ""

    @property
    def require_basic_auth(self) -> bool:
        return bool(self.basic_auth_username and self.basic_auth_password)

    @property
    def expose_auth_path(self) -> bool:
        return not self.production_mode


class WebConsoleState:
    def __init__(self, auth_path: Path, security_config: Optional[WebSecurityConfig] = None):
        raise RuntimeError(LEGACY_WEB_DISABLED_MESSAGE)
        self.lock = threading.RLock()
        self.auth_path = Path(auth_path)
        self.security_config = security_config or WebSecurityConfig()
        if self.auth_path.is_dir():
            self.auth_path = self.auth_path / "auth.json"
        self.api = self._load_api()
        self.login_tasks: dict[str, LoginTask] = {}

    def _load_api(self) -> mijiaAPI:
        try:
            return mijiaAPI(auth_data_path=str(self.auth_path))
        except json.JSONDecodeError:
            self.auth_path.unlink(missing_ok=True)
            return mijiaAPI(auth_data_path=str(self.auth_path))

    def is_authenticated(self) -> bool:
        with self.lock:
            return self.api.available

    def _status_payload(self, authenticated: bool) -> dict[str, Any]:
        payload = {
            "authenticated": authenticated,
            "production_mode": self.security_config.production_mode,
        }
        if self.security_config.expose_auth_path:
            payload["auth_path"] = str(self.auth_path)
        return payload

    def status(self) -> dict[str, Any]:
        return self._status_payload(self.is_authenticated())

    def clear_auth(self) -> dict[str, Any]:
        with self.lock:
            self.login_tasks.clear()
            self.auth_path.unlink(missing_ok=True)
            self.api = mijiaAPI(auth_data_path=str(self.auth_path))
            payload = self._status_payload(False)
            payload["cleared"] = True
            return payload

    def start_login(self) -> dict[str, Any]:
        with self.lock:
            if self.api.available:
                return self._status_payload(True)

            location_data = self.api._get_location()
            if location_data.get("code", -1) == 0 and location_data.get("message", "") == "刷新Token成功":
                self.api._save_auth_data()
                self.api._init_session()
                return self._status_payload(True)

            location_data.update({
                "theme": "",
                "bizDeviceType": "",
                "_hasLogo": "false",
                "_qrsize": "240",
                "_dc": str(int(time.time() * 1000)),
            })
            headers = {
                "User-Agent": self.api.user_agent,
                "Accept-Encoding": "gzip",
                "Content-Type": "application/x-www-form-urlencoded",
                "Connection": "keep-alive",
            }
            url = self.api.login_url + "?" + parse.urlencode(location_data)
            login_ret = requests.get(url, headers=headers)
            login_data = self.api._handle_ret(login_ret)

            session_id = uuid.uuid4().hex
            task = LoginTask(
                session_id=session_id,
                status="waiting",
                qr_url=login_data["qr"],
                login_url=login_data["loginUrl"],
                lp_url=login_data["lp"],
                headers=headers,
            )
            self.login_tasks[session_id] = task

            thread = threading.Thread(target=self._complete_login, args=(session_id,), daemon=True)
            thread.start()

            return {
                "authenticated": False,
                "session_id": session_id,
                "qr_url": task.qr_url,
                "login_url": task.login_url,
            }

    def _complete_login(self, session_id: str) -> None:
        task = self.login_tasks[session_id]
        try:
            lp_ret = task.session.get(task.lp_url, headers=task.headers, timeout=180)
            lp_data = self.api._handle_ret(lp_ret)
            auth_keys = ["psecurity", "nonce", "ssecurity", "passToken", "userId", "cUserId"]
            with self.lock:
                for key in auth_keys:
                    self.api.auth_data[key] = lp_data[key]
                callback_url = lp_data["location"]
                task.session.get(callback_url, headers=task.headers)
                cookies = task.session.cookies.get_dict()
                self.api.auth_data.update(cookies)
                self.api.auth_data.update({
                    "expireTime": int((datetime.now() + timedelta(days=30)).timestamp() * 1000),
                })
                self.api._save_auth_data()
                self.api._init_session()
            task.status = "success"
            task.message = "登录成功"
        except requests.exceptions.Timeout:
            task.status = "timeout"
            task.message = "登录超时，请重新生成二维码"
        except Exception as exc:
            logger.exception("网页登录失败")
            task.status = "error"
            task.message = str(exc)

    def get_login_status(self, session_id: str) -> dict[str, Any]:
        task = self.login_tasks.get(session_id)
        if task is None:
            raise ValueError("登录会话不存在或已过期")
        if time.time() - task.created_at > 300 and task.status == "waiting":
            task.status = "expired"
            task.message = "二维码已过期，请重新生成"
        return {
            "session_id": task.session_id,
            "status": task.status,
            "message": task.message,
            "qr_url": task.qr_url,
            "login_url": task.login_url,
        }

    def _ensure_authenticated(self) -> None:
        if not self.api.available:
            raise LoginError(-1, "当前未登录，请先扫码登录")

    def _home_name_mapping(self) -> dict[str, str]:
        homes = self.api.get_homes_list()
        return {home["id"]: home["name"] for home in homes}

    def list_devices(self) -> list[dict[str, Any]]:
        with self.lock:
            self._ensure_authenticated()
            home_names = self._home_name_mapping()
            devices = self.api.get_devices_list() + self.api.get_shared_devices_list()

        normalized = []
        for item in devices:
            normalized.append({
                "did": item["did"],
                "name": item.get("name", item["did"]),
                "model": item.get("model", ""),
                "home_id": item.get("home_id", ""),
                "home_name": home_names.get(item.get("home_id", ""), "共享设备" if item.get("home_id") == "shared" else ""),
                "isOnline": bool(item.get("isOnline", False)),
            })
        return normalized

    def list_scenes(self) -> list[dict[str, Any]]:
        with self.lock:
            self._ensure_authenticated()
            home_names = self._home_name_mapping()
            scenes = self.api.get_scenes_list()

        return [
            {
                "scene_id": item["scene_id"],
                "name": item["name"],
                "home_id": item["home_id"],
                "home_name": home_names.get(item["home_id"], ""),
            }
            for item in scenes
        ]

    def run_scene(self, scene_id: str) -> dict[str, Any]:
        with self.lock:
            self._ensure_authenticated()
            scenes = self.api.get_scenes_list()
            target = next((item for item in scenes if item["scene_id"] == scene_id), None)
            if target is None:
                raise ValueError("场景不存在")
            result = self.api.run_scene(target["scene_id"], target["home_id"])
            return {
                "scene_id": target["scene_id"],
                "name": target["name"],
                "result": result,
            }

    def _get_device_entry(self, did: str) -> dict[str, Any]:
        devices = self.list_devices()
        target = next((item for item in devices if item["did"] == did), None)
        if target is None:
            raise ValueError("设备不存在")
        return target

    def get_device_detail(self, did: str) -> dict[str, Any]:
        with self.lock:
            self._ensure_authenticated()
            device_meta = self._get_device_entry(did)
            info = get_device_info(device_meta["model"], cache_path=self.api.auth_data_path.parent)

            readable_params = []
            prop_key_mapping = {}
            for prop in info.get("properties", []):
                if "r" in prop.get("rw", ""):
                    method = prop["method"].copy()
                    method["did"] = did
                    readable_params.append(method)
                    prop_key_mapping[(prop["method"]["siid"], prop["method"]["piid"])] = prop["name"]

            values_map: dict[str, Any] = {}
            error_map: dict[str, str] = {}
            if readable_params:
                results = self.api.get_devices_prop(readable_params)
                for item in results:
                    prop_name = prop_key_mapping.get((item["siid"], item["piid"]))
                    if prop_name is None:
                        continue
                    if item.get("code", 0) == 0:
                        values_map[prop_name] = item.get("value")
                    else:
                        error_map[prop_name] = f"读取失败: {item.get('code')}"

            properties = []
            for prop in info.get("properties", []):
                properties.append({
                    "name": prop["name"],
                    "description": prop.get("description", ""),
                    "type": prop.get("type", ""),
                    "rw": prop.get("rw", ""),
                    "range": prop.get("range"),
                    "value_list": prop.get("value-list"),
                    "readable": "r" in prop.get("rw", ""),
                    "writable": "w" in prop.get("rw", ""),
                    "current_value": values_map.get(prop["name"]),
                    "current_error": error_map.get(prop["name"]),
                })

            actions = [
                {
                    "name": action["name"],
                    "description": action.get("description", ""),
                }
                for action in info.get("actions", [])
            ]

            return {
                "did": device_meta["did"],
                "name": device_meta["name"],
                "model": device_meta["model"],
                "home_name": device_meta.get("home_name", ""),
                "properties": properties,
                "actions": actions,
            }

    def set_device_property(self, did: str, prop_name: str, value: Any) -> dict[str, Any]:
        with self.lock:
            self._ensure_authenticated()
            device = mijiaDevice(self.api, did=did, sleep_time=0.1)
            device.set(prop_name, value)
            return {
                "did": did,
                "prop_name": prop_name,
                "value": value,
            }

    def run_device_action(self, did: str, action_name: str) -> dict[str, Any]:
        with self.lock:
            self._ensure_authenticated()
            device = mijiaDevice(self.api, did=did, sleep_time=0.1)
            device.run_action(action_name)
            return {
                "did": did,
                "action_name": action_name,
            }


def make_handler(state: WebConsoleState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "mijiaAPI-web/1.0"

        def log_message(self, format: str, *args: Any) -> None:
            logger.info("Web %s - %s", self.address_string(), format % args)

        def _send_json(self, payload: dict[str, Any], status: int = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _send_unauthorized(self) -> None:
            body = json.dumps({"error": "需要身份验证"}).encode("utf-8")
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("WWW-Authenticate", 'Basic realm="Mijia Web Console", charset="UTF-8"')
            self.end_headers()
            self.wfile.write(body)

        def _authorize(self) -> bool:
            if not state.security_config.require_basic_auth:
                return True
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Basic "):
                self._send_unauthorized()
                return False
            try:
                encoded = auth_header.split(" ", 1)[1]
                decoded = base64.b64decode(encoded).decode("utf-8")
            except (ValueError, binascii.Error, UnicodeDecodeError):
                self._send_unauthorized()
                return False
            username, separator, password = decoded.partition(":")
            if not separator:
                self._send_unauthorized()
                return False
            if not (
                compare_digest(username, state.security_config.basic_auth_username)
                and compare_digest(password, state.security_config.basic_auth_password)
            ):
                self._send_unauthorized()
                return False
            return True

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))

        def _handle_error(self, exc: Exception) -> None:
            if isinstance(exc, (ValueError, DeviceSetError, DeviceGetError, DeviceActionError, APIError, LoginError)):
                message = str(exc)
                status = HTTPStatus.BAD_REQUEST
            else:
                logger.exception("Web API 未处理异常")
                message = "服务器内部错误"
                status = HTTPStatus.INTERNAL_SERVER_ERROR
            self._send_json({"error": message}, status=status)

        def do_GET(self) -> None:
            parsed = parse.urlparse(self.path)
            try:
                if not self._authorize():
                    return
                if parsed.path == "/":
                    self._send_html(INDEX_HTML)
                    return
                if parsed.path == "/api/status":
                    self._send_json(state.status())
                    return
                if parsed.path == "/api/login/start":
                    self._send_json(state.start_login())
                    return
                if parsed.path == "/api/login/status":
                    query = parse.parse_qs(parsed.query)
                    session_id = query.get("session_id", [None])[0]
                    if not session_id:
                        raise ValueError("缺少 session_id")
                    self._send_json(state.get_login_status(session_id))
                    return
                if parsed.path == "/api/devices":
                    self._send_json({"devices": state.list_devices()})
                    return
                if parsed.path == "/api/scenes":
                    self._send_json({"scenes": state.list_scenes()})
                    return
                if parsed.path == "/api/device/detail":
                    query = parse.parse_qs(parsed.query)
                    did = query.get("did", [None])[0]
                    if not did:
                        raise ValueError("缺少 did")
                    self._send_json({"device": state.get_device_detail(did)})
                    return

                self._send_json({"error": "接口不存在"}, status=HTTPStatus.NOT_FOUND)
            except Exception as exc:
                self._handle_error(exc)

        def do_POST(self) -> None:
            parsed = parse.urlparse(self.path)
            try:
                if not self._authorize():
                    return
                payload = self._read_json()
                if parsed.path == "/api/login/start":
                    self._send_json(state.start_login())
                    return
                if parsed.path == "/api/logout":
                    self._send_json(state.clear_auth())
                    return
                if parsed.path == "/api/scenes/run":
                    scene_id = payload.get("scene_id")
                    if not scene_id:
                        raise ValueError("缺少 scene_id")
                    self._send_json(state.run_scene(scene_id))
                    return
                if parsed.path == "/api/device/property":
                    did = payload.get("did")
                    prop_name = payload.get("prop_name")
                    if not did or not prop_name:
                        raise ValueError("缺少 did 或 prop_name")
                    self._send_json(state.set_device_property(did, prop_name, payload.get("value")))
                    return
                if parsed.path == "/api/device/action":
                    did = payload.get("did")
                    action_name = payload.get("action_name")
                    if not did or not action_name:
                        raise ValueError("缺少 did 或 action_name")
                    self._send_json(state.run_device_action(did, action_name))
                    return

                self._send_json({"error": "接口不存在"}, status=HTTPStatus.NOT_FOUND)
            except Exception as exc:
                self._handle_error(exc)

    return Handler


def run_web_console(
    auth_path: Optional[Path] = None,
    host: str = "127.0.0.1",
    port: int = 8123,
    production_mode: bool = False,
) -> None:
    raise RuntimeError(LEGACY_WEB_DISABLED_MESSAGE)
    if auth_path is None:
        auth_path = get_default_auth_path()

    security_config = WebSecurityConfig(
        production_mode=production_mode,
        basic_auth_username=os.getenv("MIJIA_WEB_USERNAME", ""),
        basic_auth_password=os.getenv("MIJIA_WEB_PASSWORD", ""),
    )
    if production_mode and not security_config.require_basic_auth:
        raise ValueError("生产模式要求同时设置 MIJIA_WEB_USERNAME 和 MIJIA_WEB_PASSWORD")

    state = WebConsoleState(auth_path=Path(auth_path), security_config=security_config)
    server = ThreadingHTTPServer((host, port), make_handler(state))

    logger.info("Mijia Legacy Web Console 已启动: http://%s:%s", host, port)
    if security_config.expose_auth_path:
        logger.info("认证文件: %s", state.auth_path)
    else:
        logger.info("认证文件: 已隐藏（生产模式）")
    if security_config.require_basic_auth:
        logger.info("访问保护: 已启用 Basic Auth")
    logger.info("在浏览器打开地址后，可扫码登录并控制设备")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("正在关闭 Mijia Web Console")
    finally:
        server.server_close()
