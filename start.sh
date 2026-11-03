#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "未找到 python3，请先安装 Python 3.9+"
  exit 1
fi
if ! "$PY" -c "import requests, websocket, PIL" >/dev/null 2>&1; then
  echo "首次运行，正在安装依赖..."
  "$PY" -m pip install -r requirements.txt || {
    echo "依赖安装失败，可尝试：$PY -m pip install --break-system-packages -r requirements.txt"
    exit 1
  }
fi
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
  echo "未检测到图形界面，改为命令行巡查..."
  exec "$PY" patrol.py run --profile "${PROFILE:-default}"
fi
exec "$PY" gui.pyw
