#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FrpSitePatrol - 每日巡查 ME Frp 节点上的网页服务并截图留档
依赖: requests, websocket-client, Pillow (均已安装)
"""
import argparse
import base64
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib3
import warnings

warnings.filterwarnings("ignore")
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

import requests
import websocket
from PIL import Image, ImageDraw, ImageFont

import risk as riskmod
LEVELS_RENDER = riskmod.LEVELS

urllib3.disable_warnings()

if getattr(sys, "frozen", False):
    ROOT = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
CACHE = ROOT / "cache"
CONFIG_PATH = ROOT / "config.json"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


# ---------------------------------------------------------------- 基础
PROFILES = ROOT / "profiles"
DATA_ROOT = ROOT / "data"


def load_config():
    """读取应用配置；兼容旧版单节点 config.json 并自动迁移。"""
    if not CONFIG_PATH.exists():
        cfg = {
            "active_profile": "default",
            "capture": {"width": 1440, "height": 900, "settle_seconds": 4,
                        "load_timeout": 20, "probe_timeout": 6, "max_pages": 80},
            "report": {"keep_days": 60, "change_threshold": 12},
            "browser_path": "",
        }
        CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        return cfg
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    if "server" in cfg:
        cfg = _migrate_legacy(cfg)
    cfg.setdefault("active_profile", "default")
    cfg.setdefault("capture", {"width": 1440, "height": 900, "settle_seconds": 4,
                               "load_timeout": 20, "probe_timeout": 6, "max_pages": 80})
    cfg.setdefault("report", {"keep_days": 60, "change_threshold": 12})
    return cfg


def _migrate_legacy(cfg):
    srv = cfg.pop("server")
    PROFILES.mkdir(exist_ok=True)
    prof = {
        "name": "默认节点",
        "host": srv.get("host", ""),
        "mode": "frps",
        "frps_web": srv.get("frps_web", ""),
        "web_password": srv.get("web_password", ""),
        "port_min": srv.get("port_min", 1),
        "port_max": srv.get("port_max", 65535),
        "extra_ports": srv.get("extra_ports", []),
        "exclude_ports": srv.get("exclude_ports", []),
        "static_ports": srv.get("static_ports", []),
        "scan_timeout": 0.8,
        "scan_workers": 200,
        "risk_overrides": cfg.pop("risk_overrides", {}) or {},
    }
    (PROFILES / "default.json").write_text(json.dumps(prof, ensure_ascii=False, indent=2), encoding="utf-8")
    cfg["active_profile"] = "default"
    (CONFIG_PATH).write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    dest = DATA_ROOT / "default"
    if DATA_ROOT.exists():
        dest.mkdir(parents=True, exist_ok=True)
        for d in list(DATA_ROOT.iterdir()):
            if d.is_dir() and d.name != "default" and (d / "meta.json").exists():
                try:
                    shutil.move(str(d), str(dest / d.name))
                except Exception:
                    pass
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def _safe_id(name):
    return re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_") or f"node{int(time.time())}"


def profile_path(pid):
    return PROFILES / f"{pid}.json"


def list_profiles():
    load_config()
    out = []
    for f in sorted(PROFILES.glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        out.append({"id": f.stem, "name": d.get("name") or f.stem,
                    "host": d.get("host", ""), "mode": d.get("mode", "frps")})
    return out


def load_profile(pid=None):
    cfg = load_config()
    pid = pid or cfg["active_profile"]
    path = profile_path(pid)
    if not path.exists():
        profs = list_profiles()
        if not profs:
            raise RuntimeError("没有节点配置，请先在界面里新建节点")
        pid = profs[0]["id"]
        path = profile_path(pid)
    prof = json.loads(path.read_text(encoding="utf-8"))
    prof["_id"] = pid
    prof.setdefault("mode", "frps")
    prof.setdefault("port_min", 1)
    prof.setdefault("port_max", 65535)
    prof.setdefault("extra_ports", [])
    prof.setdefault("exclude_ports", [])
    prof.setdefault("static_ports", [])
    prof.setdefault("scan_timeout", 0.8)
    prof.setdefault("scan_workers", 200)
    prof.setdefault("risk_overrides", {})
    prof.setdefault("panel_user", "")
    return prof


def save_profile(prof, pid=None):
    PROFILES.mkdir(exist_ok=True)
    pid = pid or _safe_id(prof.get("name") or "")
    data = {k: v for k, v in prof.items() if not k.startswith("_")}
    profile_path(pid).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return pid


def set_active(pid):
    cfg = load_config()
    cfg["active_profile"] = pid
    save_config(cfg)


def add_log(msg, quiet=False):
    line = f"[{datetime.now():%H:%M:%S}] {msg}"
    if not quiet:
        try:
            print(line, flush=True)
        except Exception:
            pass
    DATA_ROOT.mkdir(exist_ok=True)
    with open(DATA_ROOT / "patrol.log", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def strip_prefix(name):
    return name.split(".", 1)[-1] if "." in name else name


# ---------------------------------------------------------------- 发现端口
def discover(prof, log):
    """兼容 ME Frp 面板与标准 frps 面板；地址可带任意端口/域名/https。"""
    raw = (prof.get("frps_web") or "").strip()
    if not raw:
        raise RuntimeError("该节点未配置面板地址（模式为面板发现时必须填写）")
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    base = raw.rstrip("/")
    pwd = prof.get("web_password", "") or ""
    user = prof.get("panel_user") or "admin"

    s = requests.Session()
    s.headers["User-Agent"] = UA
    is_me = False
    try:
        home = s.get(base + "/", timeout=8, verify=False)
        low = (home.text or "")[:8000].lower()
        is_me = "mefrp" in low or "me frp" in low or "/mefrp/auth" in low
    except Exception as e:
        raise RuntimeError(f"连不上面板 {base}（{type(e).__name__}），检查 IP、端口和协议")

    if is_me:
        log(f"识别为 ME Frp 面板：{base}")
        try:
            r = s.post(base + "/mefrp/auth", data={"password": pwd, "redirect": "/"},
                       timeout=8, allow_redirects=False, verify=False)
            if r.status_code not in (200, 302):
                log("ME Frp 面板登录未成功，继续尝试 Basic 认证")
        except Exception as e:
            log(f"ME Frp 登录异常：{e}")
    else:
        log(f"按标准 frps 面板访问：{base}")

    def api():
        return s.get(base + "/api/proxy/tcp", timeout=12, verify=False)

    r = api()
    if r.status_code in (401, 403):
        s.auth = (user, pwd)
        r = api()
    if r.status_code in (401, 403):
        s.auth = None
        r = api()
    if r.status_code == 404:
        raise RuntimeError("面板返回 404：端口/路径不对，或对方不是 frps 面板")
    if r.status_code in (401, 403):
        raise RuntimeError("面板认证失败：检查面板用户名、密码，或该面板不允许 API")
    r.raise_for_status()
    try:
        payload = r.json()
    except Exception:
        raise RuntimeError("面板返回的不是 JSON，可能地址指向了别的服务")

    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        code = payload.get("code")
        if code not in (None, 200):
            raise RuntimeError(str(payload.get("message") or payload.get("msg") or f"面板返回 code={code}"))
        rows = payload.get("data") or payload.get("proxies") or []
    else:
        rows = []
    if isinstance(rows, dict):
        rows = list(rows.values())

    out = {}
    lo, hi = prof.get("port_min", 0), prof.get("port_max", 65535)
    for item in rows:
        if not isinstance(item, dict):
            continue
        conf = item.get("conf") or {}
        port = conf.get("remotePort") or conf.get("remote_port") or item.get("remotePort")
        try:
            port = int(port)
        except Exception:
            continue
        if not (lo <= port <= hi):
            continue
        name = conf.get("name") or item.get("name") or ""
        out[port] = {
            "port": port,
            "name": strip_prefix(str(name)),
            "user": str(item.get("user") or "")[:8],
            "status": item.get("status") or "online",
            "client": item.get("clientVersion") or item.get("client_version") or "",
        }
    log(f"面板发现 {len(out)} 条 TCP 隧道")
    return out


def fallback_ports(prof, log):
    ports = {}
    for p in prof.get("static_ports", []):
        ports[int(p)] = {"port": int(p), "name": "static", "user": "", "status": "unknown", "client": ""}
    pdata = DATA_ROOT / prof["_id"]
    for f in sorted(pdata.glob("*/meta.json"), reverse=True):
        try:
            meta = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        for item in meta.get("pages", []):
            if item.get("port") and item["port"] not in ports:
                ports[item["port"]] = {"port": item["port"], "name": item.get("name", ""),
                                       "user": item.get("user", ""), "status": "cached", "client": ""}
        if ports:
            log(f"面板不可用，使用上一份清单 {f.parent.name}（{len(ports)} 个端口）")
            break
    return ports


def scan_range(prof, log):
    """扫描自己服务器的端口段（仅用于自有主机）。"""
    lo, hi = int(prof["port_min"]), int(prof["port_max"])
    host = prof["host"]
    timeout = float(prof.get("scan_timeout", 0.8))
    workers = max(8, min(int(prof.get("scan_workers", 200)), 400))
    log(f"开始端口扫描 {host}:{lo}-{hi}（并发 {workers}，超时 {timeout}s）")
    ports = list(range(lo, hi + 1))

    def one(p):
        s = socket.socket()
        s.settimeout(timeout)
        try:
            return p if s.connect_ex((host, p)) == 0 else None
        except Exception:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass

    out = {}
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(one, ports):
            done += 1
            if r:
                out[r] = {"port": r, "name": "scan", "user": "", "status": "open", "client": ""}
            if done % 2000 == 0:
                log(f"  扫描进度 {done}/{len(ports)}，已发现 {len(out)} 个")
    log(f"扫描完成，发现 {len(out)} 个开放端口")
    return out


def get_targets(prof, log, no_discovery=False):
    mode = prof.get("mode", "frps")
    if mode == "static":
        ports = fallback_ports(prof, log)
        log(f"使用手动端口列表：{len(ports)} 个")
    elif mode == "range":
        ports = scan_range(prof, log)
    else:
        if no_discovery:
            ports = fallback_ports(prof, log)
        else:
            try:
                ports = discover(prof, log)
            except Exception as e:
                log(f"面板发现失败: {e}")
                ports = {}
            if not ports:
                ports = fallback_ports(prof, log)
    for p in prof.get("extra_ports", []):
        ports.setdefault(int(p), {"port": int(p), "name": "extra", "user": "", "status": "unknown", "client": ""})
    for p in prof.get("exclude_ports", []):
        ports.pop(int(p), None)
    return ports


# ---------------------------------------------------------------- 协议探测
def probe(host, port, timeout=6):
    """返回 kind: http / https / ssh / rdp / tcp / closed"""
    res = {"port": port, "kind": "closed", "status": "", "server": "", "title": "",
           "length": 0, "error": "", "final": "", "headers": {}, "body": ""}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            s.sendall((f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: {UA}\r\n"
                       "Accept: */*\r\nConnection: close\r\n\r\n").encode())
            raw = b""
            while len(raw) < 8192:
                d = s.recv(4096)
                if not d:
                    break
                raw += d
        except Exception:
            raw = b""
        finally:
            try:
                s.close()
            except Exception:
                pass
        if raw.startswith(b"HTTP/"):
            res["kind"] = "http"
        elif raw.startswith(b"SSH-"):
            res["kind"] = "ssh"
            res["status"] = raw.split(b"\r\n")[0].decode("latin1", "replace")[:60]
        elif raw.startswith(b"\x03\x00"):
            res["kind"] = "rdp"
            res["status"] = "RDP"
        elif raw.startswith(b"\x15\x03"):
            res["kind"] = "https"
        elif raw:
            res["kind"] = "tcp"
            res["status"] = raw[:24].hex()
        else:
            res["kind"] = "tcp"
    except Exception as e:
        res["error"] = type(e).__name__
        return res

    scheme = "https" if res["kind"] == "https" else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                         headers={"User-Agent": UA, "Accept": "*/*"})
        res["status"] = f"{r.status_code} {r.reason}"
        res["server"] = r.headers.get("Server", "")
        res["headers"] = dict(list(r.headers.items())[:12])
        res["final"] = r.url
        ct = r.headers.get("Content-Type", "")
        body = r.content[:200000]
        res["length"] = len(r.content)
        m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.S | re.I)
        if m:
            for enc in ("utf-8", "gb18030"):
                try:
                    res["title"] = m.group(1).decode(enc, "replace").strip()[:120]
                    break
                except Exception:
                    pass
        res["body"] = body.decode("utf-8", "replace")[:3000]
        if ct[:5] not in ("text/", "appli"):
            res["kind"] = "binary"
    except requests.exceptions.SSLError:
        res["kind"] = "https" if scheme == "http" else res["kind"]
    except Exception as e:
        if res["kind"] == "http":
            res["error"] = type(e).__name__
    return res


# ---------------------------------------------------------------- 浏览器截图
def find_browser(cfg):
    if cfg.get("browser_path") and Path(cfg["browser_path"]).exists():
        return cfg["browser_path"]
    cands = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        "/usr/bin/microsoft-edge",
        "/opt/google/chrome/chrome",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    for c in cands:
        if Path(c).exists():
            return c
    for name in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge",
                 "brave-browser", "chrome"):
        hit = shutil.which(name)
        if hit:
            return hit
    raise RuntimeError("未找到 Edge / Chrome / Chromium，请在 config.json 里设置 browser_path")


class Browser:
    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.proc = None
        self.ws = None
        self._id = 0
        self.profile = CACHE / f"edge-{os.getpid()}"
        self._start()

    def _start(self):
        shutil.rmtree(self.profile, ignore_errors=True)
        self.profile.mkdir(parents=True, exist_ok=True)
        exe = find_browser(self.cfg)
        args = [exe, "--headless=new", "--disable-gpu", "--no-first-run",
                "--no-default-browser-check", "--disable-extensions",
                "--hide-scrollbars", f"--user-data-dir={self.profile}",
                "--remote-debugging-port=0", "about:blank"]
        if os.name != "nt":
            args[1:1] = ["--no-sandbox", "--disable-dev-shm-usage"]
        flags = 0x08000000 if os.name == "nt" else 0
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, creationflags=flags)
        port_file = self.profile / "DevToolsActivePort"
        for _ in range(60):
            if port_file.exists():
                try:
                    lines = port_file.read_text().splitlines()
                    port, path = int(lines[0]), lines[1]
                    self.ws = websocket.create_connection(
                        f"ws://127.0.0.1:{port}{path}", timeout=30, suppress_origin=True)
                    return
                except Exception:
                    pass
            time.sleep(0.3)
        raise RuntimeError("浏览器启动超时")

    def cmd(self, method, params=None, session=None, timeout=60):
        self._id += 1
        msg = {"id": self._id, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        self.ws.send(json.dumps(msg))
        self.ws.settimeout(timeout)
        while True:
            r = json.loads(self.ws.recv())
            if r.get("id") == self._id:
                if "error" in r:
                    raise RuntimeError(r["error"])
                return r.get("result", {})

    def shot(self, url, out_png):
        cap = self.cfg.get("capture", {})
        w, h = cap.get("width", 1440), cap.get("height", 900)
        wait, load_to = cap.get("settle_seconds", 4), cap.get("load_timeout", 20)
        tid = sid = None
        try:
            tid = self.cmd("Target.createTarget", {"url": "about:blank"})["targetId"]
            sid = self.cmd("Target.attachToTarget", {"targetId": tid, "flatten": True})["sessionId"]
            self.cmd("Page.enable", {}, sid)
            self.cmd("Security.setIgnoreCertificateErrors", {"ignore": True}, sid)
            self.cmd("Emulation.setDeviceMetricsOverride",
                     {"width": w, "height": h, "deviceScaleFactor": 1, "mobile": False}, sid)
            self.cmd("Page.navigate", {"url": url}, sid, timeout=45)
            t0 = time.time()
            while time.time() - t0 < load_to:
                time.sleep(0.6)
                try:
                    st = self.cmd("Runtime.evaluate",
                                  {"expression": "document.readyState", "returnByValue": True},
                                  sid, timeout=10)
                    if st.get("result", {}).get("value") == "complete":
                        break
                except Exception:
                    pass
            time.sleep(wait)
            title = final = ""
            try:
                r = self.cmd("Runtime.evaluate",
                             {"expression": "document.title + '\\n' + location.href",
                              "returnByValue": True}, sid, timeout=10)
                title, _, final = (r.get("result", {}).get("value") or "").partition("\n")
            except Exception:
                pass
            shot = self.cmd("Page.captureScreenshot", {"format": "png"}, sid, timeout=90)
            out_png.write_bytes(base64.b64decode(shot["data"]))
            return True, title, final
        finally:
            if sid:
                try:
                    self.cmd("Target.closeTarget", {"targetId": tid}, timeout=15)
                except Exception:
                    pass

    def close(self):
        try:
            if self.ws:
                self.ws.close()
        except Exception:
            pass
        try:
            if self.proc:
                self.proc.terminate()
                self.proc.wait(timeout=8)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        time.sleep(0.3)
        shutil.rmtree(self.profile, ignore_errors=True)


# ---------------------------------------------------------------- 图片处理
def dhash(path, size=8):
    try:
        im = Image.open(path).convert("L").resize((size + 1, size), Image.LANCZOS)
        px = list(im.getdata())
        bits = 0
        for row in range(size):
            for col in range(size):
                l = px[row * (size + 1) + col]
                r = px[row * (size + 1) + col + 1]
                bits = (bits << 1) | (1 if l > r else 0)
        return bits
    except Exception:
        return 0


def hamming(a, b):
    return bin(a ^ b).count("1")


def is_blank(path):
    try:
        im = Image.open(path).convert("L").resize((64, 40))
        px = list(im.getdata())
        mean = sum(px) / len(px)
        return (sum((p - mean) ** 2 for p in px) / len(px)) ** 0.5 < 3.0
    except Exception:
        return False


def open_path(target):
    """跨平台打开文件/目录。"""
    target = str(target)
    if os.name == "nt":
        os.startfile(target)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", target])
    else:
        subprocess.Popen(["xdg-open", target])


def _font(size, bold=False):
    if os.name == "nt":
        cands = [f"C:/Windows/Fonts/{'msyhbd.ttc' if bold else 'msyh.ttc'}",
                 "C:/Windows/Fonts/simhei.ttf", "C:/Windows/Fonts/arial.ttf"]
    else:
        cands = [
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc" if bold
            else "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]
    for f in cands:
        try:
            return ImageFont.truetype(f, size)
        except Exception:
            pass
    return ImageFont.load_default()


def info_card(path, host, item):
    W, H = 1440, 900
    im = Image.new("RGB", (W, H), (245, 246, 248))
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, W, 118], fill=(28, 32, 38))
    d.text((46, 24), str(item["port"]), font=_font(60, True), fill="white")
    d.text((240, 48), f"{host} · {item.get('title') or item.get('name') or ''}",
           font=_font(24), fill=(220, 225, 232))
    y = 175
    d.text((50, y), f"HTTP {item.get('status') or '无响应'}    {item.get('final') or ''}",
           font=_font(24), fill=(30, 30, 30))
    y += 48
    lines = [f"{k}: {v}" for k, v in (item.get("headers") or {}).items()]
    body = (item.get("body") or "").strip().replace("\r", "")
    for ln in lines + ["", "----- 响应正文 -----", ""] + body.splitlines()[:18]:
        d.text((50, y), ln[:150], font=_font(19), fill=(70, 70, 70))
        y += 30
        if y > H - 40:
            break
    im.save(path, "PNG")


def make_thumb(src, dst, width=960):
    im = Image.open(src).convert("RGB")
    im.thumbnail((width, 600))
    im.save(dst, "JPEG", quality=86)


# ---------------------------------------------------------------- 报告
def _history_items(pdata):
    items = []
    for f in sorted(pdata.glob("*/meta.json"), reverse=True):
        run = f.parent.name
        if len(run) < 15:
            continue
        try:
            m = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        pages = m.get("pages", [])
        cnt = {k: sum(1 for p in pages if (p.get("risk") or {}).get("level") == k) for k in "XSBC"}
        items.append({
            "run": run, "date": run[:10], "time": run[11:].replace("_", ":"),
            "total": len(pages), "counts": cnt,
            "changes": sum(1 for p in pages if p.get("delta")),
            "host": m.get("host", ""),
        })
    return items


def build_index(pdata, prof):
    items = _history_items(pdata)
    groups = {}
    for it in items:
        groups.setdefault(it["date"], []).append(it)
    dates = sorted(groups, reverse=True)
    total_runs = len(items)
    rows = ""
    for d in dates:
        day = groups[d]
        x = sum(i["counts"]["X"] for i in day)
        s_ = sum(i["counts"]["S"] for i in day)
        rows += f'<div class="day"><div class="dh"><b>{d}</b><span>{len(day)} 次巡查 · 极高累计 {x} · 高累计 {s_}</span></div>'
        for it in day:
            c = it["counts"]
            rows += (f'<a class="run" href="{it["run"]}/report.html">'
                     f'<span class="rt">{it["time"]}</span>'
                     f'<span class="rn">{it["total"]} 条隧道</span>'
                     f'<span class="rx" style="color:#d93025">极高 {c["X"]}</span>'
                     f'<span class="rx" style="color:#e8710a">高 {c["S"]}</span>'
                     f'<span class="rx" style="color:#1a73e8">中 {c["B"]}</span>'
                     f'<span class="rx" style="color:#8b93a1">低 {c["C"]}</span>'
                     f'<span class="rc">{it["changes"]} 条变化</span>'
                     f'<span class="go">查看 →</span></a>')
        rows += "</div>"
    html = f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{prof.get("name") or prof["_id"]} · 历史报告</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#0f1115;color:#e6e8eb;font:14px/1.55 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}}
header{{padding:30px 32px;border-bottom:1px solid #23262d;background:linear-gradient(180deg,#14171c,#0f1115)}}
h1{{margin:0 0 6px;font-size:22px}}.sub{{color:#98a0ab;font-size:13px}}
main{{padding:24px 32px 60px;max-width:1200px;margin:0 auto}}
.day{{margin-bottom:26px;border:1px solid #23262d;border-radius:12px;overflow:hidden;background:#13161b}}
.dh{{display:flex;justify-content:space-between;align-items:baseline;padding:12px 16px;background:#171b21;border-bottom:1px solid #23262d}}
.dh b{{font-size:15px}}.dh span{{color:#8b93a1;font-size:12px}}
.run{{display:grid;grid-template-columns:80px 110px repeat(4,92px) 110px 1fr;gap:8px;align-items:center;padding:10px 16px;color:inherit;text-decoration:none;border-bottom:1px solid #1e2229}}
.run:last-child{{border-bottom:0}}.run:hover{{background:#181d24}}
.rt{{font-family:Consolas,monospace;color:#fff}}.rn{{color:#c7cdd4}}.rx{{font-size:12.5px}}
.rc{{color:#8b93a1;font-size:12.5px}}.go{{text-align:right;color:#8ab4f8;font-size:12.5px}}
.empty{{color:#8b93a1}}
</style></head><body><header><h1>{prof.get("name") or prof["_id"]} · 历史报告</h1>
<div class="sub">{prof.get("host","")} · 共 {total_runs} 次巡查 · 按日期倒序</div></header>
<main>{rows or '<div class="empty">还没有记录</div>'}</main></body></html>'''
    (pdata / "index.html").write_text(html, encoding="utf-8")
    return pdata / "index.html"


def build_report(run_dir, meta, prev_meta, host):
    pages = meta["pages"]
    prev = {p["port"]: p for p in (prev_meta or {}).get("pages", [])}
    thr = meta.get("change_threshold", 12)
    order = {"X": 0, "S": 1, "B": 2, "C": 3}

    for p in pages:
        old = prev.get(p["port"])
        p["delta"] = []
        if not old:
            p["delta"].append("新增")
        else:
            if old.get("status") != p.get("status"):
                p["delta"].append("状态变化")
            if (old.get("title") or "") != (p.get("title") or "") and p.get("title"):
                p["delta"].append("标题变化")
            if p.get("hash") and old.get("hash"):
                dist = hamming(p["hash"], old["hash"])
                p["dist"] = dist
                if dist >= thr:
                    p["delta"].append(f"页面变化({dist})")
            op = (old.get("risk") or {}).get("level")
            np_ = (p.get("risk") or {}).get("level")
            if op and np_ and order[np_] < order[op]:
                p["delta"].append("风险上升")
            elif op and np_ and order[np_] > order[op]:
                p["delta"].append("风险下降")
        if p.get("kind") == "closed":
            p["delta"].append("离线")
    gone = [q for q in prev.values() if q["port"] not in {p["port"] for p in pages}]

    names = {"X": "极高", "S": "高", "B": "中", "C": "低"}
    counts = {k: sum(1 for p in pages if (p.get("risk") or {}).get("level") == k) for k in "XSBC"}
    colors = {"新增": "#7c4dff", "页面变化": "#e8710a", "标题变化": "#e8710a",
              "状态变化": "#7c4dff", "离线": "#5f6368", "风险上升": "#d93025", "风险下降": "#188038"}

    def card(p):
        img = f"shots/{p['port']}.png"
        rk = p.get("risk") or {}
        lv = rk.get("level", "C")
        lname, _, lcolor = LEVELS_RENDER[lv]
        badges = "".join(f'<span class="badge" style="background:{colors.get(b.split("(")[0], "#5f6368")}">{b}</span>'
                         for b in p.get("delta", []))
        kind = {"http": "HTTP", "https": "HTTPS", "ssh": "SSH", "rdp": "RDP",
                "tcp": "TCP", "binary": "二进制", "closed": "离线"}.get(p.get("kind"), p.get("kind"))
        meta_line = f'{p.get("status") or kind}'
        if p.get("server"):
            meta_line += f' · {p["server"]}'
        reasons = "；".join(rk.get("reasons") or [])[:88]
        live = ""
        if p.get("kind") in ("http", "https"):
            scheme = "https" if p.get("kind") == "https" or str(p.get("final") or "").startswith("https") else "http"
            live = (f'<a class="open" href="{scheme}://{host}:{p["port"]}/" target="_blank" '
                    f'rel="noopener noreferrer">打开网页 ↗</a>')
        return f'''<div class="card">
  <a class="shot" href="{img}" target="_blank"><img src="shots/thumbs/{p['port']}.jpg" alt="{p['port']}"></a>
  <div class="meta"><div class="row"><span class="port">{p['port']}</span>
  <span class="lvl" style="background:{lcolor}">{lname} {rk.get('score', 0)}</span>
  <span class="kind">{kind}</span>{badges}{live}</div>
  <div class="t">{p.get('title') or p.get('name') or '—'}</div>
  <div class="d">{meta_line}</div>
  <div class="r">{reasons}</div></div></div>'''

    sections = ""
    for lv in "XSBC":
        items = [p for p in pages if (p.get("risk") or {}).get("level") == lv]
        items.sort(key=lambda x: -(x["risk"]["score"]))
        if not items:
            continue
        lname, _, lcolor = LEVELS_RENDER[lv]
        if lv == "C":
            rows = ""
            for p in items:
                kd = {"http": "HTTP", "https": "HTTPS", "ssh": "SSH", "rdp": "RDP",
                      "tcp": "TCP", "binary": "二进制", "closed": "离线"}.get(p.get("kind"), p.get("kind"))
                link = ""
                if p.get("kind") in ("http", "https"):
                    scheme = "https" if p.get("kind") == "https" else "http"
                    link = (f'<a class="lo" href="{scheme}://{host}:{p["port"]}/" '
                            f'target="_blank" rel="noopener noreferrer">打开 ↗</a>')
                rows += (f'<div class="li"><span class="lp">{p["port"]}</span>'
                         f'<span class="ln">{p.get("title") or p.get("name") or "—"}</span>'
                         f'<span class="lk">{kd} · {p.get("status") or ""}</span>'
                         f'<span class="ls">{p["risk"]["score"]}</span>{link}</div>')
            sections += (f'<section id="lv{lv}"><h2><span class="dot" style="background:{lcolor}"></span>'
                         f'{lname}风险 <em>{len(items)}</em></h2><div class="list">{rows}</div></section>')
            continue
        sections += (f'<section id="lv{lv}"><h2><span class="dot" style="background:{lcolor}"></span>'
                     f'{lname}风险 <em>{len(items)}</em></h2><div class="grid">')
        sections += "".join(card(p) for p in items) + "</div></section>"
    if gone:
        sections += ('<section><h2>上次有、本次消失 <em>%d</em></h2><div class="gone">'
                     % len(gone) + "、".join(str(g["port"]) for g in gone) + "</div></section>")

    changed = sum(1 for p in pages if p.get("delta"))
    hist = _history_items(run_dir.parent)
    groups = {}
    for it in hist:
        groups.setdefault(it["date"], []).append(it)
    opts = ""
    for d in sorted(groups, reverse=True):
        opts += f'<optgroup label="{d}">'
        for it in groups[d]:
            sel = " selected" if it["run"] == run_dir.name else ""
            c = it["counts"]
            opts += (f'<option value="../{it["run"]}/report.html"{sel}>'
                     f'{it["date"]} {it["time"]} · {it["total"]} 条 · 极高 {c["X"]} / 高 {c["S"]}</option>')
        opts += "</optgroup>"
    hist_select = (f'<span class="hl">日期</span>'
                   f'<select onchange="if(this.value)location.href=this.value">{opts}</select>')
    html = f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{host} 巡查报告 · {meta['run_id']}</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#0f1115;color:#e6e8eb;font:14px/1.55 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}}
header{{padding:32px;border-bottom:1px solid #23262d;background:linear-gradient(180deg,#14171c,#0f1115)}}
h1{{margin:0 0 8px;font-size:22px}} .sub{{color:#98a0ab;font-size:13px}}
.sub b{{color:#e6e8eb}} .counts{{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}}
.counts span{{font-size:12.5px;border-radius:99px;padding:3px 11px;color:#fff}}
main{{padding:8px 32px 60px;max-width:1680px;margin:0 auto}}
section{{margin-top:32px}} h2{{font-size:15px;font-weight:600;color:#cfd4da;margin:0 0 14px;display:flex;align-items:center;gap:9px}}
h2 em{{font-style:normal;color:#7c8592;font-weight:400;font-size:12.5px}}
.dot{{width:9px;height:9px;border-radius:50%;display:inline-block}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:16px}}
.card{{background:#15181d;border:1px solid #23262d;border-radius:12px;overflow:hidden;color:inherit;display:flex;flex-direction:column}}
.card:hover{{border-color:#3d4450}}
.shot{{display:block;aspect-ratio:16/10;background:#0b0d10;border-bottom:1px solid #23262d;overflow:hidden}}
.open{{margin-left:auto;font-size:11.5px;color:#8ab4f8;text-decoration:none;border:1px solid #2f4b6e;border-radius:6px;padding:2px 8px;white-space:nowrap}}
.open:hover{{background:#16283c}}
.lo{{text-align:right}} .lo a{{color:#8ab4f8;text-decoration:none;font-size:12px}}
.shot img{{width:100%;height:100%;object-fit:cover;object-position:top}}
.meta{{padding:11px 13px 13px}} .row{{display:flex;gap:7px;align-items:center;margin-bottom:4px;flex-wrap:wrap}}
.port{{font-family:Consolas,monospace;font-size:15px;font-weight:700}}
.lvl{{font-size:11px;color:#fff;border-radius:4px;padding:1px 7px;font-weight:600}}
.kind{{font-size:11px;color:#9aa2ad;border:1px solid #2e333c;border-radius:4px;padding:1px 6px}}
.badge{{font-size:11px;color:#fff;border-radius:4px;padding:1px 7px}}
.t{{font-weight:600;font-size:13.5px;margin:3px 0}} .d{{color:#98a0ab;font-size:12px}}
.r{{color:#c7cdd4;font-size:12px;margin-top:4px;border-left:2px solid #2e333c;padding-left:7px}}
.list{{background:#15181d;border:1px solid #23262d;border-radius:10px;overflow:hidden}}
.li{{display:grid;grid-template-columns:70px 1fr 200px 42px 62px;gap:8px;padding:8px 12px;border-bottom:1px solid #1e2229;font-size:12.5px;align-items:center}}
.li:last-child{{border-bottom:0}}
.lp{{font-family:Consolas,monospace;font-weight:700}}
.ln{{color:#dfe3e8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.lk{{color:#8b93a1;font-size:11.5px;text-align:right}}
.ls{{color:#8b93a1;text-align:right;font-family:Consolas,monospace}}
.histrow{{margin-top:14px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
.histrow .hl{{color:#8b93a1;font-size:12.5px}}
.histrow select{{background:#1a1f27;color:#dfe3e8;border:1px solid #333a45;border-radius:8px;padding:6px 10px;font-size:12.5px;max-width:520px}}
.histlink{{color:#8ab4f8;font-size:12.5px;text-decoration:none}}
.histlink:hover{{text-decoration:underline}}
.gone{{color:#c8ced6;background:#15181d;border:1px solid #23262d;border-radius:10px;padding:14px}}
</style></head><body><header>
<h1>{host} · 网页巡查报告</h1>
<div class="sub">采集 {meta['run_id']} · 共 <b>{len(pages)}</b> 条隧道 · <b>{changed}</b> 条变化 · 对比基线 {meta.get('baseline') or '无'}</div>
<div class="counts"><span style="background:#d93025">极高 {counts['X']}</span>
<span style="background:#e8710a">高 {counts['S']}</span>
<span style="background:#1a73e8">中 {counts['B']}</span>
<span style="background:#5f6368">低 {counts['C']}</span></div>
<div class="histrow">{hist_select}<a class="histlink" href="../index.html">按日期浏览全部报告 →</a></div>
</header><main>{sections}</main></body></html>'''
    (run_dir / "report.html").write_text(html, encoding="utf-8")


# ---------------------------------------------------------------- 主流程
def run_patrol(quiet=False, only_ports=None, no_discovery=False, progress=None, profile_id=None):
    cfg = load_config()
    prof = load_profile(profile_id)
    host = prof["host"]
    pdata = DATA_ROOT / prof["_id"]
    log = lambda m: (add_log(m, quiet), progress and progress(m))
    pdata.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(exist_ok=True)

    targets = get_targets(prof, lambda m: log(m), no_discovery)
    if only_ports:
        targets = {int(p): targets.get(int(p), {"port": int(p), "name": "manual", "user": "", "status": ""})
                   for p in only_ports}
    if not targets:
        log("没有可用端口，退出")
        return None

    run_id = datetime.now().strftime("%Y-%m-%d_%H%M")
    run_dir = pdata / run_id
    (run_dir / "shots").mkdir(parents=True, exist_ok=True)
    (run_dir / "shots" / "thumbs").mkdir(parents=True, exist_ok=True)
    log(f"开始巡查 {host}，{len(targets)} 个端口 -> {run_dir.name}")

    # 1) 协议探测
    results = {}

    def do_probe(p):
        r = probe(host, p, cfg["capture"].get("probe_timeout", 6))
        r.update(name=targets[p].get("name", ""), user=targets[p].get("user", ""))
        return p, r

    with ThreadPoolExecutor(max_workers=12) as ex:
        for p, r in ex.map(do_probe, sorted(targets)):
            results[p] = r
            kind = r["kind"]
            log(f"  {p} {kind:<6} {r.get('status') or r.get('error') or ''} {r.get('title','')[:40]}")

    # 2) 截图
    web_ports = [p for p, r in results.items() if r["kind"] in ("http", "https", "binary")]
    browser = None
    if web_ports:
        log(f"启动无头浏览器，截取 {len(web_ports)} 个页面")
        try:
            browser = Browser(cfg, log)
        except Exception as e:
            log(f"浏览器启动失败: {e}")

    for i, p in enumerate(web_ports, 1):
        r = results[p]
        scheme = "https" if r["kind"] == "https" or r.get("final", "").startswith("https") else "http"
        url = f"{scheme}://{host}:{p}/"
        out = run_dir / "shots" / f"{p}.png"
        if browser:
            try:
                ok, title, final = browser.shot(url, out)
                if title:
                    r["title"] = r["title"] or title
                if final:
                    r["final"] = final
                if ok and is_blank(out) and r.get("status", "").startswith(("401", "403", "404")):
                    raise RuntimeError("blank-auth-page")
                r["ok"] = ok and not is_blank(out) or (ok and r.get("status", "")[:3] not in ("401", "403"))
            except Exception as e:
                r["ok"] = out.exists() and not is_blank(out)
                if r.get("status", "").startswith(("401", "403")):
                    info_card(out, host, r)
                    r["ok"] = True
                    r["info_card"] = True
                else:
                    log(f"  {p} 截图失败: {e}")
        else:
            r["ok"] = False
        if not out.exists():
            info_card(out, host, r)
            r["ok"] = True
            r["info_card"] = True
        if out.exists():
            r["hash"] = dhash(out)
            make_thumb(out, run_dir / "shots" / "thumbs" / f"{p}.jpg")
        log(f"  截图 {i}/{len(web_ports)}  {p} {'OK' if r.get('ok') else 'X'}")
    if browser:
        browser.close()

    # 3) 非网页端口也生成信息卡
    for p, r in results.items():
        out = run_dir / "shots" / f"{p}.png"
        if not out.exists():
            info_card(out, host, r)
            r["ok"] = True
            r["info_card"] = True
            r["hash"] = dhash(out)
            make_thumb(out, run_dir / "shots" / "thumbs" / f"{p}.jpg")

    # 4) 对比上一轮
    prev_dirs = sorted([d for d in pdata.iterdir() if d.is_dir() and (d / "meta.json").exists()
                        and d.name != run_id], reverse=True)
    prev_meta = None
    if prev_dirs:
        try:
            prev_meta = json.loads((prev_dirs[0] / "meta.json").read_text(encoding="utf-8"))
        except Exception:
            prev_meta = None

    pages = []
    for p in sorted(results):
        r = results[p]
        page = {
            "port": p, "name": r.get("name"), "user": r.get("user"), "kind": r["kind"],
            "status": r.get("status"), "server": r.get("server"), "title": r.get("title"),
            "final": r.get("final"), "ok": bool(r.get("ok")), "info_card": bool(r.get("info_card")),
            "hash": r.get("hash", 0), "headers": r.get("headers"), "body": (r.get("body") or "")[:2000],
        }
        page["risk"] = riskmod.assess(page, host, prof)
        if page["kind"] == "closed" and prev_meta:
            old = next((q for q in prev_meta.get("pages", []) if q.get("port") == p), None)
            old_risk = (old or {}).get("risk")
            if old_risk:
                page["risk"] = dict(old_risk)
                page["risk"]["reasons"] = ["本次离线，沿用上次风险"] + (old_risk.get("reasons") or [])[:2]
        pages.append(page)
    meta = {
        "run_id": run_id,
        "profile": {"id": prof["_id"], "name": prof.get("name"), "mode": prof.get("mode")},
        "host": host,
        "baseline": prev_dirs[0].name if prev_dirs else None,
        "change_threshold": cfg.get("report", {}).get("change_threshold", 12),
        "pages": pages,
    }
    build_report(run_dir, meta, prev_meta, host)
    (run_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    try:
        build_index(pdata, prof)
    except Exception as e:
        log(f"索引页生成失败: {e}")

    # 5) 最新入口 + 清理
    latest = pdata / "latest.html"
    latest.write_text(f'<!doctype html><meta charset="utf-8">'
                      f'<meta http-equiv="refresh" content="0;url={run_id}/report.html">',
                      encoding="utf-8")
    keep = cfg.get("report", {}).get("keep_days", 60)
    cutoff = datetime.now() - timedelta(days=keep)
    for d in pdata.iterdir():
        if d.is_dir() and d.name[:10].count("-") == 2:
            try:
                if datetime.strptime(d.name[:10], "%Y-%m-%d") < cutoff:
                    shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass

    changed = sum(1 for p in pages if p.get("delta"))
    lv_count = {k: sum(1 for p in pages if p["risk"]["level"] == k) for k in "XSBC"}
    log(f"风险分布：极高 {lv_count['X']} / 高 {lv_count['S']} / 中 {lv_count['B']} / 低 {lv_count['C']}")
    for p in sorted([x for x in pages if x["risk"]["level"] in ("X", "S")],
                    key=lambda x: -x["risk"]["score"])[:12]:
        log(f"  ⚠ {p['port']} [{p['risk']['label']} {p['risk']['score']}] "
            f"{p.get('title') or p.get('name') or ''} — {'；'.join(p['risk']['reasons'][:2])}")
    log(f"完成：{len(pages)} 个端口，{changed} 条变化，报告 {run_dir / 'report.html'}")
    return str(run_dir / "report.html")


def rebuild_reports(profile_id=None):
    """用现有 meta.json 重新生成所有历史报告与索引（补上日期导航）。"""
    prof = load_profile(profile_id)
    pdata = DATA_ROOT / prof["_id"]
    runs = sorted([d for d in pdata.iterdir() if (d / "meta.json").exists()])
    prev = None
    n = 0
    for d in runs:
        try:
            meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
        except Exception:
            continue
        build_report(d, meta, prev, meta.get("host") or prof["host"])
        prev = meta
        n += 1
    build_index(pdata, prof)
    return n


# ---------------------------------------------------------------- 计划任务
def task_name(pid=None):
    pid = pid or load_config().get("active_profile", "default")
    return f"FrpSitePatrol_{pid}"


def _cron_read():
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def _cron_write(text):
    try:
        r = subprocess.run(["crontab", "-"], input=text, capture_output=True, text=True)
        return r.returncode == 0, (r.stderr or r.stdout).strip()
    except Exception as e:
        return False, str(e)


def _cron_marker(pid):
    return f"# FrpSitePatrol_{pid}"


def install_task(hhmm, pid=None):
    pid = pid or load_config().get("active_profile", "default")
    hh, mm = hhmm.split(":")[0], hhmm.split(":")[1]
    if os.name != "nt":
        cur = _cron_read()
        lines = [l for l in cur.splitlines() if _cron_marker(pid) not in l]
        if getattr(sys, "frozen", False):
            cmd = f'"{sys.executable}" run --quiet --profile {pid}'
        else:
            cmd = f'cd "{ROOT}" && "{sys.executable}" "{ROOT / "patrol.py"}" run --quiet --profile {pid}'
        line = (f'{int(mm)} {int(hh)} * * * {cmd} >> "{ROOT}/data/cron.log" 2>&1 '
                f'{_cron_marker(pid)}')
        ok, msg = _cron_write("\n".join(lines + [line]) + "\n")
        return ok, msg or "已写入用户 crontab"
    if getattr(sys, "frozen", False):
        cmd = f'"{sys.executable}" run --quiet --profile {pid}'
    else:
        py = Path(sys.executable)
        pyw = py.with_name("pythonw.exe")
        exe = pyw if pyw.exists() else py
        cmd = f'"{exe}" "{ROOT / "patrol.py"}" run --quiet --profile {pid}'
    r = subprocess.run(["schtasks", "/Create", "/F", "/TN", task_name(pid), "/TR", cmd,
                        "/SC", "DAILY", "/ST", hhmm, "/RL", "LIMITED"],
                       capture_output=True, text=True, encoding="gbk", errors="ignore")
    return r.returncode == 0, (r.stdout or r.stderr).strip()


def uninstall_task(pid=None):
    pid = pid or load_config().get("active_profile", "default")
    if os.name != "nt":
        cur = _cron_read()
        lines = [l for l in cur.splitlines() if _cron_marker(pid) not in l]
        return _cron_write("\n".join(lines) + "\n")
    r = subprocess.run(["schtasks", "/Delete", "/F", "/TN", task_name(pid)],
                       capture_output=True, text=True, encoding="gbk", errors="ignore")
    return r.returncode == 0, (r.stdout or r.stderr).strip()


def task_exists(pid=None):
    pid = pid or load_config().get("active_profile", "default")
    if os.name != "nt":
        return _cron_marker(pid) in _cron_read()
    r = subprocess.run(["schtasks", "/Query", "/TN", task_name(pid)],
                       capture_output=True, text=True, encoding="gbk", errors="ignore")
    return r.returncode == 0


# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="Frp 站点每日巡查截图")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("run", help="立即巡查")
    r.add_argument("--quiet", action="store_true")
    r.add_argument("--ports", help="只查这些端口，逗号分隔")
    r.add_argument("--no-discovery", action="store_true")
    r.add_argument("--profile", help="节点 id（默认当前节点）")
    d = sub.add_parser("discover", help="只列出面板里的隧道")
    d.add_argument("--profile", help="节点 id")
    sub.add_parser("profiles", help="列出所有节点")
    it = sub.add_parser("install-task", help="安装每日计划任务")
    it.add_argument("--time", default="09:00")
    it.add_argument("--profile", help="节点 id")
    rb = sub.add_parser("rebuild", help="重新生成历史报告与索引")
    rb.add_argument("--profile", help="节点 id")
    ut = sub.add_parser("uninstall-task", help="删除计划任务")
    ut.add_argument("--profile", help="节点 id")
    op = sub.add_parser("open", help="打开最新报告")
    op.add_argument("--profile", help="节点 id")
    a = ap.parse_args()
    if a.cmd == "run":
        ports = [int(x) for x in a.ports.split(",")] if a.ports else None
        run_patrol(a.quiet, ports, a.no_discovery, profile_id=a.profile)
    elif a.cmd == "discover":
        prof = load_profile(a.profile)
        try:
            rows = discover(prof, print)
        except Exception as e:
            print(f"错误：{e}")
            sys.exit(1)
        for p, v in sorted(rows.items()):
            print(f'{p}\t{v["status"]}\t{v["user"]}\t{v["name"]}')
    elif a.cmd == "profiles":
        act = load_config().get("active_profile")
        for x in list_profiles():
            print(("· " if x["id"] == act else "  ") + f'{x["id"]}\t{x["name"]}\t{x["host"]}\t{x["mode"]}')
    elif a.cmd == "rebuild":
        n = rebuild_reports(a.profile)
        print(f"已重建 {n} 份报告，并更新 index.html")
    elif a.cmd == "install-task":
        ok, msg = install_task(a.time, a.profile)
        print(("已安装" if ok else "安装失败") + f" 每日 {a.time}: {msg}")
    elif a.cmd == "uninstall-task":
        ok, msg = uninstall_task(a.profile)
        print(("已删除" if ok else "删除失败") + f": {msg}")
    elif a.cmd == "open":
        prof = load_profile(a.profile)
        latest = DATA_ROOT / prof["_id"] / "latest.html"
        if latest.exists():
            open_path(latest)
        else:
            print("还没有报告，先运行 run")
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
