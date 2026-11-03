# -*- coding: utf-8 -*-
"""风险评分：把一条隧道判成 极高/高/中/低，并给出理由。"""
import json
import re

import requests

LEVELS = {"X": ("极高", 90, "#d93025"), "S": ("高", 72, "#e8710a"),
          "B": ("中", 45, "#1a73e8"), "C": ("低", 0, "#5f6368")}

# 内容类：命中即高危/极高（可继续补充关键词）
CONTENT_RULES = [
    (r"#EXTM3U|CCTV-?1[0-9]?|CCTV[1-9]|卫视|直播源|回看|miguvideo|iptv|电视直播", 96, "疑似 IPTV/电视直播转播"),
    (r"LunaTV|影视聚合|苹果CMS|资源站|蓝光影视|高清影院|在线影院|免费电影|追剧", 92, "疑似盗版影视聚合"),
    (r"博彩|菠菜|赌场|彩票投注|六合彩|时时彩|真人娱乐|体育投注|棋牌|百家乐|澳门|下注", 99, "疑似博彩"),
    (r"色情|成人视频|成人片|裸聊|约炮|黄片|AV片|情色", 99, "疑似色情内容"),
    (r"刷单|返利|跑分|洗钱|代付|杀猪盘|高收益理财|USDT.{0,6}充值", 96, "疑似诈骗/洗钱"),
]

# 指纹类：服务类型本身的暴露风险
APP_RULES = [
    (r"fnOS|飞牛", 86, "NAS 管理后台公网暴露"),
    (r"群晖|Synology|DSM|威联通|QNAP|TrueNAS", 86, "NAS 管理后台公网暴露"),
    (r"CSP-J|教师后台|教务|学生管理", 80, "教育后台，含学生信息"),
    (r"ERP", 76, "企业 ERP 公网暴露"),
    (r"RAGFlow", 76, "AI 知识库，可能含企业文档"),
    (r"RustFS", 80, "对象存储控制台"),
    (r"MCSManager", 82, "游戏面板 Daemon，可接管"),
    (r"NapCat|OneBot", 78, "QQ 机器人 WebUI"),
    (r"AstrBot", 70, "机器人 Dashboard"),
    (r"MT Photos|mtphotos|PhotoPrism|Immich", 76, "私人相册服务"),
    (r"Memos", 72, "笔记服务，可能含个人信息"),
    (r"lucky", 62, "反代管理面"),
    (r"OneNav", 55, "导航站后台"),
    (r"Verysync|微力同步", 50, "文件同步服务"),
    (r"FluxDown", 46, "下载器 Web 界面"),
    (r"WorkBuddy", 45, "内部管理后台"),
    (r"DeepSeek Harness|codeapi", 70, "AI 接口中转（Basic 认证）"),
    (r"录播姬|BililiveRecorder|mikufans", 45, "录播工具后台"),
    (r"AList|TvBox", 80, "影视源/网盘聚合"),
    (r"OpenList", 60, "网盘服务"),
    (r"调查表|问卷|survey", 55, "公网表单，可被刷数据"),
    (r"RustDesk", 82, "远程控制通道"),
    (r"RCON", 78, "Minecraft 远程控制台"),
    (r"SSH", 78, "SSH 公网暴露"),
    (r"RDP|Windows", 82, "远程桌面公网暴露"),
]

VIDEO_EXT = (".mp4", ".mkv", ".avi", ".mov", ".ts", ".m3u8", ".iso", ".rmvb", ".wmv")


def _norm(page, with_body=True):
    parts = [page.get("name"), page.get("title"), page.get("server"),
             page.get("final"), json.dumps(page.get("headers") or {}, ensure_ascii=False)]
    if with_body:
        parts.append(page.get("body"))
    return " ".join(p for p in parts if p)


def _openlist_listing(host, port, page):
    """尝试匿名列 OpenList/AList 根目录，返回 (公开?, 文件名列表)。"""
    try:
        url = f"http://{host}:{port}/api/fs/list"
        r = requests.post(url, json={"path": "/", "password": "", "page": 1,
                                     "per_page": 50, "refresh": False},
                          timeout=5, verify=False)
        if r.status_code != 200:
            return False, []
        d = r.json()
        if d.get("code") != 200 or not d.get("data"):
            return False, []
        names = [c.get("name", "") for c in (d["data"].get("content") or [])]
        return True, names
    except Exception:
        return False, []


def assess(page, host, cfg=None):
    """返回 {score, level, label, reasons[]}"""
    cfg = cfg or {}
    head = _norm(page, with_body=False)
    text = _norm(page, with_body=True)
    score = 30
    reasons = []

    kind = page.get("kind")
    if kind == "closed":
        base = 5
    elif kind in ("ssh", "rdp"):
        base = 70
    elif kind in ("tcp", "binary"):
        base = 20
    elif kind == "https":
        base = 32
    else:
        base = 30
    score = max(score, base)
    content_hit = False

    def hit(regex, value, why, hay=None):
        nonlocal score, content_hit
        if re.search(regex, hay if hay is not None else text, re.I):
            score = max(score, value)
            if hay is None:
                content_hit = True
            if why not in reasons:
                reasons.append(why)

    for rx, val, why in CONTENT_RULES:
        hit(rx, val, why)
    for rx, val, why in APP_RULES:
        hit(rx, val, why, hay=head)

    # OpenList / AList：先认程序特征，再实际列一次根目录
    is_disk = bool(re.search(r"OpenList|AList|嘻嘻", head, re.I) or
                   re.search(r'name="generator" content="(OpenList|AList)"|OPENLIST_CONFIG|Powered by Alist|/api/fs/list', text, re.I))
    if is_disk:
        score = max(score, 60)
        if page.get("kind") in ("http", "https"):
            public, names = _openlist_listing(host, page["port"], page)
            vids = [n for n in names if n.lower().endswith(VIDEO_EXT)]
            if public and vids:
                score = max(score, 96)
                content_hit = True
                reasons.insert(0, f"免登录影视片库（{len(vids)} 个视频：{'、'.join(vids[:4])}）")
            elif public and names:
                score = max(score, 68)
                reasons.insert(0, f"免登录网盘目录（{len(names)} 项）")
            elif not public:
                reasons.append("网盘需鉴权")
        if "网盘服务" not in reasons:
            reasons.append("网盘服务")

    # 登录/认证页 + 老版本 + 隐藏标识 等小幅加权
    status = str(page.get("status") or "")
    if status.startswith(("401", "403")):
        score += 4
        reasons.append("需认证，但服务本身公网可达")
    srv = str(page.get("server") or "")
    m = re.search(r"nginx/(\d+)\.(\d+)", srv)
    if m and int(m.group(1)) < 1 or (m and int(m.group(1)) == 1 and int(m.group(2)) < 18):
        score += 8
        reasons.append(f"组件过旧（{srv}）")
    if re.search(r"隐藏|去掉底部|Powered by", text, re.I) and re.search(r"Alist|OpenList", text, re.I):
        score += 6
        reasons.append("页面刻意隐藏程序标识")
    if not reasons and page.get("ok"):
        reasons.append("普通 Web 服务，未见明显违规")

    # 手动覆盖
    ov = (cfg.get("risk_overrides") or {}).get(str(page.get("port")))
    if ov:
        if isinstance(ov, str):
            score = LEVELS[ov][1] if ov in LEVELS else score
            reasons.insert(0, "手动标记")
        elif isinstance(ov, dict):
            if ov.get("level") in LEVELS:
                score = LEVELS[ov["level"]][1]
            if ov.get("note"):
                reasons.insert(0, ov["note"])

    if not content_hit and score > 89:
        score = 89
    score = max(0, min(100, score))
    level = "X" if score >= 90 else "S" if score >= 72 else "B" if score >= 45 else "C"
    return {"score": score, "level": level, "label": LEVELS[level][0],
            "reasons": reasons[:4]}
