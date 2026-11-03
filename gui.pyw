# -*- coding: utf-8 -*-
"""Frp 站点巡查 - 图形界面（双击运行）"""
import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

import patrol

if getattr(sys, "frozen", False):
    ROOT = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parent
BG = "#f5f6f8"
CARD = "#ffffff"
FG = "#1f2329"
MUTED = "#6b7280"
ACCENT = "#1a73e8"

MODE_TEXT = {"frps": "面板发现", "range": "端口扫描", "static": "手动列表"}
MODE_VALUE = {v: k for k, v in MODE_TEXT.items()}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Frp 站点巡查")
        self.geometry("900x640")
        self.minsize(780, 560)
        self.configure(bg=BG)
        self.q = queue.Queue()
        self.proc = None
        self.auto_open = tk.BooleanVar(value=True)
        self.profiles = []
        self._build()
        self.after(120, self._poll)
        self.reload_profiles()
        if not self.profiles:
            self.after(300, lambda: self.edit_profile(new=True))

    # ------------------------------------------------------------ UI
    def _build(self):
        head = tk.Frame(self, bg="#111827", padx=20, pady=14)
        head.pack(fill="x")
        tk.Label(head, text="Frp 站点巡查", bg="#111827", fg="white",
                 font=("Microsoft YaHei UI", 16, "bold")).pack(anchor="w")
        self.sub = tk.Label(head, text="", bg="#111827", fg="#9ca3af",
                            font=("Microsoft YaHei UI", 9))
        self.sub.pack(anchor="w", pady=(3, 0))

        sel = tk.Frame(self, bg=BG, padx=18)
        sel.pack(fill="x", pady=(10, 0))
        tk.Label(sel, text="节点", bg=BG, fg=MUTED,
                 font=("Microsoft YaHei UI", 9)).pack(side="left", padx=(0, 6))
        self.cb = ttk.Combobox(sel, state="readonly", width=42, font=("Microsoft YaHei UI", 9))
        self.cb.pack(side="left")
        self.cb.bind("<<ComboboxSelected>>", self.on_profile_change)
        self._ghost(sel, "新建节点", lambda: self.edit_profile(new=True)).pack(side="left", padx=6)
        self._ghost(sel, "编辑节点", lambda: self.edit_profile(new=False)).pack(side="left")

        stats = tk.Frame(self, bg=BG, padx=18, pady=12)
        stats.pack(fill="x")
        self.stat_labels = {}
        for key, color, text in (("X", "#d93025", "极高"), ("S", "#e8710a", "高"),
                                 ("B", "#1a73e8", "中"), ("C", "#6b7280", "低")):
            box = tk.Frame(stats, bg=CARD, highlightbackground="#e5e7eb",
                           highlightthickness=1, padx=14, pady=9)
            box.pack(side="left", padx=(0, 10))
            v = tk.Label(box, text="0", bg=CARD, fg=color,
                         font=("Microsoft YaHei UI", 17, "bold"))
            v.pack(anchor="w")
            tk.Label(box, text=text + "风险", bg=CARD, fg=MUTED,
                     font=("Microsoft YaHei UI", 9)).pack(anchor="w")
            self.stat_labels[key] = v
        self.change_label = tk.Label(stats, text="", bg=BG, fg=MUTED,
                                     font=("Microsoft YaHei UI", 9))
        self.change_label.pack(side="left", padx=8)

        bar = tk.Frame(self, bg=BG, padx=18)
        bar.pack(fill="x")
        self.btn_run = tk.Button(bar, text="立即巡查", command=self.start_run,
                                 bg=ACCENT, fg="white", activebackground="#1667d6",
                                 activeforeground="white", relief="flat", bd=0,
                                 padx=18, pady=8, font=("Microsoft YaHei UI", 10, "bold"),
                                 cursor="hand2")
        self.btn_run.pack(side="left")
        self._ghost(bar, "打开最新报告", self.open_report).pack(side="left", padx=8)
        self._ghost(bar, "历史报告", self.open_history).pack(side="left", padx=8)
        self.btn_task = self._ghost(bar, "设置每日任务", self.toggle_task)
        self.btn_task.pack(side="left")
        self._ghost(bar, "打开数据目录", self.open_data).pack(side="left", padx=8)
        self._ghost(bar, "编辑节点文件", self.open_profile_file).pack(side="left")
        tk.Checkbutton(bar, text="完成后打开报告", variable=self.auto_open, bg=BG,
                       fg=MUTED, activebackground=BG, font=("Microsoft YaHei UI", 9)
                       ).pack(side="right")

        pf = tk.Frame(self, bg=BG, padx=18, pady=8)
        pf.pack(fill="x")
        self.pb = ttk.Progressbar(pf, mode="determinate", value=0, maximum=100)
        self.pb.pack(fill="x")
        self.status = tk.Label(pf, text="就绪", bg=BG, fg=MUTED, anchor="w",
                               font=("Microsoft YaHei UI", 9))
        self.status.pack(fill="x", pady=(4, 0))

        body = tk.Frame(self, bg=BG, padx=18)
        body.pack(fill="both", expand=True, pady=(0, 16))
        self.log = tk.Text(body, bg="#0f1115", fg="#d7dbe0", insertbackground="white",
                           relief="flat", bd=0, padx=12, pady=10, wrap="word",
                           font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")
        self.refresh_task_button()

    def _ghost(self, parent, text, cmd):
        return tk.Button(parent, text=text, command=cmd, bg="#ffffff", fg=FG,
                         activebackground="#eef2f7", relief="flat", bd=0,
                         highlightbackground="#d7dbe0", highlightthickness=1,
                         padx=12, pady=7, font=("Microsoft YaHei UI", 9), cursor="hand2")

    # ------------------------------------------------------------ 节点
    def active_profile(self):
        try:
            cfg = patrol.load_config()
            return patrol.load_profile(cfg.get("active_profile"))
        except Exception:
            return None

    def reload_profiles(self):
        self.profiles = patrol.list_profiles()
        labels = [f'{p["name"]}  ({p["host"]})' for p in self.profiles]
        self.cb.configure(values=labels)
        act = patrol.load_config().get("active_profile")
        idx = next((i for i, p in enumerate(self.profiles) if p["id"] == act), 0)
        if self.profiles:
            self.cb.current(idx)
            patrol.set_active(self.profiles[idx]["id"])
        self.refresh_overview()
        self.refresh_task_button()

    def on_profile_change(self, _=None):
        idx = self.cb.current()
        if 0 <= idx < len(self.profiles):
            patrol.set_active(self.profiles[idx]["id"])
        self.refresh_overview()
        self.refresh_task_button()

    def edit_profile(self, new=False):
        prof = None if new else self.active_profile()
        if not new and not prof:
            return
        dlg = ProfileDialog(self, prof)
        self.wait_window(dlg)
        if dlg.saved:
            self.reload_profiles()

    def open_profile_file(self):
        prof = self.active_profile()
        if prof:
            f = str(patrol.profile_path(prof["_id"]))
            if os.name == "nt":
                subprocess.Popen(["notepad.exe", f])
            else:
                patrol.open_path(f)

    # ------------------------------------------------------------ 状态
    def refresh_overview(self):
        prof = self.active_profile()
        if not prof:
            self.sub.configure(text="还没有节点，点击“新建节点”开始")
            return
        pdata = patrol.DATA_ROOT / prof["_id"]
        runs = sorted([d for d in pdata.iterdir() if d.is_dir() and (d / "meta.json").exists()],
                      reverse=True) if pdata.exists() else []
        mode = MODE_TEXT.get(prof.get("mode"), prof.get("mode"))
        self.sub.configure(text=f'{prof.get("name")} · {prof["host"]} · {mode} · '
                                f'端口 {prof["port_min"]}-{prof["port_max"]} · {len(runs)} 份报告')
        if not runs:
            for v in self.stat_labels.values():
                v.configure(text="0")
            self.change_label.configure(text="还没有巡查记录")
            return
        try:
            meta = json.load(open(runs[0] / "meta.json", encoding="utf-8"))
        except Exception:
            return
        pages = meta.get("pages", [])
        cnt = {k: sum(1 for p in pages if (p.get("risk") or {}).get("level") == k) for k in "XSBC"}
        for k, v in cnt.items():
            self.stat_labels[k].configure(text=str(v))
        ch = sum(1 for p in pages if p.get("delta"))
        t = meta.get("run_id", "").replace("_", " ")
        self.change_label.configure(text=f"最近 {t} · {len(pages)} 条隧道 · {ch} 条变化")

    def refresh_task_button(self):
        prof = self.active_profile()
        try:
            exists = patrol.task_exists(prof["_id"]) if prof else False
        except Exception:
            exists = False
        self.btn_task.configure(text="取消每日任务" if exists else "设置每日任务")

    # ------------------------------------------------------------ 运行
    def start_run(self):
        if self.proc and self.proc.poll() is None:
            return
        prof = self.active_profile()
        if not prof:
            messagebox.showinfo("提示", "请先新建节点。")
            return
        self.btn_run.configure(state="disabled", text="巡查中…")
        self.pb.configure(mode="indeterminate")
        self.pb.start(12)
        self.status.configure(text="正在发现端口并截图，请稍候…")
        self._clear_log()
        self._append(f"[{datetime.now():%H:%M:%S}] 开始巡查 {prof['host']}\n")
        py = Path(sys.executable)
        python = py.with_name("python.exe") if py.name.lower() != "python.exe" else py
        if not python.exists():
            python = py
        if getattr(sys, "frozen", False):
            def work():
                try:
                    patrol.run_patrol(profile_id=prof["_id"], progress=lambda m: self.q.put(m))
                except Exception as e:
                    self.q.put(f"[错误] {e}")
                self.q.put("__DONE__")
            self.proc = None
            threading.Thread(target=work, daemon=True).start()
            return
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
        self.proc = subprocess.Popen(
            [str(python), str(ROOT / "patrol.py"), "run", "--profile", prof["_id"]],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", env=env,
            creationflags=0x08000000 if os.name == "nt" else 0)
        threading.Thread(target=self._reader, args=(self.proc,), daemon=True).start()

    def _reader(self, proc):
        for line in proc.stdout:
            self.q.put(line.rstrip())
        proc.wait()
        self.q.put("__DONE__")

    def _poll(self):
        try:
            while True:
                line = self.q.get_nowait()
                if line == "__DONE__":
                    self._finish()
                else:
                    self._append(line + "\n")
        except queue.Empty:
            pass
        self.after(120, self._poll)

    def _finish(self):
        self.pb.stop()
        self.pb.configure(mode="determinate", value=0)
        self.btn_run.configure(state="normal", text="立即巡查")
        self.status.configure(text=f"完成 · {datetime.now():%H:%M:%S}")
        self.refresh_overview()
        self.refresh_task_button()
        if self.auto_open.get():
            self.open_report()

    def _append(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ------------------------------------------------------------ 动作
    def open_report(self):
        prof = self.active_profile()
        if not prof:
            return
        latest = patrol.DATA_ROOT / prof["_id"] / "latest.html"
        if latest.exists():
            patrol.open_path(latest)
        else:
            messagebox.showinfo("提示", "还没有报告，先点“立即巡查”。")

    def open_history(self):
        prof = self.active_profile()
        if not prof:
            return
        pdata = patrol.DATA_ROOT / prof["_id"]
        index = pdata / "index.html"
        if not index.exists():
            try:
                patrol.build_index(pdata, prof)
            except Exception as e:
                messagebox.showerror("提示", f"还没有历史记录：{e}")
                return
        patrol.open_path(index)

    def open_data(self):
        prof = self.active_profile()
        if prof:
            d = patrol.DATA_ROOT / prof["_id"]
            d.mkdir(parents=True, exist_ok=True)
            patrol.open_path(d)

    def toggle_task(self):
        prof = self.active_profile()
        if not prof:
            return
        pid = prof["_id"]
        if patrol.task_exists(pid):
            if messagebox.askyesno("取消每日任务", f"确定删除节点“{prof['name']}”的每日任务？"):
                ok, msg = patrol.uninstall_task(pid)
                messagebox.showinfo("结果", msg if ok else f"失败：{msg}")
        else:
            dlg = tk.Toplevel(self)
            dlg.title("设置每日巡查")
            dlg.geometry("320x180")
            dlg.configure(bg=BG)
            dlg.transient(self)
            dlg.grab_set()
            tk.Label(dlg, text="每天几点自动巡查？", bg=BG, fg=FG,
                     font=("Microsoft YaHei UI", 10)).pack(pady=(20, 8))
            e = tk.Entry(dlg, justify="center", font=("Consolas", 12))
            e.insert(0, "09:00")
            e.pack(pady=4)
            tk.Label(dlg, text="格式 HH:MM；Windows 用计划任务，Linux 写入用户 crontab", bg=BG, fg=MUTED,
                     font=("Microsoft YaHei UI", 8)).pack()

            def do():
                t = e.get().strip()
                try:
                    datetime.strptime(t, "%H:%M")
                except Exception:
                    messagebox.showerror("格式错误", "请填 HH:MM，例如 09:00")
                    return
                ok, msg = patrol.install_task(t, pid)
                dlg.destroy()
                messagebox.showinfo("结果", f"已设置每天 {t} 巡查" if ok else f"失败：{msg}")
                self.refresh_task_button()

            tk.Button(dlg, text="确定", command=do, bg=ACCENT, fg="white",
                      relief="flat", bd=0, padx=18, pady=6).pack(pady=12)
        self.refresh_task_button()


class ProfileDialog(tk.Toplevel):
    """新建 / 编辑节点"""

    def __init__(self, master, prof=None):
        super().__init__(master)
        self.saved = False
        self.prof = prof or {}
        self.title("编辑节点" if prof else "新建节点")
        self.geometry("480x680")
        self.configure(bg=BG)
        self.transient(master)
        self.grab_set()
        self.vars = {}
        self.row = 0
        self._build()

    def _row(self, parent, label, key, default="", width=34):
        r = self.row
        self.row += 1
        tk.Label(parent, text=label, bg=BG, fg=FG, anchor="w",
                 font=("Microsoft YaHei UI", 9)).grid(row=r, column=0, sticky="w", pady=5, padx=(0, 10))
        v = tk.StringVar(value=str(default))
        opts = {"show": "*"} if key == "web_password" else {}
        e = tk.Entry(parent, textvariable=v, width=width, font=("Consolas", 10), **opts)
        e.grid(row=r, column=1, sticky="w", pady=5)
        self.vars[key] = v
        return e

    def _build(self):
        p = self.prof
        pad = tk.Frame(self, bg=BG, padx=20, pady=16)
        pad.pack(fill="both", expand=True)
        self._row(pad, "节点名称", "name", p.get("name", ""))
        self._row(pad, "服务器 IP/域名", "host", p.get("host", ""))
        r = self.row
        self.row += 1
        tk.Label(pad, text="获取端口方式", bg=BG, fg=FG, anchor="w",
                 font=("Microsoft YaHei UI", 9)).grid(row=r, column=0, sticky="w", pady=5)
        self.mode = ttk.Combobox(pad, state="readonly", width=31,
                                 values=list(MODE_TEXT.values()))
        self.mode.current(list(MODE_VALUE).index(MODE_TEXT.get(p.get("mode", "frps"), "面板发现")))
        self.mode.grid(row=r, column=1, sticky="w", pady=5)
        self._row(pad, "端口起", "port_min", p.get("port_min", 30000))
        self._row(pad, "端口止", "port_max", p.get("port_max", 60000))
        self._row(pad, "面板地址（含端口）", "frps_web", p.get("frps_web", ""))
        self._row(pad, "面板用户名（可选）", "panel_user", p.get("panel_user", ""))
        self._row(pad, "面板密码", "web_password", p.get("web_password", ""))
        self._row(pad, "额外端口（逗号）", "extra_ports",
                  ",".join(str(x) for x in p.get("extra_ports", [])))
        self._row(pad, "排除端口（逗号）", "exclude_ports",
                  ",".join(str(x) for x in p.get("exclude_ports", [])))
        self._row(pad, "手动端口（逗号）", "static_ports",
                  ",".join(str(x) for x in p.get("static_ports", [])))
        self._row(pad, "扫描超时(秒)", "scan_timeout", p.get("scan_timeout", 0.8))
        self._row(pad, "扫描并发", "scan_workers", p.get("scan_workers", 200))

        hint = tk.Label(pad, text="面板地址填完整 URL，端口任意：标准 frps 常见 7500，ME Frp 常见 2396，HTTPS 也可。\n"
                                  "端口扫描会连接端口段内每个端口，只扫描自己的服务器。",
                        bg=BG, fg=MUTED, wraplength=400, justify="left",
                        font=("Microsoft YaHei UI", 8))
        hint.grid(row=self.row, column=0, columnspan=2, sticky="w", pady=(10, 0))

        btns = tk.Frame(self, bg=BG, padx=20, pady=12)
        btns.pack(fill="x")
        tk.Button(btns, text="保存", command=self.save, bg=ACCENT, fg="white",
                  relief="flat", bd=0, padx=20, pady=7,
                  font=("Microsoft YaHei UI", 9, "bold")).pack(side="right")
        self.btn_test = tk.Button(btns, text="测试面板", command=self.test_panel,
                                  bg="#ffffff", fg=FG, relief="flat", bd=0,
                                  highlightbackground="#d7dbe0", highlightthickness=1,
                                  padx=14, pady=7, font=("Microsoft YaHei UI", 9))
        self.btn_test.pack(side="right", padx=8)
        tk.Button(btns, text="取消", command=self.destroy, bg="#ffffff", fg=FG,
                  relief="flat", bd=0, highlightbackground="#d7dbe0", highlightthickness=1,
                  padx=16, pady=7).pack(side="right", padx=8)

    def collect(self):
        g = {k: v.get().strip() for k, v in self.vars.items()}
        if not g.get("name"):
            messagebox.showerror("提示", "节点名称不能为空", parent=self)
            return None
        if not g.get("host"):
            messagebox.showerror("提示", "服务器 IP/域名不能为空", parent=self)
            return None
        try:
            lo, hi = int(g["port_min"]), int(g["port_max"])
            if lo > hi:
                raise ValueError
        except Exception:
            messagebox.showerror("提示", "端口范围不正确", parent=self)
            return None

        def nums(s):
            out = []
            for x in (s or "").split(","):
                x = x.strip()
                if x:
                    out.append(int(x))
            return out

        try:
            prof = {
                "name": g["name"],
                "host": g["host"],
                "mode": MODE_VALUE[self.mode.get()],
                "frps_web": g.get("frps_web", ""),
                "panel_user": g.get("panel_user") or "admin",
                "web_password": g.get("web_password", ""),
                "port_min": lo,
                "port_max": hi,
                "extra_ports": nums(g.get("extra_ports")),
                "exclude_ports": nums(g.get("exclude_ports")),
                "static_ports": nums(g.get("static_ports")),
                "scan_timeout": float(g.get("scan_timeout") or 0.8),
                "scan_workers": int(g.get("scan_workers") or 200),
                "risk_overrides": self.prof.get("risk_overrides", {}),
            }
        except Exception:
            messagebox.showerror("提示", "端口或数值格式不正确", parent=self)
            return None
        return prof

    def test_panel(self):
        prof = self.collect()
        if not prof:
            return
        self.btn_test.configure(state="disabled", text="测试中…")

        def work():
            try:
                res = patrol.discover(prof, lambda m: None)
                msg = f"连接成功，发现 {len(res)} 条 TCP 隧道。"
                err = False
            except Exception as e:
                msg = str(e)
                err = True
            self.after(0, lambda: (self.btn_test.configure(state="normal", text="测试面板"),
                                   messagebox.showerror("面板连接失败", msg) if err
                                   else messagebox.showinfo("面板连接", msg)))

        threading.Thread(target=work, daemon=True).start()

    def save(self):
        prof = self.collect()
        if not prof:
            return
        pid = patrol.save_profile(prof, self.prof.get("_id"))
        patrol.set_active(pid)
        self.saved = True
        self.destroy()

if __name__ == "__main__":
    App().mainloop()
