# FrpSitePatrol

对 frp 节点 / 服务器上的网页服务做每日巡查：自动发现端口、逐个截图、按风险分级，并和上一次对比变化。

支持两种用法：

- 源码版：Python 3.9+，双击 `启动巡查.cmd`（依赖检测/安装都在这个脚本里）
- 独立版：直接运行 `FrpSitePatrol.exe`（Win10/11，需系统自带 Edge 或 Chrome）

## 功能

- 三种端口来源：
  - **面板发现**：填 frps / ME Frp 面板地址和密码，自动读取在线 TCP 隧道
  - **端口扫描**：扫描自己服务器的端口段（只应扫描自有主机）
  - **手动列表**：直接填端口，逗号分隔
- 自动探测协议：HTTP / HTTPS / SSH / RDP / 其他 TCP
- 无头浏览器截图（1440×900），401/403 空白页自动生成“原始响应卡”
- 风险分级：极高 / 高 / 中 / 低，给出评分和理由
- 与上次对比：新增、消失、标题变化、页面变化（感知哈希）、风险上升/下降
- 每个节点独立目录、独立报告、独立每日任务
- 报告页顶部有“日期”下拉，可直接跳转历史；`data/<节点>/index.html` 按日期列出全部报告
- 报告保留天数可配（默认 60 天）

## Linux

核心代码跨平台，Windows / Linux 都能跑；截图依赖 Chromium 或 Chrome。

```bash
sudo apt install python3 python3-pip python3-tk chromium fonts-noto-cjk
python3 -m pip install -r requirements.txt
# Debian 12 若提示 externally-managed，可加 --break-system-packages

bash start.sh                 # 有桌面环境：打开界面
python3 patrol.py run --profile default    # 无桌面服务器：命令行巡查
python3 patrol.py install-task --time 09:00 --profile default   # 写入用户 crontab
```

说明：

- 无 `DISPLAY` / `WAYLAND_DISPLAY` 时，`start.sh` 会自动走命令行巡查
- 找不到 Chromium 时，在 `config.json` 里指定 `"browser_path": "/usr/bin/chromium"`
- Linux 的定时任务用用户 `crontab`，任务行带 `# FrpSitePatrol_<节点id>` 标记，卸载时会精确删除
- GUI 需要 `python3-tk` 和桌面环境；服务器上直接用 CLI 即可

填写示例见：[如何填写节点.md](如何填写节点.md)

## 快速开始（源码版）

1. 安装 Python 3.9+（勾选 Add to PATH）
2. 双击 `启动巡查.cmd`：首次运行会自动安装依赖，装好后以后直接打开界面
4. 点“新建节点”：
   - 名称：随便起
   - 服务器 IP/域名：你自己的机器
   - 获取端口方式：
     - 面板发现 → 填完整面板地址（端口任意，如 `http://1.2.3.4:7500`、`http://1.2.3.4:2396`、`https://frp.example.com`）和密码（ME Frp 只填密码，没有用户名；标准 frps 用户名可留空，默认 admin）
     - 端口扫描 → 填端口起止（如 30000 / 60000）
     - 手动列表 → 在“手动端口”里填 `80,443,8080`
5. 点“立即巡查”，完成后自动打开报告

## 风险分级

| 等级 | 判定 | 例子 |
|---|---|---|
| 极高 | 内容类违规（得分 90+） | IPTV 转播、影视聚合、公开影视片库、博彩、色情、诈骗 |
| 高 | 控制面 / 敏感数据 / 远程入口 | NAS 后台、ERP、RAGFlow、对象存储、RDP、SSH、RCON |
| 中 | 需登录的工具类服务 | OpenList、OneNav、同步、下载器、内部看板 |
| 低 | 游戏服、测试端口、离线 | Minecraft、test 端口 |

规则在 `risk.py` 里，可以直接加关键词。某个端口判错时，用节点文件里的 `risk_overrides` 固定等级：

```json
"risk_overrides": {
  "51999": {"level": "X", "note": "IPTV 转播"},
  "50000": {"level": "S", "note": "客户 NAS，已知"}
}
```

## 每日自动巡查

界面点“设置每日任务”，填 `HH:MM` 即可。任务名是 `FrpSitePatrol_<节点id>`，每个节点一条。
要求电脑开着且当前用户已登录；电脑关机时当天会跳过。

命令行等价写法：

```
python patrol.py install-task --time 09:00 --profile default
python patrol.py uninstall-task --profile default
```

## 命令行

```
python patrol.py profiles                # 列出节点
python patrol.py run --profile default   # 立即巡查
python patrol.py run --ports 50000,55244 # 只查指定端口
python patrol.py discover --profile x    # 只看面板隧道
python patrol.py open --profile x        # 打开最新报告
python patrol.py rebuild --profile x     # 重新生成历史报告和索引（补日期导航）
```

## 数据位置

```
profiles/<节点id>.json     节点配置（含面板密码，注意保管）
data/<节点id>/<时间>/report.html
data/<节点id>/latest.html
data/patrol.log
```

## 分享给别人的注意事项

- `profiles/*.json` 里有面板密码，**发给别人前删掉 profiles 目录**，让对方自己新建节点
- 打包给别人时也不要带 `data/`（里面是截图和报告）
- 每个人用自己的 IP、自己的面板地址和密码，互不影响

## 常见问题

- **面板登录失败**：地址要带 `http://` 或 `https://`，端口按实际填；ME Frp 常见 2396，标准 frps 常见 7500。新建节点里点“测试面板”可以直接验证
- **面板用户名**：ME Frp 没有用户名，只填访问密钥（面板密码）；标准 frps 用户名可留空，程序按 `admin` 处理
- **扫描没有结果**：提高“扫描超时”（默认 0.8 秒），或检查云安全组
- **截图空白**：401/403 会生成响应卡；若整页空白，确认 `browser_path` 指向 Edge/Chrome
- **浏览器启动失败**：在 `config.json` 里填 `"browser_path": "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"`
- **风险误报**：用 `risk_overrides` 覆盖，不必改代码
- **只应扫描自己的服务器**，不要对他人主机做端口扫描

## 文件说明

```
patrol.py      主流程：发现、探测、截图、对比、报告
启动巡查.cmd   Windows 入口：缺依赖自动装，装好直接开界面
start.sh        Linux 入口：有桌面开界面，无桌面自动跑 CLI
risk.py        风险规则与评分
gui.pyw        图形界面
main.py        打包入口（GUI / 命令行自动分发）
config.json    全局配置（截图尺寸、保留天数等）
profiles/      各节点配置
data/          截图与报告
```
