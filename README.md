# Server Sentinel

轻量级服务器监控 / 告警单文件工具。仅依赖 Python 3.8+ 标准库，零第三方依赖，
一个 `sentinel.py` 即可完成采集、去重、入库，并通过**企业微信 + Telegram 双通道**
主动推送告警与定时报告；Telegram 同时保留交互式 Bot。

## 功能列表

### Phase 1（监控与告警）
- **配置加载**：JSON 配置，缺失字段自动补默认值，支持 `SENTINEL_CONFIG` 覆盖路径。
- **采集器**（每个采集器自带异常隔离，单个失败不影响整体）：
  - SSH 暴力破解：`journalctl` 失败登录解析，回退 `sudo -n lastb`。
  - 磁盘使用率：解析 `/proc/mounts`，跳过伪文件系统、按设备去重。
  - 内存使用率：基于 `/proc/meminfo` 的 `MemAvailable` 计算，旧内核自动兜底。
  - 系统负载：`/proc/loadavg` 1 分钟负载与核数阈值比较。
  - 关键进程：`ps -eo comm=` 检查 `watch_processes` 是否存活。
- **存储层**：sqlite3 事件入库、索引、最近 N 小时历史查询，`meta` 表记录定时报告时间戳。
- **规则层**：按 `key` + 时间窗去重，抑制告警风暴（采集 → 过滤 → 入库 → 推送）。
- **企业微信推送**：Webhook，按 UTF-8 字节安全截断，网络异常不抛出。

### Phase 2（Telegram Bot）
- **长轮询主循环**：`getUpdates`（`timeout=30`）+ `offset` 推进，网络异常指数退避（最长 60 秒），`Ctrl+C` 优雅退出。
- **白名单安全边界**：仅处理 `telegram_allowed_chat_ids` 内的 `chat.id`，非白名单消息只记 INFO 日志，不回复、不泄露信息。
- **命令处理器为纯函数**，返回文本、便于离线单测：
  - `/help`：列出全部命令。
  - `/status`：实时状态（当前登录用户、1 分钟负载、内存使用率、根分区磁盘使用率、系统运行时间）。
  - `/ssh`：最近 1 小时 `category='ssh'` 事件按来源 IP 聚合展示。
  - 未知命令：提示使用 `/help`。
- **回复**：`sendMessage` 纯文本（不设 `parse_mode`），网络/HTTP/`ok=false` 只记日志不抛出。
- **仅标准库**：全部通过 `urllib.request` 实现，不引入第三方 SDK。

### Phase 3（双通道主动推送）
- **统一文本构建器（纯函数，可离线测试）**：
  - `gather_server_info()`：复用底层读取，返回负载 / 内存 / 根分区 / 运行时间快照，单项失败填“未知”。
  - `build_report_text(server_info, events, title=...)`：输出统一纯文本报告（emoji 小节标题、键名冒号对齐、每条事件一行）。
- **Telegram 主动发送**：`send_telegram_message` / `push_telegram` 通过 `urllib` 直接调用 `sendMessage`，不依赖长轮询。
- **定时报告**：`meta.last_report_ts` + `is_report_due`，默认每 3 小时（`report_interval_hours`）推一次。
- **run 双通道**：有新告警即时推；到点推送定时报告；`--force` 立即推一次定时报告并更新时间戳。
- **bot 启动推送**：进入长轮询前先推一条“服务已启动”状态。

### Phase 4（Telegram HTTP 代理）
- **配置 `telegram_proxy`**：默认 `""`（直连）；填写后 Telegram 的 `sendMessage` / `getUpdates` 全部经该 HTTP/HTTPS 代理，适配国内服务器无法直连 `api.telegram.org` 的场景。
- **只影响 Telegram**：企业微信（`qyapi.weixin.qq.com` 国内可直连）的发送函数完全不读取该配置，始终直连。
- **安全与容错**：代理 URL 中的 `user:pass` 认证信息在日志中打码；`socks5://` 等不支持的 scheme 记 WARNING 后回退直连；代理连接失败只记 ERROR 日志并返回 False / 触发退避，绝不抛出。

### Phase 5（登录用户展示）
- **交互式登录**：`_read_logged_in_users()` 解析 `who`（utmp），返回用户 / 终端 / 登录时间 / 来源，方式推导为本地控制台（tty*/seat*）/ SSH（pts* + 来源 IP）/ 本地终端。
- **SSH 会话补全**：`who` 看不到非交互式 SSH 会话（`sshd: user@notty`，如 `ssh host command`）。`_read_ssh_sessions()` 用 `ps` 找会话进程拿用户与已连接时长，再从 `/var/log/auth.log` 的 `Accepted` 记录按"同用户 + 登录时刻最接近"归属远端 IP（yzy 在 `adm` 组可读，无需 root）。
- **为什么不用 /proc/<pid>/fd**：sshd 子进程不可 dump，同用户也读不到它的 fd；且 accepted socket 的 uid 归属为 root，uid 反查走不通。auth.log 是唯一精确且无特权的归属来源。
- **定时报告顶部**：`build_report_text` 在时间行之后、服务器状态之前插入 `👥 当前登录` 节；who 覆盖不到的会话追加为"<用户> · 命令会话 · 来自 <IP> · 已连接 <时长>"；无会话显示"无登录会话"，读取失败显示"读取失败"。
- **`/status` 同步**：Telegram `/status` 首节同样展示当前登录（含 SSH 会话，Markdown 版式）。
- **固有限制**：匹配不到 Accepted 记录（如日志已轮转）的会话 IP 显示"未知"。

## 推送机制

### 双通道
所有主动推送（告警、定时报告、bot 启动通知）都会**同时尝试企业微信与 Telegram 两个通道**：

- 企业微信：配置 `wecom_webhook` 后生效，内容按 `max_push_bytes` 做 UTF-8 字节安全截断。
- Telegram：配置 `telegram_bot_token` 后，向 `telegram_allowed_chat_ids` 中的**每个** chat 各发一份。

任一通道未配置只记一条 INFO 日志跳过；发送失败（网络异常 / HTTP 错误 / 对方返回错误）
只记日志，**绝不影响 `run` / `bot` 的退出码或主流程**。

### 告警即时推
`run` 每次采集后先去重：本次出现、且最近 `dedup_hours` 小时内未出现过的 `key`
视为“新告警”，立即以标题 `🚨 Server Sentinel 告警` 推送到双通道。

### 定时报告（默认 3 小时）
即使没有告警，也会按 `report_interval_hours`（默认 `3` 小时）推送一次常规状态报告：

- 首次运行（`meta.last_report_ts` 不存在）立即推一次；
- 之后 `now - last_report_ts >= report_interval_hours * 3600` 时再推；
- 每次推送成功后写回 `last_report_ts`（epoch 秒，存于 sqlite 的 `meta` 表）；
- `run --force` 忽略时间间隔，立即推一次定时报告并更新时间戳。

报告标题为 `📋 Server Sentinel 定时报告`，内容包含**常规服务器状态 + 本次新事件**；
无事件时事件区显示 `✅ 一切正常，无异常事件`。

### bot 启动推送
`bot` 命令在进入 `getUpdates` 长轮询前，会先推送一条标题为
`🚀 Server Sentinel 服务已启动` 的状态消息。注意：在 `systemd Restart=always`
下，每次服务重启都会推送一次启动消息，这是**符合预期**的行为，可用作进程存活信号。

### 纯文本版式
推送内容统一为高可读纯文本（无 Markdown 语法依赖）：emoji 小节标题、分区之间空行、
键名冒号按显示宽度对齐、每条事件一行含 `severity / category / key / 一句话摘要`。示例：

```
🖥️ Server Sentinel
⏰ 2026-10-04 11:40:00

👥 当前登录
  yzy · pts/0 · SSH 来自 222.93.13.126 · 2026-10-04 11:35

📊 服务器状态
  1分钟负载 : 0.59 (2 核)
  内存使用  : 92.5% (7.2 / 7.7 GB)
  根分区磁盘: 1.3%
  运行时间  : 3小时42分

🚨 异常事件 (2)
  🔴 [CRITICAL] process proc:sshd — 进程 sshd 未运行
  🟡 [WARNING] memory memory — 使用率 92.5% ≥ 阈值 90
```

## Telegram 代理

### 为什么需要
国内不少服务器**直连 `api.telegram.org` 不通**（连接超时 / 被重置），但本机通常已经跑着
Clash 之类的 HTTP 代理（例如 `127.0.0.1:7890`）。此时给 Telegram 配一个出口代理即可
正常收发消息，而**企业微信 `qyapi.weixin.qq.com` 国内可直连，必须继续走直连**，
不能因为全局代理而绕远路或受影响。

### 怎么填
在 `config.json` 中新增（留空即直连）：

```json
{
  "telegram_bot_token": "123456:ABC...",
  "telegram_proxy": "http://127.0.0.1:7890",
  "telegram_allowed_chat_ids": [123456789]
}
```

- 支持 `http://` / `https://`；代理需要认证时写成 `http://user:pass@127.0.0.1:7890`。
- **留空（默认）** = 直连，行为与之前完全一致。
- 只有 **http/https** 可用；若填 `socks5://...` 之类 urllib 原生不支持的协议，程序会记一条
  WARNING 并**自动回退直连**，不会崩溃。
- 代理主机填 `127.0.0.1` 时，注意 systemd 服务与代理需在同一网络命名空间；
  若服务以其他用户运行，确认该用户能访问代理端口。

### 作用范围
- ✅ 生效：`sendMessage`（主动推送 + Bot 回复）、`getUpdates`（长轮询）。
- ❌ 不影响：企业微信 Webhook、SSH / 磁盘 / 内存 / 负载 / 进程等本地采集。
- 🔒 日志安全：代理 URL 中的 `user:pass` 认证信息在日志里一律打码为 `****`。
- 🛟 容错：代理拒绝 / 超时只会记 ERROR 日志并返回失败（长轮询触发指数退避），
  绝不抛出异常，也不会改变 `run` / `bot` 的退出码。

## 快速开始

1. **准备配置**

   ```bash
   mkdir -p ~/.config/sentinel
   cp config.example.json ~/.config/sentinel/config.json
   # 编辑 config.json：填写 wecom_webhook、telegram_bot_token、telegram_allowed_chat_ids 等
   ```

   也可以用 `SENTINEL_CONFIG=/path/to/config.json` 指定其他位置。

2. **自检采集器**（只读，不入库不推送）

   ```bash
   python3 sentinel.py check
   ```

3. **配置定时巡检**（任选其一）

   - cron：参考 `cron.example`，每 30 分钟执行一次 `run`。
   - systemd：参考 `sentinel-bot.service` 常驻运行 Telegram Bot：
     ```bash
     sudo cp sentinel-bot.service /etc/systemd/system/
     sudo systemctl daemon-reload
     sudo systemctl enable --now sentinel-bot
     ```
     注意：示例服务使用 `Restart=always`，因此**每次重启都会推送一条“服务已启动”
     状态消息**（详见下文“推送机制”），这属于预期行为，可当作进程存活信号。

## 配置字段说明

`config.example.json` 列出了全部字段，字段名与程序一致：

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `wecom_webhook` | string | `""` | 企业微信机器人 Webhook 地址；为空时跳过推送。**属敏感凭据，日志中会打码。** |
| `telegram_bot_token` | string | `""` | Telegram Bot Token；为空时 `bot` 命令报错并退出（exit 2）。**属敏感凭据，日志中会打码。** |
| `telegram_proxy` | string | `""` | Telegram 专用 HTTP/HTTPS 代理，如 `http://127.0.0.1:7890`（可含 `user:pass@`）；为空 = 直连。**只影响 Telegram，企业微信不受影响。** |
| `telegram_allowed_chat_ids` | int 列表 | `[]` | Telegram 白名单 chat.id；为空时所有消息都会被忽略。 |
| `ssh_threshold` | int | `20` | SSH 失败次数达到该值才产生 critical 事件。 |
| `ssh_window_hours` | int | `1` | SSH 失败统计时间窗口（小时）。 |
| `disk_threshold` | int | `85` | 磁盘使用率告警阈值（百分比）。 |
| `memory_threshold` | int | `90` | 内存使用率告警阈值（百分比）。 |
| `load_multiplier` | float | `2.0` | 负载阈值倍数：`核数 × load_multiplier`。 |
| `watch_processes` | string 列表 | `["sshd"]` | 需要监控存活的关键进程名（受 Linux 15 字符限制）。 |
| `dedup_hours` | int | `1` | 同一 `key` 的去重时间窗（小时），`<=0` 关闭去重。 |
| `db_path` | string | `"~/.local/share/sentinel/sentinel.db"` | sqlite 数据库路径，支持 `~`；目录不可写时自动回退当前目录。 |
| `max_push_bytes` | int | `4000` | 企业微信推送内容的最大 UTF-8 字节数，超出自动截断。 |
| `report_interval_hours` | int | `3` | 定时报告间隔（小时）；`run` 到点后推送双通道，`run --force` 可忽略间隔立即推送。 |

## CLI 命令用法

```bash
# 1) run：采集 -> 去重 -> 入库 -> 双通道推送（告警即时推 + 到点定时报告）
python3 sentinel.py run
python3 sentinel.py run --force     # 忽略间隔，立即推送一次定时报告并更新时间戳

# 2) check：逐个运行采集器，仅打印事件数量（只读，不入库不推送）
python3 sentinel.py check

# 3) report：打印最近 N 小时事件（默认 24 小时）
python3 sentinel.py report --hours 1

# 4) bot：启动 Telegram 长轮询机器人（进入轮询前先推送一条启动状态）
python3 sentinel.py bot
```

## 目录结构

```
server-sentinel/
├── sentinel.py             # 主程序（单文件，仅标准库）
├── config.example.json     # 配置模板（复制为 config.json 使用）
├── sentinel-bot.service    # systemd 服务示例（Telegram Bot 常驻）
├── cron.example            # cron 定时巡检示例
└── README.md               # 本文档
```

## 安全注意事项

- **Telegram 白名单**：`telegram_allowed_chat_ids` 是唯一准入边界，务必填写为你自己的
  chat.id；不在白名单内的消息只会记录一条 INFO 日志，程序不会回复、不会泄露任何信息。
- **Webhook 不进日志**：`wecom_webhook` 属于敏感凭据，日志中只输出打码后的地址
  （`mask_webhook`），绝不原样打印；Telegram Token 同样只在日志中以打码形式出现。
- **最小权限运行**：请勿以 root 运行 Bot。systemd 示例中的 `User=` 需替换为实际低权限用户。
- **数据库权限**：`db_path` 所在目录应仅对运行账号可读写，避免事件历史被他人读取或篡改。
- **配置文件权限**：`config.json` 含 Token 与 Webhook，建议 `chmod 600`。
- **命令注入面**：`/ssh` 只做数据库查询与展示，`/status` 只读内核伪文件，不接受用户传入的执行参数。
