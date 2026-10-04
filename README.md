# Server Sentinel

轻量级服务器监控 / 告警单文件工具。仅依赖 Python 3.8+ 标准库，零第三方依赖，
一个 `sentinel.py` 即可完成采集、去重、入库、企业微信推送与 Telegram 交互。

## 功能列表

### Phase 1（监控与告警）
- **配置加载**：JSON 配置，缺失字段自动补默认值，支持 `SENTINEL_CONFIG` 覆盖路径。
- **采集器**（每个采集器自带异常隔离，单个失败不影响整体）：
  - SSH 暴力破解：`journalctl` 失败登录解析，回退 `sudo -n lastb`。
  - 磁盘使用率：解析 `/proc/mounts`，跳过伪文件系统、按设备去重。
  - 内存使用率：基于 `/proc/meminfo` 的 `MemAvailable` 计算，旧内核自动兜底。
  - 系统负载：`/proc/loadavg` 1 分钟负载与核数阈值比较。
  - 关键进程：`ps -eo comm=` 检查 `watch_processes` 是否存活。
- **存储层**：sqlite3 事件入库、索引、最近 N 小时历史查询。
- **规则层**：按 `key` + 时间窗去重，抑制告警风暴（采集 → 过滤 → 入库 → 推送）。
- **企业微信推送**：Markdown，按 UTF-8 字节安全截断，网络异常不抛出。

### Phase 2（Telegram Bot）
- **长轮询主循环**：`getUpdates`（`timeout=30`）+ `offset` 推进，网络异常指数退避（最长 60 秒），`Ctrl+C` 优雅退出。
- **白名单安全边界**：仅处理 `telegram_allowed_chat_ids` 内的 `chat.id`，非白名单消息只记 INFO 日志，不回复、不泄露信息。
- **命令处理器为纯函数**，返回文本、便于离线单测：
  - `/help`：列出全部命令。
  - `/status`：实时状态（1 分钟负载、内存使用率、根分区磁盘使用率、系统运行时间）。
  - `/ssh`：最近 1 小时 `category='ssh'` 事件按来源 IP 聚合展示。
  - 未知命令：提示使用 `/help`。
- **回复**：`sendMessage` + `parse_mode=Markdown`，动态内容做最小转义，失败自动降级纯文本重发。
- **仅标准库**：全部通过 `urllib.request` 实现，不引入第三方 SDK。

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

## 配置字段说明

`config.example.json` 列出了全部字段，字段名与程序一致：

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `wecom_webhook` | string | `""` | 企业微信机器人 Webhook 地址；为空时跳过推送。**属敏感凭据，日志中会打码。** |
| `telegram_bot_token` | string | `""` | Telegram Bot Token；为空时 `bot` 命令报错并退出（exit 2）。 |
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

## CLI 命令用法

```bash
# 1) run：采集 -> 去重 -> 入库 -> 推送
python3 sentinel.py run
python3 sentinel.py run --force     # 无新事件时也推送“一切正常”汇总

# 2) check：逐个运行采集器，仅打印事件数量（只读，不入库不推送）
python3 sentinel.py check

# 3) report：打印最近 N 小时事件（默认 24 小时）
python3 sentinel.py report --hours 1

# 4) bot：启动 Telegram 长轮询机器人
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
