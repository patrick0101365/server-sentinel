#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Server Sentinel —— 轻量级服务器监控 / 告警单文件工具。

Phase 1 功能：
  * 配置加载（JSON，支持环境变量覆盖与缺失回退）
  * 采集器：SSH 暴力破解、磁盘、内存、负载、关键进程
  * 存储层：sqlite3（事件入库、去重查询、历史查询）
  * 规则层：按 key + 时间窗去重
  * 企业微信 Webhook 推送（Markdown，自动按字节截断、异常不抛出）
  * CLI：run / check / report

Phase 2 功能：
  * Telegram Bot：getUpdates 长轮询 + offset 推进 + 网络异常指数退避
  * 白名单：仅处理 telegram_allowed_chat_ids 内的 chat.id
  * 命令处理器为纯函数：/help、/status、/ssh（离线可测）
  * CLI：bot（token 为空时清晰报错并 exit 2）

Phase 3 功能（双通道主动推送）：
  * 统一推送文本构建器：gather_server_info / build_report_text（纯函数、离线可测）
  * Telegram 主动发送：send_telegram_message / push_telegram（urllib，纯文本，不依赖轮询）
  * meta 表存储 last_report_ts；is_report_due 控制定时报告间隔（report_interval_hours）
  * run：新告警即时推 + 到点推送定时报告，均走企业微信与 Telegram 双通道
  * bot：启动时先推送一条“服务已启动”状态，再进入 getUpdates 长轮询

设计原则：
  * 仅标准库，兼容 Python 3.8+（不使用 match、不使用运行时 X | Y 联合类型）
  * 每个采集器自带异常隔离：单个采集器失败只记日志，绝不拖垮整个 run
  * 日志一律带时间戳；企业微信 Webhook / Telegram Token 绝不原样输出（必须打码）
  * 推送失败只记日志，绝不影响 run / bot 的正常流程与退出码
"""

import argparse
import collections
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 常量与默认配置
# ---------------------------------------------------------------------------

# 默认配置文件路径：~/.config/sentinel/config.json，可用 SENTINEL_CONFIG 覆盖
DEFAULT_CONFIG_PATH = "~/.config/sentinel/config.json"

# 配置项默认值。注意：这里集中定义，load_config 会以它为基准做“缺字段补齐”，
# 因此即便用户的配置文件只写了一部分字段，其余字段也能拿到合理默认值。
DEFAULT_CONFIG = {
    "wecom_webhook": "",
    "telegram_bot_token": "",
    "telegram_allowed_chat_ids": [],
    "ssh_threshold": 20,
    "ssh_window_hours": 1,
    "disk_threshold": 85,
    "memory_threshold": 90,
    "load_multiplier": 2.0,
    "watch_processes": ["sshd"],
    "dedup_hours": 1,
    "db_path": "~/.local/share/sentinel/sentinel.db",
    "max_push_bytes": 4000,
    "report_interval_hours": 3,
}

# severity 的展示顺序与图标（critical 最严重，放最前面）
SEVERITY_ORDER = [
    ("critical", "🔴 严重"),
    ("warning", "🟡 警告"),
    ("info", "🔵 提示"),
]

# severity -> 单字符图标，供统一报告的一行式事件使用（未知 severity 用 ⚪ 兜底）
SEVERITY_ICONS = {
    "critical": "🔴",
    "warning": "🟡",
    "info": "🔵",
}

# /proc/mounts 中需要跳过的“伪文件系统”。这些都是内核虚拟文件系统，
# 讨论磁盘使用率没有意义（overlay 属于真实可写层，故不在此列，需照常统计）。
PSEUDO_FILESYSTEMS = {
    "proc", "sysfs", "devpts", "devtmpfs", "tmpfs", "cgroup", "cgroup2",
    "securityfs", "debugfs", "tracefs", "pstore", "bpf", "configfs",
    "fusectl", "mqueue", "hugetlbfs", "binfmt_misc", "rpc_pipefs",
    "autofs", "nsfs", "ramfs", "squashfs",
}


# ---------------------------------------------------------------------------
# 日志工具
# ---------------------------------------------------------------------------

def log(message: str, level: str = "INFO") -> None:
    """
    带时间戳的日志输出。

    INFO 输出到 stdout，WARNING/ERROR 输出到 stderr，方便 cron/systemd 分流。
    不做复杂日志框架，保持单文件零依赖。
    """
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s %s" % (stamp, level.upper(), message)
    if level.upper() in ("WARNING", "ERROR", "CRITICAL"):
        print(line, file=sys.stderr, flush=True)
    else:
        print(line, file=sys.stdout, flush=True)


def mask_webhook(url: str) -> str:
    """
    对企业微信 Webhook 打码。

    硬性要求：Webhook 的 key 属于敏感凭据，绝不允许原样落日志。
    这里只保留到 "key=" 之前的部分（协议+主机+路径），后面全部替换为掩码。
    """
    if not url:
        return "(未配置)"
    try:
        idx = url.find("key=")
        if idx >= 0:
            return url[: idx + 4] + "****(已打码)"
        # 没找到 key= 的非常规地址，也只保留前 24 个字符
        return url[:24] + "****(已打码)"
    except Exception:
        # 极端情况下连切分都失败，直接返回完全掩码，绝不泄露原文
        return "****(已打码)"


# ---------------------------------------------------------------------------
# 配置加载
# ---------------------------------------------------------------------------

def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_str_list(value: Any, default: List[str]) -> List[str]:
    """把配置里的列表字段规整成 List[str]，非列表则回退默认值。"""
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return list(default)


def load_config() -> Dict[str, Any]:
    """
    加载配置。

    优先级：SENTINEL_CONFIG 环境变量指定的路径 > ~/.config/sentinel/config.json。
    文件不存在时使用内置默认值并打印提示；文件损坏/字段类型不对时尽量容错，
    始终返回一份“字段齐全且类型正确”的配置，避免调用方到处判空。
    """
    env_path = os.environ.get("SENTINEL_CONFIG")
    raw_path = env_path if env_path else DEFAULT_CONFIG_PATH
    path = os.path.expanduser(raw_path)

    config = dict(DEFAULT_CONFIG)          # 先铺默认值
    # 列表字段要深拷贝，避免多个 config 实例共享同一个可变默认对象
    config["telegram_allowed_chat_ids"] = list(DEFAULT_CONFIG["telegram_allowed_chat_ids"])
    config["watch_processes"] = list(DEFAULT_CONFIG["watch_processes"])

    if not os.path.exists(path):
        # 按需求：缺失配置文件属于“可接受状态”，提示后继续用默认值
        log("配置文件不存在：%s，使用内置默认配置" % path, "WARNING")
    else:
        try:
            with open(path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            if not isinstance(data, dict):
                raise ValueError("配置根节点必须是 JSON 对象")
            # 只合并已知字段，未知字段忽略，保证前向兼容
            for key, value in data.items():
                if key in config:
                    config[key] = value
                else:
                    log("忽略未知配置项：%s" % key, "WARNING")
            log("已加载配置文件：%s" % path, "INFO")
        except Exception as exc:
            # 配置解析失败不应导致程序崩溃，退回默认值即可
            log("配置文件解析失败（%s），改用内置默认配置" % exc, "ERROR")

    # 类型规整：把用户可能写错类型的字段转回正确类型
    config["wecom_webhook"] = str(config.get("wecom_webhook") or "")
    config["telegram_bot_token"] = str(config.get("telegram_bot_token") or "")
    config["telegram_allowed_chat_ids"] = _coerce_str_list(
        config.get("telegram_allowed_chat_ids"), DEFAULT_CONFIG["telegram_allowed_chat_ids"]
    )
    config["ssh_threshold"] = _coerce_int(config.get("ssh_threshold"), DEFAULT_CONFIG["ssh_threshold"])
    config["ssh_window_hours"] = _coerce_int(config.get("ssh_window_hours"), DEFAULT_CONFIG["ssh_window_hours"])
    config["disk_threshold"] = _coerce_int(config.get("disk_threshold"), DEFAULT_CONFIG["disk_threshold"])
    config["memory_threshold"] = _coerce_int(config.get("memory_threshold"), DEFAULT_CONFIG["memory_threshold"])
    config["load_multiplier"] = _coerce_float(config.get("load_multiplier"), DEFAULT_CONFIG["load_multiplier"])
    config["watch_processes"] = _coerce_str_list(
        config.get("watch_processes"), DEFAULT_CONFIG["watch_processes"]
    )
    config["dedup_hours"] = _coerce_int(config.get("dedup_hours"), DEFAULT_CONFIG["dedup_hours"])
    config["max_push_bytes"] = _coerce_int(config.get("max_push_bytes"), DEFAULT_CONFIG["max_push_bytes"])
    config["report_interval_hours"] = _coerce_int(
        config.get("report_interval_hours"), DEFAULT_CONFIG["report_interval_hours"]
    )

    # db_path 支持 ~ 展开；启动时确保父目录存在，否则 sqlite 打开会失败
    preferred_db = os.path.expanduser(str(config.get("db_path") or DEFAULT_CONFIG["db_path"]))
    config["db_path"] = _ensure_db_path(preferred_db)

    return config


def _ensure_db_path(preferred_db: str) -> str:
    """
    解析并确保数据库路径可用。

    正常情况下直接使用配置路径。但某些受限环境（只读 HOME、容器挂载限制）
    无法创建 ~/.local/share 目录，此时如果仍然硬写，会导致所有事件丢失。
    因此这里用“实际写探测文件”的方式判断目录可写性（比 os.access 更可靠，
    因为权限可能来自挂载/沙箱而非 POSIX 位），不可写则回退到当前工作目录，
    并打印 warning，保证 run 至少能把事件落库。
    """
    def _dir_writable(directory: str) -> bool:
        try:
            os.makedirs(directory, exist_ok=True)
            probe = os.path.join(directory, ".sentinel_write_test_%d" % os.getpid())
            with open(probe, "w", encoding="utf-8") as fp:
                fp.write("")
            os.remove(probe)
            return True
        except Exception:
            return False

    parent = os.path.dirname(preferred_db)
    if not parent or _dir_writable(parent):
        return preferred_db

    # 首选目录不可写，尝试当前工作目录作为兜底
    log("数据库目录不可写：%s，尝试回退到当前目录" % parent, "WARNING")
    cwd = os.getcwd()
    if _dir_writable(cwd):
        fallback = os.path.join(cwd, os.path.basename(preferred_db) or "sentinel.db")
        log("数据库回退路径：%s" % fallback, "WARNING")
        return fallback

    # 都不可写就返回原路径，后续 sqlite 报错会被上层捕获并记日志
    log("当前目录也不可写，保持原数据库路径：%s" % preferred_db, "WARNING")
    return preferred_db


# ---------------------------------------------------------------------------
# 采集器
# ---------------------------------------------------------------------------
# 事件统一结构：
#   {"category": str, "severity": "critical|warning|info", "key": str, "detail": dict}
# key 是去重标识（例如 "ssh:1.2.3.4"），detail 是可序列化为 JSON 的字典。

def _make_event(category: str, severity: str, key: str, detail: Dict[str, Any]) -> Dict[str, Any]:
    """构造标准事件字典，统一入口便于未来加字段。"""
    return {
        "category": category,
        "severity": severity,
        "key": key,
        "detail": detail,
    }


def _human_bytes(num: Any) -> str:
    """把字节数格式化成人类可读字符串（用于推送与 report 展示）。"""
    try:
        value = float(num)
    except (TypeError, ValueError):
        return str(num)
    # 逐级换算，保留一位小数，B 级别取整
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0:
            if unit == "B":
                return "%d B" % int(value)
            return "%.1f %s" % (value, unit)
        value /= 1024.0
    return "%.1f PB" % value


def collect_ssh(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    SSH 登录失败采集。

    策略：
      1) 优先 `journalctl -u ssh --since "<N> hours ago"` 解析 "Failed password" 行；
         systemd 发行版通常只有 ssh/sshd 其中一个 unit，两者都试一遍。
      2) journalctl 不可用（无命令 / 无权限 / 非 systemd）时，回退 `sudo -n lastb`；
         非交互 sudo 失败就记 warning 并返回空列表（不抛异常）。
    按源 IP 聚合，失败次数 >= ssh_threshold 才产生 critical 事件。
    """
    events: List[Dict[str, Any]] = []
    try:
        window_hours = int(config.get("ssh_window_hours", 1))
        threshold = int(config.get("ssh_threshold", 20))

        counts: Dict[str, int] = collections.Counter()
        got_journal_output = False

        # --- 方案一：journalctl ---
        for unit in ("ssh", "sshd"):
            cmd = [
                "journalctl", "-u", unit,
                "--since", "%d hours ago" % window_hours,
                "--no-pager",
            ]
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=20,
                )
            except FileNotFoundError:
                # 没有 journalctl，直接跳出走 lastb 回退
                break
            except subprocess.TimeoutExpired:
                log("journalctl 执行超时（unit=%s）" % unit, "WARNING")
                break
            except Exception as exc:
                log("journalctl 执行异常（unit=%s）：%s" % (unit, exc), "WARNING")
                break

            if proc.returncode != 0:
                # 无权限 / 未连接 systemd bus 等，换下一个 unit 或最终回退
                continue

            # returncode == 0 说明命令可用，即使没有输出也是有效结果
            got_journal_output = True
            text = proc.stdout.decode("utf-8", errors="ignore")
            for ip in _extract_failed_ips(text):
                counts[ip] += 1
            break  # 成功的 unit 用一次即可

        # --- 方案二：lastb 回退 ---
        if not got_journal_output:
            log("journalctl 不可用，回退 `sudo -n lastb`", "WARNING")
            lastb_proc = None
            try:
                lastb_proc = subprocess.run(
                    ["sudo", "-n", "lastb"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=20,
                )
            except FileNotFoundError:
                log("未找到 sudo/lastb，SSH 采集跳过", "WARNING")
            except subprocess.TimeoutExpired:
                log("lastb 执行超时，SSH 采集跳过", "WARNING")
            except Exception as exc:
                log("lastb 执行异常：%s" % exc, "WARNING")

            if lastb_proc is not None:
                if lastb_proc.returncode == 0:
                    text = lastb_proc.stdout.decode("utf-8", errors="ignore")
                    for ip in _extract_failed_ips(text, require_failed_marker=False):
                        counts[ip] += 1
                else:
                    err = lastb_proc.stderr.decode("utf-8", errors="ignore").strip()
                    log("lastb 执行失败（sudo -n 不可用）：%s" % (err or "returncode=%d" % lastb_proc.returncode), "WARNING")

        # --- 聚合判断 ---
        for ip, count in counts.items():
            if count >= threshold:
                events.append(_make_event(
                    category="ssh",
                    severity="critical",
                    key="ssh:%s" % ip,
                    detail={
                        "ip": ip,
                        "failed_count": count,
                        "window_hours": window_hours,
                        "threshold": threshold,
                    },
                ))
        log("SSH 采集完成：窗口=%dh 阈值=%d 命中 IP 数=%d" % (window_hours, threshold, len(events)), "INFO")
    except Exception as exc:
        # 采集器自兜底：任何异常只记日志
        log("collect_ssh 失败：%s" % exc, "ERROR")
    return events


# "Failed password for [invalid user ]<user> from <ip> port <port> ssh2"
_FAILED_FROM_RE = re.compile(
    r"Failed password for (?:invalid user )?\S+ from ([0-9a-fA-F:.]+)",
    re.IGNORECASE,
)
# 通用 IP（v4/v6）提取，用于 lastb 这类无法依赖固定措辞的输出
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})\b")


def _extract_failed_ips(text: str, require_failed_marker: bool = True) -> List[str]:
    """
    从命令输出中提取失败登录的源 IP。

    require_failed_marker=True：journalctl 模式，只认 "Failed password ... from IP"；
    require_failed_marker=False：lastb 模式，整行里找 IPv4 地址即可。
    """
    ips: List[str] = []
    for line in text.splitlines():
        if require_failed_marker:
            match = _FAILED_FROM_RE.search(line)
            if match:
                ips.append(match.group(1))
        else:
            # lastb 行形如：root  ssh:notty  1.2.3.4  Thu Jul 10 ...
            if line.strip().startswith("btmp begins"):
                continue
            # 只接受 IPv4，避免把时间/端口误判成 IPv6
            for candidate in _IP_RE.findall(line):
                parts = candidate.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    ips.append(candidate)
                    break
    return ips


def collect_disk(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    磁盘使用率采集。

    遍历 /proc/mounts，跳过伪文件系统；按设备去重（同一设备可能存在 bind mount，
    重复上报没有意义）；使用率 >= disk_threshold 产生 warning 事件。
    """
    events: List[Dict[str, Any]] = []
    try:
        threshold = int(config.get("disk_threshold", 85))
        mount_info = _read_proc_mounts()
        seen_devices = set()

        for device, mountpoint, fstype in mount_info:
            if fstype in PSEUDO_FILESYSTEMS:
                continue
            if device in seen_devices:
                # 同一块设备（如 bind mount）只统计一次
                continue
            seen_devices.add(device)
            try:
                usage = shutil.disk_usage(mountpoint)
            except Exception as exc:
                # 挂载点可能已失效/无权限，跳过即可
                log("跳过挂载点 %s：%s" % (mountpoint, exc), "WARNING")
                continue
            if usage.total <= 0:
                continue
            percent = usage.used * 100.0 / usage.total
            if percent >= threshold:
                events.append(_make_event(
                    category="disk",
                    severity="warning",
                    key="disk:%s" % mountpoint,
                    detail={
                        "mount": mountpoint,
                        "usage_percent": round(percent, 1),
                        "total": _human_bytes(usage.total),
                        "total_bytes": usage.total,
                        "free": _human_bytes(usage.free),
                        "free_bytes": usage.free,
                        "threshold": threshold,
                    },
                ))
        log("磁盘采集完成：阈值=%d%% 命中挂载点数=%d" % (threshold, len(events)), "INFO")
    except Exception as exc:
        log("collect_disk 失败：%s" % exc, "ERROR")
    return events


def _read_proc_mounts() -> List[Tuple[str, str, str]]:
    """
    解析 /proc/mounts，返回 (device, mountpoint, fstype) 列表。

    /proc/mounts 用空格分隔字段，路径里的特殊字符会被转义成八进制（如 \\040 代表空格），
    标准库没有现成解析器，这里手动做最小化反转义。
    """
    result: List[Tuple[str, str, str]] = []
    with open("/proc/mounts", "r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            fields = line.split()
            if len(fields) < 3:
                continue
            device = _unescape_mount_field(fields[0])
            mountpoint = _unescape_mount_field(fields[1])
            fstype = fields[2]
            result.append((device, mountpoint, fstype))
    return result


def _unescape_mount_field(value: str) -> str:
    """还原 /proc/mounts 中的八进制转义（\\040 空格、\\011 制表符、\\012 换行、\\134 反斜杠）。"""
    mapping = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    result = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 3 < len(value):
            code = value[i + 1: i + 4]
            if code in mapping:
                result.append(mapping[code])
                i += 4
                continue
        result.append(value[i])
        i += 1
    return "".join(result)


def collect_memory(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    内存使用率采集。

    使用 MemAvailable 计算“真实可用内存”，它比 MemFree 更贴近实际
    （已扣除不可回收的缓存）。若内核过旧没有 MemAvailable，则退化用
    MemFree + Buffers + Cached 估算。
    """
    events: List[Dict[str, Any]] = []
    try:
        threshold = int(config.get("memory_threshold", 90))
        stats = _read_meminfo()
        total = stats.get("MemTotal", 0)
        if total <= 0:
            log("无法读取 MemTotal，内存采集跳过", "WARNING")
            return events

        if "MemAvailable" in stats:
            available = stats["MemAvailable"]
        else:
            # 旧内核兜底估算
            available = stats.get("MemFree", 0) + stats.get("Buffers", 0) + stats.get("Cached", 0)

        used = total - available
        if used < 0:
            used = 0
        percent = used * 100.0 / total
        if percent >= threshold:
            events.append(_make_event(
                category="memory",
                severity="warning",
                key="memory",
                detail={
                    "usage_percent": round(percent, 1),
                    "total": _human_bytes(total * 1024),
                    "available": _human_bytes(available * 1024),
                    "total_kb": total,
                    "available_kb": available,
                    "threshold": threshold,
                },
            ))
        log("内存采集完成：使用率=%.1f%% 阈值=%d%%" % (percent, threshold), "INFO")
    except Exception as exc:
        log("collect_memory 失败：%s" % exc, "ERROR")
    return events


def _read_meminfo() -> Dict[str, int]:
    """/proc/meminfo 解析为 {字段名: kB 数值} 的字典。"""
    stats: Dict[str, int] = {}
    with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            parts = rest.strip().split()
            if not parts:
                continue
            try:
                stats[name.strip()] = int(parts[0])
            except ValueError:
                continue
    return stats


def _read_load1() -> Optional[float]:
    """
    读取 /proc/loadavg 的 1 分钟负载。

    返回 None 表示文件内容为空；文件不可读时异常上抛，由调用方处理。
    collect_load 与 Telegram /status 共用，避免重复解析同一份内核数据。
    """
    with open("/proc/loadavg", "r", encoding="utf-8", errors="ignore") as fp:
        content = fp.read().strip()
    if not content:
        return None
    return float(content.split()[0])


def _read_uptime() -> float:
    """读取 /proc/uptime 第一列，返回系统运行秒数。"""
    with open("/proc/uptime", "r", encoding="utf-8", errors="ignore") as fp:
        content = fp.read().strip()
    if not content:
        return 0.0
    return float(content.split()[0])


def collect_load(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    系统负载采集。

    取 /proc/loadavg 的 1 分钟负载，与 核数 * load_multiplier 比较，
    超过则产生 warning 事件（负载高通常意味着 CPU/IO 竞争激烈）。
    """
    events: List[Dict[str, Any]] = []
    try:
        multiplier = float(config.get("load_multiplier", 2.0))
        cpu_count = os.cpu_count() or 1
        threshold = cpu_count * multiplier

        load1 = _read_load1()
        if load1 is None:
            log("loadavg 内容为空，负载采集跳过", "WARNING")
            return events

        if load1 > threshold:
            events.append(_make_event(
                category="load",
                severity="warning",
                key="load",
                detail={
                    "load1": round(load1, 2),
                    "cpu_count": cpu_count,
                    "threshold": round(threshold, 2),
                    "multiplier": multiplier,
                },
            ))
        log("负载采集完成：load1=%.2f 阈值=%.2f（%d 核）" % (load1, threshold, cpu_count), "INFO")
    except Exception as exc:
        log("collect_load 失败：%s" % exc, "ERROR")
    return events


def collect_processes(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    关键进程存活采集。

    `ps -eo comm=` 只取进程名（comm），watch_processes 里任意一个不在集合中
    就产生 critical 事件。注意：进程名受 Linux 15 字符限制，配置时需留意。
    """
    events: List[Dict[str, Any]] = []
    try:
        watch = _coerce_str_list(config.get("watch_processes"), [])
        try:
            proc = subprocess.run(
                ["ps", "-eo", "comm="],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
        except FileNotFoundError:
            log("未找到 ps 命令，进程采集跳过", "ERROR")
            return events
        except subprocess.TimeoutExpired:
            log("ps 命令超时，进程采集跳过", "ERROR")
            return events

        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="ignore").strip()
            log("ps 执行失败：%s" % (err or "returncode=%d" % proc.returncode), "ERROR")
            return events

        running = set()
        for line in proc.stdout.decode("utf-8", errors="ignore").splitlines():
            name = line.strip()
            if name:
                running.add(name)

        for name in watch:
            if name and name not in running:
                events.append(_make_event(
                    category="process",
                    severity="critical",
                    key="proc:%s" % name,
                    detail={"process": name, "running_count": len(running)},
                ))
        log("进程采集完成：关注=%d 缺失=%d" % (len(watch), len(events)), "INFO")
    except Exception as exc:
        log("collect_processes 失败：%s" % exc, "ERROR")
    return events


# 采集器注册表：check 命令与 collect_all 共用，新增采集器只需在此加一行
COLLECTORS: List[Tuple[str, Any]] = [
    ("ssh", collect_ssh),
    ("disk", collect_disk),
    ("memory", collect_memory),
    ("load", collect_load),
    ("process", collect_processes),
]


def collect_all(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    串行执行全部采集器并汇总事件。

    每个采集器内部已经 try/except，这里再包一层防御，确保 run 永远不会
    因为某个采集器崩溃而中断。
    """
    all_events: List[Dict[str, Any]] = []
    for name, func in COLLECTORS:
        try:
            events = func(config)
        except Exception as exc:
            log("采集器 %s 意外失败：%s" % (name, exc), "ERROR")
            events = []
        all_events.extend(events)
    return all_events


# ---------------------------------------------------------------------------
# 存储层（sqlite3）
# ---------------------------------------------------------------------------

def _connect(db_path: str) -> sqlite3.Connection:
    """
    打开数据库连接，并保证父目录与表结构存在。

    每次操作独立开关连接，逻辑简单、天然线程/进程安全（SQLite 自身有锁）。
    """
    parent_dir = os.path.dirname(os.path.expanduser(db_path))
    if parent_dir:
        try:
            os.makedirs(parent_dir, exist_ok=True)
        except Exception:
            # 目录创建失败时交给 sqlite 报错，上层会捕获
            pass
    conn = sqlite3.connect(os.path.expanduser(db_path), timeout=10)
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """建表 + 建索引（幂等，可重复执行）。"""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id       INTEGER PRIMARY KEY,
            ts       INTEGER,
            category TEXT,
            severity TEXT,
            key      TEXT,
            detail   TEXT
        )
        """
    )
    # key 是去重查询的核心条件，必须建索引；ts 用于时间窗和倒序查询
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_key ON events(key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    # meta：存放 last_report_ts 等键值状态，供定时报告判定使用
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )
    conn.commit()


def save_events(db_path: str, events: List[Dict[str, Any]]) -> int:
    """
    写入本次采集到的全部事件，返回写入条数。

    detail 统一序列化为 JSON 字符串；ts 使用当前 epoch 秒（同一批次取同一时刻，
    便于后续按批次排查）。
    """
    if not events:
        return 0
    now = int(time.time())
    rows = []
    for event in events:
        try:
            detail_json = json.dumps(event.get("detail", {}), ensure_ascii=False, default=str)
        except Exception:
            detail_json = "{}"
        rows.append((
            now,
            str(event.get("category", "")),
            str(event.get("severity", "info")),
            str(event.get("key", "")),
            detail_json,
        ))
    try:
        conn = _connect(db_path)
        try:
            conn.executemany(
                "INSERT INTO events (ts, category, severity, key, detail) VALUES (?, ?, ?, ?, ?)",
                rows,
            )
            conn.commit()
        finally:
            conn.close()
        log("写入数据库 %d 条事件 -> %s" % (len(rows), db_path), "INFO")
        return len(rows)
    except Exception as exc:
        log("写入数据库失败：%s" % exc, "ERROR")
        return 0


def is_duplicate(db_path: str, key: str, dedup_hours: int) -> bool:
    """
    判断同一 key 在最近 dedup_hours 小时内是否已存在。

    存在即视为重复（用于抑制重复推送 / 告警风暴）。
    dedup_hours <= 0 表示关闭去重（时间窗为空，任何事件都不算重复）。
    """
    try:
        hours = int(dedup_hours)
        if hours <= 0:
            return False
        since = int(time.time()) - hours * 3600
        conn = _connect(db_path)
        try:
            cursor = conn.execute(
                "SELECT COUNT(1) FROM events WHERE key = ? AND ts >= ?",
                (str(key), since),
            )
            row = cursor.fetchone()
            return bool(row and row[0] > 0)
        finally:
            conn.close()
    except Exception as exc:
        # 查询异常时保守地按“非重复”处理，避免漏报
        log("去重查询失败（key=%s）：%s" % (key, exc), "ERROR")
        return False


def get_recent_events(db_path: str, hours: int) -> List[Dict[str, Any]]:
    """
    查询最近 hours 小时内的事件，按时间倒序返回。

    返回结构与采集事件兼容（额外带 id 和 ts），方便 report 与 Phase 2 的
    Telegram 推送复用同一份数据格式。
    """
    result: List[Dict[str, Any]] = []
    try:
        since = int(time.time()) - int(hours) * 3600
        conn = _connect(db_path)
        try:
            cursor = conn.execute(
                """
                SELECT id, ts, category, severity, key, detail
                FROM events
                WHERE ts >= ?
                ORDER BY ts DESC, id DESC
                """,
                (since,),
            )
            for row in cursor.fetchall():
                try:
                    detail = json.loads(row[5]) if row[5] else {}
                except Exception:
                    detail = {"_raw": row[5]}
                result.append({
                    "id": row[0],
                    "ts": row[1],
                    "category": row[2],
                    "severity": row[3],
                    "key": row[4],
                    "detail": detail,
                })
        finally:
            conn.close()
    except Exception as exc:
        log("查询历史事件失败：%s" % exc, "ERROR")
    return result


def get_meta(db_path: str, key: str) -> Optional[str]:
    """
    读取 meta 表中的键值。键不存在或读取失败时返回 None（不抛异常）。
    """
    try:
        conn = _connect(db_path)
        try:
            cursor = conn.execute("SELECT value FROM meta WHERE key = ?", (str(key),))
            row = cursor.fetchone()
            return row[0] if row else None
        finally:
            conn.close()
    except Exception as exc:
        log("读取 meta 失败（key=%s）：%s" % (key, exc), "ERROR")
        return None


def set_meta(db_path: str, key: str, value: Any) -> bool:
    """
    写入/覆盖 meta 表中的键值（INSERT OR REPLACE）。

    返回 True 表示写入成功，失败只记日志并返回 False。
    """
    try:
        conn = _connect(db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                (str(key), str(value)),
            )
            conn.commit()
            return True
        finally:
            conn.close()
    except Exception as exc:
        log("写入 meta 失败（key=%s）：%s" % (key, exc), "ERROR")
        return False


# ---------------------------------------------------------------------------
# 规则层
# ---------------------------------------------------------------------------

def filter_new_events(
    db_path: str,
    events: List[Dict[str, Any]],
    dedup_hours: int,
) -> List[Dict[str, Any]]:
    """
    去重过滤：只保留最近 dedup_hours 小时内未出现过的 key。

    注意调用时序：必须在 save_events 之前调用本函数。若先入库再过滤，
    本次刚写入的事件会被自己判定为“重复”，导致永远推不出去。
    run 命令遵循“采集 -> 过滤 -> 入库 -> 推送”，正是为规避这一点。
    """
    new_events: List[Dict[str, Any]] = []
    for event in events:
        key = str(event.get("key", ""))
        if not key:
            continue
        if not is_duplicate(db_path, key, dedup_hours):
            new_events.append(event)
    return new_events


def is_report_due(db_path: str, interval_hours: Any) -> bool:
    """
    判断定时报告是否到点。

    规则：meta 中无 last_report_ts 记录，或 now - last_report_ts >= interval_hours * 3600。
    时间戳缺失/非法时保守地视为“到点”，保证不会长期不报告。
    """
    interval = _coerce_int(interval_hours, DEFAULT_CONFIG["report_interval_hours"])
    last = get_meta(db_path, "last_report_ts")
    if last is None or str(last).strip() == "":
        return True
    try:
        last_ts = int(float(last))
    except (TypeError, ValueError):
        return True
    return (int(time.time()) - last_ts) >= interval * 3600


# ---------------------------------------------------------------------------
# 企业微信推送
# ---------------------------------------------------------------------------

def truncate_utf8(text: str, max_bytes: int, suffix: str = "……（已截断）") -> str:
    """
    按 UTF-8 字节安全截断文本，末尾追加后缀。

    关键点：不能直接在 str 上按字节切，否则可能把一个多字节字符切成两半，
    导致对方收到乱码。这里先编码成 bytes 截断，再用 errors="ignore" 解码，
    残缺字节会被丢弃。
    """
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    suffix_bytes = suffix.encode("utf-8")
    budget = max_bytes - len(suffix_bytes)
    if budget <= 0:
        # 预算连后缀都放不下时，只截取后缀的前 max_bytes 字节
        return suffix_bytes[:max_bytes].decode("utf-8", errors="ignore")
    cut = raw[:budget].decode("utf-8", errors="ignore")
    return cut + suffix


def _detail_summary(detail: Any) -> str:
    """把 detail 字典压成一行 key=value 摘要，供通知与 report 展示。"""
    if not isinstance(detail, dict):
        return str(detail)
    parts = []
    for key, value in detail.items():
        parts.append("%s=%s" % (key, value))
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# 统一推送文本构建器（Phase 3）
# ---------------------------------------------------------------------------
# 设计要点：
#   * gather_server_info 复用采集器的底层读取函数，单项失败只填“未知”，不抛异常；
#   * build_report_text 是纯函数：不读系统、不发网络，便于离线单元测试；
#   * 推送文本统一为高可读纯文本（emoji 小节标题 + 键名冒号对齐 + 每事件一行）。

def _format_uptime_compact(seconds: Any) -> str:
    """
    把运行秒数格式化为紧凑中文（如“3小时42分”“2天3小时5分”）。

    与 Phase 2 的 _format_uptime 不同：这里不带空格、分钟简称“分”，
    用于统一报告里更紧凑的状态行。非法输入返回“未知”。
    """
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return "未知"
    if total < 0:
        total = 0
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days > 0:
        parts.append("%d天" % days)
        parts.append("%d小时" % hours)
    elif hours > 0:
        parts.append("%d小时" % hours)
    parts.append("%d分" % minutes)
    return "".join(parts)


def gather_server_info() -> Dict[str, Any]:
    """
    采集一份用于统一报告的服务器状态快照。

    复用现有底层读取：_read_load1 / _read_meminfo / shutil.disk_usage("/") / _read_uptime。
    返回字段：load1 / cpu_count / mem_percent / mem_used_gb / mem_total_gb /
             disk_percent / uptime_str / now_str。
    任何单项读取失败都只记日志并把该字段填为“未知”，绝不抛异常。
    """
    info: Dict[str, Any] = {
        "load1": "未知",
        "cpu_count": "未知",
        "mem_percent": "未知",
        "mem_used_gb": "未知",
        "mem_total_gb": "未知",
        "disk_percent": "未知",
        "uptime_str": "未知",
        "now_str": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # 1) CPU 核数（os.cpu_count 在极少数平台可能返回 None）
    try:
        cpu_count = os.cpu_count()
        info["cpu_count"] = int(cpu_count) if cpu_count else "未知"
    except Exception as exc:
        log("gather_server_info 读取 CPU 核数失败：%s" % exc, "WARNING")

    # 2) 1 分钟负载
    try:
        load1 = _read_load1()
        if load1 is not None:
            info["load1"] = round(float(load1), 2)
    except Exception as exc:
        log("gather_server_info 读取负载失败：%s" % exc, "WARNING")

    # 3) 内存使用率与用量（/proc/meminfo 以 kB 为单位）
    try:
        stats = _read_meminfo()
        total = stats.get("MemTotal", 0)
        if total > 0:
            if "MemAvailable" in stats:
                available = stats["MemAvailable"]
            else:
                # 旧内核兜底估算，与 collect_memory 保持一致
                available = stats.get("MemFree", 0) + stats.get("Buffers", 0) + stats.get("Cached", 0)
            used = total - available
            if used < 0:
                used = 0
            info["mem_percent"] = round(used * 100.0 / total, 1)
            info["mem_used_gb"] = round(used / 1024.0 / 1024.0, 1)
            info["mem_total_gb"] = round(total / 1024.0 / 1024.0, 1)
    except Exception as exc:
        log("gather_server_info 读取内存失败：%s" % exc, "WARNING")

    # 4) 根分区磁盘使用率
    try:
        usage = shutil.disk_usage("/")
        if usage.total > 0:
            info["disk_percent"] = round(usage.used * 100.0 / usage.total, 1)
    except Exception as exc:
        log("gather_server_info 读取根分区失败：%s" % exc, "WARNING")

    # 5) 系统运行时间
    try:
        info["uptime_str"] = _format_uptime_compact(_read_uptime())
    except Exception as exc:
        log("gather_server_info 读取运行时间失败：%s" % exc, "WARNING")

    return info


def _display_width(text: Any) -> int:
    """计算字符串的终端显示宽度（CJK 全角字符按 2 列计），用于冒号对齐。"""
    width = 0
    for char in str(text):
        if unicodedata.east_asian_width(char) in ("W", "F"):
            width += 2
        else:
            width += 1
    return width


def _event_summary(event: Dict[str, Any]) -> str:
    """
    从事件 detail 中提炼一句话摘要。

    按 category 挑选最关键的字段，保证每条事件只占一行；未知类别回退为
    通用的 key=value 摘要，避免丢失信息。
    """
    detail = event.get("detail")
    if not isinstance(detail, dict):
        return _detail_summary(detail)
    category = str(event.get("category", "")).lower()
    if category == "process":
        return "进程 %s 未运行" % detail.get("process", "未知")
    if category == "memory":
        return "使用率 %s%% ≥ 阈值 %s" % (
            detail.get("usage_percent", "?"), detail.get("threshold", "?"))
    if category == "disk":
        return "挂载点 %s 使用率 %s%% ≥ 阈值 %s" % (
            detail.get("mount", "?"), detail.get("usage_percent", "?"), detail.get("threshold", "?"))
    if category == "load":
        return "1分钟负载 %s ≥ 阈值 %s（%s 核）" % (
            detail.get("load1", "?"), detail.get("threshold", "?"), detail.get("cpu_count", "?"))
    if category == "ssh":
        return "来源 IP %s 失败 %s 次（窗口 %s 小时，阈值 %s）" % (
            detail.get("ip", "?"), detail.get("failed_count", "?"),
            detail.get("window_hours", "?"), detail.get("threshold", "?"))
    summary = _detail_summary(detail)
    return summary if summary else "无详细信息"


def _is_number(value: Any) -> bool:
    """判断是否为可用于数值格式化的 int/float（bool 不算）。"""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def build_report_text(
    server_info: Dict[str, Any],
    events: List[Dict[str, Any]],
    title: str = "Server Sentinel",
) -> str:
    """
    构建统一的高可读纯文本报告（纯函数，可离线测试）。

    版式：
        🖥️ <title>
        ⏰ <时间>

        📊 服务器状态
          <键名对齐>: <值>

        🚨 异常事件 (N)
          🔴 [CRITICAL] category key — 一句话摘要
        （无事件时显示 ✅ 一切正常，无异常事件）
    """
    info = server_info if isinstance(server_info, dict) else {}

    # 状态值格式化：任一相关字段不是数值时整行显示“未知”，避免半截数字 / 格式化异常
    if not _is_number(info.get("load1")) or not _is_number(info.get("cpu_count")):
        load_value = "未知"
    else:
        load_value = "%.2f (%d 核)" % (info.get("load1"), info.get("cpu_count"))

    if (not _is_number(info.get("mem_percent")) or not _is_number(info.get("mem_used_gb"))
            or not _is_number(info.get("mem_total_gb"))):
        mem_value = "未知"
    else:
        mem_value = "%.1f%% (%.1f / %.1f GB)" % (
            info.get("mem_percent"), info.get("mem_used_gb"), info.get("mem_total_gb"))

    if not _is_number(info.get("disk_percent")):
        disk_value = "未知"
    else:
        disk_value = "%.1f%%" % info.get("disk_percent")

    uptime_value = info.get("uptime_str") or "未知"

    status_rows = [
        ("1分钟负载", load_value),
        ("内存使用", mem_value),
        ("根分区磁盘", disk_value),
        ("运行时间", uptime_value),
    ]
    # 按显示宽度对齐冒号（CJK 全角按 2 列计）
    label_width = max(_display_width(label) for label, _ in status_rows)

    lines = [
        "🖥️ %s" % title,
        "⏰ %s" % (info.get("now_str") or "未知"),
        "",
        "📊 服务器状态",
    ]
    for label, value in status_rows:
        pad = label_width - _display_width(label)
        lines.append("  %s%s: %s" % (label, " " * pad, value))

    lines.append("")
    if events:
        lines.append("🚨 异常事件 (%d)" % len(events))
        for event in events:
            severity = str(event.get("severity", "info")).lower()
            icon = SEVERITY_ICONS.get(severity, "⚪")
            lines.append("  %s [%s] %s %s — %s" % (
                icon,
                severity.upper(),
                str(event.get("category", "-")),
                str(event.get("key", "-")),
                _event_summary(event),
            ))
    else:
        lines.append("✅ 一切正常，无异常事件")

    return "\n".join(lines)


def format_wecom_message(events: List[Dict[str, Any]]) -> str:
    """
    组装企业微信 Markdown 文本：按 severity 分组，critical 在最前。

    事件为空时返回“一切正常”汇总（供 run --force 使用）。
    """
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not events:
        return "## ✅ 一切正常\n\n> 本次巡检未发现异常。\n\n时间：%s" % now_str

    lines = ["## 🛡️ Server Sentinel 告警", "", "> 共 **%d** 条事件" % len(events), ""]
    known_severities = {sev for sev, _ in SEVERITY_ORDER}
    for severity, title in SEVERITY_ORDER:
        group = [e for e in events if str(e.get("severity")) == severity]
        if not group:
            continue
        lines.append("### %s（%d）" % (title, len(group)))
        for event in group:
            category = event.get("category", "-")
            key = event.get("key", "-")
            lines.append("- **%s** `%s`" % (category, key))
            summary = _detail_summary(event.get("detail", {}))
            if summary:
                lines.append("  > %s" % summary)
        lines.append("")
    # 兜底：万一出现未登记的 severity，也不要静默丢事件
    unknown = [e for e in events if str(e.get("severity")) not in known_severities]
    if unknown:
        lines.append("### ⚪ 其他（%d）" % len(unknown))
        for event in unknown:
            lines.append("- **%s** `%s`" % (event.get("category", "-"), event.get("key", "-")))
        lines.append("")
    lines.append("时间：%s" % now_str)
    return "\n".join(lines)


def send_wecom_text(webhook: str, text: str, max_push_bytes: int) -> bool:
    """
    向企业微信机器人 Webhook 推送任意文本内容（Phase 3 统一报告走这里）。

    返回 True 表示推送成功，False 表示跳过或失败。绝不抛异常：
    网络问题/对方限流只记日志，不影响 run 的主流程。webhook 为空时返回 False。
    """
    if not webhook:
        log("未配置 wecom_webhook，跳过企业微信推送", "INFO")
        return False

    # 组装文本并做字节级截断
    try:
        max_bytes = int(max_push_bytes)
    except (TypeError, ValueError):
        max_bytes = DEFAULT_CONFIG["max_push_bytes"]
    content = truncate_utf8(text, max_bytes)
    payload = {
        "msgtype": "markdown",
        "markdown": {"content": content},
    }
    try:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    except Exception as exc:
        log("企业微信消息序列化失败：%s" % exc, "ERROR")
        return False

    # 日志只打印打码后的地址与内容字节数，绝不打印原始 webhook
    log("企业微信推送：url=%s 内容字节数=%d" % (
        mask_webhook(webhook), len(content.encode("utf-8"))), "INFO")
    try:
        # Request 构造也放进 try：非法 URL（如缺协议）会在此抛 ValueError
        request = urllib.request.Request(
            webhook,
            data=body,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            resp_body = response.read().decode("utf-8", errors="ignore")
            status = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        log("企业微信推送 HTTP 错误：%s" % exc, "ERROR")
        return False
    except urllib.error.URLError as exc:
        log("企业微信推送网络错误：%s" % exc, "ERROR")
        return False
    except Exception as exc:
        log("企业微信推送异常：%s" % exc, "ERROR")
        return False

    # 企业微信即使 HTTP 200 也可能在 body 里返回非 0 errcode
    try:
        parsed = json.loads(resp_body) if resp_body else {}
        errcode = parsed.get("errcode", 0)
        if errcode not in (0, None):
            log("企业微信返回错误：errcode=%s errmsg=%s" % (errcode, parsed.get("errmsg", "")), "ERROR")
            return False
    except Exception:
        # 返回体不是 JSON 也无妨，HTTP 成功即视为成功
        pass

    log("企业微信推送成功（HTTP %s）" % status, "INFO")
    return True


def send_wecom(webhook: str, events: List[Dict[str, Any]], max_push_bytes: int) -> bool:
    """
    通过企业微信机器人 Webhook 推送事件列表（Phase 1 接口，保留兼容）。

    内部转成 Markdown 文本后交给 send_wecom_text 发送。
    """
    return send_wecom_text(webhook, format_wecom_message(events), max_push_bytes)


# ---------------------------------------------------------------------------
# Telegram Bot（仅标准库 urllib，Phase 2）
# ---------------------------------------------------------------------------
# 设计要点：
#   * 命令处理器（handle_*）是纯函数：只读配置 / 系统 / 数据库，返回回复文本，
#     不直接发起网络请求，便于离线单元测试。
#   * 网络层与命令层解耦：主循环只负责 getUpdates 长轮询、白名单校验、发送回复。
#   * 白名单是安全边界：非白名单消息只记 INFO 日志，绝不回复、绝不泄露信息。

# Telegram 返回的 Markdown（legacy）里需要反斜杠转义的字符。
# 只做最小转义，避免动态内容（IP、错误信息）中恰好出现这些字符导致解析失败。
_MD_SPECIAL_CHARS = set("\\_*`[")


def _md_escape(text: Any) -> str:
    """对动态文本做 Telegram Markdown(legacy) 最小转义。"""
    escaped = []
    for char in str(text):
        if char in _MD_SPECIAL_CHARS:
            escaped.append("\\" + char)
        else:
            escaped.append(char)
    return "".join(escaped)


def _format_uptime(seconds: Any) -> str:
    """把运行秒数格式化为“X 天 X 小时 X 分钟”。"""
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return str(seconds)
    if total < 0:
        total = 0
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days > 0:
        return "%d 天 %d 小时 %d 分钟" % (days, hours, minutes)
    if hours > 0:
        return "%d 小时 %d 分钟" % (hours, minutes)
    return "%d 分钟" % minutes


def _allowed_chat_id_set(config: Dict[str, Any]) -> set:
    """
    把配置里的白名单规整成整数集合。

    load_config 会把它统一成 List[str]，但离线测试或手工传入的也可能是 int，
    这里两种都兼容；无法转成整数的条目直接忽略并记 warning。
    """
    allowed = set()
    raw = config.get("telegram_allowed_chat_ids") or []
    if not isinstance(raw, (list, tuple, set)):
        raw = [raw]
    for item in raw:
        try:
            allowed.add(int(item))
        except (TypeError, ValueError):
            log("忽略非法 telegram_allowed_chat_ids 条目：%r" % (item,), "WARNING")
    return allowed


def is_chat_allowed(config: Dict[str, Any], chat_id: Any) -> bool:
    """判断 chat_id 是否在白名单内；chat_id 非法时一律拒绝。"""
    try:
        target = int(chat_id)
    except (TypeError, ValueError):
        return False
    return target in _allowed_chat_id_set(config)


def handle_help() -> str:
    """/help：列出全部命令说明。"""
    return (
        "🛡️ *Server Sentinel 命令列表*\n"
        "\n"
        "/help - 显示本帮助\n"
        "/status - 查看实时系统状态（负载 / 内存 / 根分区 / 运行时间）\n"
        "/ssh - 查看最近 1 小时 SSH 爆破记录\n"
        "\n"
        "提示：命令不区分大小写。"
    )


def handle_status(config: Dict[str, Any]) -> str:
    """/status：返回实时状态文本（单项读取失败不影响整体返回）。"""
    lines = ["🖥️ *Server Sentinel 实时状态*", ""]

    # 1 分钟负载（复用采集器的 /proc/loadavg 读取）
    try:
        load1 = _read_load1()
        cpu_count = os.cpu_count() or 1
        if load1 is None:
            lines.append("*1 分钟负载*：N/A")
        else:
            lines.append("*1 分钟负载*：`%.2f`（%d 核）" % (load1, cpu_count))
    except Exception as exc:
        log("status 读取负载失败：%s" % exc, "ERROR")
        lines.append("*1 分钟负载*：读取失败")

    # 内存使用率（复用 P1 的 _read_meminfo）
    try:
        stats = _read_meminfo()
        total = stats.get("MemTotal", 0)
        if total > 0:
            if "MemAvailable" in stats:
                available = stats["MemAvailable"]
            else:
                available = stats.get("MemFree", 0) + stats.get("Buffers", 0) + stats.get("Cached", 0)
            used = total - available
            if used < 0:
                used = 0
            percent = used * 100.0 / total
            lines.append("*内存使用率*：`%.1f%%`（%s / %s）" % (
                percent, _human_bytes(used * 1024), _human_bytes(total * 1024)))
        else:
            lines.append("*内存使用率*：N/A")
    except Exception as exc:
        log("status 读取内存失败：%s" % exc, "ERROR")
        lines.append("*内存使用率*：读取失败")

    # 根分区磁盘使用率
    try:
        usage = shutil.disk_usage("/")
        percent = usage.used * 100.0 / usage.total if usage.total > 0 else 0.0
        lines.append("*根分区磁盘*：`%.1f%%`（%s / %s）" % (
            percent, _human_bytes(usage.used), _human_bytes(usage.total)))
    except Exception as exc:
        log("status 读取根分区失败：%s" % exc, "ERROR")
        lines.append("*根分区磁盘*：读取失败")

    # 系统运行时间（/proc/uptime）
    try:
        lines.append("*系统运行时间*：%s" % _format_uptime(_read_uptime()))
    except Exception as exc:
        log("status 读取 uptime 失败：%s" % exc, "ERROR")
        lines.append("*系统运行时间*：读取失败")

    lines.append("")
    lines.append("时间：%s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return "\n".join(lines)


def handle_ssh(config: Dict[str, Any]) -> str:
    """/ssh：最近 1 小时 category='ssh' 事件按来源 IP 聚合。"""
    try:
        events = get_recent_events(config["db_path"], 1)
    except Exception as exc:
        log("status ssh 查询失败：%s" % exc, "ERROR")
        events = []

    counts = collections.Counter()
    for event in events:
        if str(event.get("category", "")).lower() != "ssh":
            continue
        detail = event.get("detail")
        if not isinstance(detail, dict):
            detail = {}
        ip = detail.get("ip")
        if not ip:
            # 兜底从 key（形如 ssh:1.2.3.4）解析
            key = str(event.get("key", ""))
            ip = key[4:] if key.startswith("ssh:") else (key or "未知")
        try:
            count = int(detail.get("failed_count", 1))
        except (TypeError, ValueError):
            count = 1
        if count <= 0:
            count = 1
        counts[str(ip)] += count

    if not counts:
        return "最近 1 小时无 SSH 爆破记录 ✅"

    lines = ["🔐 *最近 1 小时 SSH 爆破记录*", ""]
    for ip, count in counts.most_common():
        lines.append("- `%s`：%d 次" % (_md_escape(ip), count))
    lines.append("")
    lines.append("共 %d 个来源 IP" % len(counts))
    return "\n".join(lines)


def handle_unknown() -> str:
    """未知命令：引导用户查看帮助。"""
    return "未识别的命令，请使用 /help 查看可用命令。"


def handle_command(config: Dict[str, Any], text: Any) -> str:
    """
    命令分发（纯函数）。

    解析消息文本的首个 token，去掉 /cmd@BotName 的 @ 后缀，返回回复文本。
    """
    raw = str(text or "").strip()
    if not raw:
        return handle_unknown()
    first = raw.split()[0]
    if "@" in first:
        first = first.split("@", 1)[0]
    command = first.lower()
    if command == "/help":
        return handle_help()
    if command == "/status":
        return handle_status(config)
    if command == "/ssh":
        return handle_ssh(config)
    return handle_unknown()


def _telegram_api_url(token: str, method: str) -> str:
    """拼接 Bot API 地址（token 只在日志里以打码形式出现）。"""
    return "https://api.telegram.org/bot%s/%s" % (token, method)


def _mask_token(token: str) -> str:
    """Telegram token 打码，避免敏感凭据原样落日志。"""
    if not token:
        return "(未配置)"
    if len(token) <= 8:
        return "****"
    return token[:4] + "****" + token[-4:]


def _telegram_call(
    token: str,
    method: str,
    payload: Optional[Dict[str, Any]] = None,
    timeout: int = 30,
) -> Any:
    """
    调用 Telegram Bot API，成功返回 result 字段，失败返回 None。

    绝不抛异常（KeyboardInterrupt 除外）：网络 / HTTP / JSON 解析错误只记日志。
    """
    url = _telegram_api_url(token, method)
    try:
        body = json.dumps(payload or {}, ensure_ascii=False).encode("utf-8")
    except Exception as exc:
        log("Telegram 参数序列化失败（%s）：%s" % (method, exc), "ERROR")
        return None

    try:
        # Request 构造也放进 try：非法 URL（如 token 含空格/特殊字符）可能抛 ValueError
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="ignore")
        except Exception:
            pass
        log("Telegram API HTTP 错误（%s）：%s %s" % (method, exc, detail[:200]), "WARNING")
        return None
    except urllib.error.URLError as exc:
        log("Telegram API 网络错误（%s）：%s" % (method, exc), "WARNING")
        return None
    except Exception as exc:
        log("Telegram API 调用异常（%s）：%s" % (method, exc), "ERROR")
        return None

    try:
        parsed = json.loads(raw) if raw else {}
    except Exception as exc:
        log("Telegram 返回体解析失败（%s）：%s" % (method, exc), "ERROR")
        return None

    if not isinstance(parsed, dict) or not parsed.get("ok"):
        description = parsed.get("description", "") if isinstance(parsed, dict) else ""
        log("Telegram API 返回错误（%s）：%s" % (method, description), "WARNING")
        return None
    return parsed.get("result")


def _telegram_get_updates(token: str, offset: Optional[int]) -> Optional[List[Dict[str, Any]]]:
    """
    getUpdates 长轮询。

    服务端 timeout=30，客户端超时留余量设 35，避免服务端还在长轮询时客户端先超时。
    返回 None 表示调用失败（触发上层指数退避）；返回 [] 表示本次无更新。
    """
    payload: Dict[str, Any] = {
        "timeout": 30,
        "allowed_updates": ["message", "edited_message"],
    }
    if offset is not None:
        payload["offset"] = offset
    result = _telegram_call(token, "getUpdates", payload, timeout=35)
    if result is None:
        return None
    return result if isinstance(result, list) else []


def send_telegram_message(token: str, chat_id: Any, text: str) -> bool:
    """
    发送纯文本 Telegram 消息（不设置 parse_mode，避免动态内容触发解析错误）。

    token / chat_id 为空直接返回 False；网络异常 / HTTP 错误 / Telegram 返回
    ok=false 只记日志并返回 False，绝不抛异常。
    """
    if not token:
        log("未配置 telegram_bot_token，跳过 Telegram 发送", "INFO")
        return False
    if chat_id is None or str(chat_id).strip() == "":
        log("chat_id 为空，跳过 Telegram 发送", "WARNING")
        return False
    if not text:
        text = "(空消息)"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }
    # _telegram_call 已统一处理网络/HTTP/ok=false 异常，成功返回 result、失败返回 None
    return _telegram_call(token, "sendMessage", payload, timeout=10) is not None


def push_telegram(config: Dict[str, Any], text: str) -> bool:
    """
    主动向 telegram_allowed_chat_ids 中的每个 chat 推送同一条文本。

    token 为空或白名单为空时只记 INFO 并跳过；逐个发送，任一失败不影响其余。
    返回 True 表示至少有一个 chat 发送成功。
    """
    token = str(config.get("telegram_bot_token") or "").strip()
    if not token:
        log("未配置 telegram_bot_token，跳过 Telegram 推送", "INFO")
        return False

    raw_ids = config.get("telegram_allowed_chat_ids") or []
    if not isinstance(raw_ids, (list, tuple, set)):
        raw_ids = [raw_ids]
    chat_ids = [item for item in raw_ids if item is not None and str(item).strip() != ""]
    if not chat_ids:
        log("telegram_allowed_chat_ids 为空，跳过 Telegram 推送", "INFO")
        return False

    success = 0
    for chat_id in chat_ids:
        if send_telegram_message(token, chat_id, text):
            success += 1
    log("Telegram 推送完成：成功 %d/%d" % (success, len(chat_ids)), "INFO")
    return success > 0


def process_update(config: Dict[str, Any], token: str, update: Dict[str, Any]) -> None:
    """处理单条 update：白名单校验 -> 命令分发 -> 回复。"""
    if not isinstance(update, dict):
        return
    message = update.get("message") or update.get("edited_message")
    if not isinstance(message, dict):
        return
    chat = message.get("chat")
    chat_id = chat.get("id") if isinstance(chat, dict) else None
    if not is_chat_allowed(config, chat_id):
        # 安全边界：非白名单只记 INFO 日志，不回复、不泄露任何信息
        log("忽略非白名单 Telegram 消息：chat_id=%s" % chat_id, "INFO")
        return
    text = message.get("text") or message.get("caption") or ""
    reply = handle_command(config, text)
    send_telegram_message(token, chat_id, reply)


def run_telegram_bot(config: Dict[str, Any], token: Optional[str] = None) -> int:
    """
    bot 主循环：getUpdates 长轮询，offset 推进，网络异常指数退避。

    Ctrl+C（KeyboardInterrupt）时优雅退出并返回 0。
    """
    if token is None:
        token = str(config.get("telegram_bot_token") or "").strip()
    if not token:
        log("未配置 telegram_bot_token，无法启动 Telegram bot", "ERROR")
        return 2

    allowed = _allowed_chat_id_set(config)
    log("Telegram bot 启动：token=%s 白名单数量=%d" % (_mask_token(token), len(allowed)), "INFO")
    if not allowed:
        log("telegram_allowed_chat_ids 为空：所有消息都会被忽略（请在配置中添加 chat_id）", "WARNING")

    # 启动推送：先播报一条“服务已启动”状态，再进入长轮询。
    # systemd Restart=always 下每次重启都会推一次，这是符合预期的行为（README 已注明）。
    try:
        startup_text = build_report_text(
            gather_server_info(), [], title="🚀 Server Sentinel 服务已启动"
        )
        push_telegram(config, startup_text)
    except Exception as exc:
        # 启动推送无论如何都不能阻断 bot 主循环
        log("启动推送异常（已忽略）：%s" % exc, "ERROR")

    offset: Optional[int] = None
    backoff = 1
    while True:
        try:
            updates = _telegram_get_updates(token, offset)
            if updates is None:
                # 网络异常：指数退避，最长 60 秒，避免打爆 Telegram
                log("getUpdates 失败，%d 秒后重试" % backoff, "WARNING")
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 1
            for update in updates:
                update_id = update.get("update_id") if isinstance(update, dict) else None
                if isinstance(update_id, int):
                    # offset 推进：下次只取比已处理 update_id 更大的更新
                    offset = update_id + 1
                try:
                    process_update(config, token, update)
                except Exception as exc:
                    log("处理 Telegram update 异常：%s" % exc, "ERROR")
        except KeyboardInterrupt:
            log("收到 KeyboardInterrupt，Telegram bot 已优雅退出", "INFO")
            return 0
        except Exception as exc:
            log("Telegram bot 主循环异常：%s" % exc, "ERROR")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


# ---------------------------------------------------------------------------
# CLI 子命令
# ---------------------------------------------------------------------------

def push_all_channels(config: Dict[str, Any], text: str) -> bool:
    """
    把同一条文本同时推送到企业微信与 Telegram 两个通道。

    任一通道未配置只记 INFO 跳过；发送失败只记日志，返回值仅表示是否
    至少一个通道成功，调用方（run）不依赖它决定退出码。
    """
    wecom_ok = send_wecom_text(config["wecom_webhook"], text, config["max_push_bytes"])
    telegram_ok = push_telegram(config, text)
    return wecom_ok or telegram_ok


def cmd_run(config: Dict[str, Any], force: bool) -> int:
    """
    run 子命令主流程。

    采集 -> 规则过滤 -> 存库（保持不变）；随后：
      * 有新告警事件：即时推双通道（标题“🚨 ... 告警”）；
      * 定时报告：到点（或 --force）推双通道（标题“📋 ... 定时报告”）并更新
        meta.last_report_ts；无事件时报告显示“一切正常”。
    推送异常绝不影响退出码，始终返回 0。
    """
    log("=== Sentinel run 开始 ===", "INFO")
    start = time.time()

    events = collect_all(config)
    log("本次采集到 %d 条事件" % len(events), "INFO")

    # 先过滤后入库：过滤需要以“历史库”为基准，否则会把自己刚写的数据当成重复
    new_events = filter_new_events(config["db_path"], events, config["dedup_hours"])
    log("去重后待推送新事件 %d 条（dedup=%dh）" % (len(new_events), config["dedup_hours"]), "INFO")

    # 无论是否推送，本次采集到的全部事件都要落库，保证 report 有完整历史
    save_events(config["db_path"], events)

    # 状态快照供告警与定时报告共用，避免重复读取内核数据
    server_info = gather_server_info()

    # 1) 有新的告警事件 -> 即时推双通道
    if new_events:
        alert_text = build_report_text(server_info, new_events, title="🚨 Server Sentinel 告警")
        push_all_channels(config, alert_text)
    else:
        log("无新告警事件，跳过即时告警推送", "INFO")

    # 2) 定时报告 -> 到点（或 --force）推双通道并更新时间戳
    interval = config.get("report_interval_hours", DEFAULT_CONFIG["report_interval_hours"])
    due = True if force else is_report_due(config["db_path"], interval)
    if due:
        if force:
            log("--force 已开启：立即推送一次定时报告", "INFO")
        report_text = build_report_text(server_info, new_events, title="📋 Server Sentinel 定时报告")
        push_all_channels(config, report_text)
        # 报告内容可能因双通道截断而略变，但时间戳始终以实际推送时刻为准
        set_meta(config["db_path"], "last_report_ts", str(int(time.time())))
        log("定时报告已推送（间隔=%sh），last_report_ts 已更新" % interval, "INFO")
    else:
        log("未到定时报告时间（间隔=%sh），跳过定时报告" % interval, "INFO")

    log("=== Sentinel run 结束，耗时 %.2fs ===" % (time.time() - start), "INFO")
    return 0


def cmd_check(config: Dict[str, Any]) -> int:
    """
    check 子命令：逐个运行采集器，只打印名称与事件数量，不写库不推送。

    主要用于部署后验证采集逻辑与权限是否正常。
    """
    log("=== Sentinel check 开始（只读，不入库不推送）===", "INFO")
    total = 0
    for name, func in COLLECTORS:
        try:
            events = func(config)
        except Exception as exc:
            log("采集器 %s 意外失败：%s" % (name, exc), "ERROR")
            events = []
        total += len(events)
        log("采集器 %-8s 事件数=%d" % (name, len(events)), "INFO")
    log("=== Sentinel check 结束，合计 %d 条事件 ===" % total, "INFO")
    return 0


def cmd_report(config: Dict[str, Any], hours: int) -> int:
    """
    report 子命令：从库里查询最近 N 小时事件，按时间倒序打印。

    输出列：时间 / 级别 / 类别 / key / 摘要。库不存在或无数据时正常提示。
    """
    log("=== Sentinel report（最近 %d 小时）===" % hours, "INFO")
    events = get_recent_events(config["db_path"], hours)
    if not events:
        print("(无事件记录)")
        return 0

    for event in events:
        try:
            time_str = datetime.fromtimestamp(int(event.get("ts", 0))).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            time_str = str(event.get("ts", "-"))
        summary = _detail_summary(event.get("detail", {}))
        print("%s | %-8s | %-8s | %s | %s" % (
            time_str,
            str(event.get("severity", "-")).upper(),
            str(event.get("category", "-")),
            str(event.get("key", "-")),
            summary,
        ))
    log("报告结束，共 %d 条记录" % len(events), "INFO")
    return 0


def cmd_bot(config: Dict[str, Any]) -> int:
    """
    bot 子命令：启动 Telegram 长轮询机器人。

    token 为空时打印清晰错误并返回退出码 2（绝不抛 traceback）。
    """
    token = str(config.get("telegram_bot_token") or "").strip()
    if not token:
        log("未配置 telegram_bot_token，无法启动 Telegram bot。", "ERROR")
        log("请在配置文件中填写 telegram_bot_token（可参考 config.example.json）。", "ERROR")
        return 2
    return run_telegram_bot(config, token)


def build_parser() -> argparse.ArgumentParser:
    """构建 argparse 命令行解析器。"""
    parser = argparse.ArgumentParser(
        prog="sentinel.py",
        description="Server Sentinel —— 轻量级服务器监控与告警工具",
    )
    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # run：完整巡检流程
    run_parser = subparsers.add_parser(
        "run",
        help="采集 -> 入库 -> 去重 -> 双通道推送（告警即时推 + 定时报告）",
    )
    run_parser.add_argument(
        "--force", action="store_true",
        help="忽略报告间隔，立即推送一次定时报告（企业微信 + Telegram 双通道）",
    )

    # check：只读自检
    subparsers.add_parser("check", help="逐个运行采集器并打印事件数量（只读）")

    # report：历史查询
    report_parser = subparsers.add_parser("report", help="打印最近 N 小时的事件")
    report_parser.add_argument(
        "--hours", type=int, default=24,
        help="查询最近多少小时（默认 24）",
    )

    # bot：Telegram 长轮询机器人
    subparsers.add_parser(
        "bot",
        help="启动 Telegram 机器人（先推送启动状态，再 getUpdates 长轮询）",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """程序入口：解析参数、加载配置、分发子命令。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    config = load_config()

    if args.command == "run":
        return cmd_run(config, args.force)
    if args.command == "check":
        return cmd_check(config)
    if args.command == "report":
        # hours 允许为 0（等价于只看当前时刻之后），负数做保护
        hours = args.hours if args.hours and args.hours > 0 else 24
        return cmd_report(config, hours)
    if args.command == "bot":
        return cmd_bot(config)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
