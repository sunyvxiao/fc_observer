# -*- coding: utf-8 -*-
"""
qoder_report_gateway.py — Qoder CN 监测通道的统一接入门面（Web 与 CLI 共用）

定位:
  - 将 Qoder CN 监测（`daemon --mode mcp_report`，MCP tools + Hooks 确定性
    申报双通道）纳入 Web 界面（/api/qoder-monitor/*）与命令行控制台
    （menu > qoder 域）的薄门面。
  - 只读 config.yaml 的 mcp_report 配置段，不硬编码端口/路径；
  - 不修改 observer_core 任何组件、不触碰 WorkBuddy 网关
    （mcp_report_gateway.py 保持独立）。

能力:
  - start / stop: 以子进程方式拉起/优雅停止 mcp_report daemon
    （pid 文件 .monitoring/qoder_monitor.pid，日志 .monitoring/qoder_daemon.log）;
  - get_status: daemon/端口/双通道配置摘要 + 决策统计（审计文件解析）;
  - get_events: 审计 JSONL 尾随读取（轮询数据源；agent_id/decision 过滤）;
  - get_artifacts: output/qoder_monitoring 下报告/审计/汇总产物清单;
  - simulate: 构造 Hook 申报 payload 并 POST /api/hook-report，
    等效 `echo '...' | scripts/qoder_hook_reporter.py` 管道注入，
    无需真实 Qoder CN（复用 reporter 的 build_report_payload/post_report）。

SSE 实时推送（已实现，端点: GET /api/qoder-monitor/events/stream）:
  - text/event-stream 逐条推送与 get_events 同构的事件对象，首帧附
    counts 统计与历史事件；数据源: get_events()/stream_events()
    增量尾随设计，推送循环在 app.py SSE handler 内消费，本模块无需改动；
    前端 EventSource 接入，轮询 /api/qoder-monitor/events 保留为降级兜底。

P2 阻断联动预留:
  - PreToolUse Hook 拦截输出（{"decision":"block"} 回注 Agent）属 P2 范围，
    本轮不实现；simulate 已支持 hook_event_name="PreToolUse" 构造 pre 申报。
"""

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")

# 运行时文件统一放工作区内隐藏目录（避免 /tmp 权限冲突）
RUN_DIR = os.path.join(PROJECT_DIR, ".monitoring")
PID_FILE = os.path.join(RUN_DIR, "qoder_monitor.pid")
LOG_FILE = os.path.join(RUN_DIR, "qoder_daemon.log")

# scripts/ 下的 reporter 复用（simulate 与其同一 payload 构造逻辑）
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)
from scripts.qoder_hook_reporter import (build_report_payload, post_report)  # noqa: E402

# 进程管理系统（monitor_lifecycle.MonitorLifecycleManager）：
#   - track_pid/untrack_pid：daemon 纳入追踪列表，继承“随服务关闭终止”保护；
#   - 与 FIFO 内置 Monitor 隔离（生命周期管理器已按 --fifo 过滤进程扫描，
#     不会误杀本通道进程）。
from monitor_lifecycle import track_pid as _lc_track_pid  # noqa: E402
from monitor_lifecycle import untrack_pid as _lc_untrack_pid  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
DEFAULT_INGEST_PATH = "/api/hook-report"
OUTPUT_SUBDIR = "qoder_monitoring"

# 停止等待上限（秒）：优雅停止需等报告生成（含 rollup flush + L3 导出）
STOP_TIMEOUT_S = 45.0
START_READY_TIMEOUT_S = 15.0

# ── 后台任务状态（Web 侧异步执行 start/stop 的共享状态）────
_TASKS = {}


def _task(name):
    return _TASKS.setdefault(name, {
        "running": False, "done": False, "error": None, "detail": None,
        "started_at_ms": 0, "finished_at_ms": 0,
    })


def run_task(name, fn):
    """后台线程执行 fn，状态写入 _TASKS[name]。返回是否成功发起。"""
    t = _task(name)
    if t["running"]:
        return False
    t.update({"running": True, "done": False, "error": None, "detail": None,
              "started_at_ms": int(time.time() * 1000)})

    def _w():
        try:
            t["detail"] = fn()
        except Exception as e:  # noqa: BLE001
            t["error"] = str(e)
        t["running"] = False
        t["done"] = True
        t["finished_at_ms"] = int(time.time() * 1000)

    threading.Thread(target=_w, daemon=True).start()
    return True


def task_state(name):
    return dict(_task(name))


# ── 配置读取（只读 config.yaml mcp_report 段）──────────────────

def load_config(config_path=None):
    """读取 mcp_report 配置段（失败/缺失时返回安全默认值）。"""
    try:
        import yaml
        with open(config_path or CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        mcp = cfg.get("mcp_report") or {}
    except Exception:  # noqa: BLE001
        mcp = {}
    hook = mcp.get("hook_ingest") or {}
    return {
        "host": str(mcp.get("host") or DEFAULT_HOST),
        "port": int(mcp.get("port") or DEFAULT_PORT),
        "agent_id": str(mcp.get("target_agent_id") or "qoder"),
        "framework": str(mcp.get("framework") or "qoder"),
        "hook_ingest": {
            "enabled": bool(hook.get("enabled")),
            "path": str(hook.get("path") or DEFAULT_INGEST_PATH),
            "agent_id_default": str(hook.get("agent_id_default") or "qoder"),
        },
    }


def output_dir(cfg=None):
    cfg = cfg or load_config()
    return os.path.join(BASE_DIR, "output", OUTPUT_SUBDIR)


def ingest_url(cfg=None):
    """Hook 申报摄入端点完整 URL（模拟注入目标）。"""
    cfg = cfg or load_config()
    return f"http://{cfg['host']}:{cfg['port']}{cfg['hook_ingest']['path']}"


# ── 进程/端口工具 ──────────────────────────────────────────────

def _port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _read_pid():
    try:
        with open(PID_FILE, encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _is_zombie(pid):
    """进程已退出但未被父进程回收（zombie）→ 视为已停止。

    场景: Web 服务线程拉起 daemon 后自身退出，daemon 优雅停止后在极短
    窗口内可能以 zombie 残留（os.kill 0 仍可成功），避免 stop 误判超时。
    """
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("State:"):
                    return "Z" in line
    except OSError:
        pass
    return False


def daemon_alive():
    """pid 文件存在且进程存活（非 zombie）→ True。"""
    pid = _read_pid()
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # 进程存在但无权限（视为存活）
    except OSError:
        return False
    return not _is_zombie(pid)


def _log_tail(lines=80):
    """daemon 日志尾部（判定行/启动信息展示用）。"""
    if not os.path.isfile(LOG_FILE):
        return ""
    try:
        with open(LOG_FILE, "rb") as f:
            raw = f.read()
    except OSError:
        return ""
    tail = raw.decode("utf-8", errors="replace").splitlines()[-lines:]
    return "\n".join(tail)


# ── 生命周期 ───────────────────────────────────────────────────

def start():
    """以子进程拉起 mcp_report daemon（Qoder CN 专属输出目录）。"""
    cfg = load_config()
    if daemon_alive():
        return {"success": True, "already_running": True, "pid": _read_pid(),
                "message": "Qoder CN 监测 daemon 已在运行"}
    if _port_open(cfg["host"], cfg["port"]):
        return {"success": False, "error": "port_busy",
                "message": f"{cfg['host']}:{cfg['port']} 已被占用"
                           "（非本通道进程），请修改 config.yaml 的 "
                           "mcp_report.port 或停止占用进程"}
    os.makedirs(RUN_DIR, exist_ok=True)
    os.makedirs(output_dir(cfg), exist_ok=True)
    cmd = [sys.executable, os.path.join(BASE_DIR, "monitor_daemon.py"),
           "--mode", "mcp_report", "--config", CONFIG_PATH,
           "--output", output_dir(cfg)]
    log_fp = open(LOG_FILE, "ab")
    try:
        proc = subprocess.Popen(
            cmd, cwd=BASE_DIR, stdin=subprocess.DEVNULL,
            stdout=log_fp, stderr=subprocess.STDOUT,
            start_new_session=True)
    finally:
        log_fp.close()
    # reap 线程：父进程（Web 服务）wait() 回收子进程，避免僵尸条目残留；
    # 进程追踪：注册到 MonitorLifecycleManager，随服务关闭终止。
    threading.Thread(target=proc.wait, daemon=True).start()
    _lc_track_pid(proc.pid)
    try:
        with open(PID_FILE, "w", encoding="utf-8") as f:
            f.write(str(proc.pid))
    except OSError:
        pass
    deadline = time.time() + START_READY_TIMEOUT_S
    while time.time() < deadline:
        if _port_open(cfg["host"], cfg["port"]):
            return {
                "success": True, "running": True, "pid": proc.pid,
                "sse_url": f"http://{cfg['host']}:{cfg['port']}/sse",
                "ingest_url": ingest_url(cfg),
                "output_dir": output_dir(cfg), "log_path": LOG_FILE,
            }
        if proc.poll() is not None:
            return {"success": False, "error": "crashed",
                    "message": f"daemon 启动即退出（退出码 {proc.returncode}）",
                    "log_tail": _log_tail(30)}
        time.sleep(0.3)
    return {"success": False, "error": "not_ready",
            "message": f"端口 {cfg['port']} 未在 "
                       f"{START_READY_TIMEOUT_S:.0f}s 内就绪",
            "log_tail": _log_tail(30)}


def stop():
    """优雅停止（SIGTERM 触发 daemon 生成报告），返回产物清单。"""
    if not daemon_alive():
        pid = _read_pid()
        if pid is not None:
            _lc_untrack_pid(pid)
            try:
                os.remove(PID_FILE)
            except OSError:
                pass
        return {"success": True, "already_stopped": True,
                "artifacts": get_artifacts()["artifacts"]}
    pid = _read_pid()
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        return {"success": False, "error": f"kill_failed: {e}"}
    deadline = time.time() + STOP_TIMEOUT_S
    while time.time() < deadline:
        if not daemon_alive():
            break
        time.sleep(0.5)
    if daemon_alive():
        # 最后手段: 仍未退出则 SIGKILL（报告可能不完整，如实返回）
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        time.sleep(1.0)
        if daemon_alive():
            return {"success": False, "error": "timeout",
                    "message": f"daemon 未在 {STOP_TIMEOUT_S:.0f}s 内退出"}
    _lc_untrack_pid(pid)
    try:
        os.remove(PID_FILE)
    except OSError:
        pass
    time.sleep(0.5)
    return {"success": True, "stopped": True,
            "artifacts": get_artifacts()["artifacts"],
            "log_tail": _log_tail(30)}


# ── 审计事件（轮询数据源；SSE 阶段复用同一增量尾随逻辑）────────

def _latest_audit_file(agent_id):
    """定位最新审计文件：优先 audit_mcp_report_*，退化取最新任意文件。"""
    audit_dir = os.path.join(output_dir(), "audit")
    if not os.path.isdir(audit_dir):
        return None
    primary = sorted(
        (f for f in os.listdir(audit_dir)
         if f.startswith("audit_mcp_report_") and f.endswith(".jsonl")),
        key=lambda n: os.path.getmtime(os.path.join(audit_dir, n)),
        reverse=True)
    if primary:
        return os.path.join(audit_dir, primary[0])
    fallback = sorted(
        (f for f in os.listdir(audit_dir) if f.endswith(".jsonl")),
        key=lambda n: os.path.getmtime(os.path.join(audit_dir, n)),
        reverse=True)
    return os.path.join(audit_dir, fallback[0]) if fallback else None


def _parse_audit_line(line):
    """审计行 → 精简事件对象（前端/CLI 展示字段）。解析失败返回 None。"""
    try:
        d = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(d, dict):
        return None
    return {
        "event_id": d.get("event_id"),
        "agent_id": d.get("agent_id"),
        "session_id": d.get("session_id"),
        "event_type": d.get("event_type"),
        "description": d.get("description"),
        "command_string": d.get("command_string"),
        "file_path": d.get("file_path"),
        "matched_rules": d.get("matched_rules") or [],
        "decision_action": d.get("decision_action"),
        "decision_reason": d.get("decision_reason"),
        "risk_score": d.get("risk_score"),
        "risk_level": d.get("risk_level"),
        "timestamp_ns": d.get("timestamp_ns"),
    }


def get_events(tail=50, agent_id=None, decision=None):
    """审计尾随读取（轮询）。返回 {events, counts, source}。

    Args:
        tail: 返回最近 N 条（1-500）
        agent_id: 过滤 agent（如 "qoder"；None=不过滤）
        decision: 过滤决策（allow|alert|block；None=不过滤）

    SSE 预留: GET /api/qoder-monitor/events/stream 已实现，推送循环以同一审计数据源工作，
    事件对象结构保持不变，轮询接口保留为降级兜底。
    """
    tail = min(max(int(tail or 50), 1), 500)
    path = _latest_audit_file(agent_id)
    events, counts = [], {"allow": 0, "alert": 0, "block": 0, "total": 0}
    if not path or not os.path.isfile(path):
        return {"events": [], "counts": counts, "source": None}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return {"events": [], "counts": counts, "source": path}
    parsed = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        ev = _parse_audit_line(ln)
        if ev is None:
            continue
        counts["total"] += 1
        act = str(ev.get("decision_action") or "").lower()
        if act in counts:
            counts[act] += 1
        if agent_id and ev.get("agent_id") != agent_id:
            continue
        if decision and act != str(decision).lower():
            continue
        parsed.append(ev)
    return {"events": parsed[-tail:], "counts": counts, "source": path}


def stream_events(agent_id=None, poll_interval=0.5):
    """增量尾随生成器（CLI 流式输出用；Ctrl+C 打断）。

    与 get_events 同一数据源，仅产出新增审计行。
    已被 SSE 实时推送复用（已实现）：app.py 的 /api/qoder-monitor/events/stream
    handler 内逐条消费本生成器并 yield 为 data 帧，事件对象与轮询接口同构。
    """
    path = None
    pos = 0
    while True:
        if path is None or not os.path.isfile(path):
            path = _latest_audit_file(agent_id)
            pos = os.path.getsize(path) if path and os.path.isfile(path) else 0
            # 首次附着只跟踪增量，历史由 get_events 负责
        try:
            size = os.path.getsize(path) if path else 0
        except OSError:
            size = 0
        if size > pos and path:
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                for ln in chunk.splitlines():
                    ev = _parse_audit_line(ln.strip())
                    if ev is None:
                        continue
                    if agent_id and ev.get("agent_id") != agent_id:
                        continue
                    yield ev
            except OSError:
                pass
        time.sleep(poll_interval)


# ── 状态与产物 ─────────────────────────────────────────────────

def get_status():
    """Qoder CN 监测通道整体状态（结构化）。"""
    cfg = load_config()
    alive = daemon_alive()
    port_open = _port_open(cfg["host"], cfg["port"])
    ev = get_events(tail=20)
    verdicts = [
        ln.strip() for ln in _log_tail(120).splitlines()
        if any(k in ln for k in ("ALLOW", "ALERT", "BLOCK"))
    ]
    return {
        "daemon_running": alive,
        "daemon_pid": _read_pid() if alive else None,
        "port_open": port_open,
        "server": {
            "host": cfg["host"], "port": cfg["port"],
            "sse_url": f"http://{cfg['host']}:{cfg['port']}/sse",
            "ingest_url": ingest_url(cfg),
        },
        "channels": {
            "mcp_tools": port_open,           # MCP 申报（依赖 Agent 主动调用）
            "hook_ingest": bool(cfg["hook_ingest"]["enabled"] and port_open),
            "hook_ingest_enabled": cfg["hook_ingest"]["enabled"],
        },
        "agent_id": cfg["agent_id"],
        "framework": cfg["framework"],
        "output_dir": output_dir(cfg),
        "log_path": LOG_FILE,
        "counts": ev["counts"],
        "recent_events": ev["events"][-10:],
        "verdicts": verdicts[-20:],
        "sse_reserved": "GET /api/qoder-monitor/events/stream（已实现：SSE 增量推送，"
                        "前端 EventSource 接入，轮询保留为降级兜底）",
        "p2_blocking_reserved": "PreToolUse 拦截回注（P2 范围，本轮未实现）",
    }


def get_artifacts():
    """output/qoder_monitoring 下的报告/审计/汇总产物清单。"""
    out_dir = output_dir()
    items = []
    if os.path.isdir(out_dir):
        for root, _, files in os.walk(out_dir):
            for fn in files:
                full = os.path.join(root, fn)
                if (("risk_report" in fn and fn.endswith(".md"))
                        or fn.endswith(".jsonl")
                        or fn == "monitoring_summary.json"):
                    try:
                        size = os.path.getsize(full)
                        mtime = os.path.getmtime(full)
                    except OSError:
                        size, mtime = -1, 0
                    items.append({
                        "name": fn,
                        "rel_path": os.path.relpath(full, out_dir).replace(
                            os.sep, "/"),
                        "size": size,
                        "mtime": mtime,
                    })
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return {"output_dir": out_dir, "artifacts": items}


# ── 模拟注入（等效 echo '...' | qoder_hook_reporter.py）────────

def build_simulate_payload(tool_name, tool_args=None, session_id=None,
                           hook_event_name="PostToolUse", agent_id=None,
                           tool_response=None):
    """构造与真实 Hook 完全同构的申报体（复用 reporter 转换逻辑）。"""
    cfg = load_config()
    hook_event = {
        "hook_event_name": hook_event_name or "PostToolUse",
        "session_id": session_id or f"web-sim-{int(time.time() * 1000)}",
        "cwd": PROJECT_DIR,
        "tool_name": tool_name,
        "tool_input": tool_args if isinstance(tool_args, dict) else {},
        "tool_response": tool_response,
    }
    payload = build_report_payload(hook_event,
                                   agent_id=agent_id or cfg["agent_id"])
    return payload, hook_event


def simulate(tool_name, tool_args=None, session_id=None,
             hook_event_name="PostToolUse", agent_id=None,
             tool_response=None, timeout_s=3.0):
    """模拟注入一条 Hook 申报到 /api/hook-report，返回注入结果。

    Returns:
        {"sent": bool, "status": "accepted"|"rejected"|"unreachable",
         "reason": ..., "payload": ..., "url": ...}
    """
    payload, _ = build_simulate_payload(
        tool_name, tool_args=tool_args, session_id=session_id,
        hook_event_name=hook_event_name, agent_id=agent_id,
        tool_response=tool_response)
    url = ingest_url()
    if payload is None:
        return {"sent": False, "status": "rejected",
                "reason": "payload_build_failed", "payload": None, "url": url}
    result = post_report(payload, url, timeout_s=timeout_s)
    if result is None:
        return {"sent": False, "status": "unreachable",
                "reason": "监测端点不可达（请先启动 Qoder CN 监测）",
                "payload": payload, "url": url}
    return {"sent": True,
            "status": str(result.get("status") or "unknown"),
            "reason": result.get("reason"),
            "receipt": {k: v for k, v in result.items()
                        if k not in ("status", "reason")} or None,
            "payload": payload, "url": url}
