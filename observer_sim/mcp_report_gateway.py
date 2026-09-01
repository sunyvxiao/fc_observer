# -*- coding: utf-8 -*-
"""
mcp_report_gateway.py — MCP 申报降级监测的统一接入门面（CLI 与 Web 共用）

定位:
  - 将 MCP 申报通道（WorkBuddy 降级监测，`daemon --mode mcp_report`，
    HTTP+SSE `http://127.0.0.1:8765/sse`）纳入统一入口交互界面的薄门面。
  - 只读 workbuddy_connect.yaml 用户配置，不硬编码路径；
  - 生命周期复用 connect_workbuddy.py 的管家/端口/进程工具函数；
  - 为 Web 提供结构化结果（dict），为 CLI 提供子命令转发目标，
    不修改 observer_core 任何组件。

能力边界（如实说明）:
  - 适用: 合规留痕 + 风险提示（申报 → 统一管线判定 ALLOW/ALERT/BLOCK →
    风险报告/审计/图谱）。
  - 降级/不可用: 无交叉校验（无 syscall 佐证）、无 L2/L3 内核级阻断、
    依赖 Agent 主动申报；Linux FIFO 实时监测/录制-回放/eBPF 阻断为独立
    模式，与本通道无关（Windows 下不可用，见 console.py _env_gate）。
"""

import json
import os
import threading
import time

import connect_workbuddy as cw

# 进程管理系统（monitor_lifecycle.MonitorLifecycleManager）：
#   - track_pid/untrack_pid：管家与 daemon 纳入追踪列表，继承“随服务关闭终止”
#     保护；生命周期管理器已按 --fifo 过滤进程扫描，不会误杀本通道。
from monitor_lifecycle import track_pid as _lc_track_pid
from monitor_lifecycle import untrack_pid as _lc_untrack_pid

# ── 后台任务状态（Web 侧异步执行 start/stop/smoke 的共享状态）────
_TASKS = {}


def load_cfg():
    return cw.load_config(cw.DEFAULT_CONFIG)


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


def _read_watch_pids(pid_path):
    """读管家 JSON pid 文件，返回 [daemon_pid, watchdog_pid]（有效者）。"""
    pids = []
    try:
        with open(pid_path, encoding="utf-8") as f:
            info = json.load(f)
        for key in ("daemon", "watchdog"):
            pid = int(info.get(key) or 0)
            if pid > 0:
                pids.append(pid)
    except (OSError, ValueError, TypeError):
        pass
    return pids


# ── 状态查询（结构化）────────────────────────────────────────────

def _workbuddy_registration(cfg):
    """WorkBuddy mcp.json 中 observer 条目注册状态。"""
    path = cfg["workbuddy"]["mcp_config_path"]
    if not os.path.isfile(path):
        return {"registered": False, "reason": "mcp.json 不存在",
                "path": path}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        entry = data.get("mcpServers", {}).get(cw.OBSERVER_SERVER_NAME)
        if not entry:
            return {"registered": False, "reason": "未注册 observer",
                    "path": path}
        return {"registered": True, "url": entry.get("url"),
                "type": entry.get("type"),
                "disabled": bool(entry.get("disabled")), "path": path}
    except (OSError, ValueError) as e:
        return {"registered": False, "reason": f"mcp.json 解析失败: {e}",
                "path": path}


def get_status():
    """MCP 申报通道整体状态（daemon/端口/WorkBuddy/判定/配置摘要）。"""
    cfg = load_cfg()
    out_dir, pid_path, log_path, _ = cw._out_paths(cfg)
    host = cfg["server"]["host"]
    port = int(cfg["server"]["port"])
    alive = cw._daemon_alive(pid_path)
    port_open = cw._port_open(host, port)
    tail = cw._log_tail(log_path, 120)
    verdicts = [
        ln.strip() for ln in tail.splitlines()
        if any(k in ln for k in ("ALLOW", "ALERT", "BLOCK"))
    ]
    procs = cw._ps_info("WorkBuddy")
    info = {}
    if os.path.isfile(pid_path):
        try:
            with open(pid_path, encoding="utf-8") as f:
                info = json.load(f)
        except (OSError, ValueError):
            info = {}
    return {
        "daemon_running": alive,
        "daemon_pid": info.get("daemon"),
        "watchdog_pid": info.get("watchdog"),
        "port_open": port_open,
        "server": {"host": host, "port": port,
                   "sse_path": cfg["server"]["sse_path"],
                   "url": f"http://{host}:{port}{cfg['server']['sse_path']}"},
        "agent_id": cfg["workbuddy"]["agent_id"],
        "workbuddy": {
            "process_count": len(procs),
            "main_window": any(w for _, w in procs),
            "registration": _workbuddy_registration(cfg),
        },
        "output_dir": out_dir,
        "verdicts": verdicts[-20:],
        "config_ok": True,
        "config_path": cw.DEFAULT_CONFIG,
    }


def get_artifacts():
    """output/mcp_monitoring 下的报告/审计/汇总产物清单。"""
    cfg = load_cfg()
    out_dir, _, _, _ = cw._out_paths(cfg)
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


def get_logs(lines=60):
    cfg = load_cfg()
    _, _, log_path, _ = cw._out_paths(cfg)
    return {"log_path": log_path, "lines": cw._log_tail(log_path, lines)}


# ── 生命周期动作（结构化结果）────────────────────────────────────

def start(no_rollup=False):
    """启动 MCP 申报 daemon（复用 connect_workbuddy 管家托管逻辑）。

    no_rollup: test_report 轻量测试报告模式（阶段 3）——仅记录 L0
        原始事件，不触发 L1→L2→L3 分层聚合，结束后一次性输出报告。
        默认 False（走完整生产分层路径）。
    """
    cfg = load_cfg()
    out_dir, pid_path, log_path, _ = cw._out_paths(cfg)
    if cw._daemon_alive(pid_path):
        return {"success": True, "already_running": True,
                "message": "daemon 已在运行"}
    host = cfg["server"]["host"]
    port = int(cfg["server"]["port"])
    if cw._port_open(host, port):
        return {"success": False, "error": "port_busy",
                "message": f"{host}:{port} 已被占用（非本通道 daemon），"
                           "请修改 workbuddy_connect.yaml 的 server.port"}
    os.makedirs(out_dir, exist_ok=True)
    script = os.path.abspath(cw.__file__)
    cmd = [cfg["observer"]["python"], script, "--internal-watch",
           "--config", cw.DEFAULT_CONFIG]
    if no_rollup:
        cmd.append("--no-rollup")
    subprocess = __import__("subprocess")
    proc = subprocess.Popen(cmd, cwd=cw.BASE_DIR,
                            creationflags=cw.CREATE_NO_WINDOW)
    # reap 线程：回收管家进程，避免僵尸条目残留（Web 服务为长驻父进程）
    threading.Thread(target=proc.wait, daemon=True).start()
    if not cw._wait_port(cfg, float(cfg["daemon"]["ready_timeout_s"])):
        return {"success": False, "error": "not_ready",
                "message": f"端口 {port} 未在 "
                           f"{cfg['daemon']['ready_timeout_s']}s 内就绪",
                "log_tail": cw._log_tail(log_path, 30)}
    # 进程追踪：管家 + daemon 均纳入 MonitorLifecycleManager 追踪列表
    for pid in _read_watch_pids(pid_path):
        _lc_track_pid(pid)
    return {"success": True, "running": True,
            "url": f"http://{host}:{port}{cfg['server']['sse_path']}",
            "log_path": log_path}


def stop():
    """优雅停止 MCP 申报 daemon（触发报告生成）并返回产物。"""
    cfg = load_cfg()
    out_dir, pid_path, _, stop_path = cw._out_paths(cfg)
    tracked = _read_watch_pids(pid_path)  # 停止前记录，成功后解除追踪
    if not cw._daemon_alive(pid_path):
        for pid in tracked:
            _lc_untrack_pid(pid)
        if os.path.exists(pid_path):
            try:
                os.remove(pid_path)
            except OSError:
                pass
        return {"success": True, "already_stopped": True,
                "artifacts": get_artifacts()["artifacts"]}
    with open(stop_path, "w", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%dT%H:%M:%S"))
    deadline = time.time() + 45
    while time.time() < deadline:
        if not cw._daemon_alive(pid_path):
            break
        time.sleep(0.5)
    if cw._daemon_alive(pid_path):
        return {"success": False, "error": "timeout",
                "message": "daemon 未在 45s 内退出"}
    for pid in tracked:
        _lc_untrack_pid(pid)
    time.sleep(1.0)
    return {"success": True, "stopped": True,
            "artifacts": get_artifacts()["artifacts"]}


def smoke():
    """模拟 WorkBuddy 申报序列（连通性 + accepted/rejected + 判定）。"""
    cfg = load_cfg()
    agent = cfg["workbuddy"]["agent_id"]
    session_id = f"smoke-{int(time.time())}"
    results, _ = cw._mcp_roundtrip(cfg, cw._smoke_reports(agent, session_id))
    accepted = sum(1 for n, r in results
                   if n != "__initialize__" and r.get("status") == "accepted")
    rejected = sum(1 for n, r in results
                   if n != "__initialize__" and r.get("status") == "rejected")
    time.sleep(2.5)
    tail = cw._log_tail(get_logs()["log_path"], 40)
    verdicts = [ln.strip() for ln in tail.splitlines()
                if any(k in ln for k in ("ALLOW", "ALERT", "BLOCK"))]
    return {
        "session_id": session_id,
        "accepted": accepted,
        "rejected": rejected,
        "expected_accepted": 5,
        "expected_rejected": 2,
        "verdicts": verdicts[-10:],
        "ok": accepted == 5 and rejected == 2 and bool(verdicts),
    }


def check():
    """连通性自检（端口 + initialize + call_tool accepted）。"""
    cfg = load_cfg()
    host = cfg["server"]["host"]
    port = int(cfg["server"]["port"])
    port_open = cw._port_open(host, port)
    detail = {}
    if port_open:
        try:
            results, tools = cw._mcp_roundtrip(cfg, [("report_session", {
                "agent_id": cfg["workbuddy"]["agent_id"],
                "session_id": "check-session", "status": "start"})],
                list_tools=True)
            init = dict(results[0][1]) if results else {}
            call = dict(results[1][1]) if len(results) > 1 else {}
            detail = {"initialize": init, "tools": tools,
                      "call_status": call.get("status")}
        except Exception as e:  # noqa: BLE001
            detail = {"error": str(e)}
    return {"port_open": port_open,
            "ok": port_open and detail.get("call_status") == "accepted",
            "detail": detail}


def task_state(name):
    return dict(_task(name))
