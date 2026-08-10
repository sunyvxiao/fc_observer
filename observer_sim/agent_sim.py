#!/usr/bin/env python3
"""
agent_sim.py — 独立 Agent 模拟进程

模拟「Q3 商业报表市场分析」场景中的 AI Agent 行为。
读取 da04_production_demo.yaml 场景文件，将 tool_calls 转换为 RawEvent，
以 JSON 行格式输出到命名管道 (FIFO) 供监测守护进程消费。

特性:
- 完全独立运行，与监测系统无代码依赖
- 每个事件之间间隔 realistic 延迟（数百毫秒）
- 通过 FIFO 管道与监测进程通信
- 支持优雅退出 (SIGTERM/SIGINT)

用法:
    python agent_sim.py --fifo /tmp/observer_monitoring_pipe
    python agent_sim.py --fifo /tmp/observer_monitoring_pipe --speed 2.0
"""

import sys
import os
import json
import time
import signal
import argparse
import re
from typing import List, Dict, Any

import yaml

# ── 工具名 → 事件类型映射（全部小写，大小写不敏感匹配）─────────
_EXEC_TOOLS = {
    "execute", "execute_command", "run_command", "shell", "bash",
    "python3", "python",
    # pydantic-deep 任务/状态管理
    "task", "check_task", "wait_tasks",
    "update_todo_statuses", "list_skills",
    "ask_user", "search_conversation_history",
    "read_rules", "create_rule",
}
_READ_TOOLS = {
    "read_file", "read", "cat", "list_files", "grep", "glob",
    "read_memory", "read_todos",
}
_WRITE_TOOLS = {
    "write_file", "write", "edit_file", "edit", "patch",
    "write_todos", "write_memory",
}
_NET_TOOLS = {
    "web_fetch", "fetch", "web_search", "browse", "curl",
    "http_request",
}

# 工具名子串 → 事件类型的 fallback 规则（按优先级）
_TOOL_PATTERN_FALLBACKS = [
    ("search", "net_conn"),
    ("fetch", "net_conn"),
    ("browse", "net_conn"),
    ("read", "file_open"),
    ("write", "file_open"),
    ("edit", "file_open"),
    ("file", "file_open"),
    ("list", "file_open"),
    ("grep", "file_open"),
    ("glob", "file_open"),
    ("curl", "net_conn"),
    ("wget", "net_conn"),
    ("request", "net_conn"),
]

# DEBUG：记录未识别工具名（避免重复输出）
_unknown_tools_logged = set()


def _classify_tool(tool_name: str) -> str:
    """
    根据工具名推断事件类型。

    匹配优先级：精确映射 → 子串 fallback → 默认 exec
    全部大小写不敏感。
    """
    tl = tool_name.lower().strip()
    if tl in _EXEC_TOOLS:
        return "exec"
    if tl in _READ_TOOLS:
        return "file_open"
    if tl in _WRITE_TOOLS:
        return "file_open"
    if tl in _NET_TOOLS:
        return "net_conn"

    # 子串 fallback
    for pattern, etype in _TOOL_PATTERN_FALLBACKS:
        if pattern in tl:
            return etype

    # 未识别 → 记录并默认 exec
    if tl and tl not in _unknown_tools_logged:
        _unknown_tools_logged.add(tl)
        print(f"[agent_sim] DEBUG: 未知工具名映射: '{tool_name}' → 默认 exec",
              file=sys.stderr)
    return "exec"

_running = True


def _handle_signal(signum, frame):
    global _running
    _running = False


def _extract_host(url: str) -> str:
    """从 URL 提取主机地址"""
    if not url:
        return "unknown"
    host = url
    for prefix in ("https://", "http://", "ftp://", "smtp://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
            break
    host = host.split("/")[0].split("?")[0].split(":")[0]
    return host or "unknown"


def _extract_port(url: str) -> int:
    """从 URL 提取端口"""
    import re
    m = re.match(r'\w+://[^:/]+:(\d+)', url)
    if m:
        return int(m.group(1))
    if url.startswith("https"):
        return 443
    if url.startswith("smtp"):
        return 587
    return 80


def _make_event_dict(event_id: str, ts: int, event_type: str, pid: int,
                     ppid: int, agent_id: str, **kwargs) -> Dict[str, Any]:
    """构建 RawEvent 兼容字典（零 observer_sim 依赖）"""
    d: Dict[str, Any] = {
        "event_id": event_id,
        "timestamp_ns": ts,
        "event_type": event_type,
        "pid": pid,
        "ppid": ppid,
        "agent_id": agent_id,
        "agent_framework": "pydantic-deep-sim",
        "executable": None,
        "arguments": None,
        "file_path": None,
        "file_op": None,
        "remote_addr": None,
        "remote_port": None,
        "protocol": None,
    }
    d.update(kwargs)
    return d


def tool_calls_to_events(tool_calls: list, base_ts: int,
                          agent_id: str, scenario_id: str) -> List[Dict[str, Any]]:
    """将 DeepAgent YAML 的 tool_calls 转换为事件字典列表（零 observer_sim 依赖）"""
    events: List[Dict[str, Any]] = []
    seq = 0
    pid_base = 60000

    for call in tool_calls:
        seq += 1
        tool_name = call.get("tool", "execute")
        tool_input = call.get("input", {})
        delay_ms = call.get("delay_ms", 100)
        ts = base_ts + seq * delay_ms * 1_000_000  # ms → ns
        eid = f"da_{scenario_id}_{seq:03d}"
        pid = pid_base + seq

        event_type = _classify_tool(tool_name)

        if event_type == "exec":
            cmd = tool_input.get("command", tool_input.get("cmd", tool_name))
            parts = cmd.split() if isinstance(cmd, str) else [str(cmd)]
            events.append(_make_event_dict(
                eid, ts, "exec", pid, pid_base, agent_id,
                executable=parts[0] if parts else tool_name,
                arguments=parts,
            ))
        elif event_type == "file_open":
            file_path = (tool_input.get("path")
                         or tool_input.get("file_path")
                         or tool_input.get("file") or "")
            # 根据工具名判断读/写操作
            if tool_name in _READ_TOOLS:
                file_op = "read"
            elif tool_name in _WRITE_TOOLS:
                file_op = "write"
            elif any(p in tool_name.lower() for p in ("write", "edit", "patch")):
                file_op = "write"
            else:
                file_op = "read"  # 默认读
            events.append(_make_event_dict(
                eid, ts, "file_open", pid, pid_base, agent_id,
                file_path=file_path,
                file_op=file_op,
            ))
        elif event_type == "net_conn":
            url = (tool_input.get("url") or tool_input.get("query") or "")
            events.append(_make_event_dict(
                eid, ts, "net_conn", pid, pid_base, agent_id,
                remote_addr=_extract_host(url),
                remote_port=_extract_port(url),
                protocol="TCP",
            ))

    return events


def load_scenario_events(scenario_path: str) -> List[Dict[str, Any]]:
    """加载场景 YAML 文件并生成事件字典列表"""
    with open(scenario_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    tool_calls = data.get("tool_calls", [])
    if not tool_calls:
        print("[agent_sim] ERROR: No tool_calls found in scenario", file=sys.stderr)
        return []

    scenario_meta = data.get("scenario", {})
    base_ts = scenario_meta.get("base_timestamp_ns", 1718092800000000000)
    scenario_id = scenario_meta.get("id", "da04")
    agent_id = scenario_meta.get("agent_id", "deep-agent-fintech-analyst")

    return tool_calls_to_events(tool_calls, base_ts, agent_id, scenario_id)


def load_jsonl_events(jsonl_path: str) -> List[Dict[str, Any]]:
    """
    加载录制的 JSONL 文件并返回事件字典列表。

    与 load_scenario_events 返回完全相同的格式，
    保证回放与 Agent 模拟测试使用相同的 FIFO 注入逻辑。
    """
    events: List[Dict[str, Any]] = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                # 标准化事件字典字段（兼容旧录制格式）
                _normalize_event_dict(event)
                events.append(event)
            except json.JSONDecodeError as e:
                print(f"[agent_sim] WARNING: 跳过无效 JSON 行: {e}", file=sys.stderr)
    return events


def _normalize_event_dict(event: Dict[str, Any]):
    """标准化事件字典，确保包含所有必要字段"""
    # 确保 event_type
    if "event_type" not in event:
        event["event_type"] = "exec"
    # 确保 agent_id
    if "agent_id" not in event:
        event["agent_id"] = "replay-agent"
    # 确保 agent_framework
    if "agent_framework" not in event:
        event["agent_framework"] = "replay"
    # 确保时间戳
    if "timestamp_ns" not in event:
        event["timestamp_ns"] = 1718092800000000000
    # 确保 PID
    if "pid" not in event:
        event["pid"] = 0
    if "ppid" not in event:
        event["ppid"] = 0
    # 确保可选字段
    for field in ("executable", "arguments", "file_path", "file_op",
                  "remote_addr", "remote_port", "protocol", "event_id"):
        if field not in event:
            event[field] = None


def emit_events(fifo_path: str, events: List[Dict[str, Any]], speed: float = 1.0):
    """
    将事件逐条以 JSON 行写入 FIFO，模拟实时 Agent 行为。

    Args:
        fifo_path: 命名管道路径
        events:    事件字典列表（RawEvent 兼容格式）
        speed:     播放速度倍率 (1.0 = 正常, 2.0 = 2倍速)
    """
    global _running

    # 打开 FIFO（阻塞直到 Monitor 端打开）
    print(f"[agent_sim] 等待 Monitor 连接 (FIFO: {fifo_path})...", file=sys.stderr)
    try:
        fifo = open(fifo_path, "w", encoding="utf-8")
    except OSError as e:
        print(f"[agent_sim] ERROR: 无法打开 FIFO: {e}", file=sys.stderr)
        return

    total = len(events)
    print(f"[agent_sim] Agent 已启动，共 {total} 个事件 (speed={speed}x)", file=sys.stderr)

    emitted = 0
    base_delay = 0.6  # 基础事件间隔（秒）

    for i, event in enumerate(events):
        if not _running:
            print(f"\n[agent_sim] 收到停止信号，已发送 {emitted}/{total} 个事件", file=sys.stderr)
            break

        # 写入事件 JSON（零 observer_sim 依赖）
        line = json.dumps(event, ensure_ascii=False)
        fifo.write(line + "\n")
        fifo.flush()
        emitted += 1

        # 日志输出
        desc = _short_desc(event)
        et = event.get("event_type", "?")
        print(f"[agent_sim] [{emitted:02d}/{total}] {et:10s} | {desc}", file=sys.stderr)

        # 延迟（模拟真实 Agent 操作间隔）
        if i < total - 1 and _running:
            delay = base_delay / speed
            if et == "net_conn":
                delay = 0.8 / speed
            time.sleep(delay)

    fifo.close()
    print(f"[agent_sim] Agent 模拟完成，共发送 {emitted} 个事件", file=sys.stderr)


def _short_desc(event: Dict[str, Any]) -> str:
    """事件简短描述（兼容 dict 格式）"""
    et = event.get("event_type", "?")
    if et == "exec":
        exe = event.get("executable") or ""
        args = " ".join(event.get("arguments") or [])
        return f"{exe} {args}".strip()[:60]
    elif et == "file_open":
        return f"{event.get('file_op') or 'open'} {event.get('file_path') or ''}"
    elif et == "net_conn":
        return f"{event.get('remote_addr') or ''}:{event.get('remote_port') or ''}"
    return et


def main():
    parser = argparse.ArgumentParser(description="独立 Agent 模拟进程")
    parser.add_argument("--fifo", default="/tmp/observer_monitoring_pipe",
                        help="命名管道路径 (default: /tmp/observer_monitoring_pipe)")
    parser.add_argument("--scenario", default=None,
                        help="场景 YAML 文件路径 (default: da04_production_demo.yaml)")
    parser.add_argument("--replay-file", default=None,
                        help="回放模式：指定录制的 .jsonl 文件路径")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="播放速度倍率 (default: 1.0)")
    args = parser.parse_args()

    # 注册信号处理
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # ── 回放模式：加载 JSONL 录制文件 ──
    if args.replay_file:
        if not os.path.isfile(args.replay_file):
            print(f"[agent_sim] ERROR: 回放文件不存在: {args.replay_file}", file=sys.stderr)
            sys.exit(1)
        print(f"[agent_sim] 回放模式: {args.replay_file}", file=sys.stderr)
        events = load_jsonl_events(args.replay_file)
        if not events:
            print("[agent_sim] ERROR: 回放文件无有效事件", file=sys.stderr)
            sys.exit(1)
    else:
        # ── 场景模式：加载 YAML 场景文件 ──
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if args.scenario:
            scenario_path = args.scenario
        else:
            scenario_path = os.path.join(
                base_dir, "scenarios", "deep_agent", "da04_production_demo.yaml")

        if not os.path.isfile(scenario_path):
            print(f"[agent_sim] ERROR: 场景文件不存在: {scenario_path}", file=sys.stderr)
            sys.exit(1)

        print(f"[agent_sim] 加载场景: {scenario_path}", file=sys.stderr)
        events = load_scenario_events(scenario_path)

        if not events:
            print("[agent_sim] ERROR: 场景无事件", file=sys.stderr)
            sys.exit(1)

    # 确保 FIFO 存在
    if not os.path.exists(args.fifo):
        print(f"[agent_sim] ERROR: FIFO 不存在: {args.fifo}", file=sys.stderr)
        print(f"[agent_sim] 请先启动 Monitor 守护进程创建管道", file=sys.stderr)
        sys.exit(1)

    emit_events(args.fifo, events, args.speed)


if __name__ == "__main__":
    main()
