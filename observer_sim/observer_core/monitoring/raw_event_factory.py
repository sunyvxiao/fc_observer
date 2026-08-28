"""
RawEventFactory — dict 结构 → RawEvent 的唯一转换点（计划 MCP T2 / J-C）。

统一收敛原先分散在多处的手工映射，消除映射漂移：
  - main.create_raw_event()                  场景 YAML 事件 → RawEvent
  - collector/simulation_collector.start()   场景 YAML 事件（同构复制）
  - app._tool_calls_to_events()              DeepAgent tool_calls → RawEvent
  - collector/deep_agent_collector           工具名 → 事件类型分类映射
  - collector/file_replay_collector          录制 JSON 行 → RawEvent（安全转换）

后续 mcp_report_collector（MCP 申报数据）亦经本工厂构造 RawEvent，
保证申报数据与既有数据源走同一条转换路径。

工具名分类表为单一事实来源（合并自 app.py 与 deep_agent_collector
的历史集合，后者为超集；未知工具归 exec，与历史 fallback 语义一致）。
"""

import re
from typing import Optional, Tuple

from models.event import RawEvent

# ── 工具名 → 事件类型分类表（单一事实来源）───────────────────────
EXEC_TOOLS = {
    "execute", "execute_command", "run_command", "shell", "bash",
    "terminal", "command",
}
READ_TOOLS = {
    "read_file", "read", "cat", "list_files", "grep", "glob",
    "ls", "find", "head", "tail",
}
WRITE_TOOLS = {
    "write_file", "write", "edit_file", "edit", "patch",
    "append", "create_file",
}
NET_TOOLS = {
    "web_fetch", "fetch", "web_search", "browse", "curl",
    "http_request", "download",
}


def classify_tool(tool_name: str) -> str:
    """工具名 → 事件类型（exec / file_open / net_conn）。

    未知工具归 exec（与历史 fallback 语义一致）。
    """
    tool = (tool_name or "").lower().strip()
    if tool in READ_TOOLS or tool in WRITE_TOOLS:
        return "file_open"
    if tool in NET_TOOLS:
        return "net_conn"
    return "exec"  # EXEC_TOOLS 与未知工具均归 exec


def extract_host_port(url: str, default_host: str = "unknown.host",
                      default_port: int = 443) -> Tuple[str, int]:
    """URL → (host, port)。无端口时按协议回退 443/80。"""
    m = re.match(r"(\w+)://([^:/]+)(?::(\d+))?", url or "")
    if m:
        host = m.group(2)
        port = int(m.group(3)) if m.group(3) else (
            443 if url.startswith("https") else 80)
        return host, port
    return default_host, default_port


class RawEventFactory:
    """dict / 工具调用结构 → RawEvent 的统一工厂。"""

    @staticmethod
    def from_scenario_event(event_data: dict, *, seq: int, timestamp_ns: int,
                            agent_info: Optional[dict] = None) -> RawEvent:
        """场景 YAML 事件 → RawEvent（main / SimulationCollector 共用）。

        与历史 main.create_raw_event() / SimulationCollector.start()
        的字段语义完全一致。
        """
        agent_info = agent_info or {}
        agent_id = event_data.get("agent", agent_info.get("agent_id", "unknown"))
        return RawEvent(
            event_id=f"evt-{seq:04d}",
            timestamp_ns=timestamp_ns,
            event_type=event_data.get("type", "exec"),
            pid=agent_info.get("initial_pid", 10001),
            ppid=1,
            agent_id=agent_id,
            agent_framework=agent_info.get("framework", "unknown"),
            executable=event_data.get("executable"),
            arguments=event_data.get("arguments"),
            file_path=event_data.get("file_path"),
            file_op=event_data.get("file_op"),
            remote_addr=event_data.get("remote_addr"),
            remote_port=event_data.get("remote_port"),
            protocol=event_data.get("protocol"),
        )

    @staticmethod
    def from_tool_call(tool_call: dict, *, event_id: str, timestamp_ns: int,
                       pid: int, ppid: int, agent_id: str,
                       agent_framework: str,
                       arguments_include_cmd: bool = False,
                       session_id: Optional[str] = None) -> RawEvent:
        """DeepAgent / MCP 申报 tool_calls → RawEvent（统一转换点）。

        arguments_include_cmd: True 时 exec 事件 arguments 保留命令名
        （DeepAgentCollector 历史行为）；默认 False（app.py 历史行为，
        arguments 不含命令名，命令名在 executable）。
        session_id: MCP 申报会话 ID（黑盒 Agent 会话维度；其他数据源为 None）。
        """
        tool_name = str(tool_call.get("tool", "") or "").lower().strip()
        tool_input = tool_call.get("input", {}) or {}
        event_type = classify_tool(tool_name)

        executable = None
        arguments = None
        file_path = None
        file_op = None
        remote_addr = None
        remote_port = None
        protocol = None

        if event_type == "exec":
            cmd = tool_input.get("command", tool_input.get("cmd", tool_name))
            parts = cmd.split() if isinstance(cmd, str) else [str(cmd)]
            executable = parts[0] if parts else cmd
            arguments = (
                parts if arguments_include_cmd
                else (parts[1:] if len(parts) > 1 else [])
            )
        elif event_type == "file_open":
            file_path = (tool_input.get("path")
                         or tool_input.get("file_path")
                         or tool_input.get("file")
                         or "")
            file_op = "read" if tool_name in READ_TOOLS else "write"
        elif event_type == "net_conn":
            url = tool_input.get("url") or tool_input.get("query") or ""
            remote_addr, remote_port = extract_host_port(url)
            protocol = "TCP"

        return RawEvent(
            event_id=event_id,
            timestamp_ns=timestamp_ns,
            event_type=event_type,
            pid=pid,
            ppid=ppid,
            agent_id=agent_id,
            agent_framework=agent_framework,
            session_id=session_id,
            executable=executable,
            arguments=arguments,
            file_path=file_path,
            file_op=file_op,
            remote_addr=remote_addr,
            remote_port=remote_port,
            protocol=protocol,
        )

    @staticmethod
    def from_dict_checked(data: dict, *, event_id_fallback: str,
                          agent_id_default: str = "",
                          framework_default: str = "file_replay") -> RawEvent:
        """录制 JSON 行 → RawEvent（FileReplayCollector 共用）。

        含安全整数转换（None / 空串 / 非数字回退默认值）与空值 None 化，
        与历史 FileReplayCollector._dict_to_raw_event() 语义一致。
        """
        def _safe_int(value, default=0):
            if value is None or value == "":
                return default
            try:
                return int(value)
            except (ValueError, TypeError):
                return default

        remote_port_raw = data.get("remote_port")
        remote_port = (_safe_int(remote_port_raw, None)
                       if remote_port_raw not in (None, "") else None)

        return RawEvent(
            event_id=data.get("event_id", event_id_fallback),
            timestamp_ns=_safe_int(data.get("timestamp_ns"), 0),
            event_type=data.get("event_type", "exec"),
            pid=_safe_int(data.get("pid"), 0),
            ppid=_safe_int(data.get("ppid"), 0),
            agent_id=data.get("agent_id", agent_id_default),
            agent_framework=data.get("agent_framework", framework_default),
            executable=data.get("executable") or None,
            arguments=data.get("arguments") or None,
            file_path=data.get("file_path") or None,
            file_op=data.get("file_op") or None,
            remote_addr=data.get("remote_addr") or None,
            remote_port=remote_port,
            protocol=data.get("protocol") or None,
        )
