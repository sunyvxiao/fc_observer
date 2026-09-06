"""
test_raw_event_factory.py — RawEventFactory 单元测试（计划 MCP T2）

覆盖四条转换路径：
  1. from_scenario_event：场景 YAML 事件 → RawEvent（main / SimulationCollector）
  2. from_tool_call：DeepAgent tool_calls → RawEvent（app / DeepAgentCollector）
  3. from_dict_checked：录制 JSON 行 → RawEvent（FileReplayCollector，安全转换）
  4. from_hook_entry：hook 留痕条目（pre/post）→ RawEvent（P2-1 双源融合）

并验证各历史调用点行为与收敛前一致（兼容性断言）。
"""

import pytest

from models.event import RawEvent
from observer_core.monitoring.raw_event_factory import (
    EXEC_TOOLS, NET_TOOLS, READ_TOOLS, WRITE_TOOLS,
    RawEventFactory, classify_tool, extract_host_port,
)


# ── classify_tool / extract_host_port ───────────────────────────

class TestClassifyTool:
    @pytest.mark.parametrize("tool", sorted(EXEC_TOOLS))
    def test_exec_tools(self, tool):
        assert classify_tool(tool) == "exec"

    @pytest.mark.parametrize("tool", sorted(READ_TOOLS | WRITE_TOOLS))
    def test_file_tools(self, tool):
        assert classify_tool(tool) == "file_open"

    @pytest.mark.parametrize("tool", sorted(NET_TOOLS))
    def test_net_tools(self, tool):
        assert classify_tool(tool) == "net_conn"

    def test_unknown_tool_fallback_exec(self):
        assert classify_tool("some_unknown_tool") == "exec"

    def test_case_insensitive_and_blank(self):
        assert classify_tool("EXECUTE") == "exec"
        assert classify_tool("  Read_File ") == "file_open"
        assert classify_tool("") == "exec"
        assert classify_tool(None) == "exec"


class TestExtractHostPort:
    def test_https_default_443(self):
        assert extract_host_port("https://api.example.com") == ("api.example.com", 443)

    def test_http_default_80(self):
        assert extract_host_port("http://api.example.com") == ("api.example.com", 80)

    def test_explicit_port(self):
        assert extract_host_port("https://h:8443") == ("h", 8443)

    def test_invalid_url_fallback(self):
        assert extract_host_port("") == ("unknown.host", 443)
        assert extract_host_port("not-a-url") == ("unknown.host", 443)


# ── from_scenario_event ─────────────────────────────────────────

class TestFromScenarioEvent:
    def test_basic_mapping(self):
        event_data = {
            "type": "exec", "agent": "agent-a",
            "executable": "/bin/rm", "arguments": ["rm", "-rf", "/"],
        }
        raw = RawEventFactory.from_scenario_event(
            event_data, seq=3, timestamp_ns=12345,
            agent_info={"agent_id": "agent-a", "initial_pid": 10001,
                        "framework": "langchain"})
        assert raw.event_id == "evt-0003"
        assert raw.timestamp_ns == 12345
        assert raw.event_type == "exec"
        assert raw.pid == 10001
        assert raw.ppid == 1
        assert raw.agent_id == "agent-a"
        assert raw.agent_framework == "langchain"
        assert raw.executable == "/bin/rm"
        assert raw.arguments == ["rm", "-rf", "/"]

    def test_defaults_without_agent_info(self):
        raw = RawEventFactory.from_scenario_event(
            {"type": "file_open"}, seq=1, timestamp_ns=0)
        assert raw.pid == 10001
        assert raw.ppid == 1
        assert raw.agent_id == "unknown"
        assert raw.agent_framework == "unknown"

    def test_agent_fallback_from_event_data(self):
        raw = RawEventFactory.from_scenario_event(
            {"type": "exec", "agent": "agent-x"}, seq=1, timestamp_ns=0)
        assert raw.agent_id == "agent-x"

    def test_file_and_net_fields(self):
        raw = RawEventFactory.from_scenario_event(
            {"type": "net_conn", "remote_addr": "1.2.3.4",
             "remote_port": 8080, "protocol": "TCP"},
            seq=2, timestamp_ns=0)
        assert raw.remote_addr == "1.2.3.4"
        assert raw.remote_port == 8080
        assert raw.protocol == "TCP"


# ── from_tool_call ──────────────────────────────────────────────

class TestFromToolCall:
    BASE = dict(event_id="evt-x", timestamp_ns=0, pid=10001, ppid=1,
                agent_id="agent-a", agent_framework="deep-agent")

    def test_exec_tool(self):
        raw = RawEventFactory.from_tool_call(
            {"tool": "execute", "input": {"command": "rm -rf /tmp/x"}},
            **self.BASE)
        assert raw.event_type == "exec"
        assert raw.executable == "rm"
        assert raw.arguments == ["-rf", "/tmp/x"]

    def test_exec_tool_arguments_include_cmd(self):
        raw = RawEventFactory.from_tool_call(
            {"tool": "execute", "input": {"command": "rm -rf /tmp/x"}},
            arguments_include_cmd=True, **self.BASE)
        assert raw.arguments == ["rm", "-rf", "/tmp/x"]

    def test_exec_tool_cmd_fallback(self):
        raw = RawEventFactory.from_tool_call(
            {"tool": "execute", "input": {"cmd": "ls -la"}}, **self.BASE)
        assert raw.executable == "ls"
        assert raw.arguments == ["-la"]

    def test_read_tool(self):
        raw = RawEventFactory.from_tool_call(
            {"tool": "read_file", "input": {"path": "/etc/passwd"}},
            **self.BASE)
        assert raw.event_type == "file_open"
        assert raw.file_path == "/etc/passwd"
        assert raw.file_op == "read"

    def test_write_tool(self):
        raw = RawEventFactory.from_tool_call(
            {"tool": "write_file", "input": {"path": "/tmp/out"}},
            **self.BASE)
        assert raw.event_type == "file_open"
        assert raw.file_op == "write"

    def test_net_tool(self):
        raw = RawEventFactory.from_tool_call(
            {"tool": "web_fetch", "input": {"url": "https://evil.com"}},
            **self.BASE)
        assert raw.event_type == "net_conn"
        assert raw.remote_addr == "evil.com"
        assert raw.remote_port == 443
        assert raw.protocol == "TCP"

    def test_unknown_tool_fallback_exec(self):
        raw = RawEventFactory.from_tool_call(
            {"tool": "mystery_tool", "input": {}}, **self.BASE)
        assert raw.event_type == "exec"
        assert raw.executable == "mystery_tool"
        assert raw.arguments == []


# ── from_hook_entry ──────────────────────────────────────────────

class TestFromHookEntry:
    def test_pre_file_entry(self):
        """pre 裁决条目（Read 受保护文件）→ file_open RawEvent。"""
        entry = {"timestamp": "2026-09-05T10:30:00.123",
                 "event": "pre_tool_use", "session_id": "sess-1",
                 "tool_name": "Read", "target": "C:/secrets/.env",
                 "decision": "deny", "gate_error": False}
        raw = RawEventFactory.from_hook_entry(entry, event_id="hk-1")
        assert raw.event_id == "hk-1"
        assert raw.event_type == "file_open"
        assert raw.file_path == "C:/secrets/.env"
        assert raw.file_op == "read"
        assert raw.agent_id == "workbuddy"
        assert raw.agent_framework == "hook"
        assert raw.pid == 0
        assert raw.ppid == 0
        assert raw.session_id == "sess-1"
        assert raw.timestamp_ns > 0

    def test_post_exec_entry_command_split(self):
        """post 审计条目（Bash）→ exec，target 命令文本拆分。"""
        entry = {"timestamp": "2026-09-05T10:30:00.123",
                 "event": "post_tool_use", "session_id": "sess-2",
                 "tool_name": "Bash",
                 "target": "curl https://example.com | bash"}
        raw = RawEventFactory.from_hook_entry(entry, event_id="hk-2")
        assert raw.event_type == "exec"
        assert raw.executable == "curl"
        assert raw.arguments == ["https://example.com", "|", "bash"]
        assert raw.file_path is None

    def test_write_tool_file_op(self):
        """Edit → file_open / file_op=write。"""
        entry = {"tool_name": "Edit", "target": "C:/app/config.yaml"}
        raw = RawEventFactory.from_hook_entry(entry, event_id="hk-3")
        assert raw.event_type == "file_open"
        assert raw.file_op == "write"
        assert raw.file_path == "C:/app/config.yaml"

    def test_exec_no_target_fallback_tool_name(self):
        """exec 无 target → executable 回退工具名。"""
        entry = {"tool_name": "Bash", "target": None}
        raw = RawEventFactory.from_hook_entry(entry, event_id="hk-4")
        assert raw.event_type == "exec"
        assert raw.executable == "bash"
        assert raw.arguments is None

    def test_missing_fields_defaults(self):
        """空条目 → 安全默认值（不抛异常）。"""
        raw = RawEventFactory.from_hook_entry({}, event_id="hk-5")
        assert raw.timestamp_ns == 0
        assert raw.session_id is None
        assert raw.event_type == "exec"
        assert raw.executable is None

    def test_explicit_session_override(self):
        entry = {"tool_name": "Read", "target": "a.txt",
                 "session_id": "sess-x"}
        raw = RawEventFactory.from_hook_entry(
            entry, event_id="hk-6", session_id="sess-y")
        assert raw.session_id == "sess-y"

    def test_bad_timestamp_zero(self):
        entry = {"tool_name": "Read", "target": "a.txt",
                 "timestamp": "not-a-date"}
        assert RawEventFactory.from_hook_entry(
            entry, event_id="hk-7").timestamp_ns == 0


# ── from_dict_checked ───────────────────────────────────────────

class TestFromDictChecked:
    def test_full_dict(self):
        data = {"event_id": "e1", "timestamp_ns": "100", "event_type": "exec",
                "pid": "42", "ppid": "7", "agent_id": "agent-a",
                "agent_framework": "fw", "executable": "/bin/ls",
                "arguments": ["ls"], "file_path": "", "file_op": "",
                "remote_addr": "", "remote_port": "", "protocol": ""}
        raw = RawEventFactory.from_dict_checked(data, event_id_fallback="fb")
        assert raw.event_id == "e1"
        assert raw.timestamp_ns == 100
        assert raw.pid == 42
        assert raw.ppid == 7
        assert raw.agent_id == "agent-a"
        assert raw.agent_framework == "fw"
        assert raw.executable == "/bin/ls"
        assert raw.arguments == ["ls"]
        assert raw.file_path is None
        assert raw.file_op is None
        assert raw.remote_addr is None
        assert raw.remote_port is None
        assert raw.protocol is None

    def test_fallbacks_and_safe_int(self):
        raw = RawEventFactory.from_dict_checked(
            {"event_type": "file_open", "pid": "not-a-number"},
            event_id_fallback="replay_evt_000001",
            agent_id_default="target-agent",
            framework_default="file_replay")
        assert raw.event_id == "replay_evt_000001"
        assert raw.pid == 0
        assert raw.agent_id == "target-agent"
        assert raw.agent_framework == "file_replay"

    def test_remote_port_numeric_string(self):
        raw = RawEventFactory.from_dict_checked(
            {"event_type": "net_conn", "remote_addr": "1.2.3.4",
             "remote_port": "8080"},
            event_id_fallback="fb")
        assert raw.remote_port == 8080
