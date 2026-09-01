# -*- coding: utf-8 -*-
"""
test_qoder_hook_reporter.py — Qoder CN Hook reporter 测试（P1）

覆盖（验收标准: 管道模拟 Hook JSON `echo '...' | reporter`）:
1. build_report_payload 单元: PostToolUse / PostToolUseFailure /
   PreToolUse / 非工具事件 / 非 dict / result 摘要提取与截断
2. subprocess 管道 e2e: echo Hook JSON | reporter → live uvicorn
   /api/hook-report → broker 收到申报（字段保真）
3. 失败降级: 端点不可达 → exit 0（静默放行，不影响 Agent）
4. 畸形 stdin: 空输入 / 非 JSON → exit 0
5. 命令行覆盖: --agent-id / --url / 环境变量
"""

import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time

import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
REPORTER = os.path.join(PROJECT_ROOT, "scripts", "qoder_hook_reporter.py")
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def _load_reporter_module():
    """以文件路径加载 reporter（纯标准库，可安全 import）"""
    spec = importlib.util.spec_from_file_location(
        "qoder_hook_reporter", REPORTER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


reporter_mod = _load_reporter_module()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(host, port, timeout=20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


@pytest.fixture(scope="module")
def live_server():
    """启动带 hook_ingest 的申报 Server，返回 (port, broker)。"""
    pytest.importorskip("mcp")
    from mcp_bridge.server import McpReportBroker, run_server

    port = _free_port()
    broker = McpReportBroker()
    threading.Thread(
        target=run_server,
        kwargs={"host": "127.0.0.1", "port": port, "broker": broker,
                "hook_ingest": {"enabled": True,
                                "path": "/api/hook-report",
                                "agent_id_default": "qoder"}},
        daemon=True).start()
    assert _wait_port("127.0.0.1", port), "server 未在超时内就绪"
    return port, broker


def _run_reporter(stdin_text, *extra_args, env=None):
    """管道执行: echo stdin_text | reporter（返回 CompletedProcess）"""
    cmd = [sys.executable, REPORTER, *extra_args]
    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)
    return subprocess.run(cmd, input=stdin_text, capture_output=True,
                          text=True, timeout=30, env=merged_env)


# ── 1. build_report_payload 单元 ────────────────────────────────────

class TestBuildPayload:

    def test_post_tool_use(self):
        payload = reporter_mod.build_report_payload({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "cwd": "/home/u/proj",
            "tool_name": "run_in_terminal",
            "tool_input": {"command": "ls -la"},
        })
        assert payload == {
            "agent_id": "qoder",
            "tool_name": "run_in_terminal",
            "tool_args": {"command": "ls -la"},
            "session_id": "sess-1",
            "action_type": "post",
            "result": None,
        }

    def test_pre_tool_use_action_type(self):
        payload = reporter_mod.build_report_payload({
            "hook_event_name": "PreToolUse",
            "tool_name": "create_file",
            "tool_input": {"file_path": "/tmp/x.py"},
        })
        assert payload["action_type"] == "pre"

    def test_post_tool_use_failure_extracts_error(self):
        payload = reporter_mod.build_report_payload({
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "run_in_terminal",
            "tool_input": {"command": "false"},
            "tool_response": {"error": "exit code 1"},
        })
        assert payload["action_type"] == "post"
        assert payload["result"] == "exit code 1"

    def test_failure_without_response(self):
        payload = reporter_mod.build_report_payload({
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "run_in_terminal",
            "tool_input": {},
        })
        assert payload["result"] == "tool_use_failed"

    def test_non_tool_events_return_none(self):
        for event_name in ("UserPromptSubmit", "Stop", ""):
            payload = reporter_mod.build_report_payload({
                "hook_event_name": event_name,
                "session_id": "s",
            })
            assert payload is None

    def test_invalid_inputs_return_none(self):
        assert reporter_mod.build_report_payload(None) is None
        assert reporter_mod.build_report_payload("not-dict") is None
        assert reporter_mod.build_report_payload({"tool_name": ""}) is None

    def test_non_dict_tool_input_normalized(self):
        payload = reporter_mod.build_report_payload({
            "hook_event_name": "PostToolUse",
            "tool_name": "list_dir",
            "tool_input": "/tmp",          # 非 dict → 归一为空对象
        })
        assert payload["tool_args"] == {}

    def test_agent_id_override(self):
        payload = reporter_mod.build_report_payload(
            {"hook_event_name": "PostToolUse", "tool_name": "read_file"},
            agent_id="qoder-cli")
        assert payload["agent_id"] == "qoder-cli"

    def test_long_session_id_truncated(self):
        payload = reporter_mod.build_report_payload({
            "hook_event_name": "PostToolUse",
            "tool_name": "read_file",
            "session_id": "x" * 200,
        })
        assert len(payload["session_id"]) <= 128 + len("...[truncated]")


# ── 2. subprocess 管道 e2e（echo | reporter → live 端点）───────────

class TestPipeE2E:

    def test_pipe_report_enters_broker(self, live_server):
        port, broker = live_server
        hook_json = json.dumps({
            "hook_event_name": "PostToolUse",
            "session_id": "pipe-e2e",
            "tool_name": "run_in_terminal",
            "tool_input": {"command": "git status"},
        })
        result = _run_reporter(
            hook_json, "--url", f"http://127.0.0.1:{port}/api/hook-report")
        assert result.returncode == 0

        record = broker.consume_nowait()
        assert record is not None, f"broker 未收到申报: {result.stderr}"
        payload = record["payload"]
        assert payload["agent_id"] == "qoder"
        assert payload["tool_name"] == "run_in_terminal"
        assert payload["tool_args"] == {"command": "git status"}
        assert payload["session_id"] == "pipe-e2e"
        assert payload["action_type"] == "post"

    def test_pipe_agent_id_flag(self, live_server):
        port, broker = live_server
        hook_json = json.dumps({
            "hook_event_name": "PostToolUse",
            "tool_name": "read_file",
            "tool_input": {"file_path": "/tmp/t.py"},
        })
        result = _run_reporter(hook_json,
                               "--url", f"http://127.0.0.1:{port}/api/hook-report",
                               "--agent-id", "qoder-agent2")
        assert result.returncode == 0
        record = broker.consume_nowait()
        assert record["payload"]["agent_id"] == "qoder-agent2"

    def test_pipe_env_var_url(self, live_server):
        port, broker = live_server
        hook_json = json.dumps({
            "hook_event_name": "PostToolUse",
            "tool_name": "list_dir",
            "tool_input": {"path": "/tmp"},
        })
        result = _run_reporter(hook_json, env={
            "OBSERVER_HOOK_REPORT_URL":
                f"http://127.0.0.1:{port}/api/hook-report"})
        assert result.returncode == 0
        record = broker.consume_nowait()
        assert record is not None
        assert record["payload"]["tool_name"] == "list_dir"

    def test_pipe_rejected_report_still_exit_zero(self, live_server):
        port, _ = live_server
        # 超大 tool_args 触发服务端 report_too_large（HTTP 413 结构化拒绝）；
        # reporter 必须静默放行（exit 0），不影响 Agent。
        hook_json = json.dumps({
            "hook_event_name": "PostToolUse",
            "tool_name": "read_file",
            "tool_input": {"blob": "x" * (70 * 1024)},
        })
        result = _run_reporter(hook_json,
                               "--url", f"http://127.0.0.1:{port}/api/hook-report")
        assert result.returncode == 0      # 被拒也静默放行
        assert "被拒" in result.stderr or "rejected" in result.stderr


# ── 3. 失败降级 ─────────────────────────────────────────────────────

class TestFailOpen:

    def test_unreachable_endpoint_exit_zero(self):
        port = _free_port()   # 无服务监听的端口
        hook_json = json.dumps({
            "hook_event_name": "PostToolUse",
            "tool_name": "read_file",
            "tool_input": {},
        })
        result = _run_reporter(
            hook_json, "--url", f"http://127.0.0.1:{port}/api/hook-report",
            "--timeout", "1")
        assert result.returncode == 0      # 静默放行
        assert "静默放行" in result.stderr

    def test_empty_stdin_exit_zero(self):
        result = _run_reporter("")
        assert result.returncode == 0

    def test_non_json_stdin_exit_zero(self):
        result = _run_reporter("this is not json")
        assert result.returncode == 0
        assert "非 JSON" in result.stderr

    def test_non_tool_event_no_http_exit_zero(self):
        # Stop 事件无 tool_name → 不上报、不报错
        result = _run_reporter(json.dumps(
            {"hook_event_name": "Stop", "session_id": "s"}))
        assert result.returncode == 0
        assert result.stderr.strip() == ""

    def test_log_file_instead_of_stderr(self, tmp_path):
        port = _free_port()
        log_file = tmp_path / "reporter.log"
        result = _run_reporter(
            json.dumps({"hook_event_name": "PostToolUse",
                        "tool_name": "read_file", "tool_input": {}}),
            "--url", f"http://127.0.0.1:{port}/api/hook-report",
            "--timeout", "1", "--log-file", str(log_file))
        assert result.returncode == 0
        assert result.stderr.strip() == ""          # stderr 干净
        content = log_file.read_text(encoding="utf-8")
        assert "静默放行" in content


# ── 4. qoder.yaml Hook 配置注册验证 ─────────────────────────────────

class TestQoderHookConfig:

    def test_registry_loads_qoder_framework(self):
        from adapter.hook_registry import HookRegistry

        registry = HookRegistry()
        assert "qoder" in registry.list_frameworks()

    def test_qoder_tool_mapping(self):
        from adapter.hook_registry import HookRegistry

        cfg = HookRegistry().get_config("qoder")
        assert cfg is not None
        # 文档映射表: 原生工具名 → 事件类型
        assert cfg.get_event_type("run_in_terminal") == "exec"
        assert cfg.get_event_type("read_file") == "file_open"
        assert cfg.get_event_type("list_dir") == "file_open"
        assert cfg.get_event_type("grep_code") == "file_open"
        assert cfg.get_event_type("search_file") == "file_open"
        assert cfg.get_event_type("create_file") == "file_open"
        assert cfg.get_event_type("search_replace") == "file_open"
        assert cfg.get_event_type("delete_file") == "file_open"
        assert cfg.get_event_type("web_search") == "net_conn"
        assert cfg.get_event_type("web_fetch") == "net_conn"
        assert cfg.get_event_type("task") == "exec"
        # 兼容名同样命中（避免回退到 default 导致语义漂移）
        assert cfg.map_tool_to_event("bash") is not None
        assert cfg.map_tool_to_event("edit") is not None
        # 读写方向区分（SemanticGuard.is_read_tool 依赖）
        assert '"read"' in cfg.get_param_rules("read_file").get("file_op", "")
        assert '"write"' in cfg.get_param_rules("create_file").get("file_op", "")

    def test_lingma_settings_template_valid(self):
        """.lingma/settings.json 模板合法且指向 reporter 脚本"""
        settings_path = os.path.join(PROJECT_ROOT, ".lingma", "settings.json")
        assert os.path.isfile(settings_path)
        with open(settings_path, encoding="utf-8") as f:
            data = json.load(f)
        hooks = data["hooks"]
        for event in ("PostToolUse", "PostToolUseFailure"):
            entries = hooks[event]
            cmds = [h["command"] for e in entries for h in e["hooks"]]
            assert any("qoder_hook_reporter.py" in c for c in cmds)
        assert os.path.isfile(REPORTER)  # command 指向的脚本存在
