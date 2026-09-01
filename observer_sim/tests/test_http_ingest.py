# -*- coding: utf-8 -*-
"""
test_http_ingest.py — Hooks 确定性申报摄入端点测试（Qoder CN P1）

覆盖:
1. POST /api/hook-report 正常申报 → accepted + broker 入队（字段保真）
2. 畸形申报: 非 JSON / 非对象 / 缺 tool_name / 非法 action_type → 结构化拒绝
3. 超限申报: 报文 >64KB / tool_args 键数超限 → 拒绝
4. 频率限制: 同 agent 超 60 次/秒 → rate_limited
5. 端到端: 摄入 → broker → McpReportCollector → RawEventFactory
   （run_in_terminal→exec / read_file→file_open，session_id 保真）
6. 与 MCP 申报同 broker 共队列（两通道合并消费）
7. live uvicorn 挂载验证: hook_ingest enabled → 同端口 /api/hook-report
   与 /sse 共存; disabled → 不挂载（行为不变）
"""

import json
import os
import socket
import sys
import time

import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


# ── 助手 ────────────────────────────────────────────────────────────

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


@pytest.fixture
def stack():
    """broker + validator + limiter + Starlette 应用（已挂载摄入路由）"""
    pytest.importorskip("starlette")
    from mcp_bridge.server import McpReportBroker
    from mcp_bridge.validation import default_validator, default_rate_limiter
    from mcp_bridge.http_ingest import build_hook_report_route
    from starlette.applications import Starlette

    broker = McpReportBroker()
    validator = default_validator()
    limiter = default_rate_limiter()
    route = build_hook_report_route("/api/hook-report", broker, validator,
                                    limiter, agent_id_default="qoder")
    app = Starlette(routes=[route])
    return {"broker": broker, "validator": validator, "limiter": limiter,
            "app": app}


@pytest.fixture
def client(stack):
    from starlette.testclient import TestClient
    return TestClient(stack["app"])


def _post(client, body, raw=False):
    if raw:
        return client.post("/api/hook-report", content=body,
                           headers={"Content-Type": "application/json"})
    return client.post("/api/hook-report", json=body)


# ── 1. 正常申报 ─────────────────────────────────────────────────────

class TestHookReportAccepted:

    def test_normal_report_accepted_and_enqueued(self, client, stack):
        resp = _post(client, {
            "tool_name": "run_in_terminal",
            "tool_args": {"command": "ls -la"},
            "session_id": "sess-001",
            "action_type": "post",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "accepted"
        assert "event_id" in data and "received_at_ms" in data

        record = stack["broker"].consume_nowait()
        assert record is not None
        assert record["type"] == "report_tool_call"
        payload = record["payload"]
        assert payload["agent_id"] == "qoder"        # 默认 agent_id
        assert payload["tool_name"] == "run_in_terminal"
        assert payload["tool_args"] == {"command": "ls -la"}
        assert payload["session_id"] == "sess-001"
        assert payload["action_type"] == "post"

    def test_explicit_agent_id_preserved(self, client, stack):
        resp = _post(client, {"agent_id": "qoder-cli",
                              "tool_name": "read_file"})
        assert resp.status_code == 200
        record = stack["broker"].consume_nowait()
        assert record["payload"]["agent_id"] == "qoder-cli"

    def test_timestamp_ms_passthrough(self, client, stack):
        resp = _post(client, {"tool_name": "read_file",
                              "timestamp_ms": 1700000000000})
        assert resp.status_code == 200
        record = stack["broker"].consume_nowait()
        assert record["payload"]["timestamp_ms"] == 1700000000000


# ── 2. 畸形申报 ─────────────────────────────────────────────────────

class TestHookReportRejected:

    def test_invalid_json_rejected(self, client):
        resp = _post(client, b"{not-json", raw=True)
        assert resp.status_code == 400
        assert resp.json()["reason"] == "invalid_json"

    def test_non_object_rejected(self, client):
        resp = _post(client, b"[1, 2, 3]", raw=True)
        assert resp.status_code == 400
        assert "invalid_report" in resp.json()["reason"]

    def test_missing_tool_name_rejected(self, client):
        resp = _post(client, {"session_id": "s1"})
        assert resp.status_code == 400
        assert "tool_name" in resp.json()["reason"]

    def test_invalid_action_type_rejected(self, client):
        resp = _post(client, {"tool_name": "read_file",
                              "action_type": "during"})
        assert resp.status_code == 400
        assert "action_type" in resp.json()["reason"]

    def test_oversize_report_rejected(self, client):
        # tool_args 序列化 >64KB → report_too_large
        big = {"k": "x" * (70 * 1024)}
        resp = _post(client, {"tool_name": "read_file", "tool_args": big})
        assert resp.status_code in (400, 413)
        assert resp.json()["status"] == "rejected"

    def test_too_many_tool_args_keys_rejected(self, client):
        args = {f"k{i}": i for i in range(150)}   # >100 键
        resp = _post(client, {"tool_name": "read_file", "tool_args": args})
        assert resp.status_code == 400
        assert "tool_args" in resp.json()["reason"]

    def test_rejected_report_not_enqueued(self, client, stack):
        _post(client, {"session_id": "no-tool"})          # 被拒
        assert stack["broker"].consume_nowait() is None


# ── 3. 频率限制 ─────────────────────────────────────────────────────

class TestRateLimit:

    def test_rate_limited_after_window(self, client):
        # 默认 60 次/秒（同 agent）→ 第 61 次被拒
        statuses = []
        for i in range(62):
            resp = _post(client, {"tool_name": "read_file",
                                  "session_id": f"s{i}"})
            statuses.append(resp.json().get("status"))
        assert statuses.count("accepted") == 60
        assert "rejected" in statuses
        # 拒绝原因之一为 rate_limited
        resp = _post(client, {"tool_name": "read_file"})
        assert resp.json().get("reason") == "rate_limited"
        assert resp.status_code == 429


# ── 4. 端到端: 摄入 → collector → RawEventFactory ──────────────────

class TestIngestToPipeline:

    def test_records_become_raw_events(self, client, stack):
        from collector.mcp_report_collector import McpReportCollector

        # Qoder CN 工具调用序列（读 / 写 / 执行）
        reports = [
            {"tool_name": "read_file",
             "tool_args": {"file_path": "/tmp/a.py"},
             "session_id": "sess-e2e"},
            {"tool_name": "create_file",
             "tool_args": {"file_path": "/tmp/b.py",
                           "file_content": "print(1)"},
             "session_id": "sess-e2e"},
            {"tool_name": "run_in_terminal",
             "tool_args": {"command": "python /tmp/b.py"},
             "session_id": "sess-e2e"},
        ]
        for r in reports:
            assert _post(client, r).json()["status"] == "accepted"

        collector = McpReportCollector(
            {"mcp_report": {"framework": "qoder",
                            "target_agent_id": "qoder",
                            "poll_timeout_s": 0.05}},
            broker=stack["broker"])
        assert collector.attach(agent_id="qoder")

        events = []
        gen = collector.start()
        for _ in range(3):
            events.append(next(gen))
        collector.detach()
        # 排空生成器（_stop_requested 已置位，轮询退出）
        for _ in gen:
            pass

        assert len(events) == 3
        # read_file → file_open read
        assert events[0].event_type == "file_open"
        assert events[0].file_path == "/tmp/a.py"
        assert events[0].file_op == "read"
        # create_file → file_open write
        assert events[1].event_type == "file_open"
        assert events[1].file_op == "write"
        # run_in_terminal → exec（命令拆分）
        assert events[2].event_type == "exec"
        assert events[2].executable == "python"
        # 公共字段保真
        for e in events:
            assert e.agent_id == "qoder"
            assert e.session_id == "sess-e2e"
            assert e.agent_framework == "mcp_report"
        assert collector.tool_call_count == 3
        assert collector.skipped_count == 0

    def test_mcp_and_hook_ingest_share_broker(self, client, stack):
        """MCP 申报记录与 Hook 摄入记录进入同一队列（顺序合并消费）。"""
        from mcp_bridge.schemas import TOOL_REPORT_TOOL_CALL

        # Hook 摄入一条
        _post(client, {"tool_name": "read_file", "session_id": "hook"})
        # 模拟 MCP 通道入队一条（与 create_server handler 相同记录结构）
        stack["broker"].publish({
            "type": TOOL_REPORT_TOOL_CALL,
            "payload": {"agent_id": "qoder", "tool_name": "web_fetch",
                        "tool_args": {"url": "https://example.com"},
                        "session_id": "mcp",
                        "timestamp_ms": int(time.time() * 1000),
                        "action_type": "post", "result": None},
        })
        r1 = stack["broker"].consume_nowait()
        r2 = stack["broker"].consume_nowait()
        assert {r1["payload"]["tool_name"],
                r2["payload"]["tool_name"]} == {"read_file", "web_fetch"}


# ── 5. live uvicorn: 同端口挂载 + 关闭时不挂载 ─────────────────────

class TestLiveMount:

    def _start_server(self, hook_ingest):
        """后台线程启动 run_server，返回 (thread, port, broker)。"""
        import threading
        from mcp_bridge.server import McpReportBroker, run_server

        port = _free_port()
        broker = McpReportBroker()
        t = threading.Thread(
            target=run_server,
            kwargs={"host": "127.0.0.1", "port": port, "broker": broker,
                    "hook_ingest": hook_ingest},
            daemon=True)
        t.start()
        assert _wait_port("127.0.0.1", port), "server 未在超时内就绪"
        return t, port, broker

    def test_hook_ingest_enabled_same_port(self):
        pytest.importorskip("mcp")
        import urllib.request
        import urllib.error

        _, port, broker = self._start_server(
            {"enabled": True, "path": "/api/hook-report",
             "agent_id_default": "qoder"})

        # POST 申报（urllib 纯标准库，与 reporter 同路径）
        body = json.dumps({"tool_name": "run_in_terminal",
                           "tool_args": {"command": "echo hi"},
                           "session_id": "live-1"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/hook-report", data=body,
            method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        assert data["status"] == "accepted"

        record = broker.consume_nowait()
        assert record["payload"]["tool_name"] == "run_in_terminal"
        assert record["payload"]["session_id"] == "live-1"

        # 同端口 /sse 仍可用（GET 建连；Host 带端口以通过 DNS rebinding 防护）
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(f"GET /sse HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                      f"Accept: text/event-stream\r\n\r\n".encode())
            head = s.recv(256).decode(errors="ignore")
        assert "200" in head.split("\r\n", 1)[0]

    def test_hook_ingest_disabled_route_absent(self):
        pytest.importorskip("mcp")
        import urllib.request
        import urllib.error

        _, port, _ = self._start_server({"enabled": False})

        body = json.dumps({"tool_name": "read_file"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/hook-report", data=body,
            method="POST", headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
        assert status == 404   # 未挂载 → 路由不存在

    def test_mount_idempotent(self, stack):
        from mcp_bridge.http_ingest import mount_hook_report_route

        assert mount_hook_report_route(
            stack["app"], path="/api/hook-report",
            broker=stack["broker"], validator=stack["validator"],
            rate_limiter=stack["limiter"]) is False  # fixture 已挂载同名路由
