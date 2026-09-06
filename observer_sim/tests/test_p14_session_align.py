# -*- coding: utf-8 -*-
"""
test_p14_session_align.py — P1-4 hook 通知通道接入 + 方案 A session_id 对齐

覆盖:
1. McpReportBroker.note_host_session / resolve_session_id 各分支
   （UUID 登记、自造值替换、同 UUID 不改写、不同 UUID 替换、空值替换、
    TTL 过期、无登记原样、按 agent_id 分桶）
2. hook 决策通知（event=pre_tool_use 附加字段）经 /api/hook-report 摄入：
   校验通过 + 宿主 UUID 登记 + report_tool_call 格式入队
3. 端到端: hook 通知先行 → MCP 申报（Agent 自造 session_id）→ 落盘
   session_id 已替换为宿主 UUID 且 original_session_id 保留原值
"""
import json
import os
import socket
import subprocess
import sys
import time

import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

HOST_UUID = "1e14b9ea-b386-4117-bd42-7616c2fc587b"
OTHER_UUID = "9f3c2d1a-0000-1111-2222-333344445555"


# ── 1. broker 单元 ─────────────────────────────────────────────────────

def _mk_broker():
    from mcp_bridge.server import McpReportBroker
    return McpReportBroker()


def test_note_host_session_accepts_uuid_only():
    b = _mk_broker()
    assert b.note_host_session("workbuddy", HOST_UUID) is True
    assert b.note_host_session("workbuddy", "wb-20260905-1900") is False
    assert b.note_host_session("workbuddy", "") is False
    assert b.note_host_session("workbuddy", None) is False
    assert b.host_session_state()["workbuddy"]["session_id"] == HOST_UUID


def test_resolve_replaces_selfmade_session_id():
    b = _mk_broker()
    b.note_host_session("workbuddy", HOST_UUID)
    resolved, original = b.resolve_session_id("workbuddy", "wb-20260905-1915")
    assert resolved == HOST_UUID
    assert original == "wb-20260905-1915"


def test_resolve_keeps_same_uuid():
    b = _mk_broker()
    b.note_host_session("workbuddy", HOST_UUID)
    resolved, original = b.resolve_session_id("workbuddy", HOST_UUID)
    assert resolved == HOST_UUID
    assert original is None


def test_resolve_replaces_foreign_uuid():
    b = _mk_broker()
    b.note_host_session("workbuddy", HOST_UUID)
    resolved, original = b.resolve_session_id("workbuddy", OTHER_UUID)
    assert resolved == HOST_UUID
    assert original == OTHER_UUID


def test_resolve_replaces_empty_candidate():
    b = _mk_broker()
    b.note_host_session("workbuddy", HOST_UUID)
    resolved, original = b.resolve_session_id("workbuddy", "")
    assert resolved == HOST_UUID
    assert original == ""


def test_resolve_no_registration_returns_candidate():
    b = _mk_broker()
    resolved, original = b.resolve_session_id("workbuddy", "wb-x")
    assert resolved == "wb-x"
    assert original is None


def test_resolve_expired_ttl_returns_candidate():
    b = _mk_broker()
    b.note_host_session("workbuddy", HOST_UUID, now_ms=1000)
    resolved, original = b.resolve_session_id(
        "workbuddy", "wb-x", now_ms=1000 + b.HOST_SESSION_TTL_MS + 1)
    assert resolved == "wb-x"
    assert original is None


def test_resolve_bucketed_by_agent_id():
    b = _mk_broker()
    b.note_host_session("workbuddy", HOST_UUID)
    b.note_host_session("qoder", OTHER_UUID)
    r1, _ = b.resolve_session_id("workbuddy", "wb-x")
    r2, _ = b.resolve_session_id("qoder", "q-x")
    assert r1 == HOST_UUID
    assert r2 == OTHER_UUID


def test_resolve_non_uuid_registration_ignored():
    b = _mk_broker()
    b.note_host_session("workbuddy", "not-a-uuid")
    resolved, original = b.resolve_session_id("workbuddy", "wb-x")
    assert resolved == "wb-x"
    assert original is None


# ── 2. http_ingest 摄入 hook 决策事件 ──────────────────────────────────

def test_hook_report_ingest_pre_tool_use_event(tmp_path):
    """hook_gate 决策通知（event=pre_tool_use 附加字段）摄入成功 + 登记。"""
    from mcp_bridge.http_ingest import create_hook_report_handler
    from mcp_bridge.validation import default_rate_limiter, default_validator
    from mcp_bridge.server import McpReportBroker

    broker = McpReportBroker()
    handler = create_hook_report_handler(
        broker, default_validator(), default_rate_limiter(), "qoder")

    import asyncio

    class _Req:
        async def body(self):
            payload = {
                "agent_id": "workbuddy",
                "event": "pre_tool_use",
                "tool_name": "Write",
                "tool_args": {
                    "file_path": "output/x.md",
                    "decision": "allow",
                    "reason": "",
                    "gate_error": False,
                    "hook_phase": "pre",
                    "tool_input_summary": '{"content": "中文..."}',
                },
                "session_id": HOST_UUID,
                "timestamp_ms": int(time.time() * 1000),
                "action_type": "pre",
                "result": "allow",
            }
            return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    from starlette.responses import JSONResponse

    resp = asyncio.run(handler(_Req()))
    assert isinstance(resp, JSONResponse)
    body = json.loads(resp.body.decode("utf-8"))
    assert body["status"] == "accepted"
    # 宿主 UUID 已登记到 broker
    assert broker.host_session_state()["workbuddy"]["session_id"] == HOST_UUID
    # 入队记录为 report_tool_call 且 session_id 为宿主 UUID
    record = broker.consume_nowait()
    assert record["type"] == "report_tool_call"
    assert record["payload"]["session_id"] == HOST_UUID
    assert record["payload"]["action_type"] == "pre"


def test_hook_report_rejects_invalid_body(tmp_path):
    """畸形申报体被拒且不登记。"""
    from mcp_bridge.http_ingest import create_hook_report_handler
    from mcp_bridge.validation import default_rate_limiter, default_validator
    from mcp_bridge.server import McpReportBroker

    broker = McpReportBroker()
    handler = create_hook_report_handler(
        broker, default_validator(), default_rate_limiter(), "qoder")

    import asyncio

    class _Req:
        async def body(self):
            return b"{not-json"

    from starlette.responses import JSONResponse

    resp = asyncio.run(handler(_Req()))
    assert json.loads(resp.body.decode("utf-8"))["status"] == "rejected"
    assert broker.host_session_state() == {}


# ── 3. 端到端: hook 通知先行 → MCP 申报对齐 ─────────────────────────────

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(host, port, timeout=25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def _write_tmp_config(path: str, host: str, port: int, jsonl_dir: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write("mode: mcp_report\n")
        f.write("mcp_report:\n")
        f.write(f"  host: '{host}'\n")
        f.write(f"  port: {port}\n")
        f.write("  framework: pydantic-deep\n")
        f.write("  target_agent_id: workbuddy\n")
        f.write(f"  jsonl_dir: '{jsonl_dir.replace(os.sep, '/')}'\n")
        f.write("  hook_ingest:\n")
        f.write("    enabled: true\n")
        f.write("    path: '/api/hook-report'\n")
        f.write("    agent_id_default: 'qoder'\n")


def test_e2e_hook_notify_then_mcp_report_aligns_session(tmp_path):
    """hook 通知登记宿主 UUID → MCP 申报自造 session_id 被替换并留痕。"""
    port = _free_port()
    jsonl_dir = str(tmp_path / "jsonl")
    cfg_path = str(tmp_path / "cfg.yaml")
    _write_tmp_config(cfg_path, "127.0.0.1", port, jsonl_dir)

    proc = subprocess.Popen(
        [sys.executable, "observer.py", "daemon", "--mode", "mcp_report",
         "--output", str(tmp_path / "out"), "--config", cfg_path],
        cwd=BASE_DIR, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    try:
        assert _wait_port("127.0.0.1", port), "daemon 未就绪"

        import urllib.request

        # ① hook 决策通知（模拟 WorkBuddy PreToolUse hook → notify）
        hook_payload = {
            "agent_id": "workbuddy",
            "event": "pre_tool_use",
            "tool_name": "Write",
            "tool_args": {"file_path": "output/x.md",
                          "decision": "allow", "reason": "",
                          "gate_error": False, "hook_phase": "pre",
                          "tool_input_summary": '{"content": "ok"}'},
            "session_id": HOST_UUID,
            "timestamp_ms": int(time.time() * 1000),
            "action_type": "pre",
            "result": "allow",
        }
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/hook-report",
            data=json.dumps(hook_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert json.loads(resp.read().decode("utf-8"))["status"] \
                == "accepted"

        # ② MCP 申报（Agent 自造 session_id）
        from tests.test_mcp_report_e2e import _run_client  # noqa: E402
        results = _run_client("127.0.0.1", port, [
            ("report_tool_call", {
                "agent_id": "workbuddy",
                "tool_name": "Write",
                "tool_args": {"path": "output/x.md"},
                "session_id": "wb-20260905-1915",
                "action_type": "post",
            }),
            ("report_session", {
                "agent_id": "workbuddy",
                "session_id": "wb-20260905-1915",
                "status": "start",
            }),
        ])
        statuses = [d.get("status") for _, d in results]
        assert statuses == ["accepted", "accepted"]

        # ③ 停止并核验落盘
        proc.stdin.write(b"shutdown\n")
        proc.stdin.flush()
        proc.wait(timeout=30)

        jsonl_files = [os.path.join(jsonl_dir, f)
                       for f in os.listdir(jsonl_dir)
                       if f.endswith(".jsonl")]
        assert jsonl_files, "申报留痕未落盘"
        lines = []
        for jf in jsonl_files:
            with open(jf, encoding="utf-8") as f:
                lines.extend(f.read().strip().splitlines())
        records = [json.loads(l) for l in lines if l.strip()]
        assert len(records) >= 3, f"申报记录不足: {len(records)}"

        by_type = {r["type"]: r for r in records}
        tc = by_type["report_tool_call"]
        assert tc["payload"]["session_id"] == HOST_UUID, \
            "申报 session_id 未对齐宿主 UUID"
        assert tc["payload"].get("original_session_id") == \
            "wb-20260905-1915", "original_session_id 留痕缺失"
        sess = by_type["report_session"]
        assert sess["payload"]["session_id"] == HOST_UUID
        assert sess["payload"].get("original_session_id") == \
            "wb-20260905-1915"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
