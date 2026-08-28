# -*- coding: utf-8 -*-
"""
test_mcp_bridge_server.py — MCP 申报 Server 测试（P1-5）

测试内容:
1. McpReportBroker: 发布/消费/回执/JSONL 落盘/队列满丢弃
2. create_server: 三 tools 注册、直连 call_tool、非法参数拒绝
3. HTTP+SSE 端到端: 标准 MCP client 握手 → 发现 tools → 调用申报
"""

import asyncio
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mcp_bridge.server import (
    McpReportBroker,
    create_server,
    mcp_sdk_available,
)
from mcp_bridge.schemas import REPORT_TOOL_NAMES
from mcp_bridge.validation import RateLimiter

_MCP_MISSING = not mcp_sdk_available()


def _result_dict(result):
    """从 CallToolResult 提取 handler 返回的 dict（兼容 structured/content 两种包装）。"""
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        if isinstance(structured.get("result"), dict):
            return structured["result"]
        return structured
    if result.content:
        return json.loads(result.content[0].text)
    return {}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestMcpReportBroker(unittest.TestCase):
    """申报 broker 单元测试"""

    def test_publish_and_consume(self):
        broker = McpReportBroker()
        receipt = broker.publish({"type": "report_tool_call",
                                  "payload": {"agent_id": "wb"}})
        self.assertIn("event_id", receipt)
        record = broker.consume(timeout=0.1)
        self.assertIsNotNone(record)
        self.assertEqual(record["payload"]["agent_id"], "wb")
        self.assertEqual(record["event_id"], receipt["event_id"])

    def test_consume_nowait_empty(self):
        broker = McpReportBroker()
        self.assertIsNone(broker.consume_nowait())

    def test_received_and_pending_counts(self):
        broker = McpReportBroker()
        broker.publish({"type": "t", "payload": {}})
        broker.publish({"type": "t", "payload": {}})
        self.assertEqual(broker.received_count, 2)
        self.assertEqual(broker.pending_count, 2)
        broker.consume_nowait()
        self.assertEqual(broker.pending_count, 1)

    def test_jsonl_persistence(self):
        tmpdir = tempfile.mkdtemp(prefix="mcp_broker_")
        try:
            path = os.path.join(tmpdir, "reports.jsonl")
            broker = McpReportBroker(jsonl_path=path)
            broker.publish({"type": "report_session",
                            "payload": {"agent_id": "wb",
                                        "session_id": "s1"}})
            self.assertTrue(os.path.isfile(path))
            with open(path, encoding="utf-8") as f:
                lines = [json.loads(x) for x in f if x.strip()]
            self.assertEqual(len(lines), 1)
            self.assertEqual(lines[0]["payload"]["session_id"], "s1")
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_queue_overflow_drops_oldest(self):
        broker = McpReportBroker(max_queue_size=3)
        for i in range(6):
            broker.publish({"type": "t", "payload": {"i": i}})
        self.assertEqual(broker.dropped_count, 3)
        self.assertEqual(broker.pending_count, 3)
        # 队列中保留最新的 3 条
        records = []
        while True:
            r = broker.consume_nowait()
            if r is None:
                break
            records.append(r)
        self.assertEqual([r["payload"]["i"] for r in records], [3, 4, 5])


class TestCreateServer(unittest.TestCase):
    """create_server 与 tools 直连调用"""

    @unittest.skipIf(_MCP_MISSING, "mcp SDK 未安装")
    def test_tools_registered(self):
        server = create_server()
        names = [t.name for t in server._tool_manager.list_tools()]
        self.assertEqual(sorted(names), sorted(REPORT_TOOL_NAMES))

    @unittest.skipIf(_MCP_MISSING, "mcp SDK 未安装")
    def test_call_tool_directly(self):
        broker = McpReportBroker()
        server = create_server(broker=broker)
        result = asyncio.run(server.call_tool(
            "report_tool_call",
            {"agent_id": "wb", "tool_name": "read_file",
             "tool_args": {"path": "/tmp/x"}}))
        self.assertFalse(result.is_error)
        record = broker.consume(timeout=0.1)
        self.assertIsNotNone(record)
        self.assertEqual(record["type"], "report_tool_call")
        self.assertEqual(record["payload"]["tool_name"], "read_file")
        self.assertEqual(record["payload"]["tool_args"],
                         {"path": "/tmp/x"})

    @unittest.skipIf(_MCP_MISSING, "mcp SDK 未安装")
    def test_call_tool_invalid_args_rejected(self):
        """非法参数被拒（框架层/模型层校验抛 ToolError），不产生申报记录"""
        from mcp.server.mcpserver.exceptions import ToolError
        broker = McpReportBroker()
        server = create_server(broker=broker)
        with self.assertRaises(ToolError):
            asyncio.run(server.call_tool(
                "report_tool_call", {"agent_id": ""}))
        self.assertEqual(broker.pending_count, 0)

    @unittest.skipIf(_MCP_MISSING, "mcp SDK 未安装")
    def test_call_tool_rejected_by_validator(self):
        """P1-6: 畸形/超限申报返回结构化 rejected，不入队且 Server 不崩溃"""
        broker = McpReportBroker()
        server = create_server(broker=broker)

        # 非法 action_type 枚举
        r = asyncio.run(server.call_tool(
            "report_tool_call",
            {"agent_id": "wb", "tool_name": "t", "action_type": "mid"}))
        self.assertFalse(r.is_error)
        self.assertEqual(_result_dict(r)["status"], "rejected")
        self.assertIn("invalid_action_type", _result_dict(r)["reason"])

        # 非法 session status 枚举
        r = asyncio.run(server.call_tool(
            "report_session",
            {"agent_id": "wb", "session_id": "s", "status": "crash"}))
        self.assertFalse(r.is_error)
        self.assertEqual(_result_dict(r)["status"], "rejected")
        self.assertIn("invalid_status", _result_dict(r)["reason"])

        # 超 64KB 报文
        r = asyncio.run(server.call_tool(
            "report_tool_call",
            {"agent_id": "wb", "tool_name": "t",
             "tool_args": {"blob": "x" * 70000}}))
        self.assertFalse(r.is_error)
        self.assertEqual(_result_dict(r)["status"], "rejected")
        self.assertIn("too_large", _result_dict(r)["reason"])

        # 被拒申报不产生 broker 记录
        self.assertEqual(broker.pending_count, 0)

        # 拒绝后 Server 仍正常接受合法申报
        r = asyncio.run(server.call_tool(
            "report_action",
            {"agent_id": "wb", "action_type": "d", "action": "a"}))
        self.assertFalse(r.is_error)
        self.assertEqual(_result_dict(r)["status"], "accepted")
        self.assertEqual(broker.pending_count, 1)

    @unittest.skipIf(_MCP_MISSING, "mcp SDK 未安装")
    def test_call_tool_rate_limited(self):
        """P1-6: 超频申报被限流拒绝（按 agent_id 隔离）"""
        broker = McpReportBroker()
        server = create_server(
            broker=broker, rate_limiter=RateLimiter(max_per_window=1))
        r1 = asyncio.run(server.call_tool(
            "report_tool_call",
            {"agent_id": "wb", "tool_name": "t"}))
        self.assertEqual(_result_dict(r1)["status"], "accepted")
        r2 = asyncio.run(server.call_tool(
            "report_tool_call",
            {"agent_id": "wb", "tool_name": "t"}))
        self.assertEqual(_result_dict(r2)["status"], "rejected")
        self.assertEqual(_result_dict(r2)["reason"], "rate_limited")
        # 其他 agent 不受影响
        r3 = asyncio.run(server.call_tool(
            "report_tool_call",
            {"agent_id": "wb2", "tool_name": "t"}))
        self.assertEqual(_result_dict(r3)["status"], "accepted")
        self.assertEqual(broker.pending_count, 2)


@unittest.skipIf(_MCP_MISSING, "mcp SDK 未安装")
class TestMcpSseEndToEnd(unittest.TestCase):
    """HTTP+SSE 端到端: 标准 MCP client 握手与申报调用"""

    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.mkdtemp(prefix="mcp_sse_")
        cls._broker = McpReportBroker()
        cls._server = create_server(broker=cls._broker)
        cls._port = _free_port()
        app = cls._server.sse_app(host="127.0.0.1")
        import uvicorn
        config = uvicorn.Config(app, host="127.0.0.1", port=cls._port,
                                log_level="warning")
        cls._uvicorn = uvicorn.Server(config)
        cls._thread = threading.Thread(
            target=cls._uvicorn.run, daemon=True,
            name="mcp-sse-test")
        cls._thread.start()
        # 等待端口就绪
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with socket.create_connection(
                        ("127.0.0.1", cls._port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("SSE 测试服务启动超时")

    @classmethod
    def tearDownClass(cls):
        cls._uvicorn.should_exit = True
        cls._thread.join(timeout=10)
        import shutil
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def _run_client(self, coro_fn):
        """在独立事件循环中运行 MCP client 流程"""
        from mcp.client.sse import sse_client
        from mcp.client.session import ClientSession

        async def _inner():
            url = f"http://127.0.0.1:{self._port}/sse"
            async with sse_client(url, timeout=10.0) as streams:
                read, write = streams
                async with ClientSession(read, write) as session:
                    return await coro_fn(session)

        return asyncio.run(_inner())

    def test_handshake_and_discover_tools(self):
        """标准 MCP client 握手成功并可发现 3 个申报 tools"""
        async def _fn(session):
            init = await session.initialize()
            self.assertIsNotNone(init.server_info)
            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            return names

        names = self._run_client(_fn)
        self.assertEqual(names, sorted(REPORT_TOOL_NAMES))

    def test_call_report_tools_over_sse(self):
        """经 SSE 调用三类申报 tools，broker 收到申报记录"""
        async def _fn(session):
            await session.initialize()
            r1 = await session.call_tool(
                "report_tool_call",
                {"agent_id": "workbuddy", "tool_name": "execute",
                 "tool_args": {"command": "dir"}, "session_id": "sess-e2e",
                 "timestamp_ms": 1718092800000, "action_type": "pre"})
            r2 = await session.call_tool(
                "report_action",
                {"agent_id": "workbuddy", "action_type": "decision",
                 "action": "risk_notice", "session_id": "sess-e2e"})
            r3 = await session.call_tool(
                "report_session",
                {"agent_id": "workbuddy", "session_id": "sess-e2e",
                 "status": "end"})
            return [r1, r2, r3]

        results = self._run_client(_fn)
        for r in results:
            self.assertFalse(r.is_error, f"tool 调用失败: {r}")

        records = []
        for _ in range(3):
            rec = self._broker.consume(timeout=2.0)
            self.assertIsNotNone(rec, "broker 未收到申报记录")
            records.append(rec)

        by_type = {r["type"]: r for r in records}
        self.assertEqual(set(by_type), set(REPORT_TOOL_NAMES))
        tc = by_type["report_tool_call"]["payload"]
        self.assertEqual(tc["agent_id"], "workbuddy")
        self.assertEqual(tc["tool_name"], "execute")
        self.assertEqual(tc["action_type"], "pre")
        self.assertEqual(tc["timestamp_ms"], 1718092800000)
        self.assertEqual(by_type["report_action"]["payload"]["action"],
                         "risk_notice")
        self.assertEqual(by_type["report_session"]["payload"]["status"],
                         "end")

    def test_malformed_report_rejected_server_survives(self):
        """P1-6: SSE 端畸形/超大申报被拒，Server 不崩溃且后续合法申报正常"""
        async def _fn(session):
            await session.initialize()
            # 畸形申报: 非法 action_type
            r_bad = await session.call_tool(
                "report_tool_call",
                {"agent_id": "workbuddy", "tool_name": "execute",
                 "action_type": "mid"})
            # 超大申报: 超 64KB
            r_big = await session.call_tool(
                "report_tool_call",
                {"agent_id": "workbuddy", "tool_name": "execute",
                 "tool_args": {"blob": "x" * 70000}})
            # 拒绝后合法申报
            r_ok = await session.call_tool(
                "report_action",
                {"agent_id": "workbuddy", "action_type": "decision",
                 "action": "risk_notice"})
            return [r_bad, r_big, r_ok]

        results = self._run_client(_fn)
        for r in results:
            self.assertFalse(r.is_error, f"Server 崩溃或异常: {r}")
        self.assertEqual(_result_dict(results[0])["status"], "rejected")
        self.assertIn("invalid_action_type", _result_dict(results[0])["reason"])
        self.assertEqual(_result_dict(results[1])["status"], "rejected")
        self.assertIn("too_large", _result_dict(results[1])["reason"])
        self.assertEqual(_result_dict(results[2])["status"], "accepted")

        # broker 只收到合法申报
        rec = self._broker.consume(timeout=2.0)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["type"], "report_action")
        self.assertIsNone(self._broker.consume_nowait(),
                          "被拒申报不应入队")


if __name__ == "__main__":
    unittest.main()
