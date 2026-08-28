# -*- coding: utf-8 -*-
"""
test_mcp_report_collector.py — MCP 申报采集器单测（P3-8）

测试内容:
1. capabilities: 观测 + 无阻断能力（决策基线）
2. 模拟申报序列 → RawEvent 流（事件类型/字段与工厂直连一致）
3. 浅层语义保护: 敏感键不进 RawEvent、超长值截断
4. report_action / report_session 不产事件（计数）
5. 畸形申报不破坏采集循环
6. detach 后 start 正常退出
"""

import sys
import os
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from collector.mcp_report_collector import McpReportCollector
from mcp_bridge.server import McpReportBroker
from mcp_bridge.semantic_guard import SemanticGuard, MASK
from models.event import RawEvent
from observer_core.monitoring.raw_event_factory import RawEventFactory


def _broker_with_records(records):
    broker = McpReportBroker()
    for r in records:
        broker.publish(r)
    return broker


def _make_tool_call(event_id, tool_name, tool_args, agent_id="workbuddy",
                    timestamp_ms=1718092800000):
    return {
        "type": "report_tool_call",
        "event_id": event_id,
        "received_at_ms": timestamp_ms,
        "payload": {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "tool_args": tool_args,
            "session_id": "sess-1",
            "timestamp_ms": timestamp_ms,
            "action_type": "post",
            "result": None,
        },
    }


def _collect(collector, expected, timeout=5.0):
    """后台线程消费 start() 生成器，达到 expected 数量或超时后 detach。

    start() 是常驻轮询生成器（detach 才退出），必须用 detach 控制终止。
    """
    events = []
    t = threading.Thread(
        target=lambda: events.extend(collector.start()), daemon=True)
    t.start()
    deadline = time.time() + timeout
    while len(events) < expected and time.time() < deadline:
        time.sleep(0.05)
    collector.detach()
    t.join(timeout=2)
    return events


class TestMcpReportCollectorCapabilities(unittest.TestCase):
    def setUp(self):
        self.collector = McpReportCollector({})

    def test_capabilities(self):
        caps = self.collector.capabilities()
        self.assertEqual(caps.name, "MCPReport")
        self.assertTrue(caps.can_observe)
        self.assertFalse(caps.can_block_tier2)
        self.assertFalse(caps.can_block_tier3)
        self.assertFalse(caps.is_transparent)
        self.assertEqual(caps.time_source, "realtime_monotonic")

    def test_attach_without_broker_fails(self):
        self.assertFalse(self.collector.attach())

    def test_send_command_unsupported(self):
        self.assertFalse(self.collector.send_command("block"))

    def test_get_process_tree(self):
        self.assertIsInstance(self.collector.get_process_tree(), dict)


class TestMcpReportCollectorConversion(unittest.TestCase):
    """申报序列 → RawEvent 流"""

    def _make_collector(self, broker):
        collector = McpReportCollector({}, broker=broker)
        self.assertTrue(collector.attach(agent_id="workbuddy"))
        return collector

    def test_tool_call_sequence_to_raw_events(self):
        """三类工具申报 → 正确事件类型的 RawEvent 流"""
        broker = _broker_with_records([
            _make_tool_call("evt1", "read_file", {"path": "/etc/passwd"}),
            _make_tool_call("evt2", "execute", {"command": "ls -la /tmp"},
                            timestamp_ms=1718092801000),
            _make_tool_call("evt3", "web_fetch",
                            {"url": "https://api.example.com/x"},
                            timestamp_ms=1718092802000),
        ])
        collector = self._make_collector(broker)

        events = []
        gen = collector.start()
        while len(events) < 3:
            try:
                events.append(next(gen))
            except StopIteration:
                break
        collector.detach()

        self.assertEqual(len(events), 3)
        # read_file → file_open
        self.assertEqual(events[0].event_type, "file_open")
        self.assertEqual(events[0].file_path, "/etc/passwd")
        self.assertEqual(events[0].file_op, "read")
        # execute → exec
        self.assertEqual(events[1].event_type, "exec")
        self.assertEqual(events[1].executable, "ls")
        self.assertEqual(events[1].arguments, ["-la", "/tmp"])
        # web_fetch → net_conn
        self.assertEqual(events[2].event_type, "net_conn")
        self.assertEqual(events[2].remote_addr, "api.example.com")
        self.assertEqual(events[2].remote_port, 443)
        self.assertEqual(events[2].protocol, "TCP")
        # 通用字段
        for e in events:
            self.assertEqual(e.agent_id, "workbuddy")
            self.assertEqual(e.agent_framework, "mcp_report")
            self.assertEqual(e.pid, 0)
        # 时间戳: 毫秒 → 纳秒
        self.assertEqual(events[1].timestamp_ns, 1718092801000 * 1_000_000)

    def test_conversion_matches_factory_direct(self):
        """采集器产出与 RawEventFactory 直连一致（与 CLI 直连等价）"""
        tool_name, tool_args = "read_file", {"path": "/a/b.txt"}
        broker = _broker_with_records([
            _make_tool_call("evtX", tool_name, tool_args,
                            timestamp_ms=123456)])
        collector = self._make_collector(broker)
        gen = collector.start()
        collected = next(gen)
        collector.detach()

        direct = RawEventFactory.from_tool_call(
            {"tool": tool_name,
             "input": SemanticGuard().sanitize_args(tool_args)},
            event_id="mcp_evtX", timestamp_ns=123456 * 1_000_000,
            pid=0, ppid=0, agent_id="workbuddy",
            agent_framework="mcp_report",
            session_id="sess-1")
        self.assertEqual(collected.to_dict(), direct.to_dict())

    def test_sensitive_args_masked_not_in_event(self):
        """敏感键脱敏后不进 RawEvent（file_path 正常、password 被掩码）"""
        broker = _broker_with_records([
            _make_tool_call("evtS", "read_file",
                            {"path": "/tmp/conf", "password": "hunter2"})])
        collector = self._make_collector(broker)
        gen = collector.start()
        event = next(gen)
        collector.detach()

        self.assertEqual(event.file_path, "/tmp/conf")
        # 敏感键只存在于已脱敏的 args 摘要，不进入 RawEvent 固定字段
        self.assertNotIn("hunter2", str(event.to_dict()))

    def test_oversized_args_truncated(self):
        """超长参数被截断（防超长值进入规则匹配）"""
        long_path = "x" * 500
        broker = _broker_with_records([
            _make_tool_call("evtL", "read_file", {"path": long_path})])
        collector = McpReportCollector(
            {}, broker=broker,
            guard=SemanticGuard(max_str_len=64))
        collector.attach()
        gen = collector.start()
        event = next(gen)
        collector.detach()

        self.assertLess(len(event.file_path or ""), 100)
        self.assertIn("[truncated]", event.file_path)

    def test_unknown_tool_defaults_to_exec(self):
        """未知工具 → exec（与工厂 fallback 一致）"""
        broker = _broker_with_records([
            _make_tool_call("evtU", "mystery_tool_xyz", {"a": 1})])
        collector = self._make_collector(broker)
        gen = collector.start()
        event = next(gen)
        collector.detach()
        self.assertEqual(event.event_type, "exec")

    def test_action_and_session_no_raw_event(self):
        """report_action / report_session 不产 RawEvent（仅计数）"""
        broker = _broker_with_records([
            {"type": "report_action", "event_id": "a1",
             "payload": {"agent_id": "wb", "action_type": "decision",
                         "action": "risk_notice", "timestamp_ms": 1}},
            {"type": "report_session", "event_id": "s1",
             "payload": {"agent_id": "wb", "session_id": "s",
                         "status": "end", "timestamp_ms": 2}},
        ])
        collector = self._make_collector(broker)
        # 等待一段时间确认无事件产出后 detach
        events = _collect(collector, expected=1, timeout=1.0)

        self.assertEqual(events, [])
        self.assertEqual(collector.action_count, 1)
        self.assertEqual(collector.session_count, 1)
        self.assertEqual(collector.tool_call_count, 0)


class TestMcpReportCollectorRobustness(unittest.TestCase):
    """恶意/畸形申报不破坏管线"""

    def test_malformed_records_skipped(self):
        """畸形申报记录被安全跳过，采集循环继续"""
        broker = _broker_with_records([
            {"type": "report_tool_call", "event_id": "bad1",
             "payload": None},                      # payload 为 None
            {"type": "unknown_type", "event_id": "bad2",
             "payload": {}},                        # 未知类型
            {"type": "report_tool_call", "event_id": "bad3",
             "payload": {"agent_id": "wb", "tool_name": "execute",
                         "tool_args": "not-a-dict"}},  # 非 dict args
            _make_tool_call("good1", "read_file", {"path": "/ok"},
                            timestamp_ms=5),
        ])
        collector = McpReportCollector({}, broker=broker)
        collector.attach()
        events = _collect(collector, expected=2)

        # 仅合法申报产事件；畸形记录全部安全跳过
        # bad1(payload=None) 跳过；bad2(未知类型) 跳过；
        # bad3(非 dict args) 安全降级产 exec 事件；good1 产 file_open 事件
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, "exec")
        self.assertEqual(events[1].event_id, "mcp_good1")
        self.assertEqual(events[1].event_type, "file_open")
        self.assertEqual(collector.skipped_count, 2)
        self.assertEqual(collector.tool_call_count, 2)

    def test_cyclic_args_no_crash(self):
        """循环引用 tool_args 不崩溃"""
        cyclic = {"self": None}
        cyclic["self"] = cyclic
        broker = _broker_with_records([
            _make_tool_call("evtC", "read_file", cyclic)])
        collector = McpReportCollector({}, broker=broker)
        collector.attach()
        gen = collector.start()
        event = next(gen)   # 不抛异常
        collector.detach()
        self.assertIsInstance(event, RawEvent)

    def test_detach_stops_start(self):
        """detach 后 start 退出（不阻塞）"""
        broker = McpReportBroker()
        collector = McpReportCollector({}, broker=broker)
        collector.attach()
        collector.detach()
        # 队列为空 + stop 已设置 → 立即退出
        events = list(collector.start())
        self.assertEqual(events, [])

    def test_start_without_attach_returns_none(self):
        broker = McpReportBroker()
        collector = McpReportCollector({}, broker=broker)
        self.assertEqual(list(collector.start()), [])


if __name__ == "__main__":
    unittest.main()
