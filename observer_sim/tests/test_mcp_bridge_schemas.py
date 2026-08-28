# -*- coding: utf-8 -*-
"""
test_mcp_bridge_schemas.py — MCP 申报 schema 单元测试（P1-5）

测试内容:
1. ReportToolCallInput: 合法/非法输入、normalized 缺省时间戳填充
2. ReportActionInput: 合法/非法输入
3. ReportSessionInput: 合法/非法输入
4. REPORT_SCHEMAS 注册表与工具名常量
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pydantic import ValidationError

from mcp_bridge.schemas import (
    REPORT_SCHEMAS,
    REPORT_TOOL_NAMES,
    TOOL_REPORT_ACTION,
    TOOL_REPORT_SESSION,
    TOOL_REPORT_TOOL_CALL,
    ReportActionInput,
    ReportSessionInput,
    ReportToolCallInput,
)


class TestReportToolCallInput(unittest.TestCase):
    """report_tool_call 申报模型"""

    def test_valid_minimal(self):
        """最小合法输入（仅必填字段）"""
        m = ReportToolCallInput(agent_id="workbuddy", tool_name="read_file")
        self.assertEqual(m.agent_id, "workbuddy")
        self.assertEqual(m.tool_name, "read_file")
        self.assertEqual(m.tool_args, {})
        self.assertIsNone(m.session_id)
        self.assertIsNone(m.timestamp_ms)
        self.assertEqual(m.action_type, "post")
        self.assertIsNone(m.result)

    def test_valid_full(self):
        """完整合法输入"""
        m = ReportToolCallInput(
            agent_id="workbuddy", tool_name="execute",
            tool_args={"command": "ls"}, session_id="sess-1",
            timestamp_ms=1718092800000, action_type="pre",
            result="ok")
        self.assertEqual(m.tool_args["command"], "ls")
        self.assertEqual(m.action_type, "pre")

    def test_normalized_fills_timestamp(self):
        """normalized 缺省 timestamp 时填充接收时间"""
        m = ReportToolCallInput(agent_id="a", tool_name="t")
        out = m.normalized(received_at_ms=12345)
        self.assertEqual(out["timestamp_ms"], 12345)
        self.assertEqual(out["agent_id"], "a")
        self.assertEqual(out["tool_name"], "t")

    def test_normalized_keeps_explicit_timestamp(self):
        """normalized 保留显式时间戳"""
        m = ReportToolCallInput(agent_id="a", tool_name="t",
                                timestamp_ms=999)
        out = m.normalized(received_at_ms=12345)
        self.assertEqual(out["timestamp_ms"], 999)

    def test_invalid_empty_agent_id(self):
        """空 agent_id 拒绝"""
        with self.assertRaises(ValidationError):
            ReportToolCallInput(agent_id="", tool_name="t")

    def test_invalid_missing_tool_name(self):
        """缺 tool_name 拒绝"""
        with self.assertRaises(ValidationError):
            ReportToolCallInput(agent_id="a")

    def test_invalid_negative_timestamp(self):
        """负时间戳拒绝"""
        with self.assertRaises(ValidationError):
            ReportToolCallInput(agent_id="a", tool_name="t", timestamp_ms=-1)

    def test_invalid_overlong_agent_id(self):
        """超长 agent_id 拒绝"""
        with self.assertRaises(ValidationError):
            ReportToolCallInput(agent_id="x" * 65, tool_name="t")


class TestReportActionInput(unittest.TestCase):
    """report_action 申报模型"""

    def test_valid(self):
        m = ReportActionInput(agent_id="wb", action_type="decision",
                              action="risk_notice",
                              detail={"level": "high"})
        self.assertEqual(m.action, "risk_notice")
        self.assertEqual(m.detail["level"], "high")
        out = m.normalized(received_at_ms=7)
        self.assertEqual(out["timestamp_ms"], 7)

    def test_invalid_missing_action(self):
        with self.assertRaises(ValidationError):
            ReportActionInput(agent_id="wb", action_type="decision")


class TestReportSessionInput(unittest.TestCase):
    """report_session 申报模型"""

    def test_valid(self):
        m = ReportSessionInput(agent_id="wb", session_id="s1",
                               session_type="task", status="end",
                               timestamp_ms=100)
        out = m.normalized(received_at_ms=7)
        self.assertEqual(out["status"], "end")
        self.assertEqual(out["timestamp_ms"], 100)

    def test_valid_minimal(self):
        m = ReportSessionInput(agent_id="wb", session_id="s1")
        self.assertEqual(m.status, "start")

    def test_invalid_missing_session_id(self):
        with self.assertRaises(ValidationError):
            ReportSessionInput(agent_id="wb")


class TestSchemaRegistry(unittest.TestCase):
    """schema 注册表与工具名常量"""

    def test_registry_covers_all_tools(self):
        """REPORT_SCHEMAS 覆盖全部申报工具"""
        self.assertEqual(set(REPORT_SCHEMAS.keys()),
                         set(REPORT_TOOL_NAMES))

    def test_registry_types(self):
        self.assertIs(REPORT_SCHEMAS[TOOL_REPORT_TOOL_CALL],
                      ReportToolCallInput)
        self.assertIs(REPORT_SCHEMAS[TOOL_REPORT_ACTION],
                      ReportActionInput)
        self.assertIs(REPORT_SCHEMAS[TOOL_REPORT_SESSION],
                      ReportSessionInput)

    def test_tool_name_constants(self):
        self.assertEqual(TOOL_REPORT_TOOL_CALL, "report_tool_call")
        self.assertEqual(TOOL_REPORT_ACTION, "report_action")
        self.assertEqual(TOOL_REPORT_SESSION, "report_session")


if __name__ == "__main__":
    unittest.main()
