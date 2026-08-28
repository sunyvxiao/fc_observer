# -*- coding: utf-8 -*-
"""
test_mcp_bridge_validation.py — 申报校验与安全层单测（P1-6）

测试内容:
1. ReportValidator.check_size: 报文大小超限拒绝 / 不可序列化拒绝
2. ReportValidator.validate_*: 枚举约束（action_type/status）、容器规模
   （键数 + 大小）、pydantic 错误映射为可读原因、未知 tool 拒绝
3. RateLimiter: 滑动窗口放行/超限拒绝、denied_count 计数、跨 agent 隔离
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mcp_bridge.validation import (
    DEFAULT_MAX_REPORT_BYTES,
    ReportValidationError,
    ReportValidator,
    RateLimiter,
    default_rate_limiter,
    default_validator,
)


class TestReportValidatorCheckSize(unittest.TestCase):
    """报文大小限制"""

    def test_small_report_passes(self):
        v = ReportValidator()
        self.assertIsNone(v.check_size({"agent_id": "wb", "tool_name": "t"}))

    def test_oversized_report_rejected(self):
        v = ReportValidator(max_report_bytes=128)
        reason = v.check_size({"agent_id": "wb",
                               "tool_args": {"blob": "x" * 300}})
        self.assertIsNotNone(reason)
        self.assertIn("too_large", reason)

    def test_unserializable_report_rejected(self):
        """不可序列化报文（循环引用）被拒而非崩溃"""
        v = ReportValidator()
        cyclic = {"agent_id": "wb"}
        cyclic["self"] = cyclic
        reason = v.check_size(cyclic)
        self.assertIsNotNone(reason)
        self.assertIn("unserializable", reason)

    def test_default_limit_is_64k(self):
        self.assertEqual(DEFAULT_MAX_REPORT_BYTES, 64 * 1024)


class TestReportValidatorToolCall(unittest.TestCase):
    """report_tool_call 校验"""

    def _valid(self):
        return {"agent_id": "wb", "tool_name": "read_file",
                "tool_args": {"path": "/tmp/x"}, "action_type": "pre"}

    def test_valid_passes(self):
        m = ReportValidator().validate_tool_call(self._valid())
        self.assertEqual(m.tool_name, "read_file")

    def test_invalid_action_type_rejected(self):
        args = self._valid()
        args["action_type"] = "mid"
        with self.assertRaises(ReportValidationError) as ctx:
            ReportValidator().validate_tool_call(args)
        self.assertIn("invalid_action_type", ctx.exception.reason)

    def test_missing_agent_id_rejected(self):
        args = self._valid()
        del args["agent_id"]
        with self.assertRaises(ReportValidationError) as ctx:
            ReportValidator().validate_tool_call(args)
        self.assertIn("agent_id", ctx.exception.reason)

    def test_tool_args_too_many_items_rejected(self):
        args = self._valid()
        args["tool_args"] = {f"k{i}": 1 for i in range(101)}
        with self.assertRaises(ReportValidationError) as ctx:
            ReportValidator().validate_tool_call(args)
        self.assertIn("tool_args_too_many_items", ctx.exception.reason)

    def test_tool_args_oversized_rejected(self):
        v = ReportValidator(max_payload_field_bytes=64)
        args = self._valid()
        args["tool_args"] = {"blob": "x" * 200}
        with self.assertRaises(ReportValidationError) as ctx:
            v.validate_tool_call(args)
        self.assertIn("tool_args_too_large", ctx.exception.reason)

    def test_tool_args_not_dict_rejected(self):
        args = self._valid()
        args["tool_args"] = ["not", "a", "dict"]
        with self.assertRaises(ReportValidationError) as ctx:
            ReportValidator().validate_tool_call(args)
        self.assertIn("invalid_tool_args", ctx.exception.reason)

    def test_none_tool_args_rejected(self):
        """校验层直收 tool_args=None 拒绝（handler 侧已归一化为 {}）"""
        args = self._valid()
        args["tool_args"] = None
        with self.assertRaises(ReportValidationError) as ctx:
            ReportValidator().validate_tool_call(args)
        self.assertIn("tool_args", ctx.exception.reason)


class TestReportValidatorActionSession(unittest.TestCase):
    """report_action / report_session 校验"""

    def test_action_valid_passes(self):
        m = ReportValidator().validate_action(
            {"agent_id": "wb", "action_type": "decision",
             "action": "risk_notice", "detail": {"level": "high"}})
        self.assertEqual(m.action, "risk_notice")

    def test_action_detail_too_many_items_rejected(self):
        args = {"agent_id": "wb", "action_type": "decision",
                "action": "x", "detail": {f"k{i}": 1 for i in range(101)}}
        with self.assertRaises(ReportValidationError) as ctx:
            ReportValidator().validate_action(args)
        self.assertIn("detail_too_many_items", ctx.exception.reason)

    def test_action_detail_oversized_rejected(self):
        v = ReportValidator(max_payload_field_bytes=64)
        args = {"agent_id": "wb", "action_type": "decision",
                "action": "x", "detail": {"blob": "x" * 200}}
        with self.assertRaises(ReportValidationError) as ctx:
            v.validate_action(args)
        self.assertIn("detail_too_large", ctx.exception.reason)

    def test_session_valid_passes(self):
        m = ReportValidator().validate_session(
            {"agent_id": "wb", "session_id": "s1", "status": "pause"})
        self.assertEqual(m.status, "pause")

    def test_session_invalid_status_rejected(self):
        with self.assertRaises(ReportValidationError) as ctx:
            ReportValidator().validate_session(
                {"agent_id": "wb", "session_id": "s1", "status": "crash"})
        self.assertIn("invalid_status", ctx.exception.reason)

    def test_session_missing_session_id_rejected(self):
        with self.assertRaises(ReportValidationError) as ctx:
            ReportValidator().validate_session({"agent_id": "wb"})
        self.assertIn("session_id", ctx.exception.reason)


class TestReportValidatorDispatch(unittest.TestCase):
    """按 tool 名分发"""

    def test_dispatch_known_tools(self):
        v = ReportValidator()
        m1 = v.validate("report_tool_call",
                        {"agent_id": "a", "tool_name": "t"})
        m2 = v.validate("report_action",
                        {"agent_id": "a", "action_type": "d", "action": "x"})
        m3 = v.validate("report_session",
                        {"agent_id": "a", "session_id": "s"})
        self.assertEqual(m1.tool_name, "t")
        self.assertEqual(m2.action, "x")
        self.assertEqual(m3.status, "start")

    def test_unknown_tool_rejected(self):
        with self.assertRaises(ReportValidationError) as ctx:
            ReportValidator().validate("report_everything", {})
        self.assertIn("unknown_tool", ctx.exception.reason)


class TestRateLimiter(unittest.TestCase):
    """滑动窗口频率限制"""

    def test_within_limit_allowed(self):
        rl = RateLimiter(max_per_window=3, window_seconds=1.0)
        for i in range(3):
            self.assertTrue(rl.allow("wb", now=100.0 + i * 0.1))
        self.assertEqual(rl.total_checks, 3)
        self.assertEqual(rl.denied_count, 0)

    def test_over_limit_denied(self):
        rl = RateLimiter(max_per_window=3, window_seconds=1.0)
        for i in range(5):
            rl.allow("wb", now=100.0 + i * 0.1)
        self.assertEqual(rl.denied_count, 2)
        self.assertEqual(rl.total_checks, 5)

    def test_window_slides(self):
        """窗口滑动后旧记录过期，重新放行"""
        rl = RateLimiter(max_per_window=2, window_seconds=1.0)
        self.assertTrue(rl.allow("wb", now=0.0))
        self.assertTrue(rl.allow("wb", now=0.5))
        self.assertFalse(rl.allow("wb", now=0.9))
        # 1.0 之后 0.0/0.5 两条过期（cutoff = now - 1.0）
        self.assertTrue(rl.allow("wb", now=1.6))
        self.assertTrue(rl.allow("wb", now=1.7))

    def test_agents_isolated(self):
        """不同 agent 独立计数"""
        rl = RateLimiter(max_per_window=2, window_seconds=1.0)
        self.assertTrue(rl.allow("a", now=0.0))
        self.assertTrue(rl.allow("a", now=0.1))
        self.assertFalse(rl.allow("a", now=0.2))
        self.assertTrue(rl.allow("b", now=0.3))

    def test_default_factories(self):
        self.assertIsInstance(default_validator(), ReportValidator)
        rl = default_rate_limiter()
        self.assertIsInstance(rl, RateLimiter)
        self.assertEqual(rl.max_per_window, 60)


if __name__ == "__main__":
    unittest.main()
