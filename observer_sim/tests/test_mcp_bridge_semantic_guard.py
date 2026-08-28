# -*- coding: utf-8 -*-
"""
test_mcp_bridge_semantic_guard.py — 浅层语义保护层单测（P2-7）

测试内容:
1. 工具名→事件类型映射（复用 HookRegistry，classify_tool 兜底）
2. 参数摘要脱敏（敏感键 → "***"，含嵌套）
3. 字符串截断（超长值截断）
4. 规模上限（dict 键数 / list 项数 / 嵌套深度）
5. 恶意输入防御（循环引用 / 非 JSON 类型 / None 不抛异常）
6. registry 与内置分类表一致性
7. protect 组合入口 / sanitize_result
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mcp_bridge.semantic_guard import (
    DEFAULT_FRAMEWORK,
    MASK,
    SemanticGuard,
)
from observer_core.monitoring.raw_event_factory import classify_tool


def _registry():
    try:
        from adapter.hook_registry import get_registry
    except ImportError:
        from hook_registry import get_registry
    return get_registry()


class TestSemanticGuardToolMapping(unittest.TestCase):
    """工具名 → 事件类型映射"""

    def setUp(self):
        self.guard = SemanticGuard()

    def test_exec_tools(self):
        for t in ("execute", "shell", "bash", "run_command"):
            self.assertEqual(self.guard.map_tool_to_event(t), "exec")

    def test_read_tools(self):
        for t in ("read_file", "cat", "grep"):
            self.assertEqual(self.guard.map_tool_to_event(t), "file_open")

    def test_write_tools(self):
        for t in ("write_file", "edit_file", "patch"):
            self.assertEqual(self.guard.map_tool_to_event(t), "file_open")

    def test_net_tools(self):
        for t in ("web_fetch", "fetch", "curl"):
            self.assertEqual(self.guard.map_tool_to_event(t), "net_conn")

    def test_unknown_tool_falls_back_to_exec(self):
        self.assertEqual(self.guard.map_tool_to_event("totally_unknown_xyz"),
                         "exec")

    def test_degenerate_inputs_no_crash(self):
        """None / 空串 / 超长工具名不抛异常且归 exec"""
        for bad in (None, "", "  ", "x" * 1000, 123, ["a"]):
            self.assertEqual(self.guard.map_tool_to_event(bad), "exec")

    def test_registry_consistent_with_classify_table(self):
        """registry 中每个工具的事件类型与内置分类表一致"""
        reg = _registry()
        config = reg.get_config(DEFAULT_FRAMEWORK)
        if config is None:
            self.skipTest("pydantic-deep 框架配置未加载")
        for tool in config.list_tools():
            self.assertEqual(self.guard.map_tool_to_event(tool),
                             classify_tool(tool),
                             f"工具 {tool} 映射不一致")

    def test_registry_unavailable_falls_back(self):
        """registry 为 None 时回退内置分类表"""
        guard = SemanticGuard(registry=None)
        self.assertEqual(guard.map_tool_to_event("read_file"), "file_open")
        self.assertEqual(guard.map_tool_to_event("web_fetch"), "net_conn")

    def test_unknown_framework_falls_back(self):
        """未知框架名回退内置分类表"""
        guard = SemanticGuard(framework="no-such-framework")
        self.assertEqual(guard.map_tool_to_event("read_file"), "file_open")


class TestSemanticGuardSanitize(unittest.TestCase):
    """参数摘要脱敏/截断"""

    def setUp(self):
        self.guard = SemanticGuard()

    def test_sensitive_keys_masked(self):
        """敏感键脱敏（顶层 + 嵌套 + 大小写不敏感）"""
        args = {
            "command": "ls",
            "password": "hunter2",
            "config": {"api_key": "sk-123", "Token": "abc"},
            "AUTHORIZATION": "Bearer xyz",
            "session_cookie": "sess=1",
        }
        out = self.guard.sanitize_args(args)
        self.assertEqual(out["command"], "ls")
        self.assertEqual(out["password"], MASK)
        self.assertEqual(out["config"]["api_key"], MASK)
        self.assertEqual(out["config"]["Token"], MASK)
        self.assertEqual(out["AUTHORIZATION"], MASK)
        self.assertEqual(out["session_cookie"], MASK)

    def test_innocent_keys_untouched(self):
        """非敏感键保留原值（monkey 等含 key 片段的不误伤）"""
        out = self.guard.sanitize_args(
            {"monkey": "x", "keyword": "k", "path": "/tmp/a"})
        self.assertEqual(out["monkey"], "x")
        self.assertEqual(out["keyword"], "k")
        self.assertEqual(out["path"], "/tmp/a")

    def test_long_string_truncated(self):
        guard = SemanticGuard(max_str_len=16)
        out = guard.sanitize_args({"blob": "x" * 100})
        self.assertTrue(out["blob"].startswith("x" * 16))
        self.assertTrue(out["blob"].endswith("[truncated]"))

    def test_nested_truncation(self):
        guard = SemanticGuard(max_str_len=8)
        out = guard.sanitize_args({"nested": {"deep": ["y" * 50]}})
        self.assertEqual(len(out["nested"]["deep"][0]),
                         8 + len("...[truncated]"))

    def test_dict_size_capped(self):
        guard = SemanticGuard(max_dict_items=3)
        out = guard.sanitize_args({f"k{i}": i for i in range(10)})
        self.assertLessEqual(len(out), 3)

    def test_list_size_capped(self):
        guard = SemanticGuard(max_list_items=2)
        out = guard.sanitize_args({"items": list(range(10))})
        self.assertEqual(len(out["items"]), 2)

    def test_depth_capped(self):
        guard = SemanticGuard(max_depth=2)
        deep = {"l1": {"l2": {"l3": {"l4": "secret_val"}}}}
        out = guard.sanitize_args(deep)
        l1 = out["l1"]
        self.assertIsInstance(l1, dict)
        # 深度超限后降级为字符串（安全截断）
        self.assertIsInstance(l1["l2"], dict)
        self.assertIsInstance(l1["l2"]["l3"], str)

    def test_cyclic_reference_no_crash(self):
        """循环引用不抛异常、不破坏管线"""
        cyclic = {"self": None}
        cyclic["self"] = cyclic
        out = self.guard.sanitize_args(cyclic)
        self.assertIsInstance(out, dict)
        self.assertIn("self", out)

    def test_non_json_types_degraded(self):
        """set / bytes / 对象等降级为字符串"""
        out = self.guard.sanitize_args({"s": {1, 2, 3}, "b": b"raw"})
        self.assertIsInstance(out["s"], str)
        self.assertIn("1", out["s"])
        self.assertIsInstance(out["b"], str)

    def test_none_and_scalars_kept(self):
        out = self.guard.sanitize_args(
            {"n": None, "i": 5, "f": 1.5, "t": True})
        self.assertIsNone(out["n"])
        self.assertEqual(out["i"], 5)
        self.assertEqual(out["f"], 1.5)
        self.assertIs(out["t"], True)

    def test_non_dict_args_degraded(self):
        """非 dict 输入安全降级"""
        out = self.guard.sanitize_args(["a", "b"])
        self.assertEqual(out, {"_raw": "['a', 'b']"})

    def test_sanitize_result(self):
        guard = SemanticGuard(max_str_len=4)
        self.assertIsNone(guard.sanitize_result(None))
        self.assertEqual(guard.sanitize_result("abcdefg"),
                         "abcd..." + "[truncated]")


class TestSemanticGuardProtect(unittest.TestCase):
    """protect 组合入口"""

    def test_protect_read_file(self):
        guard = SemanticGuard()
        event_type, safe = guard.protect(
            "read_file", {"path": "/etc/passwd", "token": "t0k"})
        self.assertEqual(event_type, "file_open")
        self.assertEqual(safe["path"], "/etc/passwd")
        self.assertEqual(safe["token"], MASK)

    def test_protect_exec(self):
        guard = SemanticGuard()
        event_type, safe = guard.protect(
            "execute", {"command": "rm -rf /", "sudo_password": "x"})
        self.assertEqual(event_type, "exec")
        self.assertEqual(safe["command"], "rm -rf /")
        self.assertEqual(safe["sudo_password"], MASK)

    def test_protect_net(self):
        guard = SemanticGuard()
        event_type, safe = guard.protect(
            "web_fetch", {"url": "https://evil.example.com"})
        self.assertEqual(event_type, "net_conn")
        self.assertEqual(safe["url"], "https://evil.example.com")

    def test_protect_degenerate_no_crash(self):
        guard = SemanticGuard()
        event_type, safe = guard.protect(None, None)
        self.assertEqual(event_type, "exec")
        self.assertIsInstance(safe, dict)

    def test_is_read_tool(self):
        guard = SemanticGuard()
        self.assertTrue(guard.is_read_tool("read_file"))
        self.assertFalse(guard.is_read_tool("write_file"))
        self.assertFalse(guard.is_read_tool("execute"))


if __name__ == "__main__":
    unittest.main()
