"""
test_hook_registry.py — HookRegistry Hook 配置注册表单元测试

测试内容:
1. HookRegistry: YAML 加载、框架发现、get_config
2. HookFrameworkConfig: map_tool_to_event, get_event_type, get_param_rules
3. ToolMapping: 数据类构造
4. 边界条件: 空目录、无效 YAML、手动注册、默认映射
"""

import sys
import os
import unittest
import tempfile
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from adapter.hook_registry import (
    HookRegistry, HookFrameworkConfig, ToolMapping, get_registry
)


class TestToolMapping(unittest.TestCase):
    """ToolMapping 数据类测试"""

    def test_basic_construction(self):
        """基本构造"""
        tm = ToolMapping(
            tool_name="execute",
            event_type="exec",
            param_rules={"executable": "input.command"},
        )
        self.assertEqual(tm.tool_name, "execute")
        self.assertEqual(tm.event_type, "exec")
        self.assertEqual(tm.param_rules["executable"], "input.command")

    def test_default_param_rules(self):
        """默认 param_rules 为空字典"""
        tm = ToolMapping(tool_name="read_file", event_type="file_open")
        self.assertEqual(tm.param_rules, {})


class TestHookFrameworkConfig(unittest.TestCase):
    """HookFrameworkConfig 方法测试"""

    def setUp(self):
        self.config = HookFrameworkConfig(
            framework="test-fw",
            version="2.0",
            description="Test framework",
            tool_mappings={
                "execute": ToolMapping("execute", "exec",
                                       {"executable": "input.cmd"}),
                "read_file": ToolMapping("read_file", "file_open"),
                "http_get": ToolMapping("http_get", "net_conn"),
            },
            default_mapping=ToolMapping("__default__", "exec"),
        )

    def test_map_tool_to_event_case_insensitive(self):
        """工具名匹配不区分大小写"""
        result = self.config.map_tool_to_event("EXECUTE")
        self.assertIsNotNone(result)
        self.assertEqual(result.event_type, "exec")

    def test_map_tool_to_event_unknown(self):
        """未知工具返回 None"""
        result = self.config.map_tool_to_event("unknown_tool")
        self.assertIsNone(result)

    def test_get_event_type_known(self):
        """已知工具返回正确事件类型"""
        self.assertEqual(self.config.get_event_type("execute"), "exec")
        self.assertEqual(self.config.get_event_type("read_file"), "file_open")
        self.assertEqual(self.config.get_event_type("http_get"), "net_conn")

    def test_get_event_type_unknown_with_default(self):
        """未知工具回退到默认映射"""
        self.assertEqual(self.config.get_event_type("unknown"), "exec")

    def test_get_event_type_unknown_without_default(self):
        """无默认映射时未知工具返回 'exec'"""
        config = HookFrameworkConfig(framework="no-default")
        self.assertEqual(config.get_event_type("unknown"), "exec")

    def test_get_param_rules_known(self):
        """已知工具返回正确参数规则"""
        rules = self.config.get_param_rules("execute")
        self.assertEqual(rules["executable"], "input.cmd")

    def test_get_param_rules_unknown_with_default(self):
        """未知工具回退到默认参数规则"""
        config = HookFrameworkConfig(
            framework="fw",
            default_mapping=ToolMapping("__default__", "exec",
                                        {"default_arg": "x"})
        )
        rules = config.get_param_rules("unknown")
        self.assertEqual(rules.get("default_arg"), "x")

    def test_get_param_rules_unknown_without_default(self):
        """无默认映射时未知工具返回空字典"""
        config = HookFrameworkConfig(framework="fw")
        rules = config.get_param_rules("unknown")
        self.assertEqual(rules, {})

    def test_list_tools(self):
        """列出所有已映射工具"""
        tools = self.config.list_tools()
        self.assertEqual(len(tools), 3)
        self.assertIn("execute", tools)
        self.assertIn("http_get", tools)
        self.assertIn("read_file", tools)

    def test_list_tools_sorted(self):
        """工具列表按字母排序"""
        tools = self.config.list_tools()
        self.assertEqual(tools, sorted(tools))


class TestHookRegistry(unittest.TestCase):
    """HookRegistry 加载与查询测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="hook_reg_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_yaml(self, data: dict, filename: str) -> str:
        path = os.path.join(self._tmpdir, filename)
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f)
        return path

    def test_empty_directory(self):
        """空配置目录不报错"""
        registry = HookRegistry(config_dir=self._tmpdir)
        self.assertEqual(registry.framework_count, 0)

    def test_load_single_framework(self):
        """加载单个框架配置"""
        self._write_yaml({
            "framework": "test-fw",
            "version": "1.0",
            "tool_mappings": {
                "execute": {"event_type": "exec"},
            }
        }, "test_fw.yaml")
        registry = HookRegistry(config_dir=self._tmpdir)
        self.assertEqual(registry.framework_count, 1)
        self.assertIn("test-fw", registry.list_frameworks())

    def test_load_multiple_frameworks(self):
        """加载多个框架配置"""
        self._write_yaml({"framework": "fw1", "tool_mappings": {}}, "fw1.yaml")
        self._write_yaml({"framework": "fw2", "tool_mappings": {}}, "fw2.yaml")
        registry = HookRegistry(config_dir=self._tmpdir)
        self.assertEqual(registry.framework_count, 2)
        self.assertIn("fw1", registry.list_frameworks())
        self.assertIn("fw2", registry.list_frameworks())

    def test_get_config_returns_correct_config(self):
        """get_config 返回正确配置"""
        self._write_yaml({
            "framework": "my-fw",
            "version": "3.0",
            "description": "My framework",
            "tool_mappings": {
                "run": {"event_type": "exec", "param_rules": {"exe": "input.cmd"}},
            }
        }, "my_fw.yaml")
        registry = HookRegistry(config_dir=self._tmpdir)
        config = registry.get_config("my-fw")
        self.assertIsNotNone(config)
        self.assertEqual(config.framework, "my-fw")
        self.assertEqual(config.version, "3.0")
        self.assertEqual(config.get_event_type("run"), "exec")

    def test_get_config_nonexistent(self):
        """获取不存在的框架返回 None"""
        registry = HookRegistry(config_dir=self._tmpdir)
        self.assertIsNone(registry.get_config("nonexistent"))

    def test_invalid_yaml_not_crash(self):
        """无效 YAML 不导致崩溃"""
        path = os.path.join(self._tmpdir, "invalid.yaml")
        with open(path, "w") as f:
            f.write("not: valid: yaml: [")
        registry = HookRegistry(config_dir=self._tmpdir)
        # 不应抛出异常
        self.assertEqual(registry.framework_count, 0)

    def test_missing_framework_key_skipped(self):
        """缺少 framework 键的 YAML 被跳过"""
        self._write_yaml({"name": "no-framework-key"}, "bad.yaml")
        registry = HookRegistry(config_dir=self._tmpdir)
        self.assertEqual(registry.framework_count, 0)

    def test_register_framework_manually(self):
        """手动注册框架"""
        registry = HookRegistry(config_dir=self._tmpdir)
        config = HookFrameworkConfig(
            framework="manual-fw",
            tool_mappings={"test": ToolMapping("test", "net_conn")},
        )
        registry.register_framework("manual-fw", config)
        self.assertEqual(registry.framework_count, 1)
        self.assertEqual(
            registry.get_config("manual-fw").get_event_type("test"), "net_conn")

    def test_default_mapping_from_yaml(self):
        """从 YAML 加载默认映射"""
        self._write_yaml({
            "framework": "with-default",
            "tool_mappings": {},
            "default_mapping": {
                "event_type": "exec",
                "param_rules": {"default": "true"},
            }
        }, "default_fw.yaml")
        registry = HookRegistry(config_dir=self._tmpdir)
        config = registry.get_config("with-default")
        self.assertIsNotNone(config.default_mapping)
        self.assertEqual(config.default_mapping.event_type, "exec")

    def test_capture_mode_from_yaml(self):
        """从 YAML 加载 capture_mode"""
        self._write_yaml({
            "framework": "strace-fw",
            "capture_mode": "strace",
            "tool_mappings": {},
        }, "strace_fw.yaml")
        registry = HookRegistry(config_dir=self._tmpdir)
        config = registry.get_config("strace-fw")
        self.assertEqual(config.capture_mode, "strace")

    def test_hook_config_from_yaml(self):
        """从 YAML 加载 hook_config"""
        self._write_yaml({
            "framework": "hook-fw",
            "tool_mappings": {},
            "hook_config": {"pre_tool_timeout": 5.0, "post_tool_async": True},
        }, "hook_fw.yaml")
        registry = HookRegistry(config_dir=self._tmpdir)
        config = registry.get_config("hook-fw")
        self.assertEqual(config.hook_config["pre_tool_timeout"], 5.0)
        self.assertTrue(config.hook_config["post_tool_async"])

    def test_get_registry_singleton(self):
        """get_registry 返回单例"""
        r1 = get_registry(config_dir=self._tmpdir)
        r2 = get_registry()
        self.assertIs(r1, r2)


if __name__ == "__main__":
    unittest.main()
