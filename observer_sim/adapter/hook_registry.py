"""
adapter/hook_registry.py — 统一 Hook 配置注册表

从 YAML 配置文件加载 Agent 框架的工具映射规则。
支持增量扩展：新增 Agent 框架只需添加 YAML 文件，无需修改代码。

用法:
    registry = HookRegistry()
    config = registry.get_config("pydantic-deep")
    event_type = config.map_tool_to_event("read_file")
"""

import os
import glob
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

import yaml

logger = logging.getLogger(__name__)

# 默认配置目录（相对于本文件）
_DEFAULT_CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "hook_configs")


@dataclass
class ToolMapping:
    """单个工具的映射规则"""
    tool_name: str
    event_type: str                 # "exec" | "file_open" | "net_conn"
    param_rules: Dict[str, str] = field(default_factory=dict)
    # param_rules 示例:
    #   {"executable": "input.command.split()[0]", "arguments": "input.command.split()"}


@dataclass
class HookFrameworkConfig:
    """单个 Agent 框架的完整 Hook 配置"""
    framework: str
    version: str = "1.0"
    description: str = ""
    capture_mode: str = "hook"          # "hook" | "strace" | "ebpf"
    tool_mappings: Dict[str, ToolMapping] = field(default_factory=dict)
    default_mapping: Optional[ToolMapping] = None
    hook_config: Dict[str, Any] = field(default_factory=dict)

    def map_tool_to_event(self, tool_name: str) -> Optional[ToolMapping]:
        """根据工具名查找映射规则"""
        return self.tool_mappings.get(tool_name.lower())

    def get_event_type(self, tool_name: str) -> str:
        """获取工具对应的事件类型，未匹配时返回默认"""
        mapping = self.map_tool_to_event(tool_name)
        if mapping:
            return mapping.event_type
        if self.default_mapping:
            return self.default_mapping.event_type
        return "exec"

    def get_param_rules(self, tool_name: str) -> Dict[str, str]:
        """获取工具的参数映射规则"""
        mapping = self.map_tool_to_event(tool_name)
        if mapping:
            return dict(mapping.param_rules)
        if self.default_mapping:
            return dict(self.default_mapping.param_rules)
        return {}

    def list_tools(self) -> List[str]:
        """列出所有已映射的工具名"""
        return sorted(self.tool_mappings.keys())


class HookRegistry:
    """
    统一 Hook 配置注册表。

    从 hook_configs/ 目录自动发现并加载所有 YAML 配置。
    """

    def __init__(self, config_dir: str = None):
        """
        Args:
            config_dir: 配置文件目录（默认: adapter/hook_configs/）
        """
        self._config_dir = config_dir or _DEFAULT_CONFIG_DIR
        self._frameworks: Dict[str, HookFrameworkConfig] = {}
        self._load_all()

    def _load_all(self):
        """加载配置目录下所有 YAML 文件"""
        if not os.path.isdir(self._config_dir):
            logger.warning(f"Hook 配置目录不存在: {self._config_dir}")
            return

        yaml_files = sorted(glob.glob(os.path.join(self._config_dir, "*.yaml")))
        for yaml_file in yaml_files:
            try:
                self.load_framework(yaml_file)
            except Exception as e:
                logger.warning(f"加载 Hook 配置失败: {yaml_file}: {e}")

        logger.info(f"HookRegistry 已加载 {len(self._frameworks)} 个框架: "
                    f"{list(self._frameworks.keys())}")

    def load_framework(self, yaml_path: str) -> Optional[HookFrameworkConfig]:
        """从 YAML 文件加载单个框架配置"""
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "framework" not in data:
            logger.warning(f"无效的 Hook 配置文件: {yaml_path}")
            return None

        framework_name = data["framework"]

        # 解析工具映射
        tool_mappings: Dict[str, ToolMapping] = {}
        for tool_name, mapping_data in data.get("tool_mappings", {}).items():
            tool_mappings[tool_name.lower()] = ToolMapping(
                tool_name=tool_name,
                event_type=mapping_data.get("event_type", "exec"),
                param_rules=mapping_data.get("param_rules", {}),
            )

        # 解析默认映射
        default_data = data.get("default_mapping")
        default_mapping = None
        if default_data:
            default_mapping = ToolMapping(
                tool_name="__default__",
                event_type=default_data.get("event_type", "exec"),
                param_rules=default_data.get("param_rules", {}),
            )

        config = HookFrameworkConfig(
            framework=framework_name,
            version=data.get("version", "1.0"),
            description=data.get("description", ""),
            capture_mode=data.get("capture_mode", "hook"),
            tool_mappings=tool_mappings,
            default_mapping=default_mapping,
            hook_config=data.get("hook_config", {}),
        )

        self._frameworks[framework_name] = config
        logger.debug(f"已加载 Hook 配置: {framework_name} "
                     f"({len(tool_mappings)} 个工具映射)")
        return config

    def get_config(self, framework: str) -> Optional[HookFrameworkConfig]:
        """获取指定框架的配置"""
        return self._frameworks.get(framework)

    def list_frameworks(self) -> List[str]:
        """列出所有已注册的框架"""
        return sorted(self._frameworks.keys())

    def register_framework(self, name: str, config: HookFrameworkConfig):
        """手动注册框架（用于测试或运行时注册）"""
        self._frameworks[name] = config

    @property
    def framework_count(self) -> int:
        return len(self._frameworks)


# ── 全局单例 ──────────────────────────────────────────────────────
_default_registry: Optional[HookRegistry] = None


def get_registry(config_dir: str = None) -> HookRegistry:
    """获取全局 Hook 注册表单例"""
    global _default_registry
    if _default_registry is None:
        _default_registry = HookRegistry(config_dir)
    return _default_registry
