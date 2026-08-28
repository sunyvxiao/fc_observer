# -*- coding: utf-8 -*-
"""
mcp_bridge/semantic_guard.py — 浅层语义保护层（P2-7）

黑盒 Agent（WorkBuddy）仅提供浅层语义（工具名 + 参数摘要），
本模块对申报数据做保护性转换，防止恶意/畸形申报破坏监测管线:

1. 工具名 → 事件类型映射
   - 优先复用 HookRegistry（YAML 配置的框架工具映射）
   - registry 未命中/不可用时回退 RawEventFactory.classify_tool 内置分类表
   - 两者均为 exec 兜底，任何工具名都不抛异常

2. 参数摘要脱敏/截断（sanitize_args）
   - 敏感键脱敏: password/token/secret/credential/auth/cookie 等 → "***"
   - 字符串截断: 超长字符串截断到 max_str_len
   - 规模上限: dict 键数 / list 项数 / 嵌套深度
   - 防御性: 循环引用、非 JSON 类型、异常输入一律安全降级，不抛异常

3. 结果摘要截断（sanitize_text）

产出为"可安全进入监测管线的参数摘要"，P3 mcp_report_collector 直接消费。
"""

import logging
from typing import Any, Dict, Optional, Tuple

try:
    from adapter.hook_registry import get_registry
except ImportError:  # pragma: no cover
    from hook_registry import get_registry

from observer_core.monitoring.raw_event_factory import classify_tool

logger = logging.getLogger(__name__)

# ── 保护参数（默认值）───────────────────────────────────────────────────────
DEFAULT_FRAMEWORK = "pydantic-deep"
DEFAULT_MAX_STR_LEN = 256            # 字符串截断上限
DEFAULT_MAX_DICT_ITEMS = 100         # dict 键数上限
DEFAULT_MAX_LIST_ITEMS = 50          # list 项数上限
DEFAULT_MAX_DEPTH = 4                # 嵌套深度上限

# 敏感键片段（键名小写后子串匹配即脱敏）
SENSITIVE_KEY_FRAGMENTS = (
    "password", "passwd", "pwd", "token", "secret", "credential",
    "authorization", "auth", "cookie", "api_key", "apikey",
    "access_key", "private_key", "session_key",
)

MASK = "***"
TRUNCATED_SUFFIX = "...[truncated]"


def _load_registry_safely():
    """加载 HookRegistry；任何失败返回 None（语义保护不因配置问题崩溃）。"""
    try:
        return get_registry()
    except Exception as e:  # pragma: no cover
        logger.warning(f"SemanticGuard: HookRegistry 加载失败: {e}")
        return None


class SemanticGuard:
    """
    浅层语义保护器。

    用法:
        guard = SemanticGuard()
        event_type, safe_args = guard.protect("read_file",
                                              {"path": "/etc/passwd"})
    """

    def __init__(self, framework: str = DEFAULT_FRAMEWORK,
                 registry=None,
                 max_str_len: int = DEFAULT_MAX_STR_LEN,
                 max_dict_items: int = DEFAULT_MAX_DICT_ITEMS,
                 max_list_items: int = DEFAULT_MAX_LIST_ITEMS,
                 max_depth: int = DEFAULT_MAX_DEPTH):
        self.framework = framework
        self._registry = registry if registry is not None else \
            _load_registry_safely()
        self.max_str_len = max_str_len
        self.max_dict_items = max_dict_items
        self.max_list_items = max_list_items
        self.max_depth = max_depth

    # ── 工具名 → 事件类型 ──────────────────────────────────────────────

    def map_tool_to_event(self, tool_name: str) -> str:
        """
        工具名 → 事件类型（"exec" | "file_open" | "net_conn"）。

        优先级: HookRegistry 命中 → classify_tool 内置分类表 → "exec"。
        任何输入（None/空串/超长）都不抛异常。
        """
        tool = str(tool_name or "").lower().strip()
        if tool and self._registry is not None:
            try:
                config = self._registry.get_config(self.framework)
                if config is not None:
                    mapped = config.get_event_type(tool)
                    if mapped in ("exec", "file_open", "net_conn"):
                        return mapped
            except Exception as e:  # pragma: no cover
                logger.warning(f"SemanticGuard: registry 查询失败: {e}")
        return classify_tool(tool)

    def is_read_tool(self, tool_name: str) -> bool:
        """判断工具是否为只读文件操作（file_open 且非写类工具）。"""
        tool = str(tool_name or "").lower().strip()
        if self._registry is not None:
            try:
                config = self._registry.get_config(self.framework)
                if config is not None:
                    rules = config.get_param_rules(tool)
                    file_op = rules.get("file_op", "")
                    if file_op and '"read"' in str(file_op):
                        return True
            except Exception:  # pragma: no cover
                pass
        from observer_core.monitoring.raw_event_factory import READ_TOOLS
        return tool in READ_TOOLS

    # ── 参数摘要脱敏/截断 ──────────────────────────────────────────────

    def _is_sensitive_key(self, key: str) -> bool:
        key_l = str(key).lower()
        return any(frag in key_l for frag in SENSITIVE_KEY_FRAGMENTS)

    def sanitize_text(self, text: Any, *, mask: bool = False) -> str:
        """字符串（或任意标量）→ 截断后的安全文本。"""
        if mask:
            return MASK
        s = text if isinstance(text, str) else str(text)
        if len(s) > self.max_str_len:
            return s[:self.max_str_len] + TRUNCATED_SUFFIX
        return s

    def _sanitize_value(self, value: Any, depth: int) -> Any:
        """递归脱敏/截断（防御性实现：任何异常输入安全降级）。"""
        if depth > self.max_depth:
            return self.sanitize_text(value)[:self.max_str_len]
        try:
            if isinstance(value, dict):
                out: Dict[str, Any] = {}
                for k, v in value.items():
                    if len(out) >= self.max_dict_items:
                        break
                    key = self.sanitize_text(k)[:self.max_str_len]
                    if self._is_sensitive_key(k):
                        out[key] = MASK
                    else:
                        out[key] = self._sanitize_value(v, depth + 1)
                return out
            if isinstance(value, (list, tuple)):
                return [self._sanitize_value(v, depth + 1)
                        for v in list(value)[:self.max_list_items]]
            if isinstance(value, str):
                return self.sanitize_text(value)
            if isinstance(value, (int, float, bool)) or value is None:
                return value
            # 其他类型（set/bytes/对象等）→ 字符串降级
            return self.sanitize_text(value)
        except Exception:  # 防御: 循环引用等极端输入不破坏管线
            return self.sanitize_text(value)[:self.max_str_len]

    def sanitize_args(self, tool_args: Any) -> Dict[str, Any]:
        """
        工具参数摘要脱敏/截断。

        非 dict 输入安全降级（str 化后包裹）；循环引用/深嵌套不抛异常。
        """
        if not isinstance(tool_args, dict):
            return {"_raw": self.sanitize_text(tool_args)}
        return self._sanitize_value(tool_args, depth=0) or {}

    def sanitize_result(self, result: Any) -> Optional[str]:
        """工具结果摘要截断（None → None）。"""
        if result is None:
            return None
        return self.sanitize_text(result)

    # ── 组合入口 ──────────────────────────────────────────────────────

    def protect(self, tool_name: str,
                tool_args: Optional[Dict[str, Any]]) -> Tuple[str, Dict[str, Any]]:
        """
        组合保护: 工具名映射 + 参数摘要脱敏截断。

        Returns:
            (event_type, 安全参数摘要)；任何输入不抛异常。
        """
        return self.map_tool_to_event(tool_name), \
            self.sanitize_args(tool_args)
