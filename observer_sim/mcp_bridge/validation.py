# -*- coding: utf-8 -*-
"""
mcp_bridge/validation.py — 申报校验与安全层（P1-6）

职责（防止申报数据破坏监测管线）:
1. 报文大小限制: 单次申报 JSON 序列化大小上限（防超大报文拖垮管道）
2. 字段级校验: schema 约束 + 枚举约束（action_type/status）+ 容器规模上限
3. 频率限制: 按 agent_id 滑动窗口限流（防恶意/故障申报风暴）

被拒申报返回 {"status": "rejected", "reason": ...} 结构化结果，
Server 不抛异常、不崩溃、不落盘。
"""

import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError

from .schemas import (
    MAX_DETAIL_ITEMS,
    MAX_TOOL_ARGS_ITEMS,
    SESSION_STATUSES,
    TOOL_CALL_ACTION_TYPES,
    TOOL_REPORT_ACTION,
    TOOL_REPORT_SESSION,
    TOOL_REPORT_TOOL_CALL,
    ReportActionInput,
    ReportSessionInput,
    ReportToolCallInput,
)

# 单次申报报文大小上限（序列化后字节数）
DEFAULT_MAX_REPORT_BYTES = 64 * 1024  # 64 KB
# tool_args / detail 嵌套序列化大小上限（总报文限制的子集，先于总限制给出明确原因）
DEFAULT_MAX_PAYLOAD_FIELD_BYTES = 16 * 1024  # 16 KB


class ReportValidationError(Exception):
    """申报校验失败（携带拒绝原因，供 handler 返回结构化结果）"""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ReportValidator:
    """
    申报校验器。

    - check_size: 报文大小限制
    - validate:   按 tool 名分发到三类 schema 校验 + 枚举/规模约束
    """

    def __init__(self, max_report_bytes: int = DEFAULT_MAX_REPORT_BYTES,
                 max_payload_field_bytes: int = DEFAULT_MAX_PAYLOAD_FIELD_BYTES):
        self.max_report_bytes = max_report_bytes
        self.max_payload_field_bytes = max_payload_field_bytes

    # ── 报文大小 ─────────────────────────────────────────────────────────

    def check_size(self, arguments: Dict[str, Any]) -> Optional[str]:
        """
        校验单次申报报文大小。

        Returns:
            拒绝原因字符串；合法返回 None
        """
        try:
            size = len(json.dumps(arguments, ensure_ascii=False,
                                  default=str).encode("utf-8"))
        except (TypeError, ValueError):
            return "unserializable_report"
        if size > self.max_report_bytes:
            return f"report_too_large (max {self.max_report_bytes} bytes)"
        return None

    # ── 字段级校验 ───────────────────────────────────────────────────────

    def _check_container_field(self, field_name: str, value: Any,
                               max_items: int) -> None:
        """校验容器字段规模（键数 + 序列化大小）"""
        if value is None:
            return
        if not isinstance(value, dict):
            raise ReportValidationError(
                f"invalid_{field_name} (expected object)")
        if len(value) > max_items:
            raise ReportValidationError(
                f"{field_name}_too_many_items (max {max_items})")
        try:
            size = len(json.dumps(value, ensure_ascii=False,
                                  default=str).encode("utf-8"))
        except (TypeError, ValueError):
            raise ReportValidationError(f"unserializable_{field_name}")
        if size > self.max_payload_field_bytes:
            raise ReportValidationError(
                f"{field_name}_too_large "
                f"(max {self.max_payload_field_bytes} bytes)")

    def validate(self, tool_name: str,
                 arguments: Dict[str, Any]) -> Tuple[Any, Dict[str, Any]]:
        """
        按 tool 名分发校验。

        Returns:
            (模型实例, 规范化申报字典)

        Raises:
            ReportValidationError: 校验失败（携带原因）
        """
        if tool_name == TOOL_REPORT_TOOL_CALL:
            model = self.validate_tool_call(arguments)
        elif tool_name == TOOL_REPORT_ACTION:
            model = self.validate_action(arguments)
        elif tool_name == TOOL_REPORT_SESSION:
            model = self.validate_session(arguments)
        else:
            raise ReportValidationError(f"unknown_tool {tool_name}")
        return model

    def validate_tool_call(self, arguments: Dict[str, Any]) -> ReportToolCallInput:
        """校验工具调用申报"""
        try:
            model = ReportToolCallInput(**arguments)
        except ValidationError as e:
            raise ReportValidationError(self._first_error(e))
        if model.action_type not in TOOL_CALL_ACTION_TYPES:
            raise ReportValidationError(
                f"invalid_action_type (allowed: "
                f"{'/'.join(TOOL_CALL_ACTION_TYPES)})")
        self._check_container_field("tool_args", model.tool_args,
                                    MAX_TOOL_ARGS_ITEMS)
        return model

    def validate_action(self, arguments: Dict[str, Any]) -> ReportActionInput:
        """校验通用动作申报"""
        try:
            model = ReportActionInput(**arguments)
        except ValidationError as e:
            raise ReportValidationError(self._first_error(e))
        self._check_container_field("detail", model.detail, MAX_DETAIL_ITEMS)
        return model

    def validate_session(self, arguments: Dict[str, Any]) -> ReportSessionInput:
        """校验会话生命周期申报"""
        try:
            model = ReportSessionInput(**arguments)
        except ValidationError as e:
            raise ReportValidationError(self._first_error(e))
        if model.status not in SESSION_STATUSES:
            raise ReportValidationError(
                f"invalid_status (allowed: {'/'.join(SESSION_STATUSES)})")
        return model

    @staticmethod
    def _first_error(exc: ValidationError) -> str:
        """提取首个 pydantic 校验错误为可读原因"""
        try:
            err = exc.errors()[0]
            loc = ".".join(str(x) for x in err.get("loc", []))
            msg = err.get("msg", "invalid")
            return f"invalid_{loc} ({msg})"
        except (IndexError, AttributeError):
            return "invalid_report"


class RateLimiter:
    """
    按 agent_id 的滑动窗口频率限制。

    - 每个 agent 在 window 内最多 max_per_window 次申报；
    - 超限返回 False（handler 返回 rejected=rate_limited）；
    - 线程安全（server 与测试可能跨线程访问）。
    """

    def __init__(self, max_per_window: int = 60,
                 window_seconds: float = 1.0):
        self.max_per_window = max_per_window
        self.window_seconds = window_seconds
        self._hits: Dict[str, List[float]] = {}
        self._denied = 0
        self._total = 0
        self._lock = threading.Lock()

    def allow(self, agent_id: str, now: float = None) -> bool:
        """判断该 agent 本次申报是否放行（滑动窗口计数）。"""
        now = now if now is not None else time.monotonic()
        with self._lock:
            self._total += 1
            hits = self._hits.setdefault(agent_id, [])
            cutoff = now - self.window_seconds
            hits[:] = [t for t in hits if t > cutoff]
            if len(hits) >= self.max_per_window:
                self._denied += 1
                return False
            hits.append(now)
            return True

    @property
    def denied_count(self) -> int:
        with self._lock:
            return self._denied

    @property
    def total_checks(self) -> int:
        with self._lock:
            return self._total


# 便捷工厂: 默认配置的校验层
def default_validator() -> ReportValidator:
    return ReportValidator()


def default_rate_limiter() -> RateLimiter:
    return RateLimiter()
