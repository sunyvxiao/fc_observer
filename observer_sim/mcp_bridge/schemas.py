# -*- coding: utf-8 -*-
"""
mcp_bridge/schemas.py — MCP 申报通道的申报数据模型（P1-5）

定义 WorkBuddy（MCP client）向监测系统申报行为时使用的三类申报:

1. ReportToolCall — 工具调用申报（agent_id/tool_name/tool_args 摘要/
   session_id/timestamp/action_type）
2. ReportAction   — 通用动作申报（决策/提示等非工具动作）
3. ReportSession  — 会话生命周期申报（start/end/pause/resume）

设计原则:
- 申报模型与 MCP 工具签名解耦: tool handler 以基本类型入参，
  内部用本模型校验，保证 schema 可独立单测;
- 字段长度/类型约束在此集中定义（P1-6 在 server 层追加大小/频率限制）;
- timestamp_ms 缺省时由 server 填充接收时间（毫秒 epoch）。
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ── 字段长度上限（P1-6 校验层复用）─────────────────────────────────────────
MAX_AGENT_ID_LEN = 64
MAX_TOOL_NAME_LEN = 128
MAX_SESSION_ID_LEN = 128
MAX_ACTION_TYPE_LEN = 64
MAX_ACTION_NAME_LEN = 128
MAX_SESSION_TYPE_LEN = 64
MAX_RESULT_LEN = 4096
MAX_TOOL_ARGS_ITEMS = 100       # tool_args 最多 100 个键
MAX_DETAIL_ITEMS = 100          # detail 最多 100 个键

# tool_call 申报的 action_type 枚举（pre=执行前 / post=执行后）
TOOL_CALL_ACTION_TYPES = ("pre", "post")

# session 申报的 status 枚举
SESSION_STATUSES = ("start", "end", "pause", "resume")

# 申报工具名（MCP tools 对外暴露名）
TOOL_REPORT_TOOL_CALL = "report_tool_call"
TOOL_REPORT_ACTION = "report_action"
TOOL_REPORT_SESSION = "report_session"


class ReportToolCallInput(BaseModel):
    """工具调用申报（report_tool_call tool 的入参模型）"""

    agent_id: str = Field(
        ..., min_length=1, max_length=MAX_AGENT_ID_LEN,
        description="申报方 Agent 标识（如 workbuddy）")
    tool_name: str = Field(
        ..., min_length=1, max_length=MAX_TOOL_NAME_LEN,
        description="被调用的工具名（如 read_file / execute）")
    tool_args: Dict[str, Any] = Field(
        default_factory=dict,
        description="工具调用参数（申报侧应提供摘要而非完整敏感值）")
    session_id: Optional[str] = Field(
        None, max_length=MAX_SESSION_ID_LEN,
        description="会话标识，用于串联同一会话内的申报")
    timestamp_ms: Optional[int] = Field(
        None, ge=0, description="事件发生时间（毫秒 epoch），缺省为服务器接收时间")
    action_type: str = Field(
        "post", max_length=MAX_ACTION_TYPE_LEN,
        description=f"调用阶段: {'/'.join(TOOL_CALL_ACTION_TYPES)}（缺省 post）")
    result: Optional[str] = Field(
        None, max_length=MAX_RESULT_LEN,
        description="工具返回结果摘要（建议截断，缺省无）")

    def normalized(self, received_at_ms: int) -> Dict[str, Any]:
        """转为落盘/入队用的规范化申报字典（timestamp 缺省填充接收时间）"""
        return {
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "session_id": self.session_id,
            "timestamp_ms": (self.timestamp_ms
                             if self.timestamp_ms is not None
                             else received_at_ms),
            "action_type": self.action_type,
            "result": self.result,
        }


class ReportActionInput(BaseModel):
    """通用动作申报（report_action tool 的入参模型）"""

    agent_id: str = Field(
        ..., min_length=1, max_length=MAX_AGENT_ID_LEN,
        description="申报方 Agent 标识")
    action_type: str = Field(
        ..., min_length=1, max_length=MAX_ACTION_TYPE_LEN,
        description="动作类别（如 decision / note / alert）")
    action: str = Field(
        ..., min_length=1, max_length=MAX_ACTION_NAME_LEN,
        description="动作名称（如 risk_notice）")
    detail: Dict[str, Any] = Field(
        default_factory=dict, description="动作附加信息")
    session_id: Optional[str] = Field(
        None, max_length=MAX_SESSION_ID_LEN,
        description="会话标识，用于串联同一会话内的申报")
    timestamp_ms: Optional[int] = Field(
        None, ge=0, description="事件发生时间（毫秒 epoch），缺省为服务器接收时间")

    def normalized(self, received_at_ms: int) -> Dict[str, Any]:
        """转为落盘/入队用的规范化申报字典"""
        return {
            "agent_id": self.agent_id,
            "action_type": self.action_type,
            "action": self.action,
            "detail": self.detail,
            "session_id": self.session_id,
            "timestamp_ms": (self.timestamp_ms
                             if self.timestamp_ms is not None
                             else received_at_ms),
        }


class ReportSessionInput(BaseModel):
    """会话生命周期申报（report_session tool 的入参模型）"""

    agent_id: str = Field(
        ..., min_length=1, max_length=MAX_AGENT_ID_LEN,
        description="申报方 Agent 标识")
    session_id: str = Field(
        ..., min_length=1, max_length=MAX_SESSION_ID_LEN,
        description="会话标识")
    session_type: Optional[str] = Field(
        None, max_length=MAX_SESSION_TYPE_LEN,
        description="会话类型（如 task / chat），缺省无")
    status: str = Field(
        "start", max_length=MAX_ACTION_TYPE_LEN,
        description=f"会话状态: {'/'.join(SESSION_STATUSES)}（缺省 start）")
    timestamp_ms: Optional[int] = Field(
        None, ge=0, description="事件发生时间（毫秒 epoch），缺省为服务器接收时间")

    def normalized(self, received_at_ms: int) -> Dict[str, Any]:
        """转为落盘/入队用的规范化申报字典"""
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "session_type": self.session_type,
            "status": self.status,
            "timestamp_ms": (self.timestamp_ms
                             if self.timestamp_ms is not None
                             else received_at_ms),
        }


# 三类申报模型注册表（校验层按 tool 名分发）
REPORT_SCHEMAS: Dict[str, type] = {
    TOOL_REPORT_TOOL_CALL: ReportToolCallInput,
    TOOL_REPORT_ACTION: ReportActionInput,
    TOOL_REPORT_SESSION: ReportSessionInput,
}

# 全部申报工具名列表（MCP tools/ 发现断言用）
REPORT_TOOL_NAMES: List[str] = [
    TOOL_REPORT_TOOL_CALL,
    TOOL_REPORT_ACTION,
    TOOL_REPORT_SESSION,
]
