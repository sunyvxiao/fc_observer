# -*- coding: utf-8 -*-
"""
mcp_bridge — Windows WorkBuddy 降级监测的 MCP 申报通道（P1）

组成:
- schemas.py : 三类申报数据模型（report_tool_call/report_action/report_session）
- server.py  : 标准 MCP Server（官方 mcp SDK，HTTP+SSE）+ 申报 broker

用法:
    python -m mcp_bridge --host 127.0.0.1 --port 8765

WorkBuddy 以 MCP client 接入 /sse 端点后，调用三个申报 tools 完成行为申报；
申报流由 mcp_report_collector（P3）消费并转入统一监测管线。
"""

from .schemas import (  # noqa: F401
    MAX_ACTION_NAME_LEN,
    MAX_ACTION_TYPE_LEN,
    MAX_AGENT_ID_LEN,
    MAX_DETAIL_ITEMS,
    MAX_RESULT_LEN,
    MAX_SESSION_ID_LEN,
    MAX_SESSION_TYPE_LEN,
    MAX_TOOL_ARGS_ITEMS,
    MAX_TOOL_NAME_LEN,
    REPORT_SCHEMAS,
    REPORT_TOOL_NAMES,
    SESSION_STATUSES,
    TOOL_CALL_ACTION_TYPES,
    TOOL_REPORT_ACTION,
    TOOL_REPORT_SESSION,
    TOOL_REPORT_TOOL_CALL,
    ReportActionInput,
    ReportSessionInput,
    ReportToolCallInput,
)
from .server import (  # noqa: F401
    McpReportBroker,
    build_sse_app,
    create_server,
    mcp_sdk_available,
    run_server,
    run_server_async,
)
from .semantic_guard import (  # noqa: F401
    DEFAULT_FRAMEWORK,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_DICT_ITEMS,
    DEFAULT_MAX_LIST_ITEMS,
    DEFAULT_MAX_STR_LEN,
    MASK,
    SENSITIVE_KEY_FRAGMENTS,
    SemanticGuard,
)
from .validation import (  # noqa: F401
    DEFAULT_MAX_PAYLOAD_FIELD_BYTES,
    DEFAULT_MAX_REPORT_BYTES,
    RateLimiter,
    ReportValidationError,
    ReportValidator,
    default_rate_limiter,
    default_validator,
)

__all__ = [
    "McpReportBroker",
    "ReportActionInput",
    "ReportSessionInput",
    "ReportToolCallInput",
    "ReportValidationError",
    "ReportValidator",
    "RateLimiter",
    "default_validator",
    "default_rate_limiter",
    "DEFAULT_MAX_REPORT_BYTES",
    "DEFAULT_MAX_PAYLOAD_FIELD_BYTES",
    "SemanticGuard",
    "DEFAULT_FRAMEWORK",
    "MASK",
    "REPORT_SCHEMAS",
    "REPORT_TOOL_NAMES",
    "TOOL_REPORT_ACTION",
    "TOOL_REPORT_SESSION",
    "TOOL_REPORT_TOOL_CALL",
    "create_server",
    "build_sse_app",
    "mcp_sdk_available",
    "run_server",
    "run_server_async",
]
