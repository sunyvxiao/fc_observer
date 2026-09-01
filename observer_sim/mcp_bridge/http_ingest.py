# -*- coding: utf-8 -*-
"""
mcp_bridge/http_ingest.py — Hooks 确定性申报摄入端点（Qoder CN P1）

在 MCP Server 同端口同 uvicorn 应用上挂载**非 MCP 协议**的
POST 摄入路由（默认 /api/hook-report），接收 Qoder CN Hook 脚本
（scripts/qoder_hook_reporter.py）转发的工具调用申报。

与 MCP 申报通道共用全部安全层:
- ReportValidator: 报文大小（64KB）/ 字段级校验 / 容器规模上限
- RateLimiter:     按 agent_id 滑动窗口限流
- McpReportBroker: 同一内存队列 + 可选 JSONL 留痕

设计约束:
- 仅监听 127.0.0.1（由 run_server_async 的 host 决定，生产不对外暴露）;
- 被拒申报返回结构化 {"status": "rejected", "reason": ...}，不抛异常;
- hook_ingest.enabled=false 时不挂载任何路由，行为与纯 MCP 模式一致。

数据流:
    Qoder CN PostToolUse Hook → qoder_hook_reporter.py
        → POST /api/hook-report（本模块）
        → Validator + RateLimiter（复用）
        → McpReportBroker → McpReportCollector → RawEventFactory → 管线
"""

import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# 摄入端点默认路径（与 config.yaml mcp_report.hook_ingest.path 对齐）
DEFAULT_HOOK_INGEST_PATH = "/api/hook-report"

# 单请求体读取上限（字节）。申报报文合法性由 Validator 判定，
# 此处仅防恶意超大请求体拖垮事件循环。
_MAX_BODY_BYTES = 256 * 1024


def _build_arguments(body: Dict[str, Any],
                     agent_id_default: str) -> Dict[str, Any]:
    """HTTP 申报体 → report_tool_call 校验入参（与 ReportToolCallInput 对齐）。

    字段语义与 MCP report_tool_call tool 完全一致:
    agent_id / tool_name / tool_args / session_id / timestamp_ms /
    action_type / result。agent_id 缺省时使用配置默认值（"qoder"）。
    """
    agent_id = body.get("agent_id") or agent_id_default
    tool_args = body.get("tool_args")
    if tool_args is None:
        tool_args = {}
    return {
        "agent_id": agent_id,
        "tool_name": body.get("tool_name", ""),
        "tool_args": tool_args,
        "session_id": body.get("session_id"),
        "timestamp_ms": body.get("timestamp_ms"),
        "action_type": body.get("action_type", "post"),
        "result": body.get("result"),
    }


def create_hook_report_handler(broker, validator, rate_limiter,
                               agent_id_default: str = "qoder"):
    """构造 /api/hook-report 的 Starlette 端点处理函数。

    Args:
        broker: McpReportBroker 实例（与 MCP 申报共用同一队列）
        validator: ReportValidator（与 create_server 同配置）
        rate_limiter: RateLimiter（与 create_server 同配置）
        agent_id_default: 申报体未携带 agent_id 时的默认标识

    Returns:
        async 端点: (request) -> JSONResponse
    """
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    import json as _json

    from .schemas import TOOL_REPORT_TOOL_CALL
    from .validation import ReportValidationError

    async def hook_report(request: Request) -> "JSONResponse":
        # 限体读取（防恶意超大请求体）
        raw = await request.body()
        if len(raw) > _MAX_BODY_BYTES:
            return JSONResponse(
                {"status": "rejected", "reason": "request_body_too_large"},
                status_code=413)
        try:
            body = _json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, ValueError):
            return JSONResponse(
                {"status": "rejected", "reason": "invalid_json"},
                status_code=400)
        if not isinstance(body, dict):
            return JSONResponse(
                {"status": "rejected", "reason": "invalid_report "
                 "(expected object)"}, status_code=400)

        arguments = _build_arguments(body, agent_id_default)

        reason = validator.check_size(arguments)
        if reason:
            return JSONResponse(
                {"status": "rejected", "reason": reason}, status_code=413)
        if not rate_limiter.allow(str(arguments.get("agent_id") or "")):
            return JSONResponse(
                {"status": "rejected", "reason": "rate_limited"},
                status_code=429)
        try:
            model = validator.validate_tool_call(arguments)
        except ReportValidationError as e:
            return JSONResponse(
                {"status": "rejected", "reason": e.reason}, status_code=400)

        received_at_ms = int(time.time() * 1000)
        payload = model.normalized(received_at_ms)
        record = {"type": TOOL_REPORT_TOOL_CALL, "payload": payload}
        receipt = broker.publish(record)
        return JSONResponse({"status": "accepted", **receipt},
                            status_code=200)

    return hook_report


def build_hook_report_route(path: str, broker, validator, rate_limiter,
                            agent_id_default: str = "qoder"):
    """构建可挂载的 Starlette Route（POST {path}）。"""
    from starlette.routing import Route

    return Route(path, endpoint=create_hook_report_handler(
        broker, validator, rate_limiter, agent_id_default),
        methods=["POST"])


def mount_hook_report_route(app, *, path: str = DEFAULT_HOOK_INGEST_PATH,
                            broker, validator, rate_limiter,
                            agent_id_default: str = "qoder") -> bool:
    """把申报摄入路由挂到既有 Starlette 应用（MCP sse_app 同应用）。

    Returns:
        True=挂载成功; False=重复路径未挂载（幂等保护）
    """
    for r in getattr(app.router, "routes", []):
        if getattr(r, "path", None) == path:
            logger.warning(f"hook_ingest: 路由 {path} 已存在，跳过挂载")
            return False
    app.router.routes.append(build_hook_report_route(
        path, broker, validator, rate_limiter,
        agent_id_default=agent_id_default))
    logger.info(f"hook_ingest: 已挂载 POST {path}")
    return True
