# -*- coding: utf-8 -*-
"""
mcp_bridge/server.py — 标准 MCP Server（HTTP+SSE）+ 三类申报 tools（P1-5）

基于官方 mcp SDK（mcp>=2.0）的 MCPServer 实现:
- 传输: HTTP + SSE（GET /sse 建连，POST /messages/ 投递客户端消息）
- 暴露 tools: report_tool_call / report_action / report_session
- 申报数据经 pydantic schema 校验后写入 McpReportBroker:
  * 内存队列（供 P3 mcp_report_collector 消费）
  * 可选 JSONL 落盘（合规留痕）

WorkBuddy 作为 MCP client 接入后，调用申报 tools 即完成行为申报。
"""

import asyncio
import json
import logging
import os
import queue
import threading
import time
import uuid
from typing import Any, Dict, Optional

from .schemas import (
    REPORT_SCHEMAS,
    REPORT_TOOL_NAMES,
    ReportActionInput,
    ReportSessionInput,
    ReportToolCallInput,
    TOOL_REPORT_ACTION,
    TOOL_REPORT_SESSION,
    TOOL_REPORT_TOOL_CALL,
)
from .validation import (
    ReportValidationError,
    ReportValidator,
    RateLimiter,
    default_rate_limiter,
    default_validator,
)

logger = logging.getLogger(__name__)

# mcp SDK 可选依赖（check_env 检测项 + 独立安装）
try:
    from mcp.server.mcpserver import MCPServer  # type: ignore
    _MCP_AVAILABLE = True
except ImportError:  # pragma: no cover
    MCPServer = None  # type: ignore
    _MCP_AVAILABLE = False


def mcp_sdk_available() -> bool:
    """mcp SDK 是否可用（check_env / 单测断言用）"""
    return _MCP_AVAILABLE


# ── 申报 broker（线程安全队列 + 可选 JSONL 留痕）────────────────────────────


class McpReportBroker:
    """
    申报数据中转站。

    - publish(): MCP tool handler 侧入队（uvicorn 事件循环线程）
    - consume(): 采集器侧出队（任意线程），队列满时丢弃最旧并计数
    - 可选 JSONL 落盘: 每行一条申报记录（合规留痕，与队列内容一致）
    """

    MAX_QUEUE_SIZE = 10000

    def __init__(self, jsonl_path: Optional[str] = None,
                 max_queue_size: int = MAX_QUEUE_SIZE):
        self._queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(
            maxsize=max_queue_size)
        self._dropped = 0
        self._received = 0
        self._lock = threading.Lock()
        self._jsonl_path = jsonl_path
        if jsonl_path:
            os.makedirs(os.path.dirname(os.path.abspath(jsonl_path)),
                        exist_ok=True)

    def publish(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        发布一条申报记录，返回回执（event_id/received_at_ms）。

        队列满时丢弃最旧记录并计数（不阻塞 MCP 请求）。
        """
        event_id = report.get("event_id") or f"mcp_{uuid.uuid4().hex[:12]}"
        received_at_ms = report.get("received_at_ms") or int(time.time() * 1000)
        record = dict(report)
        record["event_id"] = event_id
        record["received_at_ms"] = received_at_ms

        with self._lock:
            self._received += 1
            while True:
                try:
                    self._queue.put_nowait(record)
                    break
                except queue.Full:
                    try:
                        self._queue.get_nowait()
                    except queue.Empty:
                        pass
                    self._dropped += 1

        if self._jsonl_path:
            try:
                with open(self._jsonl_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False,
                                       default=str) + "\n")
            except OSError as e:
                logger.warning(f"McpReportBroker: JSONL 落盘失败: {e}")
        return {"event_id": event_id, "received_at_ms": received_at_ms}

    def consume(self, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """阻塞取出下一条申报记录（超时返回 None）"""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def consume_nowait(self) -> Optional[Dict[str, Any]]:
        """非阻塞取出下一条申报记录（无记录返回 None）"""
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            return None

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    @property
    def received_count(self) -> int:
        with self._lock:
            return self._received

    @property
    def dropped_count(self) -> int:
        with self._lock:
            return self._dropped

    @property
    def jsonl_path(self) -> Optional[str]:
        return self._jsonl_path


# ── MCP Server 构建 ──────────────────────────────────────────────────────────


def _build_report_record(tool_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """由规范化申报字典组装完整申报记录（含 type 标记）。"""
    record = {"type": tool_name, "payload": payload}
    return record


def _reject(reason: str) -> Dict[str, Any]:
    """构造结构化拒绝结果（被拒申报不入队、不落盘）。"""
    return {"status": "rejected", "reason": reason}


def create_server(
        broker: Optional[McpReportBroker] = None,
        validator: Optional[ReportValidator] = None,
        rate_limiter: Optional[RateLimiter] = None,
        server_name: str = "workbuddy-observer",
        title: str = "WorkBuddy 降级监测申报通道") -> "MCPServer":
    """
    创建并注册申报 tools 的 MCP Server。

    Args:
        broker: 申报数据中转站（缺省时创建仅内存队列的 broker）
        validator: 申报校验器（缺省为默认配置）
        rate_limiter: 按 agent_id 的滑动窗口限流器（缺省为默认配置）
        server_name: MCP server 名
        title: MCP server 标题

    Returns:
        MCPServer 实例（已注册 report_tool_call/report_action/report_session）
    """
    if not _MCP_AVAILABLE:
        raise RuntimeError(
            "mcp SDK 未安装，无法创建 MCP Server。"
            "请执行: pip install mcp")

    broker = broker or McpReportBroker()
    validator = validator or default_validator()
    rate_limiter = rate_limiter or default_rate_limiter()
    server = MCPServer(name=server_name, title=title, version="1.0")

    @server.tool(description=(
            "申报一次 Agent 工具调用（合规留痕 + 风险提示数据源）。"
            "tool_args 建议只传脱敏后的摘要。" ))
    def report_tool_call(
            agent_id: str,
            tool_name: str,
            tool_args: Optional[Dict[str, Any]] = None,
            session_id: Optional[str] = None,
            timestamp_ms: Optional[int] = None,
            action_type: str = "post",
            result: Optional[str] = None) -> Dict[str, Any]:
        """工具调用申报: 记录 Agent 调用了哪个工具及其参数摘要。"""
        arguments = {
            "agent_id": agent_id, "tool_name": tool_name,
            "tool_args": tool_args or {}, "session_id": session_id,
            "timestamp_ms": timestamp_ms, "action_type": action_type,
            "result": result,
        }
        reason = validator.check_size(arguments)
        if reason:
            return _reject(reason)
        if not rate_limiter.allow(agent_id):
            return _reject("rate_limited")
        try:
            model = validator.validate_tool_call(arguments)
        except ReportValidationError as e:
            return _reject(e.reason)
        received_at_ms = int(time.time() * 1000)
        payload = model.normalized(received_at_ms)
        record = _build_report_record(TOOL_REPORT_TOOL_CALL, payload)
        receipt = broker.publish(record)
        return {"status": "accepted", **receipt}

    @server.tool(description=(
            "申报一次 Agent 通用动作（决策/提示等非工具动作）。"))
    def report_action(
            agent_id: str,
            action_type: str,
            action: str,
            detail: Optional[Dict[str, Any]] = None,
            session_id: Optional[str] = None,
            timestamp_ms: Optional[int] = None) -> Dict[str, Any]:
        """通用动作申报: 记录 Agent 的决策、提示等行为。"""
        arguments = {
            "agent_id": agent_id, "action_type": action_type,
            "action": action, "detail": detail or {},
            "session_id": session_id, "timestamp_ms": timestamp_ms,
        }
        reason = validator.check_size(arguments)
        if reason:
            return _reject(reason)
        if not rate_limiter.allow(agent_id):
            return _reject("rate_limited")
        try:
            model = validator.validate_action(arguments)
        except ReportValidationError as e:
            return _reject(e.reason)
        received_at_ms = int(time.time() * 1000)
        payload = model.normalized(received_at_ms)
        record = _build_report_record(TOOL_REPORT_ACTION, payload)
        receipt = broker.publish(record)
        return {"status": "accepted", **receipt}

    @server.tool(description=(
            "申报一次 Agent 会话生命周期事件（start/end/pause/resume）。"))
    def report_session(
            agent_id: str,
            session_id: str,
            session_type: Optional[str] = None,
            status: str = "start",
            timestamp_ms: Optional[int] = None) -> Dict[str, Any]:
        """会话生命周期申报: 记录会话开始/结束/暂停/恢复。"""
        arguments = {
            "agent_id": agent_id, "session_id": session_id,
            "session_type": session_type, "status": status,
            "timestamp_ms": timestamp_ms,
        }
        reason = validator.check_size(arguments)
        if reason:
            return _reject(reason)
        if not rate_limiter.allow(agent_id):
            return _reject("rate_limited")
        try:
            model = validator.validate_session(arguments)
        except ReportValidationError as e:
            return _reject(e.reason)
        received_at_ms = int(time.time() * 1000)
        payload = model.normalized(received_at_ms)
        record = _build_report_record(TOOL_REPORT_SESSION, payload)
        receipt = broker.publish(record)
        return {"status": "accepted", **receipt}

    # 挂载 broker/校验层引用供外部（采集器/测试）取用
    server._observer_broker = broker  # type: ignore[attr-defined]
    server._observer_validator = validator  # type: ignore[attr-defined]
    server._observer_rate_limiter = rate_limiter  # type: ignore[attr-defined]
    return server


def build_sse_app(server: "MCPServer", *, host: str = "127.0.0.1",
                  sse_path: str = "/sse",
                  message_path: str = "/messages/"):
    """构建 HTTP+SSE 的 Starlette 应用（供嵌入/测试）。"""
    return server.sse_app(sse_path=sse_path, message_path=message_path,
                          host=host)


async def run_server_async(host: str = "127.0.0.1", port: int = 8765,
                           broker: Optional[McpReportBroker] = None,
                           jsonl_path: Optional[str] = None,
                           hook_ingest: Optional[Dict[str, Any]] = None) -> None:
    """以 HTTP+SSE 方式运行申报 Server（阻塞至停止）。

    Args:
        hook_ingest: Hooks 确定性申报摄入配置（Qoder CN P1）。
            {"enabled": True, "path": "/api/hook-report",
             "agent_id_default": "qoder"}
            enabled 为真时，在同端口同应用上追加非 MCP 协议的
            POST 摄入路由（共用同一 broker/校验/限流层）；
            缺省或 enabled 为假时，行为与原实现完全一致。
    """
    broker = broker or McpReportBroker(jsonl_path=jsonl_path)
    server = create_server(broker=broker)
    logger.info(f"MCP 申报 Server 启动: http://{host}:{port}/sse "
                f"(tools: {', '.join(REPORT_TOOL_NAMES)})")

    hook_cfg = hook_ingest or {}
    if hook_cfg.get("enabled"):
        from .http_ingest import (DEFAULT_HOOK_INGEST_PATH,
                                  mount_hook_report_route)
        app = build_sse_app(server, host=host)
        path = str(hook_cfg.get("path") or DEFAULT_HOOK_INGEST_PATH)
        mount_hook_report_route(
            app, path=path, broker=broker,
            validator=server._observer_validator,        # type: ignore[attr-defined]
            rate_limiter=server._observer_rate_limiter,  # type: ignore[attr-defined]
            agent_id_default=str(hook_cfg.get("agent_id_default") or "qoder"))
        logger.info(f"Hook 申报摄入端点: http://{host}:{port}{path}")

        import uvicorn
        config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        await uvicorn.Server(config).serve()
        return

    await server.run_sse_async(host=host, port=port)


def run_server(host: str = "127.0.0.1", port: int = 8765,
               broker: Optional[McpReportBroker] = None,
               jsonl_path: Optional[str] = None,
               hook_ingest: Optional[Dict[str, Any]] = None) -> None:
    """同步入口: 以 HTTP+SSE 方式运行申报 Server（hook_ingest 见 run_server_async）。"""
    asyncio.run(run_server_async(host=host, port=port, broker=broker,
                                 jsonl_path=jsonl_path,
                                 hook_ingest=hook_ingest))
