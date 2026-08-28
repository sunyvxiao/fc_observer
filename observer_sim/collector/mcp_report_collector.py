# -*- coding: utf-8 -*-
"""
collector/mcp_report_collector.py — MCP 申报采集器（P3-8）

实现 ICollector 接口，把 MCP 申报流（McpReportBroker 队列）转换为
RawEvent 流，接入统一监测管线（归一化 / 规则 / 评分 / 研判 / 审计）。

数据流:
    WorkBuddy (MCP client)
        → MCP Server 申报 tools（校验 + 限流，P1）
        → McpReportBroker 队列（+ JSONL 留痕）
        → McpReportCollector（本模块，P3）
            * SemanticGuard.sanitize_args 脱敏/截断（P2 浅层语义保护）
            * RawEventFactory.from_tool_call 统一转换（P0 单一转换点）
        → RawEvent 流 → 归一化 / 规则 / 评分 / 研判 / 审计

三类申报的处理:
    - report_tool_call → RawEvent（主要事件源）
    - report_action   → 不产 RawEvent（动作留痕由 broker JSONL 承担）
    - report_session  → 不产 RawEvent（会话留痕由 broker JSONL 承担）

能力定位（计划决策基线）: 合规留痕 + 风险提示；无 L2/L3 阻断。
"""

import logging
import threading
from typing import Dict, Iterator, Optional

from collector.base_collector import ICollector, CollectorCapabilities
from models.event import RawEvent
from mcp_bridge.schemas import (
    TOOL_REPORT_ACTION,
    TOOL_REPORT_SESSION,
    TOOL_REPORT_TOOL_CALL,
)
from observer_core.monitoring.raw_event_factory import RawEventFactory

logger = logging.getLogger(__name__)


class McpReportCollector(ICollector):
    """
    MCP 申报采集器 —— 申报流 → RawEvent 流的桥。

    消费 McpReportBroker 队列中的申报记录:
    - report_tool_call 记录经浅层语义保护（脱敏/截断）后，
      复用 RawEventFactory 转换为 RawEvent；
    - report_action / report_session 不产事件（仅统计，留痕由 broker 承担）。
    """

    def __init__(self, config: dict,
                 broker=None,
                 guard=None):
        """
        Args:
            config: 配置字典（config.yaml；mcp_report 段可选）
            broker: McpReportBroker 实例（缺省时需 attach 前注入）
            guard:  SemanticGuard 实例（缺省时使用默认框架配置）
        """
        self.config = config or {}
        self.mcp_config = self.config.get("mcp_report", {})
        self.target_agent_id = self.mcp_config.get(
            "target_agent_id", "workbuddy")

        self._broker = broker
        if guard is not None:
            self._guard = guard
        else:
            from mcp_bridge.semantic_guard import SemanticGuard
            self._guard = SemanticGuard(
                framework=self.mcp_config.get(
                    "framework", "pydantic-deep"))

        # 内部状态
        self._attached = False
        self._stop_requested = threading.Event()
        self._poll_timeout = self.mcp_config.get("poll_timeout_s", 0.2)

        # 统计
        self._tool_call_count = 0
        self._action_count = 0
        self._session_count = 0
        self._skipped_count = 0

    # ── ICollector 接口 ─────────────────────────────────────────────────

    def capabilities(self) -> CollectorCapabilities:
        """能力描述: 观测 + 留痕，无阻断（决策基线: 合规留痕+风险提示）"""
        return CollectorCapabilities(
            name="MCPReport",
            can_observe=True,
            can_block_tier2=False,   # 无 L2 阻断
            can_block_tier3=False,   # 无 L3 阻断
            is_transparent=False,    # 依赖 WorkBuddy 主动申报
            performance_overhead="low",
            time_source="realtime_monotonic",
        )

    def attach(self, target_pid: int = 0, agent_id: str = "") -> bool:
        """
        附着到申报源。

        target_pid: 忽略（黑盒 Agent 无真实进程）
        agent_id:   默认 agent 标识（申报记录缺 agent_id 时使用）
        """
        if agent_id:
            self.target_agent_id = agent_id
        if self._broker is None:
            logger.error("McpReportCollector: broker 未注入，无法采集")
            return False
        self._attached = True
        logger.info(f"McpReportCollector attached "
                    f"(agent_id={self.target_agent_id})")
        return True

    def start(self) -> Iterator[RawEvent]:
        """
        开始消费申报流，yield RawEvent。

        阻塞消费 broker 队列；detach() 后当前轮询结束即退出。
        """
        if not self._attached:
            logger.warning("McpReportCollector 未附着（先调 attach）")
            return
        self._stop_requested.clear()

        while not self._stop_requested.is_set():
            record = self._broker.consume(timeout=self._poll_timeout)
            if record is None:
                continue
            event = self._record_to_raw_event(record)
            if event is not None:
                yield event

    def send_command(self, cmd) -> bool:
        """阻断指令: 不支持（无 L2/L3 阻断能力）。"""
        logger.info(f"McpReportCollector 不支持阻断（合规留痕+风险提示）: "
                    f"{getattr(cmd, 'command', cmd)}")
        return False

    def detach(self) -> None:
        """停止采集（start 循环在下个轮询退出）。"""
        self._stop_requested.set()
        self._attached = False
        logger.info("McpReportCollector 已断开")

    def get_process_tree(self) -> dict:
        """黑盒 Agent 无真实进程树；返回已观测 agent 概览。"""
        return {"note": "MCP 申报模式无进程树（黑盒 Agent）"}

    # ── 申报记录 → RawEvent ─────────────────────────────────────────────

    def _record_to_raw_event(self, record: Dict) -> Optional[RawEvent]:
        """单条申报记录 → RawEvent（异常记录安全跳过，不破坏管线）。"""
        try:
            record_type = record.get("type", "")
            payload = record.get("payload")

            if not isinstance(payload, dict):
                # 畸形记录（payload 缺失/非 dict）: 安全跳过
                self._skipped_count += 1
                logger.warning(f"McpReportCollector: 跳过无有效 payload "
                               f"的申报 {record.get('event_id', '?')}")
                return None

            if record_type == TOOL_REPORT_TOOL_CALL:
                return self._tool_call_to_raw_event(record, payload)
            if record_type == TOOL_REPORT_ACTION:
                self._action_count += 1
                return None
            if record_type == TOOL_REPORT_SESSION:
                self._session_count += 1
                return None

            # 未知类型申报: 计数跳过（留痕已在 broker JSONL）
            self._skipped_count += 1
            logger.warning(f"McpReportCollector: 跳过未知申报类型 "
                           f"{record_type!r}")
            return None
        except Exception as e:  # 防御: 畸形申报不破坏采集循环
            self._skipped_count += 1
            logger.warning(f"McpReportCollector: 申报转换失败，已跳过: {e}")
            return None

    def _tool_call_to_raw_event(self, record: Dict,
                                payload: Dict) -> RawEvent:
        """report_tool_call 申报 → RawEvent（脱敏 + 工厂统一转换）。"""
        self._tool_call_count += 1

        tool_name = str(payload.get("tool_name", "") or "")
        agent_id = str(payload.get("agent_id", "") or self.target_agent_id)
        session_id = str(payload.get("session_id", "") or "") or None

        # 浅层语义保护: 参数摘要脱敏/截断（恶意申报不破坏管线）
        safe_args = self._guard.sanitize_args(payload.get("tool_args"))

        # 时间: 毫秒 epoch → 纳秒
        timestamp_ms = payload.get("timestamp_ms") or 0
        try:
            timestamp_ns = int(timestamp_ms) * 1_000_000
        except (TypeError, ValueError):
            timestamp_ns = 0

        # 复用 RawEventFactory（与 CLI 直连/DeepAgent 采集器同一转换点）
        return RawEventFactory.from_tool_call(
            {"tool": tool_name, "input": safe_args},
            event_id=f"mcp_{record.get('event_id', '')}",
            timestamp_ns=timestamp_ns,
            pid=0,              # 黑盒 Agent 无真实 pid
            ppid=0,
            agent_id=agent_id,
            agent_framework="mcp_report",
            session_id=session_id,  # 会话维度（违规升级隔离的关键）
        )

    # ── 统计与访问器 ───────────────────────────────────────────────────

    @property
    def tool_call_count(self) -> int:
        return self._tool_call_count

    @property
    def action_count(self) -> int:
        return self._action_count

    @property
    def session_count(self) -> int:
        return self._session_count

    @property
    def skipped_count(self) -> int:
        return self._skipped_count

    @property
    def guard(self):
        """语义保护器（供高级用法/测试）"""
        return self._guard
