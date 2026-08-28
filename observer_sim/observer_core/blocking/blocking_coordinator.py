"""
BlockingCoordinator — 三级阻断协调器

核心职责:
1. 三级路由: 根据 Decision.tier 分发到对应处理器
2. CommandSender 联动: 通过反向管道下发阻断指令
3. AgentViolationTracker 集成: 违规计数 + 自动升级

三级阻断 (定稿 5.3):
- Tier1 SoftReport: 操作放行 + 记录日志 + 产生告警
- Tier2 BlockAccess: 返回 EPERM + 阻断原因 + 反向管道 block_event
- Tier3 HardInterrupt: 终止进程树 + 证据紧急写入 + 反向管道 terminate_process
"""

import os
import json
import logging
from typing import List, Optional, Dict
from dataclasses import dataclass, field
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.event import NormalizedEvent
from models.risk import (
    RiskAssessment, Decision, DecisionAction, ActionTier, BlockingResult
)
from models.command import Command, CmdType
from models.virtual_clock import VirtualClock
from observer_core.blocking.command_sender import MockCommandSender, ICommandSender
from observer_core.blocking.violation_tracker import AgentViolationTracker

logger = logging.getLogger(__name__)


@dataclass
class BlockEvent:
    """阻断事件记录"""
    timestamp_ns: int
    event_id: str
    agent_id: str
    tier: ActionTier
    action: DecisionAction
    reason: str
    cmd_id: str = ""
    blocked: bool = False
    escalated: bool = False
    session_id: str = ""  # 会话维度（修订 2.1）


class SoftReportHandler:
    """
    Tier1 软报告处理器。

    对 Agent 的影响: 无 — 操作正常执行
    系统动作:
    - JSON 审计日志写入
    - 控制台告警
    - 更新事件计数器
    反向管道: 发送 allow (确认放行)
    """

    def __init__(self, sender: ICommandSender, clock: VirtualClock):
        self._sender = sender
        self._clock = clock

    def execute(self, event: NormalizedEvent, decision: Decision) -> BlockingResult:
        """执行 Tier1 软报告"""
        cmd_id = self._sender.next_cmd_id()

        # 发送 allow 指令
        cmd = Command.make_allow(
            cmd_id=cmd_id,
            event_id=event.raw.event_id,
            timestamp_ns=self._clock.now_ns(),
        )
        self._sender.send_command(cmd)

        logger.info(
            f"[Tier1 SoftReport] Agent={event.agent_id} "
            f"event={event.raw.event_id} -> ALLOW"
        )

        return BlockingResult(
            blocked=False,
            tier=ActionTier.TIER1,
            reason=decision.reason,
            cmd_id=cmd_id,
            event_id=event.raw.event_id,
            details="操作放行，记录告警日志",
        )


class BlockAccessHandler:
    """
    Tier2 阻止访问处理器。

    对 Agent 的影响: 操作被阻止，系统继续运行 — 模拟返回 EPERM
    系统动作:
    - 事件标记 blocked
    - 审计日志写入
    - 生成阻断原因文本
    - 阻断计数器 +1
    反向管道: 发送 block_event (返回 EPERM)
    """

    def __init__(self, sender: ICommandSender, clock: VirtualClock):
        self._sender = sender
        self._clock = clock

    def execute(self, event: NormalizedEvent, decision: Decision) -> BlockingResult:
        """执行 Tier2 阻断"""
        cmd_id = self._sender.next_cmd_id()

        # 发送 block_event 指令
        cmd = Command.make_block(
            cmd_id=cmd_id,
            event_id=event.raw.event_id,
            pid=event.raw.pid,
            reason=decision.reason,
            timestamp_ns=self._clock.now_ns(),
        )
        self._sender.send_command(cmd)

        logger.warning(
            f"[Tier2 BlockAccess] Agent={event.agent_id} "
            f"event={event.raw.event_id} -> BLOCKED (EPERM)"
        )

        return BlockingResult(
            blocked=True,
            tier=ActionTier.TIER2,
            reason=decision.reason,
            cmd_id=cmd_id,
            event_id=event.raw.event_id,
            details=f"操作被阻止: {decision.reason}",
        )


class HardInterruptHandler:
    """
    Tier3 硬中断处理器。

    对 Agent 的影响: Agent 进程树被终止 — 模拟 SIGTERM→SIGKILL
    系统动作:
    - 标记 Agent 所有进程 terminated
    - 证据链紧急写入
    - 进程树清理
    - 完整事故报告
    - 最高优先级告警
    反向管道: 发送 terminate_process (终止进程树)
    """

    def __init__(self, sender: ICommandSender, clock: VirtualClock):
        self._sender = sender
        self._clock = clock

    def execute(self, event: NormalizedEvent, decision: Decision) -> BlockingResult:
        """执行 Tier3 硬中断"""
        cmd_id = self._sender.next_cmd_id()

        # 发送 terminate_process 指令
        cmd = Command.make_terminate(
            cmd_id=cmd_id,
            pid=event.raw.pid,
            reason=decision.reason,
            timestamp_ns=self._clock.now_ns(),
        )
        self._sender.send_command(cmd)

        logger.critical(
            f"[Tier3 HardInterrupt] Agent={event.agent_id} "
            f"pid={event.raw.pid} -> TERMINATED"
        )

        return BlockingResult(
            blocked=True,
            tier=ActionTier.TIER3,
            reason=decision.reason,
            cmd_id=cmd_id,
            event_id=event.raw.event_id,
            details=f"Agent 进程树已终止: {decision.reason}",
        )


class BlockingCoordinator:
    """
    三级阻断协调器。

    接收 DecisionEngine 的 Decision，根据 tier 路由到对应处理器。
    集成 AgentViolationTracker 进行违规计数和自动升级。
    通过 CommandSender 向 C++ 探针层发送反向管道指令。
    """

    def __init__(self, clock: VirtualClock,
                 sender: ICommandSender = None,
                 output_dir: str = "output"):
        """
        Args:
            clock: 虚拟时钟
            sender: 指令发送器（默认使用 MockCommandSender）
            output_dir: 输出目录
        """
        self._clock = clock
        self._sender = sender or MockCommandSender()
        self._output_dir = output_dir

        # 三级处理器
        self._tier1 = SoftReportHandler(self._sender, clock)
        self._tier2 = BlockAccessHandler(self._sender, clock)
        self._tier3 = HardInterruptHandler(self._sender, clock)

        # 违规追踪器
        self._tracker = AgentViolationTracker(clock)

        # 阻断事件历史
        self._block_events: List[BlockEvent] = []

    def set_output_dir(self, output_dir: str):
        """
        动态设置输出目录（用于支持分类目录结构）。

        Args:
            output_dir: 新的输出目录
        """
        self._output_dir = output_dir

    @property
    def tracker(self) -> AgentViolationTracker:
        return self._tracker

    @property
    def sender(self) -> ICommandSender:
        return self._sender

    @property
    def block_events(self) -> List[BlockEvent]:
        return list(self._block_events)

    def execute(self, event: NormalizedEvent, decision: Decision) -> BlockingResult:
        """
        执行阻断决策。

        流程:
        1. 检查 Agent 是否已终止
        2. 记录违规并检查升级
        3. 根据最终 tier 路由到对应处理器
        4. 记录阻断事件
        """
        agent_id = event.agent_id
        # 会话维度（修订 2.1）：升级计数按会话隔离，避免同一 agent_id
        # 下不同会话的违规互相叠加污染单事件判定
        session_id = getattr(event.raw, "session_id", None) or ""

        # 检查 Agent 会话是否已终止
        if self._tracker.is_terminated(agent_id, session_id):
            logger.warning(
                f"[BlockingCoordinator] Agent {agent_id} "
                f"(session={session_id}) already terminated, dropping event"
            )
            return BlockingResult(
                blocked=True,
                tier=ActionTier.TIER3,
                reason="Agent 会话已终止",
                event_id=event.raw.event_id,
                details="Agent 会话已被终止，后续事件丢弃",
            )

        # 确定初始 tier
        initial_tier = decision.tier

        # 对于有风险的事件，记录违规并检查升级
        if decision.action != DecisionAction.ALLOW:
            effective_tier = self._tracker.record_violation(
                agent_id=agent_id,
                tier=initial_tier,
                event_id=event.raw.event_id,
                reason=decision.reason,
                session_id=session_id or None,
            )
        else:
            effective_tier = initial_tier

        # 根据 tier 路由到对应处理器
        if effective_tier == ActionTier.TIER3:
            result = self._tier3.execute(event, decision)
            self._tracker.mark_terminated(agent_id, session_id or None)
        elif effective_tier == ActionTier.TIER2:
            result = self._tier2.execute(event, decision)
        else:
            result = self._tier1.execute(event, decision)

        # 记录阻断事件
        block_event = BlockEvent(
            timestamp_ns=self._clock.now_ns(),
            event_id=event.raw.event_id,
            agent_id=agent_id,
            tier=effective_tier,
            action=decision.action,
            reason=decision.reason,
            cmd_id=result.cmd_id,
            blocked=result.blocked,
            escalated=(effective_tier != initial_tier),
            session_id=session_id,
        )
        self._block_events.append(block_event)

        return result

    def get_statistics(self) -> Dict:
        """获取阻断统计"""
        stats = {
            "total": len(self._block_events),
            "tier1": sum(1 for e in self._block_events if e.tier == ActionTier.TIER1),
            "tier2": sum(1 for e in self._block_events if e.tier == ActionTier.TIER2),
            "tier3": sum(1 for e in self._block_events if e.tier == ActionTier.TIER3),
            "blocked": sum(1 for e in self._block_events if e.blocked),
            "escalated": sum(1 for e in self._block_events if e.escalated),
        }
        return stats

    def save_evidence(self, filepath: str = None) -> str:
        """
        保存证据链（紧急写入）。

        将所有阻断事件记录保存为 JSON 文件。
        """
        if filepath is None:
            audit_dir = os.path.join(self._output_dir, "audit")
            os.makedirs(audit_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(audit_dir, f"blocking_evidence_{ts}.json")
        else:
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        data = {
            "export_time": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "events": [
                {
                    "timestamp_ns": e.timestamp_ns,
                    "event_id": e.event_id,
                    "agent_id": e.agent_id,
                    "tier": e.tier.value,
                    "action": e.action.value,
                    "reason": e.reason,
                    "cmd_id": e.cmd_id,
                    "blocked": e.blocked,
                    "escalated": e.escalated,
                    "session_id": e.session_id,
                }
                for e in self._block_events
            ],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        logger.info(f"[BlockingCoordinator] Evidence saved to {filepath}")
        return filepath

    def reset(self) -> None:
        """重置协调器状态"""
        self._block_events.clear()
        self._tracker.reset()
        if isinstance(self._sender, MockCommandSender):
            self._sender.clear()
