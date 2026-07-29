"""
AgentViolationTracker — Agent 违规追踪器

核心职责:
1. 维护每个 Agent 的虚拟时钟滑动窗口违规计数
2. 实现自动升级逻辑: Tier1×3 → Tier2, Tier2×2 → Tier3
3. 窗口过期后自动清除计数（基于虚拟时钟）

升级机制 (定稿 5.4):
- 同一 Agent 在虚拟时钟过去 5 分钟内:
  - tier1_count >= 3 → 升级到 Tier2
  - tier2_count >= 2 → 升级到 Tier3
- 窗口过期后计数器自动清除
"""

import os
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.risk import ActionTier
from models.virtual_clock import VirtualClock

logger = logging.getLogger(__name__)


@dataclass
class ViolationRecord:
    """单条违规记录"""
    timestamp_ns: int
    tier: ActionTier
    event_id: str
    reason: str


@dataclass
class AgentViolationState:
    """单个 Agent 的违规状态"""
    agent_id: str
    violations: List[ViolationRecord] = field(default_factory=list)
    current_tier: ActionTier = ActionTier.TIER1
    is_terminated: bool = False  # Tier3 终止后标记

    @property
    def tier1_count(self) -> int:
        return sum(1 for v in self.violations if v.tier == ActionTier.TIER1)

    @property
    def tier2_count(self) -> int:
        return sum(1 for v in self.violations if v.tier == ActionTier.TIER2)


class AgentViolationTracker:
    """
    Agent 违规追踪器。

    管理所有 Agent 的违规计数和升级逻辑。
    基于虚拟时钟的滑动窗口（默认 5 分钟 = 300_000_000_000 纳秒）。
    """

    # 滑动窗口大小: 虚拟时钟 5 分钟（纳秒）
    WINDOW_SIZE_NS = 5 * 60 * 1_000_000_000  # 300,000,000,000 ns

    # 升级阈值
    TIER1_ESCALATE_THRESHOLD = 3  # Tier1 累计 3 次 → Tier2
    TIER2_ESCALATE_THRESHOLD = 2  # Tier2 累计 2 次 → Tier3

    def __init__(self, clock: VirtualClock, window_size_ns: int = None):
        """
        Args:
            clock: 虚拟时钟实例
            window_size_ns: 滑动窗口大小（纳秒），默认 5 分钟
        """
        self._clock = clock
        self._window_size = window_size_ns or self.WINDOW_SIZE_NS
        self._agents: Dict[str, AgentViolationState] = {}

    def record_violation(self, agent_id: str, tier: ActionTier,
                         event_id: str, reason: str = "") -> ActionTier:
        """
        记录一次违规并检查是否需要升级。

        Args:
            agent_id: Agent ID
            tier: 当前处置等级
            event_id: 关联事件 ID
            reason: 违规原因

        Returns:
            ActionTier: 实际应执行的等级（可能已升级）
        """
        # 获取或创建 Agent 状态
        if agent_id not in self._agents:
            self._agents[agent_id] = AgentViolationState(agent_id=agent_id)

        state = self._agents[agent_id]

        # 已终止的 Agent 不再处理
        if state.is_terminated:
            logger.warning(f"[ViolationTracker] Agent {agent_id} already terminated")
            return ActionTier.TIER3

        # 清理过期记录
        self._expire_old_records(state)

        # 记录新违规
        record = ViolationRecord(
            timestamp_ns=self._clock.now_ns(),
            tier=tier,
            event_id=event_id,
            reason=reason,
        )
        state.violations.append(record)

        # 检查升级
        effective_tier = self._check_escalation(state, tier)
        state.current_tier = effective_tier

        if effective_tier != tier:
            logger.info(
                f"[ViolationTracker] Agent {agent_id} escalated: "
                f"{tier.value} -> {effective_tier.value}"
            )

        return effective_tier

    def _expire_old_records(self, state: AgentViolationState) -> None:
        """清理滑动窗口外的过期记录"""
        now = self._clock.now_ns()
        cutoff = now - self._window_size
        state.violations = [v for v in state.violations if v.timestamp_ns >= cutoff]

    def _check_escalation(self, state: AgentViolationState,
                          current_tier: ActionTier) -> ActionTier:
        """
        检查是否需要升级。

        升级规则 (定稿 5.4):
        - Tier1 累计 >= 3 次 → 升级到 Tier2
        - Tier2 累计 >= 2 次 → 升级到 Tier3
        """
        if current_tier == ActionTier.TIER3:
            return ActionTier.TIER3

        # 检查 Tier1 → Tier2 升级
        if state.tier1_count >= self.TIER1_ESCALATE_THRESHOLD:
            logger.info(
                f"[ViolationTracker] Agent {state.agent_id}: "
                f"Tier1 count={state.tier1_count} >= {self.TIER1_ESCALATE_THRESHOLD}, escalate to Tier2"
            )
            return ActionTier.TIER2

        # 检查 Tier2 → Tier3 升级
        if state.tier2_count >= self.TIER2_ESCALATE_THRESHOLD:
            logger.info(
                f"[ViolationTracker] Agent {state.agent_id}: "
                f"Tier2 count={state.tier2_count} >= {self.TIER2_ESCALATE_THRESHOLD}, escalate to Tier3"
            )
            return ActionTier.TIER3

        return current_tier

    def mark_terminated(self, agent_id: str) -> None:
        """标记 Agent 为已终止（Tier3 执行后）"""
        if agent_id not in self._agents:
            self._agents[agent_id] = AgentViolationState(agent_id=agent_id)
        self._agents[agent_id].is_terminated = True
        logger.info(f"[ViolationTracker] Agent {agent_id} marked as terminated")

    def is_terminated(self, agent_id: str) -> bool:
        """检查 Agent 是否已终止"""
        if agent_id in self._agents:
            return self._agents[agent_id].is_terminated
        return False

    def get_violation_count(self, agent_id: str, tier: ActionTier = None) -> int:
        """获取 Agent 的违规计数"""
        if agent_id not in self._agents:
            return 0
        state = self._agents[agent_id]
        self._expire_old_records(state)
        if tier is None:
            return len(state.violations)
        return sum(1 for v in state.violations if v.tier == tier)

    def get_agent_state(self, agent_id: str) -> Optional[AgentViolationState]:
        """获取 Agent 的违规状态"""
        return self._agents.get(agent_id)

    def get_all_agents(self) -> List[str]:
        """获取所有被追踪的 Agent ID"""
        return list(self._agents.keys())

    def reset(self, agent_id: str = None) -> None:
        """重置违规记录"""
        if agent_id:
            if agent_id in self._agents:
                del self._agents[agent_id]
        else:
            self._agents.clear()
