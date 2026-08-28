"""
AgentViolationTracker — Agent 违规追踪器

核心职责:
1. 维护每个 Agent 会话维度的虚拟时钟滑动窗口违规计数
2. 实现自动升级逻辑: Tier1×5 → Tier2, Tier2×3 → Tier3
3. 窗口过期后自动清除计数（基于虚拟时钟）

升级机制:
- 同一 (Agent, 会话) 在虚拟时钟过去 5 分钟内:
  - tier1_count >= 5 → 升级到 Tier2
  - tier2_count >= 3 → 升级到 Tier3
  （阈值从 tuning.yaml 的 escalation 节热加载）
- 窗口过期后计数器自动清除

修订 2.1: 追踪粒度由「仅 agent_id」改为「(agent_id, session_id)」。
修复 E2E 实测发现的黑盒 Agent 全部会话共享同一 agent_id（如 workbuddy）
时全局累积升级污染单事件判定的缺陷；不同会话的违规互不叠加。
"""

import os
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.risk import ActionTier
from models.virtual_clock import VirtualClock
from observer_core.judgment.tuning_loader import get_tuning

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
    """单个 Agent 会话维度的违规状态"""
    agent_id: str
    session_id: Optional[str] = None
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
    TIER1_ESCALATE_THRESHOLD = 5  # Tier1 累计 5 次 → Tier2
    TIER2_ESCALATE_THRESHOLD = 3  # Tier2 累计 3 次 → Tier3

    def __init__(self, clock: VirtualClock, window_size_ns: int = None):
        """
        Args:
            clock: 虚拟时钟实例
            window_size_ns: 滑动窗口大小（纳秒），None 时从 tuning.yaml 加载
        """
        tuning = get_tuning()
        esc_cfg = tuning.get("escalation", {})

        self._clock = clock
        self._window_size = (
            window_size_ns
            or esc_cfg.get("window_size_ns", self.WINDOW_SIZE_NS)
        )
        self.TIER1_ESCALATE_THRESHOLD = esc_cfg.get(
            "tier1_escalate_threshold", self.TIER1_ESCALATE_THRESHOLD)
        self.TIER2_ESCALATE_THRESHOLD = esc_cfg.get(
            "tier2_escalate_threshold", self.TIER2_ESCALATE_THRESHOLD)
        self._agents: Dict[Tuple[str, str], AgentViolationState] = {}

    @staticmethod
    def _key(agent_id: str, session_id: Optional[str]) -> Tuple[str, str]:
        """追踪键: (agent_id, session_id)。无会话事件归空串会话。"""
        return (agent_id or "", session_id or "")

    def record_violation(self, agent_id: str, tier: ActionTier,
                         event_id: str, reason: str = "",
                         session_id: Optional[str] = None) -> ActionTier:
        """
        记录一次违规并检查是否需要升级。

        Args:
            agent_id: Agent ID
            tier: 当前处置等级
            event_id: 关联事件 ID
            reason: 违规原因
            session_id: 会话 ID（修订 2.1：升级计数按会话隔离）

        Returns:
            ActionTier: 实际应执行的等级（可能已升级）
        """
        key = self._key(agent_id, session_id)

        # 获取或创建 Agent 会话状态
        if key not in self._agents:
            self._agents[key] = AgentViolationState(
                agent_id=agent_id, session_id=session_id)

        state = self._agents[key]

        # 已终止的 Agent 会话不再处理
        if state.is_terminated:
            logger.warning(
                f"[ViolationTracker] Agent {agent_id} (session={session_id}) "
                f"already terminated")
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
                f"[ViolationTracker] Agent {agent_id} (session={session_id}) "
                f"escalated: {tier.value} -> {effective_tier.value}"
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

        升级规则 (阈值从 tuning.yaml escalation 节热加载，默认值):
        - Tier1 累计 >= 5 次 → 升级到 Tier2
        - Tier2 累计 >= 3 次 → 升级到 Tier3
        """
        if current_tier == ActionTier.TIER3:
            return ActionTier.TIER3

        # 检查 Tier1 → Tier2 升级
        if state.tier1_count >= self.TIER1_ESCALATE_THRESHOLD:
            logger.info(
                f"[ViolationTracker] Agent {state.agent_id} "
                f"(session={state.session_id}): "
                f"Tier1 count={state.tier1_count} >= {self.TIER1_ESCALATE_THRESHOLD}, escalate to Tier2"
            )
            return ActionTier.TIER2

        # 检查 Tier2 → Tier3 升级
        if state.tier2_count >= self.TIER2_ESCALATE_THRESHOLD:
            logger.info(
                f"[ViolationTracker] Agent {state.agent_id} "
                f"(session={state.session_id}): "
                f"Tier2 count={state.tier2_count} >= {self.TIER2_ESCALATE_THRESHOLD}, escalate to Tier3"
            )
            return ActionTier.TIER3

        return current_tier

    def mark_terminated(self, agent_id: str,
                        session_id: Optional[str] = None) -> None:
        """标记 Agent 会话为已终止（Tier3 执行后）"""
        key = self._key(agent_id, session_id)
        if key not in self._agents:
            self._agents[key] = AgentViolationState(
                agent_id=agent_id, session_id=session_id)
        self._agents[key].is_terminated = True
        logger.info(f"[ViolationTracker] Agent {agent_id} "
                    f"(session={session_id}) marked as terminated")

    def is_terminated(self, agent_id: str,
                      session_id: Optional[str] = None) -> bool:
        """检查 Agent 会话是否已终止"""
        key = self._key(agent_id, session_id)
        if key in self._agents:
            return self._agents[key].is_terminated
        return False

    def get_violation_count(self, agent_id: str, tier: ActionTier = None,
                            session_id: Optional[str] = None) -> int:
        """获取 Agent 会话的违规计数"""
        key = self._key(agent_id, session_id)
        if key not in self._agents:
            return 0
        state = self._agents[key]
        self._expire_old_records(state)
        if tier is None:
            return len(state.violations)
        return sum(1 for v in state.violations if v.tier == tier)

    def get_agent_state(self, agent_id: str,
                        session_id: Optional[str] = None) -> Optional[AgentViolationState]:
        """获取 Agent 会话的违规状态"""
        return self._agents.get(self._key(agent_id, session_id))

    def get_all_agents(self) -> List[str]:
        """获取所有被追踪的 Agent ID（去重）"""
        return list({key[0] for key in self._agents.keys()})

    def reset(self, agent_id: str = None,
              session_id: Optional[str] = None) -> None:
        """重置违规记录"""
        if agent_id:
            if session_id is not None:
                # 重置指定会话
                self._agents.pop(self._key(agent_id, session_id), None)
            else:
                # 重置该 Agent 的全部会话
                keys = [k for k in self._agents if k[0] == agent_id]
                for k in keys:
                    del self._agents[k]
        else:
            self._agents.clear()
