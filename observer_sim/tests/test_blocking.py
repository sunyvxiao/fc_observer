"""
test_blocking.py — Phase 4 阻断机制测试

测试内容:
1. AgentViolationTracker: 滑动窗口违规计数 + 自动升级
2. BlockingCoordinator: 三级路由 + CommandSender 联动
3. SoftReport/BlockAccess/HardInterrupt: 三级阻断处理器
4. 场景2/3 端到端: 阻断链条 + 升级逻辑 + 反向管道联动

对应定稿 8.4 测试检查点:
- Phase 4: 连续 3 次告警升级 → AgentViolationTracker 正确升级到 Tier2
- Phase 4: Tier2 阻断 + 反向管道 → BlockAccess 执行 → CommandSender 发送 block_event
- Phase 4: Tier3 进程终止 → HardInterrupt → terminate_process → 标记 terminated
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.event import RawEvent, NormalizedEvent
from models.virtual_clock import VirtualClock
from models.risk import (
    RiskAssessment, RiskLevel, Decision, DecisionAction, ActionTier
)
from observer_core.blocking.violation_tracker import AgentViolationTracker
from observer_core.blocking.blocking_coordinator import BlockingCoordinator
from observer_core.blocking.command_sender import MockCommandSender
from models.command import CmdType


class TestAgentViolationTracker(unittest.TestCase):
    """AgentViolationTracker 单元测试"""

    def setUp(self):
        self.clock = VirtualClock(start_ns=1718092800000000000)
        self.tracker = AgentViolationTracker(clock=self.clock)

    def test_single_violation_no_escalation(self):
        """单次违规不升级"""
        self.clock.advance(100)
        tier = self.tracker.record_violation("agent-1", ActionTier.TIER1, "evt_1")
        self.assertEqual(tier, ActionTier.TIER1)
        self.assertEqual(self.tracker.get_violation_count("agent-1"), 1)

    def test_three_tier1_escalate_to_tier2(self):
        """连续 3 次 Tier1 告警 → 升级到 Tier2"""
        for i in range(3):
            self.clock.advance(100)
            tier = self.tracker.record_violation("agent-1", ActionTier.TIER1, f"evt_{i}")

        # 第 3 次应该升级到 Tier2
        self.assertEqual(tier, ActionTier.TIER2)

    def test_two_tier2_escalate_to_tier3(self):
        """连续 2 次 Tier2 阻断 → 升级到 Tier3"""
        # 先记录 2 次 Tier2
        for i in range(2):
            self.clock.advance(100)
            self.tracker.record_violation("agent-1", ActionTier.TIER2, f"evt_t2_{i}")

        # 第 2 次应该升级到 Tier3
        self.clock.advance(100)
        tier = self.tracker.record_violation("agent-1", ActionTier.TIER2, "evt_t2_2")
        self.assertEqual(tier, ActionTier.TIER3)

    def test_window_expiry_clears_count(self):
        """滑动窗口过期后计数清除"""
        # 记录 2 次 Tier1
        for i in range(2):
            self.clock.advance(100)
            self.tracker.record_violation("agent-1", ActionTier.TIER1, f"evt_{i}")

        # 推进时间超过窗口（5分钟 + 1秒）
        self.clock.advance(5 * 60 * 1_000_000_000 + 1_000_000_000)

        # 再记录 1 次，不应升级（之前的 2 次已过期）
        tier = self.tracker.record_violation("agent-1", ActionTier.TIER1, "evt_new")
        self.assertEqual(tier, ActionTier.TIER1)
        self.assertEqual(self.tracker.get_violation_count("agent-1"), 1)

    def test_terminated_agent_stays_terminated(self):
        """已终止的 Agent 不再处理"""
        self.clock.advance(100)
        self.tracker.mark_terminated("agent-1")
        self.assertTrue(self.tracker.is_terminated("agent-1"))

        tier = self.tracker.record_violation("agent-1", ActionTier.TIER1, "evt_x")
        self.assertEqual(tier, ActionTier.TIER3)  # 已终止，返回 TIER3

    def test_multiple_agents_independent(self):
        """多 Agent 独立追踪"""
        self.clock.advance(100)
        self.tracker.record_violation("agent-A", ActionTier.TIER1, "evt_a1")
        self.tracker.record_violation("agent-B", ActionTier.TIER1, "evt_b1")

        self.assertEqual(self.tracker.get_violation_count("agent-A"), 1)
        self.assertEqual(self.tracker.get_violation_count("agent-B"), 1)
        self.assertIn("agent-A", self.tracker.get_all_agents())
        self.assertIn("agent-B", self.tracker.get_all_agents())

    def test_reset_tracker(self):
        """重置追踪器"""
        self.clock.advance(100)
        self.tracker.record_violation("agent-1", ActionTier.TIER1, "evt_1")
        self.tracker.reset("agent-1")
        self.assertEqual(self.tracker.get_violation_count("agent-1"), 0)


class TestBlockingCoordinator(unittest.TestCase):
    """BlockingCoordinator 单元测试"""

    def setUp(self):
        self.clock = VirtualClock(start_ns=1718092800000000000)
        self.sender = MockCommandSender()
        self.sender.connect("mock_pipe")
        self.coordinator = BlockingCoordinator(clock=self.clock, sender=self.sender)

    def _make_event(self, event_type="exec", exe="/bin/rm", agent_id="test-agent"):
        """创建测试事件"""
        self.clock.advance(100)
        raw = RawEvent(
            event_id=f"evt_{exe}_{agent_id}",
            timestamp_ns=self.clock.now_ns(),
            event_type=event_type,
            pid=10001, ppid=0,
            agent_id=agent_id,
            agent_framework="test",
            executable=exe,
            arguments=["-rf", "/"],
        )
        return NormalizedEvent(raw=raw)

    def _make_decision(self, action=DecisionAction.ALLOW, tier=ActionTier.TIER1):
        """创建测试决策"""
        return Decision(
            action=action,
            tier=tier,
            reason="test decision",
        )

    def test_tier1_soft_report(self):
        """Tier1 软报告: 放行 + 发送 allow 指令"""
        event = self._make_event()
        decision = self._make_decision(DecisionAction.ALERT, ActionTier.TIER1)
        result = self.coordinator.execute(event, decision)

        self.assertFalse(result.blocked)
        self.assertEqual(result.tier, ActionTier.TIER1)

        # 验证发送了 allow 指令
        last_cmd = self.sender.last_command
        self.assertIsNotNone(last_cmd)
        self.assertEqual(last_cmd.cmd_type, CmdType.ALLOW.value)

    def test_tier2_block_access(self):
        """Tier2 阻断: 阻止 + 发送 block_event 指令"""
        event = self._make_event()
        decision = self._make_decision(DecisionAction.BLOCK, ActionTier.TIER2)
        result = self.coordinator.execute(event, decision)

        self.assertTrue(result.blocked)
        self.assertEqual(result.tier, ActionTier.TIER2)

        # 验证发送了 block_event 指令
        last_cmd = self.sender.last_command
        self.assertIsNotNone(last_cmd)
        self.assertEqual(last_cmd.cmd_type, CmdType.BLOCK_EVENT.value)

    def test_tier3_hard_interrupt(self):
        """Tier3 硬中断: 终止 + 发送 terminate_process 指令"""
        event = self._make_event()
        decision = self._make_decision(DecisionAction.BLOCK, ActionTier.TIER3)
        result = self.coordinator.execute(event, decision)

        self.assertTrue(result.blocked)
        self.assertEqual(result.tier, ActionTier.TIER3)

        # 验证发送了 terminate_process 指令
        last_cmd = self.sender.last_command
        self.assertIsNotNone(last_cmd)
        self.assertEqual(last_cmd.cmd_type, CmdType.TERMINATE_PROCESS.value)

        # 验证 Agent 被标记为 terminated
        self.assertTrue(self.coordinator.tracker.is_terminated("test-agent"))

    def test_escalation_tier1_to_tier2(self):
        """升级测试: 3 次 Tier1 → Tier2"""
        for i in range(3):
            event = self._make_event(agent_id="escalate-agent")
            decision = self._make_decision(DecisionAction.ALERT, ActionTier.TIER1)
            result = self.coordinator.execute(event, decision)

        # 第 3 次应该升级到 Tier2
        self.assertTrue(result.blocked)
        self.assertEqual(result.tier, ActionTier.TIER2)

    def test_terminated_agent_events_dropped(self):
        """已终止 Agent 的后续事件被丢弃"""
        # 先终止 Agent
        event1 = self._make_event(agent_id="term-agent")
        decision1 = self._make_decision(DecisionAction.BLOCK, ActionTier.TIER3)
        self.coordinator.execute(event1, decision1)

        # 后续事件
        event2 = self._make_event(agent_id="term-agent")
        decision2 = self._make_decision(DecisionAction.ALLOW, ActionTier.TIER1)
        result = self.coordinator.execute(event2, decision2)

        self.assertTrue(result.blocked)
        self.assertEqual(result.tier, ActionTier.TIER3)
        self.assertTrue(len(result.details) > 0)

    def test_statistics(self):
        """阻断统计"""
        # 执行不同 tier 的阻断
        for i in range(2):
            event = self._make_event(agent_id=f"stat-agent-{i}")
            decision = self._make_decision(DecisionAction.ALERT, ActionTier.TIER1)
            self.coordinator.execute(event, decision)

        event = self._make_event(agent_id="stat-agent-2")
        decision = self._make_decision(DecisionAction.BLOCK, ActionTier.TIER2)
        self.coordinator.execute(event, decision)

        stats = self.coordinator.get_statistics()
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["tier1"], 2)
        self.assertEqual(stats["tier2"], 1)

    def test_allow_no_violation(self):
        """ALLOW 决策不记录违规"""
        event = self._make_event()
        decision = self._make_decision(DecisionAction.ALLOW, ActionTier.TIER1)
        self.coordinator.execute(event, decision)

        self.assertEqual(self.coordinator.tracker.get_violation_count("test-agent"), 0)


class TestPhase4Integration(unittest.TestCase):
    """Phase 4 集成测试: 场景2 阻断链"""

    def setUp(self):
        self.clock = VirtualClock(start_ns=1718092800000000000)
        self.sender = MockCommandSender()
        self.sender.connect("mock_pipe")
        self.coordinator = BlockingCoordinator(clock=self.clock, sender=self.sender)

    def test_scenario2_blocking_chain(self):
        """场景2: 危险操作 → Tier2 阻断 + 反向管道 block_event"""
        # 模拟场景2的危险事件
        self.clock.advance(100)
        raw = RawEvent(
            event_id="evt_rm_rf",
            timestamp_ns=self.clock.now_ns(),
            event_type="exec",
            pid=20001, ppid=0,
            agent_id="rogue-agent",
            agent_framework="test",
            executable="/bin/rm",
            arguments=["-rf", "/"],
        )
        event = NormalizedEvent(raw=raw)

        # 模拟 DecisionEngine 输出 BLOCK @ TIER2
        decision = Decision(
            action=DecisionAction.BLOCK,
            tier=ActionTier.TIER2,
            reason="危险命令 rm -rf /",
        )

        result = self.coordinator.execute(event, decision)

        # 验证阻断结果
        self.assertTrue(result.blocked)
        self.assertEqual(result.tier, ActionTier.TIER2)

        # 验证反向管道指令
        last_cmd = self.sender.last_command
        self.assertIsNotNone(last_cmd)
        self.assertEqual(last_cmd.cmd_type, CmdType.BLOCK_EVENT.value)
        self.assertEqual(last_cmd.target_pid, 20001)

    def test_scenario3_multi_agent_blocking(self):
        """场景3: Multi-Agent → 数据外传阻断"""
        self.clock.advance(100)
        raw = RawEvent(
            event_id="evt_data_exfil",
            timestamp_ns=self.clock.now_ns(),
            event_type="net_conn",
            pid=40001, ppid=0,
            agent_id="agent-beta",
            agent_framework="test",
            remote_addr="203.0.113.50",
            remote_port=443,
        )
        event = NormalizedEvent(raw=raw)

        decision = Decision(
            action=DecisionAction.BLOCK,
            tier=ActionTier.TIER2,
            reason="可疑数据外传",
        )

        result = self.coordinator.execute(event, decision)

        self.assertTrue(result.blocked)
        self.assertEqual(result.tier, ActionTier.TIER2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
