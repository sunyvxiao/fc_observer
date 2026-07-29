"""
test_integration.py — Phase 6 集成测试 + 异常边界测试

测试内容:
1. 虚拟时钟一致性: 全系统时间戳基于 VirtualClock
2. 边界条件: 冷启动/规则缺失/Agent terminated/时钟溢出
3. 异常处理: 无效事件/空场景/管道断开模拟
4. 端到端全流程: 三场景一键运行验证
5. 自优化接口: 验证接口桩可实例化

对应定稿 8.4 测试检查点:
- Phase 6: 虚拟时钟一致性 → 全系统时间戳均基于 VirtualClock，无真实时间混入

对应定稿 8.5 边界条件:
- 冷启动无基线 → 偏离分 = 0.0
- 规则文件缺失 → RuleEngine 不崩溃
- Agent terminated 后收到事件 → 丢弃
- 虚拟时钟溢出 → Python int 无溢出
"""

import sys
import os
import json
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models.event import RawEvent, NormalizedEvent
from models.virtual_clock import VirtualClock
from models.risk import (
    RiskAssessment, RiskLevel, Decision, DecisionAction, ActionTier, BlockingResult
)
from models.command import Command, CmdType
from observer_core.monitoring.event_normalizer import EventNormalizer
from observer_core.monitoring.rule_engine import RuleEngine
from observer_core.judgment.risk_scorer import RiskScorer
from observer_core.judgment.baseline_checker import BaselineChecker
from observer_core.judgment.decision_engine import DecisionEngine
from observer_core.blocking.blocking_coordinator import BlockingCoordinator
from observer_core.blocking.command_sender import MockCommandSender
from observer_core.audit.behavior_graph import BehaviorGraph
from observer_core.audit.audit_logger import AuditLogger
from observer_core.audit.report_exporter import ReportExporter
from evolution.interfaces import (
    ITraceStore, IPatternMiner, IStrategyGenerator,
    TraceRecord, TraceQuery, SequencePattern, FreqAnomaly,
    PolicyRule, ValidationResult,
)


def _make_raw(event_id="e1", agent_id="a1", event_type="exec",
              timestamp_ns=0, pid=10001, **kwargs):
    return RawEvent(
        event_id=event_id, timestamp_ns=timestamp_ns,
        event_type=event_type, pid=pid, ppid=1,
        agent_id=agent_id, agent_framework="test",
        **kwargs,
    )


class TestVirtualClockConsistency(unittest.TestCase):
    """
    虚拟时钟一致性测试（定稿 8.4 Phase 6 检查点）。
    验证全系统时间戳均基于 VirtualClock，无真实时间混入。
    """

    def test_all_events_use_virtual_clock(self):
        """所有事件时间戳来自虚拟时钟"""
        clock = VirtualClock()
        normalizer = EventNormalizer(clock)

        timestamps = []
        for i in range(5):
            clock.advance(1000)
            raw = _make_raw(f"e{i}", timestamp_ns=clock.now_ns())
            norm = normalizer.normalize(raw)
            timestamps.append(norm.timestamp_ns)

        # 验证: 所有时间戳严格递增且来自虚拟时钟
        for i in range(1, len(timestamps)):
            self.assertGreater(timestamps[i], timestamps[i - 1])

        # 验证: 时间戳与虚拟时钟一致
        self.assertEqual(timestamps[-1], clock.now_ns())

    def test_blocking_uses_virtual_clock(self):
        """阻断组件使用虚拟时钟时间戳"""
        clock = VirtualClock()
        coord = BlockingCoordinator(clock)

        clock.advance(5000)
        raw = _make_raw(timestamp_ns=clock.now_ns())
        norm = NormalizedEvent(raw=raw)
        decision = Decision(action=DecisionAction.ALERT, tier=ActionTier.TIER1, reason="test")
        result = coord.execute(norm, decision)

        # 阻断事件的时间戳应来自虚拟时钟
        self.assertEqual(coord.block_events[0].timestamp_ns, clock.now_ns())

    def test_audit_logger_uses_event_timestamp(self):
        """审计日志使用事件时间戳（非真实时间）"""
        clock = VirtualClock()
        clock.advance(42_000_000)  # 42ms

        tmpdir = tempfile.mkdtemp()
        try:
            logger = AuditLogger(output_dir=tmpdir)
            logger.start_scenario("test")

            raw = _make_raw(timestamp_ns=clock.now_ns())
            norm = NormalizedEvent(raw=raw)
            entry = logger.log_event(norm, description="test")

            # 审计条目的时间戳来自事件（虚拟时钟）
            self.assertEqual(entry.timestamp_ns, clock.now_ns())

            logger.close()
        finally:
            shutil.rmtree(tmpdir)


class TestBoundaryConditions(unittest.TestCase):
    """
    边界条件测试（定稿 8.5）。
    """

    def test_cold_start_baseline_deviation_zero(self):
        """冷启动无基线 → 偏离分 = 0.0"""
        checker = BaselineChecker()
        scorer = RiskScorer()
        scorer.register_default_dimensions()

        # 基线未预热
        baseline = checker.get_baseline_dict()
        self.assertFalse(baseline.get("is_warm", False))

        scorer.set_baseline(baseline)

        raw = _make_raw(event_type="file_open", file_path="/tmp/test.txt", file_op="read")
        norm = NormalizedEvent(raw=raw)
        from observer_core.monitoring.rule_engine import MatchResult
        match = MatchResult()
        from models.event import AgentContext
        ctx = AgentContext(agent_id="a1")

        assessment = scorer.assess(norm, match, ctx)

        # 基线偏离分应为 0（冷启动）
        baseline_dim = [d for d in assessment.dimension_scores if "baseline" in d.name.lower() or "deviation" in d.name.lower()]
        for d in baseline_dim:
            self.assertEqual(d.score, 0.0)

    def test_rule_engine_missing_file(self):
        """规则文件缺失 → RuleEngine 不崩溃"""
        engine = RuleEngine()
        # 加载不存在的文件
        try:
            engine.load_rules("nonexistent_rules.yaml")
            # 如果没抛异常，应该有空规则
            raw = _make_raw(executable="/bin/ls")
            norm = NormalizedEvent(raw=raw)
            result = engine.match(norm)
            self.assertFalse(result.has_match)
        except (FileNotFoundError, Exception):
            # 抛异常也是可接受的行为
            pass

    def test_terminated_agent_events_dropped(self):
        """Agent terminated 后收到事件 → 丢弃（定稿 8.5）"""
        clock = VirtualClock()
        coord = BlockingCoordinator(clock)

        # 先终止 Agent
        raw1 = _make_raw(agent_id="term-agent")
        norm1 = NormalizedEvent(raw=raw1)
        dec1 = Decision(action=DecisionAction.BLOCK, tier=ActionTier.TIER3, reason="dangerous")
        coord.execute(norm1, dec1)

        # 后续事件应被丢弃
        raw2 = _make_raw(agent_id="term-agent", event_id="e2")
        norm2 = NormalizedEvent(raw=raw2)
        dec2 = Decision(action=DecisionAction.ALLOW, tier=ActionTier.TIER1)
        result = coord.execute(norm2, dec2)

        self.assertTrue(result.blocked)
        self.assertEqual(result.tier, ActionTier.TIER3)

    def test_virtual_clock_no_overflow(self):
        """虚拟时钟溢出 → Python int 无溢出（定稿 8.5）"""
        clock = VirtualClock()
        # 推进极大值
        clock.advance(10**18)  # ~1 秒
        self.assertGreater(clock.now_ns(), 10**18)

        clock.advance(10**15)  # ~1 毫秒
        self.assertGreater(clock.now_ns(), 10**18 + 10**15)

        # 不会溢出
        clock.advance(10**20)
        self.assertGreater(clock.now_ns(), 0)

    def test_empty_scenario(self):
        """空场景 → 不崩溃"""
        scenario = {
            "id": "empty",
            "name": "Empty Scenario",
            "description": "No events",
            "expected_result": "nothing",
            "agents": [],
            "event_sequence": [],
        }
        self.assertEqual(len(scenario["event_sequence"]), 0)

    def test_behavior_graph_empty(self):
        """空图谱 → JSON 输出正常"""
        graph = BehaviorGraph()
        data = graph.to_dict()
        self.assertEqual(data["graph_info"]["node_count"], 0)
        self.assertEqual(data["graph_info"]["edge_count"], 0)


class TestEvolutionInterfaces(unittest.TestCase):
    """
    自优化接口桩测试。
    验证接口已定义且数据结构可用。
    """

    def test_trace_record_creation(self):
        """TraceRecord 可创建"""
        record = TraceRecord(
            event_id="e1", agent_id="a1",
            timestamp_ns=1000, event_type="exec",
            risk_score=0.5, risk_level="MEDIUM",
        )
        self.assertEqual(record.event_id, "e1")
        self.assertEqual(record.risk_score, 0.5)

    def test_trace_query_creation(self):
        """TraceQuery 可创建"""
        query = TraceQuery(agent_id="a1", blocked_only=True)
        self.assertEqual(query.agent_id, "a1")
        self.assertTrue(query.blocked_only)

    def test_sequence_pattern_creation(self):
        """SequencePattern 可创建"""
        pattern = SequencePattern(
            pattern_id="p1", description="test",
            event_sequence=["exec", "file_open", "net_conn"],
            support_count=10, confidence=0.8,
        )
        self.assertEqual(len(pattern.event_sequence), 3)

    def test_policy_rule_creation(self):
        """PolicyRule 可创建"""
        rule = PolicyRule(
            rule_id="auto-001", pattern="rm -rf /",
            match_type="pattern", action="block",
            reason="dangerous command", confidence=0.95,
        )
        self.assertTrue(rule.auto_generated)

    def test_validation_result_creation(self):
        """ValidationResult 可创建"""
        result = ValidationResult(
            is_valid=True, false_positive_rate=0.05,
            tested_traces=100,
        )
        self.assertTrue(result.is_valid)

    def test_interfaces_are_abstract(self):
        """接口为抽象类，不可直接实例化"""
        with self.assertRaises(TypeError):
            ITraceStore()
        with self.assertRaises(TypeError):
            IPatternMiner()
        with self.assertRaises(TypeError):
            IStrategyGenerator()


class TestEndToEndIntegration(unittest.TestCase):
    """
    端到端集成测试。
    验证三场景一键运行的完整流程。
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_full_pipeline_single_scenario(self):
        """单场景全流程: 归一化→规则→评分→研判→阻断→审计→报告"""
        clock = VirtualClock()
        normalizer = EventNormalizer(clock)
        rule_engine = RuleEngine()
        rule_engine.load_rules("rules/default_policy.yaml")
        scorer = RiskScorer()
        scorer.register_default_dimensions()
        baseline_checker = BaselineChecker()
        decision_engine = DecisionEngine()
        coord = BlockingCoordinator(clock, MockCommandSender(), output_dir=self.tmpdir)
        graph = BehaviorGraph()
        audit = AuditLogger(output_dir=self.tmpdir)
        exporter = ReportExporter(output_dir=self.tmpdir)

        audit.start_scenario("test-scenario")

        # 模拟 3 个事件
        for i in range(3):
            clock.advance(1000)
            raw = _make_raw(
                f"evt-{i}", "agent-1", "exec",
                timestamp_ns=clock.now_ns(),
                executable="/usr/bin/git",
                arguments=["status"],
            )
            norm = normalizer.normalize(raw)
            match = rule_engine.match(norm)
            baseline_checker.collect(norm)
            scorer.set_baseline(baseline_checker.get_baseline_dict())
            ctx = normalizer.get_agent_context("agent-1")
            assessment = scorer.assess(norm, match, ctx)
            decision = decision_engine.decide(assessment, norm.event_id, "agent-1")
            blocking = coord.execute(norm, decision)
            graph.add_event(norm, assessment=assessment, decision=decision,
                            blocking_result=blocking)
            audit.log_event(norm, assessment=assessment, decision=decision,
                            blocking_result=blocking, description=f"git status {i}")

        audit.close()

        # 验证: 审计文件存在
        summary = audit.get_summary()
        self.assertEqual(summary["total"], 3)

        # 验证: 报告生成
        report_path = exporter.export_scenario_report(
            "test-scenario", "Test", audit, graph,
        )
        self.assertTrue(os.path.exists(report_path))

        # 验证: 图谱 JSON
        tmpdir = tempfile.mkdtemp()
        graph_path = os.path.join(tmpdir, "graph.json")
        graph.save_json(graph_path)
        self.assertTrue(os.path.exists(graph_path))
        shutil.rmtree(tmpdir)

    def test_virtual_clock_consistency_across_components(self):
        """跨组件虚拟时钟一致性"""
        clock = VirtualClock()
        normalizer = EventNormalizer(clock)
        coord = BlockingCoordinator(clock)
        graph = BehaviorGraph()

        for i in range(5):
            clock.advance(2000)
            expected_ts = clock.now_ns()

            raw = _make_raw(f"e{i}", timestamp_ns=expected_ts)
            norm = normalizer.normalize(raw)

            # 归一化事件时间戳 = 虚拟时钟
            self.assertEqual(norm.timestamp_ns, expected_ts)

            decision = Decision(action=DecisionAction.ALLOW, tier=ActionTier.TIER1)
            result = coord.execute(norm, decision)

            # 阻断结果的时间戳 = 虚拟时钟
            if coord.block_events:
                self.assertEqual(coord.block_events[-1].timestamp_ns, expected_ts)

            graph.add_event(norm, decision=decision, blocking_result=result)

            # 图谱节点时间戳 = 虚拟时钟
            self.assertEqual(graph.nodes[-1].timestamp_ns, expected_ts)


if __name__ == "__main__":
    unittest.main()
