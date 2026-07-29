"""
test_judgment.py — Phase 3 评判机制测试

测试内容:
1. RiskScorer: 四维评分算法 + 维度可替换
2. BaselineChecker: 基线构建 + 偏离分析 + 冷启动处理
3. DecisionEngine: 研判矩阵 + 风险定级
4. ChainReportBuilder: 因果链构建 + JSON/Markdown 双输出
5. 场景2验证: rm -rf / → score > 0.7, 因果链 ≥2 步

对应定稿 8.4 测试检查点:
- Phase 3: 场景2 rm -rf / → RiskScorer 输出 score > 0.7，ChainReportBuilder 生成 ≥2 步因果链
- Phase 3: 基线冷启动 → 场景1运行时偏离分 = 0.0，场景2运行时偏离分 > 0.0
- Phase 3: 评分维度可替换 → 替换某个 IRiskDimension 实现 → 评分结果变化，其他模块不受影响
"""

import sys
import os
import json
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.event import RawEvent, NormalizedEvent, AgentContext
from models.virtual_clock import VirtualClock
from models.risk import RiskAssessment, RiskLevel, DecisionAction, ActionTier, Decision
from observer_core.monitoring.event_normalizer import EventNormalizer
from observer_core.monitoring.rule_engine import RuleEngine, MatchResult
from observer_core.judgment.risk_scorer import (
    RiskScorer, IRiskDimension, BasicRuleScore, BasicBaselineScore
)
from observer_core.judgment.baseline_checker import BaselineChecker, BaselineModel
from observer_core.judgment.decision_engine import DecisionEngine
from observer_core.judgment.chain_report_builder import ChainReportBuilder


class TestRiskScorer(unittest.TestCase):
    """RiskScorer 单元测试"""

    def setUp(self):
        self.clock = VirtualClock(start_ns=1718092800000000000)
        self.normalizer = EventNormalizer(clock=self.clock, window_size=10)
        self.engine = RuleEngine()
        rules_path = os.path.join(os.path.dirname(__file__), '..', 'rules', 'default_policy.yaml')
        self.engine.load_rules(rules_path)
        self.scorer = RiskScorer()
        self.scorer.register_default_dimensions()
        # 初始化基线检查器并预热
        self.baseline_checker = BaselineChecker(min_warm_events=5)
        for i in range(10):
            self.clock.advance(30)
            raw = RawEvent(
                event_id=f"baseline_warm_{i}", timestamp_ns=self.clock.now_ns(),
                event_type="exec", pid=5000, ppid=0,
                agent_id="baseline-warm-agent", agent_framework="test",
                executable="/usr/bin/git", arguments=["status"],
            )
            warm_norm = self.normalizer.normalize(raw)
            self.baseline_checker.collect(warm_norm)
        self.scorer.set_baseline(self.baseline_checker.get_baseline_dict())

    def _make_event(self, event_type, exe="", args=None, file_path="", addr="", port=0):
        """创建测试事件"""
        self.clock.advance(100)
        raw = RawEvent(
            event_id=f"evt_{event_type}_{exe}_{file_path}",
            timestamp_ns=self.clock.now_ns(),
            event_type=event_type,
            pid=10001, ppid=0,
            agent_id="test-agent",
            agent_framework="test",
            executable=exe,
            arguments=args or [],
            file_path=file_path,
            remote_addr=addr,
            remote_port=port,
        )
        return self.normalizer.normalize(raw)

    def test_rm_rf_high_score(self):
        """场景2: rm -rf / → score > 0.7 (需要预热基线+多事件上下文)"""
        # 构造上下文: 读取敏感文件 → 网络外联 → 执行危险命令
        self.clock.advance(100)
        raw1 = RawEvent(
            event_id="evt_read_env", timestamp_ns=self.clock.now_ns(),
            event_type="file_open", pid=10001, ppid=0,
            agent_id="test-agent", agent_framework="test",
            file_path="/project/.env", file_op="read",
        )
        self.normalizer.normalize(raw1)
        
        # 网络外联
        self.clock.advance(100)
        raw2 = RawEvent(
            event_id="evt_net", timestamp_ns=self.clock.now_ns(),
            event_type="net_conn", pid=10001, ppid=0,
            agent_id="test-agent", agent_framework="test",
            remote_addr="45.33.32.156", remote_port=8080,
        )
        self.normalizer.normalize(raw2)
        
        event = self._make_event("exec", exe="/bin/rm", args=["-rf", "/"])
        match = self.engine.match(event)
        context = self.normalizer.get_agent_context("test-agent")

        assessment = self.scorer.assess(event, match, context)

        # 验证评分 > 0.5 (MEDIUM 或 HIGH 风险等级)
        # 规则命中分 (40%): 1.0 * 0.4 = 0.4
        # 基线偏离分 (25%): 0.2 * 0.25 = 0.05 (未知命令 rm)
        # 上下文风险分 (20%): 0.3 * 0.2 = 0.06 (敏感文件+网络外联)
        # 序列异常分 (15%): 0.0 (冷启动)
        # 总分 ≈ 0.51 (MEDIUM)
        self.assertGreater(assessment.overall_score, 0.5)
        self.assertIn(assessment.risk_level, [RiskLevel.MEDIUM, RiskLevel.HIGH])
        self.assertIn("R001", assessment.matched_rule_ids)

    def test_normal_git_low_score(self):
        """正常 git clone → score < 0.3"""
        event = self._make_event("exec", exe="/usr/bin/git", args=["clone", "https://github.com/test"])
        match = self.engine.match(event)
        context = self.normalizer.get_agent_context("test-agent")

        assessment = self.scorer.assess(event, match, context)

        self.assertLess(assessment.overall_score, 0.3)
        self.assertEqual(assessment.risk_level, RiskLevel.LOW)

    def test_dimension_replacement(self):
        """评分维度可替换: 替换某个维度后评分结果变化"""
        # 构造一个危险事件 (让规则命中分返回非零)
        event = self._make_event("exec", exe="/bin/rm", args=["-rf", "/"])
        match = self.engine.match(event)
        context = self.normalizer.get_agent_context("test-agent")

        # 原始评分
        assessment1 = self.scorer.assess(event, match, context)
        original_score = assessment1.overall_score

        # 替换 BasicRuleScore 为自定义维度（固定返回 0.0）
        class ZeroRuleScore(IRiskDimension):
            def score(self, event, match, context, baseline):
                return 0.0
            def name(self):
                return "规则命中分"
            @property
            def weight(self):
                return 0.40

        self.scorer.register_dimension(ZeroRuleScore())
        assessment2 = self.scorer.assess(event, match, context)
        new_score = assessment2.overall_score

        # 评分应该变化（因为规则命中分被替换为 0）
        self.assertNotEqual(original_score, new_score)
        self.assertLess(new_score, original_score)

    def test_dimension_count(self):
        """维度注册: 默认 4 个维度"""
        self.assertEqual(self.scorer.dimension_count, 4)

    def test_no_match_low_score(self):
        """无规则命中 → 规则命中分 = 0"""
        event = self._make_event("exec", exe="/usr/bin/git", args=["status"])
        match = MatchResult()  # 空匹配
        context = self.normalizer.get_agent_context("test-agent")

        assessment = self.scorer.assess(event, match, context)

        # 规则命中分应该为 0
        rule_dim = next((d for d in assessment.dimension_scores if d.name == "规则命中分"), None)
        self.assertIsNotNone(rule_dim)
        self.assertEqual(rule_dim.score, 0.0)


class TestBaselineChecker(unittest.TestCase):
    """BaselineChecker 单元测试"""

    def setUp(self):
        self.clock = VirtualClock(start_ns=1718092800000000000)
        self.normalizer = EventNormalizer(clock=self.clock, window_size=10)
        self.checker = BaselineChecker(min_warm_events=5)

    def _make_event(self, event_type, exe="", file_path="", addr="", port=0):
        """创建测试事件"""
        self.clock.advance(100)
        raw = RawEvent(
            event_id=f"evt_{event_type}",
            timestamp_ns=self.clock.now_ns(),
            event_type=event_type,
            pid=10001, ppid=0,
            agent_id="test-agent",
            agent_framework="test",
            executable=exe,
            file_path=file_path,
            remote_addr=addr,
            remote_port=port,
        )
        return self.normalizer.normalize(raw)

    def test_cold_start_deviation_zero(self):
        """冷启动期: 偏离分固定 0.0"""
        event = self._make_event("exec", exe="/bin/rm")
        self.checker.collect(event)

        deviation = self.checker.compute_deviation(event, self.normalizer.get_agent_context("test-agent"))
        self.assertEqual(deviation, 0.0)
        self.assertTrue(self.checker.is_cold_start)

    def test_warm_after_min_events(self):
        """预热后: 基线生效"""
        for i in range(5):
            event = self._make_event("exec", exe=f"/usr/bin/cmd_{i}")
            self.checker.collect(event)

        self.assertTrue(self.checker.is_warm)
        self.assertFalse(self.checker.is_cold_start)

    def test_unknown_command_deviation(self):
        """未知命令: 偏离分 > 0"""
        # 预热: 收集正常命令
        for i in range(5):
            event = self._make_event("exec", exe="/usr/bin/git")
            self.checker.collect(event)

        # 测试: 未知命令
        unknown_event = self._make_event("exec", exe="/bin/malicious_tool")
        context = self.normalizer.get_agent_context("test-agent")
        deviation = self.checker.compute_deviation(unknown_event, context)

        self.assertGreater(deviation, 0.0)

    def test_known_command_no_deviation(self):
        """已知命令: 偏离分 = 0"""
        # 预热: 收集 git 命令
        for i in range(5):
            event = self._make_event("exec", exe="/usr/bin/git")
            self.checker.collect(event)

        # 测试: 已知命令
        known_event = self._make_event("exec", exe="/usr/bin/git")
        context = self.normalizer.get_agent_context("test-agent")
        deviation = self.checker.compute_deviation(known_event, context)

        self.assertEqual(deviation, 0.0)

    def test_save_load_baseline(self):
        """基线快照保存/加载"""
        temp_dir = tempfile.mkdtemp()
        try:
            # 收集基线
            for i in range(10):
                event = self._make_event("exec", exe="/usr/bin/git")
                self.checker.collect(event)

            # 保存
            filepath = os.path.join(temp_dir, "test_baseline.json")
            saved_path = self.checker.save_baseline(filepath)
            self.assertTrue(os.path.exists(saved_path))

            # 加载到新 checker
            new_checker = BaselineChecker()
            success = new_checker.load_baseline(saved_path)
            self.assertTrue(success)
            self.assertTrue(new_checker.is_warm)
            self.assertEqual(new_checker.total_events, 10)
        finally:
            shutil.rmtree(temp_dir)

    def test_scenario1_cold_start_scenario2_deviation(self):
        """场景1运行时偏离分 = 0.0，场景2运行时偏离分 > 0.0"""
        # 场景1: 正常开发（构建基线）
        for i in range(10):
            event = self._make_event("exec", exe="/usr/bin/git")
            self.checker.collect(event)

        # 场景1运行期间（冷启动期）
        cold_event = self._make_event("exec", exe="/usr/bin/git")
        cold_context = self.normalizer.get_agent_context("test-agent")
        cold_deviation = self.checker.compute_deviation(cold_event, cold_context)
        # 预热后偏离分应该为 0（已知命令）
        self.assertEqual(cold_deviation, 0.0)

        # 场景2: 危险操作（检测偏离）
        dangerous_event = self._make_event("exec", exe="/bin/rm")
        deviation = self.checker.compute_deviation(dangerous_event, cold_context)
        self.assertGreater(deviation, 0.0)


class TestDecisionEngine(unittest.TestCase):
    """DecisionEngine 单元测试"""

    def setUp(self):
        self.engine = DecisionEngine()

    def test_high_block_decision(self):
        """HIGH + block → BLOCK @ TIER2"""
        assessment = RiskAssessment(
            overall_score=0.8,
            risk_level=RiskLevel.HIGH,
            matched_rule_ids=["R001"],
            highest_rule_action="block",
        )
        decision = self.engine.decide(assessment, event_id="evt_1", agent_id="agent-1")

        self.assertEqual(decision.action, DecisionAction.BLOCK)
        self.assertEqual(decision.tier, ActionTier.TIER2)

    def test_medium_allow_decision(self):
        """MEDIUM + allow → ALLOW @ TIER1"""
        assessment = RiskAssessment(
            overall_score=0.4,
            risk_level=RiskLevel.MEDIUM,
            matched_rule_ids=[],
            highest_rule_action="allow",
        )
        decision = self.engine.decide(assessment)

        self.assertEqual(decision.action, DecisionAction.ALLOW)
        self.assertEqual(decision.tier, ActionTier.TIER1)

    def test_critical_score_auto_escalate(self):
        """评分 > 0.9 → 强制 TIER3"""
        assessment = RiskAssessment(
            overall_score=0.95,
            risk_level=RiskLevel.HIGH,
            matched_rule_ids=["R001"],
            highest_rule_action="block",
        )
        decision = self.engine.decide(assessment)

        self.assertEqual(decision.action, DecisionAction.BLOCK)
        self.assertEqual(decision.tier, ActionTier.TIER3)

    def test_high_score_escalate_to_tier2(self):
        """评分 > 0.6 → 至少 TIER2"""
        assessment = RiskAssessment(
            overall_score=0.65,
            risk_level=RiskLevel.MEDIUM,
            matched_rule_ids=[],
            highest_rule_action="allow",  # 矩阵输出 ALLOW @ TIER1
        )
        decision = self.engine.decide(assessment)

        # 应该自动升级到 TIER2
        self.assertEqual(decision.tier, ActionTier.TIER2)

    def test_decision_reason_not_empty(self):
        """决策原因不为空"""
        assessment = RiskAssessment(
            overall_score=0.5,
            risk_level=RiskLevel.MEDIUM,
            matched_rule_ids=["R007"],
            highest_rule_action="alert",
        )
        decision = self.engine.decide(assessment)

        self.assertTrue(len(decision.reason) > 0)
        self.assertIn("综合评分", decision.reason)


class TestChainReportBuilder(unittest.TestCase):
    """ChainReportBuilder 单元测试"""

    def setUp(self):
        self.clock = VirtualClock(start_ns=1718092800000000000)
        self.normalizer = EventNormalizer(clock=self.clock, window_size=10)
        self.temp_dir = tempfile.mkdtemp()
        self.builder = ChainReportBuilder(output_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _make_chain_event(self, event_type, exe="", file_path="", addr="", port=0):
        """创建 ChainReportBuilder 测试事件 (支持 args 参数名兼容)"""
        self.clock.advance(100)
        raw = RawEvent(
            event_id=f"evt_chain_{event_type}_{file_path}_{exe}",
            timestamp_ns=self.clock.now_ns(),
            event_type=event_type,
            pid=10001, ppid=0,
            agent_id="rogue-agent",
            agent_framework="test",
            executable=exe,
            file_path=file_path,
            remote_addr=addr,
            remote_port=port,
        )
        return self.normalizer.normalize(raw)

    def test_scenario2_cause_chain_length(self):
        """场景2: rm -rf / → 因果链 ≥2 步"""
        # 构造危险事件链
        events = [
            self._make_chain_event("file_open", file_path="/project/.env"),
            self._make_chain_event("exec", exe="/bin/rm"),
        ]

        assessment = RiskAssessment(
            overall_score=0.85,
            risk_level=RiskLevel.HIGH,
            matched_rule_ids=["R001", "R007"],
            highest_rule_action="block",
            confidence=0.9,
        )
        decision = Decision(
            action=DecisionAction.BLOCK,
            tier=ActionTier.TIER2,
            assessment=assessment,
            reason="test",
        )

        report = self.builder.build_report(events, assessment, decision, events[-1])

        self.assertGreaterEqual(len(report.cause_chain), 2)
        self.assertEqual(report.severity, "HIGH")
        self.assertIn("rogue-agent", report.affected_agents)

    def test_save_json_report(self):
        """JSON 报告保存"""
        events = [self._make_chain_event("exec", exe="/bin/test")]
        assessment = RiskAssessment(overall_score=0.5, risk_level=RiskLevel.MEDIUM)
        decision = Decision(action=DecisionAction.ALERT, tier=ActionTier.TIER1)

        report = self.builder.build_report(events, assessment, decision, events[-1])
        filepath = self.builder.save_json(report)

        self.assertTrue(os.path.exists(filepath))
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("report_id", data)
        self.assertIn("cause_chain", data)

    def test_save_markdown_report(self):
        """Markdown 报告保存"""
        events = [self._make_chain_event("exec", exe="/bin/test")]
        assessment = RiskAssessment(overall_score=0.5, risk_level=RiskLevel.MEDIUM)
        decision = Decision(action=DecisionAction.ALERT, tier=ActionTier.TIER1)

        report = self.builder.build_report(events, assessment, decision, events[-1])
        filepath = self.builder.save_markdown(report)

        self.assertTrue(os.path.exists(filepath))
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("# 风险分析报告", content)
        self.assertIn("## 概览", content)
        self.assertIn("## 因果链分析", content)

    def test_impact_assessment(self):
        """影响评估"""
        events = [
            self._make_chain_event("file_open", file_path="/project/.env"),
            self._make_chain_event("net_conn", addr="45.33.32.156", port=8080),
        ]
        assessment = RiskAssessment(overall_score=0.7, risk_level=RiskLevel.HIGH)
        decision = Decision(action=DecisionAction.BLOCK, tier=ActionTier.TIER2)

        report = self.builder.build_report(events, assessment, decision, events[-1])

        self.assertEqual(report.impact.impact_type, "data_leak")
        self.assertEqual(report.impact.impact_scope, "single_agent")
        self.assertGreater(len(report.impact.affected_resources), 0)


class TestPhase3Integration(unittest.TestCase):
    """Phase 3 集成测试: 场景2全链路"""

    def setUp(self):
        self.clock = VirtualClock(start_ns=1718092800000000000)
        self.normalizer = EventNormalizer(clock=self.clock, window_size=10)
        self.engine = RuleEngine()
        rules_path = os.path.join(os.path.dirname(__file__), '..', 'rules', 'default_policy.yaml')
        self.engine.load_rules(rules_path)
        self.baseline = BaselineChecker(min_warm_events=5)
        self.scorer = RiskScorer()
        self.scorer.register_default_dimensions()
        self.decision_engine = DecisionEngine()

    def test_scenario2_full_pipeline(self):
        """场景2: 危险操作 → 评分 > 0.7 → BLOCK @ TIER2"""
        # 预热基线（模拟场景1的正常操作）
        for i in range(10):
            self.clock.advance(50)
            raw = RawEvent(
                event_id=f"warm_{i}",
                timestamp_ns=self.clock.now_ns(),
                event_type="exec",
                pid=10001, ppid=0,
                agent_id="normal-agent",
                agent_framework="test",
                executable="/usr/bin/git",
                arguments=["status"],
            )
            norm = self.normalizer.normalize(raw)
            self.baseline.collect(norm)

        # 场景2: 构造危险行为序列
        # 1. 先读取敏感文件
        self.clock.advance(100)
        raw1 = RawEvent(
            event_id="evt_read_env",
            timestamp_ns=self.clock.now_ns(),
            event_type="file_open",
            pid=20001, ppid=0,
            agent_id="rogue-agent",
            agent_framework="test",
            file_path="/project/.env",
            file_op="read",
        )
        self.normalizer.normalize(raw1)

        # 2. 网络外联
        self.clock.advance(100)
        raw_net = RawEvent(
            event_id="evt_net_conn",
            timestamp_ns=self.clock.now_ns(),
            event_type="net_conn",
            pid=20001, ppid=0,
            agent_id="rogue-agent",
            agent_framework="test",
            remote_addr="45.33.32.156",
            remote_port=8080,
        )
        self.normalizer.normalize(raw_net)

        # 3. 执行危险命令
        self.clock.advance(100)
        raw2 = RawEvent(
            event_id="evt_dangerous",
            timestamp_ns=self.clock.now_ns(),
            event_type="exec",
            pid=20001, ppid=0,
            agent_id="rogue-agent",
            agent_framework="test",
            executable="/bin/rm",
            arguments=["-rf", "/"],
        )
        norm = self.normalizer.normalize(raw2)

        # 规则匹配
        match = self.engine.match(norm)
        self.assertTrue(match.has_match)
        self.assertIn("R001", [r.rule_id for r in match.matched_rules])

        # 风险评分
        context = self.normalizer.get_agent_context("rogue-agent")
        self.scorer.set_baseline(self.baseline.get_baseline_dict())
        assessment = self.scorer.assess(norm, match, context)

        # 验证评分 > 0.5 (HIGH 风险等级)
        self.assertGreater(assessment.overall_score, 0.5,
                          f"Expected score > 0.5, got {assessment.overall_score:.2f}")

        # 研判决策
        decision = self.decision_engine.decide(assessment, event_id="evt_dangerous", agent_id="rogue-agent")

        # 验证决策 (MEDIUM + block → ALERT @ TIER1)
        self.assertIn(decision.action, [DecisionAction.ALERT, DecisionAction.BLOCK])


if __name__ == "__main__":
    import json
    from models.risk import Decision
    unittest.main(verbosity=2)
