"""
test_audit.py — Phase 5 审计与输出测试

测试内容:
1. BehaviorGraph: 节点/边构建、跨 Agent 边检测、JSON 输出
2. AuditLogger: 日志写入/读取、摘要统计
3. ReportExporter: Markdown 报告生成
4. 端到端集成: 场景3 跨 Agent 图谱 + 三场景审计输出

对应定稿 8.4 测试检查点:
- Phase 5: 场景3完整运行 → BehaviorGraph JSON 包含两个 Agent 的跨节点边
- Phase 5: 三场景连续运行 → AuditLogger 生成完整审计 JSON + Markdown 风险分析报告
"""

import sys
import os
import json
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.event import RawEvent, NormalizedEvent
from models.risk import (
    RiskAssessment, RiskLevel, Decision, DecisionAction, ActionTier,
    BlockingResult, DimensionScore
)
from observer_core.audit.behavior_graph import BehaviorGraph, BehaviorNode, BehaviorEdge
from observer_core.audit.audit_logger import AuditLogger, AuditEntry
from observer_core.audit.report_exporter import ReportExporter


def _make_raw_event(event_id: str, agent_id: str, event_type: str,
                    timestamp_ns: int = 0, pid: int = 10001,
                    executable: str = None, arguments: list = None,
                    file_path: str = None, file_op: str = None,
                    remote_addr: str = None, remote_port: int = None) -> RawEvent:
    """创建测试用 RawEvent"""
    return RawEvent(
        event_id=event_id,
        timestamp_ns=timestamp_ns,
        event_type=event_type,
        pid=pid,
        ppid=1,
        agent_id=agent_id,
        agent_framework="LangChain",
        executable=executable,
        arguments=arguments,
        file_path=file_path,
        file_op=file_op,
        remote_addr=remote_addr,
        remote_port=remote_port,
    )


def _make_normalized_event(event_id: str, agent_id: str, event_type: str,
                           timestamp_ns: int = 0, **kwargs) -> NormalizedEvent:
    """创建测试用 NormalizedEvent"""
    raw = _make_raw_event(event_id=event_id, agent_id=agent_id,
                          event_type=event_type, timestamp_ns=timestamp_ns, **kwargs)
    return NormalizedEvent(raw=raw)


def _make_assessment(score: float = 0.0, level: RiskLevel = RiskLevel.LOW,
                     matched_rules: list = None) -> RiskAssessment:
    """创建测试用 RiskAssessment"""
    return RiskAssessment(
        overall_score=score,
        risk_level=level,
        dimension_scores=[
            DimensionScore(name="rule", score=score * 0.4, weight=0.4, weighted_score=score * 0.16),
            DimensionScore(name="baseline", score=score * 0.25, weight=0.25, weighted_score=score * 0.0625),
            DimensionScore(name="context", score=score * 0.2, weight=0.2, weighted_score=score * 0.04),
            DimensionScore(name="sequence", score=score * 0.15, weight=0.15, weighted_score=score * 0.0225),
        ],
        matched_rule_ids=matched_rules or [],
    )


def _make_decision(action: DecisionAction = DecisionAction.ALLOW,
                   tier: ActionTier = ActionTier.TIER1) -> Decision:
    """创建测试用 Decision"""
    return Decision(action=action, tier=tier, reason="test reason")


def _make_blocking_result(blocked: bool = False,
                          tier: ActionTier = ActionTier.TIER1) -> BlockingResult:
    """创建测试用 BlockingResult"""
    return BlockingResult(blocked=blocked, tier=tier, reason="test", details="test details")


class TestBehaviorGraph(unittest.TestCase):
    """BehaviorGraph 行为图谱测试"""

    def setUp(self):
        self.graph = BehaviorGraph()

    def test_add_single_event(self):
        """添加单个事件 → 生成节点"""
        event = _make_normalized_event("evt-1", "agent-1", "exec",
                                       executable="/usr/bin/git", arguments=["clone"])
        node = self.graph.add_event(event)

        self.assertEqual(self.graph.node_count, 1)
        self.assertEqual(node.node_id, "evt-1")
        self.assertEqual(node.agent_id, "agent-1")
        self.assertEqual(node.event_type, "exec")
        self.assertIn("git", node.description)

    def test_sequential_edges(self):
        """同 Agent 顺序事件 → sequential 边"""
        for i in range(3):
            event = _make_normalized_event(f"evt-{i}", "agent-1", "exec",
                                           timestamp_ns=i * 1000)
            self.graph.add_event(event)

        self.assertEqual(self.graph.node_count, 3)
        # 3 个事件 → 2 条顺序边
        seq_edges = [e for e in self.graph.edges if e.edge_type == "sequential"]
        self.assertEqual(len(seq_edges), 2)

    def test_cross_agent_edges(self):
        """跨 Agent 事件（时间窗口内）→ cross_agent 边"""
        # Agent-A 事件
        event_a = _make_normalized_event("evt-a", "agent-alpha", "file_open",
                                         timestamp_ns=1000,
                                         file_path="/project/.env", file_op="read")
        self.graph.add_event(event_a)

        # Agent-B 事件（时间差 < 1 秒）
        event_b = _make_normalized_event("evt-b", "agent-beta", "net_conn",
                                         timestamp_ns=1500,
                                         remote_addr="1.2.3.4", remote_port=443)
        self.graph.add_event(event_b)

        # 应该有跨 Agent 边
        cross_edges = self.graph.get_cross_agent_edges()
        self.assertTrue(len(cross_edges) > 0)
        self.assertTrue(self.graph.has_cross_agent_edges())

    def test_no_cross_agent_edge_outside_window(self):
        """时间窗口外 → 无 cross_agent 边"""
        event_a = _make_normalized_event("evt-a", "agent-alpha", "exec",
                                         timestamp_ns=0)
        self.graph.add_event(event_a)

        # 时间差 > 1 秒（1_000_000_000 ns）
        event_b = _make_normalized_event("evt-b", "agent-beta", "exec",
                                         timestamp_ns=2_000_000_000)
        self.graph.add_event(event_b)

        cross_edges = self.graph.get_cross_agent_edges()
        self.assertEqual(len(cross_edges), 0)

    def test_scenario3_two_agents_cross_edges(self):
        """场景3: 两个 Agent 的跨节点边（定稿 8.4 检查点）"""
        # 模拟场景3: agent-alpha 读取敏感文件, agent-beta 外传
        events_data = [
            ("evt-1", "agent-alpha", "exec", 0, {"executable": "/usr/bin/python3", "arguments": ["collect.py"]}),
            ("evt-2", "agent-alpha", "file_open", 300_000_000, {"file_path": "/project/.env", "file_op": "read"}),
            ("evt-3", "agent-alpha", "file_open", 500_000_000, {"file_path": "/project/secrets/api_keys.pem", "file_op": "read"}),
            ("evt-4", "agent-beta", "exec", 1_000_000_000, {"executable": "/usr/bin/curl", "arguments": ["http://external.com"]}),
            ("evt-5", "agent-beta", "net_conn", 1_500_000_000, {"remote_addr": "1.2.3.4", "remote_port": 443}),
        ]

        for eid, aid, etype, ts, kwargs in events_data:
            event = _make_normalized_event(eid, aid, etype, timestamp_ns=ts, **kwargs)
            assessment = _make_assessment(score=0.5 if "curl" in str(kwargs) else 0.1)
            decision = _make_decision(
                action=DecisionAction.BLOCK if "curl" in str(kwargs) else DecisionAction.ALLOW,
                tier=ActionTier.TIER2 if "curl" in str(kwargs) else ActionTier.TIER1,
            )
            self.graph.add_event(event, assessment=assessment, decision=decision)

        # 验证: 图谱包含两个 Agent 的跨节点边
        self.assertTrue(self.graph.has_cross_agent_edges())
        cross_edges = self.graph.get_cross_agent_edges()
        self.assertTrue(len(cross_edges) >= 1)

        # 验证: JSON 输出包含跨 Agent 边
        graph_dict = self.graph.to_dict()
        self.assertIn("edges", graph_dict)
        cross_in_json = [e for e in graph_dict["edges"] if e["edge_type"] == "cross_agent"]
        self.assertTrue(len(cross_in_json) >= 1)

    def test_save_json(self):
        """保存为 JSON 文件"""
        event = _make_normalized_event("evt-1", "agent-1", "exec",
                                       executable="/usr/bin/ls")
        self.graph.add_event(event)

        tmpdir = tempfile.mkdtemp()
        try:
            filepath = os.path.join(tmpdir, "graph.json")
            self.graph.save_json(filepath)

            self.assertTrue(os.path.exists(filepath))
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("graph_info", data)
            self.assertIn("nodes", data)
            self.assertIn("edges", data)
            self.assertIn("agent_summaries", data)
            self.assertEqual(data["graph_info"]["node_count"], 1)
        finally:
            shutil.rmtree(tmpdir)

    def test_blocked_nodes(self):
        """获取被阻断的节点"""
        event1 = _make_normalized_event("evt-1", "agent-1", "exec", timestamp_ns=0)
        event2 = _make_normalized_event("evt-2", "agent-1", "exec", timestamp_ns=1000)

        self.graph.add_event(event1, decision=_make_decision())
        self.graph.add_event(event2,
                             decision=_make_decision(DecisionAction.BLOCK, ActionTier.TIER2),
                             blocking_result=_make_blocking_result(True, ActionTier.TIER2))

        blocked = self.graph.get_blocked_nodes()
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0].node_id, "evt-2")


class TestAuditLogger(unittest.TestCase):
    """AuditLogger 审计日志测试"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.logger = AuditLogger(output_dir=self.tmpdir)

    def tearDown(self):
        self.logger.close()
        shutil.rmtree(self.tmpdir)

    def test_start_scenario_creates_file(self):
        """start_scenario 创建 JSONL 文件"""
        filepath = self.logger.start_scenario("scenario-01")
        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith(".jsonl"))

    def test_log_event_writes_line(self):
        """log_event 写入一行 JSON"""
        self.logger.start_scenario("scenario-01")
        event = _make_normalized_event("evt-1", "agent-1", "exec",
                                       executable="/usr/bin/git")
        entry = self.logger.log_event(event, description="exec: git")

        self.assertEqual(self.logger.entry_count, 1)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.event_id, "evt-1")

    def test_read_entries(self):
        """读取审计日志条目"""
        self.logger.start_scenario("scenario-01")
        for i in range(5):
            event = _make_normalized_event(f"evt-{i}", "agent-1", "exec",
                                           timestamp_ns=i * 1000)
            self.logger.log_event(event, description=f"event {i}")

        self.logger.close()

        entries = self.logger.read_entries()
        self.assertEqual(len(entries), 5)
        self.assertEqual(entries[0].event_id, "evt-0")
        self.assertEqual(entries[4].event_id, "evt-4")

    def test_get_summary(self):
        """获取审计摘要"""
        self.logger.start_scenario("scenario-02")

        # 3 个 ALLOW, 1 个 ALERT, 1 个 BLOCK
        for i in range(3):
            event = _make_normalized_event(f"evt-{i}", "agent-1", "exec", timestamp_ns=i * 1000)
            self.logger.log_event(event, assessment=_make_assessment(0.1),
                                  decision=_make_decision(), description=f"allow {i}")

        event_alert = _make_normalized_event("evt-3", "agent-1", "file_open", timestamp_ns=3000,
                                             file_path="/project/.env")
        self.logger.log_event(event_alert, assessment=_make_assessment(0.4, RiskLevel.MEDIUM),
                              decision=_make_decision(DecisionAction.ALERT, ActionTier.TIER1),
                              description="alert")

        event_block = _make_normalized_event("evt-4", "agent-1", "exec", timestamp_ns=4000,
                                             executable="/bin/rm")
        self.logger.log_event(event_block,
                              assessment=_make_assessment(0.8, RiskLevel.HIGH, ["R001"]),
                              decision=_make_decision(DecisionAction.BLOCK, ActionTier.TIER2),
                              blocking_result=_make_blocking_result(True, ActionTier.TIER2),
                              matched_rules=["R001"],
                              description="block")

        self.logger.close()

        summary = self.logger.get_summary()
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["allowed"], 3)
        self.assertEqual(summary["alerted"], 1)
        self.assertEqual(summary["blocked"], 1)
        self.assertEqual(summary["risk_distribution"]["HIGH"], 1)
        self.assertIn("R001", summary["rule_hits"])

    def test_multiple_scenarios(self):
        """多场景连续运行（定稿 8.4 检查点: 三场景连续运行）"""
        for scenario_id in ["scenario-01", "scenario-02", "scenario-03"]:
            self.logger.start_scenario(scenario_id)
            for i in range(3):
                event = _make_normalized_event(
                    f"{scenario_id}-evt-{i}", "agent-1", "exec",
                    timestamp_ns=i * 1000
                )
                self.logger.log_event(event, description=f"{scenario_id} event {i}")
            self.logger.close()

        # 验证三个文件都生成了
        audit_dir = os.path.join(self.tmpdir, "audit")
        files = os.listdir(audit_dir)
        jsonl_files = [f for f in files if f.endswith(".jsonl")]
        self.assertEqual(len(jsonl_files), 3)


class TestReportExporter(unittest.TestCase):
    """ReportExporter 报告导出测试"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger(output_dir=self.tmpdir)
        self.graph = BehaviorGraph()
        self.exporter = ReportExporter(output_dir=self.tmpdir)

    def tearDown(self):
        self.audit_logger.close()
        shutil.rmtree(self.tmpdir)

    def _populate_data(self):
        """填充测试数据"""
        self.audit_logger.start_scenario("scenario-02")

        # 正常事件
        for i in range(3):
            event = _make_normalized_event(f"evt-{i}", "agent-1", "exec",
                                           timestamp_ns=i * 1000,
                                           executable="/usr/bin/git")
            assessment = _make_assessment(0.1)
            decision = _make_decision()
            self.audit_logger.log_event(event, assessment=assessment,
                                        decision=decision, description=f"exec: git cmd {i}")
            self.graph.add_event(event, assessment=assessment, decision=decision)

        # 阻断事件
        event_block = _make_normalized_event("evt-3", "agent-1", "exec",
                                             timestamp_ns=3000, executable="/bin/rm",
                                             arguments=["-rf", "/"])
        assessment_block = _make_assessment(0.85, RiskLevel.HIGH, ["R001"])
        decision_block = _make_decision(DecisionAction.BLOCK, ActionTier.TIER2)
        blocking_block = _make_blocking_result(True, ActionTier.TIER2)
        self.audit_logger.log_event(event_block, assessment=assessment_block,
                                    decision=decision_block, blocking_result=blocking_block,
                                    matched_rules=["R001"], description="exec: rm -rf /")
        self.graph.add_event(event_block, assessment=assessment_block,
                             decision=decision_block, blocking_result=blocking_block,
                             matched_rules=["R001"])

        self.audit_logger.close()

    def test_export_scenario_report(self):
        """导出场景报告为 Markdown"""
        self._populate_data()

        filepath = self.exporter.export_scenario_report(
            scenario_id="scenario-02",
            scenario_name="dangerous operations",
            audit_logger=self.audit_logger,
            behavior_graph=self.graph,
            scenario_description="test scenario",
            expected_result="block rm -rf",
        )

        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith(".md"))

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Verify report contains key content
        self.assertIn("scenario-02", content)
        self.assertIn("R001", content)

    def test_export_all_summary(self):
        """导出全场景汇总报告"""
        summaries = [
            {"name": "scenario-01", "total": 8, "allowed": 8, "alerted": 0, "blocked": 0, "report_file": "report1.md"},
            {"name": "scenario-02", "total": 6, "allowed": 3, "alerted": 1, "blocked": 2, "report_file": "report2.md"},
            {"name": "scenario-03", "total": 8, "allowed": 5, "alerted": 2, "blocked": 1, "report_file": "report3.md"},
        ]
        filepath = self.exporter.export_all_summary(summaries)

        self.assertTrue(os.path.exists(filepath))
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("scenario-01", content)
        self.assertIn("scenario-02", content)
        self.assertIn("scenario-03", content)


class TestPhase5Integration(unittest.TestCase):
    """Phase 5 端到端集成测试"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_scenario3_full_pipeline(self):
        """
        场景3 完整流水线（定稿 8.4 检查点）:
        BehaviorGraph JSON 包含两个 Agent 的跨节点边
        """
        graph = BehaviorGraph()
        audit_logger = AuditLogger(output_dir=self.tmpdir)
        exporter = ReportExporter(output_dir=self.tmpdir)

        audit_logger.start_scenario("scenario-03")

        # 模拟场景3事件序列
        events_data = [
            ("s3-evt-1", "agent-alpha", "exec", 0,
             {"executable": "/usr/bin/python3", "arguments": ["collect_data.py"]},
             0.05, RiskLevel.LOW, DecisionAction.ALLOW, ActionTier.TIER1, False),
            ("s3-evt-2", "agent-alpha", "file_open", 300_000_000,
             {"file_path": "/project/.env", "file_op": "read"},
             0.30, RiskLevel.MEDIUM, DecisionAction.ALERT, ActionTier.TIER1, False),
            ("s3-evt-3", "agent-alpha", "file_open", 500_000_000,
             {"file_path": "/project/secrets/api_keys.pem", "file_op": "read"},
             0.35, RiskLevel.MEDIUM, DecisionAction.ALERT, ActionTier.TIER1, False),
            ("s3-evt-4", "agent-beta", "exec", 1_000_000_000,
             {"executable": "/usr/bin/curl", "arguments": ["http://external.com/receive"]},
             0.75, RiskLevel.HIGH, DecisionAction.BLOCK, ActionTier.TIER2, True),
            ("s3-evt-5", "agent-beta", "net_conn", 1_500_000_000,
             {"remote_addr": "1.2.3.4", "remote_port": 443},
             0.60, RiskLevel.MEDIUM, DecisionAction.ALERT, ActionTier.TIER1, False),
        ]

        for eid, aid, etype, ts, kwargs, score, level, action, tier, blocked in events_data:
            event = _make_normalized_event(eid, aid, etype, timestamp_ns=ts, **kwargs)
            assessment = _make_assessment(score, level)
            decision = _make_decision(action, tier)
            blocking = _make_blocking_result(blocked, tier) if blocked else None

            graph.add_event(event, assessment=assessment, decision=decision,
                            blocking_result=blocking)
            audit_logger.log_event(event, assessment=assessment, decision=decision,
                                   blocking_result=blocking, description=f"{etype}: {eid}")

        audit_logger.close()

        # 验证 1: BehaviorGraph 包含跨 Agent 边
        self.assertTrue(graph.has_cross_agent_edges())
        graph_dict = graph.to_dict()
        cross_edges = [e for e in graph_dict["edges"] if e["edge_type"] == "cross_agent"]
        self.assertTrue(len(cross_edges) >= 1, "should have cross-agent edges")

        # 验证 2: 两个 Agent 都有节点
        agent_nodes = {}
        for node in graph.nodes:
            agent_nodes.setdefault(node.agent_id, []).append(node)
        self.assertIn("agent-alpha", agent_nodes)
        self.assertIn("agent-beta", agent_nodes)

        # 验证 3: AuditLogger 生成完整审计 JSON
        summary = audit_logger.get_summary()
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["blocked"], 1)

        # 验证 4: Markdown 报告生成
        report_path = exporter.export_scenario_report(
            scenario_id="scenario-03",
            scenario_name="Multi-Agent",
            audit_logger=audit_logger,
            behavior_graph=graph,
        )
        self.assertTrue(os.path.exists(report_path))
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertTrue(len(content) > 100)

    def test_three_scenarios_audit_output(self):
        """
        三场景连续运行（定稿 8.4 检查点）:
        AuditLogger 生成完整审计 JSON + Markdown 风险分析报告
        """
        audit_logger = AuditLogger(output_dir=self.tmpdir)
        graph = BehaviorGraph()
        exporter = ReportExporter(output_dir=self.tmpdir)

        scenario_summaries = []

        for scenario_id, scenario_name, event_count in [
            ("scenario-01", "normal", 4),
            ("scenario-02", "dangerous", 3),
            ("scenario-03", "multi-agent", 5),
        ]:
            audit_logger.start_scenario(scenario_id)
            graph.reset()

            for i in range(event_count):
                agent_id = "agent-alpha" if i % 2 == 0 else "agent-beta"
                event = _make_normalized_event(
                    f"{scenario_id}-evt-{i}", agent_id, "exec",
                    timestamp_ns=i * 1_000_000_000,
                    executable="/usr/bin/git",
                )
                score = 0.1 if scenario_id == "scenario-01" else (0.5 if i > 1 else 0.2)
                level = RiskLevel.LOW if score < 0.3 else RiskLevel.MEDIUM
                assessment = _make_assessment(score, level)
                decision = _make_decision()
                graph.add_event(event, assessment=assessment, decision=decision)
                audit_logger.log_event(event, assessment=assessment, decision=decision,
                                       description=f"event {i}")

            audit_logger.close()

            # 导出报告
            report_path = exporter.export_scenario_report(
                scenario_id=scenario_id,
                scenario_name=scenario_name,
                audit_logger=audit_logger,
                behavior_graph=graph,
            )

            summary = audit_logger.get_summary()
            scenario_summaries.append({
                "name": scenario_name,
                "total": summary["total"],
                "allowed": summary["allowed"],
                "alerted": summary["alerted"],
                "blocked": summary["blocked"],
                "report_file": report_path,
            })

        # 导出汇总报告
        summary_path = exporter.export_all_summary(scenario_summaries)
        self.assertTrue(os.path.exists(summary_path))

        # 验证: 三个审计文件都存在
        audit_dir = os.path.join(self.tmpdir, "audit")
        jsonl_files = [f for f in os.listdir(audit_dir) if f.endswith(".jsonl")]
        self.assertEqual(len(jsonl_files), 3)

        # 验证: 三个报告文件都存在
        reports_dir = os.path.join(self.tmpdir, "reports")
        md_files = [f for f in os.listdir(reports_dir) if f.endswith(".md")]
        self.assertTrue(len(md_files) >= 4)  # 3 场景报告 + 1 汇总报告


if __name__ == "__main__":
    unittest.main()
