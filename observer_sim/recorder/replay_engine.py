"""
recorder/replay_engine.py — 录制回放编排引擎

加载指定的历史录制文件，通过 FileReplayCollector + observer_core 全链路处理，
输出风险报告、审计日志和行为图谱到录制目录的 replay_output/ 子目录。
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Optional

from collector.file_replay_collector import FileReplayCollector
from models.virtual_clock import VirtualClock
from models.risk import DecisionAction
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

logger = logging.getLogger(__name__)

# observer_sim/ 目录
_OBSERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ReplayEngine:
    """
    录制回放编排引擎。

    加载录制文件 → observer_core 全链路处理 → 输出报告。
    """

    def __init__(self, config: Optional[dict] = None):
        self._config = config or {}

    def replay(self, session_dir: str,
               agent_id: str = "replay-agent") -> dict:
        """
        回放指定录制会话。

        参数:
            session_dir:  录制会话目录（含 events.jsonl）
            agent_id:     回放时使用的 agent 标识

        返回:
            dict: 回放结果摘要
        """
        events_path = os.path.join(session_dir, "events.jsonl")
        if not os.path.isfile(events_path):
            raise FileNotFoundError(f"events.jsonl 不存在: {events_path}")

        # 创建输出目录
        output_dir = os.path.join(session_dir, "replay_output")
        audit_dir = os.path.join(output_dir, "audit")
        report_dir = os.path.join(output_dir, "reports")
        graph_dir = os.path.join(output_dir, "graphs")
        evidence_dir = os.path.join(output_dir, "evidence")
        for d in [audit_dir, report_dir, graph_dir, evidence_dir]:
            os.makedirs(d, exist_ok=True)

        print(f"\n{'=' * 60}")
        print(f"  REPLAY — Loading recorded session")
        print(f"{'=' * 60}")
        print(f"  Session:  {os.path.basename(session_dir)}")
        print(f"  Input:    {events_path}")

        # Phase 1: 加载录制文件
        collector = FileReplayCollector(self._config)
        event_count = collector.load_data_file(events_path)
        collector.attach(agent_id=agent_id)

        print(f"  Events:   {event_count}")
        print(f"  Agent:    {agent_id}")

        # Phase 2: 初始化 observer_core 组件
        print(f"\n{'=' * 60}")
        print(f"  ANALYZE — Running observer_core pipeline")
        print(f"{'=' * 60}")

        clock = VirtualClock(
            start_ns=self._config.get("virtual_clock", {}).get(
                "start_ns", 1718092800000000000))
        normalizer = EventNormalizer(clock)
        rule_engine = RuleEngine()

        rules_path = os.path.join(_OBSERVER_DIR, "rules", "default_policy.yaml")
        if os.path.isfile(rules_path):
            rule_engine.load_rules(rules_path)

        scorer = RiskScorer()
        scorer.register_default_dimensions()
        baseline_checker = BaselineChecker()
        decision_engine = DecisionEngine()
        sender = MockCommandSender()

        blocking_coord = BlockingCoordinator(
            clock, sender, output_dir=evidence_dir)
        behavior_graph = BehaviorGraph()
        audit_logger = AuditLogger(output_dir=audit_dir)
        audit_logger.set_output_dir(audit_dir)
        audit_logger.start_scenario("recorded_replay")
        report_exporter = ReportExporter(output_dir=report_dir)
        report_exporter.set_output_dir(report_dir)

        # Phase 3: 逐事件处理
        stats = {"total": 0, "allow": 0, "alert": 0, "block": 0}

        for raw in collector.start():
            stats["total"] += 1
            clock.advance(100)

            # 1. 事件归一化
            norm = normalizer.normalize(raw)

            # 2. 规则匹配
            match_result = rule_engine.match(norm)
            matched_rule_ids = [r.rule_id for r in match_result.matched_rules]

            # 3. 基线收集
            baseline_checker.collect(norm)

            # 4. 风险评分
            baseline_data = baseline_checker.get_baseline_dict()
            scorer.set_baseline(baseline_data)
            agent_ctx = normalizer.get_agent_context(raw.agent_id)
            assessment = scorer.assess(norm, match_result, agent_ctx)

            # 5. 研判决策
            decision = decision_engine.decide(
                assessment, norm.event_id, raw.agent_id)

            # 6. 阻断执行
            blocking_result = blocking_coord.execute(norm, decision)

            # 7. 行为图谱
            behavior_graph.add_event(
                norm, assessment=assessment, decision=decision,
                blocking_result=blocking_result,
                matched_rules=matched_rule_ids
            )

            # 8. 审计日志
            desc = _build_description(norm)
            audit_logger.log_event(
                norm, assessment=assessment, decision=decision,
                blocking_result=blocking_result,
                matched_rules=matched_rule_ids,
                description=desc
            )

            # 统计
            if blocking_result.blocked:
                stats["block"] += 1
            elif decision.action == DecisionAction.ALERT:
                stats["alert"] += 1
            else:
                stats["allow"] += 1

            status = "BLOCK" if blocking_result.blocked else (
                "ALERT" if decision.action == DecisionAction.ALERT
                else "PASS")
            print(f"  [{status:5s}] ({stats['total']:03d}) {desc}")

        collector.detach()
        audit_logger.close()

        # Phase 4: 导出报告
        print(f"\n  Generating reports...")

        try:
            report_path = report_exporter.export_scenario_report(
                scenario_id="recorded_replay",
                scenario_name="Recorded Session Replay Analysis",
                audit_logger=audit_logger,
                behavior_graph=behavior_graph,
                scenario_description=(
                    f"Replay of recorded session: "
                    f"{os.path.basename(session_dir)}"),
                expected_result="Analyze recorded AGENT behavior",
            )
        except Exception as e:
            logger.warning(f"报告导出失败: {e}")
            report_path = ""

        # 保存行为图谱
        graph_path = os.path.join(
            graph_dir, "graph_recorded_replay.json")
        try:
            behavior_graph.save_json(graph_path)
        except Exception as e:
            logger.warning(f"行为图谱保存失败: {e}")
            graph_path = ""

        # 保存回放摘要 JSON
        summary = {
            **stats,
            "session_dir": session_dir,
            "session_id": os.path.basename(session_dir),
            "events_loaded": event_count,
            "agent_id": agent_id,
            "report_path": report_path,
            "graph_path": graph_path,
            "output_dir": output_dir,
            "replay_time": datetime.now().isoformat(),
        }
        summary_path = os.path.join(output_dir, "replay_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

        print(f"\n  Analysis complete:")
        print(f"    Total:   {stats['total']}")
        print(f"    Allow:   {stats['allow']}")
        print(f"    Alert:   {stats['alert']}")
        print(f"    Block:   {stats['block']}")
        print(f"    Report:  {report_path}")
        print(f"    Graph:   {graph_path}")
        print(f"    Audit:   {audit_dir}")
        print(f"    Summary: {summary_path}")
        print(f"    Output:  {output_dir}")

        return summary


def _build_description(event) -> str:
    """构建事件的简短描述"""
    et = event.event_type
    if et == "exec":
        cmd = getattr(event, 'command_string', None) or ""
        if not cmd:
            raw = getattr(event, 'raw', event)
            exe = getattr(raw, 'executable', None) or ""
            args = getattr(raw, 'arguments', None) or []
            cmd = " ".join([exe] + list(args))
        return f"exec: {cmd[:60]}"
    elif et == "file_open":
        raw = getattr(event, 'raw', event)
        op = getattr(raw, 'file_op', None) or "open"
        path = getattr(raw, 'file_path', None) or ""
        return f"file_{op}: {path}"
    elif et == "net_conn":
        raw = getattr(event, 'raw', event)
        addr = getattr(raw, 'remote_addr', None) or ""
        port = getattr(raw, 'remote_port', None)
        return f"net: {addr}:{port}" if port else f"net: {addr}"
    return f"{et}"
