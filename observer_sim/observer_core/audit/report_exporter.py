"""
ReportExporter — Markdown 风险分析报告导出

核心职责:
1. 汇总场景运行结果，生成 Markdown 格式的风险分析报告
2. 包含：概览、事件处理明细、风险评分分布、阻断统计、因果链分析
3. 输出到 output/reports/ 目录

报告结构:
- 概览（场景信息、统计摘要）
- 风险评分明细表（四维评分）
- 阻断事件列表
- 规则命中统计
- Agent 行为摘要
- 因果链分析（如有阻断事件）
"""

import os
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from observer_core.audit.audit_logger import AuditLogger, AuditEntry
from observer_core.audit.behavior_graph import BehaviorGraph

logger = logging.getLogger(__name__)


class ReportExporter:
    """
    Markdown 风险分析报告导出器。

    从 AuditLogger 和 BehaviorGraph 收集数据，
    生成人类可读的 Markdown 报告。
    """

    def __init__(self, output_dir: str = "output"):
        self._output_dir = output_dir
        self._reports_dir = os.path.join(output_dir, "reports")

    def set_output_dir(self, output_dir: str):
        """
        动态设置报告输出目录（用于支持分类目录结构）。

        Args:
            output_dir: 新的报告目录
        """
        self._reports_dir = output_dir

    def export_scenario_report(self, scenario_id: str,
                               scenario_name: str,
                               audit_logger: AuditLogger,
                               behavior_graph: BehaviorGraph,
                               scenario_description: str = "",
                               expected_result: str = "") -> str:
        """
        导出单个场景的风险分析报告。

        Args:
            scenario_id: 场景 ID
            scenario_name: 场景名称
            audit_logger: 审计日志记录器
            behavior_graph: 行为图谱
            scenario_description: 场景描述
            expected_result: 预期结果

        Returns:
            str: 报告文件路径
        """
        os.makedirs(self._reports_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"risk_report_{scenario_id}_{ts}.md"
        filepath = os.path.join(self._reports_dir, filename)

        # 收集数据
        summary = audit_logger.get_summary()
        entries = audit_logger.read_entries()
        graph_data = behavior_graph.to_dict()

        # 生成 Markdown 内容
        lines = []
        lines.append(f"# 风险分析报告: {scenario_name}")
        lines.append("")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"> 场景 ID: {scenario_id}")
        lines.append("")

        # 概览
        lines.append("## 1. 概览")
        lines.append("")
        lines.append(f"- **场景描述**: {scenario_description}")
        lines.append(f"- **预期结果**: {expected_result}")
        lines.append(f"- **总事件数**: {summary.get('total', 0)}")
        lines.append(f"- **放行**: {summary.get('allowed', 0)}")
        lines.append(f"- **告警**: {summary.get('alerted', 0)}")
        lines.append(f"- **阻断**: {summary.get('blocked', 0)}")
        lines.append("")

        # 风险等级分布
        risk_dist = summary.get("risk_distribution", {})
        lines.append("## 2. 风险等级分布")
        lines.append("")
        lines.append("| 风险等级 | 事件数 | 占比 |")
        lines.append("|---------|:---:|:---:|")
        total = summary.get("total", 1)
        for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            count = risk_dist.get(level, 0)
            pct = f"{count / total * 100:.1f}%" if total > 0 else "0%"
            bar = self._make_bar(count, total)
            lines.append(f"| {level} | {count} | {pct} {bar} |")
        lines.append("")

        # 阻断事件明细
        blocked_entries = [e for e in entries if e.blocked]
        if blocked_entries:
            lines.append("## 3. 阻断事件明细")
            lines.append("")
            lines.append("| 事件ID | Agent | 类型 | 风险评分 | 决策 | 阻断等级 | 原因 |")
            lines.append("|--------|-------|------|---------|------|---------|------|")
            for e in blocked_entries:
                desc = e.description[:30] + "..." if len(e.description) > 30 else e.description
                lines.append(
                    f"| {e.event_id} | {e.agent_id} | {e.event_type} | "
                    f"{e.risk_score:.2f} | {e.decision_action} | {e.blocking_tier} | "
                    f"{e.decision_reason[:20]} |"
                )
            lines.append("")

        # 规则命中统计
        rule_hits = summary.get("rule_hits", {})
        if rule_hits:
            lines.append("## 4. 规则命中统计")
            lines.append("")
            lines.append("| 规则ID | 命中次数 |")
            lines.append("|--------|:---:|")
            for rule_id, count in sorted(rule_hits.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| {rule_id} | {count} |")
            lines.append("")

        # Agent 行为摘要
        agent_summaries = graph_data.get("agent_summaries", {})
        if agent_summaries:
            section_num = 5 if blocked_entries else 3
            if rule_hits:
                section_num += 1
            lines.append(f"## {section_num}. Agent 行为摘要")
            lines.append("")
            lines.append("| Agent | 事件数 | 放行 | 告警 | 阻断 | 最高风险分 | 平均风险分 |")
            lines.append("|-------|:---:|:---:|:---:|:---:|:---:|:---:|")
            for aid, s in agent_summaries.items():
                lines.append(
                    f"| {aid} | {s['total_events']} | {s['allowed']} | "
                    f"{s['alerted']} | {s['blocked']} | "
                    f"{s['max_risk_score']:.2f} | {s['avg_risk_score']:.2f} |"
                )
            lines.append("")

        # 跨 Agent 关联
        cross_edges = [e for e in graph_data.get("edges", []) if e["edge_type"] == "cross_agent"]
        if cross_edges:
            lines.append(f"## {section_num + 1}. 跨 Agent 关联分析")
            lines.append("")
            lines.append(f"检测到 **{len(cross_edges)}** 条跨 Agent 关联边:")
            lines.append("")
            for edge in cross_edges[:10]:  # 最多显示 10 条
                lines.append(f"- {edge['source_id']} -> {edge['target_id']}: {edge['description']}")
            lines.append("")

        # 事件处理时间线
        lines.append(f"## {section_num + 2}. 事件处理时间线")
        lines.append("")
        lines.append("```")
        for e in entries:
            status = "BLOCK" if e.blocked else ("ALERT" if e.decision_action == "ALERT" else "PASS")
            marker = "[X]" if e.blocked else "[ ]"
            lines.append(f"  {marker} [{status:5s}] t={e.timestamp_ns:>12d}ns  {e.description[:50]}")
        lines.append("```")
        lines.append("")

        # 页脚
        lines.append("---")
        lines.append(f"*本报告由方寸观察者模拟学习系统自动生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        # 写入文件
        content = "\n".join(lines)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"[ReportExporter] Report saved: {filepath}")
        return filepath

    def _make_bar(self, count: int, total: int, width: int = 20) -> str:
        """生成简单的文本柱状图"""
        if total == 0:
            return ""
        filled = int(count / total * width)
        return "\u2588" * filled + "\u2591" * (width - filled)

    def export_all_summary(self, scenario_summaries: List[Dict]) -> str:
        """
        导出所有场景的汇总报告。

        Args:
            scenario_summaries: 每个场景的摘要信息列表

        Returns:
            str: 汇总报告文件路径
        """
        os.makedirs(self._reports_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self._reports_dir, f"summary_all_{ts}.md")

        lines = []
        lines.append("# 方寸观察者模拟学习系统 - 全场景运行汇总报告")
        lines.append("")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        lines.append("## 场景运行摘要")
        lines.append("")
        lines.append("| 场景 | 事件数 | 放行 | 告警 | 阻断 | 报告文件 |")
        lines.append("|------|:---:|:---:|:---:|:---:|---------|")

        for s in scenario_summaries:
            lines.append(
                f"| {s.get('name', 'N/A')} | {s.get('total', 0)} | "
                f"{s.get('allowed', 0)} | {s.get('alerted', 0)} | "
                f"{s.get('blocked', 0)} | {s.get('report_file', 'N/A')} |"
            )
        lines.append("")

        total_events = sum(s.get("total", 0) for s in scenario_summaries)
        total_blocked = sum(s.get("blocked", 0) for s in scenario_summaries)
        total_alerted = sum(s.get("alerted", 0) for s in scenario_summaries)

        lines.append("## 总体统计")
        lines.append("")
        lines.append(f"- **总事件数**: {total_events}")
        lines.append(f"- **总告警数**: {total_alerted}")
        lines.append(f"- **总阻断数**: {total_blocked}")
        lines.append(f"- **场景数**: {len(scenario_summaries)}")
        lines.append("")
        lines.append("---")
        lines.append(f"*本报告由方寸观察者模拟学习系统自动生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        content = "\n".join(lines)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"[ReportExporter] Summary saved: {filepath}")
        return filepath
