"""
ChainReportBuilder — 链式结构化风险报告构建器

核心职责:
1. 构建因果链: Root Cause → Intermediate Step → Trigger Event → Impact
2. 输出双格式报告:
   - 结构化 JSON → output/audit/chain_report_*.json
   - Markdown 风险分析报告 → output/reports/风险分析报告_*.md

报告结构 (定稿 4.5):
- 报告头: report_id, timestamp, severity, affected_agents
- 因果链: CauseStep[] — 每步含 event, actor, risk_contribution, causal_link, evidence
- 风险判定详情: overall_score, score_breakdown, matched_rules, baseline_comparison
- 影响评估: impact_type, impact_scope, confidence
- 处置建议: recommended_action, alternative_actions
"""

import os
import json
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.event import NormalizedEvent
from models.risk import RiskAssessment, Decision, DecisionAction, ActionTier

logger = logging.getLogger(__name__)


@dataclass
class CauseStep:
    """因果链中的一个步骤"""
    step_id: int
    event_type: str
    description: str
    actor: str  # agent_id
    pid: Optional[int] = None
    risk_contribution: float = 0.0  # 该步骤对总风险的贡献
    causal_link: str = ""  # 与下一步的因果关系说明
    evidence: Dict = field(default_factory=dict)  # 证据数据


@dataclass
class ImpactAssessment:
    """影响评估"""
    impact_type: str = ""  # 影响类型: data_leak, system_damage, privilege_escalation, etc.
    impact_scope: str = ""  # 影响范围: single_agent, multi_agent, system_wide
    confidence: float = 0.0  # 判定置信度
    affected_resources: List[str] = field(default_factory=list)  # 受影响的资源


@dataclass
class ChainStructuredReport:
    """链式结构化报告"""
    report_id: str = ""
    timestamp_ns: int = 0
    severity: str = "LOW"
    affected_agents: List[str] = field(default_factory=list)
    cause_chain: List[CauseStep] = field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = None
    decision: Optional[Decision] = None
    impact: ImpactAssessment = field(default_factory=ImpactAssessment)
    recommended_action: str = ""
    alternative_actions: List[str] = field(default_factory=list)


class ChainReportBuilder:
    """
    链式报告构建器。

    工作流:
    1. 收集事件链（从 EventNormalizer 的滑动窗口）
    2. 构建因果链（分析事件间的因果关系）
    3. 生成双格式报告（JSON + Markdown）
    """

    def __init__(self, output_dir: str = "output"):
        """
        Args:
            output_dir: 输出根目录
        """
        self._output_dir = output_dir
        self._audit_dir = os.path.join(output_dir, "audit")
        self._reports_dir = os.path.join(output_dir, "reports")
        self._report_counter = 0

    def build_report(self, events: List[NormalizedEvent],
                     assessment: RiskAssessment,
                     decision: Decision,
                     trigger_event: NormalizedEvent) -> ChainStructuredReport:
        """
        构建链式结构化报告。

        Args:
            events: 事件链（按时间排序的事件列表）
            assessment: 风险评估结果
            decision: 研判决策
            trigger_event: 触发报告的事件

        Returns:
            ChainStructuredReport: 完整的链式报告
        """
        self._report_counter += 1
        report = ChainStructuredReport()

        # 报告头
        report.report_id = f"RPT-{datetime.now().strftime('%Y%m%d')}-{self._report_counter:03d}"
        report.timestamp_ns = trigger_event.raw.timestamp_ns
        report.severity = assessment.risk_level.value
        report.affected_agents = list(set(e.agent_id for e in events if e.agent_id))

        # 构建因果链
        report.cause_chain = self._build_cause_chain(events, assessment)

        # 风险判定详情
        report.risk_assessment = assessment
        report.decision = decision

        # 影响评估
        report.impact = self._assess_impact(events, assessment, decision)

        # 处置建议
        report.recommended_action, report.alternative_actions = \
            self._generate_recommendations(decision, assessment)

        return report

    def _build_cause_chain(self, events: List[NormalizedEvent],
                           assessment: RiskAssessment) -> List[CauseStep]:
        """
        构建因果链。

        逻辑:
        1. 从事件列表中提取关键事件（命中规则的事件）
        2. 分析事件间的因果关系
        3. 构建步骤序列: Root Cause → ... → Trigger Event
        """
        steps = []
        step_id = 1

        # 提取关键事件（命中规则的事件）
        key_events = []
        for e in events:
            # 简化: 所有事件都作为因果链的一部分
            # 实际可根据 match_result 过滤
            key_events.append(e)

        # 如果没有关键事件，使用最近的事件
        if not key_events and events:
            key_events = events[-3:]  # 最近 3 个事件

        for i, event in enumerate(key_events):
            step = CauseStep(
                step_id=step_id,
                event_type=event.event_type,
                description=self._describe_event(event),
                actor=event.agent_id or "unknown",
                pid=event.raw.pid,
                risk_contribution=self._estimate_risk_contribution(event, assessment, i, len(key_events)),
                causal_link=self._infer_causal_link(event, key_events[i + 1] if i + 1 < len(key_events) else None),
                evidence=self._extract_evidence(event),
            )
            steps.append(step)
            step_id += 1

        return steps

    def _describe_event(self, event: NormalizedEvent) -> str:
        """生成事件的文本描述"""
        if event.event_type == "exec":
            cmd = event.command_string or f"{event.raw.executable} {' '.join(event.raw.arguments or [])}"
            return f"执行命令: {cmd}"
        elif event.event_type == "file_open":
            op = event.raw.file_op or "open"
            path = event.raw.file_path or "unknown"
            return f"文件操作: {op} {path}"
        elif event.event_type == "net_conn":
            addr = event.raw.remote_addr or "unknown"
            port = event.raw.remote_port or 0
            return f"网络连接: {addr}:{port}"
        else:
            return f"事件: {event.event_type}"

    def _estimate_risk_contribution(self, event: NormalizedEvent,
                                     assessment: RiskAssessment,
                                     index: int, total: int) -> float:
        """估算单个事件对总风险的贡献"""
        # 简化: 平均分配，或根据事件类型加权
        base = assessment.overall_score / total if total > 0 else 0.0

        # 命中规则的事件贡献更大
        if event.event_type == "exec" and event.raw.executable:
            exe = event.raw.executable
            if any(kw in exe.lower() for kw in ["rm", "chmod", "sudo", "curl", "wget"]):
                return min(base * 1.5, 1.0)

        return base

    def _infer_causal_link(self, current: NormalizedEvent,
                           next_event: Optional[NormalizedEvent]) -> str:
        """推断当前事件与下一步事件的因果关系"""
        if next_event is None:
            return "触发最终风险判定"

        # 简单的因果推断规则
        if current.event_type == "file_open" and next_event.event_type == "net_conn":
            return "读取敏感数据后发起网络连接，疑似数据外传"
        elif current.event_type == "exec" and next_event.event_type == "file_open":
            return "执行命令后访问文件，可能存在权限滥用"
        elif current.event_type == "exec" and next_event.event_type == "net_conn":
            return "执行命令后发起网络连接，可能存在远程控制"
        else:
            return "行为序列异常"

    def _extract_evidence(self, event: NormalizedEvent) -> Dict:
        """提取事件的证据数据"""
        evidence = {
            "event_id": event.raw.event_id,
            "timestamp_ns": event.raw.timestamp_ns,
            "event_type": event.event_type,
            "agent_id": event.agent_id,
        }

        if event.event_type == "exec":
            evidence["executable"] = event.raw.executable
            evidence["arguments"] = event.raw.arguments
            evidence["command_string"] = event.command_string
        elif event.event_type == "file_open":
            evidence["file_path"] = event.raw.file_path
            evidence["file_op"] = event.raw.file_op
        elif event.event_type == "net_conn":
            evidence["remote_addr"] = event.raw.remote_addr
            evidence["remote_port"] = event.raw.remote_port

        return evidence

    def _assess_impact(self, events: List[NormalizedEvent],
                       assessment: RiskAssessment,
                       decision: Decision) -> ImpactAssessment:
        """评估影响"""
        impact = ImpactAssessment()

        # 影响类型推断
        has_file_access = any(e.event_type == "file_open" for e in events)
        has_net_conn = any(e.event_type == "net_conn" for e in events)
        has_dangerous_cmd = any(
            e.event_type == "exec" and e.raw.executable and
            any(kw in e.raw.executable.lower() for kw in ["rm", "chmod", "sudo"])
            for e in events
        )

        if has_file_access and has_net_conn:
            impact.impact_type = "data_leak"
        elif has_dangerous_cmd:
            impact.impact_type = "system_damage"
        elif any("sudo" in (e.command_string or "").lower() for e in events):
            impact.impact_type = "privilege_escalation"
        else:
            impact.impact_type = "suspicious_behavior"

        # 影响范围
        agents = set(e.agent_id for e in events if e.agent_id)
        if len(agents) > 1:
            impact.impact_scope = "multi_agent"
        else:
            impact.impact_scope = "single_agent"

        # 置信度
        impact.confidence = assessment.confidence

        # 受影响资源
        for e in events:
            if e.raw.file_path:
                impact.affected_resources.append(f"file:{e.raw.file_path}")
            if e.raw.remote_addr:
                impact.affected_resources.append(
                    f"net:{e.raw.remote_addr}:{e.raw.remote_port}"
                )

        return impact

    def _generate_recommendations(self, decision: Decision,
                                   assessment: RiskAssessment):
        """生成处置建议"""
        if decision.action == DecisionAction.BLOCK:
            recommended = "立即阻断该 Agent 的所有操作，进入隔离观察状态"
            alternatives = [
                "人工审核后手动解除隔离",
                "限制 Agent 的网络访问权限",
                "降低 Agent 的文件系统权限",
            ]
        elif decision.action == DecisionAction.ALERT:
            recommended = "记录告警日志，持续监控该 Agent 的后续行为"
            alternatives = [
                "增加日志详细度",
                "设置更敏感的告警阈值",
                "通知安全管理员",
            ]
        else:
            recommended = "继续监控，无需特殊处置"
            alternatives = []

        return recommended, alternatives

    def save_json(self, report: ChainStructuredReport,
                  filepath: Optional[str] = None) -> str:
        """
        保存结构化 JSON 报告。

        Args:
            report: 链式报告
            filepath: 保存路径，默认 output/audit/chain_report_<report_id>.json

        Returns:
            实际保存的文件路径
        """
        if filepath is None:
            os.makedirs(self._audit_dir, exist_ok=True)
            filepath = os.path.join(self._audit_dir, f"chain_report_{report.report_id}.json")
        else:
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        data = self._report_to_dict(report)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        logger.info(f"[ChainReportBuilder] JSON report saved to {filepath}")
        return filepath

    def save_markdown(self, report: ChainStructuredReport,
                      filepath: Optional[str] = None) -> str:
        """
        保存 Markdown 风险分析报告。

        Args:
            report: 链式报告
            filepath: 保存路径，默认 output/reports/风险分析报告_<report_id>.md

        Returns:
            实际保存的文件路径
        """
        if filepath is None:
            os.makedirs(self._reports_dir, exist_ok=True)
            filepath = os.path.join(self._reports_dir, f"风险分析报告_{report.report_id}.md")
        else:
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        md_content = self._render_markdown(report)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md_content)

        logger.info(f"[ChainReportBuilder] Markdown report saved to {filepath}")
        return filepath

    def _report_to_dict(self, report: ChainStructuredReport) -> dict:
        """将报告转换为可 JSON 序列化的字典"""
        return {
            "report_id": report.report_id,
            "timestamp_ns": report.timestamp_ns,
            "severity": report.severity,
            "affected_agents": report.affected_agents,
            "cause_chain": [
                {
                    "step_id": step.step_id,
                    "event_type": step.event_type,
                    "description": step.description,
                    "actor": step.actor,
                    "pid": step.pid,
                    "risk_contribution": step.risk_contribution,
                    "causal_link": step.causal_link,
                    "evidence": step.evidence,
                }
                for step in report.cause_chain
            ],
            "risk_assessment": {
                "overall_score": report.risk_assessment.overall_score if report.risk_assessment else 0.0,
                "risk_level": report.risk_assessment.risk_level.value if report.risk_assessment else "LOW",
                "dimension_scores": [
                    {
                        "name": ds.name,
                        "score": ds.score,
                        "weight": ds.weight,
                        "weighted_score": ds.weighted_score,
                    }
                    for ds in (report.risk_assessment.dimension_scores if report.risk_assessment else [])
                ],
                "matched_rule_ids": report.risk_assessment.matched_rule_ids if report.risk_assessment else [],
            } if report.risk_assessment else None,
            "decision": {
                "action": report.decision.action.value if report.decision else "ALLOW",
                "tier": report.decision.tier.value if report.decision else "TIER1",
                "reason": report.decision.reason if report.decision else "",
            } if report.decision else None,
            "impact": {
                "impact_type": report.impact.impact_type,
                "impact_scope": report.impact.impact_scope,
                "confidence": report.impact.confidence,
                "affected_resources": report.impact.affected_resources,
            },
            "recommended_action": report.recommended_action,
            "alternative_actions": report.alternative_actions,
        }

    def _render_markdown(self, report: ChainStructuredReport) -> str:
        """渲染 Markdown 报告"""
        lines = []

        # 标题
        lines.append("# 风险分析报告\n")

        # 概览
        lines.append("## 概览")
        lines.append(f"- **报告编号**: {report.report_id}")
        lines.append(f"- **严重程度**: {report.severity}")
        if report.risk_assessment:
            lines.append(f"- **综合评分**: {report.risk_assessment.overall_score:.2f}")
            lines.append(f"- **置信度**: {report.risk_assessment.confidence * 100:.0f}%")
        lines.append(f"- **涉及 Agent**: {', '.join(report.affected_agents)}")
        lines.append("")

        # 因果链分析
        lines.append("## 因果链分析")
        for step in report.cause_chain:
            lines.append(f"### 步骤{step.step_id}: {step.description}")
            lines.append(f"- **执行者**: {step.actor} (pid={step.pid})")
            lines.append(f"- **风险贡献**: +{step.risk_contribution:.2f}")
            if step.causal_link:
                lines.append(f"- **因果关系**: {step.causal_link}")
            lines.append("")

        # 风险评分明细
        if report.risk_assessment and report.risk_assessment.dimension_scores:
            lines.append("## 风险评分明细")
            lines.append("| 维度 | 得分 | 权重 | 加权分 |")
            lines.append("|------|------|------|--------|")
            for ds in report.risk_assessment.dimension_scores:
                lines.append(f"| {ds.name} | {ds.score:.2f} | {ds.weight * 100:.0f}% | {ds.weighted_score:.2f} |")
            lines.append(f"| **综合** | | | **{report.risk_assessment.overall_score:.2f}** |")
            lines.append("")

        # 影响评估
        lines.append("## 影响评估")
        lines.append(f"- **影响类型**: {report.impact.impact_type}")
        lines.append(f"- **影响范围**: {report.impact.impact_scope}")
        lines.append(f"- **置信度**: {report.impact.confidence * 100:.0f}%")
        if report.impact.affected_resources:
            lines.append(f"- **受影响资源**: {', '.join(report.impact.affected_resources)}")
        lines.append("")

        # 处置建议
        lines.append("## 处置建议")
        lines.append(f"**推荐处置**: {report.recommended_action}")
        if report.alternative_actions:
            lines.append("\n**备选方案**:")
            for alt in report.alternative_actions:
                lines.append(f"- {alt}")
        lines.append("")

        # 规则匹配
        if report.risk_assessment and report.risk_assessment.matched_rule_ids:
            lines.append("## 命中规则")
            lines.append(f"- {', '.join(report.risk_assessment.matched_rule_ids)}")
            lines.append("")

        return "\n".join(lines)
