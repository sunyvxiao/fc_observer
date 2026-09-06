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
from typing import Dict, List, Optional, Tuple
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

        # 阻断事件明细 — 统一使用 blocking_tier 判断是否实际执行了阻断
        blocked_entries = [e for e in entries if e.blocking_tier in ("TIER2", "TIER3")]
        if blocked_entries:
            lines.append("## 3. 阻断/升级事件明细")
            lines.append("")
            lines.append("| 事件ID | Agent | 类型 | 风险评分 | 研判决策 | 执行等级 | 原因 | 备注 |")
            lines.append("|--------|-------|------|---------|---------|---------|------|------|")
            for e in blocked_entries:
                desc = e.description[:30] + "..." if len(e.description) > 30 else e.description
                is_escalated = "升级阻断" if e.decision_action != "BLOCK" else ""
                lines.append(
                    f"| {e.event_id} | {e.agent_id} | {e.event_type} | "
                    f"{e.risk_score:.2f} | {e.decision_action} | {e.blocking_tier} | "
                    f"{e.decision_reason[:20]} | {is_escalated} |"
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
        # 章节编号（无 Agent 摘要时也需计算，供后续“跨 Agent 关联/时间线”使用；
        # 编号规则与原逻辑一致：第3节=阻断明细，第4节=规则命中统计）
        agent_summaries = graph_data.get("agent_summaries", {})
        section_num = 5 if blocked_entries else 3
        if rule_hits:
            section_num += 1
        if agent_summaries:
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
            # 统一以 BlockingResult 为数据源：blocked=True → [X] BLOCK，升级事件标 (upgraded)
            if e.blocked:
                marker = "[X]"
                status = "BLOCK"
                escalated_note = " (upgraded)" if e.decision_action != "BLOCK" else ""
            else:
                marker = "[ ]"
                status = e.decision_action if e.decision_action in ("BLOCK", "ALERT") else "PASS"
                escalated_note = ""
            session_tag = f" [{e.session_id}]" if e.session_id else ""
            lines.append(f"  {marker} [{status:5s}] t={e.timestamp_ns:>12d}ns{session_tag}  {e.description[:50]}{escalated_note}")
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

    def export_from_segments(self, merged_data: dict,
                             time_range: Tuple[int, int] = None,
                             scenario_name: str = "实时监测") -> str:
        """
        从 ReportCacheManager 合并的片段数据导出 Markdown 报告。

        Args:
            merged_data: ReportCacheManager.merge_segments() 的返回结果
            time_range:  (start_ns, end_ns) 可选时间范围
            scenario_name: 报告标题

        Returns:
            str: 报告文件路径
        """
        os.makedirs(self._reports_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"risk_report_range_{ts}.md"
        filepath = os.path.join(self._reports_dir, filename)

        stats = merged_data.get("merged_stats", {})
        coverage = merged_data.get("coverage", {})
        segment_count = merged_data.get("segment_count", 0)
        gaps_filled = merged_data.get("gaps_filled", 0)

        lines = []
        lines.append(f"# 风险分析报告: {scenario_name}")
        lines.append("")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"> 报告类型: 片段拼接 (D1+D2 双模)")

        if time_range:
            start_dt = datetime.fromtimestamp(time_range[0] / 1_000_000_000)
            end_dt = datetime.fromtimestamp(time_range[1] / 1_000_000_000)
            lines.append(f"> 时间范围: {start_dt.isoformat()} ~ {end_dt.isoformat()}")
        lines.append(f"> 覆盖片段: {segment_count} 个")
        if gaps_filled > 0:
            lines.append(f"> 间隙补充: {gaps_filled} 条（从 audit JSONL）")
        lines.append("")

        # 概览
        lines.append("## 1. 概览")
        lines.append("")
        total = stats.get("total", 0)
        lines.append(f"- **总事件数**: {total}")
        lines.append(f"- **放行**: {stats.get('allow', 0)}")
        lines.append(f"- **告警**: {stats.get('alert', 0)}")
        lines.append(f"- **阻断**: {stats.get('block', 0)}")
        lines.append(f"- **最高风险分**: {stats.get('max_score', 0):.2f}")
        lines.append("")

        # 风险等级分布
        risk_dist = stats.get("risk_dist", {})
        lines.append("## 2. 风险等级分布")
        lines.append("")
        lines.append("| 风险等级 | 事件数 | 占比 |")
        lines.append("|---------|:---:|:---:|")
        for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            count = risk_dist.get(level, 0)
            pct = f"{count / total * 100:.1f}%" if total > 0 else "0%"
            bar = self._make_bar(count, total)
            lines.append(f"| {level} | {count} | {pct} {bar} |")
        lines.append("")

        # 规则命中
        rule_hits = stats.get("rule_hits", {})
        if rule_hits:
            lines.append("## 3. 规则命中统计")
            lines.append("")
            lines.append("| 规则ID | 命中次数 |")
            lines.append("|--------|:---:|")
            sorted_rules = sorted(rule_hits.items(), key=lambda x: x[1], reverse=True)
            for rule_id, count in sorted_rules:
                lines.append(f"| {rule_id} | {count} |")
            lines.append("")

        # 覆盖率
        if coverage:
            lines.append("## 4. 数据覆盖率")
            lines.append("")
            cov_start = coverage.get("start_ns", 0)
            cov_end = coverage.get("end_ns", 0)
            duration_s = (cov_end - cov_start) / 1_000_000_000 if cov_end > cov_start else 0
            lines.append(f"- 覆盖开始: {datetime.fromtimestamp(cov_start / 1_000_000_000).isoformat() if cov_start else 'N/A'}")
            lines.append(f"- 覆盖结束: {datetime.fromtimestamp(cov_end / 1_000_000_000).isoformat() if cov_end else 'N/A'}")
            lines.append(f"- 覆盖时长: {duration_s:.1f}s")
            lines.append(f"- 拼接片段: {segment_count} 个")
            lines.append(f"- 间隙补充: {gaps_filled} 条")
            lines.append("")

        # 页脚
        lines.append("---")
        lines.append(f"*本报告由方寸观察者模拟学习系统自动生成（片段拼接模式） | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        content = "\n".join(lines)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"[ReportExporter] Segment report saved: {filepath}")
        return filepath

    @staticmethod
    def _fmt_ns(ns: int) -> str:
        """纳秒时间戳 → ISO 字符串（容错，虚拟时间可解释为历元）。"""
        try:
            return datetime.fromtimestamp(int(ns) / 1_000_000_000).isoformat()
        except (OverflowError, OSError, ValueError):
            return str(ns)

    def _build_l0_index(self, audit_dir: Optional[str]) -> Dict[str, dict]:
        """
        扫描 L0 audit_*.jsonl 文件，构建 entry_id → 下钻定位索引（L-T12）。

        Returns:
            {entry_id: {"file": 绝对路径, "line": 行号}}
        只读扫描，绝不触碰 L0 文件内容（三红线之 L0 永不删除）。
        """
        index: Dict[str, dict] = {}
        if not audit_dir or not os.path.isdir(audit_dir):
            return index
        for fn in sorted(os.listdir(audit_dir)):
            if not (fn.startswith("audit_") and fn.endswith(".jsonl")):
                continue
            path = os.path.join(audit_dir, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line_no, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        eid = obj.get("event_id")
                        if eid:
                            index[eid] = {"file": path, "line": line_no}
            except OSError:
                continue
        return index

    def export_daily_report(self, l3: dict, audit_dir: Optional[str] = None,
                            scenario_name: str = "天级深度审计") -> str:
        """
        导出 L3 天级深度审计报告（L-T12）。

        报告结构：概览 → CUSUM 漂移告警 → 串谋攻击链重建 →
        分钟级序列告警 → 违规累计与升级 → 指纹关联 → 异常明细 →
        处置建议 → L0 下钻索引（entry_id → audit_*.jsonl 行号）。

        Args:
            l3:            RollupEngine.rollup_day 的产物 dict
            audit_dir:     可选，L0 审计文件目录（构建下钻索引）
            scenario_name: 报告标题后缀

        Returns:
            str: 报告文件路径
        """
        os.makedirs(self._reports_dir, exist_ok=True)
        day_ns = int(l3.get("day_start_ns", 0))
        day_str = ""
        try:
            day_str = datetime.fromtimestamp(day_ns / 1_000_000_000).strftime("%Y%m%d")
        except (OverflowError, OSError, ValueError):
            day_str = str(day_ns)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"risk_report_daily_{day_str}_{ts}.md"
        filepath = os.path.join(self._reports_dir, filename)

        stats = l3.get("stats") or {}
        total = stats.get("total", 0)
        drift_alerts = l3.get("drift_alerts") or []
        chains = l3.get("collusion_chains") or []
        sequence_alerts = l3.get("sequence_alerts") or []
        escalation = l3.get("escalation") or {}
        fp_links = [l for l in (l3.get("fp_links") or []) if l.get("cross_agent")]
        anomalies = l3.get("anomalies") or []
        entry_ids = l3.get("entry_ids") or []

        lines = []
        lines.append(f"# 天级深度审计报告: {scenario_name}")
        lines.append("")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("> 报告类型: L3 天级审计（分层日志金字塔）")
        lines.append(f"> 审计日: {self._fmt_ns(day_ns)} ~ "
                     f"{self._fmt_ns(l3.get('day_end_ns', 0))}")
        lines.append(f"> L2 小时日志数: {l3.get('l2_count', 0)} / 24")
        lines.append(f"> 产物格式版本: {l3.get('format_version', '-')}")
        lines.append("")

        # ── 1. 概览 ──
        lines.append("## 1. 概览")
        lines.append("")
        lines.append(f"- **总事件数**: {total}")
        lines.append(f"- **放行**: {stats.get('allow', 0)}")
        lines.append(f"- **告警**: {stats.get('alert', 0)}")
        lines.append(f"- **阻断**: {stats.get('block', 0)}")
        lines.append(f"- **最高风险分**: {stats.get('max_score', 0):.2f}")
        risk_dist = stats.get("risk_dist", {})
        lines.append("")
        lines.append("| 风险等级 | 事件数 |")
        lines.append("|---------|:---:|")
        for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            lines.append(f"| {level} | {risk_dist.get(level, 0)} |")
        lines.append("")

        # ── 2. CUSUM 漂移告警 ──
        lines.append("## 2. CUSUM 基线漂移告警")
        lines.append("")
        if drift_alerts:
            lines.append(f"检出 **{len(drift_alerts)}** 项小时统计向量正向漂移:")
            lines.append("")
            lines.append("| 维度 | 告警小时桶 | 基线均值 | 基线来源 |")
            lines.append("|------|:---:|:---:|------|")
            for da in drift_alerts:
                lines.append(
                    f"| {da.get('dimension', '-')} | {da.get('alert_hour', '-')} | "
                    f"{da.get('baseline_mean', 0)} | {da.get('baseline_source', '-')} |")
        else:
            lines.append("未检出基线漂移。")
        lines.append("")

        # ── 3. 串谋攻击链重建 ──
        lines.append("## 3. 跨 Agent 串谋攻击链重建")
        lines.append("")
        if chains:
            lines.append(f"检出 **{len(chains)}** 条跨 Agent 数据传递链:")
            lines.append("")
            for i, ch in enumerate(chains, 1):
                kind = ch.get("object_kind", "-")
                obj = ch.get("object", "-")
                agents = " → ".join(ch.get("agents", []))
                lines.append(f"### 3.{i} 链 {kind}={obj}")
                lines.append("")
                lines.append(f"- **传递路径**: {agents}")
                lines.append(f"- **时间跨度**: {ch.get('span_hours', 0):.2f} 小时 "
                             f"({self._fmt_ns(ch.get('first_ns', 0))} → "
                             f"{self._fmt_ns(ch.get('last_ns', 0))})")
                lines.append(f"- **关联事件**: {len(ch.get('event_ids', []))} 个 "
                             f"`{', '.join(str(e) for e in ch.get('event_ids', [])[:8])}`"
                             + ("..." if len(ch.get('event_ids', [])) > 8 else ""))
                lines.append(f"- **外传终点**: {len(ch.get('exfil_events', []))} 个外传事件，"
                             f"远端地址 {ch.get('remote_addrs', [])}")
                anomaly_links = ch.get("anomaly_links", [])
                if anomaly_links:
                    lines.append(f"- **命中异常明细**: {len(anomaly_links)} 条")
                lines.append("")
        else:
            lines.append("未检出跨 Agent 串谋链。")
        lines.append("")

        # ── 4. 分钟级序列告警 ──
        lines.append("## 4. 分钟级攻击序列告警")
        lines.append("")
        if sequence_alerts:
            lines.append("| 模式 | 描述 | 事件数 |")
            lines.append("|------|------|:---:|")
            for sa in sequence_alerts:
                lines.append(
                    f"| {sa.get('pattern_id', '-')} | {sa.get('description', '-')} | "
                    f"{len(sa.get('event_ids', []))} |")
        else:
            lines.append("未检出已知攻击序列。")
        lines.append("")

        # ── 5. 违规累计与升级 ──
        tier_counts = escalation.get("tier_counts", {})
        lines.append("## 5. 违规累计与升级")
        lines.append("")
        lines.append(f"- TIER1: {tier_counts.get('TIER1', 0)} | "
                     f"TIER2: {tier_counts.get('TIER2', 0)} | "
                     f"TIER3: {tier_counts.get('TIER3', 0)}")
        lines.append(f"- 实际阻断: {escalation.get('blocked_count', 0)}")
        lines.append(f"- 升级 TIER2: {'是' if escalation.get('escalate_tier2') else '否'}")
        lines.append(f"- 升级 TIER3: {'是' if escalation.get('escalate_tier3') else '否'}")
        lines.append("")

        # ── 6. 指纹关联（跨 Agent）──
        lines.append("## 6. 指纹关联分析（跨 Agent）")
        lines.append("")
        if fp_links:
            lines.append("| 指纹 | Agent 集合 | 事件数 | 时间跨度 |")
            lines.append("|------|-----------|:---:|------|")
            for fl in fp_links[:20]:
                span_h = (fl.get("last_ns", 0) - fl.get("first_ns", 0)) / 3.6e12
                lines.append(
                    f"| {fl.get('fingerprint', '-')} | "
                    f"{', '.join(fl.get('agents', []))} | "
                    f"{fl.get('event_count', 0)} | {span_h:.2f} h |")
        else:
            lines.append("无跨 Agent 共享指纹。")
        lines.append("")

        # ── 7. 异常明细（三红线：全保留）──
        lines.append("## 7. 异常明细（全保留）")
        lines.append("")
        if anomalies:
            lines.append(f"共 **{len(anomalies)}** 条:")
            lines.append("")
            lines.append("| 事件ID | Agent | 类型 | 评分 | 决策 | 时间 |")
            lines.append("|--------|-------|------|:---:|------|------|")
            for a in anomalies:
                lines.append(
                    f"| {a.get('event_id', '-')} | {a.get('agent_id', '-')} | "
                    f"{a.get('event_type', '-')} | {a.get('risk_score', 0):.2f} | "
                    f"{a.get('decision_action', '-')} | "
                    f"{self._fmt_ns(a.get('timestamp_ns', 0))} |")
        else:
            lines.append("无异常明细。")
        lines.append("")

        # ── 8. 处置建议 ──
        lines.append("## 8. 处置建议")
        lines.append("")
        advice: List[str] = []
        if chains:
            advice.append("立即隔离涉事 Agent 会话，终止其网络访问权限。")
            for ch in chains:
                for addr in ch.get("remote_addrs", []):
                    advice.append(f"在网络策略层封禁外传地址 {addr}。")
            advice.append("保全相关主机取证数据（进程树、文件哈希、网络连接记录）。")
        if drift_alerts:
            advice.append("复核漂移维度的业务变更（新任务/新部署），必要时重新标定基线。")
        if sequence_alerts:
            advice.append("复核序列告警对应时段的操作记录，确认是否存在未阻断的外传链。")
        if not advice:
            advice.append("未检出高风险信号，维持常规监测与基线标定节奏。")
        for a in advice:
            lines.append(f"- {a}")
        lines.append("")

        # ── 9. L0 下钻索引 ──
        lines.append("## 9. L0 下钻索引")
        lines.append("")
        l0_index = self._build_l0_index(audit_dir)
        l0_files = sorted({v["file"] for v in l0_index.values()})
        hit_count = sum(1 for eid in entry_ids if eid in l0_index)
        lines.append(f"L3 覆盖 entry_id {len(entry_ids)} 个，"
                     f"其中 {hit_count} 个已定位到 L0 原始事件"
                     f"（分布在 {len(l0_files)} 个文件）。")
        if l0_files:
            lines.append("")
            lines.append("| L0 审计文件 |")
            lines.append("|------------|")
            for path in l0_files:
                lines.append(f"| {path} |")
        if entry_ids:
            lines.append("")
            lines.append("```")
            for eid in entry_ids:
                loc = l0_index.get(eid)
                if loc:
                    lines.append(f"{eid} -> {os.path.basename(loc['file'])}:{loc['line']}")
                else:
                    lines.append(f"{eid} -> (L0 未覆盖)")
            lines.append("```")
        lines.append("")

        # 页脚
        lines.append("---")
        lines.append(f"*本报告由方寸观察者模拟学习系统自动生成（L3 天级审计） "
                     f"| {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        content = "\n".join(lines)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"[ReportExporter] Daily audit report saved: {filepath}")
        return filepath

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

    def append_completeness_section(self, report_path: Optional[str],
                                    analysis: dict) -> bool:
        """在报告页脚「---」前插入「申报完整性核对」小节（T1.4，产出层）。

        幂等: 报告已含该小节时跳过。找不到页脚分隔线时退回末尾追加。

        Returns:
            bool: True 已写入（或已存在）；False 报告文件不可用。
        """
        if not report_path or not os.path.isfile(report_path):
            return False
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            return False
        if "申报完整性核对" in content:
            return True  # 幂等
        section = render_completeness_md(analysis)
        marker = "\n---\n"
        idx = content.rfind(marker)
        if idx >= 0:
            new_content = content[:idx] + "\n" + section + content[idx:]
        else:
            new_content = content.rstrip("\n") + "\n\n" + section
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except OSError:
            return False
        logger.info(
            f"[ReportExporter] Completeness section appended: {report_path}")
        return True

    def append_hook_coverage_section(self, report_path: Optional[str],
                                     analysis: Optional[dict]) -> bool:
        """在报告页脚「---」前插入「hook 覆盖比对」小节（P1-2，产出层）。

        幂等: 报告已含该小节时跳过。找不到页脚分隔线时退回末尾追加。

        Returns:
            bool: True 已写入（或已存在）；False 报告文件不可用。
        """
        if not report_path or not os.path.isfile(report_path):
            return False
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            return False
        if "hook 覆盖比对" in content:
            return True  # 幂等
        section = render_hook_coverage_md(analysis)
        marker = "\n---\n"
        idx = content.rfind(marker)
        if idx >= 0:
            new_content = content[:idx] + "\n" + section + content[idx:]
        else:
            new_content = content.rstrip("\n") + "\n\n" + section
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except OSError:
            return False
        logger.info(
            f"[ReportExporter] Hook coverage section appended: {report_path}")
        return True

    def append_crosscheck_section(self, report_path: Optional[str],
                                  summary: Optional[dict]) -> bool:
        """在报告页脚「---」前插入「进程交叉校验」小节（T3.1，产出层）。

        幂等: 报告已含该小节时跳过。找不到页脚分隔线时退回末尾追加。

        Returns:
            bool: True 已写入（或已存在）；False 报告文件不可用。
        """
        if not report_path or not os.path.isfile(report_path):
            return False
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            return False
        if "进程交叉校验" in content:
            return True  # 幂等
        section = render_crosscheck_md(summary)
        marker = "\n---\n"
        idx = content.rfind(marker)
        if idx >= 0:
            new_content = content[:idx] + "\n" + section + content[idx:]
        else:
            new_content = content.rstrip("\n") + "\n\n" + section
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except OSError:
            return False
        logger.info(
            f"[ReportExporter] Crosscheck section appended: {report_path}")
        return True

    def append_file_crosscheck_section(self, report_path: Optional[str],
                                       summary: Optional[dict]) -> bool:
        """在报告页脚「---」前插入「文件交叉校验」小节（T3.2，产出层）。

        幂等: 报告已含该小节时跳过。找不到页脚分隔线时退回末尾追加。

        Returns:
            bool: True 已写入（或已存在）；False 报告文件不可用。
        """
        if not report_path or not os.path.isfile(report_path):
            return False
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            return False
        if "文件交叉校验" in content:
            return True  # 幂等
        section = render_file_crosscheck_md(summary)
        marker = "\n---\n"
        idx = content.rfind(marker)
        if idx >= 0:
            new_content = content[:idx] + "\n" + section + content[idx:]
        else:
            new_content = content.rstrip("\n") + "\n\n" + section
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except OSError:
            return False
        logger.info(
            f"[ReportExporter] File crosscheck section appended: {report_path}")
        return True

    def append_snapshot_checker_section(self, report_path: Optional[str],
                                        summary: Optional[dict]) -> bool:
        """在报告页脚「---」前插入「用户态快照校验」小节（P1-3，产出层）。

        幂等: 报告已含该小节时跳过。找不到页脚分隔线时退回末尾追加。

        Returns:
            bool: True 已写入（或已存在）；False 报告文件不可用。
        """
        if not report_path or not os.path.isfile(report_path):
            return False
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            return False
        if "用户态快照校验" in content:
            return True  # 幂等
        section = render_snapshot_checker_md(summary)
        marker = "\n---\n"
        idx = content.rfind(marker)
        if idx >= 0:
            new_content = content[:idx] + "\n" + section + content[idx:]
        else:
            new_content = content.rstrip("\n") + "\n\n" + section
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except OSError:
            return False
        logger.info(
            f"[ReportExporter] Snapshot checker section appended: "
            f"{report_path}")
        return True

    def append_consistency_section(self, report_path: Optional[str],
                                   summary: Optional[dict]) -> bool:
        """在报告页脚「---」前插入「一致性核对」小节（P2-2，产出层）。

        幂等: 报告已含该小节时跳过。找不到页脚分隔线时退回末尾追加。

        Returns:
            bool: True 已写入（或已存在）；False 报告文件不可用。
        """
        if not report_path or not os.path.isfile(report_path):
            return False
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            return False
        if "一致性核对" in content:
            return True  # 幂等
        section = render_consistency_md(summary)
        marker = "\n---\n"
        idx = content.rfind(marker)
        if idx >= 0:
            new_content = content[:idx] + "\n" + section + content[idx:]
        else:
            new_content = content.rstrip("\n") + "\n\n" + section
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except OSError:
            return False
        logger.info(
            f"[ReportExporter] Consistency section appended: {report_path}")
        return True

    def append_coverage_matrix_section(self, report_path: Optional[str],
                                       matrix: Optional[dict]) -> bool:
        """在报告页脚「---」前插入「双路径覆盖矩阵」小节（P2-3，产出层）。

        幂等: 报告已含该小节时跳过。找不到页脚分隔线时退回末尾追加。

        Returns:
            bool: True 已写入（或已存在）；False 报告文件不可用。
        """
        if not report_path or not os.path.isfile(report_path):
            return False
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            return False
        if "双路径覆盖矩阵" in content:
            return True  # 幂等
        section = render_coverage_matrix_md(matrix)
        marker = "\n---\n"
        idx = content.rfind(marker)
        if idx >= 0:
            new_content = content[:idx] + "\n" + section + content[idx:]
        else:
            new_content = content.rstrip("\n") + "\n\n" + section
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(new_content)
        except OSError:
            return False
        logger.info(
            f"[ReportExporter] Coverage matrix section appended: "
            f"{report_path}")
        return True


# ── T1.4 申报完整性核对与覆盖置信度（产出层）────────────────────────
# 只解析 mcp_reports.jsonl 申报留痕做会话配对 + 静默区间检测，
# 不改动任何检测/研判逻辑；置信度措辞固定声明仅反映申报侧完整性。

COMPLETENESS_NOTE = "仅反映申报侧完整性，不代表行为覆盖"


def analyze_report_completeness(jsonl_path: Optional[str],
                                silence_alert_s: int = 600) -> dict:
    """核对申报留痕完整性，输出覆盖置信度（T1.4）。

    解析 mcp_reports.jsonl（MCP 申报留痕）:
    - report_session start/end 配对 → 未闭合会话标注
    - 相邻申报 received_at_ms 间隔超过 silence_alert_s → 可疑静默区间
    - 置信度: 高 = 会话全部闭合且无静默；低 = 无留痕/无会话级申报；
      中 = 其余（存在未闭合会话或静默区间）。

    Args:
        jsonl_path:      mcp_reports.jsonl 路径；None 表示未配置落盘
        silence_alert_s: 静默阈值（秒）；<=0 时不检测静默区间

    Returns:
        dict: {checked, reason, record_count, session_count,
               unclosed_sessions, end_without_start, silent_gaps,
               silence_threshold_s, confidence, confidence_reason, note}
    """
    result = {
        "checked": False,
        "reason": "",
        "record_count": 0,
        "session_count": 0,
        "unclosed_sessions": [],
        "end_without_start": [],
        "silent_gaps": [],
        "silence_threshold_s": int(silence_alert_s or 0),
        "confidence": "低",
        "confidence_reason": "",
        "note": COMPLETENESS_NOTE,
    }
    if not jsonl_path:
        result["reason"] = "申报留痕未落盘，完整性核对跳过"
        result["confidence_reason"] = "jsonl_dir 未配置，无申报留痕可核对"
        return result
    if not os.path.isfile(jsonl_path):
        result["reason"] = "申报留痕未落盘，完整性核对跳过"
        result["confidence_reason"] = "申报留痕文件不存在"
        return result

    records: List[dict] = []
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    records.append(obj)
    except OSError as e:
        result["reason"] = f"申报留痕读取失败，完整性核对跳过 ({e})"
        result["confidence_reason"] = "申报留痕读取失败"
        return result

    result["checked"] = True
    result["record_count"] = len(records)

    # ── 会话 start/end 配对 ──
    starts: Dict[str, Optional[int]] = {}
    ends: Dict[str, Optional[int]] = {}
    for rec in records:
        if rec.get("type") != "report_session":
            continue
        payload = rec.get("payload") or {}
        sid = payload.get("session_id")
        if not sid:
            continue
        status = str(payload.get("status") or "").lower()
        if status == "start":
            starts[sid] = payload.get("timestamp_ms")
        elif status == "end":
            ends[sid] = payload.get("timestamp_ms")
    unclosed = sorted(set(starts) - set(ends))
    end_wo_start = sorted(set(ends) - set(starts))
    result["unclosed_sessions"] = unclosed
    result["end_without_start"] = end_wo_start
    result["session_count"] = len(set(starts) | set(ends))

    # ── 申报连续性: 相邻 received_at_ms 间隔超过阈值 → 可疑静默区间 ──
    if result["silence_threshold_s"] > 0:
        ts_list = []
        for rec in records:
            rts = rec.get("received_at_ms")
            if isinstance(rts, (int, float)):
                ts_list.append(float(rts))
        ts_list.sort()
        gaps = []
        for prev, cur in zip(ts_list, ts_list[1:]):
            duration_s = (cur - prev) / 1000.0
            if duration_s > result["silence_threshold_s"]:
                gaps.append({
                    "from_ms": int(prev),
                    "to_ms": int(cur),
                    "duration_s": round(duration_s, 1),
                    "from_iso": _ms_to_iso(prev),
                    "to_iso": _ms_to_iso(cur),
                })
        result["silent_gaps"] = gaps

    # ── 覆盖置信度 ──
    if result["session_count"] == 0:
        result["confidence"] = "低"
        result["confidence_reason"] = (
            "无会话级申报（report_session），无法核对会话闭合")
    elif unclosed or end_wo_start or result["silent_gaps"]:
        result["confidence"] = "中"
        reasons = []
        if unclosed:
            reasons.append(f"{len(unclosed)} 个会话未闭合（疑似漏报）")
        if end_wo_start:
            reasons.append(
                f"{len(end_wo_start)} 个会话仅有 end 申报（疑似缺失 start）")
        if result["silent_gaps"]:
            reasons.append(f"{len(result['silent_gaps'])} 个可疑静默区间")
        result["confidence_reason"] = "；".join(reasons)
    else:
        result["confidence"] = "高"
        result["confidence_reason"] = "会话全部闭合且申报连续"
    return result


def _ms_to_iso(ms: float) -> str:
    """epoch 毫秒 → ISO 字符串（容错）。"""
    try:
        return datetime.fromtimestamp(ms / 1000.0).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return str(int(ms))


def render_completeness_md(analysis: dict) -> str:
    """将完整性核对结果渲染为 Markdown「申报完整性核对」小节（T1.4）。"""
    lines = ["## 申报完整性核对", ""]
    lines.append(f"- **覆盖置信度**: {analysis.get('confidence', '低')}")
    if analysis.get("confidence_reason"):
        lines.append(f"- **依据**: {analysis['confidence_reason']}")
    if not analysis.get("checked"):
        lines.append(f"- **核对结果**: {analysis.get('reason', '未核对')}")
    else:
        lines.append(f"- **申报记录数**: {analysis.get('record_count', 0)}")
        lines.append(f"- **会话数**: {analysis.get('session_count', 0)}")
        unclosed = analysis.get("unclosed_sessions") or []
        ews = analysis.get("end_without_start") or []
        if unclosed:
            shown = "，".join(str(s) for s in unclosed[:5])
            if len(unclosed) > 5:
                shown += f" 等 {len(unclosed)} 个"
            lines.append(f"- **未闭合会话**: {shown} — 会话未闭合，疑似漏报")
        if ews:
            shown = "，".join(str(s) for s in ews[:5])
            if len(ews) > 5:
                shown += f" 等 {len(ews)} 个"
            lines.append(f"- **仅结束未开始会话**: {shown} — 疑似缺失 start 申报")
        gaps = analysis.get("silent_gaps") or []
        if gaps:
            lines.append(f"- **可疑静默区间**: {len(gaps)} 个（相邻申报间隔"
                         f"超过 {analysis.get('silence_threshold_s', 0)}s）")
            for g in gaps[:5]:
                lines.append(f"  - {g.get('from_iso', '-')} ~ "
                             f"{g.get('to_iso', '-')}，"
                             f"持续 {g.get('duration_s', 0):g}s")
        else:
            lines.append("- **可疑静默区间**: 无")
    lines.append(f"- **说明**: {analysis.get('note', COMPLETENESS_NOTE)}")
    lines.append("")
    return "\n".join(lines)


# ── P1-2 hook 覆盖比对（产出层）───────────────────────────────
# 只渲染 collector.mcp_report_collector.analyze_hook_coverage 的
# 比对结果（hook 事件数 vs 申报事件数），不改动任何检测/研判逻辑。


def render_hook_coverage_md(analysis: Optional[dict]) -> str:
    """将 hook 覆盖比对结果渲染为 Markdown「hook 覆盖比对」小节（P1-2）。"""
    lines = ["## hook 覆盖比对（申报 vs hook 双通道）", ""]
    if not analysis:
        lines.append("- **状态**: 未执行")
        lines.append("")
        return "\n".join(lines)
    if not analysis.get("checked"):
        lines.append(f"- **状态**: 不可核对（{analysis.get('reason', '未核对')}）")
        lines.append(f"- **说明**: {analysis.get('note', '')}")
        lines.append("")
        return "\n".join(lines)

    lines.append(
        f"- **覆盖置信度**: {analysis.get('coverage_confidence', '低')}")
    if analysis.get("confidence_reason"):
        lines.append(f"- **依据**: {analysis['confidence_reason']}")
    lines.append(f"- **申报工具调用数**: {analysis.get('reported_tool_calls', 0)}；"
                 f"hook 执行前裁决: {analysis.get('hook_pre_events', 0)}；"
                 f"执行后审计: {analysis.get('hook_post_events', 0)}")
    if analysis.get("hook_deny_count"):
        lines.append(f"- **deny 拦截数**: {analysis['hook_deny_count']}")
    corrupt = analysis.get("corrupt_lines") or {}
    if corrupt:
        lines.append(f"- **留痕损坏行（容错跳过）**: {sum(corrupt.values())} 行")
    tools = analysis.get("tools") or {}
    if tools:
        lines.append("- **工具级比对**:")
        for tool, info in sorted(tools.items()):
            pre_cov = info.get("pre_coverage")
            cov_text = (f"{pre_cov:.0%}" if pre_cov is not None else "-")
            lines.append(
                f"  - {tool}: 申报 {info.get('reported', 0)} / hook执行前 "
                f"{info.get('hook_pre', 0)} / 执行后 {info.get('hook_post', 0)} "
                f"（覆盖 {cov_text}，状态 {info.get('status', '?')}"
                + (f"，deny {info.get('deny', 0)}"
                   if info.get('deny') else "") + "）")
    unreported = analysis.get("unreported_denies") or []
    if unreported:
        lines.append(f"- **deny 拦截但申报未报（疑似漏报）**: {len(unreported)} 个工具")
        for u in unreported[:5]:
            lines.append(f"  - {u.get('tool_name', '?')}: "
                         f"deny {u.get('deny_count', 0)} 次")
    if analysis.get("bash_blindspot_note"):
        lines.append(f"- **Bash 盲区报告**: {analysis['bash_blindspot_note']}")
    lines.append(f"- **说明**: {analysis.get('note', '')}")
    lines.append("")
    return "\n".join(lines)


# ── T3.1 进程快照交叉校验（产出层）────────────────────────────
# 只渲染 lightweight_crosscheck 的比对结果（疑似二级操作告警），
# 不改动任何检测/研判逻辑；比对窗口声明随文输出。

CROSSCHECK_NOTE = (
    "比对窗口仅为会话 start/end 边界快照差异，"
    "窗口内启动又退出的进程不可见；"
    "白名单外新增进程判定为「疑似二级操作」，仅告警不拦截")


def render_crosscheck_md(summary: Optional[dict]) -> str:
    """将进程快照交叉校验结果渲染为 Markdown「进程交叉校验」小节（T3.1）。"""
    lines = ["## 进程交叉校验（会话快照比对）", ""]
    if not summary or not summary.get("enabled"):
        lines.append("- **状态**: 未启用")
        lines.append("")
        return "\n".join(lines)
    if not summary.get("available"):
        lines.append("- **状态**: 不可用（进程快照失败，未做比对）")
        for u in (summary.get("unavailable") or [])[:3]:
            lines.append(f"  - 会话 {u.get('session_id', '?')} "
                         f"({u.get('phase')}): {u.get('reason')}")
        lines.append(f"- **说明**: {summary.get('note', CROSSCHECK_NOTE)}")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"- **已比对会话数**: {summary.get('sessions_checked', 0)}")
    findings = summary.get("findings") or []
    if findings:
        lines.append(f"- **疑似二级操作（申报外新增进程）**: {len(findings)} 个会话")
        for f in findings[:5]:
            suspects = f.get("suspects") or []
            shown = ", ".join(
                f"{s.get('name', '?')}(pid={s.get('pid', '?')})"
                for s in suspects[:5])
            if len(suspects) > 5:
                shown += f" 等 {len(suspects)} 个"
            lines.append(f"  - 会话 {f.get('session_id', '?')}: {shown}")
            for s in suspects[:3]:
                cmd = " ".join(s.get("cmdline") or [])[:80]
                if cmd:
                    lines.append(f"    - 命令行: {cmd}")
    else:
        lines.append("- **疑似二级操作**: 无（未发现申报外新增进程）")
    unavailable = summary.get("unavailable") or []
    if unavailable:
        lines.append(f"- **快照不可用会话**: {len(unavailable)} 个（未参与比对）")
    lines.append(f"- **说明**: {summary.get('note', CROSSCHECK_NOTE)}")
    lines.append("")
    return "\n".join(lines)


# ── T3.2 文件快照交叉校验（产出层）────────────────────────────
# 只渲染 FileCrossChecker 的比对结果（申报外受保护目录变更告警），
# 不改动任何检测/研判逻辑；比对窗口声明随文输出。

FILE_CROSSCHECK_NOTE = (
    "比对窗口仅为会话 start/end 边界快照差异，"
    "窗口内创建又删除的文件不可见；"
    "受保护目录外变更不比对；"
    "变更文件判定为「疑似二级操作」，仅告警不拦截")


def render_file_crosscheck_md(summary: Optional[dict]) -> str:
    """将文件快照交叉校验结果渲染为 Markdown「文件交叉校验」小节（T3.2）。"""
    lines = ["## 文件交叉校验（受保护目录快照比对）", ""]
    if not summary or not summary.get("enabled"):
        lines.append("- **状态**: 未启用")
        lines.append("")
        return "\n".join(lines)
    if not summary.get("available"):
        lines.append("- **状态**: 不可用（文件快照失败，未做比对）")
        for u in (summary.get("unavailable") or [])[:3]:
            lines.append(f"  - 会话 {u.get('session_id', '?')} "
                         f"({u.get('phase')}): {u.get('reason')}")
        lines.append(f"- **说明**: {summary.get('note', FILE_CROSSCHECK_NOTE)}")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"- **已比对会话数**: {summary.get('sessions_checked', 0)}")
    findings = summary.get("findings") or []
    if findings:
        lines.append(f"- **疑似二级操作（申报外文件变更）**: {len(findings)} 个会话")
        for f in findings[:5]:
            changes = f.get("changes") or {}
            n_add = len(changes.get("added") or {})
            n_mod = len(changes.get("modified") or {})
            n_del = len(changes.get("removed") or {})
            lines.append(f"  - 会话 {f.get('session_id', '?')}: "
                         f"新增 {n_add} / 修改 {n_mod} / 删除 {n_del}")
            for kind in ("added", "modified", "removed"):
                items = changes.get(kind) or {}
                for p in list(items)[:3]:
                    lines.append(f"    - {kind}: {p}")
    else:
        lines.append("- **疑似二级操作**: 无（未发现申报外文件变更）")
    unavailable = summary.get("unavailable") or []
    if unavailable:
        lines.append(f"- **快照不可用会话**: {len(unavailable)} 个（未参与比对）")
    lines.append(f"- **说明**: {summary.get('note', FILE_CROSSCHECK_NOTE)}")
    lines.append("")
    return "\n".join(lines)


# ── P1-3 用户态快照校验（产出层）───────────────────────────────
# 只渲染 SnapshotChecker 的比对结果（定时快照未申报变更 + 4663 未申报
# 访问告警），不改动任何检测/研判逻辑；比对窗口声明随文输出。

SNAPSHOT_CHECKER_NOTE = (
    "定时快照比对仅覆盖采样时刻差异；4663 审计仅在系统审计策略启用且"
    "目标目录配置 SACL 时产生事件；差异访问判定为「疑似二级操作」，"
    "仅告警不拦截")


def render_snapshot_checker_md(summary: Optional[dict]) -> str:
    """将用户态快照校验结果渲染为 Markdown「用户态快照校验」小节（P1-3）。"""
    lines = ["## 用户态快照校验（定时快照 + 4663 审计）", ""]
    if not summary or not summary.get("enabled"):
        lines.append("- **状态**: 未启用")
        lines.append("")
        return "\n".join(lines)
    lines.append(f"- **快照次数**: {summary.get('ticks', 0)}"
                 f"（间隔 {summary.get('interval_s', '?')}s）")
    if not summary.get("available"):
        lines.append("- **状态**: 不可用（快照未成功，未做比对）")
        for u in (summary.get("unavailable") or [])[:3]:
            lines.append(f"  - {u.get('phase', '?')}: {u.get('reason')}")
        lines.append(f"- **说明**: {summary.get('note', SNAPSHOT_CHECKER_NOTE)}")
        lines.append("")
        return "\n".join(lines)

    findings = summary.get("findings") or []
    if findings:
        lines.append(f"- **疑似二级操作（申报外访问/变更）**: {len(findings)} 起")
        for f in findings[:5]:
            kind = f.get("kind")
            if kind == "unreported_file_change":
                changes = f.get("changes") or {}
                n_add = len(changes.get("added") or {})
                n_mod = len(changes.get("modified") or {})
                n_del = len(changes.get("removed") or {})
                lines.append(f"  - tick {f.get('tick', '?')} 未申报文件变更: "
                             f"新增 {n_add} / 修改 {n_mod} / 删除 {n_del}")
                for kind_name in ("added", "modified", "removed"):
                    items = changes.get(kind_name) or {}
                    for p in list(items)[:3]:
                        lines.append(f"    - {kind_name}: {p}")
            elif kind == "unreported_file_access":
                accesses = f.get("accesses") or []
                lines.append(f"  - 4663 未申报文件访问 {len(accesses)} 起:")
                for a in accesses[:5]:
                    lines.append(f"    - {a.get('object_name', '?')} "
                                 f"(进程 {a.get('process_name', '?')}, "
                                 f"mask {a.get('access_mask', '?')})")
            else:
                lines.append(f"  - {kind}: {json.dumps(f, ensure_ascii=False, default=str)[:200]}")
    else:
        lines.append("- **疑似二级操作**: 无（未发现申报外访问/变更）")
    unavailable = summary.get("unavailable") or []
    if unavailable:
        lines.append(f"- **不可用记录**: {len(unavailable)} 条（未参与比对）")
        for u in unavailable[:3]:
            lines.append(f"  - {u.get('phase', '?')}: {u.get('reason')}")
            if u.get("guidance"):
                lines.append(f"    指引: {u['guidance']}")
    lines.append(f"- **说明**: {summary.get('note', SNAPSHOT_CHECKER_NOTE)}")
    lines.append("")
    return "\n".join(lines)


# ── P2-2 双源一致性核对（产出层）────────────────────────────
# 只渲染 ConsistencyChecker 的三类不一致比对结果（仅告警不拦截），
# 不改动任何检测/研判逻辑；比对窗口声明随文输出。

CONSISTENCY_CHECKER_NOTE = (
    "核对基于四源留痕（申报 / hook 执行前裁决 / hook 执行后审计 / "
    "快照校验），仅反映留痕侧观测一致性；定时快照仅覆盖采样时刻差异；"
    "各维度源缺失时独立标记不可核对，不虚构比对")


def render_consistency_md(summary: Optional[dict]) -> str:
    """将双源一致性核对结果渲染为 Markdown「一致性核对」小节（P2-2）。"""
    lines = ["## 一致性核对（申报 / hook / 快照 四源交叉）", ""]
    if not summary or not summary.get("enabled"):
        lines.append("- **状态**: 未启用")
        lines.append("")
        return "\n".join(lines)
    if not summary.get("checked"):
        lines.append("- **状态**: 未执行")
        lines.append("")
        return "\n".join(lines)

    issues = summary.get("issues") or []
    if issues:
        lines.append(f"- **不一致告警**: {len(issues)} 起")
        for i in issues[:8]:
            kind = i.get("kind")
            if kind == "unreported_hook_deny":
                lines.append(
                    f"  - 申报未报但 hook 拦截: 会话 "
                    f"{i.get('session_id', '?')} "
                    f"{i.get('tool_name', '?')} → {i.get('target', '?')}")
            elif kind == "hook_blindspot_change":
                lines.append(
                    f"  - hook 盲区（快照发现 hook 未观测）: "
                    f"{i.get('path', '?')}（{i.get('finding_kind', '?')}）")
            elif kind == "report_snapshot_conflict":
                lines.append(
                    f"  - 申报与快照矛盾（申报写入无落地证据）: 会话 "
                    f"{i.get('session_id', '?')} {i.get('tool_name', '?')} "
                    f"→ {i.get('path', '?')}")
            else:
                lines.append(
                    f"  - {kind}: "
                    f"{json.dumps(i, ensure_ascii=False, default=str)[:200]}")
    else:
        lines.append("- **不一致告警**: 无")
    unavailable = summary.get("unavailable") or []
    if unavailable:
        lines.append(f"- **不可核对维度**: {len(unavailable)} 个")
        for u in unavailable[:3]:
            lines.append(f"  - {u.get('dimension', '?')}: {u.get('reason')}")
            if u.get("guidance"):
                lines.append(f"    指引: {u['guidance']}")
    sources = summary.get("sources") or {}
    if sources:
        lines.append(
            f"- **留痕源**: 申报 {sources.get('agent_reports', 0)} / "
            f"hook 执行前 {sources.get('hook_pre_entries', 0)} / "
            f"执行后 {sources.get('hook_post_entries', 0)} / "
            f"快照 finding {sources.get('snapshot_findings', 0)} / "
            f"变更全集路径 {sources.get('snapshot_change_paths', 0)}")
    corrupt = summary.get("corrupt_lines") or {}
    if corrupt:
        lines.append(f"- **留痕损坏行（容错跳过）**: {sum(corrupt.values())} 行")
    lines.append(f"- **说明**: {summary.get('note', CONSISTENCY_CHECKER_NOTE)}")
    lines.append("")
    return "\n".join(lines)


# ── P2-3 双路径覆盖矩阵（产出层）────────────────────────────────
# 只渲染 collector.mcp_report_collector.build_coverage_matrix 的
# 「工具 × 通道」覆盖矩阵结果，不改动任何检测/研判逻辑。

_COVERAGE_MATRIX_GLYPHS = {
    "covered": "✅",
    "uncovered": "❌",
    "unavailable": "⚠️",
}


def render_coverage_matrix_md(matrix: Optional[dict]) -> str:
    """将双路径覆盖矩阵渲染为 Markdown「双路径覆盖矩阵」小节（P2-3）。"""
    lines = ["## 双路径覆盖矩阵（工具 × 通道）", ""]
    if not matrix:
        lines.append("- **状态**: 未执行")
        lines.append("")
        return "\n".join(lines)
    if not matrix.get("checked"):
        lines.append(f"- **状态**: 不可核对（{matrix.get('reason', '未核对')}）")
        lines.append(f"- **说明**: {matrix.get('note', '')}")
        lines.append("")
        return "\n".join(lines)

    tools = matrix.get("tools") or {}
    lines.append("| 工具 | 申报 | hook执行前 | hook执行后 | 快照兜底 |")
    lines.append("|---|---|---|---|---|")
    for tool in sorted(tools):
        # 防御：跳过空工具名（历史 gate_error 条目）避免渲染空行。
        if not (tool or "").strip():
            continue
        row = tools[tool] or {}
        cells = " | ".join(
            _COVERAGE_MATRIX_GLYPHS.get(row.get(ch), "❌")
            for ch in ("mcp_report", "hook_pre", "hook_post", "snapshot"))
        lines.append(f"| {tool} | {cells} |")
    counts = matrix.get("counts") or {}
    if counts:
        detail = "、".join(f"{k} {v}" for k, v in sorted(counts.items()))
        lines.append("")
        lines.append(f"- **工具覆盖状态汇总**: {detail}")
    unavailable = matrix.get("unavailable_channels") or []
    if unavailable:
        lines.append(f"- **不可核对通道**: {', '.join(unavailable)}")
    lines.append(f"- **说明**: {matrix.get('note', '')}")
    lines.append("")
    return "\n".join(lines)
