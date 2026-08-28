#!/usr/bin/env python3
"""
demo.py — observer demo 的实现模块（U4/U8）

统一入口为 observer.py（python observer.py demo ...），本文件是 demo 子命令的
实现模块，同时保留独立运行能力（__main__ 与 observer demo 转发语义一致）。

功能:
1. 主菜单: 单元测试 / 全量模拟 / 分类浏览
2. 逐事件可视化流水线（彩色输出）
3. 场景分析面板（目的/发现/归因/策略）
4. 全局统计面板
5. 支持 37 个测试场景（5 个分类）

用法:
    python observer.py demo                  # 交互式模式
    python observer.py demo --auto           # 自动播放模式
    python observer.py demo --scenario n01   # 指定场景
    python observer.py demo --category anomalous   # 按分类运行
    python demo.py [同参数]                  # 直接运行（兼容）

U8: 逐事件流水线已接入 PipelineRunner（observer_core/pipeline_runner.py），
与 app.py / main.py / monitor_daemon.py 共用同一编排实现；演示层保留
彩色逐事件打印、统计聚合、reverse_cmd 读取（cmd_sender 前后对比）。
"""

import sys
import os
import yaml
import time
import glob
import json
import re
import shutil
import logging
import subprocess
from typing import List, Dict, Optional
from dataclasses import dataclass

# 抑制 logging 的 stderr 输出（避免 PowerShell 报错）
logging.basicConfig(level=logging.WARNING, format='%(message)s')
for handler in logging.root.handlers:
    handler.stream = open(os.devnull, 'w', encoding='utf-8')

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.event import RawEvent
from models.virtual_clock import VirtualClock
from models.risk import RiskLevel, DecisionAction, ActionTier
from observer_core.monitoring.event_normalizer import EventNormalizer
from observer_core.monitoring.rule_engine import RuleEngine
from observer_core.judgment.risk_scorer import RiskScorer
from observer_core.judgment.baseline_checker import BaselineChecker
from observer_core.judgment.decision_engine import DecisionEngine
from observer_core.judgment.chain_report_builder import ChainReportBuilder
from observer_core.blocking.blocking_coordinator import BlockingCoordinator
from observer_core.blocking.command_sender import MockCommandSender
from observer_core.audit.behavior_graph import BehaviorGraph
from observer_core.audit.audit_logger import AuditLogger
from observer_core.audit.report_exporter import ReportExporter
from observer_core.audit.output_path_manager import RunOutputManager, infer_category
from observer_core.audit.output_sink import DefaultOutputSink
from observer_core.audit.file_manager import OutputFileManager
from observer_core.pipeline_runner import PipelineRunner
from collector.simulation_collector import SimulationCollector
from adapter.platform_detect import detect_and_create_collector


# ── ANSI 颜色码 ──────────────────────────────────────────────
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

def C(text, color):
    """给文本添加颜色"""
    return f"{color}{text}{Colors.RESET}"

W = 64  # 面板宽度

def _display_width(s):
    """计算字符串的显示宽度（CJK字符占2列）"""
    w = 0
    for ch in s:
        if '\u4e00' <= ch <= '\u9fff' or '\u3000' <= ch <= '\u303f' or '\uff00' <= ch <= '\uffef':
            w += 2
        elif '\u2500' <= ch <= '\u257f' or '\u2580' <= ch <= '\u259f':
            w += 1  # box drawing / block elements
        else:
            w += 1
    return w

def _strip_ansi(s):
    """去除ANSI转义码"""
    return re.sub(r'\033\[[0-9;]*m', '', s)

def _box_top():    return C("\u250c" + "\u2500" * W + "\u2510", Colors.CYAN)
def _box_bot():    return C("\u2514" + "\u2500" * W + "\u2518", Colors.CYAN)
def _box_sep():    return C("\u251c" + "\u2500" * W + "\u2524", Colors.CYAN)
def _box_line(txt, color=Colors.WHITE):
    plain = _strip_ansi(txt)
    dw = _display_width(plain)
    pad = max(W - dw, 0)
    left = 1
    right = max(pad - left, 0)
    return C("\u2502", Colors.CYAN) + C(" " * left + txt + " " * right, color) + C("\u2502", Colors.CYAN)

def print_header(title: str):
    print()
    print(C("=" * W, Colors.CYAN))
    print(C(title.center(W), Colors.CYAN + Colors.BOLD))
    print(C("=" * W, Colors.CYAN))
    print()

def print_event_header(event_num, total, event_type, description):
    print()
    sep = '\u2500' * 40
    print(C(f"\u2500\u2500 \u4e8b\u4ef6 [{event_num}/{total}] {sep}", Colors.BLUE + Colors.BOLD))
    print(C(f">> [\u8f93\u5165] {event_type}: {description}", Colors.WHITE))

def print_pipeline_step(icon, label, content, color=Colors.WHITE):
    print(C(f"   \u251c\u2500 {icon} [{label}] {content}", color))

def print_pipeline_step_last(icon, label, content, color=Colors.WHITE):
    print(C(f"   \u2514\u2500 {icon} [{label}] {content}", color))

def print_dimension_scores(scores):
    parts = [f"{ds.name[:2]}={ds.score:.2f}" for ds in scores]
    print(C(f"   \u2502   \u2514\u2500 {' '.join(parts)}", Colors.DIM))


# ── 场景分析数据 ──────────────────────────────────────────────
# 从 analysis_panels.py 导入 SA 字典（37 个场景的分析面板数据）
from analysis_panels import SA


# ── ScenarioRunner ─────────────────────────────────────────────
class ScenarioRunner:
    """场景运行器"""
    CATEGORIES = {
        'normal': ('N', '正常行为', Colors.GREEN),
        'anomalous': ('A', '异常行为', Colors.RED),
        'boundary': ('B', '边界场景', Colors.YELLOW),
        'multi_agent': ('M', '多Agent协作', Colors.MAGENTA),
        'extreme': ('E', '极端场景', Colors.CYAN),
    }

    def __init__(self, auto_mode=False, silent=False, mode=None):
        self.auto_mode = auto_mode
        self.silent = silent
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.output_dir = os.path.join(self.base_dir, 'output')
        # 统一架构: 通过 --mode 参数创建对应 Collector
        config = self._load_config()
        if mode and mode != "simulation":
            # 非模拟模式: 使用工厂函数创建对应采集器
            try:
                self.collector = detect_and_create_collector(config, mode_override=mode)
                self.clock = (self.collector.clock
                              if hasattr(self.collector, 'clock')
                              else VirtualClock(start_ns=config.get(
                                  'virtual_clock', {}).get('start_ns',
                                  1718092800000000000)))
            except RuntimeError as e:
                if not self.silent:
                    print(C(f"模式 '{mode}' 不可用: {e}，降级为 simulation", Colors.YELLOW))
                self.collector = SimulationCollector(config)
                self.clock = self.collector.clock
        else:
            # 模拟模式 (默认)
            self.collector = SimulationCollector(config)
            self.clock = self.collector.clock
        self.normalizer = EventNormalizer(clock=self.clock, window_size=10)
        self._mode_name = self.collector.capabilities().name if hasattr(self.collector, 'capabilities') else "Simulation"
        self.engine = RuleEngine()
        self.engine.load_rules(os.path.join(self.base_dir, 'rules', 'default_policy.yaml'))
        # 不传 min_warm_events，统一从 tuning.yaml 读取（baseline.min_warm_events=10）
        self.baseline = BaselineChecker()
        self.scorer = RiskScorer()
        self.scorer.register_default_dimensions()
        self.decision_engine = DecisionEngine()
        self.report_builder = ChainReportBuilder(output_dir=self.output_dir)
        self.cmd_sender = MockCommandSender()
        self.cmd_sender.connect('mock_pipe')
        self.blocking_coord = BlockingCoordinator(clock=self.clock, sender=self.cmd_sender, output_dir=self.output_dir)
        self.behavior_graph = BehaviorGraph()
        self.audit_logger = AuditLogger(
            output_dir=self.output_dir,
            # L-T3: L0 审计文件保留天数（来自 config.yaml output.retention_days）
            retention_days=config.get("output", {}).get("retention_days"),
        )
        self.report_exporter = ReportExporter(output_dir=self.output_dir)
        # U3: 输出编排收敛至 OutputSink（run 目录在 run_scenario 的 begin_run 中创建）
        self.sink = DefaultOutputSink(
            base_output_dir=self.output_dir,
            audit_logger=self.audit_logger,
            report_exporter=self.report_exporter,
            behavior_graph=self.behavior_graph,
            blocking_coord=self.blocking_coord,
        )
        # U8: 全链路流水线（与 app.py / main.py / monitor_daemon.py 共用 PipelineRunner）
        self.runner = PipelineRunner(
            normalizer=self.normalizer,
            rule_engine=self.engine,
            baseline_checker=self.baseline,
            scorer=self.scorer,
            decision_engine=self.decision_engine,
            blocking_coord=self.blocking_coord,
            behavior_graph=self.behavior_graph,
            audit_logger=self.audit_logger,
        )
        self._run_mgr: Optional[RunOutputManager] = None
        self.stats = self._empty_stats()

    def _load_config(self):
        """加载 config.yaml"""
        config_path = os.path.join(self.base_dir, 'config.yaml')
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        return {"virtual_clock": {"start_ns": 1718092800000000000}}

    def _empty_stats(self):
        return {
            'total': 0, 'allow': 0, 'alert': 0, 'block': 0,
            'risk_distribution': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
            'top_rules': {}, 'report_files': [], 'escalation_count': 0,
            'reverse_commands': [], 'max_score': 0.0, 'matched_rules_detail': [],
        }

    def load_scenario(self, scenario_path):
        if os.path.isabs(scenario_path) or os.path.exists(scenario_path):
            path = scenario_path
        else:
            path = None
            scenarios_dir = os.path.join(self.base_dir, 'scenarios')
            for cat_dir in ['normal', 'anomalous', 'boundary', 'multi_agent', 'extreme']:
                candidate = os.path.join(scenarios_dir, cat_dir, f'{scenario_path}.yaml')
                if os.path.exists(candidate):
                    path = candidate
                    break
            if path is None:
                for cat_dir in ['normal', 'anomalous', 'boundary', 'multi_agent', 'extreme']:
                    matches = glob.glob(os.path.join(scenarios_dir, cat_dir, f'*{scenario_path}*.yaml'))
                    if matches:
                        path = matches[0]
                        break
            if path is None:
                raise FileNotFoundError(f"Scenario not found: {scenario_path}")
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return data['scenario'], path

    def run_event(self, raw, event_num, total):
        """处理单个事件（接受 RawEvent，由 Collector 提供）。

        U8: 全链路流水线由 PipelineRunner.process_event 执行（与 app.py 相同）；
        演示层保留 cmd_sender 前后对比读取 reverse_cmd 与彩色逐事件打印。
        """
        cmd_count_before = len(self.cmd_sender.sent_commands)
        result = self.runner.process_event(raw)
        cmd_count_after = len(self.cmd_sender.sent_commands)
        norm = result.norm
        match = result.match
        assessment = result.assessment
        decision = result.decision
        blocking_result = result.blocking_result
        escalated = blocking_result.tier != decision.tier
        reverse_cmd = None
        if cmd_count_after > cmd_count_before:
            reverse_cmd = self.cmd_sender.sent_commands[-1]
        if not self.silent:
            self._print_event_pipeline(raw, norm, match, assessment, decision,
                                        blocking_result, reverse_cmd, escalated, event_num, total)
        self._update_stats(assessment, decision, match, blocking_result, escalated, reverse_cmd)
        if not self.auto_mode and not self.silent:
            input(C("   [\u6309 Enter \u7ee7\u7eed...]", Colors.DIM))

    def _build_event_desc(self, norm):
        if norm.event_type == "exec":
            return norm.command_string or f"{norm.raw.executable} {' '.join(norm.raw.arguments or [])}"
        elif norm.event_type == "file_open":
            return f"{norm.raw.file_op} {norm.raw.file_path}"
        elif norm.event_type == "net_conn":
            return f"{norm.raw.remote_addr}:{norm.raw.remote_port}"
        return norm.event_type

    def _print_event_pipeline(self, raw, norm, match, assessment, decision,
                               blocking_result, reverse_cmd, escalated, event_num, total):
        desc = self._build_event_desc(norm)
        print_event_header(event_num, total, norm.event_type, desc)
        if norm.command_string:
            print_pipeline_step("[N]", "\u5f52\u4e00\u5316", f"\u547d\u4ee4\u5b57\u7b26\u4e32: {norm.command_string[:50]}...", Colors.CYAN)
        else:
            print_pipeline_step("[N]", "\u5f52\u4e00\u5316", f"\u4e8b\u4ef6\u7c7b\u578b: {norm.event_type}", Colors.CYAN)
        if match.has_match:
            rule_ids = [r.rule_id for r in match.matched_rules]
            actions = [r.action for r in match.matched_rules]
            rule_str = f"{', '.join(rule_ids)}({actions[0]})"
            color = Colors.RED if 'block' in actions else Colors.YELLOW
            print_pipeline_step("[R]", "\u89c4\u5219\u5339\u914d", f"\u547d\u4e2d\u89c4\u5219: {rule_str} [!]", color)
        else:
            print_pipeline_step("[R]", "\u89c4\u5219\u5339\u914d", "\u547d\u4e2d\u89c4\u5219: \u65e0 [OK]", Colors.GREEN)
        score_color = Colors.GREEN if assessment.overall_score < 0.3 else (Colors.YELLOW if assessment.overall_score < 0.6 else Colors.RED)
        level_str = assessment.risk_level.value
        print_pipeline_step("[S]", "\u98ce\u9669\u8bc4\u5206", f"{assessment.overall_score:.2f} ({level_str})" + (" [!]" if assessment.overall_score >= 0.6 else ""), score_color)
        print_dimension_scores(assessment.dimension_scores)
        action_str = decision.action.value
        tier_str = decision.tier.value
        if decision.action == DecisionAction.BLOCK:
            print_pipeline_step("[D]", "\u7814\u5224\u51b3\u7b56", f"{action_str} ({tier_str}) [X]", Colors.RED)
        elif decision.action == DecisionAction.ALERT:
            print_pipeline_step("[D]", "\u7814\u5224\u51b3\u7b56", f"{action_str} ({tier_str}) [!]", Colors.YELLOW)
        else:
            print_pipeline_step("[D]", "\u7814\u5224\u51b3\u7b56", f"{action_str} ({tier_str})", Colors.GREEN)
        effective_tier_str = blocking_result.tier.value
        tier_escalated = escalated and effective_tier_str != tier_str
        if blocking_result.blocked:
            if blocking_result.tier == ActionTier.TIER3:
                print_pipeline_step("[!]", "\u5904\u7f6e\u7ed3\u679c", "\u786c\u4e2d\u65ad! \u8fdb\u7a0b\u6811\u7ec8\u6b62", Colors.RED)
                if reverse_cmd:
                    print(C(f"   \u2502   \u2514\u2500 [\u53cd\u5411\u7ba1\u9053] {reverse_cmd.cmd_type} -> pid={reverse_cmd.target_pid}", Colors.RED))
                if tier_escalated:
                    print(C(f"   \u2502   \u2514\u2500 [\u5347\u7ea7!] {tier_str} -> {effective_tier_str} (\u8fdd\u89c4\u7d2f\u8ba1\u5347\u7ea7)", Colors.RED + Colors.BOLD))
            else:
                print_pipeline_step("[!]", "\u5904\u7f6e\u7ed3\u679c", "\u963b\u6b62\u8bbf\u95ee! \u8fd4\u56de EPERM", Colors.RED)
                if reverse_cmd:
                    print(C(f"   \u2502   \u2514\u2500 [\u53cd\u5411\u7ba1\u9053] {reverse_cmd.cmd_type} -> event={reverse_cmd.target_event_id}", Colors.YELLOW))
                if tier_escalated:
                    print(C(f"   \u2502   \u2514\u2500 [\u5347\u7ea7!] {tier_str} -> {effective_tier_str} (\u8fdd\u89c4\u7d2f\u8ba1\u5347\u7ea7)", Colors.RED + Colors.BOLD))
        elif decision.action == DecisionAction.ALERT:
            print_pipeline_step_last("[!]", "\u5904\u7f6e\u7ed3\u679c", "\u544a\u8b66! \u8bb0\u5f55\u5ba1\u8ba1\u65e5\u5fd7", Colors.YELLOW)
            if tier_escalated:
                print(C(f"      \u2514\u2500 [\u5347\u7ea7!] {tier_str} -> {effective_tier_str} (\u8fdd\u89c4\u7d2f\u8ba1\u5347\u7ea7)", Colors.YELLOW + Colors.BOLD))
        else:
            print_pipeline_step_last("[+]", "\u5904\u7f6e\u7ed3\u679c", "\u653e\u884c", Colors.GREEN)

    def _update_stats(self, assessment, decision, match, blocking_result, escalated, reverse_cmd):
        self.stats['total'] += 1
        self.stats['risk_distribution'][assessment.risk_level.value] += 1
        if assessment.overall_score > self.stats['max_score']:
            self.stats['max_score'] = assessment.overall_score
        if blocking_result.blocked:
            self.stats['block'] += 1
        elif decision.action == DecisionAction.ALERT:
            self.stats['alert'] += 1
        else:
            self.stats['allow'] += 1
        for rule_id in assessment.matched_rule_ids:
            self.stats['top_rules'][rule_id] = self.stats['top_rules'].get(rule_id, 0) + 1
            if rule_id not in [r[0] for r in self.stats['matched_rules_detail']]:
                self.stats['matched_rules_detail'].append((rule_id, assessment.overall_score))
        if escalated and blocking_result.tier != decision.tier:
            self.stats['escalation_count'] += 1
        if reverse_cmd:
            self.stats['reverse_commands'].append(reverse_cmd)

    def run_scenario(self, scenario_path_or_name):
        scenario, scenario_file = self.load_scenario(scenario_path_or_name)
        category = infer_category(scenario_file)
        scenario_id = scenario['id']
        self.stats = self._empty_stats()
        self.behavior_graph.reset()
        self.cmd_sender.clear()
        # U3: 创建 run 目录 + 设输出目录 + 开始审计（OutputSink 统一编排）
        self._run_mgr = self.sink.begin_run(category, scenario_id)
        if not self.silent:
            print_header(f"\u573a\u666f: {scenario['name']}")
            print(C(f"\u63cf\u8ff0: {scenario['description']}", Colors.DIM))
            print(C(f"\u9884\u671f: {scenario['expected_result']}", Colors.DIM))
            print()
        events = scenario['event_sequence']
        total = len(events)
        # 统一架构: 场景回放始终使用 SimulationCollector
        # 当 --mode 为 strace/ebpf 时，collector 不支持 load_scenario，
        # 因此创建临时 SimulationCollector 用于场景事件生成
        if hasattr(self.collector, 'load_scenario'):
            scenario_collector = self.collector
        else:
            scenario_collector = SimulationCollector(self._load_config())
        scenario_collector.load_scenario(scenario_file)
        raw_events = list(scenario_collector.start())
        for i, raw in enumerate(raw_events, 1):
            self.run_event(raw, i, total)
        self.audit_logger.close()
        if not self.silent:
            self._generate_reports(scenario)
            self.stats['top_rules'] = sorted(self.stats['top_rules'].items(), key=lambda x: x[1], reverse=True)
            # 场景分析面板
            self._print_analysis_panel(scenario)
        return scenario_id, category, self.stats.copy()

    def _generate_reports(self, scenario):
        print()
        print(C("--- 生成输出文件 ---", Colors.CYAN))
        # U3: 报告导出/图谱保存/证据写入收敛至 OutputSink（行为与下沉前一致）
        outputs = self.sink.finalize(scenario, self.stats)
        if outputs["report_path"]:
            rel_report = os.path.relpath(outputs["report_path"], self.base_dir)
            print(C(f"   [MD]  风险分析报告: {rel_report}", Colors.GREEN))
            self.stats['report_files'].append(rel_report)
        if outputs["graph_path"]:
            rel_graph = os.path.relpath(outputs["graph_path"], self.base_dir)
            print(C(f"   [JSON] 行为图谱:    {rel_graph}", Colors.GREEN))
            self.stats['report_files'].append(rel_graph)
        audit_file = outputs["audit_file"]
        if audit_file:
            rel_audit = os.path.relpath(audit_file, self.base_dir)
            print(C(f"   [JSONL] 审计日志:   {rel_audit}", Colors.GREEN))
            self.stats['report_files'].append(rel_audit)
        if outputs["evidence_path"]:
            rel_evidence = os.path.relpath(outputs["evidence_path"], self.base_dir)
            print(C(f"   [JSON] 阻断证据:    {rel_evidence}", Colors.GREEN))
            self.stats['report_files'].append(rel_evidence)

    def _print_analysis_panel(self, scenario):
        """打印场景分析面板（4维度）"""
        sid = scenario['id']
        # 提取场景前缀作为key (如 a01-rm-root -> a01)
        prefix = ''
        for part in sid.split('-'):
            if part and part[0].isalpha() and part[0].lower() in 'nabme':
                prefix = part.lower()
                break
        data = SA.get(prefix, (scenario.get('description', ''), scenario.get('expected_result', ''), '', ''))
        purpose, findings, cause, strategy = data
        print()
        print(_box_top())
        print(_box_line(C("\u573a\u666f\u5206\u6790\u9762\u677f", Colors.CYAN + Colors.BOLD)))
        print(_box_sep())
        print(_box_line(C("\u2460 \u6d4b\u8bd5\u76ee\u7684", Colors.YELLOW + Colors.BOLD)))
        print(_box_line(f"   {purpose}", Colors.WHITE))
        print(_box_sep())
        print(_box_line(C("\u2461 \u98ce\u9669\u53d1\u73b0", Colors.RED + Colors.BOLD)))
        print(_box_line(f"   {findings}", Colors.WHITE))
        if self.stats['matched_rules_detail']:
            rules_str = ', '.join([f"{r[0]}(score={r[1]:.2f})" for r in self.stats['matched_rules_detail'][:5]])
            print(_box_line(f"   \u547d\u4e2d\u89c4\u5219: {rules_str}", Colors.YELLOW))
        print(_box_line(f"   \u6700\u9ad8\u98ce\u9669\u8bc4\u5206: {self.stats['max_score']:.2f}", Colors.YELLOW))
        print(_box_sep())
        print(_box_line(C("\u2462 \u98ce\u9669\u6210\u56e0\uff08\u5f52\u56e0\u5206\u6790\uff09", Colors.MAGENTA + Colors.BOLD)))
        print(_box_line(f"   {cause}", Colors.WHITE))
        print(_box_sep())
        print(_box_line(C("\u2463 \u7efc\u5408\u5904\u7f6e\u7b56\u7565", Colors.GREEN + Colors.BOLD)))
        print(_box_line(f"   {strategy}", Colors.WHITE))
        print(_box_bot())


# ── 面板打印函数 ──────────────────────────────────────────────

def print_unit_test_panel(total, passed, failed, failed_names):
    """打印单元测试结果面板"""
    print()
    print(_box_top())
    print(_box_line(C("\u5355\u5143\u6d4b\u8bd5\u7ed3\u679c", Colors.CYAN + Colors.BOLD)))
    print(_box_sep())
    print(_box_line(f"\u603b\u7528\u4f8b\u6570:  {total}", Colors.WHITE))
    color_p = Colors.GREEN if passed == total else Colors.YELLOW
    print(_box_line(f"\u901a\u8fc7:  {passed}", color_p))
    color_f = Colors.RED if failed > 0 else Colors.GREEN
    print(_box_line(f"\u5931\u8d25:  {failed}", color_f))
    if failed > 0 and failed_names:
        print(_box_sep())
        print(_box_line(C("\u5931\u8d25\u7528\u4f8b\u5217\u8868:", Colors.RED + Colors.BOLD)))
        for name in failed_names[:20]:
            print(_box_line(f"  {C('x', Colors.RED)} {name}", Colors.RED))
    else:
        print(_box_line(C("\u2713 \u5168\u90e8\u901a\u8fc7!", Colors.GREEN + Colors.BOLD)))
    print(_box_bot())
    print()


def print_global_stats_panel(all_stats, category_stats):
    """打印全量模拟测试全局统计面板"""
    total_events = sum(s['total'] for s in all_stats)
    total_allow = sum(s['allow'] for s in all_stats)
    total_alert = sum(s['alert'] for s in all_stats)
    total_block = sum(s['block'] for s in all_stats)
    print()
    print(_box_top())
    print(_box_line(C("\u5168\u91cf\u6a21\u62df\u6d4b\u8bd5 \u2014 \u5168\u5c40\u6570\u636e\u7edf\u8ba1", Colors.CYAN + Colors.BOLD)))
    print(_box_sep())
    print(_box_line(C("\u603b\u4f53\u7edf\u8ba1", Colors.YELLOW + Colors.BOLD)))
    print(_box_line(f"\u603b\u4e8b\u4ef6\u6570:    {total_events}", Colors.WHITE))
    print(_box_line(f"\u603b\u653e\u884c(ALLOW):  {total_allow}", Colors.GREEN))
    print(_box_line(f"\u603b\u544a\u8b66(ALERT):  {total_alert}", Colors.YELLOW))
    print(_box_line(f"\u603b\u963b\u65ad(BLOCK):   {total_block}", Colors.RED))
    print(_box_sep())
    print(_box_line(C("\u5206\u7c7b\u7edf\u8ba1", Colors.YELLOW + Colors.BOLD)))
    cat_labels = {
        'normal': ('\u6b63\u5e38 Normal', Colors.GREEN),
        'anomalous': ('\u5f02\u5e38 Anomalous', Colors.RED),
        'boundary': ('\u8fb9\u754c Boundary', Colors.YELLOW),
        'multi_agent': ('\u591aAgent Multi', Colors.MAGENTA),
        'extreme': ('\u6781\u7aef Extreme', Colors.CYAN),
    }
    for cat in ['normal', 'anomalous', 'boundary', 'multi_agent', 'extreme']:
        cs = category_stats.get(cat, {'allow': 0, 'alert': 0, 'block': 0})
        label, color = cat_labels[cat]
        line = f"{label:20s}  \u653e\u884c:{cs['allow']:>3d}  \u544a\u8b66:{cs['alert']:>3d}  \u963b\u65ad:{cs['block']:>3d}"
        print(_box_line(line, color))
    print(_box_bot())
    print()


# ── 场景发现 ──────────────────────────────────────────────────

def _discover_all_scenarios(base_dir):
    scenarios_dir = os.path.join(base_dir, 'scenarios')
    files = []
    for cat_dir in ['normal', 'anomalous', 'boundary', 'multi_agent', 'extreme']:
        pattern = os.path.join(scenarios_dir, cat_dir, '*.yaml')
        files.extend(sorted(glob.glob(pattern)))
    return files

def _discover_category(base_dir, category):
    pattern = os.path.join(base_dir, 'scenarios', category, '*.yaml')
    return sorted(glob.glob(pattern))

def _print_scenario_menu(base_dir):
    scenarios_dir = os.path.join(base_dir, 'scenarios')
    idx = 1
    cat_labels = {
        'normal': 'Normal \u6b63\u5e38\u884c\u4e3a (N01-N08)',
        'anomalous': 'Anomalous \u5f02\u5e38\u884c\u4e3a (A01-A12)',
        'boundary': 'Boundary \u8fb9\u754c\u573a\u666f (B01-B08)',
        'multi_agent': 'Multi-Agent \u591aAgent\u534f\u4f5c (M01-M05)',
        'extreme': 'Extreme \u6781\u7aef\u573a\u666f (E01-E04)',
    }
    cat_colors = {
        'normal': Colors.GREEN, 'anomalous': Colors.RED,
        'boundary': Colors.YELLOW, 'multi_agent': Colors.MAGENTA, 'extreme': Colors.CYAN,
    }
    all_items = []
    for cat_dir in ['normal', 'anomalous', 'boundary', 'multi_agent', 'extreme']:
        cat_path = os.path.join(scenarios_dir, cat_dir)
        if not os.path.isdir(cat_path):
            continue
        yamls = sorted(glob.glob(os.path.join(cat_path, '*.yaml')))
        if not yamls:
            continue
        print(C(f"  [{cat_labels.get(cat_dir, cat_dir)}]", cat_colors.get(cat_dir, Colors.WHITE) + Colors.BOLD))
        for yf in yamls:
            with open(yf, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            s = data.get('scenario', {})
            name = s.get('name', os.path.basename(yf))
            sid = s.get('id', '')
            print(C(f"    {idx:2d}. {sid} - {name}", Colors.WHITE))
            all_items.append(yf)
            idx += 1
    return all_items


# ── 功能选项实现 ──────────────────────────────────────────────

def run_unit_tests():
    """选项1: 运行全部单元测试"""
    print(C("\n\u6b63\u5728\u8fd0\u884c\u5355\u5143\u6d4b\u8bd5...", Colors.DIM))
    base_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pytest', base_dir, '-v', '--tb=short'],
            capture_output=True, text=True, timeout=120,
            cwd=base_dir)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        print_unit_test_panel(0, 0, 1, ['pytest \u8fd0\u884c\u8d85\u65f6(>120s)'])
        return
    # 解析结果
    total, passed, failed = 0, 0, 0
    failed_names = []
    for line in output.split('\n'):
        if ' PASSED' in line:
            passed += 1
            total += 1
        elif ' FAILED' in line:
            failed += 1
            total += 1
            # 提取测试名称
            name = line.split(' FAILED')[0].strip()
            if '::' in name:
                name = name.split('::')[-1]
            failed_names.append(name)
        elif line.startswith('passed') or 'passed' in line:
            # 尝试从 summary 行解析
            m = re.search(r'(\d+) passed', line)
            if m:
                passed = int(m.group(1))
            m = re.search(r'(\d+) failed', line)
            if m:
                failed = int(m.group(1))
            if passed + failed > total:
                total = passed + failed
    if total == 0:
        # 回退: 从 test_results.json 读取
        json_path = os.path.join(base_dir, 'output', 'unit_test', 'test_results.json')
        if os.path.exists(json_path):
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            total = data.get('total', 0)
            passed = data.get('passed', 0)
            failed = data.get('failed', 0)
            for d in data.get('details', []):
                if d.get('when') == 'call' and d.get('outcome') == 'failed':
                    failed_names.append(d.get('nodeid', ''))
    print_unit_test_panel(total, passed, failed, failed_names)


def run_all_scenarios_silent():
    """选项2: 静默运行全部37个场景"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    scenario_files = _discover_all_scenarios(base_dir)
    if not scenario_files:
        print(C("\u672a\u627e\u5230\u573a\u666f\u6587\u4ef6", Colors.RED))
        return
    print(C(f"\n\u6b63\u5728\u9759\u9ed8\u8fd0\u884c {len(scenario_files)} \u4e2a\u573a\u666f...", Colors.DIM))
    runner = ScenarioRunner(auto_mode=True, silent=True)
    all_stats = []
    category_stats = {}
    for sf in scenario_files:
        try:
            sid, cat, stats = runner.run_scenario(sf)
            all_stats.append(stats)
            if cat not in category_stats:
                category_stats[cat] = {'allow': 0, 'alert': 0, 'block': 0}
            category_stats[cat]['allow'] += stats['allow']
            category_stats[cat]['alert'] += stats['alert']
            category_stats[cat]['block'] += stats['block']
        except Exception as e:
            print(C(f"\u573a\u666f {sf} \u8fd0\u884c\u5931\u8d25: {e}", Colors.RED))
    print_global_stats_panel(all_stats, category_stats)


def browse_category():
    """选项3: 分类场景浏览"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cat_options = [
        ('normal', 'Normal \u6b63\u5e38\u884c\u4e3a', Colors.GREEN),
        ('anomalous', 'Anomalous \u5f02\u5e38\u884c\u4e3a', Colors.RED),
        ('boundary', 'Boundary \u8fb9\u754c\u573a\u666f', Colors.YELLOW),
        ('multi_agent', 'Multi-Agent \u591aAgent\u534f\u4f5c', Colors.MAGENTA),
        ('extreme', 'Extreme \u6781\u7aef\u573a\u666f', Colors.CYAN),
    ]
    print()
    print(C("\u2500\u2500 \u9009\u62e9\u573a\u666f\u5206\u7c7b \u2500\u2500", Colors.CYAN + Colors.BOLD))
    for i, (key, label, color) in enumerate(cat_options, 1):
        count = len(_discover_category(base_dir, key))
        print(C(f"  {i}. {label} ({count}\u4e2a\u573a\u666f)", color))
    print(C("  0. \u8fd4\u56de\u4e3b\u83dc\u5355", Colors.DIM))
    print()
    choice = input(C("\u8bf7\u8f93\u5165\u9009\u9879 [0-5]: ", Colors.CYAN)).strip()
    if choice == '0' or choice == '':
        return
    cat_map = {'1': 'normal', '2': 'anomalous', '3': 'boundary', '4': 'multi_agent', '5': 'extreme'}
    if choice not in cat_map:
        print(C("\u65e0\u6548\u9009\u9879", Colors.YELLOW))
        return
    cat_dir = cat_map[choice]
    _category_submenu(cat_dir)


def _category_submenu(cat_dir):
    """分类子菜单"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    files = _discover_category(base_dir, cat_dir)
    cat_labels = {
        'normal': 'Normal \u6b63\u5e38\u884c\u4e3a', 'anomalous': 'Anomalous \u5f02\u5e38\u884c\u4e3a',
        'boundary': 'Boundary \u8fb9\u754c\u573a\u666f', 'multi_agent': 'Multi-Agent \u591aAgent\u534f\u4f5c',
        'extreme': 'Extreme \u6781\u7aef\u573a\u666f',
    }
    cat_colors = {
        'normal': Colors.GREEN, 'anomalous': Colors.RED, 'boundary': Colors.YELLOW,
        'multi_agent': Colors.MAGENTA, 'extreme': Colors.CYAN,
    }
    color = cat_colors.get(cat_dir, Colors.WHITE)
    label = cat_labels.get(cat_dir, cat_dir)
    print()
    print(C(f"\u2500\u2500 {label} \u2500\u2500", color + Colors.BOLD))
    print(C("  A. \u8fd0\u884c\u8be5\u5206\u7c7b\u4e0b\u5168\u90e8\u573a\u666f", Colors.WHITE))
    print(C("  B. \u6307\u5b9a\u67d0\u4e2a\u5177\u4f53\u573a\u666f", Colors.WHITE))
    print(C("  C. \u5220\u9664\u6d4b\u8bd5\u8bb0\u5f55", Colors.YELLOW))
    print(C("  0. \u8fd4\u56de\u4e0a\u4e00\u7ea7", Colors.DIM))
    print()
    sub = input(C("\u8bf7\u8f93\u5165\u9009\u9879 [A/B/C/0]: ", Colors.CYAN)).strip().upper()
    if sub == '0' or sub == '':
        return
    elif sub == 'A':
        runner = ScenarioRunner(auto_mode=False)
        for i, sf in enumerate(files):
            runner.run_scenario(sf)
            if i < len(files) - 1:
                input(C("\n[\u6309 Enter \u7ee7\u7eed\u4e0b\u4e00\u4e2a\u573a\u666f...]", Colors.DIM))
    elif sub == 'B':
        # 列出该分类下的场景
        print()
        for i, sf in enumerate(files, 1):
            with open(sf, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            s = data.get('scenario', {})
            print(C(f"  {i:2d}. {s.get('id', '')} - {s.get('name', '')}", Colors.WHITE))
        print()
        sc = input(C("\u8f93\u5165\u573a\u666f\u5e8f\u53f7\u6216ID (\u5982 a01): ", Colors.CYAN)).strip()
        if not sc:
            return
        # 尝试作为序号
        try:
            idx = int(sc) - 1
            if 0 <= idx < len(files):
                runner = ScenarioRunner(auto_mode=False)
                runner.run_scenario(files[idx])
                return
        except ValueError:
            pass
        # 尝试作为场景ID
        runner = ScenarioRunner(auto_mode=False)
        try:
            runner.run_scenario(sc)
        except FileNotFoundError:
            print(C(f"\u672a\u627e\u5230\u573a\u666f: {sc}", Colors.RED))
    elif sub == 'C':
        _delete_records_menu(cat_dir)


def _confirm_delete(prompt_msg):
    """删除确认提示，返回 True 表示用户确认"""
    print()
    ans = input(C(prompt_msg, Colors.YELLOW)).strip().lower()
    return ans == 'y'


def _print_delete_stats(deleted_dirs, deleted_files):
    """打印删除统计信息"""
    if deleted_dirs > 0:
        print(C(f"\n\u2713 \u5220\u9664\u5b8c\u6210: {deleted_dirs} \u4e2a\u76ee\u5f55, {deleted_files} \u4e2a\u6587\u4ef6", Colors.GREEN))
    else:
        print(C("\n\u672a\u627e\u5230\u53ef\u5220\u9664\u7684\u6d4b\u8bd5\u8bb0\u5f55", Colors.YELLOW))


def _delete_records_menu(cat_dir):
    """删除测试记录子菜单（统计/删除复用 OutputFileManager，交互菜单保留）"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(base_dir, 'output', 'reports')
    fm = OutputFileManager(base_dir, os.path.dirname(base_dir))
    cat_labels = {
        'normal': 'Normal', 'anomalous': 'Anomalous',
        'boundary': 'Boundary', 'multi_agent': 'Multi-Agent', 'extreme': 'Extreme',
    }

    while True:
        print()
        print(C(f"\u2500\u2500 \u5220\u9664\u6d4b\u8bd5\u8bb0\u5f55 [{cat_labels.get(cat_dir, cat_dir)}] \u2500\u2500", Colors.YELLOW + Colors.BOLD))
        print(C("  1. \u6e05\u7a7a\u5168\u90e8\u6d4b\u8bd5\u8bb0\u5f55", Colors.WHITE))
        print(C("     \u5220\u9664 output/reports/ \u4e0b\u6240\u6709\u5206\u7c7b\u7684\u5168\u90e8\u65f6\u95f4\u6233\u5b50\u76ee\u5f55", Colors.DIM))
        print(C("  2. \u6309\u5206\u7c7b\u5220\u9664", Colors.WHITE))
        print(C("     \u9009\u62e9\u4e00\u4e2a\u5206\u7c7b\uff0c\u5220\u9664\u8be5\u5206\u7c7b\u4e0b\u6240\u6709\u573a\u666f\u7684\u6d4b\u8bd5\u8bb0\u5f55", Colors.DIM))
        print(C("  3. \u6309\u573a\u666f\u5220\u9664", Colors.WHITE))
        print(C("     \u8f93\u5165\u573a\u666f ID\uff08\u5982 e01\uff09\uff0c\u4ec5\u5220\u9664\u8be5\u573a\u666f\u7684\u65f6\u95f4\u6233\u5b50\u76ee\u5f55", Colors.DIM))
        print(C("  0. \u8fd4\u56de\u4e0a\u4e00\u7ea7", Colors.DIM))
        print()
        choice = input(C("\u8bf7\u8f93\u5165\u9009\u9879 [0-3]: ", Colors.CYAN)).strip()

        if choice == '0' or choice == '':
            return
        elif choice == '1':
            # 清空全部测试记录（场景枚举与统计复用 OutputFileManager）
            scenario_paths = []
            for cat in ['normal', 'anomalous', 'boundary', 'multi_agent', 'extreme']:
                scenario_paths.extend(
                    sp for _c, _n, sp in fm.list_scenario_dirs([cat]))
            ts_dirs_list, total_ts, total_files = fm.collect_ts_dirs(scenario_paths)
            if total_ts == 0:
                print(C("\n\u672a\u627e\u5230\u53ef\u5220\u9664\u7684\u6d4b\u8bd5\u8bb0\u5f55", Colors.YELLOW))
                continue
            print(C(f"\n\u5c06\u5220\u9664\u5168\u90e8 5 \u4e2a\u5206\u7c7b\u7684\u6d4b\u8bd5\u8bb0\u5f55: {total_ts} \u4e2a\u65f6\u95f4\u6233\u76ee\u5f55, {total_files} \u4e2a\u6587\u4ef6", Colors.YELLOW))
            if not _confirm_delete("\u786e\u8ba4\u5220\u9664\uff1f\u6b64\u64cd\u4f5c\u4e0d\u53ef\u6062\u590d [y/N]:"):
                print(C("\u5df2\u53d6\u6d88", Colors.DIM))
                continue
            d_dirs, d_files = fm.delete_ts_dirs(ts_dirs_list)
            _print_delete_stats(d_dirs, d_files)

        elif choice == '2':
            # 按分类删除
            cat_options = [
                ('normal', 'Normal \u6b63\u5e38\u884c\u4e3a', Colors.GREEN),
                ('anomalous', 'Anomalous \u5f02\u5e38\u884c\u4e3a', Colors.RED),
                ('boundary', 'Boundary \u8fb9\u754c\u573a\u666f', Colors.YELLOW),
                ('multi_agent', 'Multi-Agent \u591aAgent\u534f\u4f5c', Colors.MAGENTA),
                ('extreme', 'Extreme \u6781\u7aef\u573a\u666f', Colors.CYAN),
            ]
            print()
            for i, (key, label, color) in enumerate(cat_options, 1):
                # 统计复用 OutputFileManager（目录枚举 + 时间戳统计）
                scenario_paths = [sp for _c, _n, sp in fm.list_scenario_dirs([key])]
                _tl, ts_count, _tf = fm.collect_ts_dirs(scenario_paths)
                print(C(f"  {i}. {label} ({ts_count} 个时间戳目录)", color))
            print(C("  0. \u8fd4\u56de", Colors.DIM))
            print()
            cc = input(C("\u9009\u62e9\u5206\u7c7b [0-5]: ", Colors.CYAN)).strip()
            if cc == '0' or cc == '':
                continue
            cat_map = {'1': 'normal', '2': 'anomalous', '3': 'boundary', '4': 'multi_agent', '5': 'extreme'}
            if cc not in cat_map:
                print(C("\u65e0\u6548\u9009\u9879", Colors.RED))
                continue
            target_cat = cat_map[cc]
            target_path = os.path.join(reports_dir, target_cat)
            if not os.path.isdir(target_path):
                print(C(f"\u5206\u7c7b\u76ee\u5f55\u4e0d\u5b58\u5728: {target_cat}", Colors.YELLOW))
                continue
            # 收集要删除的目录（复用 OutputFileManager）
            scenario_paths = [sp for _c, _n, sp in fm.list_scenario_dirs([target_cat])]
            ts_dirs_list, total_ts, total_files = fm.collect_ts_dirs(scenario_paths)
            if total_ts == 0:
                print(C(f"\n\u5206\u7c7b [{cat_labels.get(target_cat)}] \u4e0b\u672a\u627e\u5230\u53ef\u5220\u9664\u7684\u6d4b\u8bd5\u8bb0\u5f55", Colors.YELLOW))
                continue
            print(C(f"\n\u5c06\u5220\u9664\u5206\u7c7b [{cat_labels.get(target_cat)}] \u7684\u6d4b\u8bd5\u8bb0\u5f55: {total_ts} \u4e2a\u65f6\u95f4\u6233\u76ee\u5f55, {total_files} \u4e2a\u6587\u4ef6", Colors.YELLOW))
            if not _confirm_delete("\u786e\u8ba4\u5220\u9664\uff1f\u6b64\u64cd\u4f5c\u4e0d\u53ef\u6062\u590d [y/N]:"):
                print(C("\u5df2\u53d6\u6d88", Colors.DIM))
                continue
            d_dirs, d_files = fm.delete_ts_dirs(ts_dirs_list)
            _print_delete_stats(d_dirs, d_files)

        elif choice == '3':
            # 按场景删除
            print()
            sc = input(C("\u8f93\u5165\u573a\u666f ID (\u5982 e01, a03): ", Colors.CYAN)).strip().lower()
            if not sc:
                continue
            # 在所有分类中搜索匹配的场景目录（模糊匹配复用 OutputFileManager）
            matched_scenario_paths = fm.list_scenario_dirs(
                ['normal', 'anomalous', 'boundary', 'multi_agent', 'extreme'],
                scenario_filter=sc)
            if not matched_scenario_paths:
                print(C(f"\n\u672a\u627e\u5230\u5339\u914d\u7684\u573a\u666f\u8bb0\u5f55: {sc}", Colors.YELLOW))
                continue
            # 显示匹配的场景及记录数
            print()
            total_ts = 0
            total_files = 0
            for cat, sname, spath in matched_scenario_paths:
                n_dirs, n_files = fm.count_dir_contents(spath)
                total_ts += n_dirs
                total_files += n_files
                print(C(f"  [{cat}] {sname}: {n_dirs} \u4e2a\u65f6\u95f4\u6233\u76ee\u5f55, {n_files} \u4e2a\u6587\u4ef6", Colors.WHITE))
            if total_ts == 0:
                print(C("\n\u8be5\u573a\u666f\u4e0b\u672a\u627e\u5230\u53ef\u5220\u9664\u7684\u6d4b\u8bd5\u8bb0\u5f55", Colors.YELLOW))
                continue
            print(C(f"\n\u5171\u8ba1: {total_ts} \u4e2a\u65f6\u95f4\u6233\u76ee\u5f55, {total_files} \u4e2a\u6587\u4ef6", Colors.YELLOW))
            if not _confirm_delete("\u786e\u8ba4\u5220\u9664\uff1f\u6b64\u64cd\u4f5c\u4e0d\u53ef\u6062\u590d [y/N]:"):
                print(C("\u5df2\u53d6\u6d88", Colors.DIM))
                continue
            # 收集并删除（复用 OutputFileManager）
            ts_dirs_list, _t, _f = fm.collect_ts_dirs(
                [spath for _c, _n, spath in matched_scenario_paths])
            d_dirs, d_files = fm.delete_ts_dirs(ts_dirs_list)
            _print_delete_stats(d_dirs, d_files)


# ── 主菜单 ────────────────────────────────────────────────────

def print_main_menu():
    print()
    print(_box_top())
    print(_box_line(C("\u65b9\u5bf8\u89c2\u5bdf\u8005\u6a21\u62df\u5b66\u4e60\u7cfb\u7edf \u2014 \u4e3b\u83dc\u5355", Colors.CYAN + Colors.BOLD)))
    print(_box_sep())
    print(_box_line("", Colors.WHITE))
    print(_box_line(C("  1.", Colors.CYAN) + C(" \u8fd0\u884c\u5168\u90e8\u5355\u5143\u6d4b\u8bd5", Colors.WHITE), Colors.WHITE))
    print(_box_line(C("     ", Colors.CYAN) + C("   \u8c03\u7528 pytest \u8fd0\u884c 130 \u4e2a\u5355\u5143\u6d4b\u8bd5\u7528\u4f8b\uff0c\u663e\u793a\u7ed3\u679c\u6458\u8981", Colors.DIM), Colors.WHITE))
    print(_box_line("", Colors.WHITE))
    print(_box_line(C("  2.", Colors.CYAN) + C(" \u8fd0\u884c\u5168\u91cf\u6a21\u62df\u73af\u5883\u6d4b\u8bd5", Colors.WHITE), Colors.WHITE))
    print(_box_line(C("     ", Colors.CYAN) + C("   \u9759\u9ed8\u8fd0\u884c 37 \u4e2a\u573a\u666f\uff0c\u663e\u793a\u5168\u5c40\u6570\u636e\u7edf\u8ba1\u9762\u677f", Colors.DIM), Colors.WHITE))
    print(_box_line("", Colors.WHITE))
    print(_box_line(C("  3.", Colors.CYAN) + C(" \u6309\u5206\u7c7b\u6d4f\u89c8\u5e76\u8fd0\u884c\u573a\u666f\u6d4b\u8bd5", Colors.WHITE), Colors.WHITE))
    print(_box_line(C("     ", Colors.CYAN) + C("   \u6d4f\u89c8 5 \u4e2a\u5206\u7c7b\uff0c\u8fd0\u884c\u5168\u90e8\u6216\u6307\u5b9a\u5355\u4e2a\u573a\u666f", Colors.DIM), Colors.WHITE))
    print(_box_line("", Colors.WHITE))
    print(_box_sep())
    print(_box_line(C("  0.", Colors.DIM) + C(" \u9000\u51fa", Colors.DIM), Colors.DIM))
    print(_box_bot())
    print()


def main():
    import argparse
    parser = argparse.ArgumentParser(description='\u65b9\u5bf8\u89c2\u5bdf\u8005\u6a21\u62df\u5b66\u4e60\u7cfb\u7edf - \u4ea4\u4e92\u5f0f\u6f14\u793a')
    parser.add_argument('--auto', action='store_true', help='\u81ea\u52a8\u64ad\u653e\u6a21\u5f0f\uff08\u4e0d\u6682\u505c\uff09')
    parser.add_argument('--scenario', type=str, help='\u6307\u5b9a\u573a\u666fID\uff08\u5982 n01, a01\uff09\u6216\u6587\u4ef6\u540d')
    parser.add_argument('--category', type=str, help='按分类运行 (normal/anomalous/boundary/multi_agent/extreme)')
    parser.add_argument('--mode', type=str, default=None,
                        choices=['auto', 'simulation', 'strace', 'ebpf'],
                        help='采集模式 (默认从 config.yaml 读取)')
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # 命令行参数兼容
    if args.scenario:
        runner = ScenarioRunner(auto_mode=args.auto, mode=args.mode)
        if not runner.silent:
            print(C(f"采集模式: {runner._mode_name}", Colors.DIM))
        all_files = _discover_all_scenarios(base_dir)
        matched = [f for f in all_files if args.scenario.lower() in os.path.basename(f).lower()]
        if not matched:
            print(C(f"\u672a\u627e\u5230\u5339\u914d\u573a\u666f: {args.scenario}", Colors.RED))
            return
        for sf in matched:
            runner.run_scenario(sf)
        return
    if args.category:
        runner = ScenarioRunner(auto_mode=args.auto, mode=args.mode)
        files = _discover_category(base_dir, args.category.lower())
        if not files:
            print(C(f"\u672a\u627e\u5230\u5206\u7c7b: {args.category}", Colors.RED))
            return
        for sf in files:
            runner.run_scenario(sf)
        return
    if args.auto:
        runner = ScenarioRunner(auto_mode=True, mode=args.mode)
        if not runner.silent:
            print(C(f"采集模式: {runner._mode_name}", Colors.DIM))
        for sf in _discover_all_scenarios(base_dir):
            runner.run_scenario(sf)
        return

    # 交互式主菜单循环
    while True:
        print_main_menu()
        choice = input(C("\u8bf7\u8f93\u5165\u9009\u9879 [0-3]: ", Colors.CYAN)).strip()
        if choice == '1':
            run_unit_tests()
        elif choice == '2':
            run_all_scenarios_silent()
        elif choice == '3':
            browse_category()
        elif choice == '0':
            print(C("\n\u518d\u89c1!\n", Colors.CYAN))
            break
        else:
            print(C("\u65e0\u6548\u9009\u9879\uff0c\u8bf7\u91cd\u65b0\u9009\u62e9", Colors.YELLOW))


if __name__ == "__main__":
    main()
