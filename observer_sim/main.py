#!/usr/bin/env python3
"""
main.py — 方寸观察者模拟学习系统 主入口

用法:
    python main.py --scenario all                      # 运行全部37个场景
    python main.py --scenario n01                      # 按场景ID前缀匹配
    python main.py --category normal                   # 按分类运行
    python main.py --scenario all --output output      # 指定输出目录

功能:
    加载场景 YAML → 逐事件处理 → 全链路Pipeline → 分类+时间戳归档输出
"""

import sys
import os
import argparse
import logging
import yaml
import glob
import time
from typing import Dict, List, Optional

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.event import RawEvent, NormalizedEvent, AgentContext
from models.virtual_clock import VirtualClock
from models.risk import (
    RiskAssessment, RiskLevel, Decision, DecisionAction, ActionTier, BlockingResult
)
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


def setup_logging(config: dict):
    """配置日志"""
    log_config = config.get("logging", {})
    level = getattr(logging, log_config.get("level", "INFO"))
    fmt = log_config.get("format", "[%(asctime)s] %(levelname)s %(name)s: %(message)s")
    logging.basicConfig(level=level, format=fmt)


def load_config(config_path: str = "config.yaml") -> dict:
    """加载配置文件"""
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_scenario(scenario_path: str) -> dict:
    """加载场景 YAML"""
    with open(scenario_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data["scenario"]


def create_raw_event(event_data: dict, agent_info: dict, seq: int) -> RawEvent:
    """从场景 YAML 事件数据创建 RawEvent"""
    return RawEvent(
        event_id=f"evt-{seq:04d}",
        timestamp_ns=0,  # 由 VirtualClock 设置
        event_type=event_data["type"],
        pid=agent_info.get("initial_pid", 10001),
        ppid=1,
        agent_id=event_data.get("agent", agent_info.get("agent_id", "unknown")),
        agent_framework=agent_info.get("framework", "unknown"),
        executable=event_data.get("executable"),
        arguments=event_data.get("arguments"),
        file_path=event_data.get("file_path"),
        file_op=event_data.get("file_op"),
        remote_addr=event_data.get("remote_addr"),
        remote_port=event_data.get("remote_port"),
        protocol=event_data.get("protocol"),
    )


def run_scenario_pipeline(scenario: dict, clock: VirtualClock,
                          normalizer: EventNormalizer,
                          rule_engine: RuleEngine,
                          scorer: RiskScorer,
                          baseline_checker: BaselineChecker,
                          decision_engine: DecisionEngine,
                          chain_builder: ChainReportBuilder,
                          blocking_coord: BlockingCoordinator,
                          behavior_graph: BehaviorGraph,
                          audit_logger: AuditLogger,
                          output_dir: str) -> Dict:
    """
    运行单个场景的全链路处理流水线。

    Returns:
        Dict: 场景运行摘要
    """
    scenario_id = scenario["id"]
    scenario_name = scenario["name"]

    # 构建 agent 信息映射
    agents_map = {}
    for agent in scenario.get("agents", []):
        agents_map[agent["agent_id"]] = agent

    events = scenario.get("event_sequence", [])
    total = len(events)

    stats = {"total": total, "allow": 0, "alert": 0, "block": 0}

    for i, event_data in enumerate(events, 1):
        seq = event_data.get("seq", i)
        delay_ms = event_data.get("delay_ms", 0)
        agent_id = event_data.get("agent", "unknown")
        agent_info = agents_map.get(agent_id, {"agent_id": agent_id, "initial_pid": 10001})

        # 1. 推进虚拟时钟
        clock.advance(delay_ms)

        # 2. 创建 RawEvent
        raw = create_raw_event(event_data, agent_info, seq)
        raw.timestamp_ns = clock.now_ns()

        # 3. 归一化
        norm = normalizer.normalize(raw)

        # 4. 规则匹配
        match_result = rule_engine.match(norm)
        matched_rule_ids = [r.rule_id for r in match_result.matched_rules]

        # 5. 基线收集
        baseline_checker.collect(norm)

        # 6. 风险评分
        baseline_data = baseline_checker.get_baseline_dict()
        scorer.set_baseline(baseline_data)
        agent_ctx = normalizer.get_agent_context(agent_id)
        assessment = scorer.assess(norm, match_result, agent_ctx)

        # 7. 研判决策
        decision = decision_engine.decide(assessment, norm.event_id, agent_id)

        # 8. 阻断执行
        blocking_result = blocking_coord.execute(norm, decision)

        # 9. 记录到行为图谱
        behavior_graph.add_event(
            norm, assessment=assessment, decision=decision,
            blocking_result=blocking_result, matched_rules=matched_rule_ids
        )

        # 10. 写入审计日志
        description = _build_description(norm)
        audit_logger.log_event(
            norm, assessment=assessment, decision=decision,
            blocking_result=blocking_result, matched_rules=matched_rule_ids,
            description=description
        )

        # 更新统计
        if blocking_result.blocked:
            stats["block"] += 1
        elif decision.action == DecisionAction.ALERT:
            stats["alert"] += 1
        else:
            stats["allow"] += 1

        # 打印进度
        status = "BLOCK" if blocking_result.blocked else ("ALERT" if decision.action == DecisionAction.ALERT else "PASS")
        logging.info(f"  [{status:5s}] ({i}/{total}) {description}")

    return stats


def _build_description(event: NormalizedEvent) -> str:
    """构建事件描述"""
    et = event.event_type
    if et == "exec":
        cmd = event.command_string or ""
        if not cmd:
            parts = [event.raw.executable or ""]
            if event.raw.arguments:
                parts.extend(event.raw.arguments)
            cmd = " ".join(parts)
        return f"exec: {cmd[:60]}"
    elif et == "file_open":
        op = event.raw.file_op or "open"
        path = event.raw.file_path or ""
        return f"file_{op}: {path}"
    elif et == "net_conn":
        addr = event.raw.remote_addr or ""
        port = event.raw.remote_port
        return f"net: {addr}:{port}" if port else f"net: {addr}"
    return f"{et}"


def discover_scenarios(base_dir: str, category: str = None, scenario_filter: str = None) -> List[str]:
    """
    发现场景文件。

    Args:
        base_dir: 项目根目录
        category: 按分类过滤 (normal/anomalous/boundary/multi_agent/extreme)
        scenario_filter: 按场景ID前缀匹配 (如 'n01', 'a01')

    Returns:
        List[str]: 场景文件路径列表
    """
    scenarios_dir = os.path.join(base_dir, "scenarios")
    files = []

    if category:
        # 按分类目录查找
        pattern = os.path.join(scenarios_dir, category, "*.yaml")
        files = sorted(glob.glob(pattern))
    elif scenario_filter and scenario_filter != "all":
        # 在所有分类中搜索匹配的场景
        for cat_dir in ["normal", "anomalous", "boundary", "multi_agent", "extreme"]:
            pattern = os.path.join(scenarios_dir, cat_dir, f"*{scenario_filter}*.yaml")
            files.extend(sorted(glob.glob(pattern)))
        # 兼容旧场景文件
        pattern = os.path.join(scenarios_dir, f"*{scenario_filter}*.yaml")
        files.extend(sorted(glob.glob(pattern)))
    else:
        # 全部场景：按分类顺序收集
        for cat_dir in ["normal", "anomalous", "boundary", "multi_agent", "extreme"]:
            pattern = os.path.join(scenarios_dir, cat_dir, "*.yaml")
            files.extend(sorted(glob.glob(pattern)))

    return files


def main():
    parser = argparse.ArgumentParser(description="方寸观察者模拟学习系统")
    parser.add_argument("--scenario", type=str, default="all",
                        help="场景ID前缀 (如 n01, a01, all)")
    parser.add_argument("--category", type=str, default=None,
                        help="按分类运行 (normal/anomalous/boundary/multi_agent/extreme)")
    parser.add_argument("--config", type=str, default="config.yaml",
                        help="配置文件路径")
    parser.add_argument("--output", type=str, default="output",
                        help="输出目录")
    args = parser.parse_args()

    # 切换到脚本所在目录
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # 加载配置
    config = load_config(args.config)
    setup_logging(config)
    logger = logging.getLogger("main")

    logger.info("=" * 60)
    logger.info("  方寸观察者模拟学习系统")
    logger.info("=" * 60)

    base_output = args.output

    # 发现场景文件
    scenario_files = discover_scenarios(
        base_dir=".",
        category=args.category,
        scenario_filter=args.scenario,
    )

    if not scenario_files:
        logger.error(f"No scenarios found (scenario={args.scenario}, category={args.category})")
        sys.exit(1)

    logger.info(f"Found {len(scenario_files)} scenario(s) to run")

    all_summaries = []

    for scenario_path in scenario_files:
        # 推断分类
        category = infer_category(scenario_path)

        logger.info(f"\n{'=' * 50}")
        logger.info(f"  Loading: {scenario_path}  [category={category}]")
        logger.info(f"{'=' * 50}")

        scenario = load_scenario(scenario_path)
        scenario_id = scenario["id"]

        # 为本次运行创建输出路径管理器
        run_mgr = RunOutputManager(base_output, category, scenario_id)

        # 初始化/重置核心组件
        clock = VirtualClock()
        normalizer = EventNormalizer(clock)
        rule_engine = RuleEngine()
        rule_engine.load_rules("rules/default_policy.yaml")
        scorer = RiskScorer()
        scorer.register_default_dimensions()
        baseline_checker = BaselineChecker()
        decision_engine = DecisionEngine()
        chain_builder = ChainReportBuilder(output_dir=run_mgr.run_dir)
        sender = MockCommandSender()
        blocking_coord = BlockingCoordinator(clock, sender, output_dir=run_mgr.run_dir)
        behavior_graph = BehaviorGraph()
        audit_logger = AuditLogger(output_dir=run_mgr.run_dir)
        report_exporter = ReportExporter(output_dir=run_mgr.run_dir)

        # 设置组件输出目录为运行时间戳目录
        audit_logger.set_output_dir(run_mgr.audit_dir)
        report_exporter.set_output_dir(run_mgr.report_dir)
        blocking_coord.set_output_dir(run_mgr.evidence_dir)

        # 开始审计日志
        audit_logger.start_scenario(scenario_id)

        # 运行流水线
        stats = run_scenario_pipeline(
            scenario=scenario, clock=clock,
            normalizer=normalizer, rule_engine=rule_engine,
            scorer=scorer, baseline_checker=baseline_checker,
            decision_engine=decision_engine, chain_builder=chain_builder,
            blocking_coord=blocking_coord, behavior_graph=behavior_graph,
            audit_logger=audit_logger, output_dir=run_mgr.run_dir,
        )

        audit_logger.close()

        # 导出报告 → run_dir
        report_path = report_exporter.export_scenario_report(
            scenario_id=scenario_id,
            scenario_name=scenario["name"],
            audit_logger=audit_logger,
            behavior_graph=behavior_graph,
            scenario_description=scenario.get("description", ""),
            expected_result=scenario.get("expected_result", ""),
        )

        # 保存行为图谱 → run_dir/graphs/
        graph_path = run_mgr.graph_filepath(f"graph_{scenario_id}.json")
        behavior_graph.save_json(graph_path)

        # 保存基线快照（N01场景结束后）
        if scenario_id.startswith("n01"):
            baseline_path = os.path.join(
                run_mgr.baseline_run_dir(), f"baseline_{scenario_id}.json"
            )
            baseline_checker.save_baseline(baseline_path)

        logger.info(f"\n  Scenario {scenario_id} complete:")
        logger.info(f"    Events: {stats['total']} | Allow: {stats['allow']} | "
                     f"Alert: {stats['alert']} | Block: {stats['block']}")
        logger.info(f"    Output: {run_mgr.run_dir}")

        all_summaries.append({
            "name": scenario["name"],
            "id": scenario_id,
            "category": category,
            "total": stats["total"],
            "allowed": stats["allow"],
            "alerted": stats["alert"],
            "blocked": stats["block"],
            "report_file": report_path,
            "output_dir": run_mgr.run_dir,
        })

    # 导出汇总报告
    if len(all_summaries) > 1:
        # 汇总报告放在 output/reports/ 根目录
        summary_exporter = ReportExporter(output_dir=base_output)
        summary_path = summary_exporter.export_all_summary(all_summaries)
        logger.info(f"\n  Summary report: {summary_path}")

    logger.info(f"\n{'=' * 60}")
    logger.info(f"  All {len(all_summaries)} scenario(s) complete.")
    logger.info(f"{'=' * 60}")


if __name__ == "__main__":
    main()
