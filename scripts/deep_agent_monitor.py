#!/usr/bin/env python3
"""
deep_agent_monitor.py — Pydantic-DeepAgents 实时监控集成脚本

功能：
  1. 启动 DeepAgentCollector (simulation/live 模式)
  2. 通过 observer_core 全链路处理事件
  3. 实时输出风险评估 (ALLOW/ALERT/BLOCK)
  4. 可选：通过 EventRecorder 录制事件流
  5. 输出风险分析报告和审计日志

用法:
  # Simulation 模式（无需 API Key）
  python3 deep_agent_monitor.py --scenario da01_data_analysis

  # Simulation 模式 + 录制
  python3 deep_agent_monitor.py --scenario da03_suspicious_behavior --record

  # Live 模式（需 OPENAI_API_KEY，配置在 .env 文件中）
  python3 deep_agent_monitor.py --live --task "分析 data/sales.csv"

  # 列出所有 Agent 场景
  python3 deep_agent_monitor.py --list

依赖:
  - pydantic-deep (pip install pydantic-deep)
  - observer_sim 项目
  - config.yaml

零改动约束: 不修改 observer_core/ / models/ / scenarios/ / rules/
"""

import os
import sys
import argparse
import logging
from datetime import datetime

# 路径设置
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
OBSERVER_DIR = os.path.join(PROJECT_ROOT, "observer_sim")
sys.path.insert(0, OBSERVER_DIR)

import yaml

# 加载敏感配置（.env 文件 → 环境变量）
from env_config import load_env_config, get_llm_config, has_api_key, get_env_status
load_env_config()

# ── 终端颜色 ──────────────────────────────────────────────────────────────────
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_header(title: str):
    print(f"\n{BOLD}{CYAN}{'=' * 65}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 65}{RESET}\n")


def print_event(idx: int, evt, decision, blocking_result=None):
    """格式化输出事件和决策"""
    blocked = blocking_result and getattr(blocking_result, 'blocked', False)
    action_str = "BLOCK" if blocked else decision.action.value

    if action_str == "ALLOW":
        color = GREEN
    elif action_str == "ALERT":
        color = YELLOW
    else:
        color = RED

    et = evt.event_type
    detail = ""
    if et == "exec":
        exe = getattr(evt, 'executable', None) or "?"
        args = getattr(evt, 'arguments', None) or []
        detail = f"{exe} {' '.join(args)}".strip()[:60]
    elif et == "file_open":
        fp = getattr(evt, 'file_path', None) or "?"
        op = getattr(evt, 'file_op', None) or "?"
        detail = f"{op} {fp}"
    elif et == "net_conn":
        addr = getattr(evt, 'remote_addr', None) or "?"
        port = getattr(evt, 'remote_port', None) or "?"
        detail = f"{addr}:{port}"

    print(f"  {color}[{action_str:5s}]{RESET} ({idx:03d}) {et:10s} | {detail}")


def list_scenarios():
    """列出所有 Agent 场景"""
    scenario_dir = os.path.join(OBSERVER_DIR, "scenarios", "deep_agent")
    if not os.path.isdir(scenario_dir):
        print("  !! scenarios/deep_agent/ 目录不存在")
        return

    print(f"\n  {'ID':6s}  {'Name':30s}  {'Category':12s}  File")
    print(f"  {'------':6s}  {'-' * 30:30s}  {'-' * 12:12s}  {'-' * 30}")

    for f in sorted(os.listdir(scenario_dir)):
        if not f.endswith(".yaml"):
            continue
        path = os.path.join(scenario_dir, f)
        with open(path, 'r', encoding='utf-8') as fh:
            data = yaml.safe_load(fh)
        sc = data.get("scenario", {})
        print(f"  {sc.get('id', '?'):6s}  {sc.get('name', '?'):30s}  "
              f"{sc.get('category', '?'):12s}  {f}")


def run_monitor(args):
    """执行监控流程"""
    # 加载配置
    config_path = os.path.join(OBSERVER_DIR, "config.yaml")
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    # 设置 deep_agent 配置段
    config.setdefault("deep_agent", {})
    config["deep_agent"]["mode"] = "live" if args.live else "simulation"
    config["deep_agent"]["target_agent_id"] = args.agent_id or "deep-agent"
    if args.live:
        config["deep_agent"]["task"] = args.task
        config["deep_agent"]["duration_s"] = args.duration

    print_header(f"方寸观察者 — Pydantic-DeepAgents 监控")

    mode = "LIVE" if args.live else "SIMULATION"
    print(f"  Mode:     {BOLD}{mode}{RESET}")
    print(f"  Agent ID: {config['deep_agent']['target_agent_id']}")
    if not args.live:
        print(f"  Scenario: {args.scenario or 'da01_data_analysis'}")
    else:
        print(f"  Task:     {args.task}")
        # 显示 LLM 配置状态
        llm_cfg = get_llm_config()
        if has_api_key():
            masked = llm_cfg['api_key'][:8] + '...' if len(llm_cfg['api_key']) > 8 else '***'
            print(f"  Model:    {llm_cfg['model']}")
            print(f"  API Key:  {masked}")
            if llm_cfg['base_url']:
                print(f"  Base URL: {llm_cfg['base_url']}")
        else:
            print(f"  {RED}!! 未配置 OPENAI_API_KEY，Live 模式将无法启动{RESET}")
            print(f"  {YELLOW}   请在 .env 文件中配置 OPENAI_API_KEY{RESET}")

    # Phase 1: 初始化 Collector
    print(f"\n{CYAN}[1/4] 初始化 DeepAgentCollector...{RESET}")
    from collector.deep_agent_collector import DeepAgentCollector
    collector = DeepAgentCollector(config)
    ok = collector.attach(agent_id=config["deep_agent"]["target_agent_id"])
    if not ok:
        print(f"  {RED}!! attach 失败{RESET}")
        return 1

    if not args.live and args.scenario:
        # 加载场景
        scenario_id = args.scenario
        if not scenario_id.endswith(".yaml"):
            scenario_id = f"{scenario_id}.yaml"
        scenario_path = os.path.join("scenarios", "deep_agent", scenario_id)
        collector.load_scenario(scenario_path)
    print(f"  {GREEN}✓ Collector 就绪 ({mode} 模式){RESET}")

    # Phase 2: 初始化 observer_core
    print(f"\n{CYAN}[2/4] 初始化 observer_core 处理链路...{RESET}")
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

    clock = VirtualClock(
        start_ns=config.get("virtual_clock", {}).get("start_ns", 1718092800_000_000_000))
    normalizer = EventNormalizer(clock)
    rule_engine = RuleEngine()

    rules_path = os.path.join(OBSERVER_DIR, "rules", "default_policy.yaml")
    if os.path.isfile(rules_path):
        rule_engine.load_rules(rules_path)

    scorer = RiskScorer()
    scorer.register_default_dimensions()
    baseline_checker = BaselineChecker()
    decision_engine = DecisionEngine()
    sender = MockCommandSender()

    output_dir = os.path.join(OBSERVER_DIR, "output", "deep_agent_monitor")
    evidence_dir = os.path.join(output_dir, "evidence")
    audit_dir = os.path.join(output_dir, "audit")
    report_dir = os.path.join(output_dir, "reports")
    graph_dir = os.path.join(output_dir, "graphs")
    for d in [evidence_dir, audit_dir, report_dir, graph_dir]:
        os.makedirs(d, exist_ok=True)

    blocking_coord = BlockingCoordinator(clock, sender, output_dir=evidence_dir)
    behavior_graph = BehaviorGraph()
    audit_logger = AuditLogger(output_dir=audit_dir)
    audit_logger.set_output_dir(audit_dir)
    audit_logger.start_scenario("deep_agent_monitor")
    report_exporter = ReportExporter(output_dir=report_dir)
    report_exporter.set_output_dir(report_dir)

    print(f"  {GREEN}✓ observer_core/ 就绪 (零改动){RESET}")

    # Phase 3: 可选录制
    recorder = None
    session_recorder = None  # SessionRecorder (兼容 test.py [B] 回放)
    if args.record or args.record_to_records is not None:
        print(f"\n{CYAN}[3/4] 启动事件录制...{RESET}")

        if args.record_to_records is not None:
            # 使用 SessionRecorder → records/ 目录 (兼容 test.py [B])
            from recorder.session_recorder import SessionRecorder
            records_dir = args.record_to_records or os.path.join(
                PROJECT_ROOT, "records")
            session_recorder = SessionRecorder(
                records_dir=records_dir,
                agent_id=config["deep_agent"]["target_agent_id"],
                collect_mode="simulation" if not args.live else "live",
            )
            session_recorder.start()
            recorder = session_recorder
            print(f"  {GREEN}✓ 录制到 records/ (兼容 test.py [B] 回放){RESET}")
            print(f"    Session: {session_recorder.session_id}")
        else:
            # 原始模式: EventRecorder → output/recorded/
            from collector.event_recorder import EventRecorder
            record_path = os.path.join(
                output_dir, "recorded",
                f"deep_agent_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
            os.makedirs(os.path.dirname(record_path), exist_ok=True)
            recorder = EventRecorder(record_path,
                                     agent_id=config["deep_agent"]["target_agent_id"])
            recorder.start()
            print(f"  {GREEN}✓ 录制到 {record_path}{RESET}")
    else:
        print(f"\n{CYAN}[3/4] 事件录制: 未启用 (使用 --record / --record-to-records 开启){RESET}")

    # Phase 4: 监控循环
    print(f"\n{CYAN}[4/4] 开始监控...{RESET}")
    print(f"\n  {'决策':6s}  {'序号':>4s}  {'事件类型':10s}  {'详情'}")
    print(f"  {'-' * 65}")

    stats = {"total": 0, "allow": 0, "alert": 0, "block": 0}

    try:
        for raw in collector.start():
            stats["total"] += 1
            clock.advance(100)

            # 录制
            if recorder:
                if session_recorder:
                    recorder.write_event(raw)
                else:
                    recorder.write(raw)

            # 1. 归一化
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
                matched_rules=matched_rule_ids)

            # 8. 审计日志
            desc = _build_desc(norm)
            audit_logger.log_event(
                norm, assessment=assessment, decision=decision,
                blocking_result=blocking_result,
                matched_rules=matched_rule_ids,
                description=desc)

            # 统计
            blocked = blocking_result.blocked
            if blocked:
                stats["block"] += 1
            elif decision.action == DecisionAction.ALERT:
                stats["alert"] += 1
            else:
                stats["allow"] += 1

            print_event(stats["total"], raw, decision, blocking_result)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}  用户中断{RESET}")
    finally:
        # 清理
        collector.detach()
        if recorder:
            if session_recorder:
                rec_summary = recorder.stop()
                print(f"\n  {GREEN}录制已保存:{RESET}")
                print(f"    Session: {rec_summary.get('session_id', '')}")
                print(f"    Events:  {rec_summary.get('event_count', 0)}")
                print(f"    File:    {rec_summary.get('events_file', '')}")
                print(f"    回放:    python3 test.py → [B] 回放录制")
            else:
                recorder.stop()
        audit_logger.close()

    # Phase 5: 导出报告
    print(f"\n{CYAN}生成报告...{RESET}")
    try:
        report_path = report_exporter.export_scenario_report(
            scenario_id="deep_agent_monitor",
            scenario_name="Pydantic-DeepAgents Monitor Report",
            audit_logger=audit_logger,
            behavior_graph=behavior_graph,
            scenario_description=f"DeepAgent monitoring ({mode} mode)",
            expected_result="Analyze agent behavior",
        )
    except Exception as e:
        logging.warning(f"报告导出失败: {e}")
        report_path = ""

    # 保存行为图谱
    graph_path = os.path.join(graph_dir, "graph_deep_agent.json")
    try:
        behavior_graph.save_json(graph_path)
    except Exception as e:
        logging.warning(f"行为图谱保存失败: {e}")

    # 输出摘要
    print(f"\n{BOLD}{'=' * 65}{RESET}")
    print(f"{BOLD}  监控摘要{RESET}")
    print(f"{BOLD}{'=' * 65}{RESET}")
    print(f"  Total:   {stats['total']}")
    print(f"  {GREEN}Allow:   {stats['allow']}{RESET}")
    print(f"  {YELLOW}Alert:   {stats['alert']}{RESET}")
    print(f"  {RED}Block:   {stats['block']}{RESET}")
    print(f"\n  Report:  {report_path}")
    print(f"  Graph:   {graph_path}")
    print(f"  Audit:   {audit_dir}")
    print(f"  Output:  {output_dir}")

    if args.record and recorder:
        print(f"\n  录制文件可通过以下方式回放:")
        print(f"  {CYAN}python3 record_and_replay.py --replay-only "
              f"{record_path}{RESET}")

    return 0 if stats["block"] == 0 else 1


def _build_desc(event) -> str:
    """构建事件简短描述"""
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


def main():
    parser = argparse.ArgumentParser(
        description="方寸观察者 — Pydantic-DeepAgents 实时监控",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # Simulation 模式（默认，无需 API Key）
  python3 deep_agent_monitor.py --scenario da01_data_analysis

  # 可疑行为场景
  python3 deep_agent_monitor.py --scenario da03_suspicious_behavior

  # 录制事件流
  python3 deep_agent_monitor.py --scenario da01 --record

  # Live 模式（需 API Key）
  python3 deep_agent_monitor.py --live --task "分析销售数据"

  # 列出场景
  python3 deep_agent_monitor.py --list
        """)
    parser.add_argument("--scenario", type=str, default="da01_data_analysis",
                        help="Agent 场景 ID (默认: da01_data_analysis)")
    parser.add_argument("--live", action="store_true",
                        help="使用 live 模式 (需 OPENAI_API_KEY，配置在 .env)")
    parser.add_argument("--task", type=str, default="列出当前目录文件并分析",
                        help="Live 模式下发给 Agent 的指令")
    parser.add_argument("--agent-id", type=str, default="deep-agent",
                        help="Agent 标识 (默认: deep-agent)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Live 模式最大监控时长 (秒, 默认: 60)")
    parser.add_argument("--record", action="store_true",
                        help="录制事件流到 JSONL 文件 (output/recorded/)")
    parser.add_argument("--record-to-records", nargs="?", const="", default=None,
                        metavar="DIR",
                        help="录制到 records/ 目录 (兼容 test.py [B] 回放，"
                             "可选指定目录，默认: ./records)")
    parser.add_argument("--list", action="store_true",
                        help="列出所有 Agent 场景")
    parser.add_argument("--config", type=str, default="",
                        help="配置文件路径 (默认: observer_sim/config.yaml)")

    args = parser.parse_args()

    if args.list:
        list_scenarios()
        return 0

    return run_monitor(args)


if __name__ == "__main__":
    sys.exit(main())
