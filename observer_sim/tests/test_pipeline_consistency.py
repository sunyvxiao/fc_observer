"""
test_pipeline_consistency.py — Web / CLI 同场景逐事件判定一致性回归测试

验收标准（阶段 0 硬标准）:
    Web（app.StreamScenarioRunner）与 CLI（main.run_scenario_pipeline）
    对同一场景的判定结果（decision_action / decision_tier / risk_level）
    必须逐事件一致。

背景:
    两入口的编排逻辑已收敛到 observer_core/pipeline_runner.py 的
    PipelineRunner（单一事实来源）。本测试从两个入口各自完整走一遍
    同一场景，对比逐事件判定序列，防止入口层漂移回归。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import yaml

from models.virtual_clock import VirtualClock
from observer_core.monitoring.event_normalizer import EventNormalizer
from observer_core.monitoring.rule_engine import RuleEngine
from observer_core.judgment.risk_scorer import RiskScorer
from observer_core.judgment.baseline_checker import BaselineChecker
from observer_core.judgment.decision_engine import DecisionEngine
from observer_core.blocking.blocking_coordinator import BlockingCoordinator
from observer_core.blocking.command_sender import MockCommandSender
from observer_core.audit.behavior_graph import BehaviorGraph
from observer_core.audit.audit_logger import AuditLogger

BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
SCENARIOS_DIR = os.path.join(BASE_DIR, 'scenarios')

# 覆盖四类场景：正常 / 异常 / 多Agent / 边界
CONSISTENCY_SCENARIOS = [
    ("normal", "n01_standard_development.yaml"),
    ("anomalous", "a02_curl_pipe_bash.yaml"),
    ("multi_agent", "m04_privilege_escalation_chain.yaml"),
    ("boundary", "b03_off_hours_operation.yaml"),
]


class RecordingAuditLogger(AuditLogger):
    """记录每条审计条目的判定结果（不写文件，文件句柄未打开时 log_event 仅返回条目）"""

    def __init__(self, output_dir):
        super().__init__(output_dir=output_dir)
        self.records = []

    def log_event(self, *args, **kwargs):
        entry = super().log_event(*args, **kwargs)
        self.records.append((
            entry.decision_action,
            entry.decision_tier,
            entry.risk_level,
        ))
        return entry


def _load_scenario(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)['scenario']


def _run_cli_side(scenario_path, out_dir):
    """镜像 main.main() 的核心初始化，走 run_scenario_pipeline（collector 路径）"""
    from main import run_scenario_pipeline
    from collector.simulation_collector import SimulationCollector

    scenario = _load_scenario(scenario_path)
    sid = scenario['id']

    collector = SimulationCollector({
        "virtual_clock": {"start_ns": 1718092800000000000}
    })
    collector.attach(agent_id=sid)
    collector.load_scenario(scenario_path)

    clock = collector.clock
    normalizer = EventNormalizer(clock)  # 默认 window_size=10，与 Web 侧一致
    rule_engine = RuleEngine()
    rule_engine.load_rules(os.path.join(BASE_DIR, 'rules', 'default_policy.yaml'))
    scorer = RiskScorer()
    scorer.register_default_dimensions()
    baseline_checker = BaselineChecker()
    decision_engine = DecisionEngine()
    sender = MockCommandSender()
    blocking_coord = BlockingCoordinator(clock, sender, output_dir=out_dir)
    behavior_graph = BehaviorGraph()
    audit_logger = RecordingAuditLogger(out_dir)

    stats = run_scenario_pipeline(
        scenario=scenario, clock=clock,
        normalizer=normalizer, rule_engine=rule_engine,
        scorer=scorer, baseline_checker=baseline_checker,
        decision_engine=decision_engine, chain_builder=None,
        blocking_coord=blocking_coord, behavior_graph=behavior_graph,
        audit_logger=audit_logger, output_dir=out_dir,
        collector=collector,
    )
    # Windows 下关闭审计文件句柄，避免 pytest 清理 tmp 目录时 PermissionError
    audit_logger.close()
    return stats, audit_logger.records


def _run_web_side(scenario_path, out_dir):
    """StreamScenarioRunner.run_stream 逐事件 step_data（Web 入口完整路径）"""
    from app import StreamScenarioRunner

    sid = _load_scenario(scenario_path)['id']
    runner = StreamScenarioRunner(BASE_DIR, out_dir, "unknown", sid)
    records = []
    for step in runner.run_stream(scenario_path):
        if step.get('type') == 'step':
            records.append((
                step.get('decision_action'),
                step.get('decision_tier'),
                step.get('risk_level'),
            ))
    return records


def test_web_cli_decision_consistency(tmp_path):
    """Web 与 CLI 对同一场景的判定结果逐事件一致"""
    for category, name in CONSISTENCY_SCENARIOS:
        scenario_path = os.path.join(SCENARIOS_DIR, category, name)
        if not os.path.exists(scenario_path):
            continue

        cli_dir = os.path.join(str(tmp_path), 'cli', name)
        web_dir = os.path.join(str(tmp_path), 'web', name)
        os.makedirs(cli_dir, exist_ok=True)
        os.makedirs(web_dir, exist_ok=True)

        stats, cli_records = _run_cli_side(scenario_path, cli_dir)
        web_records = _run_web_side(scenario_path, web_dir)

        assert len(cli_records) == len(web_records), (
            f"{name}: CLI {len(cli_records)} 事件 vs Web {len(web_records)} 事件"
        )
        assert stats['total'] == len(web_records), (
            f"{name}: stats.total={stats['total']} vs Web 事件数 {len(web_records)}"
        )

        for idx, (cli_rec, web_rec) in enumerate(zip(cli_records, web_records), 1):
            assert cli_rec == web_rec, (
                f"{name} 第 {idx} 事件判定不一致: "
                f"CLI {cli_rec} vs Web {web_rec}"
            )
