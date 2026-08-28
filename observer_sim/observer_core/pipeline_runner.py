"""
pipeline_runner.py — 全链路事件处理流水线单一事实来源

背景:
    原 Web (app.py)、CLI (main.py)、守护进程 (monitor_daemon.py) 三入口各自
    内联了一份"归一化 → 基线收集 → 规则匹配 → 风险评分 → 研判决策 →
    阻断执行 → 行为图谱 → 审计日志"编排逻辑，造成三份实现漂移。

本模块:
    PipelineRunner 将上述编排收敛为唯一实现，三入口仅保留各自的表现层
    （CLI 日志、SSE step_data、守护进程实时彩色输出）与统计聚合。

合并基准（以最强功能为准）:
    - 基线收集条件: normal 前缀判断（app.py / monitor_daemon.py 基准）
    - 事件描述: build_event_description（app.py / monitor_daemon.py 基准，
      信息最全、不截断；main.py 原 _build_description 作废）
    - 审计日志: 携带 processing_time_ms（monitor_daemon.py 基准）
"""

import time
import logging
from dataclasses import dataclass, field
from typing import List

from models.event import RawEvent, NormalizedEvent
from models.risk import RiskAssessment, Decision, BlockingResult

logger = logging.getLogger(__name__)


def build_event_description(norm: NormalizedEvent) -> str:
    """构建事件描述。

    以 app.py / monitor_daemon.py 原 _build_desc 为准（信息最全，不截断），
    main.py 原 _build_description（带 "exec:" 前缀 + 60 字符截断）作废。
    """
    et = norm.event_type
    if et == "exec":
        return norm.command_string or (
            f"{norm.raw.executable} {' '.join(norm.raw.arguments or [])}")
    elif et == "file_open":
        return f"{norm.raw.file_op} {norm.raw.file_path}"
    elif et == "net_conn":
        return f"{norm.raw.remote_addr}:{norm.raw.remote_port}"
    return et


@dataclass
class PipelineResult:
    """单事件全链路处理结果（供各入口表现层使用）"""
    norm: NormalizedEvent
    match: object = None
    matched_rule_ids: List[str] = field(default_factory=list)
    assessment: RiskAssessment = None
    decision: Decision = None
    blocking_result: BlockingResult = None
    description: str = ""
    processing_ms: float = 0.0


class PipelineRunner:
    """
    全链路事件处理流水线（三入口共用的唯一编排实现）。

    组件全部由调用方注入（依赖注入），PipelineRunner 不负责创建组件，
    从而保持"输出层整理"边界：不新增业务功能，只收敛编排。

    处理顺序（与 app.py / monitor_daemon.py 原实现一致）:
        1. 归一化
        2. 基线收集（仅 normal 前缀 agent，防攻击场景污染基线）
        3. 规则匹配
        4. 风险评分
        5. 研判决策
        6. 阻断执行
        7. 行为图谱
        8. 审计日志（含 processing_time_ms）
    """

    def __init__(self,
                 normalizer,
                 rule_engine,
                 baseline_checker,
                 scorer,
                 decision_engine,
                 blocking_coord,
                 behavior_graph,
                 audit_logger,
                 desc_builder=build_event_description):
        self._normalizer = normalizer
        self._rule_engine = rule_engine
        self._baseline = baseline_checker
        self._scorer = scorer
        self._decision_engine = decision_engine
        self._blocking_coord = blocking_coord
        self._behavior_graph = behavior_graph
        self._audit_logger = audit_logger
        self._desc_builder = desc_builder

    def process_event(self, raw: RawEvent) -> PipelineResult:
        """处理单个 RawEvent，运行全链路流水线。"""
        t0 = time.time()

        # 1. 归一化
        norm = self._normalizer.normalize(raw)

        # 2. 基线收集（仅 normal 前缀 agent 参与基线构建）
        if "normal" in raw.agent_id:
            self._baseline.collect(norm)

        # 3. 规则匹配
        match = self._rule_engine.match(norm)
        matched_rule_ids = [r.rule_id for r in match.matched_rules]

        # 4. 风险评分
        context = self._normalizer.get_agent_context(raw.agent_id)
        self._scorer.set_baseline(self._baseline.get_baseline_dict())
        assessment = self._scorer.assess(norm, match, context)

        # 5. 研判决策
        decision = self._decision_engine.decide(
            assessment, event_id=raw.event_id, agent_id=raw.agent_id)

        # 6. 阻断执行
        blocking_result = self._blocking_coord.execute(norm, decision)

        # 7. 行为图谱
        self._behavior_graph.add_event(
            norm, assessment=assessment, decision=decision,
            blocking_result=blocking_result, matched_rules=matched_rule_ids)

        # 8. 审计日志（含处理耗时）
        description = self._desc_builder(norm)
        processing_ms = (time.time() - t0) * 1000
        self._audit_logger.log_event(
            norm, assessment=assessment, decision=decision,
            blocking_result=blocking_result, matched_rules=matched_rule_ids,
            description=description, processing_time_ms=processing_ms)

        return PipelineResult(
            norm=norm,
            match=match,
            matched_rule_ids=matched_rule_ids,
            assessment=assessment,
            decision=decision,
            blocking_result=blocking_result,
            description=description,
            processing_ms=processing_ms,
        )
