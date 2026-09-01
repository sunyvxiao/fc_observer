#!/usr/bin/env python3
"""
monitor_daemon.py — observer daemon 的实现模块（U4）

统一入口为 observer.py（python observer.py daemon ...），本文件是 daemon 子命令的
实现模块，同时保留独立运行能力（__main__ 打印一行提示后继续运行，
与 observer daemon 转发语义一致）。

从命名管道 (FIFO) 读取 Agent 产生的 RawEvent，实时运行全链路监测 Pipeline:
  归一化 → 规则匹配 → 风险评分 → 研判决策 → 阻断执行 → 审计日志

接收 SIGTERM/SIGINT 后:
  1. 停止读取事件
  2. 关闭审计日志
  3. 生成风险分析报告 (Markdown + JSON)
  4. 优雅退出

特性:
- 完全独立运行，与 Agent 进程无代码依赖
- 支持在没有 Agent 时保持等待状态（FIFO 阻塞读取）
- 接收停止信号后自动生成完整报告

用法:
    python observer.py daemon --fifo /tmp/observer_monitoring_pipe
    python observer.py daemon --fifo /tmp/observer_monitoring_pipe --output output/demo_monitoring
    python observer.py daemon --mode mcp_report --output output/mcp_monitoring
        # mcp_report 模式（P4）: 启动 MCP 申报 Server（HTTP+SSE），
        # WorkBuddy 以 MCP client 接入申报，无需 FIFO。
"""

import sys
import os
import json
import time
import signal
import argparse
import hashlib
import logging
import threading
from datetime import datetime
from typing import List, Optional

import yaml

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
from observer_core.blocking.blocking_coordinator import BlockingCoordinator
from observer_core.blocking.command_sender import MockCommandSender
from observer_core.audit.behavior_graph import BehaviorGraph
from observer_core.audit.audit_logger import AuditLogger
from observer_core.audit.report_exporter import ReportExporter
from observer_core.audit.output_sink import DefaultOutputSink
from observer_core.pipeline_runner import PipelineRunner

# EbpfCommandSender 可选导入（仅在 --ebpf 时使用）
_EbpfCommandSender = None
try:
    from observer_core.blocking.ebpf_command_sender import EbpfCommandSender
    _EbpfCommandSender = EbpfCommandSender
except ImportError:
    pass

# ── 日志配置 ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format='[%(asctime)s] %(levelname)s %(name)s: %(message)s',
    stream=sys.stderr,
)

logger = logging.getLogger("monitor_daemon")

# ── 全局状态 ───────────────────────────────────────────────────
_running = True
_monitor_instance: Optional["MonitorDaemon"] = None
_mcp_collector = None  # mcp_report 模式下的采集器（信号处理 detach 用）


def _handle_signal(signum, frame):
    """信号处理：优雅停止"""
    global _running, _monitor_instance, _mcp_collector
    if hasattr(signal, "SIGUSR1") and signum == signal.SIGUSR1:
        # SIGUSR1: 显式请求生成报告（场景 c，仅 Linux/类 Unix 平台）
        if _monitor_instance:
            print("\n[monitor] 收到显式报告生成请求", file=sys.stderr)
            summary = _monitor_instance.generate_report_dedup()
            if summary:
                print(f"[monitor] 📄 报告已生成: {summary['report_path']}", file=sys.stderr)
            else:
                print(f"[monitor] ⏭️  报告无变化，跳过", file=sys.stderr)
        return
    _running = False
    if _mcp_collector is not None:
        # mcp_report 模式：终止 collector 轮询循环
        _mcp_collector.detach()
    if _monitor_instance:
        print("\n[monitor] 收到停止信号，正在生成报告...", file=sys.stderr)
        _monitor_instance._should_stop = True


class MonitorDaemon:
    """监测守护进程 — 实时事件处理 + 报告生成"""

    def __init__(self, output_dir: str = "output/demo_monitoring",
                 use_ebpf: bool = False,
                 enable_rollup: Optional[bool] = None):
        """
        Args:
            output_dir: 输出根目录
            use_ebpf: 是否启用 eBPF 阻断（降级时自动切换 Mock）
            enable_rollup: 分层滚动显式开关（阶段 3，测试隔离 / test_report 模式）：
                None=读 tuning.yaml rollup.enabled（默认开启，行为不变）；
                True/False=显式覆盖配置（优先级：显式参数 > tuning.yaml）。
                False 时（test_report 模式）：仅 L0 持续记录 + 结束一次性报告，
                不启动 L1 60s 线程、不触发 L1→L2→L3 rollup、不产生 cache/ 产物。
        """
        self._base_dir = os.path.dirname(os.path.abspath(__file__))
        self._output_dir = output_dir
        self._should_stop = False
        self._use_ebpf = use_ebpf
        # 分层滚动显式开关（None=跟随 tuning.yaml）
        self._enable_rollup = enable_rollup
        self._ebpf_degraded = False
        self._ebpf_degradation_report: Optional[dict] = None
        self._last_degradation_warning: float = 0.0

        # 初始化 Pipeline 组件
        rules_path = os.path.join(self._base_dir, "rules", "default_policy.yaml")
        self._rule_engine = RuleEngine()
        self._rule_engine.load_rules(rules_path)

        self._clock = VirtualClock(start_ns=1718092800000000000)
        self._normalizer = EventNormalizer(clock=self._clock, window_size=10)
        # 不传 min_warm_events，统一从 tuning.yaml 读取（baseline.min_warm_events=10）
        self._baseline = BaselineChecker()
        self._scorer = RiskScorer()
        self._scorer.register_default_dimensions()
        self._decision_engine = DecisionEngine()

        # ── 阻断指令发送器（Mock / eBPF）──
        self._cmd_sender = self._init_command_sender()
        self._blocking_coord = BlockingCoordinator(
            clock=self._clock, sender=self._cmd_sender, output_dir=output_dir)

        self._behavior_graph = BehaviorGraph()
        # L-T3: 从 config.yaml 读取 L0 审计文件保留天数（惰性清理）
        _retention_days = None
        try:
            with open(os.path.join(self._base_dir, "config.yaml"), "r",
                      encoding="utf-8") as _f:
                _cfg = yaml.safe_load(_f) or {}
            _retention_days = _cfg.get("output", {}).get("retention_days")
        except (IOError, OSError, yaml.YAMLError):
            pass
        self._audit_logger = AuditLogger(output_dir=output_dir,
                                         retention_days=_retention_days)
        self._report_exporter = ReportExporter(output_dir=output_dir)
        # U3: 输出编排收敛至 OutputSink（monitor 用固定输出目录，不建 run 目录，
        # 图谱写入 {output}/graphs/、报告写入 {output}/reports/，与下沉前一致）
        self._sink = DefaultOutputSink(
            base_output_dir=output_dir,
            audit_logger=self._audit_logger,
            report_exporter=self._report_exporter,
            behavior_graph=self._behavior_graph,
            use_run_dirs=False,
        )

        # 全链路流水线（单一事实来源，见 observer_core/pipeline_runner.py）
        self._pipeline = self._build_pipeline()

        # 统计
        self._stats = self._make_empty_stats()

        # ── 报告去重 ──
        self._report_fingerprints: set = set()
        self._last_report_time_ns: int = 0

        # 设置输出子目录
        os.makedirs(output_dir, exist_ok=True)
        audit_dir = os.path.join(output_dir, "audit")
        reports_dir = os.path.join(output_dir, "reports")
        os.makedirs(audit_dir, exist_ok=True)
        os.makedirs(reports_dir, exist_ok=True)
        self._audit_logger.set_output_dir(audit_dir)
        self._report_exporter.set_output_dir(reports_dir)

        # 阶段 3 L-T12：分层日志滚动挂接（开关可回退，失败不影响主链路）
        self._init_rollup()

    def _build_pipeline(self) -> PipelineRunner:
        """用当前组件构建流水线（供 __init__ 与 _reset_for_new_session 复用）"""
        return PipelineRunner(
            normalizer=self._normalizer,
            rule_engine=self._rule_engine,
            baseline_checker=self._baseline,
            scorer=self._scorer,
            decision_engine=self._decision_engine,
            blocking_coord=self._blocking_coord,
            behavior_graph=self._behavior_graph,
            audit_logger=self._audit_logger,
        )

    @staticmethod
    def _make_empty_stats() -> dict:
        return {
            "total": 0, "allow": 0, "alert": 0, "block": 0,
            "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "max_score": 0.0, "matched_rules": [],
        }

    # ── 分层日志滚动（阶段 3：L1 60s 自动片段 / GC→L2 / 虚拟日切→L3）──

    def _init_rollup(self):
        """
        挂接分层日志滚动（tuning.yaml rollup.enabled 开关，默认开启可回退）。

        三红线约束：rollup 链只消费旁路缓存，永不触碰 audit_*.jsonl（L0）；
        任何异常只降级回退，不影响监测主链路。
        """
        self._report_cache = None
        self._rollup_engine = None
        self._rollup_enabled = False
        self._last_day_bucket: Optional[int] = None
        self._rolled_days: set = set()
        self._day_bucket_id = None
        self._day_ns = 24 * 3_600_000_000_000

        try:
            from observer_core.judgment.tuning_loader import TuningLoader
            tuning = TuningLoader().load()
        except Exception:  # noqa: BLE001
            tuning = {}
        rollup_cfg = tuning.get("rollup") or {}
        # 显式开关优先于 tuning.yaml（测试隔离 / --no-rollup CLI）
        enabled = (self._enable_rollup
                   if self._enable_rollup is not None
                   else rollup_cfg.get("enabled", True))
        if not enabled:
            source = ("enable_rollup=False 显式关闭（test_report 模式）"
                      if self._enable_rollup is False
                      else "tuning.yaml rollup.enabled=false")
            print(f"[monitor] rollup 分层滚动已关闭（{source}，可回退）",
                  file=sys.stderr)
            return
        try:
            from observer_core.audit.report_cache import ReportCacheManager
            from observer_core.audit.rollup_engine import (RollupEngine,
                                                           day_bucket_id)
            self._day_bucket_id = day_bucket_id
            self._report_cache = ReportCacheManager(
                output_dir=self._output_dir,
                anomaly_score_threshold=rollup_cfg.get(
                    "anomaly_score_threshold"))
            self._report_cache.set_audit_logger(self._audit_logger)
            self._rollup_engine = RollupEngine(
                output_dir=self._output_dir,
                escalation_params=rollup_cfg.get("escalation") or {},
                cusum_params=rollup_cfg.get("cusum") or {})
            self._report_cache.set_rollup_engine(self._rollup_engine)
            # L1 自动片段（60s 周期，沿用 D2 自动模式）
            self._report_cache.start_auto(60.0)
            self._rollup_enabled = True
            print("[monitor] 分层日志滚动已启用 "
                  "(L1 60s 自动片段 / GC→L2 / 虚拟日切→L3)", file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print(f"[monitor] WARNING: rollup 挂接失败，已回退"
                  f"（不影响监测主链路）: {e}", file=sys.stderr)
            self._report_cache = None
            self._rollup_engine = None
            self._rollup_enabled = False

    def _audit_dir_path(self) -> str:
        """L0 审计文件目录（下钻索引用，只读不删）。"""
        return os.path.join(self._output_dir, "audit")

    def _maybe_rollup_day(self, raw: RawEvent):
        """虚拟时钟日切检测：跨天时把前一天 L2 汇总为 L3（L-T7）。"""
        if not self._rollup_enabled:
            return
        ts = int(getattr(raw, "timestamp_ns", 0) or 0)
        day = self._day_bucket_id(ts)
        if self._last_day_bucket is None:
            self._last_day_bucket = day
            return
        if day == self._last_day_bucket:
            return
        prev_day = self._last_day_bucket
        self._last_day_bucket = day
        self._rollup_day_bucket(prev_day)

    def _rollup_day_bucket(self, day_bucket: int):
        """把指定天的 L2 汇总为 L3 天级审计并导出深度报告（L-T7/L-T12）。"""
        if self._rollup_engine is None or day_bucket in self._rolled_days:
            return None
        self._rolled_days.add(day_bucket)
        try:
            # 日切兜底①：把审计中未入段的条目先生成 L1 片段（不依赖 60s 周期）
            if self._report_cache is not None:
                self._report_cache.force_generate()
            # 日切兜底②：前一天 L1 片段全部驱动进引擎（不依赖 GC 容量上限）
            if self._report_cache is not None:
                self._report_cache.rollup_through((day_bucket + 1) * self._day_ns)
            # 日切兜底③：前一天最后一个小时桶未满时按 partial 生成 L2
            self._rollup_engine.flush_day(day_bucket)
            l2s = [l for l in self._rollup_engine.list_l2()
                   if self._day_bucket_id(l.get("hour_start_ns", 0)) == day_bucket]
            if not l2s:
                self._rolled_days.discard(day_bucket)
                return None
            l3 = self._rollup_engine.rollup_day(l2s)
            l3_path = self._rollup_engine.save_l3(l3)
            report_path = self._report_exporter.export_daily_report(
                l3, audit_dir=self._audit_dir_path())
            print(f"[monitor] 📦 L3 天级审计已生成: {l3_path}", file=sys.stderr)
            print(f"[monitor] 📄 L3 天级报告: {report_path}", file=sys.stderr)
            return l3
        except Exception as e:  # noqa: BLE001
            self._rolled_days.discard(day_bucket)
            print(f"[monitor] WARNING: L3 rollup 失败: {e}", file=sys.stderr)
            return None

    def _shutdown_rollup(self):
        """优雅停止：flush 半满桶 → 汇总剩余 L2 为 L3 → 导出天级报告。"""
        if not self._rollup_enabled:
            return
        try:
            if self._report_cache is not None:
                self._report_cache.stop_auto()
                # 收尾：审计中未入段的条目先生成最后 L1 片段，再全部驱动进引擎
                try:
                    self._report_cache.force_generate()
                    self._report_cache.rollup_through(10 ** 30)
                except Exception as e:  # noqa: BLE001
                    print(f"[monitor] WARNING: 停止前 L1 收尾失败: {e}",
                          file=sys.stderr)
            partial_l2s: List[dict] = []
            if self._rollup_engine is not None:
                partial_l2s = self._rollup_engine.flush_all()
                l2s = self._rollup_engine.list_l2()
                for day in sorted({self._day_bucket_id(l.get("hour_start_ns", 0))
                                   for l in l2s}):
                    self._rollup_day_bucket(day)
            if partial_l2s:
                print(f"[monitor] rollup 优雅停止："
                      f"partial L2 {len(partial_l2s)} 个", file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print(f"[monitor] WARNING: rollup 优雅停止异常: {e}",
                  file=sys.stderr)

    def _reset_for_new_session(self):
        """重置统计和内部状态，准备处理下一个 Agent 会话"""
        self._stats = self._make_empty_stats()
        # 重新开始审计日志（新会话 = 新文件）
        self._audit_logger.close()
        self._audit_logger.start_scenario("demo_monitoring")
        # 重建行为图谱（隔离开不同会话的事件）
        self._behavior_graph = BehaviorGraph()
        # U3: 图谱已重建，同步重建 OutputSink 以引用新图谱（输出编排单一实现）
        self._sink = DefaultOutputSink(
            base_output_dir=self._output_dir,
            audit_logger=self._audit_logger,
            report_exporter=self._report_exporter,
            behavior_graph=self._behavior_graph,
            use_run_dirs=False,
        )
        # 流水线引用新的行为图谱
        self._pipeline = self._build_pipeline()
        # 清除报告去重缓存（新会话允许生成新报告）
        self._report_fingerprints.clear()
        # 重置阻断协调器（清除违规累计、阻断事件历史）
        self._blocking_coord.reset()

    def _init_command_sender(self):
        """初始化阻断指令发送器（Mock 或 eBPF）"""
        if not self._use_ebpf:
            sender = MockCommandSender()
            sender.connect("mock_pipe")
            return sender

        # 尝试 eBPF 模式
        if _EbpfCommandSender is None:
            print("[monitor] WARNING: EbpfCommandSender 模块不可用，降级为 Mock 模式",
                  file=sys.stderr)
            self._ebpf_degraded = True
            self._ebpf_degradation_report = {
                "alert_type": "ebpf_degradation",
                "reason": "EbpfCommandSender 模块导入失败",
                "impact": "系统已降级为非阻断模式",
                "degraded_at": datetime.now().isoformat(),
            }
            self._save_degradation_alert()
            sender = MockCommandSender()
            sender.connect("mock_pipe")
            return sender

        ebpf_sender = _EbpfCommandSender()
        ebpf_sender.connect("block_policy")

        if ebpf_sender.is_degraded:
            reason = ebpf_sender.degradation_reason
            print(f"[monitor] WARNING: eBPF 不可用 ({reason})，降级为 Mock 模式",
                  file=sys.stderr)
            self._ebpf_degraded = True
            self._ebpf_degradation_report = ebpf_sender.degradation_report()
            self._save_degradation_alert()
            # 启动后台恢复检测
            ebpf_sender.start_recovery_thread(interval=30.0)
            # 返回 ebpf_sender（降级但仍可记录指令）
            return ebpf_sender

        print(f"[monitor] eBPF 阻断已激活 (kprobe 动态挂载)", file=sys.stderr)
        return ebpf_sender

    def _save_degradation_alert(self):
        """保存 eBPF 降级告警报告（C1 决策）"""
        if not self._ebpf_degradation_report:
            return
        alerts_dir = os.path.join(self._output_dir, "alerts")
        os.makedirs(alerts_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        alert_path = os.path.join(alerts_dir, f"ebpf_degradation_{ts}.yaml")
        try:
            import yaml
            with open(alert_path, "w", encoding="utf-8") as f:
                yaml.dump(self._ebpf_degradation_report, f,
                          allow_unicode=True, default_flow_style=False)
            print(f"[monitor] ⚠️  eBPF 降级告警报告已保存: {alert_path}",
                  file=sys.stderr)
        except Exception as e:
            print(f"[monitor] ERROR: 无法保存降级告警: {e}", file=sys.stderr)

    def _maybe_warn_degradation(self):
        """降级状态下每 60s 输出一次黄色警告到 stderr"""
        if not self._ebpf_degraded:
            return
        now = time.time()
        if now - self._last_degradation_warning >= 60.0:
            self._last_degradation_warning = now
            reason = (self._ebpf_degradation_report or {}).get("reason", "未知")
            print(
                f"\033[93m[monitor] ⚠️  eBPF 降级中 ({reason}) — "
                f"系统运行在非阻断模式，请检查 eBPF 环境配置\033[0m",
                file=sys.stderr,
            )

    def process_event(self, raw: RawEvent):
        """处理单个 RawEvent：流水线编排已收敛到 PipelineRunner"""
        # 阶段 3：虚拟时钟日切检测（跨天时把前一天 L2 汇总为 L3）
        self._maybe_rollup_day(raw)
        result = self._pipeline.process_event(raw)
        assessment = result.assessment
        decision = result.decision
        blocking_result = result.blocking_result
        matched_rule_ids = result.matched_rule_ids
        desc = result.description
        processing_ms = result.processing_ms

        # 9. 更新统计
        self._stats["total"] += 1
        if assessment.overall_score > self._stats["max_score"]:
            self._stats["max_score"] = assessment.overall_score
        self._stats["risk_distribution"][assessment.risk_level.value] += 1

        # 统计口径（修订 2.1）：按主判定三态统计，与审计 decision_action 一致
        if decision.action == DecisionAction.BLOCK:
            self._stats["block"] += 1
        elif decision.action == DecisionAction.ALERT:
            self._stats["alert"] += 1
        else:
            self._stats["allow"] += 1

        for rule_id in matched_rule_ids:
            if rule_id not in [r[0] for r in self._stats["matched_rules"]]:
                self._stats["matched_rules"].append((rule_id, assessment.overall_score))

        # 10. 实时输出到 stderr
        self._print_event(desc, result.match, assessment, decision, blocking_result,
                          self._stats["total"], processing_ms)

    def _print_event(self, desc, match, assessment, decision, blocking_result, seq, ms):
        """彩色实时输出事件处理结果"""
        # 状态标记（修订 2.1）：主判定三态 + 实际阻断区分
        # - 实际阻断（TIER2/TIER3）：🔴 BLOCK
        # - 主判定 BLOCK 但 TIER1 软阻断（无真实拦截通道）：🔵 BLOCK(软)
        # - ALERT：🟡 ALERT
        # - ALLOW：🟢 ALLOW
        if blocking_result.blocked:
            status = "🔴 BLOCK"
            color = "\033[91m"  # red
        elif decision.action == DecisionAction.BLOCK:
            status = "🔵 BLOCK(软)"
            color = "\033[94m"  # blue
        elif decision.action == DecisionAction.ALERT:
            status = "🟡 ALERT"
            color = "\033[93m"  # yellow
        else:
            status = "🟢 ALLOW"
            color = "\033[92m"  # green

        R = "\033[0m"  # reset
        rules_str = ",".join([r.rule_id for r in match.matched_rules]) if match.matched_rules else "-"
        line = (
            f"{color}[{status}]{R} "
            f"[{seq:02d}] "
            f"score={assessment.overall_score:.2f} "
            f"rules=[{rules_str}] "
            f"tier={decision.tier.value} "
            f"| {desc[:50]}"
        )
        print(line, file=sys.stderr)

    def _compute_report_fingerprint(self) -> str:
        """
        计算报告内容指纹，用于去重判断。

        基于 (event_count, max_score, risk_distribution, matched_rules) 四要素
        计算 SHA256 哈希。若两次生成的报告指纹相同，说明内容无变化，可跳过重复生成。
        """
        fingerprint_data = {
            "event_count": self._stats["total"],
            "max_score": round(self._stats["max_score"], 4),
            "risk_distribution": self._stats["risk_distribution"],
            "matched_rules": sorted(self._stats["matched_rules"]),
        }
        fingerprint_json = json.dumps(fingerprint_data, sort_keys=True, default=str)
        return hashlib.sha256(fingerprint_json.encode()).hexdigest()

    def generate_report(self) -> dict:
        """生成风险分析报告"""
        self._audit_logger.close()

        # 导出报告 + 保存行为图谱（U3: OutputSink 统一编排，不写阻断证据，
        # 与原 monitor_daemon.generate_report 行为一致）
        scenario_id = "demo_monitoring"
        scenario_name = "实时监测 - Q3 商业报表分析"
        outputs = self._sink.finalize(
            {
                "id": scenario_id,
                "name": scenario_name,
                "description": "实时监测模式：Agent 模拟 Q3 市场分析任务，Monitor 旁路捕获并分析所有系统事件",
                "expected_result": "混合 ALLOW/ALERT/BLOCK，展示全链路实时检测能力",
            },
            self._stats,
            write_evidence=False,
        )
        report_path = outputs["report_path"]
        graph_path = outputs["graph_path"]

        # 统计信息
        summary = {
            "scenario": scenario_id,
            "total_events": self._stats["total"],
            "allow": self._stats["allow"],
            "alert": self._stats["alert"],
            "block": self._stats["block"],
            "max_risk_score": self._stats["max_score"],
            "risk_distribution": self._stats["risk_distribution"],
            "matched_rules": self._stats["matched_rules"],
            "report_path": report_path,
            "graph_path": graph_path,
            "audit_file": outputs["audit_file"],
            "generated_at": datetime.now().isoformat(),
        }

        # 写入 JSON 摘要
        summary_path = os.path.join(self._output_dir, "monitoring_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2, default=str)

        return summary

    def generate_report_dedup(self) -> Optional[dict]:
        """
        带去重的报告生成。

        计算当前会话的内容指纹，若与已生成报告的指纹相同则跳过重复生成。
        返回生成的报告摘要，若跳过则返回 None。

        三种触发场景均通过此方法实现去重：
          (a) Agent 正常结束 → daemon 模式自动触发
          (b) 用户主动结束 → SIGTERM 信号处理触发
          (c) 用户显式指令 → 管理 FIFO / --generate-report CLI 触发
        """
        if self._stats["total"] == 0:
            return None

        fingerprint = self._compute_report_fingerprint()

        if fingerprint in self._report_fingerprints:
            print(f"[monitor] ⏭️  报告指纹重复 (events={self._stats['total']}, "
                  f"max_score={self._stats['max_score']:.2f})，跳过重复生成",
                  file=sys.stderr)
            return None

        self._report_fingerprints.add(fingerprint)
        self._last_report_time_ns = time.time_ns()
        return self.generate_report()


def _read_fifo_session(monitor: "MonitorDaemon", fifo_path: str,
                       record_file: Optional[str] = None) -> int:
    """
    打开 FIFO 并处理一个 Agent 会话的所有事件。

    返回处理的事件数。monitor._should_stop 为 True 时提前返回。

    Args:
        monitor:     MonitorDaemon 实例
        fifo_path:   命名管道路径
        record_file: 可选，录制文件路径。非空时旁路保存原始事件到 .jsonl
    """
    if not os.path.exists(fifo_path):
        print(f"[monitor] FIFO 不存在: {fifo_path}，等待创建...", file=sys.stderr)
        # 轮询等待 FIFO 被创建（最多 60s）
        for _ in range(600):
            if monitor._should_stop:
                return 0
            if os.path.exists(fifo_path):
                break
            time.sleep(0.1)
        else:
            print(f"[monitor] ERROR: FIFO 创建超时", file=sys.stderr)
            return 0

    print(f"[monitor] 等待 Agent 连接 (FIFO: {fifo_path})...", file=sys.stderr)
    try:
        fifo = open(fifo_path, "r", encoding="utf-8")
    except OSError as e:
        print(f"[monitor] ERROR: 无法打开 FIFO: {e}", file=sys.stderr)
        time.sleep(1)
        return 0

    print(f"[monitor] FIFO 已连接，开始实时监测...", file=sys.stderr)
    if record_file:
        print(f"[monitor] 📼 旁路录制: {record_file}", file=sys.stderr)
        os.makedirs(os.path.dirname(record_file), exist_ok=True)
    print(f"[monitor] {'='*50}", file=sys.stderr)

    rec_fh = None
    if record_file:
        try:
            rec_fh = open(record_file, "w", encoding="utf-8")
        except OSError as e:
            print(f"[monitor] WARNING: 无法创建录制文件: {e}", file=sys.stderr)

    events_processed = 0
    rec_bytes = 0
    try:
        for line in fifo:
            if monitor._should_stop:
                print(f"[monitor] 停止信号，已处理 {events_processed} 个事件", file=sys.stderr)
                break

            # 降级警告（每 60s）
            monitor._maybe_warn_degradation()

            line = line.strip()
            if not line:
                continue

            # 旁路录制：保存原始事件行（在解析前写入，确保原始数据完整）
            if rec_fh:
                rec_fh.write(line + "\n")
                rec_bytes += len(line) + 1

            try:
                raw = RawEvent.from_json_line(line)
                monitor.process_event(raw)
                events_processed += 1
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[monitor] WARNING: 解析事件失败: {e}", file=sys.stderr)
                continue

    except KeyboardInterrupt:
        print(f"\n[monitor] 收到中断信号", file=sys.stderr)
    finally:
        fifo.close()
        if rec_fh:
            rec_fh.close()
            if events_processed > 0:
                print(f"[monitor] 📼 录制完成: {events_processed} 事件, {rec_bytes} bytes → {record_file}",
                      file=sys.stderr)

    if events_processed > 0:
        print(f"[monitor] Agent 已断开连接 (本会话: {events_processed} 个事件)", file=sys.stderr)

    return events_processed


def run_monitor(fifo_path: str, output_dir: str, mode: str = "oneshot",
                use_ebpf: bool = False, record: bool = False,
                record_dir: str = "records",
                enable_rollup: Optional[bool] = None):
    """
    主循环：从 FIFO 阻塞读取事件，实时处理。

    Args:
        fifo_path:  命名管道路径
        output_dir: 输出目录
        mode:       "oneshot" (Agent 断开后退出) | "daemon" (持续等待)
        use_ebpf:   是否启用 eBPF 阻断（降级时自动切换 Mock + 告警）
        record:     是否启用旁路录制
        record_dir: 录制文件存放目录
        enable_rollup: 分层滚动显式开关（None=读 tuning.yaml；
                       False=test_report 模式，见 MonitorDaemon.__init__）
    """
    global _monitor_instance

    monitor = MonitorDaemon(output_dir=output_dir, use_ebpf=use_ebpf,
                            enable_rollup=enable_rollup)
    _monitor_instance = monitor

    mode_label = "守护进程 (daemon)" if mode == "daemon" else "单次 (oneshot)"
    print(f"[monitor] 监测{mode_label}启动", file=sys.stderr)
    print(f"[monitor] FIFO: {fifo_path}", file=sys.stderr)
    print(f"[monitor] 输出: {output_dir}", file=sys.stderr)

    # 启动审计日志
    monitor._audit_logger.start_scenario("demo_monitoring")

    total_events = 0
    session_count = 0

    def _print_session_summary(summary: dict, session_num: int):
        """打印会话监测摘要"""
        print(f"[monitor] {'='*50}", file=sys.stderr)
        print(f"[monitor] 📊 会话 {session_num} 监测摘要:", file=sys.stderr)
        print(f"[monitor]   事件数:    {summary['total_events']}", file=sys.stderr)
        print(f"[monitor]   🟢 放行:    {summary['allow']}", file=sys.stderr)
        print(f"[monitor]   🟡 告警:    {summary['alert']}", file=sys.stderr)
        print(f"[monitor]   🔴 阻断:    {summary['block']}", file=sys.stderr)
        print(f"[monitor]   最高风险分: {summary['max_risk_score']:.2f}", file=sys.stderr)
        print(f"[monitor]   📄 报告:    {summary['report_path']}", file=sys.stderr)
        print(f"[monitor]   📋 审计日志: {summary['audit_file']}", file=sys.stderr)

    while True:
        if monitor._should_stop:
            break

        # 计算当前会话的录制文件路径（每次新会话使用新时间戳）
        session_record_file = None
        if record:
            rec_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            session_record_file = os.path.join(record_dir, rec_ts, "events.jsonl")

        n = _read_fifo_session(monitor, fifo_path, session_record_file)
        total_events += n
        if n > 0:
            session_count += 1

            if mode == "daemon":
                # daemon 模式：每个会话结束后自动生成报告（带去重）
                print(f"[monitor] 正在生成会话 {session_count} 风险分析报告...", file=sys.stderr)
                summary = monitor.generate_report_dedup()
                if summary:
                    _print_session_summary(summary, session_count)
                # 准备下一会话
                monitor._reset_for_new_session()

        if mode == "oneshot":
            # 单次模式：Agent 断开后退出
            break

        # daemon 模式：短暂等待后重新监听
        if not monitor._should_stop:
            print(f"[monitor] (daemon) 等待下一个 Agent 连接... (已处理 {session_count} 个会话, 共 {total_events} 个事件)",
                  file=sys.stderr)
            time.sleep(0.5)

    # 阶段 3：优雅停止 flush 半满桶 → 汇总剩余 L2 为 L3 → 导出天级报告
    monitor._shutdown_rollup()

    # 生成最终报告 (oneshot 模式 或 最终停止时的汇总)
    if mode == "oneshot" and total_events > 0:
        print(f"[monitor] {'='*50}", file=sys.stderr)
        print(f"[monitor] 正在生成风险分析报告...", file=sys.stderr)
        summary = monitor.generate_report_dedup() or monitor.generate_report()

        print(f"[monitor] {'='*50}", file=sys.stderr)
        print(f"[monitor] 📊 监测摘要:", file=sys.stderr)
        print(f"[monitor]   会话数:    {session_count}", file=sys.stderr)
        print(f"[monitor]   总事件数:  {summary['total_events']}", file=sys.stderr)
        print(f"[monitor]   🟢 放行:    {summary['allow']}", file=sys.stderr)
        print(f"[monitor]   🟡 告警:    {summary['alert']}", file=sys.stderr)
        print(f"[monitor]   🔴 阻断:    {summary['block']}", file=sys.stderr)
        print(f"[monitor]   最高风险分: {summary['max_risk_score']:.2f}", file=sys.stderr)
        print(f"[monitor]   📄 报告:    {summary['report_path']}", file=sys.stderr)
        print(f"[monitor]   📋 审计日志: {summary['audit_file']}", file=sys.stderr)
    elif total_events == 0:
        print(f"[monitor] 无事件，跳过报告生成", file=sys.stderr)

    return 0


def run_monitor_mcp_report(output_dir: str, config_path: str = "config.yaml",
                           enable_rollup: Optional[bool] = None):
    """
    mcp_report 模式主循环（P4-9）:
      - 启动 MCP 申报 Server（HTTP+SSE，后台线程）
      - McpReportCollector 消费 broker 申报流 → RawEvent →
        MonitorDaemon 全链路管线（与 FIFO 模式同一套管线）
      - SIGTERM/SIGINT 停止后生成风险报告（语义与 FIFO 模式一致）

    Args:
        output_dir: 输出目录
        config_path: 配置文件路径（读取 mcp_report 配置段）
        enable_rollup: 分层滚动显式开关（None=读 tuning.yaml；
                       False=test_report 模式）

    Returns:
        int: 0 成功 / 1 失败（mcp SDK 缺失或采集器附着失败）
    """
    global _monitor_instance, _mcp_collector

    # ── 加载配置（失败降级为空配置，使用默认值）──
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
    except (IOError, OSError, yaml.YAMLError) as e:
        print(f"[monitor] WARNING: 配置读取失败 ({e})，使用默认值",
              file=sys.stderr)
        config = {}
    mcp_config = config.get("mcp_report", {}) or {}

    host = str(mcp_config.get("host", "127.0.0.1"))
    port = int(mcp_config.get("port", 8765))
    jsonl_dir = mcp_config.get("jsonl_dir")
    # P1: Hooks 确定性申报摄入配置（enabled=false/缺省时行为不变）
    hook_ingest = mcp_config.get("hook_ingest") or {}

    # ── mcp SDK 可用性（与 check_env 检测项同源）──
    from mcp_bridge.server import (McpReportBroker, mcp_sdk_available,
                                   run_server)
    if not mcp_sdk_available():
        print("[monitor] ERROR: mcp SDK 未安装，mcp_report 模式不可用。"
              "请执行: pip install mcp", file=sys.stderr)
        return 1

    # 注册信号处理（幂等；与 main() 的注册一致，支持直接调用路径）
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, _handle_signal)

    monitor = MonitorDaemon(output_dir=output_dir, use_ebpf=False,
                            enable_rollup=enable_rollup)
    _monitor_instance = monitor
    monitor._audit_logger.start_scenario("mcp_report")

    # ── broker: Server 与 Collector 共享同一申报队列 ──
    jsonl_path = None
    if jsonl_dir:
        os.makedirs(jsonl_dir, exist_ok=True)
        jsonl_path = os.path.join(jsonl_dir, "mcp_reports.jsonl")
    broker = McpReportBroker(jsonl_path=jsonl_path)

    # ── collector（复用 RawEventFactory + SemanticGuard）──
    from collector.mcp_report_collector import McpReportCollector
    collector = McpReportCollector(config, broker=broker)
    target_agent = str(mcp_config.get("target_agent_id", "workbuddy"))
    if not collector.attach(agent_id=target_agent):
        print("[monitor] ERROR: MCP 采集器附着失败", file=sys.stderr)
        return 1
    _mcp_collector = collector

    # ── MCP Server（HTTP+SSE，后台线程；daemon 线程随主进程退出）──
    # run_server 内部用同一 broker 创建 Server，保证与 collector 同队列。
    server_thread = threading.Thread(
        target=run_server,
        kwargs={"host": host, "port": port, "broker": broker,
                "jsonl_path": jsonl_path, "hook_ingest": hook_ingest},
        name="mcp-report-server", daemon=True)
    server_thread.start()

    print(f"[monitor] mcp_report 模式启动", file=sys.stderr)
    print(f"[monitor] MCP Server: http://{host}:{port}/sse "
          f"(申报 tools: report_tool_call / report_action / report_session)",
          file=sys.stderr)
    if hook_ingest.get("enabled"):
        _hook_path = str(hook_ingest.get("path") or "/api/hook-report")
        print(f"[monitor] Hook 申报摄入: POST http://{host}:{port}{_hook_path} "
              f"(Qoder CN Hooks 确定性申报通道)", file=sys.stderr)
    print(f"[monitor] 输出: {output_dir}", file=sys.stderr)
    print(f"[monitor] 申报留痕: {jsonl_path or '内存队列 (未落盘)'}",
          file=sys.stderr)
    print(f"[monitor] 等待申报... (MCP tools / Hook 摄入; Ctrl+C 停止并生成报告)",
          file=sys.stderr)

    # ── stdin 优雅停止通道（跨平台确定性停止，供进程管理器/测试驱动）:
    # 读入一行 stop/shutdown/quit 即触发与 SIGINT 相同的优雅停止。
    def _stdin_watch():
        try:
            while not monitor._should_stop:
                line = sys.stdin.readline()
                if not line:  # stdin 关闭（管道断开/父进程退出）
                    break
                if line.strip().lower() in ("stop", "shutdown", "quit"):
                    monitor._should_stop = True
                    collector.detach()
                    break
        except Exception:
            pass

    threading.Thread(target=_stdin_watch, daemon=True,
                     name="mcp-stdin-watch").start()

    total_events = 0
    try:
        for raw in collector.start():
            if monitor._should_stop:
                break
            monitor.process_event(raw)
            total_events += 1
    except KeyboardInterrupt:
        print(f"\n[monitor] 收到中断信号", file=sys.stderr)
    finally:
        collector.detach()
        _mcp_collector = None

    # 阶段 3：优雅停止 flush 半满桶 → 汇总剩余 L2 为 L3 → 导出天级报告
    monitor._shutdown_rollup()

    # ── 生成最终报告 ──
    if total_events > 0:
        print(f"[monitor] {'='*50}", file=sys.stderr)
        print(f"[monitor] 正在生成风险分析报告...", file=sys.stderr)
        summary = monitor.generate_report_dedup() or monitor.generate_report()

        print(f"[monitor] {'='*50}", file=sys.stderr)
        print(f"[monitor] 📊 mcp_report 监测摘要:", file=sys.stderr)
        print(f"[monitor]   申报计数: tool_call={collector.tool_call_count}, "
              f"action={collector.action_count}, "
              f"session={collector.session_count}, "
              f"跳过={collector.skipped_count}", file=sys.stderr)
        print(f"[monitor]   申报→事件数: {total_events}", file=sys.stderr)
        print(f"[monitor]   🟢 放行:    {summary['allow']}", file=sys.stderr)
        print(f"[monitor]   🟡 告警:    {summary['alert']}", file=sys.stderr)
        print(f"[monitor]   🔴 阻断:    {summary['block']}", file=sys.stderr)
        print(f"[monitor]   最高风险分: {summary['max_risk_score']:.2f}",
              file=sys.stderr)
        print(f"[monitor]   📄 报告:    {summary['report_path']}", file=sys.stderr)
        print(f"[monitor]   📋 审计日志: {summary['audit_file']}", file=sys.stderr)
    else:
        print(f"[monitor] 无申报事件，跳过报告生成", file=sys.stderr)

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="独立监测守护进程",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
模式说明:
  oneshot     单次模式（默认）：Agent 断开后生成报告并退出
  daemon      守护模式：Agent 断开后继续监听，仅在 SIGTERM 时退出
  mcp_report  MCP 申报模式（P4）：启动 MCP 申报 Server（HTTP+SSE），
              消费 WorkBuddy 申报流，SIGTERM/SIGINT 停止后生成报告

用法示例:
  python monitor_daemon.py --mode daemon
  python monitor_daemon.py --mode oneshot --fifo /tmp/my_pipe
  python monitor_daemon.py --mode mcp_report --output output/mcp_monitoring
  python monitor_daemon.py --mode oneshot --no-rollup  # 测试模式：仅 L0 + 结束一次性报告
        """)
    parser.add_argument("--fifo", default="/tmp/observer_monitoring_pipe",
                        help="命名管道路径 (default: /tmp/observer_monitoring_pipe)")
    parser.add_argument("--output", default=None,
                        help="输出目录 (default: observer_sim/output/demo_monitoring)")
    parser.add_argument("--mode", choices=["oneshot", "daemon", "mcp_report"],
                        default="oneshot",
                        help="运行模式: oneshot (默认) | daemon | mcp_report")
    parser.add_argument("--config", default="config.yaml",
                        help="配置文件路径 (mcp_report 模式读取 mcp_report 配置段)")
    parser.add_argument("--ebpf", action="store_true", default=False,
                        help="启用 eBPF 阻断（需要 root 权限 + libbpf）")
    parser.add_argument("--record", action="store_true", default=False,
                        help="启用旁路录制：将 FIFO 原始事件保存为 .jsonl 录制文件")
    parser.add_argument("--record-dir", default=None,
                        help="录制文件存放目录 (default: observer_sim/records)")
    parser.add_argument("--no-rollup", action="store_true", default=False,
                        help="关闭分层日志滚动（test_report 模式：仅 L0 持续记录"
                             " + 结束一次性报告，不生成 L1/L2/L3 产物）")
    parser.add_argument("--generate-report", action="store_true", default=False,
                        help="向运行中的 daemon 发送 SIGUSR1 请求生成报告")
    parser.add_argument("--pid-file", default=None,
                        help="Monitor PID 文件路径（用于 --generate-report 定位进程）")
    args = parser.parse_args()

    # ── 显式报告生成请求（场景 c）──
    if args.generate_report:
        pid_file = args.pid_file or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", ".monitoring", "monitor.pid")
        pid_file = os.path.abspath(pid_file)
        if not os.path.isfile(pid_file):
            print(f"ERROR: PID 文件不存在: {pid_file}", file=sys.stderr)
            print("请确认 Monitor daemon 正在运行", file=sys.stderr)
            return 1
        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGUSR1)
            print(f"已向 Monitor daemon (PID={pid}) 发送报告生成请求", file=sys.stderr)
            return 0
        except ProcessLookupError:
            print(f"ERROR: Monitor daemon (PID={pid}) 未在运行", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

    # 确定输出目录
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = args.output or os.path.join(base_dir, "output", "demo_monitoring")

    # 注册信号处理（SIGUSR1 仅类 Unix 平台存在，Windows 上跳过）
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, _handle_signal)  # 显式报告生成请求

    # ── 写入 PID 文件（daemon/oneshot 模式，非报告请求）──
    if args.pid_file:
        pid_path = os.path.abspath(args.pid_file)
        try:
            os.makedirs(os.path.dirname(pid_path), exist_ok=True)
            with open(pid_path, "w") as pf:
                pf.write(str(os.getpid()))
        except OSError as e:
            print(f"[monitor] WARNING: 无法写入 PID 文件 {pid_path}: {e}",
                  file=sys.stderr)

    # ── mcp_report 模式: 不走 FIFO 主循环（P4-9 统一入口挂载）──
    _enable_rollup = False if args.no_rollup else None
    if args.mode == "mcp_report":
        return run_monitor_mcp_report(output_dir, config_path=args.config,
                                      enable_rollup=_enable_rollup)

    return run_monitor(args.fifo, output_dir, mode=args.mode, use_ebpf=args.ebpf,
                       record=args.record,
                       record_dir=args.record_dir or os.path.join(os.path.dirname(base_dir), "records"),
                       enable_rollup=_enable_rollup)


if __name__ == "__main__":
    # U4: 统一入口为 observer.py，直接运行保留但打印一行提示
    print("[提示] 统一入口: python observer.py daemon [--fifo F --output O --mode M]")
    sys.exit(main())
