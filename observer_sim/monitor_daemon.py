#!/usr/bin/env python3
"""
monitor_daemon.py — 独立监测守护进程

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
    python monitor_daemon.py --fifo /tmp/observer_monitoring_pipe
    python monitor_daemon.py --fifo /tmp/observer_monitoring_pipe --output output/demo_monitoring
"""

import sys
import os
import json
import time
import signal
import argparse
import hashlib
import logging
from datetime import datetime
from typing import Optional

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


def _handle_signal(signum, frame):
    """信号处理：优雅停止"""
    global _running, _monitor_instance
    if signum == signal.SIGUSR1:
        # SIGUSR1: 显式请求生成报告（场景 c）
        if _monitor_instance:
            print("\n[monitor] 收到显式报告生成请求", file=sys.stderr)
            summary = _monitor_instance.generate_report_dedup()
            if summary:
                print(f"[monitor] 📄 报告已生成: {summary['report_path']}", file=sys.stderr)
            else:
                print(f"[monitor] ⏭️  报告无变化，跳过", file=sys.stderr)
        return
    _running = False
    if _monitor_instance:
        print("\n[monitor] 收到停止信号，正在生成报告...", file=sys.stderr)
        _monitor_instance._should_stop = True


class MonitorDaemon:
    """监测守护进程 — 实时事件处理 + 报告生成"""

    def __init__(self, output_dir: str = "output/demo_monitoring",
                 use_ebpf: bool = False):
        self._base_dir = os.path.dirname(os.path.abspath(__file__))
        self._output_dir = output_dir
        self._should_stop = False
        self._use_ebpf = use_ebpf
        self._ebpf_degraded = False
        self._ebpf_degradation_report: Optional[dict] = None
        self._last_degradation_warning: float = 0.0

        # 初始化 Pipeline 组件
        rules_path = os.path.join(self._base_dir, "rules", "default_policy.yaml")
        self._rule_engine = RuleEngine()
        self._rule_engine.load_rules(rules_path)

        self._clock = VirtualClock(start_ns=1718092800000000000)
        self._normalizer = EventNormalizer(clock=self._clock, window_size=10)
        self._baseline = BaselineChecker(min_warm_events=5)
        self._scorer = RiskScorer()
        self._scorer.register_default_dimensions()
        self._decision_engine = DecisionEngine()

        # ── 阻断指令发送器（Mock / eBPF）──
        self._cmd_sender = self._init_command_sender()
        self._blocking_coord = BlockingCoordinator(
            clock=self._clock, sender=self._cmd_sender, output_dir=output_dir)

        self._behavior_graph = BehaviorGraph()
        self._audit_logger = AuditLogger(output_dir=output_dir)
        self._report_exporter = ReportExporter(output_dir=output_dir)

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

    @staticmethod
    def _make_empty_stats() -> dict:
        return {
            "total": 0, "allow": 0, "alert": 0, "block": 0,
            "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "max_score": 0.0, "matched_rules": [],
        }

    def _reset_for_new_session(self):
        """重置统计和内部状态，准备处理下一个 Agent 会话"""
        self._stats = self._make_empty_stats()
        # 重新开始审计日志（新会话 = 新文件）
        self._audit_logger.close()
        self._audit_logger.start_scenario("demo_monitoring")
        # 重建行为图谱（隔离开不同会话的事件）
        self._behavior_graph = BehaviorGraph()
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
        """处理单个 RawEvent，运行全链路 Pipeline"""
        t0 = time.time()

        # 1. 归一化
        norm = self._normalizer.normalize(raw)

        # 2. 基线收集
        if "normal" in raw.agent_id:
            self._baseline.collect(norm)

        # 3. 规则匹配
        match = self._rule_engine.match(norm)

        # 4. 风险评分
        context = self._normalizer.get_agent_context(raw.agent_id)
        self._scorer.set_baseline(self._baseline.get_baseline_dict())
        assessment = self._scorer.assess(norm, match, context)

        # 5. 研判决策
        decision = self._decision_engine.decide(
            assessment, event_id=raw.event_id, agent_id=raw.agent_id)

        # 6. 阻断执行
        blocking_result = self._blocking_coord.execute(norm, decision)

        # 7. 记录行为图谱
        matched_rule_ids = [r.rule_id for r in match.matched_rules]
        self._behavior_graph.add_event(
            norm, assessment=assessment, decision=decision,
            blocking_result=blocking_result, matched_rules=matched_rule_ids)

        # 8. 审计日志
        desc = self._build_desc(norm)
        processing_ms = (time.time() - t0) * 1000
        self._audit_logger.log_event(
            norm, assessment=assessment, decision=decision,
            blocking_result=blocking_result, matched_rules=matched_rule_ids,
            description=desc, processing_time_ms=processing_ms)

        # 9. 更新统计
        self._stats["total"] += 1
        if assessment.overall_score > self._stats["max_score"]:
            self._stats["max_score"] = assessment.overall_score
        self._stats["risk_distribution"][assessment.risk_level.value] += 1

        if blocking_result.blocked:
            self._stats["block"] += 1
        elif decision.action == DecisionAction.ALERT:
            self._stats["alert"] += 1
        else:
            self._stats["allow"] += 1

        for rule_id in matched_rule_ids:
            if rule_id not in [r[0] for r in self._stats["matched_rules"]]:
                self._stats["matched_rules"].append((rule_id, assessment.overall_score))

        # 10. 实时输出到 stderr
        self._print_event(desc, match, assessment, decision, blocking_result,
                          self._stats["total"], processing_ms)

    def _build_desc(self, norm) -> str:
        """构建事件描述"""
        et = norm.event_type
        if et == "exec":
            return norm.command_string or f"{norm.raw.executable} {' '.join(norm.raw.arguments or [])}"
        elif et == "file_open":
            return f"{norm.raw.file_op} {norm.raw.file_path}"
        elif et == "net_conn":
            return f"{norm.raw.remote_addr}:{norm.raw.remote_port}"
        return et

    def _print_event(self, desc, match, assessment, decision, blocking_result, seq, ms):
        """彩色实时输出事件处理结果"""
        # 状态标记
        if blocking_result.blocked:
            status = "🔴 BLOCK"
            color = "\033[91m"  # red
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

        # 导出报告
        scenario_id = "demo_monitoring"
        scenario_name = "实时监测 - Q3 商业报表分析"

        report_path = self._report_exporter.export_scenario_report(
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            audit_logger=self._audit_logger,
            behavior_graph=self._behavior_graph,
            scenario_description="实时监测模式：Agent 模拟 Q3 市场分析任务，Monitor 旁路捕获并分析所有系统事件",
            expected_result="混合 ALLOW/ALERT/BLOCK，展示全链路实时检测能力",
        )

        # 保存行为图谱
        graph_dir = os.path.join(self._output_dir, "graphs")
        os.makedirs(graph_dir, exist_ok=True)
        graph_path = os.path.join(graph_dir, f"graph_{scenario_id}.json")
        self._behavior_graph.save_json(graph_path)

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
            "audit_file": self._audit_logger.current_file,
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
                record_dir: str = "records"):
    """
    主循环：从 FIFO 阻塞读取事件，实时处理。

    Args:
        fifo_path:  命名管道路径
        output_dir: 输出目录
        mode:       "oneshot" (Agent 断开后退出) | "daemon" (持续等待)
        use_ebpf:   是否启用 eBPF 阻断（降级时自动切换 Mock + 告警）
        record:     是否启用旁路录制
        record_dir: 录制文件存放目录
    """
    global _monitor_instance

    monitor = MonitorDaemon(output_dir=output_dir, use_ebpf=use_ebpf)
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


def main():
    parser = argparse.ArgumentParser(
        description="独立监测守护进程",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
模式说明:
  oneshot  单次模式（默认）：Agent 断开后生成报告并退出
  daemon   守护模式：Agent 断开后继续监听，仅在 SIGTERM 时退出

用法示例:
  python monitor_daemon.py --mode daemon
  python monitor_daemon.py --mode oneshot --fifo /tmp/my_pipe
        """)
    parser.add_argument("--fifo", default="/tmp/observer_monitoring_pipe",
                        help="命名管道路径 (default: /tmp/observer_monitoring_pipe)")
    parser.add_argument("--output", default=None,
                        help="输出目录 (default: observer_sim/output/demo_monitoring)")
    parser.add_argument("--mode", choices=["oneshot", "daemon"], default="oneshot",
                        help="运行模式: oneshot (默认) | daemon")
    parser.add_argument("--ebpf", action="store_true", default=False,
                        help="启用 eBPF 阻断（需要 root 权限 + libbpf）")
    parser.add_argument("--record", action="store_true", default=False,
                        help="启用旁路录制：将 FIFO 原始事件保存为 .jsonl 录制文件")
    parser.add_argument("--record-dir", default=None,
                        help="录制文件存放目录 (default: observer_sim/records)")
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

    # 注册信号处理
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
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

    return run_monitor(args.fifo, output_dir, mode=args.mode, use_ebpf=args.ebpf,
                       record=args.record,
                       record_dir=args.record_dir or os.path.join(os.path.dirname(base_dir), "records"))


if __name__ == "__main__":
    sys.exit(main())
