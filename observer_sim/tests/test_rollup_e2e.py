# -*- coding: utf-8 -*-
"""
test_rollup_e2e.py — 分层日志金字塔端到端测试（阶段 3 L-T12 / m05）

用真实全链路 PipelineRunner 跑 m05 时间分散式隐性协作场景
（虚拟时钟加速，4 小时 delay 瞬时推进），验证：
1. L1 片段 → L2 → L3 全链（GC / 日切驱动路径）
2. m05 跨 Agent 串谋链在天级审计中被检出并完整重建
3. L3 天级深度报告含攻击链重建 + L0 下钻索引
4. 三红线：fingerprint_edges 全链无损透传，L0 文件不被触碰
5. monitor_daemon 挂接：虚拟日切→L3 + 优雅停止 partial flush + 开关回退
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from models.event import RawEvent
from models.virtual_clock import VirtualClock
from observer_core.monitoring.event_normalizer import EventNormalizer
from observer_core.monitoring.rule_engine import RuleEngine
from observer_core.monitoring.raw_event_factory import RawEventFactory
from observer_core.judgment.risk_scorer import RiskScorer
from observer_core.judgment.baseline_checker import BaselineChecker
from observer_core.judgment.decision_engine import DecisionEngine
from observer_core.blocking.blocking_coordinator import BlockingCoordinator
from observer_core.blocking.command_sender import MockCommandSender
from observer_core.audit.behavior_graph import BehaviorGraph
from observer_core.audit.audit_logger import AuditLogger
from observer_core.audit.report_cache import ReportCacheManager
from observer_core.audit.report_exporter import ReportExporter
from observer_core.audit.rollup_engine import RollupEngine, DAY_NS
from observer_core.pipeline_runner import PipelineRunner

SCENARIO_PATH = os.path.join(os.path.dirname(__file__), "..", "scenarios",
                             "multi_agent", "m05_time_dispersed_collusion.yaml")


def _build_pipeline(tmpdir):
    """构建与 MonitorDaemon 一致的真实全链路（不含 daemon 调度）。"""
    clock = VirtualClock(start_ns=1718092800000000000)
    normalizer = EventNormalizer(clock=clock, window_size=10)
    rule_engine = RuleEngine()
    rules_path = os.path.join(os.path.dirname(__file__), "..",
                              "rules", "default_policy.yaml")
    rule_engine.load_rules(rules_path)
    baseline = BaselineChecker()
    scorer = RiskScorer()
    scorer.register_default_dimensions()
    decision_engine = DecisionEngine()
    sender = MockCommandSender()
    sender.connect("mock_pipe")
    blocking_coord = BlockingCoordinator(clock=clock, sender=sender,
                                         output_dir=tmpdir)
    graph = BehaviorGraph()
    audit_logger = AuditLogger(output_dir=tmpdir)
    audit_logger.start_scenario("m05_rollup_e2e")
    runner = PipelineRunner(
        normalizer=normalizer,
        rule_engine=rule_engine,
        baseline_checker=baseline,
        scorer=scorer,
        decision_engine=decision_engine,
        blocking_coord=blocking_coord,
        behavior_graph=graph,
        audit_logger=audit_logger,
    )
    return clock, runner, audit_logger


def _run_scenario_events(clock, runner, scenario):
    """按 m05 YAML 推进虚拟时钟并逐事件走全链路（与 main.py 语义一致）。"""
    agents_map = {a["agent_id"]: a for a in scenario.get("agents", [])}
    for i, event_data in enumerate(scenario.get("event_sequence", []), 1):
        seq = event_data.get("seq", i)
        delay_ms = event_data.get("delay_ms", 0)
        agent_id = event_data.get("agent", "unknown")
        agent_info = agents_map.get(agent_id,
                                    {"agent_id": agent_id, "initial_pid": 10001})
        clock.advance(delay_ms)
        raw = RawEventFactory.from_scenario_event(
            event_data, seq=seq, timestamp_ns=0, agent_info=agent_info)
        raw.timestamp_ns = clock.now_ns()
        runner.process_event(raw)


class TestM05RollupE2E(unittest.TestCase):
    """m05 虚拟时钟加速：全链路 → L1/L2/L3 → 串谋检出 + 报告下钻。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="rollup_e2e_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_m05_day_level_collusion_detected_and_reported(self):
        with open(SCENARIO_PATH, "r", encoding="utf-8") as f:
            scenario = yaml.safe_load(f)["scenario"]

        clock, runner, audit_logger = _build_pipeline(self.tmpdir)
        _run_scenario_events(clock, runner, scenario)

        entries = audit_logger.read_entries()
        self.assertEqual(len(entries), 8, "m05 共 8 个事件")
        # 指纹单一接入点透传（net_conn 亦有指纹 → 外传终点可入边区）
        for e in entries:
            self.assertTrue(getattr(e, "fingerprint", None),
                            f"事件 {e.event_id} 缺指纹")

        # L1 片段（force_generate 复用 60s 自动片段同一代码路径）
        cache = ReportCacheManager(output_dir=self.tmpdir)
        cache.set_audit_logger(audit_logger)
        engine = RollupEngine(output_dir=self.tmpdir)
        cache.set_rollup_engine(engine)
        segments = []
        while True:
            seg = cache.force_generate()
            if seg is None:
                break
            segments.append(seg)
        self.assertEqual(len(segments), 1)
        self.assertTrue(segments[0]["fingerprint_edges"],
                        "L1 片段必须携带指纹边（三红线）")

        # 日切驱动路径：全部 L1 进引擎 → partial L2 → L3
        day_end = (clock.now_ns() // DAY_NS + 1) * DAY_NS
        self.assertEqual(cache.rollup_through(day_end), 1)
        partial_l2s = engine.flush_all()
        self.assertEqual(len(partial_l2s), 1)
        self.assertTrue(partial_l2s[0]["partial"])

        all_l2 = engine.list_l2()
        self.assertGreaterEqual(len(all_l2), 1)
        l3 = engine.rollup_day(all_l2)
        self.assertEqual(l3["type"], "l3_daily_audit")
        self.assertLessEqual(l3["l2_count"], 24)

        # m05 串谋链检出：路径传递链 /tmp/stage/temp_data.json
        chains = l3["collusion_chains"]
        self.assertTrue(chains, f"m05 串谋链未在天级审计检出: {l3}")
        stage_chains = [c for c in chains
                        if "/tmp/stage/temp_data.json" in str(c.get("object"))]
        self.assertTrue(stage_chains, "未检出暂存区路径传递链")
        ch = stage_chains[0]
        self.assertEqual(set(ch["agents"]), {"agent-a", "agent-b"})
        self.assertGreaterEqual(ch["span_hours"], 3.9,
                                "m05 时间分散跨度应约 4 小时")
        self.assertIn("203.0.113.42", ch["remote_addrs"],
                      "外传终点地址应进入攻击链")

        # 三红线：指纹边全链无损（L1 → L3）
        l1_fp = {e["event_id"] for e in segments[0]["fingerprint_edges"]}
        l3_fp = {e["event_id"] for e in l3["fingerprint_edges"]}
        self.assertTrue(l1_fp.issubset(l3_fp),
                        f"指纹边 L1→L3 丢失: {l1_fp - l3_fp}")

        # 三红线：L0 永不删除（audit 文件保留且内容不变）
        audit_dir = os.path.join(self.tmpdir, "audit")
        l0_files = sorted(f for f in os.listdir(audit_dir)
                          if f.startswith("audit_") and f.endswith(".jsonl"))
        self.assertEqual(len(l0_files), 1)
        l0_path = os.path.join(audit_dir, l0_files[0])
        with open(l0_path, "r", encoding="utf-8") as f:
            l0_content = f.read()
        self.assertEqual(len(l0_content.strip().splitlines()), 8)

        # L3 天级深度报告 + L0 下钻索引
        exporter = ReportExporter(output_dir=self.tmpdir)
        report_path = exporter.export_daily_report(l3, audit_dir=audit_dir)
        self.assertTrue(os.path.exists(report_path))
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("串谋攻击链重建", content)
        self.assertIn("/tmp/stage/temp_data.json", content)
        self.assertIn("agent-a", content)
        self.assertIn("agent-b", content)
        self.assertIn("203.0.113.42", content)
        self.assertIn("L0 下钻索引", content)
        self.assertIn("audit_m05_rollup_e2e", content)
        # L0 内容未被报告链路修改
        with open(l0_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), l0_content)


def _noop_start_auto(self, interval: float = 60.0):
    """测试替身：标记自动片段已启动但不真正起线程（保证确定性）。"""
    self._auto_interval = interval
    self._auto_running = True


class TestDaemonRollupHook(unittest.TestCase):
    """3.4.3: monitor_daemon 挂接 rollup 调度（日切→L3 / 停止 flush / 开关）。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="daemon_rollup_")
        patcher = mock.patch(
            "observer_core.audit.report_cache.ReportCacheManager.start_auto",
            new=_noop_start_auto)
        patcher.start()
        self.addCleanup(patcher.stop)
        from monitor_daemon import MonitorDaemon
        self.monitor = MonitorDaemon(output_dir=self.tmpdir, use_ebpf=False)
        # run_monitor 会在启动时开启审计场景，测试直接构造需显式开启
        self.monitor._audit_logger.start_scenario("daemon_rollup_e2e")

    def tearDown(self):
        try:
            self.monitor._shutdown_rollup()
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _m05_raw(self, seq, delay_ms, agent, type_, file_path=None,
                 file_op=None, remote_addr=None, remote_port=None,
                 executable=None, arguments=None):
        base = 1718092800000000000
        return RawEvent(
            event_id=f"m05_e2e_{seq}",
            timestamp_ns=base + delay_ms * 1_000_000,
            event_type=type_,
            pid=40000 + seq, ppid=1,
            agent_id=agent, agent_framework="test",
            executable=executable, arguments=arguments,
            file_path=file_path, file_op=file_op,
            remote_addr=remote_addr, remote_port=remote_port,
            protocol="TCP" if type_ == "net_conn" else None)

    def test_day_boundary_rolls_l3_and_shutdown_flushes(self):
        mon = self.monitor
        self.assertTrue(mon._rollup_enabled, "rollup 默认开启（tuning.yaml）")
        self.assertTrue(mon._report_cache._auto_running,
                        "L1 自动片段已启动（60s 周期）")

        # 第一天：A 收集并写暂存区
        mon.process_event(self._m05_raw(
            1, 0, "agent-a", "file_open",
            file_path="/data/customers/contacts.csv", file_op="read"))
        mon.process_event(self._m05_raw(
            2, 500, "agent-a", "file_open",
            file_path="/tmp/stage/temp_data.json", file_op="write"))
        mon.process_event(self._m05_raw(
            3, 700, "agent-a", "exec", executable="/usr/bin/exit"))

        # 第二天（跨虚拟日切，m05 的 4h + 24h 跨度）: B 读取并外传
        day2 = 100_800_000  # 14_400_000 (4h) + 86_400_000 (24h)
        mon.process_event(self._m05_raw(
            4, day2, "agent-b", "exec",
            executable="/usr/bin/python3", arguments=["start_work.py"]))
        # ↑ 第一个第二天事件触发日切：前一天 L2→L3
        l3_dir = os.path.join(self.tmpdir, "cache", "l3")
        l3_files = sorted(f for f in os.listdir(l3_dir)
                          if f.startswith("l3_") and f.endswith(".json"))
        self.assertEqual(len(l3_files), 1, "虚拟日切应生成前一天 L3")
        with open(os.path.join(l3_dir, l3_files[0]), "r",
                  encoding="utf-8") as f:
            day1_l3 = json.load(f)
        self.assertEqual(day1_l3["type"], "l3_daily_audit")
        # 三红线：前一天指纹边（A 写暂存）无损进入 L3
        day1_ids = {e["event_id"] for e in day1_l3["fingerprint_edges"]}
        self.assertIn("m05_e2e_2", day1_ids)

        mon.process_event(self._m05_raw(
            5, day2 + 1000, "agent-b", "file_open",
            file_path="/tmp/stage/temp_data.json", file_op="read"))
        mon.process_event(self._m05_raw(
            7, day2 + 2500, "agent-b", "net_conn",
            remote_addr="203.0.113.42", remote_port=21))

        # 优雅停止：flush 半满桶 → 第二天 partial L3 + 天级报告
        mon._shutdown_rollup()
        l2_files = sorted(f for f in os.listdir(
            os.path.join(self.tmpdir, "cache", "l2"))
            if f.startswith("l2_") and f.endswith(".json"))
        self.assertTrue(l2_files, "优雅停止应生成 partial L2")
        l3_files_after = sorted(f for f in os.listdir(l3_dir)
                                if f.startswith("l3_"))
        self.assertEqual(len(l3_files_after), 2,
                         "停止时应补生成最后一天的 L3")
        # 天级报告落盘（含攻击链与 L0 下钻）
        reports = [f for f in os.listdir(os.path.join(self.tmpdir, "reports"))
                   if f.startswith("risk_report_daily_")]
        self.assertTrue(reports, "L3 天级深度报告应落盘")
        with open(os.path.join(self.tmpdir, "reports", reports[0]), "r",
                  encoding="utf-8") as f:
            self.assertIn("L0 下钻索引", f.read())
        # L0 永不删除
        l0_files = [f for f in os.listdir(os.path.join(self.tmpdir, "audit"))
                    if f.startswith("audit_")]
        self.assertTrue(l0_files)

    def test_rollup_disabled_switch_falls_back(self):
        """tuning.yaml rollup.enabled=false → 挂接关闭，主链路不受影响。"""
        with mock.patch(
                "observer_core.judgment.tuning_loader.TuningLoader.load",
                return_value={"rollup": {"enabled": False}}):
            from monitor_daemon import MonitorDaemon
            mon = MonitorDaemon(output_dir=self.tmpdir, use_ebpf=False)
        self.assertFalse(mon._rollup_enabled)
        self.assertIsNone(mon._report_cache)
        # 主链路照常处理事件，不因 rollup 关闭而报错
        mon.process_event(self._m05_raw(
            1, 0, "agent-a", "file_open",
            file_path="/data/customers/contacts.csv", file_op="read"))
        self.assertEqual(mon._stats["total"], 1)
        mon._shutdown_rollup()  # 无操作，不崩溃


if __name__ == "__main__":
    unittest.main()
