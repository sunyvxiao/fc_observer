# -*- coding: utf-8 -*-
"""
test_test_report_mode.py — 端到端测试专用轻量日志/报告模式（test_report 模式）

MonitorDaemon(enable_rollup=False) 即 test_report 模式：
  进程启动后仅持续监测并记录 L0 audit JSONL + 内存统计；
  不实例化 ReportCacheManager / RollupEngine（无 60s 线程、无 GC、
  无 L1→L2→L3 rollup、无 cache/ 产物、不依赖 monitor_daemon 调度）；
  测试结束一次性输出最终报告（复用 generate_report 既有路径）。

验证点：
1. rollup 链完全跳过，主链路照常工作
2. 最终报告一次性输出，无分层日志痕迹
3. L0 审计文件完整且不被修改
4. 开关优先级：显式参数 > tuning.yaml
5. 生产模式（默认）与 test_report 模式产物对比
6. CLI --no-rollup flag 透传
"""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from models.event import RawEvent
from monitor_daemon import MonitorDaemon


def _make_raw(seq, agent="agent-a"):
    """构造一个最小合法 RawEvent（file_open，与 test_rollup_e2e 同构）。"""
    return RawEvent(
        event_id=f"tst_evt_{seq}",
        timestamp_ns=1718092800000000000 + seq * 1_000_000_000,
        event_type="file_open",
        pid=40000 + seq, ppid=1,
        agent_id=agent, agent_framework="test",
        executable="/usr/bin/python3",
        arguments=["work.py"],
        file_path=f"/tmp/work/file_{seq}.txt", file_op="read",
        remote_addr=None, remote_port=None, protocol=None)


def _noop_start_auto(self, interval: float = 60.0):
    """测试替身：标记自动片段已启动但不真正起线程（保证确定性）。"""
    self._auto_interval = interval
    self._auto_running = True


class TestTestReportMode(unittest.TestCase):
    """test_report 模式：轻量日志路径，与生产分层逻辑完全隔离。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="test_report_mode_")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _new_monitor(self, enable_rollup=False):
        mon = MonitorDaemon(output_dir=self.tmpdir, use_ebpf=False,
                            enable_rollup=enable_rollup)
        mon._audit_logger.start_scenario("test_report_mode")
        return mon

    def test_test_mode_skips_rollup_chain(self):
        """test_report 模式：不实例化 rollup 组件，主链路照常工作。"""
        mon = self._new_monitor(enable_rollup=False)
        self.assertFalse(mon._rollup_enabled)
        self.assertIsNone(mon._report_cache)
        self.assertIsNone(mon._rollup_engine)

        mon.process_event(_make_raw(1))
        mon.process_event(_make_raw(2))
        self.assertEqual(mon._stats["total"], 2)

        mon._shutdown_rollup()  # no-op，不崩溃
        # 无任何 cache 分层产物（L1 片段/L2/L3/rollup 转存均不生成）
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, "cache")))

    def test_test_mode_final_report_once(self):
        """test_report 模式：结束一次性输出最终报告，无分层日志痕迹。"""
        mon = self._new_monitor(enable_rollup=False)
        for i in range(5):
            mon.process_event(_make_raw(i))

        summary = mon.generate_report()
        self.assertEqual(summary["total_events"], 5)

        # 报告一次性输出（仅 1 个 Markdown 报告）
        self.assertTrue(os.path.exists(summary["report_path"]))
        reports_dir = os.path.join(self.tmpdir, "reports")
        md_files = [f for f in os.listdir(reports_dir)
                    if f.startswith("risk_report_") and f.endswith(".md")]
        self.assertEqual(len(md_files), 1)
        self.assertTrue(os.path.exists(
            os.path.join(self.tmpdir, "monitoring_summary.json")))

        with open(summary["report_path"], "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("分层日志金字塔", content)

    def test_test_mode_l0_audit_intact(self):
        """test_report 模式：L0 审计完整记录，关闭/报告链路均不修改。"""
        mon = self._new_monitor(enable_rollup=False)
        for i in range(4):
            mon.process_event(_make_raw(i))

        audit_dir = os.path.join(self.tmpdir, "audit")
        l0_files = [f for f in os.listdir(audit_dir)
                    if f.startswith("audit_") and f.endswith(".jsonl")]
        self.assertEqual(len(l0_files), 1)
        l0_path = os.path.join(audit_dir, l0_files[0])
        with open(l0_path, "r", encoding="utf-8") as f:
            content_before = f.read()
        lines = [ln for ln in content_before.strip().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 4, "L0 应逐事件记录 4 行")

        mon._shutdown_rollup()   # no-op
        mon.generate_report()    # 一次性最终报告
        with open(l0_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), content_before,
                             "L0 内容不得被关闭/报告链路修改")

    def test_explicit_false_overrides_tuning_enabled(self):
        """开关优先级：显式 enable_rollup=False 覆盖 tuning 的 enabled=true。"""
        with mock.patch(
                "observer_core.judgment.tuning_loader.TuningLoader.load",
                return_value={"rollup": {"enabled": True}}):
            mon = MonitorDaemon(output_dir=self.tmpdir, use_ebpf=False,
                                enable_rollup=False)
        self.assertFalse(mon._rollup_enabled)
        self.assertIsNone(mon._report_cache)
        mon._audit_logger.start_scenario("override_test")
        mon.process_event(_make_raw(1))
        self.assertEqual(mon._stats["total"], 1)

    def test_production_mode_artifacts_vs_test_mode(self):
        """生产模式（默认）产生分层产物；test_report 模式零 cache 产物。"""
        prod_dir = tempfile.mkdtemp(prefix="prod_mode_")
        try:
            patcher = mock.patch(
                "observer_core.audit.report_cache."
                "ReportCacheManager.start_auto",
                new=_noop_start_auto)
            patcher.start()
            prod = MonitorDaemon(output_dir=prod_dir, use_ebpf=False)
            prod._audit_logger.start_scenario("prod_rollup")
            self.assertTrue(prod._rollup_enabled,
                            "默认应读 tuning.yaml rollup.enabled=true")
            for i in range(3):
                prod.process_event(_make_raw(i))
            prod._shutdown_rollup()
            l3_dir = os.path.join(prod_dir, "cache", "l3")
            self.assertTrue(os.path.exists(l3_dir), "生产模式应有 L3 产物目录")
            l3_files = [f for f in os.listdir(l3_dir)
                        if f.startswith("l3_")]
            self.assertTrue(l3_files, "优雅停止应生成 L3 天级产物")
        finally:
            patcher.stop()
            shutil.rmtree(prod_dir, ignore_errors=True)

        # 同量事件的 test_report 模式：零 cache 产物
        mon = self._new_monitor(enable_rollup=False)
        for i in range(3):
            mon.process_event(_make_raw(i))
        mon._shutdown_rollup()
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, "cache")))

    def test_cli_no_rollup_flag_disables_rollup(self):
        """CLI --no-rollup → run_monitor 收到 enable_rollup=False。"""
        import monitor_daemon
        with mock.patch.object(
                sys, "argv",
                ["monitor_daemon.py", "--no-rollup",
                 "--output", self.tmpdir]):
            with mock.patch("monitor_daemon.run_monitor") as run_mock:
                monitor_daemon.main()
        self.assertTrue(run_mock.called)
        self.assertIs(run_mock.call_args.kwargs["enable_rollup"], False)


if __name__ == "__main__":
    unittest.main()
