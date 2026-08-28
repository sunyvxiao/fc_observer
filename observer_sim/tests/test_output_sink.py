"""
test_output_sink.py — U3 IOutputSink 输出抽象测试

测试内容:
1. begin_run 创建 run 目录结构 + 按天审计文件名（audit_{scenario_id}_{YYYYMMDD}.jsonl）
2. finalize 产出报告 .md / 图谱 .json / 审计 .jsonl（block=0 不写证据）
3. block>0 时写阻断证据 evidence_{scenario_id}.json；write_evidence=False 不写
4. tolerate_export_error 容错（报告失败不中断图谱输出，main.py 原行为）
5. save_baseline n01 前缀判断
6. use_run_dirs=False monitor 模式固定目录（无时间戳 run 目录）
"""

import os
import sys
import json
import tempfile
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models.event import RawEvent, NormalizedEvent
from models.virtual_clock import VirtualClock
from observer_core.audit.behavior_graph import BehaviorGraph
from observer_core.audit.audit_logger import AuditLogger
from observer_core.audit.report_exporter import ReportExporter
from observer_core.audit.output_sink import DefaultOutputSink
from observer_core.blocking.blocking_coordinator import BlockingCoordinator


def _make_raw_event(event_id="evt-1", agent_id="agent-a", event_type="exec",
                    timestamp_ns=1718092800000000000, pid=10001,
                    executable="/usr/bin/python3", arguments=None,
                    file_path=None, file_op=None,
                    remote_addr=None, remote_port=None):
    """创建测试用 RawEvent"""
    return RawEvent(
        event_id=event_id,
        timestamp_ns=timestamp_ns,
        event_type=event_type,
        pid=pid,
        ppid=1,
        agent_id=agent_id,
        agent_framework="LangChain",
        executable=executable,
        arguments=arguments,
        file_path=file_path,
        file_op=file_op,
        remote_addr=remote_addr,
        remote_port=remote_port,
    )


def _make_normalized_event(event_id="evt-1", agent_id="agent-a",
                           event_type="exec", **kwargs):
    """创建测试用 NormalizedEvent"""
    raw = _make_raw_event(event_id=event_id, agent_id=agent_id,
                          event_type=event_type, **kwargs)
    return NormalizedEvent(raw=raw)


def _make_sink(tmpdir, blocking_coord=None, baseline_checker=None,
               use_run_dirs=True, report_exporter=None):
    """构造 DefaultOutputSink 及注入的组件"""
    audit_logger = AuditLogger(output_dir=str(tmpdir))
    exporter = report_exporter or ReportExporter(output_dir=str(tmpdir))
    graph = BehaviorGraph()
    sink = DefaultOutputSink(
        base_output_dir=str(tmpdir),
        audit_logger=audit_logger,
        report_exporter=exporter,
        behavior_graph=graph,
        blocking_coord=blocking_coord,
        baseline_checker=baseline_checker,
        use_run_dirs=use_run_dirs,
    )
    return sink, audit_logger, exporter, graph


def _meta(scenario_id, name=None):
    return {
        "id": scenario_id,
        "name": name or f"{scenario_id} 测试场景",
        "description": "desc",
        "expected_result": "expect",
    }


class TestOutputSink(unittest.TestCase):
    """U3 IOutputSink 输出抽象"""

    def test_begin_run_creates_run_dir_and_audit_file(self):
        """begin_run：run 目录 + 子目录 + 按天审计文件名"""
        with tempfile.TemporaryDirectory() as tmp:
            sink, audit_logger, exporter, _ = _make_sink(tmp)
            run_mgr = sink.begin_run("normal", "n01-sink-test")
            self.assertIsNotNone(run_mgr)
            # run 目录: {tmp}/reports/normal/n01-sink-test/{ts}/
            base = os.path.join(tmp, "reports", "normal", "n01-sink-test")
            self.assertTrue(run_mgr.run_dir.startswith(base))
            self.assertTrue(os.path.isdir(run_mgr.run_dir))
            self.assertTrue(os.path.isdir(run_mgr.audit_dir))
            self.assertTrue(os.path.isdir(run_mgr.graph_dir))
            self.assertTrue(os.path.isdir(run_mgr.evidence_dir))
            # 报告导出目录指向 run_dir
            self.assertEqual(exporter._reports_dir, run_mgr.run_dir)
            # 审计文件: audit_{scenario_id}_{YYYYMMDD}.jsonl
            day = datetime.now().strftime("%Y%m%d")
            expected = os.path.join(
                run_mgr.audit_dir, f"audit_n01-sink-test_{day}.jsonl")
            self.assertEqual(audit_logger.current_file, expected)
            self.assertTrue(os.path.exists(expected))
            audit_logger.close()

    def test_finalize_produces_report_graph_audit(self):
        """finalize：报告 .md + 图谱 .json + 审计 .jsonl；block=0 无证据"""
        with tempfile.TemporaryDirectory() as tmp:
            sink, audit_logger, _, graph = _make_sink(tmp)
            run_mgr = sink.begin_run("normal", "n02-sink")
            audit_logger.log_event(
                _make_normalized_event(event_id="evt-1", executable="/usr/bin/python3",
                                       arguments=["-c", "print(1)"]))
            audit_logger.log_event(
                _make_normalized_event(event_id="evt-2", executable="/bin/ls",
                                       arguments=["-la"]))
            audit_logger.close()

            outputs = sink.finalize(_meta("n02-sink"), {"block": 0})
            # 报告 .md 在 run_dir 下
            self.assertIsNotNone(outputs["report_path"])
            self.assertTrue(outputs["report_path"].endswith(".md"))
            self.assertTrue(os.path.isfile(outputs["report_path"]))
            self.assertEqual(os.path.dirname(outputs["report_path"]), run_mgr.run_dir)
            # 图谱 .json 在 graph_dir 下
            self.assertEqual(outputs["graph_path"],
                             run_mgr.graph_filepath("graph_n02-sink.json"))
            self.assertTrue(os.path.isfile(outputs["graph_path"]))
            # 图谱文件为合法 JSON 结构（含 nodes/edges/agent_summaries 键）
            with open(outputs["graph_path"], encoding="utf-8") as f:
                saved_file = json.load(f)
            for key in ("nodes", "edges", "agent_summaries"):
                self.assertIn(key, saved_file)
            # 审计 .jsonl 2 行
            self.assertTrue(outputs["audit_file"].endswith(".jsonl"))
            with open(outputs["audit_file"], encoding="utf-8") as f:
                lines = [ln for ln in f if ln.strip()]
            self.assertEqual(len(lines), 2)
            # block=0 → 无证据
            self.assertIsNone(outputs["evidence_path"])
            self.assertFalse(
                os.path.exists(run_mgr.evidence_filepath("evidence_n02-sink.json")))

    def test_finalize_writes_evidence_when_block(self):
        """block>0 → 写阻断证据 evidence_{scenario_id}.json"""
        with tempfile.TemporaryDirectory() as tmp:
            blocking = BlockingCoordinator(
                clock=VirtualClock(start_ns=1718092800000000000), output_dir=tmp)
            sink, audit_logger, _, _ = _make_sink(tmp, blocking_coord=blocking)
            run_mgr = sink.begin_run("anomalous", "a01-sink")
            audit_logger.close()

            outputs = sink.finalize(_meta("a01-sink"), {"block": 1})
            expected = run_mgr.evidence_filepath("evidence_a01-sink.json")
            self.assertEqual(outputs["evidence_path"], expected)
            self.assertTrue(os.path.isfile(expected))
            with open(expected, encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("statistics", data)
            self.assertIn("events", data)

    def test_write_evidence_disabled(self):
        """write_evidence=False（main/monitor 原行为）→ block>0 也不写证据"""
        with tempfile.TemporaryDirectory() as tmp:
            blocking = BlockingCoordinator(
                clock=VirtualClock(start_ns=1718092800000000000), output_dir=tmp)
            sink, audit_logger, _, _ = _make_sink(tmp, blocking_coord=blocking)
            run_mgr = sink.begin_run("anomalous", "a02-sink")
            audit_logger.close()

            outputs = sink.finalize(_meta("a02-sink"), {"block": 1},
                                    write_evidence=False)
            self.assertIsNone(outputs["evidence_path"])
            self.assertFalse(
                os.path.exists(run_mgr.evidence_filepath("evidence_a02-sink.json")))

    def test_tolerate_export_error(self):
        """tolerate_export_error=True：报告失败置 None 但图谱仍保存（main 原行为）"""

        class FailingExporter:
            def __init__(self):
                self._reports_dir = None

            def set_output_dir(self, output_dir):
                self._reports_dir = output_dir

            def export_scenario_report(self, **kwargs):
                raise RuntimeError("boom")

        with tempfile.TemporaryDirectory() as tmp:
            sink, audit_logger, _, _ = _make_sink(
                tmp, report_exporter=FailingExporter())
            sink.begin_run("normal", "n03-sink")
            audit_logger.close()

            outputs = sink.finalize(_meta("n03-sink"), {"block": 0},
                                    tolerate_export_error=True)
            self.assertIsNone(outputs["report_path"])
            self.assertTrue(os.path.isfile(outputs["graph_path"]))

    def test_export_error_raises_without_tolerate(self):
        """tolerate_export_error=False（app/demo 行为）→ 导出失败冒泡"""
        class FailingExporter:
            def __init__(self):
                self._reports_dir = None

            def set_output_dir(self, output_dir):
                self._reports_dir = output_dir

            def export_scenario_report(self, **kwargs):
                raise RuntimeError("boom")

        with tempfile.TemporaryDirectory() as tmp:
            sink, audit_logger, _, _ = _make_sink(
                tmp, report_exporter=FailingExporter())
            sink.begin_run("normal", "n04-sink")
            audit_logger.close()
            with self.assertRaises(RuntimeError):
                sink.finalize(_meta("n04-sink"), {"block": 0})

    def test_save_baseline_n01_prefix(self):
        """save_baseline：仅 n01 前缀保存；无 baseline_checker 返回 None"""
        class RecordingBaselineChecker:
            def __init__(self):
                self.calls = []

            def save_baseline(self, path):
                self.calls.append(path)

        with tempfile.TemporaryDirectory() as tmp:
            baseline = RecordingBaselineChecker()
            sink, audit_logger, _, _ = _make_sink(tmp, baseline_checker=baseline)
            sink.begin_run("normal", "n01-sink")
            audit_logger.close()

            path = sink.save_baseline("n01-sink")
            self.assertEqual(len(baseline.calls), 1)
            self.assertTrue(path.endswith("baseline_n01-sink.json"))
            self.assertTrue(os.path.isdir(os.path.dirname(path)))
            # 非 n01 前缀 → 不保存
            self.assertIsNone(sink.save_baseline("a02-sink"))
            self.assertEqual(len(baseline.calls), 1)

            # 未注入 baseline_checker → None
            sink2, audit_logger2, _, _ = _make_sink(tmp)
            sink2.begin_run("normal", "n01-sink2")
            audit_logger2.close()
            self.assertIsNone(sink2.save_baseline("n01-sink2"))

    def test_monitor_mode_fixed_dirs(self):
        """use_run_dirs=False（monitor 原行为）：固定目录，无时间戳 run 目录"""
        with tempfile.TemporaryDirectory() as tmp:
            sink, audit_logger, _, _ = _make_sink(tmp, use_run_dirs=False)
            run_mgr = sink.begin_run("unknown", "demo_monitoring")
            self.assertIsNone(run_mgr)
            # 审计目录固定 {tmp}/audit/
            day = datetime.now().strftime("%Y%m%d")
            self.assertEqual(
                audit_logger.current_file,
                os.path.join(tmp, "audit", f"audit_demo_monitoring_{day}.jsonl"))
            audit_logger.close()

            outputs = sink.finalize(
                _meta("demo_monitoring", "实时监测"), {"block": 0})
            # 图谱固定 {tmp}/graphs/
            self.assertEqual(
                outputs["graph_path"],
                os.path.join(tmp, "graphs", "graph_demo_monitoring.json"))
            self.assertTrue(os.path.isfile(outputs["graph_path"]))
            # 报告在 {tmp}/reports/ 下（无时间戳子目录）
            self.assertEqual(os.path.dirname(outputs["report_path"]),
                             os.path.join(tmp, "reports"))
            self.assertTrue(os.path.isfile(outputs["report_path"]))
            self.assertIsNone(outputs["evidence_path"])


if __name__ == "__main__":
    unittest.main()
