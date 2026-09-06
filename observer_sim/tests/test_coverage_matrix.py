# -*- coding: utf-8 -*-
"""
test_coverage_matrix.py — P2-3 双路径覆盖矩阵单测

对应计划文档《监测与拦截解耦双路径_开发落地计划.md》P2-3：
`collector/mcp_report_collector.py` 增加 build_coverage_matrix
（工具 × 通道 × 状态），report_exporter 渲染「双路径覆盖矩阵」
报告小节，monitoring_summary.json 增加 coverage_matrix 字段。

测试内容:
1. 不可核对: 三源留痕缺失 → checked=False + 三通道 unavailable
2. 全观测: 申报+pre+post 均有 + 快照可用 → 四通道 covered
3. Bash 盲区补位: pre=0、post>0 → hook_pre=uncovered / hook_post=covered
4. 监测盲区: 申报有、hook 双无 → uncovered
5. over_observed: hook 观测但申报未报 → mcp_report=uncovered
6. 快照未启用/不可用 → snapshot 整列 unavailable
7. counts 按 analyze_hook_coverage status 汇总
8. 渲染: None/不可核对/表格符号/汇总/不可核对通道
9. 报告小节写入 + 幂等
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from collector.mcp_report_collector import (analyze_hook_coverage,
                                            build_coverage_matrix)
from observer_core.audit.report_exporter import (
    ReportExporter, render_coverage_matrix_md)


def _report(event_id, tool_name, ts=1718092800000):
    return {
        "type": "report_tool_call",
        "event_id": event_id,
        "received_at_ms": ts,
        "payload": {"agent_id": "workbuddy", "tool_name": tool_name,
                    "tool_args": {}, "session_id": "sess-1",
                    "timestamp_ms": ts},
    }


def _pre(tool_name, decision="allow", gate_error=False):
    return {
        "timestamp": "2026-09-05T15:11:10.123",
        "event": "pre_tool_use",
        "session_id": "uuid-1",
        "tool_name": tool_name,
        "cwd": "C:/tmp",
        "tool_input": {},
        "target": None,
        "decision": decision,
        "gate_error": gate_error,
        "reason": "",
    }


def _post(tool_name):
    return {
        "timestamp": "2026-09-05T15:11:11.123",
        "event": "post_tool_use",
        "session_id": "uuid-1",
        "tool_name": tool_name,
        "cwd": "C:/tmp",
        "tool_input": {},
        "tool_response": "",
        "target": None,
        "protected": False,
        "gate_error": False,
        "reason": "",
    }


def _write_jsonl(path, objs):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for o in objs:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    return path


def _tmp():
    """临时三处留痕路径（模块级，供所有测试类共用）。"""
    base = tempfile.mkdtemp(prefix="cov_matrix_")
    return {
        "reports": os.path.join(base, "mcp_reports.jsonl"),
        "pre": os.path.join(base, "hook_decisions.jsonl"),
        "post": os.path.join(base, "hook_post_decisions.jsonl"),
    }


def _snap(available=True):
    return {"enabled": True, "available": available, "ticks": 1,
            "interval_s": 1, "findings": [], "unavailable": [],
            "note": ""}


class TestBuildCoverageMatrix(unittest.TestCase):
    """矩阵构建：通道状态与可用性口径"""

    def test_no_sources_unavailable(self):
        d = _tmp()  # 不写任何留痕文件
        hc = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        m = build_coverage_matrix(hc, _snap(True))
        self.assertFalse(m["checked"])
        self.assertIn("mcp_report", m["unavailable_channels"])
        self.assertIn("hook_pre", m["unavailable_channels"])
        self.assertIn("hook_post", m["unavailable_channels"])
        self.assertEqual(m["tools"], {})
        self.assertIn("不可核对", m["reason"])

    def test_full_observation_covered(self):
        d = _tmp()
        _write_jsonl(d["reports"],
                     [_report("e1", "Read"), _report("e2", "Write")])
        _write_jsonl(d["pre"], [_pre("Read"), _pre("Write")])
        _write_jsonl(d["post"], [_post("Read"), _post("Write")])
        hc = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        m = build_coverage_matrix(hc, _snap(True))
        self.assertTrue(m["checked"])
        for tool in ("Read", "Write"):
            row = m["tools"][tool]
            self.assertEqual(row["mcp_report"], "covered")
            self.assertEqual(row["hook_pre"], "covered")
            self.assertEqual(row["hook_post"], "covered")
            self.assertEqual(row["snapshot"], "covered")
        self.assertEqual(m["unavailable_channels"], [])
        self.assertEqual(m["counts"]["covered"], 2)

    def test_post_covered_blindspot(self):
        d = _tmp()
        _write_jsonl(d["reports"], [_report("e1", "Bash")])
        _write_jsonl(d["pre"], [])
        _write_jsonl(d["post"], [_post("Bash")])
        hc = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        m = build_coverage_matrix(hc, _snap(True))
        row = m["tools"]["Bash"]
        self.assertEqual(row["hook_pre"], "uncovered")
        self.assertEqual(row["hook_post"], "covered")
        self.assertEqual(row["mcp_report"], "covered")
        self.assertEqual(m["counts"]["post_covered"], 1)

    def test_uncovered_blank_spot(self):
        d = _tmp()
        _write_jsonl(d["reports"], [_report("e1", "Edit")])
        _write_jsonl(d["pre"], [])
        _write_jsonl(d["post"], [])
        hc = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        m = build_coverage_matrix(hc, _snap(True))
        row = m["tools"]["Edit"]
        self.assertEqual(row["hook_pre"], "uncovered")
        self.assertEqual(row["hook_post"], "uncovered")
        self.assertEqual(m["counts"]["uncovered"], 1)

    def test_over_observed_reported_missing(self):
        d = _tmp()
        _write_jsonl(d["reports"], [])
        _write_jsonl(d["pre"], [_pre("Glob")])
        _write_jsonl(d["post"], [])
        hc = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        m = build_coverage_matrix(hc, _snap(True))
        row = m["tools"]["Glob"]
        self.assertEqual(row["mcp_report"], "uncovered")
        self.assertEqual(row["hook_pre"], "covered")
        self.assertEqual(m["counts"]["over_observed"], 1)

    def test_snapshot_not_enabled_unavailable(self):
        d = _tmp()
        _write_jsonl(d["reports"], [_report("e1", "Read")])
        _write_jsonl(d["pre"], [_pre("Read")])
        _write_jsonl(d["post"], [_post("Read")])
        hc = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        m = build_coverage_matrix(hc, None)
        self.assertIn("snapshot", m["unavailable_channels"])
        self.assertEqual(m["tools"]["Read"]["snapshot"], "unavailable")

    def test_snapshot_unavailable_failed(self):
        d = _tmp()
        _write_jsonl(d["reports"], [_report("e1", "Read")])
        _write_jsonl(d["pre"], [_pre("Read")])
        _write_jsonl(d["post"], [_post("Read")])
        hc = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        m = build_coverage_matrix(hc, _snap(False))
        self.assertIn("snapshot", m["unavailable_channels"])
        self.assertEqual(m["tools"]["Read"]["snapshot"], "unavailable")

    def test_empty_tool_name_skipped(self):
        """历史 gate_error 条目 tool_name 为空 → 矩阵跳过空工具名行。"""
        hc = {
            "checked": True,
            "reason": "",
            "tools": {
                "": {"reported": 0, "hook_pre": 1, "hook_post": 0,
                     "status": "over_observed"},
                "Read": {"reported": 1, "hook_pre": 1, "hook_post": 1,
                        "status": "covered"},
            },
        }
        m = build_coverage_matrix(hc, _snap(True))
        self.assertNotIn("", m["tools"])
        self.assertEqual(list(m["tools"]), ["Read"])
        self.assertEqual(m["counts"], {"covered": 1})


class TestRenderCoverageMatrixMd(unittest.TestCase):
    """报告小节渲染"""

    def test_none_not_executed(self):
        text = render_coverage_matrix_md(None)
        self.assertIn("## 双路径覆盖矩阵", text)
        self.assertIn("未执行", text)

    def test_unchecked_unavailable(self):
        m = {"checked": False, "reason": "无留痕文件",
             "unavailable_channels": ["mcp_report", "hook_pre",
                                      "hook_post"],
             "tools": {}, "counts": {}, "note": "note-x"}
        text = render_coverage_matrix_md(m)
        self.assertIn("不可核对", text)
        self.assertIn("无留痕文件", text)

    def test_table_rendered(self):
        m = {
            "checked": True,
            "unavailable_channels": [],
            "tools": {
                "Bash": {"mcp_report": "covered", "hook_pre": "uncovered",
                         "hook_post": "covered", "snapshot": "covered"},
            },
            "counts": {"post_covered": 1},
            "note": "note-x",
        }
        text = render_coverage_matrix_md(m)
        self.assertIn("| 工具 | 申报 | hook执行前 | hook执行后 | 快照兜底 |",
                      text)
        self.assertIn("✅", text)
        self.assertIn("❌", text)
        self.assertIn("工具覆盖状态汇总", text)
        self.assertIn("post_covered 1", text)

    def test_unavailable_glyph_and_channels(self):
        m = {
            "checked": True,
            "unavailable_channels": ["snapshot"],
            "tools": {"Read": {"mcp_report": "covered",
                               "hook_pre": "covered",
                               "hook_post": "covered",
                               "snapshot": "unavailable"}},
            "counts": {"covered": 1},
            "note": "note-x",
        }
        text = render_coverage_matrix_md(m)
        self.assertIn("⚠️", text)
        self.assertIn("- **不可核对通道**: snapshot", text)

    def test_empty_tool_name_row_skipped(self):
        """渲染防御：空工具名行不渲染。"""
        m = {
            "checked": True,
            "unavailable_channels": [],
            "tools": {
                "": {"mcp_report": "uncovered", "hook_pre": "covered",
                     "hook_post": "covered", "snapshot": "covered"},
                "Read": {"mcp_report": "covered", "hook_pre": "covered",
                        "hook_post": "covered", "snapshot": "covered"},
            },
            "counts": {"covered": 1},
            "note": "note-x",
        }
        text = render_coverage_matrix_md(m)
        self.assertNotIn("|  | ❌ |", text)
        self.assertIn("| Read |", text)


class TestAppendCoverageMatrixSection(unittest.TestCase):
    """报告小节写入与幂等"""

    def test_append_and_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="cov_matrix_") as tmp:
            rpt = os.path.join(tmp, "report.md")
            with open(rpt, "w", encoding="utf-8") as f:
                f.write("# 标题\n\n正文\n\n---\n\n页脚\n")
            m = {"checked": True, "unavailable_channels": [],
                 "tools": {"Read": {"mcp_report": "covered",
                                    "hook_pre": "covered",
                                    "hook_post": "covered",
                                    "snapshot": "covered"}},
                 "counts": {"covered": 1}, "note": "note-x"}
            exporter = ReportExporter(output_dir=tmp)
            self.assertTrue(exporter.append_coverage_matrix_section(rpt, m))
            with open(rpt, encoding="utf-8") as f:
                content = f.read()
            self.assertEqual(content.count("## 双路径覆盖矩阵"), 1)
            # 幂等：再写不重复
            self.assertTrue(exporter.append_coverage_matrix_section(rpt, m))
            with open(rpt, encoding="utf-8") as f:
                content2 = f.read()
            self.assertEqual(content2.count("## 双路径覆盖矩阵"), 1)
            self.assertEqual(content2, content)


if __name__ == "__main__":
    unittest.main()
