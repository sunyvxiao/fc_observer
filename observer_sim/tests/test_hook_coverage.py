# -*- coding: utf-8 -*-
"""
test_hook_coverage.py — P1-2 申报完整性核对 + 覆盖置信度单测

对应计划文档《监测与拦截解耦双路径_开发落地计划.md》P1-2：
`collector/mcp_report_collector.py` 增加「hook 事件数 vs 申报事件数」
比对，输出 coverage_confidence（依赖 P0-5 留痕格式）。

测试内容:
1. 正常比对: 申报与 hook 执行前裁决一致 → covered / 置信度高
2. Bash 盲区: 申报有、PreToolUse 0、PostToolUse 补位 → post_covered
   + bash_blindspot_note（TC-05「申报完整性核对报告 Bash 未覆盖」）
3. 损坏行容错: jsonl 半行损坏跳过计数（P1-1 并发损坏实测坑）
4. 无留痕文件 → checked=False + reason
5. deny 未申报 → unreported_denies + 置信度低（疑似漏报）
6. partial 覆盖 → 置信度中
7. uncovered 监测盲区 → 置信度低
8. 双通道无事件 → 置信度低 + 原因
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from collector.mcp_report_collector import analyze_hook_coverage


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
            if o is None:
                f.write('{"timestamp": "2026-09-05T14:58:02.680", '
                        '"event": "pre_tool_use", "session_id": "u"\n')  # 半行损坏
            else:
                f.write(json.dumps(o, ensure_ascii=False) + "\n")
    return path


def _tmp():
    """临时三处留痕路径（模块级，供所有测试类共用）。"""
    import tempfile
    base = tempfile.mkdtemp(prefix="hook_cov_")
    return {
        "reports": os.path.join(base, "mcp_reports.jsonl"),
        "pre": os.path.join(base, "hook_decisions.jsonl"),
        "post": os.path.join(base, "hook_post_decisions.jsonl"),
    }


class TestHookCoverageBasic(unittest.TestCase):
    """正常比对与置信度分档"""

    def test_covered_high_confidence(self):
        d = _tmp()
        reports = [_report("e1", "Read"), _report("e2", "Write"),
                   _report("e3", "Glob")]
        _write_jsonl(d["reports"], reports)
        _write_jsonl(d["pre"], [_pre("Read"), _pre("Write"), _pre("Glob")])
        _write_jsonl(d["post"], [_post("Read"), _post("Write"), _post("Glob")])
        a = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        self.assertTrue(a["checked"])
        self.assertEqual(a["reported_tool_calls"], 3)
        self.assertEqual(a["hook_pre_events"], 3)
        self.assertEqual(a["coverage_confidence"], "高")
        for tool in ("Read", "Write", "Glob"):
            self.assertEqual(a["tools"][tool]["status"], "covered")
            self.assertAlmostEqual(a["tools"][tool]["pre_coverage"], 1.0)

    def test_partial_medium_confidence(self):
        d = _tmp()
        _write_jsonl(d["reports"], [_report(f"e{i}", "Read")
                                    for i in range(5)])
        _write_jsonl(d["pre"], [_pre("Read"), _pre("Read")])
        a = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        self.assertEqual(a["tools"]["Read"]["status"], "partial")
        self.assertAlmostEqual(a["tools"]["Read"]["pre_coverage"], 0.4)
        self.assertEqual(a["coverage_confidence"], "中")

    def test_uncovered_blank_spot_low_confidence(self):
        d = _tmp()
        _write_jsonl(d["reports"], [_report("e1", "Edit"),
                                    _report("e2", "Edit")])
        _write_jsonl(d["pre"], [])
        a = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        self.assertEqual(a["tools"]["Edit"]["status"], "uncovered")
        self.assertTrue(a["tools"]["Edit"]["blindspot"])
        self.assertEqual(a["coverage_confidence"], "低")
        self.assertIn("监测盲区", a["confidence_reason"])


class TestHookCoverageBashBlindspot(unittest.TestCase):
    """TC-05: Bash PreToolUse 盲区 + PostToolUse 审计补位"""

    def test_bash_post_covered_and_note(self):
        d = _tmp()
        _write_jsonl(d["reports"], [_report(f"b{i}", "Bash")
                                    for i in range(3)])
        _write_jsonl(d["pre"], [])
        _write_jsonl(d["post"], [_post("Bash"), _post("Bash"), _post("Bash")])
        a = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        t = a["tools"]["Bash"]
        self.assertEqual(t["status"], "post_covered")
        self.assertTrue(t["blindspot"])
        self.assertEqual(t["hook_post"], 3)
        self.assertIn("Bash 未覆盖", a["bash_blindspot_note"])
        self.assertIn("PostToolUse 审计补位 3 条", a["bash_blindspot_note"])
        self.assertEqual(a["coverage_confidence"], "中")

    def test_bash_no_post_audit_alert(self):
        d = _tmp()
        _write_jsonl(d["reports"], [_report("b1", "Bash")])
        _write_jsonl(d["pre"], [])
        a = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        self.assertEqual(a["tools"]["Bash"]["status"], "uncovered")
        self.assertIn("监测盲区告警", a["bash_blindspot_note"])
        self.assertEqual(a["coverage_confidence"], "低")


class TestHookCoverageRobustness(unittest.TestCase):
    """损坏行 / 缺文件 / 缺报 / 无数据容错"""

    def test_corrupt_lines_tolerated(self):
        d = _tmp()
        _write_jsonl(d["reports"], [_report("e1", "Read")])
        # pre 留痕含 1 行半行损坏（P1-1 并发损坏实测坑的历史证据）
        _write_jsonl(d["pre"], [_pre("Read"), None])
        a = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        self.assertTrue(a["checked"])
        self.assertEqual(a["hook_pre_events"], 1)  # 损坏行跳过
        self.assertEqual(sum(a["corrupt_lines"].values()), 1)

    def test_no_files_unchecked(self):
        a = analyze_hook_coverage("C:/nonexist_reports.jsonl",
                                  "C:/nonexist_pre.jsonl",
                                  "C:/nonexist_post.jsonl")
        self.assertFalse(a["checked"])
        self.assertEqual(a["coverage_confidence"], "低")
        self.assertIn("不可核对", a["reason"])

    def test_deny_unreported_low_confidence(self):
        d = _tmp()
        _write_jsonl(d["reports"], [_report("e1", "Read")])
        _write_jsonl(d["pre"], [_pre("Read"), _pre("Write", decision="deny")])
        a = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        self.assertEqual(a["hook_deny_count"], 1)
        self.assertEqual(len(a["unreported_denies"]), 1)
        self.assertEqual(a["unreported_denies"][0]["tool_name"], "Write")
        self.assertEqual(a["coverage_confidence"], "低")
        self.assertIn("漏报", a["confidence_reason"])
        # Write 在 hook 观测但申报未报 → over_observed
        self.assertEqual(a["tools"]["Write"]["status"], "over_observed")

    def test_over_observed_low_confidence(self):
        d = _tmp()
        _write_jsonl(d["reports"], [])
        _write_jsonl(d["pre"], [_pre("Read")])
        a = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        self.assertEqual(a["tools"]["Read"]["status"], "over_observed")
        self.assertEqual(a["coverage_confidence"], "低")

    def test_both_channels_empty_low(self):
        d = _tmp()
        _write_jsonl(d["reports"], [])
        _write_jsonl(d["pre"], [])
        a = analyze_hook_coverage(d["reports"], d["pre"], d["post"])
        self.assertTrue(a["checked"])
        self.assertEqual(a["coverage_confidence"], "低")
        self.assertIn("双通道均无事件", a["confidence_reason"])


if __name__ == "__main__":
    unittest.main()
