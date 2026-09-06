# -*- coding: utf-8 -*-
"""
test_consistency_checker.py — P2-2 双源一致性核对单测

对应计划文档《监测与拦截解耦双路径_开发落地计划.md》P2-2：
新建 `observer_sim/observer_core/monitoring/consistency_checker.py`——
四源留痕（申报 / hook 执行前裁决 / hook 执行后审计 / 快照校验）
交叉比对，产出三类不一致告警（仅告警、不拦截）。验收 TC-06/TC-11。

测试内容:
1. 维度① unreported_hook_deny: deny 无对应申报 → issue；
   有匹配申报 → 无 issue；hook notify 申报不自证（防自证）；
   无 session 的 deny 不虚构比对
2. 维度② hook_blindspot_change: finding 路径 hook 两轨均无 → issue；
   hook 有观测 → 无 issue；unreported_file_access 路径同样核对
3. 维度③ report_snapshot_conflict: write 类申报受保护路径无快照
   变化且 hook 无裁决 → issue；快照有变化 / hook 有裁决 → 无 issue；
   read 类申报不核对；受保护目录外不核对
4. P2-4 降级: 源缺失 → 各维度独立 unavailable，不中断其余维度；
   未声明受保护目录 → 仅维度③ unavailable
5. 健壮性: 损坏行容错计数；留痕落盘（issue/unavailable 双类型）；
   无 issue 且无 unavailable 不落盘；summary sources 计数
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from observer_core.monitoring.consistency_checker import (  # noqa: E402
    ConsistencyChecker)


def _write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _report(tool_name, tool_args, session_id="sess-1"):
    return {"type": "report_tool_call", "payload": {
        "tool_name": tool_name, "tool_args": tool_args,
        "session_id": session_id}}


def _pre_deny(target, session_id="sess-1", tool_name="write_file"):
    return {"event": "pre_tool_use", "decision": "deny",
            "target": target, "session_id": session_id,
            "tool_name": tool_name, "timestamp": "2026-07-31T10:00:00Z"}


class ConsistencyTestBase(unittest.TestCase):
    """共用临时目录与四源留痕写入。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = self.tmp.name
        self.protected = os.path.join(self.tmp.name, "protected")
        self.reports = os.path.join(self.out, "mcp_reports.jsonl")
        self.pre = os.path.join(self.out, "hook_decisions.jsonl")
        self.post = os.path.join(self.out, "hook_post_decisions.jsonl")
        self.findings = os.path.join(self.out, "snapshot_checker.jsonl")
        self.changes = os.path.join(self.out, "snapshot_changes.jsonl")

    def _checker(self, protected_dirs=None):
        return ConsistencyChecker(
            output_dir=self.out,
            reports_path=self.reports,
            pre_decisions_path=self.pre,
            post_decisions_path=self.post,
            snapshot_findings_path=self.findings,
            snapshot_changes_path=self.changes,
            protected_dirs=protected_dirs
            if protected_dirs is not None else [self.protected],
        )

    def _run(self, protected_dirs=None):
        return self._checker(protected_dirs).finish()

    def _kinds(self, summary):
        return [i["kind"] for i in summary["issues"]]


class UnreportedHookDenyTest(ConsistencyTestBase):
    """维度① 申报未报但 hook 拦截。"""

    def test_deny_without_agent_report(self):
        _write_jsonl(self.pre, [_pre_deny(
            os.path.join(self.protected, "secret.txt"))])
        s = self._run()
        self.assertIn("unreported_hook_deny", self._kinds(s))
        self.assertEqual(s["issue_counts"]["unreported_hook_deny"], 1)

    def test_deny_with_matching_report(self):
        _write_jsonl(self.pre, [_pre_deny(
            os.path.join(self.protected, "secret.txt"))])
        _write_jsonl(self.reports, [_report(
            "read_file", {"file_path":
                          os.path.join(self.protected, "secret.txt")})])
        s = self._run()
        self.assertNotIn("unreported_hook_deny", self._kinds(s))

    def test_hook_notify_report_not_self_certifying(self):
        # hook notify 申报（tool_args.hook_phase 标记）不计入 Agent 申报，
        # 防自证：deny 仍判定为「申报未报」。
        _write_jsonl(self.pre, [_pre_deny(
            os.path.join(self.protected, "secret.txt"))])
        _write_jsonl(self.reports, [_report(
            "read_file", {"file_path":
                          os.path.join(self.protected, "secret.txt"),
                          "hook_phase": "post"})])
        s = self._run()
        self.assertIn("unreported_hook_deny", self._kinds(s))

    def test_deny_without_session_skipped(self):
        _write_jsonl(self.pre, [{
            "event": "pre_tool_use", "decision": "deny",
            "target": os.path.join(self.protected, "secret.txt")}])
        s = self._run()
        self.assertNotIn("unreported_hook_deny", self._kinds(s))

    def test_allow_decision_not_checked(self):
        _write_jsonl(self.pre, [{
            "event": "pre_tool_use", "decision": "allow",
            "target": os.path.join(self.protected, "secret.txt"),
            "session_id": "sess-1"}])
        s = self._run()
        self.assertNotIn("unreported_hook_deny", self._kinds(s))


class HookBlindspotTest(ConsistencyTestBase):
    """维度② hook 未触发但快照发现访问/变更。"""

    def test_finding_path_not_in_hook(self):
        p = os.path.join(self.protected, "secret.txt")
        _write_jsonl(self.findings, [{
            "type": "snapshot_checker_finding",
            "kind": "unreported_file_change",
            "changes": {"added": {p: {"size": 1}}}}])
        _write_jsonl(self.pre, [])  # hook 已部署但无裁决
        s = self._run()
        self.assertIn("hook_blindspot_change", self._kinds(s))
        self.assertEqual(s["issues"][0]["path"], p)

    def test_finding_path_in_hook_pre(self):
        p = os.path.join(self.protected, "secret.txt")
        _write_jsonl(self.findings, [{
            "type": "snapshot_checker_finding",
            "kind": "unreported_file_change",
            "changes": {"added": {p: {"size": 1}}}}])
        _write_jsonl(self.pre, [{
            "event": "pre_tool_use", "decision": "allow", "target": p,
            "session_id": "sess-1"}])
        s = self._run()
        self.assertNotIn("hook_blindspot_change", self._kinds(s))

    def test_access_finding_path_checked(self):
        p = os.path.join(self.protected, "secret.txt")
        _write_jsonl(self.findings, [{
            "type": "snapshot_checker_finding",
            "kind": "unreported_file_access",
            "accesses": [{"object_name": p}]}])
        _write_jsonl(self.pre, [])  # hook 已部署但无裁决
        s = self._run()
        self.assertIn("hook_blindspot_change", self._kinds(s))


class ReportSnapshotConflictTest(ConsistencyTestBase):
    """维度③ 申报与快照矛盾（仅 write 类申报）。"""

    def test_write_report_without_evidence(self):
        p = os.path.join(self.protected, "new.txt")
        _write_jsonl(self.reports, [_report(
            "write_file", {"file_path": p})])
        _write_jsonl(self.changes, [{
            "type": "snapshot_checker_change", "tick": 1,
            "changes": {}}])
        _write_jsonl(self.pre, [])  # hook 已部署但无裁决
        s = self._run()
        self.assertIn("report_snapshot_conflict", self._kinds(s))
        self.assertEqual(s["issues"][0]["path"], p)

    def test_write_report_with_snapshot_change(self):
        p = os.path.join(self.protected, "new.txt")
        _write_jsonl(self.reports, [_report(
            "write_file", {"file_path": p})])
        _write_jsonl(self.changes, [{
            "type": "snapshot_checker_change", "tick": 1,
            "changes": {"added": {p: {"size": 1}}}}])
        _write_jsonl(self.pre, [])  # hook 已部署但无裁决
        s = self._run()
        self.assertNotIn("report_snapshot_conflict", self._kinds(s))

    def test_write_report_with_hook_verdict(self):
        p = os.path.join(self.protected, "new.txt")
        _write_jsonl(self.reports, [_report(
            "write_file", {"file_path": p})])
        _write_jsonl(self.changes, [{
            "type": "snapshot_checker_change", "tick": 1,
            "changes": {}}])
        _write_jsonl(self.pre, [{
            "event": "pre_tool_use", "decision": "allow", "target": p,
            "session_id": "sess-1"}])
        s = self._run()
        self.assertNotIn("report_snapshot_conflict", self._kinds(s))

    def test_read_report_not_checked(self):
        p = os.path.join(self.protected, "secret.txt")
        _write_jsonl(self.reports, [_report(
            "read_file", {"file_path": p})])
        _write_jsonl(self.changes, [{
            "type": "snapshot_checker_change", "tick": 1,
            "changes": {}}])
        _write_jsonl(self.pre, [])  # hook 已部署但无裁决
        s = self._run()
        self.assertNotIn("report_snapshot_conflict", self._kinds(s))

    def test_outside_protected_dirs_not_checked(self):
        outside = os.path.join(self.tmp.name, "elsewhere", "x.txt")
        _write_jsonl(self.reports, [_report(
            "write_file", {"file_path": outside})])
        _write_jsonl(self.changes, [{
            "type": "snapshot_checker_change", "tick": 1,
            "changes": {}}])
        _write_jsonl(self.pre, [])  # hook 已部署但无裁决
        s = self._run()
        self.assertNotIn("report_snapshot_conflict", self._kinds(s))


class UnavailableDegradationTest(ConsistencyTestBase):
    """P2-4 各维度独立降级语义。"""

    def test_all_sources_missing_mark_unavailable(self):
        s = self._run()
        self.assertTrue(s["checked"])
        self.assertEqual(s["issues"], [])
        dims = {u["dimension"] for u in s["unavailable"]}
        self.assertEqual(dims, {"unreported_hook_deny",
                                "hook_blindspot_change",
                                "report_snapshot_conflict"})

    def test_no_protected_dirs_only_dim3_unavailable(self):
        p = os.path.join(self.protected, "secret.txt")
        p2 = os.path.join(self.protected, "secret2.txt")
        _write_jsonl(self.pre, [_pre_deny(p2)])
        _write_jsonl(self.reports, [_report(
            "read_file", {"file_path": p})])
        _write_jsonl(self.changes, [{
            "type": "snapshot_checker_change", "tick": 1,
            "changes": {}}])
        _write_jsonl(self.findings, [])  # 快照校验已运行但无 finding
        s = self._run(protected_dirs=[])
        dims = {u["dimension"] for u in s["unavailable"]}
        self.assertEqual(dims, {"report_snapshot_conflict"})
        # 维度①不受维度③降级影响：deny 无匹配申报 → 仍产出 issue
        self.assertIn("unreported_hook_deny", self._kinds(s))

    def test_each_unavailable_has_guidance(self):
        s = self._run()
        for u in s["unavailable"]:
            self.assertTrue(u.get("guidance"))


class RobustnessTest(ConsistencyTestBase):
    """损坏行容错、留痕落盘与 summary 结构。"""

    def test_corrupt_lines_tolerated_and_counted(self):
        p = os.path.join(self.protected, "secret.txt")
        with open(self.pre, "w", encoding="utf-8") as f:
            f.write('{"broken": \n')  # 损坏行
            f.write(json.dumps(_pre_deny(p)) + "\n")
        s = self._run()
        self.assertIn("unreported_hook_deny", self._kinds(s))
        self.assertGreaterEqual(sum(s["corrupt_lines"].values()), 1)

    def test_jsonl_trace_written_with_both_types(self):
        p = os.path.join(self.protected, "secret.txt")
        _write_jsonl(self.pre, [_pre_deny(p)])
        s = self._run()
        path = os.path.join(self.out, "consistency_issues.jsonl")
        self.assertTrue(os.path.isfile(path))
        types = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                types.append(json.loads(line)["type"])
        self.assertIn("consistency_issue", types)
        self.assertIn("consistency_unavailable", types)

    def test_no_issues_no_trace(self):
        p = os.path.join(self.protected, "secret.txt")
        _write_jsonl(self.pre, [_pre_deny(p)])
        _write_jsonl(self.reports, [_report(
            "read_file", {"file_path": p})])
        # 维度②③ 源缺失会产出 unavailable → 必然落盘；
        # 全源齐备且无不一致时不落盘。
        _write_jsonl(self.findings, [{
            "type": "snapshot_checker_finding",
            "kind": "unreported_file_change",
            "changes": {}}])
        _write_jsonl(self.changes, [{
            "type": "snapshot_checker_change", "tick": 1,
            "changes": {}}])
        s = self._run()
        self.assertEqual(s["issues"], [])
        self.assertEqual(s["unavailable"], [])
        self.assertFalse(os.path.isfile(
            os.path.join(self.out, "consistency_issues.jsonl")))

    def test_summary_sources_counts(self):
        p = os.path.join(self.protected, "secret.txt")
        _write_jsonl(self.pre, [_pre_deny(p)])
        _write_jsonl(self.reports, [_report(
            "read_file", {"file_path": p}),
            _report("bash", {"command": "ls"},
                    session_id="sess-2")])
        _write_jsonl(self.post, [{
            "event": "post_tool_use", "target": p,
            "session_id": "sess-1"}])
        _write_jsonl(self.findings, [{
            "type": "snapshot_checker_finding",
            "kind": "unreported_file_change",
            "changes": {"added": {p: {"size": 1}}}}])
        _write_jsonl(self.changes, [{
            "type": "snapshot_checker_change", "tick": 1,
            "changes": {"added": {p: {"size": 1}}}}])
        s = self._run()
        src = s["sources"]
        self.assertEqual(src["agent_reports"], 2)
        self.assertEqual(src["hook_pre_entries"], 1)
        self.assertEqual(src["hook_post_entries"], 1)
        self.assertEqual(src["snapshot_findings"], 1)
        self.assertEqual(src["snapshot_change_paths"], 1)
        # 申报与 hook 均有观测、快照全集有变化 → 三类均无不一致
        self.assertEqual(s["issues"], [])
        self.assertEqual(s["issue_counts"], {})


if __name__ == "__main__":
    unittest.main()
