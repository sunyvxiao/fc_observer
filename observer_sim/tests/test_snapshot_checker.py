# -*- coding: utf-8 -*-
"""
test_snapshot_checker.py — P1-3 用户态快照交叉校验单测

对应计划文档《监测与拦截解耦双路径_开发落地计划.md》P1-3：
新建 `observer_sim/observer_core/monitoring/snapshot_checker.py`——
受保护目录文件快照（大小/mtime/hash）定时比对 + Windows 审计日志
Security 4663（文件对象访问）读取；发现「申报未报但文件被访问/
变更」→ 不一致告警（仅告警、不拦截）。验收 TC-06/TC-09。

测试内容:
1. parse_4663_xml: 合法 4663 解析 / 非 4663 拒绝 / 坏 XML / 缺 ObjectName
2. tick: 首 tick 仅 baseline 不比对；diff 未申报变更 → finding；
   已申报路径排除；快照失败 → unavailable 不破坏主流程
3. 4663 审计比对: 受保护目录内未申报访问 → finding；
   系统/自身/白名单进程排除；目录外排除；已申报排除；
   查询异常 / 窗口无事件 → unavailable + 启用指引
4. finish: summary 结构 + snapshot_checker.jsonl 留痕落盘
5. _in_protected_dirs / _process_skipped 边界
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from observer_core.monitoring.snapshot_checker import (  # noqa: E402
    AUDIT_4663_GUIDANCE, ObjectAccessAuditReader, SnapshotChecker,
    _in_protected_dirs, _process_skipped, parse_4663_xml)
from collector.lightweight_crosscheck import FileSnapshotter  # noqa: E402

_XML_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _xml_4663(object_name, process_name="C:\\Windows\\System32\\cmd.exe",
              time_str="2026-09-05T09:00:00.000000000Z", eid=4663,
              access_mask="0x1"):
    return (
        f'<Event xmlns="{_XML_NS}">'
        f"<System><EventID>{eid}</EventID>"
        f'<TimeCreated SystemTime="{time_str}"/></System>'
        f"<EventData>"
        f'<Data Name="ObjectName">{object_name}</Data>'
        f'<Data Name="AccessMask">{access_mask}</Data>'
        f'<Data Name="ProcessName">{process_name}</Data>'
        f"</EventData></Event>"
    )


class FakeSnapshotter:
    """按预设序列返回快照（精确控制 diff 场景）。

    序列耗尽时重复最后一个结果（模拟持续同态）；
    从未有过结果则返回 None（持续失败）。
    """

    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def snapshot(self, previous=None):
        self.calls.append(previous)
        if not self._results:
            return None
        last = self._results.pop(0)
        if not self._results:
            self._results.append(last)  # 耗尽后重复最后结果
        return last


class FakeAuditQuery:
    """注入 query_fn 的假 4663 查询源。"""

    def __init__(self, xml_events=None, error=None):
        self._xml_events = xml_events
        self._error = error
        self.calls = []

    def __call__(self, log_name, ids, start_epoch, end_epoch,
                 max_events, timeout_s):
        self.calls.append((log_name, ids, start_epoch, end_epoch))
        if self._error is not None:
            raise self._error
        return list(self._xml_events or [])


class Parse4663XmlTest(unittest.TestCase):
    """parse_4663_xml 解析与拒绝。"""

    def test_valid_4663(self):
        evt = parse_4663_xml(
            _xml_4663("C:\\protected\\secret.txt",
                      process_name="C:\\Windows\\System32\\cmd.exe"))
        self.assertIsNotNone(evt)
        self.assertEqual(evt["event_id"], 4663)
        self.assertEqual(evt["source"], "security_4663")
        self.assertEqual(evt["object_name"], "C:\\protected\\secret.txt")
        self.assertEqual(evt["access_mask"], "0x1")
        self.assertEqual(evt["process_name"],
                         "C:\\Windows\\System32\\cmd.exe")
        # 2026-09-05T09:00:00Z 的 UTC 毫秒 epoch
        self.assertEqual(evt["time_ms"], 1788598800000)

    def test_non_4663_rejected(self):
        self.assertIsNone(parse_4663_xml(
            _xml_4663("C:\\x", eid=4688)))

    def test_bad_xml_rejected(self):
        self.assertIsNone(parse_4663_xml("not xml at all"))

    def test_missing_object_name_rejected(self):
        xml = (
            f'<Event xmlns="{_XML_NS}">'
            f"<System><EventID>4663</EventID>"
            f'<TimeCreated SystemTime="2026-09-05T09:00:00Z"/></System>'
            f"<EventData></EventData></Event>"
        )
        self.assertIsNone(parse_4663_xml(xml))


class PathHelperTest(unittest.TestCase):
    """_in_protected_dirs / _process_skipped 边界。"""

    def test_in_protected_dirs(self):
        dirs = [r"C:\protected"]
        self.assertTrue(_in_protected_dirs(r"C:\protected", dirs))
        self.assertTrue(_in_protected_dirs(
            r"C:\protected\sub\file.txt", dirs))
        self.assertTrue(_in_protected_dirs(
            r"c:\PROTECTED\file.txt", dirs))  # 大小写不敏感
        self.assertFalse(_in_protected_dirs(r"C:\other\file.txt", dirs))
        self.assertFalse(_in_protected_dirs(
            r"C:\protected2\file.txt", dirs))  # 前缀但不越界
        self.assertFalse(_in_protected_dirs("", dirs))

    def test_process_skipped(self):
        self.assertTrue(_process_skipped("", None))  # 无进程名
        self.assertTrue(_process_skipped(
            r"C:\Python\python.exe", None))  # 观察者自身
        self.assertTrue(_process_skipped(
            r"C:\Windows\System32\svchost.exe", None))  # 系统白名单
        self.assertTrue(_process_skipped(
            r"C:\WorkBuddy\WorkBuddy.exe", ["workbuddy.exe"]))  # 额外白名单
        self.assertFalse(_process_skipped(
            r"C:\Windows\System32\cmd.exe", None))
        self.assertFalse(_process_skipped(
            r"C:\temp\evil.exe", ["safe.exe"]))


class SnapshotCheckerTickTest(unittest.TestCase):
    """tick 定时快照比对。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.protected = os.path.join(self.tmp.name, "protected")
        os.makedirs(self.protected)
        self.out_dir = os.path.join(self.tmp.name, "out")

    def _checker(self, snapshotter=None, **kw):
        return SnapshotChecker(
            self.out_dir,
            snapshotter=snapshotter or FileSnapshotter([self.protected]),
            protected_dirs=[self.protected],
            **kw)

    def test_first_tick_baseline_only(self):
        with open(os.path.join(self.protected, "a.txt"), "w") as f:
            f.write("hello")
        ck = self._checker()
        ck.tick()
        self.assertEqual(ck._tick_count, 1)
        self.assertEqual(ck._findings, [])
        self.assertEqual(ck._unavailable, [])
        self.assertIsNotNone(ck._last_snap)
        self.assertIn("@0/a.txt", ck._last_snap)

    def test_unreported_change_finding(self):
        ck = self._checker()
        ck.tick()  # baseline
        with open(os.path.join(self.protected, "new.txt"), "w") as f:
            f.write("secret")
        ck.tick()
        self.assertEqual(len(ck._findings), 1)
        f0 = ck._findings[0]
        self.assertEqual(f0["kind"], "unreported_file_change")
        self.assertEqual(f0["severity"], "suspect_secondary_action")
        self.assertEqual(f0["tick"], 2)
        self.assertIn("@0/new.txt", f0["changes"]["added"])

    def test_reported_change_excluded(self):
        ck = self._checker()
        ck.tick()
        new_path = os.path.join(self.protected, "new.txt")
        with open(new_path, "w") as f:
            f.write("secret")
        ck.tick(reported_paths=[new_path])
        self.assertEqual(ck._findings, [])

    def test_modified_and_removed_diff(self):
        target = os.path.join(self.protected, "m.txt")
        with open(target, "w") as f:
            f.write("v1")
        ck = self._checker()
        ck.tick()  # baseline 含 m.txt
        with open(target, "w") as f:
            f.write("v2-longer")
        ck.tick()
        self.assertEqual(len(ck._findings), 1)
        changes = ck._findings[0]["changes"]
        self.assertIn("@0/m.txt", changes["modified"])

    def test_snapshot_failure_unavailable(self):
        ck = self._checker(snapshotter=FakeSnapshotter([None]))
        ck.tick()
        self.assertEqual(ck._findings, [])
        self.assertEqual(len(ck._unavailable), 1)
        self.assertEqual(ck._unavailable[0]["phase"], "tick1")
        self.assertIn("不可用", ck._unavailable[0]["reason"])
        # 快照失败不破坏主流程：可继续 tick
        ck.tick()
        self.assertEqual(ck._tick_count, 2)

    # ── P2-2 配套: snapshot_changes.jsonl 变更全集落盘 ────────────

    def test_changes_fullset_written_before_exclusion(self):
        # 已申报路径在变更全集留痕中可见（排除前），finding 为空
        # （排除后）——维度③依赖全集判断「申报写入是否有落地证据」。
        ck = self._checker()
        ck.tick()  # baseline
        new_path = os.path.join(self.protected, "new.txt")
        with open(new_path, "w") as f:
            f.write("secret")
        ck.tick(reported_paths=[new_path])
        self.assertEqual(ck._findings, [])
        jsonl_path = os.path.join(self.out_dir, "snapshot_changes.jsonl")
        self.assertTrue(os.path.isfile(jsonl_path))
        with open(jsonl_path, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(lines), 1)
        rec = lines[0]
        self.assertEqual(rec["type"], "snapshot_checker_change")
        self.assertEqual(rec["tick"], 2)
        self.assertIn("@0/new.txt", rec["changes"]["added"])
        self.assertIn("timestamp_ms", rec)

    def test_changes_empty_diff_still_written(self):
        # 同态快照 diff 为空 → 仍落一条空 changes 记录（使「无变化」
        # 成为可判定状态，而非源缺失）。
        with open(os.path.join(self.protected, "a.txt"), "w") as f:
            f.write("hello")
        ck = self._checker()
        ck.tick()  # baseline
        ck.tick()  # 无变化
        jsonl_path = os.path.join(self.out_dir, "snapshot_changes.jsonl")
        self.assertTrue(os.path.isfile(jsonl_path))
        with open(jsonl_path, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["changes"],
                         {"added": {}, "modified": {}, "removed": {}})

    def test_first_tick_no_changes_written(self):
        # 首 tick 仅 baseline 不比对 → 不写变更全集留痕。
        with open(os.path.join(self.protected, "a.txt"), "w") as f:
            f.write("hello")
        ck = self._checker()
        ck.tick()
        self.assertFalse(os.path.isfile(
            os.path.join(self.out_dir, "snapshot_changes.jsonl")))


class SnapshotCheckerAuditTest(unittest.TestCase):
    """4663 对象访问审计比对。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.protected = os.path.join(self.tmp.name, "protected")
        os.makedirs(self.protected)
        self.out_dir = os.path.join(self.tmp.name, "out")

    def _checker(self, query, **kw):
        reader = ObjectAccessAuditReader(timeout_s=30.0, query_fn=query)
        return SnapshotChecker(
            self.out_dir,
            snapshotter=None,
            protected_dirs=[self.protected],
            audit_reader=reader, **kw)

    def _hit_xml(self, rel="secret.txt", proc="cmd.exe"):
        return _xml_4663(
            os.path.join(self.protected, rel),
            process_name=f"C:\\Windows\\System32\\{proc}")

    def test_unreported_access_finding(self):
        query = FakeAuditQuery([self._hit_xml()])
        ck = self._checker(query)
        ck._audit_compare()
        self.assertEqual(len(ck._findings), 1)
        f0 = ck._findings[0]
        self.assertEqual(f0["kind"], "unreported_file_access")
        self.assertEqual(f0["accesses"][0]["process_name"],
                         "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(query.calls[0][0], "Security")
        self.assertEqual(query.calls[0][1], [4663])

    def test_system_and_self_process_skipped(self):
        for proc in ("svchost.exe", "python.exe"):
            query = FakeAuditQuery([self._hit_xml(proc=proc)])
            ck = self._checker(query)
            ck._audit_compare()
            self.assertEqual(ck._findings, [], proc)

    def test_whitelist_extra_skipped(self):
        query = FakeAuditQuery([self._hit_xml(proc="myagent.exe")])
        ck = self._checker(query, whitelist_extra=["myagent.exe"])
        ck._audit_compare()
        self.assertEqual(ck._findings, [])

    def test_outside_protected_dirs_skipped(self):
        query = FakeAuditQuery([
            _xml_4663("C:\\unrelated\\other.txt")])
        ck = self._checker(query)
        ck._audit_compare()
        self.assertEqual(ck._findings, [])

    def test_reported_access_skipped(self):
        hit_path = os.path.join(self.protected, "secret.txt")
        query = FakeAuditQuery([_xml_4663(hit_path)])
        ck = self._checker(query)
        ck.add_reported_path(hit_path)
        ck._audit_compare()
        self.assertEqual(ck._findings, [])

    def test_query_failure_unavailable_with_guidance(self):
        query = FakeAuditQuery(error=PermissionError("denied"))
        ck = self._checker(query)
        ck._audit_compare()
        self.assertEqual(ck._findings, [])
        self.assertEqual(len(ck._unavailable), 1)
        u = ck._unavailable[0]
        self.assertEqual(u["phase"], "audit_4663")
        self.assertIn("4663", u["reason"])
        self.assertEqual(u["guidance"], AUDIT_4663_GUIDANCE)

    def test_no_events_unavailable(self):
        query = FakeAuditQuery([])
        ck = self._checker(query)
        ck._audit_compare()
        self.assertEqual(ck._findings, [])
        self.assertEqual(len(ck._unavailable), 1)
        self.assertEqual(ck._unavailable[0]["phase"], "audit_4663")
        self.assertIn("guidance", ck._unavailable[0])

    def test_no_audit_reader_no_compare(self):
        ck = SnapshotChecker(
            self.out_dir, protected_dirs=[self.protected],
            snapshotter=None, audit_reader=None)
        ck._audit_compare()
        self.assertEqual(ck._findings, [])
        self.assertEqual(ck._unavailable, [])


class SnapshotCheckerFinishTest(unittest.TestCase):
    """finish 收尾 summary 与留痕落盘。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.protected = os.path.join(self.tmp.name, "protected")
        os.makedirs(self.protected)
        self.out_dir = os.path.join(self.tmp.name, "out")

    def test_finish_summary_and_jsonl(self):
        query = FakeAuditQuery([_xml_4663(
            os.path.join(self.protected, "leak.txt"),
            process_name="C:\\Windows\\System32\\cmd.exe")])
        reader = ObjectAccessAuditReader(timeout_s=30.0, query_fn=query)
        ck = SnapshotChecker(
            self.out_dir,
            snapshotter=FileSnapshotter([self.protected]),
            protected_dirs=[self.protected],
            audit_reader=reader, interval_s=30, lookback_s=60)
        ck.tick()  # baseline
        summary = ck.finish()
        self.assertTrue(summary["enabled"])
        self.assertTrue(summary["available"])
        self.assertGreaterEqual(summary["ticks"], 2)  # baseline + 末次
        self.assertEqual(summary["interval_s"], 30)
        self.assertIn("note", summary)
        # 4663 命中 → unreported_file_access finding
        kinds = {f["kind"] for f in summary["findings"]}
        self.assertIn("unreported_file_access", kinds)
        # 留痕落盘
        jsonl_path = os.path.join(self.out_dir, "snapshot_checker.jsonl")
        self.assertTrue(os.path.isfile(jsonl_path))
        with open(jsonl_path, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        self.assertTrue(lines)
        types = {l["type"] for l in lines}
        self.assertIn("snapshot_checker_finding", types)
        self.assertTrue(all("timestamp_ms" in l for l in lines))

    def test_finish_unavailable_recorded_in_jsonl(self):
        ck = SnapshotChecker(
            self.out_dir,
            snapshotter=FakeSnapshotter([None]),
            protected_dirs=[self.protected],
            audit_reader=None)
        summary = ck.finish()
        self.assertTrue(summary["enabled"])
        self.assertFalse(summary["available"])
        self.assertEqual(summary["findings"], [])
        self.assertTrue(summary["unavailable"])
        jsonl_path = os.path.join(self.out_dir, "snapshot_checker.jsonl")
        with open(jsonl_path, encoding="utf-8") as f:
            types = {json.loads(l)["type"] for l in f if l.strip()}
        self.assertIn("snapshot_checker_unavailable", types)


if __name__ == "__main__":
    unittest.main()
