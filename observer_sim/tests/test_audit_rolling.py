"""
test_audit_rolling.py — L-T3 L0 审计文件按天滚动 + retention_days 测试

验证:
1. 同场景同日二次 start_scenario → 追加（行数翻倍，不覆盖历史）
2. 跨天 → 新文件（audit_{scenario_id}_{YYYYMMDD}.jsonl）
3. 跨场景同日 → 各自文件
4. retention_days 清理：过期删除、未过期保留、非 audit 文件忽略
5. 默认（retention_days=None）不清理
"""

import os
import sys
import shutil
import tempfile
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.event import RawEvent, NormalizedEvent
from observer_core.audit.audit_logger import AuditLogger


def _make_event(event_id: str, agent_id: str = "agent-1") -> NormalizedEvent:
    """创建测试用 NormalizedEvent"""
    raw = RawEvent(
        event_id=event_id, timestamp_ns=0, event_type="exec",
        pid=1, ppid=1, agent_id=agent_id, agent_framework="t",
        executable="/bin/x", arguments=[],
    )
    return NormalizedEvent(raw=raw)


class TestDailyRolling(unittest.TestCase):
    """L0 按天滚动行为测试（注入日期源）"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _logger(self, day: int, retention_days=None) -> AuditLogger:
        """注入固定日期源（2026-08-{day}）的 AuditLogger"""
        return AuditLogger(
            output_dir=self.tmpdir,
            retention_days=retention_days,
            now_fn=lambda: datetime(2026, 8, day, 10, 0, 0),
        )

    def test_same_scenario_same_day_appends(self):
        """同场景同日二次 start_scenario → 追加，不覆盖历史"""
        logger = self._logger(day=9)
        logger.start_scenario("scenario-01")
        logger.log_event(_make_event("evt-1"), description="first")
        logger.close()

        logger.start_scenario("scenario-01")
        self.assertTrue(
            logger.current_file.endswith("audit_scenario-01_20260809.jsonl"))
        logger.log_event(_make_event("evt-2"), description="second")
        logger.close()

        audit_dir = os.path.join(self.tmpdir, "audit")
        self.assertEqual(os.listdir(audit_dir),
                         ["audit_scenario-01_20260809.jsonl"])
        entries = logger.read_entries()
        self.assertEqual([e.event_id for e in entries], ["evt-1", "evt-2"])

    def test_cross_day_creates_new_file(self):
        """跨天 → 新文件，历史文件保留"""
        logger = self._logger(day=9)
        logger.start_scenario("scenario-01")
        logger.log_event(_make_event("evt-1"))
        logger.close()

        logger2 = AuditLogger(
            output_dir=self.tmpdir,
            now_fn=lambda: datetime(2026, 8, 10, 10, 0, 0))
        logger2.start_scenario("scenario-01")
        logger2.log_event(_make_event("evt-2"))
        logger2.close()

        audit_dir = os.path.join(self.tmpdir, "audit")
        self.assertEqual(sorted(os.listdir(audit_dir)),
                         ["audit_scenario-01_20260809.jsonl",
                          "audit_scenario-01_20260810.jsonl"])
        # 新文件只含新事件
        self.assertEqual([e.event_id for e in logger2.read_entries()], ["evt-2"])

    def test_cross_scenario_same_day_separate_files(self):
        """不同场景同日 → 各自文件"""
        logger = self._logger(day=9)
        logger.start_scenario("scenario-01")
        logger.close()
        logger.start_scenario("scenario-02")
        logger.close()
        audit_dir = os.path.join(self.tmpdir, "audit")
        self.assertEqual(sorted(os.listdir(audit_dir)),
                         ["audit_scenario-01_20260809.jsonl",
                          "audit_scenario-02_20260809.jsonl"])

    def test_filename_matches_new_format(self):
        """文件名符合 audit_{scenario_id}_{YYYYMMDD}.jsonl"""
        logger = self._logger(day=9)
        path = logger.start_scenario("n01-standard-development")
        logger.close()
        self.assertTrue(
            path.endswith("audit_n01-standard-development_20260809.jsonl"))


class TestRetention(unittest.TestCase):
    """retention_days 惰性清理测试"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _make_old_file(self, name: str, age_days: int) -> str:
        """在 audit 目录创建 mtime 为 N 天前的文件"""
        audit_dir = os.path.join(self.tmpdir, "audit")
        os.makedirs(audit_dir, exist_ok=True)
        fpath = os.path.join(audit_dir, name)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("{}\n")
        old = time.time() - age_days * 86400
        os.utime(fpath, (old, old))
        return fpath

    def test_retention_cleans_expired_files(self):
        """过期文件清理、未过期保留（start_scenario 自动触发）"""
        old_file = self._make_old_file("audit_old_20260101.jsonl", age_days=31)
        fresh_file = self._make_old_file("audit_fresh_20260809.jsonl", age_days=1)

        logger = AuditLogger(output_dir=self.tmpdir, retention_days=30)
        logger.start_scenario("scenario-01")
        logger.close()

        self.assertFalse(os.path.exists(old_file))
        self.assertTrue(os.path.exists(fresh_file))

    def test_retention_ignores_non_audit_files(self):
        """非 audit_*.jsonl 文件不清理"""
        other_jsonl = self._make_old_file("other.jsonl", age_days=60)
        other_md = self._make_old_file("risk_report_x.md", age_days=60)

        logger = AuditLogger(output_dir=self.tmpdir, retention_days=30)
        logger.start_scenario("scenario-01")
        logger.close()

        self.assertTrue(os.path.exists(other_jsonl))
        self.assertTrue(os.path.exists(other_md))

    def test_retention_disabled_by_default(self):
        """默认 retention_days=None → 不清理"""
        old_file = self._make_old_file("audit_old_20260101.jsonl", age_days=31)

        logger = AuditLogger(output_dir=self.tmpdir)
        logger.start_scenario("scenario-01")
        logger.close()

        self.assertTrue(os.path.exists(old_file))

    def test_apply_retention_returns_stats(self):
        """apply_retention 返回删除统计"""
        self._make_old_file("audit_old_20260101.jsonl", age_days=31)
        self._make_old_file("audit_fresh_20260809.jsonl", age_days=1)

        logger = AuditLogger(output_dir=self.tmpdir, retention_days=30)
        result = logger.apply_retention()
        self.assertEqual(result["scanned"], 2)
        self.assertEqual(result["deleted"], 1)
        self.assertEqual(result["deleted_files"], ["audit_old_20260101.jsonl"])


if __name__ == "__main__":
    unittest.main()
