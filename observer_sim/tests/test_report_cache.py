"""
test_report_cache.py — ReportCacheManager 报告片段缓存管理器单元测试

测试内容:
1. ReportCacheManager: 构造、初始化、segment_dir
2. 片段生成: _generate_segment (使用 mock AuditLogger)
3. 手动查询: query_range 按时间窗口查找
4. 合并拼接: merge_segments 去重与间隙填充
5. GC 机制: _gc_segments 旧片段清理
6. force_generate: 手动触发生成
"""

import sys
import os
import unittest
import tempfile
import json
import shutil
from unittest.mock import Mock, MagicMock, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from observer_core.audit.report_cache import ReportCacheManager


def _make_mock_audit_entry(event_id, timestamp_ns, decision_action="ALLOW",
                           blocked=False, risk_score=0.1, risk_level="LOW",
                           matched_rules=None):
    """创建模拟的 AuditEntry"""
    entry = Mock()
    entry.event_id = event_id
    entry.timestamp_ns = timestamp_ns
    entry.decision_action = decision_action
    entry.blocked = blocked
    entry.risk_score = risk_score
    entry.risk_level = risk_level
    entry.matched_rules = matched_rules or []
    return entry


class TestReportCacheManagerBasic(unittest.TestCase):
    """ReportCacheManager 基础功能测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="rcache_")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_constructor_creates_directories(self):
        """构造时创建 segments 目录"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        seg_dir = os.path.join(self._tmpdir, "cache", "segments")
        self.assertTrue(os.path.isdir(seg_dir))
        self.assertEqual(cache.segments_dir, seg_dir)

    def test_initial_segment_count_zero(self):
        """初始片段数为 0"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        self.assertEqual(cache.segment_count, 0)

    def test_list_segments_empty_initially(self):
        """初始 list_segments 为空"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        self.assertEqual(cache.list_segments(), [])

    def test_set_audit_logger(self):
        """注入 AuditLogger"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        cache.set_audit_logger(mock_logger)
        self.assertIs(cache._audit_logger, mock_logger)

    def test_set_stats_provider(self):
        """注入 stats_provider"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        provider = lambda: {"total": 10}
        cache.set_stats_provider(provider)
        self.assertIs(cache._stats_provider, provider)


class TestReportCacheManagerSegmentGeneration(unittest.TestCase):
    """ReportCacheManager 片段生成测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="rcache_seg_")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_generate_segment_without_audit_logger(self):
        """无 AuditLogger 时不生成片段"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        result = cache._generate_segment()
        self.assertIsNone(result)
        self.assertEqual(cache.segment_count, 0)

    def test_generate_segment_with_empty_entries(self):
        """空条目时不生成片段"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        mock_logger.read_entries.return_value = []
        cache.set_audit_logger(mock_logger)
        result = cache._generate_segment()
        self.assertIsNone(result)

    def test_generate_segment_creates_file(self):
        """生成片段时创建 JSON 文件"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        entries = [
            _make_mock_audit_entry("e1", 1000, "ALLOW", risk_score=0.1),
            _make_mock_audit_entry("e2", 2000, "ALERT", risk_score=0.7,
                                   risk_level="HIGH", matched_rules=["R001"]),
            _make_mock_audit_entry("e3", 3000, "ALLOW", risk_score=0.05),
        ]
        mock_logger.read_entries.return_value = entries
        cache.set_audit_logger(mock_logger)

        result = cache._generate_segment()
        self.assertIsNotNone(result)
        self.assertEqual(cache.segment_count, 1)

        # 验证文件存在
        seg_path = os.path.join(
            self._tmpdir, "cache", "segments", f"{result['segment_id']}.json")
        self.assertTrue(os.path.isfile(seg_path))

    def test_generate_segment_stats_correct(self):
        """片段统计正确"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        entries = [
            _make_mock_audit_entry("e1", 1000, "ALLOW", risk_score=0.1),
            _make_mock_audit_entry("e2", 2000, "ALERT", risk_level="HIGH",
                                   risk_score=0.8, matched_rules=["R001"]),
            _make_mock_audit_entry("e3", 3000, "ALLOW", risk_score=0.05),
            _make_mock_audit_entry("e4", 4000, "ALLOW", blocked=True,
                                   risk_score=0.95, risk_level="CRITICAL",
                                   matched_rules=["R001", "R005"]),
        ]
        mock_logger.read_entries.return_value = entries
        cache.set_audit_logger(mock_logger)

        result = cache._generate_segment()
        stats = result["stats"]
        self.assertEqual(stats["total"], 4)
        # ALLOW(blocked=True) 同时计入 allow 和 block
        self.assertEqual(stats["allow"], 3)  # e1+e3+e4
        self.assertEqual(stats["alert"], 1)  # e2
        self.assertEqual(stats["block"], 1)  # e4
        self.assertAlmostEqual(stats["max_score"], 0.95)
        self.assertEqual(stats["risk_dist"]["HIGH"], 1)
        self.assertEqual(stats["risk_dist"]["CRITICAL"], 1)
        self.assertEqual(stats["rule_hits"]["R001"], 2)
        self.assertEqual(stats["rule_hits"]["R005"], 1)

    def test_generate_segment_deduplicates_entry_ids(self):
        """第二次生成时不重复统计已覆盖条目"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        entries = [
            _make_mock_audit_entry("e1", 1000, "ALLOW"),
            _make_mock_audit_entry("e2", 2000, "ALLOW"),
        ]
        mock_logger.read_entries.return_value = entries
        cache.set_audit_logger(mock_logger)

        # 第一次生成
        result1 = cache._generate_segment()
        self.assertEqual(result1["stats"]["total"], 2)

        # 第二次生成（相同条目）
        result2 = cache._generate_segment()
        self.assertIsNone(result2)  # 无新条目

    def test_force_generate(self):
        """force_generate 手动触发"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        mock_logger.read_entries.return_value = [
            _make_mock_audit_entry("e1", 1000, "ALLOW"),
        ]
        cache.set_audit_logger(mock_logger)
        result = cache.force_generate()
        self.assertIsNotNone(result)


class TestReportCacheManagerQuery(unittest.TestCase):
    """ReportCacheManager 查询与合并测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="rcache_q_")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _add_segment_directly(self, cache, seg_id, start_ns, end_ns,
                              stats=None, entry_ids=None):
        """直接向缓存添加测试片段（绕过 AuditLogger）"""
        segment = {
            "segment_id": seg_id,
            "start_ns": start_ns,
            "end_ns": end_ns,
            "created_at": "2025-01-01T00:00:00",
            "stats": stats or {
                "total": 1, "allow": 1, "alert": 0, "block": 0,
                "risk_dist": {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                "rule_hits": {},
                "max_score": 0.1,
            },
            "entry_ids": entry_ids or [f"e_{seg_id}"],
        }
        cache._segments.append(segment)
        return segment

    def test_query_range_exact_match(self):
        """精确时间匹配"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        self._add_segment_directly(cache, "seg_1", 1000, 2000)
        self._add_segment_directly(cache, "seg_2", 2000, 3000)
        self._add_segment_directly(cache, "seg_3", 3000, 4000)

        result = cache.query_range(1500, 2500)
        self.assertEqual(len(result), 2)

    def test_query_range_no_match(self):
        """无匹配片段"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        self._add_segment_directly(cache, "seg_1", 1000, 2000)
        result = cache.query_range(5000, 6000)
        self.assertEqual(len(result), 0)

    def test_query_range_sorted_by_time(self):
        """结果按时间排序"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        self._add_segment_directly(cache, "seg_3", 3000, 4000)
        self._add_segment_directly(cache, "seg_1", 1000, 2000)
        self._add_segment_directly(cache, "seg_2", 2000, 3000)

        result = cache.query_range(0, 9999)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["start_ns"], 1000)
        self.assertEqual(result[1]["start_ns"], 2000)
        self.assertEqual(result[2]["start_ns"], 3000)

    def test_merge_segments_basic(self):
        """基本合并：加法统计"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        self._add_segment_directly(cache, "seg_1", 1000, 2000, stats={
            "total": 2, "allow": 2, "alert": 0, "block": 0,
            "risk_dist": {"LOW": 2, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "rule_hits": {"R001": 1}, "max_score": 0.2,
        }, entry_ids=["e1", "e2"])
        self._add_segment_directly(cache, "seg_2", 2000, 3000, stats={
            "total": 3, "allow": 1, "alert": 1, "block": 1,
            "risk_dist": {"LOW": 1, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 1},
            "rule_hits": {"R001": 2, "R005": 1}, "max_score": 0.95,
        }, entry_ids=["e3", "e4", "e5"])

        result = cache.merge_segments(cache._segments)
        self.assertEqual(result["segment_count"], 2)
        ms = result["merged_stats"]
        self.assertEqual(ms["total"], 5)
        self.assertEqual(ms["allow"], 3)
        self.assertEqual(ms["alert"], 1)
        self.assertEqual(ms["block"], 1)
        self.assertAlmostEqual(ms["max_score"], 0.95)
        self.assertEqual(ms["rule_hits"]["R001"], 3)
        self.assertEqual(ms["rule_hits"]["R005"], 1)

    def test_merge_segments_empty(self):
        """空片段合并"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        result = cache.merge_segments([])
        self.assertEqual(result["segment_count"], 0)
        self.assertEqual(result["merged_stats"], {})

    def test_merge_segments_de_duplicates_entry_ids(self):
        """去重：相同 entry_id 只计一次"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        self._add_segment_directly(cache, "seg_a", 1000, 2000,
                                   entry_ids=["shared", "a_only"])
        self._add_segment_directly(cache, "seg_b", 2000, 3000,
                                   entry_ids=["shared", "b_only"])

        result = cache.merge_segments(cache._segments)
        ids = result["total_entry_ids"]
        self.assertEqual(len(ids), 3)  # shared + a_only + b_only
        self.assertIn("shared", ids)
        self.assertIn("a_only", ids)
        self.assertIn("b_only", ids)


class TestReportCacheManagerGC(unittest.TestCase):
    """ReportCacheManager 垃圾回收测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="rcache_gc_")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_gc_removes_oldest_segments(self):
        """GC 移除最旧片段"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        # 添加超过 MAX_SEGMENTS 个片段
        for i in range(70):
            seg_path = os.path.join(
                self._tmpdir, "cache", "segments", f"seg_{i:04d}.json")
            with open(seg_path, "w") as f:
                json.dump({"segment_id": f"seg_{i:04d}"}, f)
            cache._segments.append({
                "segment_id": f"seg_{i:04d}",
                "start_ns": i * 1000,
                "end_ns": (i + 1) * 1000,
                "stats": {},
                "entry_ids": [],
            })

        cache._gc_segments()
        self.assertLessEqual(len(cache._segments), cache.MAX_SEGMENTS)

    def test_gc_archives_detail_rollup_before_delete(self):
        """L-T4: GC 删前将事件明细转存 rollup JSONL，GC 后明细可查"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        entries = [
            _make_mock_audit_entry("e1", 1000, "ALLOW", risk_score=0.1),
            _make_mock_audit_entry("e2", 2000, "ALERT", risk_level="HIGH",
                                   risk_score=0.8, matched_rules=["R001"]),
        ]
        mock_logger.read_entries.return_value = entries
        cache.set_audit_logger(mock_logger)

        # 最旧片段含 e1/e2 明细，其余填满 MAX_SEGMENTS 个空片段
        cache._segments = [{
            "segment_id": "seg_old", "start_ns": 0, "end_ns": 1000,
            "stats": {"total": 2}, "entry_ids": ["e1", "e2"],
        }]
        for i in range(cache.MAX_SEGMENTS):
            cache._segments.append({
                "segment_id": f"seg_{i:04d}",
                "start_ns": (i + 1) * 1000, "end_ns": (i + 2) * 1000,
                "stats": {}, "entry_ids": [],
            })

        cache._gc_segments()
        self.assertLessEqual(len(cache._segments), cache.MAX_SEGMENTS)
        self.assertFalse(any(s["segment_id"] == "seg_old"
                             for s in cache._segments))

        # GC 后明细可查
        rollup = cache.read_rollup("seg_old")
        self.assertGreaterEqual(len(rollup), 2)
        meta = rollup[0]
        self.assertEqual(meta.get("type"), "segment_meta")
        self.assertEqual(meta.get("segment_id"), "seg_old")
        self.assertEqual(meta.get("stats", {}).get("total"), 2)
        entry_ids = {line.get("event_id") for line in rollup[1:]}
        self.assertEqual(entry_ids, {"e1", "e2"})
        e1 = next(line for line in rollup[1:]
                  if line.get("event_id") == "e1")
        self.assertEqual(e1.get("decision_action"), "ALLOW")
        # rollup 文件落盘且 list_rollups 可见
        self.assertIn("seg_old", cache.list_rollups())
        self.assertTrue(os.path.isfile(os.path.join(
            cache.rollup_dir, "rollup_seg_old.jsonl")))

    def test_gc_rollup_without_audit_logger_keeps_meta(self):
        """无 AuditLogger 时 rollup 保留 meta 行，GC 不崩溃"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        cache._segments = [{
            "segment_id": "seg_meta", "start_ns": 0, "end_ns": 1000,
            "stats": {"total": 3}, "entry_ids": ["e1"],
        }]
        for i in range(cache.MAX_SEGMENTS):
            cache._segments.append({
                "segment_id": f"seg_{i:04d}",
                "start_ns": (i + 1) * 1000, "end_ns": (i + 2) * 1000,
                "stats": {}, "entry_ids": [],
            })

        cache._gc_segments()
        rollup = cache.read_rollup("seg_meta")
        self.assertEqual(len(rollup), 2)  # meta 行 + 缺失标记行
        self.assertEqual(rollup[0]["type"], "segment_meta")
        self.assertEqual(rollup[1]["event_id"], "e1")
        self.assertTrue(rollup[1]["missing"])


class TestL1AnomalyAndFingerprintZones(unittest.TestCase):
    """L-T5: L1 片段异常明细区（anomalies）与指纹边区（fingerprint_edges）测试。

    三红线约束：
    - 异常明细全保留（ALERT/BLOCK/高分事件完整字段+决策链进 anomalies）
    - 指纹边全透传（fingerprint_edges 全量不聚合）
    - 向后兼容（旧片段无新区键 merge 不崩溃）
    """

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="rcache_l1z_")

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_generate_segment_fills_anomalies_zone(self):
        """异常明细区收录 ALERT/BLOCK/高分事件，完整字段+决策链保留"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        entries = [
            _make_mock_audit_entry("e1", 1000, "ALLOW", risk_score=0.1),
            _make_mock_audit_entry("e2", 2000, "ALERT", risk_score=0.3,
                                   risk_level="MEDIUM", matched_rules=["R001"]),
            _make_mock_audit_entry("e3", 3000, "ALLOW", blocked=True,
                                   risk_score=0.5),
            _make_mock_audit_entry("e4", 4000, "ALLOW", risk_score=0.7,
                                   risk_level="HIGH"),
        ]
        mock_logger.read_entries.return_value = entries
        cache.set_audit_logger(mock_logger)

        result = cache._generate_segment()
        anomalies = result["anomalies"]
        ids = {a["event_id"] for a in anomalies}
        self.assertEqual(ids, {"e2", "e3", "e4"},
                         "ALERT/BLOCK/高分事件必须全部进异常明细区")
        e2 = next(a for a in anomalies if a["event_id"] == "e2")
        self.assertEqual(e2["decision_action"], "ALERT")
        self.assertEqual(e2["risk_level"], "MEDIUM")
        self.assertEqual(e2["matched_rules"], ["R001"])

    def test_generate_segment_fingerprint_edges_full_passthrough(self):
        """指纹边区全量透传不聚合：同指纹不同事件各一条，无指纹不进"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        entries = [
            _make_mock_audit_entry("e1", 1000, "ALLOW", risk_score=0.1),
            _make_mock_audit_entry("e2", 2000, "ALERT", risk_score=0.3),
            _make_mock_audit_entry("e3", 3000, "ALLOW", risk_score=0.1),
        ]
        entries[0].fingerprint = "fp_a"
        entries[1].fingerprint = "fp_a"   # 同指纹，不聚合
        entries[2].fingerprint = None     # 无指纹
        for i, entry in enumerate(entries):
            entry.agent_id = f"agent-{i}"
            entry.event_type = "file_open"
            entry.file_path = "/tmp/f.csv"
            entry.remote_addr = None
        mock_logger.read_entries.return_value = entries
        cache.set_audit_logger(mock_logger)

        result = cache._generate_segment()
        edges = result["fingerprint_edges"]
        self.assertEqual(len(edges), 2, "同指纹两条事件必须全量透传不聚合")
        self.assertEqual({f["event_id"] for f in edges}, {"e1", "e2"})
        self.assertEqual({f["fingerprint"] for f in edges}, {"fp_a"})
        self.assertEqual({f["agent_id"] for f in edges},
                         {"agent-0", "agent-1"})

    def test_generate_segment_marks_format_version(self):
        """新片段带 format_version 标记（旧片段缺省视作 0）"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        mock_logger.read_entries.return_value = [
            _make_mock_audit_entry("e1", 1000, "ALLOW"),
        ]
        cache.set_audit_logger(mock_logger)
        result = cache._generate_segment()
        self.assertEqual(result.get("format_version"),
                         ReportCacheManager.FORMAT_VERSION)

    def test_merge_segments_passthrough_zones_dedup(self):
        """merge 透传新区并去重（anomalies 按 event_id、edges 按指纹+事件）"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        stats = {
            "total": 1, "allow": 1, "alert": 0, "block": 0,
            "risk_dist": {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "rule_hits": {}, "max_score": 0.1,
        }
        cache._segments = [
            {"segment_id": "seg_a", "start_ns": 1000, "end_ns": 2000,
             "stats": stats, "entry_ids": ["e1"],
             "anomalies": [{"event_id": "e1", "timestamp_ns": 1500,
                            "decision_action": "ALERT"}],
             "fingerprint_edges": [{"fingerprint": "fp_x", "event_id": "e1",
                                     "timestamp_ns": 1500}]},
            {"segment_id": "seg_b", "start_ns": 2000, "end_ns": 3000,
             "stats": stats, "entry_ids": ["e1", "e2"],
             "anomalies": [{"event_id": "e1", "timestamp_ns": 1500,
                            "decision_action": "ALERT"},
                           {"event_id": "e2", "timestamp_ns": 2500,
                            "decision_action": "BLOCK"}],
             "fingerprint_edges": [{"fingerprint": "fp_x", "event_id": "e1",
                                     "timestamp_ns": 1500},
                                   {"fingerprint": "fp_y", "event_id": "e2",
                                    "timestamp_ns": 2500}]},
        ]
        result = cache.merge_segments(cache._segments)
        self.assertEqual(len(result["anomalies"]), 2, "e1 跨片段重复只保留一次")
        self.assertEqual(len(result["fingerprint_edges"]), 2)
        # 时间升序
        self.assertEqual([a["event_id"] for a in result["anomalies"]],
                         ["e1", "e2"])

    def test_merge_segments_legacy_segments_compatible(self):
        """旧片段（无新区键）merge 不崩溃，新区为空"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        cache._segments = [{
            "segment_id": "seg_legacy", "start_ns": 1000, "end_ns": 2000,
            "stats": {
                "total": 1, "allow": 1, "alert": 0, "block": 0,
                "risk_dist": {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                "rule_hits": {}, "max_score": 0.1,
            },
            "entry_ids": ["e1"],
        }]
        result = cache.merge_segments(cache._segments)
        self.assertEqual(result["anomalies"], [])
        self.assertEqual(result["fingerprint_edges"], [])
        self.assertEqual(result["merged_stats"]["total"], 1)

    def test_merge_gap_fill_includes_zones(self):
        """间隙填充条目同样进新区（三红线：任一时刻不丢失）"""
        cache = ReportCacheManager(output_dir=self._tmpdir)
        mock_logger = Mock()
        gap = _make_mock_audit_entry("gap1", 1500, "ALERT",
                                     risk_score=0.65, risk_level="HIGH")
        gap.fingerprint = "fp_gap"
        gap.agent_id = "agent-x"
        gap.event_type = "net_conn"
        mock_logger.read_entries.return_value = [gap]
        cache._segments = [{
            "segment_id": "seg_a", "start_ns": 1000, "end_ns": 2000,
            "stats": {
                "total": 1, "allow": 1, "alert": 0, "block": 0,
                "risk_dist": {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                "rule_hits": {}, "max_score": 0.1,
            },
            "entry_ids": ["e1"],
        }]
        result = cache.merge_segments(cache._segments, audit_logger=mock_logger)
        self.assertEqual(result["gaps_filled"], 1)
        self.assertEqual([a["event_id"] for a in result["anomalies"]],
                         ["gap1"], "间隙补充的 ALERT 事件必须进异常明细区")
        self.assertEqual([f["event_id"] for f in result["fingerprint_edges"]],
                         ["gap1"], "间隙补充的指纹边必须进指纹边区")


if __name__ == "__main__":
    unittest.main()
