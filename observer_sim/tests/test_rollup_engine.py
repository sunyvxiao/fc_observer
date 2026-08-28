# -*- coding: utf-8 -*-
"""
test_rollup_engine.py — 分层日志滚动引擎单元测试（阶段 3 L-T6 / L-T7）

覆盖:
1. rollup_hour（L1→L2）: 结构 / 三红线透传 / 序列检测 / 违规升级 /
   指纹关联 / 计算量 O(60) 与事件明细数解耦
2. 调度（accumulate / flush）: 跨桶 flush、满桶 flush、优雅停止 partial
3. GC 集成: 删前累计 L1、rollup 失败不删
4. rollup_day（L2→L3）: 结构 / 三红线透传 / CUSUM 漂移 / m05 式串谋检出
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from observer_core.audit.rollup_engine import (  # noqa: E402
    CusumDetector, RollupEngine, HOUR_NS, DAY_NS,
    hour_bucket_id, day_bucket_id, bucket_start_ns, SEGMENTS_PER_HOUR,
)

BASE_STATS = {
    "total": 1, "allow": 1, "alert": 0, "block": 0,
    "risk_dist": {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
    "rule_hits": {}, "max_score": 0.1,
}


def _make_l1(seg_id, start_ns, entry_ids=None, anomalies=None,
             fp_edges=None, stats=None):
    """构造一个 L1 片段 dict。"""
    return {
        "segment_id": seg_id,
        "start_ns": start_ns,
        "end_ns": start_ns + 60_000_000_000,
        "created_at": "2025-01-01T00:00:00",
        "format_version": 1,
        "stats": stats or dict(BASE_STATS),
        "entry_ids": entry_ids or [],
        "anomalies": anomalies or [],
        "fingerprint_edges": fp_edges or [],
    }


def _make_anomaly(event_id, ts_ns, agent="agent-a", event_type="exec",
                  decision="ALERT", tier="TIER1", blocked=False,
                  score=0.8):
    return {
        "event_id": event_id, "agent_id": agent, "event_type": event_type,
        "timestamp_ns": ts_ns, "decision_action": decision,
        "decision_tier": tier, "blocked": blocked, "risk_score": score,
    }


def _make_edge(event_id, ts_ns, fp, agent="agent-a", event_type="file_open",
               file_path=None, remote_addr=None):
    return {
        "fingerprint": fp, "event_id": event_id, "agent_id": agent,
        "event_type": event_type, "timestamp_ns": ts_ns,
        "file_path": file_path, "remote_addr": remote_addr,
    }


class TestRollupHour(unittest.TestCase):
    """L1→L2 小时日志 rollup 测试。"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="rollup_l2_")
        self._engine = RollupEngine(output_dir=self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_rollup_hour_basic_structure(self):
        segs = [
            _make_l1("seg_1", 1_000, entry_ids=["e1", "e2"]),
            _make_l1("seg_2", 1_060, entry_ids=["e3"]),
        ]
        l2 = self._engine.rollup_hour(segs)
        self.assertEqual(l2["type"], "l2_hour_log")
        self.assertEqual(l2["format_version"], 1)
        self.assertEqual(l2["hour_bucket_id"], hour_bucket_id(1_000))
        self.assertEqual(l2["hour_start_ns"], bucket_start_ns(hour_bucket_id(1_000)))
        self.assertEqual(l2["segment_ids"], ["seg_1", "seg_2"])
        self.assertEqual(l2["stats"]["total"], 2)
        self.assertEqual(l2["entry_ids"], ["e1", "e2", "e3"])
        self.assertFalse(l2["partial"])

    def test_rollup_hour_redline_anomalies_passthrough(self):
        """三红线之异常明细全保留：anomalies 无损透传（去重不丢字段）。"""
        a1 = _make_anomaly("ev_a", 1_100, decision="ALERT", score=0.75)
        a2 = _make_anomaly("ev_b", 1_200, decision="BLOCK", blocked=True,
                           tier="TIER2", score=0.95)
        segs = [
            _make_l1("seg_1", 1_000, anomalies=[a1]),
            _make_l1("seg_2", 1_060, anomalies=[a1, a2]),
        ]
        l2 = self._engine.rollup_hour(segs)
        self.assertEqual(len(l2["anomalies"]), 2)
        by_id = {a["event_id"]: a for a in l2["anomalies"]}
        self.assertEqual(by_id["ev_a"]["decision_action"], "ALERT")
        self.assertEqual(by_id["ev_b"]["blocked"], True)
        self.assertEqual(by_id["ev_b"]["decision_tier"], "TIER2")

    def test_rollup_hour_redline_fp_edges_full_passthrough(self):
        """三红线之指纹边全透传：同指纹两条边保留两条，不聚合。"""
        e1 = _make_edge("f1", 1_100, "fp_x", agent="agent-a")
        e2 = _make_edge("f2", 1_200, "fp_x", agent="agent-b")
        segs = [
            _make_l1("seg_1", 1_000, fp_edges=[e1]),
            _make_l1("seg_2", 1_060, fp_edges=[e2]),
        ]
        l2 = self._engine.rollup_hour(segs)
        self.assertEqual(len(l2["fingerprint_edges"]), 2,
                         "同指纹边必须全量透传不聚合")

    def test_rollup_hour_sequence_alerts(self):
        """分钟级序列检测：file_open→net_conn 外传链命中。"""
        a1 = _make_anomaly("s1", 1_100, event_type="file_open")
        a2 = _make_anomaly("s2", 1_200, event_type="net_conn")
        segs = [_make_l1("seg_1", 1_000, anomalies=[a1, a2])]
        l2 = self._engine.rollup_hour(segs)
        alerts = l2["sequence_alerts"]
        self.assertTrue(any(al["pattern_id"] == "collect_exfil"
                            for al in alerts), f"未检出外传序列: {alerts}")

    def test_rollup_hour_escalation_stats(self):
        """违规累计与升级：tier1 ≥ 5 → escalate_tier2。"""
        anomalies = [_make_anomaly(f"t{i}", 1_100 + i, tier="TIER1")
                     for i in range(5)]
        segs = [_make_l1("seg_1", 1_000, anomalies=anomalies)]
        l2 = self._engine.rollup_hour(segs)
        self.assertEqual(l2["escalation"]["tier_counts"]["TIER1"], 5)
        self.assertTrue(l2["escalation"]["escalate_tier2"])

    def test_rollup_hour_fp_links_cross_agent(self):
        """指纹关联分析：同指纹跨 Agent 标记 cross_agent。"""
        e1 = _make_edge("f1", 1_100, "fp_x", agent="agent-a")
        e2 = _make_edge("f2", 1_200, "fp_x", agent="agent-b")
        segs = [_make_l1("seg_1", 1_000, fp_edges=[e1, e2])]
        l2 = self._engine.rollup_hour(segs)
        links = [l for l in l2["fp_links"] if l["fingerprint"] == "fp_x"]
        self.assertEqual(len(links), 1)
        self.assertTrue(links[0]["cross_agent"])
        self.assertEqual(links[0]["agents"], ["agent-a", "agent-b"])

    def test_rollup_hour_complexity_independent_of_entries(self):
        """计算量 O(60 片段)：entry_ids 巨量不影响 rollup 耗时。"""
        huge_ids = [f"evt_{i}" for i in range(100_000)]
        segs = [_make_l1(f"seg_{i}", 1_000 + i, entry_ids=huge_ids)
                for i in range(60)]
        started = time.time()
        l2 = self._engine.rollup_hour(segs)
        elapsed = time.time() - started
        self.assertEqual(len(l2["entry_ids"]), 100_000)
        self.assertLess(elapsed, 5.0,
                        f"rollup 耗时应与事件明细数解耦: {elapsed:.2f}s")

    def test_rollup_hour_partial_flag(self):
        l2 = self._engine.rollup_hour([_make_l1("seg_1", 1_000)],
                                      partial=True)
        self.assertTrue(l2["partial"])


class TestRollupScheduling(unittest.TestCase):
    """accumulate / flush 调度测试（GC 驱动）。"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="rollup_sched_")
        self._engine = RollupEngine(output_dir=self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_accumulate_flushes_on_bucket_change(self):
        """跨小时桶时 flush 旧桶生成 L2（虚拟时间语义）。"""
        hour0 = bucket_start_ns(1000)
        hour1 = bucket_start_ns(1001)
        for i in range(5):
            self.assertIsNone(self._engine.accumulate_l1(
                _make_l1(f"h0_{i}", hour0 + i)))
        self.assertEqual(self._engine.pending_buckets, 1)
        l2 = self._engine.accumulate_l1(_make_l1("h1_0", hour1))
        self.assertIsNotNone(l2, "跨桶必须触发旧桶 flush")
        self.assertEqual(l2["hour_bucket_id"], 1000)
        self.assertEqual(len(l2["segment_ids"]), 5)
        self.assertFalse(l2["partial"])
        self.assertEqual(self._engine.pending_buckets, 1)

    def test_accumulate_flushes_on_full_bucket(self):
        """满 60 片段时 flush 当前桶。"""
        hour0 = bucket_start_ns(1000)
        result = None
        for i in range(SEGMENTS_PER_HOUR):
            result = self._engine.accumulate_l1(
                _make_l1(f"seg_{i}", hour0 + i))
        self.assertIsNotNone(result, "满桶必须触发 flush")
        self.assertEqual(len(result["segment_ids"]), SEGMENTS_PER_HOUR)
        self.assertEqual(self._engine.pending_buckets, 0)
        # 产物落盘且可列出
        self.assertEqual(len(self._engine.list_l2()), 1)

    def test_flush_all_partial(self):
        """优雅停止 flush：半满桶以 partial 生成 L2，数据不丢。"""
        hour0 = bucket_start_ns(1000)
        for i in range(3):
            self._engine.accumulate_l1(_make_l1(f"seg_{i}", hour0 + i))
        results = self._engine.flush_all()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["partial"])
        self.assertEqual(len(results[0]["segment_ids"]), 3)
        self.assertEqual(self._engine.pending_buckets, 0)

    def test_rollup_day_empty_input_raises(self):
        with self.assertRaises(ValueError):
            self._engine.rollup_day([])


class TestGcIntegration(unittest.TestCase):
    """ReportCacheManager GC 与 RollupEngine 集成测试。"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="rollup_gc_")
        from observer_core.audit.report_cache import ReportCacheManager
        self._cache = ReportCacheManager(output_dir=self._tmpdir)
        self._engine = RollupEngine(output_dir=self._tmpdir)
        self._cache.set_rollup_engine(self._engine)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_gc_accumulates_l1_before_delete(self):
        """GC 删片段前先累计 L1；跨桶时生成 L2（L-T6）。"""
        hour0 = bucket_start_ns(1000)
        hour1 = bucket_start_ns(1001)
        self._cache._segments = [
            _make_l1("old_a", hour0, entry_ids=["e1"]),
            _make_l1("old_b", hour1, entry_ids=["e2"]),
        ]
        for i in range(self._cache.MAX_SEGMENTS):
            self._cache._segments.append(
                _make_l1(f"fill_{i}", hour1 + i, entry_ids=[]))
        self._cache._gc_segments()
        # old_a 被累计进旧桶并触发 L2
        self.assertFalse(any(s["segment_id"] == "old_a"
                             for s in self._cache._segments))
        l2s = self._engine.list_l2()
        self.assertEqual(len(l2s), 1)
        self.assertEqual(l2s[0]["hour_bucket_id"], 1000)
        # 三红线：entry_ids 透传进 L2
        self.assertIn("e1", l2s[0]["entry_ids"])

    def test_gc_rollup_failure_keeps_segment(self):
        """rollup 失败时不删片段（数据不丢）。"""
        failing = Mock(side_effect=RuntimeError("boom"))
        self._cache._rollup_engine.accumulate_l1 = failing
        self._cache._segments = [_make_l1("old_a", 1_000, entry_ids=["e1"])]
        for i in range(self._cache.MAX_SEGMENTS):
            self._cache._segments.append(_make_l1(f"fill_{i}", 2_000 + i))
        self._cache._gc_segments()
        self.assertTrue(any(s["segment_id"] == "old_a"
                            for s in self._cache._segments),
                        "rollup 失败时片段不得删除")

    def test_flush_rollup_via_cache(self):
        """优雅停止：cache.flush_rollup 透传引擎 partial flush。"""
        hour0 = bucket_start_ns(1000)
        self._engine.accumulate_l1(_make_l1("seg_1", hour0))
        results = self._cache.flush_rollup()
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["partial"])


class TestCusumDetector(unittest.TestCase):
    """CUSUM 漂移检测器单元测试。"""

    def test_cusum_no_drift(self):
        det = CusumDetector(k=0.5, h=2.0)
        values = [10.0] * 24
        result = det.detect(values, baseline_mean=10.0)
        self.assertFalse(result["alerted"])

    def test_cusum_drift_detected(self):
        det = CusumDetector(k=0.5, h=2.0)
        values = [10.0] * 12 + [12.0] * 12   # 后半段漂移
        result = det.detect(values, baseline_mean=10.0)
        self.assertTrue(result["alerted"])
        self.assertIsNotNone(result["alert_index"])
        self.assertGreaterEqual(result["alert_index"], 12)

    def test_cusum_parameter_sensitivity(self):
        """h 越大越不敏感（参数边界）。"""
        strict = CusumDetector(k=0.5, h=10.0)
        values = [10.0] * 12 + [11.0] * 12
        self.assertFalse(strict.detect(values, 10.0)["alerted"])
        loose = CusumDetector(k=0.1, h=1.0)
        self.assertTrue(loose.detect(values, 10.0)["alerted"])


class TestRollupDay(unittest.TestCase):
    """L2→L3 天级审计 rollup 测试。"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="rollup_l3_")
        self._engine = RollupEngine(output_dir=self._tmpdir)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_l2(self, hour_bucket, anomalies=None, fp_edges=None,
                 stats=None, entry_ids=None):
        hour_start = bucket_start_ns(hour_bucket)
        return {
            "type": "l2_hour_log",
            "format_version": 1,
            "hour_bucket_id": hour_bucket,
            "hour_start_ns": hour_start,
            "hour_end_ns": hour_start + HOUR_NS,
            "start_ns": hour_start,
            "end_ns": hour_start + HOUR_NS - 1,
            "created_at": "2025-01-01T00:00:00",
            "segment_ids": [f"seg_{hour_bucket}"],
            "stats": stats or dict(BASE_STATS),
            "entry_ids": entry_ids or [],
            "anomalies": anomalies or [],
            "fingerprint_edges": fp_edges or [],
            "sequence_alerts": [],
            "escalation": {},
            "fp_links": [],
            "partial": False,
        }

    def test_rollup_day_basic_structure(self):
        day_bucket = 1000
        first_hour = day_bucket * 24
        l2s = [self._make_l2(first_hour + h, entry_ids=[f"e{h}"])
               for h in range(24)]
        l3 = self._engine.rollup_day(l2s)
        self.assertEqual(l3["type"], "l3_daily_audit")
        self.assertEqual(l3["day_bucket_id"], day_bucket)
        self.assertEqual(l3["l2_count"], 24)
        self.assertEqual(len(l3["entry_ids"]), 24)
        self.assertEqual(len(l3["hourly_vector"]), 24)

    def test_rollup_day_redline_passthrough(self):
        """三红线：anomalies / fingerprint_edges 从 L2 无损透传到 L3。"""
        day_bucket = 1000
        first_hour = day_bucket * 24
        a1 = _make_anomaly("ev_a", first_hour * HOUR_NS + 100,
                           decision="ALERT", score=0.77)
        e1 = _make_edge("f1", first_hour * HOUR_NS + 200, "fp_x",
                        agent="agent-a")
        l2s = [
            self._make_l2(first_hour, anomalies=[a1], fp_edges=[e1]),
        ] + [self._make_l2(first_hour + h) for h in range(1, 24)]
        l3 = self._engine.rollup_day(l2s)
        self.assertEqual(len(l3["anomalies"]), 1)
        self.assertEqual(l3["anomalies"][0]["decision_action"], "ALERT")
        self.assertEqual(len(l3["fingerprint_edges"]), 1)

    def test_rollup_day_cusum_drift_alert(self):
        """CUSUM 漂移：后半段小时 event_rate 上升被检出。"""
        day_bucket = 1000
        first_hour = day_bucket * 24
        l2s = []
        for h in range(24):
            stats = dict(BASE_STATS)
            if h >= 12:
                stats["total"] = 50   # 后半段事件率漂移
                stats["allow"] = 48
                stats["alert"] = 2
            l2s.append(self._make_l2(first_hour + h, stats=stats))
        l3 = self._engine.rollup_day(l2s)
        self.assertTrue(l3["drift_alerts"],
                        f"事件率漂移未被 CUSUM 检出: {l3['drift_alerts']}")
        self.assertTrue(any(a["dimension"] == "event_rate"
                            for a in l3["drift_alerts"]))

    def test_rollup_day_collusion_m05_style_detected(self):
        """m05 式分散攻击：A 写暂存 → 4 小时后 B 读同路径 → B 外传。

        跨 Agent 路径传递链（op 不同指纹不同）+ 外传终点 → 检出串谋链。
        """
        day_bucket = 1000
        first_hour = day_bucket * 24
        hour_ns = lambda h: first_hour * HOUR_NS + h * HOUR_NS
        stage = "/tmp/stage/temp_data.json"
        edges_a = [
            _make_edge("a1", hour_ns(0), "fp_read_csv", agent="agent-a",
                       file_path="/data/customers/contacts.csv"),
            _make_edge("a2", hour_ns(0) + 100, "fp_write_stage",
                       agent="agent-a", file_path=stage),
        ]
        edges_b = [
            _make_edge("b1", hour_ns(4), "fp_read_stage", agent="agent-b",
                       file_path=stage),
            _make_edge("b2", hour_ns(4) + 500, "fp_exfil", agent="agent-b",
                       event_type="net_conn", remote_addr="203.0.113.42"),
        ]
        anomalies = [
            _make_anomaly("b1", hour_ns(4), agent="agent-b",
                          event_type="file_open", decision="ALERT"),
            _make_anomaly("b2", hour_ns(4) + 500, agent="agent-b",
                          event_type="net_conn", decision="ALERT"),
        ]
        l2s = [
            self._make_l2(first_hour, fp_edges=edges_a),
            self._make_l2(first_hour + 4, anomalies=anomalies,
                          fp_edges=edges_b),
        ] + [self._make_l2(first_hour + h) for h in [1, 2, 3, 5]]
        # 补满 24 小时
        l2s += [self._make_l2(first_hour + h) for h in range(6, 24)]
        l3 = self._engine.rollup_day(l2s)
        chains = l3["collusion_chains"]
        self.assertTrue(chains, f"m05 式分散攻击未被检出: {l3}")
        # 检出链必须包含路径传递轴与跨 Agent 外传
        path_chains = [c for c in chains
                       if c["object_kind"] == "file_path"
                       and c["object"] == stage]
        self.assertTrue(path_chains, f"缺路径传递链: {chains}")
        chain = path_chains[0]
        self.assertEqual(chain["agents"], ["agent-a", "agent-b"])
        self.assertGreaterEqual(chain["span_hours"], 3.0)
        self.assertIn("b2", chain["exfil_events"])

    def test_rollup_day_no_collusion_without_exfil(self):
        """无外传终点时不产生串谋误报。"""
        day_bucket = 1000
        first_hour = day_bucket * 24
        stage = "/tmp/stage/temp_data.json"
        l2s = [
            self._make_l2(first_hour, fp_edges=[
                _make_edge("a1", first_hour * HOUR_NS, "fp_w", agent="agent-a",
                           file_path=stage)]),
            self._make_l2(first_hour + 4, fp_edges=[
                _make_edge("b1", (first_hour + 4) * HOUR_NS, "fp_r",
                           agent="agent-b", file_path=stage)]),
        ] + [self._make_l2(first_hour + h) for h in range(1, 24) if h != 4]
        l3 = self._engine.rollup_day(l2s)
        self.assertEqual(l3["collusion_chains"], [],
                         "无 net_conn 外传时不得误报串谋")

    def test_rollup_day_complexity_o24(self):
        """计算量 O(24)：L2 内巨量 entry_ids 不影响 L3 耗时。"""
        day_bucket = 1000
        first_hour = day_bucket * 24
        huge_ids = [f"evt_{i}" for i in range(50_000)]
        l2s = [self._make_l2(first_hour + h, entry_ids=huge_ids)
               for h in range(24)]
        started = time.time()
        l3 = self._engine.rollup_day(l2s)
        elapsed = time.time() - started
        self.assertEqual(len(l3["entry_ids"]), 50_000)
        self.assertLess(elapsed, 5.0,
                        f"L3 耗时与事件明细数解耦: {elapsed:.2f}s")

    def test_save_and_list_l3(self):
        day_bucket = 1000
        first_hour = day_bucket * 24
        l3 = self._engine.rollup_day(
            [self._make_l2(first_hour + h) for h in range(24)])
        path = self._engine.save_l3(l3)
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(len(self._engine.list_l3()), 1)


if __name__ == "__main__":
    unittest.main()
