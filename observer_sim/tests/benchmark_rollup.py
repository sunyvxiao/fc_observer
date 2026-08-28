# -*- coding: utf-8 -*-
"""
benchmark_rollup.py — 阶段 3 性能验收基准（计划 3.4.4）

验证计算量模型：分层 rollup 链 O(N+60+24) vs 全量重算 O(1440N)。

路径 A（分层链）: 一次性 O(N) 构建 1440 个 L1 片段（每分钟一段）
    → accumulate_l1 × 1440（每小时 60 段满桶触发 L2，O(60) 分析）
    → rollup_day(24 × L2)（O(24) 分析）
路径 B（全量重算）: 逐分钟扫描全部 N 原始事件聚合统计 = O(1440N)

两类断言：
1. 机器无关的操作计数（复杂度结构证明）：
   - 全量重算的逐分钟扫描次数 == 1440 × N（精确等式）
   - 分层链事件级处理量（anomalies/fingerprint_edges 透传合并）≤ 5 × N
   - 扫描次数 / 事件处理量 ≥ 200（1440 次触碰 vs 单次透传的量级差）
2. 墙钟耗时收敛（本机实测，打印供验收记录）：
   - 全量重算随 N 近似线性增长（N2 = 4×N1 → 耗时 > 2×）
   - 大 N 下分层链快于全量重算（≥ 1.5×）
   - 比值 full/rollup 随 N 增大而增长（固定开销摊销，比值收敛）

运行方式（默认跳过，pytest -m perf 显式启用）:
    python -m pytest tests/benchmark_rollup.py -m perf -q -s
"""

import os
import sys
import tempfile
import time
import unittest
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from observer_core.audit.rollup_engine import (
    RollupEngine, day_bucket_id,
)

# 基准规模：1440 分钟（24h），两档 N（4 倍差）
MINUTES_PER_DAY = 1440
BASE_NS = 1718064000000000000          # 2024-06-11 00:00 UTC
MINUTE_NS = 60_000_000_000
N_SMALL = 15000
N_LARGE = 60000


def _build_events(n):
    """合成 N 事件/天（原始事件 dict，模拟 L0 解析后的形态）。

    分钟位置 (i*37) % 1440 伪随机打散（gcd(37,1440)=1，均匀覆盖全天）。
    5% ALERT（高危明细）、0.1% net_conn（外传终点），指纹按事件唯一
    （真实数据指纹大多唯一，串谋分析受异常指纹数约束）。
    """
    events = []
    for i in range(n):
        minute = (i * 37) % MINUTES_PER_DAY
        if i % 1000 == 0:
            etype = "net_conn"
            action, score, blocked = "ALLOW", 0.3, False
        elif i % 20 == 0:
            etype = "file_read"
            action, score, blocked = "ALERT", 0.7, False
        else:
            etype = "file_read"
            action, score, blocked = "ALLOW", 0.1, False
        events.append({
            "id": f"e{i}",
            # L0 JSONL 形态：时间戳为字符串，逐分钟重算需每次扫描解析
            "minute": str(minute),
            "score": score,
            "action": action, "blocked": blocked,
            "agent": f"agent-{'a' if i % 2 else 'b'}",
            "fp": f"fp-{i}", "etype": etype,
        })
    return events


def _build_segments(events):
    """O(N)：按分钟分桶 → 1440 个 L1 片段（stats/anomalies/fingerprint_edges）。

    三红线形状与生产一致：异常明细全保留 + 指纹边全量透传（不聚合）。
    """
    buckets = {m: [] for m in range(MINUTES_PER_DAY)}
    for e in events:
        buckets[int(e["minute"])].append(e)
    segments = []
    seg_counter = 0
    for minute in range(MINUTES_PER_DAY):
        chunk = buckets[minute]
        if not chunk:
            continue
        total = len(chunk)
        allowed = sum(1 for e in chunk if e["action"] == "ALLOW" and not e["blocked"])
        alerted = sum(1 for e in chunk if e["action"] == "ALERT" and not e["blocked"])
        blocked = sum(1 for e in chunk if e["blocked"])
        start_ns = BASE_NS + minute * MINUTE_NS
        anomalies = []
        fp_edges = []
        for e in chunk:
            fp_edges.append({
                "fingerprint": e["fp"], "event_id": e["id"],
                "agent_id": e["agent"], "event_type": e["etype"],
                "timestamp_ns": start_ns, "file_path": None,
                "remote_addr": ("203.0.113.42"
                                if e["etype"] == "net_conn" else None),
            })
            if e["blocked"] or e["action"] == "ALERT" or e["score"] >= 0.6:
                anomalies.append({
                    "event_id": e["id"], "agent_id": e["agent"],
                    "event_type": e["etype"], "timestamp_ns": start_ns,
                    "risk_score": e["score"], "decision_action": e["action"],
                    "blocked": e["blocked"], "decision_tier": "TIER1",
                    "decision_reason": "synthetic", "decision_chain": [],
                    "file_path": None, "fingerprint": e["fp"],
                })
        seg_counter += 1
        segments.append({
            "segment_id": f"seg_{seg_counter:04d}",
            "start_ns": start_ns,
            "end_ns": start_ns + MINUTE_NS,
            "format_version": 1,
            "stats": {
                "total": total, "allow": allowed,
                "alert": alerted, "block": blocked,
                "risk_dist": {"LOW": allowed, "MEDIUM": 0,
                              "HIGH": alerted, "CRITICAL": 0},
                "rule_hits": {},
                "max_score": max(e["score"] for e in chunk),
            },
            "entry_ids": [e["id"] for e in chunk],
            "anomalies": anomalies,
            "fingerprint_edges": fp_edges,
        })
    return segments


def _run_rollup_chain(segments, out_dir):
    """分层链：L1 片段 × 1440 → 24 × L2（O(60)/小时）→ L3（O(24)）。

    Returns: (l2s, l3, zone_touches)
    zone_touches: anomalies/fingerprint_edges 透传合并的事件级处理量
    （_merge_zone 计数包装，机器无关的复杂度证据）。
    """
    import observer_core.audit.rollup_engine as re_mod

    counter = {"touches": 0}
    real_merge = re_mod._merge_zone

    def _counting_merge(segments_like, key, id_key="event_id"):
        counter["touches"] += sum(len(s.get(key) or [])
                                  for s in segments_like)
        return real_merge(segments_like, key, id_key=id_key)

    engine = RollupEngine(out_dir)
    with mock.patch.object(re_mod, "_merge_zone", new=_counting_merge):
        for seg in segments:
            engine.accumulate_l1(seg)
        engine.flush_all()
        l2s = engine.list_l2()
        l3 = engine.rollup_day(l2s)
    return l2s, l3, counter["touches"]


def _full_recompute(events):
    """O(1440N)：逐分钟扫描全部 N 原始事件聚合（无摘要层的朴素重算）。

    Returns: (per_minute, comparisons)
    comparisons: 逐分钟扫描的总比较次数（== 1440 × N，复杂度结构证据）。
    """
    evs = events
    per_minute = []
    comparisons = 0
    for minute in range(MINUTES_PER_DAY):
        total = 0
        alert = 0
        block = 0
        for e in evs:
            comparisons += 1
            # L0 时间戳为字符串：每次扫描需解析（真实逐分钟重算成本）
            if int(e["minute"]) != minute:
                continue
            total += 1
            if e["blocked"]:
                block += 1
            elif e["action"] == "ALERT":
                alert += 1
        per_minute.append((total, alert, block))
    return per_minute, comparisons


@pytest.mark.perf
class TestRollupComplexityBenchmark(unittest.TestCase):
    """O(N+60+24) vs O(1440N) 对比（计划 3.4.4 性能验收）。"""

    def test_rollup_chain_vs_full_recompute_convergence(self):
        """操作计数证明复杂度结构 + 墙钟耗时比值随 N 收敛增长。"""
        # ── N1（小档）────────────────────────────────────────────
        t0 = time.perf_counter()
        events_small = _build_events(N_SMALL)
        segs_small = _build_segments(events_small)
        t_build1 = time.perf_counter() - t0

        with tempfile.TemporaryDirectory() as tmp:
            t0 = time.perf_counter()
            l2s_small, l3_small, touches1 = _run_rollup_chain(segs_small, tmp)
            t_chain1 = time.perf_counter() - t0
        t0 = time.perf_counter()
        _, comparisons1 = _full_recompute(events_small)
        t_full1 = time.perf_counter() - t0
        t_rollup1 = t_build1 + t_chain1

        # ── N2（大档，4×）────────────────────────────────────────
        t0 = time.perf_counter()
        events_large = _build_events(N_LARGE)
        segs_large = _build_segments(events_large)
        t_build2 = time.perf_counter() - t0

        with tempfile.TemporaryDirectory() as tmp:
            t0 = time.perf_counter()
            l2s_large, l3_large, touches2 = _run_rollup_chain(segs_large, tmp)
            t_chain2 = time.perf_counter() - t0
        t0 = time.perf_counter()
        _, comparisons2 = _full_recompute(events_large)
        t_full2 = time.perf_counter() - t0
        t_rollup2 = t_build2 + t_chain2

        ratio1 = t_full1 / max(t_rollup1, 1e-9)
        ratio2 = t_full2 / max(t_rollup2, 1e-9)

        print(f"\n[benchmark] N={N_SMALL}: "
              f"L1构建={t_build1:.3f}s 链={t_chain1:.3f}s "
              f"rollup合计={t_rollup1:.3f}s 全量重算={t_full1:.3f}s "
              f"比值={ratio1:.1f}x "
              f"扫描={comparisons1}(1440N={1440 * N_SMALL}) "
              f"事件处理量={touches1}")
        print(f"[benchmark] N={N_LARGE}: "
              f"L1构建={t_build2:.3f}s 链={t_chain2:.3f}s "
              f"rollup合计={t_rollup2:.3f}s 全量重算={t_full2:.3f}s "
              f"比值={ratio2:.1f}x "
              f"扫描={comparisons2}(1440N={1440 * N_LARGE}) "
              f"事件处理量={touches2}")

        # ── 结构不变式：两档 N 均产出 24 个 L2 + 完整天级 L3 ──────
        self.assertEqual(len(l2s_small), 24)
        self.assertEqual(len(l2s_large), 24)
        self.assertEqual(l3_small["stats"]["total"], N_SMALL)
        self.assertEqual(l3_large["stats"]["total"], N_LARGE)

        # ── 机器无关：复杂度结构证明 ─────────────────────────────
        # 全量重算 = 逐分钟全扫描：比较次数精确等于 1440 × N
        self.assertEqual(comparisons1, 1440 * N_SMALL)
        self.assertEqual(comparisons2, 1440 * N_LARGE)
        # 分层链 = 单次透传：事件级处理量 O(N)（含余量上限 5N）
        self.assertLessEqual(touches1, 5 * N_SMALL)
        self.assertLessEqual(touches2, 5 * N_LARGE)
        # 1440 次触碰 vs 单次透传的量级差（≥ 200 倍余量）
        self.assertGreaterEqual(comparisons1, 200 * touches1)
        self.assertGreaterEqual(comparisons2, 200 * touches2)

        # ── 墙钟：线性增长 + 显著优势 + 比值收敛增长 ─────────────
        # 全量重算随 N 近似线性增长（4× 数据 → 至少 2× 耗时）
        self.assertGreater(t_full2, t_full1 * 2.0,
                           f"全量重算应随 N 近似线性增长: "
                           f"{t_full2:.3f}s vs {t_full1:.3f}s")
        # 分层链在大 N 下快于全量重算（本机墙钟验证；复杂度结构
        # 已由上方机器无关的操作计数断言证明：1440N 扫描 vs ≤5N 透传）
        self.assertGreater(t_full2, t_rollup2 * 1.5,
                           f"分层链应快于全量重算: "
                           f"rollup={t_rollup2:.3f}s full={t_full2:.3f}s")
        # 比值随 N 增大而增长（固定开销摊销 → 比值向 O(1440) 收敛）
        self.assertGreaterEqual(ratio2, ratio1 * 1.1,
                                f"比值应随 N 增大收敛增长: "
                                f"{ratio1:.1f}x → {ratio2:.1f}x")

    def test_rollup_stats_match_full_recompute(self):
        """正确性交叉验证：分层链 L2/L3 统计与全量重算逐小时一致。"""
        events = _build_events(12000)
        segments = _build_segments(events)
        with tempfile.TemporaryDirectory() as tmp:
            l2s, l3, touches = _run_rollup_chain(segments, tmp)
        per_minute, comparisons = _full_recompute(events)

        self.assertEqual(comparisons, 1440 * 12000)
        self.assertLessEqual(touches, 5 * 12000)

        # 小时聚合（全量重算口径）
        hourly = {}
        for m, (t, a, b) in enumerate(per_minute):
            h = hourly.setdefault(m // 60, [0, 0, 0])
            h[0] += t
            h[1] += a
            h[2] += b

        by_hour = {l["hour_bucket_id"]: l for l in l2s}
        day_bucket = day_bucket_id(BASE_NS)
        self.assertEqual(len(l2s), 24)
        for hour in range(24):
            l2 = by_hour[day_bucket * 24 + hour]
            self.assertEqual(l2["stats"]["total"], hourly[hour][0],
                             f"小时 {hour} total 不一致")
            self.assertEqual(l2["stats"]["alert"], hourly[hour][1],
                             f"小时 {hour} alert 不一致")
            self.assertEqual(l2["stats"]["block"], hourly[hour][2],
                             f"小时 {hour} block 不一致")

        # 天级：L3 统计 + 三红线透传（异常明细 / 指纹边全量）
        self.assertEqual(l3["stats"]["total"], len(events))
        self.assertEqual(len(l3["anomalies"]),
                         sum(1 for e in events if e["action"] == "ALERT"))
        self.assertEqual(len(l3["fingerprint_edges"]), len(events))


if __name__ == "__main__":
    unittest.main()
