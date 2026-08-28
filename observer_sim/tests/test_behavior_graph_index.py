"""
test_behavior_graph_index.py — T6 图谱时间分桶索引等价性测试

验证 BehaviorGraph._detect_cross_agent_edges 的时间分桶索引实现
与"直接全量遍历"参考算法（oracle，旧实现语义）产生的 cross_agent
边集合完全一致，并验证极端密度下检测不再 O(n²)。

覆盖场景:
1. 随机 1000 事件（多 Agent、密集/稀疏/乱序时间戳）→ 边集合等价
2. 密集同桶（同一时间戳多 Agent 交替）
3. 乱序插入（新事件时间戳早于已有事件）
4. 时间窗口边界（恰好 1s 含/略超 1s 不含）
5. 桶边界（事件紧贴 100ms 桶边界两侧，验证 ±10 桶覆盖不遗漏）
6. 极端密度性能（1e5 节点规模下 1e5 次检测总成本 < 5 秒）
7. reset 清空桶索引
"""

import sys
import os
import random
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.event import RawEvent, NormalizedEvent
from observer_core.audit.behavior_graph import (
    BehaviorGraph, BehaviorNode, CROSS_AGENT_WINDOW_NS, BUCKET_WIDTH_NS, _bucket_id,
)


def _make_event(event_id: str, agent_id: str, timestamp_ns: int) -> NormalizedEvent:
    """创建测试用 NormalizedEvent（exec 类型）。"""
    raw = RawEvent(
        event_id=event_id,
        timestamp_ns=timestamp_ns,
        event_type="exec",
        pid=10001,
        ppid=1,
        agent_id=agent_id,
        agent_framework="LangChain",
        executable="/usr/bin/git",
        arguments=["status"],
    )
    return NormalizedEvent(raw=raw)


def _oracle_cross_agent_edges(events):
    """
    参考算法：旧实现的"全量遍历"语义。
    events: [(node_id, agent_id, timestamp_ns)]，按插入顺序。
    每插入一个事件，遍历所有已存在节点，对不同 Agent 且时间差
    <= CROSS_AGENT_WINDOW_NS 的节点建立 (source_id, target_id) 边。
    返回边集合 set[(source_id, target_id)]。
    """
    nodes = {}   # node_id -> (agent_id, timestamp_ns)
    edges = set()
    for node_id, agent_id, ts in events:
        for other_id, (other_agent, other_ts) in nodes.items():
            if other_agent == agent_id:
                continue
            if abs(ts - other_ts) <= CROSS_AGENT_WINDOW_NS:
                edges.add((other_id, node_id))
        nodes[node_id] = (agent_id, ts)
    return edges


def _graph_cross_agent_edges(events):
    """BehaviorGraph 分桶索引实现产生的 cross_agent 边集合。"""
    graph = BehaviorGraph()
    for node_id, agent_id, ts in events:
        graph.add_event(_make_event(node_id, agent_id, ts))
    return {(e.source_id, e.target_id) for e in graph.get_cross_agent_edges()}


class TestBucketIndexEquivalence(unittest.TestCase):
    """时间分桶索引与全量遍历的等价性测试"""

    def test_equivalence_random_1000_events(self):
        """随机 1000 事件（多 Agent、密集/稀疏/乱序）→ 边集合完全一致"""
        rng = random.Random(20260101)
        agents = ["agent-a", "agent-b", "agent-c"]
        base = 1718092800000000000
        events = []
        for i in range(1000):
            aid = rng.choice(agents)
            mode = rng.random()
            if mode < 0.5:
                step = rng.randint(0, 100_000_000)                    # 密集（同桶/相邻桶）
            elif mode < 0.9:
                step = rng.randint(0, 2_000_000_000)                  # 跨窗口边缘
            else:
                step = rng.randint(2_000_000_000, 10_000_000_000)     # 稀疏（超出窗口）
            base += step
            events.append((f"evt-{i}", aid, base))

        # 乱序插入：插入顺序与时间戳顺序不一致
        shuffled = events[:]
        rng.shuffle(shuffled)

        oracle_edges = _oracle_cross_agent_edges(shuffled)
        graph_edges = _graph_cross_agent_edges(shuffled)
        # 随机密集多 Agent 序列必然产生跨 Agent 边，确保测试有效性
        self.assertTrue(oracle_edges, "随机序列未产生跨 Agent 边，seed 需调整")
        self.assertEqual(graph_edges, oracle_edges)

    def test_equivalence_dense_same_bucket(self):
        """密集同桶：100 事件同一时间戳、5 Agent 交替"""
        ts = 1718092800000000000
        events = [(f"e{i}", f"a{i % 5}", ts) for i in range(100)]
        self.assertEqual(_graph_cross_agent_edges(events),
                         _oracle_cross_agent_edges(events))

    def test_equivalence_out_of_order_timestamps(self):
        """乱序插入：新事件时间戳早于已有事件，双向窗口检测仍等价"""
        base = 1718092800000000000
        events = [
            ("e1", "a", base),
            ("e2", "b", base + 500_000_000),
            ("e3", "a", base - 200_000_000),        # 时间戳早于 e1/e2（乱序）
            ("e4", "b", base + 1_200_000_000),
            ("e5", "a", base + 1_700_000_000),
        ]
        self.assertEqual(_graph_cross_agent_edges(events),
                         _oracle_cross_agent_edges(events))

    def test_equivalence_window_boundary(self):
        """时间窗口边界：恰好 1s 建边（含）、略超 1s 不建边"""
        base = 1718092800000000000
        events = [
            ("e1", "a", base),
            ("e2", "b", base + CROSS_AGENT_WINDOW_NS),              # 恰在窗口内
            ("e3", "a", base + 2 * CROSS_AGENT_WINDOW_NS),          # 与 e2 恰差 1s
            ("e4", "b", base + 2 * CROSS_AGENT_WINDOW_NS + 1),      # 超窗口 1ns
        ]
        self.assertEqual(_graph_cross_agent_edges(events),
                         _oracle_cross_agent_edges(events))

    def test_equivalence_bucket_boundary(self):
        """桶边界：事件紧贴 100ms 桶边界两侧，±10 桶覆盖不遗漏"""
        edge = (1718092800000000000 // BUCKET_WIDTH_NS + 1) * BUCKET_WIDTH_NS
        events = [
            ("e1", "a", edge - 1),                                  # 前桶末位
            ("e2", "b", edge),                                      # 后桶首位
            ("e3", "a", edge - CROSS_AGENT_WINDOW_NS),              # 窗口下边界
            ("e4", "b", edge + CROSS_AGENT_WINDOW_NS),              # 窗口上边界
            ("e5", "a", edge - CROSS_AGENT_WINDOW_NS - 1),          # 窗口外 1ns
            ("e6", "b", edge + CROSS_AGENT_WINDOW_NS + 1),          # 窗口外 1ns
        ]
        self.assertEqual(_graph_cross_agent_edges(events),
                         _oracle_cross_agent_edges(events))

    def test_reset_clears_time_buckets(self):
        """reset 后桶索引与节点一并清空"""
        graph = BehaviorGraph()
        graph.add_event(_make_event("e1", "a", 1718092800000000000))
        self.assertTrue(graph._time_buckets)
        graph.reset()
        self.assertEqual(graph._time_buckets, {})
        self.assertEqual(graph.node_count, 0)


class TestBucketIndexPerformance(unittest.TestCase):
    """极端密度性能测试"""

    def test_extreme_density_detection_performance(self):
        """
        1e5 节点规模（单 Agent、10ms 间隔）下执行 1e5 次跨 Agent 检测，
        总成本 < 5 秒 —— 证明检测不再 O(n²)。

        对比基准：旧全量遍历算法同等规模需遍历 sum(i, i=0..1e5) ≈ 5e9
        个节点（预计数十分钟），本机实测分桶检测 1e5 次 ≈ 1.7 秒。

        说明：节点与桶索引直接按 add_event 的登记逻辑填充，绕过
        _update_agent_summary 中既有代码的 sum() 全量求和成本点
        （与本改动无关的独立 O(n²)），聚焦验证本次分桶改动。
        """
        graph = BehaviorGraph()
        base = 1718092800000000000
        step = 10_000_000   # 10ms/事件 → 每 100ms 桶 10 个节点
        n = 100_000

        # 按 add_event 的登记逻辑直接填充节点与桶索引
        for i in range(n):
            eid = f"e{i}"
            ts = base + i * step
            graph._nodes[eid] = BehaviorNode(
                node_id=eid, agent_id="agent-1", event_type="exec",
                description="x", timestamp_ns=ts,
            )
            graph._time_buckets.setdefault(_bucket_id(ts), []).append(eid)

        t0 = time.perf_counter()
        # 1e5 次检测（同 Agent 场景：每事件遍历 ±10 桶内约 210 个候选后
        # 经 agent_id 过滤跳过建边，遍历成本与跨 Agent 场景相同）
        for i in range(n):
            graph._detect_cross_agent_edges(f"new-{i}", "agent-1", base + i * step)
        elapsed = time.perf_counter() - t0

        self.assertLess(elapsed, 5.0)


if __name__ == "__main__":
    unittest.main()
