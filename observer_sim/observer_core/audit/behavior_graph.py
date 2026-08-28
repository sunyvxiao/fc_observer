"""
BehaviorGraph — 简化版行为图谱

核心职责:
1. 构建 Agent 行为节点图（每个事件为一个节点）
2. 建立节点间的因果关系边
3. 支持跨 Agent 节点边（Multi-Agent 串谋检测）
4. 结构化 JSON 输出（便于程序解析和溯源）

输出格式:
- nodes: 行为节点列表（每个事件一个节点）
- edges: 因果关系边列表（含跨 Agent 边）
- agent_summaries: 每个 Agent 的行为摘要
"""

import os
import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.event import NormalizedEvent
from models.risk import RiskAssessment, Decision, DecisionAction, ActionTier, BlockingResult
from observer_core.audit.fingerprint_tracker import FingerprintTracker

logger = logging.getLogger(__name__)

# ── 跨 Agent 检测窗口与时间分桶索引 ─────────────────────────────
CROSS_AGENT_WINDOW_NS = 1_000_000_000  # 1 秒窗口
BUCKET_WIDTH_NS = 100_000_000          # 时间分桶宽度：100ms（窗口 = ±10 桶）


def _bucket_id(timestamp_ns: int) -> int:
    """时间戳 → 分桶 ID（100ms 一桶）。"""
    return timestamp_ns // BUCKET_WIDTH_NS


@dataclass
class BehaviorNode:
    """
    行为节点 — 对应一个已处理的事件。

    字段:
    - node_id: 唯一标识（使用 event_id）
    - agent_id: 所属 Agent
    - event_type: 事件类型 (exec/file_open/net_conn)
    - description: 人类可读描述
    - timestamp_ns: 虚拟时钟时间戳
    - risk_score: 风险评分
    - risk_level: 风险等级
    - decision: 处置动作 (ALLOW/ALERT/BLOCK)
    - tier: 处置等级
    - blocked: 是否被阻断
    - matched_rules: 命中的规则 ID 列表
    - metadata: 附加信息（命令字符串/文件路径/远程地址等）
    """
    node_id: str
    agent_id: str
    event_type: str
    description: str
    timestamp_ns: int
    risk_score: float = 0.0
    risk_level: str = "LOW"
    decision: str = "ALLOW"
    tier: str = "TIER1"
    blocked: bool = False
    matched_rules: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """转为字典（JSON 序列化用）"""
        return {
            "node_id": self.node_id,
            "agent_id": self.agent_id,
            "event_type": self.event_type,
            "description": self.description,
            "timestamp_ns": self.timestamp_ns,
            "risk_score": round(self.risk_score, 4),
            "risk_level": self.risk_level,
            "decision": self.decision,
            "tier": self.tier,
            "blocked": self.blocked,
            "matched_rules": self.matched_rules,
            "metadata": self.metadata,
        }


@dataclass
class BehaviorEdge:
    """
    行为边 — 两个节点之间的因果关系。

    类型:
    - sequential: 同一 Agent 内顺序因果关系
    - cross_agent: 跨 Agent 因果关系（串谋检测关键）
    - escalation: 升级关系（同一事件因违规升级导致 tier 变化）
    """
    source_id: str
    target_id: str
    edge_type: str  # "sequential" | "cross_agent" | "escalation"
    weight: float = 1.0
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "weight": round(self.weight, 4),
            "description": self.description,
        }


@dataclass
class AgentSummary:
    """Agent 行为摘要"""
    agent_id: str
    total_events: int = 0
    allowed: int = 0
    alerted: int = 0
    blocked: int = 0
    avg_risk_score: float = 0.0
    max_risk_score: float = 0.0
    matched_rules: Dict[str, int] = field(default_factory=dict)
    first_event_ns: int = 0
    last_event_ns: int = 0

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "total_events": self.total_events,
            "allowed": self.allowed,
            "alerted": self.alerted,
            "blocked": self.blocked,
            "avg_risk_score": round(self.avg_risk_score, 4),
            "max_risk_score": round(self.max_risk_score, 4),
            "matched_rules": self.matched_rules,
            "first_event_ns": self.first_event_ns,
            "last_event_ns": self.last_event_ns,
        }


class BehaviorGraph:
    """
    行为图谱。

    记录所有事件节点和因果关系边。
    支持跨 Agent 关联分析。
    输出结构化 JSON。
    """

    def __init__(self):
        self._nodes: Dict[str, BehaviorNode] = {}  # node_id -> node
        self._edges: List[BehaviorEdge] = []
        self._agent_summaries: Dict[str, AgentSummary] = {}
        self._agent_last_node: Dict[str, str] = {}  # agent_id -> last_node_id
        self._risk_scores: Dict[str, List[float]] = {}  # agent_id -> [scores]
        # 时间分桶索引：bucket_id -> [node_id, ...]（T6 图谱性能治理，消除 O(n²)）
        self._time_buckets: Dict[int, List[str]] = {}

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    @property
    def nodes(self) -> List[BehaviorNode]:
        return list(self._nodes.values())

    @property
    def edges(self) -> List[BehaviorEdge]:
        return list(self._edges)

    def add_event(self, event: NormalizedEvent,
                  assessment: RiskAssessment = None,
                  decision: Decision = None,
                  blocking_result: BlockingResult = None,
                  matched_rules: List[str] = None) -> BehaviorNode:
        """
        添加事件节点到图谱。

        自动建立因果关系边:
        1. 同 Agent 顺序因果（sequential）
        2. 跨 Agent 关联（如果事件时间窗口内有其他 Agent 活动）
        """
        event_id = event.raw.event_id
        agent_id = event.agent_id

        # 构建节点描述
        description = self._build_description(event)
        metadata = self._build_metadata(event)

        node = BehaviorNode(
            node_id=event_id,
            agent_id=agent_id,
            event_type=event.event_type,
            description=description,
            timestamp_ns=event.timestamp_ns,
            risk_score=assessment.overall_score if assessment else 0.0,
            risk_level=assessment.risk_level.value if assessment else "LOW",
            decision=decision.action.value if decision else "ALLOW",
            tier=decision.tier.value if decision else "TIER1",
            blocked=blocking_result.blocked if blocking_result else False,
            matched_rules=matched_rules or [],
            metadata=metadata,
        )
        self._nodes[event_id] = node

        # 登记时间分桶索引（供跨 Agent 检测按相邻桶查询）
        bucket = _bucket_id(event.timestamp_ns)
        self._time_buckets.setdefault(bucket, []).append(event_id)

        # 更新 Agent 摘要
        self._update_agent_summary(agent_id, node, assessment, decision, blocking_result)

        # 建立顺序因果边（同 Agent 的前一个事件 → 当前事件）
        if agent_id in self._agent_last_node:
            prev_id = self._agent_last_node[agent_id]
            self._edges.append(BehaviorEdge(
                source_id=prev_id,
                target_id=event_id,
                edge_type="sequential",
                weight=1.0,
                description=f"Agent {agent_id} 行为序列",
            ))
        self._agent_last_node[agent_id] = event_id

        # 检测跨 Agent 关联（最近 1000ms 内有其他 Agent 活动）
        self._detect_cross_agent_edges(event_id, agent_id, event.timestamp_ns)

        return node

    def _build_description(self, event: NormalizedEvent) -> str:
        """构建事件的人类可读描述"""
        et = event.event_type
        if et == "exec":
            cmd = event.command_string or ""
            if not cmd:
                parts = [event.raw.executable or ""]
                if event.raw.arguments:
                    parts.extend(event.raw.arguments)
                cmd = " ".join(parts)
            return f"exec: {cmd}"
        elif et == "file_open":
            op = event.raw.file_op or "open"
            path = event.raw.file_path or ""
            return f"file_{op}: {path}"
        elif et == "net_conn":
            addr = event.raw.remote_addr or ""
            port = event.raw.remote_port
            proto = event.raw.protocol or "TCP"
            return f"net_{proto}: {addr}:{port}" if port else f"net_{proto}: {addr}"
        return f"{et}: unknown"

    def _build_metadata(self, event: NormalizedEvent) -> dict:
        """构建附加信息"""
        meta = {
            "pid": event.raw.pid,
            "ppid": event.raw.ppid,
            "agent_framework": event.raw.agent_framework,
        }
        # L-T1: 动作指纹（供阶段 2.3 T3 图谱指纹边复用；
        # 阶段 1 仅预置输出结构，不参与任何判定）
        fingerprint = FingerprintTracker.fingerprint_event(event)[1]
        if fingerprint:
            meta["fingerprint"] = fingerprint
        if event.event_type == "exec":
            meta["executable"] = event.raw.executable
            meta["arguments"] = event.raw.arguments
            if event.command_string:
                meta["command_string"] = event.command_string
        elif event.event_type == "file_open":
            meta["file_path"] = event.raw.file_path
            meta["file_op"] = event.raw.file_op
        elif event.event_type == "net_conn":
            meta["remote_addr"] = event.raw.remote_addr
            meta["remote_port"] = event.raw.remote_port
            meta["protocol"] = event.raw.protocol
        return meta

    def _update_agent_summary(self, agent_id: str, node: BehaviorNode,
                              assessment: RiskAssessment, decision: Decision,
                              blocking_result: BlockingResult = None):
        """更新 Agent 摘要统计"""
        if agent_id not in self._agent_summaries:
            self._agent_summaries[agent_id] = AgentSummary(
                agent_id=agent_id,
                first_event_ns=node.timestamp_ns,
            )
            self._risk_scores[agent_id] = []

        summary = self._agent_summaries[agent_id]
        summary.total_events += 1
        summary.last_event_ns = node.timestamp_ns

        # 统一以 BlockingResult 为最终判定源：升级后的 blocked 优先于原始 decision
        if blocking_result and blocking_result.blocked:
            summary.blocked += 1
        elif decision:
            if decision.action == DecisionAction.ALLOW:
                summary.allowed += 1
            elif decision.action == DecisionAction.ALERT:
                summary.alerted += 1
            elif decision.action == DecisionAction.BLOCK:
                summary.blocked += 1

        score = node.risk_score
        self._risk_scores[agent_id].append(score)
        summary.max_risk_score = max(summary.max_risk_score, score)
        summary.avg_risk_score = sum(self._risk_scores[agent_id]) / len(self._risk_scores[agent_id])

        # 更新规则命中计数
        for rule_id in node.matched_rules:
            summary.matched_rules[rule_id] = summary.matched_rules.get(rule_id, 0) + 1

    def _detect_cross_agent_edges(self, new_node_id: str, new_agent_id: str,
                                  timestamp_ns: int):
        """
        检测跨 Agent 关联边。

        如果最近 1000ms (1_000_000_000 ns) 内有其他 Agent 的活动，
        则建立 cross_agent 边。

        性能：借助时间分桶索引只遍历窗口覆盖的相邻桶（±10 桶），
        与全量遍历算法行为完全等价（见 tests/test_behavior_graph_index.py）。
        """
        first_bucket = _bucket_id(timestamp_ns - CROSS_AGENT_WINDOW_NS)
        last_bucket = _bucket_id(timestamp_ns + CROSS_AGENT_WINDOW_NS)

        for bucket in range(first_bucket, last_bucket + 1):
            for node_id in self._time_buckets.get(bucket, ()):
                if node_id == new_node_id:
                    continue
                node = self._nodes[node_id]
                if node.agent_id == new_agent_id:
                    continue
                # 检查时间窗口（双保险：分桶只收窄候选集，判定仍按精确时间差）
                time_diff = abs(timestamp_ns - node.timestamp_ns)
                if time_diff <= CROSS_AGENT_WINDOW_NS:
                    self._edges.append(BehaviorEdge(
                        source_id=node_id,
                        target_id=new_node_id,
                        edge_type="cross_agent",
                        weight=0.5,
                        description=f"跨 Agent 关联: {node.agent_id} -> {new_agent_id}",
                    ))

    def get_cross_agent_edges(self) -> List[BehaviorEdge]:
        """获取所有跨 Agent 边"""
        return [e for e in self._edges if e.edge_type == "cross_agent"]

    def get_agent_nodes(self, agent_id: str) -> List[BehaviorNode]:
        """获取指定 Agent 的所有节点"""
        return [n for n in self._nodes.values() if n.agent_id == agent_id]

    def get_blocked_nodes(self) -> List[BehaviorNode]:
        """获取所有被阻断的节点"""
        return [n for n in self._nodes.values() if n.blocked]

    def has_cross_agent_edges(self) -> bool:
        """是否存在跨 Agent 边"""
        return any(e.edge_type == "cross_agent" for e in self._edges)

    def to_dict(self) -> dict:
        """转为结构化字典（JSON 序列化用）"""
        return {
            "graph_info": {
                "node_count": self.node_count,
                "edge_count": self.edge_count,
                "agent_count": len(self._agent_summaries),
                "cross_agent_edges": len(self.get_cross_agent_edges()),
                "generated_at": datetime.now().isoformat(),
            },
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "agent_summaries": {
                aid: s.to_dict() for aid, s in self._agent_summaries.items()
            },
        }

    def save_json(self, filepath: str) -> str:
        """保存为 JSON 文件"""
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
        logger.info(f"[BehaviorGraph] Saved to {filepath}")
        return filepath

    def reset(self):
        """重置图谱"""
        self._nodes.clear()
        self._edges.clear()
        self._agent_summaries.clear()
        self._agent_last_node.clear()
        self._risk_scores.clear()
        self._time_buckets.clear()
