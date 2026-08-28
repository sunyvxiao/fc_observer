# -*- coding: utf-8 -*-
"""
rollup_engine.py — 分层日志滚动引擎（L-T6 / L-T7）

分层滚动摘要金字塔（阶段 3）的核心模块：

    L1 片段（ReportCacheManager，60s/段，stats + anomalies + fingerprint_edges）
        │  rollup_hour()  每 60 个片段 / 跨小时桶边界
        ▼
    L2 小时日志（小时级审计：分钟级序列模式检测、违规累计与升级、指纹关联分析）
        │  rollup_day()   每 24 个 L2 / 跨天桶边界
        ▼
    L3 天级审计（CUSUM 基线漂移检测、跨 Agent 串谋全图分析）

三红线贯穿（任何一项实现不得违反）：
1. 异常明细全保留 —— anomalies 区从 L1 一路原样透传到 L3；
2. 指纹边全透传   —— fingerprint_edges 区全量透传，仅去重、绝不聚合；
3. L0 永不删除    —— 本模块不触碰 audit_*.jsonl（L0），只消费摘要层。

时间桶语义：一律按事件 timestamp_ns（虚拟时钟）分桶，不按墙钟——
虚拟时钟可在数秒内推进数小时（如 m05 的 4 小时 delay），墙钟分桶会漏桶。

计算量：L2 = O(60 片段)（只读 stats/anomalies/fingerprint_edges，不逐条
处理事件明细）；L3 = O(24 小时)。全链 O(N+60+24) 而非 O(1440N)。

本模块为纯逻辑 + 产物落盘，不依赖 daemon/线程，可直接单测。
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = None
try:
    import logging
    logger = logging.getLogger(__name__)
except Exception:  # noqa: BLE001
    pass


# ── 时间桶常量 ────────────────────────────────────────────────────────────
HOUR_NS = 3_600_000_000_000          # 1 小时（纳秒）
DAY_NS = 24 * HOUR_NS                # 1 天（纳秒）
SEGMENTS_PER_HOUR = 60               # L1 片段容量（60s × 60 = 1 小时）
L2_PER_DAY = 24                      # L2 容量（24 × 1h = 1 天）

# 分钟级序列检测窗口（模板匹配要求窗口内时间跨度 ≤ 10 分钟）
SEQUENCE_WINDOW_NS = 10 * 60 * 1_000_000_000

# 串谋链外传判定：指纹链终点为 net_conn 即视为数据外发
COLLUSION_MIN_SPAN_NS = HOUR_NS      # 跨 Agent 串谋最小时间跨度（≥1 小时）

# 已知攻击序列模板（event_type 短序列，2~4 元，在异常明细时间序列上匹配）
ATTACK_SEQUENCE_TEMPLATES = [
    {"pattern_id": "stage_exfil",
     "sequence": ["file_open", "file_open", "net_conn"],
     "description": "暂存-压缩-外传链（敏感文件写暂存区后网络外发）"},
    {"pattern_id": "collect_exfil",
     "sequence": ["file_open", "net_conn"],
     "description": "读取敏感文件后网络外发"},
    {"pattern_id": "download_exec",
     "sequence": ["net_conn", "exec"],
     "description": "网络下载后执行（下载即执行）"},
    {"pattern_id": "persist_exec",
     "sequence": ["file_open", "exec"],
     "description": "文件写入后执行（植入后运行）"},
]

# L2 / L3 产物格式版本（旧格式无 format_version → 视作 0）
FORMAT_VERSION = 1


def hour_bucket_id(timestamp_ns: int) -> int:
    """时间戳 → 小时桶 ID（ns // HOUR_NS，虚拟时间语义）。"""
    return int(timestamp_ns) // HOUR_NS


def day_bucket_id(timestamp_ns: int) -> int:
    """时间戳 → 天桶 ID（ns // DAY_NS，虚拟时间语义）。"""
    return int(timestamp_ns) // DAY_NS


def bucket_start_ns(bucket_id: int, width_ns: int = HOUR_NS) -> int:
    """桶 ID → 桶起始时间戳。"""
    return int(bucket_id) * width_ns


def _iso(ns: int) -> str:
    """纳秒时间戳 → ISO 字符串（虚拟时间可解释为真实历元）。"""
    try:
        return datetime.fromtimestamp(int(ns) / 1_000_000_000,
                                      tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return str(ns)


def _merge_stats(segments: List[dict]) -> dict:
    """合并多个 L1/L2 的 stats 区（加法 + max）。"""
    merged = {
        "total": 0, "allow": 0, "alert": 0, "block": 0,
        "risk_dist": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
        "rule_hits": {}, "max_score": 0.0,
    }
    for seg in segments:
        stats = seg.get("stats") or {}
        merged["total"] += stats.get("total", 0)
        merged["allow"] += stats.get("allow", 0)
        merged["alert"] += stats.get("alert", 0)
        merged["block"] += stats.get("block", 0)
        if stats.get("max_score", 0) > merged["max_score"]:
            merged["max_score"] = stats["max_score"]
        for level, count in (stats.get("risk_dist") or {}).items():
            if level in merged["risk_dist"]:
                merged["risk_dist"][level] += count
        for rule_id, count in (stats.get("rule_hits") or {}).items():
            merged["rule_hits"][rule_id] = (
                merged["rule_hits"].get(rule_id, 0) + count)
    return merged


def _merge_zone(segments: List[dict], key: str,
                id_key: str = "event_id") -> List[dict]:
    """透传合并新区（anomalies/fingerprint_edges）：去重 + 时间升序。"""
    seen = set()
    merged: List[dict] = []
    for seg in segments:
        for item in (seg.get(key) or []):
            item_id = item.get(id_key)
            if item_id and item_id in seen:
                continue
            if item_id:
                seen.add(item_id)
            merged.append(item)
    merged.sort(key=lambda x: x.get("timestamp_ns", 0))
    return merged


def _detect_sequences(anomalies: List[dict]) -> List[dict]:
    """分钟级序列模式检测：异常明细时间序列上匹配已知攻击模板（2~4 元）。"""
    alerts: List[dict] = []
    if len(anomalies) < 2:
        return alerts
    ordered = sorted(anomalies, key=lambda a: a.get("timestamp_ns", 0))
    types = [a.get("event_type", "") for a in ordered]
    for tmpl in ATTACK_SEQUENCE_TEMPLATES:
        seq = tmpl["sequence"]
        k = len(seq)
        for i in range(len(types) - k + 1):
            if types[i:i + k] != seq:
                continue
            window = ordered[i:i + k]
            span = (window[-1].get("timestamp_ns", 0)
                    - window[0].get("timestamp_ns", 0))
            if span > SEQUENCE_WINDOW_NS:
                continue
            alerts.append({
                "pattern_id": tmpl["pattern_id"],
                "description": tmpl["description"],
                "event_ids": [a.get("event_id", "") for a in window],
                "first_ns": window[0].get("timestamp_ns", 0),
                "last_ns": window[-1].get("timestamp_ns", 0),
            })
    return alerts


def _escalation_stats(anomalies: List[dict],
                      params: Optional[dict] = None) -> dict:
    """违规累计与升级：小时级复用 5 分钟窗口的升级语义（阈值可参数化）。"""
    params = params or {}
    tier1_th = params.get("tier1_escalate_threshold", 5)
    tier2_th = params.get("tier2_escalate_threshold", 3)
    tier_counts = {"TIER1": 0, "TIER2": 0, "TIER3": 0}
    blocked = 0
    for a in anomalies:
        tier = a.get("decision_tier", "")
        if tier in tier_counts:
            tier_counts[tier] += 1
        if a.get("blocked"):
            blocked += 1
    escalate_tier2 = tier_counts["TIER1"] >= tier1_th
    escalate_tier3 = tier_counts["TIER2"] >= tier2_th or tier_counts["TIER3"] > 0
    return {
        "tier_counts": tier_counts,
        "blocked_count": blocked,
        "escalate_tier2": escalate_tier2,
        "escalate_tier3": escalate_tier3,
        "thresholds": {"tier1": tier1_th, "tier2": tier2_th},
    }


def _fingerprint_links(edges: List[dict]) -> List[dict]:
    """指纹关联分析：同指纹事件聚类，标注跨 Agent 关联（不聚合边本身）。"""
    by_fp: Dict[str, List[dict]] = {}
    for edge in edges:
        fp = edge.get("fingerprint")
        if not fp:
            continue
        by_fp.setdefault(fp, []).append(edge)
    links = []
    for fp, items in sorted(by_fp.items()):
        agents = sorted({e.get("agent_id", "") for e in items})
        links.append({
            "fingerprint": fp,
            "event_ids": [e.get("event_id", "") for e in items],
            "agents": agents,
            "cross_agent": len(agents) > 1,
            "first_ns": min(e.get("timestamp_ns", 0) for e in items),
            "last_ns": max(e.get("timestamp_ns", 0) for e in items),
            "event_count": len(items),
        })
    return links


class CusumDetector:
    """单侧 CUSUM 漂移检测器（L-T7）。

    输入为逐小时统计向量（L2 递层），对滑动基线检测正向漂移：
      S_t = max(0, S_{t-1} + (x_t - mu_0) - k)
      S_t >= h  → 告警
    mu_0 为基线（前 N 天同维度均值），k 为参考漂移幅度，h 为决策阈值。
    纯计算、无状态外置（基线由调用方传入）。
    """

    def __init__(self, k: float = 0.5, h: float = 2.0):
        self._k = k
        self._h = h

    def detect(self, values: List[float], baseline_mean: float) -> dict:
        """对一维时间序列做 CUSUM，返回告警结果。"""
        s = 0.0
        alert_at: Optional[int] = None
        for i, x in enumerate(values):
            s = max(0.0, s + (x - baseline_mean) - self._k)
            if s >= self._h:
                alert_at = i
                break
        return {
            "alerted": alert_at is not None,
            "alert_index": alert_at,
            "peak_cusum": s,
            "baseline_mean": round(baseline_mean, 4),
            "values": [round(v, 4) for v in values],
            "k": self._k,
            "h": self._h,
        }


class RollupEngine:
    """分层日志滚动引擎（纯逻辑 + 产物落盘）。"""

    def __init__(self, output_dir: str,
                 escalation_params: Optional[dict] = None,
                 cusum_params: Optional[dict] = None):
        self._output_dir = output_dir
        self._l2_dir = os.path.join(output_dir, "cache", "l2")
        self._l3_dir = os.path.join(output_dir, "cache", "l3")
        os.makedirs(self._l2_dir, exist_ok=True)
        os.makedirs(self._l3_dir, exist_ok=True)
        self._escalation_params = escalation_params or {}
        cusum_params = cusum_params or {}
        self._cusum = CusumDetector(
            k=float(cusum_params.get("k", 0.5)),
            h=float(cusum_params.get("h", 2.0)))

        # L1 累计缓冲：hour_bucket_id -> [L1 segments]（GC 驱动填充）
        self._pending_l1: Dict[int, List[dict]] = {}
        # 已生成 L2（内存镜像，供 L3 rollup 与 flush 后查询）
        self._l2_logs: List[dict] = []

    # ── L1 累计与调度（GC 驱动）────────────────────────────────────────────

    def accumulate_l1(self, segment: dict) -> Optional[dict]:
        """累计一个 L1 片段；出现新桶或当前桶满 60 片段时 flush 旧桶生成 L2。

        Returns:
            触发 flush 时返回 L2 dict；否则 None。
        """
        start_ns = segment.get("start_ns", 0)
        bucket = hour_bucket_id(start_ns)
        result = None
        other_buckets = sorted(b for b in self._pending_l1 if b != bucket)
        for b in other_buckets:
            l2 = self._flush_bucket(b, partial=False)
            if l2 is not None:
                result = l2
        self._pending_l1.setdefault(bucket, []).append(segment)
        if len(self._pending_l1[bucket]) >= SEGMENTS_PER_HOUR:
            l2 = self._flush_bucket(bucket, partial=False)
            if l2 is not None:
                result = l2
        return result

    def flush_all(self) -> List[dict]:
        """优雅停止 flush：全部未满桶按 partial 生成 L2（数据不丢）。"""
        results = []
        for b in sorted(self._pending_l1):
            l2 = self._flush_bucket(b, partial=True)
            if l2 is not None:
                results.append(l2)
        return results

    def flush_day(self, day_bucket: int) -> List[dict]:
        """日切兜底：把指定天内的未满 L1 桶按 partial flush 为 L2（L-T7）。

        虚拟时钟跨天时，前一天最后一个小时桶可能未满 60 片段，
        由调度方（monitor_daemon）在日切点调用，保证 L3 输入完整。
        """
        results = []
        for b in sorted(self._pending_l1):
            if day_bucket_id(bucket_start_ns(b, HOUR_NS)) == day_bucket:
                l2 = self._flush_bucket(b, partial=True)
                if l2 is not None:
                    results.append(l2)
        return results

    def _flush_bucket(self, bucket_id: int, partial: bool) -> Optional[dict]:
        segments = self._pending_l1.pop(bucket_id, [])
        if not segments:
            return None
        l2 = self.rollup_hour(segments, partial=partial)
        self._save_l2(l2)
        self._l2_logs.append(l2)
        if logger:
            logger.debug(f"RollupEngine: L2 生成 bucket={bucket_id} "
                         f"segments={len(segments)} partial={partial}")
        return l2

    # ── L1 → L2（小时日志）─────────────────────────────────────────────────

    def rollup_hour(self, l1_segments: List[dict],
                    partial: bool = False) -> dict:
        """60 个 L1 片段 → L2 小时日志。

        计算量 O(60 片段)：只读 stats / anomalies / fingerprint_edges /
        entry_ids，不逐条处理事件明细。
        """
        segments = sorted(l1_segments, key=lambda s: s.get("start_ns", 0))
        bucket_id = hour_bucket_id(segments[0].get("start_ns", 0))
        hour_start = bucket_start_ns(bucket_id, HOUR_NS)

        anomalies = _merge_zone(segments, "anomalies")
        fp_edges = _merge_zone(segments, "fingerprint_edges")

        entry_ids: List[str] = []
        seen = set()
        for seg in segments:
            for eid in seg.get("entry_ids") or []:
                if eid not in seen:
                    seen.add(eid)
                    entry_ids.append(eid)

        l2 = {
            "type": "l2_hour_log",
            "format_version": FORMAT_VERSION,
            "hour_bucket_id": bucket_id,
            "hour_start_ns": hour_start,
            "hour_end_ns": hour_start + HOUR_NS,
            "start_ns": segments[0].get("start_ns", 0),
            "end_ns": segments[-1].get("end_ns", 0),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "segment_ids": [s.get("segment_id", "") for s in segments],
            "stats": _merge_stats(segments),
            "entry_ids": entry_ids,
            "anomalies": anomalies,
            "fingerprint_edges": fp_edges,
            "sequence_alerts": _detect_sequences(anomalies),
            "escalation": _escalation_stats(anomalies, self._escalation_params),
            "fp_links": _fingerprint_links(fp_edges),
            "partial": partial,
        }
        return l2

    # ── L2 → L3（天级审计）─────────────────────────────────────────────────

    def rollup_day(self, l2_logs: List[dict],
                   baseline_stats: Optional[dict] = None) -> dict:
        """24 个 L2 → L3 天级审计。

        含：CUSUM 基线漂移检测（小时统计向量）与跨 Agent 串谋全图分析。
        计算量 O(24 小时)：只读 L2 摘要区，不触碰事件明细。
        """
        logs = sorted(l2_logs, key=lambda l: l.get("hour_start_ns", 0))
        if not logs:
            raise ValueError("rollup_day: 无 L2 输入")
        bucket_id = day_bucket_id(logs[0].get("hour_start_ns", 0))
        day_start = bucket_start_ns(bucket_id, DAY_NS)

        anomalies = _merge_zone(logs, "anomalies")
        fp_edges = _merge_zone(logs, "fingerprint_edges")
        entry_ids: List[str] = []
        seen = set()
        for log in logs:
            for eid in log.get("entry_ids") or []:
                if eid not in seen:
                    seen.add(eid)
                    entry_ids.append(eid)

        # 小时统计向量（CUSUM 输入）与基线漂移检测
        hourly_vector = [self._hourly_features(log) for log in logs]
        drift_alerts = self._drift_scan(hourly_vector, baseline_stats)

        l3 = {
            "type": "l3_daily_audit",
            "format_version": FORMAT_VERSION,
            "day_bucket_id": bucket_id,
            "day_start_ns": day_start,
            "day_end_ns": day_start + DAY_NS,
            "start_ns": logs[0].get("start_ns", 0),
            "end_ns": logs[-1].get("end_ns", 0),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "l2_count": len(logs),
            "l2_hours": [l.get("hour_bucket_id") for l in logs],
            "stats": _merge_stats(logs),
            "entry_ids": entry_ids,
            "anomalies": anomalies,
            "fingerprint_edges": fp_edges,
            "sequence_alerts": [a for l in logs
                                for a in (l.get("sequence_alerts") or [])],
            "escalation": _escalation_stats(anomalies, self._escalation_params),
            "fp_links": _fingerprint_links(fp_edges),
            "hourly_vector": hourly_vector,
            "drift_alerts": drift_alerts,
            "collusion_chains": self._detect_collusion(fp_edges, anomalies),
        }
        return l3

    def _hourly_features(self, l2: dict) -> dict:
        """L2 → 小时统计特征向量（CUSUM 输入）。"""
        stats = l2.get("stats") or {}
        total = stats.get("total", 0)
        return {
            "hour_bucket_id": l2.get("hour_bucket_id"),
            "event_rate": float(total),
            "alert_rate": round(float(stats.get("alert", 0)) / max(total, 1), 4),
            "block_rate": round(float(stats.get("block", 0)) / max(total, 1), 4),
            "distinct_fingerprints": len(
                {e.get("fingerprint") for e in (l2.get("fingerprint_edges") or [])}),
            "avg_risk_score": round(
                sum(a.get("risk_score", 0) for a in (l2.get("anomalies") or []))
                / max(len(l2.get("anomalies") or []), 1), 4),
        }

    def _drift_scan(self, hourly_vector: List[dict],
                    baseline_stats: Optional[dict]) -> List[dict]:
        """CUSUM 基线漂移扫描：对多维护小时特征向量逐维检测。

        baseline_stats: {"event_rate_mean": ..., "alert_rate_mean": ...}
        缺省时用当前天数据均值作弱基线（标注 baseline="self"）。
        """
        alerts: List[dict] = []
        dims = ("event_rate", "alert_rate", "block_rate",
                "distinct_fingerprints", "avg_risk_score")
        baseline = baseline_stats or {}
        for dim in dims:
            values = [v[dim] for v in hourly_vector]
            if not values:
                continue
            mean = baseline.get(f"{dim}_mean")
            if mean is None:
                mean = sum(values) / len(values)
            result = self._cusum.detect(values, mean)
            if result["alerted"]:
                alerts.append({
                    "dimension": dim,
                    "alert_index": result["alert_index"],
                    "alert_hour": (hourly_vector[result["alert_index"]]
                                   .get("hour_bucket_id")),
                    "baseline_mean": result["baseline_mean"],
                    "values": result["values"],
                    "baseline_source": "configured" if baseline else "self",
                })
        return alerts

    def _detect_collusion(self, fp_edges: List[dict],
                          anomalies: List[dict]) -> List[dict]:
        """跨 Agent 串谋全图分析（L-T7）。

        两条关联轴（数据血缘靠数据对象而非时间窗口维系）：
        1. 指纹链：同一动作指纹在不同 Agent 间出现；
        2. 路径链：同一 file_path 在不同 Agent 间传递（写→读暂存交换，
           如 m05 中 A 写 /tmp/stage 后 B 读同一路径，op 不同指纹也不同）。
        任一轴满足：跨 Agent、时间跨度 ≥ 1 小时、且链上 Agent 后续存在
        外传终点（net_conn）→ 判定为串谋链。仅对指纹/路径子图做分析
        （节点数受对象数约束），规避 O(节点²)。
        """
        by_fp: Dict[str, List[dict]] = {}
        by_path: Dict[str, List[dict]] = {}
        for edge in fp_edges:
            fp = edge.get("fingerprint")
            if fp:
                by_fp.setdefault(fp, []).append(edge)
            if edge.get("event_type") == "file_open" and edge.get("file_path"):
                by_path.setdefault(edge["file_path"], []).append(edge)

        anomaly_by_event = {a.get("event_id"): a for a in anomalies}
        chains: List[dict] = []
        seen_keys = set()

        # 1) 指纹链（同指纹跨 Agent）
        for fp, items in sorted(by_fp.items()):
            chain = self._build_collusion_chain(
                fp, "fingerprint", items, fp_edges, anomaly_by_event)
            if chain and chain["key"] not in seen_keys:
                seen_keys.add(chain["key"])
                chains.append(chain)

        # 2) 路径传递链（同路径跨 Agent 写→读交换）
        for path, items in sorted(by_path.items()):
            if len(items) < 2:
                continue
            chain = self._build_collusion_chain(
                path, "file_path", items, fp_edges, anomaly_by_event)
            if chain and chain["key"] not in seen_keys:
                seen_keys.add(chain["key"])
                chains.append(chain)
        return chains

    def _build_collusion_chain(self, obj: str, obj_kind: str,
                               items: List[dict], all_edges: List[dict],
                               anomaly_by_event: Dict[str, dict]):
        """单一数据对象（指纹/路径）的串谋链构建与判定。"""
        ordered = sorted(items, key=lambda e: e.get("timestamp_ns", 0))
        agents = sorted({e.get("agent_id", "") for e in ordered})
        if len(agents) < 2:
            return None  # 无跨 Agent 传递
        span = (ordered[-1].get("timestamp_ns", 0)
                - ordered[0].get("timestamp_ns", 0))
        if span < COLLUSION_MIN_SPAN_NS:
            return None  # 时间分散不达标
        # 外传终点：链上 Agent 在传递起点之后的 net_conn 事件
        exfil_edges = [e for e in all_edges
                       if e.get("event_type") == "net_conn"
                       and e.get("agent_id") in agents
                       and e.get("timestamp_ns", 0) >= ordered[0].get("timestamp_ns", 0)]
        if not exfil_edges:
            return None
        return {
            "key": f"{obj_kind}:{obj}",
            "object_kind": obj_kind,
            "object": obj,
            "agents": agents,
            "span_ns": span,
            "span_hours": round(span / HOUR_NS, 2),
            "first_ns": ordered[0].get("timestamp_ns", 0),
            "last_ns": max(e.get("timestamp_ns", 0) for e in exfil_edges),
            "event_ids": [e.get("event_id", "") for e in ordered],
            "exfil_events": [e.get("event_id", "") for e in exfil_edges],
            "remote_addrs": sorted({e.get("remote_addr")
                                    for e in exfil_edges
                                    if e.get("remote_addr")}),
            "anomaly_links": [e.get("event_id") for e in ordered
                              if anomaly_by_event.get(e.get("event_id"))],
        }

    # ── 产物落盘与读取 ─────────────────────────────────────────────────────

    def _save_l2(self, l2: dict) -> str:
        path = os.path.join(self._l2_dir, f"l2_{l2['hour_start_ns']}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(l2, f, ensure_ascii=False, indent=2, default=str)
        return path

    def _save_l3(self, l3: dict) -> str:
        path = os.path.join(self._l3_dir, f"l3_{l3['day_start_ns']}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(l3, f, ensure_ascii=False, indent=2, default=str)
        return path

    def save_l3(self, l3: dict) -> str:
        """落盘 L3（供 daemon 日切后调用）。"""
        return self._save_l3(l3)

    def list_l2(self) -> List[dict]:
        """列出 L2 产物目录中的小时日志（磁盘，含内存未落盘）。"""
        logs = list(self._l2_logs)
        if os.path.isdir(self._l2_dir):
            for fn in sorted(os.listdir(self._l2_dir)):
                if not (fn.startswith("l2_") and fn.endswith(".json")):
                    continue
                path = os.path.join(self._l2_dir, fn)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        logs.append(json.load(f))
                except (OSError, json.JSONDecodeError):
                    continue
        # 去重（按 hour_start_ns），保持内存版本优先
        seen = set()
        result = []
        for log in sorted(logs, key=lambda l: l.get("hour_start_ns", 0)):
            key = log.get("hour_start_ns")
            if key in seen:
                continue
            seen.add(key)
            result.append(log)
        return result

    def list_l3(self) -> List[dict]:
        """列出 L3 产物目录中的天级审计。"""
        result = []
        if not os.path.isdir(self._l3_dir):
            return result
        for fn in sorted(os.listdir(self._l3_dir)):
            if not (fn.startswith("l3_") and fn.endswith(".json")):
                continue
            path = os.path.join(self._l3_dir, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    result.append(json.load(f))
            except (OSError, json.JSONDecodeError):
                continue
        return result

    @property
    def l2_dir(self) -> str:
        return self._l2_dir

    @property
    def l3_dir(self) -> str:
        return self._l3_dir

    @property
    def pending_buckets(self) -> int:
        """未 flush 的小时桶数（诊断用）。"""
        return len(self._pending_l1)
