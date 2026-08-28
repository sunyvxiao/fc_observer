"""
audit/report_cache.py — 报告片段缓存管理器

D1+D2 组合方案:
- 自动模式 (D2): 后台线程每 60s 生成片段 JSON，保留最近 60 个（1小时）
- 手动模式 (D1): query_range(start_ns, end_ns) → 查找覆盖片段 → 拼接去重

片段格式:
  {
    "segment_id": "seg_0001",
    "start_ns": 1718092800000000000,
    "end_ns":   1718092860000000000,
    "created_at": "2025-06-11T10:01:00",
    "stats": {
      "total": 10, "allow": 6, "alert": 2, "block": 2,
      "risk_dist": {"LOW": 5, "MEDIUM": 2, "HIGH": 2, "CRITICAL": 1},
      "rule_hits": {"R001": 2, "R005": 1},
      "max_score": 0.92
    },
    "entry_ids": ["evt_001", "evt_002", ...]
  }

用法:
    cache = ReportCacheManager(output_dir="output/daemon_monitoring")
    cache.start_auto(interval=60.0)
    ...
    segments = cache.query_range(start_ns, end_ns)
    cache.stop()
"""

import os
import json
import time
import logging
import threading
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class ReportCacheManager:
    """
    报告片段缓存管理器。

    自动模式下每 60s 从 AuditLogger 抓取数据生成片段 JSON。
    手动模式按时间窗口查找覆盖片段并拼接。
    """

    # 最大保留片段数
    MAX_SEGMENTS = 60

    # L-T5: 片段格式版本（旧片段无 format_version → 视作 0，读取兼容）
    FORMAT_VERSION = 1

    # L-T5: 异常明细区收录阈值默认值（与 tuning decision.thresholds.high_score
    # 保持一致）；实例阈值可在构造时注入（tuning 联动，避免硬编码漂移）
    ANOMALY_SCORE_THRESHOLD = 0.6

    def __init__(self, output_dir: str = "output/daemon_monitoring",
                 anomaly_score_threshold: Optional[float] = None):
        self._output_dir = output_dir
        cache_dir = os.path.join(output_dir, "cache", "segments")
        os.makedirs(cache_dir, exist_ok=True)
        self._segments_dir = cache_dir
        # L-T4: GC 删前转存明细的 rollup JSONL 目录（懒创建）
        self._rollup_dir = os.path.join(output_dir, "cache", "rollup")

        self._segments: List[dict] = []
        self._segment_counter: int = 0
        self._lock = threading.Lock()
        # L-T5: 异常明细区收录阈值（构造注入优先，缺省回退类常量默认值）
        self._anomaly_threshold = (
            float(anomaly_score_threshold)
            if anomaly_score_threshold is not None
            else self.ANOMALY_SCORE_THRESHOLD)
        # L-T7: 已从内存移除（GC/日切 rollup）片段的 entry_ids 追踪。
        # 防止 rollup 移除段后 force_generate 把已转存条目重新成段
        # （会导致跨天条目被错误归入旧天小时桶）。
        self._covered_entry_ids: set = set()

        # 自动模式
        self._auto_thread: Optional[threading.Thread] = None
        self._auto_running: bool = False
        self._auto_interval: float = 60.0

        # 外部依赖（由 MonitorDaemon 注入）
        self._audit_logger = None  # AuditLogger 实例
        self._stats_provider = None  # 可选的 stats dict 提供者
        # L-T6: 分层滚动引擎（可选注入；未注入时 GC 仅走最小闭环转存）
        self._rollup_engine = None

    def set_rollup_engine(self, engine):
        """注入 RollupEngine（L-T6）：GC 删片段前先累计 L1 供 L2 生成。"""
        self._rollup_engine = engine

    def flush_rollup(self):
        """优雅停止：flush 引擎中未满的小时桶生成 partial L2（L-T6）。"""
        if self._rollup_engine is None:
            return []
        return self._rollup_engine.flush_all()

    def set_audit_logger(self, audit_logger):
        """注入 AuditLogger 实例"""
        self._audit_logger = audit_logger

    def set_stats_provider(self, provider):
        """注入统计信息提供者（callable → dict）"""
        self._stats_provider = provider

    # ── 自动片段生成 ─────────────────────────────────────────────────────────

    def start_auto(self, interval: float = 60.0):
        """
        启动自动片段生成后台线程。

        Args:
            interval: 片段生成间隔（秒）
        """
        if self._auto_running:
            return
        self._auto_interval = interval
        self._auto_running = True
        self._auto_thread = threading.Thread(
            target=self._auto_loop, daemon=True, name="report-cache")
        self._auto_thread.start()
        logger.info(f"ReportCacheManager: 自动片段生成已启动 (间隔={interval}s)")

    def stop_auto(self):
        """停止自动片段生成"""
        self._auto_running = False
        if self._auto_thread:
            self._auto_thread.join(timeout=5.0)
            self._auto_thread = None
        logger.info("ReportCacheManager: 自动片段生成已停止")

    def _auto_loop(self):
        """自动片段生成循环"""
        while self._auto_running:
            time.sleep(self._auto_interval)
            if not self._auto_running:
                break
            try:
                self._generate_segment()
            except Exception as e:
                logger.warning(f"ReportCacheManager: 片段生成失败: {e}")

    def _generate_segment(self) -> Optional[dict]:
        """
        生成一个时间窗口的片段。

        从 AuditLogger 获取自上次片段以来的新条目，
        生成片段 JSON 并写入文件。
        """
        if self._audit_logger is None:
            logger.debug("ReportCacheManager: AuditLogger 未注入，跳过片段生成")
            return None

        with self._lock:
            entries = self._audit_logger.read_entries()
            if not entries:
                return None

            # 确定已覆盖的 entry_ids（含已 rollup 移除段的条目，L-T7）
            covered_ids = set(self._covered_entry_ids)
            for seg in self._segments:
                covered_ids.update(seg.get("entry_ids", []))

            # 筛选新条目
            new_entries = [e for e in entries if e.event_id not in covered_ids]
            if not new_entries:
                return None

            # 计算统计
            total = len(new_entries)
            allowed = sum(1 for e in new_entries if e.decision_action == "ALLOW")
            alerted = sum(1 for e in new_entries
                         if e.decision_action == "ALERT" and not e.blocked)
            blocked = sum(1 for e in new_entries if e.blocked)

            risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            max_score = 0.0
            rule_hits: Dict[str, int] = {}

            for e in new_entries:
                level = e.risk_level
                if level in risk_dist:
                    risk_dist[level] += 1
                if e.risk_score > max_score:
                    max_score = e.risk_score
                for rule_id in e.matched_rules:
                    rule_hits[rule_id] = rule_hits.get(rule_id, 0) + 1

            # 生成片段
            start_ns = min(e.timestamp_ns for e in new_entries)
            end_ns = max(e.timestamp_ns for e in new_entries)

            # L-T5: 异常明细区（三红线之"异常明细全保留"）与
            # 指纹边区（三红线之"指纹边全透传"，不聚合）
            anomalies = []
            fingerprint_edges = []
            for e in new_entries:
                anomaly = self._entry_anomaly(e)
                if anomaly is not None:
                    anomalies.append(anomaly)
                edge = self._entry_fp_edge(e)
                if edge is not None:
                    fingerprint_edges.append(edge)

            self._segment_counter += 1
            seg_id = f"seg_{self._segment_counter:04d}"

            segment = {
                "segment_id": seg_id,
                "start_ns": start_ns,
                "end_ns": end_ns,
                "created_at": datetime.now().isoformat(),
                "format_version": self.FORMAT_VERSION,
                "stats": {
                    "total": total,
                    "allow": allowed,
                    "alert": alerted,
                    "block": blocked,
                    "risk_dist": risk_dist,
                    "rule_hits": rule_hits,
                    "max_score": max_score,
                },
                "entry_ids": [e.event_id for e in new_entries],
                "anomalies": anomalies,
                "fingerprint_edges": fingerprint_edges,
            }

            self._segments.append(segment)

            # 写入文件
            seg_path = os.path.join(self._segments_dir, f"{seg_id}.json")
            with open(seg_path, "w", encoding="utf-8") as f:
                json.dump(segment, f, ensure_ascii=False, indent=2, default=str)

            # GC 旧片段
            self._gc_segments()

            logger.debug(f"ReportCacheManager: 片段生成 {seg_id} "
                         f"({total} 条目, {len(self._segments)} 个片段)")
            return segment

    def _gc_segments(self):
        """清理超出上限的旧片段（删前先 rollup L2 再转存明细，L-T4/L-T6）。

        三红线：rollup 失败则不删片段（数据不丢）；L0 audit JSONL 永不触碰。
        """
        while len(self._segments) > self.MAX_SEGMENTS:
            oldest = self._segments.pop(0)
            # L-T6: 分层滚动 —— 删前将片段累计进小时桶（满桶/跨桶时生成 L2）
            if self._rollup_engine is not None:
                try:
                    self._rollup_engine.accumulate_l1(oldest)
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"ReportCacheManager: L2 rollup 失败，"
                                   f"片段 {oldest['segment_id']} 不删除: {e}")
                    self._segments.insert(0, oldest)
                    break
            # L-T4: 删前转存事件明细（最小闭环 rollup），避免明细随片段文件丢失
            self._archive_segment_detail(oldest)
            # 删除旧片段文件
            old_path = os.path.join(
                self._segments_dir, f"{oldest['segment_id']}.json")
            try:
                os.remove(old_path)
            except OSError:
                pass
            # L-T7: 记录已移除段条目，防止后续 force_generate 重复成段
            self._covered_entry_ids.update(oldest.get("entry_ids", []))
            logger.debug(f"ReportCacheManager: GC 旧片段 {oldest['segment_id']}")

    def rollup_through(self, day_start_ns: int) -> int:
        """
        日切驱动（L-T7）：把 day_start_ns 之前的片段累计进 RollupEngine
        并移除（不依赖 60 片段容量上限，保证虚拟日切时前一天 L1 全部
        进入 L2 再进入 L3）。

        安全语义与 _gc_segments 一致：先 rollup（失败则不删）+ 删前转存
        明细；L0 audit JSONL 永不触碰。

        Returns:
            int: 本次处理的片段数
        """
        with self._lock:
            to_roll = [s for s in self._segments
                       if s.get("start_ns", 0) < day_start_ns]
            if not to_roll:
                return 0
            count = 0
            for seg in to_roll:
                if self._rollup_engine is not None:
                    try:
                        self._rollup_engine.accumulate_l1(seg)
                    except Exception as e:  # noqa: BLE001
                        logger.warning(f"ReportCacheManager: 日切 rollup 失败，"
                                       f"片段 {seg['segment_id']} 保留: {e}")
                        break
                self._archive_segment_detail(seg)
                old_path = os.path.join(
                    self._segments_dir, f"{seg['segment_id']}.json")
                try:
                    os.remove(old_path)
                except OSError:
                    pass
                self._segments.remove(seg)
                # L-T7: 记录已移除段条目，防止后续 force_generate 重复成段
                self._covered_entry_ids.update(seg.get("entry_ids", []))
                count += 1
            return count

    def _entry_anomaly(self, entry) -> Optional[dict]:
        """
        判断条目是否进入异常明细区并输出完整字段 + 决策链（L-T5）。

        收录条件: 被阻断 / 判定为 ALERT|BLOCK / 风险分达到高分阈值。
        返回 None 表示不收录。
        """
        blocked = bool(getattr(entry, "blocked", False))
        action = getattr(entry, "decision_action", "ALLOW")
        score = float(getattr(entry, "risk_score", 0.0) or 0.0)
        if not (blocked or action in ("ALERT", "BLOCK")
                or score >= self._anomaly_threshold):
            return None
        return self._entry_to_detail_dict(entry)

    def _entry_fp_edge(self, entry) -> Optional[dict]:
        """
        输出指纹边记录（L-T5，三红线之"指纹边全透传"）。

        全量透传、不做任何聚合压缩；无指纹的条目返回 None。
        """
        fp = getattr(entry, "fingerprint", None)
        if not fp:
            return None
        return {
            "fingerprint": fp,
            "event_id": getattr(entry, "event_id", ""),
            "agent_id": getattr(entry, "agent_id", ""),
            "event_type": getattr(entry, "event_type", ""),
            "timestamp_ns": getattr(entry, "timestamp_ns", 0),
            "file_path": getattr(entry, "file_path", None),
            "remote_addr": getattr(entry, "remote_addr", None),
        }

    def _entry_to_detail_dict(self, entry) -> dict:
        """将 AuditEntry 转换为明细字典（兼容真实对象与 Mock）"""
        if hasattr(entry, "to_json_line"):
            try:
                data = entry.to_json_line()
                if isinstance(data, str):
                    return json.loads(data)
                if isinstance(data, dict):
                    return data
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
        return {
            "event_id": getattr(entry, "event_id", ""),
            "agent_id": getattr(entry, "agent_id", ""),
            "event_type": getattr(entry, "event_type", ""),
            "timestamp_ns": getattr(entry, "timestamp_ns", 0),
            "pid": getattr(entry, "pid", 0),
            "description": getattr(entry, "description", ""),
            "command_string": getattr(entry, "command_string", None),
            "file_path": getattr(entry, "file_path", None),
            "remote_addr": getattr(entry, "remote_addr", None),
            "matched_rules": getattr(entry, "matched_rules", []),
            "risk_score": getattr(entry, "risk_score", 0.0),
            "risk_level": getattr(entry, "risk_level", "LOW"),
            "decision_action": getattr(entry, "decision_action", "ALLOW"),
            "decision_tier": getattr(entry, "decision_tier", ""),
            "decision_reason": getattr(entry, "decision_reason", ""),
            "blocked": getattr(entry, "blocked", False),
            "blocking_tier": getattr(entry, "blocking_tier", ""),
            "blocking_details": getattr(entry, "blocking_details", ""),
            "cmd_id": getattr(entry, "cmd_id", ""),
            "fingerprint": getattr(entry, "fingerprint", None),
        }

    def _archive_segment_detail(self, segment: dict):
        """
        将片段的明细条目转存为 rollup JSONL（GC 删前调用）。

        首行写入 segment_meta，随后每行一条事件明细；
        AuditLogger 未注入时仅保留 meta 与缺失标记。
        """
        try:
            os.makedirs(self._rollup_dir, exist_ok=True)
        except OSError:
            return

        entry_ids = segment.get("entry_ids", [])
        entries_by_id: Dict[str, Any] = {}
        if self._audit_logger is not None:
            try:
                for entry in self._audit_logger.read_entries():
                    entries_by_id[getattr(entry, "event_id", "")] = entry
            except Exception as e:
                logger.warning(f"ReportCacheManager: rollup 读取明细失败: {e}")

        rollup_path = os.path.join(
            self._rollup_dir, f"rollup_{segment['segment_id']}.jsonl")
        try:
            with open(rollup_path, "w", encoding="utf-8") as f:
                meta = {
                    "type": "segment_meta",
                    "segment_id": segment.get("segment_id", ""),
                    "start_ns": segment.get("start_ns", 0),
                    "end_ns": segment.get("end_ns", 0),
                    "stats": segment.get("stats", {}),
                    "entry_count": len(entry_ids),
                    "archived_at": datetime.now().isoformat(),
                }
                f.write(json.dumps(meta, ensure_ascii=False, default=str) + "\n")
                for eid in entry_ids:
                    entry = entries_by_id.get(eid)
                    if entry is None:
                        f.write(json.dumps(
                            {"type": "entry", "event_id": eid,
                             "missing": True},
                            ensure_ascii=False) + "\n")
                        continue
                    f.write(json.dumps(
                        self._entry_to_detail_dict(entry),
                        ensure_ascii=False, default=str) + "\n")
        except OSError as e:
            logger.warning(f"ReportCacheManager: rollup 写入失败: {e}")
            return
        logger.debug(
            f"ReportCacheManager: 明细转存 rollup_{segment['segment_id']} "
            f"({len(entry_ids)} 条目)")

    def read_rollup(self, segment_id: str) -> List[dict]:
        """读取指定片段的 rollup 明细（GC 后明细可查，L-T4）"""
        rollup_path = os.path.join(
            self._rollup_dir, f"rollup_{segment_id}.jsonl")
        if not os.path.isfile(rollup_path):
            return []
        lines: List[dict] = []
        with open(rollup_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    lines.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return lines

    def list_rollups(self) -> List[str]:
        """列出已转存的 rollup 对应的 segment_id 列表"""
        if not os.path.isdir(self._rollup_dir):
            return []
        result = []
        for fn in os.listdir(self._rollup_dir):
            if fn.startswith("rollup_") and fn.endswith(".jsonl"):
                result.append(fn[len("rollup_"):-len(".jsonl")])
        return sorted(result)

    # ── 手动查询与拼接 ───────────────────────────────────────────────────────

    def query_range(self, start_ns: int, end_ns: int) -> List[dict]:
        """
        按时间窗口查询覆盖片段。

        Args:
            start_ns: 开始时间戳（纳秒）
            end_ns:   结束时间戳（纳秒）

        Returns:
            List[dict]: 片段列表，按时间排序
        """
        with self._lock:
            matching = []
            for seg in self._segments:
                # 片段与查询窗口有交集
                if seg["end_ns"] >= start_ns and seg["start_ns"] <= end_ns:
                    matching.append(seg)
            return sorted(matching, key=lambda s: s["start_ns"])

    def merge_segments(self, segments: List[dict],
                       audit_logger=None) -> dict:
        """
        拼接多个片段为统一摘要。

        Args:
            segments:     要合并的片段列表
            audit_logger: AuditLogger（用于补充间隙）

        Returns:
            dict: {
                "merged_stats": {...},
                "total_entry_ids": [...],  # 去重后
                "segment_count": int,
                "coverage": {"start_ns": ..., "end_ns": ...},
                "gaps_filled": int,  # 从 audit JSONL 补充的条目数
            }
        """
        if not segments:
            return {
                "merged_stats": {},
                "total_entry_ids": [],
                "segment_count": 0,
                "coverage": {},
                "gaps_filled": 0,
            }

        # 合并 stats
        merged_stats = {
            "total": 0, "allow": 0, "alert": 0, "block": 0,
            "risk_dist": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "rule_hits": {},
            "max_score": 0.0,
        }

        all_ids: List[str] = []
        seen_ids = set()

        for seg in segments:
            stats = seg["stats"]
            merged_stats["total"] += stats.get("total", 0)
            merged_stats["allow"] += stats.get("allow", 0)
            merged_stats["alert"] += stats.get("alert", 0)
            merged_stats["block"] += stats.get("block", 0)
            if stats.get("max_score", 0) > merged_stats["max_score"]:
                merged_stats["max_score"] = stats["max_score"]
            for level, count in stats.get("risk_dist", {}).items():
                merged_stats["risk_dist"][level] += count
            for rule_id, count in stats.get("rule_hits", {}).items():
                merged_stats["rule_hits"][rule_id] = (
                    merged_stats["rule_hits"].get(rule_id, 0) + count)

            # 去重合并 entry_ids
            for eid in seg.get("entry_ids", []):
                if eid not in seen_ids:
                    seen_ids.add(eid)
                    all_ids.append(eid)

        # L-T5: 透传异常明细区与指纹边区（去重合并，旧片段缺省为空区）
        merged_anomalies: List[dict] = []
        seen_anomaly_ids = set()
        merged_fp_edges: List[dict] = []
        seen_fp_keys = set()
        for seg in segments:
            for anomaly in (seg.get("anomalies") or []):
                aid = anomaly.get("event_id", "")
                if aid and aid in seen_anomaly_ids:
                    continue
                if aid:
                    seen_anomaly_ids.add(aid)
                merged_anomalies.append(anomaly)
            for edge in (seg.get("fingerprint_edges") or []):
                key = (edge.get("fingerprint"), edge.get("event_id"))
                if key in seen_fp_keys:
                    continue
                seen_fp_keys.add(key)
                merged_fp_edges.append(edge)

        # 间隙填充：从 audit JSONL 补充未覆盖的条目
        gaps_filled = 0
        if audit_logger is not None and len(segments) > 0:
            full_start = min(s["start_ns"] for s in segments)
            full_end = max(s["end_ns"] for s in segments)
            all_entries = audit_logger.read_entries()
            for entry in all_entries:
                if entry.event_id in seen_ids:
                    continue
                if full_start <= entry.timestamp_ns <= full_end:
                    seen_ids.add(entry.event_id)
                    all_ids.append(entry.event_id)
                    # 更新统计
                    merged_stats["total"] += 1
                    if entry.decision_action == "ALLOW":
                        merged_stats["allow"] += 1
                    elif entry.blocked:
                        merged_stats["block"] += 1
                    else:
                        merged_stats["alert"] += 1
                    level = entry.risk_level
                    if level in merged_stats["risk_dist"]:
                        merged_stats["risk_dist"][level] += 1
                    if entry.risk_score > merged_stats["max_score"]:
                        merged_stats["max_score"] = entry.risk_score
                    for rule_id in entry.matched_rules:
                        merged_stats["rule_hits"][rule_id] = (
                            merged_stats["rule_hits"].get(rule_id, 0) + 1)
                    # L-T5: 间隙补充条目同样进入新区，保证三红线不丢
                    anomaly = self._entry_anomaly(entry)
                    if anomaly is not None:
                        merged_anomalies.append(anomaly)
                    edge = self._entry_fp_edge(entry)
                    if edge is not None:
                        key = (edge["fingerprint"], edge["event_id"])
                        if key not in seen_fp_keys:
                            seen_fp_keys.add(key)
                            merged_fp_edges.append(edge)
                    gaps_filled += 1

        merged_anomalies.sort(key=lambda a: a.get("timestamp_ns", 0))
        merged_fp_edges.sort(key=lambda f: f.get("timestamp_ns", 0))

        return {
            "merged_stats": merged_stats,
            "total_entry_ids": all_ids,
            "segment_count": len(segments),
            "coverage": {
                "start_ns": min(s["start_ns"] for s in segments) if segments else 0,
                "end_ns": max(s["end_ns"] for s in segments) if segments else 0,
            },
            "gaps_filled": gaps_filled,
            "anomalies": merged_anomalies,
            "fingerprint_edges": merged_fp_edges,
        }

    def force_generate(self) -> Optional[dict]:
        """手动触发生成一个片段"""
        return self._generate_segment()

    def list_segments(self) -> List[dict]:
        """列出所有缓存的片段"""
        with self._lock:
            return list(self._segments)

    @property
    def segment_count(self) -> int:
        return len(self._segments)

    @property
    def segments_dir(self) -> str:
        return self._segments_dir

    @property
    def rollup_dir(self) -> str:
        return self._rollup_dir
