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

    def __init__(self, output_dir: str = "output/daemon_monitoring"):
        self._output_dir = output_dir
        cache_dir = os.path.join(output_dir, "cache", "segments")
        os.makedirs(cache_dir, exist_ok=True)
        self._segments_dir = cache_dir

        self._segments: List[dict] = []
        self._segment_counter: int = 0
        self._lock = threading.Lock()

        # 自动模式
        self._auto_thread: Optional[threading.Thread] = None
        self._auto_running: bool = False
        self._auto_interval: float = 60.0

        # 外部依赖（由 MonitorDaemon 注入）
        self._audit_logger = None  # AuditLogger 实例
        self._stats_provider = None  # 可选的 stats dict 提供者

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

            # 确定已覆盖的 entry_ids
            covered_ids = set()
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

            self._segment_counter += 1
            seg_id = f"seg_{self._segment_counter:04d}"

            segment = {
                "segment_id": seg_id,
                "start_ns": start_ns,
                "end_ns": end_ns,
                "created_at": datetime.now().isoformat(),
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
        """清理超出上限的旧片段"""
        while len(self._segments) > self.MAX_SEGMENTS:
            oldest = self._segments.pop(0)
            # 删除旧片段文件
            old_path = os.path.join(
                self._segments_dir, f"{oldest['segment_id']}.json")
            try:
                os.remove(old_path)
            except OSError:
                pass
            logger.debug(f"ReportCacheManager: GC 旧片段 {oldest['segment_id']}")

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
                    gaps_filled += 1

        return {
            "merged_stats": merged_stats,
            "total_entry_ids": all_ids,
            "segment_count": len(segments),
            "coverage": {
                "start_ns": min(s["start_ns"] for s in segments) if segments else 0,
                "end_ns": max(s["end_ns"] for s in segments) if segments else 0,
            },
            "gaps_filled": gaps_filled,
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
