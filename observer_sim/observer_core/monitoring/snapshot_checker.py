# -*- coding: utf-8 -*-
"""
observer_core/monitoring/snapshot_checker.py — P1-3 用户态快照交叉校验

定位:
    长期路线「轻量交叉校验」的落地起点，以**定时驱动**（不依赖会话边界）
    的用户态快照 + Windows 审计日志 4663（文件对象访问）为独立观测源，
    发现「申报未报但文件被访问/变更」→ 不一致告警（仅告警、不拦截）。

两个独立观测源:
    A. 定时文件快照: 每隔 interval_s 对受保护目录做快照
       （复用 FileSnapshotter 的 size/mtime_ns/sha256 口径），与前次快照
       diff_files；变更文件与申报路径比对（matches_reported_path 宽松匹配）
       → 未申报变更 finding（kind=unreported_file_change）。
    B. 4663 审计: 停止监测时按 lookback_s 窗口查询 Security 4663
       （文件对象访问），解析 ObjectName/ProcessName；ObjectName 落在
       受保护目录内、访问进程非系统白名单/观察者自身、且路径未申报
       → 未申报访问 finding（kind=unreported_file_access）。

设计约束（硬性）:
- 仅告警不拦截，不改判定管线（与 T3.1-T3.3 同层，产出层呈现）；
- 快照失败 / 审计未启用或无权限时如实标记 unavailable 并输出指引，
  不静默失败（计划 R-5 降级语义）；
- 复用既有口径: FileSnapshotter / diff_files / matches_reported_path /
  DEFAULT_SYSTEM_WHITELIST（collector.lightweight_crosscheck）、
  _ps_get_winevent / to_utc_epoch_ms（collector.windows_audit_reader），
  不重复实现、不新引入依赖；
- 比对窗口如实声明（定时采样 + 审计窗口外事件不可见）。

数据流:
    daemon 定时线程 ──► tick(reported_paths) 快照 + diff + 排除已申报
    停止监测       ──► finish(reported_paths) 末次比对 + 4663 窗口查询
                       → snapshot_checker.jsonl 留痕 + summary
"""

import json
import logging
import os
import time
import xml.etree.ElementTree as ET
from typing import Callable, Dict, List, Optional

from collector.lightweight_crosscheck import (  # noqa: E402
    DEFAULT_SYSTEM_WHITELIST, FileSnapshotter, diff_files,
    matches_reported_path)
from collector.windows_audit_reader import (  # noqa: E402
    _ps_get_winevent, to_utc_epoch_ms)

logger = logging.getLogger(__name__)

# 定时快照比对窗口声明（写入产物与报告固定措辞，如实披露采样局限）
SNAPSHOT_NOTE = (
    "定时快照比对仅覆盖采样时刻差异（间隔内创建又删除的文件不可见）；"
    "受保护目录外变更不比对；未申报的变更文件判定为「疑似二级操作」，"
    "仅告警不拦截")

# 4663 审计比对窗口声明（写入产物与报告固定措辞）
AUDIT_4663_NOTE = (
    "4663 对象访问审计仅在系统审计策略启用且目标目录配置 SACL 时产生事件；"
    "比对窗口为停止监测前 lookback_s；窗口外访问不可见；未申报的受保护"
    "文件访问判定为「疑似二级操作」，仅告警不拦截")

# 4663 审计启用指引（不可用时随 unavailable 输出，不静默失败）
AUDIT_4663_GUIDANCE = (
    "以管理员运行 secpol.msc → 安全设置 → 高级审核策略配置 → 对象访问 → "
    "审核文件系统 → 勾选成功；并对受保护目录配置 SACL（属性 → 安全 → "
    "高级 → 审核 → 添加 Everyone/指定用户 → 读取等访问权限）")

# 观察者自身进程名（daemon/hook 子进程由 python 解释器承载；其读取
# 行为属观察者自身，不构成「未申报访问」信号，予以排除）
SELF_PROCESS_NAMES = {"python.exe", "python", "pythonw.exe"}

# XML 命名空间（Get-WinEvent ToXml() 输出，与 windows_audit_reader 同源）
_XML_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def parse_4663_xml(xml_text: str) -> Optional[dict]:
    """Get-WinEvent ToXml() 输出 → 标准化 4663（文件对象访问）事件。

    - ObjectName → object_name（目标文件路径）；
    - AccessMask → access_mask（访问掩码原文）；
    - ProcessName → process_name（发起访问的进程路径）；
    - TimeCreated(SystemTime, UTC) → time_ms（UTC 毫秒 epoch）；
    - 非 4663 事件 / 解析失败返回 None。
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    system = root.find(f"{_XML_NS}System")
    if system is None:
        return None
    eid_el = system.find(f"{_XML_NS}EventID")
    time_el = system.find(f"{_XML_NS}TimeCreated")
    try:
        eid = int(eid_el.text) if eid_el is not None and eid_el.text else 0
    except ValueError:
        eid = 0
    if eid != 4663:
        return None
    sys_time = time_el.get("SystemTime") if time_el is not None else None
    time_ms = to_utc_epoch_ms(sys_time)
    data: Dict[str, str] = {}
    for d in root.findall(f"{_XML_NS}EventData/{_XML_NS}Data"):
        name = d.get("Name")
        if name:
            data[name] = (d.text or "").strip()
    obj = data.get("ObjectName", "")
    if not obj:
        return None
    return {"event_id": 4663, "source": "security_4663",
            "time_ms": time_ms, "object_name": obj,
            "access_mask": data.get("AccessMask", ""),
            "process_name": data.get("ProcessName", "")}


class ObjectAccessAuditReader:
    """Security 4663（文件对象访问）读取器（query_fn 可注入，供测试替代）。"""

    def __init__(self, timeout_s: float = 30.0,
                 query_fn: Optional[Callable] = None):
        self._timeout_s = timeout_s
        self._query_fn = query_fn or _ps_get_winevent

    def query(self, start_epoch: float, end_epoch: float,
              max_events: int) -> List[dict]:
        """查询窗口内 4663 事件，返回 parse_4663_xml 标准化事件列表。

        失败（权限不足/通道不存在/超时）抛异常，由上层转 unavailable。
        """
        xml_events = self._query_fn("Security", [4663], start_epoch,
                                    end_epoch, max_events, self._timeout_s)
        events = []
        for xml_text in xml_events or []:
            evt = parse_4663_xml(str(xml_text))
            if evt:
                events.append(evt)
        return events


def _in_protected_dirs(path: str, dirs: List[str]) -> bool:
    """路径是否落在任一受保护目录内（大小写不敏感 + 规范化前缀比较）。"""
    p = os.path.normpath(str(path or "").lower())
    if not p:
        return False
    for d in dirs:
        dn = os.path.normpath(str(d).lower()).rstrip(os.sep)
        if not dn:
            continue
        if p == dn or p.startswith(dn + os.sep):
            return True
    return False


def _process_skipped(process_name: str,
                     whitelist_extra: Optional[List[str]]) -> bool:
    """访问进程是否应跳过（系统白名单 / 观察者自身 / 额外白名单）。"""
    base = os.path.basename(str(process_name or "").lower())
    if not base:
        return True  # 无进程名无法归因，跳过（如实声明窗口局限）
    if base in SELF_PROCESS_NAMES:
        return True
    if base in DEFAULT_SYSTEM_WHITELIST:
        return True
    for w in (whitelist_extra or []):
        wl = str(w).lower()
        if wl and (wl == base or wl in base or base in wl):
            return True
    return False


class SnapshotChecker:
    """用户态快照交叉校验器（P1-3，定时驱动 + 4663 对象访问审计）。

    定时线程逐 tick 调用 tick()：首 tick 仅记 baseline，后续 tick 与前次
    快照 diff，变更文件排除已申报路径后产出「未申报变更」告警；
    停止监测调用 finish()：末次比对 + 4663 窗口查询比对，产出
    「未申报访问」告警；两者统一落 snapshot_checker.jsonl 留痕。

    快照失败 / 审计失败均如实记录 unavailable，不破坏监测主流程。
    """

    def __init__(self, output_dir: str, *,
                 snapshotter: Optional[FileSnapshotter] = None,
                 protected_dirs: Optional[List[str]] = None,
                 interval_s: int = 30,
                 audit_reader: Optional[ObjectAccessAuditReader] = None,
                 lookback_s: int = 60,
                 max_events: int = 500,
                 whitelist_extra: Optional[List[str]] = None,
                 jsonl_name: str = "snapshot_checker.jsonl",
                 changes_jsonl_name: str = "snapshot_changes.jsonl"):
        self._output_dir = output_dir
        self._snapshotter = snapshotter
        self._dirs = [os.path.normpath(str(d)) for d in
                      (protected_dirs or []) if d]
        self._interval_s = int(interval_s or 30)
        self._audit_reader = audit_reader
        self._lookback_s = int(lookback_s or 60)
        self._max_events = int(max_events or 500)
        self._whitelist_extra = list(whitelist_extra or [])
        self._jsonl_name = jsonl_name
        self._changes_jsonl_name = changes_jsonl_name

        self._tick_count = 0
        self._last_snap: Optional[Dict[str, Dict]] = None
        self._reported_extra: List[str] = []
        self._findings: List[Dict] = []
        self._unavailable: List[Dict] = []

    # ── 定时驱动（daemon 定时线程逐 tick 调用）──────────────────────

    def add_reported_path(self, path: str) -> None:
        """登记已申报文件路径（比对时用于排除申报内变更/访问）。"""
        text = (path or "").strip()
        if text:
            self._reported_extra.append(text)

    def tick(self, reported_paths: Optional[List[str]] = None) -> None:
        """一次定时比对：快照 → 与前次 diff → 排除已申报 → finding。

        首 tick 仅记 baseline 不比对；快照失败记 unavailable（不破坏
        既有 baseline，后续 tick 继续尝试）。
        """
        self._tick_count += 1
        for p in (reported_paths or []):
            self.add_reported_path(p)
        if self._snapshotter is None:
            return
        snap = self._snapshotter.snapshot(previous=self._last_snap)
        if snap is None:
            self._unavailable.append(
                {"phase": f"tick{self._tick_count}",
                 "reason": "文件快照不可用"})
            return
        if self._last_snap is None:
            self._last_snap = snap  # baseline，下轮起比对
            return
        changes = diff_files(self._last_snap, snap)
        # P2-2 配套: 排除申报前的 diff 全集落 snapshot_changes.jsonl，
        # 供一致性核对维度③（申报与快照矛盾）比对；finding 只存
        # 「排除申报后」子集，全集需独立留痕（空集也落盘，使
        # 「无变化」成为可判定状态而非源缺失）。
        self._write_changes_jsonl(changes)
        reported = list(self._reported_extra)
        kept = {
            kind: {p: info for p, info in items.items()
                   if not matches_reported_path(p, reported)}
            for kind, items in changes.items()
        }
        if any(kept.values()):
            self._findings.append({
                "kind": "unreported_file_change",
                "severity": "suspect_secondary_action",
                "tick": self._tick_count,
                "changes": kept,
                "note": SNAPSHOT_NOTE,
            })
        self._last_snap = snap

    def _write_changes_jsonl(self, changes: Dict) -> None:
        """追加写排除申报前的快照 diff 全集（P2-2 配套留痕）。

        每次 diff 后无条件落盘一条 snapshot_checker_change 记录
        （tick 号 + added/modified/removed 全集），供 ConsistencyChecker
        维度③判断「申报写入的路径在快照中是否观察到变化」。
        留痕失败仅告警，不破坏快照比对主流程。
        """
        os.makedirs(self._output_dir, exist_ok=True)
        path = os.path.join(self._output_dir, self._changes_jsonl_name)
        entry = {
            "type": "snapshot_checker_change",
            "timestamp_ms": int(time.time() * 1000),
            "tick": self._tick_count,
            "changes": changes,
        }
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str)
                        + "\n")
        except OSError as e:
            logger.warning(f"快照变更全集留痕写入失败: {e}")

    # ── 4663 审计比对（finish 收尾时执行）───────────────────────────

    def _audit_compare(self) -> None:
        """按 lookback_s 窗口查询 4663 → 排除系统/自身进程 → 排除已申报
        → 剩余 ObjectName 落受保护目录内的事件记 finding。"""
        if self._audit_reader is None or not self._dirs:
            return
        end = time.time()
        start = end - self._lookback_s
        try:
            events = self._audit_reader.query(start, end, self._max_events)
        except Exception as e:  # noqa: BLE001 审计失败不破坏主流程
            self._unavailable.append({
                "phase": "audit_4663",
                "reason": f"4663 审计查询失败: {e}",
                "guidance": AUDIT_4663_GUIDANCE,
            })
            return
        if not events:
            self._unavailable.append({
                "phase": "audit_4663",
                "reason": "窗口内无 4663 事件（审计策略未启用或对象访问"
                          "未产生事件）",
                "guidance": AUDIT_4663_GUIDANCE,
            })
            return
        reported = list(self._reported_extra)
        hits = []
        for evt in events:
            obj = str(evt.get("object_name") or "")
            if not _in_protected_dirs(obj, self._dirs):
                continue
            if _process_skipped(str(evt.get("process_name") or ""),
                                self._whitelist_extra):
                continue
            if matches_reported_path(obj, reported):
                continue
            hits.append({
                "object_name": obj,
                "access_mask": evt.get("access_mask", ""),
                "process_name": evt.get("process_name", ""),
                "time_ms": evt.get("time_ms"),
            })
        if hits:
            self._findings.append({
                "kind": "unreported_file_access",
                "severity": "suspect_secondary_action",
                "accesses": hits,
                "note": AUDIT_4663_NOTE,
            })

    # ── 收尾与产出 ──────────────────────────────────────────────────

    def finish(self, reported_paths: Optional[List[str]] = None) -> Dict:
        """停止监测收尾: 末次快照比对 + 4663 查询 → 留痕 → summary。"""
        for p in (reported_paths or []):
            self.add_reported_path(p)
        self.tick()  # 末次比对（tick_count 自增，与定时节奏一致）
        self._audit_compare()

        # available 语义：至少一次快照成功（存在可比对 baseline）；
        # 纯 tick 计数不能代表可用（快照连续失败时如实标记不可核对，
        # 计划 R-5 降级语义：不静默、不虚构比对）。
        available = self._last_snap is not None
        summary = {
            "enabled": True,
            "available": available,
            "ticks": self._tick_count,
            "interval_s": self._interval_s,
            "findings": self._findings,
            "unavailable": self._unavailable,
            "note": (SNAPSHOT_NOTE + "；" + AUDIT_4663_NOTE),
        }
        self._write_jsonl()
        return summary

    def _write_jsonl(self) -> None:
        """追加写比对留痕（幂等追加，不覆盖历史；daemon 单进程写）。"""
        if not self._findings and not self._unavailable:
            return
        os.makedirs(self._output_dir, exist_ok=True)
        path = os.path.join(self._output_dir, self._jsonl_name)
        entries = [{
            "type": "snapshot_checker_finding",
            "timestamp_ms": int(time.time() * 1000),
            **f,
        } for f in self._findings]
        for u in self._unavailable:
            entries.append({
                "type": "snapshot_checker_unavailable",
                "timestamp_ms": int(time.time() * 1000),
                **u,
            })
        try:
            with open(path, "a", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, ensure_ascii=False, default=str)
                            + "\n")
        except OSError as e:
            logger.warning(f"用户态快照校验留痕写入失败: {e}")
