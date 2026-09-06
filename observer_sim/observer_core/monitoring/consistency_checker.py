# -*- coding: utf-8 -*-
"""
observer_core/monitoring/consistency_checker.py — P2-2 双源一致性核对

定位:
    双源融合的一致性核对器：四源留痕（申报 / hook 执行前裁决 /
    hook 执行后审计 / 快照校验）交叉比对，产出三类不一致告警
    （仅告警不拦截、产出层呈现，不改检测/研判管线）。

三类不一致:
    ① unreported_hook_deny: 「申报未报但 hook 拦截」——hook 执行前
       deny 的 (session, target) 在 Agent 申报流中无对应申报
       （hook 自身的 notify 申报不计入 Agent 申报，防自证）；
    ② hook_blindspot_change: 「hook 未触发但快照发现访问/变更」——
       快照校验 finding 的路径在 hook 执行前+执行后裁决中均无对应；
    ③ report_snapshot_conflict: 「申报与快照矛盾」——仅 write 类申报
       核对：申报声明写入的受保护目录内路径，快照 diff 全集无变化
       且 hook 两轨均无裁决（申报的写入无任何落地证据）。

设计约束（硬性）:
- 仅告警不拦截，不改判定管线（产出层呈现，与 P1-2/P1-3 同层）；
- 各维度独立降级（P2-4）: 依赖源缺失/不可用 → 该维度 unavailable
  （不可核对 + 指引），不中断其余维度核对，不虚构比对；
- 复用既有口径: _iter_jsonl（损坏行容错，collector.mcp_report_collector）、
  matches_reported_path（宽松路径匹配，collector.lightweight_crosscheck）、
  _in_protected_dirs（snapshot_checker）、RawEventFactory.from_hook_entry
  （hook 条目归一视图，P2-1）;
- 比对窗口如实声明（定时采样局限 / hook 源依赖）。

数据流:
    daemon 停止监测 ──► finish() 四源解析 + 三类比对
                       → consistency_issues.jsonl 留痕 + summary
                       → 报告小节 + monitoring_summary.json
"""

import json
import logging
import os
import time
from typing import Dict, List, Optional

from collector.lightweight_crosscheck import (  # noqa: E402
    FILE_TOOL_NAMES, matches_reported_path)
from collector.mcp_report_collector import _iter_jsonl  # noqa: E402
from observer_core.monitoring.snapshot_checker import (  # noqa: E402
    _in_protected_dirs)

logger = logging.getLogger(__name__)

# 申报口径中「write 类」文件工具（申报声明写入/变更，供维度③核对）
WRITE_TOOL_NAMES = FILE_TOOL_NAMES - {"read_file", "list_files"}

# 申报口径中「exec 类」工具（命令文本参与 deny 对应比对）
EXEC_REPORT_TOOL_NAMES = {"bash", "execute", "execute_command", "shell",
                          "run_command", "terminal", "command"}

# 快照变更全集留痕（snapshot_checker 配套落盘，P2-2 依赖）
DEFAULT_CHANGES_JSONL = "snapshot_changes.jsonl"

# 一致性核对说明（写入产物与报告固定措辞）
CONSISTENCY_NOTE = (
    "核对基于四源留痕（申报 / hook 执行前裁决 / hook 执行后审计 / "
    "快照校验），仅反映留痕侧观测一致性；定时快照仅覆盖采样时刻差异"
    "（间隔内创建又删除的文件不可见）；各维度源缺失时独立标记不可核对，"
    "不虚构比对")

# 各类不一致的严重度（与 P1-3 finding 同口径，仅告警不拦截）
ISSUE_SEVERITY = "suspect_secondary_action"

# 维度名 → 说明（unavailable 时随指引输出）
_DIMENSION_DESC = {
    "unreported_hook_deny": "申报缺报核对（依赖申报留痕 + hook 执行前裁决）",
    "hook_blindspot_change": "hook 盲区核对（依赖快照 finding + hook 裁决）",
    "report_snapshot_conflict": ("申报快照矛盾核对（依赖申报留痕 + "
                                 "快照变更全集 + hook 裁决 + 受保护目录）"),
}

# 维度缺失时的指引（如实告知需要哪些源）
_SOURCE_GUIDANCE = {
    "unreported_hook_deny": "需 mcp_reports.jsonl（申报留痕）与 "
                            "hook_decisions.jsonl（PreToolUse 裁决）均落盘",
    "hook_blindspot_change": "需 snapshot_checker.jsonl（快照 finding）与 "
                             "hook 两轨裁决留痕均落盘",
    "report_snapshot_conflict": "需 mcp_reports.jsonl、snapshot_changes.jsonl"
                                "（快照变更全集）、hook 两轨裁决留痕均落盘"
                                "且声明受保护目录",
}


def _payload_paths(payload: dict) -> List[str]:
    """申报 tool_args → 文件路径集（与 parse_reported_paths 同口径）。"""
    args = payload.get("tool_args") or {}
    if not isinstance(args, dict):
        return []
    paths = []
    for key in ("path", "file_path", "file", "old_path", "new_path",
                "src", "dst"):
        val = args.get(key)
        if val and isinstance(val, str):
            paths.append(val)
    return paths


def _payload_command(payload: dict) -> str:
    """申报 tool_args → exec 命令文本（无则空串）。"""
    args = payload.get("tool_args") or {}
    if not isinstance(args, dict):
        return ""
    return str(args.get("command") or args.get("cmd") or "").strip()


def _is_hook_notify(payload: dict) -> bool:
    """申报是否来自 hook 自身的 notify（tool_args.hook_phase 标记）。

    P1-4/P2-1 后 hook pre/post 裁决经通知通道进入申报流；「申报未报」
    比对只认 Agent 主动 MCP 申报，hook notify 申报不计入（防自证）。
    """
    args = payload.get("tool_args") or {}
    return isinstance(args, dict) and "hook_phase" in args


def _snapshot_finding_paths(finding: dict) -> List[str]:
    """快照 finding → 路径集（unreported_file_change 变更集 /
    unreported_file_access 访问对象）。"""
    kind = finding.get("kind")
    if kind == "unreported_file_change":
        paths = []
        for k in ("added", "modified", "removed"):
            for p in (finding.get("changes") or {}).get(k) or {}:
                paths.append(str(p))
        return paths
    if kind == "unreported_file_access":
        return [str(a.get("object_name") or "")
                for a in (finding.get("accesses") or [])]
    return []


class ConsistencyChecker:
    """双源一致性核对器（P2-2，四源留痕交叉比对，仅告警不拦截）。

    停止监测时 finish() 解析四源留痕 → 三类不一致比对 → 落盘
    consistency_issues.jsonl + summary。各维度依赖源缺失时独立
    unavailable（P2-4 降级语义），不中断其余维度。
    """

    def __init__(self, output_dir: str, *,
                 reports_path: Optional[str] = None,
                 pre_decisions_path: Optional[str] = None,
                 post_decisions_path: Optional[str] = None,
                 snapshot_findings_path: Optional[str] = None,
                 snapshot_changes_path: Optional[str] = None,
                 protected_dirs: Optional[List[str]] = None,
                 jsonl_name: str = "consistency_issues.jsonl"):
        self._output_dir = output_dir
        self._reports_path = reports_path
        self._pre_path = pre_decisions_path
        self._post_path = post_decisions_path
        self._snapshot_path = snapshot_findings_path
        self._changes_path = snapshot_changes_path
        self._dirs = [os.path.normpath(str(d)) for d in
                      (protected_dirs or []) if d]
        self._jsonl_name = jsonl_name

    # ── 源解析（损坏行容错，复用 _iter_jsonl）───────────────────────

    def _load_reports(self, errors: dict) -> Dict[str, list]:
        """申报留痕 → agent_reports 列表（排除 hook notify 申报）。

        每条: {session_id, tool_name, paths, command, write_class}
        """
        agent_reports = []
        for rec in _iter_jsonl(self._reports_path, errors):
            if rec.get("type") != "report_tool_call":
                continue
            payload = rec.get("payload") or {}
            if _is_hook_notify(payload):
                continue
            tool_name = str(payload.get("tool_name", "") or "").strip()
            session_id = str(payload.get("session_id", "") or "")
            agent_reports.append({
                "session_id": session_id,
                "tool_name": tool_name,
                "paths": _payload_paths(payload),
                "command": _payload_command(payload),
                "write_class": (tool_name.lower() in WRITE_TOOL_NAMES),
            })
        return {"agent_reports": agent_reports}

    def _load_hook_entries(self, path: str, errors: dict,
                           event: str) -> List[dict]:
        """hook 裁决/审计留痕 → 条目列表（仅指定 event）。"""
        entries = []
        for rec in _iter_jsonl(path, errors):
            if rec.get("event") != event:
                continue
            entries.append(rec)
        return entries

    def _load_snapshot_findings(self, errors: dict) -> List[dict]:
        """快照校验留痕 → finding 列表。"""
        findings = []
        for rec in _iter_jsonl(self._snapshot_path, errors):
            if rec.get("type") != "snapshot_checker_finding":
                continue
            findings.append(rec)
        return findings

    def _load_snapshot_changes(self, errors: dict) -> List[dict]:
        """快照变更全集留痕 → 变更路径集（排除申报前 diff 全集）。

        与 snapshot_checker 配套：每个 tick 的 diff 全集落
        snapshot_changes.jsonl（含被「已申报排除」过滤前的变更）。
        """
        paths: List[str] = []
        for rec in _iter_jsonl(self._changes_path, errors):
            if rec.get("type") != "snapshot_checker_change":
                continue
            for k in ("added", "modified", "removed"):
                for p in (rec.get("changes") or {}).get(k) or {}:
                    paths.append(str(p))
        return paths

    # ── 三类不一致比对 ──────────────────────────────────────────────

    def _check_unreported_deny(self, pre_entries: List[dict],
                               agent_reports: List[dict],
                               issues: List[dict],
                               unavailable: List[dict],
                               errors: dict):
        """① 申报未报但 hook 拦截: deny 的 (session,target) 在 Agent
        申报流（同会话路径/命令）中无对应。"""
        pre_ok = self._pre_path and os.path.isfile(self._pre_path)
        # 申报留痕未配置落盘（jsonl_dir 未设）才算源缺失；配置了但
        # 文件不存在 = 监测期间零申报，视为空申报流可核对（deny 全缺报）。
        reports_ok = bool(self._reports_path)
        if not pre_ok or not reports_ok:
            unavailable.append({
                "dimension": "unreported_hook_deny",
                "reason": ("申报留痕未配置落盘或 hook 执行前裁决缺失，"
                           "申报缺报核对不可核对"),
                "guidance": _SOURCE_GUIDANCE["unreported_hook_deny"],
            })
            return
        # 同会话 Agent 申报比对集（文件路径 + exec 命令）
        by_session: Dict[str, List[str]] = {}
        for r in agent_reports:
            if not r["session_id"]:
                continue
            cand = list(r["paths"]) + ([r["command"]] if r["command"] else [])
            by_session.setdefault(r["session_id"], []).extend(cand)
        for e in pre_entries:
            if str(e.get("decision", "")) != "deny":
                continue
            target = str(e.get("target") or "").strip()
            session_id = str(e.get("session_id", "") or "")
            if not target or not session_id:
                continue  # 无路径/会话无法配对，不虚构不一致
            cand = by_session.get(session_id, [])
            if matches_reported_path(target, cand):
                continue  # 有对应申报 → 一致
            issues.append({
                "kind": "unreported_hook_deny",
                "severity": ISSUE_SEVERITY,
                "session_id": session_id,
                "tool_name": str(e.get("tool_name", "") or ""),
                "target": target[:500],
                "hook_timestamp": e.get("timestamp", ""),
            })

    def _check_hook_blindspot(self, findings: List[dict],
                              pre_entries: List[dict],
                              post_entries: List[dict],
                              issues: List[dict],
                              unavailable: List[dict]):
        """② hook 未触发但快照发现访问/变更: finding 路径在 hook
        执行前+执行后裁决中均无对应。"""
        pre_ok = self._pre_path and os.path.isfile(self._pre_path)
        post_ok = self._post_path and os.path.isfile(self._post_path)
        snap_ok = self._snapshot_path and os.path.isfile(
            self._snapshot_path)
        if not snap_ok or (not pre_ok and not post_ok):
            unavailable.append({
                "dimension": "hook_blindspot_change",
                "reason": ("快照 finding 或 hook 裁决留痕缺失，"
                           "hook 盲区核对不可核对"),
                "guidance": _SOURCE_GUIDANCE["hook_blindspot_change"],
            })
            return
        hook_targets = []
        for e in pre_entries + post_entries:
            t = str(e.get("target") or "").strip()
            if t:
                hook_targets.append(t)
        for f in findings:
            for p in _snapshot_finding_paths(f):
                if not p:
                    continue
                if matches_reported_path(p, hook_targets):
                    continue  # hook 有观测 → 非盲区
                issues.append({
                    "kind": "hook_blindspot_change",
                    "severity": ISSUE_SEVERITY,
                    "path": p[:500],
                    "finding_kind": f.get("kind", "?"),
                })

    def _check_report_snapshot_conflict(self, agent_reports: List[dict],
                                        snapshot_changes: List[str],
                                        pre_entries: List[dict],
                                        post_entries: List[dict],
                                        issues: List[dict],
                                        unavailable: List[dict]):
        """③ 申报与快照矛盾: write 类申报声明的受保护目录内路径，
        快照 diff 全集无变化且 hook 两轨均无裁决。"""
        if not self._dirs:
            unavailable.append({
                "dimension": "report_snapshot_conflict",
                "reason": "未声明受保护目录，快照侧无比对范围",
                "guidance": _SOURCE_GUIDANCE["report_snapshot_conflict"],
            })
            return
        reports_ok = bool(self._reports_path)
        changes_ok = self._changes_path and os.path.isfile(
            self._changes_path)
        pre_ok = self._pre_path and os.path.isfile(self._pre_path)
        post_ok = self._post_path and os.path.isfile(self._post_path)
        if not reports_ok or not changes_ok or (not pre_ok and not post_ok):
            unavailable.append({
                "dimension": "report_snapshot_conflict",
                "reason": ("申报留痕未配置落盘、快照变更全集或 hook 裁决"
                           "留痕缺失，申报快照矛盾核对不可核对"),
                "guidance": _SOURCE_GUIDANCE["report_snapshot_conflict"],
            })
            return
        hook_targets = []
        for e in pre_entries + post_entries:
            t = str(e.get("target") or "").strip()
            if t:
                hook_targets.append(t)
        for r in agent_reports:
            if not r["write_class"]:
                continue
            for p in r["paths"]:
                if not p or not _in_protected_dirs(p, self._dirs):
                    continue  # 受保护目录外不在快照比对范围
                if matches_reported_path(p, snapshot_changes):
                    continue  # 快照观察到变化 → 一致
                if matches_reported_path(p, hook_targets):
                    continue  # hook 有裁决 → 通道佐证
                issues.append({
                    "kind": "report_snapshot_conflict",
                    "severity": ISSUE_SEVERITY,
                    "session_id": r["session_id"],
                    "tool_name": r["tool_name"],
                    "path": p[:500],
                })

    # ── 收尾与产出 ──────────────────────────────────────────────────

    def finish(self, reported_paths: Optional[List[str]] = None) -> dict:
        """停止监测收尾: 四源解析 + 三类比对 → 留痕 → summary。"""
        del reported_paths  # 预留扩展位（当前比对不依赖 daemon 传入集）
        errors: Dict[str, dict] = {}
        reports = self._load_reports(errors)
        agent_reports = reports["agent_reports"]
        pre_entries = self._load_hook_entries(
            self._pre_path, errors, "pre_tool_use")
        post_entries = self._load_hook_entries(
            self._post_path, errors, "post_tool_use")
        findings = self._load_snapshot_findings(errors)
        snapshot_changes = self._load_snapshot_changes(errors)

        issues: List[dict] = []
        unavailable: List[dict] = []

        self._check_unreported_deny(pre_entries, agent_reports,
                                    issues, unavailable, errors)
        self._check_hook_blindspot(findings, pre_entries, post_entries,
                                   issues, unavailable)
        self._check_report_snapshot_conflict(agent_reports,
                                             snapshot_changes,
                                             pre_entries, post_entries,
                                             issues, unavailable)

        counts: Dict[str, int] = {}
        for i in issues:
            counts[i["kind"]] = counts.get(i["kind"], 0) + 1

        summary = {
            "enabled": True,
            "checked": True,
            "issues": issues,
            "issue_counts": counts,
            "unavailable": unavailable,
            "sources": {
                "agent_reports": len(agent_reports),
                "hook_pre_entries": len(pre_entries),
                "hook_post_entries": len(post_entries),
                "snapshot_findings": len(findings),
                "snapshot_change_paths": len(snapshot_changes),
            },
            "corrupt_lines": errors.get("corrupt_lines", {}),
            "note": CONSISTENCY_NOTE,
        }
        self._write_jsonl(issues, unavailable)
        return summary

    def _write_jsonl(self, issues: List[dict],
                     unavailable: List[dict]) -> None:
        """追加写一致性核对留痕（幂等追加，不覆盖历史；daemon 单进程写）。"""
        if not issues and not unavailable:
            return
        os.makedirs(self._output_dir, exist_ok=True)
        path = os.path.join(self._output_dir, self._jsonl_name)
        entries = [{
            "type": "consistency_issue",
            "timestamp_ms": int(time.time() * 1000),
            **i,
        } for i in issues]
        for u in unavailable:
            entries.append({
                "type": "consistency_unavailable",
                "timestamp_ms": int(time.time() * 1000),
                **u,
            })
        try:
            with open(path, "a", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, ensure_ascii=False, default=str)
                            + "\n")
        except OSError as e:
            logger.warning(f"一致性核对留痕写入失败: {e}")
