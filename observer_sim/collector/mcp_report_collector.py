# -*- coding: utf-8 -*-
"""
collector/mcp_report_collector.py — MCP 申报采集器（P3-8）

实现 ICollector 接口，把 MCP 申报流（McpReportBroker 队列）转换为
RawEvent 流，接入统一监测管线（归一化 / 规则 / 评分 / 研判 / 审计）。

数据流:
    WorkBuddy (MCP client)
        → MCP Server 申报 tools（校验 + 限流，P1）
        → McpReportBroker 队列（+ JSONL 留痕）
        → McpReportCollector（本模块，P3）
            * SemanticGuard.sanitize_args 脱敏/截断（P2 浅层语义保护）
            * RawEventFactory.from_tool_call 统一转换（P0 单一转换点）
        → RawEvent 流 → 归一化 / 规则 / 评分 / 研判 / 审计

三类申报的处理:
    - report_tool_call → RawEvent（主要事件源）
    - report_action   → 不产 RawEvent（动作留痕由 broker JSONL 承担）
    - report_session  → 不产 RawEvent（会话留痕由 broker JSONL 承担）

能力定位（计划决策基线）: 合规留痕 + 风险提示；无 L2/L3 阻断。
"""

import logging
import os
import threading
from typing import Dict, Iterator, Optional

from collector.base_collector import ICollector, CollectorCapabilities
from models.event import RawEvent
from mcp_bridge.schemas import (
    TOOL_REPORT_ACTION,
    TOOL_REPORT_SESSION,
    TOOL_REPORT_TOOL_CALL,
)
from observer_core.monitoring.raw_event_factory import RawEventFactory

logger = logging.getLogger(__name__)


class McpReportCollector(ICollector):
    """
    MCP 申报采集器 —— 申报流 → RawEvent 流的桥。

    消费 McpReportBroker 队列中的申报记录:
    - report_tool_call 记录经浅层语义保护（脱敏/截断）后，
      复用 RawEventFactory 转换为 RawEvent；
    - report_action / report_session 不产事件（仅统计，留痕由 broker 承担）。
    """

    def __init__(self, config: dict,
                 broker=None,
                 guard=None):
        """
        Args:
            config: 配置字典（config.yaml；mcp_report 段可选）
            broker: McpReportBroker 实例（缺省时需 attach 前注入）
            guard:  SemanticGuard 实例（缺省时使用默认框架配置）
        """
        self.config = config or {}
        self.mcp_config = self.config.get("mcp_report", {})
        self.target_agent_id = self.mcp_config.get(
            "target_agent_id", "workbuddy")

        self._broker = broker
        if guard is not None:
            self._guard = guard
        else:
            from mcp_bridge.semantic_guard import SemanticGuard
            self._guard = SemanticGuard(
                framework=self.mcp_config.get(
                    "framework", "pydantic-deep"))

        # 内部状态
        self._attached = False
        self._stop_requested = threading.Event()
        self._poll_timeout = self.mcp_config.get("poll_timeout_s", 0.2)

        # 统计
        self._tool_call_count = 0
        self._action_count = 0
        self._session_count = 0
        self._skipped_count = 0

        # T3.1: 会话申报回调（session_id, status, payload）；
        # 供外部（如轻量交叉校验器）在会话边界做进程快照等观测动作。
        self._session_listener = None

    # ── ICollector 接口 ─────────────────────────────────────────────────

    def capabilities(self) -> CollectorCapabilities:
        """能力描述: 观测 + 留痕，无阻断（决策基线: 合规留痕+风险提示）"""
        return CollectorCapabilities(
            name="MCPReport",
            can_observe=True,
            can_block_tier2=False,   # 无 L2 阻断
            can_block_tier3=False,   # 无 L3 阻断
            is_transparent=False,    # 依赖 WorkBuddy 主动申报
            performance_overhead="low",
            time_source="realtime_monotonic",
        )

    def attach(self, target_pid: int = 0, agent_id: str = "") -> bool:
        """
        附着到申报源。

        target_pid: 忽略（黑盒 Agent 无真实进程）
        agent_id:   默认 agent 标识（申报记录缺 agent_id 时使用）
        """
        if agent_id:
            self.target_agent_id = agent_id
        if self._broker is None:
            logger.error("McpReportCollector: broker 未注入，无法采集")
            return False
        self._attached = True
        logger.info(f"McpReportCollector attached "
                    f"(agent_id={self.target_agent_id})")
        return True

    def start(self) -> Iterator[RawEvent]:
        """
        开始消费申报流，yield RawEvent。

        阻塞消费 broker 队列；detach() 后当前轮询结束即退出。
        """
        if not self._attached:
            logger.warning("McpReportCollector 未附着（先调 attach）")
            return
        self._stop_requested.clear()

        while not self._stop_requested.is_set():
            record = self._broker.consume(timeout=self._poll_timeout)
            if record is None:
                continue
            event = self._record_to_raw_event(record)
            if event is not None:
                yield event

    def send_command(self, cmd) -> bool:
        """阻断指令: 不支持（无 L2/L3 阻断能力）。"""
        logger.info(f"McpReportCollector 不支持阻断（合规留痕+风险提示）: "
                    f"{getattr(cmd, 'command', cmd)}")
        return False

    def detach(self) -> None:
        """停止采集（start 循环在下个轮询退出）。"""
        self._stop_requested.set()
        self._attached = False
        logger.info("McpReportCollector 已断开")

    def set_session_listener(self, listener) -> None:
        """注册会话申报回调（T3.1 交叉校验等观测侧扩展点）。

        listener(session_id, status, payload) 在每条 report_session
        记录被消费时同步调用；回调异常只记日志，不破坏采集循环。
        """
        self._session_listener = listener

    def get_process_tree(self) -> dict:
        """黑盒 Agent 无真实进程树；返回已观测 agent 概览。"""
        return {"note": "MCP 申报模式无进程树（黑盒 Agent）"}

    # ── 申报记录 → RawEvent ─────────────────────────────────────────────

    def _record_to_raw_event(self, record: Dict) -> Optional[RawEvent]:
        """单条申报记录 → RawEvent（异常记录安全跳过，不破坏管线）。"""
        try:
            record_type = record.get("type", "")
            payload = record.get("payload")

            if not isinstance(payload, dict):
                # 畸形记录（payload 缺失/非 dict）: 安全跳过
                self._skipped_count += 1
                logger.warning(f"McpReportCollector: 跳过无有效 payload "
                               f"的申报 {record.get('event_id', '?')}")
                return None

            if record_type == TOOL_REPORT_TOOL_CALL:
                return self._tool_call_to_raw_event(record, payload)
            if record_type == TOOL_REPORT_ACTION:
                self._action_count += 1
                return None
            if record_type == TOOL_REPORT_SESSION:
                self._session_count += 1
                self._notify_session_listener(payload)
                return None

            # 未知类型申报: 计数跳过（留痕已在 broker JSONL）
            self._skipped_count += 1
            logger.warning(f"McpReportCollector: 跳过未知申报类型 "
                           f"{record_type!r}")
            return None
        except Exception as e:  # 防御: 畸形申报不破坏采集循环
            self._skipped_count += 1
            logger.warning(f"McpReportCollector: 申报转换失败，已跳过: {e}")
            return None

    def _notify_session_listener(self, payload: Dict) -> None:
        """会话申报回调通知（异常隔离，不影响主循环）。"""
        listener = self._session_listener
        if listener is None:
            return
        try:
            session_id = str(payload.get("session_id", "") or "") or None
            status = str(payload.get("status", "") or "")
            listener(session_id, status, payload)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"McpReportCollector: 会话回调异常（已隔离）: {e}")

    def _tool_call_to_raw_event(self, record: Dict,
                                payload: Dict) -> RawEvent:
        """report_tool_call 申报 → RawEvent（脱敏 + 工厂统一转换）。"""
        self._tool_call_count += 1

        tool_name = str(payload.get("tool_name", "") or "")
        agent_id = str(payload.get("agent_id", "") or self.target_agent_id)
        session_id = str(payload.get("session_id", "") or "") or None

        # 浅层语义保护: 参数摘要脱敏/截断（恶意申报不破坏管线）
        safe_args = self._guard.sanitize_args(payload.get("tool_args"))

        # 时间: 毫秒 epoch → 纳秒
        timestamp_ms = payload.get("timestamp_ms") or 0
        try:
            timestamp_ns = int(timestamp_ms) * 1_000_000
        except (TypeError, ValueError):
            timestamp_ns = 0

        # 复用 RawEventFactory（与 CLI 直连/DeepAgent 采集器同一转换点）
        return RawEventFactory.from_tool_call(
            {"tool": tool_name, "input": safe_args},
            event_id=f"mcp_{record.get('event_id', '')}",
            timestamp_ns=timestamp_ns,
            pid=0,              # 黑盒 Agent 无真实 pid
            ppid=0,
            agent_id=agent_id,
            agent_framework="mcp_report",
            session_id=session_id,  # 会话维度（违规升级隔离的关键）
        )

    # ── 统计与访问器 ───────────────────────────────────────────────────

    @property
    def tool_call_count(self) -> int:
        return self._tool_call_count

    @property
    def action_count(self) -> int:
        return self._action_count

    @property
    def session_count(self) -> int:
        return self._session_count

    @property
    def skipped_count(self) -> int:
        return self._skipped_count

    @property
    def guard(self):
        """语义保护器（供高级用法/测试）"""
        return self._guard


# ── P1-2: 申报完整性核对 + 覆盖置信度（hook 事件数 vs 申报事件数）──
# 只读三处留痕做计数比对，不改动任何检测/研判逻辑；
# 置信度措辞固定声明「仅反映留痕侧观测完整性」。

# PreToolUse 盲区工具（宿主 5.3.14 实测：Bash 不经过 PreToolUse，
# 见计划文档 P1-1 宿主实测结论；仅影响盲区标注，不影响比对计数）。
HOOK_PRE_BLINDSPOT_TOOLS = ("Bash", "PowerShell")

HOOK_COVERAGE_NOTE = (
    "比对基于三处留痕计数（申报 mcp_reports.jsonl / hook 执行前裁决 "
    "hook_decisions.jsonl / hook 执行后审计 hook_post_decisions.jsonl），"
    "仅反映留痕侧观测完整性，不代表行为全覆盖")


def _iter_jsonl(path: str, errors: dict):
    """逐行容错解析 JSONL，yield dict；损坏行计数入 errors[path]。

    实测坑（P1-1）: 宿主并发 hook 进程曾致 jsonl 行交错损坏，
    历史损坏行保留为证据——比对器必须容错跳过并如实计数。
    """
    import json as _json
    counter = errors.setdefault("corrupt_lines", {})
    if not path or not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = _json.loads(line)
            except (ValueError, TypeError):
                counter[path] = counter.get(path, 0) + 1
                continue
            if isinstance(obj, dict):
                yield obj


def _payload_of(record: dict) -> dict:
    payload = record.get("payload")
    return payload if isinstance(payload, dict) else {}


def analyze_hook_coverage(reports_path: Optional[str] = None,
                          pre_decisions_path: Optional[str] = None,
                          post_decisions_path: Optional[str] = None) -> dict:
    """P1-2: hook 事件数 vs 申报事件数比对，输出 coverage_confidence。

    数据源（三处留痕，均缺失/空时如实标注不可核对）:
    - reports_path:        mcp_reports.jsonl（第 1 轨申报留痕，
                           type=report_tool_call 按 payload.tool_name 计数）
    - pre_decisions_path:  hook_decisions.jsonl（第 2 轨 PreToolUse 裁决，
                           event=pre_tool_use 按 tool_name 计数）
    - post_decisions_path: hook_post_decisions.jsonl（P1-1 PostToolUse
                           审计，event=post_tool_use 按 tool_name 计数）

    比对口径:
    - 覆盖状态（按工具）: covered（hook_pre >= reported）/
      partial（0 < hook_pre < reported）/
      post_covered（PreToolUse 盲区但 PostToolUse 审计补位，如 Bash）/
      uncovered（双通道均无观测 → 监测盲区）/
      over_observed（hook 观测到但申报未报 → 申报缺报信号）
    - coverage_confidence: 高 = 全部 covered 且无缺报/盲区；
      中 = 存在 partial 或 post_covered 补位（无 uncovered/缺报）；
      低 = 存在 uncovered、申报缺报、deny 未申报、或双通道无数据。

    Returns:
        dict: {checked, reason, reported_tool_calls, hook_pre_events,
               hook_post_events, hook_deny_count, hook_gate_error_count,
               corrupt_lines, tools{...}, unreported_denies[...],
               coverage_confidence, confidence_reason,
               bash_blindspot_note, note}
    """
    result = {
        "checked": False,
        "reason": "",
        "reported_tool_calls": 0,
        "hook_pre_events": 0,
        "hook_post_events": 0,
        "hook_deny_count": 0,
        "hook_gate_error_count": 0,
        "corrupt_lines": {},
        "tools": {},
        "unreported_denies": [],
        "coverage_confidence": "低",
        "confidence_reason": "",
        "bash_blindspot_note": "",
        "note": HOOK_COVERAGE_NOTE,
    }
    paths = [p for p in (reports_path, pre_decisions_path,
                         post_decisions_path) if p]
    existing = [p for p in paths if os.path.isfile(p)]
    if not existing:
        result["reason"] = "申报与 hook 留痕均不存在，覆盖比对不可核对"
        result["confidence_reason"] = "无留痕文件可读（申报未落盘或 hook 未部署）"
        return result

    # ── 三源计数（损坏行容错）──
    reported: Dict[str, int] = {}
    session_reports = 0
    for rec in _iter_jsonl(reports_path, result):
        if rec.get("type") == TOOL_REPORT_TOOL_CALL:
            tool = str(_payload_of(rec).get("tool_name", "") or "").strip()
            if tool:
                reported[tool] = reported.get(tool, 0) + 1
                result["reported_tool_calls"] += 1
        elif rec.get("type") == TOOL_REPORT_SESSION:
            session_reports += 1
    hook_pre: Dict[str, int] = {}
    deny_tools: Dict[str, int] = {}
    for rec in _iter_jsonl(pre_decisions_path, result):
        if rec.get("event") != "pre_tool_use":
            continue
        tool = str(rec.get("tool_name", "") or "").strip()
        hook_pre[tool] = hook_pre.get(tool, 0) + 1
        result["hook_pre_events"] += 1
        if str(rec.get("decision", "")) == "deny":
            result["hook_deny_count"] += 1
            deny_tools[tool] = deny_tools.get(tool, 0) + 1
        if rec.get("gate_error"):
            result["hook_gate_error_count"] += 1
    hook_post: Dict[str, int] = {}
    for rec in _iter_jsonl(post_decisions_path, result):
        if rec.get("event") != "post_tool_use":
            continue
        tool = str(rec.get("tool_name", "") or "").strip()
        hook_post[tool] = hook_post.get(tool, 0) + 1
        result["hook_post_events"] += 1

    result["checked"] = True
    result["reason"] = ""

    # ── 工具级比对 ──
    all_tools = set(reported) | set(hook_pre) | set(hook_post)
    uncovered_tools = []
    over_observed_tools = []
    partial_tools = []
    post_covered_tools = []
    for tool in sorted(all_tools):
        r = reported.get(tool, 0)
        pre = hook_pre.get(tool, 0)
        post = hook_post.get(tool, 0)
        deny = deny_tools.get(tool, 0)
        if r > 0 and pre >= r:
            status = "covered"
        elif r > 0 and pre > 0:
            status = "partial"
            partial_tools.append(tool)
        elif r > 0 and pre == 0 and post > 0:
            status = "post_covered"
            post_covered_tools.append(tool)
        elif r > 0 and pre == 0 and post == 0:
            status = "uncovered"
            uncovered_tools.append(tool)
        else:  # r == 0（hook 观测到但申报未报）
            status = "over_observed"
            over_observed_tools.append(tool)
        result["tools"][tool] = {
            "reported": r,
            "hook_pre": pre,
            "hook_post": post,
            "deny": deny,
            "pre_coverage": (pre / r) if r > 0 else None,
            "status": status,
            "blindspot": (r > 0 and pre == 0),
        }

    # ── deny 未申报（申报缺报的强信号）──
    for tool, dcount in sorted(deny_tools.items()):
        if reported.get(tool, 0) == 0:
            result["unreported_denies"].append(
                {"tool_name": tool, "deny_count": dcount})

    # ── Bash 盲区说明（TC-05「申报完整性核对报告 Bash 未覆盖」）──
    bash_lines = []
    for tool in sorted(set(HOOK_PRE_BLINDSPOT_TOOLS) & set(reported)):
        pre = hook_pre.get(tool, 0)
        post = hook_post.get(tool, 0)
        r = reported.get(tool, 0)
        if pre > 0:
            bash_lines.append(f"{tool}: PreToolUse 有触发（{pre} 条裁决，"
                             f"申报 {r} 条）")
        elif post > 0:
            bash_lines.append(
                f"{tool} 未覆盖（PreToolUse 盲区，宿主实测不触发）；"
                f"PostToolUse 审计补位 {post} 条（申报 {r} 条）——"
                f"监测路径降级告警生效")
        else:
            bash_lines.append(
                f"{tool} 未覆盖（PreToolUse 盲区且无 PostToolUse 审计，"
                f"申报 {r} 条）——监测盲区告警")
    if bash_lines:
        result["bash_blindspot_note"] = "；".join(bash_lines)

    # ── coverage_confidence ──
    if not reported and not hook_pre and not hook_post:
        result["coverage_confidence"] = "低"
        result["confidence_reason"] = "申报与 hook 双通道均无事件（无会话活动或部署未生效）"
    elif result["unreported_denies"] or uncovered_tools or over_observed_tools:
        result["coverage_confidence"] = "低"
        reasons = []
        if result["unreported_denies"]:
            reasons.append(f"{len(result['unreported_denies'])} 个工具存在 "
                           f"deny 拦截但申报未报（疑似漏报）")
        if uncovered_tools:
            reasons.append(f"监测盲区工具: {', '.join(uncovered_tools)}")
        if over_observed_tools:
            reasons.append(f"hook 观测到但申报未报的工具: "
                           f"{', '.join(over_observed_tools)}")
        result["confidence_reason"] = "；".join(reasons)
    elif partial_tools or post_covered_tools:
        result["coverage_confidence"] = "中"
        reasons = []
        if partial_tools:
            reasons.append(f"部分覆盖工具: {', '.join(partial_tools)}")
        if post_covered_tools:
            reasons.append(f"执行后审计补位工具: {', '.join(post_covered_tools)}")
        result["confidence_reason"] = "；".join(reasons)
    else:
        result["coverage_confidence"] = "高"
        result["confidence_reason"] = (
            f"申报工具调用 {result['reported_tool_calls']} 条全部被 hook "
            f"执行前裁决完整观测（{result['hook_pre_events']} 条裁决）")
    return result


# ── P2-3 双路径覆盖矩阵（产出层）────────────────────────────────
# 复用 analyze_hook_coverage 的工具级计数与 snapshot_checker summary
# 产出「工具 × 通道」覆盖矩阵，供报告页小节与 monitoring_summary.json
# 的 coverage_matrix 字段使用（仅呈现，不触碰检测/研判逻辑）。

COVERAGE_MATRIX_NOTE = (
    "覆盖矩阵按工具 × 通道（申报 / hook执行前 / hook执行后 / 快照兜底）"
    "呈现观测覆盖状态；快照通道为工具无关兜底观测面（findings 不带工具"
    "维度），按通道可用性整体标记；仅呈现、不判定")


def build_coverage_matrix(hook_coverage: Optional[dict] = None,
                          snapshot_summary: Optional[dict] = None) -> dict:
    """P2-3: 双路径覆盖矩阵（工具 × 通道 × 状态）。

    复用 analyze_hook_coverage 的工具级计数（reported/hook_pre/
    hook_post）与 snapshot_checker.finish() 的 summary（available）
    产出「工具 × 通道」覆盖矩阵。

    通道状态语义（每工具每通道）:
    - covered:     该通道观测到该工具（有记录）
    - uncovered:   通道可用但未观测到该工具
    - unavailable: 通道不可核对（留痕缺失 / 未启用 / 快照失败）

    通道可用性口径:
    - mcp_report / hook_pre / hook_post: hook_coverage.checked=False
      （三处留痕均不存在）时全部 unavailable；checked=True 时按工具
      计数判定 covered/uncovered。
    - snapshot: 快照通道为工具无关兜底观测面，整列按通道可用性标记:
      snapshot_summary 为 None（未启用）或 available=False → 整列
      unavailable；available=True → 整列 covered。

    Returns:
        dict: {checked, reason, unavailable_channels, tools{tool:
               {mcp_report, hook_pre, hook_post, snapshot}}, counts,
               note}
    """
    result = {
        "checked": False,
        "reason": "",
        "unavailable_channels": [],
        "tools": {},
        "counts": {},
        "note": COVERAGE_MATRIX_NOTE,
    }
    hc = hook_coverage or {}
    tools = hc.get("tools") or {}
    hc_checked = bool(hc.get("checked"))

    # ── 通道可用性 ──
    if not hc_checked:
        result["reason"] = ("申报与 hook 留痕均不可核对（"
                            + str(hc.get("reason") or "无留痕文件")
                            + "）")
        for ch in ("mcp_report", "hook_pre", "hook_post"):
            result["unavailable_channels"].append(ch)
    else:
        result["checked"] = True

    snap_state = "unavailable"
    if snapshot_summary is None:
        result["unavailable_channels"].append("snapshot")
    elif not snapshot_summary.get("available"):
        result["unavailable_channels"].append("snapshot")
    else:
        snap_state = "covered"

    # ── 每工具矩阵行 ──
    counts = {}
    for tool, info in sorted((tools or {}).items()):
        # 防御：历史 gate_error 条目 tool_name 为空，跳过避免矩阵
        # 出现无意义的空工具名行（counts 也随之不含该条目）。
        if not (tool or "").strip():
            continue
        row = {
            "mcp_report": ("covered" if info.get("reported", 0) > 0
                           else "uncovered"),
            "hook_pre": ("covered" if info.get("hook_pre", 0) > 0
                         else "uncovered"),
            "hook_post": ("covered" if info.get("hook_post", 0) > 0
                          else "uncovered"),
            "snapshot": snap_state,
        }
        if not hc_checked:
            for ch in ("mcp_report", "hook_pre", "hook_post"):
                row[ch] = "unavailable"
        result["tools"][tool] = row
        status = info.get("status", "uncovered")
        counts[status] = counts.get(status, 0) + 1
    result["counts"] = counts
    return result

