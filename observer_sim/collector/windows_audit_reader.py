# -*- coding: utf-8 -*-
"""
collector/windows_audit_reader.py — T3.3 Windows 审计日志读取（第 3 层，用户态）

定位:
    以 Windows 系统自带审计日志为独立观测源，做「系统行为 vs 申报」差异比对:
    - 4688（安全日志 Security: 进程创建，需管理员 + 启用「审核进程创建」策略）
    - 4104（Microsoft-Windows-PowerShell/Operational: 脚本块日志，
           需启用 PowerShell 脚本块日志）
    经 PowerShell Get-WinEvent 子进程读取（零新依赖、纯用户态），
    与会话申报比对，输出「疑似二级操作」差异告警（仅告警不拦截）。

设计约束（硬性）:
- 不引入 ETW / 内核驱动级检测（Event Log 为系统既有用户态日志）；
- 不改动判定管线（只读查询 + 产出层呈现，比对仅排除已申报/白名单）；
- 审计未启用 / 无权限 / 查询失败时如实标记 unavailable 并输出启用指引，
  不静默失败；
- 时钟对齐: 系统日志 SystemTime 为 UTC，申报侧为毫秒 epoch / 本地 ISO，
  统一转 UTC 毫秒 epoch 后做窗口比对（解析侧二次过滤兜底），
  避免系统性偏移误报。

数据流:
    report_session(start/end) ──► AuditCrossChecker 记录会话 UTC 窗口
    停止监测 ──► finish(): 按窗口查询 4688/4104 → 解析 XML
        → 排除系统白名单 / Agent 进程 / 已申报命令与路径
        └─ 剩余 → 「疑似二级操作」告警 → crosscheck_audit.jsonl
"""

import json
import logging
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

# 复用 T3.1 的系统进程白名单与命令匹配口径（跨模块共享同一口径）
from collector.lightweight_crosscheck import (  # noqa: E402
    DEFAULT_SYSTEM_WHITELIST, matches_reported)

logger = logging.getLogger(__name__)

# 审计通道定义（log_name / 事件 ID / 说明 / 启用指引）
CHANNEL_DEFS = {
    "4688": {
        "log_name": "Security",
        "ids": [4688],
        "desc": "进程创建审计",
        "guidance": (
            "以管理员运行 secpol.msc → 安全设置 → 高级审核策略配置 → "
            "详细跟踪 → 审核进程创建 → 勾选成功"),
    },
    "4104": {
        "log_name": "Microsoft-Windows-PowerShell/Operational",
        "ids": [4104],
        "desc": "PowerShell 脚本块日志",
        "guidance": (
            "运行 gpedit.msc → 计算机配置 → 管理模板 → Windows 组件 → "
            "Windows PowerShell → 打开脚本块日志 → 已启用"),
    },
}

# 比对窗口与措辞声明（写入产物与报告固定措辞，如实披露采样局限）
AUDIT_NOTE = (
    "系统审计日志仅覆盖已启用审计的进程创建(4688)与 PowerShell 脚本块"
    "(4104)；审计未启用时该观测源不可用；比对窗口为会话 start/end 边界"
    "（前扩 lookback_s），窗口外事件不可见；差异事件判定为「疑似二级操作」，"
    "仅告警不拦截")

# XML 命名空间（Get-WinEvent ToXml() 输出）
_XML_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def to_utc_epoch_ms(value) -> Optional[int]:
    """时间形态 → UTC 毫秒 epoch（时钟对齐统一口径）。

    - 数字: 按量级识别秒 / 毫秒 / 纳秒（均为 epoch 语义，时区无关）；
    - 字符串: ISO 格式；无时区按本地时区解释（申报侧口径），
      带时区（含 Z）按 UTC 对齐；
    - 无法解析返回 None（调用方按「时间不可用」处理，不参与窗口比对）。
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if value > 10 ** 15:          # 纳秒
            return int(value // 10 ** 6)
        if value > 10 ** 11:          # 毫秒
            return int(value)
        return int(value * 1000)      # 秒
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.astimezone()      # 本地时区 → 带时区
        return int(dt.timestamp() * 1000)
    return None


def parse_event_xml(xml_text: str) -> Optional[dict]:
    """Get-WinEvent ToXml() 输出 → 标准化事件 dict。

    - 4688 → NewProcessName / CommandLine / ParentProcessName；
    - 4104 → ScriptBlockText / Path；
    - TimeCreated(SystemTime, UTC) → time_ms（UTC 毫秒 epoch）；
    - 其他事件 ID / 解析失败返回 None。
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
    sys_time = time_el.get("SystemTime") if time_el is not None else None
    time_ms = to_utc_epoch_ms(sys_time)
    data: Dict[str, str] = {}
    for d in root.findall(f"{_XML_NS}EventData/{_XML_NS}Data"):
        name = d.get("Name")
        if name:
            data[name] = (d.text or "").strip()
    if eid == 4688:
        return {"event_id": 4688, "source": "security_4688",
                "time_ms": time_ms,
                "process": data.get("NewProcessName", ""),
                "command": data.get("CommandLine", ""),
                "parent": data.get("ParentProcessName", "")}
    if eid == 4104:
        text = data.get("ScriptBlockText", "")
        return {"event_id": 4104, "source": "ps_4104",
                "time_ms": time_ms,
                "process": data.get("Path", ""),
                "command": text[:500],   # 脚本块截断，仅用于比对
                "parent": ""}
    return None


# ── 查询执行（真实实现: PowerShell Get-WinEvent 子进程）────────────

def _ps_get_winevent(log_name: str, ids: List[int], start_epoch: float,
                     end_epoch: float, max_events: int,
                     timeout_s: float) -> List[dict]:
    """PowerShell Get-WinEvent 子进程查询（Windows 自带，零新依赖）。

    - StartTime/EndTime 经 FileTime(UTC) 构造，Kind=Utc；
    - 无匹配事件（NoMatchingEventsFound）→ 空列表；
    - 权限不足 / 通道不存在 → 抛异常（上层转 unavailable + 指引）；
    - 返回已解析事件列表（parse_event_xml）。
    """
    if os.name != "nt":
        raise RuntimeError("Windows 审计日志读取仅在 Windows 平台可用")
    filetime = lambda s: int(s) * 10_000_000 + 116444736000000000  # noqa: E731
    id_list = ",".join(str(i) for i in ids)
    ps = (
        "$ErrorActionPreference='Stop';"
        "try {"
        f"$evts = Get-WinEvent -FilterHashtable @{{LogName='{log_name}';"
        f" Id={id_list}; "
        f"StartTime=[DateTime]::FromFileTimeUtc([long]{filetime(start_epoch)});"
        f" EndTime=[DateTime]::FromFileTimeUtc([long]{filetime(end_epoch)})"
        f"}} -MaxEvents {max_events} -ErrorAction Stop;"
        "$out = @(); foreach ($e in $evts) { $out += $e.ToXml() };"
        "ConvertTo-Json -Compress -InputObject $out"
        "} catch {"
        # 无匹配事件判定需语言无关（中文系统错误消息为中文）：
        # FullyQualifiedErrorId 恒为英文（NoMatchingEventsFound,...）；
        # Exception.Message 英文匹配仅作非中文系统兑底。
        "if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or "
        "$_.Exception.Message -match 'NoMatchingEventsFound') { '[]' }"
        "else { Write-Error $_.Exception.Message; exit 1 }"
        "}"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-Command", ps],
            capture_output=True, timeout=timeout_s,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"审计日志查询超时（>{timeout_s}s）: {log_name}")
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(
            f"审计日志查询失败: {log_name}（{err or '未知错误'}）")
    try:
        payload = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
    except ValueError:
        raise RuntimeError(f"审计日志查询输出解析失败: {log_name}")
    events = []
    for xml_text in payload or []:
        evt = parse_event_xml(str(xml_text))
        if evt:
            events.append(evt)
    return events


class WindowsAuditReader:
    """Windows 审计日志读取器（query_fn 可注入，供测试以假事件替代）。"""

    def __init__(self, channels: Optional[Dict[str, dict]] = None,
                 timeout_s: float = 30.0,
                 query_fn: Optional[Callable] = None):
        self._channels = {k: dict(v)
                          for k, v in (channels or CHANNEL_DEFS).items()}
        self._timeout_s = timeout_s
        self._query_fn = query_fn or _ps_get_winevent

    @property
    def channels(self) -> Dict[str, dict]:
        return self._channels

    def availability(self) -> dict:
        """探测各通道可读性（近 1 小时轻量查询，失败给指引）。

        Returns:
            {"available": bool, "channels": {key: {ok, detail, log_name}},
             "guidance": [指引行]}
        """
        end = time.time()
        start = end - 3600
        result: Dict[str, any] = {"available": False, "channels": {},
                                  "guidance": []}
        any_ok = False
        for key, defn in self._channels.items():
            ok = False
            try:
                events = self._query_fn(defn["log_name"], list(defn["ids"]),
                                        start, end, 1, self._timeout_s)
                ok = True
                detail = (f"可读（近 1 小时 {len(events)} 条；"
                          f"无记录时可能未启用审计策略）")
            except Exception as e:  # noqa: BLE001 防御: 通道不可读不破坏主流程
                detail = f"读取失败: {e}"
                result["guidance"].append(
                    f"{key}（{defn['desc']}）: {defn['guidance']}")
            if ok:
                any_ok = True
            result["channels"][key] = {
                "ok": ok,
                "detail": detail,
                "log_name": defn["log_name"],
                "desc": defn["desc"],
            }
        result["available"] = any_ok
        if not any_ok and os.name != "nt":
            result["guidance"].append("当前平台非 Windows，本能力不可用")
        return result

    def read_events(self, start_ms: int, end_ms: int,
                    max_events: int = 500) -> tuple:
        """按 UTC 毫秒窗口查询所有通道事件。

        Returns:
            (events, errors): events 为窗口内（含解析侧时钟对齐过滤）
            事件列表；errors 为通道级失败 [{"channel", "error", "guidance"}]。
        """
        events: List[dict] = []
        errors: List[dict] = []
        for key, defn in self._channels.items():
            try:
                raw = self._query_fn(defn["log_name"], list(defn["ids"]),
                                     start_ms / 1000.0, end_ms / 1000.0,
                                     max_events, self._timeout_s)
            except Exception as e:  # noqa: BLE001
                errors.append({"channel": key, "error": str(e),
                               "guidance": defn["guidance"]})
                continue
            for evt in raw or []:
                t = evt.get("time_ms")
                # 时钟对齐兜底: 仅保留窗口内事件（SystemTime 已转 UTC epoch）
                if t is None or not (start_ms <= t <= end_ms):
                    continue
                events.append(evt)
        return events, errors


# 4104 脚本块比对时忽略的最小长度（过短片段无匹配意义）
_MIN_SCRIPT_LEN = 8


def _process_basename(process: str) -> str:
    return os.path.basename((process or "").replace("\\", "/")).lower()


class AuditCrossChecker:
    """会话级「系统审计 vs 申报」差异比对（第 3 层 T3.3）。

    与 T3.1/T3.2 同构: 会话 start/end 边界（前扩 lookback_s）查询
    4688/4104 事件 → 排除系统白名单 / Agent 进程 / 已申报命令与路径 →
    剩余标记「疑似二级操作」告警（仅告警不拦截）。
    审计通道不可读时如实记录 unavailable 与启用指引，不破坏主流程。
    """

    def __init__(self, output_dir: str, *,
                 reader: Optional[WindowsAuditReader] = None,
                 lookback_s: int = 60, max_events: int = 500,
                 agent_process_names: Optional[List[str]] = None,
                 whitelist_extra: Optional[List[str]] = None,
                 jsonl_name: str = "crosscheck_audit.jsonl"):
        self._output_dir = output_dir
        self._reader = reader or WindowsAuditReader()
        self._lookback_s = int(lookback_s)
        self._max_events = int(max_events)
        self._agent_names = {n.lower() for n in (agent_process_names or [])}
        self._whitelist_extra = {w.lower() for w in (whitelist_extra or [])}
        self._jsonl_name = jsonl_name
        # session_id -> {"start_ms", "end_ms", "closed"}
        self._sessions: Dict[str, Dict] = {}
        self._unavailable: List[Dict] = []
        self._findings: List[Dict] = []
        self._checked_count = 0
        self._availability: Optional[dict] = None

    # ── 会话生命周期（由 monitor_daemon 经 collector 回调驱动）──────

    def on_session_start(self, session_id: str,
                         payload: Optional[dict] = None) -> None:
        if not session_id:
            return
        ts_ms = to_utc_epoch_ms((payload or {}).get("timestamp_ms")) \
            or int(time.time() * 1000)
        self._sessions[session_id] = {"start_ms": ts_ms, "end_ms": None,
                                      "closed": False}

    def on_session_end(self, session_id: str,
                       payload: Optional[dict] = None) -> None:
        if not session_id:
            return
        sess = self._sessions.get(session_id)
        if sess is None:
            self._unavailable.append(
                {"session_id": session_id, "phase": "end",
                 "reason": "无 start 会话，无法比对"})
            return
        ts_ms = to_utc_epoch_ms((payload or {}).get("timestamp_ms")) \
            or int(time.time() * 1000)
        sess["end_ms"] = ts_ms
        sess["closed"] = True

    # ── 收尾与产出 ────────────────────────────────────────────────

    def _ensure_availability(self) -> dict:
        if self._availability is None:
            try:
                self._availability = self._reader.availability()
            except Exception as e:  # noqa: BLE001
                self._availability = {
                    "available": False, "channels": {},
                    "guidance": [f"审计通道探测失败: {e}"]}
        return self._availability

    def finish(self, reported_commands_by_session: Optional[Dict[str, List[str]]]
               = None, reported_paths_by_session: Optional[Dict[str, List[str]]]
               = None) -> Dict:
        """停止监测时收尾: 补 end 时间 → 查询比对 → 写产物 → summary。"""
        availability = self._ensure_availability()
        channel_errors: List[dict] = []
        for session_id, sess in list(self._sessions.items()):
            if not sess.get("end_ms"):
                sess["end_ms"] = int(time.time() * 1000)  # 未闭合会话按当前时刻
            start_ms = int(sess["start_ms"]) - self._lookback_s * 1000
            end_ms = int(sess["end_ms"])
            events, errors = self._reader.read_events(
                start_ms, end_ms, self._max_events)
            channel_errors.extend(errors)
            reported_cmds = (reported_commands_by_session or {}).get(
                session_id, [])
            reported_paths = (reported_paths_by_session or {}).get(
                session_id, [])
            suspects = self._classify(events, reported_cmds, reported_paths)
            self._checked_count += 1
            if suspects:
                self._findings.append({
                    "session_id": session_id,
                    "kind": "unreported_system_event",
                    "severity": "suspect_secondary_action",
                    "events": suspects,
                    "note": AUDIT_NOTE,
                })
        # 通道级失败如实并入 unavailable（不静默失败）
        for err in channel_errors:
            self._unavailable.append({
                "session_id": "-", "phase": "query",
                "reason": f"通道 {err['channel']} 查询失败: {err['error']}"
                          f"（指引: {err['guidance']}）"})
        summary = {
            "enabled": True,
            "available": bool(availability.get("available")),
            "channels": availability.get("channels") or {},
            "sessions_checked": self._checked_count,
            "findings": self._findings,
            "unavailable": self._unavailable,
            "guidance": availability.get("guidance") or [],
            "note": AUDIT_NOTE,
        }
        self._write_jsonl()
        return summary

    def _classify(self, events: List[dict], reported_cmds: List[str],
                  reported_paths: List[str]) -> List[dict]:
        """事件 → 可疑事件集（排除白名单 / Agent / 已申报）。"""
        suspects: List[dict] = []
        for evt in events:
            process = _process_basename(evt.get("process") or "")
            command = (evt.get("command") or "").strip()
            if process in DEFAULT_SYSTEM_WHITELIST:
                continue
            if process in self._agent_names or process in self._whitelist_extra:
                continue
            if evt.get("event_id") == 4104:
                # 脚本块: 与已申报命令子串匹配即排除；过短片段不比对
                if len(command) < _MIN_SCRIPT_LEN:
                    continue
                if any(cmd and cmd.strip() in command
                       for cmd in reported_cmds):
                    continue
            else:
                if matches_reported({"name": process,
                                     "cmdline": [command]},
                                    reported_cmds):
                    continue
            # 已申报文件路径出现在命令/进程名中 → 排除
            # （两侧统一正斜杠归一后比对，兼容申报正斜杠与审计反斜杠形态）
            norm_text = (command + " " + process).replace("\\", "/").lower()
            if any(p and p.replace("\\", "/").lower() in norm_text
                   for p in reported_paths):
                continue
            suspects.append({
                "event_id": evt.get("event_id"),
                "source": evt.get("source"),
                "time_ms": evt.get("time_ms"),
                "process": evt.get("process") or "",
                "command": command[:200],
                "parent": evt.get("parent") or "",
            })
        return suspects

    def _write_jsonl(self) -> None:
        """追加写比对留痕（幂等追加，不覆盖历史）。"""
        if not self._findings and not self._unavailable:
            return
        os.makedirs(self._output_dir, exist_ok=True)
        path = os.path.join(self._output_dir, self._jsonl_name)
        entries = [{
            "type": "audit_crosscheck",
            "timestamp_ms": int(time.time() * 1000),
            **f,
        } for f in self._findings]
        for u in self._unavailable:
            entries.append({
                "type": "audit_crosscheck_unavailable",
                "timestamp_ms": int(time.time() * 1000),
                **u,
            })
        try:
            with open(path, "a", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, ensure_ascii=False, default=str)
                            + "\n")
        except OSError as e:
            logger.warning(f"审计交叉校验留痕写入失败: {e}")
