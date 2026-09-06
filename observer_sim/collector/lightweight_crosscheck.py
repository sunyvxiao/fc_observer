# -*- coding: utf-8 -*-
"""
collector/lightweight_crosscheck.py — 用户态轻量交叉校验（第 3 层，T3.1 进程快照比对）

定位:
    会话边界（report_session start/end）对进程集做 psutil 快照，
    与会话内申报命令比对，检出「申报外的新增进程」，
    输出「疑似二级操作」告警（仅告警、不拦截）。

设计约束（硬性）:
- 只做用户态 psutil 枚举 + 申报留痕解析，不引入 ETW / 内核驱动级检测；
- 不改动判定管线（规则/评分/研判零改动），产出仅追加式告警与留痕；
- 快照失败 / psutil 缺失时标记「不可用」并如实声明，不破坏监测主流程；
- 比对窗口如实声明（边界时刻采样，窗口内瞬时进程不可见）。

数据流:
    report_session(start) ──► ProcessCrossChecker.on_session_start 快照
    report_session(end)   ──► ProcessCrossChecker.on_session_end  快照 + 比对
    停止监测             ──► finish(): 未闭合会话补 end 快照 → 比对
    比对: end-start 新增进程 ─ 系统白名单 ─ Agent 进程树 ─ 申报命令匹配
          └─ 剩余 → 「疑似二级操作」告警 → crosscheck_process.jsonl
"""

import hashlib
import json
import logging
import os
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# 比对窗口声明（写入产物与报告固定措辞，如实披露采样局限）
WINDOW_NOTE = (
    "比对窗口仅为会话 start/end 边界快照差异；窗口内启动又退出的进程不可见；"
    "白名单外新增进程判定为「疑似二级操作」，仅告警不拦截")

# 会话申报记录里视为「命令执行类」的工具名集合（与 RawEventFactory 的
# Bash/execute_command 类映射同口径；WorkBuddy 申报名以 Bash 为主）
EXEC_TOOL_NAMES = {"bash", "run_in_terminal", "execute_command", "shell"}

# Windows 常驻系统进程白名单（快照过滤防误报；跨平台时仅按名称匹配）
DEFAULT_SYSTEM_WHITELIST = {
    "system", "registry", "memcompression", "csrss.exe", "smss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "fontdrvhost.exe", "dwm.exe", "explorer.exe",
    "sihost.exe", "taskhostw.exe", "ctfmon.exe", "conhost.exe",
    "audiodg.exe", "spoolsv.exe", "wmiprvse.exe", "dllhost.exe",
    "rundll32.exe", "splwow64.exe", "textinputhost.exe",
    "searchindexer.exe", "shellexperiencehost.exe", "runtimebroker.exe",
    "startmenuexperiencehost.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "backgroundtaskhost.exe",
    "mousocoreworker.exe", "smartscreen.exe", "applicationframehost.exe",
    "comppkgsrv.exe", "searchhost.exe", "systemsettings.exe",
    "settingsynchost.exe", "widgets.exe", "widgetservice.exe",
}


def _psutil_enumerate() -> Optional[Dict[int, Dict]]:
    """psutil 进程枚举 → {pid: {name, exe, cmdline, create_time, ppid}}。

    单个进程枚举失败（NoSuchProcess/AccessDenied/Zombie）安全跳过；
    整体异常（psutil 缺失等）由上层捕获转为「不可用」。
    """
    import psutil
    snap: Dict[int, Dict] = {}
    for p in psutil.process_iter(
            ["name", "exe", "cmdline", "create_time", "ppid"]):
        try:
            info = p.info
            snap[p.pid] = {
                "name": info.get("name") or "",
                "exe": info.get("exe") or "",
                "cmdline": list(info.get("cmdline") or []),
                "create_time": info.get("create_time"),
                "ppid": info.get("ppid"),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess):
            continue
    return snap


class ProcessSnapshotter:
    """进程集快照器（enum_fn 可注入，供测试以假快照替代真实枚举）。"""

    def __init__(self, enum_fn: Optional[Callable[[], Dict[int, Dict]]] = None):
        self._enum_fn = enum_fn or _psutil_enumerate

    def snapshot(self) -> Optional[Dict[int, Dict]]:
        """进程集快照；失败返回 None（不可用，不参与比对）。"""
        try:
            return self._enum_fn()
        except Exception as e:  # noqa: BLE001 防御: 枚举失败不破坏主流程
            logger.warning(f"进程快照失败: {e}")
            return None


def diff_new_processes(start: Dict[int, Dict],
                       end: Dict[int, Dict]) -> Dict[int, Dict]:
    """end 相对 start 的新增进程（含 PID 复用：同 pid 不同 create_time）。"""
    new: Dict[int, Dict] = {}
    for pid, info in end.items():
        before = start.get(pid)
        if before is None:
            new[pid] = info
        elif before.get("create_time") != info.get("create_time"):
            new[pid] = info
    return new


def extract_command(command) -> str:
    """从申报 tool_args 提取命令串（dict/str/list 多形态兼容）。"""
    if isinstance(command, dict):
        for key in ("command", "cmd", "script", "args"):
            val = command.get(key)
            if val:
                return extract_command(val)
        return ""
    if isinstance(command, (list, tuple)):
        return " ".join(str(x) for x in command)
    return str(command or "")


def matches_reported(info: Dict, reported_commands: List[str]) -> bool:
    """进程是否与任一已申报命令匹配。

    匹配口径（宽松）:
    - 进程名 == 命令首 token 的 basename（如申报 `curl` → 进程 curl.exe）；
    - 或进程整条 cmdline 包含命令首 token / 整条命令串。
    仅用于「排除已申报进程」，不产生新增判定。
    """
    name = (info.get("name") or "").lower()
    cmdline = " ".join(info.get("cmdline") or []).lower()
    for cmd in reported_commands:
        text = (cmd or "").strip()
        if not text:
            continue
        first = text.split()[0]
        base = os.path.basename(first).lower()
        if base and (name == base or base in cmdline):
            return True
        if text.lower() in cmdline:
            return True
    return False


class ProcessCrossChecker:
    """会话级进程快照比对（第 3 层 T3.1）。

    会话 start/end 时调用 on_session_start / on_session_end；
    停止监测时调用 finish() 收尾未闭合会话并产出:
    - crosscheck_process.jsonl（逐条比对留痕）
    - summary dict（sessions_checked / findings / unavailable / note）

    findings 语义: 「疑似二级操作」告警 —— 白名单外且未匹配申报命令
    的新增进程。仅告警，不改动判定管线、不产生拦截。
    """

    def __init__(self, output_dir: str, *,
                 snapshotter: Optional[ProcessSnapshotter] = None,
                 whitelist_extra: Optional[List[str]] = None,
                 agent_process_names: Optional[List[str]] = None,
                 agent_process_dirs: Optional[List[str]] = None,
                 jsonl_name: str = "crosscheck_process.jsonl"):
        self._output_dir = output_dir
        self._snapshotter = snapshotter or ProcessSnapshotter()
        self._whitelist = set(DEFAULT_SYSTEM_WHITELIST)
        for w in (whitelist_extra or []):
            if w:
                self._whitelist.add(str(w).lower())
        self._agent_names = {str(n).lower() for n in (agent_process_names or [])
                             if n}
        # Agent 安装目录前缀（小写 + 去尾分隔符，供 exe 路径前缀匹配）
        self._agent_dirs = [
            str(d).lower().rstrip("/\\")
            for d in (agent_process_dirs or []) if d
        ]
        self._jsonl_name = jsonl_name
        self._self_name = self._own_process_name().lower()

        # session_id -> {"start": snap|None, "end": snap|None, "closed": bool}
        self._sessions: Dict[str, Dict] = {}
        # 快照不可用记录: [{session_id, phase, reason}]
        self._unavailable: List[Dict] = []
        # 会话级申报命令: {session_id: [command_str]}
        self._reported_commands: Dict[str, List[str]] = {}
        # 比对结论（finish 时汇总）
        self._findings: List[Dict] = []
        # 成功完成比对的会话数（无论是否有疑似进程）
        self._checked_count = 0

    # ── 会话生命周期（由 monitor_daemon 经 collector 回调驱动）──────

    @staticmethod
    def _own_process_name() -> str:
        try:
            import psutil
            return str(psutil.Process(os.getpid()).name())
        except Exception:  # noqa: BLE001
            return ""

    def on_session_start(self, session_id: str) -> None:
        if not session_id:
            return
        snap = self._snapshotter.snapshot()
        if snap is None:
            self._unavailable.append(
                {"session_id": session_id, "phase": "start", "reason": "快照不可用"})
            return
        self._sessions[session_id] = {"start": snap, "end": None,
                                      "closed": False}

    def on_session_end(self, session_id: str) -> None:
        if not session_id:
            return
        snap = self._snapshotter.snapshot()
        sess = self._sessions.get(session_id)
        if sess is None:
            # 无 start 快照（此前不可用或未配对）: 如实记录，不做比对
            if snap is None:
                self._unavailable.append(
                    {"session_id": session_id, "phase": "end",
                     "reason": "无 start 快照且 end 快照不可用"})
            else:
                self._unavailable.append(
                    {"session_id": session_id, "phase": "end",
                     "reason": "无 start 快照，无法比对"})
            return
        sess["end"] = snap
        sess["closed"] = True

    def add_reported_command(self, session_id: str, command: str) -> None:
        """登记会话内已申报命令（比对时用于排除已申报进程）。"""
        text = (command or "").strip()
        if not text or not session_id:
            return
        self._reported_commands.setdefault(session_id, []).append(text)

    # ── 收尾与产出 ──────────────────────────────────────────────────

    def finish(self, reported_by_session: Optional[Dict[str, List[str]]] = None
               ) -> Dict:
        """停止监测时收尾: 补 end 快照 → 比对 → 写产物 → 返回 summary。

        reported_by_session: 可选，外部解析申报留痕得到的
            {session_id: [command_str]}；与 add_reported_command 合并。
        """
        if reported_by_session:
            for sid, cmds in reported_by_session.items():
                for c in cmds:
                    self.add_reported_command(sid, c)

        for session_id, sess in list(self._sessions.items()):
            if not sess.get("closed"):
                snap = self._snapshotter.snapshot()
                if snap is None:
                    self._unavailable.append(
                        {"session_id": session_id, "phase": "finish",
                         "reason": "未闭合会话补快照失败"})
                    self._sessions.pop(session_id, None)
                    continue
                sess["end"] = snap
            self._compare_session(session_id)

        available = self._checked_count > 0
        summary = {
            "enabled": True,
            "available": available,
            "sessions_checked": self._checked_count,
            "findings": self._findings,
            "unavailable": self._unavailable,
            "note": WINDOW_NOTE,
        }
        self._write_jsonl()
        return summary

    def _compare_session(self, session_id: str) -> None:
        """单个会话比对: 新增进程 − 白名单 − Agent 进程 − 申报命令。"""
        sess = self._sessions.pop(session_id, None)
        if sess is None:
            return
        start, end = sess.get("start"), sess.get("end")
        if start is None or end is None:
            self._unavailable.append(
                {"session_id": session_id, "phase": "compare",
                 "reason": "快照缺失，跳过比对"})
            return

        reported = self._reported_commands.get(session_id, [])
        suspects = []
        for pid, info in diff_new_processes(start, end).items():
            name = str(info.get("name") or "").lower()
            exe = str(info.get("exe") or "").lower()
            if name in self._whitelist:
                continue
            if name and name == self._self_name:
                continue  # 观察者自身进程
            if name in self._agent_names:
                continue  # Agent（WorkBuddy）自身进程树
            if any(exe.startswith(d) for d in self._agent_dirs):
                continue  # Agent 安装目录下的进程
            if matches_reported(info, reported):
                continue  # 会话内已申报命令对应的进程
            suspects.append({
                "pid": pid,
                "name": name,
                "exe": exe,
                "cmdline": info.get("cmdline") or [],
                "ppid": info.get("ppid"),
            })

        self._checked_count += 1
        if suspects:
            self._findings.append({
                "session_id": session_id,
                "kind": "unreported_process",
                "severity": "suspect_secondary_action",
                "suspects": suspects,
                "note": WINDOW_NOTE,
            })

    def _write_jsonl(self) -> None:
        """追加写比对留痕（幂等追加，不覆盖历史）。"""
        if not self._findings and not self._unavailable:
            return
        os.makedirs(self._output_dir, exist_ok=True)
        path = os.path.join(self._output_dir, self._jsonl_name)
        entries = [{
            "type": "process_crosscheck",
            "timestamp_ms": int(time.time() * 1000),
            **f,
        } for f in self._findings]
        for u in self._unavailable:
            entries.append({
                "type": "process_crosscheck_unavailable",
                "timestamp_ms": int(time.time() * 1000),
                **u,
            })
        try:
            with open(path, "a", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, ensure_ascii=False, default=str)
                            + "\n")
        except OSError as e:
            logger.warning(f"交叉校验留痕写入失败: {e}")


def parse_reported_commands(jsonl_path: Optional[str]
                            ) -> Dict[str, List[str]]:
    """解析申报留痕 JSONL，提取会话级命令集（命令执行类申报）。

    只读解析，不产生判定；文件缺失/畸形行安全跳过。
    """
    result: Dict[str, List[str]] = {}
    if not jsonl_path or not os.path.isfile(jsonl_path):
        return result
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("type") != "report_tool_call":
                    continue
                payload = rec.get("payload") or {}
                tool_name = str(payload.get("tool_name") or "").lower()
                if tool_name not in EXEC_TOOL_NAMES:
                    continue
                command = extract_command(payload.get("tool_args"))
                if not command:
                    continue
                session_id = str(payload.get("session_id") or "")
                if session_id:
                    result.setdefault(session_id, []).append(command)
    except OSError:
        logger.warning(f"申报留痕解析失败: {jsonl_path}")
    return result


# ══════════════════════════════════════════════════════════════
# T3.2 文件快照比对（受保护目录，同模块扩展）
# ══════════════════════════════════════════════════════════════

# 比对窗口声明（写入产物与报告固定措辞）
FILE_WINDOW_NOTE = (
    "比对窗口仅为会话 start/end 边界快照差异；窗口内创建又删除的文件不可见；"
    "受保护目录外变更不比对；变更文件判定为「疑似二级操作」，仅告警不拦截")

# 会话申报记录里视为「文件操作类」的工具名（用于提取申报路径做排除）
FILE_TOOL_NAMES = {
    "read_file", "write_file", "write", "edit_file", "replace_in_file",
    "delete_file", "create_file", "list_files", "move_file", "copy_file",
}

DEFAULT_MAX_FILES = 2000
DEFAULT_HASH_MAX_SIZE = 10 * 1024 * 1024  # 10MB，超出只记 size/mtime


def _hash_file(path: str) -> str:
    """文件 SHA256（流式分块，避免大文件整读内存）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class FileSnapshotter:
    """受保护目录文件快照器（size + mtime_ns + sha256，增量哈希）。

    - 仅对声明目录递归快照，目录缺失安全跳过；
    - max_files 上限：超出截断并如实标记 truncated（快照返回 {"__truncated__": True}）；
    - hash_max_size：单文件超出仅记 size/mtime（sha256 置空）；
    - 增量哈希：传入 previous 快照时，size+mtime 未变的文件复用旧哈希，
      避免会话 end 时刻重复全量哈希（性能约束：仅对变更/新增文件计算）。
    """

    def __init__(self, dirs: List[str], *,
                 max_files: int = DEFAULT_MAX_FILES,
                 hash_max_size: int = DEFAULT_HASH_MAX_SIZE):
        self._dirs = [os.path.normpath(str(d)) for d in dirs if d]
        self._max_files = max_files
        self._hash_max_size = hash_max_size

    def snapshot(self, previous: Optional[Dict[str, Dict]] = None
                 ) -> Optional[Dict[str, Dict]]:
        """目录快照；整体异常返回 None（不可用，不破坏主流程）。"""
        try:
            return self._scan(previous)
        except Exception as e:  # noqa: BLE001 防御: 快照失败不破坏主流程
            logger.warning(f"文件快照失败: {e}")
            return None

    def _scan(self, previous: Optional[Dict[str, Dict]]) -> Dict[str, Dict]:
        result: Dict[str, Dict] = {}
        truncated = False
        for idx, d in enumerate(self._dirs):
            if not os.path.isdir(d):
                continue
            base = os.path.normpath(d)
            for root, dirs, files in os.walk(base):
                dirs.sort()
                for fn in sorted(files):
                    if len(result) >= self._max_files:
                        truncated = True
                        break
                    full = os.path.join(root, fn)
                    try:
                        st = os.stat(full)
                    except OSError:
                        continue
                    size, mtime = st.st_size, st.st_mtime_ns
                    rel = os.path.relpath(full, base).replace(os.sep, "/")
                    key = f"@{idx}/{rel}"  # 目录索引前缀，避免跨目录重名冲突
                    prev = (previous or {}).get(key)
                    if prev and prev.get("size") == size \
                            and prev.get("mtime_ns") == mtime \
                            and prev.get("sha256"):
                        sha = prev["sha256"]  # 增量哈希：未变更复用
                    elif size <= self._hash_max_size:
                        try:
                            sha = _hash_file(full)
                        except OSError:
                            sha = ""
                    else:
                        sha = ""
                    result[key] = {"size": size, "mtime_ns": mtime,
                                   "sha256": sha}
                if truncated:
                    break
            if truncated:
                break
        if truncated:
            result["__truncated__"] = True
        return result


def diff_files(start: Dict[str, Dict],
               end: Dict[str, Dict]) -> Dict[str, Dict[str, Dict]]:
    """end 相对 start 的文件变更: added / removed / modified。"""
    added = {p: end[p] for p in end if p not in start and p != "__truncated__"}
    removed = {p: start[p] for p in start
               if p not in end and p != "__truncated__"}
    modified: Dict[str, Dict] = {}
    for p, info in end.items():
        if p == "__truncated__":
            continue
        before = start.get(p)
        if before is None:
            continue
        if (before.get("size") != info.get("size")
                or before.get("mtime_ns") != info.get("mtime_ns")
                or before.get("sha256") != info.get("sha256")):
            modified[p] = info
    return {"added": added, "removed": removed, "modified": modified}


def matches_reported_path(rel_path: str, reported_paths: List[str]) -> bool:
    """文件路径是否与任一已申报文件路径匹配（宽松，仅用于排除）。"""
    norm = str(rel_path or "").replace("\\", "/").lower()
    base = os.path.basename(norm)
    for rp in reported_paths:
        r = str(rp or "").replace("\\", "/").lower().strip()
        if not r:
            continue
        if r in norm or norm in r or (base and base == os.path.basename(r)):
            return True
    return False


class FileCrossChecker:
    """会话级受保护目录文件快照比对（第 3 层 T3.2）。

    与 ProcessCrossChecker 同构：会话 start/end 边界快照 → diff_files →
    排除已申报路径 → 剩余变更标记「疑似二级操作」告警（仅告警不拦截）。
    快照失败/未配对如实记录 unavailable，不破坏主流程。
    """

    def __init__(self, output_dir: str, *,
                 snapshotter: Optional[FileSnapshotter] = None,
                 jsonl_name: str = "crosscheck_file.jsonl"):
        self._output_dir = output_dir
        self._snapshotter = snapshotter
        self._jsonl_name = jsonl_name
        # session_id -> {"start": snap|None, "end": snap|None, "closed": bool}
        self._sessions: Dict[str, Dict] = {}
        self._unavailable: List[Dict] = []
        self._reported_paths: Dict[str, List[str]] = {}
        self._findings: List[Dict] = []
        self._checked_count = 0

    # ── 会话生命周期（由 monitor_daemon 经 collector 回调驱动）──────

    def on_session_start(self, session_id: str) -> None:
        if not session_id or self._snapshotter is None:
            return
        snap = self._snapshotter.snapshot()
        if snap is None:
            self._unavailable.append(
                {"session_id": session_id, "phase": "start",
                 "reason": "文件快照不可用"})
            return
        self._sessions[session_id] = {"start": snap, "end": None,
                                      "closed": False}

    def on_session_end(self, session_id: str) -> None:
        if not session_id:
            return
        sess = self._sessions.get(session_id)
        if sess is None:
            self._unavailable.append(
                {"session_id": session_id, "phase": "end",
                 "reason": "无 start 快照，无法比对"})
            return
        snap = self._snapshotter.snapshot(previous=sess["start"]) \
            if self._snapshotter else None
        if snap is None:
            self._unavailable.append(
                {"session_id": session_id, "phase": "end",
                 "reason": "end 文件快照不可用"})
            return
        sess["end"] = snap
        sess["closed"] = True

    def add_reported_path(self, session_id: str, path: str) -> None:
        """登记会话内已申报文件路径（比对时用于排除申报内变更）。"""
        text = (path or "").strip()
        if not text or not session_id:
            return
        self._reported_paths.setdefault(session_id, []).append(text)

    # ── 收尾与产出 ────────────────────────────────────────────────

    def finish(self, reported_paths_by_session: Optional[Dict[str, List[str]]]
               = None) -> Dict:
        """停止监测时收尾: 补 end 快照 → 比对 → 写产物 → 返回 summary。"""
        if reported_paths_by_session:
            for sid, paths in reported_paths_by_session.items():
                for p in paths:
                    self.add_reported_path(sid, p)

        for session_id, sess in list(self._sessions.items()):
            if not sess.get("closed"):
                snap = self._snapshotter.snapshot(previous=sess["start"]) \
                    if self._snapshotter else None
                if snap is None:
                    self._unavailable.append(
                        {"session_id": session_id, "phase": "finish",
                         "reason": "未闭合会话补文件快照失败"})
                    self._sessions.pop(session_id, None)
                    continue
                sess["end"] = snap
            self._compare_session(session_id)

        available = self._checked_count > 0
        summary = {
            "enabled": True,
            "available": available,
            "sessions_checked": self._checked_count,
            "findings": self._findings,
            "unavailable": self._unavailable,
            "note": FILE_WINDOW_NOTE,
        }
        self._write_jsonl()
        return summary

    def _compare_session(self, session_id: str) -> None:
        sess = self._sessions.pop(session_id, None)
        if sess is None:
            return
        start, end = sess.get("start"), sess.get("end")
        if start is None or end is None:
            self._unavailable.append(
                {"session_id": session_id, "phase": "compare",
                 "reason": "文件快照缺失，跳过比对"})
            return

        reported = self._reported_paths.get(session_id, [])
        changes = diff_files(start, end)
        kept = {
            kind: {p: info for p, info in items.items()
                   if not matches_reported_path(p, reported)}
            for kind, items in changes.items()
        }
        self._checked_count += 1
        if any(kept.values()):
            self._findings.append({
                "session_id": session_id,
                "kind": "unreported_file_change",
                "severity": "suspect_secondary_action",
                "changes": kept,
                "note": FILE_WINDOW_NOTE,
            })

    def _write_jsonl(self) -> None:
        """追加写比对留痕（幂等追加，不覆盖历史）。"""
        if not self._findings and not self._unavailable:
            return
        os.makedirs(self._output_dir, exist_ok=True)
        path = os.path.join(self._output_dir, self._jsonl_name)
        entries = [{
            "type": "file_crosscheck",
            "timestamp_ms": int(time.time() * 1000),
            **f,
        } for f in self._findings]
        for u in self._unavailable:
            entries.append({
                "type": "file_crosscheck_unavailable",
                "timestamp_ms": int(time.time() * 1000),
                **u,
            })
        try:
            with open(path, "a", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, ensure_ascii=False, default=str)
                            + "\n")
        except OSError as e:
            logger.warning(f"文件交叉校验留痕写入失败: {e}")


def parse_reported_paths(jsonl_path: Optional[str]
                         ) -> Dict[str, List[str]]:
    """解析申报留痕 JSONL，提取会话级文件路径集（文件操作类申报）。

    只读解析，不产生判定；文件缺失/畸形行安全跳过。
    """
    result: Dict[str, List[str]] = {}
    if not jsonl_path or not os.path.isfile(jsonl_path):
        return result
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("type") != "report_tool_call":
                    continue
                payload = rec.get("payload") or {}
                tool_name = str(payload.get("tool_name") or "").lower()
                if tool_name not in FILE_TOOL_NAMES:
                    continue
                args = payload.get("tool_args") or {}
                paths = []
                if isinstance(args, dict):
                    for key in ("path", "file_path", "file", "old_path",
                                "new_path", "src", "dst"):
                        val = args.get(key)
                        if val and isinstance(val, str):
                            paths.append(val)
                session_id = str(payload.get("session_id") or "")
                if session_id and paths:
                    result.setdefault(session_id, []).extend(paths)
    except OSError:
        logger.warning(f"申报留痕解析失败: {jsonl_path}")
    return result
