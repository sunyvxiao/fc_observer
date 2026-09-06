#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hook_gate.py — 方寸观察者 拦截路径 hook 判定入口（PreToolUse）

所属计划: 《监测与拦截解耦双路径_开发落地计划.md》P0 拦截路径底座
宿主挂载: ~/.workbuddy/settings.json hooks.PreToolUse（由 connect_workbuddy.py
          hook-deploy 部署，command 路径必须正斜杠，见计划 1.3-6 实测坑）

架构约束（计划 v1.1 已决策口径，不得违反）:
- D-2 规则唯一基准: 本脚本不内嵌任何业务规则（不含目录/扩展名/命令正则
  字面量）。资源级红线唯一数据源为 config.yaml 的 hook.protected_paths /
  hook.protected_extensions，改规则只改配置文件不改本脚本（TC-13 验收）。
- D-1 判定协议: config hook.protocol 开关——
    "json"  = stdout JSON 三态 {hookSpecificOutput: {permissionDecision:
              allow|deny|ask, permissionDecisionReason}} + exit 0;
    "exit2" = deny 时 stderr 输出 reason + exit 2，allow 时 exit 0。
    ask 态默认关闭（ask_enabled=false）。实测不支持 JSON 三态时把配置
    改为 "exit2" 即可回退（自动回退触发条件见计划 TC-12）。
- D-3 分级失效语义:
    ① 脚本正常运行时按资源级红线判定（受保护资源 deny / 其余 allow）；
    ② 判定前异常（payload 解析失败、目标提取异常、判定无法确认）→
       按 fail-closed 阻止（deny + gate_error）；
    ③ 判定已出的后续环节异常（留痕/通知失败）→ 决策不变，仅三处告警
       （stderr 告警行 + 决策留痕 gate_error 标记 + 通知通道 gate_error
       高优先级事件）——即其余操作 fail-open + 告警；
    ④ 脚本进程崩溃 → 宿主 fail-closed 全局阻止（实测基线，脚本不处理）。
- 留痕（P0-5）: 每次裁决追加 hook.decisions_file（JSONL，三轨证据第 2 轨）。
- 通知: HTTP POST 到 hook.notify_url（timeout 默认 2s），失败不阻塞判定。

用法:
    hook_gate.py                 # 宿主 hook 模式: stdin JSON 入 → 决策出
    hook_gate.py --check-config  # 预检: 资源级红线配置有效性（部署前置校验）
    hook_gate.py --self-test     # 自检: 内置三种 payload 输出判定结果（调试）

环境变量:
    OBSERVER_CONFIG  覆盖 config.yaml 路径（缺省从脚本位置向上定位）
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime

try:
    import yaml  # noqa: WPS433
except ImportError:  # pragma: no cover
    yaml = None


# ── 配置定位与加载（D-2: 唯一基准 = config.yaml hook 段）──────────

def locate_config() -> str:
    """定位 config.yaml: OBSERVER_CONFIG 环境变量 > 脚本向上查找。"""
    env = os.environ.get("OBSERVER_CONFIG")
    if env and os.path.isfile(env):
        return env
    cur = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        candidate = os.path.join(cur, "config.yaml")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return ""


def load_config(path: str = "", _cache: dict = None) -> dict:
    """加载 config.yaml 的 hook 段并解析相对路径（mtime 缓存）。

    返回 dict: protocol / ask_enabled / notify_url / notify_timeout_s /
    decisions_file(绝对) / protected_paths(绝对列表) /
    protected_extensions(小写列表) / _config_path / _project_dir。
    protected_paths 为空 = 未配置资源级红线，一切放行（如实语义）。
    """
    cache = _cache if _cache is not None else _CONFIG_CACHE
    path = path or locate_config()
    if not path or not os.path.isfile(path):
        raise RuntimeError(f"未找到 config.yaml（path={path!r}，"
                           "可用 OBSERVER_CONFIG 指定）")
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = -1
    if cache.get("path") == path and cache.get("mtime") == mtime:
        return cache["cfg"]
    if yaml is None:
        raise RuntimeError("PyYAML 未安装，请执行: pip install pyyaml")
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    hook = data.get("hook") or {}
    project_dir = os.path.dirname(os.path.abspath(path))
    cfg = {
        "protocol": str(hook.get("protocol", "json")),
        "ask_enabled": bool(hook.get("ask_enabled", False)),
        "notify_url": str(hook.get("notify_url", "") or ""),
        "notify_timeout_s": float(hook.get("notify_timeout_s", 2)),
        "decisions_file": hook.get("decisions_file",
                                   "output/hook_decisions.jsonl"),
        "protected_paths": list(hook.get("protected_paths") or []),
        "protected_extensions": [str(e).lower()
                                 for e in (hook.get("protected_extensions")
                                           or [])],
        "_config_path": path,
        "_project_dir": project_dir,
    }
    cfg["protected_paths"] = [
        p if os.path.isabs(p) else os.path.join(project_dir, str(p))
        for p in cfg["protected_paths"] if p]
    if not os.path.isabs(cfg["decisions_file"]):
        cfg["decisions_file"] = os.path.join(project_dir,
                                             cfg["decisions_file"])
    cache["path"], cache["mtime"], cache["cfg"] = path, mtime, cfg
    return cfg


_CONFIG_CACHE: dict = {}


# ── 判定核心（不内嵌业务规则，只实现「配置 → 判定」算法）─────────

def _normcase(s: str) -> str:
    """统一大小写与斜杠（Windows 大小写不敏感 + /\\ 混用容错）。"""
    return os.path.normcase(str(s)).replace("\\", "/")


def extract_target(tool_name: str, tool_input):
    """从 hook payload 提取操作目标（资源路径/glob/命令）。

    返回 None = 该工具无资源目标（放行）；其余返回值交由 is_protected
    判定。字段名与 WorkBuddy/Claude Code 同构 payload 对齐。
    """
    if not isinstance(tool_input, dict):
        return None
    if tool_name == "Read":
        return tool_input.get("file_path")
    if tool_name in ("Write", "Edit"):
        return tool_input.get("file_path")
    if tool_name == "Glob":
        return tool_input.get("pattern")
    if tool_name == "Grep":
        return tool_input.get("path")
    if tool_name in ("Bash", "PowerShell", "Shell", "Command"):
        return tool_input.get("command")
    return None


def is_protected(target, cfg: dict, cwd: str = "") -> bool:
    """资源级红线判定: 目标是否命中受保护目录(+扩展名约束)。

    命中规则（目录/扩展名均来自 config hook 段，算法本身不含业务值）:
    - 目标为受保护目录本身或其下路径，且（配置了扩展名时）扩展名命中;
    - 无法解析为绝对路径的字符串（glob/命令），目录前缀包含命中后，
      扩展名非空时要求字符串中同时出现受保护扩展名;
    - protected_extensions 为空 = 目录命中即保护（保守语义）。
    """
    dirs = cfg.get("protected_paths") or []
    exts = cfg.get("protected_extensions") or []
    if not target or not dirs or not isinstance(target, str):
        return False
    target_n = _normcase(target)
    for d in dirs:
        d_n = _normcase(d).rstrip("/")
        if not d_n:
            continue
        # 1) 绝对/可解析路径: 目录精确或前缀命中
        if target_n == d_n or target_n.startswith(d_n + "/"):
            if not exts:
                return True
            if os.path.splitext(target)[1].lower() in exts:
                return True
        # 2) 相对路径: 以 hook cwd 解析后重试
        if cwd and not os.path.isabs(target):
            try:
                joined = _normcase(os.path.normpath(
                    os.path.join(cwd, target)))
                if joined == d_n or joined.startswith(d_n + "/"):
                    if not exts or os.path.splitext(target)[1].lower() in exts:
                        return True
            except (TypeError, ValueError, OSError):
                pass
        # 3) 字符串包含（glob pattern / 命令 / 无法解析路径）
        # 要求 d_n 作为完整路径段出现（d_n + "/"），避免误伤兄弟目录
        # （如受保护目录 dir 不应命中其兄弟目录 dir2 下路径）
        if (d_n + "/") in target_n:
            if not exts:
                return True
            alt = r"\.(?:" + "|".join(
                re.escape(e.lstrip(".")) for e in exts if e) + r")"
            if re.search(alt + r"(?:\b|[\s\"'<>:;,()\[\]])", target_n):
                return True
    return False


def decide(payload: dict, cfg: dict) -> dict:
    """执行裁决，返回决策留痕条目（不输出、不退出）。

    D-3 分级失效语义:
    - 目标提取异常 / 判定异常（无法确认是否受保护）→ deny（fail-closed）;
    - 无资源目标 → allow。
    """
    now = datetime.now().isoformat(timespec="milliseconds")
    tool_name = str(payload.get("tool_name", "") or "")
    tool_input = payload.get("tool_input", {})
    entry = {
        "timestamp": now,
        "event": "pre_tool_use",
        "session_id": str(payload.get("session_id", "") or ""),
        "tool_name": tool_name,
        "cwd": str(payload.get("cwd", "") or ""),
        "tool_input": tool_input,
        "gate_error": False,
    }
    try:
        target = extract_target(tool_name, tool_input)
    except Exception as e:  # noqa: BLE001
        entry.update(decision="deny", target=None, gate_error=True,
                     reason=(f"gate_error: 目标提取异常（{e}），"
                             "按 fail-closed 阻止"))
        return entry
    if target is None:
        entry.update(decision="allow", target=None, reason="")
        return entry
    try:
        protected = is_protected(target, cfg, entry["cwd"])
    except Exception as e:  # noqa: BLE001
        entry.update(decision="deny", target=str(target)[:500],
                     gate_error=True,
                     reason=(f"gate_error: 判定无法确认（{e}），"
                             "按 fail-closed 阻止"))
        return entry
    entry["target"] = str(target)[:500]
    if protected:
        decision = "ask" if cfg.get("ask_enabled") else "deny"
        entry.update(
            decision=decision,
            reason=(f"已拦截访问受保护资源: {target}"
                    f"（config.yaml hook 资源级红线，"
                    f"规则唯一基准 {cfg.get('_config_path')}）"))
    else:
        entry.update(decision="allow", reason="")
    return entry


# ── 留痕（P0-5: 三轨证据第 2 轨）与通知 ──────────────────────────

def locked_append_jsonl(path: str, entry: dict) -> str:
    """二进制模式 + Windows 文件锁的原子 JSONL 追加（并发 hook 进程安全）。

    实测坑（2026-09-05 P1-1 宿主实测）: 宿主并发触发多个 hook 进程时，
    text 模式 append 曾致两行交错损坏（半行丢失）。二进制单次 write +
    msvcrt LK_LOCK 保证每行原子落盘。返回留痕文件路径。

    实测坑（2026-09-05 P1-2 并发回归）: 锁「锁定时各自 EOF 位置」
    的 1 字节区域，两进程锁区域不重叠 → 互斥失效（复现 159/160 丢行）。
    修复: 固定锁文件首字节区域 [0,1)——所有进程锁同一区域，
    实现全局互斥（append 写入 EOF 之后，不受锁定区域影响）。
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # errors="replace": stdin 解码残留 surrogate 时不因 encode 崩溃
    #（留痕失败不中断 hook，D-3 语义）
    data = json.dumps(entry, ensure_ascii=False).encode("utf-8", errors="replace") + b"\n"
    with open(path, "a+b") as f:
        if os.name == "nt":
            import msvcrt  # Windows 专用
            # 锁定固定首字节区域 [0,1)：同一文件的并发进程互斥排队。
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            try:
                f.seek(0, os.SEEK_END)
                f.write(data)
                f.flush()
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            f.seek(0, os.SEEK_END)
            f.write(data)
            f.flush()
    return path


def append_decision(cfg: dict, entry: dict) -> str:
    """追加决策留痕，返回留痕文件路径（异常抛出，由调用方按 D-3 告警）。"""
    return locked_append_jsonl(cfg["decisions_file"], entry)


def _iso_to_ms(ts: str):
    """ISO 时间戳 → 毫秒 epoch（无法解析时返回 None，由接收端补接收时间）。"""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", ""))
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return None


def _notify_payload(entry: dict) -> dict:
    """P1-4: 通知 payload 对齐 daemon /api/hook-report 的 report_tool_call 摄入格式。

    agent_id 固定为 workbuddy（WorkBuddy 宿主 hook 的申报标识，与 MCP
    申报 agent_id 同桶）；session_id 沿用宿主注入的会话 UUID（第 2 轨
    与第 1/3 轨统一关联键，方案 A）。tool_input 截断 2K 摘要防超限。
    """
    ti = entry.get("tool_input") or {}
    try:
        ti_summary = json.dumps(ti, ensure_ascii=False, default=str)[:2000]
    except (TypeError, ValueError):
        ti_summary = str(ti)[:2000]
    # 命令类工具的 target 是命令文本：放 command 键（daemon
    # from_tool_call exec 分支读 command/cmd 键拼 executable+arguments；
    # 若放 file_path 会 fallback 到 tool_name，命令文本丢失、规则无法命中
    # ——批次 C 实测发现的真实缺陷）。文件类工具保持 file_path 键。
    target_key = ("command"
                  if entry.get("tool_name", "") in
                  ("Bash", "PowerShell", "Shell", "Command")
                  else "file_path")
    return {
        "agent_id": "workbuddy",
        "event": "pre_tool_use",
        "tool_name": entry.get("tool_name", ""),
        "tool_args": {
            target_key: entry.get("target"),
            "decision": entry.get("decision", ""),
            "reason": str(entry.get("reason", ""))[:500],
            "gate_error": bool(entry.get("gate_error")),
            "hook_phase": "pre",
            "tool_input_summary": ti_summary,
        },
        "session_id": entry.get("session_id", ""),
        "timestamp_ms": _iso_to_ms(entry.get("timestamp", "")),
        "action_type": "pre",
        "result": ("gate_error" if entry.get("gate_error")
                   else entry.get("decision", ""))[:200],
    }


def notify(cfg: dict, payload: dict, err=None) -> bool:
    """HTTP POST 通知（timeout 2s 缺省，失败不阻塞判定，err 流记录）。"""
    url = cfg.get("notify_url", "")
    if not url:
        return False
    if err is None:
        err = sys.stderr
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST")
        with urllib.request.urlopen(req,
                                    timeout=cfg.get("notify_timeout_s", 2)):
            pass
        return True
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"[hook_gate] notify failed (non-blocking): {e}",
              file=err)
        return False


# ── 决策输出（D-1 双协议）────────────────────────────────────────

def format_decision(decision: str, reason: str, cfg: dict):
    """按协议开关生成输出，返回 (exit_code, stdout_text, stderr_text)。"""
    if cfg.get("protocol") == "exit2":
        if decision in ("deny",):
            return 2, "", reason
        return 0, "", ""
    out = json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        },
    }, ensure_ascii=False)
    return 0, out, ""


# ── 主流程（宿主 hook 模式）──────────────────────────────────────

def run(stdin_text: str, cfg: dict, out=sys.stdout, err=sys.stderr):
    """完整 hook 执行: 解析 → 裁决 → 留痕 → 通知 → 输出。

    返回 (exit_code, stdout_text, stderr_text)；不直接 sys.exit，
    便于测试与 --self-test 复用。D-3 判定后异常仅告警不改决策。
    """
    stderr_lines = []
    try:
        payload = json.loads(stdin_text or "{}")
        if not isinstance(payload, dict):
            raise ValueError("payload 不是 JSON 对象")
    except ValueError as e:
        entry = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "event": "pre_tool_use",
            "session_id": "",
            "tool_name": "",
            "cwd": "",
            "tool_input": None,
            "decision": "deny",
            "target": None,
            "gate_error": True,
            "reason": (f"gate_error: hook payload 解析失败（{e}），"
                       "按 fail-closed 阻止"),
        }
        stderr_lines.append(entry["reason"])
    else:
        entry = decide(payload, cfg)

    # 判定已出 → 留痕/通知异常仅告警（D-3 fail-open + 告警，决策不变）
    alerts = []
    try:
        append_decision(cfg, entry)
    except OSError as e:
        alerts.append(f"决策留痕失败: {e}")
    notify_payload = _notify_payload(entry)
    if entry.get("gate_error") or alerts:
        notify_payload["action"] = "gate_error"
        notify_payload["alerts"] = alerts
    notify(cfg, notify_payload, err=err)
    for a in alerts:
        stderr_lines.append(f"[hook_gate] gate_error: {a}")

    code, so, se = format_decision(entry["decision"], entry["reason"], cfg)
    if se:
        stderr_lines.append(se)
    stderr_text = "\n".join(stderr_lines)
    if stderr_text:
        err.write(stderr_text + "\n")
        err.flush()
    if so:
        out.write(so + "\n")
        out.flush()
    return code, so, stderr_text


# ── 预检与自检子命令 ─────────────────────────────────────────────

def check_config(cfg: dict) -> list:
    """资源级红线配置预检，返回错误列表（空 = 通过）。"""
    errors = []
    if cfg["protocol"] not in ("json", "exit2"):
        errors.append(f"hook.protocol 非法值: {cfg['protocol']}"
                      "（允许 json | exit2）")
    for ext in cfg["protected_extensions"]:
        if not ext.startswith("."):
            errors.append(f"hook.protected_extensions 格式错误: {ext}"
                          "（必须以 . 开头）")
    if cfg["protected_paths"]:
        for p in cfg["protected_paths"]:
            if not os.path.isdir(p):
                errors.append(f"hook.protected_paths 目录不存在: {p}")
    elif cfg["protected_extensions"]:
        errors.append("hook.protected_extensions 已配置但 "
                      "hook.protected_paths 为空（扩展名约束不生效）")
    try:
        parent = os.path.dirname(cfg["decisions_file"])
        if parent:
            os.makedirs(parent, exist_ok=True)
            probe = os.path.join(parent, ".hook_gate_write_probe")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(probe)
    except OSError as e:
        errors.append(f"hook.decisions_file 目录不可写: {e}")
    return errors


_SELF_TEST_PAYLOADS = [
    # (描述, payload) —— 资源级红线以实际配置为准，结果随配置变化
    ("Read 受保护目录下文件",
     {"tool_name": "Read", "tool_input": {"file_path": ""},
      "session_id": "selftest-1", "cwd": ""}),
    ("Read 普通目录文件",
     {"tool_name": "Read", "tool_input": {"file_path": "C:/nonexist.txt"},
      "session_id": "selftest-2", "cwd": ""}),
    ("Bash 空命令（无资源目标）",
     {"tool_name": "Bash", "tool_input": {"command": ""},
      "session_id": "selftest-3", "cwd": ""}),
]


def self_test(cfg: dict) -> int:
    """自检: 打印当前配置与内置 payload 的判定结果（不触发留痕/通知）。"""
    print(f"[self-test] config: {cfg.get('_config_path')}")
    print(f"[self-test] protocol={cfg['protocol']} "
          f"ask_enabled={cfg['ask_enabled']}")
    print(f"[self-test] protected_paths={cfg['protected_paths']}")
    print(f"[self-test] protected_extensions={cfg['protected_extensions']}")
    for desc, payload in _SELF_TEST_PAYLOADS:
        # 将第一个 payload 的目标替换为当前配置首个受保护路径（若已配置）
        if desc.startswith("Read 受保护") and cfg["protected_paths"]:
            first = cfg["protected_paths"][0]
            ext = cfg["protected_extensions"][0] if (
                cfg["protected_extensions"]) else "x"
            payload = dict(payload)
            payload["tool_input"] = dict(payload["tool_input"],
                                         file_path=os.path.join(
                                             first, f"self_test.{ext.lstrip('.')}"))
        entry = decide(payload, cfg)
        print(f"[self-test] {desc} -> {entry['decision']}"
              f"{(' (' + entry['reason'][:80] + ')') if entry['reason'] else ''}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hook_gate",
        description="方寸观察者 拦截路径 hook 判定入口（PreToolUse）")
    parser.add_argument("--config", type=str, default="",
                        help="config.yaml 路径（缺省自动定位 / OBSERVER_CONFIG）")
    parser.add_argument("--check-config", action="store_true",
                        help="资源级红线配置预检（部署前置校验）")
    parser.add_argument("--self-test", action="store_true",
                        help="内置 payload 判定自检（调试）")
    return parser


def _read_stdin() -> str:
    """显式按字节读取 stdin 并按 UTF-8 解码（宿主 hook payload 恒为 UTF-8）。

    实测坑（2026-09-05 P1-3 宿主实测）: sys.stdin.read() 在中文 Windows 按
    locale 编码（cp936）解码 UTF-8 字节流——中文末字节与紧随其后的 JSON 语法
    字符（闭合引号等）被 GBK 解码器合并为双字节字吞掉 → JSON 结构断裂 →
    fail-closed 误拦；部分字节经 surrogateescape 残留 surrogate 字符 →
    留痕 encode 崩溃。修复: 绕过文本层直接读字节，按 UTF-8 显式解码
    （errors=replace 不抛解码异常，解码失败由 json.loads 按 D-3 处理）。
    """
    if hasattr(sys.stdin, "buffer"):
        data = sys.stdin.buffer.read()
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return data
    return sys.stdin.read()


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
    except RuntimeError as e:
        print(f"[hook_gate] 配置加载失败: {e}", file=sys.stderr)
        return 3
    if args.check_config:
        errors = check_config(cfg)
        if errors:
            print("[check-config] FAIL:", file=sys.stderr)
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            return 1
        print("[check-config] OK 资源级红线配置有效")
        print(f"  config: {cfg['_config_path']}")
        print(f"  protocol: {cfg['protocol']} (ask_enabled={cfg['ask_enabled']})")
        print(f"  protected_paths: {cfg['protected_paths']}")
        print(f"  protected_extensions: {cfg['protected_extensions']}")
        print(f"  decisions_file: {cfg['decisions_file']}")
        return 0
    if args.self_test:
        return self_test(cfg)
    code, _, _ = run(_read_stdin(), cfg)
    return code


if __name__ == "__main__":
    sys.exit(main())
