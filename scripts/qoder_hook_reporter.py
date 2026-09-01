#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qoder_hook_reporter.py — Qoder CN Hooks 确定性申报 reporter（P1）

由 Qoder CN 的 Hook 机制（.lingma/settings.json 配置）在每次工具调用后
以子进程方式执行: 从 stdin 读取 Hook 事件 JSON（官方协议），转换为
申报 payload 并 POST 到监测端点 /api/hook-report。

设计约束（硬性）:
- 纯标准库实现（禁重型 import）: Hook 在每次工具调用都执行且默认 30s 超时;
- 失败静默放行: 任何异常（网络不可达/超时/畸形输入）一律 exit 0，
  绝不阻断或影响 Agent 正常工作;
- 仅输出诊断到 stderr/本地日志（Hook stderr 会反馈给用户，保持简洁）。

用法（.lingma/settings.json）:
    {"hooks": {"PostToolUse": [{"matcher": "", "hooks": [
        {"type": "command",
         "command": "python3 /path/to/scripts/qoder_hook_reporter.py"}]}]}}

调试（官方文档推荐方式）:
    echo '{"hook_event_name":"PostToolUse","session_id":"s1",
           "tool_name":"run_in_terminal","tool_input":{"command":"ls"}}' \
      | python3 scripts/qoder_hook_reporter.py --url http://127.0.0.1:8765/api/hook-report

环境变量:
    OBSERVER_HOOK_REPORT_URL  摄入端点（覆盖默认）
    OBSERVER_AGENT_ID         agent 标识（覆盖默认 "qoder"）
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8765/api/hook-report"
DEFAULT_AGENT_ID = "qoder"
DEFAULT_TIMEOUT_S = 3.0
MAX_RESULT_LEN = 512          # result 摘要本地截断（服务端上限 4096）
MAX_TOOL_NAME_LEN = 128       # 与服务端 schema 对齐


# ── Hook 事件 → 申报 payload ────────────────────────────────────────────────

def _shorten(text, limit):
    """截断为安全摘要（非字符串安全降级为 str）"""
    if text is None:
        return None
    s = text if isinstance(text, str) else str(text)
    return s if len(s) <= limit else s[:limit] + "...[truncated]"


def _extract_result(hook_event, event_name):
    """PostToolUseFailure 提取失败摘要作为 result；其余事件不带 result。"""
    if event_name != "PostToolUseFailure":
        return None
    resp = hook_event.get("tool_response")
    if resp is None:
        return "tool_use_failed"
    if isinstance(resp, dict):
        for key in ("error", "stderr", "message", "output"):
            if resp.get(key):
                return _shorten(resp[key], MAX_RESULT_LEN)
        return _shorten(json.dumps(resp, ensure_ascii=False, default=str),
                        MAX_RESULT_LEN)
    return _shorten(resp, MAX_RESULT_LEN)


def build_report_payload(hook_event, agent_id=DEFAULT_AGENT_ID):
    """
    Qoder CN Hook 事件 JSON（stdin 协议）→ /api/hook-report 申报体。

    字段对应（与 mcp_bridge.schemas.ReportToolCallInput 一致）:
      tool_name   ← hook_event.tool_name
      tool_args   ← hook_event.tool_input（原样转发，服务端脱敏/校验）
      session_id  ← hook_event.session_id
      action_type ← pre(PreToolUse) / post(PostToolUse, PostToolUseFailure)
      result      ← PostToolUseFailure 时提取失败摘要

    Returns:
        dict（可 JSON 序列化的申报体）；无可申报的工具调用时返回 None。
    """
    if not isinstance(hook_event, dict):
        return None
    tool_name = hook_event.get("tool_name")
    if not tool_name:
        return None  # UserPromptSubmit/Stop 等非工具事件不申报

    event_name = str(hook_event.get("hook_event_name", "") or "")
    tool_input = hook_event.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    return {
        "agent_id": agent_id or DEFAULT_AGENT_ID,
        "tool_name": _shorten(str(tool_name), MAX_TOOL_NAME_LEN),
        "tool_args": tool_input,
        "session_id": _shorten(hook_event.get("session_id"), 128),
        "action_type": "pre" if event_name == "PreToolUse" else "post",
        "result": _extract_result(hook_event, event_name),
    }


# ── HTTP 上报（失败静默放行）────────────────────────────────────────────────

def post_report(payload, url, timeout_s=DEFAULT_TIMEOUT_S):
    """POST 申报体。成功返回响应 dict；任何失败返回 None（不抛异常）。"""
    try:
        data = json.dumps(payload, ensure_ascii=False,
                          default=str).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = resp.read()
            try:
                return json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                return {"status": "accepted_raw", "http": resp.status}
    except urllib.error.HTTPError as e:
        # 服务端结构化拒绝（400/413/429）: 解析响应体拿到 reason
        try:
            return json.loads(e.read().decode("utf-8"))
        except Exception:
            return {"status": "rejected", "reason": f"http_{e.code}"}
    except Exception:
        return None


def _log(message, log_file=None):
    """诊断日志: 优先写本地文件（避免 stderr 反馈给 Agent），否则 stderr。"""
    line = f"[qoder_hook_reporter] {message}"
    if log_file:
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            return
        except OSError:
            pass
    print(line, file=sys.stderr)


# ── 入口 ────────────────────────────────────────────────────────────────────

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Qoder CN Hook 申报 reporter（纯标准库，失败静默放行）")
    parser.add_argument("--url",
                        default=os.environ.get("OBSERVER_HOOK_REPORT_URL",
                                               DEFAULT_URL),
                        help="摄入端点 (默认 %(default)s)")
    parser.add_argument("--agent-id",
                        default=os.environ.get("OBSERVER_AGENT_ID",
                                               DEFAULT_AGENT_ID),
                        help="agent 标识 (默认 %(default)s)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                        help="HTTP 超时秒数 (默认 %(default)s)")
    parser.add_argument("--log-file", default=None,
                        help="诊断日志文件（缺省输出到 stderr）")
    args = parser.parse_args(argv)

    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0  # 空输入静默放行
        try:
            hook_event = json.loads(raw)
        except ValueError:
            _log("stdin 非 JSON，忽略", args.log_file)
            return 0
        payload = build_report_payload(hook_event, agent_id=args.agent_id)
        if payload is None:
            return 0  # 非工具事件（UserPromptSubmit/Stop）不申报
        result = post_report(payload, args.url, timeout_s=args.timeout)
        if result is None:
            _log(f"上报失败（监测端点不可达？），静默放行: {args.url}",
                 args.log_file)
        elif str(result.get("status")) == "rejected":
            _log(f"申报被拒: {result.get('reason')}", args.log_file)
    except Exception as e:  # 最后防线: 任何异常不得影响 Agent
        _log(f"内部异常，静默放行: {e}", getattr(args, "log_file", None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
