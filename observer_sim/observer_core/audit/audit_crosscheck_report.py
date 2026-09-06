# -*- coding: utf-8 -*-
"""
observer_core/audit/audit_crosscheck_report.py — T3.3 系统审计交叉校验
（产出层，独立模块）

定位:
    将 AuditCrossChecker（collector/windows_audit_reader.py）的比对结果
    渲染为 Markdown「系统审计交叉校验」小节并追加到报告页脚「---」前。
    与 T3.1/T3.2 的 report_exporter 小节同构；T3.3 渲染与追加逻辑独立
    成模块（产出层，不改动任何检测/研判逻辑）。

功能:
- render_audit_crosscheck_md(summary): 渲染小节（未启用 / 不可用+指引 /
  已比对会话+疑似二级操作事件 / 说明）；
- append_audit_crosscheck_section(report_path, summary): 幂等追加
  （报告已含该小节时跳过；找不到页脚分隔线时退回末尾追加）；
- install_on_report_exporter(): 把追加方法以幂等方式挂到 ReportExporter，
  供 monitor_daemon 以 ReportExporter(...).append_audit_crosscheck_section
  形式调用（与 T3.1/T3.2 调用方式一致）。
"""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# 比对窗口与措辞声明（写入报告固定措辞，如实披露采样局限）
AUDIT_CROSSCHECK_NOTE = (
    "系统审计日志仅覆盖已启用审计的进程创建(4688)与 PowerShell 脚本块"
    "(4104)；审计未启用时该观测源不可用；"
    "比对窗口为会话 start/end 边界（前扩 lookback_s），窗口外事件不可见；"
    "差异事件判定为「疑似二级操作」，仅告警不拦截")

SECTION_TITLE = "系统审计交叉校验"


def render_audit_crosscheck_md(summary: Optional[dict]) -> str:
    """将系统审计交叉校验结果渲染为 Markdown「系统审计交叉校验」小节（T3.3）。"""
    lines = ["## 系统审计交叉校验（Windows 审计日志比对）", ""]
    if not summary or not summary.get("enabled"):
        lines.append("- **状态**: 未启用")
        lines.append("")
        return "\n".join(lines)
    if not summary.get("available"):
        lines.append("- **状态**: 不可用（审计通道不可读，未做比对）")
        channels = summary.get("channels") or {}
        for key, ch in list(channels.items())[:4]:
            lines.append(f"  - 通道 {key}（{ch.get('desc', '?')}）: "
                         f"{ch.get('detail', '?')}")
        for g in (summary.get("guidance") or [])[:4]:
            lines.append(f"  - 启用指引: {g}")
        for u in (summary.get("unavailable") or [])[:3]:
            lines.append(f"  - 会话 {u.get('session_id', '?')} "
                         f"({u.get('phase')}): {u.get('reason')}")
        lines.append(f"- **说明**: {summary.get('note', AUDIT_CROSSCHECK_NOTE)}")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"- **已比对会话数**: {summary.get('sessions_checked', 0)}")
    findings = summary.get("findings") or []
    if findings:
        lines.append(f"- **疑似二级操作（申报外系统事件）**: {len(findings)} 个会话")
        for f in findings[:5]:
            events = f.get("events") or []
            n_evt = len(events)
            lines.append(f"  - 会话 {f.get('session_id', '?')}: "
                         f"{n_evt} 条申报外系统事件")
            for e in events[:3]:
                src = e.get("source", "?")
                proc = e.get("process") or "-"
                cmd = (e.get("command") or "-")[:100]
                lines.append(f"    - [{src}] {proc}: {cmd}")
    else:
        lines.append("- **疑似二级操作**: 无（未发现申报外系统事件）")
    unavailable = summary.get("unavailable") or []
    if unavailable:
        lines.append(f"- **查询不可用会话/通道**: {len(unavailable)} 条（未参与比对）")
    lines.append(f"- **说明**: {summary.get('note', AUDIT_CROSSCHECK_NOTE)}")
    lines.append("")
    return "\n".join(lines)


def append_audit_crosscheck_section(report_path: Optional[str],
                                    summary: Optional[dict]) -> bool:
    """在报告页脚「---」前插入「系统审计交叉校验」小节（T3.3，产出层）。

    幂等: 报告已含该小节时跳过。找不到页脚分隔线时退回末尾追加。

    Returns:
        bool: True 已写入（或已存在）；False 报告文件不可用。
    """
    if not report_path or not os.path.isfile(report_path):
        return False
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return False
    if SECTION_TITLE in content:
        return True  # 幂等
    section = render_audit_crosscheck_md(summary)
    marker = "\n---\n"
    idx = content.rfind(marker)
    if idx >= 0:
        new_content = content[:idx] + "\n" + section + content[idx:]
    else:
        new_content = content.rstrip("\n") + "\n\n" + section
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(new_content)
    except OSError:
        return False
    logger.info(
        f"[AuditCrosscheckReport] Audit crosscheck section appended: "
        f"{report_path}")
    return True


def _append_method(self, report_path: Optional[str],
                   summary: Optional[dict]) -> bool:
    """ReportExporter 方法形态（self 被忽略，转发到模块级函数）。"""
    return append_audit_crosscheck_section(report_path, summary)


def install_on_report_exporter() -> bool:
    """把 append_audit_crosscheck_section 挂到 ReportExporter（幂等）。

    monitor_daemon 以 ReportExporter(...).append_audit_crosscheck_section
    形式调用（与 T3.1/T3.2 小节调用方式一致）；因 report_exporter.py
    体积超过编辑工具上限无法直接追加方法，采用包初始化时运行期挂载
    接入（产出层，不改动判定管线）。

    Returns:
        bool: True 已挂载（或此前已挂载）；False ReportExporter 不可导入。
    """
    try:
        from observer_core.audit.report_exporter import ReportExporter
    except Exception as e:  # noqa: BLE001 防御: 挂载失败不破坏主流程
        logger.warning("ReportExporter 不可导入，审计交叉校验小节未挂载: %s",
                       e)
        return False
    if hasattr(ReportExporter, "append_audit_crosscheck_section"):
        return True  # 幂等
    ReportExporter.append_audit_crosscheck_section = _append_method
    logger.info(
        "[AuditCrosscheckReport] append_audit_crosscheck_section 已挂载到 "
        "ReportExporter")
    return True