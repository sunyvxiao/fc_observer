# -*- coding: utf-8 -*-
"""
test_mcp_report_completeness.py — T1.4 申报完整性核对与覆盖置信度测试

覆盖 T1.4 验收:
1. 未闭合会话 + 静默申报集 → 报告出现对应标注与置信度
2. 完整闭合会话无异常标注
3. jsonl_dir 未配置 → 如实标注「申报留痕未落盘，完整性核对跳过」
4. 覆盖置信度分级（高/中/低）、报告页脚插入位置与幂等

全部为纯函数测试（模拟申报留痕 JSONL），不依赖真实 WorkBuddy 环境。
"""

import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from observer_core.audit.report_exporter import (
    ReportExporter,
    analyze_report_completeness,
    render_completeness_md,
)

T0 = 1_700_000_000_000  # epoch ms 基准


def _session_rec(sid, status, received_at_ms):
    return {
        "type": "report_session",
        "payload": {"agent_id": "workbuddy", "session_id": sid,
                    "status": status, "timestamp_ms": received_at_ms},
        "event_id": f"evt-{sid}-{status}",
        "received_at_ms": received_at_ms,
    }


def _tool_rec(name, received_at_ms, sid="sess-1"):
    return {
        "type": "report_tool_call",
        "payload": {"agent_id": "workbuddy", "tool_name": name,
                    "tool_args": {}, "session_id": sid},
        "event_id": f"evt-{name}",
        "received_at_ms": received_at_ms,
    }


def _write_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return path


# ── analyze_report_completeness 正常/异常路径 ─────────────────────────

def test_closed_session_high_confidence(tmp_path):
    """完整闭合会话（start+end 配对、无静默）→ 高置信度、无异常标注。"""
    jsonl = _write_jsonl(str(tmp_path / "mcp_reports.jsonl"), [
        _session_rec("sess-1", "start", T0),
        _tool_rec("read_file", T0 + 1000),
        _session_rec("sess-1", "end", T0 + 2000),
    ])
    a = analyze_report_completeness(jsonl, silence_alert_s=600)
    assert a["checked"] is True
    assert a["record_count"] == 3
    assert a["session_count"] == 1
    assert a["unclosed_sessions"] == []
    assert a["end_without_start"] == []
    assert a["silent_gaps"] == []
    assert a["confidence"] == "高"
    md = render_completeness_md(a)
    assert "覆盖置信度**: 高" in md
    assert "会话未闭合" not in md
    assert "可疑静默区间**: 无" in md
    assert "仅反映申报侧完整性，不代表行为覆盖" in md


def test_unclosed_session_marked(tmp_path):
    """start 无 end → 未闭合会话标注 + 中置信度。"""
    jsonl = _write_jsonl(str(tmp_path / "mcp_reports.jsonl"), [
        _session_rec("sess-1", "start", T0),
        _tool_rec("read_file", T0 + 1000),
    ])
    a = analyze_report_completeness(jsonl, silence_alert_s=600)
    assert a["unclosed_sessions"] == ["sess-1"]
    assert a["confidence"] == "中"
    assert "未闭合" in a["confidence_reason"]
    md = render_completeness_md(a)
    assert "会话未闭合，疑似漏报" in md
    assert "sess-1" in md


def test_end_without_start_marked(tmp_path):
    """仅有 end 申报 → 疑似缺失 start 标注 + 中置信度。"""
    jsonl = _write_jsonl(str(tmp_path / "mcp_reports.jsonl"), [
        _session_rec("sess-9", "end", T0),
    ])
    a = analyze_report_completeness(jsonl, silence_alert_s=600)
    assert a["end_without_start"] == ["sess-9"]
    assert a["unclosed_sessions"] == []
    assert a["confidence"] == "中"
    md = render_completeness_md(a)
    assert "疑似缺失 start 申报" in md


def test_silent_gap_marked(tmp_path):
    """相邻申报间隔 5s > 阈值 2s → 可疑静默区间标注 + 中置信度。"""
    jsonl = _write_jsonl(str(tmp_path / "mcp_reports.jsonl"), [
        _session_rec("sess-1", "start", T0),
        _tool_rec("read_file", T0 + 1000),
        _session_rec("sess-1", "end", T0 + 6000),
    ])
    a = analyze_report_completeness(jsonl, silence_alert_s=2)
    assert len(a["silent_gaps"]) == 1
    assert a["silent_gaps"][0]["duration_s"] == 5.0
    assert a["confidence"] == "中"
    md = render_completeness_md(a)
    assert "可疑静默区间" in md
    assert "超过 2s" in md


def test_no_session_report_low_confidence(tmp_path):
    """无 report_session 申报 → 低置信度。"""
    jsonl = _write_jsonl(str(tmp_path / "mcp_reports.jsonl"), [
        _tool_rec("read_file", T0),
        _tool_rec("list_files", T0 + 1000),
    ])
    a = analyze_report_completeness(jsonl, silence_alert_s=600)
    assert a["session_count"] == 0
    assert a["confidence"] == "低"
    assert "无会话级申报" in a["confidence_reason"]


def test_silence_zero_disables_gap_detection(tmp_path):
    """silence_alert_s=0 → 不检测静默区间（闭合会话仍为高置信度）。"""
    jsonl = _write_jsonl(str(tmp_path / "mcp_reports.jsonl"), [
        _session_rec("sess-1", "start", T0),
        _session_rec("sess-1", "end", T0 + 60_000_000),  # 间隔巨大
    ])
    a = analyze_report_completeness(jsonl, silence_alert_s=0)
    assert a["silent_gaps"] == []
    assert a["confidence"] == "高"


def test_jsonl_not_configured_skipped(tmp_path):
    """jsonl_dir 未配置（None）→ 如实标注跳过 + 低置信度。"""
    a = analyze_report_completeness(None, silence_alert_s=600)
    assert a["checked"] is False
    assert "申报留痕未落盘，完整性核对跳过" in a["reason"]
    assert a["confidence"] == "低"
    md = render_completeness_md(a)
    assert "申报留痕未落盘，完整性核对跳过" in md
    assert "覆盖置信度**: 低" in md


def test_jsonl_missing_file_skipped(tmp_path):
    """留痕文件不存在 → 如实标注跳过。"""
    a = analyze_report_completeness(str(tmp_path / "no_such.jsonl"),
                                    silence_alert_s=600)
    assert a["checked"] is False
    assert "申报留痕未落盘，完整性核对跳过" in a["reason"]


def test_jsonl_malformed_lines_tolerated(tmp_path):
    """畸形行/空行容错跳过，合法记录正常核对。"""
    path = str(tmp_path / "mcp_reports.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write("not-json\n\n")
        f.write(json.dumps(_session_rec("sess-1", "start", T0)) + "\n")
        f.write(json.dumps(_session_rec("sess-1", "end", T0 + 1000)) + "\n")
    a = analyze_report_completeness(path, silence_alert_s=600)
    assert a["checked"] is True
    assert a["record_count"] == 2
    assert a["confidence"] == "高"


# ── render_completeness_md / append_completeness_section ─────────────

def test_append_section_before_footer_and_idempotent(tmp_path):
    """小节插入页脚「---」之前，重复追加幂等。"""
    report = str(tmp_path / "report.md")
    content = ("# 风险分析报告\n\n## 1. 概览\n\n"
               "---\n*本报告由方寸观察者模拟学习系统自动生成*\n")
    with open(report, "w", encoding="utf-8") as f:
        f.write(content)

    a = analyze_report_completeness(None, silence_alert_s=600)
    exporter = ReportExporter(output_dir=str(tmp_path))
    assert exporter.append_completeness_section(report, a) is True

    with open(report, encoding="utf-8") as f:
        new_content = f.read()
    assert "申报完整性核对" in new_content
    assert "申报留痕未落盘，完整性核对跳过" in new_content
    # 小节位于页脚「---」之前
    assert new_content.index("申报完整性核对") < new_content.index("---")
    # 幂等: 再次追加不产生重复内容
    assert exporter.append_completeness_section(report, a) is True
    with open(report, encoding="utf-8") as f:
        assert f.read() == new_content


def test_append_section_missing_report_returns_false(tmp_path):
    """报告文件不存在 → 返回 False（不抛异常）。"""
    exporter = ReportExporter(output_dir=str(tmp_path))
    a = analyze_report_completeness(None)
    assert exporter.append_completeness_section(
        str(tmp_path / "nope.md"), a) is False
