# -*- coding: utf-8 -*-
"""
tests/test_windows_audit_reader.py — T3.3 Windows 审计日志读取与交叉校验

覆盖:
- to_utc_epoch_ms: 秒 / 毫秒 / 纳秒 / ISO-Z / ISO 本地 / 非法形态
- parse_event_xml: 4688 / 4104 / 截断 / 非法 XML / 未知 eid / 缺时间
- WindowsAuditReader: 窗口过滤 / 通道失败 / 可用性三态
- AuditCrossChecker: 会话窗口断言、申报外告警、各排除口径、未闭合、
  end 无 start、审计不可用降级、jsonl 留痕
- audit_crosscheck_report: 渲染 / 追加幂等 / 缺失报告 / 方法挂载

所有审计事件经 query_fn 注入假数据，不依赖真实审计环境（模拟申报即可）。
"""

import json
import os
import time
from datetime import datetime

import pytest

from collector.windows_audit_reader import (
    AUDIT_NOTE,
    AuditCrossChecker,
    WindowsAuditReader,
    parse_event_xml,
    to_utc_epoch_ms,
)
from observer_core.audit.audit_crosscheck_report import (
    SECTION_TITLE,
    append_audit_crosscheck_section,
    install_on_report_exporter,
    render_audit_crosscheck_md,
)

# 基准毫秒 epoch（会话窗口的锚点，远离当前时刻避免与「补当前时刻」混淆）
T0_MS = 1_700_000_000_000


def _iso_ms(text: str) -> int:
    """ISO 时间 → UTC 毫秒 epoch（测试内动态计算期望值，避免硬编码）。"""
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


# ── 时间转换（时钟对齐统一口径）────────────────────────────────────

class TestToUtcEpochMs:
    def test_seconds(self):
        assert to_utc_epoch_ms(1_700_000_000) == 1_700_000_000_000

    def test_milliseconds(self):
        assert to_utc_epoch_ms(1_700_000_000_123) == 1_700_000_000_123

    def test_nanoseconds(self):
        assert to_utc_epoch_ms(1_700_000_000_123_456_789) == 1_700_000_000_123

    def test_zero(self):
        assert to_utc_epoch_ms(0) == 0

    def test_iso_z(self):
        assert to_utc_epoch_ms("2026-01-01T00:00:00Z") == _iso_ms(
            "2026-01-01T00:00:00Z")

    def test_iso_offset(self):
        assert to_utc_epoch_ms("2026-01-01T00:00:00+08:00") == _iso_ms(
            "2026-01-01T00:00:00+08:00")

    def test_iso_local_no_timezone(self):
        # 无时区按本地时区解释（申报侧口径），与 datetime.astimezone 一致
        text = "2026-01-01T00:00:00"
        expected = int(
            datetime.fromisoformat(text).astimezone().timestamp() * 1000)
        assert to_utc_epoch_ms(text) == expected

    def test_none_and_bool(self):
        assert to_utc_epoch_ms(None) is None
        assert to_utc_epoch_ms(True) is None

    def test_invalid(self):
        assert to_utc_epoch_ms("not-a-time") is None
        assert to_utc_epoch_ms("") is None
        assert to_utc_epoch_ms(["2026-01-01"]) is None


# ── 事件 XML 解析 ──────────────────────────────────────────────────

_NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def _event_xml(eid: str, sys_time: str, datas: str) -> str:
    return (
        f'<Event {_NS}><System><EventID>{eid}</EventID>'
        f'<TimeCreated SystemTime="{sys_time}"/></System>'
        f"<EventData>{datas}</EventData></Event>")


def _data(name: str, text: str) -> str:
    return f'<Data Name="{name}">{text}</Data>'


class TestParseEventXml:
    def test_4688(self):
        xml = _event_xml(
            "4688", "2026-01-01T00:00:00.000000000Z",
            _data("NewProcessName", r"C:\evil\bad.exe")
            + _data("CommandLine", "bad.exe --steal")
            + _data("ParentProcessName", r"C:\Windows\System32\cmd.exe"))
        evt = parse_event_xml(xml)
        assert evt is not None
        assert evt["event_id"] == 4688
        assert evt["source"] == "security_4688"
        assert evt["time_ms"] == _iso_ms("2026-01-01T00:00:00Z")
        assert evt["process"] == r"C:\evil\bad.exe"
        assert evt["command"] == "bad.exe --steal"
        assert evt["parent"] == r"C:\Windows\System32\cmd.exe"

    def test_4104_truncates_script(self):
        script = "Invoke-WebRequest " + ("x" * 600)
        xml = _event_xml(
            "4104", "2026-01-01T00:00:00.000000000Z",
            _data("ScriptBlockText", script)
            + _data("Path", r"C:\Windows\System32\WindowsPowerShell\v1.0"))
        evt = parse_event_xml(xml)
        assert evt is not None
        assert evt["event_id"] == 4104
        assert evt["source"] == "ps_4104"
        assert len(evt["command"]) == 500  # 脚本块截断，仅用于比对
        assert evt["process"] == r"C:\Windows\System32\WindowsPowerShell\v1.0"

    def test_invalid_xml(self):
        assert parse_event_xml("not xml at all") is None

    def test_unknown_event_id(self):
        xml = _event_xml("9999", "2026-01-01T00:00:00Z",
                         _data("X", "y"))
        assert parse_event_xml(xml) is None

    def test_missing_time(self):
        xml = (
            f'<Event {_NS}><System><EventID>4688</EventID></System>'
            f"<EventData>{_data('NewProcessName', 'x.exe')}</EventData>"
            "</Event>")
        evt = parse_event_xml(xml)
        assert evt is not None
        assert evt["time_ms"] is None  # 时间不可用，不参与窗口比对


# ── 读取器（query_fn 注入）─────────────────────────────────────────

def _mk_event(eid: int, time_ms: int, process: str, command: str = "",
              parent: str = "") -> dict:
    source = "security_4688" if eid == 4688 else "ps_4104"
    return {"event_id": eid, "source": source, "time_ms": time_ms,
            "process": process, "command": command, "parent": parent}


class TestWindowsAuditReader:
    def test_read_events_filters_window(self):
        """窗口内事件保留，窗口外（含时间缺失）事件被时钟对齐过滤。"""
        inside = _mk_event(4688, T0_MS + 10_000, "a.exe", "a")
        outside = _mk_event(4688, T0_MS - 99_999, "b.exe", "b")
        no_time = _mk_event(4688, None, "c.exe", "c")
        calls = []

        def fake(log_name, ids, start, end, max_events, timeout_s):
            calls.append((log_name, start, end, max_events))
            if log_name == "Security":
                return [inside, outside, no_time]
            return []

        reader = WindowsAuditReader(query_fn=fake)
        events, errors = reader.read_events(T0_MS, T0_MS + 60_000)
        assert errors == []
        assert [e["process"] for e in events] == ["a.exe"]
        # 查询窗口以秒 epoch 传入
        assert calls[0][1] == pytest.approx(T0_MS / 1000.0)
        assert calls[0][2] == pytest.approx((T0_MS + 60_000) / 1000.0)

    def test_read_events_channel_failure_reported(self):
        """单通道失败 → errors 含 channel/error/guidance，其余通道不受影响。"""

        def fake(log_name, ids, start, end, max_events, timeout_s):
            if log_name == "Security":
                raise RuntimeError("权限不足")
            return [_mk_event(4104, T0_MS + 5_000, "pwsh.exe", "Get-Thing")]

        reader = WindowsAuditReader(query_fn=fake)
        events, errors = reader.read_events(T0_MS, T0_MS + 60_000)
        assert len(events) == 1
        assert len(errors) == 1
        assert errors[0]["channel"] == "4688"
        assert "权限不足" in errors[0]["error"]
        assert errors[0]["guidance"]  # 启用指引随错误一并给出

    def test_availability_all_ok(self):
        def fake(log_name, ids, start, end, max_events, timeout_s):
            return []

        reader = WindowsAuditReader(query_fn=fake)
        avail = reader.availability()
        assert avail["available"] is True
        assert set(avail["channels"]) == {"4688", "4104"}
        assert all(ch["ok"] for ch in avail["channels"].values())

    def test_availability_all_fail_with_guidance(self):
        def fake(log_name, ids, start, end, max_events, timeout_s):
            raise RuntimeError("通道不存在")

        reader = WindowsAuditReader(query_fn=fake)
        avail = reader.availability()
        assert avail["available"] is False
        assert all(not ch["ok"] for ch in avail["channels"].values())
        assert len(avail["guidance"]) == 2  # 每通道一条启用指引

    def test_availability_non_windows_extra_guidance(self, monkeypatch):
        def fake(log_name, ids, start, end, max_events, timeout_s):
            raise RuntimeError("通道不存在")

        monkeypatch.setattr(os, "name", "posix")
        reader = WindowsAuditReader(query_fn=fake)
        avail = reader.availability()
        assert avail["available"] is False
        assert any("非 Windows" in g for g in avail["guidance"])


# ── 会话级交叉比对 ────────────────────────────────────────────────

class TestAuditCrossChecker:
    def _make(self, tmp_path, events_by_channel, *, agent_names=None,
              whitelist_extra=None):
        """构造 checker，query_fn 记录调用并返回注入事件。"""
        calls = []

        def fake(log_name, ids, start, end, max_events, timeout_s):
            calls.append({"log_name": log_name, "start": start,
                          "end": end, "max_events": max_events})
            if max_events == 1:  # availability 探测 → 空列表（可读）
                return []
            return events_by_channel.get(log_name, [])

        reader = WindowsAuditReader(query_fn=fake)
        checker = AuditCrossChecker(
            str(tmp_path), reader=reader, lookback_s=60,
            agent_process_names=agent_names or ["workbuddy.exe"],
            whitelist_extra=whitelist_extra or [])
        return checker, calls

    def test_window_and_summary_shape(self, tmp_path):
        """闭合会话 → 查询窗口含前扩 lookback_s；summary 字段齐全。"""
        checker, calls = self._make(tmp_path, {})
        checker.on_session_start("s1", {"timestamp_ms": T0_MS + 5_000})
        checker.on_session_end("s1", {"timestamp_ms": T0_MS + 60_000})
        summary = checker.finish()
        assert summary["enabled"] is True
        assert summary["available"] is True
        assert summary["sessions_checked"] == 1
        assert summary["findings"] == []
        assert summary["unavailable"] == []
        assert summary["note"] == AUDIT_NOTE
        # read_events 查询窗口: start = start_ms - lookback, end = end_ms
        reads = [c for c in calls if c["max_events"] > 1]
        assert reads, "finish 应执行窗口查询"
        for c in reads:
            assert c["start"] == pytest.approx(
                (T0_MS + 5_000 - 60_000) / 1000.0)
            assert c["end"] == pytest.approx((T0_MS + 60_000) / 1000.0)

    def test_unreported_event_finding_and_jsonl(self, tmp_path):
        """申报外进程创建 → 「疑似二级操作」finding + jsonl 留痕。"""
        events = {
            "Security": [_mk_event(4688, T0_MS + 30_000, "evil.exe",
                                   "evil.exe --steal",
                                   "cmd.exe")],
        }
        checker, _ = self._make(tmp_path, events)
        checker.on_session_start("s1", {"timestamp_ms": T0_MS + 5_000})
        checker.on_session_end("s1", {"timestamp_ms": T0_MS + 60_000})
        summary = checker.finish({}, {})
        assert len(summary["findings"]) == 1
        f = summary["findings"][0]
        assert f["session_id"] == "s1"
        assert f["kind"] == "unreported_system_event"
        assert f["severity"] == "suspect_secondary_action"
        assert f["events"][0]["process"] == "evil.exe"
        # jsonl 留痕
        path = os.path.join(str(tmp_path), "crosscheck_audit.jsonl")
        assert os.path.isfile(path)
        with open(path, encoding="utf-8") as fh:
            entries = [json.loads(line) for line in fh]
        assert entries[0]["type"] == "audit_crosscheck"
        assert entries[0]["session_id"] == "s1"

    def test_exclusions(self, tmp_path):
        """系统白名单 / Agent / whitelist_extra / 已申报命令与路径 /
        4104 短脚本与已申报子串 → 全部排除，无 findings。"""
        events = {
            "Security": [
                # 系统白名单
                _mk_event(4688, T0_MS + 10_000, "svchost.exe", "svchost"),
                # Agent 进程
                _mk_event(4688, T0_MS + 11_000, "WorkBuddy.exe", "wb"),
                # whitelist_extra
                _mk_event(4688, T0_MS + 12_000, "MyTool.exe", "mytool"),
                # 已申报命令（进程名首 token 匹配）
                _mk_event(4688, T0_MS + 13_000, "curl.exe",
                          "curl.exe https://example.com"),
                # 已申报路径出现在命令中
                _mk_event(4688, T0_MS + 14_000, "notepad.exe",
                          r"notepad.exe C:\work\notes.txt"),
            ],
            "Microsoft-Windows-PowerShell/Operational": [
                # 短脚本（<8 字符）不比对
                _mk_event(4104, T0_MS + 15_000, "pwsh.exe", "if($a)"),
                # 脚本块包含已申报命令子串
                _mk_event(4104, T0_MS + 16_000, "pwsh.exe",
                          "param() Get-ChildItem C:/src"),
            ],
        }
        checker, _ = self._make(
            tmp_path, events,
            whitelist_extra=["mytool.exe"])
        checker.on_session_start("s1", {"timestamp_ms": T0_MS + 5_000})
        checker.on_session_end("s1", {"timestamp_ms": T0_MS + 60_000})
        summary = checker.finish(
            {"s1": ["curl https://example.com", "Get-ChildItem C:/src"]},
            {"s1": ["C:/work/notes.txt"]})
        assert summary["findings"] == []
        # 无 findings 且无 unavailable → 不写 jsonl
        assert not os.path.isfile(
            os.path.join(str(tmp_path), "crosscheck_audit.jsonl"))

    def test_end_without_start_unavailable(self, tmp_path):
        """end 无 start → unavailable 记录 + jsonl 留痕（不静默失败）。"""
        checker, _ = self._make(tmp_path, {})
        checker.on_session_end("ghost", {"timestamp_ms": T0_MS + 60_000})
        summary = checker.finish()
        assert summary["sessions_checked"] == 0
        assert len(summary["unavailable"]) == 1
        u = summary["unavailable"][0]
        assert u["session_id"] == "ghost"
        assert u["phase"] == "end"
        assert "无 start 会话" in u["reason"]
        path = os.path.join(str(tmp_path), "crosscheck_audit.jsonl")
        assert os.path.isfile(path)
        with open(path, encoding="utf-8") as fh:
            entries = [json.loads(line) for line in fh]
        assert entries[0]["type"] == "audit_crosscheck_unavailable"

    def test_unclosed_session_padded(self, tmp_path):
        """未闭合会话按当前时刻补 end_ms，正常参与比对不崩溃。"""
        checker, calls = self._make(tmp_path, {})
        before = int(time.time() * 1000)
        checker.on_session_start("s1", {"timestamp_ms": T0_MS + 5_000})
        summary = checker.finish()
        after = int(time.time() * 1000)
        assert summary["sessions_checked"] == 1
        reads = [c for c in calls if c["max_events"] > 1]
        assert reads
        # end 窗口应落在 [before, after] 附近（补当前时刻）
        assert reads[0]["end"] * 1000 >= before - 1_000
        assert reads[0]["end"] * 1000 <= after + 1_000

    def test_audit_unavailable_degrades(self, tmp_path):
        """审计通道全部不可读 → available False + 指引 + unavailable 记录，
        主流程不崩溃（如实降级不静默失败）。"""

        def failing(log_name, ids, start, end, max_events, timeout_s):
            raise RuntimeError("权限不足")

        reader = WindowsAuditReader(query_fn=failing)
        checker = AuditCrossChecker(str(tmp_path), reader=reader,
                                    lookback_s=60)
        checker.on_session_start("s1", {"timestamp_ms": T0_MS + 5_000})
        checker.on_session_end("s1", {"timestamp_ms": T0_MS + 60_000})
        summary = checker.finish()
        assert summary["enabled"] is True
        assert summary["available"] is False
        assert summary["guidance"]
        assert summary["unavailable"]  # 通道级失败如实并入
        assert summary["sessions_checked"] == 1  # 会话仍计数（已尝试比对）


# ── 产出层渲染 / 追加 / 挂载 ───────────────────────────────────────

class TestAuditCrosscheckReportRender:
    def test_render_disabled(self):
        for summary in (None, {"enabled": False}, {}):
            md = render_audit_crosscheck_md(summary)
            assert "系统审计交叉校验" in md
            assert "未启用" in md

    def test_render_unavailable_with_guidance(self):
        summary = {
            "enabled": True, "available": False,
            "channels": {"4688": {"desc": "进程创建审计",
                                  "detail": "读取失败: x"}},
            "guidance": ["以管理员运行 secpol.msc ..."],
            "unavailable": [{"session_id": "s1", "phase": "query",
                             "reason": "通道失败"}],
            "note": AUDIT_NOTE,
        }
        md = render_audit_crosscheck_md(summary)
        assert "不可用" in md
        assert "启用指引" in md
        assert "以管理员运行 secpol.msc" in md
        assert "会话 s1" in md

    def test_render_available_with_findings(self):
        summary = {
            "enabled": True, "available": True,
            "sessions_checked": 2,
            "findings": [{
                "session_id": "s1",
                "events": [{"event_id": 4688, "source": "security_4688",
                            "process": "evil.exe", "command": "evil --steal",
                            "parent": "cmd.exe", "time_ms": T0_MS}],
            }],
            "unavailable": [],
            "note": AUDIT_NOTE,
        }
        md = render_audit_crosscheck_md(summary)
        assert "- **已比对会话数**: 2" in md
        assert "疑似二级操作" in md
        assert "evil.exe" in md
        assert "会话 s1: 1 条申报外系统事件" in md
        assert AUDIT_NOTE in md

    def test_render_available_clean(self):
        summary = {"enabled": True, "available": True,
                   "sessions_checked": 1, "findings": [],
                   "unavailable": [], "note": AUDIT_NOTE}
        md = render_audit_crosscheck_md(summary)
        assert "疑似二级操作" in md
        assert "无（未发现申报外系统事件）" in md

    def test_append_and_idempotent(self, tmp_path):
        report = tmp_path / "report.md"
        report.write_text(
            "# 风险报告\n\n正文内容\n\n---\n\n生成时间: 2026", encoding="utf-8")
        summary = {"enabled": True, "available": True, "sessions_checked": 1,
                   "findings": [], "unavailable": [], "note": AUDIT_NOTE}
        assert append_audit_crosscheck_section(str(report), summary) is True
        content = report.read_text(encoding="utf-8")
        assert "系统审计交叉校验（Windows 审计日志比对）" in content
        # 小节插在页脚「---」之前
        assert content.index(SECTION_TITLE) < content.index("\n---\n")
        # 幂等: 二次调用不重复追加
        assert append_audit_crosscheck_section(str(report), summary) is True
        assert report.read_text(encoding="utf-8") == content

    def test_append_missing_report(self, tmp_path):
        assert append_audit_crosscheck_section(
            str(tmp_path / "nope.md"), {"enabled": True}) is False
        assert append_audit_crosscheck_section(None, None) is False

    def test_install_on_report_exporter(self):
        """方法挂载到 ReportExporter，供 monitor_daemon 直接调用（幂等）。"""
        from observer_core.audit.report_exporter import ReportExporter
        assert install_on_report_exporter() is True
        assert hasattr(ReportExporter, "append_audit_crosscheck_section")
        # 幂等: 重复安装不报错不重复挂载
        assert install_on_report_exporter() is True
        # 实例方法与模块级函数行为一致
        exporter = ReportExporter.__new__(ReportExporter)
        assert exporter.append_audit_crosscheck_section(None, None) is False


if __name__ == "__main__":
    pytest.main([__file__, "-q"])