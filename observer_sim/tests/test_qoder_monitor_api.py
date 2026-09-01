# -*- coding: utf-8 -*-
"""
test_qoder_monitor_api.py — Qoder CN 监测前端/CLI 接入层测试（第二步）

覆盖:
1. qoder_report_gateway 配置读取（config.yaml mcp_report 段 → 结构化默认值）
2. 模拟注入 payload 构造（与 reporter build_report_payload 语义一致:
   PostToolUse→post / PreToolUse→pre / PostToolUseFailure→失败摘要）
3. 审计事件尾随读取（解析/计数/过滤/截断；轮询数据源，SSE 阶段复用）
4. 模拟注入端到端（live uvicorn 挂载 /api/hook-report → accepted 入 broker；
   畸形申报 → rejected 结构化原因；端点不可达 → unreachable 不抛异常）
5. app.py 处理器（missing_tool_name 拒绝 / events 参数解析 /
   SSE /api/qoder-monitor/events/stream 帧结构与同构性）
6. console.py qoder 域（主菜单项 / 子菜单渲染 / 预置注入序列）

不覆盖（如实说明）:
- daemon 真实启停（start/stop）依赖长驻子进程，由 P1 验收与手工冒烟覆盖；
- SSE 推送已实现，本文件验证 handler 帧结构与过滤/计数语义，
  生产长驻流由手工冒烟（curl -N）覆盖。
"""

import json
import os
import socket
import sys
import threading
import time

import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import qoder_report_gateway as gw  # noqa: E402


# ── 助手 ────────────────────────────────────────────────────────────

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(host, port, timeout=20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


# ── 1. 配置读取 ─────────────────────────────────────────────────────

class TestGatewayConfig:

    def test_load_config_reads_mcp_report_section(self):
        cfg = gw.load_config()
        assert cfg["agent_id"] == "qoder"
        assert cfg["framework"] == "qoder"
        assert isinstance(cfg["port"], int)
        hook = cfg["hook_ingest"]
        assert hook["enabled"] is True
        assert hook["path"] == "/api/hook-report"
        assert hook["agent_id_default"] == "qoder"

    def test_ingest_url_and_output_dir(self):
        cfg = gw.load_config()
        url = gw.ingest_url(cfg)
        assert url == (f"http://{cfg['host']}:{cfg['port']}"
                       f"{cfg['hook_ingest']['path']}")
        assert gw.output_dir(cfg).endswith(
            os.path.join("output", gw.OUTPUT_SUBDIR))

    def test_load_config_missing_file_falls_back(self, tmp_path):
        cfg = gw.load_config(str(tmp_path / "no_such.yaml"))
        assert cfg["host"] == gw.DEFAULT_HOST
        assert cfg["port"] == gw.DEFAULT_PORT
        assert cfg["agent_id"] == "qoder"


# ── 2. 模拟注入 payload 构造 ────────────────────────────────────────

class TestSimulatePayload:

    def test_post_tool_use_payload(self):
        payload, hook_event = gw.build_simulate_payload(
            "run_in_terminal", tool_args={"command": "ls"},
            session_id="sess-x")
        assert payload["tool_name"] == "run_in_terminal"
        assert payload["tool_args"] == {"command": "ls"}
        assert payload["session_id"] == "sess-x"
        assert payload["action_type"] == "post"
        assert payload["agent_id"] == "qoder"
        assert hook_event["hook_event_name"] == "PostToolUse"
        assert hook_event["tool_input"] == {"command": "ls"}

    def test_pre_tool_use_maps_to_pre(self):
        payload, _ = gw.build_simulate_payload(
            "read_file", hook_event_name="PreToolUse")
        assert payload["action_type"] == "pre"

    def test_failure_event_extracts_result(self):
        payload, _ = gw.build_simulate_payload(
            "run_in_terminal", hook_event_name="PostToolUseFailure",
            tool_response={"stderr": "boom"})
        assert payload["action_type"] == "post"
        assert payload["result"] == "boom"

    def test_non_dict_args_coerced(self):
        payload, hook_event = gw.build_simulate_payload(
            "read_file", tool_args="not-a-dict")
        assert payload["tool_args"] == {}
        assert hook_event["tool_input"] == {}


# ── 3. 审计事件尾随读取 ─────────────────────────────────────────────

def _write_audit(tmp_path, rows, filename=None):
    audit_dir = tmp_path / "output" / gw.OUTPUT_SUBDIR / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_dir / (filename or "audit_mcp_report_20260730.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return path


def _row(decision="allow", agent="qoder", rules=None, score=0.1,
         etype="exec", desc="run_in_terminal: ls"):
    return {"event_id": f"ev-{decision}-{time.time_ns()}",
            "agent_id": agent, "session_id": "sess-t",
            "event_type": etype, "timestamp_ns": time.time_ns(),
            "pid": 1, "description": desc,
            "command_string": "ls", "file_path": None,
            "matched_rules": rules or [],
            "decision_action": decision, "risk_score": score}


@pytest.fixture
def gw_tmp(tmp_path, monkeypatch):
    """把 gateway 的输出目录重定向到临时目录（避免污染真实 output）。"""
    monkeypatch.setattr(gw, "BASE_DIR", str(tmp_path))
    return tmp_path


class TestEventsFromAudit:

    def test_parse_counts_and_tail(self, gw_tmp):
        _write_audit(gw_tmp, [_row("allow"), _row("alert", rules=["R007"],
                                                   score=0.55),
                              _row("block", rules=["R002"], score=0.93)])
        r = gw.get_events(tail=50)
        assert r["counts"] == {"allow": 1, "alert": 1, "block": 1,
                               "total": 3}
        assert len(r["events"]) == 3
        ev = r["events"][-1]
        assert ev["decision_action"] == "block"
        assert ev["matched_rules"] == ["R002"]
        assert ev["risk_score"] == 0.93
        assert ev["session_id"] == "sess-t"

    def test_agent_and_decision_filter(self, gw_tmp):
        _write_audit(gw_tmp, [_row("allow", agent="qoder"),
                              _row("allow", agent="workbuddy"),
                              _row("block", agent="qoder", rules=["R001"])])
        r = gw.get_events(tail=50, agent_id="qoder")
        assert len(r["events"]) == 2
        assert r["counts"]["total"] == 3   # 计数不受过滤影响
        r2 = gw.get_events(tail=50, agent_id="qoder", decision="block")
        assert len(r2["events"]) == 1
        assert r2["events"][0]["decision_action"] == "block"

    def test_tail_limit_and_empty(self, gw_tmp):
        _write_audit(gw_tmp, [_row() for _ in range(5)])
        assert len(gw.get_events(tail=2)["events"]) == 2
        empty = gw.get_events(tail=10, agent_id="nobody")
        assert empty["events"] == []

    def test_no_audit_file_returns_empty(self, gw_tmp):
        r = gw.get_events(tail=10)
        assert r["events"] == [] and r["source"] is None
        assert r["counts"]["total"] == 0

    def test_sse_reserved_stream_generator_exists(self):
        """SSE 数据源: stream_events 增量生成器存在且可附着（已被 SSE 端点复用）。"""
        assert callable(gw.stream_events)
        gen = gw.stream_events(poll_interval=0.01)
        assert hasattr(gen, "__next__")
        gen.close()


# ── 4. 模拟注入端到端（live /api/hook-report）───────────────────────

class TestSimulateLive:

    def _start_server(self):
        pytest.importorskip("mcp")
        from mcp_bridge.server import McpReportBroker, run_server

        port = _free_port()
        broker = McpReportBroker()
        t = threading.Thread(
            target=run_server,
            kwargs={"host": "127.0.0.1", "port": port, "broker": broker,
                    "hook_ingest": {"enabled": True,
                                    "path": "/api/hook-report",
                                    "agent_id_default": "qoder"}},
            daemon=True)
        t.start()
        assert _wait_port("127.0.0.1", port), "server 未在超时内就绪"
        return port, broker

    def _patch_cfg(self, monkeypatch, port, enabled=True):
        cfg = {"host": "127.0.0.1", "port": port, "agent_id": "qoder",
               "framework": "qoder",
               "hook_ingest": {"enabled": enabled,
                               "path": "/api/hook-report",
                               "agent_id_default": "qoder"}}
        monkeypatch.setattr(gw, "load_config", lambda *a, **k: cfg)

    def test_simulate_accepted_enters_broker(self, monkeypatch):
        port, broker = self._start_server()
        self._patch_cfg(monkeypatch, port)
        r = gw.simulate("run_in_terminal",
                        tool_args={"command": "echo gateway-e2e"},
                        session_id="gw-e2e")
        assert r["sent"] is True
        assert r["status"] == "accepted"
        assert r["url"].endswith("/api/hook-report")
        record = broker.consume_nowait()
        assert record is not None
        assert record["payload"]["tool_name"] == "run_in_terminal"
        assert record["payload"]["session_id"] == "gw-e2e"
        assert record["payload"]["agent_id"] == "qoder"

    def test_simulate_rejected_with_reason(self, monkeypatch):
        port, broker = self._start_server()
        self._patch_cfg(monkeypatch, port)
        # 超大 tool_args → Validator check_size 拒绝（>64KB 报文上限）
        r = gw.simulate("read_file",
                        tool_args={"blob": "x" * 70000})
        assert r["sent"] is True
        assert r["status"] == "rejected"
        assert "too_large" in str(r["reason"])
        assert broker.consume_nowait() is None   # 未入队

    def test_simulate_unreachable_no_exception(self, monkeypatch):
        port = _free_port()   # 已关闭的端口
        self._patch_cfg(monkeypatch, port)
        r = gw.simulate("read_file", tool_args={"file_path": "/etc/hosts"},
                        timeout_s=1.0)
        assert r["sent"] is False
        assert r["status"] == "unreachable"
        assert r["payload"]["tool_name"] == "read_file"


# ── 5. app.py 处理器 ────────────────────────────────────────────────

class TestAppHandlers:

    def _make_handler(self):
        from app import ObserverHTTPHandler
        return ObserverHTTPHandler.__new__(ObserverHTTPHandler)

    def test_simulate_missing_tool_name_rejected(self):
        h = self._make_handler()
        sent = {}

        def fake_send_json(data, status=200):
            sent.update(data)
        h._send_json = fake_send_json
        h._handle_qoder_monitor_simulate({"tool_name": ""})
        assert sent["status"] == "rejected"
        assert sent["reason"] == "missing_tool_name"

    def test_events_handler_parses_params(self):
        h = self._make_handler()
        r = h._get_qoder_monitor_events(
            {"tail": ["5"], "agent_id": ["qoder"], "decision": ["block"]})
        assert "events" in r and "counts" in r
        assert set(r["counts"]) == {"allow", "alert", "block", "total"}

    def test_status_handler_shape(self):
        h = self._make_handler()
        r = h._get_qoder_monitor_status()
        assert "daemon_running" in r
        assert "tasks" in r and "start" in r["tasks"]
        assert "sse_reserved" in r          # SSE 预留说明存在

    def test_artifacts_handler_shape(self):
        h = self._make_handler()
        r = h._get_qoder_monitor_artifacts()
        assert "artifacts" in r and isinstance(r["artifacts"], list)


# ── 5b. SSE 事件流处理器（/api/qoder-monitor/events/stream）──────

def _sse_event(i, act="allow", agent="qoder", rules=None, score=0.1):
    """构造与轮询接口同构的事件对象（_parse_audit_line 输出字段）。"""
    return {
        "event_id": f"ev-{i}", "agent_id": agent, "session_id": "sess-t",
        "event_type": "exec", "description": f"cmd {i}",
        "command_string": f"ls {i}", "file_path": None,
        "matched_rules": rules or [], "decision_action": act,
        "decision_reason": "test", "risk_score": score,
        "risk_level": "LOW", "timestamp_ns": 1000 + i,
    }


class TestSSEStream:
    """GET /api/qoder-monitor/events/stream — SSE 帧结构验证。

    以有限生成器替换 stream_events（生产中不耗尽），验证:
    connected 首帧（history+counts）→ event 帧（逐条+计数累计）→ stream_end。
    """

    def _make_handler(self, events):
        from app import ObserverHTTPHandler
        h = ObserverHTTPHandler.__new__(ObserverHTTPHandler)
        frames = []
        # 模拟生产 _sse_send 的即时 JSON 序列化语义（快照而非引用）
        h._sse_send = lambda data: frames.append(json.loads(json.dumps(data)))
        h.send_response = lambda code: None
        h.send_header = lambda k, v: None
        h.end_headers = lambda: None
        h._send_cors_headers = lambda: None

        def _fake_get_events(tail=50, agent_id=None, decision=None):
            counts = {"allow": 0, "alert": 0, "block": 0, "total": 0}
            for ev in events:
                counts["total"] += 1
                a = str(ev.get("decision_action") or "").lower()
                if a in counts:
                    counts[a] += 1
            return {"events": events[-tail:], "counts": counts,
                    "source": "/tmp/audit_mcp_report_x.jsonl"}

        def _fake_stream_events(agent_id=None, poll_interval=0.5):
            yield from events

        class _FakeGW:
            get_events = staticmethod(_fake_get_events)
            stream_events = staticmethod(_fake_stream_events)

        h._qoder_gateway = lambda: _FakeGW()
        return h, frames

    def test_connected_frame_carries_history_and_counts(self):
        evs = [_sse_event(1, "allow"), _sse_event(2, "block",
               rules=["R001"], score=0.9)]
        h, frames = self._make_handler(evs)
        h._handle_sse_qoder_events_stream({})
        first = frames[0]
        assert first["type"] == "connected"
        assert first["counts"] == {"allow": 1, "alert": 0, "block": 1,
                                   "total": 2}
        assert len(first["history"]) == 2
        assert first["source"] == "audit_mcp_report_x.jsonl"

    def test_event_frames_isomorphic_with_counts_update(self):
        evs = [_sse_event(1, "allow"), _sse_event(2, "alert",
               rules=["R007"], score=0.55)]
        h, frames = self._make_handler(evs)
        h._handle_sse_qoder_events_stream({})
        # connected + 2 event + stream_end
        assert [f["type"] for f in frames] == \
            ["connected", "event", "event", "stream_end"]
        e1, e2 = frames[1], frames[2]
        assert e1["seq"] == 1 and e2["seq"] == 2
        # 事件对象与轮询接口同构（同一字段集）
        assert set(e1["event"]) == set(evs[0])
        assert e2["event"]["matched_rules"] == ["R007"]
        # counts 随增量累计更新（首帧 2 → 每条 +1）
        assert e1["counts"]["total"] == 3
        assert e2["counts"] == {"allow": 2, "alert": 2, "block": 0,
                                "total": 4}

    def test_decision_filter_skips_frames_but_counts_all(self):
        evs = [_sse_event(1, "allow"), _sse_event(2, "block",
               rules=["R002"])]
        h, frames = self._make_handler(evs)
        h._handle_sse_qoder_events_stream({"decision": ["block"]})
        ev_frames = [f for f in frames if f["type"] == "event"]
        assert len(ev_frames) == 1                     # 仅 block 帧推送
        assert ev_frames[0]["event"]["decision_action"] == "block"
        # counts 仍按未过滤全量累计（与 get_events 语义同构）
        assert ev_frames[0]["counts"]["total"] == \
            frames[0]["counts"]["total"] + 2

    def test_agent_id_filter(self):
        evs = [_sse_event(1, "allow", agent="qoder"),
               _sse_event(2, "allow", agent="workbuddy")]
        h, frames = self._make_handler(evs)
        h._handle_sse_qoder_events_stream({"agent_id": ["qoder"]})
        ev_frames = [f for f in frames if f["type"] == "event"]
        assert len(ev_frames) == 1
        assert ev_frames[0]["event"]["agent_id"] == "qoder"

    def test_empty_audit_still_sends_connected_and_end(self):
        h, frames = self._make_handler([])
        h._handle_sse_qoder_events_stream({})
        assert frames[0]["type"] == "connected"
        assert frames[0]["history"] == []
        assert frames[0]["counts"]["total"] == 0
        assert frames[-1]["type"] == "stream_end"


# ── 6. console.py qoder 域 ──────────────────────────────────────────

class TestConsoleQoderDomain:

    def test_main_menu_contains_qoder_domain(self):
        import console
        keys = [d[0] for d in console.DOMAINS]
        assert "qoder" in keys
        title = dict((d[0], d[1]) for d in console.DOMAINS)["qoder"]
        assert "Qoder CN" in title

    def test_render_domain_qoder(self, capsys):
        import console
        console._render_domain("qoder")
        out = capsys.readouterr().out
        assert "Qoder CN 监测" in out
        for token in ("start", "stop", "status", "events", "stream",
                      "simulate"):
            assert token in out

    def test_domain_help_contains_qoder(self, capsys):
        import console
        console._print_domain_help("qoder")
        out = capsys.readouterr().out
        assert "stream" in out and "simulate" in out

    def test_sim_presets_cover_required_tools(self):
        import console
        assert len(console._QODER_SIM_PRESETS) >= 5
        tools = [p[0] for p in console._QODER_SIM_PRESETS]
        assert "run_in_terminal" in tools
        assert "read_file" in tools

    def test_unknown_qoder_command_hint(self, capsys):
        import console
        console._exec_qoder("nosuch")
        out = capsys.readouterr().out
        assert "未知 qoder 命令" in out
