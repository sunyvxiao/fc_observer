# -*- coding: utf-8 -*-
"""
test_mcp_report_mode.py — P4-9 mcp_report 模式接入单测

覆盖计划 P4-9 四项产出:
1. config.yaml mode 枚举 + mcp_report 配置段
2. 采集模式选择纳入（platform_detect 分支 / main.run_cli 转发）
3. check_env 增加 mcp SDK 可用性检测项
4. 统一入口挂载（observer daemon --mode mcp_report / monitor_daemon 分发）
"""

import os
import sys

import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


# ── 1. config.yaml 枚举 + 配置段 ────────────────────────────────────

def test_config_yaml_declares_mcp_report_mode():
    """config.yaml: mode 枚举注释含 mcp_report，且存在 mcp_report 配置段。

    当前接入目标为 Qoder CN（P0/P1）: framework=qoder、target_agent_id=qoder，
    并声明 hook_ingest 摄入配置（enabled/path/agent_id_default）。
    """
    import yaml

    cfg_path = os.path.join(BASE_DIR, "config.yaml")
    text = open(cfg_path, "r", encoding="utf-8").read()
    assert '"mcp_report"' in text  # mode 可选值注释

    cfg = yaml.safe_load(text)
    mcp = cfg.get("mcp_report")
    assert isinstance(mcp, dict)
    assert mcp.get("framework") == "qoder"
    assert mcp.get("target_agent_id") == "qoder"
    assert mcp.get("host") == "127.0.0.1"
    assert mcp.get("port") == 8765
    assert mcp.get("poll_timeout_s") == 0.2
    assert mcp.get("jsonl_dir") is None

    # P1: Hooks 确定性申报摄入配置契约（前端/CLI 对接点）
    hook = mcp.get("hook_ingest")
    assert isinstance(hook, dict)
    assert hook.get("path") == "/api/hook-report"
    assert isinstance(hook.get("enabled"), bool)
    assert hook.get("agent_id_default") == "qoder"


# ── 2. 采集模式选择纳入 ──────────────────────────────────────────────

def test_platform_detect_mcp_report_branch():
    """platform_detect: mode_override / config["mode"] 均能创建 McpReportCollector。"""
    from adapter.platform_detect import detect_and_create_collector
    from collector.mcp_report_collector import McpReportCollector

    col = detect_and_create_collector({"mode": "auto"}, mode_override="mcp_report")
    assert isinstance(col, McpReportCollector)

    col2 = detect_and_create_collector({"mode": "mcp_report"})
    assert isinstance(col2, McpReportCollector)


def test_run_cli_forwards_mcp_report_mode(monkeypatch, tmp_path):
    """main.run_cli --mode mcp_report 通过 choices 校验并转发到采集器工厂。"""
    import main

    monkeypatch.chdir(BASE_DIR)
    captured = {}

    def _fake_factory(config, mode_override=None):
        captured["mode"] = mode_override
        from collector.mcp_report_collector import McpReportCollector
        return McpReportCollector(config)

    monkeypatch.setattr(main, "detect_and_create_collector", _fake_factory)
    code = main.run_cli(["--scenario", "n01", "--mode", "mcp_report",
                         "--output", str(tmp_path / "out"),
                         "--config", "config.yaml"])
    assert code == 0
    assert captured["mode"] == "mcp_report"


def test_run_cli_rejects_unknown_mode(monkeypatch):
    """main.run_cli 非法 mode 被 argparse choices 拒绝。"""
    import main

    monkeypatch.chdir(BASE_DIR)
    with pytest.raises(SystemExit):
        main.run_cli(["--scenario", "n01", "--mode", "bogus_mode"])


# ── 3. check_env 检测项 ─────────────────────────────────────────────

def test_check_env_mcp_items():
    """check_env: MODULE_CHECKS/CRITICAL_FILES 覆盖 MCP 通道，mcp SDK 检测项可用。"""
    from check_env import (CRITICAL_FILES, MODULE_CHECKS, collect_modules,
                           collect_mcp_sdk)

    assert ("collector.mcp_report_collector", "McpReportCollector") in MODULE_CHECKS
    assert ("mcp_bridge.server", "create_server") in MODULE_CHECKS
    assert ("mcp_bridge.validation", "ReportValidator") in MODULE_CHECKS
    assert ("mcp_bridge.semantic_guard", "SemanticGuard") in MODULE_CHECKS
    assert "mcp_bridge/server.py" in CRITICAL_FILES
    assert "collector/mcp_report_collector.py" in CRITICAL_FILES

    # 模块导入检查全部通过（环境已安装 mcp SDK）
    items = collect_modules()
    assert len(items) == len(MODULE_CHECKS)
    assert all(i.passed for i in items), [
        i.name for i in items if not i.passed]

    mcp_items = collect_mcp_sdk()
    assert len(mcp_items) == 1
    assert mcp_items[0].name == "mcp SDK (mcp_report 模式)"
    assert mcp_items[0].passed


# ── 4. 统一入口挂载 ─────────────────────────────────────────────────

def test_observer_daemon_mode_choices_include_mcp_report():
    """observer daemon --mode 接受 mcp_report，非法值被拒绝。"""
    import observer

    parser = observer._build_parser()
    args = parser.parse_args(["daemon", "--mode", "mcp_report"])
    assert args.mode == "mcp_report"

    with pytest.raises(SystemExit):
        parser.parse_args(["daemon", "--mode", "bogus"])


def test_monitor_daemon_main_dispatches_mcp_report(monkeypatch):
    """monitor_daemon.main --mode mcp_report 分发到 run_monitor_mcp_report。"""
    import monitor_daemon

    calls = {}

    def _fake_run_mcp(output_dir, config_path="config.yaml",
                      enable_rollup=None):
        calls["mcp"] = output_dir
        calls["enable_rollup"] = enable_rollup
        return 42

    monkeypatch.setattr(monitor_daemon, "run_monitor_mcp_report", _fake_run_mcp)
    monkeypatch.setattr(monitor_daemon, "run_monitor",
                        lambda *a, **k: calls.setdefault("fifo", k.get("mode")))
    # 避免在 pytest 主进程覆盖信号处理器
    monkeypatch.setattr(monitor_daemon.signal, "signal",
                        lambda *a, **k: None)
    monkeypatch.setattr(sys, "argv",
                        ["monitor_daemon.py", "--mode", "mcp_report"])

    assert monitor_daemon.main() == 42
    assert "mcp" in calls
    assert calls["enable_rollup"] is None  # 未传 --no-rollup 时不显式关闭


def test_monitor_daemon_main_rejects_unknown_mode(monkeypatch):
    """monitor_daemon --mode 非法值被 argparse choices 拒绝。"""
    import monitor_daemon

    monkeypatch.setattr(sys, "argv",
                        ["monitor_daemon.py", "--mode", "bogus"])
    with pytest.raises(SystemExit):
        monitor_daemon.main()


def test_run_monitor_mcp_report_requires_sdk(monkeypatch, tmp_path):
    """mcp SDK 缺失时 run_monitor_mcp_report 返回 1（含配置缺失降级路径）。"""
    import monitor_daemon
    import mcp_bridge.server as ms

    monkeypatch.setattr(ms, "mcp_sdk_available", lambda: False)
    # 正常配置路径
    assert monitor_daemon.run_monitor_mcp_report(str(tmp_path)) == 1
    # 配置缺失降级路径（使用默认值，仍先检测 SDK）
    assert monitor_daemon.run_monitor_mcp_report(
        str(tmp_path),
        config_path=str(tmp_path / "nonexist.yaml")) == 1


def test_handle_signal_windows_safe(monkeypatch):
    """Windows 无 SIGUSR1: _handle_signal 不抛 AttributeError 且 detach mcp collector。"""
    import signal as sig
    import monitor_daemon

    class _FakeCollector:
        def __init__(self):
            self.detached = False

        def detach(self):
            self.detached = True

    fake = _FakeCollector()
    monkeypatch.setattr(monitor_daemon, "_monitor_instance", None)
    monkeypatch.setattr(monitor_daemon, "_running", True)
    monkeypatch.setattr(monitor_daemon, "_mcp_collector", fake)

    monitor_daemon._handle_signal(sig.SIGINT, None)
    assert monitor_daemon._running is False
    assert fake.detached is True
