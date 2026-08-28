# -*- coding: utf-8 -*-
"""
test_test_report_cli_web.py — test_report 轻量测试报告模式的 CLI/Web 切换入口

覆盖 CLI 与 Web 两端新增的切换选项（复用既有 --no-rollup / enable_rollup 语义）：
1. CLI：observer daemon 子命令 --no-rollup 解析与转发（默认不传）
2. CLI：console.py daemon 菜单 testreport 短命令 → --no-rollup
3. Web 生命周期：MonitorLifecycleManager.start_monitor(no_rollup=...) 拼入子进程命令
4. Web API：POST /api/monitor/start body.no_rollup 透传 + 响应回显（默认关闭）

默认行为约束：未显式开启时各路径不出现 --no-rollup / no_rollup=True。
"""

import io
import os
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestObserverCliNoRollup(unittest.TestCase):
    """CLI 统一入口 observer.py：daemon 子命令 --no-rollup 透传。"""

    def _run_observer(self, argv):
        import observer
        with mock.patch("observer._cmd_daemon") as cmd_mock:
            cmd_mock.return_value = 0
            observer.main(argv)
        return cmd_mock

    def test_daemon_no_rollup_flag_forwarded(self):
        """--no-rollup 显式传入 → 透传给 monitor_daemon.py。"""
        cmd_mock = self._run_observer(["daemon", "--no-rollup"])
        self.assertTrue(cmd_mock.called)
        forwarded = cmd_mock.call_args[0][0]
        self.assertIn("--no-rollup", forwarded)

    def test_daemon_default_no_rollup_flag(self):
        """默认不带 --no-rollup → 透传参数不含该 flag（行为不变）。"""
        cmd_mock = self._run_observer(["daemon"])
        forwarded = cmd_mock.call_args[0][0]
        self.assertNotIn("--no-rollup", forwarded)

    def test_daemon_help_mentions_test_report(self):
        """--help 文案包含 test_report 轻量模式说明（交互可发现性）。"""
        import observer
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", ["observer.py", "daemon", "--help"]), \
                mock.patch("sys.stdout", buf):
            try:
                observer.main(["daemon", "--help"])
            except SystemExit:
                pass
        out = buf.getvalue()
        self.assertIn("test_report", out)
        self.assertIn("--no-rollup", out)


class TestConsoleDaemonTestReport(unittest.TestCase):
    """console.py 菜单层：daemon 域 testreport 短命令。"""

    def test_exec_daemon_testreport_forwards_no_rollup(self):
        """_exec_daemon('testreport') → _run_action('daemon', ['--no-rollup'], ...)。"""
        import console
        with mock.patch.object(console, "_env_gate", return_value=True), \
                mock.patch.object(console, "_run_action") as run_mock:
            console._exec_daemon("testreport")
        self.assertTrue(run_mock.called)
        which, argv = run_mock.call_args[0][0], run_mock.call_args[0][1]
        self.assertEqual(which, "daemon")
        self.assertIn("--no-rollup", argv)
        self.assertTrue(run_mock.call_args.kwargs.get("interruptable"))

    def test_exec_daemon_start_default_no_no_rollup(self):
        """start 短命令（默认路径）不带 --no-rollup。"""
        import console
        with mock.patch.object(console, "_env_gate", return_value=True), \
                mock.patch.object(console, "_run_action") as run_mock:
            console._exec_daemon("start")
        argv = run_mock.call_args[0][1]
        self.assertNotIn("--no-rollup", argv)


class TestLifecycleStartMonitorNoRollup(unittest.TestCase):
    """Web 生命周期：start_monitor 子进程命令组装。"""

    def setUp(self):
        from monitor_lifecycle import MonitorLifecycleManager
        self.mgr = MonitorLifecycleManager.instance()

    def _start(self, record=False, no_rollup=False):
        """mock 掉子进程/FIFO/轮询后调用 start_monitor，捕获 Popen 命令。"""
        self.mgr._lock = threading.RLock()  # 新锁，避免前次状态
        status_effects = [
            {"monitor_running": False},
            {"monitor_running": True, "monitor_pid": 999,
             "fifo_path": "/tmp/fifo", "fifo_exists": True},
        ]
        with mock.patch.object(self.mgr, "_check_status",
                               side_effect=status_effects), \
                mock.patch.object(self.mgr, "_clean_stale_pid_file"), \
                mock.patch.object(self.mgr, "_is_pid_alive", return_value=True), \
                mock.patch("os.path.isfile", return_value=True), \
                mock.patch("os.path.exists", return_value=False), \
                mock.patch("os.makedirs"), \
                mock.patch("os.mkfifo", create=True), \
                mock.patch("os.chmod"), \
                mock.patch("builtins.open", mock.mock_open(read_data="999")), \
                mock.patch("subprocess.Popen") as popen_mock, \
                mock.patch("time.sleep"):
            result = self.mgr.start_monitor(record=record,
                                            no_rollup=no_rollup)
        cmd = popen_mock.call_args[0][0]
        return result, cmd

    def test_start_monitor_no_rollup_and_record_cmd(self):
        """no_rollup=True 时子进程命令含 --no-rollup（与 --record 可组合）。"""
        result, cmd = self._start(record=True, no_rollup=True)
        self.assertTrue(result and result["monitor_running"])
        self.assertIn("--no-rollup", cmd)
        self.assertIn("--record", cmd)
        self.assertIn("--record-dir", cmd)

    def test_start_monitor_default_cmd_no_no_rollup(self):
        """默认（no_rollup=False）命令不含 --no-rollup（默认行为不变）。"""
        result, cmd = self._start()
        self.assertTrue(result and result["monitor_running"])
        self.assertNotIn("--no-rollup", cmd)
        self.assertNotIn("--record", cmd)


class TestAppMonitorStartNoRollup(unittest.TestCase):
    """Web API：POST /api/monitor/start body.no_rollup 透传与回显。"""

    def _handler(self):
        from app import ObserverHTTPHandler
        return ObserverHTTPHandler.__new__(ObserverHTTPHandler)

    def _call(self, body, running=False):
        import app
        h = self._handler()
        status = {"monitor_running": running, "monitor_pid": 123,
                  "fifo_path": "/f", "fifo_exists": True}
        result = {"monitor_running": True, "monitor_pid": 456,
                  "fifo_path": "/f", "fifo_exists": True}
        responses = []
        with mock.patch("app._platform_gate", return_value=(True, None)), \
                mock.patch.object(h, "_get_monitor_status",
                                  return_value=status), \
                mock.patch.object(h, "_ensure_monitor_running",
                                  return_value=result) as ensure_mock, \
                mock.patch.object(h, "_send_json",
                                  side_effect=lambda data, status_code=200:
                                  responses.append(data)), \
                mock.patch.object(h, "_send_error"):
            h._handle_monitor_start(body)
        return ensure_mock, responses

    def test_body_no_rollup_true_forwarded_and_echoed(self):
        """body {no_rollup: true} → start_monitor 收到 no_rollup=True，响应回显。"""
        ensure_mock, responses = self._call({"no_rollup": True})
        self.assertTrue(ensure_mock.call_args.kwargs["no_rollup"])
        self.assertTrue(responses[0]["no_rollup"])
        self.assertIn("test_report", responses[0]["message"])

    def test_body_no_rollup_false_default(self):
        """body {no_rollup: false}（默认）→ 透传 False，响应回显 False。"""
        ensure_mock, responses = self._call({"no_rollup": False})
        self.assertFalse(ensure_mock.call_args.kwargs["no_rollup"])
        self.assertFalse(responses[0]["no_rollup"])
        self.assertNotIn("test_report", responses[0]["message"])

    def test_body_empty_or_none_defaults_false(self):
        """body 缺失 / 空 dict / 非 dict → no_rollup 默认 False（防御）。"""
        for body in (None, {}, "not-json"):
            ensure_mock, responses = self._call(body)
            self.assertFalse(ensure_mock.call_args.kwargs["no_rollup"])
            self.assertFalse(responses[0]["no_rollup"])

    def test_already_running_echoes_no_rollup_no_restart(self):
        """Monitor 已运行：幂等返回，不调用 ensure（模式切换需先停止）。"""
        import app
        h = self._handler()
        responses = []
        with mock.patch("app._platform_gate", return_value=(True, None)), \
                mock.patch.object(h, "_get_monitor_status", return_value={
                    "monitor_running": True, "monitor_pid": 123,
                    "fifo_path": "/f", "fifo_exists": True}), \
                mock.patch.object(h, "_ensure_monitor_running") as ensure_mock, \
                mock.patch.object(h, "_send_json",
                                  side_effect=lambda data, status_code=200:
                                  responses.append(data)):
            h._handle_monitor_start({"no_rollup": True})
        self.assertFalse(ensure_mock.called)
        self.assertTrue(responses[0]["already_running"])
        self.assertTrue(responses[0]["no_rollup"])


if __name__ == "__main__":
    unittest.main()
