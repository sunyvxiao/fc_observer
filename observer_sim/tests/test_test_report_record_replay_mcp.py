# -*- coding: utf-8 -*-
"""
test_test_report_record_replay_mcp.py — test_report 轻量测试报告模式的
录制/回放与 MCP 申报入口切换选项（复用既有 --no-rollup / enable_rollup 语义）。

覆盖范围：
1. CLI：observer daemon --record --no-rollup 组合透传（默认不传）
2. CLI：console.py daemon 域 record-testreport 短命令
3. CLI：console.py mcp 域 start-testreport 短命令 → connect_workbuddy start --no-rollup
4. CLI：record_and_replay.py --no-rollup flag（录制/回放两分支透传）
5. Web：_handle_sse_replay / _handle_sse_record_start_only 的 no_rollup 解析与透传
6. Web：_handle_mcp_report_start body.no_rollup → gateway.start(no_rollup=...)
7. MCP：mcp_report_gateway.start / connect_workbuddy._watch / cmd_start 命令组装

默认行为约束：未显式开启时各路径不出现 --no-rollup / no_rollup=True。
"""

import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestObserverCliRecordNoRollup(unittest.TestCase):
    """CLI 统一入口 observer.py：daemon 子命令 --record --no-rollup 组合。"""

    def _run_observer(self, argv):
        import observer
        with mock.patch("observer._cmd_daemon") as cmd_mock:
            cmd_mock.return_value = 0
            observer.main(argv)
        return cmd_mock

    def test_daemon_record_no_rollup_forwarded(self):
        """--record --no-rollup 组合 → 两个 flag 均透传给 monitor_daemon.py。"""
        cmd_mock = self._run_observer(["daemon", "--record", "--no-rollup"])
        self.assertTrue(cmd_mock.called)
        forwarded = cmd_mock.call_args[0][0]
        self.assertIn("--no-rollup", forwarded)
        self.assertIn("--record", forwarded)

    def test_daemon_record_default_no_no_rollup(self):
        """仅 --record（默认路径）→ 透传参数不含 --no-rollup。"""
        cmd_mock = self._run_observer(["daemon", "--record"])
        forwarded = cmd_mock.call_args[0][0]
        self.assertIn("--record", forwarded)
        self.assertNotIn("--no-rollup", forwarded)


class TestConsoleRecordTestreport(unittest.TestCase):
    """console.py 菜单层：daemon 域 record-testreport 短命令。"""

    def test_exec_daemon_record_testreport(self):
        """_exec_daemon('record-testreport') → ('daemon', ['--record', '--no-rollup'])。"""
        import console
        with mock.patch.object(console, "_env_gate", return_value=True), \
                mock.patch.object(console, "_run_action") as run_mock:
            console._exec_daemon("record-testreport")
        self.assertTrue(run_mock.called)
        which, argv = run_mock.call_args[0][0], run_mock.call_args[0][1]
        self.assertEqual(which, "daemon")
        self.assertEqual(argv, ["--record", "--no-rollup"])
        self.assertTrue(run_mock.call_args.kwargs.get("interruptable"))

    def test_exec_daemon_record_default_no_no_rollup(self):
        """record 短命令（默认路径）不含 --no-rollup。"""
        import console
        with mock.patch.object(console, "_env_gate", return_value=True), \
                mock.patch.object(console, "_run_action") as run_mock:
            console._exec_daemon("record")
        argv = run_mock.call_args[0][1]
        self.assertEqual(argv, ["--record"])
        self.assertNotIn("--no-rollup", argv)

    def test_daemon_menu_option_5_record_testreport(self):
        """daemon 域菜单输入数字 5 → record-testreport。"""
        import console
        with mock.patch.object(console, "_exec_daemon") as exec_mock:
            nav = console._dispatch_domain("daemon", "5")
        self.assertIsNone(nav)
        exec_mock.assert_called_once_with("record-testreport")


class TestConsoleMcpStartTestreport(unittest.TestCase):
    """console.py mcp 域：start-testreport 短命令转发。"""

    def test_exec_mcp_start_testreport(self):
        """_exec_mcp('start-testreport') → connect_workbuddy.py start --no-rollup。"""
        import console
        with mock.patch.object(console.subprocess, "call", return_value=0) as call_mock:
            console._exec_mcp("start-testreport")
        self.assertTrue(call_mock.called)
        argv = call_mock.call_args[0][0]
        self.assertEqual(argv[-2:], ["start", "--no-rollup"])
        self.assertTrue(argv[-3].endswith("connect_workbuddy.py"))

    def test_exec_mcp_start_default_no_no_rollup(self):
        """start 短命令（默认路径）不附加 --no-rollup。"""
        import console
        with mock.patch.object(console.subprocess, "call", return_value=0) as call_mock:
            console._exec_mcp("start")
        argv = call_mock.call_args[0][0]
        self.assertEqual(argv[-1], "start")
        self.assertNotIn("--no-rollup", argv)

    def test_start_testreport_in_subcommands(self):
        """start-testreport 已注册到 mcp 域可用命令表。"""
        import console
        self.assertIn("start-testreport", console._MCP_SUBCOMMANDS)

    def test_mcp_menu_option_8_start_testreport(self):
        """mcp 域菜单输入数字 8 → start-testreport。"""
        import console
        with mock.patch.object(console, "_exec_mcp") as exec_mock:
            nav = console._dispatch_domain("mcp", "8")
        self.assertIsNone(nav)
        exec_mock.assert_called_once_with("start-testreport")


class TestRecordAndReplayNoRollup(unittest.TestCase):
    """record_and_replay.py：--no-rollup flag 与 _start_monitor 透传。"""

    def test_start_monitor_forward_no_rollup(self):
        import record_and_replay as rr
        mgr_mock = mock.MagicMock()
        mgr_mock.start_monitor.return_value = {"monitor_running": True}
        with mock.patch.object(rr.MonitorLifecycleManager, "instance",
                               return_value=mgr_mock):
            ok = rr._start_monitor(record=True, no_rollup=True)
        self.assertTrue(ok)
        mgr_mock.start_monitor.assert_called_once_with(record=True,
                                                       no_rollup=True)

    def test_start_monitor_default_no_no_rollup(self):
        import record_and_replay as rr
        mgr_mock = mock.MagicMock()
        mgr_mock.start_monitor.return_value = {"monitor_running": True}
        with mock.patch.object(rr.MonitorLifecycleManager, "instance",
                               return_value=mgr_mock):
            rr._start_monitor(record=False)
        mgr_mock.start_monitor.assert_called_once_with(record=False,
                                                       no_rollup=False)

    def _run_main(self, argv, mode="replay"):
        import record_and_replay as rr
        with mock.patch.object(sys, "argv", ["record_and_replay.py"] + argv), \
                mock.patch.object(rr.os, "chdir"), \
                mock.patch.object(rr.os.path, "isfile", return_value=True), \
                mock.patch.object(rr, "_start_monitor", return_value=True) as sm, \
                mock.patch.object(rr, "_run_agent_sim") as ras, \
                mock.patch.object(rr, "_wait_for_report"), \
                mock.patch.object(rr, "_print_report"), \
                mock.patch.object(rr, "_stop_monitor"), \
                mock.patch.object(rr, "_find_latest_recording",
                                  return_value="records/x/events.jsonl"), \
                mock.patch.object(rr.time, "sleep"):
            rr.main()
        return sm

    def test_main_replay_no_rollup_flag(self):
        """--replay-only --no-rollup → 回放分支透传 no_rollup=True。"""
        sm = self._run_main(["--replay-only", "f.jsonl", "--no-rollup"])
        sm.assert_called_once_with(record=False, no_rollup=True)

    def test_main_replay_default_no_no_rollup(self):
        """--replay-only 默认 → no_rollup=False。"""
        sm = self._run_main(["--replay-only", "f.jsonl"])
        sm.assert_called_once_with(record=False, no_rollup=False)

    def test_main_record_no_rollup_flag(self):
        """录制模式 + --no-rollup → record=True, no_rollup=True。"""
        sm = self._run_main(["--scenario", "s.yaml", "--no-rollup"])
        sm.assert_called_once_with(record=True, no_rollup=True)

    def test_main_record_default_no_no_rollup(self):
        """录制模式默认 → record=True, no_rollup=False。"""
        sm = self._run_main(["--scenario", "s.yaml"])
        sm.assert_called_once_with(record=True, no_rollup=False)


class TestAppRecordReplayMcpNoRollup(unittest.TestCase):
    """app.py Web API：录制/回放/MCP 启动的 no_rollup 透传。"""

    def _new_handler(self):
        from app import ObserverHTTPHandler
        h = ObserverHTTPHandler.__new__(ObserverHTTPHandler)
        h._sse_send = mock.MagicMock()
        h._send_json = mock.MagicMock()
        h._send_error = mock.MagicMock()
        h._ensure_monitor_running = mock.MagicMock(
            return_value={"monitor_running": True, "monitor_pid": 999})
        h._wait_and_stream_monitor_events = mock.MagicMock()
        h._get_monitor_report = mock.MagicMock(
            return_value={"available": False, "summary": {}})
        h._get_monitor_status = mock.MagicMock(
            return_value={"monitor_running": False})
        h.send_response = mock.MagicMock()
        h.send_header = mock.MagicMock()
        h._send_cors_headers = mock.MagicMock()
        h.end_headers = mock.MagicMock()
        return h

    def _sse_sent(self, h):
        return [c[0][0] for c in h._sse_send.call_args_list]

    def test_sse_replay_forward_no_rollup(self):
        from app import MonitorLifecycleManager
        h = self._new_handler()
        with mock.patch("app._platform_gate", return_value=(True, None)), \
                mock.patch("app.os.path.isdir", return_value=True), \
                mock.patch("app.os.path.isfile", return_value=True), \
                mock.patch("builtins.open",
                           mock.mock_open(read_data="a\nb\n")), \
                mock.patch("app.subprocess.run") as run_mock, \
                mock.patch("app.time.sleep"), \
                mock.patch.object(MonitorLifecycleManager, "instance"):
            h._handle_sse_replay("sess123", True)
        h._ensure_monitor_running.assert_called_once_with(no_rollup=True)
        replay_start = next(m for m in self._sse_sent(h)
                            if m.get("type") == "replay_start")
        self.assertTrue(replay_start["no_rollup"])

    def test_sse_replay_default_no_rollup(self):
        from app import MonitorLifecycleManager
        h = self._new_handler()
        with mock.patch("app._platform_gate", return_value=(True, None)), \
                mock.patch("app.os.path.isdir", return_value=True), \
                mock.patch("app.os.path.isfile", return_value=True), \
                mock.patch("builtins.open",
                           mock.mock_open(read_data="a\nb\n")), \
                mock.patch("app.subprocess.run"), \
                mock.patch("app.time.sleep"), \
                mock.patch.object(MonitorLifecycleManager, "instance"):
            h._handle_sse_replay("sess123")
        h._ensure_monitor_running.assert_called_once_with(no_rollup=False)

    def test_sse_record_start_only_forward_no_rollup(self):
        from app import MonitorLifecycleManager
        h = self._new_handler()
        with mock.patch("app._platform_gate", return_value=(True, None)), \
                mock.patch("app.glob.glob", return_value=[]), \
                mock.patch("app.time.sleep"), \
                mock.patch.object(MonitorLifecycleManager, "instance"):
            h._handle_sse_record_start_only(True)
        h._ensure_monitor_running.assert_called_once_with(record=True,
                                                          no_rollup=True)
        started = next(m for m in self._sse_sent(h)
                       if m.get("type") == "recording_started")
        self.assertTrue(started["no_rollup"])

    def test_sse_record_start_only_default_no_rollup(self):
        from app import MonitorLifecycleManager
        h = self._new_handler()
        with mock.patch("app._platform_gate", return_value=(True, None)), \
                mock.patch("app.glob.glob", return_value=[]), \
                mock.patch("app.time.sleep"), \
                mock.patch.object(MonitorLifecycleManager, "instance"):
            h._handle_sse_record_start_only()
        h._ensure_monitor_running.assert_called_once_with(record=True,
                                                          no_rollup=False)

    def test_mcp_report_start_forward_no_rollup(self):
        h = self._new_handler()
        gw = mock.MagicMock()
        gw.run_task.return_value = True
        h._mcp_gateway = mock.MagicMock(return_value=gw)
        h._handle_mcp_report_start({"no_rollup": True})
        gw.run_task.assert_called_once()
        fn = gw.run_task.call_args[0][1]
        fn()
        gw.start.assert_called_once_with(no_rollup=True)
        payload = h._send_json.call_args[0][0]
        self.assertTrue(payload["no_rollup"])

    def test_mcp_report_start_default_no_rollup(self):
        h = self._new_handler()
        gw = mock.MagicMock()
        gw.run_task.return_value = True
        h._mcp_gateway = mock.MagicMock(return_value=gw)
        h._handle_mcp_report_start()
        fn = gw.run_task.call_args[0][1]
        fn()
        gw.start.assert_called_once_with(no_rollup=False)
        payload = h._send_json.call_args[0][0]
        self.assertFalse(payload["no_rollup"])

    def test_mcp_report_start_non_json_body_default(self):
        """防御：body 为字符串时按默认 False 处理。"""
        h = self._new_handler()
        gw = mock.MagicMock()
        gw.run_task.return_value = True
        h._mcp_gateway = mock.MagicMock(return_value=gw)
        h._handle_mcp_report_start("not-json")
        fn = gw.run_task.call_args[0][1]
        fn()
        gw.start.assert_called_once_with(no_rollup=False)


class TestGatewayStartNoRollup(unittest.TestCase):
    """mcp_report_gateway.start：Popen 命令组装透传。"""

    def _cfg(self):
        return {"server": {"host": "127.0.0.1", "port": 8099,
                          "sse_path": "/sse"},
                "observer": {"python": "python"},
                "daemon": {"ready_timeout_s": "30"}}

    def _patch_gateway(self, no_rollup):
        import mcp_report_gateway as g
        with mock.patch.object(g, "load_cfg", return_value=self._cfg()), \
                mock.patch.object(g.cw, "_out_paths",
                                  return_value=("out", "pid", "log", "stop")), \
                mock.patch.object(g.cw, "_daemon_alive", return_value=False), \
                mock.patch.object(g.cw, "_port_open", return_value=False), \
                mock.patch.object(g.cw, "_wait_port", return_value=True), \
                mock.patch("os.makedirs"), \
                mock.patch("subprocess.Popen") as popen_mock:
            result = g.start(no_rollup=no_rollup)
        return popen_mock, result

    def test_start_with_no_rollup(self):
        popen_mock, result = self._patch_gateway(True)
        self.assertTrue(result["success"])
        cmd = popen_mock.call_args[0][0]
        self.assertIn("--internal-watch", cmd)
        self.assertIn("--no-rollup", cmd)

    def test_start_default_no_no_rollup(self):
        popen_mock, result = self._patch_gateway(False)
        self.assertTrue(result["success"])
        cmd = popen_mock.call_args[0][0]
        self.assertNotIn("--no-rollup", cmd)


class TestConnectWorkbuddyNoRollup(unittest.TestCase):
    """connect_workbuddy.py：--no-rollup flag 解析与命令组装透传。"""

    def test_main_internal_watch_no_rollup(self):
        import connect_workbuddy as cwb
        with mock.patch.object(cwb, "load_config", return_value={}), \
                mock.patch.object(cwb, "_watch", return_value=0) as watch_mock:
            cwb.main(["--internal-watch", "--no-rollup"])
        watch_mock.assert_called_once()
        self.assertTrue(watch_mock.call_args.kwargs["no_rollup"])

    def test_main_internal_watch_default_no_no_rollup(self):
        import connect_workbuddy as cwb
        with mock.patch.object(cwb, "load_config", return_value={}), \
                mock.patch.object(cwb, "_watch", return_value=0) as watch_mock:
            cwb.main(["--internal-watch"])
        self.assertFalse(watch_mock.call_args.kwargs["no_rollup"])

    def test_main_start_subcommand_no_rollup(self):
        import connect_workbuddy as cwb
        with mock.patch.object(cwb, "load_config", return_value={}), \
                mock.patch.object(cwb, "cmd_start", return_value=0) as cs_mock:
            cwb.main(["start", "--no-rollup"])
        cs_mock.assert_called_once()
        self.assertTrue(cs_mock.call_args.kwargs["no_rollup"])

    def test_main_start_subcommand_default_no_no_rollup(self):
        import connect_workbuddy as cwb
        with mock.patch.object(cwb, "load_config", return_value={}), \
                mock.patch.object(cwb, "cmd_start", return_value=0) as cs_mock:
            cwb.main(["start"])
        self.assertFalse(cs_mock.call_args.kwargs["no_rollup"])

    def test_watch_forwards_no_rollup_to_observer_daemon(self):
        import connect_workbuddy as cwb
        cfg = {"observer": {"python": "python", "output_dir": "out",
                            "project_dir": "proj"}}
        proc = mock.MagicMock()
        proc.poll.return_value = 0
        proc.returncode = 0
        with mock.patch.object(cwb, "_out_paths",
                               return_value=("out", "pid.json", "log", "stop")), \
                mock.patch.object(cwb, "_prepare_config",
                                  return_value=({}, None)), \
                mock.patch("os.makedirs"), \
                mock.patch("os.path.exists", return_value=False), \
                mock.patch("os.remove"), \
                mock.patch("builtins.open", mock.mock_open()), \
                mock.patch("subprocess.Popen", return_value=proc) as popen_mock, \
                mock.patch("time.sleep"), \
                mock.patch("json.dump"):
            rc = cwb._watch(cfg, no_rollup=True)
        self.assertIn(rc, (0, None))
        args = popen_mock.call_args[0][0]
        self.assertIn("observer.py", args)
        self.assertIn("--no-rollup", args)

    def test_watch_default_no_no_rollup(self):
        import connect_workbuddy as cwb
        cfg = {"observer": {"python": "python", "output_dir": "out",
                            "project_dir": "proj"}}
        proc = mock.MagicMock()
        proc.poll.return_value = 0
        with mock.patch.object(cwb, "_out_paths",
                               return_value=("out", "pid.json", "log", "stop")), \
                mock.patch.object(cwb, "_prepare_config",
                                  return_value=({}, None)), \
                mock.patch("os.makedirs"), \
                mock.patch("os.path.exists", return_value=False), \
                mock.patch("os.remove"), \
                mock.patch("builtins.open", mock.mock_open()), \
                mock.patch("subprocess.Popen", return_value=proc) as popen_mock, \
                mock.patch("time.sleep"), \
                mock.patch("json.dump"):
            cwb._watch(cfg)
        args = popen_mock.call_args[0][0]
        self.assertNotIn("--no-rollup", args)

    def test_cmd_start_forwards_no_rollup(self):
        import connect_workbuddy as cwb
        cfg = {"observer": {"python": "python", "output_dir": "out",
                            "project_dir": "proj"},
               "server": {"host": "127.0.0.1", "port": 8099,
                          "sse_path": "/sse"},
               "daemon": {"ready_timeout_s": "30"}}
        with mock.patch.object(cwb, "_out_paths",
                               return_value=("out", "pid.json", "log", "stop")), \
                mock.patch.object(cwb, "_daemon_alive", return_value=False), \
                mock.patch.object(cwb, "_port_open", return_value=False), \
                mock.patch("os.makedirs"), \
                mock.patch.object(cwb, "_wait_port", return_value=True), \
                mock.patch("subprocess.Popen") as popen_mock:
            rc = cwb.cmd_start(cfg, no_rollup=True)
        self.assertEqual(rc, 0)
        cmd = popen_mock.call_args[0][0]
        self.assertIn("--internal-watch", cmd)
        self.assertIn("--no-rollup", cmd)

    def test_cmd_start_default_no_no_rollup(self):
        import connect_workbuddy as cwb
        cfg = {"observer": {"python": "python", "output_dir": "out",
                            "project_dir": "proj"},
               "server": {"host": "127.0.0.1", "port": 8099,
                          "sse_path": "/sse"},
               "daemon": {"ready_timeout_s": "30"}}
        with mock.patch.object(cwb, "_out_paths",
                               return_value=("out", "pid.json", "log", "stop")), \
                mock.patch.object(cwb, "_daemon_alive", return_value=False), \
                mock.patch.object(cwb, "_port_open", return_value=False), \
                mock.patch("os.makedirs"), \
                mock.patch.object(cwb, "_wait_port", return_value=True), \
                mock.patch("subprocess.Popen") as popen_mock:
            cwb.cmd_start(cfg)
        cmd = popen_mock.call_args[0][0]
        self.assertNotIn("--no-rollup", cmd)


if __name__ == "__main__":
    unittest.main()
