# -*- coding: utf-8 -*-
"""
test_monitor_lifecycle.py — MonitorLifecycleManager 进程管理系统测试

覆盖（A 档审查改动）:
1. _find_monitor_processes 模式过滤:
   - 仅匹配含 --fifo 的 FIFO 内置 Monitor 进程;
   - --mode mcp_report 的 Qoder CN / WorkBuddy daemon 被排除（防跨通道误杀）。
2. track_pid / untrack_pid:
   - 幂等注册/移除外部通道进程;
   - shutdown() 终止已追踪进程（真实 sleep 子进程验证）;
   - untrack 后 shutdown 不再触碰该进程。
"""

import os
import subprocess
import time
import unittest
from unittest import mock

from monitor_lifecycle import MonitorLifecycleManager


def _ps_result(lines):
    """构造 ps -eo pid,args 的 CompletedProcess mock 返回。"""
    return subprocess.CompletedProcess(
        args=["ps"], returncode=0, stdout="\n".join(lines) + "\n", stderr="")


class TestFindMonitorProcessesFilter(unittest.TestCase):
    """进程扫描模式过滤（防跨通道误杀）。"""

    def setUp(self):
        # 独立实例，避免污染全局单例状态
        self.mgr = MonitorLifecycleManager()

    def test_excludes_mcp_report_mode(self):
        """--mode mcp_report 的 monitor_daemon（qoder/workbuddy）不被匹配。"""
        lines = [
            "12345 /usr/bin/python3 monitor_daemon.py --mode mcp_report "
            "--config config.yaml --output output/qoder_monitoring",
            "23456 python observer.py daemon --mode mcp_report",
        ]
        with mock.patch("subprocess.run", return_value=_ps_result(lines)):
            self.assertEqual(self.mgr._find_monitor_processes(), [])

    def test_includes_fifo_monitor(self):
        """含 --fifo 的 FIFO 内置 Monitor 进程仍被匹配。"""
        lines = [
            "34567 /usr/bin/python3 monitor_daemon.py --fifo "
            "/x/.monitoring/pipe --output output/demo_monitoring "
            "--mode daemon --pid-file /x/.monitoring/monitor.pid",
        ]
        with mock.patch("subprocess.run", return_value=_ps_result(lines)):
            self.assertEqual(self.mgr._find_monitor_processes(), [34567])

    def test_mixed_only_fifo_kept(self):
        """混合进程表中仅保留 FIFO Monitor。"""
        lines = [
            "111 /usr/bin/python3 monitor_daemon.py --fifo /tmp/pipe "
            "--mode daemon",
            "222 /usr/bin/python3 monitor_daemon.py --mode mcp_report "
            "--output output/qoder_monitoring",
            "333 python app.py --port 8080",
        ]
        with mock.patch("subprocess.run", return_value=_ps_result(lines)):
            self.assertEqual(self.mgr._find_monitor_processes(), [111])

    def test_excludes_self_pid(self):
        """自身 PID 被排除（即使命令行含 monitor_daemon 字样）。"""
        lines = [f"{os.getpid()} python monitor_daemon.py --fifo /tmp/pipe"]
        with mock.patch("subprocess.run", return_value=_ps_result(lines)):
            self.assertEqual(self.mgr._find_monitor_processes(), [])


class TestTrackPid(unittest.TestCase):
    """外部通道进程追踪（qoder/workbuddy 网关注册入口）。"""

    def setUp(self):
        self.mgr = MonitorLifecycleManager()

    def test_track_pid_idempotent(self):
        self.mgr.track_pid(1234)
        self.mgr.track_pid(1234)
        self.assertEqual(self.mgr._tracked_pids.count(1234), 1)

    def test_track_pid_ignores_falsy(self):
        self.mgr.track_pid(0)
        self.mgr.track_pid(None)
        self.assertEqual(self.mgr._tracked_pids, [])

    def test_untrack_pid_removes(self):
        self.mgr.track_pid(1234)
        self.mgr.untrack_pid(1234)
        self.assertNotIn(1234, self.mgr._tracked_pids)
        # 重复移除不报错
        self.mgr.untrack_pid(1234)

    def test_shutdown_terminates_tracked_process(self):
        """注册到追踪列表的真实子进程随 shutdown() 终止。"""
        proc = subprocess.Popen(["sleep", "60"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            self.mgr.track_pid(proc.pid)
            self.mgr.shutdown()
            deadline = time.time() + 5
            alive = True
            while time.time() < deadline:
                try:
                    os.kill(proc.pid, 0)
                except OSError:
                    alive = False
                    break
                time.sleep(0.1)
            # 僵尸窗口内 /proc 状态为 Z 也算已终止
            if alive:
                try:
                    with open(f"/proc/{proc.pid}/stat") as f:
                        stat = f.read()
                    state = stat[stat.rfind(")") + 2]
                    alive = state != "Z"
                except OSError:
                    alive = False
            self.assertFalse(alive, "已追踪进程应随 shutdown() 终止")
            self.assertEqual(self.mgr._tracked_pids, [])
        finally:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:  # noqa: BLE001
                pass

    def test_untracked_process_survives_shutdown(self):
        """未注册的进程不受 shutdown() 影响（新通道未接入前的现状语义）。"""
        proc = subprocess.Popen(["sleep", "60"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        try:
            self.mgr.shutdown()  # 不注册该进程
            time.sleep(0.3)
            self.assertIsNone(proc.poll(), "未追踪进程不应被 shutdown 终止")
        finally:
            proc.kill()
            proc.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
