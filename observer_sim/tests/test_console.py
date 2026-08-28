"""
test_console.py — observer menu 命令行控制台（console.py 调度层）逻辑测试

测试内容:
1. 动作执行期间 KeyboardInterrupt → 打印"[已中断] 返回菜单"（回到菜单而非退出）
2. 长驻动作（serve/daemon/demo）以 interruptable=True 转发（可中断转发参数透传）
3. observer._forward interruptable 轮询版: 主线程收到 KeyboardInterrupt 后
   及时 terminate 子进程并重新抛出（模拟真实 Ctrl+C 的时序，用
   _thread.interrupt_main 在进程内注入 KeyboardInterrupt）
4. 主菜单等待输入时 Ctrl+C → 退出控制台
5. 子菜单等待输入时 Ctrl+C → 返回主菜单（而非退出）
6. 环境检测（会话级内存缓存 + 跨平台前置提醒分级拦截）:
   - 轻量/完整检测缓存与 env 强制重检
   - _env_gate: Windows 下 daemon/录制-回放 → 阻止；Linux 无 eBPF → 确认后继续
   - 主菜单状态行: 检测失败项标红（环境 ✗ N 项未过）

说明: Windows 真实键盘 Ctrl+C 的控制台事件广播无法在无控制台的管道测试
环境中自动模拟（GenerateConsoleCtrlEvent 实验证实环境限制），真实键盘
行为由 PowerShell 实机演示人工验收；本文件覆盖控制台进程内可测的
全部 Ctrl+C 处理路径。
"""

import contextlib
import io
import os
import sys
import tempfile
import threading
import time
import unittest
import _thread
from unittest import mock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

import console  # noqa: E402


class TestConsoleActionInterrupt(unittest.TestCase):
    """动作执行期间的 Ctrl+C（KeyboardInterrupt）处理路径。"""

    def test_action_keyboard_interrupt_prints_return_menu(self):
        """_run_action 捕获 KeyboardInterrupt 后打印中断提示（不抛出、不退出）。"""
        with mock.patch.object(console, "_call", side_effect=KeyboardInterrupt):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                console._run_action("serve", ["--no-browser"], note="test",
                                    interruptable=True)
        self.assertIn("[已中断] 返回菜单", buf.getvalue())

    def test_long_running_action_passes_interruptable_flag(self):
        """serve/daemon/demo 动作必须以 interruptable=True 转发（可中断）。"""
        with mock.patch.object(console, "_call") as m_call, \
                mock.patch.object(console, "_env_gate", return_value=True):
            m_call.return_value = 0
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                console._exec_serve("nb")
                console._exec_daemon("start")
                console._exec_demo("menu")
        flags = [c.kwargs.get("interruptable", False)
                 for c in m_call.call_args_list]
        self.assertTrue(all(flags), f"长驻动作应 interruptable=True: {flags}")

    def test_short_action_not_interruptable(self):
        """非长驻动作（如 files tree）不强制 interruptable。"""
        with mock.patch.object(console, "_call") as m_call:
            m_call.return_value = 0
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                console._exec_files(["tree"])
        self.assertFalse(
            m_call.call_args_list[0].kwargs.get("interruptable", False))


class TestObserverForwardInterruptable(unittest.TestCase):
    """observer._forward interruptable 轮询版: 中断时序验证。"""

    def test_interrupt_terminates_child_and_reraises(self):
        """主线程被 interrupt_main 注入 KeyboardInterrupt 后:
        轮询版 _forward 应终止长驻子进程并重新抛出（模拟真实 Ctrl+C）。"""
        import observer
        with tempfile.NamedTemporaryFile(
                "w", suffix=".py", delete=False,
                dir=BASE_DIR, encoding="utf-8") as f:
            f.write("import time\nwhile True:\n    time.sleep(0.5)\n")
            child_script = f.name
        try:
            timer = threading.Timer(1.5, _thread.interrupt_main)
            timer.start()
            started = time.time()
            with self.assertRaises(KeyboardInterrupt):
                observer._forward(child_script, [], interruptable=True)
            elapsed = time.time() - started
            self.assertLess(elapsed, 10, "中断响应过慢")
        finally:
            timer.cancel()
            os.unlink(child_script)

    def test_non_interruptable_forward_still_works(self):
        """非可中断转发（subprocess.call）保持原有行为。"""
        import observer
        with tempfile.NamedTemporaryFile(
                "w", suffix=".py", delete=False,
                dir=BASE_DIR, encoding="utf-8") as f:
            f.write("import sys\nsys.exit(3)\n")
            child_script = f.name
        try:
            rc = observer._forward(child_script, [], interruptable=False)
            self.assertEqual(rc, 3)
        finally:
            os.unlink(child_script)


class TestConsoleInputCtrlC(unittest.TestCase):
    """菜单等待输入期间的 Ctrl+C 处理路径（主菜单退出 / 子菜单返回）。"""

    def test_main_menu_ctrl_c_quits_console(self):
        """主菜单等待输入时 Ctrl+C → 打印提示并退出控制台（返回码 0）。"""
        with mock.patch.object(console, "_read_input",
                               side_effect=[KeyboardInterrupt]):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = console.run_console([])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("[Ctrl+C] 已退出控制台", out)

    def test_submenu_ctrl_c_returns_to_main_menu(self):
        """子菜单等待输入时 Ctrl+C → 返回主菜单；随后输入 0 正常退出。"""
        with mock.patch.object(
                console, "_read_input",
                side_effect=["1", KeyboardInterrupt, "0"]):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = console.run_console([])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("[Ctrl+C] 已返回主菜单", out)
        self.assertIn("已退出控制台", out)
        # 返回后主菜单再次渲染（标题出现 >= 2 次）
        self.assertGreaterEqual(out.count("方寸观察者 命令行控制台"), 2)

    def test_eof_input_treated_as_quit(self):
        """stdin 结束（管道喂入完毕，input 抛 EOFError）→ _read_input 返回 q。"""
        with mock.patch("console.input", side_effect=[EOFError]):
            self.assertEqual(console._read_input(), "q")


class TestConsoleEnv(unittest.TestCase):
    """环境检测（会话级内存缓存）与跨平台前置提醒分级拦截。"""

    def _platform(self, platform="windows", is_windows=True, is_linux=False,
                  has_ebpf=False, has_strace=False):
        from adapter.platform_detect import PlatformInfo
        return PlatformInfo(platform=platform, is_windows=is_windows,
                            is_linux=is_linux, has_ebpf=has_ebpf,
                            has_strace=has_strace)

    def test_env_light_cache_and_refresh(self):
        """轻量检测缓存: 重复调用返回同一对象；refresh=True 强制重新检测。"""
        console._ENV_CACHE["light"] = None
        first = console._env_light()
        second = console._env_light()
        self.assertIs(first, second, "轻量检测应命中会话级缓存")
        self.assertGreaterEqual(len(first), 1)
        refreshed = console._env_light(refresh=True)
        self.assertIsNot(refreshed, first, "refresh=True 应重新检测")
        self.assertEqual(len(refreshed), len(first))

    def test_env_full_cache_and_refresh(self):
        """完整检测缓存: 首次执行后缓存，env 动作 refresh 重新检测。"""
        console._ENV_CACHE["full"] = None
        first = console._env_full()
        self.assertIs(console._env_full(), first, "完整检测应命中缓存")
        self.assertGreaterEqual(len(first), 20, "完整检测应包含全部检查项")
        self.assertIsNot(console._env_full(refresh=True), first)

    def test_env_gate_blocks_daemon_on_windows(self):
        """Windows 下 daemon 依赖 FIFO 必然失败 → 红色提醒后阻止。"""
        with mock.patch.object(console, "_get_platform",
                               return_value=self._platform("windows")):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                allowed = console._env_gate("daemon")
        self.assertFalse(allowed)
        out = buf.getvalue()
        self.assertIn("[环境提醒]", out)
        self.assertIn("Windows 环境", out)
        self.assertIn("仅限 Linux 环境使用", out)
        self.assertIn("[已阻止]", out)

    def test_env_gate_blocks_record_replay_on_windows(self):
        """Windows 下录制-回放依赖 FIFO 架构必然失败 → 阻止。"""
        with mock.patch.object(console, "_get_platform",
                               return_value=self._platform("windows")):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                allowed = console._env_gate("record-replay")
        self.assertFalse(allowed)
        self.assertIn("[环境提醒]", buf.getvalue())

    def test_env_gate_linux_no_ebpf_confirm_continue(self):
        """Linux 无 eBPF 能力（软受限）→ 提示后 y 确认继续 / n 取消。"""
        plat = self._platform("linux", is_windows=False, is_linux=True,
                              has_ebpf=False, has_strace=True)
        with mock.patch.object(console, "_get_platform", return_value=plat), \
                mock.patch.object(console, "_confirm", return_value=True):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertTrue(console._env_gate("daemon"))
        self.assertIn("eBPF 能力", buf.getvalue())
        with mock.patch.object(console, "_get_platform", return_value=plat), \
                mock.patch.object(console, "_confirm", return_value=False):
            self.assertFalse(console._env_gate("daemon"))

    def test_env_gate_linux_with_ebpf_passes(self):
        """Linux 且 eBPF 可用 → 直接放行（无提醒）。"""
        plat = self._platform("linux", is_windows=False, is_linux=True,
                              has_ebpf=True, has_strace=True)
        with mock.patch.object(console, "_get_platform", return_value=plat):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertTrue(console._env_gate("daemon"))
        self.assertNotIn("[环境提醒]", buf.getvalue())

    def test_env_status_str_marks_failures(self):
        """轻量检测含失败项 → 状态行标红（环境 ✗ N 项未过）。"""
        items = [
            type("EnvItem", (), {"name": "平台", "passed": True})(),
            type("EnvItem", (), {"name": "关键文件", "passed": False})(),
            type("EnvItem", (), {"name": "关键文件2", "passed": False})(),
        ]
        with mock.patch.object(console, "_env_light", return_value=items):
            status = console._env_status_str()
        self.assertIn("环境 ✗ 2 项未过", status)
        with mock.patch.object(console, "_env_light",
                               return_value=items[:1]):
            self.assertIn("环境 ✓", console._env_status_str())

    def test_exec_env_prints_report_and_refreshes(self):
        """_exec_env 复用 check_env.print_report 渲染并刷新缓存。"""
        console._ENV_CACHE["full"] = None
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            console._exec_env()
        out = buf.getvalue()
        self.assertIn("环境预检", out)
        self.assertIn("检查汇总", out)
        self.assertIn("[完成] 返回菜单", out)
        self.assertIsNotNone(console._ENV_CACHE["full"],
                             "_exec_env 应填充完整检测缓存")


if __name__ == "__main__":
    unittest.main()
