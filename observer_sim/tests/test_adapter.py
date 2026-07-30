"""
test_adapter.py — 适配层单元测试

测试内容:
1. PlatformInfo.detect(): 平台检测分支覆盖
2. _check_ebpf_capability(): Windows 上返回 False
3. detect_and_create_collector(): 模式选择工厂（simulation / auto / ebpf / strace）
4. PipeAdapter.create(): 管道工厂（Windows / Linux）
5. WindowsPipeAdapter: 初始化 + 配置读取
6. LinuxFifoAdapter: 初始化 + 配置读取
7. VirtualClockSource: 虚拟时钟源
8. RealtimeClockSource: 真实时钟源
"""

import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from adapter.platform_detect import PlatformInfo, _check_ebpf_capability, detect_and_create_collector
from adapter.pipe_factory import PipeAdapter, WindowsPipeAdapter, LinuxFifoAdapter
from adapter.time_source import TimeSource, VirtualClockSource, RealtimeClockSource


class TestPlatformInfo(unittest.TestCase):
    """平台检测测试"""

    def test_detect_returns_platform_info(self):
        """detect() 返回 PlatformInfo 实例"""
        info = PlatformInfo.detect()
        self.assertIsInstance(info, PlatformInfo)
        self.assertIn(info.platform, ("windows", "linux", sys.platform))
        self.assertIsInstance(info.is_windows, bool)
        self.assertIsInstance(info.is_linux, bool)
        self.assertIsInstance(info.has_ebpf, bool)
        self.assertIsInstance(info.has_strace, bool)

    @patch('adapter.platform_detect.sys')
    def test_detect_windows(self, mock_sys):
        """Windows 平台检测"""
        mock_sys.platform = "win32"
        info = PlatformInfo.detect()
        self.assertTrue(info.is_windows)
        self.assertFalse(info.is_linux)
        self.assertFalse(info.has_ebpf)
        self.assertEqual(info.platform, "windows")

    def test_ebpf_capability_on_windows(self):
        """Windows 上 eBPF 能力检查返回 False"""
        if sys.platform == "win32":
            self.assertFalse(_check_ebpf_capability())


class TestDetectAndCreateCollector(unittest.TestCase):
    """Collector 工厂函数测试"""

    def test_simulation_mode(self):
        """mode=simulation 创建 SimulationCollector"""
        config = {"mode": "simulation", "virtual_clock": {"start_ns": 0}}
        collector = detect_and_create_collector(config)
        from collector.simulation_collector import SimulationCollector
        self.assertIsInstance(collector, SimulationCollector)

    def test_mode_override_takes_priority(self):
        """mode_override 优先于 config["mode"]"""
        config = {"mode": "ebpf", "virtual_clock": {"start_ns": 0}}
        # mode_override=simulation 应覆盖 config 中的 ebpf
        collector = detect_and_create_collector(config, mode_override="simulation")
        from collector.simulation_collector import SimulationCollector
        self.assertIsInstance(collector, SimulationCollector)

    def test_ebpf_mode_on_windows_raises(self):
        """Windows 上强制 ebpf 模式应抛异常"""
        if sys.platform == "win32":
            config = {"mode": "ebpf"}
            with self.assertRaises(RuntimeError) as ctx:
                detect_and_create_collector(config)
            self.assertIn("Linux", str(ctx.exception))

    def test_strace_mode_on_windows_raises(self):
        """Windows 上强制 strace 模式应抛异常"""
        if sys.platform == "win32":
            config = {"mode": "strace"}
            with self.assertRaises(RuntimeError) as ctx:
                detect_and_create_collector(config)
            self.assertIn("Linux", str(ctx.exception))

    def test_auto_mode_on_windows(self):
        """Windows 上 auto 模式应返回 SimulationCollector"""
        if sys.platform == "win32":
            config = {"virtual_clock": {"start_ns": 0}}
            collector = detect_and_create_collector(config)
            from collector.simulation_collector import SimulationCollector
            self.assertIsInstance(collector, SimulationCollector)

    def test_default_mode_is_auto(self):
        """无 mode 配置时默认为 auto"""
        config = {"virtual_clock": {"start_ns": 0}}
        collector = detect_and_create_collector(config)
        from collector.simulation_collector import SimulationCollector
        # Windows 上 auto 降级为 simulation
        if sys.platform == "win32":
            self.assertIsInstance(collector, SimulationCollector)


class TestPipeFactory(unittest.TestCase):
    """管道工厂测试"""

    def test_create_windows(self):
        """工厂创建 Windows 管道适配器"""
        config = {
            "pipeline": {
                "win_event_pipe": r"\\.\pipe\test_events",
                "win_command_pipe": r"\\.\pipe\test_commands",
            },
            "pipes": {"connect_timeout_ms": 3000}
        }
        adapter = PipeAdapter.create(config, platform="windows")
        self.assertIsInstance(adapter, WindowsPipeAdapter)
        self.assertEqual(adapter.event_pipe_name, r"\\.\pipe\test_events")
        self.assertEqual(adapter.command_pipe_name, r"\\.\pipe\test_commands")
        self.assertEqual(adapter.connect_timeout_ms, 3000)

    def test_create_linux(self):
        """工厂创建 Linux FIFO 适配器"""
        config = {
            "pipeline": {
                "linux_event_fifo": "/tmp/test/events",
                "linux_command_fifo": "/tmp/test/commands",
            }
        }
        adapter = PipeAdapter.create(config, platform="linux")
        self.assertIsInstance(adapter, LinuxFifoAdapter)
        self.assertEqual(adapter.event_fifo, "/tmp/test/events")
        self.assertEqual(adapter.command_fifo, "/tmp/test/commands")

    def test_windows_default_pipe_names(self):
        """Windows 管道默认名称"""
        config = {}
        adapter = PipeAdapter.create(config, platform="windows")
        self.assertIsInstance(adapter, WindowsPipeAdapter)
        self.assertIn("observer_events", adapter.event_pipe_name)
        self.assertIn("observer_commands", adapter.command_pipe_name)

    def test_linux_default_fifo_paths(self):
        """Linux FIFO 默认路径"""
        config = {}
        adapter = PipeAdapter.create(config, platform="linux")
        self.assertIsInstance(adapter, LinuxFifoAdapter)
        self.assertIn("observer", adapter.event_fifo)
        self.assertIn("observer", adapter.command_fifo)

    def test_repr(self):
        """repr 包含关键信息"""
        config = {}
        win = PipeAdapter.create(config, platform="windows")
        self.assertIn("WindowsPipeAdapter", repr(win))
        lin = PipeAdapter.create(config, platform="linux")
        self.assertIn("LinuxFifoAdapter", repr(lin))


class TestTimeSource(unittest.TestCase):
    """时间源测试"""

    def test_virtual_clock_source_basic(self):
        """VirtualClockSource 基本操作"""
        src = VirtualClockSource(start_ns=1000)
        self.assertEqual(src.now_ns(), 1000)
        src.advance(100)  # 推进 100ms = 100_000_000ns
        self.assertEqual(src.now_ns(), 1000 + 100_000_000)

    def test_virtual_clock_source_reset(self):
        """VirtualClockSource 重置"""
        src = VirtualClockSource(start_ns=5000)
        src.advance(50)
        src.reset(start_ns=0)
        self.assertEqual(src.now_ns(), 0)

    def test_virtual_clock_source_elapsed(self):
        """VirtualClockSource 经过时间"""
        src = VirtualClockSource(start_ns=1000)
        src.advance(200)
        self.assertEqual(src.elapsed_ns(), 200_000_000)

    def test_virtual_clock_source_clock_property(self):
        """VirtualClockSource.clock 返回 VirtualClock 实例"""
        from models.virtual_clock import VirtualClock
        src = VirtualClockSource(start_ns=0)
        self.assertIsInstance(src.clock, VirtualClock)

    def test_realtime_clock_source_basic(self):
        """RealtimeClockSource 返回正整数时间戳"""
        src = RealtimeClockSource()
        ns = src.now_ns()
        self.assertIsInstance(ns, int)
        self.assertGreater(ns, 0)

    def test_realtime_clock_source_advance(self):
        """RealtimeClockSource.advance() 不报错"""
        src = RealtimeClockSource()
        result = src.advance(100)
        self.assertIsInstance(result, int)
        self.assertGreater(result, 0)

    def test_realtime_clock_source_elapsed(self):
        """RealtimeClockSource 经过时间为非负"""
        import time
        src = RealtimeClockSource()
        time.sleep(0.01)
        elapsed = src.elapsed_ns()
        self.assertGreaterEqual(elapsed, 0)

    def test_realtime_clock_source_reset(self):
        """RealtimeClockSource 重置后 elapsed 接近 0"""
        src = RealtimeClockSource()
        src.reset()
        # 重置后 elapsed 应非常小
        self.assertLess(src.elapsed_ns(), 1_000_000_000)  # < 1秒

    def test_time_source_is_abstract(self):
        """TimeSource 不能直接实例化"""
        with self.assertRaises(TypeError):
            TimeSource()


if __name__ == "__main__":
    unittest.main()
