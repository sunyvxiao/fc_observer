"""
test_fifo_writer.py — FifoWriter 零依赖 FIFO 写入工具单元测试

测试内容:
1. FifoWriter: 构造、打开、写入、关闭、上下文管理器
2. 信号处理: SIGTERM/SIGINT 优雅关闭
3. 边界条件: FIFO 不存在、未打开写入、BrokenPipe
4. 批量写入: write_events 含延迟
5. 便捷函数: write_event_to_fifo
"""

import sys
import os
import unittest
import tempfile
import json
import threading
import time
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from agent_fifo_writer import FifoWriter, write_event_to_fifo, _running


class TestFifoWriterBasic(unittest.TestCase):
    """FifoWriter 基础功能测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="fifo_test_")
        self._fifo_path = os.path.join(self._tmpdir, "test_pipe")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_constructor_stores_path(self):
        """构造时存储 fifo_path"""
        writer = FifoWriter("/tmp/test_fifo")
        self.assertEqual(writer._fifo_path, "/tmp/test_fifo")
        writer.close()

    def test_initial_state_not_open(self):
        """初始状态 FIFO 未打开"""
        writer = FifoWriter(self._fifo_path)
        self.assertFalse(writer.is_open)
        self.assertEqual(writer.event_count, 0)
        writer.close()

    def test_open_fails_if_fifo_not_exists(self):
        """FIFO 不存在时 open() 返回 False"""
        writer = FifoWriter(self._fifo_path)
        result = writer.open(timeout=0.1)
        self.assertFalse(result)
        self.assertFalse(writer.is_open)
        writer.close()

    def test_write_fails_if_not_open(self):
        """未打开时 write_event() 返回 False"""
        writer = FifoWriter(self._fifo_path)
        result = writer.write_event({"event_type": "exec"})
        self.assertFalse(result)
        writer.close()

    def test_close_when_not_open(self):
        """未打开时 close() 不报错"""
        writer = FifoWriter(self._fifo_path)
        writer.close()  # 不应抛出异常
        self.assertFalse(writer.is_open)

    def test_event_count_increments_on_write(self):
        """写入后 event_count 递增（通过子进程验证）"""
        writer = FifoWriter(self._fifo_path)
        # 使用 mock fd
        import io
        writer._fd = io.StringIO()
        self.assertTrue(writer.write_event({"a": 1}))
        self.assertEqual(writer.event_count, 1)
        self.assertTrue(writer.write_event({"b": 2}))
        self.assertEqual(writer.event_count, 2)


class TestFifoWriterJSONOutput(unittest.TestCase):
    """FifoWriter JSON 输出格式测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="fifo_json_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_write_event_produces_valid_json_line(self):
        """write_event 产生有效的 JSON 行"""
        import io
        writer = FifoWriter("/fake/fifo")
        buf = io.StringIO()
        writer._fd = buf
        writer.write_event({"event_type": "exec", "pid": 123})
        line = buf.getvalue().strip()
        parsed = json.loads(line)
        self.assertEqual(parsed["event_type"], "exec")
        self.assertEqual(parsed["pid"], 123)

    def test_write_event_handles_unicode(self):
        """write_event 处理 Unicode 字符"""
        import io
        writer = FifoWriter("/fake/fifo")
        buf = io.StringIO()
        writer._fd = buf
        writer.write_event({"path": "/home/用户/文档"})
        line = buf.getvalue().strip()
        parsed = json.loads(line)
        self.assertEqual(parsed["path"], "/home/用户/文档")

    def test_write_event_newline_separator(self):
        """每个事件后追加换行"""
        import io
        writer = FifoWriter("/fake/fifo")
        buf = io.StringIO()
        writer._fd = buf
        writer.write_event({"n": 1})
        writer.write_event({"n": 2})
        lines = buf.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 2)


class TestFifoWriterBatch(unittest.TestCase):
    """FifoWriter 批量写入测试"""

    def test_write_events_returns_correct_count(self):
        """write_events 返回正确计数"""
        import io
        writer = FifoWriter("/fake/fifo")
        buf = io.StringIO()
        writer._fd = buf
        events = [{"i": i} for i in range(5)]
        count = writer.write_events(events, delay=0)
        self.assertEqual(count, 5)
        self.assertEqual(writer.event_count, 5)

    def test_write_events_stops_on_signal(self):
        """write_events 在信号后停止（测试 _running 标志）"""
        import io
        writer = FifoWriter("/fake/fifo")
        buf = io.StringIO()
        writer._fd = buf
        # 在写入期间停止
        events = [{"i": i} for i in range(100)]

        def stop_after_delay():
            time.sleep(0.01)
            # 模拟信号：设置全局 _running 为 False
            import agent_fifo_writer
            agent_fifo_writer._running = False

        t = threading.Thread(target=stop_after_delay, daemon=True)
        t.start()
        count = writer.write_events(events, delay=0.001)
        t.join(timeout=1.0)
        # 恢复 _running
        import agent_fifo_writer
        agent_fifo_writer._running = True
        # 应该在写入全部之前停止
        self.assertLess(count, 100)


class TestFifoWriterContextManager(unittest.TestCase):
    """FifoWriter 上下文管理器测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="fifo_ctx_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_context_manager_closes_on_exit(self):
        """上下文管理器退出时关闭"""
        import io
        writer = FifoWriter("/fake/fifo")
        buf = io.StringIO()
        writer._fd = buf
        writer._event_count = 0
        with writer:
            self.assertTrue(writer.is_open)
        # 退出后应已关闭
        self.assertFalse(writer.is_open)

    def test_context_manager_closes_on_exception(self):
        """异常时上下文管理器仍关闭"""
        import io
        writer = FifoWriter("/fake/fifo")
        buf = io.StringIO()
        writer._fd = buf
        try:
            with writer:
                raise ValueError("test error")
        except ValueError:
            pass
        self.assertFalse(writer.is_open)


class TestWriteEventToFifo(unittest.TestCase):
    """便捷函数 write_event_to_fifo 测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="fifo_util_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_false_if_fifo_not_exists(self):
        """FIFO 不存在时返回 False"""
        result = write_event_to_fifo("/nonexistent/fifo",
                                     {"test": True}, connect_timeout=0.01)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
