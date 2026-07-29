"""
test_virtual_clock.py — VirtualClock 单元测试

测试虚拟时钟的核心功能:
- 时间推进 (advance)
- 时间查询 (now_ns, now_ms, elapsed_ms)
- 窗口判定 (is_within_window)
- 重置 (reset)
- 边界条件 (负数 delay_ms)

对应定稿 8.4 测试检查点:
- Phase 6: 虚拟时钟一致性 — 全系统时间戳均基于 VirtualClock
"""

import sys
import os
import unittest

# 添加项目路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.virtual_clock import VirtualClock


class TestVirtualClock(unittest.TestCase):
    """VirtualClock 单元测试"""

    def setUp(self):
        self.clock = VirtualClock(start_ns=0)

    # === 基础推进测试 ===

    def test_initial_state(self):
        """初始状态: 时间为 0"""
        self.assertEqual(self.clock.now_ns(), 0)
        self.assertEqual(self.clock.now_ms(), 0)
        self.assertEqual(self.clock.elapsed_ms(), 0)

    def test_advance_basic(self):
        """基础推进: advance(500) 应推进 500ms"""
        result = self.clock.advance(500)
        self.assertEqual(result, 500_000_000)  # 500ms = 500,000,000ns
        self.assertEqual(self.clock.now_ns(), 500_000_000)
        self.assertEqual(self.clock.now_ms(), 500)

    def test_advance_multiple(self):
        """多次推进: 累加效果"""
        self.clock.advance(100)
        self.clock.advance(200)
        self.clock.advance(300)
        self.assertEqual(self.clock.now_ms(), 600)

    def test_advance_zero(self):
        """推进 0ms: 时间不变"""
        self.clock.advance(100)
        result = self.clock.advance(0)
        self.assertEqual(result, 100_000_000)

    def test_advance_negative_raises(self):
        """负数 delay_ms 应抛出 ValueError"""
        with self.assertRaises(ValueError):
            self.clock.advance(-1)

    # === 时间查询测试 ===

    def test_now_ns_precision(self):
        """纳秒精度验证"""
        self.clock.advance(1)  # 1ms
        self.assertEqual(self.clock.now_ns(), 1_000_000)

    def test_now_ms_truncation(self):
        """毫秒查询: 截断（非四入）"""
        self.clock._current_ns = 1_500_000  # 1.5ms
        self.assertEqual(self.clock.now_ms(), 1)  # 截断为 1ms

    def test_elapsed_ms(self):
        """经过时间计算"""
        clock = VirtualClock(start_ns=1_000_000_000)  # 起始 1s
        clock.advance(500)  # 推进 500ms
        self.assertEqual(clock.elapsed_ms(), 500)

    def test_elapsed_ns(self):
        """经过时间（纳秒）"""
        clock = VirtualClock(start_ns=1_000_000_000)
        clock.advance(100)
        self.assertEqual(clock.elapsed_ns(), 100_000_000)

    # === 窗口判定测试 ===

    def test_within_window_true(self):
        """事件在窗口内"""
        self.clock.advance(10000)  # 当前 10s
        # 事件在 5s 前（在 5 分钟窗口内）
        event_ts = self.clock.now_ns() - 5_000_000_000  # 5s 前
        self.assertTrue(self.clock.is_within_window(event_ts, 300000))  # 5 分钟窗口

    def test_within_window_false(self):
        """事件在窗口外"""
        self.clock.advance(10000)  # 当前 10s
        # 事件在 10 分钟前（超出 5 分钟窗口）
        event_ts = self.clock.now_ns() - 600_000_000_000  # 10 分钟前
        self.assertFalse(self.clock.is_within_window(event_ts, 300000))

    def test_within_window_boundary(self):
        """窗口边界: 恰好等于窗口大小"""
        self.clock.advance(10000)
        event_ts = self.clock.now_ns() - 300_000_000_000  # 恰好 5 分钟前
        self.assertTrue(self.clock.is_within_window(event_ts, 300000))

    # === 重置测试 ===

    def test_reset(self):
        """重置时钟"""
        self.clock.advance(5000)
        self.clock.reset()
        self.assertEqual(self.clock.now_ns(), 0)
        self.assertEqual(self.clock.elapsed_ms(), 0)

    def test_reset_with_start(self):
        """重置到指定起始时间"""
        self.clock.advance(5000)
        self.clock.reset(start_ns=1_000_000_000)
        self.assertEqual(self.clock.now_ns(), 1_000_000_000)

    # === 大数值测试（验证无溢出） ===

    def test_large_timestamp(self):
        """大时间戳: 模拟真实 Unix 时间戳级别"""
        clock = VirtualClock(start_ns=1718092800000000000)  # 2024-06-11
        clock.advance(86400000)  # 推进 1 天
        expected = 1718092800000000000 + 86400000 * 1_000_000
        self.assertEqual(clock.now_ns(), expected)

    def test_repr(self):
        """字符串表示"""
        self.clock.advance(1000)
        repr_str = repr(self.clock)
        self.assertIn("1000", repr_str)


if __name__ == '__main__':
    unittest.main()
