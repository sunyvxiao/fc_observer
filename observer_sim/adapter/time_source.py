"""
adapter/time_source.py — 时间源抽象

提供两种时间源实现:
- VirtualClockSource:   虚拟时钟（模拟模式，按 delay_ms 推进）
- RealtimeClockSource:  真实时钟（eBPF/strace 模式，使用系统单调时钟）

两者实现统一接口，上层通过 now_ns() 获取纳秒级时间戳。
"""

import time
from abc import ABC, abstractmethod


class TimeSource(ABC):
    """时间源抽象基类"""

    @abstractmethod
    def now_ns(self) -> int:
        """获取当前时间戳（纳秒）"""
        ...

    @abstractmethod
    def advance(self, delay_ms: int) -> int:
        """
        推进时间。

        虚拟模式: 按 delay_ms 推进
        真实模式: delay_ms 仅用于记录（真实时间自动推进）

        返回:
            推进后的时间戳（纳秒）
        """
        ...

    @abstractmethod
    def reset(self, start_ns: int = 0):
        """重置时间源"""
        ...

    @abstractmethod
    def elapsed_ns(self) -> int:
        """获取从启动到现在的经过时间（纳秒）"""
        ...


class VirtualClockSource(TimeSource):
    """
    虚拟时钟源 — 封装 models.virtual_clock.VirtualClock。

    用于模拟模式（SimulationCollector），按场景 delay_ms 推进时间。
    """

    def __init__(self, start_ns: int = 0):
        from models.virtual_clock import VirtualClock
        self._clock = VirtualClock(start_ns=start_ns)

    def now_ns(self) -> int:
        return self._clock.now_ns()

    def advance(self, delay_ms: int) -> int:
        return self._clock.advance(delay_ms)

    def reset(self, start_ns: int = 0):
        self._clock.reset(start_ns=start_ns)

    def elapsed_ns(self) -> int:
        return self._clock.elapsed_ns()

    @property
    def clock(self):
        """获取内部 VirtualClock 实例（供 EventNormalizer 使用）"""
        return self._clock

    def __repr__(self):
        return f"VirtualClockSource(now_ns={self.now_ns()}, elapsed_ms={self._clock.elapsed_ms()})"


class RealtimeClockSource(TimeSource):
    """
    真实时钟源 — 使用 time.time_ns() 获取系统时间。

    用于 eBPF / strace 模式（真实采集），时间自动推进。
    advance() 在此模式下为无操作（仅返回当前时间）。
    """

    def __init__(self, start_ns: int = 0):
        self._start_ns = start_ns or time.time_ns()
        self._current_ns = self._start_ns

    def now_ns(self) -> int:
        self._current_ns = time.time_ns()
        return self._current_ns

    def advance(self, delay_ms: int) -> int:
        """真实模式下 advance 仅更新时间缓存，不人为推进"""
        self._current_ns = time.time_ns()
        return self._current_ns

    def reset(self, start_ns: int = 0):
        self._start_ns = start_ns or time.time_ns()
        self._current_ns = self._start_ns

    def elapsed_ns(self) -> int:
        return self.now_ns() - self._start_ns

    def __repr__(self):
        return f"RealtimeClockSource(now_ns={self.now_ns()}, elapsed_ns={self.elapsed_ns()})"
