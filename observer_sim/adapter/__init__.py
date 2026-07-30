"""
adapter/ — 平台适配层

封装 Windows / Linux 平台差异:
- platform_detect: 平台检测 + Collector 工厂
- pipe_factory:    管道适配器（命名管道 / FIFO）
- time_source:     时间源抽象（虚拟时钟 / 真实时钟）
"""

from adapter.platform_detect import detect_and_create_collector, PlatformInfo
from adapter.pipe_factory import PipeAdapter, WindowsPipeAdapter, LinuxFifoAdapter
from adapter.time_source import TimeSource, VirtualClockSource, RealtimeClockSource

__all__ = [
    "detect_and_create_collector",
    "PlatformInfo",
    "PipeAdapter",
    "WindowsPipeAdapter",
    "LinuxFifoAdapter",
    "TimeSource",
    "VirtualClockSource",
    "RealtimeClockSource",
]
