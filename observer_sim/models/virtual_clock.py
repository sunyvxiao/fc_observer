"""
虚拟时钟子系统 — VirtualClock

按场景 delay_ms 推进虚拟时间，驱动全系统时间判定。
设计动机：场景事件中的 delay_ms 是事件间的时间间隔元数据。
如果直接使用系统真实时间，运行速度受限于实际处理耗时，无法快速演示且结果不确定。

影响范围:
- EventNormalizer: 事件序列窗口超时清理
- AgentViolationTracker: 违规升级的 5 分钟滑动窗口
- BaselineChecker: 时间模式偏离分析
- ChainReportBuilder: 因果链中步骤间时间差
"""


class VirtualClock:
    """
    虚拟时钟 — 按场景 delay_ms 推进，驱动全系统时间判定。
    
    使用纳秒精度（int 类型，Python 支持任意精度整数），不存在溢出问题。
    全系统时间源统一由此类提供，C++ 侧不维护独立时钟。
    """

    def __init__(self, start_ns: int = 0):
        """
        初始化虚拟时钟。
        
        Args:
            start_ns: 起始虚拟时间戳（纳秒），默认为 0
        """
        self._current_ns: int = start_ns
        self._start_ns: int = start_ns

    def advance(self, delay_ms: int) -> int:
        """
        推进虚拟时钟。
        
        Args:
            delay_ms: 推进的毫秒数
            
        Returns:
            推进后的虚拟时间戳（纳秒）
        """
        if delay_ms < 0:
            raise ValueError(f"delay_ms 不能为负数: {delay_ms}")
        self._current_ns += delay_ms * 1_000_000
        return self._current_ns

    def now_ns(self) -> int:
        """获取当前虚拟时间戳（纳秒）"""
        return self._current_ns

    def now_ms(self) -> int:
        """获取当前虚拟时间戳（毫秒）"""
        return self._current_ns // 1_000_000

    def elapsed_ns(self) -> int:
        """获取从启动到现在的虚拟经过时间（纳秒）"""
        return self._current_ns - self._start_ns

    def elapsed_ms(self) -> int:
        """获取从启动到现在的虚拟经过时间（毫秒）"""
        return (self._current_ns - self._start_ns) // 1_000_000

    def reset(self, start_ns: int = 0):
        """
        重置虚拟时钟。
        
        Args:
            start_ns: 新的起始时间戳（纳秒），默认为 0
        """
        self._current_ns = start_ns
        self._start_ns = start_ns

    def is_within_window(self, event_timestamp_ns: int, window_ms: int) -> bool:
        """
        判断给定时间戳是否在当前虚拟时钟的指定窗口内。
        用于违规升级滑动窗口判定。
        
        Args:
            event_timestamp_ns: 待检查的事件时间戳（纳秒）
            window_ms: 窗口大小（毫秒）
            
        Returns:
            True 如果事件时间戳在当前时间的 window_ms 毫秒范围内
        """
        window_ns = window_ms * 1_000_000
        return (self._current_ns - event_timestamp_ns) <= window_ns

    def __repr__(self) -> str:
        return f"VirtualClock(current_ns={self._current_ns}, elapsed_ms={self.elapsed_ms()})"
