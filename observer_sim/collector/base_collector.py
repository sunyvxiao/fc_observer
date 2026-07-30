"""
collector/base_collector.py — ICollector 抽象接口 + CollectorCapabilities

定义采集层统一接口，所有采集方案（模拟探针 / strace / eBPF）必须实现此接口。
上层 (main.py / demo.py / app.py) 通过此接口与采集层交互，不关心底层实现。

5 个抽象方法:
  - attach(target_pid, agent_id) → bool
  - start() → Iterator[RawEvent]
  - send_command(cmd: Command) → bool
  - detach() → None
  - get_process_tree() → dict

1 个能力查询:
  - capabilities() → CollectorCapabilities
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from models.event import RawEvent
    from models.command import Command


@dataclass
class CollectorCapabilities:
    """采集器能力描述 —— 供上层查询"""
    name: str                       # "Simulation" | "Strace" | "Ebpf"
    can_observe: bool               # 是否支持观测
    can_block_tier2: bool           # 是否支持 Tier2 阻断（返回 EPERM）
    can_block_tier3: bool           # 是否支持 Tier3 阻断（终止进程）
    is_transparent: bool            # 对 Agent 是否无感知
    performance_overhead: str       # "low" | "medium" | "high"
    time_source: str                # "virtual" | "realtime_monotonic"


class ICollector(ABC):
    """
    采集层统一抽象接口。

    所有采集方案（模拟探针 / strace / eBPF）必须实现此接口。
    上层 (main.py / demo.py / app.py) 通过此接口与采集层交互，
    不关心底层是模拟还是真实采集。
    """

    @abstractmethod
    def capabilities(self) -> CollectorCapabilities:
        """返回采集器能力描述"""
        ...

    @abstractmethod
    def attach(self, target_pid: int = 0, agent_id: str = "") -> bool:
        """
        附着到目标 Agent 进程。

        参数:
            target_pid: Agent 主进程 PID（模拟模式下忽略，eBPF/strace 模式使用）
            agent_id:   Agent 标识字符串

        返回:
            True:  附着成功
            False: 附着失败

        模拟模式: 接受 agent_id 用于场景加载，target_pid 忽略
        strace:   subprocess.Popen(["strace", "-p", str(target_pid), ...])
        eBPF:     通过 libbpf 加载并挂载探针（全局观测，非单进程）
        """
        ...

    @abstractmethod
    def start(self) -> Iterator['RawEvent']:
        """
        开始采集，返回 RawEvent 生成器。
        上层直接 for 循环消费，不需要管道中转。

        Yields:
            RawEvent: 每个捕获到的系统调用事件

        模拟模式: 读取场景 YAML → 逐个生成 RawEvent → yield（含 VirtualClock 推进）
        strace:   逐行读取 strace 输出 → 解析 → yield RawEvent
        eBPF:     消费 perf ring buffer → 构造 RawEvent → yield
        """
        ...

    @abstractmethod
    def send_command(self, cmd: 'Command') -> bool:
        """
        接收阻断指令（反向通道）。

        模拟模式: 通过 MockCommandSender 模拟阻断
        strace:   不支持（返回 False，记录警告）
        eBPF:     第一版不支持（返回 False），第二版更新 eBPF map
        """
        ...

    @abstractmethod
    def detach(self) -> None:
        """断开采集，清理资源。"""
        ...

    @abstractmethod
    def get_process_tree(self) -> dict:
        """
        获取当前追踪的进程树快照。
        返回: {pid: {"ppid": ..., "agent_id": ..., "comm": ...}, ...}

        模拟模式: 返回空 dict {}
        strace/eBPF: 从 /proc/{pid}/stat 构建
        """
        ...
