"""
collector/simulation_collector.py — 模拟采集器

封装现有场景 YAML + VirtualClock 逻辑，实现 ICollector 接口。
从 demo.py ScenarioRunner 和 main.py 中提取的采集逻辑:
  1. 加载场景 YAML 文件
  2. 遍历 event_sequence
  3. 推进 VirtualClock
  4. 构造 RawEvent（与现有 create_raw_event() 逻辑一致）
  5. yield RawEvent 给上层

支持多 Agent 场景: attach() 时 agent_id 可为空（表示全局模式），
start() 中按场景 YAML 的 agent 字段标注每个 RawEvent 的 agent_id。
"""

import os
import yaml
import logging
from typing import Iterator, Optional

from collector.base_collector import ICollector, CollectorCapabilities
from models.event import RawEvent
from models.virtual_clock import VirtualClock

logger = logging.getLogger(__name__)


class SimulationCollector(ICollector):
    """
    模拟采集器 —— 封装现有场景 YAML + VirtualClock 逻辑。

    与现有代码的对应关系:
    - main.py create_raw_event()  → self.start() 中的 RawEvent 构造
    - demo.py ScenarioRunner.__init__() 中的 VirtualClock 初始化
    - main.py load_scenario()     → self.load_scenario()
    """

    def __init__(self, config: dict):
        """
        初始化模拟采集器。

        参数:
            config: 配置字典（从 config.yaml 加载）
        """
        self.config = config
        self.scenarios_dir = config.get("simulation", {}).get(
            "scenarios_dir", "scenarios/")
        start_ns = config.get("simulation", {}).get(
            "virtual_clock_start_ns",
            config.get("virtual_clock", {}).get("start_ns", 1718092800000000000))
        self.clock = VirtualClock(start_ns=start_ns)
        self.scenario: Optional[dict] = None
        self.scenario_path: Optional[str] = None
        self._attached = False

    def capabilities(self) -> CollectorCapabilities:
        """返回模拟采集器能力描述"""
        return CollectorCapabilities(
            name="Simulation",
            can_observe=True,
            can_block_tier2=True,    # 模拟阻断
            can_block_tier3=True,    # 模拟终止
            is_transparent=False,    # Agent 可感知（模拟环境）
            performance_overhead="low",
            time_source="virtual",
        )

    def attach(self, target_pid: int = 0, agent_id: str = "") -> bool:
        """
        模拟模式下的 attach。

        target_pid 在模拟模式下忽略。
        agent_id 可用于场景标识，但实际场景由 load_scenario() 加载。
        """
        self._attached = True
        logger.debug(f"SimulationCollector attached (agent_id={agent_id})")
        return True

    def load_scenario(self, scenario_path: str):
        """
        加载场景文件。

        兼容现有 ScenarioRunner.load_scenario 和 main.py load_scenario 逻辑。

        参数:
            scenario_path: 场景 YAML 文件路径（绝对或相对）
        """
        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        self.scenario = data['scenario']
        self.scenario_path = scenario_path
        # 重置时钟状态
        start_ns = self.config.get("simulation", {}).get(
            "virtual_clock_start_ns",
            self.config.get("virtual_clock", {}).get("start_ns", 1718092800000000000))
        self.clock.reset(start_ns=start_ns)
        logger.info(f"加载场景: {self.scenario.get('id', '?')} ({scenario_path})")

    def start(self) -> Iterator[RawEvent]:
        """
        遍历场景事件序列，yield RawEvent。

        关键实现: 复用现有 main.py create_raw_event() 的逻辑，
        包括 VirtualClock 推进（delay_ms）、事件字段填充、
        多 Agent 场景的 agent_id 映射。

        Yields:
            RawEvent: 场景中的每个事件
        """
        if not self.scenario:
            logger.warning("SimulationCollector.start() called without loaded scenario")
            return

        # 构建 agent 信息映射（支持多 Agent 场景）
        agents_map = {}
        for agent in self.scenario.get("agents", []):
            agents_map[agent["agent_id"]] = agent

        events = self.scenario.get("event_sequence", [])
        for i, event_data in enumerate(events, 1):
            seq = event_data.get("seq", i)
            delay_ms = event_data.get("delay_ms", 0)
            agent_id = event_data.get("agent", "unknown")
            agent_info = agents_map.get(agent_id, {
                "agent_id": agent_id, "initial_pid": 10001})

            # 推进虚拟时钟
            self.clock.advance(delay_ms)

            # 构造 RawEvent（与 main.py create_raw_event() 一致）
            yield RawEvent(
                event_id=f"evt-{seq:04d}",
                timestamp_ns=self.clock.now_ns(),
                event_type=event_data["type"],
                pid=agent_info.get("initial_pid", 10001),
                ppid=1,
                agent_id=agent_id,
                agent_framework=agent_info.get("framework", "unknown"),
                executable=event_data.get("executable"),
                arguments=event_data.get("arguments"),
                file_path=event_data.get("file_path"),
                file_op=event_data.get("file_op"),
                remote_addr=event_data.get("remote_addr"),
                remote_port=event_data.get("remote_port"),
                protocol=event_data.get("protocol"),
            )

    def send_command(self, cmd) -> bool:
        """
        模拟模式: 记录阻断指令（与现有 MockCommandSender 行为一致）。

        始终返回 True 表示"模拟成功"。
        """
        logger.debug(f"SimulationCollector 收到阻断指令: {cmd}")
        return True

    def detach(self) -> None:
        """断开采集，清理场景状态"""
        self.scenario = None
        self.scenario_path = None
        self._attached = False
        logger.debug("SimulationCollector detached")

    def get_process_tree(self) -> dict:
        """模拟模式不维护真实进程树，返回空字典"""
        return {}
