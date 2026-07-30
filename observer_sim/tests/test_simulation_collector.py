"""
test_simulation_collector.py — SimulationCollector 单元测试

测试内容:
1. capabilities(): 返回正确的 CollectorCapabilities
2. attach(): 模拟模式始终返回 True
3. load_scenario() + start(): 加载场景 yield 正确数量的 RawEvent
4. VirtualClock 推进: delay_ms 正确映射到 timestamp_ns
5. 多 Agent 映射: agent_id / framework / initial_pid 正确
6. send_command(): 模拟模式始终返回 True
7. detach(): 清理场景状态
8. get_process_tree(): 返回空 dict
9. start() 无场景时不 yield
10. event_id 格式: evt-NNNN
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from collector.base_collector import ICollector, CollectorCapabilities
from collector.simulation_collector import SimulationCollector
from models.event import RawEvent

# 测试用场景路径
BASE_DIR = os.path.join(os.path.dirname(__file__), '..')
SCENARIO_N01 = os.path.join(BASE_DIR, "scenarios", "normal", "n01_standard_development.yaml")
SCENARIO_M01 = os.path.join(BASE_DIR, "scenarios", "multi_agent", "m01_legitimate_collaboration.yaml")


class TestCollectorCapabilities(unittest.TestCase):
    """CollectorCapabilities 数据类测试"""

    def test_capabilities_fields(self):
        """CollectorCapabilities 包含所有必要字段"""
        cap = CollectorCapabilities(
            name="Test",
            can_observe=True,
            can_block_tier2=False,
            can_block_tier3=False,
            is_transparent=True,
            performance_overhead="low",
            time_source="virtual",
        )
        self.assertEqual(cap.name, "Test")
        self.assertTrue(cap.can_observe)
        self.assertFalse(cap.can_block_tier2)


class TestICollectorAbstract(unittest.TestCase):
    """ICollector 抽象接口测试"""

    def test_cannot_instantiate(self):
        """ICollector 不能直接实例化"""
        with self.assertRaises(TypeError):
            ICollector()

    def test_simulation_collector_is_icollector(self):
        """SimulationCollector 是 ICollector 的子类"""
        config = {"virtual_clock": {"start_ns": 0}}
        collector = SimulationCollector(config)
        self.assertIsInstance(collector, ICollector)


class TestSimulationCollectorBasic(unittest.TestCase):
    """SimulationCollector 基本操作测试"""

    def setUp(self):
        self.config = {
            "virtual_clock": {"start_ns": 1718092800000000000},
            "simulation": {"scenarios_dir": "scenarios/"},
        }
        self.collector = SimulationCollector(self.config)

    def test_capabilities(self):
        """capabilities() 返回正确的能力描述"""
        cap = self.collector.capabilities()
        self.assertIsInstance(cap, CollectorCapabilities)
        self.assertEqual(cap.name, "Simulation")
        self.assertTrue(cap.can_observe)
        self.assertTrue(cap.can_block_tier2)
        self.assertTrue(cap.can_block_tier3)
        self.assertFalse(cap.is_transparent)
        self.assertEqual(cap.performance_overhead, "low")
        self.assertEqual(cap.time_source, "virtual")

    def test_attach_returns_true(self):
        """attach() 模拟模式始终返回 True"""
        result = self.collector.attach(target_pid=12345, agent_id="test-agent")
        self.assertTrue(result)

    def test_attach_ignores_pid(self):
        """attach() 忽略 target_pid"""
        result = self.collector.attach(target_pid=99999, agent_id="ignored")
        self.assertTrue(result)

    def test_get_process_tree_returns_empty(self):
        """get_process_tree() 返回空 dict"""
        self.assertEqual(self.collector.get_process_tree(), {})

    def test_send_command_returns_true(self):
        """send_command() 模拟模式始终返回 True"""
        from models.command import Command, CmdType
        cmd = Command(
            cmd_id="cmd-001",
            cmd_type=CmdType.BLOCK_EVENT,
            target_event_id="evt-0001",
            target_pid=10001,
            action="block",
            reason="test",
        )
        result = self.collector.send_command(cmd)
        self.assertTrue(result)

    def test_detach_clears_state(self):
        """detach() 清理场景状态"""
        self.collector.load_scenario(SCENARIO_N01)
        self.assertIsNotNone(self.collector.scenario)
        self.collector.detach()
        self.assertIsNone(self.collector.scenario)
        self.assertIsNone(self.collector.scenario_path)

    def test_start_without_scenario_yields_nothing(self):
        """start() 无场景时不 yield 任何事件"""
        events = list(self.collector.start())
        self.assertEqual(len(events), 0)


class TestSimulationCollectorScenario(unittest.TestCase):
    """SimulationCollector 场景加载与事件生成测试"""

    def setUp(self):
        self.config = {
            "virtual_clock": {"start_ns": 1718092800000000000},
        }
        self.collector = SimulationCollector(self.config)

    def test_load_scenario_n01(self):
        """加载 N01 场景"""
        self.collector.load_scenario(SCENARIO_N01)
        self.assertIsNotNone(self.collector.scenario)
        self.assertEqual(self.collector.scenario["id"], "n01-standard-development")

    def test_start_yields_correct_count(self):
        """N01 场景 yield 正确数量的 RawEvent"""
        self.collector.load_scenario(SCENARIO_N01)
        events = list(self.collector.start())
        # N01 有 8 个事件
        self.assertEqual(len(events), 8)

    def test_start_yields_raw_events(self):
        """yield 的对象都是 RawEvent"""
        self.collector.load_scenario(SCENARIO_N01)
        for raw in self.collector.start():
            self.assertIsInstance(raw, RawEvent)

    def test_event_id_format(self):
        """event_id 格式为 evt-NNNN"""
        self.collector.load_scenario(SCENARIO_N01)
        events = list(self.collector.start())
        for i, evt in enumerate(events, 1):
            self.assertEqual(evt.event_id, f"evt-{i:04d}")

    def test_event_types(self):
        """事件类型与场景 YAML 一致"""
        self.collector.load_scenario(SCENARIO_N01)
        events = list(self.collector.start())
        # N01 第一个事件是 exec (git clone)
        self.assertEqual(events[0].event_type, "exec")
        self.assertEqual(events[0].executable, "/usr/bin/git")

    def test_virtual_clock_advancement(self):
        """VirtualClock 按 delay_ms 正确推进"""
        self.collector.load_scenario(SCENARIO_N01)
        events = list(self.collector.start())
        # 时间戳应单调递增
        for i in range(1, len(events)):
            self.assertGreaterEqual(events[i].timestamp_ns, events[i - 1].timestamp_ns)

    def test_virtual_clock_delay_mapping(self):
        """delay_ms 正确映射到时间戳差"""
        self.collector.load_scenario(SCENARIO_N01)
        events = list(self.collector.start())
        # N01 第二个事件 delay_ms=500, 时间差应为 500ms = 500_000_000ns
        if len(events) >= 2:
            diff = events[1].timestamp_ns - events[0].timestamp_ns
            self.assertEqual(diff, 500_000_000)

    def test_clock_reset_on_load(self):
        """load_scenario() 重置时钟"""
        self.collector.load_scenario(SCENARIO_N01)
        list(self.collector.start())  # 消耗所有事件
        ts_after_first = self.collector.clock.now_ns()

        # 重新加载场景，时钟应重置
        self.collector.load_scenario(SCENARIO_N01)
        events = list(self.collector.start())
        # 第一个事件的时间戳应回到初始值附近
        start_ns = self.config.get("virtual_clock", {}).get("start_ns", 0)
        self.assertEqual(events[0].timestamp_ns, start_ns)  # delay_ms=0

    def test_agent_id_from_yaml(self):
        """agent_id 从场景 YAML 正确读取"""
        self.collector.load_scenario(SCENARIO_N01)
        events = list(self.collector.start())
        # N01 所有事件的 agent 都是 code-agent-1
        for evt in events:
            self.assertEqual(evt.agent_id, "code-agent-1")

    def test_agent_framework(self):
        """agent_framework 从 agents 映射正确读取"""
        self.collector.load_scenario(SCENARIO_N01)
        events = list(self.collector.start())
        for evt in events:
            self.assertEqual(evt.agent_framework, "LangChain")

    def test_pid_from_agents_map(self):
        """pid 从 agents 映射的 initial_pid 读取"""
        self.collector.load_scenario(SCENARIO_N01)
        events = list(self.collector.start())
        for evt in events:
            self.assertEqual(evt.pid, 10001)  # N01 agent initial_pid=10001


class TestSimulationCollectorMultiAgent(unittest.TestCase):
    """多 Agent 场景测试"""

    def setUp(self):
        self.config = {
            "virtual_clock": {"start_ns": 1718092800000000000},
        }
        self.collector = SimulationCollector(self.config)

    def test_multi_agent_event_count(self):
        """M01 场景 yield 正确数量的事件"""
        self.collector.load_scenario(SCENARIO_M01)
        events = list(self.collector.start())
        # M01 有 6 个事件
        self.assertEqual(len(events), 6)

    def test_multi_agent_id_mapping(self):
        """多 Agent 场景的 agent_id 正确归属"""
        self.collector.load_scenario(SCENARIO_M01)
        events = list(self.collector.start())
        # M01: 前 2 个事件是 agent-code, 后 4 个是 agent-test
        self.assertEqual(events[0].agent_id, "agent-code")
        self.assertEqual(events[1].agent_id, "agent-code")
        self.assertEqual(events[2].agent_id, "agent-test")
        self.assertEqual(events[3].agent_id, "agent-test")
        self.assertEqual(events[4].agent_id, "agent-test")
        self.assertEqual(events[5].agent_id, "agent-test")

    def test_multi_agent_pid_mapping(self):
        """多 Agent 场景的 pid 映射到对应 agent 的 initial_pid"""
        self.collector.load_scenario(SCENARIO_M01)
        events = list(self.collector.start())
        # agent-code initial_pid=40001, agent-test initial_pid=50001
        self.assertEqual(events[0].pid, 40001)
        self.assertEqual(events[1].pid, 40001)
        self.assertEqual(events[2].pid, 50001)
        self.assertEqual(events[3].pid, 50001)

    def test_multi_agent_framework_mapping(self):
        """多 Agent 场景的 framework 正确"""
        self.collector.load_scenario(SCENARIO_M01)
        events = list(self.collector.start())
        # agent-code: LangChain, agent-test: CrewAI
        self.assertEqual(events[0].agent_framework, "LangChain")
        self.assertEqual(events[2].agent_framework, "CrewAI")


class TestSimulationCollectorConfig(unittest.TestCase):
    """配置兼容性测试"""

    def test_config_without_simulation_section(self):
        """无 simulation 配置段时使用默认值"""
        config = {"virtual_clock": {"start_ns": 42}}
        collector = SimulationCollector(config)
        self.assertEqual(collector.scenarios_dir, "scenarios/")
        # 时钟从 virtual_clock.start_ns 读取
        self.assertEqual(collector.clock.now_ns(), 42)

    def test_config_simulation_section_priority(self):
        """simulation.virtual_clock_start_ns 优先于 virtual_clock.start_ns"""
        config = {
            "virtual_clock": {"start_ns": 100},
            "simulation": {"virtual_clock_start_ns": 200},
        }
        collector = SimulationCollector(config)
        self.assertEqual(collector.clock.now_ns(), 200)

    def test_config_default_start_ns(self):
        """无任何时钟配置时使用默认值"""
        config = {}
        collector = SimulationCollector(config)
        self.assertEqual(collector.clock.now_ns(), 1718092800000000000)


if __name__ == "__main__":
    unittest.main()
