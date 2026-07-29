"""
test_pipe_communication.py — Phase 1 管道通信联调测试

测试内容:
1. RawEvent 序列化/反序列化往返一致性
2. Command 序列化/反序列化往返一致性
3. MockPipeReader 事件注入与读取
4. MockCommandSender 指令发送与记录
5. 场景 YAML 加载验证
6. 端到端数据流验证（场景 → 事件模型 → JSON → 反序列化）

对应定稿 8.4 测试检查点:
- Phase 1: 双向管道通信 — C++ 发送事件 → Python 全部接收
- Phase 1: 管道断开重连 — 关闭 C++ → 重启 → Python 自动重连成功
- Phase 1: 写入失败缓冲 — 关闭 Python → C++ 继续写入 → RingBuffer 暂存
"""

import sys
import os
import json
import unittest

# 添加项目路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.event import RawEvent, NormalizedEvent, AgentContext, ProcessNode
from models.command import Command, CmdType, BlockAction
from models.virtual_clock import VirtualClock
from observer_core.monitoring.pipe_reader import MockPipeReader
from observer_core.blocking.command_sender import MockCommandSender


class TestRawEventSerialization(unittest.TestCase):
    """RawEvent 序列化/反序列化测试"""

    def _make_exec_event(self):
        return RawEvent(
            event_id="evt_001",
            timestamp_ns=1718092800000000000,
            event_type="exec",
            pid=12345,
            ppid=12340,
            agent_id="code-agent-1",
            agent_framework="LangChain",
            executable="/bin/rm",
            arguments=["-rf", "/"],
        )

    def _make_file_event(self):
        return RawEvent(
            event_id="evt_002",
            timestamp_ns=1718092801000000000,
            event_type="file_open",
            pid=12345,
            ppid=12340,
            agent_id="code-agent-1",
            agent_framework="LangChain",
            file_path="/project/.env",
            file_op="read",
        )

    def _make_net_event(self):
        return RawEvent(
            event_id="evt_003",
            timestamp_ns=1718092802000000000,
            event_type="net_conn",
            pid=12345,
            ppid=12340,
            agent_id="rogue-agent",
            agent_framework="AutoGen",
            remote_addr="45.33.32.156",
            remote_port=8080,
            protocol="TCP",
        )

    def test_exec_event_roundtrip(self):
        """exec 事件序列化→反序列化往返一致"""
        original = self._make_exec_event()
        json_line = original.to_json_line()
        restored = RawEvent.from_json_line(json_line)

        self.assertEqual(restored.event_id, "evt_001")
        self.assertEqual(restored.timestamp_ns, 1718092800000000000)
        self.assertEqual(restored.event_type, "exec")
        self.assertEqual(restored.pid, 12345)
        self.assertEqual(restored.ppid, 12340)
        self.assertEqual(restored.agent_id, "code-agent-1")
        self.assertEqual(restored.executable, "/bin/rm")
        self.assertEqual(restored.arguments, ["-rf", "/"])
        # 非相关字段应为 None
        self.assertIsNone(restored.file_path)
        self.assertIsNone(restored.remote_addr)

    def test_file_event_roundtrip(self):
        """file_open 事件序列化→反序列化往返一致"""
        original = self._make_file_event()
        json_line = original.to_json_line()
        restored = RawEvent.from_json_line(json_line)

        self.assertEqual(restored.event_type, "file_open")
        self.assertEqual(restored.file_path, "/project/.env")
        self.assertEqual(restored.file_op, "read")

    def test_net_event_roundtrip(self):
        """net_conn 事件序列化→反序列化往返一致"""
        original = self._make_net_event()
        json_line = original.to_json_line()
        restored = RawEvent.from_json_line(json_line)

        self.assertEqual(restored.event_type, "net_conn")
        self.assertEqual(restored.remote_addr, "45.33.32.156")
        self.assertEqual(restored.remote_port, 8080)
        self.assertEqual(restored.protocol, "TCP")

    def test_json_line_format(self):
        """JSON 行格式: 单行、可解析、无尾部换行"""
        event = self._make_exec_event()
        json_line = event.to_json_line()
        self.assertNotIn('\n', json_line)
        parsed = json.loads(json_line)
        self.assertIsInstance(parsed, dict)

    def test_null_fields(self):
        """缺失字段应为 null（不使用 omitempty）"""
        event = self._make_exec_event()
        json_line = event.to_json_line()
        parsed = json.loads(json_line)
        self.assertIsNone(parsed["file_path"])
        self.assertIsNone(parsed["file_op"])
        self.assertIsNone(parsed["remote_addr"])
        self.assertIsNone(parsed["remote_port"])
        self.assertIsNone(parsed["protocol"])


class TestCommandSerialization(unittest.TestCase):
    """Command 序列化/反序列化测试"""

    def test_allow_command_roundtrip(self):
        """allow 指令往返一致"""
        cmd = Command.make_allow("cmd_001", "evt_005", timestamp_ns=1000000)
        json_line = cmd.to_json_line()
        restored = Command.from_json_line(json_line)

        self.assertEqual(restored.cmd_id, "cmd_001")
        self.assertEqual(restored.cmd_type, "allow")
        self.assertEqual(restored.target_event_id, "evt_005")

    def test_block_command_roundtrip(self):
        """block_event 指令往返一致"""
        cmd = Command.make_block("cmd_002", "evt_010", 12345,
                                 "R001: block-dangerous-commands",
                                 timestamp_ns=2000000)
        json_line = cmd.to_json_line()
        restored = Command.from_json_line(json_line)

        self.assertEqual(restored.cmd_type, "block_event")
        self.assertEqual(restored.target_pid, 12345)
        self.assertEqual(restored.action, "return_eperm")
        self.assertIn("R001", restored.reason)

    def test_terminate_command_roundtrip(self):
        """terminate_process 指令往返一致"""
        cmd = Command.make_terminate("cmd_003", 12345,
                                     "Tier3: 硬中断",
                                     timestamp_ns=3000000)
        json_line = cmd.to_json_line()
        restored = Command.from_json_line(json_line)

        self.assertEqual(restored.cmd_type, "terminate_process")
        self.assertEqual(restored.target_pid, 12345)
        self.assertEqual(restored.action, "kill_process")

    def test_heartbeat_command(self):
        """heartbeat 指令往返一致"""
        cmd = Command.make_heartbeat("cmd_004", timestamp_ns=4000000)
        json_line = cmd.to_json_line()
        restored = Command.from_json_line(json_line)

        self.assertEqual(restored.cmd_type, "heartbeat")


class TestMockPipeReader(unittest.TestCase):
    """MockPipeReader 测试 — 模拟管道读取"""

    def test_connect_disconnect(self):
        """连接/断开"""
        reader = MockPipeReader()
        self.assertFalse(reader.is_connected)
        reader.connect("\\\\.\\pipe\\test")
        self.assertTrue(reader.is_connected)
        reader.disconnect()
        self.assertFalse(reader.is_connected)

    def test_inject_and_read(self):
        """注入事件→读取"""
        reader = MockPipeReader()
        reader.connect("\\\\.\\pipe\\test")

        event = RawEvent(
            event_id="evt_001", timestamp_ns=100, event_type="exec",
            pid=1, ppid=0, agent_id="a1", agent_framework="test"
        )
        reader.inject_event(event)
        self.assertEqual(reader.pending_count, 1)

        result = reader.read_event()
        self.assertIsNotNone(result)
        self.assertEqual(result.event_id, "evt_001")
        self.assertEqual(reader.pending_count, 0)

    def test_read_empty_returns_none(self):
        """空队列返回 None"""
        reader = MockPipeReader()
        reader.connect("\\\\.\\pipe\\test")
        self.assertIsNone(reader.read_event())

    def test_read_disconnected_returns_none(self):
        """未连接时返回 None"""
        reader = MockPipeReader()
        self.assertIsNone(reader.read_event())

    def test_batch_inject(self):
        """批量注入"""
        reader = MockPipeReader()
        reader.connect("\\\\.\\pipe\\test")
        events = [
            RawEvent(event_id=f"evt_{i}", timestamp_ns=i*100, event_type="exec",
                     pid=1, ppid=0, agent_id="a1", agent_framework="test")
            for i in range(5)
        ]
        reader.inject_events(events)
        self.assertEqual(reader.pending_count, 5)

        # 按顺序读取
        for i in range(5):
            result = reader.read_event()
            self.assertEqual(result.event_id, f"evt_{i}")


class TestMockCommandSender(unittest.TestCase):
    """MockCommandSender 测试 — 模拟指令发送"""

    def test_connect_disconnect(self):
        """连接/断开"""
        sender = MockCommandSender()
        self.assertFalse(sender.is_connected)
        sender.connect("\\\\.\\pipe\\test")
        self.assertTrue(sender.is_connected)
        sender.disconnect()
        self.assertFalse(sender.is_connected)

    def test_send_and_record(self):
        """发送指令→记录"""
        sender = MockCommandSender()
        sender.connect("\\\\.\\pipe\\test")

        cmd = Command.make_allow("cmd_001", "evt_001")
        self.assertTrue(sender.send_command(cmd))
        self.assertEqual(len(sender.sent_commands), 1)
        self.assertEqual(sender.last_command.cmd_type, "allow")

    def test_send_disconnected_fails(self):
        """未连接时发送失败"""
        sender = MockCommandSender()
        cmd = Command.make_allow("cmd_001", "evt_001")
        self.assertFalse(sender.send_command(cmd))

    def test_cmd_id_generation(self):
        """指令 ID 自增"""
        sender = MockCommandSender()
        self.assertEqual(sender.next_cmd_id(), "cmd_0001")
        self.assertEqual(sender.next_cmd_id(), "cmd_0002")
        self.assertEqual(sender.next_cmd_id(), "cmd_0003")


class TestNormalizedEvent(unittest.TestCase):
    """NormalizedEvent 测试"""

    def test_get_match_target_exec(self):
        """exec 事件匹配目标: 完整命令字符串"""
        raw = RawEvent(
            event_id="evt_001", timestamp_ns=0, event_type="exec",
            pid=1, ppid=0, agent_id="a1", agent_framework="test",
            executable="/bin/rm", arguments=["-rf", "/"]
        )
        norm = NormalizedEvent(raw=raw)
        self.assertEqual(norm.get_match_target(), "/bin/rm -rf /")

    def test_get_match_target_file(self):
        """file_open 事件匹配目标: 文件路径"""
        raw = RawEvent(
            event_id="evt_002", timestamp_ns=0, event_type="file_open",
            pid=1, ppid=0, agent_id="a1", agent_framework="test",
            file_path="/project/.env", file_op="read"
        )
        norm = NormalizedEvent(raw=raw)
        self.assertEqual(norm.get_match_target(), "/project/.env")

    def test_get_match_target_net(self):
        """net_conn 事件匹配目标: 地址:端口"""
        raw = RawEvent(
            event_id="evt_003", timestamp_ns=0, event_type="net_conn",
            pid=1, ppid=0, agent_id="a1", agent_framework="test",
            remote_addr="45.33.32.156", remote_port=8080
        )
        norm = NormalizedEvent(raw=raw)
        self.assertEqual(norm.get_match_target(), "45.33.32.156:8080")


class TestScenarioYAML(unittest.TestCase):
    """场景 YAML 加载验证"""

    def test_load_scenario_01(self):
        """场景1 YAML 可正常加载"""
        import yaml
        scenario_path = os.path.join(os.path.dirname(__file__), '..', 'scenarios', 'scenario_01_normal.yaml')
        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        scenario = data['scenario']
        self.assertEqual(scenario['id'], 'scenario-01')
        self.assertEqual(len(scenario['agents']), 1)
        self.assertEqual(len(scenario['event_sequence']), 8)

    def test_load_scenario_02(self):
        """场景2 YAML 可正常加载"""
        import yaml
        scenario_path = os.path.join(os.path.dirname(__file__), '..', 'scenarios', 'scenario_02_dangerous.yaml')
        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        scenario = data['scenario']
        self.assertEqual(scenario['id'], 'scenario-02')
        self.assertEqual(len(scenario['event_sequence']), 6)

    def test_load_scenario_03(self):
        """场景3 YAML 可正常加载"""
        import yaml
        scenario_path = os.path.join(os.path.dirname(__file__), '..', 'scenarios', 'scenario_03_multi_agent.yaml')
        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        scenario = data['scenario']
        self.assertEqual(scenario['id'], 'scenario-03')
        self.assertEqual(len(scenario['agents']), 2)
        self.assertEqual(len(scenario['event_sequence']), 8)

    def test_scenario_event_fields(self):
        """场景事件字段完整性"""
        import yaml
        scenario_path = os.path.join(os.path.dirname(__file__), '..', 'scenarios', 'scenario_01_normal.yaml')
        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        for event in data['scenario']['event_sequence']:
            self.assertIn('seq', event)
            self.assertIn('delay_ms', event)
            self.assertIn('agent', event)
            self.assertIn('type', event)
            self.assertIn(event['type'], ['exec', 'file_open', 'net_conn'])


class TestEndToEndDataFlow(unittest.TestCase):
    """端到端数据流验证 — 场景 → 事件模型 → JSON → 反序列化"""

    def test_scenario_to_event_pipeline(self):
        """场景 YAML → EventSpec → RawEvent → JSON → RawEvent 完整链路"""
        import yaml
        scenario_path = os.path.join(os.path.dirname(__file__), '..', 'scenarios', 'scenario_01_normal.yaml')
        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        clock = VirtualClock(start_ns=1718092800000000000)
        reader = MockPipeReader()
        reader.connect("test_pipe")

        for event_spec in data['scenario']['event_sequence']:
            # 推进虚拟时钟
            clock.advance(event_spec['delay_ms'])

            # 构造 RawEvent（模拟 C++ 探针输出）
            raw = RawEvent(
                event_id=f"evt_{event_spec['seq']:03d}",
                timestamp_ns=clock.now_ns(),
                event_type=event_spec['type'],
                pid=10001,
                ppid=0,
                agent_id=event_spec['agent'],
                agent_framework="LangChain",
                executable=event_spec.get('executable'),
                arguments=event_spec.get('arguments'),
                file_path=event_spec.get('file_path'),
                file_op=event_spec.get('file_op'),
                remote_addr=event_spec.get('remote_addr'),
                remote_port=event_spec.get('remote_port'),
                protocol=event_spec.get('protocol'),
            )

            # 序列化 → 反序列化（模拟管道传输）
            json_line = raw.to_json_line()
            restored = RawEvent.from_json_line(json_line)

            # 注入到 MockPipeReader
            reader.inject_event(restored)

        # 验证所有 8 个事件可读取
        self.assertEqual(reader.pending_count, 8)
        events_read = []
        while reader.pending_count > 0:
            events_read.append(reader.read_event())

        self.assertEqual(len(events_read), 8)
        # 验证时间戳递增
        for i in range(1, len(events_read)):
            self.assertGreater(events_read[i].timestamp_ns, events_read[i-1].timestamp_ns)


if __name__ == '__main__':
    unittest.main()
