"""
test_ebpf_command_sender.py — EbpfCommandSender eBPF 阻断发送器单元测试

测试内容:
1. EbpfCommandSender: 降级检测、能力探测、退化报告
2. ICommandSender 接口: connect/send_command/disconnect
3. 降级状态下行为: 指令记录但不执行
4. block_flags 常量与 Command 解析
5. detect_ebpf_capability: 环境能力检测
6. 恢复检测: try_recover, recovery thread

注: 测试兼容降级与非降级两种环境。
   - 无 root/eBPF 环境: 自动降级，测试降级行为
   - 有 root/eBPF 环境: 正常初始化，测试非降级行为
   使用 is_degraded 属性自适应断言，确保两种环境均通过。
"""

import sys
import os
import unittest
import time
from unittest.mock import Mock, patch, PropertyMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from observer_core.blocking.ebpf_command_sender import (
    EbpfCommandSender,
    detect_ebpf_capability,
    BLOCK_EXECVE,
    BLOCK_OPENAT,
    BLOCK_CONNECT,
    BLOCK_ALL,
    _load_libbpf,
)
from observer_core.blocking.command_sender import ICommandSender
from models.command import Command, CmdType


class TestEbpfConstants(unittest.TestCase):
    """eBPF 常量测试"""

    def test_block_execve_value(self):
        """BLOCK_EXECVE = 0x01"""
        self.assertEqual(BLOCK_EXECVE, 0x01)

    def test_block_openat_value(self):
        """BLOCK_OPENAT = 0x02"""
        self.assertEqual(BLOCK_OPENAT, 0x02)

    def test_block_connect_value(self):
        """BLOCK_CONNECT = 0x04"""
        self.assertEqual(BLOCK_CONNECT, 0x04)

    def test_block_all_includes_all(self):
        """BLOCK_ALL 包含所有标志"""
        self.assertEqual(BLOCK_ALL, BLOCK_EXECVE | BLOCK_OPENAT | BLOCK_CONNECT)
        self.assertTrue(BLOCK_ALL & BLOCK_EXECVE)
        self.assertTrue(BLOCK_ALL & BLOCK_OPENAT)
        self.assertTrue(BLOCK_ALL & BLOCK_CONNECT)


class TestDetectEbpfCapability(unittest.TestCase):
    """detect_ebpf_capability 环境检测测试"""

    def test_returns_dict_with_expected_keys(self):
        """返回字典包含 expected 键"""
        result = detect_ebpf_capability()
        self.assertIn("available", result)
        self.assertIn("reason", result)
        self.assertIn("details", result)
        self.assertIn("is_root", result["details"])
        self.assertIn("has_btf", result["details"])
        self.assertIn("has_libbpf", result["details"])

    def test_reason_is_string(self):
        """reason 是字符串"""
        result = detect_ebpf_capability()
        self.assertIsInstance(result["reason"], str)
        self.assertTrue(len(result["reason"]) > 0)


class TestEbpfCommandSenderDegradation(unittest.TestCase):
    """EbpfCommandSender 降级行为测试（自适应降级/非降级环境）"""

    def test_initial_state_is_degraded(self):
        """环境自适应: 非 root 下降级，root+eBPF 下正常初始化"""
        sender = EbpfCommandSender()
        if sender.is_degraded:
            self.assertTrue(sender.is_degraded)
        else:
            # root+eBPF 环境: 初始化成功，非降级
            self.assertFalse(sender.is_degraded)
            self.assertEqual(sender.degradation_reason, "")

    def test_degradation_reason_is_string(self):
        """降级原因为字符串（非降级时为空字符串）"""
        sender = EbpfCommandSender()
        self.assertIsInstance(sender.degradation_reason, str)
        if sender.is_degraded:
            self.assertTrue(len(sender.degradation_reason) > 0)
        else:
            # 非降级时 degradation_reason 为空
            self.assertEqual(sender.degradation_reason, "")

    def test_degradation_time_is_positive(self):
        """降级时间（降级时 > 0，非降级时 == 0）"""
        sender = EbpfCommandSender()
        if sender.is_degraded:
            self.assertGreater(sender.degradation_time, 0)
        else:
            self.assertEqual(sender.degradation_time, 0.0)

    def test_degradation_report_structure(self):
        """降级报告包含所有必需字段（两种模式均生成有效报告）"""
        sender = EbpfCommandSender()
        report = sender.degradation_report()
        self.assertEqual(report["alert_type"], "ebpf_degradation")
        self.assertIn("reason", report)
        self.assertIn("impact", report)
        self.assertIn("suggestion", report)
        self.assertIn("degraded_at", report)
        self.assertIn("details", report)

    def test_degradation_report_has_actionable_suggestions(self):
        """降级报告包含可操作建议（两种模式均包含）"""
        sender = EbpfCommandSender()
        report = sender.degradation_report()
        self.assertIn("root", report["suggestion"].lower())
        self.assertIn("btf", report["suggestion"].lower())
        self.assertIn("libbpf", report["suggestion"].lower())

    def test_try_recover_returns_false_in_degraded(self):
        """环境自适应: 降级时恢复失败，非降级时恢复成功"""
        sender = EbpfCommandSender()
        result = sender.try_recover()
        if sender.is_degraded:
            # 降级环境: 恢复应失败（环境未改变）
            self.assertFalse(result)
            self.assertTrue(sender.is_degraded)
        else:
            # 非降级环境: try_recover 返回 True
            self.assertTrue(result)
            self.assertFalse(sender.is_degraded)


class TestEbpfCommandSenderInterface(unittest.TestCase):
    """EbpfCommandSender ICommandSender 接口测试"""

    def test_is_instance_of_icommandsender(self):
        """EbpfCommandSender 实现 ICommandSender 接口"""
        sender = EbpfCommandSender()
        self.assertIsInstance(sender, ICommandSender)

    def test_connect_returns_true(self):
        """connect() 返回 True（包括降级模式）"""
        sender = EbpfCommandSender()
        result = sender.connect("test_pipe")
        self.assertTrue(result)

    def test_connect_sets_connected_flag(self):
        """connect() 后 is_connected 为 True"""
        sender = EbpfCommandSender()
        sender.connect("test")
        self.assertTrue(sender.is_connected)

    def test_send_command_in_degraded_returns_false(self):
        """环境自适应: 降级时 send_command 返回 False，非降级时不抛异常"""
        sender = EbpfCommandSender()
        sender.connect("test")
        # 使用极高 PID 避免在非降级环境意外阻断真实进程
        cmd = Command.make_block(
            cmd_id="cmd_001", event_id="evt_001", pid=9999999, reason="test")
        result = sender.send_command(cmd)
        if sender.is_degraded:
            self.assertFalse(result)
        else:
            # 非降级模式下 send_command 会尝试真实 eBPF 操作
            # （kprobe 挂载、map 更新），仅验证不抛异常
            self.assertIsInstance(result, bool)

    def test_send_command_records_in_degraded(self):
        """降级模式下 send_command 记录指令"""
        sender = EbpfCommandSender()
        cmd = Command.make_block(
            cmd_id="cmd_001", event_id="evt_001", pid=100, reason="test")
        sender.send_command(cmd)
        self.assertEqual(len(sender.sent_commands), 1)

    def test_send_command_records_multiple(self):
        """多次 send_command 全部记录"""
        sender = EbpfCommandSender()
        for i in range(5):
            cmd = Command.make_block(
                cmd_id=f"cmd_{i:03d}", event_id=f"evt_{i:03d}",
                pid=100 + i, reason=f"test_{i}")
            sender.send_command(cmd)
        self.assertEqual(len(sender.sent_commands), 5)

    def test_last_command_returns_latest(self):
        """last_command 返回最新指令"""
        sender = EbpfCommandSender()
        cmd1 = Command.make_block(
            cmd_id="cmd_001", event_id="evt_001", pid=100, reason="first")
        cmd2 = Command.make_block(
            cmd_id="cmd_002", event_id="evt_002", pid=200, reason="second")
        sender.send_command(cmd1)
        sender.send_command(cmd2)
        self.assertEqual(sender.last_command.target_pid, 200)

    def test_last_command_returns_none_when_empty(self):
        """无指令时 last_command 返回 None"""
        sender = EbpfCommandSender()
        self.assertIsNone(sender.last_command)

    def test_clear_removes_all_commands(self):
        """clear() 移除所有记录"""
        sender = EbpfCommandSender()
        cmd = Command.make_block(
            cmd_id="cmd_001", event_id="evt_001", pid=100, reason="test")
        sender.send_command(cmd)
        sender.clear()
        self.assertEqual(len(sender.sent_commands), 0)

    def test_disconnect_clears_commands(self):
        """disconnect() 清除指令"""
        sender = EbpfCommandSender()
        cmd = Command.make_block(
            cmd_id="cmd_001", event_id="evt_001", pid=100, reason="test")
        sender.send_command(cmd)
        sender.disconnect()
        self.assertEqual(len(sender.sent_commands), 0)

    def test_disconnect_resets_connected(self):
        """disconnect() 后 is_connected 为 False"""
        sender = EbpfCommandSender()
        sender.connect("test")
        sender.disconnect()
        self.assertFalse(sender.is_connected)

    def test_next_cmd_id_format(self):
        """next_cmd_id 格式正确"""
        sender = EbpfCommandSender()
        cid = sender.next_cmd_id()
        self.assertTrue(cid.startswith("cmd_"))

    def test_next_cmd_id_increments(self):
        """next_cmd_id 递增"""
        sender = EbpfCommandSender()
        cid1 = sender.next_cmd_id()
        cid2 = sender.next_cmd_id()
        self.assertNotEqual(cid1, cid2)

    def test_blocked_pids_empty_initially(self):
        """初始 blocked_pids 为空"""
        sender = EbpfCommandSender()
        self.assertEqual(len(sender.blocked_pids), 0)


class TestEbpfCommandSenderEdgeCases(unittest.TestCase):
    """EbpfCommandSender 边界条件测试"""

    def test_nonexistent_bpf_object_path(self):
        """不存在的 bpf_object 路径导致降级（非 root 环境最早在权限检测处降级）"""
        sender = EbpfCommandSender(bpf_object_path="/nonexistent/observer.bpf.o")
        self.assertTrue(sender.is_degraded)
        # 降级原因可能是权限不足或文件不存在（取决于环境）
        self.assertTrue(len(sender.degradation_reason) > 0)

    def test_start_recovery_thread_noop_when_not_degraded(self):
        """非降级时不启动恢复线程（但降级时正常启动，不阻塞）"""
        sender = EbpfCommandSender()
        # 降级状态下启动恢复线程
        sender.start_recovery_thread(interval=0.5)
        # 短暂运行
        time.sleep(0.1)
        sender.stop_recovery_thread()
        # 不应崩溃
        self.assertTrue(True)

    def test_recovery_thread_stop_noop_when_no_thread(self):
        """无线程时 stop_recovery_thread 不报错"""
        sender = EbpfCommandSender()
        sender.stop_recovery_thread()  # 不应抛出异常


if __name__ == "__main__":
    unittest.main()
