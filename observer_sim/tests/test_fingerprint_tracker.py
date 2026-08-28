"""
test_fingerprint_tracker.py — L-T1 指纹追踪模块测试

验证:
1. 同命令不同参数顺序 → 同指纹（去伪装）
2. 不同可执行路径/文件路径/远端地址端口 → 不同指纹
3. 时间戳/pid/event_id 变化 → 指纹不变（排除易变字段）
4. L0 JSONL 行含 fingerprint 字段
5. 旧格式 JSONL（无 fingerprint 字段）可正常 from_json_line（向后兼容）
6. BehaviorGraph 节点 metadata 含 fingerprint（预置输出结构）
"""

import os
import sys
import json
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.event import RawEvent, NormalizedEvent
from observer_core.audit.fingerprint_tracker import FingerprintTracker
from observer_core.audit.audit_logger import AuditLogger, AuditEntry
from observer_core.audit.behavior_graph import BehaviorGraph


def _make_raw_event(event_id: str, agent_id: str, event_type: str,
                    timestamp_ns: int = 0, pid: int = 10001,
                    executable: str = None, arguments: list = None,
                    file_path: str = None, file_op: str = None,
                    remote_addr: str = None, remote_port: int = None) -> RawEvent:
    """创建测试用 RawEvent"""
    return RawEvent(
        event_id=event_id,
        timestamp_ns=timestamp_ns,
        event_type=event_type,
        pid=pid,
        ppid=1,
        agent_id=agent_id,
        agent_framework="LangChain",
        executable=executable,
        arguments=arguments,
        file_path=file_path,
        file_op=file_op,
        remote_addr=remote_addr,
        remote_port=remote_port,
    )


def _make_event(event_type: str, event_id: str = "evt-1",
                agent_id: str = "agent-1", timestamp_ns: int = 0,
                pid: int = 10001, **kwargs) -> NormalizedEvent:
    """创建测试用 NormalizedEvent"""
    raw = _make_raw_event(event_id=event_id, agent_id=agent_id,
                          event_type=event_type, timestamp_ns=timestamp_ns,
                          pid=pid, **kwargs)
    return NormalizedEvent(raw=raw)


class TestFingerprintTracker(unittest.TestCase):
    """指纹计算规则测试"""

    def test_exec_args_order_insensitive(self):
        """同命令不同参数顺序 → 同指纹"""
        e1 = _make_event("exec", executable="/usr/bin/git",
                         arguments=["clone", "https://example.com/repo.git"])
        e2 = _make_event("exec", executable="/usr/bin/git",
                         arguments=["https://example.com/repo.git", "clone"])
        self.assertEqual(FingerprintTracker.fingerprint_event(e1),
                         FingerprintTracker.fingerprint_event(e2))

    def test_exec_different_executable_differs(self):
        """不同可执行路径 → 不同指纹"""
        e1 = _make_event("exec", executable="/usr/bin/git", arguments=["status"])
        e2 = _make_event("exec", executable="/usr/bin/svn", arguments=["status"])
        self.assertNotEqual(FingerprintTracker.fingerprint_event(e1)[1],
                            FingerprintTracker.fingerprint_event(e2)[1])

    def test_exec_different_args_differ(self):
        """不同参数 → 不同指纹"""
        e1 = _make_event("exec", executable="/usr/bin/git", arguments=["status"])
        e2 = _make_event("exec", executable="/usr/bin/git", arguments=["push"])
        self.assertNotEqual(FingerprintTracker.fingerprint_event(e1)[1],
                            FingerprintTracker.fingerprint_event(e2)[1])

    def test_file_open_differs_by_path_and_op(self):
        """文件事件：路径或操作不同 → 不同指纹"""
        e1 = _make_event("file_open", file_path="/home/dev/a.py", file_op="read")
        e2 = _make_event("file_open", file_path="/home/dev/a.py", file_op="write")
        e3 = _make_event("file_open", file_path="/home/dev/b.py", file_op="read")
        self.assertNotEqual(FingerprintTracker.fingerprint_event(e1)[1],
                            FingerprintTracker.fingerprint_event(e2)[1])
        self.assertNotEqual(FingerprintTracker.fingerprint_event(e1)[1],
                            FingerprintTracker.fingerprint_event(e3)[1])

    def test_net_conn_differs_by_addr_port(self):
        """网络事件：地址或端口不同 → 不同指纹"""
        e1 = _make_event("net_conn", remote_addr="10.0.0.1", remote_port=443)
        e2 = _make_event("net_conn", remote_addr="10.0.0.1", remote_port=80)
        e3 = _make_event("net_conn", remote_addr="10.0.0.2", remote_port=443)
        self.assertNotEqual(FingerprintTracker.fingerprint_event(e1)[1],
                            FingerprintTracker.fingerprint_event(e2)[1])
        self.assertNotEqual(FingerprintTracker.fingerprint_event(e1)[1],
                            FingerprintTracker.fingerprint_event(e3)[1])

    def test_volatile_fields_ignored(self):
        """时间戳/pid/event_id 变化 → 指纹不变"""
        e1 = _make_event("exec", event_id="evt-1", timestamp_ns=1000, pid=10001,
                         executable="/bin/rm", arguments=["-rf", "/tmp/x"])
        e2 = _make_event("exec", event_id="evt-2", timestamp_ns=999999999, pid=99999,
                         executable="/bin/rm", arguments=["-rf", "/tmp/x"])
        self.assertEqual(FingerprintTracker.fingerprint_event(e1),
                         FingerprintTracker.fingerprint_event(e2))

    def test_unknown_type_returns_none(self):
        """未知事件类型 → fingerprint None"""
        e = _make_event("unknown_type")
        ftype, fp = FingerprintTracker.fingerprint_event(e)
        self.assertEqual(ftype, "unknown_type")
        self.assertIsNone(fp)


class TestFingerprintOutput(unittest.TestCase):
    """L0 输出字段透传与旧文件兼容测试"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_audit_entry_includes_fingerprint(self):
        """L0 JSONL 行含 fingerprint 字段"""
        logger = AuditLogger(output_dir=self.tmpdir)
        logger.start_scenario("scenario-01")
        event = _make_event("exec", executable="/usr/bin/git", arguments=["status"])
        logger.log_event(event, description="exec: git")
        logger.close()

        with open(logger.current_file, "r", encoding="utf-8") as f:
            data = json.loads(f.readline())
        self.assertIn("fingerprint", data)
        expected = FingerprintTracker.fingerprint_event(event)[1]
        self.assertEqual(data["fingerprint"], expected)
        self.assertIsNotNone(expected)

    def test_from_json_line_compat_without_fingerprint(self):
        """旧格式 JSONL（无 fingerprint 字段）可正常反序列化"""
        old_line = json.dumps({
            "event_id": "evt-old", "agent_id": "a", "event_type": "exec",
            "timestamp_ns": 0, "pid": 1, "description": "x",
            "command_string": None, "file_path": None, "remote_addr": None,
            "matched_rules": [], "highest_rule_action": "allow",
            "risk_score": 0.0, "risk_level": "LOW", "dimension_scores": {},
            "decision_action": "ALLOW", "decision_tier": "TIER1",
            "decision_reason": "", "blocked": False, "blocking_tier": "",
            "blocking_details": "", "cmd_id": "", "processing_time_ms": 0.0,
        }, ensure_ascii=False)
        entry = AuditEntry.from_json_line(old_line)
        self.assertEqual(entry.event_id, "evt-old")
        self.assertIsNone(entry.fingerprint)

    def test_graph_metadata_includes_fingerprint(self):
        """BehaviorGraph 节点 metadata 含 fingerprint（预置输出结构）"""
        graph = BehaviorGraph()
        event = _make_event("exec", executable="/usr/bin/git", arguments=["status"])
        node = graph.add_event(event)
        expected = FingerprintTracker.fingerprint_event(event)[1]
        self.assertEqual(node.metadata.get("fingerprint"), expected)


if __name__ == "__main__":
    unittest.main()
