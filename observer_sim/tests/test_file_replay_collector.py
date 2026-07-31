"""
tests/test_file_replay_collector.py — FileReplayCollector 单元测试

测试覆盖:
  1. JSONL 文件加载（正常数据、注释行、空行、格式错误）
  2. CSV 文件加载
  3. capabilities() 返回值验证
  4. send_command() 返回 False + 日志记录
  5. 生命周期管理（attach/detach 状态转换）
  6. 事件格式一致性（与 RawEvent 模型对齐）
  7. 白盒测试数据文件回放
  8. 数据校验规则（缺少必填字段、未知 event_type）
"""

import os
import json
import logging
import tempfile
import pytest

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.file_replay_collector import FileReplayCollector
from collector.base_collector import ICollector, CollectorCapabilities
from models.event import RawEvent


# ============================================================
# 辅助函数
# ============================================================

def _create_collector(config: dict = None) -> FileReplayCollector:
    """创建 FileReplayCollector 实例"""
    if config is None:
        config = {
            "file_replay": {
                "default_agent_id": "test-agent",
            }
        }
    return FileReplayCollector(config)


def _write_jsonl(tmpdir: str, lines: list, filename: str = "test.jsonl") -> str:
    """写入 JSONL 临时文件"""
    path = os.path.join(tmpdir, filename)
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    return path


# ============================================================
# 测试类: JSONL 文件加载
# ============================================================

class TestJSONLLoading:
    """JSONL 文件加载测试"""

    def test_load_basic_jsonl(self, tmp_path):
        """加载基本 JSONL 文件"""
        lines = [
            json.dumps({"event_type": "exec", "pid": 100, "executable": "/bin/ls",
                        "timestamp_ns": 1000}),
            json.dumps({"event_type": "file_open", "pid": 100,
                        "file_path": "/etc/passwd", "file_op": "read",
                        "timestamp_ns": 2000}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()

        count = collector.load_data_file(path)

        assert count == 2
        assert collector.event_count == 2

    def test_load_with_comments(self, tmp_path):
        """加载含注释行的 JSONL（白盒特性）"""
        lines = [
            "# 这是注释行",
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000}),
            "# 另一个注释",
            "",  # 空行
            json.dumps({"event_type": "net_conn", "pid": 100,
                        "remote_addr": "1.2.3.4", "remote_port": 80,
                        "protocol": "TCP", "timestamp_ns": 2000}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()

        count = collector.load_data_file(path)

        assert count == 2  # 注释行和空行被跳过

    def test_load_with_invalid_json(self, tmp_path):
        """加载含无效 JSON 的文件（跳过无效行）"""
        lines = [
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000}),
            "this is not json",
            json.dumps({"event_type": "file_open", "pid": 100,
                        "file_path": "/tmp/x", "timestamp_ns": 2000}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()

        count = collector.load_data_file(path)

        assert count == 2  # 无效行被跳过

    def test_load_missing_event_type(self, tmp_path):
        """缺少 event_type 的行被跳过"""
        lines = [
            json.dumps({"pid": 100, "executable": "/bin/ls"}),  # 无 event_type
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()

        count = collector.load_data_file(path)

        assert count == 1

    def test_load_invalid_event_type(self, tmp_path):
        """未知 event_type 的行被跳过"""
        lines = [
            json.dumps({"event_type": "unknown_type", "pid": 100}),
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()

        count = collector.load_data_file(path)

        assert count == 1

    def test_load_file_not_found(self):
        """文件不存在抛出 FileNotFoundError"""
        collector = _create_collector()

        with pytest.raises(FileNotFoundError):
            collector.load_data_file("/nonexistent/path.jsonl")

    def test_load_empty_file(self, tmp_path):
        """空文件加载成功，事件数为 0"""
        path = _write_jsonl(str(tmp_path), [])
        collector = _create_collector()

        count = collector.load_data_file(path)

        assert count == 0

    def test_load_all_comments(self, tmp_path):
        """全部是注释的文件，事件数为 0"""
        lines = ["# comment 1", "# comment 2", ""]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()

        count = collector.load_data_file(path)

        assert count == 0


# ============================================================
# 测试类: CSV 文件加载
# ============================================================

class TestCSVLoading:
    """CSV 文件加载测试"""

    def test_load_basic_csv(self, tmp_path):
        """加载基本 CSV 文件"""
        path = os.path.join(str(tmp_path), "test.csv")
        with open(path, "w") as f:
            f.write("event_type,pid,ppid,executable,timestamp_ns\n")
            f.write("exec,100,99,/bin/ls,1000\n")
            f.write("exec,101,99,/bin/cat,2000\n")

        collector = _create_collector()
        count = collector.load_data_file(path)

        assert count == 2

    def test_csv_with_all_event_types(self, tmp_path):
        """CSV 包含三种事件类型"""
        path = os.path.join(str(tmp_path), "test.csv")
        with open(path, "w") as f:
            f.write("event_type,pid,file_path,file_op,remote_addr,remote_port,protocol,timestamp_ns\n")
            f.write("exec,100,,,,,,1000\n")
            f.write("file_open,100,/etc/passwd,read,,,,2000\n")
            f.write("net_conn,100,,,,8.8.8.8,53,TCP,3000\n")

        collector = _create_collector()
        count = collector.load_data_file(path)

        assert count == 3


# ============================================================
# 测试类: 事件格式一致性
# ============================================================

class TestEventFormat:
    """事件格式一致性测试"""

    def test_events_are_raw_event(self, tmp_path):
        """加载的事件是 RawEvent 实例"""
        lines = [
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())

        assert len(events) == 1
        assert isinstance(events[0], RawEvent)

    def test_event_type_values(self, tmp_path):
        """event_type 值域与其他 Collector 一致"""
        lines = [
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000}),
            json.dumps({"event_type": "file_open", "pid": 100,
                        "file_path": "/etc/passwd", "timestamp_ns": 2000}),
            json.dumps({"event_type": "net_conn", "pid": 100,
                        "remote_addr": "1.2.3.4", "remote_port": 80,
                        "protocol": "TCP", "timestamp_ns": 3000}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())
        types = {e.event_type for e in events}

        assert types == {"exec", "file_open", "net_conn"}

    def test_agent_framework_is_file_replay(self, tmp_path):
        """agent_framework 固定为 file_replay"""
        lines = [
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())
        assert events[0].agent_framework == "file_replay"

    def test_agent_id_from_config(self, tmp_path):
        """agent_id 从配置读取"""
        lines = [
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector({"file_replay": {"default_agent_id": "my-agent"}})
        collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())
        assert events[0].agent_id == "my-agent"

    def test_agent_id_from_data(self, tmp_path):
        """agent_id 从数据文件读取（覆盖配置）"""
        lines = [
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000,
                        "agent_id": "data-agent"}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())
        assert events[0].agent_id == "data-agent"

    def test_event_id_auto_generated(self, tmp_path):
        """event_id 自动生成"""
        lines = [
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000}),
            json.dumps({"event_type": "exec", "pid": 101,
                        "executable": "/bin/cat", "timestamp_ns": 2000}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())
        assert events[0].event_id == "replay_evt_000001"
        assert events[1].event_id == "replay_evt_000002"

    def test_event_id_from_data(self, tmp_path):
        """event_id 从数据读取（覆盖自动生成）"""
        lines = [
            json.dumps({"event_type": "exec", "pid": 100,
                        "executable": "/bin/ls", "timestamp_ns": 1000,
                        "event_id": "custom_id_001"}),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())
        assert events[0].event_id == "custom_id_001"

    def test_to_dict_roundtrip(self, tmp_path):
        """RawEvent → to_dict → from_dict → 一致"""
        lines = [
            json.dumps({
                "event_type": "exec", "pid": 100, "ppid": 99,
                "executable": "/bin/ls", "arguments": ["ls", "-la"],
                "timestamp_ns": 1000, "agent_id": "test",
                "agent_framework": "file_replay"
            }),
        ]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())
        d = events[0].to_dict()
        restored = RawEvent.from_dict(d)

        assert restored.event_type == events[0].event_type
        assert restored.pid == events[0].pid
        assert restored.executable == events[0].executable
        assert restored.arguments == events[0].arguments


# ============================================================
# 测试类: capabilities()
# ============================================================

class TestCapabilities:
    """能力查询测试"""

    def test_is_icollector(self):
        """实现 ICollector 接口"""
        collector = _create_collector()
        assert isinstance(collector, ICollector)

    def test_capabilities_name(self):
        """能力名称为 FileReplay"""
        caps = _create_collector().capabilities()
        assert caps.name == "FileReplay"

    def test_capabilities_observe(self):
        """支持观测"""
        caps = _create_collector().capabilities()
        assert caps.can_observe is True

    def test_capabilities_no_blocking(self):
        """不支持阻断"""
        caps = _create_collector().capabilities()
        assert caps.can_block_tier2 is False
        assert caps.can_block_tier3 is False

    def test_capabilities_transparent(self):
        """对 Agent 无感知"""
        caps = _create_collector().capabilities()
        assert caps.is_transparent is True

    def test_capabilities_performance_low(self):
        """性能开销低"""
        caps = _create_collector().capabilities()
        assert caps.performance_overhead == "low"

    def test_capabilities_time_source(self):
        """时间源为 file_timestamp"""
        caps = _create_collector().capabilities()
        assert caps.time_source == "file_timestamp"


# ============================================================
# 测试类: send_command()
# ============================================================

class TestSendCommand:
    """阻断指令测试"""

    def test_send_command_returns_false(self):
        """send_command 始终返回 False"""
        collector = _create_collector()
        assert collector.send_command(None) is False

    def test_send_command_logs_warning(self, caplog):
        """send_command 记录警告日志"""
        collector = _create_collector()
        with caplog.at_level(logging.WARNING):
            collector.send_command(None)

        assert any("不支持" in r.message or "回放" in r.message
                    for r in caplog.records)


# ============================================================
# 测试类: 生命周期管理
# ============================================================

class TestLifecycle:
    """生命周期管理测试"""

    def test_initial_state(self):
        """初始状态未附着"""
        collector = _create_collector()
        assert collector._attached is False
        assert collector.event_count == 0
        assert collector.data_path is None

    def test_attach_without_data_returns_false(self):
        """未加载数据时 attach 返回 False"""
        collector = _create_collector()
        assert collector.attach() is False

    def test_attach_with_data_returns_true(self, tmp_path):
        """加载数据后 attach 返回 True"""
        lines = [json.dumps({"event_type": "exec", "pid": 100,
                             "executable": "/bin/ls", "timestamp_ns": 1000})]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)

        assert collector.attach() is True

    def test_detach_clears_events(self, tmp_path):
        """detach 清理事件"""
        lines = [json.dumps({"event_type": "exec", "pid": 100,
                             "executable": "/bin/ls", "timestamp_ns": 1000})]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)
        collector.attach()

        collector.detach()

        assert collector.event_count == 0
        assert collector._attached is False

    def test_get_process_tree_empty(self):
        """get_process_tree 返回空字典"""
        collector = _create_collector()
        assert collector.get_process_tree() == {}

    def test_start_without_attach_yields_nothing(self, tmp_path):
        """未 attach 时 start 不产出事件"""
        lines = [json.dumps({"event_type": "exec", "pid": 100,
                             "executable": "/bin/ls", "timestamp_ns": 1000})]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)

        events = list(collector.start())
        assert len(events) == 0


# ============================================================
# 测试类: 白盒测试数据文件回放
# ============================================================

class TestWhiteboxDataFiles:
    """白盒测试数据文件回放测试"""

    def _get_data_dir(self) -> str:
        """获取测试数据目录"""
        return os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "test_data", "whitebox")

    def test_malicious_curl_jsonl(self):
        """回放 malicious_curl.jsonl"""
        data_dir = self._get_data_dir()
        path = os.path.join(data_dir, "malicious_curl.jsonl")
        if not os.path.exists(path):
            pytest.skip("测试数据文件不存在")

        collector = _create_collector()
        count = collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())

        assert count == 4
        assert len(events) == 4
        assert events[0].event_type == "exec"
        assert events[0].executable == "/usr/bin/curl"
        assert events[1].event_type == "net_conn"
        assert events[1].remote_addr == "192.168.1.100"
        assert events[2].event_type == "file_open"
        assert events[2].file_op == "write"
        assert events[3].event_type == "exec"
        assert events[3].executable == "/bin/bash"

    def test_normal_dev_jsonl(self):
        """回放 normal_dev.jsonl"""
        data_dir = self._get_data_dir()
        path = os.path.join(data_dir, "normal_dev.jsonl")
        if not os.path.exists(path):
            pytest.skip("测试数据文件不存在")

        collector = _create_collector()
        count = collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())

        assert count == 5
        assert len(events) == 5
        # 全部是正常操作
        types = [e.event_type for e in events]
        assert types == ["exec", "file_open", "file_open", "exec", "net_conn"]

    def test_sample_events_csv(self):
        """回放 sample_events.csv"""
        data_dir = self._get_data_dir()
        path = os.path.join(data_dir, "sample_events.csv")
        if not os.path.exists(path):
            pytest.skip("测试数据文件不存在")

        collector = _create_collector()
        count = collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())

        assert count == 3
        assert events[0].event_type == "exec"
        assert events[1].event_type == "file_open"
        assert events[2].event_type == "net_conn"
        assert events[2].remote_addr == "8.8.8.8"
        assert events[2].remote_port == 53


# ============================================================
# 测试类: 数据校验规则
# ============================================================

class TestDataValidation:
    """数据校验规则测试"""

    def test_missing_required_field_event_type(self, tmp_path):
        """缺少 event_type 跳过"""
        lines = [json.dumps({"pid": 100, "executable": "/bin/ls"})]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()

        count = collector.load_data_file(path)
        assert count == 0

    def test_empty_event_type(self, tmp_path):
        """空 event_type 跳过"""
        lines = [json.dumps({"event_type": "", "pid": 100})]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()

        count = collector.load_data_file(path)
        assert count == 0

    def test_defaults_for_missing_optional_fields(self, tmp_path):
        """可选字段缺失时使用默认值"""
        lines = [json.dumps({"event_type": "exec", "pid": 100,
                             "executable": "/bin/ls"})]
        path = _write_jsonl(str(tmp_path), lines)
        collector = _create_collector()
        collector.load_data_file(path)
        collector.attach()

        events = list(collector.start())
        raw = events[0]

        assert raw.timestamp_ns == 0  # 默认值
        assert raw.ppid == 0
        assert raw.arguments is None
        assert raw.file_path is None
        assert raw.remote_addr is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
