"""
tests/test_ebpf_collector.py — EbpfCollector 单元测试

测试覆盖:
  1. _to_raw_event() 字段映射（execve/openat/connect 三种事件类型）
  2. capabilities() 返回值验证
  3. send_command() 返回 False + 日志记录
  4. 生命周期管理（attach/detach 状态转换）
  5. 事件转换的边界条件

注意: 由于 eBPF 加载需要 root 权限，测试中 mock libbpf 调用，
      重点验证数据转换逻辑而非实际 eBPF 操作。
"""

import struct
import socket
import ctypes
import logging
import pytest
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.ebpf_collector import (
    EbpfCollector, EventT, EventExec, EventFile, EventNet, EventUnion,
    EVENT_EXECVE, EVENT_OPENAT, EVENT_CONNECT,
    FILENAME_MAX_LEN, ARGV_MAX_LEN, COMM_MAX_LEN,
)
from collector.base_collector import CollectorCapabilities


# ============================================================
# 辅助函数
# ============================================================

def _make_execve_event(
    filename: str = "/bin/ls",
    argv_parts: list = None,
    pid: int = 12345,
    ppid: int = 12340,
    uid: int = 1000,
    timestamp_ns: int = 1000000000,
    comm: str = "ls",
) -> bytes:
    """构造 execve 事件的字节数据"""
    event = EventT()
    event.timestamp_ns = timestamp_ns
    event.pid = pid
    event.ppid = ppid
    event.uid = uid
    event.event_type = EVENT_EXECVE
    event.blocked = 0
    event.padding = 0

    # filename
    event.data.exec.filename = filename.encode("utf-8")[:FILENAME_MAX_LEN - 1]

    # argv: \0 分隔的参数列表
    if argv_parts is None:
        argv_parts = ["ls", "-la"]
    argv_bytes = b"\x00".join(a.encode("utf-8") for a in argv_parts) + b"\x00"
    # 使用 memmove 直接写入 event 结构体的 argv 字段偏移
    argv_offset = EventT.data.offset + EventUnion.exec.offset + EventExec.argv.offset
    ctypes.memmove(
        ctypes.addressof(event) + argv_offset,
        argv_bytes,
        min(len(argv_bytes), ARGV_MAX_LEN)
    )

    # comm
    event.comm = comm.encode("utf-8")[:COMM_MAX_LEN - 1]

    return bytes(event)


def _make_openat_event(
    filename: str = "/etc/passwd",
    flags: int = 0,  # O_RDONLY
    pid: int = 12345,
    ppid: int = 12340,
    timestamp_ns: int = 2000000000,
) -> bytes:
    """构造 openat 事件的字节数据"""
    event = EventT()
    event.timestamp_ns = timestamp_ns
    event.pid = pid
    event.ppid = ppid
    event.uid = 1000
    event.event_type = EVENT_OPENAT
    event.blocked = 0
    event.padding = 0

    event.data.file.filename = filename.encode("utf-8")[:FILENAME_MAX_LEN - 1]
    event.data.file.flags = flags
    event.comm = b"cat"

    return bytes(event)


def _make_connect_event(
    ip_addr: str = "93.184.216.34",
    port: int = 443,
    protocol: int = 0,  # TCP
    pid: int = 12345,
    ppid: int = 12340,
    timestamp_ns: int = 3000000000,
) -> bytes:
    """构造 connect 事件的字节数据"""
    event = EventT()
    event.timestamp_ns = timestamp_ns
    event.pid = pid
    event.ppid = ppid
    event.uid = 1000
    event.event_type = EVENT_CONNECT
    event.blocked = 0
    event.padding = 0

    # IP 地址: 点分十进制 → 网络字节序
    event.data.net.ip_addr = struct.unpack("!I", socket.inet_aton(ip_addr))[0]
    # 端口: 主机字节序 → 网络字节序
    event.data.net.port = socket.htons(port)
    event.data.net.protocol = protocol
    event.comm = b"curl"

    return bytes(event)


def _create_collector_mock_lib(config: dict = None) -> EbpfCollector:
    """创建带有 mock libbpf 的 EbpfCollector 实例"""
    if config is None:
        config = {
            "ebpf": {
                "bpf_object_path": "/tmp/test_observer.bpf.o",
                "target_agent_id": "test-agent",
                "perf_buffer_page_count": 64,
            }
        }

    # Mock libbpf
    mock_lib = MagicMock()
    mock_lib.bpf_object__open.return_value = MagicMock()
    mock_lib.bpf_object__load.return_value = 0
    mock_lib.bpf_object__find_program_by_name.return_value = MagicMock()
    mock_lib.bpf_program__attach.return_value = MagicMock()
    mock_lib.bpf_object__find_map_fd_by_name.return_value = 5  # mock fd
    mock_lib.perf_buffer__new_raw.return_value = MagicMock()

    with patch("collector.ebpf_collector._load_libbpf", return_value=mock_lib):
        collector = EbpfCollector(config)
        collector._lib = mock_lib
        # 设置函数签名（已在 __init__ 中调用）
        return collector


# ============================================================
# 测试类: _to_raw_event() 字段映射
# ============================================================

class TestToRawEventExecve:
    """execve 事件转换测试"""

    def test_basic_execve(self):
        """基本 execve 事件转换"""
        collector = _create_collector_mock_lib()
        data = _make_execve_event(
            filename="/bin/ls",
            argv_parts=["ls", "-la", "/tmp"],
            pid=12345,
            ppid=12340,
            timestamp_ns=1000000000,
        )

        raw = collector._to_raw_event(data)

        assert raw is not None
        assert raw.event_id == "ebpf_evt_000001"
        assert raw.event_type == "exec"
        assert raw.pid == 12345
        assert raw.ppid == 12340
        assert raw.agent_id == "test-agent"
        assert raw.agent_framework == "ebpf"
        assert raw.executable == "/bin/ls"
        assert raw.arguments == ["ls", "-la", "/tmp"]
        assert raw.timestamp_ns == 1000000000

    def test_execve_single_arg(self):
        """execve 只有一个参数"""
        collector = _create_collector_mock_lib()
        data = _make_execve_event(
            filename="/usr/bin/python3",
            argv_parts=["python3"],
        )

        raw = collector._to_raw_event(data)

        assert raw is not None
        assert raw.event_type == "exec"
        assert raw.executable == "/usr/bin/python3"
        assert raw.arguments == ["python3"]

    def test_execve_empty_argv(self):
        """execve 空 argv"""
        collector = _create_collector_mock_lib()
        data = _make_execve_event(
            filename="/bin/true",
            argv_parts=[],
        )

        raw = collector._to_raw_event(data)

        assert raw is not None
        assert raw.executable == "/bin/true"
        # 空 argv 应该为 None 或空列表
        assert raw.arguments is None or raw.arguments == []

    def test_execve_seq_increment(self):
        """事件序号自增"""
        collector = _create_collector_mock_lib()

        data1 = _make_execve_event(filename="/bin/ls")
        data2 = _make_execve_event(filename="/bin/cat")

        raw1 = collector._to_raw_event(data1)
        raw2 = collector._to_raw_event(data2)

        assert raw1.event_id == "ebpf_evt_000001"
        assert raw2.event_id == "ebpf_evt_000002"


class TestToRawEventOpenat:
    """openat 事件转换测试"""

    def test_basic_openat_read(self):
        """基本 openat 读事件"""
        collector = _create_collector_mock_lib()
        data = _make_openat_event(
            filename="/etc/passwd",
            flags=0,  # O_RDONLY
            pid=12345,
        )

        raw = collector._to_raw_event(data)

        assert raw is not None
        assert raw.event_type == "file_open"
        assert raw.file_path == "/etc/passwd"
        assert raw.file_op == "read"

    def test_openat_write(self):
        """openat 写事件 (O_WRONLY)"""
        collector = _create_collector_mock_lib()
        data = _make_openat_event(
            filename="/tmp/test.txt",
            flags=1,  # O_WRONLY
        )

        raw = collector._to_raw_event(data)

        assert raw is not None
        assert raw.file_path == "/tmp/test.txt"
        assert raw.file_op == "write"

    def test_openat_rdwr(self):
        """openat 读写事件 (O_RDWR)"""
        collector = _create_collector_mock_lib()
        data = _make_openat_event(
            filename="/tmp/data.bin",
            flags=2,  # O_RDWR
        )

        raw = collector._to_raw_event(data)

        assert raw is not None
        assert raw.file_op == "write"  # O_RDWR 映射为 write


class TestToRawEventConnect:
    """connect 事件转换测试"""

    def test_basic_connect(self):
        """基本 connect 事件"""
        collector = _create_collector_mock_lib()
        data = _make_connect_event(
            ip_addr="93.184.216.34",
            port=443,
            protocol=0,  # TCP
            pid=12345,
        )

        raw = collector._to_raw_event(data)

        assert raw is not None
        assert raw.event_type == "net_conn"
        assert raw.remote_addr == "93.184.216.34"
        assert raw.remote_port == 443
        assert raw.protocol == "TCP"

    def test_connect_different_ip(self):
        """connect 不同 IP 地址"""
        collector = _create_collector_mock_lib()
        data = _make_connect_event(
            ip_addr="10.0.1.100",
            port=5432,
        )

        raw = collector._to_raw_event(data)

        assert raw is not None
        assert raw.remote_addr == "10.0.1.100"
        assert raw.remote_port == 5432

    def test_connect_udp(self):
        """connect UDP 事件"""
        collector = _create_collector_mock_lib()
        data = _make_connect_event(
            ip_addr="8.8.8.8",
            port=53,
            protocol=1,  # UDP
        )

        raw = collector._to_raw_event(data)

        assert raw is not None
        assert raw.protocol == "UDP"


class TestToRawEventEdgeCases:
    """事件转换边界条件测试"""

    def test_unknown_event_type(self):
        """未知事件类型返回 None"""
        collector = _create_collector_mock_lib()
        event = EventT()
        event.event_type = 99  # 未知类型
        data = bytes(event)

        raw = collector._to_raw_event(data)
        assert raw is None

    def test_truncated_data(self):
        """截断数据应返回 None 或优雅处理"""
        collector = _create_collector_mock_lib()
        # 提供比 EventT 更短的数据
        short_data = b"\x00" * 10

        raw = collector._to_raw_event(short_data)
        # 应该能处理（可能返回部分填充的 RawEvent 或 None）
        # 具体行为取决于实现

    def test_empty_data(self):
        """空数据产生默认 RawEvent"""
        collector = _create_collector_mock_lib()
        raw = collector._to_raw_event(b"")
        # 空数据仍会解析为默认值的 RawEvent（event_type=exec 因为 0=EXECVE）
        # 这是预期行为，因为 EventT 的默认 event_type 为 0
        assert raw is not None
        assert raw.event_id.startswith("ebpf_evt_")


# ============================================================
# 测试类: capabilities()
# ============================================================

class TestCapabilities:
    """能力查询测试"""

    def test_capabilities_name(self):
        """能力名称为 Ebpf"""
        collector = _create_collector_mock_lib()
        caps = collector.capabilities()
        assert caps.name == "Ebpf"

    def test_capabilities_observe(self):
        """支持观测"""
        collector = _create_collector_mock_lib()
        caps = collector.capabilities()
        assert caps.can_observe is True

    def test_capabilities_no_block_tier2(self):
        """第一版不支持 Tier2 阻断"""
        collector = _create_collector_mock_lib()
        caps = collector.capabilities()
        assert caps.can_block_tier2 is False

    def test_capabilities_no_block_tier3(self):
        """第一版不支持 Tier3 阻断"""
        collector = _create_collector_mock_lib()
        caps = collector.capabilities()
        assert caps.can_block_tier3 is False

    def test_capabilities_transparent(self):
        """对 Agent 无感知"""
        collector = _create_collector_mock_lib()
        caps = collector.capabilities()
        assert caps.is_transparent is True

    def test_capabilities_performance(self):
        """性能开销低"""
        collector = _create_collector_mock_lib()
        caps = collector.capabilities()
        assert caps.performance_overhead == "low"

    def test_capabilities_time_source(self):
        """时间源为 realtime_monotonic"""
        collector = _create_collector_mock_lib()
        caps = collector.capabilities()
        assert caps.time_source == "realtime_monotonic"


# ============================================================
# 测试类: send_command()
# ============================================================

class TestSendCommand:
    """阻断指令测试"""

    def test_send_command_returns_false(self):
        """send_command 始终返回 False"""
        collector = _create_collector_mock_lib()
        result = collector.send_command(MagicMock())
        assert result is False

    def test_send_command_logs_warning(self, caplog):
        """send_command 记录警告日志"""
        collector = _create_collector_mock_lib()
        with caplog.at_level(logging.WARNING):
            collector.send_command(MagicMock())

        assert any("不支持阻断" in record.message or
                    "第一版" in record.message
                    for record in caplog.records)


# ============================================================
# 测试类: 生命周期管理
# ============================================================

class TestLifecycle:
    """生命周期管理测试"""

    def test_initial_state(self):
        """初始状态未附着"""
        collector = _create_collector_mock_lib()
        assert collector._attached is False
        assert collector._running is False

    def test_get_process_tree_empty(self):
        """get_process_tree 第一版返回空字典"""
        collector = _create_collector_mock_lib()
        tree = collector.get_process_tree()
        assert tree == {}

    def test_detach_resets_state(self):
        """detach 重置状态"""
        collector = _create_collector_mock_lib()
        collector._attached = True
        collector._running = True

        collector.detach()

        assert collector._attached is False
        assert collector._running is False


# ============================================================
# 测试类: RawEvent 字段一致性
# ============================================================

class TestRawEventConsistency:
    """验证 eBPF RawEvent 与模拟 RawEvent 字段一致"""

    def test_event_type_values(self):
        """event_type 值域与模拟模式一致"""
        collector = _create_collector_mock_lib()

        exec_data = _make_execve_event()
        file_data = _make_openat_event()
        net_data = _make_connect_event()

        exec_raw = collector._to_raw_event(exec_data)
        file_raw = collector._to_raw_event(file_data)
        net_raw = collector._to_raw_event(net_data)

        assert exec_raw.event_type == "exec"
        assert file_raw.event_type == "file_open"
        assert net_raw.event_type == "net_conn"

    def test_pid_ppid_are_integers(self):
        """pid/ppid 为整数类型"""
        collector = _create_collector_mock_lib()
        data = _make_execve_event(pid=12345, ppid=12340)
        raw = collector._to_raw_event(data)

        assert isinstance(raw.pid, int)
        assert isinstance(raw.ppid, int)

    def test_timestamp_ns_is_integer(self):
        """timestamp_ns 为整数类型"""
        collector = _create_collector_mock_lib()
        data = _make_execve_event(timestamp_ns=1000000000)
        raw = collector._to_raw_event(data)

        assert isinstance(raw.timestamp_ns, int)
        assert raw.timestamp_ns == 1000000000

    def test_agent_id_from_config(self):
        """agent_id 从配置读取"""
        config = {
            "ebpf": {
                "bpf_object_path": "/tmp/test.bpf.o",
                "target_agent_id": "my-custom-agent",
            }
        }
        collector = _create_collector_mock_lib(config)
        data = _make_execve_event()
        raw = collector._to_raw_event(data)

        assert raw.agent_id == "my-custom-agent"

    def test_agent_framework_is_ebpf(self):
        """agent_framework 固定为 ebpf"""
        collector = _create_collector_mock_lib()
        data = _make_execve_event()
        raw = collector._to_raw_event(data)

        assert raw.agent_framework == "ebpf"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
