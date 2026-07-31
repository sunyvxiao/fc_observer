"""
tests/test_ebpf_field_mapping.py — eBPF 字段映射一致性测试

验证 EbpfCollector._to_raw_event() 三种事件类型的字段映射
与模拟探针 (SimulationCollector) 产出的 RawEvent 格式完全等价。

测试方法: 构造 EventT ctypes 结构体 → 转为 bytes → 调用 _to_raw_event() → 断言 RawEvent 字段。
无需真实 eBPF 环境，mock libbpf 即可。
"""

import os
import sys
import ctypes
import struct
import socket
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 导入 eBPF 结构定义
from collector.ebpf_collector import (
    EventT, EventExec, EventFile, EventNet, EventUnion,
    EVENT_EXECVE, EVENT_OPENAT, EVENT_CONNECT,
    FILENAME_MAX_LEN, ARGV_MAX_LEN, COMM_MAX_LEN,
)


# ============================================================
# 辅助函数
# ============================================================

def _make_ebpf_collector():
    """
    创建 EbpfCollector 实例（mock libbpf，不加载真实 eBPF 程序）。
    """
    with patch("collector.ebpf_collector._load_libbpf") as mock_lib:
        mock_lib.return_value = MagicMock()
        from collector.ebpf_collector import EbpfCollector
        config = {
            "ebpf": {
                "bpf_object_path": "ebpf/observer.bpf.o",
                "target_agent_id": "test-agent",
                "perf_buffer_page_count": 64,
            }
        }
        collector = EbpfCollector(config)
        return collector


def _build_event_bytes(event_type, pid, ppid, uid, timestamp_ns,
                       data_union, comm=b"test"):
    """
    构造 EventT 结构体并转为 bytes。
    """
    event = EventT()
    event.timestamp_ns = timestamp_ns
    event.pid = pid
    event.ppid = ppid
    event.uid = uid
    event.event_type = event_type
    event.blocked = 0
    event.padding = 0
    # 设置 union 数据
    if event_type == EVENT_EXECVE:
        event.data.exec.filename = data_union.get("filename", b"")
        # argv 需要保留 \0 分隔符，不能通过 ctypes 赋值（会在第一个 \0 截断）
        # 使用 memmove 写入完整缓冲区
        argv_data = data_union.get("argv", b"")
        if argv_data:
            argv_src = ctypes.addressof(event) + EventT.data.offset + EventUnion.exec.offset + EventExec.argv.offset
            argv_buf = ctypes.create_string_buffer(argv_data, ARGV_MAX_LEN)
            ctypes.memmove(argv_src, argv_buf, ARGV_MAX_LEN)
    elif event_type == EVENT_OPENAT:
        event.data.file.filename = data_union.get("filename", b"")
        event.data.file.flags = data_union.get("flags", 0)
    elif event_type == EVENT_CONNECT:
        event.data.net.ip_addr = data_union.get("ip_addr", 0)
        event.data.net.port = data_union.get("port", 0)
        event.data.net.protocol = data_union.get("protocol", 0)
    # 设置 comm
    comm_padded = comm[:COMM_MAX_LEN - 1] + b"\x00" * max(0, COMM_MAX_LEN - len(comm))
    event.comm = comm_padded[:COMM_MAX_LEN]

    return bytes(event)


# ============================================================
# 测试类: execve 字段映射
# ============================================================

class TestExecveMapping:
    """用例 1.1: 验证 execve → exec 字段映射"""

    def test_execve_basic_mapping(self):
        """基本 execve 事件映射到 RawEvent"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=EVENT_EXECVE,
            pid=12345,
            ppid=12340,
            uid=1000,
            timestamp_ns=1718092800000000000,
            data_union={
                "filename": b"/usr/bin/python3",
                "argv": b"python3\x00script.py\x00--verbose\x00",
            },
            comm=b"python3",
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "exec"
        assert raw.pid == 12345
        assert raw.ppid == 12340
        assert raw.executable == "/usr/bin/python3"
        assert raw.arguments == ["python3", "script.py", "--verbose"]
        assert raw.timestamp_ns == 1718092800000000000
        assert raw.agent_id == "test-agent"
        assert raw.event_id.startswith("ebpf_evt_")
        assert raw.agent_framework == "ebpf"

    def test_execve_single_argument(self):
        """execve 只有一个参数"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=EVENT_EXECVE,
            pid=100,
            ppid=99,
            uid=0,
            timestamp_ns=1000000,
            data_union={
                "filename": b"/bin/true",
                "argv": b"true\x00",
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "exec"
        assert raw.executable == "/bin/true"
        assert raw.arguments == ["true"]

    def test_execve_empty_argv(self):
        """execve argv 为空时 arguments 为 None"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=EVENT_EXECVE,
            pid=200,
            ppid=199,
            uid=1000,
            timestamp_ns=2000000,
            data_union={
                "filename": b"/bin/ls",
                "argv": b"\x00",
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "exec"
        assert raw.executable == "/bin/ls"
        assert raw.arguments is None


# ============================================================
# 测试类: openat 字段映射
# ============================================================

class TestOpenatMapping:
    """用例 1.2: 验证 openat → file_open 字段映射"""

    def test_openat_read(self):
        """O_RDONLY → file_op='read'"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=EVENT_OPENAT,
            pid=5000,
            ppid=4999,
            uid=1000,
            timestamp_ns=1718092800100000000,
            data_union={
                "filename": b"/etc/passwd",
                "flags": 0,  # O_RDONLY
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "file_open"
        assert raw.file_path == "/etc/passwd"
        assert raw.file_op == "read"

    def test_openat_write_only(self):
        """O_WRONLY → file_op='write'"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=EVENT_OPENAT,
            pid=5001,
            ppid=5000,
            uid=1000,
            timestamp_ns=1718092800200000000,
            data_union={
                "filename": b"/tmp/output.txt",
                "flags": 1,  # O_WRONLY
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "file_open"
        assert raw.file_path == "/tmp/output.txt"
        assert raw.file_op == "write"

    def test_openat_read_write(self):
        """O_RDWR → file_op='write'"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=EVENT_OPENAT,
            pid=5002,
            ppid=5000,
            uid=1000,
            timestamp_ns=1718092800300000000,
            data_union={
                "filename": b"/home/dev/data.db",
                "flags": 2,  # O_RDWR
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "file_open"
        assert raw.file_op == "write"


# ============================================================
# 测试类: connect 字段映射
# ============================================================

class TestConnectMapping:
    """用例 1.3: 验证 connect → net_conn 字段映射"""

    def test_connect_tcp(self):
        """TCP 连接映射"""
        collector = _make_ebpf_collector()

        # 10.0.0.1 网络字节序 = 0x0A000001
        ip_addr = struct.unpack("!I", socket.inet_aton("10.0.0.1"))[0]
        # 4444 网络字节序
        port_net = socket.htons(4444)

        event_bytes = _build_event_bytes(
            event_type=EVENT_CONNECT,
            pid=6000,
            ppid=5999,
            uid=1000,
            timestamp_ns=1718092800400000000,
            data_union={
                "ip_addr": ip_addr,
                "port": port_net,
                "protocol": 0,  # TCP
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "net_conn"
        assert raw.remote_addr == "10.0.0.1"
        assert raw.remote_port == 4444
        assert raw.protocol == "TCP"

    def test_connect_udp(self):
        """UDP 连接映射"""
        collector = _make_ebpf_collector()

        ip_addr = struct.unpack("!I", socket.inet_aton("8.8.8.8"))[0]
        port_net = socket.htons(53)

        event_bytes = _build_event_bytes(
            event_type=EVENT_CONNECT,
            pid=6001,
            ppid=6000,
            uid=1000,
            timestamp_ns=1718092800500000000,
            data_union={
                "ip_addr": ip_addr,
                "port": port_net,
                "protocol": 1,  # UDP
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "net_conn"
        assert raw.remote_addr == "8.8.8.8"
        assert raw.remote_port == 53
        assert raw.protocol == "UDP"

    def test_connect_high_port(self):
        """高端口连接映射"""
        collector = _make_ebpf_collector()

        ip_addr = struct.unpack("!I", socket.inet_aton("192.168.1.100"))[0]
        port_net = socket.htons(8080)

        event_bytes = _build_event_bytes(
            event_type=EVENT_CONNECT,
            pid=6002,
            ppid=6000,
            uid=1000,
            timestamp_ns=1718092800600000000,
            data_union={
                "ip_addr": ip_addr,
                "port": port_net,
                "protocol": 0,  # TCP
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.remote_addr == "192.168.1.100"
        assert raw.remote_port == 8080


# ============================================================
# 测试类: 时间戳与 event_id 一致性
# ============================================================

class TestTimestampAndId:
    """用例 1.4: 验证时间戳来源和 event_id 格式"""

    def test_timestamp_preserved(self):
        """时间戳从 event_t 原样传递到 RawEvent"""
        collector = _make_ebpf_collector()

        ts = 1718092800000000000  # ~2024-06-11 纳秒时间戳
        event_bytes = _build_event_bytes(
            event_type=EVENT_EXECVE,
            pid=100,
            ppid=99,
            uid=0,
            timestamp_ns=ts,
            data_union={"filename": b"/bin/ls", "argv": b"ls\x00"},
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw.timestamp_ns == ts
        assert raw.timestamp_ns > 0

    def test_event_id_format(self):
        """event_id 以 'ebpf_evt_' 开头且递增"""
        collector = _make_ebpf_collector()

        ids = []
        for i in range(3):
            event_bytes = _build_event_bytes(
                event_type=EVENT_EXECVE,
                pid=100 + i,
                ppid=99,
                uid=0,
                timestamp_ns=1000000 + i,
                data_union={"filename": b"/bin/true", "argv": b"true\x00"},
            )
            raw = collector._to_raw_event(event_bytes)
            assert raw is not None
            ids.append(raw.event_id)

        assert ids[0].startswith("ebpf_evt_")
        assert ids[1].startswith("ebpf_evt_")
        # 递增序列号
        seq_nums = [int(eid.split("_")[-1]) for eid in ids]
        assert seq_nums[1] > seq_nums[0]
        assert seq_nums[2] > seq_nums[1]

    def test_timestamp_monotonic_ordering(self):
        """多个事件时间戳保持单调递增"""
        collector = _make_ebpf_collector()

        timestamps = []
        for i in range(5):
            ts = 1718092800000000000 + i * 100000000  # 每 100ms 一个事件
            event_bytes = _build_event_bytes(
                event_type=EVENT_EXECVE,
                pid=200,
                ppid=199,
                uid=1000,
                timestamp_ns=ts,
                data_union={"filename": b"/bin/true", "argv": b"true\x00"},
            )
            raw = collector._to_raw_event(event_bytes)
            assert raw is not None
            timestamps.append(raw.timestamp_ns)

        # 验证单调递增
        for i in range(len(timestamps) - 1):
            assert timestamps[i] < timestamps[i + 1]

        # 验证数量级合理 (~10^18)
        for ts in timestamps:
            assert ts > 10**17


# ============================================================
# 测试类: 未知事件类型处理
# ============================================================

class TestUnknownEventType:
    """未知事件类型返回 None"""

    def test_unknown_type_returns_none(self):
        """event_type=255 返回 None"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=255,
            pid=100,
            ppid=99,
            uid=0,
            timestamp_ns=1000000,
            data_union={"filename": b"/bin/ls", "argv": b"ls\x00"},
        )

        raw = collector._to_raw_event(event_bytes)
        assert raw is None

    def test_corrupted_data_short_bytes(self):
        """过短字节数据仍产生事件（memmove 填充零），但字段为默认值"""
        collector = _make_ebpf_collector()

        # 短数据不会崩溃，memmove 使用 min(len, sizeof)
        raw = collector._to_raw_event(b"\x00\x01\x02")
        # event_type=0 (EXECVE) 因为短数据填充零
        assert raw is not None
        assert raw.event_type == "exec"
        assert raw.pid == 0
        assert raw.ppid == 0
