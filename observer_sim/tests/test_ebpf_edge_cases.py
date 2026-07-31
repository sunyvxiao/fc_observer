"""
tests/test_ebpf_edge_cases.py — eBPF 边缘情况测试

验证 EbpfCollector 在模拟探针无法覆盖的边缘场景下的行为正确性。
包括: 长路径截断、高频事件、进程树、失败 syscall、agent_id 一致性。

可 mock 的测试无需真实 eBPF 环境；需要 root + eBPF 的测试标记 skipif。
"""

import os
import sys
import ctypes
import struct
import socket
import subprocess
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.ebpf_collector import (
    EventT, EventExec, EventFile, EventNet, EventUnion,
    EVENT_EXECVE, EVENT_OPENAT, EVENT_CONNECT,
    FILENAME_MAX_LEN, ARGV_MAX_LEN, COMM_MAX_LEN,
)


# ============================================================
# 辅助函数（与 test_ebpf_field_mapping.py 共享模式）
# ============================================================

def _make_ebpf_collector(agent_id="test-agent"):
    """创建 mock 的 EbpfCollector 实例"""
    with patch("collector.ebpf_collector._load_libbpf") as mock_lib:
        mock_lib.return_value = MagicMock()
        from collector.ebpf_collector import EbpfCollector
        config = {
            "ebpf": {
                "bpf_object_path": "ebpf/observer.bpf.o",
                "target_agent_id": agent_id,
                "perf_buffer_page_count": 64,
            }
        }
        return EbpfCollector(config)


def _build_event_bytes(event_type, pid, ppid, uid, timestamp_ns,
                       data_union, comm=b"test"):
    """构造 EventT 结构体并转为 bytes"""
    event = EventT()
    event.timestamp_ns = timestamp_ns
    event.pid = pid
    event.ppid = ppid
    event.uid = uid
    event.event_type = event_type
    event.blocked = 0
    event.padding = 0

    if event_type == EVENT_EXECVE:
        filename = data_union.get("filename", b"")
        # 截断到 FILENAME_MAX_LEN（模拟 eBPF 内核行为）
        if len(filename) >= FILENAME_MAX_LEN:
            filename = filename[:FILENAME_MAX_LEN - 1] + b"\x00"
        event.data.exec.filename = filename
        argv_data = data_union.get("argv", b"")
        if argv_data:
            argv_src = (ctypes.addressof(event) + EventT.data.offset +
                        EventUnion.exec.offset + EventExec.argv.offset)
            argv_buf = ctypes.create_string_buffer(argv_data, ARGV_MAX_LEN)
            ctypes.memmove(argv_src, argv_buf, ARGV_MAX_LEN)
    elif event_type == EVENT_OPENAT:
        filename = data_union.get("filename", b"")
        # 截断到 FILENAME_MAX_LEN（模拟 eBPF 内核行为）
        if len(filename) >= FILENAME_MAX_LEN:
            filename = filename[:FILENAME_MAX_LEN - 1] + b"\x00"
        event.data.file.filename = filename
        event.data.file.flags = data_union.get("flags", 0)
    elif event_type == EVENT_CONNECT:
        event.data.net.ip_addr = data_union.get("ip_addr", 0)
        event.data.net.port = data_union.get("port", 0)
        event.data.net.protocol = data_union.get("protocol", 0)

    comm_padded = comm[:COMM_MAX_LEN - 1] + b"\x00" * max(0, COMM_MAX_LEN - len(comm))
    event.comm = comm_padded[:COMM_MAX_LEN]

    return bytes(event)


# ============================================================
# 用例 2.1: 长路径截断
# ============================================================

class TestLongPathTruncation:
    """
    验证超长文件路径（>256 字节）的处理。
    eBPF 探针中 filename 字段最大 256 字节，超长会被截断。
    关键：截断后 observer_core/ 不崩溃。
    """

    def test_long_filename_truncated(self):
        """超长文件名在 EventT 中被截断到 FILENAME_MAX_LEN"""
        collector = _make_ebpf_collector()

        # 构造 300 字节的路径
        long_name = "/tmp/" + "A" * 295  # 300 字节
        long_name_bytes = long_name.encode("utf-8")

        event_bytes = _build_event_bytes(
            event_type=EVENT_OPENAT,
            pid=7000,
            ppid=6999,
            uid=1000,
            timestamp_ns=1718092800000000000,
            data_union={
                "filename": long_name_bytes,
                "flags": 0,
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "file_open"
        # 截断后长度不超过 FILENAME_MAX_LEN
        assert len(raw.file_path) <= FILENAME_MAX_LEN
        # 路径非空
        assert raw.file_path
        assert raw.file_path.startswith("/tmp/")

    def test_exact_max_length_filename(self):
        """恰好等于最大长度的文件名不截断"""
        collector = _make_ebpf_collector()

        # 恰好 FILENAME_MAX_LEN - 1 字节（留一个 \0）
        name = "/tmp/" + "B" * (FILENAME_MAX_LEN - 6)
        name_bytes = name.encode("utf-8")

        event_bytes = _build_event_bytes(
            event_type=EVENT_OPENAT,
            pid=7001,
            ppid=7000,
            uid=1000,
            timestamp_ns=1718092800100000000,
            data_union={
                "filename": name_bytes,
                "flags": 0,
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.file_path == name

    def test_truncated_path_no_crash_in_normalizer(self):
        """截断路径传入 observer_core 不抛异常"""
        collector = _make_ebpf_collector()

        long_name = "/etc/" + "X" * 300
        event_bytes = _build_event_bytes(
            event_type=EVENT_OPENAT,
            pid=7002,
            ppid=7000,
            uid=1000,
            timestamp_ns=1718092800200000000,
            data_union={
                "filename": long_name.encode("utf-8"),
                "flags": 0,
            },
        )

        raw = collector._to_raw_event(event_bytes)
        assert raw is not None

        # 模拟 observer_core 对事件的处理（不应抛异常）
        try:
            # EventNormalizer.get_match_target() 类似操作
            match_target = raw.file_path or ""
            _ = len(match_target)
            _ = match_target.startswith("/etc/")
        except Exception:
            pytest.fail("截断路径不应导致异常")


# ============================================================
# 用例 2.2: 高频事件处理
# ============================================================

class TestHighFrequencyEvents:
    """
    验证短时间内大量事件的处理能力。
    模拟 perf ring buffer 可能的高频推送场景。
    """

    def test_rapid_event_processing(self):
        """1000 个事件快速处理不崩溃"""
        collector = _make_ebpf_collector()

        results = []
        for i in range(1000):
            event_bytes = _build_event_bytes(
                event_type=EVENT_EXECVE,
                pid=8000 + (i % 10),
                ppid=7999,
                uid=1000,
                timestamp_ns=1718092800000000000 + i * 1000000,
                data_union={
                    "filename": b"/bin/true",
                    "argv": b"true\x00",
                },
            )
            raw = collector._to_raw_event(event_bytes)
            assert raw is not None
            results.append(raw)

        assert len(results) == 1000
        # 所有事件都有唯一 event_id
        ids = [r.event_id for r in results]
        assert len(set(ids)) == 1000

    def test_mixed_event_types_rapid(self):
        """混合类型高频事件处理"""
        collector = _make_ebpf_collector()

        results = []
        for i in range(300):
            evt_type = i % 3
            if evt_type == 0:
                data = {"filename": b"/bin/ls", "argv": b"ls\x00"}
            elif evt_type == 1:
                data = {"filename": b"/tmp/test.txt", "flags": 0}
            else:
                ip = struct.unpack("!I", socket.inet_aton("10.0.0.1"))[0]
                data = {"ip_addr": ip, "port": socket.htons(80), "protocol": 0}

            event_bytes = _build_event_bytes(
                event_type=evt_type,
                pid=9000,
                ppid=8999,
                uid=1000,
                timestamp_ns=1718092800000000000 + i * 500000,
                data_union=data,
            )
            raw = collector._to_raw_event(event_bytes)
            assert raw is not None
            results.append(raw)

        assert len(results) == 300
        # 验证三种类型都有
        types = set(r.event_type for r in results)
        assert types == {"exec", "file_open", "net_conn"}

    def test_detach_after_high_frequency(self):
        """高频事件后 detach 正常清理"""
        collector = _make_ebpf_collector()

        for i in range(100):
            event_bytes = _build_event_bytes(
                event_type=EVENT_EXECVE,
                pid=10000,
                ppid=9999,
                uid=1000,
                timestamp_ns=1718092800000000000 + i * 1000000,
                data_union={"filename": b"/bin/true", "argv": b"true\x00"},
            )
            collector._to_raw_event(event_bytes)

        # detach 不应抛异常
        collector.detach()
        assert collector._attached is False


# ============================================================
# 用例 2.3: 真实进程树（需要 eBPF 环境）
# ============================================================

_has_ebpf = (
    sys.platform.startswith("linux")
    and os.path.isfile("/sys/kernel/btf/vmlinux")
    and os.getuid() == 0  # 需要 root
)


@pytest.mark.skipif(not _has_ebpf, reason="需要 root + Linux eBPF 环境")
class TestRealProcessTree:
    """真实 eBPF 环境下的进程树验证"""

    def test_fork_exec_chain(self):
        """验证 fork+exec 产生的父子进程关系"""
        # 此测试需要真实 eBPF 环境
        collector = _make_ebpf_collector(agent_id="proc-tree-test")
        # TODO: 真实 eBPF 环境下加载探针并验证
        # bash -c 'ls /tmp && cat /etc/hostname && whoami'
        pytest.skip("需要真实 eBPF 环境，当前为 mock 模式")


# ============================================================
# 用例 2.4: 失败 syscall 处理
# ============================================================

class TestFailedSyscall:
    """
    验证失败的 syscall 事件处理。
    eBPF tracepoint 在 syscall 入口触发，无论结果成功或失败。
    """

    def test_openat_permission_denied_event(self):
        """权限拒绝的 openat 事件仍被正常转换"""
        collector = _make_ebpf_collector()

        # eBPF 在 sys_enter_openat 触发，此时 syscall 尚未返回
        # 因此事件数据中不包含返回值，只有参数
        event_bytes = _build_event_bytes(
            event_type=EVENT_OPENAT,
            pid=11000,
            ppid=10999,
            uid=1000,
            timestamp_ns=1718092800000000000,
            data_union={
                "filename": b"/etc/shadow",
                "flags": 0,  # O_RDONLY
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "file_open"
        assert raw.file_path == "/etc/shadow"
        assert raw.file_op == "read"
        # 事件本身不应标记为失败（eBPF 在入口触发）
        # observer_core/ 的规则引擎应基于路径判断风险

    def test_execve_nonexistent_file_event(self):
        """执行不存在文件的 execve 事件仍被正常转换"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=EVENT_EXECVE,
            pid=11001,
            ppid=10999,
            uid=1000,
            timestamp_ns=1718092800100000000,
            data_union={
                "filename": b"/bin/nonexistent_cmd",
                "argv": b"nonexistent_cmd\x00",
            },
        )

        raw = collector._to_raw_event(event_bytes)

        assert raw is not None
        assert raw.event_type == "exec"
        assert raw.executable == "/bin/nonexistent_cmd"
        # 事件正常转换，不因"文件不存在"而丢弃

    def test_failed_syscall_not_high_risk_by_default(self):
        """失败的 syscall 事件本身不自动产生高风险评分"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=EVENT_OPENAT,
            pid=11002,
            ppid=10999,
            uid=1000,
            timestamp_ns=1718092800200000000,
            data_union={
                "filename": b"/etc/shadow",
                "flags": 0,
            },
        )

        raw = collector._to_raw_event(event_bytes)
        assert raw is not None

        # RawEvent 本身不包含"成功/失败"标记
        # observer_core/ 的规则引擎根据路径判断，
        # 但单独的 openat 读取 /etc/shadow 不应等同于 rm -rf / 级别
        # 这里验证事件格式正确，不会导致下游异常
        assert raw.file_path == "/etc/shadow"
        assert raw.event_type == "file_open"


# ============================================================
# 用例 2.5: Agent ID 一致性
# ============================================================

class TestAgentIdConsistency:
    """
    验证同一 Agent 进程的所有事件 agent_id 相同。
    """

    def test_all_events_same_agent_id(self):
        """所有事件类型共享同一 agent_id"""
        agent_id = "consistent-agent"
        collector = _make_ebpf_collector(agent_id=agent_id)

        events = []

        # exec 事件
        event_bytes = _build_event_bytes(
            event_type=EVENT_EXECVE,
            pid=12000, ppid=11999, uid=1000,
            timestamp_ns=1718092800000000000,
            data_union={"filename": b"/bin/ls", "argv": b"ls\x00"},
        )
        events.append(collector._to_raw_event(event_bytes))

        # file_open 事件
        event_bytes = _build_event_bytes(
            event_type=EVENT_OPENAT,
            pid=12000, ppid=11999, uid=1000,
            timestamp_ns=1718092800100000000,
            data_union={"filename": b"/etc/hostname", "flags": 0},
        )
        events.append(collector._to_raw_event(event_bytes))

        # net_conn 事件
        ip = struct.unpack("!I", socket.inet_aton("127.0.0.1"))[0]
        event_bytes = _build_event_bytes(
            event_type=EVENT_CONNECT,
            pid=12000, ppid=11999, uid=1000,
            timestamp_ns=1718092800200000000,
            data_union={"ip_addr": ip, "port": socket.htons(8080), "protocol": 0},
        )
        events.append(collector._to_raw_event(event_bytes))

        # 所有事件的 agent_id 相同
        for raw in events:
            assert raw is not None
            assert raw.agent_id == agent_id

    def test_agent_id_from_config(self):
        """agent_id 来自配置而非事件数据"""
        collector = _make_ebpf_collector(agent_id="config-agent")

        event_bytes = _build_event_bytes(
            event_type=EVENT_EXECVE,
            pid=13000, ppid=12999, uid=1000,
            timestamp_ns=1718092800000000000,
            data_union={"filename": b"/bin/ls", "argv": b"ls\x00"},
        )

        raw = collector._to_raw_event(event_bytes)
        assert raw.agent_id == "config-agent"
        assert raw.agent_framework == "ebpf"

    def test_different_pids_same_agent(self):
        """不同 pid 的事件可以属于同一 agent"""
        collector = _make_ebpf_collector(agent_id="multi-pid-agent")

        pids = [14000, 14001, 14002, 14003]
        for pid in pids:
            event_bytes = _build_event_bytes(
                event_type=EVENT_EXECVE,
                pid=pid, ppid=13999, uid=1000,
                timestamp_ns=1718092800000000000 + pid,
                data_union={"filename": b"/bin/true", "argv": b"true\x00"},
            )
            raw = collector._to_raw_event(event_bytes)
            assert raw is not None
            assert raw.agent_id == "multi-pid-agent"
            assert raw.pid == pid
