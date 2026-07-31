"""
tests/test_ebpf_performance.py — eBPF 性能基准测试（可选）

建立性能基线，监控后续优化效果。
包括: 事件处理延迟测量、模拟模式与 eBPF 模式等价性验证。

大部分测试使用 mock 数据，无需真实 eBPF 环境。
"""

import os
import sys
import time
import ctypes
import struct
import socket
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.ebpf_collector import (
    EventT, EventExec, EventFile, EventNet, EventUnion,
    EVENT_EXECVE, EVENT_OPENAT, EVENT_CONNECT,
    FILENAME_MAX_LEN, ARGV_MAX_LEN, COMM_MAX_LEN,
)


def _make_ebpf_collector():
    """创建 mock 的 EbpfCollector 实例"""
    with patch("collector.ebpf_collector._load_libbpf") as mock_lib:
        mock_lib.return_value = MagicMock()
        from collector.ebpf_collector import EbpfCollector
        config = {
            "ebpf": {
                "bpf_object_path": "ebpf/observer.bpf.o",
                "target_agent_id": "perf-test-agent",
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
# 用例 3.1: 事件处理延迟基准
# ============================================================

class TestEventProcessingLatency:
    """
    测量 _to_raw_event() 的处理延迟，建立性能基线。
    非硬性指标，仅用于监控后续优化的效果。
    """

    def test_single_event_latency(self):
        """单事件处理延迟 < 1ms（宽松基线）"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=EVENT_EXECVE,
            pid=20000, ppid=19999, uid=1000,
            timestamp_ns=1718092800000000000,
            data_union={"filename": b"/usr/bin/python3", "argv": b"python3\x00script.py\x00"},
        )

        # 预热
        for _ in range(10):
            collector._to_raw_event(event_bytes)

        # 测量 100 次
        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            raw = collector._to_raw_event(event_bytes)
            assert raw is not None
        elapsed = time.perf_counter() - start

        avg_latency_ms = (elapsed / iterations) * 1000
        # 宽松基线: 单事件 < 1ms
        assert avg_latency_ms < 1.0, f"平均延迟 {avg_latency_ms:.3f}ms 超过 1ms 基线"

    def test_batch_100_events(self):
        """100 个事件批量处理总时间 < 100ms"""
        collector = _make_ebpf_collector()

        # 构造 100 个不同类型的事件
        event_bytes_list = []
        for i in range(100):
            evt_type = i % 3
            if evt_type == 0:
                data = {"filename": b"/bin/true", "argv": b"true\x00"}
            elif evt_type == 1:
                data = {"filename": b"/tmp/test.txt", "flags": 0}
            else:
                ip = struct.unpack("!I", socket.inet_aton("10.0.0.1"))[0]
                data = {"ip_addr": ip, "port": socket.htons(80), "protocol": 0}

            event_bytes_list.append(_build_event_bytes(
                event_type=evt_type,
                pid=21000 + i, ppid=20999, uid=1000,
                timestamp_ns=1718092800000000000 + i * 1000000,
                data_union=data,
            ))

        start = time.perf_counter()
        results = []
        for eb in event_bytes_list:
            raw = collector._to_raw_event(eb)
            assert raw is not None
            results.append(raw)
        elapsed = time.perf_counter() - start

        assert len(results) == 100
        elapsed_ms = elapsed * 1000
        assert elapsed_ms < 100, f"100 事件处理耗时 {elapsed_ms:.2f}ms，超过 100ms 基线"


# ============================================================
# 用例 3.2: 模拟模式与 eBPF 模式事件格式等价性
# ============================================================

class TestSimulationVsEbpfEquivalence:
    """
    验证 eBPF 模式产出的 RawEvent 与模拟模式在格式上完全等价。
    observer_core/ 对两种来源的事件处理行为一致。
    """

    def test_event_type_values_match(self):
        """eBPF 和模拟模式的 event_type 值域完全一致"""
        collector = _make_ebpf_collector()

        # eBPF 模式产出的 event_type
        ebpf_types = set()
        for evt_type_id in (EVENT_EXECVE, EVENT_OPENAT, EVENT_CONNECT):
            if evt_type_id == EVENT_EXECVE:
                data = {"filename": b"/bin/ls", "argv": b"ls\x00"}
            elif evt_type_id == EVENT_OPENAT:
                data = {"filename": b"/tmp/f", "flags": 0}
            else:
                ip = struct.unpack("!I", socket.inet_aton("10.0.0.1"))[0]
                data = {"ip_addr": ip, "port": socket.htons(80), "protocol": 0}

            eb = _build_event_bytes(
                event_type=evt_type_id,
                pid=22000, ppid=21999, uid=1000,
                timestamp_ns=1718092800000000000,
                data_union=data,
            )
            raw = collector._to_raw_event(eb)
            assert raw is not None
            ebpf_types.add(raw.event_type)

        # 模拟模式的 event_type 值域（来自 models/event.py EventType 枚举）
        from models.event import EventType
        sim_types = {et.value for et in EventType}

        assert ebpf_types == sim_types, (
            f"eBPF 事件类型 {ebpf_types} 与模拟模式 {sim_types} 不一致"
        )

    def test_raw_event_fields_compatible(self):
        """eBPF RawEvent 包含 observer_core/ 所需的全部字段"""
        collector = _make_ebpf_collector()

        event_bytes = _build_event_bytes(
            event_type=EVENT_EXECVE,
            pid=23000, ppid=22999, uid=1000,
            timestamp_ns=1718092800000000000,
            data_union={"filename": b"/usr/bin/gcc", "argv": b"gcc\x00-o\x00main\x00main.c\x00"},
        )

        raw = collector._to_raw_event(event_bytes)
        assert raw is not None

        # 验证 observer_core/ 使用的所有字段都有值
        assert raw.event_id          # 非空
        assert raw.timestamp_ns > 0  # 有效时间戳
        assert raw.event_type        # 非空
        assert raw.pid >= 0          # 非负
        assert raw.ppid >= 0         # 非负
        assert raw.agent_id          # 非空
        assert raw.agent_framework   # 非空

        # 验证与 RawEvent.to_dict() 兼容（observer_core 序列化路径）
        d = raw.to_dict()
        assert "event_type" in d
        assert "pid" in d
        assert "timestamp_ns" in d
        assert "executable" in d
        assert "arguments" in d
