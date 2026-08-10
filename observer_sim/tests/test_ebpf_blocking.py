"""
tests/test_ebpf_blocking.py — eBPF 阻断功能单元测试

覆盖 send_command() 阻断链路、kprobe 动态挂载/卸载、
多 PID 独立阻断、降级行为等场景。

测试分两层：
  1. Mock 层: 模拟 libbpf，验证业务逻辑和状态机（无需 root）
  2. 集成层: 真实 eBPF 加载（需 root + BTF，pytest skip 条件自动跳过）
"""

import pytest
import ctypes
import os
from unittest.mock import Mock, patch, PropertyMock, MagicMock, call
from typing import Optional

from collector.ebpf_collector import EbpfCollector, _load_libbpf, _setup_libbpf_signatures
from models.command import Command, CmdType, BlockAction


# ============================================================
# 测试基类：提供 mock libbpf 和基本 EbpfCollector 实例
# ============================================================

class _MockLibbpf:
    """模拟 libbpf CDLL，提供可控的函数返回值。

    所有 libbpf 函数名（如 bpf_object__open 等）通过 __getattr__
    返回 MagicMock，自动支持 .argtypes / .restype 赋值。
    """

    def __init__(self, *,
                 block_policy_fd: int = 10,
                 events_fd: int = 11,
                 kprobe_progs_available: bool = True,
                 map_update_ok: bool = True,
                 map_delete_ok: bool = True,
                 map_lookup_value: Optional[int] = 0,
                 kprobe_attach_ok: bool = True):
        self.block_policy_fd = block_policy_fd
        self.events_fd = events_fd
        self.kprobe_progs_available = kprobe_progs_available
        self.map_update_ok = map_update_ok
        self.map_delete_ok = map_delete_ok
        self.map_lookup_value = map_lookup_value
        self.kprobe_attach_ok = kprobe_attach_ok

        # 记录调用历史
        self.map_update_calls = []
        self.map_delete_calls = []
        self.map_lookup_calls = []
        self.prog_attach_calls = []
        self.link_destroy_calls = []

    # ---- libbpf function name mapping (通过 __getattr__ 自动生成 MagicMock) ----
    # 以下方法对应的 libbpf 函数名通过 __getattr__ 返回 MagicMock，自动支持
    # _setup_libbpf_signatures() 中的 .argtypes / .restype 赋值。
    # 但像 bpf_object__find_map_fd_by_name 等需要在 mock 中有自定义逻辑的函数，
    # 仍然直接定义为方法（Python 方法优先于 __getattr__）。

    def __getattr__(self, name):
        """为所有未定义的属性返回 MagicMock（兼容 ctypes 签名设置）"""
        # 避免无限递归：__getattr__ 只在常规属性查找失败时调用
        # 直接定义的方法（如 bpf_object__find_map_fd_by_name）不会触发此方法
        mock = MagicMock()
        setattr(self, name, mock)
        return mock

    # ---- Map operations ----

    def bpf_object__find_map_fd_by_name(self, bpf_object, name_bytes):
        if name_bytes == b"block_policy":
            return self.block_policy_fd
        if name_bytes == b"events":
            return self.events_fd
        return -1

    def bpf_map_update_elem(self, fd, key_ptr, value_ptr, flags):
        c_key = ctypes.cast(key_ptr, ctypes.POINTER(ctypes.c_uint32)).contents.value
        c_value = ctypes.cast(value_ptr, ctypes.POINTER(ctypes.c_uint64)).contents.value
        self.map_update_calls.append((c_key, c_value, flags))
        return 0 if self.map_update_ok else -1

    def bpf_map_delete_elem(self, fd, key_ptr):
        c_key = ctypes.cast(key_ptr, ctypes.POINTER(ctypes.c_uint32)).contents.value
        self.map_delete_calls.append(c_key)
        return 0 if self.map_delete_ok else -1

    def bpf_map_lookup_elem(self, fd, key_ptr, value_ptr):
        c_key = ctypes.cast(key_ptr, ctypes.POINTER(ctypes.c_uint32)).contents.value
        self.map_lookup_calls.append(c_key)
        if self.map_lookup_value is not None:
            ctypes.cast(value_ptr, ctypes.POINTER(ctypes.c_uint64)).contents.value = self.map_lookup_value
            return 0
        return -1

    # ---- Program operations ----

    def bpf_object__find_program_by_name(self, bpf_object, name_bytes):
        if self.kprobe_progs_available:
            # 返回非空指针模拟找到了程序
            return 0xDEAD0000 + hash(name_bytes) & 0xFFFF
        return None

    def bpf_program__fd(self, prog):
        return 42  # 模拟 fd

    def bpf_program__attach(self, prog):
        if self.kprobe_attach_ok:
            addr = 0xBEEF0000 + (prog & 0xFFFF)
            self.prog_attach_calls.append(addr)
            return addr  # 模拟 link 指针
        return None

    def bpf_link__destroy(self, link):
        self.link_destroy_calls.append(link)

    # ---- Stubs for other libbpf functions ----

    def bpf_object__open(self, path_bytes):
        return 0xCAFE0000  # mock bpf_object ptr

    def bpf_object__load(self, bpf_object):
        return 0  # success

    def bpf_object__close(self, bpf_object):
        pass

    def perf_buffer__new(self, map_fd, page_cnt, sample_cb, lost_cb, ctx, opts):
        return 0xBEEF0001  # mock perf_buffer ptr

    def perf_buffer__free(self, pb):
        pass

    def perf_buffer__poll(self, pb, timeout_ms):
        return 0  # no events

    def libbpf_get_error(self, ptr):
        return 0

    def libbpf_strerror(self, err, buf, size):
        return 0


def _make_mock_collector(mock_lib: _MockLibbpf = None, **kwargs) -> EbpfCollector:
    """创建带有 mock libbpf 的 EbpfCollector 实例（已 attach）"""
    mock_lib = mock_lib or _MockLibbpf()

    config = {
        "ebpf": {
            "bpf_object_path": "ebpf/observer.bpf.o",
            "target_agent_id": "test-agent",
            "perf_buffer_page_count": 64,
        }
    }

    # _setup_libbpf_signatures 在 mock 上可能失败（自定义方法不支持 argtypes），
    # 但这不影响测试——mock 的核心函数（map 操作、kprobe attach）已有自定义逻辑。
    with patch("collector.ebpf_collector._load_libbpf", return_value=mock_lib), \
         patch("collector.ebpf_collector._setup_libbpf_signatures", return_value=None):
        collector = EbpfCollector(config)
        collector._bpf_object = 0xCAFE0000  # 模拟已加载
        collector._attached = True
        collector._lib = mock_lib
    return collector


# 移除不再需要的 _setup_libbpf_signatures_for_mock 函数


def make_block_command(pid: int, event_id: str = "evt_001",
                       reason: str = "Tier2 违规") -> Command:
    """快捷创建阻断指令"""
    return Command.make_block(
        cmd_id=f"cmd_{pid}",
        event_id=event_id,
        pid=pid,
        reason=reason,
        timestamp_ns=1000000,
    )


def make_allow_command(pid: int) -> Command:
    """快捷创建放行指令（携带 target_pid 以解除指定 PID 的阻断）"""
    cmd = Command.make_allow(
        cmd_id=f"allow_{pid}",
        event_id="evt_001",
        timestamp_ns=2000000,
    )
    cmd.target_pid = pid
    return cmd


def make_terminate_command(pid: int) -> Command:
    """快捷创建终止指令"""
    return Command.make_terminate(
        cmd_id=f"term_{pid}",
        pid=pid,
        reason="Tier3 违规",
        timestamp_ns=3000000,
    )


# ============================================================
# 第 1 组：Command 解析 → block_flags 推导
# ============================================================

class TestResolveBlockFlags:
    """测试 Command → block_flags 解析逻辑"""

    def test_block_event_resolves_to_all(self):
        """BLOCK_EVENT → 0x07 (全部阻断)"""
        collector = _make_mock_collector()
        cmd = make_block_command(pid=100)
        flags = collector._resolve_block_flags(cmd)
        assert flags == EbpfCollector.BLOCK_ALL
        assert flags == 0x07

    def test_allow_resolves_to_zero(self):
        """ALLOW → 0x00 (清除阻断)"""
        collector = _make_mock_collector()
        cmd = make_allow_command(pid=100)
        flags = collector._resolve_block_flags(cmd)
        assert flags == 0

    def test_terminate_resolves_to_all(self):
        """TERMINATE_PROCESS → 0x07 (全部阻断 + 终止标记)"""
        collector = _make_mock_collector()
        cmd = make_terminate_command(pid=100)
        flags = collector._resolve_block_flags(cmd)
        assert flags == EbpfCollector.BLOCK_ALL

    def test_heartbeat_returns_negative(self):
        """HEARTBEAT → -1 (不处理)"""
        collector = _make_mock_collector()
        cmd = Command.make_heartbeat("hb_1")
        flags = collector._resolve_block_flags(cmd)
        assert flags == -1


# ============================================================
# 第 2 组：block_policy map 增删查（mock libbpf）
# ============================================================

class TestBlockPolicyMapOperations:
    """测试 block_policy map 的增、删、查操作"""

    def test_update_block_policy_sends_correct_key_value(self):
        """_update_block_policy 应调用 bpf_map_update_elem 并传入正确的 key/value"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        result = collector._update_block_policy(pid=123, flags=0x03)
        assert result is True
        assert len(mock_lib.map_update_calls) == 1
        key, value, flags = mock_lib.map_update_calls[0]
        assert key == 123
        assert value == 0x03

    def test_update_block_policy_returns_false_on_error(self):
        """map 更新失败时应返回 False"""
        mock_lib = _MockLibbpf(map_update_ok=False)
        collector = _make_mock_collector(mock_lib)

        result = collector._update_block_policy(pid=456, flags=0x07)
        assert result is False

    def test_delete_block_policy_removes_pid(self):
        """_delete_block_policy 应调用 bpf_map_delete_elem"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        result = collector._delete_block_policy(pid=789)
        assert result is True
        assert mock_lib.map_delete_calls == [789]

    def test_delete_block_policy_returns_false_on_error(self):
        """map 删除失败时应返回 False"""
        mock_lib = _MockLibbpf(map_delete_ok=False)
        collector = _make_mock_collector(mock_lib)

        result = collector._delete_block_policy(pid=999)
        assert result is False

    def test_query_block_policy_returns_stored_value(self):
        """查询应返回之前存储的 block_flags"""
        mock_lib = _MockLibbpf(map_lookup_value=0x05)
        collector = _make_mock_collector(mock_lib)

        value = collector._query_block_policy(pid=111)
        assert value == 0x05
        assert mock_lib.map_lookup_calls == [111]

    def test_query_block_policy_returns_none_when_not_found(self):
        """查询不存在的 PID 应返回 None"""
        mock_lib = _MockLibbpf(map_lookup_value=None)
        collector = _make_mock_collector(mock_lib)

        value = collector._query_block_policy(pid=999)
        assert value is None

    def test_get_block_policy_fd_caches_result(self):
        """_get_block_policy_fd 应缓存 map fd"""
        mock_lib = _MockLibbpf(block_policy_fd=42)
        collector = _make_mock_collector(mock_lib)

        fd1 = collector._get_block_policy_fd()
        fd2 = collector._get_block_policy_fd()
        assert fd1 == 42
        assert fd2 == 42


# ============================================================
# 第 3 组：kprobe 动态挂载/卸载状态转换
# ============================================================

class TestKprobeLifecycle:
    """测试 kprobe 挂载/卸载的状态机"""

    def test_first_block_attaches_kprobes(self):
        """第一次 send_command(BLOCK) 应触发 kprobe 挂载"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        assert collector._kprobe_attached is False
        assert collector._kprobe_links == []

        cmd = make_block_command(pid=100)
        result = collector.send_command(cmd)

        assert result is True
        assert collector._kprobe_attached is True
        assert len(collector._kprobe_links) == 3  # execve + openat + connect

    def test_subsequent_blocks_skip_kprobe_attach(self):
        """第二次 send_command(BLOCK) 不应重复挂载 kprobe"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        # 第一次阻断 → 挂载 kprobe
        collector.send_command(make_block_command(pid=100))
        assert collector._kprobe_attached is True
        attach_count_before = len(mock_lib.prog_attach_calls)

        # 第二次阻断 → 不应再次挂载
        collector.send_command(make_block_command(pid=200))
        assert collector._kprobe_attached is True
        assert len(mock_lib.prog_attach_calls) == attach_count_before

    def test_detach_when_all_pids_unblocked(self):
        """所有 PID 解禁后应卸载 kprobe"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        # 阻断 PID 100
        collector.send_command(make_block_command(pid=100))
        assert collector._kprobe_attached is True
        assert 100 in collector._blocked_pids

        # 解禁 PID 100
        collector.send_command(make_allow_command(pid=100))
        assert collector._kprobe_attached is False
        assert 100 not in collector._blocked_pids
        # kprobe link 应被销毁
        assert len(mock_lib.link_destroy_calls) == 3

    def test_multiple_pids_only_detach_when_all_cleared(self):
        """多个 PID 中仅部分解禁时 kprobe 应保持挂载"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        # 阻断 PID 100 和 PID 200
        collector.send_command(make_block_command(pid=100))
        collector.send_command(make_block_command(pid=200))
        assert collector._kprobe_attached is True
        assert collector._blocked_pids == {100, 200}

        # 仅解禁 PID 100 → kprobe 仍应挂载
        collector.send_command(make_allow_command(pid=100))
        assert collector._kprobe_attached is True
        assert collector._blocked_pids == {200}

        # 解禁 PID 200 → kprobe 卸载
        collector.send_command(make_allow_command(pid=200))
        assert collector._kprobe_attached is False
        assert collector._blocked_pids == set()

    def test_detach_cleans_up_all_kprobe_links(self):
        """detach() 应销毁所有 kprobe link"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        collector.send_command(make_block_command(pid=100))
        assert len(collector._kprobe_links) == 3

        collector.detach()
        assert collector._kprobe_attached is False
        assert collector._kprobe_links == []


# ============================================================
# 第 4 组：send_command() 异常路径与降级
# ============================================================

class TestSendCommandEdgeCases:
    """测试 send_command() 的边界条件和降级行为"""

    def test_send_command_returns_false_when_not_attached(self):
        """未 attach 时 send_command 应返回 False"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)
        collector._attached = False

        cmd = make_block_command(pid=100)
        result = collector.send_command(cmd)
        assert result is False

    def test_send_command_returns_false_when_no_bpf_object(self):
        """bpf_object 为 None 时 send_command 应返回 False"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)
        collector._bpf_object = None

        cmd = make_block_command(pid=100)
        result = collector.send_command(cmd)
        assert result is False

    def test_send_command_fails_without_valid_pid(self):
        """没有 target_pid 时应返回 False"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        cmd = Command.make_allow("no_pid_cmd", "evt_001")
        cmd.target_pid = None
        result = collector.send_command(cmd)
        assert result is False

    def test_send_command_fails_with_zero_pid(self):
        """target_pid=0 时应返回 False"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        cmd = make_block_command(pid=0)
        result = collector.send_command(cmd)
        assert result is False

    def test_send_command_heartbeat_is_noop(self):
        """HEARTBEAT Command 应被忽略"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        cmd = Command.make_heartbeat("hb_test")
        result = collector.send_command(cmd)
        assert result is False  # 不处理
        # 不应触发任何 map 操作或 kprobe 操作
        assert len(mock_lib.map_update_calls) == 0
        assert len(mock_lib.prog_attach_calls) == 0

    def test_block_then_allow_clears_map_entry(self):
        """阻断后解除应删除 map 条目"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        # 阻断
        collector.send_command(make_block_command(pid=300))
        assert len(mock_lib.map_update_calls) == 1

        # 解禁
        collector.send_command(make_allow_command(pid=300))
        assert len(mock_lib.map_delete_calls) == 1
        assert mock_lib.map_delete_calls[0] == 300

    def test_kprobe_attach_failure_blocks_returns_false(self):
        """kprobe 挂载失败时 send_command 应返回 False"""
        mock_lib = _MockLibbpf(kprobe_attach_ok=False)
        collector = _make_mock_collector(mock_lib)

        cmd = make_block_command(pid=400)
        result = collector.send_command(cmd)
        assert result is False
        assert collector._kprobe_attached is False

    def test_map_update_failure_returns_false(self):
        """map 更新失败时 send_command 应返回 False"""
        mock_lib = _MockLibbpf(map_update_ok=False)
        collector = _make_mock_collector(mock_lib)

        cmd = make_block_command(pid=500)
        result = collector.send_command(cmd)
        assert result is False

    def test_terminate_command_triggers_blocking(self):
        """TERMINATE_PROCESS 指令应触发阻断（全部 syscall）"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        cmd = make_terminate_command(pid=600)
        result = collector.send_command(cmd)
        assert result is True
        assert 600 in collector._blocked_pids
        assert len(mock_lib.map_update_calls) == 1
        key, value, _ = mock_lib.map_update_calls[0]
        assert key == 600
        assert value == EbpfCollector.BLOCK_ALL


# ============================================================
# 第 5 组：多 PID 独立阻断
# ============================================================

class TestMultiPidBlocking:
    """测试多 PID 独立阻断场景"""

    def test_each_pid_has_independent_block_policy(self):
        """不同 PID 应有独立的 block_policy 条目"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        # 阻断 PID 100 和 200
        collector.send_command(make_block_command(pid=100))
        collector.send_command(make_block_command(pid=200))

        # 验证两次 map 更新
        assert len(mock_lib.map_update_calls) == 2
        pids_updated = {call[0] for call in mock_lib.map_update_calls}
        assert pids_updated == {100, 200}

    def test_unblock_one_pid_does_not_affect_others(self):
        """解禁一个 PID 不应影响其他被阻断的 PID"""
        mock_lib = _MockLibbpf()
        collector = _make_mock_collector(mock_lib)

        # 阻断三个 PID
        collector.send_command(make_block_command(pid=100))
        collector.send_command(make_block_command(pid=200))
        collector.send_command(make_block_command(pid=300))

        # 解禁 PID 200
        collector.send_command(make_allow_command(pid=200))

        # PID 100 和 300 仍在 blocked_pids 中
        assert 100 in collector._blocked_pids
        assert 200 not in collector._blocked_pids
        assert 300 in collector._blocked_pids

        # 解禁 PID 200 的 map 条目被删除
        assert mock_lib.map_delete_calls == [200]


# ============================================================
# 第 6 组：capabilities 接口
# ============================================================

class TestCapabilities:
    """测试 capabilities() 返回值正确反映 v2.0 能力"""

    def test_capabilities_reflect_blocking_support(self):
        """v2.0 应报告阻断能力"""
        collector = _make_mock_collector()
        caps = collector.capabilities()
        assert caps.name == "Ebpf"
        assert caps.can_observe is True
        assert caps.can_block_tier2 is True
        assert caps.can_block_tier3 is True
        assert caps.is_transparent is True


# ============================================================
# 第 7 组：集成验证（需 sudo + eBPF 环境）
# ============================================================

@pytest.mark.skipif(
    os.geteuid() != 0,
    reason="eBPF 加载需要 root 权限"
)
@pytest.mark.skipif(
    not os.path.isfile("ebpf/observer.bpf.o"),
    reason="observer.bpf.o 未编译，请先运行 make"
)
class TestEbpfIntegration:
    """
    真实 eBPF 加载集成测试（需 root + BTF）。

    验证: bpf_object 加载 → block_policy map 可用 → send_command
    生效 → 解禁后 map 条目清除。
    """

    def test_load_and_attach_block_policy_map(self):
        """真实加载 eBPF，验证 block_policy map 存在且可操作"""
        collector = EbpfCollector({
            "ebpf": {
                "bpf_object_path": "ebpf/observer.bpf.o",
                "target_agent_id": "test-integration",
                "perf_buffer_page_count": 16,
            }
        })
        try:
            ok = collector.attach(target_pid=0, agent_id="test-integration")
            assert ok, "bpf_object 加载或 tracepoint 挂载失败"

            fd = collector._get_block_policy_fd()
            assert fd >= 0, f"block_policy map fd 无效: {fd}"

            # 更新 map
            result = collector._update_block_policy(
                pid=os.getpid(), flags=0x07)
            assert result, "bpf_map_update_elem 失败"

            # 查询验证
            flags = collector._query_block_policy(pid=os.getpid())
            assert flags == 0x07, f"查询到的 flags 不符: {flags}"

            # 删除条目
            result = collector._delete_block_policy(pid=os.getpid())
            assert result, "bpf_map_delete_elem 失败"

            # 确认已删除
            flags = collector._query_block_policy(pid=os.getpid())
            assert flags is None, "删除后仍能查到条目"

        finally:
            collector.detach()

    def test_send_command_updates_map_correctly(self):
        """send_command 应成功更新 block_policy map"""
        collector = EbpfCollector({
            "ebpf": {
                "bpf_object_path": "ebpf/observer.bpf.o",
                "target_agent_id": "test-integration",
                "perf_buffer_page_count": 16,
            }
        })
        test_pid = os.getpid()
        try:
            ok = collector.attach(target_pid=test_pid, agent_id="test")
            assert ok

            # 发送阻断指令
            cmd = make_block_command(pid=test_pid)
            result = collector.send_command(cmd)
            assert result, "send_command(BLOCK) 失败"

            # 验证 kernel map 中的值
            flags = collector._query_block_policy(pid=test_pid)
            assert flags == EbpfCollector.BLOCK_ALL, (
                f"kernel map 中 flags: {flags}，期望: {EbpfCollector.BLOCK_ALL}")

            # 解禁
            cmd_allow = make_allow_command(pid=test_pid)
            result = collector.send_command(cmd_allow)
            assert result, "send_command(ALLOW) 失败"

            # 验证删除
            flags = collector._query_block_policy(pid=test_pid)
            assert flags is None, "解禁后仍能查到条目"

        finally:
            collector.detach()
