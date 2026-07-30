"""
tests/test_strace_collector.py — StraceCollector 单元测试

测试覆盖:
  1. _parse_line() 行解析（execve/openat/connect 三种格式）
  2. capabilities() 返回值验证
  3. send_command() 返回 False + 日志记录
  4. 生命周期管理（attach/detach 状态转换）
  5. 行解析边界条件（格式错误、返回值非零、空行等）
  6. RawEvent 字段一致性（与 SimulationCollector/EbpfCollector 对比）
"""

import logging
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.strace_collector import (
    StraceCollector,
    _RE_EXECVE, _RE_OPENAT, _RE_CONNECT,
)
from collector.base_collector import CollectorCapabilities


# ============================================================
# 辅助函数
# ============================================================

def _create_collector(config: dict = None) -> StraceCollector:
    """创建 StraceCollector 实例（mock strace 可用性检查）"""
    if config is None:
        config = {
            "strace": {
                "strace_bin": "strace",
                "target_agent_id": "test-agent",
            }
        }
    return StraceCollector(config)


# ============================================================
# 测试类: _parse_line() execve 解析
# ============================================================

class TestParseLineExecve:
    """execve 行解析测试"""

    def test_basic_execve(self):
        """基本 execve 行解析"""
        collector = _create_collector()
        line = 'execve("/bin/ls", ["ls", "-la", "/tmp"], 0x7fff... /* 20 vars */) = 0'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.event_type == "exec"
        assert raw.executable == "/bin/ls"
        assert raw.arguments == ["ls", "-la", "/tmp"]
        assert raw.agent_id == "test-agent"
        assert raw.agent_framework == "strace"
        assert raw.pid == 0  # 默认 target_pid=0

    def test_execve_with_pid(self):
        """带 [pid NNN] 前缀的 execve"""
        collector = _create_collector()
        line = '[pid 12345] execve("/usr/bin/python3", ["python3", "script.py"], ["HOME=/home/user", ...]) = 0'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.pid == 12345
        assert raw.executable == "/usr/bin/python3"
        assert raw.arguments == ["python3", "script.py"]

    def test_execve_failed_returns_none(self):
        """失败的 execve（返回值非0）返回 None"""
        collector = _create_collector()
        line = 'execve("/nonexistent", ["/nonexistent"], 0x7fff...) = -1 ENOENT'

        raw = collector._parse_line(line)
        assert raw is None

    def test_execve_single_arg(self):
        """execve 只有一个参数"""
        collector = _create_collector()
        line = 'execve("/bin/true", ["true"], 0x7fff...) = 0'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.executable == "/bin/true"
        assert raw.arguments == ["true"]

    def test_execve_seq_increment(self):
        """事件序号自增"""
        collector = _create_collector()
        line1 = 'execve("/bin/ls", ["ls"], 0x7fff...) = 0'
        line2 = 'execve("/bin/cat", ["cat"], 0x7fff...) = 0'

        raw1 = collector._parse_line(line1)
        raw2 = collector._parse_line(line2)

        assert raw1.event_id == "strace_evt_000001"
        assert raw2.event_id == "strace_evt_000002"


# ============================================================
# 测试类: _parse_line() openat 解析
# ============================================================

class TestParseLineOpenat:
    """openat 行解析测试"""

    def test_basic_openat_read(self):
        """基本 openat 读操作"""
        collector = _create_collector()
        line = 'openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.event_type == "file_open"
        assert raw.file_path == "/etc/passwd"
        assert raw.file_op == "read"

    def test_openat_write(self):
        """openat 写操作 (O_WRONLY)"""
        collector = _create_collector()
        line = 'openat(AT_FDCWD, "/tmp/test.txt", O_WRONLY|O_CREAT, 0644) = 3'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.file_path == "/tmp/test.txt"
        assert raw.file_op == "write"

    def test_openat_rdwr(self):
        """openat 读写操作 (O_RDWR)"""
        collector = _create_collector()
        line = 'openat(AT_FDCWD, "/tmp/data.bin", O_RDWR) = 5'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.file_op == "write"

    def test_openat_with_pid(self):
        """带 [pid NNN] 前缀的 openat"""
        collector = _create_collector()
        line = '[pid 12345] openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 4'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.pid == 12345
        assert raw.file_path == "/etc/shadow"

    def test_openat_failed_returns_none(self):
        """失败的 openat（返回值 -1）返回 None"""
        collector = _create_collector()
        line = 'openat(AT_FDCWD, "/nonexistent", O_RDONLY) = -1 ENOENT'

        raw = collector._parse_line(line)
        assert raw is None

    def test_openat_with_dirfd(self):
        """openat 使用数字 dirfd"""
        collector = _create_collector()
        line = 'openat(3, "/proc/self/status", O_RDONLY) = 4'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.file_path == "/proc/self/status"


# ============================================================
# 测试类: _parse_line() connect 解析
# ============================================================

class TestParseLineConnect:
    """connect 行解析测试"""

    def test_basic_connect(self):
        """基本 connect 事件"""
        collector = _create_collector()
        line = 'connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.event_type == "net_conn"
        assert raw.remote_addr == "93.184.216.34"
        assert raw.remote_port == 443
        assert raw.protocol == "TCP"

    def test_connect_with_pid(self):
        """带 [pid NNN] 前缀的 connect"""
        collector = _create_collector()
        line = '[pid 12345] connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = 0'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.pid == 12345
        assert raw.remote_addr == "8.8.8.8"
        assert raw.remote_port == 53

    def test_connect_different_port(self):
        """connect 不同端口"""
        collector = _create_collector()
        line = 'connect(5, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("10.0.1.100")}, 16) = 0'

        raw = collector._parse_line(line)

        assert raw is not None
        assert raw.remote_addr == "10.0.1.100"
        assert raw.remote_port == 5432


# ============================================================
# 测试类: 行解析边界条件
# ============================================================

class TestParseLineEdgeCases:
    """行解析边界条件测试"""

    def test_empty_line(self):
        """空行返回 None"""
        collector = _create_collector()
        assert collector._parse_line("") is None

    def test_garbage_line(self):
        """无关行返回 None"""
        collector = _create_collector()
        assert collector._parse_line("+++ exited with 0 +++") is None

    def test_unfinished_syscall(self):
        """未完成的 syscall 行"""
        collector = _create_collector()
        assert collector._parse_line("read(0, ") is None

    def test_other_syscall(self):
        """其他 syscall（不在跟踪列表中）"""
        collector = _create_collector()
        assert collector._parse_line('read(3, "hello", 1024) = 5') is None

    def test_timestamp_ns_is_integer(self):
        """timestamp_ns 为整数类型"""
        collector = _create_collector()
        line = 'execve("/bin/ls", ["ls"], 0x7fff...) = 0'
        raw = collector._parse_line(line)

        assert raw is not None
        assert isinstance(raw.timestamp_ns, int)
        assert raw.timestamp_ns > 0


# ============================================================
# 测试类: capabilities()
# ============================================================

class TestCapabilities:
    """能力查询测试"""

    def test_capabilities_name(self):
        """能力名称为 Strace"""
        collector = _create_collector()
        caps = collector.capabilities()
        assert caps.name == "Strace"

    def test_capabilities_observe(self):
        """支持观测"""
        collector = _create_collector()
        caps = collector.capabilities()
        assert caps.can_observe is True

    def test_capabilities_no_block_tier2(self):
        """不支持 Tier2 阻断"""
        collector = _create_collector()
        caps = collector.capabilities()
        assert caps.can_block_tier2 is False

    def test_capabilities_no_block_tier3(self):
        """不支持 Tier3 阻断"""
        collector = _create_collector()
        caps = collector.capabilities()
        assert caps.can_block_tier3 is False

    def test_capabilities_not_transparent(self):
        """非透明（strace -p 附着到进程）"""
        collector = _create_collector()
        caps = collector.capabilities()
        assert caps.is_transparent is False

    def test_capabilities_performance_medium(self):
        """性能开销中等"""
        collector = _create_collector()
        caps = collector.capabilities()
        assert caps.performance_overhead == "medium"

    def test_capabilities_time_source(self):
        """时间源为 realtime_monotonic"""
        collector = _create_collector()
        caps = collector.capabilities()
        assert caps.time_source == "realtime_monotonic"


# ============================================================
# 测试类: send_command()
# ============================================================

class TestSendCommand:
    """阻断指令测试"""

    def test_send_command_returns_false(self):
        """send_command 始终返回 False"""
        collector = _create_collector()
        result = collector.send_command(MagicMock())
        assert result is False

    def test_send_command_logs_warning(self, caplog):
        """send_command 记录警告日志"""
        collector = _create_collector()
        with caplog.at_level(logging.WARNING):
            collector.send_command(MagicMock())

        assert any("不支持阻断" in record.message or
                    "strace" in record.message
                    for record in caplog.records)


# ============================================================
# 测试类: 生命周期管理
# ============================================================

class TestLifecycle:
    """生命周期管理测试"""

    def test_initial_state(self):
        """初始状态未附着"""
        collector = _create_collector()
        assert collector._attached is False
        assert collector._running is False
        assert collector._process is None

    def test_get_process_tree_empty(self):
        """get_process_tree 第一版返回空字典"""
        collector = _create_collector()
        tree = collector.get_process_tree()
        assert tree == {}

    def test_detach_resets_state(self):
        """detach 重置状态"""
        collector = _create_collector()
        collector._attached = True
        collector._running = True

        collector.detach()

        assert collector._attached is False
        assert collector._running is False

    def test_detach_with_mock_process(self):
        """detach 终止 strace 子进程"""
        collector = _create_collector()
        mock_process = MagicMock()
        mock_process.wait.return_value = 0
        collector._process = mock_process
        collector._attached = True
        collector._running = True

        collector.detach()

        mock_process.terminate.assert_called_once()
        assert collector._process is None

    def test_detach_timeout_force_kill(self):
        """detach 超时强制 kill"""
        import subprocess
        collector = _create_collector()
        mock_process = MagicMock()
        # 第一次 wait 超时，kill 后第二次 wait 成功
        mock_process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="strace", timeout=5),
            None  # kill 后正常退出
        ]
        collector._process = mock_process
        collector._attached = True
        collector._running = True

        collector.detach()

        mock_process.terminate.assert_called_once()
        mock_process.kill.assert_called_once()
        assert collector._process is None

    def test_attach_invalid_pid(self):
        """attach 无效 PID 返回 False"""
        collector = _create_collector()
        result = collector.attach(target_pid=0)
        assert result is False

    def test_attach_negative_pid(self):
        """attach 负数 PID 返回 False"""
        collector = _create_collector()
        result = collector.attach(target_pid=-1)
        assert result is False


# ============================================================
# 测试类: RawEvent 字段一致性
# ============================================================

class TestRawEventConsistency:
    """验证 strace RawEvent 与模拟/eBPF RawEvent 字段一致"""

    def test_event_type_values(self):
        """event_type 值域与模拟模式一致"""
        collector = _create_collector()

        exec_line = 'execve("/bin/ls", ["ls"], 0x7fff...) = 0'
        file_line = 'openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
        net_line = 'connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0'

        exec_raw = collector._parse_line(exec_line)
        file_raw = collector._parse_line(file_line)
        net_raw = collector._parse_line(net_line)

        assert exec_raw.event_type == "exec"
        assert file_raw.event_type == "file_open"
        assert net_raw.event_type == "net_conn"

    def test_pid_ppid_are_integers(self):
        """pid/ppid 为整数类型"""
        collector = _create_collector()
        line = '[pid 12345] execve("/bin/ls", ["ls"], 0x7fff...) = 0'
        raw = collector._parse_line(line)

        assert isinstance(raw.pid, int)
        assert isinstance(raw.ppid, int)

    def test_agent_framework_is_strace(self):
        """agent_framework 固定为 strace"""
        collector = _create_collector()
        line = 'execve("/bin/ls", ["ls"], 0x7fff...) = 0'
        raw = collector._parse_line(line)

        assert raw.agent_framework == "strace"

    def test_agent_id_from_config(self):
        """agent_id 从配置读取"""
        config = {
            "strace": {
                "strace_bin": "strace",
                "target_agent_id": "my-custom-agent",
            }
        }
        collector = StraceCollector(config)
        line = 'execve("/bin/ls", ["ls"], 0x7fff...) = 0'
        raw = collector._parse_line(line)

        assert raw.agent_id == "my-custom-agent"

    def test_event_id_format(self):
        """event_id 格式一致"""
        collector = _create_collector()
        line = 'execve("/bin/ls", ["ls"], 0x7fff...) = 0'
        raw = collector._parse_line(line)

        assert raw.event_id.startswith("strace_evt_")


# ============================================================
# 测试类: 正则表达式单元测试
# ============================================================

class TestRegexPatterns:
    """正则表达式模式匹配测试"""

    def test_execve_regex(self):
        """execve 正则匹配"""
        line = 'execve("/bin/ls", ["ls", "-la"], 0x7fff...) = 0'
        m = _RE_EXECVE.search(line)
        assert m is not None
        assert m.group(2) == "/bin/ls"
        assert "ls" in m.group(3)

    def test_openat_regex(self):
        """openat 正则匹配"""
        line = 'openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3'
        m = _RE_OPENAT.search(line)
        assert m is not None
        assert m.group(2) == "/etc/passwd"
        assert "O_RDONLY" in m.group(3)

    def test_connect_regex(self):
        """connect 正则匹配"""
        line = 'connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0'
        m = _RE_CONNECT.search(line)
        assert m is not None
        assert m.group(3) == "443"
        assert m.group(4) == "93.184.216.34"

    def test_execve_with_pid_regex(self):
        """带 pid 前缀的 execve 正则匹配"""
        line = '[pid 12345] execve("/bin/cat", ["cat", "file.txt"], 0x7fff...) = 0'
        m = _RE_EXECVE.search(line)
        assert m is not None
        assert m.group(1) == "12345"

    def test_openat_with_pid_regex(self):
        """带 pid 前缀的 openat 正则匹配"""
        line = '[pid 99999] openat(AT_FDCWD, "/tmp/x", O_WRONLY) = 5'
        m = _RE_OPENAT.search(line)
        assert m is not None
        assert m.group(1) == "99999"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
