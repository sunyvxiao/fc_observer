"""
tests/test_collector_integration.py — Phase 4 集成测试

测试覆盖:
  1. 三模式切换（simulation / strace / ebpf / auto）
  2. 三种 Collector 的 capabilities() 对比验证
  3. 降级逻辑验证（eBPF → strace → simulation）
  4. 事件格式一致性验证（三种 Collector 产生的 RawEvent 字段一致）
  5. 工厂函数 detect_and_create_collector() 各分支覆盖
  6. ICollector 接口一致性（所有采集器实现全部抽象方法）
"""

import sys
import os
import logging
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.base_collector import ICollector, CollectorCapabilities
from collector.simulation_collector import SimulationCollector
from collector.strace_collector import StraceCollector
from collector.ebpf_collector import EbpfCollector
from adapter.platform_detect import detect_and_create_collector, PlatformInfo
from models.event import RawEvent


# ============================================================
# 辅助函数
# ============================================================

def _make_base_config():
    """基础测试配置"""
    return {
        "mode": "auto",
        "simulation": {
            "scenarios_dir": "scenarios/",
            "virtual_clock_start_ns": 1718092800000000000,
        },
        "ebpf": {
            "bpf_object_path": "/tmp/test_observer.bpf.o",
            "target_agent_id": "test-agent",
            "perf_buffer_page_count": 64,
        },
        "strace": {
            "strace_bin": "strace",
            "target_agent_id": "test-agent",
        },
        "virtual_clock": {
            "start_ns": 1718092800000000000,
        },
    }


def _create_mock_ebpf_collector(config=None):
    """创建 mock libbpf 的 EbpfCollector"""
    if config is None:
        config = _make_base_config()
    mock_lib = MagicMock()
    mock_lib.bpf_object__open.return_value = MagicMock()
    mock_lib.bpf_object__load.return_value = 0
    mock_lib.bpf_object__find_program_by_name.return_value = MagicMock()
    mock_lib.bpf_program__attach.return_value = MagicMock()
    mock_lib.bpf_object__find_map_fd_by_name.return_value = 5
    mock_lib.perf_buffer__new_raw.return_value = MagicMock()

    with patch("collector.ebpf_collector._load_libbpf", return_value=mock_lib):
        collector = EbpfCollector(config)
        collector._lib = mock_lib
        return collector


# ============================================================
# 测试类: 工厂函数模式切换
# ============================================================

class TestFactoryModeSwitching:
    """detect_and_create_collector() 模式切换测试"""

    def test_simulation_mode(self):
        """simulation 模式返回 SimulationCollector"""
        config = _make_base_config()
        collector = detect_and_create_collector(config, mode_override="simulation")
        assert isinstance(collector, SimulationCollector)

    @pytest.mark.skipif(sys.platform == "win32", reason="strace 模式仅支持 Linux")
    def test_strace_mode(self):
        """strace 模式返回 StraceCollector"""
        config = _make_base_config()
        collector = detect_and_create_collector(config, mode_override="strace")
        assert isinstance(collector, StraceCollector)

    @pytest.mark.skipif(sys.platform == "win32", reason="eBPF 模式仅支持 Linux")
    def test_ebpf_mode_linux(self):
        """ebpf 模式在 Linux 上返回 EbpfCollector"""
        config = _make_base_config()
        # mock libbpf 加载
        with patch("collector.ebpf_collector._load_libbpf", return_value=MagicMock()):
            collector = detect_and_create_collector(config, mode_override="ebpf")
            assert isinstance(collector, EbpfCollector)

    def test_ebpf_mode_windows_raises(self):
        """ebpf 模式在 Windows 上抛出 RuntimeError"""
        config = _make_base_config()
        with patch("sys.platform", "win32"):
            with pytest.raises(RuntimeError, match="仅支持 Linux"):
                detect_and_create_collector(config, mode_override="ebpf")

    def test_strace_mode_windows_raises(self):
        """strace 模式在 Windows 上抛出 RuntimeError"""
        config = _make_base_config()
        with patch("sys.platform", "win32"):
            with pytest.raises(RuntimeError, match="仅支持 Linux"):
                detect_and_create_collector(config, mode_override="strace")

    def test_auto_mode_windows_returns_simulation(self):
        """auto 模式在 Windows 上返回 SimulationCollector"""
        config = _make_base_config()
        with patch("sys.platform", "win32"):
            collector = detect_and_create_collector(config, mode_override="auto")
            assert isinstance(collector, SimulationCollector)

    def test_auto_mode_linux_ebpf_available(self):
        """auto 模式在 Linux + eBPF 可用时返回 EbpfCollector"""
        config = _make_base_config()
        with patch("sys.platform", "linux"):
            with patch("adapter.platform_detect._check_ebpf_capability", return_value=True):
                with patch("collector.ebpf_collector._load_libbpf", return_value=MagicMock()):
                    collector = detect_and_create_collector(config, mode_override="auto")
                    assert isinstance(collector, EbpfCollector)

    def test_auto_mode_linux_ebpf_unavailable_strace(self):
        """auto 模式在 Linux + eBPF 不可用时降级为 StraceCollector"""
        config = _make_base_config()
        with patch("sys.platform", "linux"):
            with patch("adapter.platform_detect._check_ebpf_capability", return_value=False):
                collector = detect_and_create_collector(config, mode_override="auto")
                assert isinstance(collector, StraceCollector)

    def test_auto_mode_linux_ebpf_fail_strace_fail(self):
        """auto 模式 eBPF 和 strace 都不可用时降级为 SimulationCollector"""
        config = _make_base_config()
        with patch("sys.platform", "linux"):
            with patch("adapter.platform_detect._check_ebpf_capability", return_value=False):
                with patch("collector.strace_collector.StraceCollector.__init__",
                           side_effect=ImportError("no strace")):
                    collector = detect_and_create_collector(config, mode_override="auto")
                    assert isinstance(collector, SimulationCollector)

    def test_mode_override_takes_priority(self):
        """mode_override 优先于 config['mode']"""
        config = _make_base_config()
        config["mode"] = "ebpf"  # config 设为 ebpf
        # override 为 simulation，应返回 SimulationCollector
        collector = detect_and_create_collector(config, mode_override="simulation")
        assert isinstance(collector, SimulationCollector)

    def test_config_mode_used_when_no_override(self):
        """无 mode_override 时使用 config['mode']"""
        config = _make_base_config()
        config["mode"] = "simulation"
        collector = detect_and_create_collector(config)
        assert isinstance(collector, SimulationCollector)


# ============================================================
# 测试类: 三种 Collector capabilities() 对比
# ============================================================

class TestCapabilitiesComparison:
    """三种采集器能力对比测试"""

    def test_all_implement_icollector(self):
        """三种采集器都实现 ICollector 接口"""
        config = _make_base_config()

        sim = SimulationCollector(config)
        strace = StraceCollector(config)
        ebpf = _create_mock_ebpf_collector(config)

        assert isinstance(sim, ICollector)
        assert isinstance(strace, ICollector)
        assert isinstance(ebpf, ICollector)

    def test_all_have_capabilities(self):
        """三种采集器都能返回 capabilities"""
        config = _make_base_config()

        sim_caps = SimulationCollector(config).capabilities()
        strace_caps = StraceCollector(config).capabilities()
        ebpf_caps = _create_mock_ebpf_collector(config).capabilities()

        assert isinstance(sim_caps, CollectorCapabilities)
        assert isinstance(strace_caps, CollectorCapabilities)
        assert isinstance(ebpf_caps, CollectorCapabilities)

    def test_names_are_distinct(self):
        """三种采集器名称不同"""
        config = _make_base_config()

        names = {
            SimulationCollector(config).capabilities().name,
            StraceCollector(config).capabilities().name,
            _create_mock_ebpf_collector(config).capabilities().name,
        }
        assert names == {"Simulation", "Strace", "Ebpf"}

    def test_simulation_supports_blocking(self):
        """模拟模式支持阻断"""
        caps = SimulationCollector(_make_base_config()).capabilities()
        assert caps.can_block_tier2 is True
        assert caps.can_block_tier3 is True

    def test_strace_no_blocking(self):
        """strace 模式不支持阻断"""
        caps = StraceCollector(_make_base_config()).capabilities()
        assert caps.can_block_tier2 is False
        assert caps.can_block_tier3 is False

    def test_ebpf_v1_no_blocking(self):
        """eBPF 第一版不支持阻断"""
        caps = _create_mock_ebpf_collector().capabilities()
        assert caps.can_block_tier2 is False
        assert caps.can_block_tier3 is False

    def test_all_can_observe(self):
        """三种采集器都支持观测"""
        config = _make_base_config()

        assert SimulationCollector(config).capabilities().can_observe is True
        assert StraceCollector(config).capabilities().can_observe is True
        assert _create_mock_ebpf_collector(config).capabilities().can_observe is True

    def test_time_sources_differ(self):
        """三种采集器时间源不同"""
        config = _make_base_config()

        sim_ts = SimulationCollector(config).capabilities().time_source
        strace_ts = StraceCollector(config).capabilities().time_source
        ebpf_ts = _create_mock_ebpf_collector(config).capabilities().time_source

        assert sim_ts == "virtual"
        assert strace_ts == "realtime_monotonic"
        assert ebpf_ts == "realtime_monotonic"

    def test_ebpf_is_transparent(self):
        """eBPF 对 Agent 无感知"""
        caps = _create_mock_ebpf_collector().capabilities()
        assert caps.is_transparent is True

    def test_strace_not_transparent(self):
        """strace 附着到进程，非完全透明"""
        caps = StraceCollector(_make_base_config()).capabilities()
        assert caps.is_transparent is False

    def test_simulation_not_transparent(self):
        """模拟模式 Agent 可感知"""
        caps = SimulationCollector(_make_base_config()).capabilities()
        assert caps.is_transparent is False


# ============================================================
# 测试类: send_command() 行为一致性
# ============================================================

class TestSendCommandBehavior:
    """send_command 行为一致性测试"""

    def test_simulation_send_command(self):
        """SimulationCollector send_command 返回 True"""
        collector = SimulationCollector(_make_base_config())
        assert collector.send_command(MagicMock()) is True

    def test_strace_send_command_returns_false(self):
        """StraceCollector send_command 返回 False"""
        collector = StraceCollector(_make_base_config())
        assert collector.send_command(MagicMock()) is False

    def test_ebpf_send_command_returns_false(self):
        """EbpfCollector send_command 返回 False"""
        collector = _create_mock_ebpf_collector()
        assert collector.send_command(MagicMock()) is False


# ============================================================
# 测试类: 事件格式一致性验证
# ============================================================

class TestEventFormatConsistency:
    """验证三种 Collector 产生的 RawEvent 字段格式一致"""

    def test_all_produce_raw_event(self):
        """三种采集器都能产生 RawEvent 对象"""
        config = _make_base_config()

        # SimulationCollector: 从场景生成
        sim = SimulationCollector(config)
        sim.attach(agent_id="test")
        scenario_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "scenarios", "normal", "n01_standard_development.yaml"
        )
        if os.path.exists(scenario_path):
            sim.load_scenario(scenario_path)
            events = list(sim.start())
            if events:
                assert isinstance(events[0], RawEvent)

        # StraceCollector: 从 strace 行解析
        strace_c = StraceCollector(config)
        raw = strace_c._parse_line(
            'execve("/bin/ls", ["ls", "-la"], 0x7fff...) = 0')
        assert isinstance(raw, RawEvent)

        # EbpfCollector: 从 event_t 转换
        from tests.test_ebpf_collector import _make_execve_event
        ebpf_c = _create_mock_ebpf_collector(config)
        data = _make_execve_event()
        raw = ebpf_c._to_raw_event(data)
        assert isinstance(raw, RawEvent)

    def test_event_type_strings_consistent(self):
        """三种采集器使用相同的 event_type 字符串"""
        config = _make_base_config()

        # strace
        strace_c = StraceCollector(config)
        exec_raw = strace_c._parse_line(
            'execve("/bin/ls", ["ls"], 0x7fff...) = 0')
        file_raw = strace_c._parse_line(
            'openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3')
        net_raw = strace_c._parse_line(
            'connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("1.2.3.4")}, 16) = 0')

        assert exec_raw.event_type == "exec"
        assert file_raw.event_type == "file_open"
        assert net_raw.event_type == "net_conn"

        # ebpf
        from tests.test_ebpf_collector import (
            _make_execve_event, _make_openat_event, _make_connect_event)
        ebpf_c = _create_mock_ebpf_collector(config)

        ebpf_exec = ebpf_c._to_raw_event(_make_execve_event())
        ebpf_file = ebpf_c._to_raw_event(_make_openat_event())
        ebpf_net = ebpf_c._to_raw_event(_make_connect_event())

        # 类型字符串一致
        assert exec_raw.event_type == ebpf_exec.event_type
        assert file_raw.event_type == ebpf_file.event_type
        assert net_raw.event_type == ebpf_net.event_type

    def test_raw_event_has_all_required_fields(self):
        """RawEvent 包含所有必需字段"""
        config = _make_base_config()
        strace_c = StraceCollector(config)
        raw = strace_c._parse_line(
            'execve("/bin/ls", ["ls", "-la"], 0x7fff...) = 0')

        # 必需字段
        assert raw.event_id is not None
        assert raw.timestamp_ns > 0
        assert raw.event_type == "exec"
        assert isinstance(raw.pid, int)
        assert isinstance(raw.ppid, int)
        assert raw.agent_id != ""
        assert raw.agent_framework != ""

        # to_dict() 包含所有键
        d = raw.to_dict()
        required_keys = [
            "event_id", "timestamp_ns", "event_type", "pid", "ppid",
            "agent_id", "agent_framework", "executable", "arguments",
            "file_path", "file_op", "remote_addr", "remote_port", "protocol"
        ]
        for key in required_keys:
            assert key in d, f"缺少字段: {key}"

    def test_agent_framework_values_differ(self):
        """不同采集器的 agent_framework 值不同"""
        config = _make_base_config()

        strace_c = StraceCollector(config)
        strace_raw = strace_c._parse_line(
            'execve("/bin/ls", ["ls"], 0x7fff...) = 0')
        assert strace_raw.agent_framework == "strace"

        from tests.test_ebpf_collector import _make_execve_event
        ebpf_c = _create_mock_ebpf_collector(config)
        ebpf_raw = ebpf_c._to_raw_event(_make_execve_event())
        assert ebpf_raw.agent_framework == "ebpf"


# ============================================================
# 测试类: ICollector 接口一致性
# ============================================================

class TestICollectorInterface:
    """验证所有采集器正确实现 ICollector 全部抽象方法"""

    def test_all_have_attach(self):
        """所有采集器实现 attach()"""
        config = _make_base_config()
        for collector in [
            SimulationCollector(config),
            StraceCollector(config),
            _create_mock_ebpf_collector(config),
        ]:
            assert hasattr(collector, "attach")
            assert callable(collector.attach)

    def test_all_have_start(self):
        """所有采集器实现 start()"""
        config = _make_base_config()
        for collector in [
            SimulationCollector(config),
            StraceCollector(config),
            _create_mock_ebpf_collector(config),
        ]:
            assert hasattr(collector, "start")
            assert callable(collector.start)

    def test_all_have_send_command(self):
        """所有采集器实现 send_command()"""
        config = _make_base_config()
        for collector in [
            SimulationCollector(config),
            StraceCollector(config),
            _create_mock_ebpf_collector(config),
        ]:
            assert hasattr(collector, "send_command")
            assert callable(collector.send_command)

    def test_all_have_detach(self):
        """所有采集器实现 detach()"""
        config = _make_base_config()
        for collector in [
            SimulationCollector(config),
            StraceCollector(config),
            _create_mock_ebpf_collector(config),
        ]:
            assert hasattr(collector, "detach")
            assert callable(collector.detach)

    def test_all_have_get_process_tree(self):
        """所有采集器实现 get_process_tree()"""
        config = _make_base_config()
        for collector in [
            SimulationCollector(config),
            StraceCollector(config),
            _create_mock_ebpf_collector(config),
        ]:
            assert hasattr(collector, "get_process_tree")
            assert callable(collector.get_process_tree)
            assert isinstance(collector.get_process_tree(), dict)

    def test_all_have_capabilities(self):
        """所有采集器实现 capabilities()"""
        config = _make_base_config()
        for collector in [
            SimulationCollector(config),
            StraceCollector(config),
            _create_mock_ebpf_collector(config),
        ]:
            caps = collector.capabilities()
            assert isinstance(caps, CollectorCapabilities)
            assert isinstance(caps.name, str)
            assert isinstance(caps.can_observe, bool)
            assert isinstance(caps.can_block_tier2, bool)
            assert isinstance(caps.can_block_tier3, bool)
            assert isinstance(caps.is_transparent, bool)
            assert isinstance(caps.performance_overhead, str)
            assert isinstance(caps.time_source, str)


# ============================================================
# 测试类: 降级逻辑验证
# ============================================================

class TestDegradationLogic:
    """降级逻辑测试"""

    def test_ebpf_import_error_degrades(self):
        """eBPF 导入失败时降级"""
        config = _make_base_config()
        with patch("sys.platform", "linux"):
            with patch("adapter.platform_detect._check_ebpf_capability", return_value=True):
                # 模拟 EbpfCollector 导入失败
                with patch("collector.ebpf_collector._load_libbpf",
                           side_effect=ImportError("no libbpf")):
                    # auto 模式应该降级
                    with patch("adapter.platform_detect._check_ebpf_capability",
                               return_value=False):
                        collector = detect_and_create_collector(
                            config, mode_override="auto")
                        # 应该得到 StraceCollector 或 SimulationCollector
                        assert isinstance(collector, (StraceCollector, SimulationCollector))

    def test_simulation_always_works(self):
        """simulation 模式始终可用"""
        config = _make_base_config()
        collector = detect_and_create_collector(config, mode_override="simulation")
        assert isinstance(collector, SimulationCollector)

    def test_strace_available_on_linux(self):
        """Linux 上 strace 可用"""
        info = PlatformInfo.detect()
        if info.is_linux:
            # strace 应该已安装
            assert info.has_strace is True


# ============================================================
# 测试类: PlatformInfo 检测
# ============================================================

class TestPlatformInfo:
    """平台信息检测测试"""

    def test_detect_returns_platform_info(self):
        """detect() 返回 PlatformInfo"""
        info = PlatformInfo.detect()
        assert isinstance(info, PlatformInfo)
        assert isinstance(info.platform, str)
        assert isinstance(info.is_windows, bool)
        assert isinstance(info.is_linux, bool)

    def test_linux_platform(self):
        """Linux 平台检测"""
        info = PlatformInfo.detect()
        if sys.platform.startswith("linux"):
            assert info.is_linux is True
            assert info.is_windows is False
            assert info.platform == "linux"

    def test_windows_detection(self):
        """Windows 平台模拟检测"""
        with patch("sys.platform", "win32"):
            info = PlatformInfo.detect()
            assert info.is_windows is True
            assert info.is_linux is False
            assert info.has_ebpf is False
            assert info.has_strace is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
