"""
adapter/platform_detect.py — 平台检测 + Collector 工厂

核心职责:
1. 检测当前运行平台 (Windows / Linux)
2. 查询 eBPF 能力 (BTF / libbpf / CAP_BPF)
3. 根据 config["mode"] 或 --mode 参数创建对应的 ICollector 实例

模式选择优先级: mode_override > config["mode"] > "auto"
"""

import sys
import os
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class PlatformInfo:
    """平台信息描述"""
    platform: str           # "windows" | "linux"
    is_windows: bool
    is_linux: bool
    has_ebpf: bool          # eBPF 能力是否可用
    has_strace: bool        # strace 是否可用

    @staticmethod
    def detect() -> "PlatformInfo":
        """检测当前平台信息"""
        is_win = sys.platform == "win32"
        is_linux = sys.platform.startswith("linux")
        has_ebpf = False
        has_strace = False

        if is_linux:
            has_ebpf = _check_ebpf_capability()
            has_strace = os.path.isfile("/usr/bin/strace") or os.path.isfile("/usr/local/bin/strace")

        return PlatformInfo(
            platform="windows" if is_win else ("linux" if is_linux else sys.platform),
            is_windows=is_win,
            is_linux=is_linux,
            has_ebpf=has_ebpf,
            has_strace=has_strace,
        )


def _check_ebpf_capability() -> bool:
    """
    检查 eBPF 能力: BTF + libbpf + CAP_BPF

    仅在 Linux 上执行，Windows 上返回 False。
    """
    if sys.platform == "win32":
        return False

    # 1. BTF 文件存在
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        return False

    # 2. libbpf.so 可加载
    try:
        import ctypes
        ctypes.CDLL("libbpf.so")
    except OSError:
        return False

    # 3. CAP_BPF + CAP_PERFMON 权限检查
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_hex = int(line.split(":")[1].strip(), 16)
                    # CAP_BPF = 39, CAP_PERFMON = 38
                    return bool(cap_hex & (1 << 39)) and bool(cap_hex & (1 << 38))
    except Exception:
        return False

    return False


def detect_and_create_collector(config: dict, mode_override: str = None):
    """
    平台检测 + Collector 创建工厂。

    优先级: mode_override > config["mode"] > "auto"

    参数:
        config:        配置字典（从 config.yaml 加载）
        mode_override: CLI --mode 参数覆盖值

    返回:
        对应平台的 ICollector 实例

    异常:
        RuntimeError: 在不支持的平台上强制使用特定模式
    """
    mode = mode_override or config.get("mode", "auto")

    # 延迟导入避免循环依赖
    from collector.simulation_collector import SimulationCollector

    if mode == "simulation":
        return SimulationCollector(config)

    elif mode == "ebpf":
        if sys.platform == "win32":
            raise RuntimeError("eBPF 模式仅支持 Linux")
        try:
            from collector.ebpf_collector import EbpfCollector
            return EbpfCollector(config)
        except ImportError:
            raise RuntimeError("eBPF 采集器未实现或依赖缺失 (libbpf)")

    elif mode == "strace":
        if sys.platform == "win32":
            raise RuntimeError("strace 模式仅支持 Linux")
        try:
            from collector.strace_collector import StraceCollector
            return StraceCollector(config)
        except ImportError:
            raise RuntimeError("strace 采集器未实现")

    elif mode == "file_replay":
        try:
            from collector.file_replay_collector import FileReplayCollector
            return FileReplayCollector(config)
        except ImportError:
            raise RuntimeError("文件回放采集器未实现")

    else:  # auto
        if sys.platform == "win32":
            logger.info("检测到 Windows 平台，启用模拟模式")
            return SimulationCollector(config)
        else:
            if _check_ebpf_capability():
                logger.info("检测到 eBPF 支持，启用真实观测模式")
                try:
                    from collector.ebpf_collector import EbpfCollector
                    return EbpfCollector(config)
                except ImportError:
                    logger.warning("eBPF 采集器加载失败，降级为模拟模式")
                    return SimulationCollector(config)
            else:
                logger.info("eBPF 不可用，降级为 strace 观测模式")
                try:
                    from collector.strace_collector import StraceCollector
                    return StraceCollector(config)
                except ImportError:
                    logger.warning("strace 采集器也未实现，降级为模拟模式")
                    return SimulationCollector(config)
