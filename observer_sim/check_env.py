#!/usr/bin/env python3
"""
check_env.py — 环境预检脚本（Windows / Linux 双端通用）

检查项目运行和开发所需的全部环境依赖，输出清晰的 ✅ / ❌ 状态报告。

已挂载至 observer 统一入口:
    python observer.py env [--light]        # 独立环境检测子命令（完整 / 轻量）
    python observer.py samples check-env    # 兼容入口（等价完整检测）

结构化 API（供 console.py 菜单复用，检测逻辑单一事实来源）:
    run_checks(light=False) -> list[EnvItem]    # 纯收集，无打印副作用
    print_report(items, light=False) -> None    # 打印格式化报告

检测项说明:
    - 轻量检测（<1 秒，无子进程）: 平台 / Python 版本 / 关键文件存在性
    - 完整检测: 轻量检测 + pyyaml/pytest 依赖包 + 模块导入
                + 平台专有工具链（Linux: eBPF 工具链 + g++/cmake；
                  Windows: cmake + pywin32）

使用方法:
    python check_env.py                      # 直接运行（完整检测）
    python check_env.py --light              # 轻量检测
"""

import sys
import os
import shutil
import subprocess
import importlib
from dataclasses import dataclass
from typing import List

# Windows 终端编码兼容
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except (AttributeError, Exception):
    pass

# ============================================================
# 输出工具
# ============================================================

PASS = "[OK]"
FAIL = "[FAIL]"
WARN = "[WARN]"

# ============================================================
# 检测清单常量（轻量检测与完整检测共用，单一事实来源）
# ============================================================

CRITICAL_FILES = [
    "main.py",
    "demo.py",
    "app.py",
    "config.yaml",
    "conftest.py",
    "adapter/__init__.py",
    "adapter/platform_detect.py",
    "adapter/pipe_factory.py",
    "adapter/time_source.py",
    "collector/__init__.py",
    "collector/base_collector.py",
    "collector/simulation_collector.py",
    "collector/ebpf_collector.py",
    "collector/strace_collector.py",
    "collector/mcp_report_collector.py",
    "mcp_bridge/__init__.py",
    "mcp_bridge/server.py",
    "mcp_bridge/validation.py",
    "mcp_bridge/semantic_guard.py",
    "scenarios/normal/n01_standard_development.yaml",
    "rules/default_policy.yaml",
]

MODULE_CHECKS = [
    ("adapter.platform_detect", "detect_and_create_collector"),
    ("collector.base_collector", "ICollector"),
    ("collector.simulation_collector", "SimulationCollector"),
    ("collector.ebpf_collector", "EbpfCollector"),
    ("collector.strace_collector", "StraceCollector"),
    ("collector.file_replay_collector", "FileReplayCollector"),
    ("collector.deep_agent_collector", "DeepAgentCollector"),
    ("collector.mcp_report_collector", "McpReportCollector"),
    ("mcp_bridge.server", "create_server"),
    ("mcp_bridge.validation", "ReportValidator"),
    ("mcp_bridge.semantic_guard", "SemanticGuard"),
]


@dataclass
class EnvItem:
    """单项检测结果（结构化，供菜单/CLI 复用）。"""
    name: str
    passed: bool
    detail: str = ""
    section: str = ""


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _is_windows() -> bool:
    return sys.platform == "win32"


def run_cmd(cmd: list, timeout: int = 10) -> tuple:
    """运行命令并返回 (returncode, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"
    except Exception as e:
        return -3, "", str(e)


# ============================================================
# 结构化检测收集（纯收集，无打印副作用）
# ============================================================

def collect_platform() -> List[EnvItem]:
    """平台识别（Windows / Linux）。"""
    if _is_windows():
        name = "windows"
    elif _is_linux():
        name = "linux"
    else:
        name = sys.platform
    return [EnvItem("平台", True, f"{name} ({sys.platform})", "基础环境")]


def collect_python(light: bool = False) -> List[EnvItem]:
    """Python 版本（必查）+ pyyaml / pytest 依赖包（完整检测）。"""
    items = []
    ver = sys.version_info
    passed = ver >= (3, 10)
    items.append(EnvItem(
        "Python 版本", passed,
        f"{ver.major}.{ver.minor}.{ver.micro}" + ("" if passed else ", 需要 >= 3.10"),
        "Python 环境"))
    if light:
        return items

    # pyyaml
    try:
        import yaml
        items.append(EnvItem("pyyaml", True, f"版本 {yaml.__version__}", "Python 环境"))
    except ImportError:
        items.append(EnvItem("pyyaml", False, "pip install pyyaml", "Python 环境"))

    # pytest
    try:
        import pytest
        items.append(EnvItem("pytest", True, f"版本 {pytest.__version__}", "Python 环境"))
    except ImportError:
        items.append(EnvItem("pytest", False, "pip install pytest", "Python 环境"))
    return items


def collect_files() -> List[EnvItem]:
    """项目关键文件完整性（21 项）。"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    items = []
    for f in CRITICAL_FILES:
        path = os.path.join(base_dir, f)
        items.append(EnvItem(f, os.path.isfile(path), "", "项目文件完整性"))
    return items


def collect_modules() -> List[EnvItem]:
    """Python 模块导入检查（11 项，覆盖全部采集器与 MCP 申报通道）。"""
    items = []
    for mod_name, symbol in MODULE_CHECKS:
        try:
            mod = importlib.import_module(mod_name)
            has_symbol = hasattr(mod, symbol)
            items.append(EnvItem(f"{mod_name}.{symbol}", has_symbol,
                                 "", "Python 模块导入"))
        except Exception as e:
            items.append(EnvItem(f"{mod_name}", False,
                                 str(e).split("\n")[0][:80], "Python 模块导入"))
    return items


def collect_mcp_sdk() -> List[EnvItem]:
    """mcp_report 模式依赖检测（官方 mcp SDK 可用性，P4-9）。"""
    items = []
    try:
        from mcp_bridge.server import mcp_sdk_available
        available = mcp_sdk_available()
        if available:
            try:
                import mcp
                detail = f"版本 {getattr(mcp, '__version__', '未知')}"
            except ImportError:
                detail = "可用"
            items.append(EnvItem("mcp SDK (mcp_report 模式)", True, detail,
                                 "MCP 申报通道"))
        else:
            items.append(EnvItem("mcp SDK (mcp_report 模式)", False,
                                 "pip install mcp", "MCP 申报通道"))
    except Exception as e:
        items.append(EnvItem("mcp SDK (mcp_report 模式)", False,
                             str(e).split("\n")[0][:80], "MCP 申报通道"))
    return items


def _collect_linux_ebpf() -> List[EnvItem]:
    """Linux eBPF 工具链检查（仅在 Linux 上执行）。"""
    items = []

    # clang
    rc, out, _ = run_cmd(["clang", "--version"])
    if rc == 0:
        first_line = out.split("\n")[0] if out else ""
        items.append(EnvItem("clang", True, first_line[:60], "Linux eBPF 工具链"))
    else:
        items.append(EnvItem("clang", False, "sudo apt install clang", "Linux eBPF 工具链"))

    # bpftool
    rc, out, _ = run_cmd(["bpftool", "version"])
    if rc == 0:
        items.append(EnvItem("bpftool", True, out.split("\n")[0] if out else "",
                             "Linux eBPF 工具链"))
    else:
        items.append(EnvItem("bpftool", False, "sudo apt install linux-tools-generic",
                             "Linux eBPF 工具链"))

    # libbpf-dev
    libbpf_path = "/usr/lib/x86_64-linux-gnu/libbpf.so"
    libbpf_alt = "/usr/lib/libbpf.so"
    has_libbpf = os.path.isfile(libbpf_path) or os.path.isfile(libbpf_alt)
    if not has_libbpf:
        # 尝试 ldconfig
        rc, out, _ = run_cmd(["ldconfig", "-p"])
        if rc == 0 and "libbpf" in out:
            has_libbpf = True
    items.append(EnvItem("libbpf.so", has_libbpf,
                         "" if has_libbpf else "sudo apt install libbpf-dev",
                         "Linux eBPF 工具链"))

    # BTF 支持
    btf_path = "/sys/kernel/btf/vmlinux"
    items.append(EnvItem("BTF 支持", os.path.exists(btf_path), btf_path,
                         "Linux eBPF 工具链"))

    # 内核版本
    rc, out, _ = run_cmd(["uname", "-r"])
    if rc == 0:
        kernel_ver = out.strip()
        parts = kernel_ver.split(".")
        try:
            major, minor = int(parts[0]), int(parts[1])
            kernel_ok = (major, minor) >= (5, 15)
        except (IndexError, ValueError):
            kernel_ok = False
        items.append(EnvItem("内核版本", kernel_ok,
                             kernel_ver + ("" if kernel_ok else ", 需要 >= 5.15"),
                             "Linux eBPF 工具链"))
    else:
        items.append(EnvItem("内核版本", False, "无法获取", "Linux eBPF 工具链"))

    # strace
    rc, out, _ = run_cmd(["strace", "-V"])
    if rc == 0:
        ver_line = out.split("\n")[0] if out else ""
        items.append(EnvItem("strace", True, ver_line[:50], "Linux eBPF 工具链"))
    else:
        items.append(EnvItem("strace", False, "sudo apt install strace", "Linux eBPF 工具链"))

    # eBPF 编译产物
    base_dir = os.path.dirname(os.path.abspath(__file__))
    bpf_c = os.path.join(base_dir, "ebpf", "observer.bpf.c")
    bpf_o = os.path.join(base_dir, "ebpf", "observer.bpf.o")
    bpf_makefile = os.path.join(base_dir, "ebpf", "Makefile")

    items.append(EnvItem("ebpf/observer.bpf.c", os.path.isfile(bpf_c), "",
                         "Linux eBPF 工具链"))
    items.append(EnvItem("ebpf/Makefile", os.path.isfile(bpf_makefile), "",
                         "Linux eBPF 工具链"))
    items.append(EnvItem(
        "ebpf/observer.bpf.o (编译产物)", os.path.isfile(bpf_o),
        "" if os.path.isfile(bpf_o) else "cd ebpf && make",
        "Linux eBPF 工具链"))
    return items


def _collect_linux_cpp() -> List[EnvItem]:
    """Linux 上 C++ 编译工具（可选）。"""
    items = []
    rc, out, _ = run_cmd(["g++", "--version"])
    if rc == 0:
        first_line = out.split("\n")[0] if out else ""
        items.append(EnvItem("g++", True, first_line[:60], "C++ 编译工具（可选）"))
    else:
        items.append(EnvItem("g++", False, "sudo apt install g++", "C++ 编译工具（可选）"))

    rc, out, _ = run_cmd(["cmake", "--version"])
    if rc == 0:
        first_line = out.split("\n")[0] if out else ""
        items.append(EnvItem("cmake", True, first_line, "C++ 编译工具（可选）"))
    else:
        items.append(EnvItem("cmake", False, "sudo apt install cmake", "C++ 编译工具（可选）"))
    return items


def _collect_windows_toolchain() -> List[EnvItem]:
    """Windows 上 C++ 编译工具（可选）+ pywin32（命名管道辅助通道）。"""
    items = []
    rc, out, _ = run_cmd(["cmake", "--version"])
    if rc == 0:
        first_line = out.split("\n")[0] if out else ""
        items.append(EnvItem("cmake", True, first_line, "C++ 编译工具（可选）"))
    else:
        items.append(EnvItem("cmake", False, "安装 CMake 或 Visual Studio Build Tools",
                             "C++ 编译工具（可选）"))

    # pywin32（Windows 命名管道辅助通道依赖，模拟模式主路径不强制）
    try:
        import win32pipe  # noqa: F401
        import win32file  # noqa: F401
        items.append(EnvItem("pywin32 (win32pipe)", True, "命名管道辅助通道",
                             "Python 依赖（Windows）"))
    except ImportError:
        items.append(EnvItem("pywin32 (win32pipe)", False,
                             "pip install pywin32（命名管道辅助通道）",
                             "Python 依赖（Windows）"))
    return items


def collect_toolchain() -> List[EnvItem]:
    """平台专有工具链检查（条件执行）。"""
    if _is_linux():
        return _collect_linux_ebpf() + _collect_linux_cpp()
    return _collect_windows_toolchain()


# ============================================================
# 统一检测入口（结构化，供 observer / console 复用）
# ============================================================

def run_checks(light: bool = False) -> List[EnvItem]:
    """执行环境检测并返回结构化结果。

    light=True: 平台 / Python 版本 / 关键文件（<1 秒，无子进程）。
    light=False: 完整检测（轻量 + 依赖包 + 模块导入 + 平台工具链）。
    """
    items = collect_platform() + collect_python(light=light) + collect_files()
    if not light:
        items += collect_modules() + collect_mcp_sdk() + collect_toolchain()
    return items


def print_report(items: List[EnvItem], light: bool = False) -> None:
    """打印格式化检测报告（原 check()/section() 输出风格的统一渲染）。"""
    print("=" * 50)
    print("  方寸观察者 — 环境预检" + ("（轻量）" if light else ""))
    print("=" * 50)
    print(f"  平台: {sys.platform}")
    print(f"  Python: {sys.executable}")
    print(f"  工作目录: {os.path.dirname(os.path.abspath(__file__))}")

    current_section = None
    for item in items:
        if item.section != current_section:
            current_section = item.section
            print(f"\n{'=' * 50}")
            print(f"  {current_section}")
            print(f"{'=' * 50}")
        status = PASS if item.passed else FAIL
        msg = f"  {status} {item.name}"
        if item.detail:
            msg += f"  ({item.detail})"
        print(msg)

    total = len(items)
    passed = sum(1 for i in items if i.passed)
    failed = total - passed

    print(f"\n{'=' * 50}")
    print(f"  检查汇总")
    print(f"{'=' * 50}")
    print(f"  总计: {total} 项")
    print(f"  {PASS} 通过: {passed}")
    print(f"  {FAIL} 失败: {failed}")

    if failed == 0:
        print(f"\n  === 环境就绪！所有 {total} 项检查通过。 ===")
    else:
        print(f"\n  === {failed} 项检查未通过，请根据上方提示安装缺失依赖。 ===")

    if not light:
        print(f"\n  参考测试基线 (Windows 实机): 749 passed, 6 skipped (Linux-only)")
        print(f"  运行测试: python -m pytest tests/ -v")
    print()


def main(light: bool = False) -> int:
    """CLI 壳: 执行检测并打印报告。返回 0=全部通过 / 1=存在失败项。"""
    items = run_checks(light=light)
    print_report(items, light=light)
    failed = sum(1 for i in items if not i.passed)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    # 确保项目目录在 sys.path 中
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    _light = "--light" in sys.argv[1:]
    sys.exit(main(light=_light))
