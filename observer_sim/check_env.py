#!/usr/bin/env python3
"""
check_env.py — 环境预检脚本（Windows / Linux 双端通用）

检查项目运行和开发所需的全部环境依赖，输出清晰的 ✅ / ❌ 状态报告。

使用方法:
    python check_env.py
"""

import sys
import os
import shutil
import subprocess
import importlib

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

results = []


def check(name: str, passed: bool, detail: str = ""):
    """记录一项检查结果"""
    status = PASS if passed else FAIL
    msg = f"  {status} {name}"
    if detail:
        msg += f"  ({detail})"
    print(msg)
    results.append(passed)
    return passed


def section(title: str):
    """打印分组标题"""
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")


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
# 通用检查（Windows + Linux）
# ============================================================

def check_python():
    section("Python 环境")

    ver = sys.version_info
    passed = ver >= (3, 10)
    check(
        "Python 版本",
        passed,
        f"{ver.major}.{ver.minor}.{ver.micro}" + ("" if passed else ", 需要 >= 3.10")
    )

    # pyyaml
    try:
        import yaml
        check("pyyaml", True, f"版本 {yaml.__version__}")
    except ImportError:
        check("pyyaml", False, "pip install pyyaml")

    # pytest
    try:
        import pytest
        check("pytest", True, f"版本 {pytest.__version__}")
    except ImportError:
        check("pytest", False, "pip install pytest")


def check_project_files():
    section("项目文件完整性")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    critical_files = [
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
        "scenarios/normal/n01_standard_development.yaml",
        "rules/default_policy.yaml",
    ]

    for f in critical_files:
        path = os.path.join(base_dir, f)
        check(f, os.path.isfile(path))


def check_modules():
    section("Python 模块导入")

    modules = [
        ("adapter.platform_detect", "detect_and_create_collector"),
        ("collector.base_collector", "ICollector"),
        ("collector.simulation_collector", "SimulationCollector"),
        ("collector.ebpf_collector", "EbpfCollector"),
        ("collector.strace_collector", "StraceCollector"),
    ]

    for mod_name, symbol in modules:
        try:
            mod = importlib.import_module(mod_name)
            has_symbol = hasattr(mod, symbol)
            check(f"{mod_name}.{symbol}", has_symbol)
        except Exception as e:
            check(f"{mod_name}", False, str(e).split("\n")[0][:80])


# ============================================================
# Linux 专有检查（条件执行）
# ============================================================

def check_linux_ebpf():
    """仅在 Linux 上执行 eBPF 工具链检查"""
    section("Linux eBPF 工具链")

    # clang
    rc, out, _ = run_cmd(["clang", "--version"])
    if rc == 0:
        # 解析版本号
        first_line = out.split("\n")[0] if out else ""
        check("clang", True, first_line[:60])
    else:
        check("clang", False, "sudo apt install clang")

    # bpftool
    rc, out, _ = run_cmd(["bpftool", "version"])
    if rc == 0:
        check("bpftool", True, out.split("\n")[0] if out else "")
    else:
        check("bpftool", False, "sudo apt install linux-tools-generic")

    # libbpf-dev
    libbpf_path = "/usr/lib/x86_64-linux-gnu/libbpf.so"
    libbpf_alt = "/usr/lib/libbpf.so"
    has_libbpf = os.path.isfile(libbpf_path) or os.path.isfile(libbpf_alt)
    if not has_libbpf:
        # 尝试 ldconfig
        rc, out, _ = run_cmd(["ldconfig", "-p"])
        if rc == 0 and "libbpf" in out:
            has_libbpf = True
    check("libbpf.so", has_libbpf, "" if has_libbpf else "sudo apt install libbpf-dev")

    # BTF 支持
    btf_path = "/sys/kernel/btf/vmlinux"
    check("BTF 支持", os.path.exists(btf_path), btf_path)

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
        check("内核版本", kernel_ok, kernel_ver + ("" if kernel_ok else ", 需要 >= 5.15"))
    else:
        check("内核版本", False, "无法获取")

    # strace
    rc, out, _ = run_cmd(["strace", "-V"])
    if rc == 0:
        ver_line = out.split("\n")[0] if out else ""
        check("strace", True, ver_line[:50])
    else:
        check("strace", False, "sudo apt install strace")

    # eBPF 编译产物
    base_dir = os.path.dirname(os.path.abspath(__file__))
    bpf_c = os.path.join(base_dir, "ebpf", "observer.bpf.c")
    bpf_o = os.path.join(base_dir, "ebpf", "observer.bpf.o")
    bpf_makefile = os.path.join(base_dir, "ebpf", "Makefile")

    check("ebpf/observer.bpf.c", os.path.isfile(bpf_c))
    check("ebpf/Makefile", os.path.isfile(bpf_makefile))
    check(
        "ebpf/observer.bpf.o (编译产物)",
        os.path.isfile(bpf_o),
        "" if os.path.isfile(bpf_o) else "cd ebpf && make"
    )


def check_linux_cpp():
    """Linux 上 C++ 编译工具（可选）"""
    section("C++ 编译工具（可选）")

    rc, out, _ = run_cmd(["g++", "--version"])
    if rc == 0:
        first_line = out.split("\n")[0] if out else ""
        check("g++", True, first_line[:60])
    else:
        check("g++", False, "sudo apt install g++")

    rc, out, _ = run_cmd(["cmake", "--version"])
    if rc == 0:
        first_line = out.split("\n")[0] if out else ""
        check("cmake", True, first_line)
    else:
        check("cmake", False, "sudo apt install cmake")


# ============================================================
# Windows 专有检查
# ============================================================

def check_windows_cpp():
    """Windows 上 C++ 编译工具（可选）"""
    section("C++ 编译工具（可选）")

    rc, out, _ = run_cmd(["cmake", "--version"])
    if rc == 0:
        first_line = out.split("\n")[0] if out else ""
        check("cmake", True, first_line)
    else:
        check("cmake", False, "安装 CMake 或 Visual Studio Build Tools")


# ============================================================
# 主流程
# ============================================================

def main():
    print("=" * 50)
    print("  方寸观察者 — 环境预检")
    print("=" * 50)
    print(f"  平台: {sys.platform}")
    print(f"  Python: {sys.executable}")
    print(f"  工作目录: {os.path.dirname(os.path.abspath(__file__))}")

    is_linux = sys.platform.startswith("linux")
    is_windows = sys.platform == "win32"

    # 通用检查
    check_python()
    check_project_files()
    check_modules()

    # 平台专有检查
    if is_linux:
        check_linux_ebpf()
        check_linux_cpp()
    elif is_windows:
        check_windows_cpp()

    # 汇总
    total = len(results)
    passed = sum(results)
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

    # 测试基线提示
    if is_linux:
        print(f"\n  预期测试基线: 297 passed, 0 failed")
    else:
        print(f"\n  预期测试基线: 295 passed, 2 skipped (Linux-only)")

    print(f"  运行测试: python -m pytest tests/ -v")
    print()

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    # 确保项目目录在 sys.path 中
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)

    sys.exit(main())
