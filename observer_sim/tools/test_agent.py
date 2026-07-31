#!/usr/bin/env python3
"""
tools/test_agent.py — 测试 Agent 生成器

执行预定义的操作序列，产生真实 syscall 供 eBPF 探针捕获。
用于验证 EbpfCollector 在真实环境下的采集能力。

用法:
    python3 tools/test_agent.py --scenario baseline_check
    python3 tools/test_agent.py --scenario flood
    python3 tools/test_agent.py --scenario fork_chain
    python3 tools/test_agent.py --scenario long_path
    python3 tools/test_agent.py --scenario failed_ops
    python3 tools/test_agent.py --scenario network

场景列表:
    baseline_check  — ls /tmp → cat /etc/hostname → curl localhost:8080
    long_path       — 创建 300 字节文件名 → 写入 → 读取
    flood           — 循环 1000 次 /bin/true
    fork_chain      — bash 脚本执行 ls && cat && whoami
    failed_ops      — cat /etc/shadow + /bin/nonexistent
    network         — curl + Python socket 连接
"""

import os
import sys
import json
import argparse
import subprocess
import tempfile
import shutil


def _run_cmd(cmd, check=False, timeout=10):
    """执行命令，返回 (成功, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, check=check,
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "timeout"
    except Exception as e:
        return False, "", str(e)


def scenario_baseline_check():
    """
    基线检查: ls /tmp → cat /etc/hostname → curl localhost:8080
    覆盖 syscall: execve, openat, connect
    """
    ops = 0
    success = 0
    skipped = 0

    # ls /tmp
    ops += 1
    ok, _, _ = _run_cmd("ls /tmp > /dev/null 2>&1")
    if ok:
        success += 1

    # cat /etc/hostname
    ops += 1
    ok, _, _ = _run_cmd("cat /etc/hostname > /dev/null 2>&1")
    if ok:
        success += 1

    # curl localhost:8080 (离线兼容: 失败仍产生 execve 事件)
    ops += 1
    ok, _, _ = _run_cmd("curl -s --connect-timeout 2 http://localhost:8080 > /dev/null 2>&1")
    if ok:
        success += 1
    else:
        skipped += 1  # 网络不可用，但 execve 已产生

    return {"operations": ops, "success": success, "skipped": skipped}


def scenario_long_path():
    """
    长路径测试: 创建 300 字节文件名 → 写入 → 读取
    覆盖 syscall: openat
    """
    ops = 0
    success = 0
    skipped = 0

    tmpdir = tempfile.mkdtemp(prefix="test_agent_")
    try:
        # 创建 300 字节文件名
        long_name = "A" * 295
        long_path = os.path.join(tmpdir, long_name)

        # 写入
        ops += 1
        try:
            with open(long_path, "w") as f:
                f.write("test data")
            success += 1
        except OSError:
            skipped += 1

        # 读取
        ops += 1
        try:
            with open(long_path, "r") as f:
                _ = f.read()
            success += 1
        except OSError:
            skipped += 1

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return {"operations": ops, "success": success, "skipped": skipped}


def scenario_flood():
    """
    高频事件: 循环 100 次 /bin/true
    覆盖 syscall: execve (大量)
    """
    count = 100
    success = 0

    for _ in range(count):
        ok, _, _ = _run_cmd("/bin/true")
        if ok:
            success += 1

    return {"operations": count, "success": success, "skipped": 0}


def scenario_fork_chain():
    """
    进程链: bash 执行 ls && cat /etc/hostname && whoami
    覆盖 syscall: execve (含父子进程关系)
    """
    ops = 0
    success = 0

    ops += 1
    ok, _, _ = _run_cmd("bash -c 'ls /tmp > /dev/null 2>&1 && cat /etc/hostname > /dev/null 2>&1 && whoami > /dev/null 2>&1'")
    if ok:
        success += 1

    return {"operations": ops, "success": success, "skipped": 0}


def scenario_failed_ops():
    """
    失败操作: cat /etc/shadow + /bin/nonexistent
    覆盖 syscall: execve (失败), openat (失败)
    """
    ops = 0
    success = 0
    skipped = 0

    # cat /etc/shadow (普通用户无权限)
    ops += 1
    ok, _, _ = _run_cmd("cat /etc/shadow > /dev/null 2>&1")
    if not ok:
        skipped += 1  # 预期失败

    # /bin/nonexistent
    ops += 1
    ok, _, _ = _run_cmd("/bin/nonexistent_cmd_xyz > /dev/null 2>&1")
    if not ok:
        skipped += 1  # 预期失败

    return {"operations": ops, "success": success, "skipped": skipped}


def scenario_network():
    """
    网络测试: curl + Python socket
    覆盖 syscall: connect
    """
    ops = 0
    success = 0
    skipped = 0

    # curl localhost
    ops += 1
    ok, _, _ = _run_cmd("curl -s --connect-timeout 2 http://localhost:80 > /dev/null 2>&1")
    if ok:
        success += 1
    else:
        skipped += 1

    # Python socket 连接
    ops += 1
    try:
        import socket as sock
        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", 80))
        s.close()
        success += 1
    except (ConnectionRefusedError, OSError, TimeoutError):
        skipped += 1

    return {"operations": ops, "success": success, "skipped": skipped}


# ============================================================
# 场景注册表
# ============================================================

SCENARIOS = {
    "baseline_check": scenario_baseline_check,
    "long_path": scenario_long_path,
    "flood": scenario_flood,
    "fork_chain": scenario_fork_chain,
    "failed_ops": scenario_failed_ops,
    "network": scenario_network,
}


def main():
    parser = argparse.ArgumentParser(
        description="测试 Agent 生成器 — 产生真实 syscall 供 eBPF 探针捕获"
    )
    parser.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS.keys()),
        required=True,
        help="要执行的测试场景",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="列出所有可用场景",
    )

    args = parser.parse_args()

    if args.list:
        for name, func in SCENARIOS.items():
            print(f"  {name:20s} — {func.__doc__.strip().split(chr(10))[0]}")
        return 0

    func = SCENARIOS[args.scenario]
    result = func()

    # stdout 输出 JSON 摘要
    output = {
        "scenario": args.scenario,
        "agent": "test_agent",
        **result,
    }
    print(json.dumps(output, ensure_ascii=False))

    # 退出码: 0=全部成功, 1=部分跳过, 2=关键操作失败
    if result["skipped"] == 0 and result["success"] == result["operations"]:
        return 0
    elif result["success"] > 0:
        return 1
    else:
        return 2


if __name__ == "__main__":
    sys.exit(main())
