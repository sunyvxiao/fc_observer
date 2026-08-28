#!/usr/bin/env python3
"""
record_and_replay.py — 录制-回放工作流 CLI 便捷入口

通过调用 Monitor daemon + agent_sim FIFO 架构完成录制/回放。
与 Web 端（app.py）使用完全相同的底层架构。

用法:
    # 录制：Monitor 旁路录制 + agent_sim 写 FIFO
    python record_and_replay.py

    # 仅回放：指定已有的 JSONL 录制文件
    python record_and_replay.py --replay-only records/20250601_120000/events.jsonl

    # 指定自定义场景
    python record_and_replay.py --scenario scenarios/deep_agent/da04_production_demo.yaml

    # test_report 轻量测试报告模式（录制/回放均支持）：
    # 仅记录 L0 原始事件，不触发 L1→L2→L3 分层聚合，结束后一次性输出报告
    python record_and_replay.py --no-rollup
    python record_and_replay.py --replay-only <file.jsonl> --no-rollup
"""

import sys
import os
import argparse
import subprocess
import time
import json
import signal
from datetime import datetime

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from monitor_lifecycle import MonitorLifecycleManager


def _project_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _monitoring_dir():
    return os.path.join(os.path.dirname(_project_dir()), ".monitoring")


def _monitoring_fifo():
    return os.path.join(_monitoring_dir(), "pipe")


def _monitoring_pid_file():
    return os.path.join(_monitoring_dir(), "monitor.pid")


def _monitoring_output_dir():
    return os.path.join(_project_dir(), "output", "demo_monitoring")


def _records_dir():
    return os.path.join(os.path.dirname(_project_dir()), "records")


def _scenario_path(scenario_arg=None):
    if scenario_arg:
        return scenario_arg
    return os.path.join(_project_dir(), "scenarios", "deep_agent",
                        "da04_production_demo.yaml")


def _summary_path():
    return os.path.join(_monitoring_output_dir(), "monitoring_summary.json")


def _is_monitor_running():
    """检测 Monitor 是否在运行 (委托给生命周期管理器)"""
    return MonitorLifecycleManager.instance().status()["monitor_running"]


def _start_monitor(record=False, no_rollup=False):
    """启动 Monitor 守护进程 (委托给生命周期管理器)

    no_rollup: test_report 轻量测试报告模式——仅记录 L0 原始事件，
        不触发 L1→L2→L3 分层聚合，结束后一次性输出报告（默认关闭）。
    """
    mgr = MonitorLifecycleManager.instance()
    # 先清理残留
    mgr.startup_cleanup()
    status = mgr.start_monitor(record=record, no_rollup=no_rollup)
    return status is not None and status.get("monitor_running", False)


def _stop_monitor():
    """停止 Monitor 守护进程 (委托给生命周期管理器)"""
    MonitorLifecycleManager.instance().stop_monitor_forced()


def _run_agent_sim(scenario=None, replay_file=None, speed=3.0):
    """运行 agent_sim 将事件写入 FIFO"""
    agent_sim_path = os.path.join(_project_dir(), "agent_sim.py")
    fifo = _monitoring_fifo()

    cmd = [
        sys.executable, agent_sim_path,
        "--fifo", fifo,
        "--speed", str(speed),
    ]
    if replay_file:
        cmd.extend(["--replay-file", replay_file])
    elif scenario:
        cmd.extend(["--scenario", scenario])

    print(f"[CLI] 运行 agent_sim: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=120, cwd=_project_dir())
    if result.stdout:
        print(result.stdout)
    return result


def _wait_for_report(max_wait=30):
    """等待 Monitor 生成 monitoring_summary.json"""
    sp = _summary_path()
    mtime_before = os.path.getmtime(sp) if os.path.isfile(sp) else 0
    for _ in range(max_wait * 2):
        time.sleep(0.5)
        if os.path.isfile(sp) and os.path.getmtime(sp) > mtime_before:
            return True
    return False


def _print_report():
    """打印监测报告摘要"""
    sp = _summary_path()
    if not os.path.isfile(sp):
        print("  (无报告)")
        return
    with open(sp, "r", encoding="utf-8") as f:
        summary = json.load(f)
    print(f"\n{'='*60}")
    print(f"  监测摘要:")
    print(f"    总事件:    {summary.get('total_events', 0)}")
    print(f"    🟢 放行:    {summary.get('allow', 0)}")
    print(f"    🟡 告警:    {summary.get('alert', 0)}")
    print(f"    🔴 阻断:    {summary.get('block', 0)}")
    print(f"    最高风险:   {summary.get('max_risk_score', 0):.2f}")
    print(f"    📄 报告:    {summary.get('report_path', '-')}")
    print(f"    📋 审计:    {summary.get('audit_file', '-')}")


def _find_latest_recording():
    """查找最新的录制会话"""
    rd = _records_dir()
    if not os.path.isdir(rd):
        return None
    dirs = sorted(
        [d for d in os.listdir(rd) if os.path.isdir(os.path.join(rd, d))],
        reverse=True
    )
    for d in dirs:
        ep = os.path.join(rd, d, "events.jsonl")
        if os.path.isfile(ep):
            return ep
    return None


def main():
    parser = argparse.ArgumentParser(
        description="录制-回放工作流 CLI (Monitor + agent_sim FIFO 架构)")
    parser.add_argument("--replay-only", type=str, default=None,
                        help="仅回放模式：指定已有的 JSONL 录制文件路径")
    parser.add_argument("--scenario", type=str, default=None,
                        help="场景 YAML 文件路径 (默认: da04_production_demo.yaml)")
    parser.add_argument("--speed", type=float, default=3.0,
                        help="回放速度倍率 (默认: 3.0)")
    parser.add_argument("--no-rollup", action="store_true", default=False,
                        help="test_report 轻量测试报告模式：仅记录 L0 原始事件，"
                             "不触发 L1→L2→L3 分层聚合，结束后一次性输出报告"
                             "（默认关闭，走完整生产分层路径）")
    args = parser.parse_args()

    os.chdir(_project_dir())

    print(f"\n{'#'*60}")
    print(f"#  Record-and-Replay Workflow (Monitor + FIFO)")
    print(f"#  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'#'*60}")

    try:
        if args.replay_only:
            # ── 仅回放模式 ──
            replay_path = args.replay_only
            if not os.path.isfile(replay_path):
                print(f"\n  ERROR: 回放文件不存在: {replay_path}")
                sys.exit(1)

            print(f"\n  回放文件: {replay_path}")
            if args.no_rollup:
                print("  模式: test_report 轻量测试报告（仅 L0 记录，结束后一次性出报告）")

            # 启动 Monitor（非录制模式）
            if not _start_monitor(record=False, no_rollup=args.no_rollup):
                print("ERROR: Monitor 启动失败", file=sys.stderr)
                sys.exit(1)
            time.sleep(0.5)

            # 运行 agent_sim --replay-file
            result = _run_agent_sim(replay_file=replay_path, speed=args.speed)

            # 等待 Monitor 处理完成
            _wait_for_report()

            # 打印报告
            _print_report()

            # 停止 Monitor
            _stop_monitor()

        else:
            # ── 录制模式 ──
            scenario = _scenario_path(args.scenario)
            if not os.path.isfile(scenario):
                print(f"\n  ERROR: 场景文件不存在: {scenario}")
                sys.exit(1)

            print(f"\n  场景文件: {scenario}")
            if args.no_rollup:
                print("  模式: test_report 轻量测试报告（仅 L0 记录，结束后一次性出报告）")

            # 启动 Monitor（录制模式）
            if not _start_monitor(record=True, no_rollup=args.no_rollup):
                print("ERROR: Monitor 启动失败", file=sys.stderr)
                sys.exit(1)
            time.sleep(0.5)

            # 运行 agent_sim --scenario
            result = _run_agent_sim(scenario=scenario, speed=args.speed)

            # 等待 Monitor 处理完成
            _wait_for_report()

            # 查找录制文件
            recording = _find_latest_recording()
            if recording:
                print(f"\n  📼 录制文件: {recording}")
                try:
                    count = sum(1 for _ in open(recording))
                    print(f"     事件数: {count}")
                except Exception:
                    pass

            # 打印报告
            _print_report()

            # 停止 Monitor
            _stop_monitor()

        print(f"\n{'#'*60}")
        print(f"#  Complete!")
        print(f"{'#'*60}\n")

    except KeyboardInterrupt:
        print("\n中断")
        _stop_monitor()
    except subprocess.TimeoutExpired:
        print("ERROR: 超时 (120s)", file=sys.stderr)
        _stop_monitor()
        sys.exit(1)


if __name__ == "__main__":
    main()
