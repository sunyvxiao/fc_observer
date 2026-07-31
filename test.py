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
    print("║  [0] 退出                                                  ║")
    print("║                                                          ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    choice = input("请选择 [0-8]: ").strip()
    all_names = ["unit", "collector", "integration", "scenario", "e2e", "web"]
    mapping = {
        "1": ["unit"], "2": ["collector"], "3": ["integration"],
        "4": ["scenario"], "5": ["e2e"], "6": ["web"],
        "7": all_names, "8": ["check"],
    }
    return mapping.get(choice, [])


# ── 主逻辑 ──────────────────────────────────────────────────────────────────
def run_selected(names: List[str], env: EnvCapabilities, categories: List[TestCategory]) -> bool:
    """运行选定的测试分类，返回是否全部通过"""
    results: List[TestResult] = []

    for name in names:
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

    if args.list:
        list_tests(env, categories)
        return 0

    # 确定要运行的分类
    selected = []
    has_flag = any([args.all, args.unit, args.collector, args.integration,
                    args.scenario, args.e2e, args.web])

    if not has_flag:
        # 交互式菜单
        selected = interactive_menu(env, categories)
        if not selected or selected == ["check"]:
            print("\n  环境能力:")
            for line in env.summary():
                print(f"  {line}")
            print()
            return 0
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
