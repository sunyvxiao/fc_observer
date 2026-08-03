#!/usr/bin/env python3
"""
demo_workflow.py — 生产环境端到端演示工作流编排

设计理念: 用户操作指令与监控系统完全解耦。
  - 监控系统独立运行（deep_agent_monitor.py / test.py）
  - Agent 在独立环境（Docker/宿主机）中执行任务
  - 两者互不干扰，模拟真实生产环境中的旁路监控场景

六个阶段（每阶段由用户手动驱动）:
  Phase 1  准备     — 构建 Agent 运行环境
  Phase 2  启动监控 — 通过 deep_agent_monitor.py 开始监控+录制
  Phase 3  Agent    — 在另一个终端运行 Agent
  Phase 4  终止监控 — Ctrl+C 停止监控
  Phase 5  回放     — 通过 test.py [B] 回放录制
  Phase 6  查看产物 — 检查 Agent 输出

用法:
    python3 demo_workflow.py              # 交互式引导
    python3 demo_workflow.py --phase 1    # 执行指定阶段
    python3 demo_workflow.py --check      # 仅检测环境

零改动约束: 不修改 observer_core/ / models/ / rules/
"""

import os
import sys
import subprocess
import shutil
import argparse
from datetime import datetime

# ── 路径 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR = os.path.join(SCRIPT_DIR, "deep-agents-demo")
OBSERVER_DIR = os.path.join(SCRIPT_DIR, "observer_sim")
RECORDS_DIR = os.path.join(SCRIPT_DIR, "records")

# ── 终端颜色 ──────────────────────────────────────────────────────────────────
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"
BOLD = "\033[1m"


def banner(title: str):
    print(f"\n{BOLD}{CYAN}{'═' * 70}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 70}{RESET}\n")


def hint(text: str):
    print(f"  {DIM}💡 {text}{RESET}")


def cmd_box(title: str, commands: list, note: str = ""):
    """显示一个命令框"""
    print(f"\n  {BOLD}{title}{RESET}")
    if note:
        print(f"  {DIM}{note}{RESET}")
    print(f"  {CYAN}┌{'─' * 60}┐{RESET}")
    for c in commands:
        print(f"  {CYAN}│{RESET}  {GREEN}$ {c}{RESET}")
    print(f"  {CYAN}└{'─' * 60}┘{RESET}")


def pause(prompt: str = "按 Enter 继续..."):
    try:
        input(f"\n  {YELLOW}▶ {prompt}{RESET}")
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)


# ── 环境检测 ──────────────────────────────────────────────────────────────────

def check_env() -> dict:
    """检测环境能力"""
    env = {}

    # Docker
    docker_path = shutil.which("docker")
    env["docker"] = docker_path is not None
    if docker_path:
        try:
            result = subprocess.run(["docker", "--version"],
                                    capture_output=True, text=True, timeout=5)
            env["docker_version"] = result.stdout.strip().split(",")[0] if result.returncode == 0 else "?"
        except Exception:
            env["docker_version"] = "?"

    # pydantic-deep
    try:
        import pydantic_deep
        env["pydantic_deep"] = True
    except ImportError:
        env["pydantic_deep"] = False

    # API Key
    # 尝试加载 .env
    env_file = os.path.join(SCRIPT_DIR, ".env")
    if os.path.isfile(env_file):
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file, override=False)
        except ImportError:
            pass
    env["api_key"] = bool(os.environ.get("OPENAI_API_KEY", "").strip())
    env["env_file_exists"] = os.path.isfile(env_file)

    # 工作目录
    env["workspace_ready"] = os.path.isfile(
        os.path.join(DEMO_DIR, "workspace", "data", "sales_q3.csv"))

    # strace
    env["strace"] = shutil.which("strace") is not None

    return env


def print_env(env: dict):
    """显示环境检测结果"""
    banner("环境能力检测")

    items = [
        ("Docker", env["docker"],
         env.get("docker_version", "") if env["docker"] else "未安装"),
        ("pydantic-deep", env["pydantic_deep"],
         "已安装" if env["pydantic_deep"] else "未安装"),
        ("API Key", env["api_key"],
         "已配置" if env["api_key"] else "未配置 (OPENAI_API_KEY)"),
        (".env 文件", env["env_file_exists"],
         "存在" if env["env_file_exists"] else "不存在"),
        ("Agent 工作目录", env["workspace_ready"],
         "已初始化" if env["workspace_ready"] else "未初始化"),
        ("strace", env["strace"],
         "可用" if env["strace"] else "不可用"),
    ]

    for name, ok, detail in items:
        icon = f"{GREEN}✅{RESET}" if ok else f"{YELLOW}⚠️{RESET}"
        print(f"  {icon}  {name:20s}  {detail}")


# ── Phase 实现 ────────────────────────────────────────────────────────────────

def phase_1_prepare(env: dict):
    """Phase 1: 准备 Agent 运行环境"""
    banner("Phase 1: 准备 — 构建 Agent 运行环境")

    # 初始化工作目录
    setup_script = os.path.join(DEMO_DIR, "setup_workspace.sh")
    if not env["workspace_ready"]:
        print(f"  初始化 Agent 工作目录...")
        subprocess.run(["bash", setup_script], cwd=DEMO_DIR)
        print(f"  {GREEN}✓ 工作目录已初始化{RESET}")
    else:
        print(f"  {GREEN}✓ 工作目录已就绪（跳过初始化）{RESET}")

    if env["docker"]:
        print(f"\n  {BOLD}Docker 已安装，构建镜像:{RESET}")
        cmd_box("构建 Docker 镜像", [
            "cd ~/projects/observer_sim/deep-agents-demo",
            "docker build -t deep-agents-demo .",
        ])
        pause("构建完成后按 Enter 继续...")
    else:
        print(f"\n  {YELLOW}Docker 未安装，使用宿主机降级模式{RESET}")
        print(f"\n  {BOLD}安装 Docker（可选）:{RESET}")
        cmd_box("安装 Docker", [
            "sudo snap install docker",
            "# 或: sudo apt install docker.io",
        ], note="安装后需要重新登录")

        print(f"\n  {BOLD}降级方案（直接在宿主机运行 Agent）:{RESET}")
        if env["pydantic_deep"] and env["api_key"]:
            print(f"  {GREEN}✓ pydantic-deep 和 API Key 已就绪，可直接运行{RESET}")
        else:
            missing = []
            if not env["pydantic_deep"]:
                missing.append("pip install pydantic-deep")
            if not env["api_key"]:
                missing.append("在 .env 中配置 OPENAI_API_KEY")
            print(f"  {YELLOW}缺少: {', '.join(missing)}{RESET}")

    print(f"\n  {GREEN}Phase 1 完成{RESET}")


def phase_2_start_monitor(env: dict):
    """Phase 2: 启动监控"""
    banner("Phase 2: 启动监控")

    print(f"  监控系统将独立运行，实时捕获 Agent 产生的事件。")
    print(f"  监控系统与 Agent 完全解耦 — 旁路监控模式。\n")

    print(f"  {BOLD}方式 A: 使用 deep_agent_monitor.py (推荐){RESET}")
    print(f"  在终端 1 中执行:\n")
    cmd_box("终端 1 — 启动监控 (Simulation 模式)", [
        "cd ~/projects/observer_sim",
        "python3 deep_agent_monitor.py --scenario da04_production_demo --record",
    ], note="da04 是生产演示场景，--record 启用事件录制")

    print(f"\n  {BOLD}方式 B: 使用 test.py 菜单{RESET}")
    print(f"  在终端 1 中执行:\n")
    cmd_box("终端 1 — test.py 交互式", [
        "cd ~/projects/observer_sim",
        "python3 test.py",
        "# 选择 [9] 开始录制 → 输入 da04 → 输入 done 结束选择",
    ])

    if env["api_key"] and env["pydantic_deep"]:
        print(f"\n  {BOLD}方式 C: Live 模式 (真实 Agent){RESET}")
        cmd_box("终端 1 — Live 监控", [
            "cd ~/projects/observer_sim",
            "python3 deep_agent_monitor.py --live --record "
            "--task \"$(cat deep-agents-demo/task_instruction.txt)\"",
        ])

    pause("监控启动后，在另一个终端执行 Phase 3...")
    print(f"\n  {GREEN}Phase 2 完成 — 请确保监控在另一个终端运行{RESET}")


def phase_3_run_agent(env: dict):
    """Phase 3: Agent 执行任务"""
    banner("Phase 3: Agent 执行任务")

    print(f"  Agent 在独立环境中执行 Q3 市场分析任务。")
    print(f"  产生的工具调用被监控系统的 Hook 机制捕获。\n")

    if env["docker"]:
        print(f"  {BOLD}Docker 模式:{RESET}")
        cmd_box("终端 2 — Docker 容器内运行 Agent", [
            "cd ~/projects/observer_sim/deep-agents-demo",
            "docker run --rm -v $(pwd)/workspace:/workspace \\",
            "  --env-file ../.env deep-agents-demo",
        ])
    else:
        print(f"  {BOLD}宿主机降级模式:{RESET}")
        cmd_box("终端 2 — 宿主机直接运行 Agent", [
            "cd ~/projects/observer_sim/deep-agents-demo",
            "python3 run_agent.py --task-file task_instruction.txt",
        ])

    print(f"\n  {DIM}Agent 执行期间，终端 1 的监控窗口会实时显示事件和决策:{RESET}")
    print(f"  {GREEN}  [ALLOW]{RESET} 正常操作（pip install、读取数据、Python 分析）")
    print(f"  {YELLOW}  [ALERT]{RESET} 可疑行为（外部 API 调用、SMTP 连接）")
    print(f"  {RED}  [BLOCK]{RESET} 高风险（读取凭据、SSH 密钥、rm -rf）")

    pause("Agent 执行完成后按 Enter 继续...")
    print(f"\n  {GREEN}Phase 3 完成{RESET}")


def phase_4_stop_monitor():
    """Phase 4: 终止监控"""
    banner("Phase 4: 终止监控并保存录制")

    print(f"  Agent 已完成，现在停止监控并保存录制文件。\n")

    print(f"  {BOLD}方式 A: deep_agent_monitor.py{RESET}")
    print(f"  在终端 1 按 Ctrl+C 停止监控")
    print(f"  系统自动生成报告和录制文件\n")

    print(f"  {BOLD}方式 B: test.py 菜单{RESET}")
    cmd_box("test.py 菜单操作", [
        "# 选择 [A] 结束录制并保存",
    ])

    print(f"\n  录制文件保存在: {RECORDS_DIR}/<时间戳>/events.jsonl")

    pause("录制保存后按 Enter 继续...")
    print(f"\n  {GREEN}Phase 4 完成{RESET}")


def phase_5_replay():
    """Phase 5: 回放录制"""
    banner("Phase 5: 回放录制 — 展示风险报告")

    print(f"  通过 observer_core 全链路处理录制事件:\n")
    print(f"  归一化 → 规则匹配 → 风险评分 → 决策 → 阻断 → 审计 → 报告\n")

    print(f"  {BOLD}方式 A: test.py 菜单 (推荐){RESET}")
    cmd_box("test.py 回放", [
        "cd ~/projects/observer_sim",
        "python3 test.py",
        "# 选择 [B] 回放录制 → 选择最近的录制会话",
    ])

    print(f"\n  {BOLD}方式 B: deep_agent_monitor.py 录制输出{RESET}")
    print(f"  如果 Phase 2 使用了 --record，监控输出中会显示回放命令:")
    cmd_box("使用 record_and_replay.py", [
        "cd ~/projects/observer_sim/observer_sim",
        "python3 record_and_replay.py --replay-only "
        "output/deep_agent_monitor/recorded/<文件名>.jsonl",
    ])

    print(f"\n  回放将生成:")
    print(f"    • 风险报告 (Markdown)")
    print(f"    • 审计日志 (JSONL)")
    print(f"    • 行为图谱 (JSON)")

    pause("回放完成后按 Enter 继续...")
    print(f"\n  {GREEN}Phase 5 完成{RESET}")


def phase_6_view_output():
    """Phase 6: 查看 Agent 输出"""
    banner("Phase 6: 查看 Agent 输出结果")

    ws = os.path.join(DEMO_DIR, "workspace")

    print(f"  检查 Agent 在{'Docker 容器' if shutil.which('docker') else '宿主机'}中生成的分析产物:\n")

    cmd_box("查看 Agent 产物", [
        f"cat {ws}/data/market_report_q3.md",
        f"ls -la {ws}/data/charts/",
        f"cat {ws}/data/agent_output.txt",
    ])

    # 实际检查文件
    report = os.path.join(ws, "data", "market_report_q3.md")
    if os.path.isfile(report):
        print(f"\n  {GREEN}✓ 报告已生成: {report}{RESET}")
    else:
        print(f"\n  {YELLOW}⚠ 报告尚未生成（Agent 可能未完成）{RESET}")

    output = os.path.join(ws, "data", "agent_output.txt")
    if os.path.isfile(output):
        print(f"  {GREEN}✓ Agent 输出: {output}{RESET}")

    print(f"\n  {GREEN}Phase 6 完成{RESET}")


# ── 完整流程 ──────────────────────────────────────────────────────────────────

def run_full_demo(env: dict):
    """执行完整的 6 阶段演示"""
    banner("方寸观察者 — 生产环境端到端演示")
    print(f"  {BOLD}Q3 商业报表市场分析{RESET}")
    print(f"  金融科技公司 AI Agent 安全监控全流程\n")
    print(f"  设计理念: 监控与 Agent 完全解耦（旁路监控）")
    print(f"  事件覆盖: ALLOW / ALERT / BLOCK 三级风险决策\n")

    phases = [
        ("Phase 1: 准备", lambda: phase_1_prepare(env)),
        ("Phase 2: 启动监控", lambda: phase_2_start_monitor(env)),
        ("Phase 3: Agent 执行", lambda: phase_3_run_agent(env)),
        ("Phase 4: 终止监控", phase_4_stop_monitor),
        ("Phase 5: 回放录制", phase_5_replay),
        ("Phase 6: 查看产物", phase_6_view_output),
    ]

    for i, (name, func) in enumerate(phases, 1):
        print(f"\n{BOLD}{'─' * 70}{RESET}")
        print(f"  即将执行: {CYAN}{name}{RESET}")
        print(f"{BOLD}{'─' * 70}{RESET}")
        if i > 1:
            pause(f"准备执行 {name}，按 Enter 继续...")
        func()

    banner("演示完成！")
    print(f"  {GREEN}✓{RESET} 完整演示了从环境准备到风险分析的全流程")
    print(f"  {GREEN}✓{RESET} 监控系统与 Agent 完全解耦（旁路监控模式）")
    print(f"  {GREEN}✓{RESET} 录制-回放功能验证实通过")
    print(f"\n  提示: 可通过 test.py [B] 随时回放历史录制\n")


# ── 快速演示 (无需 Docker/API Key) ───────────────────────────────────────────

def run_quick_demo():
    """快速演示: 直接用 da04 场景 simulation + 录制 + 回放"""
    banner("快速演示 — 无需 Docker / API Key")
    print(f"  使用 da04 生产演示场景 (simulation 模式)")
    print(f"  自动完成: 录制 → 回放 → 报告生成\n")

    sys.path.insert(0, OBSERVER_DIR)
    from recorder.session_recorder import SessionRecorder

    # 录制
    print(f"  {CYAN}[1/3] 录制 da04 场景...{RESET}")
    recorder = SessionRecorder(
        records_dir=RECORDS_DIR,
        agent_id="quick-demo-agent",
        collect_mode="simulation",
    )
    recorder.start()

    # 加载 da04 事件
    sys.path.insert(0, SCRIPT_DIR)
    import importlib.util
    spec = importlib.util.spec_from_file_location("test_mod",
                                                   os.path.join(SCRIPT_DIR, "test.py"))
    mod = importlib.util.module_from_spec(spec)
    mod.__file__ = os.path.join(SCRIPT_DIR, "test.py")
    sys.argv = ["test.py", "--check"]
    spec.loader.exec_module(mod)

    events = mod._builtin_da04_events("quick-demo-agent")
    for evt in events:
        recorder.write_event(evt)

    summary = recorder.stop()
    session_id = summary["session_id"]
    print(f"  {GREEN}✓ 录制完成: {len(events)} events → {session_id}{RESET}")

    # 回放
    print(f"\n  {CYAN}[2/3] 回放录制...{RESET}")
    from recorder.replay_engine import ReplayEngine

    config_path = os.path.join(OBSERVER_DIR, "config.yaml")
    import yaml
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    engine = ReplayEngine(config)
    session_dir = os.path.join(RECORDS_DIR, session_id)
    engine.replay(session_dir)

    # 查看产物
    print(f"\n  {CYAN}[3/3] 输出摘要{RESET}")
    replay_output = os.path.join(session_dir, "replay_output")
    summary_file = os.path.join(replay_output, "replay_summary.json")
    if os.path.isfile(summary_file):
        import json
        with open(summary_file, "r") as f:
            stats = json.load(f)
        print(f"  Total:   {stats.get('total_events', '?')}")
        print(f"  {GREEN}Allow:   {stats.get('allow', '?')}{RESET}")
        print(f"  {YELLOW}Alert:   {stats.get('alert', '?')}{RESET}")
        print(f"  {RED}Block:   {stats.get('block', '?')}{RESET}")
    print(f"\n  报告目录: {replay_output}")
    print(f"\n  {GREEN}✓ 快速演示完成{RESET}")


# ── 主入口 ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="方寸观察者 — 生产环境端到端演示工作流",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 demo_workflow.py              # 交互式完整演示
  python3 demo_workflow.py --phase 1    # 仅执行 Phase 1
  python3 demo_workflow.py --check      # 环境检测
  python3 demo_workflow.py --quick      # 快速演示（无需 Docker）
        """)
    parser.add_argument("--phase", type=int, choices=[1, 2, 3, 4, 5, 6],
                        help="执行指定阶段")
    parser.add_argument("--check", action="store_true",
                        help="仅检测环境能力")
    parser.add_argument("--quick", action="store_true",
                        help="快速演示（simulation + 录制 + 回放，无需 Docker）")

    args = parser.parse_args()
    env = check_env()

    if args.check:
        print_env(env)
        return 0

    if args.quick:
        run_quick_demo()
        return 0

    if args.phase:
        phase_map = {
            1: lambda: phase_1_prepare(env),
            2: lambda: phase_2_start_monitor(env),
            3: lambda: phase_3_run_agent(env),
            4: phase_4_stop_monitor,
            5: phase_5_replay,
            6: phase_6_view_output,
        }
        phase_map[args.phase]()
        return 0

    # 交互式: 完整演示 or 快速演示
    print(f"\n{BOLD}方寸观察者 — 生产环境演示工作流{RESET}\n")
    print(f"  [1] 完整演示 (6 阶段，需两个终端)")
    print(f"  [2] 快速演示 (simulation 模式，单终端)")
    print(f"  [3] 环境检测")
    print(f"  [4] 单独执行某个阶段")
    print(f"  [0] 退出")

    choice = input(f"\n  请选择 [0-4]: ").strip()
    if choice == "1":
        run_full_demo(env)
    elif choice == "2":
        run_quick_demo()
    elif choice == "3":
        print_env(env)
    elif choice == "4":
        p = input("  阶段编号 [1-6]: ").strip()
        if p.isdigit() and 1 <= int(p) <= 6:
            phase_map = {
                1: lambda: phase_1_prepare(env),
                2: lambda: phase_2_start_monitor(env),
                3: lambda: phase_3_run_agent(env),
                4: phase_4_stop_monitor,
                5: phase_5_replay,
                6: phase_6_view_output,
            }
            phase_map[int(p)]()
    else:
        print("  退出")

    return 0


if __name__ == "__main__":
    sys.exit(main())
