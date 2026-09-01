#!/usr/bin/env python3
"""
observer.py — 方寸观察者模拟学习系统 统一入口（U4）

旧 6 入口（main.py / app.py / demo.py / monitor_daemon.py / test_api.py /
test_sse.py）收敛为 1 个统一入口，10 个顶层子命令（samples 内再挂载
check-env / gen-scenarios 两个工具动作，共 11 个可达命令入口）：

    python observer.py run      [--scenario S --category C --config F --output O --mode M]
                                # 运行场景流水线（CLI 模式，复用 main.run_cli）
    python observer.py serve    [--host H --port P --no-browser]   # Web 服务（转发 app.py）
    python observer.py daemon   [--fifo F --output O --mode M --ebpf --record
                                 --no-rollup --generate-report --pid-file F]
                                 # 监测守护进程（转发 monitor_daemon.py；
                                 #   --no-rollup = test_report 轻量测试报告模式）
    python observer.py demo     [--auto --scenario S --category C --mode M]
                                # 交互式演示（转发 demo.py）
    python observer.py files    tree|view <path>|delete <path>|delete-category <cat>
                                # 文件管理（OutputFileManager 的 CLI 视图，U7）
    python observer.py reports  list|view <path>|delete [--scope ...]
                                # 报告管理（OutputFileManager，U7）
    python observer.py samples  check-env|gen-scenarios            # 样例与工具（U9 挂载；
                                #   n01 基线快照已随 run 自动保存，无需独立命令，U9 收口）
    python observer.py env     [--light]    # 环境配置检测（独立前置检查，复用 check_env.py；
                                #   samples check-env 等价于 env 完整检测）
    python observer.py test     [unit|api|sse|all]                 # 统一测试入口
    python observer.py menu     # 命令行交互控制台（编号菜单 + 短命令，console.py 调度层）

降级说明（验收标准 4）：
  - main.py     → run/test 兼容壳（复用本入口同一实现 run_cli/cmd_test）
  - app.py      → observer serve 的实现模块（__main__ 仅打印一行提示）
  - monitor_daemon.py → observer daemon 的实现模块（__main__ 仅打印一行提示）
  - demo.py     → observer demo 的实现模块（不再自称独立入口）
  - test_api.py / test_sse.py → 冒烟脚本（经 observer test api/sse 调用）
"""

import argparse
import json
import os
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Windows 管道/重定向下强制 UTF-8 输出，避免 GBK 编码中文/emoji 崩溃
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

SERVE_MODES = ["auto", "simulation", "strace", "ebpf"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="observer",
        description="方寸观察者模拟学习系统 统一入口（10 子命令）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    # ── run ──────────────────────────────────────────────────
    p_run = sub.add_parser("run", help="运行场景流水线（CLI 模式，复用 main.run_cli）")
    p_run.add_argument("--scenario", type=str, default="all",
                       help="场景ID前缀 (如 n01, a01, all)")
    p_run.add_argument("--category", type=str, default=None,
                       help="按分类运行 (normal/anomalous/boundary/multi_agent/extreme)")
    p_run.add_argument("--config", type=str, default="config.yaml",
                       help="配置文件路径")
    p_run.add_argument("--output", type=str, default="output",
                       help="输出目录")
    p_run.add_argument("--mode", type=str, default=None, choices=SERVE_MODES,
                       help="采集模式 (默认从 config.yaml 读取)")

    # ── serve ────────────────────────────────────────────────
    p_serve = sub.add_parser("serve", help="启动 Web 服务（转发 app.py，与 SmokeServer 同法避免 import 副作用）")
    p_serve.add_argument("--host", type=str, default=None,
                         help="监听地址 (默认 localhost)")
    p_serve.add_argument("--port", type=int, default=None,
                         help="监听端口 (默认 8080)")
    p_serve.add_argument("--no-browser", action="store_true",
                         help="不自动打开浏览器")
    p_serve.add_argument("--mode", type=str, default=None, choices=SERVE_MODES,
                         help="采集模式 (默认从 config.yaml 读取)")

    # ── daemon ───────────────────────────────────────────────
    p_daemon = sub.add_parser("daemon", help="实时监测守护进程（转发 monitor_daemon.py）")
    p_daemon.add_argument("--fifo", type=str, default=None,
                          help="命名管道路径")
    p_daemon.add_argument("--output", type=str, default=None,
                          help="输出目录 (default: observer_sim/output/demo_monitoring)")
    p_daemon.add_argument("--mode", type=str, default=None,
                          choices=["oneshot", "daemon", "mcp_report"],
                          help="运行模式: oneshot | daemon | mcp_report "
                               "(MCP 申报监测，Windows WorkBuddy 降级监测)")
    p_daemon.add_argument("--config", type=str, default=None,
                          help="配置文件路径 (mcp_report 模式读取 mcp_report 配置段)")
    p_daemon.add_argument("--ebpf", action="store_true", default=False,
                          help="启用 eBPF 阻断（需要 root 权限 + libbpf）")
    p_daemon.add_argument("--record", action="store_true", default=False,
                          help="启用旁路录制：将 FIFO 原始事件保存为 .jsonl 录制文件")
    p_daemon.add_argument("--record-dir", type=str, default=None,
                          help="录制文件存放目录 (default: observer_sim/records)")
    p_daemon.add_argument("--generate-report", action="store_true", default=False,
                          help="向运行中的 daemon 发送 SIGUSR1 请求生成报告")
    p_daemon.add_argument("--no-rollup", action="store_true", default=False,
                          help="test_report 轻量测试报告模式：仅持续记录 L0 原始事件"
                               "与必要摘要，不触发 L1→L2→L3 分层聚合，监测结束后"
                               "一次性输出报告（默认关闭，走完整生产分层路径）")
    p_daemon.add_argument("--pid-file", type=str, default=None,
                          help="Monitor PID 文件路径")

    # ── demo ─────────────────────────────────────────────────
    p_demo = sub.add_parser("demo", help="交互式演示（转发 demo.py）")
    p_demo.add_argument("--auto", action="store_true", default=False,
                        help="自动播放模式（不暂停）")
    p_demo.add_argument("--scenario", type=str, default=None,
                        help="指定场景ID（如 n01, a01）或文件名")
    p_demo.add_argument("--category", type=str, default=None,
                        help="按分类运行 (normal/anomalous/boundary/multi_agent/extreme)")
    p_demo.add_argument("--mode", type=str, default=None, choices=SERVE_MODES,
                        help="采集模式 (默认从 config.yaml 读取)")

    # ── files ────────────────────────────────────────────────
    p_files = sub.add_parser("files", help="文件管理（OutputFileManager 的 CLI 视图，U7）")
    p_files.add_argument("action", choices=["tree", "view", "delete", "delete-category"],
                         help="tree: 四区文件树 / view: 查看文件 / delete: 删除路径 / "
                              "delete-category: 清空分类")
    p_files.add_argument("path", nargs="?", default=None,
                         help="文件路径（view/delete/delete-category 用，如 reports/normal/...）")

    # ── reports ──────────────────────────────────────────────
    p_reports = sub.add_parser("reports", help="报告管理（OutputFileManager，U7）")
    p_reports.add_argument("action", choices=["list", "view", "delete"],
                           help="list: 报告树 / view: 查看报告 / delete: 三级删除")
    p_reports.add_argument("path", nargs="?", default=None,
                           help="报告路径（view 用）")
    p_reports.add_argument("--scope", type=str, default="scenario",
                           choices=["all", "category", "scenario"],
                           help="删除范围（delete 用）")
    p_reports.add_argument("--category", type=str, default=None,
                           help="报告分类（delete category/scenario 用）")
    p_reports.add_argument("--scenario-id", type=str, default=None,
                           help="场景目录名（delete scenario 用）")

    # ── samples ──────────────────────────────────────────────
    p_samples = sub.add_parser("samples", help="样例与工具（U9 挂载：check-env / gen-scenarios）")
    p_samples.add_argument("action", choices=["check-env", "gen-scenarios"],
                           help="check-env: 环境预检 / gen-scenarios: 重新生成 37 个场景 YAML")

    # ── env ────────────────────────────────────────────────
    p_env = sub.add_parser("env", help="环境配置检测（独立前置检查，复用 check_env.py）")
    p_env.add_argument("--light", action="store_true", default=False,
                       help="轻量检测（平台/Python 版本/关键文件，<1 秒，无子进程）")

    # ── test ─────────────────────────────────────────────────
    p_test = sub.add_parser("test", help="统一测试入口 (unit|api|sse|all)")
    p_test.add_argument("target", nargs="?", default="all",
                        choices=["unit", "api", "sse", "all"],
                        help="测试目标: unit 单元测试 / api Web API 回归 / sse SSE 回归 / all 全部")

    # ── menu ─────────────────────────────────────────────────
    p_menu = sub.add_parser("menu", help="命令行交互控制台（编号菜单 + 短命令直达，console.py 调度层）")
    return parser


def _forward(script: str, argv: list, interruptable: bool = False) -> int:
    """subprocess 转发到实现模块（与 run_tests.SmokeServer 同法，避免 import 副作用）。

    interruptable=True（console 菜单内启动长驻进程时使用）：
    Popen + 0.2s 轮询代替 subprocess.call，使 Ctrl+C（KeyboardInterrupt）能及时
    打断等待——call 阻塞在 C 层 WaitForSingleObject，子进程若吞掉 SIGINT 则永远
    无法返回；轮询版收到 KeyboardInterrupt 后 terminate 子进程并重新抛出。
    """
    cmd = [sys.executable, os.path.join(BASE_DIR, script)] + argv
    if not interruptable:
        return subprocess.call(cmd)
    proc = subprocess.Popen(cmd)
    try:
        while True:
            try:
                return proc.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                continue
    except KeyboardInterrupt:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise


def _mcp_extra_roots():
    """推导 MCP 申报产物目录（output/mcp_monitoring）作为文件管理扩展安全根。

    只读 workbuddy_connect.yaml（observer.output_dir，相对 project_dir 拼接）；
    配置缺失/目录不存在时返回 None，不影响四区默认行为。
    """
    try:
        from connect_workbuddy import (DEFAULT_CONFIG, load_config, _out_paths)
        out_dir = _out_paths(load_config(DEFAULT_CONFIG))[0]
        if os.path.isdir(out_dir):
            return {"mcp_monitoring": os.path.realpath(out_dir)}
    except Exception:  # noqa: BLE001
        pass
    return None


def _monitoring_extra_roots():
    """合并全部扩展分区安全根（mcp_monitoring + qoder_monitoring）。

    与 app.py _monitoring_extra_roots 同构：qoder_monitoring 为
    output/qoder_monitoring（Qoder CN 监测产物），不存在时不注入。
    """
    roots = dict(_mcp_extra_roots() or {})
    try:
        qoder_dir = os.path.join(BASE_DIR, "output", "qoder_monitoring")
        if os.path.isdir(qoder_dir):
            roots["qoder_monitoring"] = os.path.realpath(qoder_dir)
    except OSError:
        pass
    return roots or None


def _manager():
    from observer_core.audit.file_manager import OutputFileManager
    return OutputFileManager(BASE_DIR, os.path.dirname(BASE_DIR),
                             extra_roots=_monitoring_extra_roots())


def _cmd_run(argv: list) -> int:
    from main import run_cli
    return run_cli(argv)


def _cmd_serve(argv: list, interruptable: bool = False) -> int:
    # 仅传显式指定的参数，其余交 app.py 默认值
    return _forward("app.py", argv, interruptable=interruptable)


def _cmd_daemon(argv: list, interruptable: bool = False) -> int:
    return _forward("monitor_daemon.py", argv, interruptable=interruptable)


def _cmd_demo(argv: list, interruptable: bool = False) -> int:
    return _forward("demo.py", argv, interruptable=interruptable)


def _cmd_test(argv: list) -> int:
    from main import cmd_test
    target = argv[0] if argv else "all"
    return cmd_test(target)


def _cmd_menu(argv: list) -> int:
    """命令行交互控制台（console.py 纯菜单调度层，复用本入口 _cmd_* 共享实现）。"""
    from console import run_console
    return run_console(argv)


def _cmd_env(argv: list) -> int:
    """环境配置检测（独立子命令，复用 check_env.py 结构化检测）。"""
    from check_env import main as check_env_main
    light = "--light" in argv
    return check_env_main(light=light)


def _read_text(path: str) -> int:
    """读取文本文件到 stdout；返回 0 成功 / 1 失败。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            sys.stdout.write(f.read())
        return 0
    except UnicodeDecodeError:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                sys.stdout.write(f.read())
            return 0
        except OSError as e:
            print(f"读取失败: {e}", file=sys.stderr)
            return 1
    except OSError as e:
        print(f"读取失败: {e}", file=sys.stderr)
        return 1


def _cmd_files(argv: list) -> int:
    manager = _manager()
    action = argv[0] if argv else ""
    path = argv[1] if len(argv) > 1 else None

    if action == "tree":
        print(json.dumps(manager.build_tree(), ensure_ascii=False, indent=2))
        return 0

    if action == "view":
        if not path:
            print("用法: observer files view <path>（如 records/xxx、reports/normal/...）",
                  file=sys.stderr)
            return 1
        resolved, err = manager.resolve_strict(path)
        if err == "traversal":
            print(f"拒绝访问: 路径遍历检测（{path}）", file=sys.stderr)
            return 1
        if err == "unknown_prefix":
            print(f"拒绝访问: 未知前缀（{path}）", file=sys.stderr)
            return 1
        return _read_text(resolved)

    if action == "delete":
        if not path:
            print("用法: observer files delete <path>", file=sys.stderr)
            return 1
        resolved, err = manager.resolve_strict(path)
        if err:
            print(f"拒绝访问: {err}（{path}）", file=sys.stderr)
            return 1
        deleted = manager.delete_resolved(resolved)
        print(json.dumps({"deleted": deleted}, ensure_ascii=False, indent=2))
        return 0

    if action == "delete-category":
        if not path:
            print("用法: observer files delete-category "
                  "<records|monitoring|mcp_monitoring|qoder_monitoring|reports|unit_test>",
                  file=sys.stderr)
            return 1
        if path not in manager.safe_roots:
            print(f"拒绝访问: 未知分类（{path}）", file=sys.stderr)
            return 1
        deleted = manager.delete_category(path)
        print(json.dumps({"deleted": deleted}, ensure_ascii=False, indent=2))
        return 0

    print(f"未知 files 动作: {action}", file=sys.stderr)
    return 1


def _cmd_reports(argv: list) -> int:
    manager = _manager()
    action = argv[0] if argv else ""
    path = argv[1] if len(argv) > 1 else None

    if action == "list":
        tree = manager.build_tree()
        print(json.dumps(tree.get("tree", {}).get("reports", {}),
                         ensure_ascii=False, indent=2))
        return 0

    if action == "view":
        if not path:
            print("用法: observer reports view <path>（如 reports/normal/...）", file=sys.stderr)
            return 1
        resolved, err = manager.resolve_strict(path)
        if err:
            print(f"拒绝访问: {err}（{path}）", file=sys.stderr)
            return 1
        return _read_text(resolved)

    if action == "delete":
        # 从 observer 层 argparse 透传的剩余参数（scope/category/scenario-id 由 main 处理）
        scope = "scenario"
        category = ""
        scenario_id = ""
        rest = argv[1:]
        i = 0
        while i < len(rest):
            arg = rest[i]
            if arg == "--scope" and i + 1 < len(rest):
                scope = rest[i + 1]
                i += 2
                continue
            if arg == "--category" and i + 1 < len(rest):
                category = rest[i + 1]
                i += 2
                continue
            if arg == "--scenario-id" and i + 1 < len(rest):
                scenario_id = rest[i + 1]
                i += 2
                continue
            i += 1
        deleted = manager.delete_reports(scope, category, scenario_id)
        print(json.dumps({"success": True, "deleted": deleted},
                         ensure_ascii=False, indent=2))
        return 0

    print(f"未知 reports 动作: {action}", file=sys.stderr)
    return 1


def _cmd_samples(argv: list) -> int:
    action = argv[0] if argv else ""
    if action == "check-env":
        from check_env import main as check_env_main
        return check_env_main()
    if action == "gen-scenarios":
        return _forward("generate_scenarios.py", argv[1:])
    print(f"未知 samples 动作: {action}", file=sys.stderr)
    return 1


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # 所有子命令均在 observer_sim 目录下执行（run_cli 内部也会 chdir）
    os.chdir(BASE_DIR)

    command = args.command

    if command == "run":
        run_argv = ["--scenario", args.scenario]
        if args.category:
            run_argv += ["--category", args.category]
        if args.config != "config.yaml":
            run_argv += ["--config", args.config]
        run_argv += ["--output", args.output]
        if args.mode:
            run_argv += ["--mode", args.mode]
        return _cmd_run(run_argv)

    if command == "serve":
        serve_argv = []
        if args.host is not None:
            serve_argv += ["--host", args.host]
        if args.port is not None:
            serve_argv += ["--port", str(args.port)]
        if args.no_browser:
            serve_argv.append("--no-browser")
        if args.mode:
            serve_argv += ["--mode", args.mode]
        return _cmd_serve(serve_argv)

    if command == "daemon":
        daemon_argv = []
        if args.fifo is not None:
            daemon_argv += ["--fifo", args.fifo]
        if args.output is not None:
            daemon_argv += ["--output", args.output]
        if args.mode is not None:
            daemon_argv += ["--mode", args.mode]
        if args.config is not None:
            daemon_argv += ["--config", args.config]
        if args.ebpf:
            daemon_argv.append("--ebpf")
        if args.record:
            daemon_argv.append("--record")
        if args.record_dir is not None:
            daemon_argv += ["--record-dir", args.record_dir]
        if args.generate_report:
            daemon_argv.append("--generate-report")
        if args.no_rollup:
            daemon_argv.append("--no-rollup")
        if args.pid_file is not None:
            daemon_argv += ["--pid-file", args.pid_file]
        return _cmd_daemon(daemon_argv)

    if command == "demo":
        demo_argv = []
        if args.auto:
            demo_argv.append("--auto")
        if args.scenario:
            demo_argv += ["--scenario", args.scenario]
        if args.category:
            demo_argv += ["--category", args.category]
        if args.mode:
            demo_argv += ["--mode", args.mode]
        return _cmd_demo(demo_argv)

    if command == "files":
        files_argv = [args.action]
        if args.path:
            files_argv.append(args.path)
        return _cmd_files(files_argv)

    if command == "reports":
        reports_argv = [args.action]
        if args.path:
            reports_argv.append(args.path)
        reports_argv += ["--scope", args.scope]
        if args.category:
            reports_argv += ["--category", args.category]
        if args.scenario_id:
            reports_argv += ["--scenario-id", args.scenario_id]
        return _cmd_reports(reports_argv)

    if command == "samples":
        return _cmd_samples([args.action])

    if command == "env":
        return _cmd_env(["--light"] if args.light else [])

    if command == "test":
        return _cmd_test([args.target])

    if command == "menu":
        return _cmd_menu([])

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
