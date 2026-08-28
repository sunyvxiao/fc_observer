#!/usr/bin/env python3
"""
console.py — 方寸观察者 命令行控制台（PowerShell 终端内的编号菜单交互界面）

observer.py 统一入口第 10 个子命令 menu 的实现模块（纯菜单调度层）：
  - 主菜单按功能域分组展示系统全部能力，数字选菜单项（新手看菜单）
  - 任意菜单下支持短命令直达，如 run n01 / files tree / test unit（熟手敲命令）
  - h / help / ? 即时展示命令速查表，无需查手册（遇疑查 help）
  - serve / daemon / demo / 录制-回放 等长驻进程在菜单内启动，
    按 Ctrl+C 中断后回到菜单，而非退出整个控制台
  - 主菜单第 10 项 "环境检测"（短命令 env / env light）：启动时自动执行
    轻量检测（平台/Python/关键文件，<1 秒）驱动状态行与跨平台前置提醒，
    完整检测复用 check_env.py 结构化 API（不重复实现检测逻辑）
  - 平台受限功能（daemon / 录制-回放 依赖 Linux FIFO）在入口处按
    分级策略前置提醒：必然失败 → 阻止返回；软受限 → 提示后确认；
    提醒依据来自缓存的平台检测结果（adapter.platform_detect.PlatformInfo）
  - 底层逻辑全部复用 observer.py 统一入口（_cmd_* 共享实现），
    不重复实现流水线、文件管理、报告管理等业务逻辑

用法:
    python observer.py menu        # 推荐（统一入口）
    python console.py              # 直接运行等价
"""

import glob
import os
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Windows 管道/重定向下强制 UTF-8 输出（幂等；经 observer 进入时已执行过一次）
for _s in (sys.stdout, sys.stderr):
    if hasattr(_s, "reconfigure"):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


# ── ANSI 颜色（样式常量，与 demo.py 同风格）──────────────────
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


def C(text, color):
    """给文本添加颜色。"""
    return f"{color}{text}{Colors.RESET}"


# ── 常量与状态 ───────────────────────────────────────────────
CATEGORIES = ["normal", "anomalous", "boundary", "multi_agent", "extreme"]
CAT_LABELS = {
    "normal": "Normal 正常行为 (N01-N08)",
    "anomalous": "Anomalous 异常行为 (A01-A12)",
    "boundary": "Boundary 边界场景 (B01-B08)",
    "multi_agent": "Multi-Agent 多Agent协作 (M01-M05)",
    "extreme": "Extreme 极端场景 (E01-E04)",
}
CAT_IDS = {
    "normal": "n01-n08", "anomalous": "a01-a12", "boundary": "b01-b08",
    "multi_agent": "m01-m05", "extreme": "e01-e04",
}
SAFE_ROOTS = ["records", "monitoring", "mcp_monitoring", "reports", "unit_test"]

SEP = "─" * 64
SEP_D = "═" * 64


def _count_scenarios():
    """扫描 scenarios/ 下 5 分类的 YAML 场景数（仅统计，与 demo 发现逻辑等价）。"""
    n = 0
    for cat in CATEGORIES:
        n += len(glob.glob(os.path.join(BASE_DIR, "scenarios", cat, "*.yaml")))
    return n


def _find_scenario(prefix):
    """按 ID 前缀匹配场景文件（小写不敏感），返回文件 basename 或 None。"""
    prefix = prefix.lower()
    for cat in CATEGORIES:
        for f in sorted(glob.glob(os.path.join(BASE_DIR, "scenarios", cat, "*.yaml"))):
            if prefix in os.path.basename(f).lower():
                return os.path.basename(f)
    return None


def _confirm(prompt="确认操作？此操作不可恢复 [y/N]: "):
    """删除类操作的 y/N 二次确认（样式与 demo.py 一致）。"""
    while True:
        try:
            ans = input(C(prompt, Colors.YELLOW)).strip().lower()
        except (KeyboardInterrupt, EOFError):
            return False
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no", ""):
            return False
        print(C("  请输入 y 或 n", Colors.DIM))


def _read_input(prompt="> "):
    """读取一行输入；EOF（管道结束）等价于退出指令。"""
    try:
        return input(C(prompt, Colors.GREEN)).strip()
    except EOFError:
        return "q"
    except KeyboardInterrupt:
        raise


# ── 环境检测状态（会话级内存缓存）──────────────────────────────
_ENV_CACHE = {"light": None, "full": None}
_PLATFORM = None


def _get_platform():
    """复用 adapter.platform_detect.PlatformInfo.detect()（无副作用，微秒级）。

    缓存于会话；跨平台前置提醒的依据（平台 / eBPF / strace 能力）。
    """
    global _PLATFORM
    if _PLATFORM is None:
        from adapter.platform_detect import PlatformInfo
        _PLATFORM = PlatformInfo.detect()
    return _PLATFORM


def _env_light(refresh=False):
    """轻量环境检测（平台/Python 版本/关键文件，<1 秒，无子进程）。

    首次调用自动执行并缓存；refresh=True 强制重新检测。
    检测逻辑复用 check_env.run_checks(light=True)，不重复实现。
    """
    if _ENV_CACHE["light"] is None or refresh:
        from check_env import run_checks as _run_checks
        _ENV_CACHE["light"] = _run_checks(light=True)
    return _ENV_CACHE["light"]


def _env_full(refresh=False):
    """完整环境检测（轻量 + 依赖包 + 模块导入 + 平台工具链）。

    首次调用自动执行并缓存；refresh=True 强制重新检测。
    检测逻辑复用 check_env.run_checks(light=False)，不重复实现。
    """
    if _ENV_CACHE["full"] is None or refresh:
        from check_env import run_checks as _run_checks
        _ENV_CACHE["full"] = _run_checks(light=False)
    return _ENV_CACHE["full"]


def _env_status_str():
    """主菜单 [状态] 行环境片段（启动时自动轻量检测，<1 秒）。"""
    items = _env_light()
    failed = sum(1 for i in items if not i.passed)
    if failed:
        return C(f"环境 ✗ {failed} 项未过（输入 env 查看详情）", Colors.RED)
    return C("环境 ✓", Colors.GREEN)


def _mode_hint():
    """当前生效采集模式提示（复用 PlatformInfo 能力，auto 降级链）。"""
    plat = _get_platform()
    if plat.is_windows:
        return "采集 simulation (auto)"
    if plat.has_ebpf:
        return "采集 ebpf (auto)"
    if plat.has_strace:
        return "采集 strace (auto，eBPF 不可用)"
    return "采集 simulation (auto 降级)"


def _env_gate(feature):
    """平台能力前置判断（依据缓存的平台检测结果，即环境配置检测结果）。

    分级策略:
      - 必然失败级（Windows 下 daemon / 录制-回放，FIFO 硬依赖）
        → 红色提醒后阻止返回菜单；
      - 软受限级（Linux 无 eBPF 能力时 daemon 阻断能力降级）
        → 黄色提醒后 y/N 确认，确认后继续。

    返回 True=放行；False=已打印提醒并阻止。
    """
    plat = _get_platform()
    if feature in ("daemon", "record-replay") and plat.is_windows:
        print()
        print(C("[环境提醒] 当前为 Windows 环境，该功能依赖 Linux FIFO 命名管道"
                "（os.mkfifo），不支持。", Colors.RED))
        print(C("          该功能仅限 Linux 环境使用 · 依据: 环境检测 #平台=windows"
                " · 重新检测请输入 env", Colors.DIM))
        print(C("[已阻止] 返回菜单", Colors.YELLOW))
        print(C(SEP, Colors.CYAN))
        return False
    if feature == "daemon" and plat.is_linux and not plat.has_ebpf:
        print()
        print(C("[环境提醒] 当前 Linux 环境未检测到 eBPF 能力"
                "（BTF/libbpf/CAP_BPF 不完整），阻断能力不可用。", Colors.YELLOW))
        print(C("          监测守护进程仍可运行（FIFO 链路），eBPF 阻断将降级跳过"
                " · 依据: 环境检测 #eBPF 能力=不可用", Colors.DIM))
        if not _confirm("是否继续启动？[y/N]: "):
            print(C("[已取消] 返回菜单", Colors.YELLOW))
            print(C(SEP, Colors.CYAN))
            return False
    return True


# ── 底层转发（复用 observer.py 统一入口的 _cmd_* 共享实现）────
def _call(which, argv, interruptable=False):
    """调用 observer.py 统一入口的 _cmd_* 函数（延迟 import，无副作用）。

    interruptable=True 时 serve/daemon/demo 走 observer 的可中断转发
    （Popen + 0.2s 轮询），使 Ctrl+C 能及时打断并终止子进程后返回菜单。
    """
    from observer import (_cmd_run, _cmd_serve, _cmd_daemon, _cmd_demo,
                          _cmd_files, _cmd_reports, _cmd_samples, _cmd_test)
    funcs = {
        "run": _cmd_run, "serve": _cmd_serve, "daemon": _cmd_daemon,
        "demo": _cmd_demo, "files": _cmd_files, "reports": _cmd_reports,
        "samples": _cmd_samples, "test": _cmd_test,
    }
    fn = funcs[which]
    if which in ("serve", "daemon", "demo"):
        return fn(argv, interruptable=interruptable)
    return fn(argv)


def _run_action(which, argv, note=None, interruptable=False):
    """执行一个动作；长驻动作 Ctrl+C 中断后回到菜单（不退出控制台）。"""
    print()
    if note:
        print(C(note, Colors.YELLOW))
    print(C(SEP, Colors.CYAN))
    try:
        code = _call(which, argv, interruptable=interruptable)
    except KeyboardInterrupt:
        print(C("\n[已中断] 返回菜单", Colors.YELLOW))
        print(C(SEP, Colors.CYAN))
        return
    if code != 0:
        print(C(f"[完成] 退出码 {code}（非零），输入 h 查看用法", Colors.YELLOW))
    else:
        print(C("[完成] 返回菜单", Colors.DIM))
    print(C(SEP, Colors.CYAN))


def _exec_env(light=False):
    """环境检测动作：env（完整）/ env light（轻量）。刷新会话缓存并打印报告。

    检测逻辑复用 check_env.run_checks / print_report（单一事实来源）。
    """
    print()
    print(C(">>> 环境配置检测（" + ("轻量" if light else "完整") + "）", Colors.YELLOW))
    print(C(SEP, Colors.CYAN))
    from check_env import print_report as _print_report
    _print_report(_env_full(refresh=True) if not light else _env_light(refresh=True),
                  light=light)
    print(C("[完成] 返回菜单", Colors.DIM))
    print(C(SEP, Colors.CYAN))


def _run_record_replay():
    """转发 record_and_replay.py（录制-回放工作流，长驻，Ctrl+C 返回菜单）。

    Popen + 0.2s 轮询（与 observer._forward interruptable 同法），
    确保 Ctrl+C 能及时终止子进程返回菜单。
    前置判断: 录制-回放依赖 Linux FIFO 架构，Windows 下阻止（_env_gate）。
    """
    if not _env_gate("record-replay"):
        return
    print()
    print(C(">>> 启动录制-回放工作流（Ctrl+C 中断返回菜单）", Colors.YELLOW))
    print(C(SEP, Colors.CYAN))
    proc = subprocess.Popen(
        [sys.executable, os.path.join(BASE_DIR, "record_and_replay.py")])
    try:
        while True:
            try:
                code = proc.wait(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                continue
    except KeyboardInterrupt:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print(C("\n[已中断] 返回菜单", Colors.YELLOW))
        print(C(SEP, Colors.CYAN))
        return
    if code != 0:
        print(C(f"[完成] 退出码 {code}（非零）", Colors.YELLOW))
    else:
        print(C("[完成] 返回菜单", Colors.DIM))
    print(C(SEP, Colors.CYAN))


# ── 菜单渲染 ─────────────────────────────────────────────────
DOMAINS = [
    ("run", "场景运行", "运行全部/按分类/指定场景的流水线"),
    ("demo", "交互式演示", "进入演示编号菜单 或 指定场景自动播放"),
    ("daemon", "实时监测", "FIFO 监测守护进程（Ctrl+C 返回菜单）"),
    ("mcp", "MCP 申报监测", "WorkBuddy 降级监测通道（启动/停止/状态/烟测/报告）"),
    ("serve", "Web 服务", "启动 localhost:8080 Web 界面（Ctrl+C 返回菜单）"),
    ("files", "文件管理", "五区文件树 / 查看 / 删除 / 清空分类"),
    ("reports", "报告管理", "报告列表 / 查看 / 三级删除"),
    ("samples", "样例与工具", "环境预检 / 场景生成 / 录制-回放"),
    ("test", "测试运行", "单元测试 / API 冒烟 / SSE 冒烟 / 全部"),
]


def _render_main():
    plat = _get_platform()
    status = _env_status_str()
    print()
    print(C(SEP_D, Colors.CYAN))
    print(C("  方寸观察者 命令行控制台", Colors.CYAN + Colors.BOLD))
    print(C("  编号菜单 · 短命令直达 · h 命令速查 · 0 退出", Colors.DIM))
    print(C(SEP_D, Colors.CYAN))
    print(C(f"  [状态] 内置场景 {_count_scenarios()} 个 · 输出目录 observer_sim/output"
            f" · 平台 {plat.platform} · {_mode_hint()} · ", Colors.DIM) + status)
    print(C(SEP, Colors.CYAN))
    for i, (key, title, desc) in enumerate(DOMAINS, 1):
        print(f"  {C(str(i) + '.', Colors.CYAN)} {C(title, Colors.WHITE + Colors.BOLD)}"
              f" {C('[' + key + ']', Colors.DIM)}  {C(desc, Colors.DIM)}")
    print(f"  {C(str(len(DOMAINS) + 1) + '.', Colors.CYAN)} {C('环境检测', Colors.WHITE + Colors.BOLD)}"
          f" {C('[env]', Colors.DIM)}  {C('系统前置检查（env light 轻量 / env 完整检测）', Colors.DIM)}")
    print(C(SEP, Colors.CYAN))
    print(f"  {C('0.', Colors.DIM)} {C('退出', Colors.DIM)}"
          f"    {C('h.', Colors.DIM)} {C('命令速查（全部短命令）', Colors.DIM)}")
    print()


def _render_domain(key):
    """渲染域子菜单（编号规则与主菜单一致：数字选择 / 0 返回 / h 帮助）。"""
    print()
    print(C(SEP_D, Colors.CYAN))
    print(C(f"  主菜单 > {key} 域", Colors.CYAN + Colors.BOLD))
    print(C(SEP_D, Colors.CYAN))

    if key == "run":
        print(C(f"  运行场景流水线（产出报告/行为图谱/审计日志，n01 自动保存基线快照）", Colors.DIM))
        print(C(SEP, Colors.CYAN))
        print(f"  {C('1.', Colors.CYAN)} {C('运行全部场景', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: all)', Colors.DIM)}")
        print(f"  {C('2.', Colors.CYAN)} {C('按分类运行', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: normal/anomalous/boundary/multi_agent/extreme)', Colors.DIM)}")
        print(f"  {C('3.', Colors.CYAN)} {C('指定场景 ID', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: n01/a01/b01/m01/e01 …)', Colors.DIM)}")
    elif key == "demo":
        print(C("  交互式演示（彩色逐事件流水线，Ctrl+C 返回菜单）", Colors.DIM))
        print(C(SEP, Colors.CYAN))
        print(f"  {C('1.', Colors.CYAN)} {C('进入演示编号菜单', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: menu，即 demo.py 原有菜单)', Colors.DIM)}")
        print(f"  {C('2.', Colors.CYAN)} {C('指定场景自动播放', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: <场景ID>，如 n01)', Colors.DIM)}")
        print(f"  {C('3.', Colors.CYAN)} {C('按分类自动播放', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: <分类>，如 anomalous)', Colors.DIM)}")
    elif key == "daemon":
        desc = "实时监测守护进程（FIFO 命名管道，Linux 环境使用，Ctrl+C 返回菜单）"
        if _get_platform().is_windows:
            desc += " " + C("[当前环境不支持]", Colors.RED)
        print(C(desc, Colors.DIM))
        print(C(SEP, Colors.CYAN))
        print(f"  {C('1.', Colors.CYAN)} {C('启动监测守护进程', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: start)', Colors.DIM)}")
        print(f"  {C('2.', Colors.CYAN)} {C('启动并旁路录制', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: record，--record)', Colors.DIM)}")
        print(f"  {C('3.', Colors.CYAN)} {C('轻量测试报告模式（test_report）', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: testreport，--no-rollup)', Colors.DIM)}")
        print(f"  {C('4.', Colors.CYAN)} {C('请求运行中的守护进程生成报告', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: report)', Colors.DIM)}")
        print(f"  {C('5.', Colors.CYAN)} {C('录制 + 轻量测试报告（test_report）', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: record-testreport，--record --no-rollup)', Colors.DIM)}")
    elif key == "mcp":
        try:
            from connect_workbuddy import (DEFAULT_CONFIG as _cw_cfg_path,
                                           load_config as _cw_load)
            _cw_cfg = _cw_load(_cw_cfg_path)
            _cw_url = (f"http://{_cw_cfg['server']['host']}:"
                       f"{int(_cw_cfg['server']['port'])}"
                       f"{_cw_cfg['server']['sse_path']}")
            _cw_agent = _cw_cfg['workbuddy']['agent_id']
        except Exception:  # noqa: BLE001
            _cw_url, _cw_agent = "(读取 workbuddy_connect.yaml 失败)", "-"
        print(C("  MCP 申报监测（WorkBuddy 降级监测通道，跨平台可用）", Colors.DIM))
        print(C(f"  申报 Server: {_cw_url} · agent_id: {_cw_agent}", Colors.DIM))
        print(C("  定位: 合规留痕 + 风险提示（无内核阻断能力，依赖 Agent 主动申报）", Colors.DIM))
        print(C(SEP, Colors.CYAN))
        print(f"  {C('1.', Colors.CYAN)} {C('启动 MCP 申报 daemon', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: start，后台管家托管)', Colors.DIM)}")
        print(f"  {C('2.', Colors.CYAN)} {C('停止 daemon 并生成报告', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: stop，优雅停止)', Colors.DIM)}")
        print(f"  {C('3.', Colors.CYAN)} {C('状态查看', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: status，daemon/WorkBuddy/注册状态)', Colors.DIM)}")
        print(f"  {C('4.', Colors.CYAN)} {C('连通性自检', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: check，端口+initialize+call_tool)', Colors.DIM)}")
        print(f"  {C('5.', Colors.CYAN)} {C('申报烟测', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: smoke，模拟 WorkBuddy 申报序列)', Colors.DIM)}")
        print(f"  {C('6.', Colors.CYAN)} {C('查看 daemon 日志', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: logs)', Colors.DIM)}")
        print(f"  {C('7.', Colors.CYAN)} {C('报告产物', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: report，风险报告/审计/汇总)', Colors.DIM)}")
        print(f"  {C('8.', Colors.CYAN)} {C('启动 + 轻量测试报告（test_report）', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: start-testreport，--no-rollup)', Colors.DIM)}")
    elif key == "serve":
        print(C("  Web 服务（localhost:8080，Ctrl+C 返回菜单）", Colors.DIM))
        print(C(SEP, Colors.CYAN))
        print(f"  {C('1.', Colors.CYAN)} {C('启动 Web 服务并自动打开浏览器', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: start)', Colors.DIM)}")
        print(f"  {C('2.', Colors.CYAN)} {C('启动 Web 服务（不打开浏览器）', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: nb)', Colors.DIM)}")
        print(f"  {C('3.', Colors.CYAN)} {C('API 冒烟测试', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: api，自动拉起/关闭服务)', Colors.DIM)}")
        print(f"  {C('4.', Colors.CYAN)} {C('SSE 冒烟测试', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: sse，自动拉起/关闭服务)', Colors.DIM)}")
    elif key == "files":
        print(C("  文件管理（五区: records / monitoring / mcp_monitoring / reports / unit_test，路径遍历防护）", Colors.DIM))
        print(C(SEP, Colors.CYAN))
        print(f"  {C('1.', Colors.CYAN)} {C('查看五区文件树', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: tree)', Colors.DIM)}")
        print(f"  {C('2.', Colors.CYAN)} {C('查看文件', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: view <path>)', Colors.DIM)}")
        print(f"  {C('3.', Colors.CYAN)} {C('删除文件/目录', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: delete <path>，y/N 确认)', Colors.DIM)}")
        print(f"  {C('4.', Colors.CYAN)} {C('清空分类', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: del-cat <records|monitoring|mcp_monitoring|reports|unit_test>)', Colors.DIM)}")
    elif key == "reports":
        print(C("  报告管理（场景模拟报告 / 监测守护进程报告）", Colors.DIM))
        print(C(SEP, Colors.CYAN))
        print(f"  {C('1.', Colors.CYAN)} {C('报告列表', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: list)', Colors.DIM)}")
        print(f"  {C('2.', Colors.CYAN)} {C('查看报告', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: view <path>)', Colors.DIM)}")
        print(f"  {C('3.', Colors.CYAN)} {C('删除报告', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: delete，全部/按分类/按场景 三级，y/N 确认)', Colors.DIM)}")
    elif key == "samples":
        print(C("  样例与工具", Colors.DIM))
        print(C(SEP, Colors.CYAN))
        print(f"  {C('1.', Colors.CYAN)} {C('环境预检', Colors.WHITE + Colors.BOLD)}"
              f"  {C(f'(短命令: check，等价主菜单 {len(DOMAINS) + 1} / env 完整检测)', Colors.DIM)}")
        print(f"  {C('2.', Colors.CYAN)} {C('重新生成 37 个场景 YAML', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: gen，y/N 确认)', Colors.DIM)}")
        rr_title = "录制-回放工作流"
        if _get_platform().is_windows:
            rr_title += " " + C("[当前环境不支持]", Colors.RED)
        print(f"  {C('3.', Colors.CYAN)} {C(rr_title, Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: rr，Ctrl+C 返回菜单)', Colors.DIM)}")
    elif key == "test":
        print(C("  测试运行（统一测试入口，run_tests.py 单一事实来源）", Colors.DIM))
        print(C(SEP, Colors.CYAN))
        print(f"  {C('1.', Colors.CYAN)} {C('单元测试', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: unit，pytest 全量)', Colors.DIM)}")
        print(f"  {C('2.', Colors.CYAN)} {C('API 冒烟测试', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: api，13 项)', Colors.DIM)}")
        print(f"  {C('3.', Colors.CYAN)} {C('SSE 冒烟测试', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: sse，12 项)', Colors.DIM)}")
        print(f"  {C('4.', Colors.CYAN)} {C('全部测试', Colors.WHITE + Colors.BOLD)}"
              f"  {C('(短命令: all，unit → api → sse)', Colors.DIM)}")
    print(C(SEP, Colors.CYAN))
    print(f"  {C('0.', Colors.DIM)} {C('返回主菜单', Colors.DIM)}"
          f"    {C('h.', Colors.DIM)} {C('本域命令帮助', Colors.DIM)}"
          f"    {C('q', Colors.DIM)} {C('退出', Colors.DIM)}")
    print()


# ── 帮助（命令速查表）────────────────────────────────────────
def _print_main_help():
    print()
    print(C(SEP_D, Colors.CYAN))
    print(C("  命令速查表（任意菜单下直接输入即可执行，无需查手册）", Colors.CYAN + Colors.BOLD))
    print(C(SEP_D, Colors.CYAN))
    rows = [
        ("run all | <分类> | <场景ID>", "运行场景流水线", "observer run"),
        ("demo menu | <场景ID> | <分类>", "交互演示 / 自动播放", "observer demo"),
        ("daemon start | record | testreport | record-testreport | report",
         "监测守护进程（仅 Linux）", "observer daemon"),
        ("mcp start | start-testreport | stop | status | check | smoke | logs | report",
         "MCP 申报监测（WorkBuddy 降级通道）", "connect_workbuddy.py"),
        ("serve start | nb | api | sse", "Web 服务与冒烟", "observer serve / test"),
        ("files tree | view <p> | delete <p> | del-cat <c>", "文件管理（五区含 mcp_monitoring）", "observer files"),
        ("reports list | view <p> | delete", "报告管理", "observer reports"),
        ("samples check | gen | rr", "环境预检/场景生成/录制回放", "observer samples"),
        ("test unit | api | sse | all", "测试运行", "observer test"),
        ("env | env light", "环境检测（完整 / 轻量）", "observer env"),
    ]
    for short, desc, bottom in rows:
        print(f"  {C(short, Colors.GREEN)}")
        print(f"      {C(desc, Colors.DIM)}   [= {C(bottom, Colors.DIM)}]")
    print(C(SEP, Colors.CYAN))
    print(f"  {C('h/help/?', Colors.GREEN)} 显示本速查表    {C('0/b/back', Colors.GREEN)} 返回上一级")
    print(f"  {C('q/quit/exit', Colors.GREEN)} 退出控制台    {C('Ctrl+C', Colors.GREEN)} 长驻进程中断后返回菜单")
    print()


def _print_domain_help(key):
    helps = {
        "run": [("all", "运行全部 37 个场景"), ("<分类>", "normal/anomalous/boundary/multi_agent/extreme"),
                ("<场景ID>", "n01-n08 / a01-a12 / b01-b08 / m01-m05 / e01-e04")],
        "demo": [("menu", "进入 demo.py 原有编号菜单"), ("<场景ID>", "自动播放指定场景（如 n01）"),
                 ("<分类>", "自动播放整个分类（如 anomalous）")],
        "daemon": [("start", "启动监测守护进程（默认 FIFO/oneshot）"), ("record", "启动并旁路录制 .jsonl"),
                   ("testreport", "轻量测试报告模式（test_report：不生成 L1/L2/L3 分层日志）"),
                   ("record-testreport", "录制 + 轻量测试报告（--record --no-rollup）"),
                   ("report", "请求运行中的守护进程生成报告")],
        "mcp": [("start", "启动 MCP 申报 daemon（后台管家托管，跨平台）"),
                ("start-testreport", "启动 + 轻量测试报告（--no-rollup，不生成分层日志）"),
                ("stop", "优雅停止并生成风险报告/审计"),
                ("status", "daemon/端口/WorkBuddy 注册状态"),
                ("check", "连通性自检（端口+initialize+call_tool）"),
                ("smoke", "模拟 WorkBuddy 申报序列（5 accepted + 2 rejected）"),
                ("logs", "查看 daemon 运行日志尾部"),
                ("report", "列出风险报告/审计/汇总产物")],
        "serve": [("start", "启动 Web 服务并自动打开浏览器"), ("nb", "启动 Web 服务（不打开浏览器）"),
                  ("api", "API 冒烟测试"), ("sse", "SSE 冒烟测试")],
        "files": [("tree", "五区文件树（含 mcp_monitoring 产物）"), ("view <path>", "查看文件（如 mcp_monitoring/reports/…）"),
                  ("delete <path>", "删除文件/目录（y/N 确认）"),
                  ("del-cat <c>", "清空分类 records/monitoring/mcp_monitoring/reports/unit_test")],
        "reports": [("list", "报告列表"), ("view <path>", "查看报告"),
                    ("delete", "三级删除（全部/按分类/按场景，y/N 确认）")],
        "samples": [("check", f"环境预检（完整检测，等价 env / 主菜单 {len(DOMAINS) + 1}）"), ("gen", "重新生成 37 个场景 YAML（y/N 确认）"),
                    ("rr", "录制-回放工作流（Ctrl+C 返回菜单，仅 Linux）")],
        "test": [("unit", "pytest 单元测试全量"), ("api", "API 冒烟 13 项"),
                 ("sse", "SSE 冒烟 12 项"), ("all", "unit → api → sse")],
    }
    print()
    print(C(SEP_D, Colors.CYAN))
    print(C(f"  {key} 域命令帮助", Colors.CYAN + Colors.BOLD))
    print(C(SEP_D, Colors.CYAN))
    for short, desc in helps.get(key, []):
        print(f"  {C(short, Colors.GREEN)}  {C('— ' + desc, Colors.DIM)}")
    print(C(SEP, Colors.CYAN))
    print(f"  {C('0/b/back', Colors.GREEN)} 返回主菜单    {C('h', Colors.GREEN)} 全部命令速查    {C('q', Colors.GREEN)} 退出")
    print()


# ── 域动作执行 ───────────────────────────────────────────────
def _exec_run(token):
    """run 域短命令: all | <分类> | <场景ID>。"""
    token = token.lower()
    if token == "all":
        _run_action("run", ["--scenario", "all"],
                    ">>> 运行全部场景（37 个，产出报告/图谱/审计）")
        return
    if token in CATEGORIES:
        _run_action("run", ["--category", token],
                    f">>> 按分类运行 {CAT_LABELS[token]}")
        return
    name = _find_scenario(token)
    if not name:
        print(C(f"未找到场景 '{token}'，可用 ID: n01-n08 / a01-a12 / b01-b08 / m01-m05 / e01-e04",
                Colors.RED))
        print(C("也可输入分类名（如 normal）或 all；输入 h 查看帮助", Colors.DIM))
        return
    _run_action("run", ["--scenario", name[:-5]], f">>> 运行场景 {name}")


def _exec_demo(token):
    """demo 域短命令: menu | <场景ID> | <分类>。"""
    token = token.lower()
    if token in ("menu", "main"):
        _run_action("demo", [], ">>> 进入演示编号菜单（demo.py 原有菜单，Ctrl+C 返回）",
                    interruptable=True)
        return
    if token in CATEGORIES:
        _run_action("demo", ["--auto", "--category", token],
                    f">>> 按分类自动播放 {CAT_LABELS[token]}", interruptable=True)
        return
    name = _find_scenario(token)
    if not name:
        print(C(f"未找到场景 '{token}'，可用 ID: n01-n08 / a01-a12 / b01-b08 / m01-m05 / e01-e04",
                Colors.RED))
        print(C("也可输入 menu 进入演示菜单；输入 h 查看帮助", Colors.DIM))
        return
    _run_action("demo", ["--auto", "--scenario", name[:-5]],
                f">>> 自动播放场景 {name}", interruptable=True)


def _exec_daemon(token):
    """daemon 域短命令: start | record | testreport | record-testreport | report。

    前置判断: daemon 依赖 Linux FIFO 命名管道，Windows 下阻止（_env_gate）。
    """
    if not _env_gate("daemon"):
        return
    if token == "start":
        _run_action("daemon", [],
                    ">>> 启动监测守护进程（Ctrl+C 中断返回菜单；命名管道需 Linux 环境）",
                    interruptable=True)
    elif token == "record":
        _run_action("daemon", ["--record"],
                    ">>> 启动守护进程并旁路录制 .jsonl（Ctrl+C 中断返回菜单）",
                    interruptable=True)
    elif token == "testreport":
        _run_action("daemon", ["--no-rollup"],
                    ">>> 启动守护进程（test_report 轻量模式：仅记录原始事件，"
                    "结束后一次性输出报告；Ctrl+C 中断返回菜单）",
                    interruptable=True)
    elif token == "record-testreport":
        _run_action("daemon", ["--record", "--no-rollup"],
                    ">>> 启动守护进程并旁路录制（test_report 轻量模式："
                    "仅记录原始事件，结束后一次性输出报告；Ctrl+C 中断返回菜单）",
                    interruptable=True)
    elif token == "report":
        _run_action("daemon", ["--generate-report"],
                    ">>> 请求运行中的守护进程生成报告（需守护进程已启动）")
    else:
        print(C(f"未知 daemon 命令 '{token}'，可用: start / record / testreport / record-testreport / report",
                Colors.RED))


_MCP_SUBCOMMANDS = ("start", "start-testreport", "stop", "status", "check",
                    "smoke", "logs", "report", "configure-workbuddy",
                    "unconfigure-workbuddy", "launch-workbuddy",
                    "restart-workbuddy")


def _exec_mcp(token):
    """mcp 域短命令: 转发 connect_workbuddy.py 子命令。

    MCP 申报通道跨平台可用（不依赖 Linux FIFO），无需 _env_gate 阻止；
    所有可变信息（host/port/路径）由 connect_workbuddy.py 只读
    workbuddy_connect.yaml，本菜单不硬编码。

    start-testreport: 启动 + test_report 轻量测试报告模式（--no-rollup）。
    """
    token = (token or "").strip().lower()
    if token not in _MCP_SUBCOMMANDS:
        print(C(f"未知 mcp 命令 '{token}'，可用: "
                f"start / start-testreport / stop / status / check / smoke"
                f" / logs / report / configure-workbuddy / launch-workbuddy",
                Colors.RED))
        return
    print()
    print(C(f">>> MCP 申报监测: {token}", Colors.YELLOW))
    print(C(SEP, Colors.CYAN))
    argv = [token]
    if token == "start-testreport":
        argv = ["start", "--no-rollup"]
        print(C("（test_report 轻量模式：仅记录 L0 原始事件，"
                "不触发 L1→L2→L3 分层聚合，结束后一次性输出报告）",
                Colors.DIM))
    code = subprocess.call(
        [sys.executable, os.path.join(BASE_DIR, "connect_workbuddy.py")] + argv,
        cwd=BASE_DIR)
    if code != 0:
        print(C(f"[完成] 退出码 {code}（非零），输入 h 查看用法", Colors.YELLOW))
    else:
        print(C("[完成] 返回菜单", Colors.DIM))
    print(C(SEP, Colors.CYAN))


def _exec_serve(token):
    """serve 域短命令: start | nb | api | sse。"""
    if token == "start":
        _run_action("serve", [],
                    ">>> 启动 Web 服务并自动打开浏览器 localhost:8080（Ctrl+C 返回菜单）",
                    interruptable=True)
    elif token in ("nb", "nobrowser", "no-browser"):
        _run_action("serve", ["--no-browser"],
                    ">>> 启动 Web 服务 localhost:8080（不打开浏览器，Ctrl+C 返回菜单）",
                    interruptable=True)
    elif token == "api":
        _run_action("test", ["api"], ">>> API 冒烟测试（自动拉起/关闭临时服务）")
    elif token == "sse":
        _run_action("test", ["sse"], ">>> SSE 冒烟测试（自动拉起/关闭临时服务）")
    else:
        print(C(f"未知 serve 命令 '{token}'，可用: start / nb / api / sse", Colors.RED))


def _input_path(prompt):
    try:
        return input(C(prompt, Colors.GREEN)).strip()
    except (KeyboardInterrupt, EOFError):
        return ""


def _exec_files(tokens):
    """files 域短命令: tree | view <p> | delete <p> | del-cat <c>。"""
    if not tokens:
        print(C("用法: tree | view <path> | delete <path> | del-cat <c>", Colors.YELLOW))
        return
    head = tokens[0].lower()
    if head == "tree":
        _run_action("files", ["tree"], ">>> 五区文件树")
    elif head == "view":
        path = tokens[1] if len(tokens) > 1 else _input_path("请输入文件相对路径（如 reports/normal/…）: ")
        if path:
            _run_action("files", ["view", path], f">>> 查看文件 {path}")
    elif head == "delete":
        path = tokens[1] if len(tokens) > 1 else _input_path("请输入要删除的路径: ")
        if path and _confirm(f"确认删除 '{path}'？此操作不可恢复 [y/N]: "):
            _run_action("files", ["delete", path], f">>> 删除 {path}")
        elif path:
            print(C("已取消", Colors.DIM))
    elif head in ("del-cat", "delete-category"):
        cat = tokens[1].lower() if len(tokens) > 1 else ""
        if cat not in SAFE_ROOTS:
            cat = _input_path("请输入分类（records/monitoring/mcp_monitoring/reports/unit_test）: ").lower()
        if cat not in SAFE_ROOTS:
            print(C(f"未知分类 '{cat}'，可用: records / monitoring / mcp_monitoring / reports / unit_test", Colors.RED))
            return
        if _confirm(f"确认清空分类 '{cat}' 下全部记录？此操作不可恢复 [y/N]: "):
            _run_action("files", ["delete-category", cat], f">>> 清空分类 {cat}")
        else:
            print(C("已取消", Colors.DIM))
    else:
        print(C(f"未知 files 命令 '{head}'，可用: tree / view / delete / del-cat", Colors.RED))


def _exec_reports(tokens):
    """reports 域短命令: list | view <p> | delete。"""
    if not tokens:
        print(C("用法: list | view <path> | delete（三级删除）", Colors.YELLOW))
        return
    head = tokens[0].lower()
    if head == "list":
        _run_action("reports", ["list"], ">>> 报告列表")
    elif head == "view":
        path = tokens[1] if len(tokens) > 1 else _input_path("请输入报告相对路径（如 reports/normal/…）: ")
        if path:
            _run_action("reports", ["view", path], f">>> 查看报告 {path}")
    elif head == "delete":
        print()
        print(C("  删除报告范围:", Colors.WHITE))
        print(C("    1. 全部报告（all）", Colors.DIM))
        print(C("    2. 按分类（category，如 normal）", Colors.DIM))
        print(C("    3. 按场景（scenario，如 n01_xxx 目录）", Colors.DIM))
        scope = _input_path("  选择范围 [1/2/3，默认取消]: ").strip()
        argv = ["delete"]
        if scope == "1":
            argv += ["--scope", "all"]
            label = "全部报告"
        elif scope == "2":
            cat = _input_path("  输入分类（normal/anomalous/boundary/multi_agent/extreme）: ").strip().lower()
            if cat not in CATEGORIES:
                print(C(f"未知分类 '{cat}'", Colors.RED))
                return
            argv += ["--scope", "category", "--category", cat]
            label = f"分类 {cat} 的报告"
        elif scope == "3":
            sid = _input_path("  输入场景 ID（如 n01）: ").strip().lower()
            argv += ["--scope", "scenario", "--scenario-id", sid]
            label = f"场景 {sid} 的报告"
        else:
            print(C("已取消", Colors.DIM))
            return
        if _confirm(f"确认删除{label}？此操作不可恢复 [y/N]: "):
            _run_action("reports", argv, f">>> 删除{label}")
        else:
            print(C("已取消", Colors.DIM))
    else:
        print(C(f"未知 reports 命令 '{head}'，可用: list / view / delete", Colors.RED))


def _exec_samples(token):
    """samples 域短命令: check | gen | rr。"""
    if token in ("check", "check-env"):
        _exec_env()
    elif token in ("gen", "gen-scenarios"):
        if _confirm("确认重新生成 37 个场景 YAML（覆盖 scenarios/ 现有文件）？[y/N]: "):
            _run_action("samples", ["gen-scenarios"], ">>> 重新生成场景 YAML")
        else:
            print(C("已取消", Colors.DIM))
    elif token in ("rr", "record-replay"):
        _run_record_replay()
    else:
        print(C(f"未知 samples 命令 '{token}'，可用: check / gen / rr", Colors.RED))


def _exec_test(token):
    """test 域短命令: unit | api | sse | all。"""
    if token in ("unit", "api", "sse", "all"):
        _run_action("test", [token], f">>> 测试运行: {token}")
    else:
        print(C(f"未知 test 命令 '{token}'，可用: unit / api / sse / all", Colors.RED))


# ── 域分派（数字选项 + 短命令）──────────────────────────────
def _dispatch_domain(key, raw):
    """处理域子菜单输入。返回 'back' / 'quit' / None（留在本菜单）。"""
    raw = raw.strip()
    if raw == "":
        return None
    if raw in ("0", "b", "back"):
        return "back"
    if raw in ("q", "quit", "exit"):
        return "quit"
    if raw in ("h", "help", "?"):
        _print_domain_help(key)
        return None

    parts = raw.split()
    # 环境检测短命令（任意菜单下直达）
    if parts[0] == "env":
        _exec_env(light=(len(parts) > 1 and parts[1] in ("light", "l")))
        return None
    # 数字选项（与短命令等价，二次输入由各执行器内 input 引导）
    if parts[0].isdigit():
        num = parts[0]
        if key == "run":
            if num == "1":
                _exec_run("all")
            elif num == "2":
                cat = _input_path("输入分类（normal/anomalous/boundary/multi_agent/extreme）: ").lower()
                if cat in CATEGORIES:
                    _exec_run(cat)
                else:
                    print(C(f"未知分类 '{cat}'", Colors.RED))
            elif num == "3":
                sid = _input_path("输入场景 ID（如 n01）: ").lower()
                _exec_run(sid)
            else:
                print(C(f"无效选项 {num}，请输入 1-3", Colors.RED))
        elif key == "demo":
            if num == "1":
                _exec_demo("menu")
            elif num == "2":
                sid = _input_path("输入场景 ID（如 n01）: ").lower()
                _exec_demo(sid)
            elif num == "3":
                cat = _input_path("输入分类（normal/anomalous/boundary/multi_agent/extreme）: ").lower()
                if cat in CATEGORIES:
                    _exec_demo(cat)
                else:
                    print(C(f"未知分类 '{cat}'", Colors.RED))
            else:
                print(C(f"无效选项 {num}，请输入 1-3", Colors.RED))
        elif key == "daemon":
            if num == "1":
                _exec_daemon("start")
            elif num == "2":
                _exec_daemon("record")
            elif num == "3":
                _exec_daemon("testreport")
            elif num == "4":
                _exec_daemon("report")
            elif num == "5":
                _exec_daemon("record-testreport")
            else:
                print(C(f"无效选项 {num}，请输入 1-5", Colors.RED))
        elif key == "mcp":
            _mcp_options = {"1": "start", "2": "stop", "3": "status",
                            "4": "check", "5": "smoke", "6": "logs",
                            "7": "report", "8": "start-testreport"}
            if num in _mcp_options:
                _exec_mcp(_mcp_options[num])
            else:
                print(C(f"无效选项 {num}，请输入 1-8", Colors.RED))
        elif key == "serve":
            if num == "1":
                _exec_serve("start")
            elif num == "2":
                _exec_serve("nb")
            elif num == "3":
                _exec_serve("api")
            elif num == "4":
                _exec_serve("sse")
            else:
                print(C(f"无效选项 {num}，请输入 1-4", Colors.RED))
        elif key == "files":
            if num == "1":
                _exec_files(["tree"])
            elif num == "2":
                path = _input_path("请输入文件相对路径（如 reports/normal/…）: ")
                if path:
                    _exec_files(["view", path])
            elif num == "3":
                path = _input_path("请输入要删除的路径: ")
                if path:
                    _exec_files(["delete", path])
            elif num == "4":
                _exec_files(["del-cat"])
            else:
                print(C(f"无效选项 {num}，请输入 1-4", Colors.RED))
        elif key == "reports":
            if num == "1":
                _exec_reports(["list"])
            elif num == "2":
                path = _input_path("请输入报告相对路径（如 reports/normal/…）: ")
                if path:
                    _exec_reports(["view", path])
            elif num == "3":
                _exec_reports(["delete"])
            else:
                print(C(f"无效选项 {num}，请输入 1-3", Colors.RED))
        elif key == "samples":
            if num == "1":
                _exec_samples("check")
            elif num == "2":
                _exec_samples("gen")
            elif num == "3":
                _exec_samples("rr")
            else:
                print(C(f"无效选项 {num}，请输入 1-3", Colors.RED))
        elif key == "test":
            if num == "1":
                _exec_test("unit")
            elif num == "2":
                _exec_test("api")
            elif num == "3":
                _exec_test("sse")
            elif num == "4":
                _exec_test("all")
            else:
                print(C(f"无效选项 {num}，请输入 1-4", Colors.RED))
        return None

    # 短命令直达
    if key == "run":
        _exec_run(parts[0])
    elif key == "demo":
        _exec_demo(parts[0])
    elif key == "daemon":
        _exec_daemon(parts[0])
    elif key == "mcp":
        _exec_mcp(parts[0])
    elif key == "serve":
        _exec_serve(parts[0])
    elif key == "files":
        _exec_files(parts)
    elif key == "reports":
        _exec_reports(parts)
    elif key == "samples":
        _exec_samples(parts[0])
    elif key == "test":
        _exec_test(parts[0])
    return None


# ── 主菜单分派 ───────────────────────────────────────────────
_DOMAIN_KEYS = [d[0] for d in DOMAINS]


def _dispatch_main(raw):
    """处理主菜单输入。返回 'quit' / 'sub:<key>' / None（留在主菜单）。"""
    raw = raw.strip()
    if raw == "":
        return None
    if raw in ("0", "q", "quit", "exit"):
        print(C("已退出控制台，再见！", Colors.DIM))
        return "quit"
    if raw in ("h", "help", "?"):
        _print_main_help()
        return None

    parts = raw.split()
    # 环境检测短命令: env（完整）/ env light（轻量）
    if parts[0] == "env":
        _exec_env(light=(len(parts) > 1 and parts[1] in ("light", "l")))
        return None
    # 数字 → 进入域子菜单（9 = 环境检测直接执行）
    if parts[0].isdigit():
        idx = int(parts[0])
        if 1 <= idx <= len(DOMAINS):
            return "sub:" + _DOMAIN_KEYS[idx - 1]
        if idx == len(DOMAINS) + 1:
            _exec_env()
            return None
        print(C(f"无效选项 {parts[0]}，请输入 1-{len(DOMAINS) + 1}（输入 h 查看命令速查）", Colors.RED))
        return None

    # 短命令直达：<域> [参数...]；域命令无参数时进入对应子菜单
    key = parts[0].lower()
    if key not in _DOMAIN_KEYS:
        print(C(f"无效输入 '{raw}'，请输入 1-{len(DOMAINS) + 1} 或短命令（输入 h 查看全部短命令）",
                Colors.RED))
        return None
    rest = parts[1:]
    if not rest:
        return "sub:" + key
    # 带参数直达执行（复用域执行器），执行完留在主菜单
    if key == "run":
        _exec_run(" ".join(rest))
    elif key == "demo":
        _exec_demo(rest[0])
    elif key == "daemon":
        _exec_daemon(rest[0])
    elif key == "mcp":
        _exec_mcp(rest[0])
    elif key == "serve":
        _exec_serve(rest[0])
    elif key == "files":
        _exec_files(rest)
    elif key == "reports":
        _exec_reports(rest)
    elif key == "samples":
        _exec_samples(rest[0])
    elif key == "test":
        _exec_test(rest[0])
    return None


# ── 主循环 ───────────────────────────────────────────────────
def run_console(argv=None) -> int:
    """控制台主循环：主菜单 → 域子菜单 → 动作执行 → 返回。返回进程退出码。"""
    if argv is None:
        argv = []
    menu = "main"
    while True:
        if menu == "main":
            _render_main()
        else:
            _render_domain(menu)
        try:
            raw = _read_input("请输入选项或短命令 > ")
        except KeyboardInterrupt:
            if menu == "main":
                print(C("\n[Ctrl+C] 已退出控制台", Colors.DIM))
                return 0
            print(C("\n[Ctrl+C] 已返回主菜单", Colors.DIM))
            menu = "main"
            continue
        except EOFError:  # 防御性兜底（_read_input 已处理，此处双保险）
            print(C("\n[stdin 结束] 已退出控制台", Colors.DIM))
            return 0

        if menu == "main":
            nav = _dispatch_main(raw)
            if nav == "quit":
                return 0
            if nav and nav.startswith("sub:"):
                menu = nav[4:]
        else:
            nav = _dispatch_domain(menu, raw)
            if nav == "quit":
                print(C("已退出控制台，再见！", Colors.DIM))
                return 0
            if nav == "back":
                menu = "main"
        # nav == None 时留在当前菜单重新渲染


if __name__ == "__main__":
    sys.exit(run_console())
