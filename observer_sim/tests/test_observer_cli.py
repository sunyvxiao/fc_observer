"""
test_observer_cli.py — U4 observer 统一入口 CLI 测试

测试内容:
1. observer --help 可解析，列出 10 个顶层子命令
   （run/serve/daemon/demo/files/reports/samples/env/test/menu；samples 内挂载
   check-env/gen-scenarios 两动作，合计 11 个可达命令入口）
2. 10 个子命令 help 均可解析（usage: observer <sub>）
3. observer files tree 输出 JSON 结构（含 tree 键）
4. observer files view 路径遍历 / 未知前缀拒绝（退出码非 0）
5. observer env / env --light 环境配置检测（独立前置检查）
6. observer menu 命令行控制台（console.py 调度层）:
   启动主菜单（含环境状态行）、非法输入引导、越界提示、help 速查、
   短命令直达（含 env）、子菜单导航与返回、退出别名
7. 兼容性回归: python main.py --scenario n01 退出码 0；
   observer run 与 main.py 输出目录结构一致（时间戳 run 目录归一化后）
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OBSERVER = os.path.join(BASE_DIR, "observer.py")
MAIN_PY = os.path.join(BASE_DIR, "main.py")

# run 目录时间戳（2026_08_18_13_27_10）与报告文件名时间戳（20260818_133446）两种格式
_TS_RE = re.compile(r"\d{4}_\d{2}_\d{2}_\d{2}_\d{2}_\d{2}|\d{8}_\d{6}")


def _run(args, cwd=BASE_DIR, timeout=300, input_text=None):
    """subprocess 运行 python 脚本，统一 UTF-8 环境（Windows 管道兼容）。

    input_text: 提供时作为 stdin 写入（text 模式），用于交互菜单测试。
    """
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    kwargs = dict(cwd=cwd, env=env, timeout=timeout)
    if input_text is not None:
        return subprocess.run(
            [sys.executable] + args, input=input_text, text=True,
            encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    return subprocess.run(
        [sys.executable] + args,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def _rel_files(root):
    """收集 root 下所有文件相对路径（run 目录时间戳归一化为 TS）。"""
    out = set()
    for dirpath, _dirnames, filenames in os.walk(root):
        for f in filenames:
            rel = os.path.relpath(os.path.join(dirpath, f), root)
            rel = _TS_RE.sub("TS", rel)
            out.add(rel.replace(os.sep, "/"))
    return out


class TestObserverHelp(unittest.TestCase):
    """observer --help 及全部子命令 help 可解析。"""

    SUBCOMMANDS = ["run", "serve", "daemon", "demo", "files", "reports",
                   "samples", "env", "test", "menu"]

    def test_root_help_lists_all_subcommands(self):
        r = _run([OBSERVER, "--help"])
        self.assertEqual(r.returncode, 0,
                         r.stderr.decode("utf-8", "replace"))
        out = r.stdout.decode("utf-8", "replace")
        for name in self.SUBCOMMANDS:
            self.assertIn(name, out, f"根 help 缺少子命令 {name}")

    def test_each_subcommand_help_parses(self):
        for name in self.SUBCOMMANDS:
            r = _run([OBSERVER, name, "--help"])
            self.assertEqual(r.returncode, 0,
                             f"{name} --help 失败: {r.stderr.decode('utf-8', 'replace')}")
            out = r.stdout.decode("utf-8", "replace")
            self.assertIn(f"usage: observer {name}", out)

    def test_samples_actions_listed(self):
        """samples 子命令挂载 check-env / gen-scenarios（U9）。"""
        r = _run([OBSERVER, "samples", "--help"])
        self.assertEqual(r.returncode, 0)
        out = r.stdout.decode("utf-8", "replace")
        self.assertIn("check-env", out)
        self.assertIn("gen-scenarios", out)


class TestObserverEnv(unittest.TestCase):
    """observer env 独立环境配置检测（复用 check_env.py）。"""

    def test_env_full_check_exit_zero(self):
        """完整检测在环境就绪时退出码 0（Windows 本机预期全通过）。"""
        r = _run([OBSERVER, "env"], timeout=120)
        self.assertEqual(r.returncode, 0,
                         r.stderr.decode("utf-8", "replace"))
        out = r.stdout.decode("utf-8", "replace")
        self.assertIn("环境预检", out)
        self.assertIn("检查汇总", out)

    def test_env_light_check_fast(self):
        """轻量检测 <1 秒级完成且不执行子进程工具链探测。"""
        import time
        started = time.time()
        r = _run([OBSERVER, "env", "--light"], timeout=60)
        elapsed = time.time() - started
        self.assertEqual(r.returncode, 0,
                         r.stderr.decode("utf-8", "replace"))
        out = r.stdout.decode("utf-8", "replace")
        self.assertIn("环境预检（轻量）", out)
        self.assertLess(elapsed, 10, "轻量检测耗时过长")

    def test_samples_check_env_compatible(self):
        """兼容入口: observer samples check-env 等价完整检测。"""
        r = _run([OBSERVER, "samples", "check-env"], timeout=120)
        self.assertEqual(r.returncode, 0,
                         r.stderr.decode("utf-8", "replace"))
        self.assertIn("环境预检", r.stdout.decode("utf-8", "replace"))


class TestObserverFiles(unittest.TestCase):
    """observer files 子命令（U7 manager 的 CLI 视图）。"""

    def test_files_tree_json_structure(self):
        r = _run([OBSERVER, "files", "tree"])
        self.assertEqual(r.returncode, 0,
                         r.stderr.decode("utf-8", "replace"))
        data = json.loads(r.stdout.decode("utf-8"))
        self.assertIn("tree", data)
        self.assertIsInstance(data["tree"], dict)

    def test_files_view_path_traversal_rejected(self):
        # 前缀匹配但 realpath 越界 → traversal 拒绝，退出码非 0
        r = _run([OBSERVER, "files", "view", "records/../../../Windows/win.ini"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("拒绝访问",
                      r.stderr.decode("utf-8", "replace"))

    def test_files_view_unknown_prefix_rejected(self):
        r = _run([OBSERVER, "files", "view", "../etc/passwd"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("拒绝访问",
                      r.stderr.decode("utf-8", "replace"))

    def test_files_tree_includes_mcp_monitoring(self):
        """files tree 纳入 mcp_monitoring 分区（产物存在时）。"""
        if BASE_DIR not in sys.path:
            sys.path.insert(0, BASE_DIR)
        try:
            import connect_workbuddy as cw
            out_dir = cw._out_paths(cw.load_config(cw.DEFAULT_CONFIG))[0]
        except Exception:  # noqa: BLE001
            self.skipTest("workbuddy_connect.yaml 不可用")
        if not os.path.isdir(out_dir) or not os.listdir(out_dir):
            self.skipTest("output/mcp_monitoring 为空或不存在")
        r = _run([OBSERVER, "files", "tree"])
        self.assertEqual(r.returncode, 0,
                         r.stderr.decode("utf-8", "replace"))
        data = json.loads(r.stdout.decode("utf-8"))
        self.assertIn("mcp_monitoring", data["tree"],
                      f"文件树缺少 mcp_monitoring 分区: {list(data['tree'])}")

    def test_files_view_mcp_traversal_rejected(self):
        """mcp_monitoring 前缀同样受路径遍历防护（与四区一致）。"""
        r = _run([OBSERVER, "files", "view",
                  "mcp_monitoring/../../../Windows/win.ini"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("拒绝访问",
                      r.stderr.decode("utf-8", "replace"))

    def test_files_tree_includes_qoder_monitoring(self):
        """files tree 纳入 qoder_monitoring 分区（产物存在时）。"""
        out_dir = os.path.join(BASE_DIR, "output", "qoder_monitoring")
        if not os.path.isdir(out_dir) or not os.listdir(out_dir):
            self.skipTest("output/qoder_monitoring 为空或不存在")
        r = _run([OBSERVER, "files", "tree"])
        self.assertEqual(r.returncode, 0,
                         r.stderr.decode("utf-8", "replace"))
        data = json.loads(r.stdout.decode("utf-8"))
        self.assertIn("qoder_monitoring", data["tree"],
                      f"文件树缺少 qoder_monitoring 分区: "
                      f"{list(data['tree'])}")
        node = data["tree"]["qoder_monitoring"]
        self.assertEqual(node["label"], "Qoder CN 监测产物")
        self.assertTrue(node.get("children"), "qoder_monitoring 分区为空")
        # 文件路径均以分区前缀开头（与 view/delete 前缀约定一致）
        def _paths(items):
            for it in items:
                if it.get("type") == "file" and "path" in it:
                    yield it["path"]
                yield from _paths(it.get("children") or [])
        for p in _paths(node["children"]):
            self.assertTrue(p.startswith("qoder_monitoring/"), p)

    def test_files_view_qoder_traversal_rejected(self):
        """qoder_monitoring 前缀同样受路径遍历防护（与其余分区一致）。"""
        r = _run([OBSERVER, "files", "view",
                  "qoder_monitoring/../../../etc/passwd"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("拒绝访问",
                      r.stderr.decode("utf-8", "replace"))


class TestObserverMenu(unittest.TestCase):
    """observer menu 命令行控制台（console.py 调度层，编号菜单 + 短命令）。"""

    def _menu(self, inputs):
        """喂入 stdin 行序列运行菜单，返回 CompletedProcess。"""
        return _run([OBSERVER, "menu"], input_text="\n".join(inputs) + "\n",
                    timeout=120)

    def test_menu_launch_and_quit(self):
        r = self._menu(["0"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("方寸观察者 命令行控制台", r.stdout)
        self.assertIn("已退出控制台", r.stdout)

    def test_menu_invalid_input_guidance(self):
        r = self._menu(["xyz", "0"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("无效输入", r.stdout)
        self.assertIn("h", r.stdout)  # 引导查看帮助

    def test_menu_out_of_range_option(self):
        r = self._menu(["99", "0"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("无效选项 99", r.stdout)
        self.assertIn("1-11", r.stdout)  # 菜单项数随 qoder 域加入变为 11

    def test_menu_help_shortcut_shows_command_table(self):
        r = self._menu(["h", "0"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("命令速查表", r.stdout)
        for key in ("run all", "files tree", "test unit", "samples check"):
            self.assertIn(key, r.stdout, f"速查表缺少 {key}")

    def test_menu_short_command_direct_files_tree(self):
        """短命令直达: 主菜单直接输入 files tree，输出四区文件树 JSON。"""
        r = self._menu(["files tree", "0"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('"tree"', r.stdout)
        self.assertIn("已退出控制台", r.stdout)

    def test_menu_short_command_direct_reports_list(self):
        r = self._menu(["reports list", "q"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("reports", r.stdout)

    def test_menu_launch_status_line_has_env(self):
        """启动主菜单自动执行轻量检测，状态行展示平台与环境状态。"""
        r = self._menu(["0"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[状态]", r.stdout)
        self.assertIn("平台", r.stdout)
        self.assertIn("环境", r.stdout)

    def test_menu_short_command_env_full_check(self):
        """短命令直达: 主菜单输入 env 执行完整环境检测（复用 check_env）。"""
        r = self._menu(["env", "0"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("环境预检", r.stdout)
        self.assertIn("检查汇总", r.stdout)

    def test_menu_option_11_runs_env_check(self):
        """主菜单数字 11 = 环境检测（env 恒为末位编号，qoder 域加入后为 11）。"""
        r = self._menu(["11", "0"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("环境预检", r.stdout)
        self.assertIn("检查汇总", r.stdout)

    def test_menu_submenu_navigate_and_back(self):
        """数字 1 进入 run 域子菜单，0 返回主菜单，0 退出。"""
        r = self._menu(["1", "0", "0"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("主菜单 > run 域", r.stdout)
        # 返回后主菜单再次出现（标题出现次数 >= 2）
        self.assertGreaterEqual(r.stdout.count("方寸观察者 命令行控制台"), 2)

    def test_menu_quit_aliases(self):
        for alias in ("q", "quit", "exit"):
            r = self._menu([alias])
            self.assertEqual(r.returncode, 0, f"{alias} 退出失败: {r.stderr}")
            self.assertIn("已退出控制台", r.stdout)


class TestObserverCompatibility(unittest.TestCase):
    """兼容性回归: main.py 旧用法保持可用，observer run 输出一致。"""

    @classmethod
    def setUpClass(cls):
        cls._tmp_main = tempfile.TemporaryDirectory()
        cls._tmp_obs = tempfile.TemporaryDirectory()
        cls.main_result = _run(
            [MAIN_PY, "--scenario", "n01", "--output", cls._tmp_main.name])
        cls.obs_result = _run(
            [OBSERVER, "run", "--scenario", "n01", "--output", cls._tmp_obs.name])

    @classmethod
    def tearDownClass(cls):
        cls._tmp_main.cleanup()
        cls._tmp_obs.cleanup()

    def test_main_py_scenario_n01_exit_zero(self):
        self.assertEqual(self.main_result.returncode, 0,
                         self.main_result.stderr.decode("utf-8", "replace"))

    def test_observer_run_exit_zero(self):
        self.assertEqual(self.obs_result.returncode, 0,
                         self.obs_result.stderr.decode("utf-8", "replace"))

    def test_observer_run_and_main_output_structure_identical(self):
        files_obs = _rel_files(self._tmp_obs.name)
        files_main = _rel_files(self._tmp_main.name)
        self.assertTrue(files_obs, "observer run 输出目录为空")
        self.assertEqual(files_obs, files_main,
                         "observer run 与 main.py 输出目录结构不一致")


if __name__ == "__main__":
    unittest.main()
