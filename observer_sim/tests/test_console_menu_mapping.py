"""
test_console_menu_mapping.py — 菜单「显示编号 ↔ 数字分派映射 ↔ 错误提示范围 ↔ 帮助表」一致性回归测试

背景: 菜单新增项后曾出现数字映射表漏改（daemon 第 5 项 record-testreport /
mcp 第 8 项 start-testreport 输入编号时报"无效选项"）。本文件对每个域做
四重校验，任何一处单独改动（渲染加项 / 分派漏项 / 提示范围过期 / 帮助表
漏命令）都会触发失败:

1. 渲染一致性: 捕获 _render_domain 输出解析编号，必须与 DOMAIN_TOKENS
   期望映射的编号集合完全一致（新增菜单项而未同步映射 → 集合不匹配）；
2. 分派行为: 每个编号输入必须路由到正确的 _exec_* 调用与参数；
3. 错误提示: 越界编号（N+1）必须提示 "请输入 1-N"（N 随映射表派生）；
4. 帮助表: _print_domain_help 的短命令片段必须覆盖该域全部可执行命令。
主菜单（_render_main / _dispatch_main / _print_main_help）同样校验。
"""

import contextlib
import io
import os
import re
import sys
import unittest
from unittest import mock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

import console  # noqa: E402

# 各域期望的编号 → 短命令映射（与 _render_domain 菜单项一一对应）。
# "<…>" 为交互式二次输入项（不直接对应 _exec_* 的单 token）。
DOMAIN_TOKENS = {
    "run": ["all", "<cat>", "<sid>"],
    "demo": ["menu", "<sid>", "<cat>"],
    "daemon": ["start", "record", "testreport", "report",
               "record-testreport"],
    "mcp": ["start", "stop", "status", "check", "smoke", "logs", "report",
            "start-testreport"],
    "serve": ["start", "nb", "api", "sse"],
    "files": ["tree", "view", "delete", "del-cat"],
    "reports": ["list", "view", "delete"],
    "samples": ["check", "gen", "rr"],
    "test": ["unit", "api", "sse", "all"],
}

# (域, 编号) → (执行函数名, 期望调用参数, [交互输入序列], 是否需要确认)。
# 交互输入序列缺省时统一 mock 为 "path1"；确认缺省时统一 mock 为 True
# （files 3 / reports 3 依赖确认放行才会调用 _exec_*）。
DISPATCH_SPEC = {
    ("run", "1"): ("_exec_run", "all"),
    ("run", "2"): ("_exec_run", "normal", ["normal"]),
    ("run", "3"): ("_exec_run", "n01", ["n01"]),
    ("demo", "1"): ("_exec_demo", "menu"),
    ("demo", "2"): ("_exec_demo", "n01", ["n01"]),
    ("demo", "3"): ("_exec_demo", "anomalous", ["anomalous"]),
    ("daemon", "1"): ("_exec_daemon", "start"),
    ("daemon", "2"): ("_exec_daemon", "record"),
    ("daemon", "3"): ("_exec_daemon", "testreport"),
    ("daemon", "4"): ("_exec_daemon", "report"),
    ("daemon", "5"): ("_exec_daemon", "record-testreport"),
    ("mcp", "1"): ("_exec_mcp", "start"),
    ("mcp", "2"): ("_exec_mcp", "stop"),
    ("mcp", "3"): ("_exec_mcp", "status"),
    ("mcp", "4"): ("_exec_mcp", "check"),
    ("mcp", "5"): ("_exec_mcp", "smoke"),
    ("mcp", "6"): ("_exec_mcp", "logs"),
    ("mcp", "7"): ("_exec_mcp", "report"),
    ("mcp", "8"): ("_exec_mcp", "start-testreport"),
    ("serve", "1"): ("_exec_serve", "start"),
    ("serve", "2"): ("_exec_serve", "nb"),
    ("serve", "3"): ("_exec_serve", "api"),
    ("serve", "4"): ("_exec_serve", "sse"),
    ("files", "1"): ("_exec_files", ["tree"]),
    ("files", "2"): ("_exec_files", ["view", "path1"], ["path1"]),
    ("files", "3"): ("_exec_files", ["delete", "path1"], ["path1"], True),
    ("files", "4"): ("_exec_files", ["del-cat"]),
    ("reports", "1"): ("_exec_reports", ["list"]),
    ("reports", "2"): ("_exec_reports", ["view", "path1"], ["path1"]),
    ("reports", "3"): ("_exec_reports", ["delete"]),
    ("samples", "1"): ("_exec_samples", "check"),
    ("samples", "2"): ("_exec_samples", "gen"),
    ("samples", "3"): ("_exec_samples", "rr"),
    ("test", "1"): ("_exec_test", "unit"),
    ("test", "2"): ("_exec_test", "api"),
    ("test", "3"): ("_exec_test", "sse"),
    ("test", "4"): ("_exec_test", "all"),
}

# 菜单编号以 CYAN 色打印（C(str(i) + '.', Colors.CYAN)），据此解析渲染输出。
_NUM_RE = re.compile(r"\x1b\[96m(\d+)\.\x1b\[0m")
# 帮助表短命令以 GREEN 色打印（\033[92m），据此解析帮助片段。
_HELP_RE = re.compile(r"\x1b\[92m(.*?)\x1b\[0m")


def _render_numbers(key):
    """捕获 _render_domain(key) 输出，返回菜单编号列表（字符串）。"""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        console._render_domain(key)
    return _NUM_RE.findall(buf.getvalue())


class TestDomainMenuConsistency(unittest.TestCase):
    """各域子菜单：显示编号 / 数字分派 / 错误提示范围 / 帮助表四重一致。"""

    def test_dispatch_spec_covers_all_domains(self):
        """DISPATCH_SPEC 的编号集合与 DOMAIN_TOKENS 完全一致。"""
        for key, tokens in DOMAIN_TOKENS.items():
            with self.subTest(key=key):
                spec_nums = sorted(
                    int(n) for k, n in DISPATCH_SPEC if k == key)
                self.assertEqual(spec_nums, list(range(1, len(tokens) + 1)),
                                 f"{key} 域 DISPATCH_SPEC 编号与期望映射脱节")

    def test_render_numbers_match_mapping(self):
        """菜单显示的编号集合必须与期望映射的编号集合一致（防新增项漏改）。"""
        for key, tokens in DOMAIN_TOKENS.items():
            with self.subTest(key=key):
                self.assertEqual(_render_numbers(key),
                                 [str(i) for i in range(1, len(tokens) + 1)],
                                 f"{key} 域菜单显示项数与数字映射脱节，"
                                 f"请同步更新映射表")

    def test_number_dispatch_routes_to_executors(self):
        """每个编号输入必须路由到正确的 _exec_* 调用与参数。"""
        for (key, num), spec in sorted(DISPATCH_SPEC.items()):
            func_name, expected = spec[0], spec[1]
            input_vals = spec[2] if len(spec) > 2 else None
            confirm_val = spec[3] if len(spec) > 3 else None
            with self.subTest(key=key, num=num):
                with mock.patch.object(console, func_name) as m_func, \
                        mock.patch.object(
                            console, "_input_path",
                            side_effect=input_vals
                            if input_vals is not None else ["path1"]), \
                        mock.patch.object(
                            console, "_confirm",
                            return_value=True
                            if confirm_val is None else confirm_val):
                    nav = console._dispatch_domain(key, num)
                self.assertIsNone(nav)
                m_func.assert_called_once_with(expected)

    def test_out_of_range_hint_matches_count(self):
        """越界编号（N+1）必须提示 1-N，N 与映射表长度一致。"""
        for key, tokens in DOMAIN_TOKENS.items():
            with self.subTest(key=key):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    nav = console._dispatch_domain(key, str(len(tokens) + 1))
                self.assertIsNone(nav)
                self.assertIn(f"请输入 1-{len(tokens)}", buf.getvalue(),
                              f"{key} 域越界提示范围与菜单项数脱节")

    def test_domain_help_covers_all_tokens(self):
        """域帮助表必须覆盖该域全部可执行短命令。"""
        for key, tokens in DOMAIN_TOKENS.items():
            with self.subTest(key=key):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    console._print_domain_help(key)
                frags = _HELP_RE.findall(buf.getvalue())
                heads = {f.split()[0] for f in frags if f.strip()}
                for tok in tokens:
                    if tok.startswith("<"):
                        continue  # 交互式占位项不要求出现在帮助表
                    self.assertIn(tok, heads,
                                  f"{key} 域帮助表缺少短命令 '{tok}'")


class TestMainMenuDispatch(unittest.TestCase):
    """主菜单：显示编号 / 数字分派（域 + 环境检测）/ 错误提示 / 主帮助表。"""

    def _plat(self):
        from adapter.platform_detect import PlatformInfo
        return PlatformInfo(platform="windows", is_windows=True,
                            is_linux=False, has_ebpf=False, has_strace=False)

    def _render_main_numbers(self):
        with mock.patch.object(console, "_get_platform",
                               return_value=self._plat()), \
                mock.patch.object(console, "_env_status_str",
                                  return_value="ok"), \
                mock.patch.object(console, "_count_scenarios",
                                  return_value=37):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                console._render_main()
        return _NUM_RE.findall(buf.getvalue())

    def test_main_menu_numbers_cover_domains_and_env(self):
        """主菜单编号 1..N 为域、N+1 为环境检测。"""
        n = len(console.DOMAINS)
        self.assertEqual(self._render_main_numbers(),
                         [str(i) for i in range(1, n + 2)])

    def test_main_dispatch_numbers_to_domains(self):
        """编号 1..N 进入对应域子菜单。"""
        for i, key in enumerate(console._DOMAIN_KEYS, 1):
            with self.subTest(key=key):
                self.assertEqual(console._dispatch_main(str(i)), "sub:" + key)

    def test_main_dispatch_env_number(self):
        """编号 N+1 执行环境检测。"""
        with mock.patch.object(console, "_exec_env") as m_env:
            nav = console._dispatch_main(str(len(console.DOMAINS) + 1))
        self.assertIsNone(nav)
        m_env.assert_called_once_with()

    def test_main_dispatch_out_of_range(self):
        """越界编号（N+2）提示 1-(N+1)。"""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            nav = console._dispatch_main(str(len(console.DOMAINS) + 2))
        self.assertIsNone(nav)
        self.assertIn(f"请输入 1-{len(console.DOMAINS) + 1}", buf.getvalue())

    def test_main_help_covers_all_domains_and_env(self):
        """主命令速查表覆盖全部域与 env 行。"""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            console._print_main_help()
        out = buf.getvalue()
        for key in console._DOMAIN_KEYS + ["env"]:
            with self.subTest(key=key):
                self.assertIn(f"\x1b[92m{key} ", out,
                              f"主命令速查表缺少 '{key}' 行")


if __name__ == "__main__":
    unittest.main()
