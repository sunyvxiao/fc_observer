"""
conftest.py — pytest 配置 + unit_test 输出管理

功能:
1. 每次运行单元测试前清空 output/unit_test/ 中的旧结果
2. 将最新的 pytest 运行结果写入 output/unit_test/
3. 该文件夹始终只保留最近一次的测试结果
"""

import os
import sys
import shutil
import pytest

# 确保项目路径在 sys.path 中
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)


def _get_unit_test_dir() -> str:
    """获取 unit_test 输出目录路径"""
    output_dir = os.path.join(PROJECT_DIR, "output", "unit_test")
    return output_dir


def _clear_unit_test_dir(unit_test_dir: str):
    """清空 unit_test 目录中的旧结果"""
    if os.path.exists(unit_test_dir):
        shutil.rmtree(unit_test_dir)
    os.makedirs(unit_test_dir, exist_ok=True)


class UnitTestReportWriter:
    """将 pytest 运行结果写入 output/unit_test/ 目录"""

    def __init__(self, unit_test_dir: str):
        self._dir = unit_test_dir
        self._results = []

    def pytest_runtest_logreport(self, report):
        """收集每个测试的结果"""
        self._results.append({
            "nodeid": report.nodeid,
            "outcome": report.outcome,
            "when": report.when,
            "duration": report.duration,
            "longrepr": str(report.longrepr) if report.longrepr else "",
        })

    def pytest_sessionfinish(self, session):
        """会话结束后写入结果文件"""
        import json
        from datetime import datetime

        # 写入测试结果 JSON
        results_path = os.path.join(self._dir, "test_results.json")
        summary = {
            "session_time": datetime.now().isoformat(),
            "total": len(set(r["nodeid"] for r in self._results if r["when"] == "call")),
            "passed": sum(1 for r in self._results if r["when"] == "call" and r["outcome"] == "passed"),
            "failed": sum(1 for r in self._results if r["when"] == "call" and r["outcome"] == "failed"),
            "skipped": sum(1 for r in self._results if r["when"] == "call" and r["outcome"] == "skipped"),
            "details": self._results,
        }
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

        # 写入可读的文本摘要
        txt_path = os.path.join(self._dir, "test_output.txt")
        lines = [
            f"pytest 运行结果 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"通过: {summary['passed']}  失败: {summary['failed']}  跳过: {summary['skipped']}",
            "=" * 60,
        ]
        for r in self._results:
            if r["when"] == "call":
                status = r["outcome"].upper()
                lines.append(f"  [{status:6s}] {r['nodeid']} ({r['duration']:.3f}s)")
                if r["longrepr"]:
                    lines.append(f"          {r['longrepr'][:200]}")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


# === pytest hooks ===

def pytest_configure(config):
    """pytest 启动时清空 unit_test 目录"""
    unit_test_dir = _get_unit_test_dir()
    _clear_unit_test_dir(unit_test_dir)
    # 注册报告写入插件
    writer = UnitTestReportWriter(unit_test_dir)
    config.pluginmanager.register(writer, "unit_test_report_writer")


def pytest_collection_modifyitems(config, items):
    """测试收集完成后显示信息"""
    unit_test_dir = _get_unit_test_dir()
    print(f"\n[unit_test] 输出目录: {unit_test_dir}")
    print(f"[unit_test] 收集到 {len(items)} 个测试用例")
