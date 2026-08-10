"""
conftest.py — pytest 配置 + unit_test 输出管理 + Monitor 生命周期管理

功能:
1. 每次运行单元测试前清空 output/unit_test/ 中的旧结果
2. 将最新的 pytest 运行结果写入 output/unit_test/
3. 该文件夹始终只保留最近一次的测试结果
4. 提供 Monitor 生命周期 fixture，自动管理测试中的 Monitor 启停

注意:
  录制和实时监测功能拥有独立的手动启停控制，
  不应被自动启停机制干扰。自动启停仅用于需要 Monitor 的测试场景。
"""

import os
import sys
import shutil
import pytest

# 确保项目路径在 sys.path 中
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

# 延迟导入，避免阻塞 pytest 插件加载
_monitor_lifecycle_manager = None


def _get_lifecycle_manager():
    """延迟获取 MonitorLifecycleManager 单例"""
    global _monitor_lifecycle_manager
    if _monitor_lifecycle_manager is None:
        from monitor_lifecycle import MonitorLifecycleManager
        _monitor_lifecycle_manager = MonitorLifecycleManager.instance()
    return _monitor_lifecycle_manager


# ── Monitor 生命周期 fixtures ────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def monitor_session_cleanup():
    """
    Session 级 fixture: 测试会话开始前清理残留 Monitor，结束后清理。
    autouse=True 确保不依赖显式引用。
    """
    mgr = _get_lifecycle_manager()
    # 启动前清理 (不干扰正在运行的手动 Monitor)
    mgr.startup_cleanup()
    yield
    # 会话结束后确保清理
    mgr.shutdown()


@pytest.fixture
def monitor_for_test():
    """
    Function 级 fixture: 为需要 Monitor 的测试提供自动启停。

    用法:
        def test_xxx(monitor_for_test):
            # Monitor 已启动并在测试结束后自动停止
            mgr = MonitorLifecycleManager.instance()
            assert mgr.status()["monitor_running"]
    """
    mgr = _get_lifecycle_manager()
    mgr.startup_cleanup()
    status = mgr.start_monitor()
    if not status or not status.get("monitor_running"):
        pytest.skip("Monitor 启动失败，跳过依赖 Monitor 的测试")
    yield mgr
    mgr.stop_monitor_forced()


def _get_unit_test_dir() -> str:
    """获取 unit_test 输出目录路径"""
    output_dir = os.path.join(PROJECT_DIR, "output", "unit_test")
    return output_dir


def _clear_unit_test_dir(unit_test_dir: str):
    """清空 unit_test 目录中的旧结果（兼容 sudo 遗留的 root 权限文件）"""
    if os.path.exists(unit_test_dir):
        def _on_error(func, path, exc_info):
            """权限不足时尝试 chmod 后重试"""
            try:
                os.chmod(path, 0o777)
                func(path)
            except PermissionError:
                pass  # 非 root 无法删除 root 文件，跳过
        shutil.rmtree(unit_test_dir, onerror=_on_error)
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

        summary = {
            "session_time": datetime.now().isoformat(),
            "total": len(set(r["nodeid"] for r in self._results if r["when"] == "call")),
            "passed": sum(1 for r in self._results if r["when"] == "call" and r["outcome"] == "passed"),
            "failed": sum(1 for r in self._results if r["when"] == "call" and r["outcome"] == "failed"),
            "skipped": sum(1 for r in self._results if r["when"] == "call" and r["outcome"] == "skipped"),
            "details": self._results,
        }

        # 写入测试结果 JSON
        results_path = os.path.join(self._dir, "test_results.json")
        try:
            with open(results_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, ensure_ascii=False, indent=2)
        except PermissionError:
            # 目录可能由 root 创建，尝试临时目录
            import tempfile
            fallback = os.path.join(tempfile.gettempdir(), "observer_unit_test")
            os.makedirs(fallback, exist_ok=True)
            results_path = os.path.join(fallback, "test_results.json")
            with open(results_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, ensure_ascii=False, indent=2)

        # 写入可读的文本摘要
        txt_path = results_path.replace(".json", ".txt")
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
