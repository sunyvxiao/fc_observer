"""
run_tests.py — 统一测试入口（单一事实来源）

收敛四个分散的测试入口:
  1. tests/ pytest 套件        ← 原: python -m pytest tests/
  2. test_api.py（API 冒烟）    ← 原: 手动先起服务再跑脚本
  3. test_sse.py（SSE 冒烟）    ← 原: 手动先起服务再跑脚本
  4. Web POST /api/tests/run    ← 委托 run_unit_tests()（本模块）

统一子命令（main.py）:
    python main.py test unit   # 单元测试（pytest 套件）
    python main.py test api    # API 冒烟（自动拉起/关闭服务）
    python main.py test sse    # SSE 冒烟（自动拉起/关闭服务）
    python main.py test all    # 依次执行 unit → api → sse

冒烟测试自动拉起服务:
    SmokeServer 以子进程方式启动 app.py（--no-browser，独立端口，
    避免与开发中的 8080 冲突），等待 /api/health 就绪后运行冒烟脚本，
    结束后通过 POST /api/server/stop 优雅停服，超时则 terminate 兜底。
"""

import os
import re
import sys
import json
import time
import subprocess
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SMOKE_PORT_DEFAULT = 18080      # 冒烟测试默认端口（避开开发用的 8080）
SERVER_START_TIMEOUT = 30.0     # 服务就绪等待上限（秒）
SERVER_STOP_TIMEOUT = 10.0      # 优雅停服等待上限（秒）
UNIT_TEST_TIMEOUT = 300         # pytest 超时（秒）


def run_unit_tests(failfast: bool = False) -> dict:
    """
    运行 tests/ 下的 pytest 套件。

    Args:
        failfast: True 时加 -x（首次失败即停，Web /api/tests/run 原行为）

    Returns:
        dict: {status, total, passed, failed, failed_names, duration_seconds, output}
    """
    cmd = [sys.executable, "-m", "pytest", "tests/", "-q"]
    if failfast:
        cmd = [sys.executable, "-m", "pytest", "tests/", "-x", "--tb=short", "-q"]
    start = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=UNIT_TEST_TIMEOUT, cwd=BASE_DIR,
            encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "total": 0, "passed": 0, "failed": 0,
            "failed_names": [],
            "duration_seconds": round(time.time() - start, 1),
            "output": f"pytest 超时（{UNIT_TEST_TIMEOUT}s）",
        }

    output = proc.stdout or ""
    passed, failed = 0, 0
    failed_names = []
    for line in output.split("\n"):
        line = line.strip()
        m_passed = re.search(r"(\d+) passed", line)
        m_failed = re.search(r"(\d+) failed", line)
        if m_passed:
            passed = int(m_passed.group(1))
        if m_failed:
            failed = int(m_failed.group(1))
        if line.startswith("FAILED"):
            parts = line.split("::", 1)
            if len(parts) > 1:
                failed_names.append(parts[-1].strip())

    return {
        "status": "completed" if proc.returncode == 0 else "failed",
        "total": passed + failed,
        "passed": passed,
        "failed": failed,
        "failed_names": failed_names,
        "duration_seconds": round(time.time() - start, 1),
        "output": output[-2000:],
    }


class SmokeServer:
    """冒烟测试用 Web 服务：自动拉起 / 优雅关闭。"""

    def __init__(self, port: int = SMOKE_PORT_DEFAULT):
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self.proc = None

    def start(self):
        """启动 app.py 子进程并等待 /api/health 就绪。"""
        self.proc = subprocess.Popen(
            [sys.executable, "app.py",
             "--host", "127.0.0.1",
             "--port", str(self.port),
             "--no-browser"],
            cwd=BASE_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + SERVER_START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"Web 服务启动失败（退出码 {self.proc.returncode}）")
            try:
                with urllib.request.urlopen(
                        f"{self.base_url}/api/health", timeout=2) as resp:
                    data = json.loads(resp.read())
                    if data.get("status") == "ok":
                        return
            except Exception:
                time.sleep(0.3)
        raise RuntimeError(f"Web 服务 {SERVER_START_TIMEOUT}s 内未就绪")

    def stop(self):
        """优先 POST /api/server/stop 优雅停服，超时则强杀兜底。"""
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/server/stop", data=b"{}",
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=SERVER_STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


def _run_smoke_script(script_name: str, port: int) -> int:
    """以子进程运行冒烟脚本（端口经 argv 传入），返回退出码。"""
    proc = subprocess.run(
        [sys.executable, script_name, str(port)],
        cwd=BASE_DIR,
    )
    return proc.returncode


def _run_smoke(script_name: str, port: int) -> bool:
    """拉起服务 → 运行冒烟脚本 → 关闭服务。返回是否全部通过。"""
    server = SmokeServer(port)
    print(f"\n[run_tests] 拉起 Web 服务: {server.base_url}")
    server.start()
    try:
        print(f"[run_tests] 运行冒烟脚本: {script_name}")
        code = _run_smoke_script(script_name, port)
        return code == 0
    finally:
        print("[run_tests] 关闭 Web 服务...")
        server.stop()


def run_api_smoke(port: int = SMOKE_PORT_DEFAULT) -> bool:
    """API 冒烟测试（test_api.py，自动拉起/关闭服务）。"""
    return _run_smoke("test_api.py", port)


def run_sse_smoke(port: int = SMOKE_PORT_DEFAULT) -> bool:
    """SSE 冒烟测试（test_sse.py，自动拉起/关闭服务）。"""
    return _run_smoke("test_sse.py", port)
