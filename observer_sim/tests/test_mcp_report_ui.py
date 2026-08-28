# -*- coding: utf-8 -*-
"""
test_mcp_report_ui.py — MCP 申报降级监测统一入口（CLI + Web）测试

覆盖统一入口集成的两个面:
1. CLI 侧（console.py）: mcp 域菜单存在性 / 子菜单渲染（URL 与 agent_id
   从 workbuddy_connect.yaml 动态读取）/ 短命令转发与未知命令拒绝。
2. Web 侧（app.py + mcp_report_gateway.py）: /api/mcp-report/* 四类查询
   端点与 start/stop/smoke 三个动作端点的完整生命周期闭环。

独立性: Web 生命周期测试不干扰用户已运行的 daemon ——
daemon 已在运行时仅执行只读烟测（smoke），未运行时完整走
start → smoke → stop 闭环；端口与路径全部来自 workbuddy_connect.yaml，
测试不硬编码。
"""

import json
import os
import socket
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import console  # noqa: E402
import connect_workbuddy as cw  # noqa: E402
import mcp_report_gateway as gw  # noqa: E402


# ── 工具函数 ────────────────────────────────────────────────────────

def _http_json(url, method="GET", body=None, timeout=20):
    """发起 JSON 请求并返回 (status, data)。非 2xx 抛 HTTPError。"""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = Request(url, data=data, method=method,
                  headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def _wait_web_task(base, name, timeout=90.0):
    """轮询 /api/mcp-report/task?name=... 直到 done。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _, data = _http_json(f"{base}/api/mcp-report/task?name={name}")
        except OSError:
            time.sleep(0.5)
            continue
        if data.get("done"):
            return data
        time.sleep(1.0)
    pytest.fail(f"后台任务 {name} 未在 {timeout}s 内完成")


def _wait_daemon_state(base, running, timeout=90.0):
    """轮询 /api/mcp-report/status 直到 daemon_running 达到期望值。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _, data = _http_json(f"{base}/api/mcp-report/status")
        except OSError:
            time.sleep(0.5)
            continue
        if bool(data.get("daemon_running")) is running:
            return data
        time.sleep(1.0)
    pytest.fail(f"daemon 未在 {timeout}s 内达到 running={running}")


# ── Web 测试服务器 fixture ──────────────────────────────────────────

@pytest.fixture(scope="module")
def web_base():
    """在自由端口起一个真实 Web 服务（app.ObserverHTTPHandler）。"""
    import app
    server = ThreadingHTTPServer(("127.0.0.1", 0), app.ObserverHTTPHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


# ── 1. CLI 集成（console.py mcp 域）─────────────────────────────────

class TestCliMcpDomain:
    """mcp 域菜单存在性 / 子命令 / 渲染 / 转发。"""

    def test_domains_include_mcp(self):
        """DOMAINS 含 mcp 域（主菜单可见）。"""
        keys = [d[0] for d in console.DOMAINS]
        assert "mcp" in keys, f"DOMAINS 缺少 mcp 域: {keys}"
        mcp_entry = [d for d in console.DOMAINS if d[0] == "mcp"][0]
        assert "MCP 申报监测" in mcp_entry[1], (
            f"mcp 域标题异常: {mcp_entry}")

    def test_mcp_subcommands_complete(self):
        """短命令集包含启动/停止/状态/自检/烟测/日志/报告与 WorkBuddy 配置类。"""
        for name in ("start", "stop", "status", "check", "smoke",
                     "logs", "report", "configure-workbuddy",
                     "unconfigure-workbuddy", "launch-workbuddy",
                     "restart-workbuddy"):
            assert name in console._MCP_SUBCOMMANDS, (
                f"_MCP_SUBCOMMANDS 缺少 {name}")

    def test_render_domain_mcp_menu(self, capsys):
        """子菜单渲染 7 个入口，URL/agent_id 从 yaml 动态读取（非硬编码）。"""
        cfg = cw.load_config(cw.DEFAULT_CONFIG)
        expect_url = (f"http://{cfg['server']['host']}:"
                      f"{int(cfg['server']['port'])}{cfg['server']['sse_path']}")
        expect_agent = cfg["workbuddy"]["agent_id"]
        console._render_domain("mcp")
        out = capsys.readouterr().out
        for label in ("启动 MCP 申报 daemon", "停止 daemon 并生成报告",
                      "状态查看", "连通性自检", "申报烟测",
                      "查看 daemon 日志", "报告产物"):
            assert label in out, f"mcp 子菜单缺少入口: {label}"
        assert expect_url in out, (
            f"子菜单未展示配置 URL {expect_url}（疑似硬编码）:\n{out}")
        assert f"agent_id: {expect_agent}" in out, (
            f"子菜单未展示配置 agent_id {expect_agent}:\n{out}")

    def test_exec_mcp_unknown_rejected(self, capsys):
        """未知短命令被拒绝并给出可用命令提示。"""
        console._exec_mcp("bogus-cmd")
        out = capsys.readouterr().out
        assert "未知 mcp 命令" in out, f"未知命令未被拒绝:\n{out}"
        assert "smoke" in out, f"拒绝提示缺少可用命令清单:\n{out}"

    def test_exec_mcp_status_forwards(self, capsys):
        """status 短命令真实转发 connect_workbuddy.py（只读、无副作用）。"""
        console._exec_mcp("status")
        out = capsys.readouterr().out
        assert ">>> MCP 申报监测: status" in out, (
            f"未进入 mcp 转发分支:\n{out}")
        assert "返回菜单" in out or "退出码" in out, (
            f"转发未完成（缺收尾提示）:\n{out}")


# ── 2. Web 查询端点（app.py /api/mcp-report/*）──────────────────────

class TestWebApiEndpoints:
    """status / artifacts / logs / task 查询端点结构正确性。"""

    def test_status_endpoint(self, web_base):
        """GET /api/mcp-report/status 返回通道状态 + 后台任务。"""
        status, data = _http_json(f"{web_base}/api/mcp-report/status")
        assert status == 200, f"HTTP {status}"
        assert "daemon_running" in data, f"缺少 daemon_running: {data}"
        assert data["server"].get("url", "").startswith("http://127.0.0.1"), (
            f"server.url 异常: {data.get('server')}")
        assert data.get("agent_id"), f"缺少 agent_id: {data}"
        assert set(data.get("tasks", {})) == {"start", "stop", "smoke"}, (
            f"tasks 键异常: {data.get('tasks')}")

    def test_artifacts_endpoint(self, web_base):
        """GET /api/mcp-report/artifacts 返回产物目录与清单结构。"""
        status, data = _http_json(f"{web_base}/api/mcp-report/artifacts")
        assert status == 200, f"HTTP {status}"
        assert "output_dir" in data, f"缺少 output_dir: {data}"
        assert "artifacts" in data and isinstance(data["artifacts"], list), (
            f"artifacts 结构异常: {data}")

    def test_logs_endpoint(self, web_base):
        """GET /api/mcp-report/logs 返回日志路径与文本。"""
        status, data = _http_json(f"{web_base}/api/mcp-report/logs")
        assert status == 200, f"HTTP {status}"
        assert "log_path" in data and "lines" in data, (
            f"logs 结构异常: {data}")

    def test_task_endpoint(self, web_base):
        """GET /api/mcp-report/task?name=smoke 返回任务状态结构。"""
        status, data = _http_json(
            f"{web_base}/api/mcp-report/task?name=smoke")
        assert status == 200, f"HTTP {status}"
        for key in ("running", "done"):
            assert key in data, f"任务状态缺少 {key}: {data}"

    def test_unknown_route_404(self, web_base):
        """未知 mcp-report 路由返回 404 且不破坏服务。"""
        with pytest.raises(HTTPError) as exc:
            _http_json(f"{web_base}/api/mcp-report/bogus")
        assert exc.value.code == 404, f"期望 404，实际 {exc.value.code}"

    def test_files_tree_includes_mcp_monitoring(self, web_base):
        """统一文件管理树纳入 mcp_monitoring 分区（产物存在时）。"""
        out_dir = cw._out_paths(cw.load_config(cw.DEFAULT_CONFIG))[0]
        if not os.path.isdir(out_dir) or not os.listdir(out_dir):
            pytest.skip("output/mcp_monitoring 为空或不存在")
        status, data = _http_json(f"{web_base}/api/files/tree")
        assert status == 200, f"HTTP {status}"
        assert "mcp_monitoring" in data.get("tree", {}), (
            f"文件树缺少 mcp_monitoring 分区: {list(data.get('tree', {}))}")


# ── 3. Web 生命周期闭环（start → smoke → stop → 产物）───────────────

def test_web_lifecycle_flow(web_base):
    """Web 入口完整闭环: 启动 daemon → 申报烟测(5/2+判定) → 优雅停止 → 报告产物。

    daemon 已在运行时（用户手动启动）不重复 start/stop，仅做只读烟测。
    """
    base = web_base

    # 3.1 当前状态（若用户 daemon 已在运行，走只读分支）
    _, init = _http_json(f"{base}/api/mcp-report/status")
    if init.get("daemon_running"):
        print("[提示] daemon 已在运行（可能为用户手动启动），"
              "本测试仅执行只读烟测，不重复 start/stop")
        already_running = True
    else:
        already_running = False

    if not already_running:
        # 3.2 POST /api/mcp-report/start → 后台任务 → 轮询至端口就绪
        status, resp = _http_json(f"{base}/api/mcp-report/start",
                                  method="POST", body={})
        assert status == 200 and resp.get("accepted"), (
            f"start 未被接受: {resp}")
        task = _wait_web_task(base, "start", timeout=120.0)
        assert not task.get("error"), f"start 任务失败: {task}"
        assert task["detail"].get("success"), (
            f"start 未成功: {task['detail']}")
        _wait_daemon_state(base, True)

    try:
        # 3.3 POST /api/mcp-report/smoke → 等待任务完成 → 5 accepted + 2 rejected
        status, resp = _http_json(f"{base}/api/mcp-report/smoke",
                                  method="POST", body={})
        assert status == 200 and resp.get("accepted"), (
            f"smoke 未被接受: {resp}")
        task = _wait_web_task(base, "smoke", timeout=120.0)
        assert not task.get("error"), f"smoke 任务失败: {task}"
        detail = task["detail"]
        assert detail.get("ok"), (
            f"烟测未通过（期望 5 accepted + 2 rejected 且有判定）: {detail}")
        assert detail["accepted"] == 5 and detail["rejected"] == 2, (
            f"申报计数异常: {detail}")
        assert detail.get("verdicts"), (
            f"判定输出为空（ALLOW/ALERT/BLOCK）: {detail}")
    finally:
        if not already_running:
            # 3.4 POST /api/mcp-report/stop → 优雅停止并生成报告
            status, resp = _http_json(f"{base}/api/mcp-report/stop",
                                      method="POST", body={})
            assert status == 200 and resp.get("accepted"), (
                f"stop 未被接受: {resp}")
            task = _wait_web_task(base, "stop", timeout=120.0)
            assert not task.get("error"), f"stop 任务失败: {task}"
            assert task["detail"].get("success"), (
                f"stop 未成功: {task['detail']}")
            _wait_daemon_state(base, False)

    # 3.5 报告产物（output/mcp_monitoring）
    _, art = _http_json(f"{base}/api/mcp-report/artifacts")
    names = " ".join(a["name"] for a in art.get("artifacts", []))
    assert "risk_report" in names and ".md" in names, (
        f"缺风险报告产物: {art}")
    assert "monitoring_summary.json" in names, (
        f"缺监测汇总产物: {art}")
    assert ".jsonl" in names, f"缺审计日志产物: {art}"
