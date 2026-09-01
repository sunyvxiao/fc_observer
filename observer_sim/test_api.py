"""test_api.py — Phase 1 API 验证脚本

冒烟脚本：需先启动 Web 服务。
- 独立运行: python test_api.py（默认 localhost:8080）
- 统一入口: python main.py test api（自动拉起/关闭服务，端口经 argv 传入）
"""
import urllib.request
import urllib.error
import json
import sys

_port = sys.argv[1] if len(sys.argv) > 1 else "8080"
BASE = f"http://localhost:{_port}"
passed = 0
failed = 0

def test(name, url, check_fn=None, method="GET", body=None, expect_error=False):
    global passed, failed
    try:
        if method == "POST":
            data = json.dumps(body or {}).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        else:
            req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req)
        ct = resp.headers.get("Content-Type", "")
        if "json" in ct:
            result = json.loads(resp.read())
        else:
            result = resp.read().decode("utf-8", errors="replace")
        if check_fn and not check_fn(result):
            print(f"  FAIL: {name} — check function returned False")
            failed += 1
            return
        print(f"  PASS: {name}")
        passed += 1
    except urllib.error.HTTPError as e:
        if expect_error:
            try:
                result = json.loads(e.read())
            except Exception:
                result = {}
            if check_fn and not check_fn(result, e.code):
                print(f"  FAIL: {name} — check function returned False (HTTP {e.code})")
                failed += 1
                return
            print(f"  PASS: {name} (HTTP {e.code})")
            passed += 1
        else:
            print(f"  FAIL: {name} — HTTP {e.code}: {e.reason}")
            failed += 1
    except Exception as e:
        print(f"  FAIL: {name} — {e}")
        failed += 1

print("=== Phase 1 API Tests ===\n")

# 1. Health
test("GET /api/health", f"{BASE}/api/health",
     lambda d: d.get("status") == "ok")

# 2. Categories
test("GET /api/categories", f"{BASE}/api/categories",
     lambda d: len(d.get("categories", [])) == 5
               and sum(c["count"] for c in d["categories"]) == 37)

# 3. Scenarios - anomalous
test("GET /api/scenarios?category=anomalous", f"{BASE}/api/scenarios?category=anomalous",
     lambda d: len(d.get("scenarios", [])) == 12)

# 4. Scenarios - normal
test("GET /api/scenarios?category=normal", f"{BASE}/api/scenarios?category=normal",
     lambda d: len(d.get("scenarios", [])) == 8)

# 5. Scenarios - all
test("GET /api/scenarios (all)", f"{BASE}/api/scenarios",
     lambda d: len(d.get("scenarios", [])) == 37)

# 6. Reports list
test("GET /api/reports/list", f"{BASE}/api/reports/list",
     lambda d: "categories" in d)

# 7. Reports view - path traversal protection (403)
test("GET /api/reports/view (traversal 403)", f"{BASE}/api/reports/view?path=../../config.yaml",
     lambda d, code: code == 403 and "traversal" in d.get("error", "").lower(),
     expect_error=True)

# 8. Reports view - missing path (400)
test("GET /api/reports/view (no path 400)", f"{BASE}/api/reports/view",
     lambda d, code: code == 400, expect_error=True)

# 9. 404 handling
test("GET /api/nonexistent (404)", f"{BASE}/api/nonexistent",
     lambda d, code: code == 404, expect_error=True)

# 10. POST tests/run
print("\n  [Running unit tests via API — this takes ~10s...]")
test("POST /api/tests/run", f"{BASE}/api/tests/run",
     lambda d: d.get("passed", 0) >= 130 and d.get("status") in ("completed",),
     method="POST")

# 11. POST reports/delete (dry — nothing to delete for 'extreme')
test("POST /api/reports/delete (extreme)", f"{BASE}/api/reports/delete",
     lambda d: d.get("success") is True,
     method="POST", body={"scope": "category", "category": "extreme"})

# 12. Static file (index.html)
test("GET / (index.html)", f"{BASE}/",
     lambda d: "方寸观察者" in d)

# 13. Scenario result (non-existent)
test("GET /api/scenario/result/xxx", f"{BASE}/api/scenario/result/xxx",
     lambda d: "error" in d or d.get("status") == "not_found")

# 14. Qoder CN 监测: 状态（独立通道，不复用 WorkBuddy 网关）
test("GET /api/qoder-monitor/status", f"{BASE}/api/qoder-monitor/status",
     lambda d: "daemon_running" in d and "channels" in d
               and "tasks" in d and "sse_reserved" in d)

# 15. Qoder CN 监测: 审计事件尾随（轮询数据源，兼作 SSE 降级兜底）
test("GET /api/qoder-monitor/events?tail=5", f"{BASE}/api/qoder-monitor/events?tail=5",
     lambda d: isinstance(d.get("events"), list)
               and set(d.get("counts", {})) == {"allow", "alert", "block", "total"})

# 16. Qoder CN 监测: 产物清单
test("GET /api/qoder-monitor/artifacts", f"{BASE}/api/qoder-monitor/artifacts",
     lambda d: isinstance(d.get("artifacts"), list))

# 17. Qoder CN 监测: 模拟注入（daemon 未启动时确定性返回 unreachable）
test("POST /api/qoder-monitor/simulate (unreachable)", f"{BASE}/api/qoder-monitor/simulate",
     lambda d: d.get("status") in ("unreachable", "accepted")
               and d.get("sent") in (True, False),
     method="POST", body={"tool_name": "read_file",
                          "tool_args": {"file_path": "observer_sim/config.yaml"}})

# 18. Qoder CN 监测: 模拟注入缺 tool_name → 结构化拒绝
test("POST /api/qoder-monitor/simulate (missing tool)", f"{BASE}/api/qoder-monitor/simulate",
     lambda d: d.get("status") == "rejected"
               and d.get("reason") == "missing_tool_name",
     method="POST", body={})

# 19. Qoder CN 监测: SSE 事件流（已实现，验证 text/event-stream 与 connected 首帧）
def _check_sse_stream():
    try:
        req = urllib.request.Request(f"{BASE}/api/qoder-monitor/events/stream")
        resp = urllib.request.urlopen(req, timeout=8)
        ctype = resp.headers.get("Content-Type", "")
        line = resp.readline().decode("utf-8", errors="replace")
        resp.close()
        return ("text/event-stream" in ctype and line.startswith("data: ")
                and '"type": "connected"' in line)
    except Exception as e:
        print(f"  FAIL: GET /api/qoder-monitor/events/stream — {e}")
        return None

_sse_r = _check_sse_stream()
if _sse_r is None:
    failed += 1
elif _sse_r:
    print("  PASS: GET /api/qoder-monitor/events/stream (SSE connected 首帧)")
    passed += 1
else:
    print("  FAIL: GET /api/qoder-monitor/events/stream — 首帧不符合预期")
    failed += 1

print(f"\n=== Results: {passed} passed, {failed} failed ===")
sys.exit(1 if failed > 0 else 0)
