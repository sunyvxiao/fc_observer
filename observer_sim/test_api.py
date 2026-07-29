"""test_api.py — Phase 1 API 验证脚本"""
import urllib.request
import urllib.error
import json
import sys

BASE = "http://localhost:8080"
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

print(f"\n=== Results: {passed} passed, {failed} failed ===")
sys.exit(1 if failed > 0 else 0)
