"""test_sse.py — Phase 2 SSE 验证脚本"""
import urllib.request
import json
import sys

BASE = "http://localhost:8080"
passed = 0
failed = 0

def check(name, condition):
    global passed, failed
    if condition:
        print(f"  PASS: {name}")
        passed += 1
    else:
        print(f"  FAIL: {name}")
        failed += 1

print("=== Phase 2 SSE Tests ===\n")

# 1. Start scenario a01
print("[1] POST /api/scenario/run (a01)")
try:
    data = json.dumps({"scenario_id": "a01", "category": "anomalous"}).encode("utf-8")
    req = urllib.request.Request(f"{BASE}/api/scenario/run", data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read())
    run_id = result.get("run_id", "")
    check("run response has run_id", bool(run_id))
    check("status is running", result.get("status") == "running")
    print(f"       run_id = {run_id}")
except Exception as e:
    check("start scenario", False)
    print(f"       error: {e}")
    sys.exit(1)

def read_sse_events(resp, timeout=30):
    """Read SSE events from response until done/error or timeout"""
    import time
    events = []
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = resp.read(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n\n" in buf:
                event_text, buf = buf.split(b"\n\n", 1)
                for line in event_text.decode("utf-8", errors="replace").split("\n"):
                    if line.startswith("data: "):
                        try:
                            events.append(json.loads(line[6:]))
                        except json.JSONDecodeError:
                            pass
                if events and events[-1].get("type") in ("done", "error"):
                    return events
        except Exception:
            break
    return events
# 2. Connect SSE and read events
print("\n[2] GET /api/scenario/stream/{run_id} (SSE)")
try:
    req = urllib.request.Request(f"{BASE}/api/scenario/stream/{run_id}")
    resp = urllib.request.urlopen(req, timeout=30)
    ct = resp.headers.get("Content-Type", "")
    if "event-stream" in ct:
        events = read_sse_events(resp)
    else:
        # Scenario completed before SSE connected, returned as JSON
        result = json.loads(resp.read())
        events = [{"type": "done", "analysis_panel": result.get("analysis_panel", {}),
                   "files_generated": result.get("files_generated", []),
                   "statistics": result.get("statistics", {})}]
        print("       (scenario already completed, got JSON result)")

    steps = [e for e in events if e.get("type") == "step"]
    done = [e for e in events if e.get("type") == "done"]

    check("received step or done events", len(steps) > 0 or len(done) > 0)

    if steps:
        s = steps[0]
        check("step has seq field", "seq" in s)
        check("step has total field", "total" in s)
        check("step has event_type field", "event_type" in s)
        check("step has risk_score field", "risk_score" in s)
        check("step has decision_action field", "decision_action" in s)
        check("step has rule_match field", "rule_match" in s)
        print(f"       first step: seq={s.get('seq')}/{s.get('total')}, "
              f"action={s.get('decision_action')}, score={s.get('risk_score'):.2f}")
    else:
        print("       (no step events - scenario completed before SSE connected)")

    check("received done event", len(done) == 1)
    if done:
        d = done[0]
        check("done has analysis_panel", "analysis_panel" in d)
        check("done has files_generated", "files_generated" in d)
        check("done has statistics", "statistics" in d)
        if "analysis_panel" in d:
            panel = d["analysis_panel"]
            check("panel has test_purpose", "test_purpose" in panel)
            check("panel test_purpose non-empty", bool(panel.get("test_purpose")))
            print(f"       purpose: {panel.get('test_purpose', '')[:60]}")

except Exception as e:
    check("SSE stream", False)
    print(f"       error: {e}")

# 3. Check result endpoint after completion
print(f"\n[3] GET /api/scenario/result/{run_id}")
try:
    resp = urllib.request.urlopen(f"{BASE}/api/scenario/result/{run_id}")
    result = json.loads(resp.read())
    check("result status is completed", result.get("status") == "completed")
    check("result has analysis_panel", "analysis_panel" in result)
except Exception as e:
    check("result endpoint", False)
    print(f"       error: {e}")

# 4. Test scenario n01 (normal - should have all ALLOW)
print("\n[4] POST /api/scenario/run (n01 - normal)")
try:
    data = json.dumps({"scenario_id": "n01", "category": "normal"}).encode("utf-8")
    req = urllib.request.Request(f"{BASE}/api/scenario/run", data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    resp = urllib.request.urlopen(req)
    result = json.loads(resp.read())
    run_id2 = result.get("run_id", "")

    req2 = urllib.request.Request(f"{BASE}/api/scenario/stream/{run_id2}")
    resp2 = urllib.request.urlopen(req2, timeout=30)
    ct2 = resp2.headers.get("Content-Type", "")
    if "event-stream" in ct2:
        events2 = read_sse_events(resp2)
    else:
        result2 = json.loads(resp2.read())
        events2 = [{"type": "done", "statistics": result2.get("statistics", {})}]
        print("       (n01 already completed, got JSON)")

    steps2 = [e for e in events2 if e.get("type") == "step"]
    done2 = [e for e in events2 if e.get("type") == "done"]
    if steps2:
        all_allow = all(e.get("decision_action") == "ALLOW" for e in steps2)
        check(f"n01: all events ALLOW ({len(steps2)} events)", all_allow)
    elif done2:
        stats = done2[0].get("statistics", {})
        check("n01: stats show all allow (no blocks)", stats.get("block", 0) == 0 and stats.get("alert", 0) == 0)

except Exception as e:
    check("n01 scenario", False)
    print(f"       error: {e}")

print(f"\n=== Results: {passed} passed, {failed} failed ===")
sys.exit(1 if failed > 0 else 0)
