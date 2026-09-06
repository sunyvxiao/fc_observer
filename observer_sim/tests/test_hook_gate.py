# -*- coding: utf-8 -*-
"""
test_hook_gate.py — 拦截路径 hook 判定脚本单元测试（P0-6）

对应计划文档《监测与拦截解耦双路径_开发落地计划.md》§4 验收用例:
- TC-01 拦截 Read 受保护文件（脚本侧判定 deny + 留痕）
- TC-03 放行回归（非受保护路径 allow）
- TC-04a 失效语义（D-3）: 受保护资源 fail-closed
        （payload 解析失败 / 判定异常 → deny + gate_error）
- TC-04b 失效语义（D-3）: 非受保护资源 fail-open + 告警
        （留痕/通知失败不改决策，stderr + gate_error 标记 + 通知高优先级）
- TC-12 D-1 双协议: json 三态 / exit2 双态输出格式
        （宿主按语义执行与否在真实部署环节 TC-12 验证，此处验证脚本侧协议）
- TC-13 规则唯一基准（D-2）: 源码不含业务规则硬编码；
        改配置文件不改脚本 → 行为随配置变化
- TC-09 通知容错: 通知失败不阻塞判定（notify_url 指向不可达端口）
- P0-5  决策留痕格式: 字段完整性（三轨证据第 2 轨）
"""

import io
import json
import os
import re
import subprocess
import sys
import time

import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCKING_DIR = os.path.join(BASE_DIR, "observer_core", "blocking")
if BLOCKING_DIR not in sys.path:
    sys.path.insert(0, BLOCKING_DIR)

import hook_gate as hg  # noqa: E402

GATE_PATH = os.path.join(BLOCKING_DIR, "hook_gate.py")


# ── 工具 ───────────────────────────────────────────────────────────

def _mk_cfg(tmp_path, protocol="json", ask_enabled=False,
            extensions=(".pem",), protected=True):
    """构造临时 config.yaml（资源级红线指向 tmp 受保护目录），返回 cfg。

    notify_url 固定指向 127.0.0.1:1（未监听端口）→ 通知必失败，
    用于验证「通知失败不阻塞判定」（TC-09 容错）。
    """
    prot = tmp_path / "protected"
    prot.mkdir(exist_ok=True)
    (prot / "secret.pem").write_text("k", encoding="utf-8")
    (prot / "notes.txt").write_text("n", encoding="utf-8")
    sibling = tmp_path / "protected2"
    sibling.mkdir(exist_ok=True)
    (sibling / "secret.pem").write_text("s", encoding="utf-8")
    decisions = tmp_path / "out" / "hook_decisions.jsonl"
    ext_list = ", ".join(f"'{e}'" for e in extensions)
    paths = f"['{str(prot).replace(os.sep, '/')}']" if protected else "[]"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "hook:\n"
        f"  protocol: '{protocol}'\n"
        f"  ask_enabled: {'true' if ask_enabled else 'false'}\n"
        "  notify_url: 'http://127.0.0.1:1/hook'\n"
        "  notify_timeout_s: 0.5\n"
        f"  decisions_file: '{str(decisions).replace(os.sep, '/')}'\n"
        f"  protected_paths: {paths}\n"
        f"  protected_extensions: [{ext_list}]\n",
        encoding="utf-8")
    return hg.load_config(str(config_path))


def _payload(tool_name, tool_input, session_id="tc-test", cwd=""):
    return {"tool_name": tool_name, "tool_input": tool_input,
            "session_id": session_id, "cwd": cwd}


def _run_stdin(cfg, payload_dict, stdin_text=None):
    """模拟宿主 hook: stdin JSON 入 → run() 输出三件套。"""
    out, err = io.StringIO(), io.StringIO()
    text = stdin_text if stdin_text is not None else json.dumps(payload_dict)
    code, so, se = hg.run(text, cfg, out=out, err=err)
    return code, so, se, out.getvalue(), err.getvalue()


def _read_decisions(cfg):
    with open(cfg["decisions_file"], encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ── TC-01 / TC-03: 拦截与放行判定 ─────────────────────────────────

def test_tc01_read_protected_file_deny(tmp_path):
    """TC-01 脚本侧: Read 受保护目录下 .pem 文件 → deny + 留痕。"""
    cfg = _mk_cfg(tmp_path)
    prot = cfg["protected_paths"][0]
    code, so, se, stdout, stderr = _run_stdin(
        cfg, _payload("Read", {"file_path": os.path.join(prot, "secret.pem")}))
    assert code == 0, f"json 协议 deny 应 exit 0（实际 {code}）"
    decision = json.loads(so)
    hs = decision["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny", f"应 deny: {decision}"
    assert hs["hookEventName"] == "PreToolUse"
    assert "受保护资源" in hs["permissionDecisionReason"], (
        f"reason 应可解释: {hs['permissionDecisionReason']}")
    entries = _read_decisions(cfg)
    assert len(entries) == 1, f"应留痕 1 条: {entries}"
    e = entries[0]
    assert e["decision"] == "deny"
    assert e["tool_name"] == "Read"
    assert e["gate_error"] is False
    assert e["session_id"] == "tc-test"
    assert e["timestamp"] and e["event"] == "pre_tool_use"
    # TC-09 通知容错: 通知端点不可达不影响 deny 决策
    assert "notify failed" in stderr, "通知失败应在 stderr 记录（TC-09）"


def test_tc01_write_edit_protected_deny(tmp_path):
    """TC-02 脚本侧: Write/Edit 受保护文件 → deny。"""
    cfg = _mk_cfg(tmp_path)
    prot = cfg["protected_paths"][0]
    for tool in ("Write", "Edit"):
        code, so, _, _, _ = _run_stdin(
            cfg, _payload(tool, {"file_path": os.path.join(prot, "x.pem")}))
        assert code == 0
        hs = json.loads(so)["hookSpecificOutput"]
        assert hs["permissionDecision"] == "deny", f"{tool} 应 deny"


def test_tc03_non_protected_allow(tmp_path):
    """TC-03: 非受保护路径 → allow + 留痕（业务不中断）。"""
    cfg = _mk_cfg(tmp_path)
    prot = cfg["protected_paths"][0]
    code, so, _, _, _ = _run_stdin(
        cfg, _payload("Read",
                      {"file_path": os.path.join(prot, "notes.txt")}))
    assert code == 0
    hs = json.loads(so)["hookSpecificOutput"]
    assert hs["permissionDecision"] == "allow", "非受保护扩展名应 allow"
    entries = _read_decisions(cfg)
    assert entries[-1]["decision"] == "allow"


def test_sibling_dir_not_matched(tmp_path):
    """受保护目录的兄弟目录（如 protected2）不误伤（路径段边界）。"""
    cfg = _mk_cfg(tmp_path)
    prot = cfg["protected_paths"][0]
    sibling = prot + "2"
    code, so, _, _, _ = _run_stdin(
        cfg, _payload("Read", {"file_path": os.path.join(sibling,
                                                         "secret.pem")}))
    assert code == 0
    hs = json.loads(so)["hookSpecificOutput"]
    assert hs["permissionDecision"] == "allow", (
        f"兄弟目录 {sibling} 不应被命中: {so}")


def test_command_target_matched(tmp_path):
    """命令类工具（Bash/PowerShell）字符串目标含受保护目录+扩展名 → deny。"""
    cfg = _mk_cfg(tmp_path)
    prot = cfg["protected_paths"][0]
    cmd = f"type {prot}/secret.pem"
    code, so, _, _, _ = _run_stdin(
        cfg, _payload("PowerShell", {"command": cmd}))
    assert code == 0
    hs = json.loads(so)["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny", f"命令 {cmd} 应 deny"


def test_extract_target_fields():
    """入参字段级提取: Read/Write/Edit→file_path, Glob→pattern,
    Grep→path, Bash/PowerShell/Shell→command, 未知工具→None。"""
    assert hg.extract_target("Read", {"file_path": "a"}) == "a"
    assert hg.extract_target("Write", {"file_path": "b"}) == "b"
    assert hg.extract_target("Edit", {"file_path": "c"}) == "c"
    assert hg.extract_target("Glob", {"pattern": "d"}) == "d"
    assert hg.extract_target("Grep", {"path": "e"}) == "e"
    for t in ("Bash", "PowerShell", "Shell", "Command"):
        assert hg.extract_target(t, {"command": "f"}) == "f"
    assert hg.extract_target("UnknownTool", {"x": 1}) is None
    assert hg.extract_target("Read", "not-a-dict") is None


# ── TC-04a: 受保护资源 fail-closed ───────────────────────────────

def test_tc04a_payload_parse_fail_fail_closed(tmp_path):
    """TC-04a: stdin 非法 JSON → deny + gate_error 标记（fail-closed）。"""
    cfg = _mk_cfg(tmp_path)
    code, so, se, stdout, stderr = _run_stdin(cfg, {}, stdin_text="{bad json")
    assert code == 0, "json 协议下 fail-closed deny 仍 exit 0（决策走 JSON）"
    hs = json.loads(so)["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny", "解析失败必须 deny"
    assert "gate_error" in hs["permissionDecisionReason"]
    entries = _read_decisions(cfg)
    assert entries[-1]["gate_error"] is True
    assert entries[-1]["decision"] == "deny"


def test_tc04a_judge_exception_fail_closed(tmp_path, monkeypatch):
    """TC-04a: 判定异常（is_protected 抛错）→ deny + gate_error。"""
    cfg = _mk_cfg(tmp_path)

    def _boom(target, cfg2, cwd=""):
        raise RuntimeError("注入异常")

    monkeypatch.setattr(hg, "is_protected", _boom)
    prot = cfg["protected_paths"][0]
    code, so, _, _, stderr = _run_stdin(
        cfg, _payload("Read", {"file_path": os.path.join(prot, "secret.pem")}))
    assert code == 0
    hs = json.loads(so)["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny", "判定异常必须 fail-closed"
    assert "注入异常" in hs["permissionDecisionReason"]
    entries = _read_decisions(cfg)
    assert entries[-1]["gate_error"] is True
    assert entries[-1]["decision"] == "deny"


# ── TC-04b: 非受保护资源 fail-open + 告警 ────────────────────────

def test_tc04b_append_failure_keeps_allow(tmp_path, monkeypatch):
    """TC-04b: 留痕失败（判定已出 allow）→ 决策不变（fail-open），
    且三处告警同步: stderr 告警行 + 留痕 gate_error（通知载荷）+ 通知
    通道高优先级事件（action=gate_error）。"""
    cfg = _mk_cfg(tmp_path)
    # 令 decisions_file 父路径被文件占用 → 留痕必然 OSError
    blocker = tmp_path / "out"
    blocker.write_text("block", encoding="utf-8")
    captured_notify = {}

    def _fake_notify(cfg2, payload, err=None):
        captured_notify.update(payload)
        return False

    monkeypatch.setattr(hg, "notify", _fake_notify)
    code, so, _, _, stderr = _run_stdin(
        cfg, _payload("Read", {"file_path": "C:/nowhere/notes.txt"}))
    assert code == 0
    hs = json.loads(so)["hookSpecificOutput"]
    assert hs["permissionDecision"] == "allow", (
        "留痕失败不得改变 allow 决策（fail-open）")
    # 告警 1: stderr 告警行
    assert "gate_error" in stderr, f"stderr 应含告警: {stderr!r}"
    # 告警 2+3: 通知通道高优先级事件（action=gate_error + alerts）
    assert captured_notify["action"] == "gate_error", (
        f"通知应为高优先级 gate_error: {captured_notify}")
    assert captured_notify["alerts"], "通知应携带 alerts 明细"


# ── TC-12: D-1 双协议输出格式 ────────────────────────────────────

def test_tc12_json_protocol_three_states(tmp_path):
    """TC-12 脚本侧: json 协议输出 hookSpecificOutput 三态结构。"""
    # deny 形态（ask 关闭时受保护资源 → deny）
    cfg_deny = _mk_cfg(tmp_path, protocol="json", ask_enabled=False)
    prot = cfg_deny["protected_paths"][0]
    _, so, _, _, _ = _run_stdin(
        cfg_deny,
        _payload("Read", {"file_path": os.path.join(prot, "secret.pem")}))
    hs = json.loads(so)["hookSpecificOutput"]
    assert set(hs.keys()) == {"hookEventName", "permissionDecision",
                              "permissionDecisionReason"}, (
        "json 协议结构应为 hookSpecificOutput 三字段")
    assert hs["hookEventName"] == "PreToolUse"
    assert hs["permissionDecision"] == "deny", (
        f"ask 关闭时受保护资源应 deny: {hs}")
    assert hs["permissionDecisionReason"], "deny 必须携带 reason"
    # ask 形态（ask_enabled=true 时受保护资源 → ask）
    cfg_ask = _mk_cfg(tmp_path, protocol="json", ask_enabled=True)
    _, so2, _, _, _ = _run_stdin(
        cfg_ask,
        _payload("Read", {"file_path": os.path.join(
            cfg_ask["protected_paths"][0], "secret.pem")}))
    hs2 = json.loads(so2)["hookSpecificOutput"]
    assert hs2["permissionDecision"] == "ask", "ask_enabled=true 应输出 ask"
    assert hs2["permissionDecisionReason"], "ask 必须携带 reason"
    # allow 形态（非受保护）
    _, so3, _, _, _ = _run_stdin(
        cfg_ask, _payload("Read", {"file_path": "C:/nowhere/notes.txt"}))
    hs3 = json.loads(so3)["hookSpecificOutput"]
    assert hs3["permissionDecision"] == "allow"


def test_tc12_ask_disabled_by_default(tmp_path):
    """TC-12: ask 态默认关闭（D-1 口径）→ 受保护资源直接 deny 而非 ask。"""
    cfg = _mk_cfg(tmp_path, protocol="json", ask_enabled=False)
    prot = cfg["protected_paths"][0]
    _, so, _, _, _ = _run_stdin(
        cfg, _payload("Read", {"file_path": os.path.join(prot, "secret.pem")}))
    hs = json.loads(so)["hookSpecificOutput"]
    assert hs["permissionDecision"] == "deny", "ask 默认关闭时应为 deny"


def test_tc12_exit2_protocol(tmp_path):
    """TC-12 回退形态: exit2 协议 deny → exit 2 + stderr reason；allow → 0。"""
    cfg = _mk_cfg(tmp_path, protocol="exit2")
    prot = cfg["protected_paths"][0]
    # deny → exit 2 + stderr
    code, so, se, stdout, stderr = _run_stdin(
        cfg, _payload("Read", {"file_path": os.path.join(prot, "secret.pem")}))
    assert code == 2, f"exit2 协议 deny 应 exit 2（实际 {code}）"
    assert so == "" and stdout == "", "exit2 deny 不应写 stdout"
    assert "受保护资源" in stderr, f"exit2 deny reason 应入 stderr: {stderr!r}"
    # allow → exit 0 且无输出
    code2, so2, se2, stdout2, stderr2 = _run_stdin(
        cfg, _payload("Read", {"file_path": "C:/nowhere/notes.txt"}))
    assert code2 == 0 and so2 == "" and se2 == "", "exit2 allow 应静默放行"


# ── TC-13: D-2 规则唯一基准 ───────────────────────────────────────

def test_tc13_no_hardcoded_business_rules():
    """TC-13 ①: 静态检查 hook_gate.py 源码不含业务规则硬编码。

    资源级红线（受保护目录/扩展名）只能来自 config.yaml hook 段；
    源码中不得出现任何具体业务值（目录字面量、扩展名字面量、命令正则）。
    """
    with open(GATE_PATH, encoding="utf-8") as f:
        src = f.read()
    banned = [".pem", ".key", ".pdf", "C:/work", "C:/Users", "secret",
              "protected_dir", "rm -rf", "curl", "WATCH_DIRS"]
    for token in banned:
        assert token not in src, (
            f"TC-13 失败: hook_gate.py 源码含业务规则硬编码 {token!r}")
    # 判定所需全部来自配置字段
    for key in ("protected_paths", "protected_extensions", "protocol",
                "ask_enabled"):
        assert f"cfg.get(\"{key}\")" in src or f"cfg[\"{key}\"]" in src, (
            f"判定未引用配置字段 {key}")


def test_tc13_config_change_drives_behavior(tmp_path):
    """TC-13 ②: 修改 config.yaml 后不改脚本，行为随配置变化。"""
    config_path = tmp_path / "config.yaml"
    prot = tmp_path / "protected"
    prot.mkdir(exist_ok=True)
    (prot / "a.pem").write_text("x", encoding="utf-8")
    (prot / "b.key").write_text("y", encoding="utf-8")
    decisions = tmp_path / "out" / "hook_decisions.jsonl"

    def _write(exts):
        ext_list = ", ".join(f"'{e}'" for e in exts)
        config_path.write_text(
            "hook:\n"
            "  protocol: 'json'\n"
            "  ask_enabled: false\n"
            "  notify_url: 'http://127.0.0.1:1/hook'\n"
            "  notify_timeout_s: 0.5\n"
            f"  decisions_file: '{str(decisions).replace(os.sep, '/')}'\n"
            f"  protected_paths: ['{str(prot).replace(os.sep, '/')}']\n"
            f"  protected_extensions: [{ext_list}]\n",
            encoding="utf-8")

    def _decide(ext_file):
        cfg = hg.load_config(str(config_path))
        _, so, _, _, _ = _run_stdin(
            cfg, _payload("Read", {"file_path": os.path.join(prot,
                                                             ext_file)}))
        return json.loads(so)["hookSpecificOutput"]["permissionDecision"]

    # 配置 A: 保护 .pem → a.pem deny、b.key allow
    _write([".pem"])
    assert _decide("a.pem") == "deny"
    assert _decide("b.key") == "allow"
    # 配置 B: 保护 .key → a.pem allow、b.key deny（脚本未动）
    time.sleep(0.05)  # 确保 mtime 变化（缓存失效）
    _write([".key"])
    assert _decide("a.pem") == "allow"
    assert _decide("b.key") == "deny"
    # 配置 C: 清空 protected_paths → 一切放行
    time.sleep(0.05)
    config_path.write_text(
        "hook:\n"
        "  protocol: 'json'\n"
        "  ask_enabled: false\n"
        "  notify_url: 'http://127.0.0.1:1/hook'\n"
        "  notify_timeout_s: 0.5\n"
        f"  decisions_file: '{str(decisions).replace(os.sep, '/')}'\n"
        "  protected_paths: []\n"
        "  protected_extensions: []\n",
        encoding="utf-8")
    assert _decide("a.pem") == "allow", "红线清空后应放行"


# ── P0-5: 决策留痕格式 / 子命令 ──────────────────────────────────

def test_p05_decision_entry_fields(tmp_path):
    """P0-5: 留痕条目字段完整（三轨证据第 2 轨格式定版）。"""
    cfg = _mk_cfg(tmp_path)
    prot = cfg["protected_paths"][0]
    _run_stdin(cfg, _payload("Glob", {"pattern": f"{prot}/*.pem"}))
    e = _read_decisions(cfg)[-1]
    for key in ("timestamp", "event", "session_id", "tool_name", "cwd",
                "tool_input", "decision", "target", "gate_error", "reason"):
        assert key in e, f"留痕缺字段 {key}: {e}"
    assert e["tool_name"] == "Glob"
    assert e["decision"] == "deny"


def test_check_config_subcommand_ok_and_bad(tmp_path):
    """--check-config: 合法配置 rc 0；protocol 非法 rc 1。"""
    cfg = _mk_cfg(tmp_path)
    ok = subprocess.run(
        [sys.executable, GATE_PATH, "--config", cfg["_config_path"],
         "--check-config"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=30)
    assert ok.returncode == 0, f"合法配置应 rc 0:\n{ok.stderr}"
    assert "OK" in ok.stdout

    bad = tmp_path / "config_bad.yaml"
    prot = tmp_path / "protected"
    bad.write_text(
        "hook:\n"
        "  protocol: 'yaml'\n"  # 非法协议
        "  protected_paths: []\n"
        "  protected_extensions: []\n",
        encoding="utf-8")
    r = subprocess.run(
        [sys.executable, GATE_PATH, "--config", str(bad), "--check-config"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=30)
    assert r.returncode == 1, f"非法协议应 rc 1:\n{r.stdout}"
    assert "非法值" in r.stderr


def test_self_test_subcommand(tmp_path):
    """--self-test: 内置 payload 判定自检 rc 0。"""
    cfg = _mk_cfg(tmp_path)
    r = subprocess.run(
        [sys.executable, GATE_PATH, "--config", cfg["_config_path"],
         "--self-test"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=30)
    assert r.returncode == 0, f"self-test 应 rc 0:\n{r.stderr}"
    assert "deny" in r.stdout, "受保护 payload 应输出 deny"


# ── P1-1: 并发原子追加（实测坑修复）──────────────────────────────

def test_locked_append_jsonl_concurrent(tmp_path):
    """并发原子追加: 8 子进程同时 append 每行完整可解析（无交错损坏）。

    实测坑（2026-09-05 宿主实测）: 宿主并发触发 4 个 hook 进程时，
    text 模式 append 曾致两行交错损坏（半行丢失）。
    """
    target = tmp_path / "out" / "hook_decisions.jsonl"
    target.parent.mkdir(parents=True, exist_ok=True)
    blocking_js = BLOCKING_DIR.replace("\\", "/")
    worker_code = (
        "import json,sys\n"
        "sys.path.insert(0, r'" + blocking_js + "')\n"
        "import hook_gate as hg\n"
        "idx=int(sys.argv[1])\n"
        "for j in range(20):\n"
        "    hg.locked_append_jsonl(r'" + str(target) + "', dict(timestamp='t',\n"
        "        worker=idx, seq=j, tool_name='Read',\n"
        "        tool_input=dict(file_path='C:/x/'+'y'*200+f'/{idx}-{j}'.format(idx=idx,j=j)),\n"
        "        decision='allow', reason=''))\n"
    )
    procs = [subprocess.Popen(
        [sys.executable, "-c", worker_code, str(i)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE) for i in range(8)]
    for p in procs:
        _, err = p.communicate(timeout=120)
        assert p.returncode == 0, f"worker 失败: {err.decode('utf-8', 'replace')[:300]}"

    with open(target, encoding="utf-8") as f:
        lines = [l for l in f.read().splitlines() if l]
    assert len(lines) == 8 * 20
    for l in lines:
        e = json.loads(l)  # 每行必须完整可解析（无交错损坏）
        assert "worker" in e and "seq" in e


def test_append_decision_binary_mode(tmp_path):
    """append_decision 走原子追加路径（返回路径 + 内容 UTF-8 可解析）。"""
    cfg = _mk_cfg(tmp_path)
    entry = {"timestamp": "t", "event": "pre_tool_use",
             "session_id": "s", "tool_name": "Read", "cwd": "",
             "tool_input": {"file_path": "C:/中文/路径.pem"},
             "gate_error": False, "target": "C:/中文/路径.pem",
             "decision": "deny", "reason": "已拦截"}
    path = hg.append_decision(cfg, entry)
    with open(path, "rb") as f:
        raw = f.read()
    assert raw.endswith(b"\n")
    json.loads(raw.decode("utf-8"))


# ── P1-3 实测坑修复: stdin 编码（大中文 payload fail-closed 误拦）────

def test_stdin_utf8_large_chinese_payload(tmp_path):
    """宿主以 UTF-8 字节写大中文 payload → 解析成功 allow（不再 fail-closed）。

    实测坑（2026-09-05 P1-3 宿主实测）: sys.stdin.read() 在中文 Windows 按
    locale（cp936）解码 UTF-8 字节流，中文末字节与后续 JSON 语法字符被
    合并吞掉 → JSON 结构断裂 → 误拦；修复后 _read_stdin 按字节读 + UTF-8 解码。
    """
    cfg = _mk_cfg(tmp_path)
    big_content = ("中文测试内容" * 900) + "tail-'\"\\"  # 5K+ 字符
    payload = {"session_id": "wb-test", "transcript_path": "",
               "cwd": "C:/x", "hook_event_name": "PreToolUse",
               "tool_name": "Write",
               "tool_input": {"file_path": "C:/tmp/probe.txt",
                              "content": big_content}}
    text = json.dumps(payload, ensure_ascii=False)
    r = subprocess.run(
        [sys.executable, GATE_PATH, "--config", cfg["_config_path"]],
        input=text.encode("utf-8"), capture_output=True, timeout=60)
    assert r.returncode == 0, (
        f"大中文 payload 应 allow rc 0:\n"
        f"stderr={r.stderr.decode('utf-8', 'replace')[:400]}")
    with open(cfg["decisions_file"], encoding="utf-8") as f:
        lines = [l for l in f.read().splitlines() if l]
    assert len(lines) == 1
    d = json.loads(lines[0])
    assert d["decision"] == "allow" and d["gate_error"] is False
    assert "中文测试内容" in d["tool_input"]["content"], "留痕 content 乱码/丢失"


def test_locked_append_jsonl_surrogate_safe(tmp_path):
    """留痕 entry 含 surrogate 字符时不崩溃（errors=replace 容错）。

    实测坑: stdin 解码残留 surrogate（U+DCXX 范围）时 json.dumps().encode()
    抛 UnicodeEncodeError → hook 崩溃；修复后留痕不中断（D-3 语义）。
    """
    target = tmp_path / "out" / "h.jsonl"
    entry = {"timestamp": "t", "tool_name": "Write",
             "tool_input": {"content": "ok" + chr(0xDCAD) + "-broken"},
             "decision": "allow", "reason": ""}
    hg.locked_append_jsonl(str(target), entry)  # 不应抛异常
    with open(target, "rb") as f:
        raw = f.read()
    assert raw.endswith(b"\n")
    d = json.loads(raw.decode("utf-8"))
    assert "ok" in d["tool_input"]["content"]


def test_read_stdin_bytes_utf8_decode(monkeypatch):
    """_read_stdin: 字节流按 UTF-8 解码（errors=replace 不抛解码异常）。"""
    class _FakeBuf:
        def __init__(self, data):
            self._data = data

        def read(self):
            return self._data

    class _FakeStdin:
        buffer = _FakeBuf("中文-payload-内容".encode("utf-8"))

    monkeypatch.setattr(sys, "stdin", _FakeStdin())
    out = hg._read_stdin()
    assert out == "中文-payload-内容"
    # 非法 UTF-8 字节 → replace 不抛异常
    sys.stdin.buffer = _FakeBuf(b"ok\xff\xfe-bad")
    out2 = hg._read_stdin()
    assert out2.startswith("ok") and "bad" in out2
