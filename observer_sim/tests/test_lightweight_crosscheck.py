# -*- coding: utf-8 -*-
"""
test_lightweight_crosscheck.py — T3.1 进程 / T3.2 文件快照交叉校验模块单测

覆盖开发计划 T3.1 验收:
① 构造「申报外启动进程」场景 → 比对结果出现「疑似二级操作」告警；
② 正常会话（白名单 / WorkBuddy 自身进程 / 已申报命令对应进程）零误报；
③ 快照失败 / 会话未配对等异常路径如实标记「不可用」，不破坏主流程。

覆盖开发计划 T3.2 验收:
① 申报外受保护目录文件变更被检出 → 「疑似二级操作」告警；
② 申报内路径变更不误报（basename/子路径宽松匹配排除）；
③ 大目录场景双快照耗时在声明预算内（200 文件 < 10s，增量哈希复用）；
④ 快照失败 / 目录缺失 / 截断等异常路径如实标记，不破坏主流程。

设计要点:
- 进程用例全部通过 ProcessSnapshotter(enum_fn=...) 注入假快照，
  不依赖真实系统进程与 WorkBuddy 环境，可重复、可断言；
- 文件用例基于 pytest tmp_path 真实临时目录做哈希快照，
  不依赖外部环境；增量哈希验证经 monkeypatch 拦截模块级 _hash_file。
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import collector.lightweight_crosscheck as lc
from collector.lightweight_crosscheck import (
    ProcessCrossChecker,
    ProcessSnapshotter,
    diff_new_processes,
    extract_command,
    matches_reported,
    parse_reported_commands,
    FileCrossChecker,
    FileSnapshotter,
    diff_files,
    matches_reported_path,
    parse_reported_paths,
)


# ── 假快照构造 ───────────────────────────────────────────────────

def _proc(pid, name, create_time=100.0, cmdline=None, exe=None, ppid=1):
    return {
        "pid": pid,
        "name": name,
        "exe": exe or f"C:/fake/{name}",
        "cmdline": cmdline or [name],
        "create_time": create_time,
        "ppid": ppid,
    }


def _make_snapshot(procs):
    """[{pid, ...}] → {pid: {...}}（pid 从 dict 提取）。"""
    return {p["pid"]: p for p in procs}


def _checker(seq, tmp_path, **kw):
    """构造 checker: enum_fn 依次返回 seq 中的快照（start/end/finish 补拍）。"""
    it = iter(seq)

    def enum():
        try:
            return next(it)
        except StopIteration:
            raise RuntimeError("enum 序列耗尽（快照次数超出预期）")

    return ProcessCrossChecker(
        output_dir=str(tmp_path),
        snapshotter=ProcessSnapshotter(enum_fn=enum),
        **kw)


# ── diff_new_processes / extract_command / matches_reported ──────

def test_diff_new_processes_new_pid_and_pid_reuse():
    start = _make_snapshot([_proc(1, "a.exe")])
    end = _make_snapshot([
        _proc(1, "a.exe"),                     # 同 pid 同 create_time → 不算新增
        _proc(2, "b.exe"),                     # 新 pid → 新增
        _proc(3, "c.exe", create_time=200.0),  # pid 复用（create_time 不同）→ 新增
    ])
    new = diff_new_processes(start, end)
    assert sorted(new) == [2, 3]


def test_extract_command_forms():
    assert extract_command("ls -la") == "ls -la"
    assert extract_command({"command": "curl evil.sh"}) == "curl evil.sh"
    assert extract_command({"cmd": ["git", "clone", "x"]}) == "git clone x"
    assert extract_command(["python", "-c", "1"]) == "python -c 1"
    assert extract_command({"script": "npm install"}) == "npm install"
    assert extract_command({"other": "x"}) == ""
    assert extract_command(None) == ""


def test_matches_reported_by_name_and_cmdline():
    info = _proc(9, "curl.exe", cmdline=["curl.exe", "-s", "http://evil.sh/x"])
    assert matches_reported(info, ["curl http://evil.sh/x"])
    assert matches_reported(info, ["curl -s http://evil.sh/x"])
    info2 = _proc(10, "python.exe",
                  cmdline=["python.exe", "script.py", "--flag"])
    assert matches_reported(info2, ["python script.py --flag"])
    assert not matches_reported(info2, ["whoami"])


# ── 核心比对场景（验收标准 ①/②）─────────────────────────────────

def test_unreported_process_flagged(tmp_path):
    """申报外新增进程 → 「疑似二级操作」告警（验收标准①）。"""
    cc = _checker([
        _make_snapshot([_proc(1, "base.exe")]),
        _make_snapshot([_proc(1, "base.exe"),
                        _proc(2, "backdoor.exe",
                              cmdline=["backdoor.exe", "--connect", "1.2.3.4"],
                              ppid=1)]),
    ], tmp_path)
    cc.on_session_start("s1")
    cc.on_session_end("s1")
    summary = cc.finish()

    assert summary["available"] is True
    assert summary["sessions_checked"] == 1
    assert len(summary["findings"]) == 1
    f = summary["findings"][0]
    assert f["session_id"] == "s1"
    assert f["kind"] == "unreported_process"
    assert f["severity"] == "suspect_secondary_action"
    assert f["suspects"][0]["name"] == "backdoor.exe"
    assert f["suspects"][0]["cmdline"][1] == "--connect"
    assert "仅告警不拦截" in f["note"]


def test_system_whitelist_and_extra_filtered(tmp_path):
    """系统白名单进程 + 用户扩展白名单 → 零误报（验收标准②）。"""
    cc = _checker([
        _make_snapshot([_proc(1, "base.exe")]),
        _make_snapshot([_proc(1, "base.exe"),
                        _proc(2, "svchost.exe"),
                        _proc(3, "dwm.exe"),
                        _proc(4, "teamviewer_service.exe")]),
    ], tmp_path, whitelist_extra=["teamviewer_service.exe"])
    cc.on_session_start("s1")
    cc.on_session_end("s1")
    summary = cc.finish()

    assert summary["available"] is True
    assert summary["findings"] == []


def test_agent_process_and_dir_filtered(tmp_path):
    """WorkBuddy 自身进程名 → 零误报（验收标准②）。"""
    cc = _checker([
        _make_snapshot([_proc(1, "base.exe")]),
        _make_snapshot([_proc(1, "base.exe"),
                        _proc(2, "WorkBuddy.exe", exe="C:/WorkBuddy/WorkBuddy.exe"),
                        _proc(3, "workbuddy.exe"),
                        _proc(4, "electron-helper.exe",
                              exe="C:/WorkBuddy/electron-helper.exe")]),
    ], tmp_path,
        agent_process_names=["WorkBuddy.exe", "workbuddy.exe"],
        agent_process_dirs=["C:/WorkBuddy"])
    cc.on_session_start("s1")
    cc.on_session_end("s1")
    summary = cc.finish()

    assert summary["available"] is True
    assert summary["findings"] == []


def test_reported_command_excluded(tmp_path):
    """会话内已申报命令对应的新增进程 → 排除，零误报（验收标准②）。"""
    cc = _checker([
        _make_snapshot([_proc(1, "base.exe")]),
        _make_snapshot([_proc(1, "base.exe"),
                        _proc(2, "curl.exe",
                              cmdline=["curl.exe", "-s", "http://safe/api"])]),
    ], tmp_path)
    cc.on_session_start("s1")
    cc.add_reported_command("s1", "curl -s http://safe/api")
    cc.on_session_end("s1")
    summary = cc.finish()

    assert summary["available"] is True
    assert summary["findings"] == []


def test_reported_commands_from_jsonl_merged(tmp_path):
    """finish(reported_by_session=...) 与 add_reported_command 合并生效。"""
    cc = _checker([
        _make_snapshot([_proc(1, "base.exe")]),
        _make_snapshot([_proc(1, "base.exe"),
                        _proc(2, "curl.exe", cmdline=["curl.exe", "-s", "x"]),
                        _proc(3, "nmap.exe", cmdline=["nmap.exe", "-sS", "x"])]),
    ], tmp_path)
    cc.on_session_start("s1")
    cc.on_session_end("s1")
    summary = cc.finish(
        reported_by_session={"s1": ["curl -s x", "nmap -sS x"]})

    assert summary["available"] is True
    assert summary["findings"] == []


# ── 异常路径（快照失败 / 会话未配对）────────────────────────────

def test_snapshot_failure_marks_unavailable(tmp_path):
    """start 快照失败 → 记录 unavailable，finish 后 available=False。"""

    def boom():
        raise OSError("psutil missing")

    cc = ProcessCrossChecker(
        output_dir=str(tmp_path),
        snapshotter=ProcessSnapshotter(enum_fn=boom))
    cc.on_session_start("s1")
    summary = cc.finish()

    assert summary["enabled"] is True
    assert summary["available"] is False
    assert summary["sessions_checked"] == 0
    assert summary["findings"] == []
    assert any(u["session_id"] == "s1" and u["phase"] == "start"
               for u in summary["unavailable"])


def test_end_without_start_unavailable(tmp_path):
    """仅有 end 申报（无 start 快照）→ 不可用记录，不做比对。"""
    cc = _checker([
        _make_snapshot([_proc(1, "base.exe")]),
    ], tmp_path)
    cc.on_session_end("s2")   # 无 start
    summary = cc.finish()

    assert summary["available"] is False
    assert any(u["session_id"] == "s2" and u["phase"] == "end"
               and "无 start 快照" in u["reason"] for u in summary["unavailable"])


def test_finish_closes_unclosed_session(tmp_path):
    """未闭合会话由 finish() 补 end 快照 → 正常比对（异常中断场景）。"""
    cc = _checker([
        _make_snapshot([_proc(1, "base.exe")]),
        _make_snapshot([_proc(1, "base.exe"),
                        _proc(2, "stealth.exe")]),
    ], tmp_path)
    cc.on_session_start("s3")   # 未申报 end
    summary = cc.finish()

    assert summary["available"] is True
    assert summary["sessions_checked"] == 1
    assert len(summary["findings"]) == 1
    assert summary["findings"][0]["suspects"][0]["name"] == "stealth.exe"


def test_no_sessions_marks_unavailable(tmp_path):
    """没有任何会话申报 → available=False（如实声明，不虚构比对）。"""
    cc = _checker([], tmp_path)
    summary = cc.finish()

    assert summary["available"] is False
    assert summary["sessions_checked"] == 0
    assert summary["findings"] == []


# ── 产物留痕 ────────────────────────────────────────────────────

def test_jsonl_output(tmp_path):
    """findings 与 unavailable 均写入 crosscheck_process.jsonl（追加式）。"""
    cc = _checker([
        _make_snapshot([_proc(1, "base.exe")]),
        _make_snapshot([_proc(1, "base.exe"), _proc(2, "sus.exe")]),
    ], tmp_path)
    cc.on_session_start("s1")
    cc.on_session_end("s1")
    cc.on_session_end("s2")   # 无 start → unavailable
    cc.finish()

    path = os.path.join(str(tmp_path), "crosscheck_process.jsonl")
    assert os.path.isfile(path)
    with open(path, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    types = {l["type"] for l in lines}
    assert "process_crosscheck" in types
    assert "process_crosscheck_unavailable" in types
    assert all(l["timestamp_ms"] > 0 for l in lines)


def test_jsonl_skipped_when_clean(tmp_path):
    """无 findings 且无 unavailable → 不产生空留痕文件。"""
    cc = _checker([
        _make_snapshot([_proc(1, "base.exe")]),
        _make_snapshot([_proc(1, "base.exe")]),
    ], tmp_path)
    cc.on_session_start("s1")
    cc.on_session_end("s1")
    cc.finish()

    assert not os.path.exists(os.path.join(str(tmp_path),
                                           "crosscheck_process.jsonl"))


# ── parse_reported_commands ─────────────────────────────────────

def test_parse_reported_commands(tmp_path):
    """正常解析 + 畸形行容错 + 非执行类过滤 + 文件缺失。"""
    path = os.path.join(str(tmp_path), "mcp_reports.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"type": "report_tool_call", "payload": {
            "tool_name": "execute_command",
            "tool_args": {"command": "curl http://x/y"},
            "session_id": "s1"}}) + "\n")
        f.write(json.dumps({"type": "report_tool_call", "payload": {
            "tool_name": "Bash",
            "tool_args": {"cmd": "whoami"},
            "session_id": "s1"}}) + "\n")
        f.write(json.dumps({"type": "report_tool_call", "payload": {
            "tool_name": "read_file",
            "tool_args": {"path": "C:/a.txt"},
            "session_id": "s1"}}) + "\n")
        f.write("not-json-line\n")
        f.write("")  # 空行
        f.write(json.dumps({"type": "report_session", "payload": {
            "session_id": "s1", "status": "start"}}) + "\n")
        f.write(json.dumps({"type": "report_tool_call", "payload": {
            "tool_name": "execute_command",
            "tool_args": {"command": "ls -la"},
            "session_id": "s2"}}) + "\n")

    result = parse_reported_commands(path)
    assert result["s1"] == ["curl http://x/y", "whoami"]
    assert result["s2"] == ["ls -la"]


def test_parse_reported_commands_missing_file(tmp_path):
    """jsonl 文件不存在 → 返回空映射（不抛异常）。"""
    assert parse_reported_commands(os.path.join(str(tmp_path), "nope.jsonl")) \
        == {}


def test_parse_reported_commands_none_path():
    assert parse_reported_commands(None) == {}


# ══════════════════════════════════════════════════════════════
# T3.2 文件快照比对单测（受保护目录，验收①②③④）
# ══════════════════════════════════════════════════════════════


def _prot_dir(tmp_path, name="prot"):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _file_checker(tmp_path, dirs=None, **kw):
    """构造 FileCrossChecker，输出目录独立于受保护目录。"""
    out = tmp_path / "out"
    return FileCrossChecker(
        output_dir=str(out),
        snapshotter=FileSnapshotter(dirs or [str(_prot_dir(tmp_path))],
                                    **kw))


# ── FileSnapshotter / diff_files / matches_reported_path ──────

def test_file_snapshot_basic(tmp_path):
    """基本快照: 记录 size/mtime_ns/sha256，目录索引前缀避免重名。"""
    prot = _prot_dir(tmp_path)
    (prot / "a.txt").write_text("aaaa", encoding="utf-8")
    (prot / "sub").mkdir()
    (prot / "sub" / "b.txt").write_text("bbbb", encoding="utf-8")
    snap = FileSnapshotter([str(prot)]).snapshot()

    assert snap is not None
    assert snap["@0/a.txt"]["size"] == 4
    assert snap["@0/sub/b.txt"]["size"] == 4
    assert len(snap["@0/a.txt"]["sha256"]) == 64
    assert snap["@0/a.txt"]["sha256"] != snap["@0/sub/b.txt"]["sha256"]
    assert "__truncated__" not in snap


def test_file_snapshot_skips_missing_dir(tmp_path):
    """声明目录不存在 → 安全跳过，快照为空（不抛异常）。"""
    snap = FileSnapshotter([str(tmp_path / "nope")]).snapshot()
    assert snap == {}


def test_file_snapshot_truncation(tmp_path):
    """max_files 上限截断并如实标记 __truncated__。"""
    prot = _prot_dir(tmp_path)
    for i in range(3):
        (prot / f"f{i}.txt").write_text("x", encoding="utf-8")
    snap = FileSnapshotter([str(prot)], max_files=2).snapshot()

    assert snap["__truncated__"] is True
    assert len([k for k in snap if k != "__truncated__"]) == 2


def test_file_snapshot_large_file_skips_hash(tmp_path):
    """单文件超过 hash_max_size → 仅记 size/mtime，sha256 置空。"""
    prot = _prot_dir(tmp_path)
    (prot / "big.bin").write_bytes(b"x" * 100)
    snap = FileSnapshotter([str(prot)], hash_max_size=8).snapshot()

    assert snap["@0/big.bin"]["size"] == 100
    assert snap["@0/big.bin"]["sha256"] == ""


def test_file_snapshot_incremental_hash_reuse(tmp_path, monkeypatch):
    """增量哈希: size+mtime 未变文件复用旧哈希，不重新计算。"""
    prot = _prot_dir(tmp_path)
    (prot / "a.txt").write_text("aaaa", encoding="utf-8")
    (prot / "b.txt").write_text("bbbb", encoding="utf-8")
    sn = FileSnapshotter([str(prot)])
    snap1 = sn.snapshot()

    calls = []

    def fake_hash(path):
        calls.append(os.path.basename(path))
        return "fake-" + os.path.basename(path)

    monkeypatch.setattr(lc, "_hash_file", fake_hash)
    (prot / "b.txt").write_text("bbbb-modified", encoding="utf-8")
    snap2 = sn.snapshot(previous=snap1)

    assert calls == ["b.txt"]                      # a.txt 复用旧哈希
    assert "a.txt" not in calls
    assert snap2["@0/a.txt"]["sha256"] == snap1["@0/a.txt"]["sha256"]
    assert snap2["@0/b.txt"]["sha256"] == "fake-b.txt"


def test_diff_files_added_removed_modified():
    start = {
        "@0/a.txt": {"size": 1, "mtime_ns": 1, "sha256": "h1"},
        "@0/b.txt": {"size": 2, "mtime_ns": 2, "sha256": "h2"},
        "@0/m.txt": {"size": 3, "mtime_ns": 3, "sha256": "h3"},
    }
    end = {
        "@0/b.txt": {"size": 2, "mtime_ns": 2, "sha256": "h2"},
        "@0/c.txt": {"size": 4, "mtime_ns": 4, "sha256": "h4"},
        "@0/m.txt": {"size": 30, "mtime_ns": 30, "sha256": "h30"},
    }
    d = diff_files(start, end)
    assert list(d["added"]) == ["@0/c.txt"]
    assert list(d["removed"]) == ["@0/a.txt"]
    assert list(d["modified"]) == ["@0/m.txt"]


def test_matches_reported_path_variants():
    assert matches_reported_path("@0/src/app.py", ["C:/work/src/app.py"])
    assert matches_reported_path("@0/config.json", ["config.json"])
    assert matches_reported_path("@0/sub/config.json",
                                 ["C:/work/sub/config.json"])
    assert not matches_reported_path("@0/config.json",
                                     ["C:/work/other.json"])
    assert not matches_reported_path("@0/x.txt", [])
    assert not matches_reported_path("@0/x.txt", [""])


# ── 核心比对场景（验收标准①/②）─────────────────────────────

def test_unreported_file_change_flagged(tmp_path):
    """申报外新增文件 → 「疑似二级操作」告警（验收标准①）。"""
    prot = _prot_dir(tmp_path)
    (prot / "base.txt").write_text("base", encoding="utf-8")
    cc = _file_checker(tmp_path)
    cc.on_session_start("s1")
    (prot / "secret.txt").write_text("secret", encoding="utf-8")
    cc.on_session_end("s1")
    summary = cc.finish()

    assert summary["available"] is True
    assert summary["sessions_checked"] == 1
    assert len(summary["findings"]) == 1
    f = summary["findings"][0]
    assert f["session_id"] == "s1"
    assert f["kind"] == "unreported_file_change"
    assert f["severity"] == "suspect_secondary_action"
    assert "@0/secret.txt" in f["changes"]["added"]
    assert "仅告警不拦截" in f["note"]


def test_reported_file_change_excluded(tmp_path):
    """申报内路径变更（basename 匹配）→ 排除，零误报（验收标准②）。"""
    prot = _prot_dir(tmp_path)
    (prot / "base.txt").write_text("base", encoding="utf-8")
    cc = _file_checker(tmp_path)
    cc.on_session_start("s1")
    cc.add_reported_path("s1", "C:/safe/secret.txt")
    (prot / "secret.txt").write_text("secret", encoding="utf-8")
    cc.on_session_end("s1")
    summary = cc.finish()

    assert summary["available"] is True
    assert summary["findings"] == []


def test_reported_paths_from_jsonl_merged(tmp_path):
    """finish(reported_paths_by_session=...) 与 add_reported_path 合并生效。"""
    prot = _prot_dir(tmp_path)
    (prot / "base.txt").write_text("base", encoding="utf-8")
    cc = _file_checker(tmp_path)
    cc.on_session_start("s1")
    (prot / "x.json").write_text("x", encoding="utf-8")
    (prot / "y.json").write_text("y", encoding="utf-8")
    cc.on_session_end("s1")
    summary = cc.finish(
        reported_paths_by_session={"s1": ["C:/a/x.json", "C:/b/y.json"]})

    assert summary["available"] is True
    assert summary["findings"] == []


def test_file_snapshot_failure_marks_unavailable(tmp_path, monkeypatch):
    """start 快照失败 → 记录 unavailable，finish 后 available=False。"""
    monkeypatch.setattr(FileSnapshotter, "snapshot",
                        lambda self, previous=None: None)
    cc = _file_checker(tmp_path)
    cc.on_session_start("s1")
    summary = cc.finish()

    assert summary["enabled"] is True
    assert summary["available"] is False
    assert summary["sessions_checked"] == 0
    assert summary["findings"] == []
    assert any(u["session_id"] == "s1" and u["phase"] == "start"
               for u in summary["unavailable"])


def test_file_end_without_start_unavailable(tmp_path):
    """仅有 end 申报（无 start 快照）→ 不可用记录，不做比对。"""
    cc = _file_checker(tmp_path)
    cc.on_session_end("s2")
    summary = cc.finish()

    assert summary["available"] is False
    assert any(u["session_id"] == "s2" and u["phase"] == "end"
               and "无 start 快照" in u["reason"] for u in summary["unavailable"])


def test_file_finish_closes_unclosed_session(tmp_path):
    """未闭合会话由 finish() 补 end 快照 → 正常比对（异常中断场景）。"""
    prot = _prot_dir(tmp_path)
    (prot / "base.txt").write_text("base", encoding="utf-8")
    cc = _file_checker(tmp_path)
    cc.on_session_start("s3")
    (prot / "late.txt").write_text("late", encoding="utf-8")
    summary = cc.finish()

    assert summary["available"] is True
    assert summary["sessions_checked"] == 1
    assert len(summary["findings"]) == 1
    assert "@0/late.txt" in summary["findings"][0]["changes"]["added"]


def test_file_no_sessions_marks_unavailable(tmp_path):
    """没有任何会话申报 → available=False（如实声明，不虚构比对）。"""
    cc = _file_checker(tmp_path)
    summary = cc.finish()

    assert summary["available"] is False
    assert summary["sessions_checked"] == 0
    assert summary["findings"] == []


# ── 产物留痕 ────────────────────────────────────────────────

def test_file_jsonl_output(tmp_path):
    """findings 与 unavailable 均写入 crosscheck_file.jsonl（追加式）。"""
    prot = _prot_dir(tmp_path)
    (prot / "base.txt").write_text("base", encoding="utf-8")
    cc = _file_checker(tmp_path)
    cc.on_session_start("s1")
    (prot / "new.txt").write_text("new", encoding="utf-8")
    cc.on_session_end("s1")
    cc.on_session_end("s2")   # 无 start → unavailable
    cc.finish()

    path = os.path.join(str(tmp_path / "out"), "crosscheck_file.jsonl")
    assert os.path.isfile(path)
    with open(path, encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]
    types = {l["type"] for l in lines}
    assert "file_crosscheck" in types
    assert "file_crosscheck_unavailable" in types
    assert all(l["timestamp_ms"] > 0 for l in lines)


def test_file_jsonl_skipped_when_clean(tmp_path):
    """无 findings 且无 unavailable → 不产生空留痕文件。"""
    prot = _prot_dir(tmp_path)
    (prot / "base.txt").write_text("base", encoding="utf-8")
    cc = _file_checker(tmp_path)
    cc.on_session_start("s1")
    cc.on_session_end("s1")
    cc.finish()

    assert not os.path.exists(os.path.join(str(tmp_path / "out"),
                                           "crosscheck_file.jsonl"))


# ── parse_reported_paths ─────────────────────────────────────

def test_parse_reported_paths(tmp_path):
    """正常解析 + 多字段提取 + 非文件类过滤 + 畸形行容错。"""
    path = os.path.join(str(tmp_path), "mcp_reports.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"type": "report_tool_call", "payload": {
            "tool_name": "write_file",
            "tool_args": {"path": "C:/a/out.txt"},
            "session_id": "s1"}}) + "\n")
        f.write(json.dumps({"type": "report_tool_call", "payload": {
            "tool_name": "read_file",
            "tool_args": {"file_path": "C:/b/in.txt"},
            "session_id": "s1"}}) + "\n")
        f.write(json.dumps({"type": "report_tool_call", "payload": {
            "tool_name": "edit_file",
            "tool_args": {"old_path": "C:/c/a.py", "new_path": "C:/c/b.py"},
            "session_id": "s1"}}) + "\n")
        f.write(json.dumps({"type": "report_tool_call", "payload": {
            "tool_name": "execute_command",
            "tool_args": {"command": "whoami"},
            "session_id": "s1"}}) + "\n")
        f.write(json.dumps({"type": "report_tool_call", "payload": {
            "tool_name": "write_file",
            "tool_args": {"path": "C:/no/session.txt"}}}) + "\n")
        f.write("not-json-line\n")

    result = parse_reported_paths(path)
    assert result["s1"] == ["C:/a/out.txt", "C:/b/in.txt",
                             "C:/c/a.py", "C:/c/b.py"]
    assert len(result) == 1


def test_parse_reported_paths_missing_file(tmp_path):
    assert parse_reported_paths(os.path.join(str(tmp_path), "nope.jsonl")) \
        == {}


def test_parse_reported_paths_none_path():
    assert parse_reported_paths(None) == {}


# ── 性能预算（验收标准③）────────────────────────────────────

def test_file_snapshot_performance_budget(tmp_path):
    """200 文件双快照（含增量哈希）耗时在声明预算 < 10s 内。"""
    prot = _prot_dir(tmp_path)
    for i in range(200):
        (prot / f"f{i:03d}.txt").write_text(f"content-{i}" * 4,
                                             encoding="utf-8")
    sn = FileSnapshotter([str(prot)])
    t0 = time.perf_counter()
    snap1 = sn.snapshot()
    snap2 = sn.snapshot(previous=snap1)
    elapsed = time.perf_counter() - t0

    assert snap1 and len(snap1) == 200
    assert snap2 and len(snap2) == 200
    assert elapsed < 10.0, f"200 文件双快照耗时 {elapsed:.2f}s，超出声明预算"

