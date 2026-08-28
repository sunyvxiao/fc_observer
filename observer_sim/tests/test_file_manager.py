"""
OutputFileManager 单元测试（U7 文件/报告管理下沉）

覆盖：
  - resolve 前缀匹配 + realpath 校验（拒绝 ../ 路径遍历、绝对路径、未知前缀）
  - resolve_strict 错误码（traversal / unknown_prefix）
  - build_tree 四区结构（records / monitoring / reports / unit_test）
  - delete_resolved / delete_category / delete_reports 统计正确
  - find_monitor_report 定位（含 L-T3 按天 audit 文件名）
  - demo 删除菜单原语（count / collect / delete_ts_dirs / list_scenario_dirs）
"""
import os
import pytest

from observer_core.audit.file_manager import OutputFileManager


@pytest.fixture
def fm(tmp_path):
    """构造 OutputFileManager：base=tmp/sim（observer_sim 目录），project=tmp（上级目录）"""
    base = tmp_path / "sim"
    base.mkdir()
    return OutputFileManager(str(base), str(tmp_path))


def _touch(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


# ── resolve：路径遍历拒绝 ──────────────────────────────────────

def test_resolve_accepts_valid_prefixed_path(fm, tmp_path):
    _touch(os.path.join(fm.records_dir, "s1", "r.jsonl"))
    resolved = fm.resolve("records/s1/r.jsonl")
    assert resolved == os.path.join(fm.records_dir, "s1", "r.jsonl")


def test_resolve_rejects_dotdot_traversal(fm, tmp_path):
    # records/../secret.txt → realpath 落在 records 根之外 → 拒绝
    _touch(os.path.join(str(tmp_path), "secret.txt"))
    assert fm.resolve("records/../secret.txt") is None
    # 前缀匹配但 realpath 越界（reports 根外的兄弟目录）
    _touch(os.path.join(str(tmp_path), "sim", "evil.txt"))
    assert fm.resolve("reports/../evil.txt") is None


def test_resolve_rejects_absolute_path_outside_roots(fm):
    # Windows/Linux 系统绝对路径不落在任何白名单根内 → 拒绝
    assert fm.resolve(os.path.join(os.sep, "Windows", "system32")) is None
    assert fm.resolve(os.path.join(os.sep, "etc", "passwd")) is None


def test_resolve_rejects_unknown_prefix(fm):
    assert fm.resolve("etc/passwd") is None
    assert fm.resolve("") is None


def test_resolve_allows_full_root_path_match(fm):
    # files/view 特有：直接用完整根路径匹配（行为与 app.py 原实现一致）
    _touch(os.path.join(fm.records_dir, "x.txt"))
    resolved = fm.resolve(os.path.join(fm.records_dir, "x.txt"))
    assert resolved == os.path.join(fm.records_dir, "x.txt")


def test_resolve_strict_error_codes(fm, tmp_path):
    # 前缀匹配但越界 → traversal
    assert fm.resolve_strict("records/../secret.txt") == (None, "traversal")
    # 无前缀匹配 → unknown_prefix
    assert fm.resolve_strict("nope/x.txt") == (None, "unknown_prefix")
    # 合法路径 → 解析成功
    assert fm.resolve_strict("records/ok.txt") == (
        os.path.join(fm.records_dir, "ok.txt"), None)


# ── build_tree：四区结构 ──────────────────────────────────────

def test_build_tree_four_sections(fm):
    _touch(os.path.join(fm.records_dir, "session1", "rec1.jsonl"))
    _touch(os.path.join(fm.monitoring_dir, "reports", "risk_report_a.md"))
    _touch(os.path.join(fm.monitoring_dir, "monitoring_summary.json"))
    _touch(os.path.join(fm.reports_dir, "normal", "n01-standard-development",
                        "20260101_000000", "report.md"))
    _touch(os.path.join(fm.unit_test_dir, "results.txt"))

    tree = fm.build_tree()["tree"]
    assert set(tree.keys()) == {"records", "monitoring", "reports", "unit_test"}

    # records 区
    assert tree["records"]["label"] == "录制文件"
    assert tree["records"]["children"][0]["name"] == "session1"
    # monitoring 区：reports 子目录 + monitoring_summary.json
    mon_children = tree["monitoring"]["children"]
    assert any(c["name"] == "reports" for c in mon_children)
    assert any(c["name"] == "monitoring_summary.json" for c in mon_children)
    # reports 区：分类名按 CATEGORY_META 渲染
    cat_names = [c["name"] for c in tree["reports"]["children"]]
    assert "Normal 正常行为" in cat_names
    # unit_test 区
    assert tree["unit_test"]["children"][0]["name"] == "results.txt"


def test_build_tree_empty_when_no_dirs(fm):
    tree = fm.build_tree()["tree"]
    assert tree == {}


# ── 删除原语 ──────────────────────────────────────────────────

def test_delete_resolved_file_and_dir(fm, tmp_path):
    f = os.path.join(fm.records_dir, "a.txt")
    _touch(f)
    deleted = fm.delete_resolved(f)
    assert deleted == {"type": "file", "name": "a.txt", "files": 1}
    assert not os.path.exists(f)

    d = os.path.join(fm.records_dir, "ts1")
    _touch(os.path.join(d, "1.json"))
    _touch(os.path.join(d, "sub", "2.json"))
    deleted = fm.delete_resolved(d)
    assert deleted == {"type": "directory", "name": "ts1", "files": 2}
    assert not os.path.exists(d)


def test_delete_category_clears_contents_keeps_root(fm):
    _touch(os.path.join(fm.records_dir, "a", "1.txt"))
    _touch(os.path.join(fm.records_dir, "b", "2.txt"))
    deleted = fm.delete_category("records")
    assert deleted == {"type": "directory", "name": "records", "files": 2}
    assert os.path.isdir(fm.records_dir)          # 根目录保留
    assert not os.path.exists(os.path.join(fm.records_dir, "a"))
    assert not os.path.exists(os.path.join(fm.records_dir, "b"))


def test_delete_category_missing_root(fm):
    deleted = fm.delete_category("unit_test")
    assert deleted == {"type": "directory", "name": "unit_test", "files": 0}


def test_delete_reports_scopes(fm):
    _touch(os.path.join(fm.reports_dir, "normal", "sc1", "ts1", "a.md"))
    _touch(os.path.join(fm.reports_dir, "normal", "sc1", "ts2", "b.md"))
    _touch(os.path.join(fm.reports_dir, "extreme", "sc2", "ts3", "c.md"))
    _touch(os.path.join(fm.reports_dir, "deep_agent", "sc1", "ts4", "d.md"))

    # scenario 级：sc1（normal 下 ts1/ts2 + deep_agent 下 ts4）→ 3 目录 3 文件
    deleted = fm.delete_reports("scenario", scenario_id="sc1")
    assert deleted == {"directories": 3, "files": 3}
    # extreme/sc2 保留
    assert os.path.isdir(os.path.join(fm.reports_dir, "extreme", "sc2"))

    # category 级：extreme → 1 目录 1 文件
    deleted = fm.delete_reports("category", category="extreme")
    assert deleted == {"directories": 1, "files": 1}

    # all 级：清空剩余
    deleted = fm.delete_reports("all")
    assert deleted == {"directories": 0, "files": 0}

    with pytest.raises(ValueError):
        fm.delete_reports("bogus")


# ── Monitor 报告定位 ──────────────────────────────────────────

def test_find_monitor_report_listing_and_files(fm):
    report_file = os.path.join(
        fm.monitoring_dir, "reports",
        "risk_report_demo_monitoring_20260809_000710.md")
    # L-T3：audit 文件按天滚动 → 时间戳前 8 位日期定位
    audit_file = os.path.join(
        fm.monitoring_dir, "audit",
        "audit_demo_monitoring_20260809.jsonl")
    _touch(report_file)
    _touch(audit_file)

    parts = ["deep_agent", "da04", "20260809_000710"]

    # 两个文件都可用 → 目录列表
    result = fm.find_monitor_report("20260809_000710", parts)
    assert result["kind"] == "listing"
    assert result["listing"] == {"directory": True,
                                 "files": ["risk_report.md", "audit.jsonl"],
                                 "base_path": "/".join(parts)}

    # 子路径 risk_report.md → 直接文件
    result = fm.find_monitor_report("20260809_000710", parts + ["risk_report.md"])
    assert result == {"kind": "file", "file": report_file}

    # 子路径 audit.jsonl → 直接文件
    result = fm.find_monitor_report("20260809_000710", parts + ["audit.jsonl"])
    assert result == {"kind": "file", "file": audit_file}


def test_find_monitor_report_single_file_and_missing(fm):
    report_file = os.path.join(
        fm.monitoring_dir, "reports",
        "risk_report_demo_monitoring_20260809_000710.md")
    _touch(report_file)

    parts = ["deep_agent", "da04", "20260809_000710"]
    # 仅报告存在 → 直接返回文件
    result = fm.find_monitor_report("20260809_000710", parts)
    assert result == {"kind": "file", "file": report_file}

    # 无任何文件 → None（404）
    assert fm.find_monitor_report("20260809_999999", parts) is None


# ── demo 删除菜单原语 ─────────────────────────────────────────

def test_demo_primitives(fm):
    sc1 = os.path.join(fm.reports_dir, "normal", "sc1")
    sc2 = os.path.join(fm.reports_dir, "extreme", "other")
    _touch(os.path.join(sc1, "ts1", "a.md"))
    _touch(os.path.join(sc1, "ts2", "b.md"))
    _touch(os.path.join(sc2, "ts3", "c.md"))

    # count_dir_contents
    assert fm.count_dir_contents(sc1) == (2, 2)

    # list_scenario_dirs：全枚举 + 模糊匹配
    all_dirs = fm.list_scenario_dirs(
        ["normal", "anomalous", "boundary", "multi_agent", "extreme"])
    assert sorted(d[0] for d in all_dirs) == ["extreme", "normal"]
    matched = fm.list_scenario_dirs(
        ["normal", "extreme"], scenario_filter="sc")
    assert [d[1] for d in matched] == ["sc1"]

    # collect_ts_dirs + delete_ts_dirs
    ts_list, total_ts, total_files = fm.collect_ts_dirs([sc1, sc2])
    assert total_ts == 3 and total_files == 3
    d_dirs, d_files = fm.delete_ts_dirs(ts_list)
    assert (d_dirs, d_files) == (3, 3)
    assert fm.count_dir_contents(sc1) == (0, 0)
    assert fm.count_dir_contents(sc2) == (0, 0)


# ── MCP 申报产物分区（extra_roots 注入扩展）──────────────────────

def test_extra_roots_injects_mcp_monitoring_partition(tmp_path):
    """extra_roots 注入 mcp_monitoring 安全根后，build_tree 新增分区
    且不影响默认四区；隐藏运行时文件（daemon pid/stop）不展示。"""
    base = tmp_path / "sim"
    base.mkdir()
    mcp_dir = tmp_path / "mcp_out"
    _touch(os.path.join(mcp_dir, "reports", "risk_report_x.md"))
    _touch(os.path.join(mcp_dir, "audit", "audit_x.jsonl"))
    _touch(os.path.join(mcp_dir, "monitoring_summary.json"))
    _touch(os.path.join(mcp_dir, ".mcp_daemon.pid"))      # 运行时隐藏文件
    _touch(os.path.join(mcp_dir, ".stop_request"))        # 运行时隐藏文件
    fm = OutputFileManager(str(base), str(tmp_path),
                           extra_roots={"mcp_monitoring": str(mcp_dir)})

    tree = fm.build_tree()["tree"]
    assert "mcp_monitoring" in tree, f"缺少 mcp_monitoring 分区: {list(tree)}"
    node = tree["mcp_monitoring"]
    assert node["label"].startswith("MCP 申报监测产物"), node["label"]
    names = [(c["name"], c["type"]) for c in node["children"]]
    assert ("reports", "dir") in names, names
    assert ("audit", "dir") in names, names
    assert ("monitoring_summary.json", "file") in names, names
    assert not any(n.startswith(".") for n, _ in names), \
        f"运行时隐藏文件不应展示: {names}"
    reports = [c for c in node["children"] if c["name"] == "reports"][0]
    assert reports["children"][0]["path"] == \
        "mcp_monitoring/reports/risk_report_x.md"


def test_extra_roots_resolve_view_and_traversal_guard(tmp_path):
    """mcp_monitoring 前缀可解析；../ 越界仍被拒绝（安全机制一致）。"""
    base = tmp_path / "sim"
    base.mkdir()
    mcp_dir = tmp_path / "mcp_out"
    _touch(os.path.join(mcp_dir, "reports", "r.md"))
    _touch(os.path.join(str(tmp_path), "secret.txt"))
    fm = OutputFileManager(str(base), str(tmp_path),
                           extra_roots={"mcp_monitoring": str(mcp_dir)})

    resolved = fm.resolve("mcp_monitoring/reports/r.md")
    assert resolved == os.path.join(mcp_dir, "reports", "r.md")
    assert fm.resolve("mcp_monitoring/../secret.txt") is None
    assert fm.resolve_strict("mcp_monitoring/../secret.txt") == \
        (None, "traversal")


def test_extra_roots_delete_category_and_file(tmp_path):
    """mcp_monitoring 分类支持文件删除与分类清空（保留根目录）。"""
    base = tmp_path / "sim"
    base.mkdir()
    mcp_dir = tmp_path / "mcp_out"
    _touch(os.path.join(mcp_dir, "reports", "a.md"))
    fm = OutputFileManager(str(base), str(tmp_path),
                           extra_roots={"mcp_monitoring": str(mcp_dir)})

    deleted = fm.delete_resolved(os.path.join(mcp_dir, "reports", "a.md"))
    assert deleted["type"] == "file" and deleted["files"] == 1
    _touch(os.path.join(mcp_dir, "audit", "b.jsonl"))
    deleted = fm.delete_category("mcp_monitoring")
    assert deleted == {"type": "directory", "name": "mcp_monitoring",
                       "files": 1}
    assert os.path.isdir(mcp_dir)  # 根目录保留
