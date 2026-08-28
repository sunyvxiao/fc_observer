"""
file_manager.py — 输出文件/报告管理（U7 下沉）

将 app.py 内联约 500 行文件/报告管理逻辑下沉到 observer_core：
  - 安全根白名单 + realpath 前缀校验（防路径遍历，行为与 app.py 原实现逐字一致）
  - 文件树构建（records / monitoring / reports / unit_test 四区）
  - Monitor 报告定位（audit 文件名按 L-T3 规则按天滚动定位）
  - 文件/目录删除、分类清空、报告三级删除（all / category / scenario）
  - demo.py 删除菜单复用的场景目录枚举 / 时间戳目录收集 / 批量删除原语

纯逻辑实现，不依赖 HTTP；HTTP handler 只保留薄绑定（_send_json/_send_error/_serve_file_content），
demo.py 只保留交互菜单与打印。
"""

import os
import shutil
from typing import Dict, List, Optional, Tuple


# 报告分类目录（与 app.py CATEGORY_DIRS / EXTRA_REPORT_DIRS 一致）
CATEGORY_DIRS = ["normal", "anomalous", "boundary", "multi_agent", "extreme"]
EXTRA_REPORT_DIRS = ["deep_agent", "agent_sim"]

# 分类显示名（与 app.py CATEGORY_META 第一列一致，供文件树渲染）
CATEGORY_META = {
    "normal":      ("Normal 正常行为",      "正常开发操作，验证不产生误报"),
    "anomalous":   ("Anomalous 异常行为",   "高危命令/数据窃取/反弹Shell等攻击场景"),
    "boundary":    ("Boundary 边界场景",    "规则边界判定，验证精确区分能力"),
    "multi_agent": ("Multi-Agent 多Agent协作", "跨Agent数据流动/投毒/权限提升"),
    "extreme":     ("Extreme 极端场景",     "管道吞吐/超长命令/通信故障等极限测试"),
    "deep_agent":  ("真实Agent报告",        "真实Agent运行产生的监测报告"),
    "agent_sim":   ("模拟Agent报告",        "Agent模拟测试产生的报告"),
}


class OutputFileManager:
    """输出文件/报告管理（纯逻辑，不依赖 HTTP）。

    base_dir: observer_sim 目录（含 output/）
    project_dir: observer_sim 上级目录（含 records/）
    safe_roots: 安全根白名单，可构造参数注入（默认与 app.py _SAFE_ROOTS 一致）
    extra_roots: 额外追加的安全根（如 MCP 申报产物目录 mcp_monitoring），
        与 safe_roots 合并（已有键不覆盖），仅用于扩展分区不改变默认行为
    """

    def __init__(self, base_dir: str, project_dir: str,
                 safe_roots: Optional[Dict[str, str]] = None,
                 extra_roots: Optional[Dict[str, str]] = None):
        self.base_dir = base_dir
        self.project_dir = project_dir
        # 安全目录白名单：仅允许管理系统自身产生的文件（前缀 -> 绝对根路径）
        if safe_roots is None:
            safe_roots = {
                "records": os.path.join(project_dir, "records"),
                "monitoring": os.path.join(base_dir, "output", "demo_monitoring"),
                "reports": os.path.realpath(os.path.join(base_dir, "output", "reports")),
                "unit_test": os.path.join(base_dir, "output", "unit_test"),
            }
        self.safe_roots: Dict[str, str] = dict(safe_roots)
        if extra_roots:
            for key, root in extra_roots.items():
                self.safe_roots.setdefault(key, root)
        # 派生便捷路径
        self.reports_dir = self.safe_roots["reports"]
        self.monitoring_dir = self.safe_roots["monitoring"]
        self.records_dir = self.safe_roots["records"]
        self.unit_test_dir = self.safe_roots["unit_test"]
        self.category_dirs = list(CATEGORY_DIRS)
        self.extra_report_dirs = list(EXTRA_REPORT_DIRS)

    # ══════════════════════════════════════════════════════════
    #  路径解析（防路径遍历）
    # ══════════════════════════════════════════════════════════

    def resolve(self, path: str) -> Optional[str]:
        """前缀匹配 + realpath 前缀校验，返回安全解析后的绝对路径；拒绝返回 None。

        与 app.py _serve_file_view 的解析行为逐字一致：
        先按 "prefix/..." 前缀匹配安全根，realpath 越界则继续尝试下一个根；
        同时支持直接用完整根路径开头匹配（files/view 特有）。
        """
        if not path:
            return None
        for prefix, root in self.safe_roots.items():
            # path 可以是 "records/xxx"、"monitoring/reports/xxx"、"reports/xxx" 等
            if path.startswith(prefix + "/") or path == prefix:
                resolved = os.path.realpath(
                    os.path.join(root, path[len(prefix) + 1:] if path != prefix else ""))
                if not resolved.startswith(os.path.realpath(root) + os.sep) \
                        and resolved != os.path.realpath(root):
                    continue
                return resolved
            # 也支持直接用完整路径匹配
            if path.startswith(root):
                resolved = os.path.realpath(path)
                if resolved.startswith(os.path.realpath(root) + os.sep) \
                        or resolved == os.path.realpath(root):
                    return resolved
        return None

    def resolve_strict(self, path: str) -> Tuple[Optional[str], Optional[str]]:
        """严格解析（供 files/delete 使用），与 app.py _handle_files_delete 逐字一致。

        返回 (resolved, error)：
          resolved 为绝对路径、error 为 None 表示成功；
          error = "traversal"      → 前缀匹配但 realpath 越界；
          error = "unknown_prefix" → 无任何前缀匹配。
        """
        for prefix, root in self.safe_roots.items():
            if path.startswith(prefix + "/") or path == prefix:
                resolved = os.path.realpath(
                    os.path.join(root, path[len(prefix) + 1:] if path != prefix else ""))
                safe_root = os.path.realpath(root)
                if not resolved.startswith(safe_root + os.sep) and resolved != safe_root:
                    return None, "traversal"
                return resolved, None
        return None, "unknown_prefix"

    # ══════════════════════════════════════════════════════════
    #  文件树构建（GET /api/files/tree 数据源）
    # ══════════════════════════════════════════════════════════

    def _scan_dir_files(self, dirpath: str, base_dir: str,
                        path_prefix: str = "", _depth: int = 0) -> List[Dict]:
        """递归扫描目录下的文件，返回文件树节点列表。

        path_prefix: 所有文件路径前添加的分类前缀（如 "monitoring"）
        """
        if _depth > 5:
            return []
        items = []
        try:
            entries = sorted(os.listdir(dirpath))
        except PermissionError:
            return []
        for name in entries:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, base_dir)
            if name.startswith("."):
                continue
            if os.path.isdir(full):
                children = self._scan_dir_files(full, base_dir, path_prefix, _depth + 1)
                item = {"name": name, "type": "dir"}
                if children:
                    item["children"] = children
                else:
                    item["children"] = []
                items.append(item)
            elif os.path.isfile(full):
                path = os.path.join(path_prefix, rel) if path_prefix else rel
                # 统一正斜杠（与 resolve 的前缀匹配约定一致，Windows 下可用）
                path = path.replace(os.sep, "/")
                items.append({
                    "name": name,
                    "type": "file",
                    "size": os.path.getsize(full),
                    "path": path,
                })
        return items

    def build_tree(self, category_meta: Optional[Dict] = None) -> Dict:
        """构建四区文件树（records / monitoring / reports / unit_test）。

        返回 {"tree": {...}}，字段与 app.py _get_files_tree 逐字一致。
        """
        meta = category_meta if category_meta is not None else CATEGORY_META
        tree = {}

        # 1. 录制文件 (records/)
        if os.path.isdir(self.records_dir):
            records_tree = []
            for d in sorted(os.listdir(self.records_dir), reverse=True):
                dpath = os.path.join(self.records_dir, d)
                if not os.path.isdir(dpath):
                    continue
                children = self._scan_dir_files(dpath, self.records_dir, "records")
                if children:
                    records_tree.append({
                        "name": d, "type": "dir",
                        "children": children,
                    })
            if records_tree:
                tree["records"] = {"label": "录制文件", "icon": "🎬",
                                   "children": records_tree}

        # 2. 监测报告 (output/demo_monitoring/)
        mon_tree = []
        mon_base = self.monitoring_dir
        if os.path.isdir(mon_base):
            for sub in ["reports", "audit", "graphs"]:
                sub_path = os.path.join(mon_base, sub)
                if os.path.isdir(sub_path):
                    children = self._scan_dir_files(sub_path, mon_base, "monitoring")
                    if children:
                        mon_tree.append({
                            "name": sub, "type": "dir",
                            "children": children,
                        })
            # monitoring_summary.json
            summary_path = os.path.join(mon_base, "monitoring_summary.json")
            if os.path.isfile(summary_path):
                mon_tree.append({
                    "name": "monitoring_summary.json",
                    "type": "file",
                    "size": os.path.getsize(summary_path),
                    "path": "monitoring/monitoring_summary.json",
                })
        if mon_tree:
            tree["monitoring"] = {"label": "监测报告 (Agent)", "icon": "📡",
                                  "children": mon_tree}

        # 3. 场景模拟报告 (output/reports/)
        if os.path.isdir(self.reports_dir):
            rep_tree = []
            for cat_id in sorted(os.listdir(self.reports_dir)):
                cat_path = os.path.join(self.reports_dir, cat_id)
                if not os.path.isdir(cat_path):
                    continue
                cat_children = []
                for sc_dir in sorted(os.listdir(cat_path)):
                    sc_path = os.path.join(cat_path, sc_dir)
                    if not os.path.isdir(sc_path):
                        continue
                    children = self._scan_dir_files(sc_path, self.reports_dir, "reports")
                    if children:
                        cat_children.append({
                            "name": sc_dir, "type": "dir",
                            "children": children,
                        })
                if cat_children:
                    cat_name = meta.get(cat_id, (cat_id,))[0]
                    rep_tree.append({
                        "name": f"{cat_name}", "type": "dir",
                        "children": cat_children,
                    })
            if rep_tree:
                tree["reports"] = {"label": "场景模拟报告", "icon": "📊",
                                   "children": rep_tree}

        # 4. pytest 测试输出 (output/unit_test/)
        ut_path = self.unit_test_dir
        if os.path.isdir(ut_path):
            children = self._scan_dir_files(ut_path, ut_path, "unit_test")
            if children:
                tree["unit_test"] = {"label": "Pytest 测试输出", "icon": "🧪",
                                     "children": children}

        # 5. MCP 申报监测产物（extra_roots 注入的 mcp_monitoring 分区）
        #    顶层子目录（reports/audit/graphs…）+ 顶层文件（monitoring_summary.json 等）；
        #    隐藏文件（daemon pid/stop 运行时文件）由扫描器自动跳过。
        if "mcp_monitoring" in self.safe_roots:
            mcp_root = self.safe_roots["mcp_monitoring"]
            if os.path.isdir(mcp_root):
                mcp_children: List[Dict] = []
                try:
                    entries = sorted(os.listdir(mcp_root))
                except PermissionError:
                    entries = []
                for name in entries:
                    if name.startswith("."):
                        continue
                    full = os.path.join(mcp_root, name)
                    if os.path.isdir(full):
                        children = self._scan_dir_files(
                            full, mcp_root, "mcp_monitoring")
                        mcp_children.append({
                            "name": name, "type": "dir",
                            "children": children,
                        })
                    elif os.path.isfile(full):
                        mcp_children.append({
                            "name": name, "type": "file",
                            "size": os.path.getsize(full),
                            "path": f"mcp_monitoring/{name}",
                        })
                if mcp_children:
                    tree["mcp_monitoring"] = {
                        "label": "MCP 申报监测产物 (WorkBuddy)",
                        "icon": "🤖",
                        "children": mcp_children,
                    }

        return {"tree": tree}

    # ══════════════════════════════════════════════════════════
    #  Monitor 报告定位（GET /api/reports/view 回退分支）
    # ══════════════════════════════════════════════════════════

    def find_monitor_report(self, ts: str, path_parts: List[str]) -> Optional[Dict]:
        """定位 Monitor 报告文件，与 app.py _serve_monitor_report 行为逐字一致。

        ts: 时间戳字符串如 20260809_000710
        path_parts: 路径分段如 ['deep_agent', 'da04', '20260809_000710']

        返回：
          {"kind": "file", "file": <绝对路径>}            → 直接提供该文件
          {"kind": "listing", "listing": {directory...}} → 返回目录列表 JSON
          None                                            → 找不到（404）
        """
        reports_dir = os.path.join(self.monitoring_dir, "reports")
        audit_dir = os.path.join(self.monitoring_dir, "audit")

        report_file = os.path.join(reports_dir,
                                   f"risk_report_demo_monitoring_{ts}.md")
        # L-T3: audit 文件按天滚动 → 用报告时间戳的前 8 位日期定位
        audit_file = os.path.join(audit_dir,
                                  f"audit_demo_monitoring_{ts[:8]}.jsonl")

        # 检查是否有额外子路径（如 risk_report.md、audit.jsonl）
        if len(path_parts) > 3:
            sub = path_parts[3]
            if sub == "risk_report.md" and os.path.isfile(report_file):
                return {"kind": "file", "file": report_file}
            elif sub == "audit.jsonl" and os.path.isfile(audit_file):
                return {"kind": "file", "file": audit_file}

        # 列出该时间戳下可用的文件
        available = []
        if os.path.isfile(report_file):
            available.append("risk_report.md")
        if os.path.isfile(audit_file):
            available.append("audit.jsonl")

        if not available:
            return None

        if len(available) == 1 and os.path.isfile(report_file):
            # 只有一个报告文件，直接返回
            return {"kind": "file", "file": report_file}

        # 多个文件：返回目录列表
        return {
            "kind": "listing",
            "listing": {"directory": True, "files": available,
                        "base_path": "/".join(path_parts)},
        }

    # ══════════════════════════════════════════════════════════
    #  删除原语
    # ══════════════════════════════════════════════════════════

    def delete_resolved(self, resolved: str) -> Dict:
        """删除已通过安全校验的绝对路径（文件或目录）。

        返回 deleted 统计（字段与 app.py _handle_files_delete 一致）：
          {"type": "directory"|"file", "name": ..., "files": N}
        """
        if os.path.isdir(resolved):
            deleted_files = sum(len(files) for _, _, files in os.walk(resolved))
            shutil.rmtree(resolved, ignore_errors=True)
            return {"type": "directory", "name": os.path.basename(resolved),
                    "files": deleted_files}
        else:
            os.remove(resolved)
            return {"type": "file", "name": os.path.basename(resolved),
                    "files": 1}

    def delete_category(self, category: str) -> Dict:
        """清空某个分类根目录下的全部内容（保留根目录本身）。

        返回 {"type": "directory", "name": category, "files": N}，
        字段与 app.py _handle_files_delete_category 一致；根目录不存在时 files=0。
        """
        root = self.safe_roots[category]
        if not os.path.isdir(root):
            return {"type": "directory", "name": category, "files": 0}
        # 统计并删除目录下所有文件和子目录
        total_files = 0
        for _root, _dirs, files in os.walk(root):
            for f in files:
                file_path = os.path.join(_root, f)
                try:
                    os.remove(file_path)
                    total_files += 1
                except OSError:
                    pass
        # 删除空子目录
        for _root, dirs, _files in os.walk(root, topdown=False):
            for d in dirs:
                try:
                    os.rmdir(os.path.join(_root, d))
                except OSError:
                    pass
        return {"type": "directory", "name": category, "files": total_files}

    def _delete_ts_under(self, dir_path: str) -> Tuple[int, int]:
        """删除 dir_path 下的所有时间戳子目录，返回 (删除目录数, 删除文件数)。"""
        deleted_dirs = 0
        deleted_files = 0
        if not os.path.isdir(dir_path):
            return 0, 0
        for ts_dir in os.listdir(dir_path):
            ts_path = os.path.join(dir_path, ts_dir)
            if os.path.isdir(ts_path):
                count = sum(len(files) for _, _, files in os.walk(ts_path))
                deleted_files += count
                deleted_dirs += 1
                shutil.rmtree(ts_path, ignore_errors=True)
        return deleted_dirs, deleted_files

    def _delete_ts_under_cat(self, cat_dir: str) -> Tuple[int, int]:
        """删除分类目录下所有场景（cat → scenario → ts 三层）的时间戳子目录。

        与 app.py _delete_reports_all/_delete_reports_category 原实现一致。
        """
        deleted_dirs = 0
        deleted_files = 0
        if not os.path.isdir(cat_dir):
            return 0, 0
        for scenario_dir in os.listdir(cat_dir):
            scenario_path = os.path.join(cat_dir, scenario_dir)
            if os.path.isdir(scenario_path):
                d, f = self._delete_ts_under(scenario_path)
                deleted_dirs += d
                deleted_files += f
        return deleted_dirs, deleted_files

    def delete_reports(self, scope: str, category: str = "",
                       scenario_id: str = "") -> Dict:
        """报告三级删除（all / category / scenario），
        返回 {"directories": N, "files": N}，与 app.py _delete_reports_* 一致。
        """
        deleted_dirs = 0
        deleted_files = 0
        all_categories = list(self.category_dirs) + self.extra_report_dirs

        if scope == "all":
            for cat_id in all_categories:
                d, f = self._delete_ts_under_cat(
                    os.path.join(self.reports_dir, cat_id))
                deleted_dirs += d
                deleted_files += f
        elif scope == "category":
            d, f = self._delete_ts_under_cat(
                os.path.join(self.reports_dir, category))
            deleted_dirs += d
            deleted_files += f
        elif scope == "scenario":
            dirs_to_search = [category] if category else all_categories
            for cat_id in dirs_to_search:
                scenario_dir = os.path.join(self.reports_dir, cat_id, scenario_id)
                d, f = self._delete_ts_under(scenario_dir)
                deleted_dirs += d
                deleted_files += f
        else:
            raise ValueError(
                f"Invalid scope: {scope}. Use 'all', 'category', or 'scenario'")

        return {"directories": deleted_dirs, "files": deleted_files}

    # ══════════════════════════════════════════════════════════
    #  demo 删除菜单原语（交互与打印保留在 demo 层）
    # ══════════════════════════════════════════════════════════

    def count_dir_contents(self, path: str) -> Tuple[int, int]:
        """统计目录下的时间戳子目录数和文件总数。"""
        if not os.path.isdir(path):
            return 0, 0
        ts_dirs = 0
        file_count = 0
        for entry in os.listdir(path):
            entry_path = os.path.join(path, entry)
            if os.path.isdir(entry_path):
                ts_dirs += 1
                for _dp, _dn, fn in os.walk(entry_path):
                    file_count += len(fn)
        return ts_dirs, file_count

    def collect_ts_dirs(self, scenario_paths: List[str]) -> Tuple[List[str], int, int]:
        """收集场景目录下的全部时间戳子目录，返回 (ts_dirs_list, total_ts, total_files)。"""
        ts_dirs_list: List[str] = []
        total_ts = 0
        total_files = 0
        for scenario_path in scenario_paths:
            if not os.path.isdir(scenario_path):
                continue
            n_dirs, n_files = self.count_dir_contents(scenario_path)
            total_ts += n_dirs
            total_files += n_files
            for entry in os.listdir(scenario_path):
                entry_path = os.path.join(scenario_path, entry)
                if os.path.isdir(entry_path):
                    ts_dirs_list.append(entry_path)
        return ts_dirs_list, total_ts, total_files

    def delete_ts_dirs(self, paths: List[str]) -> Tuple[int, int]:
        """删除指定的时间戳子目录列表，返回 (删除目录数, 删除文件数)。"""
        deleted_dirs = 0
        deleted_files = 0
        for p in paths:
            if os.path.isdir(p):
                # 统计文件数
                for _dp, _dn, fn in os.walk(p):
                    deleted_files += len(fn)
                shutil.rmtree(p)
                deleted_dirs += 1
        return deleted_dirs, deleted_files

    def list_scenario_dirs(self, categories: List[str],
                           scenario_filter: str = "") -> List[Tuple[str, str, str]]:
        """按分类枚举报告场景目录，可选模糊匹配场景名（demo 按场景删除）。

        返回 [(category, scenario_dir_name, scenario_path)]。
        """
        matched = []
        for cat in categories:
            cat_path = os.path.join(self.reports_dir, cat)
            if not os.path.isdir(cat_path):
                continue
            for scenario_dir_name in sorted(os.listdir(cat_path)):
                if scenario_filter and scenario_filter not in scenario_dir_name:
                    continue
                matched.append(
                    (cat, scenario_dir_name, os.path.join(cat_path, scenario_dir_name)))
        return matched
