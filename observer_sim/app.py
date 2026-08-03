"""
app.py — 方寸观察者模拟学习系统 Web 模式

功能:
  - ThreadingHTTPServer 提供 HTTP 服务（每请求独立线程）
  - 14 个 API 端点（JSON / SSE / 静态文件）
  - StreamScenarioRunner 适配层（将 ScenarioRunner 流程 yield 为 step_data）
  - SSE 实时推送场景运行过程
  - 路径安全校验（防路径遍历攻击）
  - 零 pip install 依赖，全部使用 Python 标准库

用法:
    python app.py              # 启动 Web 服务器 (localhost:8080)
    python app.py --port 9090  # 指定端口

与 CLI 模式 (demo.py) 并存，互不干扰。observer_core/ 零改动。
"""

import sys
import os
import json
import time
import glob
import yaml
import queue
import shutil
import threading
import urllib.parse
import webbrowser
import subprocess
import logging
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# 抑制 logging 的 stderr 输出
logging.basicConfig(level=logging.WARNING, format='%(message)s')
for handler in logging.root.handlers:
    handler.stream = open(os.devnull, 'w', encoding='utf-8')

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analysis_panels import SA
from models.event import RawEvent
from models.virtual_clock import VirtualClock
from models.risk import RiskLevel, DecisionAction, ActionTier
from observer_core.monitoring.event_normalizer import EventNormalizer
from observer_core.monitoring.rule_engine import RuleEngine
from observer_core.judgment.risk_scorer import RiskScorer
from observer_core.judgment.baseline_checker import BaselineChecker
from observer_core.judgment.decision_engine import DecisionEngine
from observer_core.blocking.blocking_coordinator import BlockingCoordinator
from observer_core.blocking.command_sender import MockCommandSender
from observer_core.audit.behavior_graph import BehaviorGraph
from observer_core.audit.audit_logger import AuditLogger
from observer_core.audit.report_exporter import ReportExporter
from observer_core.audit.output_path_manager import RunOutputManager
from collector.simulation_collector import SimulationCollector

# ── 全局常量 ──────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)          # ~/projects/observer_sim
SCENARIOS_DIR = os.path.join(BASE_DIR, "scenarios")
REPORTS_DIR = os.path.realpath(os.path.join(BASE_DIR, "output", "reports"))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DEMO_DIR = os.path.join(PROJECT_DIR, "deep-agents-demo")
RECORDS_DIR = os.path.join(PROJECT_DIR, "records")

CATEGORY_DIRS = ["normal", "anomalous", "boundary", "multi_agent", "extreme"]
CATEGORY_META = {
    "normal":      ("Normal 正常行为",      "正常开发操作，验证不产生误报"),
    "anomalous":   ("Anomalous 异常行为",   "高危命令/数据窃取/反弹Shell等攻击场景"),
    "boundary":    ("Boundary 边界场景",    "规则边界判定，验证精确区分能力"),
    "multi_agent": ("Multi-Agent 多Agent协作", "跨Agent数据流动/投毒/权限提升"),
    "extreme":     ("Extreme 极端场景",     "管道吞吐/超长命令/通信故障等极限测试"),
}

# ── 线程安全全局状态 ──────────────────────────────────────────
active_runs = {}      # run_id -> Queue
run_results = {}      # run_id -> result dict
run_status = {}       # run_id -> "running" / "completed" / "error"
run_all_progress = {"completed": 0, "total": 0, "current_scenario": "", "status": "idle"}


# ── StreamScenarioRunner 适配层 ──────────────────────────────
# Phase 2 实现。当前为占位存根。
class StreamScenarioRunner:
    """
    app.py 专用适配层。
    复用 ScenarioRunner 的组件初始化逻辑，但将命令式流程转为生成器。
    不修改 ScenarioRunner 和 observer_core/ 的任何代码。
    """

    def __init__(self, base_dir, output_dir, category, scenario_id):
        self.base_dir = base_dir
        self.output_dir = output_dir
        # 统一架构: 使用 SimulationCollector 替代直接创建 VirtualClock
        self.collector = SimulationCollector({
            "virtual_clock": {"start_ns": 1718092800000000000}
        })
        self.clock = self.collector.clock  # 共享时钟引用
        self.normalizer = EventNormalizer(clock=self.clock, window_size=10)
        self.engine = RuleEngine()
        self.engine.load_rules(os.path.join(base_dir, 'rules', 'default_policy.yaml'))
        self.baseline = BaselineChecker(min_warm_events=5)
        self.scorer = RiskScorer()
        self.scorer.register_default_dimensions()
        self.decision_engine = DecisionEngine()
        self.cmd_sender = MockCommandSender()
        self.cmd_sender.connect('mock_pipe')
        self.blocking_coord = BlockingCoordinator(
            clock=self.clock, sender=self.cmd_sender, output_dir=output_dir)
        self.behavior_graph = BehaviorGraph()
        self.audit_logger = AuditLogger(output_dir=output_dir)
        self.report_exporter = ReportExporter(output_dir=output_dir)
        self.run_mgr = RunOutputManager(output_dir, category, scenario_id)
        self.audit_logger.set_output_dir(self.run_mgr.audit_dir)
        self.report_exporter.set_output_dir(self.run_mgr.report_dir)
        self.blocking_coord.set_output_dir(self.run_mgr.evidence_dir)
        self.behavior_graph.reset()
        self.cmd_sender.clear()
        self.stats = {
            'total': 0, 'allow': 0, 'alert': 0, 'block': 0,
            'max_score': 0.0, 'matched_rules': [], 'escalation_count': 0,
        }

    def run_stream(self, scenario_path):
        """生成器：每处理一个事件 yield step_data 字典"""
        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        scenario = data['scenario']
        self.audit_logger.start_scenario(scenario['id'])
        events = scenario['event_sequence']
        total = len(events)

        # 统一架构: 使用 Collector 提供事件
        self.collector.load_scenario(scenario_path)
        raw_events = list(self.collector.start())

        for i, raw in enumerate(raw_events, 1):
            # 微小延迟让 SSE 客户端有时间连接和接收
            delay_ms = events[i - 1].get('delay_ms', 0) if i - 1 < len(events) else 0
            if delay_ms > 0:
                time.sleep(min(delay_ms / 1000.0, 0.3))
            yield self._process_one_event(raw, scenario, i, total)

        self.audit_logger.close()
        files = self._generate_reports(scenario)
        panel = self._build_analysis_panel(scenario)

        yield {
            "type": "done",
            "analysis_panel": panel,
            "files_generated": files,
            "statistics": self.stats.copy(),
        }

    def _process_one_event(self, raw, scenario, seq, total):
        """处理单个事件，接受 RawEvent，返回结构化 step_data"""
        norm = self.normalizer.normalize(raw)
        if 'normal' in raw.agent_id:
            self.baseline.collect(norm)
        match = self.engine.match(norm)
        context = self.normalizer.get_agent_context(raw.agent_id)
        self.scorer.set_baseline(self.baseline.get_baseline_dict())
        assessment = self.scorer.assess(norm, match, context)
        decision = self.decision_engine.decide(
            assessment, event_id=raw.event_id, agent_id=raw.agent_id)

        blocking_result = self.blocking_coord.execute(norm, decision)
        self.behavior_graph.add_event(
            norm, assessment=assessment, decision=decision,
            blocking_result=blocking_result,
            matched_rules=[r.rule_id for r in match.matched_rules])
        desc = self._build_desc(norm)
        self.audit_logger.log_event(
            norm, assessment=assessment, decision=decision,
            blocking_result=blocking_result,
            matched_rules=[r.rule_id for r in match.matched_rules],
            description=desc)

        # 更新统计
        self.stats['total'] += 1
        if assessment.overall_score > self.stats['max_score']:
            self.stats['max_score'] = assessment.overall_score
        if blocking_result.blocked:
            self.stats['block'] += 1
        elif decision.action == DecisionAction.ALERT:
            self.stats['alert'] += 1
        else:
            self.stats['allow'] += 1
        for rule_id in assessment.matched_rule_ids:
            if rule_id not in [r[0] for r in self.stats['matched_rules']]:
                self.stats['matched_rules'].append((rule_id, assessment.overall_score))

        return {
            "type": "step", "seq": seq, "total": total,
            "event_type": norm.event_type,
            "raw_input": desc,
            "normalized_summary": norm.command_string or f"{norm.event_type}: {desc}",
            "rule_match": {
                "hit": match.has_match,
                "rules": [{"id": r.rule_id, "name": r.name, "action": r.action}
                          for r in match.matched_rules]
            },
            "risk_score": assessment.overall_score,
            "risk_level": assessment.risk_level.value,
            "risk_breakdown": {
                "rule": assessment.dimension_scores[0].score if len(assessment.dimension_scores) > 0 else 0,
                "baseline": assessment.dimension_scores[1].score if len(assessment.dimension_scores) > 1 else 0,
                "context": assessment.dimension_scores[2].score if len(assessment.dimension_scores) > 2 else 0,
                "sequence": assessment.dimension_scores[3].score if len(assessment.dimension_scores) > 3 else 0,
            },
            "decision_action": decision.action.value,
            "decision_tier": decision.tier.value,
            "disposal_summary": self._disposal_text(blocking_result, decision),
            "timestamp_ns": norm.timestamp_ns,
        }

    def _build_desc(self, norm):
        if norm.event_type == "exec":
            return norm.command_string or f"{norm.raw.executable} {' '.join(norm.raw.arguments or [])}"
        elif norm.event_type == "file_open":
            return f"{norm.raw.file_op} {norm.raw.file_path}"
        elif norm.event_type == "net_conn":
            return f"{norm.raw.remote_addr}:{norm.raw.remote_port}"
        return norm.event_type

    def _disposal_text(self, blocking_result, decision):
        if blocking_result.blocked:
            return "硬中断! 进程树终止" if blocking_result.tier == ActionTier.TIER3 else "阻止访问! 返回 EPERM"
        elif decision.action == DecisionAction.ALERT:
            return "告警! 记录审计日志"
        return "放行"

    def _build_analysis_panel(self, scenario):
        sid = scenario['id']
        prefix = ''
        for part in sid.split('-'):
            if part and part[0].isalpha() and part[0].lower() in 'nabme':
                prefix = part.lower()
                break
        data = SA.get(prefix, (scenario.get('description', ''), '', '', ''))
        return {
            "test_purpose": data[0], "risk_findings": data[1],
            "root_cause": data[2], "comprehensive_strategy": data[3],
            "max_risk_score": self.stats['max_score'],
            "matched_rules": self.stats['matched_rules'],
        }

    def _generate_reports(self, scenario):
        files = []
        report_path = self.report_exporter.export_scenario_report(
            scenario_id=scenario['id'], scenario_name=scenario['name'],
            audit_logger=self.audit_logger, behavior_graph=self.behavior_graph,
            scenario_description=scenario.get('description', ''),
            expected_result=scenario.get('expected_result', ''))
        files.append({"type": "md", "path": os.path.relpath(report_path, self.base_dir)})
        graph_path = self.run_mgr.graph_filepath(f'graph_{scenario["id"]}.json')
        self.behavior_graph.save_json(graph_path)
        files.append({"type": "json", "path": os.path.relpath(graph_path, self.base_dir)})
        if self.audit_logger.current_file:
            files.append({"type": "jsonl", "path": os.path.relpath(
                self.audit_logger.current_file, self.base_dir)})
        if self.stats['block'] > 0:
            evidence_path = self.blocking_coord.save_evidence(
                filepath=self.run_mgr.evidence_filepath(f'evidence_{scenario["id"]}.json'))
            files.append({"type": "json", "path": os.path.relpath(evidence_path, self.base_dir)})
        return files


# ══════════════════════════════════════════════════════════════
#  HTTP Handler
# ══════════════════════════════════════════════════════════════
class ObserverHTTPHandler(BaseHTTPRequestHandler):
    """Web 请求处理器，包含路由分发、JSON API、SSE 端点、静态文件服务"""

    # ── 路由分发 ──────────────────────────────────────────────
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            self._serve_static_file("static/index.html", "text/html")
        elif path == "/api/health":
            self._send_json({"status": "ok", "timestamp": datetime.now().isoformat()})
        elif path == "/api/categories":
            self._send_json(self._get_categories())
        elif path == "/api/scenarios":
            category = params.get("category", [None])[0]
            self._send_json(self._get_scenarios(category))
        elif path.startswith("/api/scenario/stream/"):
            run_id = path.split("/")[-1]
            self._handle_sse_stream(run_id)
        elif path == "/api/scenario/run-all":
            category = params.get("category", [None])[0]
            self._handle_sse_run_all(category)
        elif path == "/api/scenario/run-all/progress":
            self._send_json(run_all_progress)
        elif path.startswith("/api/scenario/result/"):
            run_id = path.split("/")[-1]
            self._send_json(self._get_result(run_id))
        elif path == "/api/reports/list":
            self._send_json(self._get_report_list())
        elif path == "/api/reports/view":
            file_path = params.get("path", [None])[0]
            self._serve_report_file(file_path)
        elif path == "/api/demo/workspace-tree":
            self._send_json(self._get_workspace_tree())
        elif path == "/api/demo/task-instruction":
            self._send_json(self._get_task_instruction())
        elif path == "/api/demo/recordings":
            self._send_json(self._get_recordings())
        elif path == "/api/demo/recording-detail":
            session_id = params.get("session_id", [None])[0]
            self._send_json(self._get_recording_detail(session_id))
        elif path == "/api/demo/file-content":
            file_path = params.get("path", [None])[0]
            self._serve_demo_file(file_path)
        elif path.startswith("/api/demo/run-record"):
            self._handle_sse_run_record()
        elif path.startswith("/api/demo/replay"):
            session_id = params.get("session_id", [None])[0]
            self._handle_sse_replay(session_id)
        else:
            self._send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        body = self._read_body()

        if path == "/api/scenario/run":
            self._handle_scenario_run(body)
        elif path == "/api/tests/run":
            self._handle_tests_run()
        elif path == "/api/reports/delete":
            self._handle_reports_delete(body)
        elif path == "/api/server/stop":
            self._handle_server_stop()
        elif path == "/api/demo/delete-recordings":
            self._handle_delete_recordings(body)
        elif path == "/api/demo/delete-replay-output":
            self._handle_delete_replay_output(body)
        else:
            self._send_error(404, "Not Found")

    def do_OPTIONS(self):
        """CORS 预检"""
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    # ── 抑制默认日志 ─────────────────────────────────────────
    def log_message(self, format, *args):
        pass  # 静默 HTTP 请求日志

    # ══════════════════════════════════════════════════════════
    #  JSON API 实现
    # ══════════════════════════════════════════════════════════

    def _get_categories(self):
        """GET /api/categories — 返回 5 个分类及其场景数"""
        categories = []
        for cat_id in CATEGORY_DIRS:
            cat_path = os.path.join(SCENARIOS_DIR, cat_id)
            count = len(glob.glob(os.path.join(cat_path, "*.yaml"))) if os.path.isdir(cat_path) else 0
            name, desc = CATEGORY_META.get(cat_id, (cat_id, ""))
            categories.append({
                "id": cat_id,
                "name": name,
                "count": count,
                "description": desc,
            })
        return {"categories": categories}

    def _get_scenarios(self, category):
        """GET /api/scenarios?category=xxx — 返回分类下的场景列表"""
        if category and category not in CATEGORY_DIRS:
            return {"error": f"Unknown category: {category}", "scenarios": []}

        scenarios = []
        dirs = [category] if category else CATEGORY_DIRS
        for cat_id in dirs:
            cat_path = os.path.join(SCENARIOS_DIR, cat_id)
            if not os.path.isdir(cat_path):
                continue
            for yaml_file in sorted(glob.glob(os.path.join(cat_path, "*.yaml"))):
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    sc = data.get("scenario", {})
                    events = sc.get("event_sequence", [])
                    # 从事件序列推断 expected_blocks/alerts
                    expected_blocks = None
                    expected_alerts = None
                    if "expected" in sc:
                        expected_blocks = sc["expected"].get("blocks")
                        expected_alerts = sc["expected"].get("alerts")
                    scenarios.append({
                        "id": sc.get("id", os.path.basename(yaml_file).replace(".yaml", "")),
                        "name": sc.get("name", ""),
                        "category": cat_id,
                        "event_count": len(events),
                        "expected_blocks": expected_blocks,
                        "expected_alerts": expected_alerts,
                        "description": sc.get("description", ""),
                    })
                except Exception as e:
                    scenarios.append({
                        "id": os.path.basename(yaml_file).replace(".yaml", ""),
                        "name": f"[解析错误] {yaml_file}",
                        "category": cat_id,
                        "event_count": 0,
                        "expected_blocks": None,
                        "expected_alerts": None,
                        "description": str(e),
                    })
        return {"category": category, "scenarios": scenarios}

    def _get_result(self, run_id):
        """GET /api/scenario/result/{run_id} — 查询运行结果"""
        if run_id in run_results:
            return run_results[run_id]
        if run_id in run_status:
            return {"run_id": run_id, "status": run_status[run_id]}
        return {"error": f"Run ID not found: {run_id}", "status": "not_found"}

    def _get_report_list(self):
        """GET /api/reports/list — 列出所有报告文件（含场景中文名）"""
        result = {}
        if not os.path.isdir(REPORTS_DIR):
            return {"categories": result}

        # 构建场景 ID -> 中文名映射
        scenario_names = {}
        for cat_id in CATEGORY_DIRS:
            cat_path = os.path.join(SCENARIOS_DIR, cat_id)
            if not os.path.isdir(cat_path):
                continue
            for yaml_file in glob.glob(os.path.join(cat_path, "*.yaml")):
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    sc = data.get("scenario", {})
                    sid = sc.get("id", "")
                    sname = sc.get("name", "")
                    if sid:
                        scenario_names[sid] = sname
                        # 同时存储下划线版本
                        scenario_names[sid.replace("-", "_")] = sname
                        scenario_names[sid.replace("_", "-")] = sname
                except Exception:
                    pass

        for cat_id in CATEGORY_DIRS:
            cat_dir = os.path.join(REPORTS_DIR, cat_id)
            if not os.path.isdir(cat_dir):
                continue
            scenarios = []
            for scenario_dir in sorted(os.listdir(cat_dir)):
                scenario_path = os.path.join(cat_dir, scenario_dir)
                if not os.path.isdir(scenario_path):
                    continue
                timestamps = sorted(
                    [d for d in os.listdir(scenario_path)
                     if os.path.isdir(os.path.join(scenario_path, d))],
                    reverse=True
                )
                if timestamps:
                    # 查找中文名
                    name = scenario_names.get(scenario_dir, "")
                    if not name:
                        # 尝试变体
                        name = scenario_names.get(
                            scenario_dir.replace("_", "-"),
                            scenario_names.get(scenario_dir.replace("-", "_"), scenario_dir))
                    scenarios.append({
                        "scenario_id": scenario_dir,
                        "scenario_name": name,
                        "timestamps": timestamps,
                        "count": len(timestamps),
                    })
            if scenarios:
                result[cat_id] = scenarios
        return {"categories": result}

    def _serve_report_file(self, file_path):
        """GET /api/reports/view?path=... — 安全读取报告文件"""
        if not file_path:
            self._send_error(400, "Missing 'path' parameter")
            return

        # 路径安全校验: realpath + 前缀检查
        requested = os.path.realpath(os.path.join(REPORTS_DIR, file_path))
        if not requested.startswith(REPORTS_DIR + os.sep) and requested != REPORTS_DIR:
            self._send_error(403, "Access denied: path traversal detected")
            return

        # 如果路径是目录，自动查找其中的 .md 报告文件
        if os.path.isdir(requested):
            md_files = glob.glob(os.path.join(requested, "*.md"))
            if md_files:
                requested = sorted(md_files)[0]
            else:
                # 列出目录内容供前端选择
                all_files = []
                for f in sorted(os.listdir(requested)):
                    fp = os.path.join(requested, f)
                    if os.path.isfile(fp):
                        all_files.append(f)
                if all_files:
                    self._send_json({"directory": True, "files": all_files,
                                     "base_path": file_path})
                    return
                self._send_error(404, f"No files in directory: {file_path}")
                return

        if not os.path.isfile(requested):
            self._send_error(404, f"File not found: {file_path}")
            return

        try:
            with open(requested, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(requested, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

        # 根据扩展名设置 Content-Type
        ext = os.path.splitext(requested)[1].lower()
        ct_map = {
            ".md": "text/markdown; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".jsonl": "application/json; charset=utf-8",
            ".yaml": "text/yaml; charset=utf-8",
            ".txt": "text/plain; charset=utf-8",
        }
        content_type = ct_map.get(ext, "text/plain; charset=utf-8")
        self._send_text(content, content_type=content_type)

    # ══════════════════════════════════════════════════════════
    #  POST API 实现
    # ══════════════════════════════════════════════════════════

    def _handle_scenario_run(self, body):
        """POST /api/scenario/run — 启动场景运行（Phase 2 完善）"""
        scenario_id = body.get("scenario_id", "")
        category = body.get("category", "")

        if not scenario_id:
            self._send_error(400, "Missing 'scenario_id'")
            return

        # 查找场景文件
        scenario_path = self._find_scenario(scenario_id, category)
        if not scenario_path:
            self._send_error(404, f"Scenario not found: {scenario_id}")
            return

        # 生成 run_id
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_id = f"{scenario_id}_{timestamp}"

        # 创建事件队列
        event_queue = queue.Queue()
        active_runs[run_id] = event_queue
        run_status[run_id] = "running"

        # 启动后台工作线程
        def _worker():
            try:
                runner = StreamScenarioRunner(
                    BASE_DIR, os.path.join(BASE_DIR, "output"),
                    category or "unknown", scenario_id)
                for step_data in runner.run_stream(scenario_path):
                    event_queue.put(step_data)
                    if step_data.get("type") == "done":
                        run_results[run_id] = {
                            "run_id": run_id,
                            "scenario_id": scenario_id,
                            "status": "completed",
                            "analysis_panel": step_data.get("analysis_panel", {}),
                            "files_generated": step_data.get("files_generated", []),
                            "statistics": step_data.get("statistics", {}),
                        }
                        run_status[run_id] = "completed"
            except Exception as e:
                event_queue.put({"type": "error", "message": str(e)})
                run_status[run_id] = "error"
                run_results[run_id] = {
                    "run_id": run_id,
                    "scenario_id": scenario_id,
                    "status": "error",
                    "error": str(e),
                }
            finally:
                if run_id in active_runs:
                    del active_runs[run_id]

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

        self._send_json({
            "run_id": run_id,
            "scenario_id": scenario_id,
            "status": "running",
        })

    def _handle_tests_run(self):
        """POST /api/tests/run — 同步运行单元测试"""
        start_time = time.time()
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/", "-x", "--tb=short", "-q"],
                capture_output=True, text=True, timeout=120,
                cwd=BASE_DIR, encoding="utf-8", errors="replace",
            )
            duration = round(time.time() - start_time, 1)
            output = result.stdout
            # 解析 pytest 输出
            passed, failed, total = 0, 0, 0
            failed_names = []
            for line in output.split("\n"):
                line = line.strip()
                if "passed" in line or "failed" in line:
                    import re
                    m_passed = re.search(r"(\d+) passed", line)
                    m_failed = re.search(r"(\d+) failed", line)
                    if m_passed:
                        passed = int(m_passed.group(1))
                    if m_failed:
                        failed = int(m_failed.group(1))
                if line.startswith("FAILED"):
                    # 提取失败测试名
                    parts = line.split("::", 1)
                    if len(parts) > 1:
                        failed_names.append(parts[-1].strip())
            total = passed + failed
            self._send_json({
                "status": "completed" if result.returncode == 0 else "failed",
                "total": total,
                "passed": passed,
                "failed": failed,
                "failed_names": failed_names,
                "duration_seconds": duration,
                "output": output[-2000:],  # 截取最后 2000 字符
            })
        except subprocess.TimeoutExpired:
            self._send_error(504, "Tests timed out (120s)")
        except Exception as e:
            self._send_error(500, f"Failed to run tests: {e}")

    def _handle_reports_delete(self, body):
        """POST /api/reports/delete — 三级删除"""
        scope = body.get("scope", "")

        if scope == "all":
            return self._delete_reports_all()
        elif scope == "category":
            category = body.get("category", "")
            if not category or category not in CATEGORY_DIRS:
                self._send_error(400, f"Invalid category: {category}")
                return
            return self._delete_reports_category(category)
        elif scope == "scenario":
            scenario_id = body.get("scenario_id", "")
            category = body.get("category", "")
            if not scenario_id:
                self._send_error(400, "Missing 'scenario_id'")
                return
            return self._delete_reports_scenario(scenario_id, category)
        else:
            self._send_error(400, f"Invalid scope: {scope}. Use 'all', 'category', or 'scenario'")

    def _delete_reports_all(self):
        """删除所有报告"""
        deleted_dirs = 0
        deleted_files = 0
        if os.path.isdir(REPORTS_DIR):
            for cat_id in CATEGORY_DIRS:
                cat_dir = os.path.join(REPORTS_DIR, cat_id)
                if os.path.isdir(cat_dir):
                    for scenario_dir in os.listdir(cat_dir):
                        scenario_path = os.path.join(cat_dir, scenario_dir)
                        if os.path.isdir(scenario_path):
                            for ts_dir in os.listdir(scenario_path):
                                ts_path = os.path.join(scenario_path, ts_dir)
                                if os.path.isdir(ts_path):
                                    count = sum(len(files) for _, _, files in os.walk(ts_path))
                                    deleted_files += count
                                    deleted_dirs += 1
                                    shutil.rmtree(ts_path, ignore_errors=True)
        self._send_json({
            "success": True,
            "deleted": {"directories": deleted_dirs, "files": deleted_files},
        })

    def _delete_reports_category(self, category):
        """删除指定分类的所有报告"""
        deleted_dirs = 0
        deleted_files = 0
        cat_dir = os.path.join(REPORTS_DIR, category)
        if os.path.isdir(cat_dir):
            for scenario_dir in os.listdir(cat_dir):
                scenario_path = os.path.join(cat_dir, scenario_dir)
                if os.path.isdir(scenario_path):
                    for ts_dir in os.listdir(scenario_path):
                        ts_path = os.path.join(scenario_path, ts_dir)
                        if os.path.isdir(ts_path):
                            count = sum(len(files) for _, _, files in os.walk(ts_path))
                            deleted_files += count
                            deleted_dirs += 1
                            shutil.rmtree(ts_path, ignore_errors=True)
        self._send_json({
            "success": True,
            "deleted": {"directories": deleted_dirs, "files": deleted_files},
        })

    def _delete_reports_scenario(self, scenario_id, category):
        """删除指定场景的所有报告"""
        deleted_dirs = 0
        deleted_files = 0
        dirs_to_search = [category] if category else CATEGORY_DIRS
        for cat_id in dirs_to_search:
            scenario_dir = os.path.join(REPORTS_DIR, cat_id, scenario_id)
            if os.path.isdir(scenario_dir):
                for ts_dir in os.listdir(scenario_dir):
                    ts_path = os.path.join(scenario_dir, ts_dir)
                    if os.path.isdir(ts_path):
                        count = sum(len(files) for _, _, files in os.walk(ts_path))
                        deleted_files += count
                        deleted_dirs += 1
                        shutil.rmtree(ts_path, ignore_errors=True)
        self._send_json({
            "success": True,
            "deleted": {"directories": deleted_dirs, "files": deleted_files},
        })

    def _handle_server_stop(self):
        """POST /api/server/stop — 关闭服务器"""
        for run_id, q in list(active_runs.items()):
            try:
                q.put_nowait({"type": "error", "message": "Server shutting down", "code": "server_shutdown"})
            except Exception:
                pass
        time.sleep(0.5)
        def _shutdown():
            self.server.shutdown()
        threading.Thread(target=_shutdown, daemon=True).start()
        self._send_json({"success": True, "message": "Server shutting down"})

    # ══════════════════════════════════════════════════════════
    #  SSE 端点（Phase 2 完善实现）
    # ══════════════════════════════════════════════════════════

    def _handle_sse_stream(self, run_id):
        """GET /api/scenario/stream/{run_id} — SSE 事件流"""
        event_queue = active_runs.get(run_id)
        if not event_queue:
            # 检查是否已完成
            result = run_results.get(run_id)
            if result:
                self._send_json(result)
                return
            self._send_error(404, f"Run ID not found: {run_id}")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        try:
            while True:
                try:
                    data = event_queue.get(timeout=15)
                except queue.Empty:
                    hb = json.dumps({"type": "heartbeat", "timestamp": datetime.now().isoformat()})
                    self.wfile.write(f"data: {hb}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    continue

                event_type = data.get("type", "step")
                json_data = json.dumps(data, ensure_ascii=False, default=str)
                self.wfile.write(f"data: {json_data}\n\n".encode("utf-8"))
                self.wfile.flush()

                if event_type in ("done", "error"):
                    break

        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            if run_id in active_runs:
                del active_runs[run_id]

    def _handle_sse_run_all(self, category):
        """GET /api/scenario/run-all?category=xxx — SSE 批量运行"""
        # 收集场景列表
        dirs = [category] if category and category in CATEGORY_DIRS else CATEGORY_DIRS
        scenario_files = []
        for cat_id in dirs:
            cat_path = os.path.join(SCENARIOS_DIR, cat_id)
            if not os.path.isdir(cat_path):
                continue
            for yaml_file in sorted(glob.glob(os.path.join(cat_path, "*.yaml"))):
                scenario_files.append((cat_id, yaml_file))

        total = len(scenario_files)
        if total == 0:
            self._send_error(400, "No scenarios found")
            return

        # 更新全局进度
        run_all_progress.update({"completed": 0, "total": total, "current_scenario": "", "status": "running"})

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        try:
            for idx, (cat_id, yaml_file) in enumerate(scenario_files):
                # 读取场景 ID
                try:
                    with open(yaml_file, 'r', encoding='utf-8') as f:
                        sc_data = yaml.safe_load(f)
                    sc_id = sc_data['scenario']['id']
                    sc_name = sc_data['scenario']['name']
                except Exception:
                    sc_id = os.path.basename(yaml_file).replace('.yaml', '')
                    sc_name = sc_id

                run_all_progress["current_scenario"] = sc_id

                # 发送 scenario_start
                start_data = json.dumps({
                    "type": "scenario_start",
                    "scenario_id": sc_id,
                    "scenario_name": sc_name,
                    "category": cat_id,
                    "completed": idx,
                    "total": total,
                }, ensure_ascii=False, default=str)
                self.wfile.write(f"data: {start_data}\n\n".encode("utf-8"))
                self.wfile.flush()

                # 运行场景
                try:
                    runner = StreamScenarioRunner(
                        BASE_DIR, os.path.join(BASE_DIR, "output"),
                        cat_id, sc_id)
                    for step_data in runner.run_stream(yaml_file):
                        json_data = json.dumps(step_data, ensure_ascii=False, default=str)
                        self.wfile.write(f"data: {json_data}\n\n".encode("utf-8"))
                        self.wfile.flush()
                except Exception as e:
                    err_data = json.dumps({
                        "type": "error",
                        "scenario_id": sc_id,
                        "message": str(e),
                    }, ensure_ascii=False, default=str)
                    self.wfile.write(f"data: {err_data}\n\n".encode("utf-8"))
                    self.wfile.flush()

                run_all_progress["completed"] = idx + 1

                # 发送 scenario_done
                done_data = json.dumps({
                    "type": "scenario_done",
                    "scenario_id": sc_id,
                    "completed": idx + 1,
                    "total": total,
                }, ensure_ascii=False, default=str)
                self.wfile.write(f"data: {done_data}\n\n".encode("utf-8"))
                self.wfile.flush()

            # 全部完成
            all_done_data = json.dumps({
                "type": "all_done",
                "total": total,
                "completed": total,
            }, ensure_ascii=False, default=str)
            self.wfile.write(f"data: {all_done_data}\n\n".encode("utf-8"))
            self.wfile.flush()

        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            run_all_progress["status"] = "idle"

    # ══════════════════════════════════════════════════════════
    #  辅助方法
    # ══════════════════════════════════════════════════════════

    # ══════════════════════════════════════════════════════════
    #  录制-回放 Demo API
    # ══════════════════════════════════════════════════════════

    def _get_workspace_tree(self):
        """GET /api/demo/workspace-tree — 返回 Agent 工作目录文件树"""
        ws_dir = os.path.join(DEMO_DIR, "workspace")
        if not os.path.isdir(ws_dir):
            return {"tree": [], "base_path": ""}
        tree = self._build_file_tree(ws_dir, ws_dir)
        return {"tree": tree, "base_path": ws_dir}

    def _build_file_tree(self, root_dir, base_dir, max_depth=4, _depth=0):
        """递归构建文件树结构"""
        if _depth >= max_depth:
            return []
        items = []
        try:
            entries = sorted(os.listdir(root_dir))
        except PermissionError:
            return items
        # 目录先，然后文件
        dirs = [e for e in entries if os.path.isdir(os.path.join(root_dir, e)) and not e.startswith('.')]
        files = [e for e in entries if os.path.isfile(os.path.join(root_dir, e))]
        # 包含隐藏文件（如 .env、.db_credentials）
        hidden_files = [e for e in entries if os.path.isfile(os.path.join(root_dir, e)) and e.startswith('.')]
        hidden_dirs = [e for e in entries if os.path.isdir(os.path.join(root_dir, e)) and e.startswith('.') and e not in ('__pycache__', '.git')]
        dirs = sorted(dirs + hidden_dirs)
        files = sorted(files + hidden_files)
        for d in dirs:
            dpath = os.path.join(root_dir, d)
            rel = os.path.relpath(dpath, base_dir)
            children = self._build_file_tree(dpath, base_dir, max_depth, _depth + 1)
            items.append({"name": d, "type": "dir", "path": rel, "children": children})
        for f in files:
            fpath = os.path.join(root_dir, f)
            rel = os.path.relpath(fpath, base_dir)
            try:
                size = os.path.getsize(fpath)
            except OSError:
                size = 0
            items.append({"name": f, "type": "file", "path": rel, "size": size})
        return items

    def _get_task_instruction(self):
        """GET /api/demo/task-instruction — 返回任务提示词内容"""
        ti_path = os.path.join(DEMO_DIR, "task_instruction.txt")
        if not os.path.isfile(ti_path):
            return {"content": "", "error": "task_instruction.txt not found"}
        with open(ti_path, "r", encoding="utf-8") as f:
            content = f.read()
        return {"content": content}

    def _get_recordings(self):
        """GET /api/demo/recordings — 列出所有录制会话"""
        if not os.path.isdir(RECORDS_DIR):
            return {"recordings": []}
        recordings = []
        for session_dir in sorted(os.listdir(RECORDS_DIR), reverse=True):
            session_path = os.path.join(RECORDS_DIR, session_dir)
            if not os.path.isdir(session_path):
                continue
            meta = self._read_session_meta(session_path)
            meta["session_id"] = session_dir
            # 统计回放产物目录数量
            replay_runs = self._list_replay_runs(session_path)
            meta["has_replay"] = len(replay_runs) > 0
            meta["replay_count"] = len(replay_runs)
            meta["replay_runs"] = replay_runs
            recordings.append(meta)
        return {"recordings": recordings}

    def _read_session_meta(self, session_path):
        """读取录制会话的 meta.yaml"""
        meta_path = os.path.join(session_path, "meta.yaml")
        meta = {"event_count": 0, "duration_seconds": 0, "collect_mode": "unknown",
                "agent_id": "", "start_time": "", "end_time": ""}
        if not os.path.isfile(meta_path):
            return meta
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if ":" not in line or line.startswith("#"):
                        continue
                    key, _, val = line.partition(":")
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if "_" in val:
                        meta[key] = val
                    else:
                        try:
                            if "." in val:
                                meta[key] = float(val)
                            else:
                                meta[key] = int(val)
                        except ValueError:
                            meta[key] = val
        except Exception:
            pass
        return meta

    def _list_replay_runs(self, session_path):
        """列出会话目录下的所有回放产物目录"""
        runs = []
        if not os.path.isdir(session_path):
            return runs
        for entry in sorted(os.listdir(session_path), reverse=True):
            if entry.startswith("replay_output") and os.path.isdir(os.path.join(session_path, entry)):
                replay_dir = os.path.join(session_path, entry)
                # 从目录名提取时间戳
                ts = entry.replace("replay_output_", "").replace("replay_output", "")
                # 统计文件数
                file_count = sum(len(f) for _, _, f in os.walk(replay_dir))
                # 查找回放摘要
                summary_path = os.path.join(replay_dir, "replay_summary.json")
                summary = {}
                if os.path.isfile(summary_path):
                    try:
                        with open(summary_path, "r", encoding="utf-8") as f:
                            summary = json.load(f)
                    except Exception:
                        pass
                runs.append({
                    "replay_dir": entry,
                    "replay_id": ts or "original",
                    "file_count": file_count,
                    "total": summary.get("total", 0),
                    "allow": summary.get("allow", 0),
                    "alert": summary.get("alert", 0),
                    "block": summary.get("block", 0),
                    "replay_time": summary.get("replay_time", ts),
                })
        return runs

    def _get_recording_detail(self, session_id):
        """GET /api/demo/recording-detail?session_id=xxx — 获取录制详情及多次回放产物"""
        if not session_id:
            return {"error": "Missing session_id"}
        session_path = os.path.join(RECORDS_DIR, session_id)
        if not os.path.isdir(session_path):
            return {"error": f"Session not found: {session_id}"}
        meta = self._read_session_meta(session_path)
        meta["session_id"] = session_id
        # 列出所有回放产物目录
        replay_runs = self._list_replay_runs(session_path)
        # 每个回放目录的文件列表
        for run in replay_runs:
            replay_dir_path = os.path.join(session_path, run["replay_dir"])
            files = []
            for root, dirs, fnames in os.walk(replay_dir_path):
                dirs.sort()
                for fname in sorted(fnames):
                    fpath = os.path.join(root, fname)
                    rel = os.path.relpath(fpath, session_path)
                    try:
                        size = os.path.getsize(fpath)
                    except OSError:
                        size = 0
                    files.append({"name": fname, "path": rel, "size": size})
            run["files"] = files
        # 录制文件
        events_path = os.path.join(session_path, "events.jsonl")
        recorded_files = []
        if os.path.isfile(events_path):
            recorded_files.append({
                "name": "events.jsonl",
                "path": "events.jsonl",
                "size": os.path.getsize(events_path),
            })
        meta_path = os.path.join(session_path, "meta.yaml")
        if os.path.isfile(meta_path):
            recorded_files.append({
                "name": "meta.yaml",
                "path": "meta.yaml",
                "size": os.path.getsize(meta_path),
            })
        return {
            "meta": meta,
            "recorded_files": recorded_files,
            "replay_runs": replay_runs,
            "base_path": session_path,
        }

    def _serve_demo_file(self, file_path):
        """GET /api/demo/file-content?path=... — 安全读取 demo 相关文件"""
        if not file_path:
            self._send_error(400, "Missing 'path' parameter")
            return
        # 允许访问: deep-agents-demo/ (含 workspace) 和 records/ 目录下的文件
        # 安全校验: 防路径遍历
        ws_dir = os.path.join(DEMO_DIR, "workspace")
        allowed_bases = [ws_dir, DEMO_DIR, RECORDS_DIR]
        resolved = None
        for base in allowed_bases:
            candidate = os.path.realpath(os.path.join(base, file_path))
            if (candidate.startswith(base + os.sep) or candidate == base) and os.path.isfile(candidate):
                resolved = candidate
                break
        if not resolved:
            self._send_error(403, "Access denied")
            return
        if not os.path.isfile(resolved):
            self._send_error(404, f"File not found: {file_path}")
            return
        try:
            with open(resolved, "r", encoding="utf-8") as f:
                content = f.read(200000)  # 限制 200KB
        except UnicodeDecodeError:
            self._send_error(415, "Binary file cannot be previewed")
            return
        ext = os.path.splitext(resolved)[1].lower()
        ct_map = {
            ".md": "text/markdown; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".jsonl": "application/json; charset=utf-8",
            ".yaml": "text/yaml; charset=utf-8",
            ".txt": "text/plain; charset=utf-8",
            ".csv": "text/csv; charset=utf-8",
            ".sh": "text/plain; charset=utf-8",
            ".py": "text/plain; charset=utf-8",
        }
        content_type = ct_map.get(ext, "text/plain; charset=utf-8")
        self._send_text(content, content_type=content_type)

    def _handle_sse_run_record(self):
        """GET /api/demo/run-record — SSE: 运行 da04 场景并录制"""
        from recorder.session_recorder import SessionRecorder

        # 加载 da04 场景
        scenario_path = os.path.join(SCENARIOS_DIR, "deep_agent", "da04_production_demo.yaml")
        if not os.path.isfile(scenario_path):
            self._send_error(404, "da04_production_demo.yaml not found")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        try:
            # 初始化录制器
            recorder = SessionRecorder(
                records_dir=RECORDS_DIR,
                agent_id="deep-agent-fintech-analyst",
                collect_mode="simulation",
            )
            recorder.start()
            session_id = recorder.session_id

            # 发送开始事件
            self._sse_send({"type": "recording_start", "session_id": session_id})

            # 加载场景并转换事件
            tool_calls, base_ts, scenario = self._load_da04_scenario()
            raw_events = self._tool_calls_to_events(
                tool_calls, base_ts, "deep-agent-fintech-analyst", "da04")

            # 初始化 observer_core pipeline
            runner = StreamScenarioRunner(
                BASE_DIR, os.path.join(BASE_DIR, "output"),
                "deep_agent", "da04")

            total = len(raw_events)
            stats = {"total": 0, "allow": 0, "alert": 0, "block": 0}
            start_time = time.time()

            for i, raw in enumerate(raw_events, 1):
                # 录制原始事件
                recorder.write_event(raw)
                # 处理事件
                step_data = runner._process_one_event(raw, scenario, i, total)
                step_data["type"] = "step"
                self._sse_send(step_data)
                # 统计
                stats["total"] += 1
                action = step_data.get("decision_action", "ALLOW")
                if action == "BLOCK":
                    stats["block"] += 1
                elif action == "ALERT":
                    stats["alert"] += 1
                else:
                    stats["allow"] += 1
                time.sleep(0.15)  # 演示用延迟

            # 停止录制
            recorder.stop()

            # 发送完成事件
            self._sse_send({
                "type": "recording_done",
                "session_id": session_id,
                "event_count": stats["total"],
                "stats": stats,
                "duration_seconds": round(time.time() - start_time, 2),
            })

        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            try:
                self._sse_send({"type": "error", "message": str(e)})
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    def _load_da04_scenario(self):
        """加载 da04 场景 YAML 并返回 (tool_calls, base_ts, scenario_dict)"""
        scenario_path = os.path.join(SCENARIOS_DIR, "deep_agent", "da04_production_demo.yaml")
        with open(scenario_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        tool_calls = data.get("tool_calls", [])
        scenario_meta = data.get("scenario", {})
        base_ts = scenario_meta.get("base_timestamp_ns", 1718092800000000000)
        # 构建兼容 StreamScenarioRunner 的 scenario 字典
        scenario = {
            "id": scenario_meta.get("id", "da04"),
            "name": scenario_meta.get("name", "Q3 商业报表分析"),
            "description": scenario_meta.get("description", ""),
            "expected_result": scenario_meta.get("expected_result", ""),
        }
        return tool_calls, base_ts, scenario

    def _tool_calls_to_events(self, tool_calls, base_ts, agent_id, scenario_id):
        """将 DeepAgent YAML tool_calls 转换为 RawEvent 列表"""
        _EXEC_TOOLS = {"execute", "execute_command", "run_command", "shell", "bash"}
        _READ_TOOLS = {"read_file", "read", "cat", "list_files", "grep", "glob"}
        _WRITE_TOOLS = {"write_file", "write", "edit_file", "edit", "patch"}
        _NET_TOOLS = {"web_fetch", "fetch", "web_search", "browse", "curl"}
        events = []
        ts = base_ts
        pid = 10000
        for i, tc in enumerate(tool_calls):
            tool_name = tc.get("tool", "").lower().strip()
            tool_input = tc.get("input", {})
            delay_ms = tc.get("delay_ms", 100)
            ts += int(delay_ms * 1_000_000)
            eid = f"evt-{agent_id}-{i+1:04d}"
            pid += 1
            base_kwargs = dict(
                event_id=eid, timestamp_ns=ts, pid=pid, ppid=1,
                agent_id=agent_id, agent_framework="deep-agent",
            )
            if tool_name in _EXEC_TOOLS:
                cmd = tool_input.get("command", "echo hello")
                parts = cmd.split()
                events.append(RawEvent(
                    event_type="exec",
                    executable=parts[0] if parts else cmd,
                    arguments=parts[1:] if len(parts) > 1 else [],
                    **base_kwargs,
                ))
            elif tool_name in _READ_TOOLS:
                fpath = tool_input.get("path", "/tmp/unknown")
                events.append(RawEvent(
                    event_type="file_open",
                    file_path=fpath, file_op="read",
                    **base_kwargs,
                ))
            elif tool_name in _WRITE_TOOLS:
                fpath = tool_input.get("path", "/tmp/unknown")
                events.append(RawEvent(
                    event_type="file_open",
                    file_path=fpath, file_op="write",
                    **base_kwargs,
                ))
            elif tool_name in _NET_TOOLS:
                url = tool_input.get("url", "https://example.com")
                host, port = self._extract_host_port(url)
                events.append(RawEvent(
                    event_type="net_conn",
                    remote_addr=host, remote_port=port,
                    **base_kwargs,
                ))
            else:
                events.append(RawEvent(
                    event_type="exec",
                    executable=tool_name, arguments=[],
                    **base_kwargs,
                ))
        return events

    def _extract_host_port(self, url):
        """从 URL 提取 host 和 port"""
        import re
        m = re.match(r'(\w+)://([^:/]+)(?::(\d+))?', url)
        if m:
            host = m.group(2)
            port = int(m.group(3)) if m.group(3) else (443 if url.startswith("https") else 80)
            return host, port
        return "unknown.host", 443

    def _sse_send(self, data):
        """SSE 发送单条消息"""
        json_data = json.dumps(data, ensure_ascii=False, default=str)
        self.wfile.write(f"data: {json_data}\n\n".encode("utf-8"))
        self.wfile.flush()

    def _handle_delete_recordings(self, body):
        """POST /api/demo/delete-recordings — 删除录制会话"""
        scope = body.get("scope", "")
        session_id = body.get("session_id", "")
        deleted_dirs = 0
        deleted_files = 0
        if scope == "all":
            if os.path.isdir(RECORDS_DIR):
                for d in os.listdir(RECORDS_DIR):
                    dpath = os.path.join(RECORDS_DIR, d)
                    if os.path.isdir(dpath):
                        count = sum(len(f) for _, _, f in os.walk(dpath))
                        deleted_files += count
                        deleted_dirs += 1
                        shutil.rmtree(dpath, ignore_errors=True)
        elif scope == "session" and session_id:
            session_path = os.path.join(RECORDS_DIR, session_id)
            if os.path.isdir(session_path):
                count = sum(len(f) for _, _, f in os.walk(session_path))
                deleted_files += count
                deleted_dirs += 1
                shutil.rmtree(session_path, ignore_errors=True)
        else:
            self._send_error(400, f"Invalid scope or missing session_id")
            return
        self._send_json({
            "success": True,
            "deleted": {"directories": deleted_dirs, "files": deleted_files},
        })

    def _handle_sse_replay(self, session_id):
        """GET /api/demo/replay?session_id=xxx — SSE: 回放指定录制会话"""
        if not session_id:
            self._send_error(400, "Missing session_id")
            return
        session_path = os.path.join(RECORDS_DIR, session_id)
        if not os.path.isdir(session_path):
            self._send_error(404, f"Session not found: {session_id}")
            return
        events_path = os.path.join(session_path, "events.jsonl")
        if not os.path.isfile(events_path):
            self._send_error(404, "events.jsonl not found in session")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        try:
            from recorder.replay_engine import ReplayEngine
            from collector.file_replay_collector import FileReplayCollector

            # 生成带时间戳的回放输出目录名
            replay_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            replay_dir_name = f"replay_output_{replay_ts}"
            replay_output_dir = os.path.join(session_path, replay_dir_name)

            self._sse_send({
                "type": "replay_start",
                "session_id": session_id,
                "replay_id": replay_ts,
                "message": f"开始回放会话 {session_id}"
            })

            # 加载事件文件统计行数
            with open(events_path, "r", encoding="utf-8") as f:
                total_lines = sum(1 for line in f if line.strip())

            self._sse_send({
                "type": "replay_info",
                "total_events": total_lines,
                "replay_dir": replay_dir_name,
            })

            # 配置 ReplayEngine 使用自定义输出目录
            config = {"virtual_clock": {"start_ns": 1718092800000000000}}
            engine = ReplayEngine(config)

            # 调用 replay() 获取结果
            result = engine.replay(session_path, agent_id=session_id)

            # 将默认的 replay_output/ 重命名为带时间戳的目录
            default_output = os.path.join(session_path, "replay_output")
            if os.path.isdir(default_output) and default_output != replay_output_dir:
                if os.path.isdir(replay_output_dir):
                    shutil.rmtree(replay_output_dir, ignore_errors=True)
                os.rename(default_output, replay_output_dir)

            # 发送逐事件回放步骤（从摘要中获取统计）
            stats = {
                "total": result.get("total", 0),
                "allow": result.get("allow", 0),
                "alert": result.get("alert", 0),
                "block": result.get("block", 0),
            }

            # 列出回放产物文件
            replay_files = []
            if os.path.isdir(replay_output_dir):
                for root, dirs, files in os.walk(replay_output_dir):
                    dirs.sort()
                    for fname in sorted(files):
                        fpath = os.path.join(root, fname)
                        rel = os.path.relpath(fpath, session_path)
                        try:
                            size = os.path.getsize(fpath)
                        except OSError:
                            size = 0
                        replay_files.append({"name": fname, "path": rel, "size": size})

            self._sse_send({
                "type": "replay_done",
                "session_id": session_id,
                "replay_id": replay_ts,
                "replay_dir": replay_dir_name,
                "stats": stats,
                "event_count": stats["total"],
                "replay_files": replay_files,
                "output_dir": os.path.relpath(replay_output_dir, session_path),
            })

        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            try:
                self._sse_send({"type": "error", "message": str(e)})
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    def _handle_delete_replay_output(self, body):
        """POST /api/demo/delete-replay-output — 删除指定回放产物"""
        session_id = body.get("session_id", "")
        replay_dir = body.get("replay_dir", "")
        if not session_id or not replay_dir:
            self._send_error(400, "Missing session_id or replay_dir")
            return
        # 安全校验：replay_dir 必须是 replay_output 开头
        if not replay_dir.startswith("replay_output"):
            self._send_error(400, "Invalid replay_dir name")
            return
        session_path = os.path.join(RECORDS_DIR, session_id)
        replay_path = os.path.join(session_path, replay_dir)
        # 路径安全检查
        real_path = os.path.realpath(replay_path)
        real_session = os.path.realpath(session_path)
        if not real_path.startswith(real_session + os.sep):
            self._send_error(403, "Path traversal detected")
            return
        if not os.path.isdir(replay_path):
            self._send_error(404, f"Replay dir not found: {replay_dir}")
            return
        count = sum(len(f) for _, _, f in os.walk(replay_path))
        shutil.rmtree(replay_path, ignore_errors=True)
        self._send_json({
            "success": True,
            "deleted": {"directories": 1, "files": count},
            "replay_dir": replay_dir,
        })

    def _find_scenario(self, scenario_id, category=None):
        """查找场景 YAML 文件路径"""
        # 尝试多种 ID 格式：原始 / 下划线 / 短横线
        variants = [
            scenario_id,
            scenario_id.replace('-', '_'),
            scenario_id.replace('_', '-'),
        ]
        dirs = [category] if category else CATEGORY_DIRS
        # 精确匹配
        for cat_id in dirs:
            for variant in variants:
                candidate = os.path.join(SCENARIOS_DIR, cat_id, f"{variant}.yaml")
                if os.path.isfile(candidate):
                    return candidate
        # 模糊匹配（使用 ID 前缀如 a01, n01 等）
        prefix = scenario_id.split('-')[0].split('_')[0]
        if prefix:
            for cat_id in CATEGORY_DIRS:
                matches = glob.glob(os.path.join(SCENARIOS_DIR, cat_id, f"{prefix}*.yaml"))
                if matches:
                    return matches[0]
        return None

    def _read_body(self):
        """读取 POST 请求体并解析 JSON"""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        try:
            body = self.rfile.read(content_length)
            return json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _send_json(self, data, status=200):
        """发送 JSON 响应"""
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text, content_type="text/plain; charset=utf-8", status=200):
        """发送文本响应"""
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code, message):
        """发送错误响应"""
        self._send_json({"error": message}, status=code)

    def _send_cors_headers(self):
        """发送 CORS 头"""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _serve_static_file(self, rel_path, content_type):
        """服务静态文件"""
        file_path = os.path.join(BASE_DIR, rel_path)
        if not os.path.isfile(file_path):
            self._send_error(404, f"Static file not found: {rel_path}")
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            self._send_text(content, content_type=content_type)
        except Exception as e:
            self._send_error(500, f"Failed to read static file: {e}")


# ══════════════════════════════════════════════════════════════
#  入口
# ══════════════════════════════════════════════════════════════
def main():
    import argparse
    parser = argparse.ArgumentParser(description="方寸观察者 Web 模式")
    parser.add_argument("--port", type=int, default=8080, help="监听端口 (默认 8080)")
    parser.add_argument("--host", default="localhost", help="监听地址 (默认 localhost)")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--mode", type=str, default=None,
                        choices=["auto", "simulation", "strace", "ebpf"],
                        help="采集模式 (默认从 config.yaml 读取)")
    args = parser.parse_args()

    host, port = args.host, args.port

    try:
        server = ThreadingHTTPServer((host, port), ObserverHTTPHandler)
    except OSError as e:
        print(f"[错误] 端口 {port} 被占用: {e}")
        print(f"请尝试: python app.py --port {port + 1}")
        return

    url = f"http://{host}:{port}"
    print(f"╔══════════════════════════════════════════════╗")
    print(f"║    方寸观察者模拟学习系统 — Web 模式          ║")
    print(f"╠══════════════════════════════════════════════╣")
    print(f"║  地址: {url:<37s}║")
    print(f"║  按 Ctrl+C 停止服务器                        ║")
    print(f"╚══════════════════════════════════════════════╝")

    if not args.no_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在关闭服务器...")
        for run_id, q in list(active_runs.items()):
            try:
                q.put_nowait({"type": "error", "message": "Server shutting down", "code": "server_shutdown"})
            except Exception:
                pass
        time.sleep(0.3)
        server.shutdown()
        print("服务器已关闭")


if __name__ == "__main__":
    main()
