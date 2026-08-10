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
from monitor_lifecycle import MonitorLifecycleManager

# ── 全局常量 ──────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)          # ~/projects/observer_sim
SCENARIOS_DIR = os.path.join(BASE_DIR, "scenarios")
REPORTS_DIR = os.path.realpath(os.path.join(BASE_DIR, "output", "reports"))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DEMO_DIR = os.path.join(PROJECT_DIR, "deep-agents-demo")
RECORDS_DIR = os.path.join(PROJECT_DIR, "records")
MONITORING_RUN_DIR = os.path.join(PROJECT_DIR, ".monitoring")
MONITORING_FIFO = os.path.join(MONITORING_RUN_DIR, "pipe")
MONITORING_PID_FILE = os.path.join(MONITORING_RUN_DIR, "monitor.pid")
MONITORING_OUTPUT_DIR = os.path.join(BASE_DIR, "output", "demo_monitoring")
DEMO_MONITOR_SCRIPT = os.path.join(PROJECT_DIR, "scripts", "start_demo_monitoring.sh")

CATEGORY_DIRS = ["normal", "anomalous", "boundary", "multi_agent", "extreme"]
EXTRA_REPORT_DIRS = ["deep_agent", "agent_sim"]
CATEGORY_META = {
    "normal":      ("Normal 正常行为",      "正常开发操作，验证不产生误报"),
    "anomalous":   ("Anomalous 异常行为",   "高危命令/数据窃取/反弹Shell等攻击场景"),
    "boundary":    ("Boundary 边界场景",    "规则边界判定，验证精确区分能力"),
    "multi_agent": ("Multi-Agent 多Agent协作", "跨Agent数据流动/投毒/权限提升"),
    "extreme":     ("Extreme 极端场景",     "管道吞吐/超长命令/通信故障等极限测试"),
    "deep_agent":  ("真实Agent报告",        "真实Agent运行产生的监测报告"),
    "agent_sim":   ("模拟Agent报告",        "Agent模拟测试产生的报告"),
}

# ── 线程安全全局状态 ──────────────────────────────────────────
active_runs = {}      # run_id -> Queue
run_results = {}      # run_id -> result dict
run_status = {}       # run_id -> "running" / "completed" / "error"
run_all_progress = {"completed": 0, "total": 0, "current_scenario": "", "status": "idle"}
# 注意: Monitor 任务计数已迁移至 MonitorLifecycleManager, 参见 monitor_lifecycle.py


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
        elif path == "/api/files/tree":
            self._send_json(self._get_files_tree())
        elif path == "/api/files/view":
            file_path = params.get("path", [None])[0]
            self._serve_file_view(file_path)
        elif path == "/api/demo/workspace-tree":
            self._send_json(self._get_workspace_tree())
        elif path == "/api/demo/task-instruction":
            self._send_json(self._get_task_instruction())
        elif path == "/api/demo/recordings":
            self._send_json(self._get_recordings())
        elif path == "/api/demo/recording-detail":
            session_id = params.get("session_id", [None])[0]
            self._send_json(self._get_recording_detail(session_id))
        elif path == "/api/demo/scenario-samples":
            self._send_json(self._get_scenario_samples())
        elif path == "/api/demo/scenario-sample":
            scenario_id = params.get("scenario_id", [None])[0]
            self._send_json(self._get_scenario_sample(scenario_id))
        elif path == "/api/demo/file-content":
            file_path = params.get("path", [None])[0]
            self._serve_demo_file(file_path)
        elif path.startswith("/api/demo/run-record"):
            self._handle_sse_run_record()
        elif path.startswith("/api/demo/replay"):
            session_id = params.get("session_id", [None])[0]
            self._handle_sse_replay(session_id)
        elif path == "/api/demo/start-record":
            self._handle_sse_start_record()
        elif path == "/api/demo/record/start":
            self._handle_sse_record_start_only()
        elif path == "/api/demo/start-monitor":
            self._handle_sse_start_monitor()
        elif path == "/api/monitor/status":
            self._send_json(self._get_monitor_status())
        elif path == "/api/monitor/report":
            self._send_json(self._get_monitor_report())
        elif path == "/api/monitor/events":
            self._handle_sse_monitor_events()
        elif path == "/api/agent-sim/scenarios":
            self._send_json(self._get_agent_sim_scenarios())
        elif path.startswith("/api/agent-sim/run/"):
            scenario_key = path.split("/")[-1]
            self._handle_sse_agent_sim_run(scenario_key)
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
        elif path == "/api/files/delete":
            self._handle_files_delete(body)
        elif path == "/api/files/delete-category":
            self._handle_files_delete_category(body)
        elif path == "/api/server/stop":
            self._handle_server_stop()
        elif path == "/api/demo/delete-recordings":
            self._handle_delete_recordings(body)
        elif path == "/api/demo/delete-replay-output":
            self._handle_delete_replay_output(body)
        elif path == "/api/demo/record/stop":
            self._handle_record_stop()
        elif path == "/api/monitor/start":
            self._handle_monitor_start()
        elif path == "/api/monitor/stop":
            self._handle_monitor_stop()
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

    def _report_tags_path(self):
        """报告来源标签文件路径"""
        return os.path.join(MONITORING_OUTPUT_DIR, ".report_tags.json")

    def _tag_report_source(self, ts: str, source_type: str):
        """记录一次报告运行时的来源类型.

        Args:
            ts: 时间戳字符串 (YYYYMMDD_HHMMSS)
            source_type: "real_agent" | "agent_sim"
        """
        tags_path = self._report_tags_path()
        tags = {}
        if os.path.isfile(tags_path):
            try:
                with open(tags_path, "r", encoding="utf-8") as f:
                    tags = json.load(f)
            except (json.JSONDecodeError, IOError):
                tags = {}
        tags[ts] = source_type
        # 保留最近 500 条记录，防止无限增长
        if len(tags) > 500:
            sorted_keys = sorted(tags.keys())
            tags = {k: tags[k] for k in sorted_keys[-500:]}
        os.makedirs(os.path.dirname(tags_path), exist_ok=True)
        with open(tags_path, "w", encoding="utf-8") as f:
            json.dump(tags, f, ensure_ascii=False, indent=2)

    def _load_report_tags(self) -> dict:
        """加载所有报告的来源类型标签.

        Returns:
            dict: {timestamp_str: source_type}
        """
        tags_path = self._report_tags_path()
        if not os.path.isfile(tags_path):
            return {}
        try:
            with open(tags_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}

    def _get_report_list(self):
        """GET /api/reports/list — 列出所有报告文件（含场景中文名）"""
        result = {}

        # 构建场景 ID -> 中文名映射（从所有 yaml 场景文件）
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
                        scenario_names[sid.replace("-", "_")] = sname
                        scenario_names[sid.replace("_", "-")] = sname
                except Exception:
                    pass
        # 同时从 deep_agent 场景目录加载名称
        deep_agent_scenario_dir = os.path.join(SCENARIOS_DIR, "deep_agent")
        if os.path.isdir(deep_agent_scenario_dir):
            for yaml_file in glob.glob(os.path.join(deep_agent_scenario_dir, "*.yaml")):
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    sc = data.get("scenario", {})
                    sid = sc.get("id", "")
                    sname = sc.get("name", "")
                    if sid:
                        scenario_names[sid] = sname
                except Exception:
                    pass

        # ── 扫描 REPORTS_DIR（旧架构：output/reports/） ──
        if os.path.isdir(REPORTS_DIR):
            all_report_dirs = list(CATEGORY_DIRS) + EXTRA_REPORT_DIRS
            for cat_id in all_report_dirs:
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
                        name = scenario_names.get(scenario_dir, "")
                        if not name:
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

        # ── 扫描 MONITORING_OUTPUT_DIR（新架构：Monitor+FIFO 报告）──
        self._merge_monitoring_reports(result, scenario_names)

        return {"categories": result}

    def _merge_monitoring_reports(self, result: dict, scenario_names: dict):
        """将 MONITORING_OUTPUT_DIR 中的 Monitor 报告按来源分类。

        通过审计日志中的 event_id 前缀推断场景 ID（如 da_da04_001 → da04）。
        通过 .report_tags.json 区分真实Agent报告 (source_type=real_agent → deep_agent)
        与 模拟Agent报告 (source_type=agent_sim → agent_sim)。
        """
        reports_dir = os.path.join(MONITORING_OUTPUT_DIR, "reports")
        audit_dir = os.path.join(MONITORING_OUTPUT_DIR, "audit")
        if not os.path.isdir(reports_dir):
            return

        # 加载来源标签
        report_tags = self._load_report_tags()

        # 收集所有报告文件及其时间戳
        # 文件名格式: risk_report_demo_monitoring_YYYYMMDD_HHMMSS.md
        import re as _re
        report_ts_map = {}  # timestamp -> report_path
        for fname in sorted(os.listdir(reports_dir)):
            m = _re.match(r'risk_report_demo_monitoring_(\d{8}_\d{6})\.md$', fname)
            if m:
                ts = m.group(1)
                report_ts_map[ts] = os.path.join(reports_dir, fname)

        # 通过审计日志推断每个报告对应的场景
        # audit 文件格式: audit_demo_monitoring_YYYYMMDD_HHMMSS.jsonl
        ts_to_scenario = {}  # timestamp -> scenario_id
        if os.path.isdir(audit_dir):
            for fname in sorted(os.listdir(audit_dir)):
                m = _re.match(r'audit_demo_monitoring_(\d{8}_\d{6})\.jsonl$', fname)
                if not m:
                    continue
                ts = m.group(1)
                audit_path = os.path.join(audit_dir, fname)
                # 只读取非空的审计日志
                fsize = os.path.getsize(audit_path)
                if fsize == 0:
                    continue
                try:
                    with open(audit_path, "r", encoding="utf-8") as f:
                        first_line = f.readline().strip()
                    if first_line:
                        entry = json.loads(first_line)
                        event_id = entry.get("event_id", "")
                        # event_id 格式: da_da04_001 → 提取 da04
                        parts = event_id.split("_")
                        if len(parts) >= 2:
                            scenario_id = parts[1]  # da04, da05, etc.
                            ts_to_scenario[ts] = scenario_id
                except Exception:
                    pass

        # 按来源类型分组
        # 关键修复: daemon 模式下报告时间戳与审计时间戳可能不同
        # （报告在会话结束时生成，审计在会话开始时创建）。
        # 因此改为：以审计时间戳为基准，匹配最接近的稍晚报告。
        #
        # 也为 report_tags 做同样匹配：如果标签的 审计时间戳 下有报告，
        # 就用最近的报告时间戳。
        all_report_ts = sorted(report_ts_map.keys())

        deep_scenario_reports = {}   # scenario_id -> [report_timestamp_str, ...]
        sim_scenario_reports = {}    # scenario_id -> [report_timestamp_str, ...]

        for audit_ts, sid in sorted(ts_to_scenario.items()):
            # 找到最接近且 >= audit_ts 的报告时间戳
            matched_report_ts = None
            for rts in all_report_ts:
                if rts >= audit_ts:
                    matched_report_ts = rts
                    break
            if matched_report_ts is None:
                continue  # 没有对应的报告

            # 检查来源标签 (标签键也可能是审计或报告时间戳)
            source = report_tags.get(audit_ts) or report_tags.get(matched_report_ts, "real_agent")
            if source == "agent_sim":
                target = sim_scenario_reports
            else:
                target = deep_scenario_reports
            if sid not in target:
                target[sid] = []
            # 使用报告时间戳作为显示/查询键
            if matched_report_ts not in target[sid]:
                target[sid].append(matched_report_ts)

        # 合并到 result 的 deep_agent 分类
        existing_deep = {s["scenario_id"]: s for s in result.get("deep_agent", [])}
        for sid, timestamps in deep_scenario_reports.items():
            name = scenario_names.get(sid, sid)
            if sid in existing_deep:
                existing_ts = set(existing_deep[sid]["timestamps"])
                for ts in timestamps:
                    if ts not in existing_ts:
                        existing_deep[sid]["timestamps"].append(ts)
                existing_deep[sid]["timestamps"] = sorted(
                    existing_deep[sid]["timestamps"], reverse=True)
                existing_deep[sid]["count"] = len(existing_deep[sid]["timestamps"])
            else:
                existing_deep[sid] = {
                    "scenario_id": sid,
                    "scenario_name": name,
                    "timestamps": timestamps,
                    "count": len(timestamps),
                    "source_type": "real_agent",
                }
        if existing_deep:
            result["deep_agent"] = sorted(
                existing_deep.values(), key=lambda x: x["scenario_id"])

        # 合并到 result 的 agent_sim 分类 (新建)
        existing_sim = {s["scenario_id"]: s for s in result.get("agent_sim", [])}
        for sid, timestamps in sim_scenario_reports.items():
            name = scenario_names.get(sid, sid)
            if sid in existing_sim:
                existing_ts = set(existing_sim[sid]["timestamps"])
                for ts in timestamps:
                    if ts not in existing_ts:
                        existing_sim[sid]["timestamps"].append(ts)
                existing_sim[sid]["timestamps"] = sorted(
                    existing_sim[sid]["timestamps"], reverse=True)
                existing_sim[sid]["count"] = len(existing_sim[sid]["timestamps"])
            else:
                existing_sim[sid] = {
                    "scenario_id": sid,
                    "scenario_name": name,
                    "timestamps": timestamps,
                    "count": len(timestamps),
                    "source_type": "agent_sim",
                }
        if existing_sim:
            result["agent_sim"] = sorted(
                existing_sim.values(), key=lambda x: x["scenario_id"])

    def _serve_report_file(self, file_path):
        """GET /api/reports/view?path=... — 安全读取报告文件

        优先从 REPORTS_DIR 读取；若为 deep_agent 的 Monitor 时间戳格式
        (YYYYMMDD_HHMMSS) 则回退到 MONITORING_OUTPUT_DIR 查找。
        """
        if not file_path:
            self._send_error(400, "Missing 'path' parameter")
            return

        # 路径安全校验: realpath + 前缀检查
        requested = os.path.realpath(os.path.join(REPORTS_DIR, file_path))
        if not requested.startswith(REPORTS_DIR + os.sep) and requested != REPORTS_DIR:
            self._send_error(403, "Access denied: path traversal detected")
            return

        # ── 尝试从 MONITORING_OUTPUT_DIR 回退 ──
        # 当路径不在 REPORTS_DIR 时，检查是否为 Monitor 时间戳格式
        if not os.path.exists(requested):
            import re as _re2
            path_parts = file_path.replace("\\", "/").split("/")
            if len(path_parts) >= 2 and path_parts[0] in ("deep_agent", "agent_sim"):
                # 从右向左查找时间戳（支持子路径如 .../20260808_214534/report）
                ts = None
                for part in reversed(path_parts):
                    if _re2.match(r'^\d{8}_\d{6}$', part):
                        ts = part
                        break
                if ts:
                    self._serve_monitor_report(ts, path_parts)
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

        self._serve_file_content(requested)

    def _serve_monitor_report(self, ts: str, path_parts: list):
        """从 MONITORING_OUTPUT_DIR 提供 Monitor 报告。

        ts: 时间戳字符串如 20260809_000710
        path_parts: 路径分段如 ['deep_agent', 'da04', '20260809_000710']
        """
        reports_dir = os.path.join(MONITORING_OUTPUT_DIR, "reports")
        audit_dir = os.path.join(MONITORING_OUTPUT_DIR, "audit")

        report_file = os.path.join(reports_dir,
                                   f"risk_report_demo_monitoring_{ts}.md")
        audit_file = os.path.join(audit_dir,
                                  f"audit_demo_monitoring_{ts}.jsonl")

        # 检查是否有额外子路径（如 risk_report.md、audit.jsonl）
        if len(path_parts) > 3:
            sub = path_parts[3]
            if sub == "risk_report.md" and os.path.isfile(report_file):
                self._serve_file_content(report_file)
                return
            elif sub == "audit.jsonl" and os.path.isfile(audit_file):
                self._serve_file_content(audit_file)
                return

        # 列出该时间戳下可用的文件
        available = []
        if os.path.isfile(report_file):
            available.append("risk_report.md")
        if os.path.isfile(audit_file):
            available.append("audit.jsonl")

        if not available:
            self._send_error(404, f"No Monitor report found for timestamp: {ts}")
            return

        if len(available) == 1 and os.path.isfile(report_file):
            # 只有一个报告文件，直接返回
            self._serve_file_content(report_file)
            return

        # 多个文件：返回目录列表
        self._send_json({"directory": True, "files": available,
                         "base_path": "/".join(path_parts)})

    def _serve_file_content(self, filepath: str):
        """安全读取并返回文件内容"""
        if not os.path.isfile(filepath):
            self._send_error(404, f"File not found")
            return
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

        ext = os.path.splitext(filepath)[1].lower()
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
            all_valid = list(CATEGORY_DIRS) + EXTRA_REPORT_DIRS
            if not category or category not in all_valid:
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
            for cat_id in list(CATEGORY_DIRS) + EXTRA_REPORT_DIRS:
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
        dirs_to_search = [category] if category else list(CATEGORY_DIRS) + EXTRA_REPORT_DIRS
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

    # ══════════════════════════════════════════════════════════
    #  统一文件管理系统 API
    # ══════════════════════════════════════════════════════════

    # 安全目录白名单：仅允许管理系统自身产生的文件
    _SAFE_ROOTS = {
        "records": os.path.join(PROJECT_DIR, "records"),
        "monitoring": MONITORING_OUTPUT_DIR,
        "reports": REPORTS_DIR,
        "unit_test": os.path.join(BASE_DIR, "output", "unit_test"),
    }

    def _get_files_tree(self):
        """GET /api/files/tree — 返回分类文件树"""
        tree = {}

        # 1. 录制文件 (records/)
        if os.path.isdir(RECORDS_DIR):
            records_tree = []
            for d in sorted(os.listdir(RECORDS_DIR), reverse=True):
                dpath = os.path.join(RECORDS_DIR, d)
                if not os.path.isdir(dpath):
                    continue
                children = self._scan_dir_files(dpath, RECORDS_DIR, "records")
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
        mon_base = MONITORING_OUTPUT_DIR
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
        if os.path.isdir(REPORTS_DIR):
            rep_tree = []
            for cat_id in sorted(os.listdir(REPORTS_DIR)):
                cat_path = os.path.join(REPORTS_DIR, cat_id)
                if not os.path.isdir(cat_path):
                    continue
                cat_children = []
                for sc_dir in sorted(os.listdir(cat_path)):
                    sc_path = os.path.join(cat_path, sc_dir)
                    if not os.path.isdir(sc_path):
                        continue
                    children = self._scan_dir_files(sc_path, REPORTS_DIR, "reports")
                    if children:
                        cat_children.append({
                            "name": sc_dir, "type": "dir",
                            "children": children,
                        })
                if cat_children:
                    cat_name = CATEGORY_META.get(cat_id, (cat_id,))[0]
                    rep_tree.append({
                        "name": f"{cat_name}", "type": "dir",
                        "children": cat_children,
                    })
            if rep_tree:
                tree["reports"] = {"label": "场景模拟报告", "icon": "📊",
                                   "children": rep_tree}

        # 4. pytest 测试输出 (output/unit_test/)
        ut_path = os.path.join(BASE_DIR, "output", "unit_test")
        if os.path.isdir(ut_path):
            children = self._scan_dir_files(ut_path, ut_path, "unit_test")
            if children:
                tree["unit_test"] = {"label": "Pytest 测试输出", "icon": "🧪",
                                     "children": children}

        return {"tree": tree}

    def _scan_dir_files(self, dirpath, base_dir, path_prefix="", _depth=0):
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
                items.append({
                    "name": name,
                    "type": "file",
                    "size": os.path.getsize(full),
                    "path": path,
                })
        return items

    def _serve_file_view(self, file_path):
        """GET /api/files/view?path=... — 安全读取并返回任意系统输出文件内容"""
        if not file_path:
            self._send_error(400, "Missing 'path' parameter")
            return

        # 在前缀上匹配安全根目录
        resolved = None
        for prefix, root in self._SAFE_ROOTS.items():
            # path 可以是 "records/xxx"、"monitoring/reports/xxx"、"reports/xxx" 等
            if file_path.startswith(prefix + "/") or file_path == prefix:
                resolved = os.path.realpath(os.path.join(root, file_path[len(prefix) + 1:] if file_path != prefix else ""))
                if not resolved.startswith(os.path.realpath(root) + os.sep) and resolved != os.path.realpath(root):
                    resolved = None
                    continue
                break
            # 也支持直接用完整路径匹配
            if file_path.startswith(root):
                resolved = os.path.realpath(file_path)
                if resolved.startswith(os.path.realpath(root) + os.sep) or resolved == os.path.realpath(root):
                    break
                resolved = None

        if resolved is None:
            self._send_error(403, "Access denied: invalid path")
            return

        if not os.path.exists(resolved):
            self._send_error(404, f"File not found: {file_path}")
            return

        if os.path.isdir(resolved):
            # 列出目录内容
            try:
                entries = []
                for name in sorted(os.listdir(resolved)):
                    full = os.path.join(resolved, name)
                    if name.startswith("."):
                        continue
                    entries.append({
                        "name": name,
                        "type": "dir" if os.path.isdir(full) else "file",
                    })
                self._send_json({"directory": True, "files": entries,
                                 "base_path": file_path})
            except PermissionError:
                self._send_error(403, "Permission denied")
            return

        self._serve_file_content(resolved)

    def _handle_files_delete(self, body):
        """POST /api/files/delete — 删除文件或目录（仅系统自身产物）"""
        path = body.get("path", "")
        if not path:
            self._send_error(400, "Missing 'path' parameter")
            return

        # 安全检查
        resolved = None
        for prefix, root in self._SAFE_ROOTS.items():
            if path.startswith(prefix + "/") or path == prefix:
                resolved = os.path.realpath(os.path.join(root, path[len(prefix) + 1:] if path != prefix else ""))
                safe_root = os.path.realpath(root)
                if not resolved.startswith(safe_root + os.sep) and resolved != safe_root:
                    self._send_error(403, "Access denied: path traversal detected")
                    return
                break

        if resolved is None:
            self._send_error(403, "Access denied: unknown path prefix")
            return

        if not os.path.exists(resolved):
            self._send_error(404, f"Not found: {path}")
            return

        try:
            if os.path.isdir(resolved):
                deleted_files = sum(len(files) for _, _, files in os.walk(resolved))
                shutil.rmtree(resolved, ignore_errors=True)
                self._send_json({
                    "success": True,
                    "deleted": {"type": "directory", "name": os.path.basename(resolved),
                                "files": deleted_files},
                })
            else:
                os.remove(resolved)
                self._send_json({
                    "success": True,
                    "deleted": {"type": "file", "name": os.path.basename(resolved),
                                "files": 1},
                })
        except Exception as e:
            self._send_error(500, f"Delete failed: {e}")

    def _handle_files_delete_category(self, body):
        """POST /api/files/delete-category — 批量删除某个分类下的全部文件"""
        category = body.get("category", "")
        if category not in self._SAFE_ROOTS:
            self._send_error(400, f"Invalid category: {category}. Must be one of {list(self._SAFE_ROOTS.keys())}")
            return

        root = self._SAFE_ROOTS[category]
        if not os.path.isdir(root):
            self._send_json({"success": True, "deleted": {"type": "directory", "name": category, "files": 0}, "message": "目录不存在，无需删除"})
            return

        try:
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
            self._send_json({
                "success": True,
                "deleted": {"type": "directory", "name": category, "files": total_files},
                "message": f"已清空 {category} 分类：{total_files} 个文件"
            })
        except Exception as e:
            self._send_error(500, f"Batch delete failed: {e}")

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

    def _get_scenario_samples(self):
        """GET /api/demo/scenario-samples — 返回所有 deep_agent 场景的详细信息"""
        deep_agent_dir = os.path.join(SCENARIOS_DIR, "deep_agent")
        samples = []
        if not os.path.isdir(deep_agent_dir):
            return {"samples": samples}

        for yaml_file in sorted(glob.glob(os.path.join(deep_agent_dir, "*.yaml"))):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
            except Exception:
                continue
            sc = data.get("scenario", {})
            tool_calls = data.get("tool_calls", [])

            # 分析 tool_calls 生成操作摘要和安全风险评估
            ops_summary = []
            risks = []
            _EXEC = {"execute", "execute_command", "run_command", "shell", "bash"}
            _READ = {"read_file", "read", "cat", "list_files", "grep", "glob"}
            _WRITE = {"write_file", "write", "edit_file", "edit", "patch"}
            _NET = {"web_fetch", "fetch", "web_search", "browse", "curl"}
            for tc in tool_calls:
                tool = tc.get("tool", "").lower().strip()
                inp = tc.get("input", {})
                if tool in _EXEC:
                    cmd = inp.get("command", "?")
                    ops_summary.append(f"执行: {cmd[:80]}")
                    if any(kw in cmd.lower() for kw in ["rm -rf", "curl |", "wget |", "chmod 777", ">> /etc/", "nc -"]):
                        risks.append(f"危险命令: {cmd[:60]}")
                elif tool in _READ:
                    path = inp.get("path", "?")
                    ops_summary.append(f"读取: {path}")
                    if any(s in path.lower() for s in ["/etc/shadow", "/etc/passwd", ".ssh/", ".env", "credentials", "secret", "id_rsa"]):
                        risks.append(f"敏感文件读取: {path}")
                elif tool in _WRITE:
                    path = inp.get("path", "?")
                    ops_summary.append(f"写入: {path}")
                elif tool in _NET:
                    url = inp.get("url", "?")
                    ops_summary.append(f"网络: {url[:80]}")
                    risks.append(f"外部网络连接: {url[:60]}")
                else:
                    ops_summary.append(f"{tool}")

            # 读取任务提示词文件
            task_prompt = ""
            task_file = os.path.join(DEMO_DIR, "task_instruction.txt")
            if os.path.isfile(task_file):
                try:
                    with open(task_file, "r", encoding="utf-8") as f:
                        task_prompt = f.read()[:2000]
                except Exception:
                    pass

            # 生成 Agent 命令行
            agent_cmd = f"cd deep-agents-demo && python run_agent.py --fifo ../.monitoring/pipe"

            samples.append({
                "scenario_id": sc.get("id", ""),
                "name": sc.get("name", ""),
                "description": sc.get("description", ""),
                "category": sc.get("category", ""),
                "expected_result": sc.get("expected_result", ""),
                "event_count": len(tool_calls),
                "operations": ops_summary[:20],
                "risks": list(set(risks))[:10],
                "task_prompt": task_prompt,
                "agent_command": agent_cmd,
                "agent_sim_command": f"cd deep-agents-demo && python agent_sim.py --fifo ../.monitoring/pipe --scenario {sc.get('id', '')}",
            })
        return {"samples": samples}

    def _get_scenario_sample(self, scenario_id):
        """GET /api/demo/scenario-sample?scenario_id=xxx — 返回单个场景的详细信息"""
        if not scenario_id:
            return {"error": "Missing 'scenario_id'"}
        # 复用 _get_scenario_samples 中的逻辑
        deep_agent_dir = os.path.join(SCENARIOS_DIR, "deep_agent")
        yaml_file = os.path.join(deep_agent_dir, f"{scenario_id}.yaml")
        if not os.path.isfile(yaml_file):
            for f in sorted(glob.glob(os.path.join(deep_agent_dir, "*.yaml"))):
                bn = os.path.splitext(os.path.basename(f))[0]
                if bn.startswith(scenario_id) or scenario_id in bn:
                    yaml_file = f
                    break
            else:
                return {"error": f"Scenario not found: {scenario_id}"}
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            return {"error": f"Failed to load scenario: {scenario_id}"}
        sc = data.get("scenario", {})
        tool_calls = data.get("tool_calls", [])
        operations = []
        _EXEC = {"execute", "execute_command", "run_command", "shell", "bash"}
        _READ = {"read_file", "read", "cat", "list_files", "grep", "glob"}
        _WRITE = {"write_file", "write", "edit_file", "edit", "patch"}
        _NET = {"web_fetch", "fetch", "web_search", "browse", "curl"}
        for tc in tool_calls:
            tool = tc.get("tool", "")
            inp = tc.get("input", {})
            delay = tc.get("delay_ms", 0)
            detail = ""
            if tool in _EXEC:
                detail = f"执行: {inp.get('command', '?')}"
            elif tool in _READ:
                detail = f"读取: {inp.get('path', '?')}"
            elif tool in _WRITE:
                detail = f"写入: {inp.get('path', '?')}"
            elif tool in _NET:
                detail = f"网络: {inp.get('url', '?')}"
            else:
                detail = f"{tool}: {json.dumps(inp, ensure_ascii=False)}"
            operations.append({
                "seq": len(operations) + 1,
                "tool": tool,
                "detail": detail[:200],
                "delay_ms": delay,
            })
        task_prompt = ""
        task_file = os.path.join(DEMO_DIR, "task_instruction.txt")
        if os.path.isfile(task_file):
            try:
                with open(task_file, "r", encoding="utf-8") as f:
                    task_prompt = f.read()
            except Exception:
                pass
        return {
            "scenario_id": sc.get("id", ""),
            "name": sc.get("name", ""),
            "description": sc.get("description", ""),
            "category": sc.get("category", ""),
            "expected_result": sc.get("expected_result", ""),
            "event_count": len(tool_calls),
            "operations": operations,
            "task_prompt": task_prompt,
            "agent_command": f"cd deep-agents-demo && python run_agent.py --fifo ../.monitoring/pipe",
        }

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
        """GET /api/demo/run-record — SSE: 运行 da04 场景并录制

        使用 Monitor + agent_sim FIFO 架构：Monitor 旁路录制，agent_sim 写 FIFO
        """
        # 委托给统一的录制流程
        self._run_demo_with_monitor(mode="record")

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
        try:
            json_data = json.dumps(data, ensure_ascii=False, default=str)
            self.wfile.write(f"data: {json_data}\n\n".encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

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
        """GET /api/demo/replay?session_id=xxx — SSE: 回放指定录制会话

        使用 Monitor + agent_sim --replay-file FIFO 架构：
        1. 启动 Monitor 守护进程
        2. 运行 agent_sim --replay-file <events.jsonl> 将事件注入 FIFO
        3. Monitor 从 FIFO 读取并执行全链路 Pipeline
        4. 流式推送 step 事件 + replay_done
        """
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

        replay_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # 使用 context manager 自动管理任务引用计数（包括异常路径）
        with MonitorLifecycleManager.instance().task_scope():
            try:
                self._sse_send({
                    "type": "replay_start",
                    "session_id": session_id,
                    "replay_id": replay_ts,
                    "message": f"开始回放会话 {session_id}"
                })

                # 统计事件数
                with open(events_path, "r", encoding="utf-8") as f:
                    total_lines = sum(1 for line in f if line.strip())

                self._sse_send({
                    "type": "replay_info",
                    "total_events": total_lines,
                })

                # Step 1: 确保 Monitor 运行
                self._sse_send({"type": "log", "message": "正在启动 Monitor 守护进程..."})
                mon_status = self._ensure_monitor_running()
                if not mon_status or not mon_status["monitor_running"]:
                    self._sse_send({"type": "error", "message": "Monitor 启动失败"})
                    return
                self._sse_send({"type": "log", "message":
                                f"Monitor 已运行 (PID={mon_status['monitor_pid']})"})
                time.sleep(0.5)

                # Step 2: 运行 agent_sim --replay-file
                agent_sim_path = os.path.join(BASE_DIR, "agent_sim.py")
                self._sse_send({"type": "log", "message": "正在回放录制事件..."})

                result = subprocess.run(
                    [sys.executable, agent_sim_path,
                     "--replay-file", events_path,
                     "--fifo", MONITORING_FIFO,
                     "--speed", "3.0"],
                    capture_output=True, text=True, timeout=120,
                    cwd=BASE_DIR,
                )

                if result.stdout:
                    self._sse_send({"type": "log", "message": result.stdout[-2000:]})

                # Step 3: 等待 Monitor 处理完成并流式推送 step 事件
                self._wait_and_stream_monitor_events()

                # Step 4: 获取报告
                report = self._get_monitor_report()
                summary = report.get("summary", {}) if report.get("available") else {}

                self._sse_send({
                    "type": "replay_done",
                    "session_id": session_id,
                    "replay_id": replay_ts,
                    "stats": {
                        "total": summary.get("total_events", 0),
                        "allow": summary.get("allow", 0),
                        "alert": summary.get("alert", 0),
                        "block": summary.get("block", 0),
                    },
                    "event_count": summary.get("total_events", 0),
                    "report": report,
                })

                # 自动关闭由 task_scope().__exit__ 在 finally 中处理

            except subprocess.TimeoutExpired:
                self._sse_send({"type": "error", "message": "回放超时 (120s)"})
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

    # ══════════════════════════════════════════════════════════
    #  实时监测 API
    # ══════════════════════════════════════════════════════════

    def _get_monitor_status(self):
        """GET /api/monitor/status — 检测Monitor守护进程运行状态"""
        return MonitorLifecycleManager.instance().status()

    def _ensure_monitor_running(self, record: bool = False):
        """
        确保 Monitor 守护进程在运行（内部方法，不返回 HTTP 响应）。

        委托给 MonitorLifecycleManager，具备：
          - 僵尸进程/PID文件自动清理
          - 幂等启动 (已运行则直接返回)
          - 竞态条件保护

        Args:
            record: 是否启用旁路录制

        Returns:
            dict: Monitor 状态 或 None（启动失败）
        """
        return MonitorLifecycleManager.instance().start_monitor(record=record)

    def _handle_monitor_start(self):
        """POST /api/monitor/start — 启动Monitor守护进程"""
        status = self._get_monitor_status()
        if status["monitor_running"]:
            self._send_json({"success": True, "message": "Monitor already running",
                             "pid": status["monitor_pid"], "already_running": True,
                             "monitor_running": True,
                             "fifo_path": status["fifo_path"],
                             "fifo_exists": status["fifo_exists"]})
            return

        result = self._ensure_monitor_running()
        if result and result["monitor_running"]:
            self._send_json({"success": True, "pid": result["monitor_pid"],
                             "monitor_running": True,
                             "fifo": MONITORING_FIFO,
                             "fifo_path": result["fifo_path"],
                             "fifo_exists": result["fifo_exists"],
                             "message": f"Monitor started (PID={result['monitor_pid']})"})
        else:
            self._send_error(500, "Failed to start monitor")

    def _handle_monitor_stop(self):
        """POST /api/monitor/stop — 停止Monitor守护进程

        使用 MonitorLifecycleManager.stop_monitor_forced() 代替旧 shell 脚本。
        不受任务计数限制，用于手动启停控制。
        """
        status = self._get_monitor_status()
        if not status["monitor_running"]:
            self._send_json({"success": True, "message": "Monitor not running",
                             "already_stopped": True})
            return

        MonitorLifecycleManager.instance().stop_monitor_forced()
        time.sleep(0.5)

        # 读取最新报告（Monitor 在 SIGTERM 后会生成报告）
        report = self._get_monitor_report()

        # 将此报告标记为 real_agent 来源（不覆盖已有标签）
        if report.get("available") and report["summary"].get("audit_file"):
            audit_name = os.path.basename(report["summary"]["audit_file"])
            import re as _re_stop
            m = _re_stop.match(r'audit_demo_monitoring_(\d{8}_\d{6})\.jsonl$', audit_name)
            if m:
                ts = m.group(1)
                existing_tags = self._load_report_tags()
                if ts not in existing_tags:
                    self._tag_report_source(ts, "real_agent")

        self._send_json({
            "success": True,
            "message": "Monitor stopped",
            "report": report,
        })

    def _stop_monitor_internal(self):
        """内部方法：安全停止 Monitor 守护进程（不返回 HTTP 响应）。

        委托给 MonitorLifecycleManager.stop_monitor_auto()：
          - 递减任务引用计数
          - 仅当所有任务完成后才执行停止
          - 自动清理 PID 文件和资源

        由 SSE handler 在任务完成后调用以实现自动关闭。
        """
        MonitorLifecycleManager.instance().stop_monitor_auto()

    def _get_monitor_report(self):
        """GET /api/monitor/report — 获取最新监测报告摘要"""
        summary_path = os.path.join(MONITORING_OUTPUT_DIR, "monitoring_summary.json")
        if not os.path.isfile(summary_path):
            return {"available": False, "message": "No report yet"}
        try:
            with open(summary_path, "r", encoding="utf-8") as f:
                summary = json.load(f)
            return {"available": True, "summary": summary}
        except Exception as e:
            return {"available": False, "error": str(e)}

    # ══════════════════════════════════════════════════════════
    #  实时监测事件流 (SSE tail audit log)
    # ══════════════════════════════════════════════════════════

    def _handle_sse_monitor_events(self):
        """GET /api/monitor/events — SSE: tail Monitor audit log for real-time events"""
        status = self._get_monitor_status()
        if not status["monitor_running"]:
            self._send_error(400, "Monitor not running")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        # Find the latest audit log file
        audit_dir = os.path.join(MONITORING_OUTPUT_DIR, "audit")
        audit_files = sorted(
            glob.glob(os.path.join(audit_dir, "audit_demo_monitoring_*.jsonl")),
            key=os.path.getmtime, reverse=True
        )
        if not audit_files:
            self._sse_send({"type": "waiting", "message": "等待审计事件..."})
            audit_file = None
            last_pos = 0
        else:
            audit_file = audit_files[0]
            last_pos = os.path.getsize(audit_file)

        self._sse_send({"type": "connected", "message": "已连接到事件流",
                         "file": os.path.basename(audit_file) if audit_file else None})

        try:
            seq = 0
            while True:
                # Check if a newer audit file exists
                current_files = sorted(
                    glob.glob(os.path.join(audit_dir, "audit_demo_monitoring_*.jsonl")),
                    key=os.path.getmtime, reverse=True
                )
                if current_files and current_files[0] != audit_file:
                    audit_file = current_files[0]
                    last_pos = 0
                    self._sse_send({"type": "new_file",
                                     "file": os.path.basename(audit_file)})

                if audit_file and os.path.isfile(audit_file):
                    current_size = os.path.getsize(audit_file)
                    if current_size > last_pos:
                        with open(audit_file, "r", encoding="utf-8") as f:
                            f.seek(last_pos)
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                    seq += 1
                                    self._sse_send({
                                        "type": "step",
                                        "seq": seq,
                                        "event_type": entry.get("event_type", "?"),
                                        "raw_input": entry.get("description", ""),
                                        "normalized_summary": entry.get("command_string") or entry.get("description", ""),
                                        "rule_match": {
                                            "hit": bool(entry.get("matched_rules")),
                                            "rules": [{"id": r} for r in entry.get("matched_rules", [])]
                                        },
                                        "risk_score": entry.get("risk_score", 0),
                                        "risk_level": entry.get("risk_level", "LOW"),
                                        "decision_action": entry.get("decision_action", "ALLOW"),
                                        "decision_tier": entry.get("decision_tier", "TIER1"),
                                        "disposal_summary": "阻止" if entry.get("blocked") else "放行",
                                        "timestamp_ns": entry.get("timestamp_ns", 0),
                                    })
                                except json.JSONDecodeError:
                                    pass
                        last_pos = current_size

                # Check if Monitor is still running
                status = self._get_monitor_status()
                if not status["monitor_running"]:
                    self._sse_send({"type": "monitor_stopped",
                                     "message": "Monitor has stopped"})
                    break

                time.sleep(1.0)

        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    # ══════════════════════════════════════════════════════════
    #  Agent 模拟测试 API
    # ══════════════════════════════════════════════════════════

    def _get_agent_sim_scenarios(self):
        """GET /api/agent-sim/scenarios — 返回Agent模拟测试场景列表"""
        scenarios = [
            {
                "key": "1",
                "label": "Tier2 阻断验证",
                "description": "验证违规累计升级到 Tier2，BlockAccessHandler 执行阻断",
                "run_type": "agent_sim",
                "scenario_id": "da05",
                "expected": "4 ALERT + 2 BLOCK @ Tier2 + 1 ALLOW",
            },
            {
                "key": "2",
                "label": "Tier3 升级验证",
                "description": "Tier2→Tier3 升级链 + Agent 终止逻辑",
                "run_type": "script",
                "script_path": "observer_sim/tests/verify_tier3_escalation.py",
            },
            {
                "key": "3",
                "label": "生产场景演示",
                "description": "Q3 商业报表市场分析，17 个事件综合演示",
                "run_type": "agent_sim",
                "scenario_id": "da04",
                "expected": "混合 ALLOW/ALERT/BLOCK 全链路演示",
            },
            {
                "key": "4",
                "label": "单元测试 (阻断机制)",
                "description": "运行 test_blocking.py — 16 个阻断相关单元测试",
                "run_type": "pytest",
            },
        ]
        return {"scenarios": scenarios}

    def _handle_sse_agent_sim_run(self, scenario_key):
        """GET /api/agent-sim/run/{key} — SSE: 运行Agent模拟测试"""
        scenarios = self._get_agent_sim_scenarios()["scenarios"]
        sc = next((s for s in scenarios if s["key"] == scenario_key), None)
        if not sc:
            self._send_error(404, f"Unknown scenario: {scenario_key}")
            return

        run_type = sc.get("run_type", "agent_sim")

        if run_type == "script":
            self._handle_sse_script_run(sc)
        elif run_type == "pytest":
            self._handle_sse_pytest_run(sc)
        else:
            self._handle_sse_agent_sim_scenario(sc)

    def _handle_sse_script_run(self, sc):
        """SSE: 运行独立验证脚本"""
        script_path = os.path.join(PROJECT_DIR, sc["script_path"])
        if not os.path.isfile(script_path):
            self._send_error(404, f"Script not found: {sc['script_path']}")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        try:
            self._sse_send({"type": "test_start", "label": sc["label"],
                            "description": sc["description"]})

            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True, text=True, timeout=120,
                cwd=PROJECT_DIR,
            )
            stdout = result.stdout[-4000:] if result.stdout else ""
            stderr = result.stderr[-2000:] if result.stderr else ""

            # 解析输出获取通过/失败数
            import re
            passed = 0
            failed = 0
            for line in (stdout + stderr).split("\n"):
                m = re.search(r'(\d+)/(\d+)\s*通过', line)
                if m:
                    passed = int(m.group(1))
                    failed = int(m.group(2)) - passed
                    break
                m = re.search(r'(\d+)\s*passed', line)
                if m:
                    passed = int(m.group(1))
                m = re.search(r'(\d+)\s*failed', line)
                if m:
                    failed = int(m.group(1))

            self._sse_send({
                "type": "test_done",
                "label": sc["label"],
                "passed": passed,
                "failed": failed,
                "total": passed + failed,
                "exit_code": result.returncode,
                "output": stdout,
                "stderr": stderr,
            })
        except subprocess.TimeoutExpired:
            self._sse_send({"type": "error", "message": "Script timeout (120s)"})
        except Exception as e:
            self._sse_send({"type": "error", "message": str(e)})

    def _handle_sse_pytest_run(self, sc):
        """SSE: 运行 pytest 测试"""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        try:
            self._sse_send({"type": "test_start", "label": sc["label"],
                            "description": sc["description"]})

            test_files = ["test_blocking.py"]
            paths = []
            for f in test_files:
                p = os.path.join(BASE_DIR, "tests", f)
                if os.path.isfile(p):
                    paths.append(p)

            result = subprocess.run(
                [sys.executable, "-m", "pytest", "--tb=short", "-q"] + paths,
                capture_output=True, text=True, timeout=120,
                cwd=BASE_DIR,
            )
            output = result.stdout + result.stderr

            import re
            passed = 0
            failed = 0
            m = re.search(r'(\d+) passed', output)
            if m:
                passed = int(m.group(1))
            m = re.search(r'(\d+) failed', output)
            if m:
                failed = int(m.group(1))

            self._sse_send({
                "type": "test_done",
                "label": sc["label"],
                "passed": passed,
                "failed": failed,
                "total": passed + failed,
                "exit_code": result.returncode,
                "output": output[-3000:],
            })
        except subprocess.TimeoutExpired:
            self._sse_send({"type": "error", "message": "Test timeout (120s)"})
        except Exception as e:
            self._sse_send({"type": "error", "message": str(e)})

    def _handle_sse_agent_sim_scenario(self, sc):
        """SSE: 运行 agent_sim 场景（Monitor + agent_sim FIFO通信）"""
        scenario_path = os.path.join(
            SCENARIOS_DIR, "deep_agent",
            f"{sc['scenario_id']}_blocking_tier2_test.yaml" if sc['scenario_id'] == 'da05'
            else f"{sc['scenario_id']}_production_demo.yaml"
        )
        if not os.path.isfile(scenario_path):
            self._send_error(404, f"Scenario file not found: {scenario_path}")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        # 使用 context manager 自动管理任务引用计数（包括异常路径）
        with MonitorLifecycleManager.instance().task_scope():
            try:
                self._sse_send({"type": "test_start", "label": sc["label"],
                                "description": sc["description"],
                                "expected": sc.get("expected", "")})

                # Step 1: 确保 Monitor 运行
                mon_status = self._get_monitor_status()
                if not mon_status["monitor_running"]:
                    self._sse_send({"type": "log", "message": "正在启动 Monitor 守护进程..."})
                    mon_status = self._ensure_monitor_running()
                    time.sleep(1)
                else:
                    self._sse_send({"type": "log", "message": f"Monitor 已在运行 (PID={mon_status['monitor_pid']})"})

                # Step 2: 运行 agent_sim
                agent_sim_path = os.path.join(BASE_DIR, "agent_sim.py")
                self._sse_send({"type": "log", "message": "正在运行 Agent 模拟器..."})

                result = subprocess.run(
                    [sys.executable, agent_sim_path,
                     "--scenario", scenario_path,
                     "--fifo", MONITORING_FIFO],
                    capture_output=True, text=True, timeout=120,
                    cwd=PROJECT_DIR,
                )

                if result.stdout:
                    self._sse_send({"type": "log", "message": result.stdout[-2000:]})

                # Step 3: 等待 Monitor 完成事件处理并生成报告
                # agent_sim 关闭 FIFO 后，Monitor 需要时间来:
                #   - 处理 FIFO 缓冲中剩余的事件
                #   - 生成报告 (monitoring_summary.json)
                summary_path = os.path.join(MONITORING_OUTPUT_DIR, "monitoring_summary.json")
                summary_mtime_before = os.path.getmtime(summary_path) if os.path.isfile(summary_path) else 0

                for _ in range(30):  # 最多等待 15 秒
                    time.sleep(0.5)
                    if os.path.isfile(summary_path) and os.path.getmtime(summary_path) > summary_mtime_before:
                        break

                report = self._get_monitor_report()

                # 将此报告标记为 agent_sim 来源
                if report.get("available") and report["summary"].get("audit_file"):
                    audit_name = os.path.basename(report["summary"]["audit_file"])
                    # audit_demo_monitoring_20260809_134608.jsonl → 20260809_134608
                    import re as _re3
                    m = _re3.match(r'audit_demo_monitoring_(\d{8}_\d{6})\.jsonl$', audit_name)
                    if m:
                        self._tag_report_source(m.group(1), "agent_sim")

                # Step 4: 从审计日志读取事件并流式推送 step 事件
                total_events = 0
                if report.get("available") and report["summary"].get("audit_file"):
                    audit_file = report["summary"]["audit_file"]
                    if os.path.isfile(audit_file):
                        entries = []
                        with open(audit_file, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        entries.append(json.loads(line))
                                    except json.JSONDecodeError:
                                        pass

                        total_events = len(entries)
                        for i, entry in enumerate(entries, 1):
                            self._sse_send({
                                "type": "step",
                                "seq": i,
                                "total": total_events,
                                "event_type": entry.get("event_type", "?"),
                                "normalized_summary": entry.get("description", ""),
                                "decision_action": entry.get("decision_action", "ALLOW"),
                                "risk_score": entry.get("risk_score", 0.0),
                                "risk_level": entry.get("risk_level", "LOW"),
                            })

                # Step 5: 发送完成事件（使用实际统计）
                summary = report.get("summary", {}) if report.get("available") else {}
                self._sse_send({
                    "type": "test_done",
                    "label": sc["label"],
                    "exit_code": result.returncode,
                    "report": report,
                    "passed": summary.get("allow", 0),
                    "failed": summary.get("block", 0),
                    "total": summary.get("total_events", total_events),
                })

                # 自动关闭由 task_scope().__exit__ 在 finally 中处理

            except subprocess.TimeoutExpired:
                self._sse_send({"type": "error", "message": "Agent sim timeout (120s)"})
            except Exception as e:
                self._sse_send({"type": "error", "message": str(e)})

    # ══════════════════════════════════════════════════════════
    #  录制/监测双模式 API
    # ══════════════════════════════════════════════════════════

    def _handle_sse_start_record(self):
        """POST /api/demo/start-record — SSE: 录制模式（旁路记录 FIFO 事件）"""
        self._run_demo_with_monitor(mode="record")

    def _handle_sse_start_monitor(self):
        """POST /api/demo/start-monitor — SSE: 监测模式（完整风险评估）"""
        self._run_demo_with_monitor(mode="monitor")

    def _run_demo_with_monitor(self, mode="monitor"):
        """
        统一录制/监测流程 — 使用 Monitor daemon + agent_sim FIFO 架构。

        mode="record":  Monitor 启用 --record 旁路录制，agent_sim 写 FIFO
        mode="monitor": Monitor 正常处理，agent_sim 写 FIFO，推送 step 事件
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        # 使用 context manager 自动管理任务引用计数（包括异常路径）
        with MonitorLifecycleManager.instance().task_scope():
            try:
                # Step 1: 启动 Monitor（录制模式带 --record）
                is_record = (mode == "record")
                self._sse_send({"type": "log", "message":
                                "正在启动 Monitor 守护进程" + (" (录制模式)" if is_record else "") + "..."})
                mon_status = self._ensure_monitor_running(record=is_record)
                if not mon_status or not mon_status["monitor_running"]:
                    self._sse_send({"type": "error", "message": "Monitor 启动失败"})
                    return
                self._sse_send({"type": "log", "message":
                                f"Monitor 已运行 (PID={mon_status['monitor_pid']})"})
                time.sleep(0.5)

                # Step 2: 运行 agent_sim
                agent_sim_path = os.path.join(BASE_DIR, "agent_sim.py")
                scenario_path = os.path.join(SCENARIOS_DIR, "deep_agent",
                                             "da04_production_demo.yaml")
                self._sse_send({"type": "session_start",
                                "mode": "record" if is_record else "monitor"})
                self._sse_send({"type": "log", "message": "正在运行 Agent 模拟器..."})

                result = subprocess.run(
                    [sys.executable, agent_sim_path,
                     "--scenario", scenario_path,
                     "--fifo", MONITORING_FIFO,
                     "--speed", "3.0"],  # 加速以便快速完成
                    capture_output=True, text=True, timeout=120,
                    cwd=BASE_DIR,
                )

                if result.stdout:
                    self._sse_send({"type": "log", "message": result.stdout[-2000:]})

                # Step 3: 等待 Monitor 处理完成
                self._wait_and_stream_monitor_events()

                # Step 4: 获取报告
                report = self._get_monitor_report()
                summary = report.get("summary", {}) if report.get("available") else {}

                if is_record:
                    # 查找最新录制文件
                    recording_info = self._find_latest_recording()
                    self._sse_send({
                        "type": "session_done",
                        "session_id": recording_info.get("session_id", ""),
                        "mode": mode,
                        "event_count": summary.get("total_events", 0),
                        "stats": {
                            "total": summary.get("total_events", 0),
                            "allow": summary.get("allow", 0),
                            "alert": summary.get("alert", 0),
                            "block": summary.get("block", 0),
                        },
                        "duration_seconds": 0,
                        "record_file": recording_info.get("record_file", ""),
                    })
                else:
                    self._sse_send({
                        "type": "session_done",
                        "mode": mode,
                        "event_count": summary.get("total_events", 0),
                        "stats": {
                            "total": summary.get("total_events", 0),
                            "allow": summary.get("allow", 0),
                            "alert": summary.get("alert", 0),
                            "block": summary.get("block", 0),
                        },
                        "duration_seconds": 0,
                        "report": report,
                    })

                # 自动关闭由 task_scope().__exit__ 在 finally 中处理

            except subprocess.TimeoutExpired:
                self._sse_send({"type": "error", "message": "超时 (120s)"})
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            except Exception as e:
                try:
                    self._sse_send({"type": "error", "message": str(e)})
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass

    def _wait_and_stream_monitor_events(self, max_wait: int = 30):
        """等待 Monitor 生成报告并流式推送审计日志中的 step 事件"""
        summary_path = os.path.join(MONITORING_OUTPUT_DIR, "monitoring_summary.json")
        summary_mtime_before = os.path.getmtime(summary_path) if os.path.isfile(summary_path) else 0

        for _ in range(max_wait * 2):
            time.sleep(0.5)
            if os.path.isfile(summary_path) and os.path.getmtime(summary_path) > summary_mtime_before:
                break

        report = self._get_monitor_report()
        if report.get("available") and report["summary"].get("audit_file"):
            audit_file = report["summary"]["audit_file"]
            if os.path.isfile(audit_file):
                entries = []
                with open(audit_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass

                total = len(entries)
                for i, entry in enumerate(entries, 1):
                    self._sse_send({
                        "type": "step",
                        "seq": i,
                        "total": total,
                        "event_type": entry.get("event_type", "?"),
                        "normalized_summary": entry.get("description", ""),
                        "decision_action": entry.get("decision_action", "ALLOW"),
                        "risk_score": entry.get("risk_score", 0.0),
                        "risk_level": entry.get("risk_level", "LOW"),
                    })

    def _find_latest_recording(self) -> dict:
        """查找最新的录制会话"""
        if not os.path.isdir(RECORDS_DIR):
            return {}
        dirs = sorted(
            [d for d in os.listdir(RECORDS_DIR)
             if os.path.isdir(os.path.join(RECORDS_DIR, d))],
            reverse=True
        )
        for d in dirs:
            events_path = os.path.join(RECORDS_DIR, d, "events.jsonl")
            if os.path.isfile(events_path):
                try:
                    count = sum(1 for _ in open(events_path))
                    return {"session_id": d, "record_file": events_path,
                            "event_count": count}
                except Exception:
                    pass
        return {}

    # ══════════════════════════════════════════════════════════
    #  录制解耦：纯录制模式（不运行 Agent）
    # ══════════════════════════════════════════════════════════

    def _handle_sse_record_start_only(self):
        """GET /api/demo/record/start — SSE: 纯录制模式

        仅启动 Monitor 守护进程（--record 模式），不运行任何 Agent。
        用户需在系统外手动启动 Agent 并通过 agent_bridge 将事件写入 FIFO。
        事件会通过 SSE 实时推送给前端，直到用户手动停止录制。
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        with MonitorLifecycleManager.instance().task_scope():
            try:
                # Step 1: 启动 Monitor（录制模式）
                self._sse_send({"type": "log", "message": "正在启动 Monitor 守护进程（纯录制模式）..."})
                mon_status = self._ensure_monitor_running(record=True)
                if not mon_status or not mon_status["monitor_running"]:
                    self._sse_send({"type": "error", "message": "Monitor 启动失败"})
                    return
                self._sse_send({"type": "log", "message":
                                f"Monitor 已运行 (PID={mon_status['monitor_pid']})"})
                self._sse_send({"type": "recording_started",
                                "message": "录制已开始，请在终端中手动启动 Agent",
                                "agent_command": f"cd deep-agents-demo && python run_agent.py --fifo ../.monitoring/pipe",
                                "pid": mon_status["monitor_pid"],
                                "fifo": MONITORING_FIFO})

                # Step 2: 轮询审计日志，实时推送事件
                audit_dir = os.path.join(MONITORING_OUTPUT_DIR, "audit")
                audit_file = None
                last_pos = 0
                seq = 0

                # 等待审计文件出现
                for _ in range(10):
                    time.sleep(0.5)
                    current_files = sorted(
                        glob.glob(os.path.join(audit_dir, "audit_demo_monitoring_*.jsonl")),
                        key=os.path.getmtime, reverse=True
                    )
                    if current_files:
                        audit_file = current_files[0]
                        last_pos = os.path.getsize(audit_file)
                        break

                if audit_file:
                    self._sse_send({"type": "log", "message":
                                    f"审计文件已就绪: {os.path.basename(audit_file)}"})
                else:
                    self._sse_send({"type": "log", "message": "等待 Agent 发送事件..."})

                # 持续轮询新事件
                while True:
                    status = self._get_monitor_status()
                    if not status["monitor_running"]:
                        self._sse_send({"type": "monitor_stopped",
                                         "message": "Monitor 已停止"})
                        break

                    current_files = sorted(
                        glob.glob(os.path.join(audit_dir, "audit_demo_monitoring_*.jsonl")),
                        key=os.path.getmtime, reverse=True
                    )
                    if current_files and current_files[0] != audit_file:
                        audit_file = current_files[0]
                        last_pos = 0
                        self._sse_send({"type": "new_file",
                                         "file": os.path.basename(audit_file)})

                    if audit_file and os.path.isfile(audit_file):
                        current_size = os.path.getsize(audit_file)
                        if current_size > last_pos:
                            with open(audit_file, "r", encoding="utf-8") as f:
                                f.seek(last_pos)
                                for line in f:
                                    line = line.strip()
                                    if not line:
                                        continue
                                    try:
                                        entry = json.loads(line)
                                        seq += 1
                                        self._sse_send({
                                            "type": "record_step",
                                            "seq": seq,
                                            "event_type": entry.get("event_type", "?"),
                                            "summary": entry.get("description", ""),
                                            "decision_action": entry.get("decision_action", "ALLOW"),
                                            "risk_score": entry.get("risk_score", 0.0),
                                            "risk_level": entry.get("risk_level", "LOW"),
                                        })
                                    except json.JSONDecodeError:
                                        pass
                            last_pos = current_size

                    time.sleep(1.0)

            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            except Exception as e:
                try:
                    self._sse_send({"type": "error", "message": str(e)})
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass

    def _handle_record_stop(self):
        """POST /api/demo/record/stop — 停止录制并返回录制结果"""
        status = self._get_monitor_status()
        if not status["monitor_running"]:
            self._send_json({"success": True, "message": "Monitor not running",
                             "already_stopped": True})
            return

        MonitorLifecycleManager.instance().stop_monitor_forced()
        time.sleep(0.5)

        # 查找最新录制文件
        recording_info = self._find_latest_recording()
        self._send_json({
            "success": True,
            "message": "录制已停止",
            "session_id": recording_info.get("session_id", ""),
            "event_count": recording_info.get("event_count", 0),
            "record_file": recording_info.get("record_file", ""),
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
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_text(self, text, content_type="text/plain; charset=utf-8", status=200):
        """发送文本响应"""
        body = text.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

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

    # ── 启动阶段清理 ──────────────────────────────────────────
    # 清理前次运行残留的僵尸 Monitor 进程、过期 PID 文件、FIFO 管道
    print("[启动] 清理残留 Monitor 进程...")
    cleanup_result = MonitorLifecycleManager.instance().startup_cleanup()
    if cleanup_result["zombies_killed"] > 0:
        print(f"[启动] 已终止 {cleanup_result['zombies_killed']} 个僵尸 Monitor 进程")
    if cleanup_result["pid_file_cleaned"]:
        print("[启动] 已清理过期 PID 文件")
    if cleanup_result["fifo_cleaned"]:
        print("[启动] 已清理残留 FIFO 管道")

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
        # ── 关闭阶段清理 ──────────────────────────────────────
        print("[关闭] 正在终止 Monitor 子进程并清理资源...")
        MonitorLifecycleManager.instance().shutdown()
        print("[关闭] Monitor 资源已清理")
        print("服务器已关闭")


if __name__ == "__main__":
    main()
