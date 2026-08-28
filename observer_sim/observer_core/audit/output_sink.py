"""
output_sink.py — IOutputSink 输出抽象（U3）

四入口（main / app / monitor_daemon / demo）各自内联的
"设输出目录 → 导出报告 → 存图谱 → 存证据 → 基线快照"输出编排
收敛为单一 DefaultOutputSink 实现（输出层的 PipelineRunner 对应物）。

行为基准（与四入口下沉前逐字一致）：
  - 报告导出失败默认冒泡（app/demo 行为）；tolerate_export_error=True 时
    置 report_path=None 继续图谱输出（main.py 行为）；
  - 证据仅当 stats["block"] > 0 时写入（app/demo 行为）；main/monitor 传
    write_evidence=False 保持原有不写证据行为；
  - 基线快照仅 n01 前缀场景保存（main.py 行为）；
  - monitor（use_run_dirs=False）不创建时间戳 run 目录，图谱写入
    {output}/graphs/、报告写入 exporter 已设的 {output}/reports/（原
    monitor_daemon.generate_report 行为）。

纯逻辑实现，不依赖 HTTP；目录树清理/树视图复用 OutputFileManager（U7）。
"""

import os
from abc import ABC, abstractmethod
from typing import Dict, Optional

from observer_core.audit.output_path_manager import RunOutputManager


class OutputSink(ABC):
    """输出编排抽象接口。"""

    @abstractmethod
    def begin_run(self, category: str, scenario_id: str):
        """创建 run 上下文（设各组件输出目录 + start_scenario），返回 run 上下文。"""

    @abstractmethod
    def finalize(self, scenario_meta: Dict, stats: Dict) -> Dict:
        """导出场景报告、保存图谱 JSON、写证据。

        返回 {"report_path", "graph_path", "audit_file", "evidence_path"}。
        """

    @abstractmethod
    def save_baseline(self, scenario_id: str) -> Optional[str]:
        """保存基线快照（n01 前缀），返回基线文件路径或 None。"""


class DefaultOutputSink(OutputSink):
    """默认输出编排实现（构造注入各输出组件，单次运行一个实例）。"""

    def __init__(self, base_output_dir: str, audit_logger,
                 report_exporter, behavior_graph,
                 blocking_coord=None, baseline_checker=None,
                 use_run_dirs: bool = True):
        """
        Args:
            base_output_dir: 输出根目录（如 "output"）。
            audit_logger / report_exporter / behavior_graph: 输出组件。
            blocking_coord: 阻断协调器（写证据用，可缺省）。
            baseline_checker: 基线检查器（save_baseline 用，可缺省）。
            use_run_dirs: True（main/app/demo）由 begin_run 创建时间戳 run 目录；
                          False（monitor_daemon）使用固定输出目录，不创建 run 目录。
        """
        self._base_output_dir = base_output_dir
        self._audit_logger = audit_logger
        self._report_exporter = report_exporter
        self._behavior_graph = behavior_graph
        self._blocking_coord = blocking_coord
        self._baseline_checker = baseline_checker
        self._use_run_dirs = use_run_dirs
        self._run_mgr: Optional[RunOutputManager] = None

    @property
    def run_mgr(self) -> Optional[RunOutputManager]:
        """当前运行的 RunOutputManager（begin_run 后可用）。"""
        return self._run_mgr

    def begin_run(self, category: str, scenario_id: str):
        """创建 run 目录（use_run_dirs=True）、设各组件输出目录、start_scenario。

        返回 run 上下文（RunOutputManager；use_run_dirs=False 时为 None）。
        """
        if self._use_run_dirs:
            self._run_mgr = RunOutputManager(
                self._base_output_dir, category, scenario_id)
            self._audit_logger.set_output_dir(self._run_mgr.audit_dir)
            self._report_exporter.set_output_dir(self._run_mgr.report_dir)
            if self._blocking_coord is not None:
                self._blocking_coord.set_output_dir(self._run_mgr.evidence_dir)
        else:
            self._run_mgr = None
            self._audit_logger.set_output_dir(
                os.path.join(self._base_output_dir, "audit"))
            self._report_exporter.set_output_dir(
                os.path.join(self._base_output_dir, "reports"))
            if self._blocking_coord is not None:
                self._blocking_coord.set_output_dir(
                    os.path.join(self._base_output_dir, "audit"))
        self._audit_logger.start_scenario(scenario_id)
        return self._run_mgr

    def finalize(self, scenario_meta: Dict, stats: Dict,
                 write_evidence: bool = True,
                 tolerate_export_error: bool = False) -> Dict:
        """导出场景报告、保存图谱 JSON、写证据（stats["block"] > 0 时）。

        Args:
            scenario_meta: {"id", "name", "description", "expected_result"}。
            stats: 统计 dict（需含 "block"）。
            write_evidence: False 时不写阻断证据（main/monitor 原行为）。
            tolerate_export_error: True 时报告导出失败不冒泡，
                                   report_path=None 继续图谱输出（main 原行为）。

        返回 {"report_path", "graph_path", "audit_file", "evidence_path"}。
        """
        scenario_id = scenario_meta["id"]
        report_path = None
        try:
            report_path = self._report_exporter.export_scenario_report(
                scenario_id=scenario_id,
                scenario_name=scenario_meta.get("name", scenario_id),
                audit_logger=self._audit_logger,
                behavior_graph=self._behavior_graph,
                scenario_description=scenario_meta.get("description", ""),
                expected_result=scenario_meta.get("expected_result", ""),
            )
        except Exception:
            if not tolerate_export_error:
                raise
            report_path = None

        # 保存行为图谱（monitor 模式写入 {output}/graphs/，run 模式写入 run_dir/graphs/）
        if self._run_mgr is not None:
            graph_path = self._run_mgr.graph_filepath(
                f"graph_{scenario_id}.json")
        else:
            graph_dir = os.path.join(self._base_output_dir, "graphs")
            os.makedirs(graph_dir, exist_ok=True)
            graph_path = os.path.join(graph_dir, f"graph_{scenario_id}.json")
        self._behavior_graph.save_json(graph_path)

        # 写阻断证据（仅 block > 0 且注入 blocking_coord 时）
        evidence_path = None
        if (write_evidence and stats.get("block", 0) > 0
                and self._blocking_coord is not None):
            if self._run_mgr is not None:
                evidence_path = self._blocking_coord.save_evidence(
                    filepath=self._run_mgr.evidence_filepath(
                        f"evidence_{scenario_id}.json"))
            else:
                evidence_path = self._blocking_coord.save_evidence()

        return {
            "report_path": report_path,
            "graph_path": graph_path,
            "audit_file": self._audit_logger.current_file,
            "evidence_path": evidence_path,
        }

    def save_baseline(self, scenario_id: str) -> Optional[str]:
        """保存基线快照（n01 前缀判断，迁移 main.py 原逻辑），返回路径或 None。"""
        if not scenario_id.startswith("n01") or self._baseline_checker is None:
            return None
        baseline_path = os.path.join(
            self._run_mgr.baseline_run_dir(), f"baseline_{scenario_id}.json")
        self._baseline_checker.save_baseline(baseline_path)
        return baseline_path
