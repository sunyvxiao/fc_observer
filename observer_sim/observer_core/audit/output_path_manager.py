"""
RunOutputManager — 运行输出目录管理器

管理每次场景运行的输出目录结构:
- output/reports/{category}/{scenario_id}/{timestamp}/  ← 审计报告/审计日志/图谱/证据
- output/baselines/{category}/{scenario_id}/{timestamp}/ ← 基线快照
- output/unit_test/                                      ← 单元测试结果（仅保留最新）

每次运行使用时间戳子文件夹防止覆盖。
"""

import os
import shutil
from datetime import datetime
from typing import Optional


# 场景分类映射
CATEGORY_MAP = {
    'normal': 'normal',
    'anomalous': 'anomalous',
    'boundary': 'boundary',
    'multi_agent': 'multi_agent',
    'extreme': 'extreme',
}


def infer_category(scenario_path: str) -> str:
    """
    从场景文件路径推断分类类别。

    例如:
    - scenarios/normal/n01_*.yaml → 'normal'
    - scenarios/anomalous/a01_*.yaml → 'anomalous'
    - scenarios/scenario_01_normal.yaml → 'normal' (兼容旧路径)
    """
    path_parts = scenario_path.replace('\\', '/').lower()

    # 先检查路径中是否包含分类子目录
    for cat in CATEGORY_MAP:
        if f'/{cat}/' in path_parts or f'\\{cat}\\' in path_parts:
            return cat

    # 兼容旧的场景文件命名
    if 'scenario_01' in path_parts or 'normal' in path_parts:
        return 'normal'
    elif 'scenario_02' in path_parts or 'dangerous' in path_parts:
        return 'anomalous'
    elif 'scenario_03' in path_parts or 'multi_agent' in path_parts:
        return 'multi_agent'

    return 'normal'  # 默认分类


def _make_unique_timestamp_dir(base_path: str) -> str:
    """
    创建唯一的时间戳目录。

    格式: YYYY_MM_DD_HH_mm_ss
    同秒冲突时追加 (1), (2), ...
    """
    ts = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    candidate = os.path.join(base_path, ts)

    if not os.path.exists(candidate):
        os.makedirs(candidate, exist_ok=True)
        return candidate

    # 处理同秒冲突
    counter = 1
    while True:
        candidate = os.path.join(base_path, f"{ts}({counter})")
        if not os.path.exists(candidate):
            os.makedirs(candidate, exist_ok=True)
            return candidate
        counter += 1


class RunOutputManager:
    """
    单次运行输出目录管理器。

    每次场景运行时创建一个时间戳子目录，所有输出文件放入其中。
    """

    def __init__(self, base_output_dir: str, category: str, scenario_id: str):
        """
        Args:
            base_output_dir: 输出根目录 (如 "output")
            category: 场景分类 (normal/anomalous/boundary/multi_agent/extreme)
            scenario_id: 场景 ID (如 "scenario-01")
        """
        self._base = base_output_dir
        self._category = category
        self._scenario_id = scenario_id

        # 创建时间戳运行目录（用于 reports/audit/graphs 等）
        reports_base = os.path.join(base_output_dir, "reports", category, scenario_id)
        self._run_dir = _make_unique_timestamp_dir(reports_base)

    @property
    def run_dir(self) -> str:
        """当前运行的根目录"""
        return self._run_dir

    @property
    def category(self) -> str:
        return self._category

    @property
    def scenario_id(self) -> str:
        return self._scenario_id

    @property
    def audit_dir(self) -> str:
        """审计日志目录"""
        path = os.path.join(self._run_dir, "audit")
        os.makedirs(path, exist_ok=True)
        return path

    @property
    def report_dir(self) -> str:
        """报告目录（与 run_dir 相同，报告直接放在运行目录下）"""
        return self._run_dir

    @property
    def graph_dir(self) -> str:
        """图谱目录"""
        path = os.path.join(self._run_dir, "graphs")
        os.makedirs(path, exist_ok=True)
        return path

    @property
    def evidence_dir(self) -> str:
        """证据目录"""
        path = os.path.join(self._run_dir, "evidence")
        os.makedirs(path, exist_ok=True)
        return path

    def baseline_dir(self, create: bool = True) -> str:
        """基线快照目录（独立于运行目录，按分类存放）"""
        path = os.path.join(self._base, "baselines", self._category, self._scenario_id)
        if create:
            os.makedirs(path, exist_ok=True)
        return path

    def baseline_run_dir(self) -> str:
        """基线快照的运行时间戳目录"""
        base = self.baseline_dir(create=True)
        return _make_unique_timestamp_dir(base)

    @staticmethod
    def unit_test_dir(base_output_dir: str) -> str:
        """
        单元测试输出目录（始终只保留最新一次）。

        每次调用时清空旧内容。
        """
        path = os.path.join(base_output_dir, "unit_test")
        # 清空旧结果
        if os.path.exists(path):
            shutil.rmtree(path)
        os.makedirs(path, exist_ok=True)
        return path

    def audit_filepath(self, filename: str) -> str:
        """审计日志文件完整路径"""
        return os.path.join(self.audit_dir, filename)

    def report_filepath(self, filename: str) -> str:
        """报告文件完整路径"""
        return os.path.join(self.report_dir, filename)

    def graph_filepath(self, filename: str) -> str:
        """图谱文件完整路径"""
        return os.path.join(self.graph_dir, filename)

    def evidence_filepath(self, filename: str) -> str:
        """证据文件完整路径"""
        return os.path.join(self.evidence_dir, filename)
