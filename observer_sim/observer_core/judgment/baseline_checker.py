"""
BaselineChecker — 基线构建 + 偏离分析 + 冷启动处理

核心职责:
1. 收集正常行为数据，构建基线模型
2. 检测当前事件与基线的偏离程度
3. 冷启动处理: 无基线时偏离分固定 0.0
4. 基线快照保存/加载 (JSON 格式 → output/baselines/)

基线模型包含:
- command_freq: 命令频率分布 {cmd_name: count}
- file_paths: 常见文件路径前缀集合
- net_targets: 常见网络目标集合 {addr:port}
- event_type_freq: 事件类型频率分布 {event_type: count}
- agent_profiles: Agent 行为画像 {agent_id: profile_dict}
"""

import os
import json
import logging
from typing import Dict, Set, List, Optional
from dataclasses import dataclass, field

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.event import NormalizedEvent, AgentContext
from models.virtual_clock import VirtualClock
from observer_core.judgment.tuning_loader import get_tuning

logger = logging.getLogger(__name__)


@dataclass
class BaselineModel:
    """基线模型 — 记录正常行为的统计特征"""
    command_freq: Dict[str, int] = field(default_factory=dict)
    file_path_prefixes: Set[str] = field(default_factory=set)
    net_targets: Set[str] = field(default_factory=set)
    event_type_freq: Dict[str, int] = field(default_factory=dict)
    agent_profiles: Dict[str, dict] = field(default_factory=dict)
    total_events: int = 0
    is_warm: bool = False  # 基线是否已预热（有足够的样本）

    def to_dict(self) -> dict:
        """序列化为字典"""
        return {
            "command_freq": dict(self.command_freq),
            "file_path_prefixes": list(self.file_path_prefixes),
            "net_targets": list(self.net_targets),
            "event_type_freq": dict(self.event_type_freq),
            "agent_profiles": {
                k: {
                    "event_count": v.get("event_count", 0),
                    "known_commands": list(v.get("known_commands", [])),
                    "known_paths": list(v.get("known_paths", [])),
                    "known_net_targets": list(v.get("known_net_targets", [])),
                }
                for k, v in self.agent_profiles.items()
            },
            "total_events": self.total_events,
            "is_warm": self.is_warm,
        }

    @staticmethod
    def from_dict(data: dict) -> "BaselineModel":
        """从字典反序列化"""
        model = BaselineModel()
        model.command_freq = data.get("command_freq", {})
        model.file_path_prefixes = set(data.get("file_path_prefixes", []))
        model.net_targets = set(data.get("net_targets", []))
        model.event_type_freq = data.get("event_type_freq", {})
        model.agent_profiles = {
            k: {
                "event_count": v.get("event_count", 0),
                "known_commands": set(v.get("known_commands", [])),
                "known_paths": set(v.get("known_paths", [])),
                "known_net_targets": set(v.get("known_net_targets", [])),
            }
            for k, v in data.get("agent_profiles", {}).items()
        }
        model.total_events = data.get("total_events", 0)
        model.is_warm = data.get("is_warm", False)
        return model


class BaselineChecker:
    """
    基线检查器。

    工作流:
    1. 场景1（正常开发）运行期间: 收集行为数据构建基线
    2. 场景1结束后: 保存基线快照到 output/baselines/
    3. 场景2/3运行时: 加载已有基线，偏离检测生效
    4. 冷启动期（total_events < min_warm_events）: 偏离分固定 0.0
    """

    # 安全目录前缀（正常 Agent 通常访问的目录）
    SAFE_DIR_PREFIXES = [
        "/home/", "/project/", "/tmp/", "/var/log/",
        "/usr/bin/git", "/usr/bin/python",
        "C:\\Users\\", "C:\\Projects\\",
    ]

    # 常见安全命令
    SAFE_COMMANDS = {
        "git", "python", "python3", "pytest", "pip", "pip3",
        "npm", "node", "make", "cmake", "gcc", "g++", "javac",
        "docker", "ls", "cat", "grep", "echo", "cd", "mkdir",
        "cp", "mv", "touch", "find", "head", "tail", "wc",
    }

    def __init__(self, min_warm_events: int = None,
                 baseline_dir: str = None):
        """
        Args:
            min_warm_events: 基线预热所需的最小事件数。None 时从 tuning.yaml 加载
            baseline_dir: 基线快照保存目录。None 时从 tuning.yaml 加载
        """
        tuning = get_tuning()
        baseline_cfg = tuning.get("baseline", {})

        self._min_warm_events = (
            min_warm_events
            if min_warm_events is not None
            else baseline_cfg.get("min_warm_events", 10)
        )
        self._baseline_dir = (
            baseline_dir
            if baseline_dir is not None
            else baseline_cfg.get("baseline_dir", "output/baselines")
        )
        self._model = BaselineModel()
        self._is_cold_start = True  # 初始为冷启动

    @property
    def model(self) -> BaselineModel:
        """获取当前基线模型"""
        return self._model

    @property
    def is_cold_start(self) -> bool:
        """是否处于冷启动期"""
        return self._is_cold_start

    @property
    def is_warm(self) -> bool:
        """基线是否已预热"""
        return self._model.is_warm

    @property
    def total_events(self) -> int:
        """已收集的基线事件总数"""
        return self._model.total_events

    def collect(self, event: NormalizedEvent) -> None:
        """
        收集一个事件到基线模型。

        在基线构建阶段（如场景1运行期间），每个归一化事件
        都应调用此方法更新基线统计。
        """
        model = self._model
        model.total_events += 1

        # 更新事件类型频率
        et = event.event_type
        model.event_type_freq[et] = model.event_type_freq.get(et, 0) + 1

        # 更新命令频率
        if event.event_type == "exec" and event.raw.executable:
            exe = event.raw.executable
            cmd_name = exe.split("/")[-1] if "/" in exe else exe.split("\\")[-1]
            model.command_freq[cmd_name] = model.command_freq.get(cmd_name, 0) + 1

        # 更新文件路径前缀
        if event.event_type == "file_open" and event.raw.file_path:
            path = event.raw.file_path
            # 提取前两级目录作为前缀
            parts = path.replace("\\", "/").split("/")
            if len(parts) >= 3:
                prefix = "/".join(parts[:3]) + "/"
                model.file_path_prefixes.add(prefix)

        # 更新网络目标
        if event.event_type == "net_conn" and event.raw.remote_addr:
            target = f"{event.raw.remote_addr}:{event.raw.remote_port}"
            model.net_targets.add(target)

        # 更新 Agent 画像
        agent_id = event.agent_id
        if agent_id:
            if agent_id not in model.agent_profiles:
                model.agent_profiles[agent_id] = {
                    "event_count": 0,
                    "known_commands": set(),
                    "known_paths": set(),
                    "known_net_targets": set(),
                }
            profile = model.agent_profiles[agent_id]
            profile["event_count"] += 1
            if event.event_type == "exec" and event.raw.executable:
                exe = event.raw.executable
                cmd_name = exe.split("/")[-1] if "/" in exe else exe
                profile["known_commands"].add(cmd_name)
            if event.event_type == "file_open" and event.raw.file_path:
                profile["known_paths"].add(event.raw.file_path)
            if event.event_type == "net_conn" and event.raw.remote_addr:
                profile["known_net_targets"].add(
                    f"{event.raw.remote_addr}:{event.raw.remote_port}"
                )

        # 检查是否完成预热
        if not model.is_warm and model.total_events >= self._min_warm_events:
            model.is_warm = True
            self._is_cold_start = False
            logger.info(
                f"[BaselineChecker] Baseline warmed after {model.total_events} events"
            )

    def compute_deviation(self, event: NormalizedEvent,
                          context: AgentContext) -> float:
        """
        计算事件相对于基线的偏离度。

        冷启动期（事件数 < min_warm_events）→ 固定返回 0.0
        否则返回 0.0 ~ 1.0 的偏离值。

        偏离检测维度:
        - 命令偏离: 未知命令 → +0.3
        - 文件路径偏离: 未知路径前缀 → +0.3
        - 网络目标偏离: 未知网络目标 → +0.25
        - 频率偏离: 事件类型频率异常 → +0.15
        """
        # 冷启动期
        if not self._model.is_warm:
            return 0.0

        model = self._model
        deviation = 0.0

        # 1. 命令偏离
        if event.event_type == "exec" and event.raw.executable:
            exe = event.raw.executable
            cmd_name = exe.split("/")[-1] if "/" in exe else exe.split("\\")[-1]
            if cmd_name not in model.command_freq:
                deviation += 0.3

        # 2. 文件路径偏离
        if event.event_type == "file_open" and event.raw.file_path:
            path = event.raw.file_path
            is_known = any(
                path.startswith(prefix) for prefix in model.file_path_prefixes
            )
            if not is_known and model.file_path_prefixes:
                deviation += 0.3

        # 3. 网络目标偏离
        if event.event_type == "net_conn" and event.raw.remote_addr:
            target = f"{event.raw.remote_addr}:{event.raw.remote_port}"
            if target not in model.net_targets and model.net_targets:
                deviation += 0.25

        # 4. 频率偏离（简化: 当前事件类型在历史中的占比是否异常低）
        et = event.event_type
        if model.total_events > 0:
            hist_ratio = model.event_type_freq.get(et, 0) / model.total_events
            # 如果历史占比极低（< 5%），视为异常
            if hist_ratio < 0.05 and model.total_events >= self._min_warm_events:
                deviation += 0.15

        return min(deviation, 1.0)

    def get_baseline_dict(self) -> dict:
        """获取基线模型的字典表示（供 RiskScorer 使用）"""
        return {
            "command_freq": dict(self._model.command_freq),
            "file_path_prefixes": list(self._model.file_path_prefixes),
            "net_targets": list(self._model.net_targets),
            "event_type_freq": dict(self._model.event_type_freq),
            "is_warm": self._model.is_warm,
            "total_events": self._model.total_events,
        }

    def save_baseline(self, filepath: Optional[str] = None) -> str:
        """
        保存基线快照到 JSON 文件。

        Args:
            filepath: 保存路径，默认 output/baselines/baseline_<timestamp>.json

        Returns:
            实际保存的文件路径
        """
        if filepath is None:
            os.makedirs(self._baseline_dir, exist_ok=True)
            import time
            ts = int(time.time())
            filepath = os.path.join(self._baseline_dir, f"baseline_{ts}.json")
        else:
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        data = self._model.to_dict()
        # set 不能直接 JSON 序列化，to_dict 已处理
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        logger.info(f"[BaselineChecker] Baseline saved to {filepath}")
        return filepath

    def load_baseline(self, filepath: str) -> bool:
        """
        从 JSON 文件加载基线模型。

        Args:
            filepath: 基线文件路径

        Returns:
            是否加载成功
        """
        if not os.path.exists(filepath):
            logger.warning(f"[BaselineChecker] Baseline file not found: {filepath}")
            return False

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._model = BaselineModel.from_dict(data)
            self._is_cold_start = not self._model.is_warm
            logger.info(
                f"[BaselineChecker] Baseline loaded from {filepath} "
                f"(events={self._model.total_events}, warm={self._model.is_warm})"
            )
            return True
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"[BaselineChecker] Failed to load baseline: {e}")
            return False

    def reset(self) -> None:
        """重置基线模型（用于新场景开始前）"""
        self._model = BaselineModel()
        self._is_cold_start = True
        logger.info("[BaselineChecker] Baseline reset")
