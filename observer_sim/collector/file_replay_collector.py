"""
collector/file_replay_collector.py — 文件回放采集器

实现 ICollector 接口，从外部 JSONL/CSV 文件导入测试数据，
逐行解析并 yield RawEvent 给上层 observer_core/ 处理链路。

支持的数据源:
  - 生产环境 eBPF 采集的 JSONL 导出
  - strace 输出经脚本转换后的 JSONL
  - Falco/Sysdig 告警转换后的 JSONL
  - 手工构造的白盒测试数据（文本编辑器可编辑）

白盒特性:
  - JSONL 每行是一个完整事件，可逐行审计
  - Git diff 友好，变更可追溯
  - 支持注释行（# 开头），方便标注测试意图
"""

import os
import csv
import json
import logging
from typing import Iterator, Optional, List

from collector.base_collector import ICollector, CollectorCapabilities
from models.event import RawEvent

logger = logging.getLogger(__name__)


class FileReplayCollector(ICollector):
    """
    文件回放采集器 —— 从外部 JSONL/CSV 文件导入测试数据。

    实现 ICollector 接口，observer_core/ 零改动。
    支持 JSONL（首选）和 CSV 两种文件格式。
    """

    def __init__(self, config: dict):
        """
        初始化文件回放采集器。

        参数:
            config: 配置字典（从 config.yaml 加载）
        """
        self.config = config
        self.replay_config = config.get("file_replay", {})
        self.target_agent_id = self.replay_config.get(
            "target_agent_id",
            self.replay_config.get("default_agent_id", "replay-agent"))

        # 内部状态
        self._events: List[RawEvent] = []
        self._data_path: Optional[str] = None
        self._attached = False
        self._seq = 0

    def capabilities(self) -> CollectorCapabilities:
        """返回文件回放采集器能力描述"""
        return CollectorCapabilities(
            name="FileReplay",
            can_observe=True,
            can_block_tier2=False,    # 离线回放不阻断
            can_block_tier3=False,
            is_transparent=True,      # 回放模式对 Agent 无感知
            performance_overhead="low",
            time_source="file_timestamp",  # 使用文件中的时间戳
        )

    def load_data_file(self, path: str) -> int:
        """
        加载数据文件。自动检测文件格式（JSONL 或 CSV）。

        参数:
            path: 数据文件路径（.jsonl 或 .csv）

        返回:
            加载的事件数量

        异常:
            FileNotFoundError: 文件不存在
            ValueError: 文件格式不支持或解析失败
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"数据文件不存在: {path}")

        ext = os.path.splitext(path)[1].lower()
        if ext == ".jsonl" or ext == ".json":
            count = self._load_jsonl(path)
        elif ext == ".csv":
            count = self._load_csv(path)
        else:
            # 尝试作为 JSONL 解析
            try:
                count = self._load_jsonl(path)
            except (json.JSONDecodeError, ValueError):
                raise ValueError(
                    f"不支持的文件格式: {ext}。支持 .jsonl / .csv")

        self._data_path = path
        logger.info(f"加载数据文件: {path} ({count} 个事件)")
        return count

    def _load_jsonl(self, path: str) -> int:
        """
        加载 JSONL 格式数据文件。

        每行一个 JSON 对象，对应一个 RawEvent。
        支持:
          - 空行跳过
          - # 开头行为注释（白盒特性）
          - 自动补充缺失的必填字段（event_id, agent_framework）
        """
        self._events = []
        count = 0

        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                stripped = line.strip()

                # 跳过空行
                if not stripped:
                    continue

                # 跳过注释行（白盒特性）
                if stripped.startswith("#"):
                    continue

                try:
                    data = json.loads(stripped)
                except json.JSONDecodeError as e:
                    logger.warning(
                        f"{path}:{line_no} JSON 解析失败: {e}")
                    continue

                # 验证必填字段
                if not self._validate_event(data, path, line_no):
                    continue

                # 构造 RawEvent
                raw = self._dict_to_raw_event(data, count + 1)
                self._events.append(raw)
                count += 1

        return count

    def _load_csv(self, path: str) -> int:
        """
        加载 CSV 格式数据文件。

        第一行为表头，必须包含 event_type 列。
        支持的列名与 RawEvent 字段一一对应。
        """
        self._events = []
        count = 0

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row_no, row in enumerate(reader, 2):
                # CSV 行转为字典
                data = self._csv_row_to_dict(row)

                if not self._validate_event(data, path, row_no):
                    continue

                raw = self._dict_to_raw_event(data, count + 1)
                self._events.append(raw)
                count += 1

        return count

    def _csv_row_to_dict(self, row: dict) -> dict:
        """
        将 CSV 行转换为 RawEvent 数据字典。

        处理类型转换:
          - pid/ppid/timestamp_ns/remote_port → int
          - arguments → JSON 数组或逗号分隔列表
        """
        data = {}
        for key, value in row.items():
            if key is None:
                continue  # CSV 多余列（None key）跳过
            key = key.strip()
            value = value.strip() if value else ""

            if not value:
                data[key] = None
                continue

            # 整数字段
            if key in ("pid", "ppid", "timestamp_ns", "remote_port"):
                try:
                    data[key] = int(value)
                except ValueError:
                    data[key] = None
                    continue
            # 列表字段（JSON 数组或逗号分隔）
            elif key == "arguments":
                if value.startswith("["):
                    try:
                        data[key] = json.loads(value)
                    except json.JSONDecodeError:
                        data[key] = [value]
                else:
                    data[key] = [a.strip() for a in value.split(",") if a.strip()]
            else:
                data[key] = value

        return data

    def _validate_event(self, data: dict, path: str, line_no: int) -> bool:
        """
        验证事件数据的必填字段。

        必填字段: event_type
        可选字段: 其余字段有默认值
        """
        if "event_type" not in data or not data["event_type"]:
            logger.warning(
                f"{path}:{line_no} 缺少必填字段 event_type，跳过")
            return False

        event_type = data["event_type"]
        valid_types = ("exec", "file_open", "net_conn")
        if event_type not in valid_types:
            logger.warning(
                f"{path}:{line_no} 未知 event_type '{event_type}'，"
                f"有效值: {valid_types}，跳过")
            return False

        return True

    @staticmethod
    def _safe_int(value, default: int = 0) -> int:
        """安全整数转换，处理 None / 空字符串 / 非数字。"""
        if value is None or value == "":
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def _dict_to_raw_event(self, data: dict, seq: int) -> RawEvent:
        """
        将数据字典转换为 RawEvent，自动补充缺失字段。
        """
        self._seq += 1

        return RawEvent(
            event_id=data.get("event_id", f"replay_evt_{seq:06d}"),
            timestamp_ns=self._safe_int(data.get("timestamp_ns"), 0),
            event_type=data["event_type"],
            pid=self._safe_int(data.get("pid"), 0),
            ppid=self._safe_int(data.get("ppid"), 0),
            agent_id=data.get("agent_id", self.target_agent_id),
            agent_framework=data.get("agent_framework", "file_replay"),
            executable=data.get("executable") or None,
            arguments=data.get("arguments") or None,
            file_path=data.get("file_path") or None,
            file_op=data.get("file_op") or None,
            remote_addr=data.get("remote_addr") or None,
            remote_port=self._safe_int(data.get("remote_port"), None) if data.get("remote_port") not in (None, "") else None,
            protocol=data.get("protocol") or None,
        )

    def attach(self, target_pid: int = 0, agent_id: str = "") -> bool:
        """
        附着到目标。

        回放模式下 target_pid 忽略。
        如果尚未加载数据文件，返回 False。
        """
        if agent_id:
            self.target_agent_id = agent_id

        if not self._events:
            logger.warning(
                "FileReplayCollector: 未加载数据文件，"
                "请先调用 load_data_file()")
            return False

        self._attached = True
        logger.info(
            f"FileReplayCollector 已附着 "
            f"({len(self._events)} 个事件, agent_id={self.target_agent_id})")
        return True

    def start(self) -> Iterator[RawEvent]:
        """
        开始回放，逐条 yield RawEvent。
        """
        if not self._attached:
            logger.warning("FileReplayCollector 未附着，请先调用 attach()")
            return

        for event in self._events:
            yield event

    def send_command(self, cmd) -> bool:
        """
        回放模式不支持动态阻断。

        返回 False 并记录警告日志。
        """
        logger.warning(
            "文件回放模式不支持动态阻断，send_command() 忽略。"
            "如需阻断功能，请使用 SimulationCollector")
        return False

    def detach(self) -> None:
        """断开采集，清理事件列表"""
        self._events.clear()
        self._attached = False
        logger.info("FileReplayCollector 已断开")

    def get_process_tree(self) -> dict:
        """回放模式不维护进程树，返回空字典"""
        return {}

    @property
    def event_count(self) -> int:
        """已加载的事件数量"""
        return len(self._events)

    @property
    def data_path(self) -> Optional[str]:
        """当前加载的数据文件路径"""
        return self._data_path
