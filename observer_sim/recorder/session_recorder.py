"""
recorder/session_recorder.py — 会话级事件录制器

管理完整的录制会话:
  - 创建 records/<timestamp>/ 目录
  - 写入 meta.yaml（录制元信息）
  - 通过 EventRecorder 录制 events.jsonl
  - 支持 simulation / auto 模式
"""

import os
import sys
import json
import logging
import time
from datetime import datetime
from typing import Optional, List

from collector.event_recorder import EventRecorder
from models.event import RawEvent

logger = logging.getLogger(__name__)

# 项目根目录: records/ 在此层级
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_OBSERVER_DIR = os.path.dirname(_SCRIPT_DIR)     # observer_sim/
_PROJECT_ROOT = os.path.dirname(_OBSERVER_DIR)    # project root
RECORDS_DIR = os.path.join(_PROJECT_ROOT, "records")


class SessionRecorder:
    """
    会话级录制管理器。

    每次录制创建 records/<YYYYMMDD_HHMMSS>/ 目录，包含:
      - meta.yaml:     录制元信息
      - events.jsonl:  事件流（兼容 FileReplayCollector）
    """

    def __init__(self, records_dir: str = RECORDS_DIR,
                 agent_id: str = "record-agent",
                 collect_mode: str = "simulation",
                 config: Optional[dict] = None):
        self._records_dir = records_dir
        self._agent_id = agent_id
        self._collect_mode = collect_mode
        self._config = config or {}

        self._session_dir: Optional[str] = None
        self._session_id: Optional[str] = None
        self._recorder: Optional[EventRecorder] = None
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None
        self._event_count: int = 0
        self._collector_name: str = ""
        self._is_recording: bool = False

    # ── 属性 ──────────────────────────────────────────────────────────────────

    @property
    def session_dir(self) -> Optional[str]:
        """当前录制会话目录"""
        return self._session_dir

    @property
    def session_id(self) -> Optional[str]:
        """当前录制会话 ID（时间戳格式）"""
        return self._session_id

    @property
    def is_recording(self) -> bool:
        """是否正在录制"""
        return self._is_recording

    @property
    def event_count(self) -> int:
        """已录制的事件数"""
        return self._event_count

    @property
    def events_path(self) -> Optional[str]:
        """events.jsonl 文件路径"""
        if self._session_dir:
            return os.path.join(self._session_dir, "events.jsonl")
        return None

    # ── 录制控制 ──────────────────────────────────────────────────────────────

    def start(self) -> str:
        """
        开始录制会话。

        创建 records/<timestamp>/ 目录并初始化 EventRecorder。

        返回:
            str: 会话目录路径
        """
        if self._is_recording:
            logger.warning("已在录制中，忽略重复 start()")
            return self._session_dir

        # 创建会话目录
        self._start_time = datetime.now()
        self._session_id = self._start_time.strftime("%Y%m%d_%H%M%S")
        self._session_dir = os.path.join(self._records_dir, self._session_id)
        os.makedirs(self._session_dir, exist_ok=True)

        # 初始化 EventRecorder
        events_path = os.path.join(self._session_dir, "events.jsonl")
        self._recorder = EventRecorder(
            output_path=events_path,
            agent_id=self._agent_id,
            agent_framework="recorded",
            header_comments=[
                f"Session: {self._session_id}",
                f"Agent: {self._agent_id}",
                f"Mode: {self._collect_mode}",
            ],
        )
        self._recorder.start()
        self._event_count = 0
        self._is_recording = True

        logger.info(f"录制会话已启动: {self._session_dir}")
        return self._session_dir

    def stop(self) -> dict:
        """
        停止录制并写入 meta.yaml。

        返回:
            dict: 录制摘要（含 session_id, event_count, duration_s 等）
        """
        if not self._is_recording:
            logger.warning("未在录制中，忽略 stop()")
            return {}

        self._end_time = datetime.now()
        self._event_count = self._recorder.stop()
        self._is_recording = False

        # 计算持续时长
        duration_s = (self._end_time - self._start_time).total_seconds()

        # 写入 meta.yaml
        meta = {
            "session_id": self._session_id,
            "start_time": self._start_time.isoformat(),
            "end_time": self._end_time.isoformat(),
            "duration_seconds": round(duration_s, 2),
            "collect_mode": self._collect_mode,
            "collector_name": self._collector_name or self._collect_mode,
            "agent_id": self._agent_id,
            "event_count": self._event_count,
            "events_file": "events.jsonl",
            "events_file_size_bytes": self._recorder.get_recorded_file_size(),
        }
        meta_path = os.path.join(self._session_dir, "meta.yaml")
        self._write_meta_yaml(meta_path, meta)

        summary = {
            "session_id": self._session_id,
            "session_dir": self._session_dir,
            "event_count": self._event_count,
            "duration_s": round(duration_s, 2),
            "collect_mode": self._collect_mode,
            "events_file": os.path.join(self._session_dir, "events.jsonl"),
            "meta_file": meta_path,
        }

        logger.info(
            f"录制会话已停止: {self._session_id} "
            f"({self._event_count} events, {duration_s:.1f}s)")
        return summary

    def write_event(self, event: RawEvent) -> RawEvent:
        """
        写入单个事件到录制文件。

        参数:
            event: RawEvent 事件

        返回:
            RawEvent: 原样返回
        """
        if not self._is_recording or not self._recorder:
            logger.warning("未在录制中，事件被忽略")
            return event

        self._recorder.write(event)
        self._event_count += 1
        return event

    def record_from_collector(self, collector, max_events: int = 0,
                               timeout_s: float = 0) -> int:
        """
        从 ICollector 录制事件流。

        透明包裹 collector.start() 迭代器，逐条录制后原样 yield。

        参数:
            collector:    ICollector 实例（已 attach）
            max_events:   最大录制事件数（0 = 不限）
            timeout_s:    超时秒数（0 = 不限）

        返回:
            int: 录制的事件总数
        """
        if not self._is_recording:
            self.start()

        self._collector_name = collector.capabilities().name

        deadline = time.time() + timeout_s if timeout_s > 0 else 0
        count = 0

        for event in collector.start():
            self.write_event(event)
            count += 1

            # 实时显示进度
            desc = _event_description(event)
            print(f"  [REC {count:03d}] {event.event_type:10s} | {desc}")

            # 终止条件
            if max_events > 0 and count >= max_events:
                break
            if deadline > 0 and time.time() >= deadline:
                break

        return count

    # ── 静态方法 ──────────────────────────────────────────────────────────────

    @staticmethod
    def list_recordings(records_dir: str = RECORDS_DIR) -> List[dict]:
        """
        列出所有历史录制，按时间倒序。

        返回:
            List[dict]: 录制摘要列表
        """
        if not os.path.isdir(records_dir):
            return []

        recordings = []
        for name in sorted(os.listdir(records_dir), reverse=True):
            session_dir = os.path.join(records_dir, name)
            if not os.path.isdir(session_dir):
                continue

            meta_path = os.path.join(session_dir, "meta.yaml")
            if not os.path.isfile(meta_path):
                continue

            meta = _read_meta_yaml(meta_path)
            if not meta:
                continue

            recordings.append({
                "session_id": meta.get("session_id", name),
                "session_dir": session_dir,
                "start_time": meta.get("start_time", ""),
                "duration_seconds": meta.get("duration_seconds", 0),
                "collect_mode": meta.get("collect_mode", "unknown"),
                "event_count": meta.get("event_count", 0),
                "agent_id": meta.get("agent_id", ""),
                "events_file_size_bytes": meta.get("events_file_size_bytes", 0),
            })

        return recordings

    @staticmethod
    def _write_meta_yaml(path: str, meta: dict):
        """写入 meta.yaml（纯 Python，不依赖 pyyaml）"""
        lines = []
        for key, value in meta.items():
            if isinstance(value, str):
                lines.append(f"{key}: \"{value}\"")
            elif isinstance(value, float):
                lines.append(f"{key}: {value}")
            elif isinstance(value, int):
                lines.append(f"{key}: {value}")
            else:
                lines.append(f"{key}: \"{value}\"")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


# ── 辅助函数 ──────────────────────────────────────────────────────────────────

def _event_description(event: RawEvent) -> str:
    """构建事件的简短描述"""
    et = event.event_type
    if et == "exec":
        exe = event.executable or ""
        args = " ".join(event.arguments or [])
        return f"{exe} {args}".strip()[:60]
    elif et == "file_open":
        op = event.file_op or "open"
        path = event.file_path or ""
        return f"{op} {path}"
    elif et == "net_conn":
        addr = event.remote_addr or ""
        port = event.remote_port
        return f"{addr}:{port}" if port else addr
    return et


def _read_meta_yaml(path: str) -> dict:
    """
    读取 meta.yaml（轻量解析，不依赖 pyyaml）。
    仅处理简单的 key: value 格式。
    """
    meta = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                # 尝试数值转换（排除含下划线的字符串，如 session_id）
                if "_" not in value:
                    try:
                        if "." in value:
                            meta[key] = float(value)
                        else:
                            meta[key] = int(value)
                    except ValueError:
                        meta[key] = value
                else:
                    meta[key] = value
    except Exception as e:
        logger.warning(f"读取 meta.yaml 失败: {path}: {e}")
    return meta
