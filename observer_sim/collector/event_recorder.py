"""
collector/event_recorder.py — 事件录制器

将 RawEvent 流实时录制为 JSONL 文件，录制的文件可直接被
FileReplayCollector 回放，实现"录制-回放"工作流。

核心设计:
  - 透明中间件: 包裹任意 RawEvent 迭代器，逐条写入 JSONL 后原样 yield
  - 实时落盘: 每条事件写入后立即 flush，确保进程中断不丢数据
  - 格式兼容: 输出格式与 FileReplayCollector._load_jsonl() 完全一致
  - 白盒友好: 支持 # 注释行标注录制元信息

用法:
    # 方式一: 包裹迭代器（推荐）
    recorder = EventRecorder("output/recorded.jsonl", agent_id="my-agent")
    recorder.start()
    for raw_event in recorder.record(collector.start()):
        process(raw_event)
    recorder.stop()

    # 方式二: 手动逐条写入
    recorder = EventRecorder("output/recorded.jsonl")
    recorder.start()
    recorder.write(raw_event)
    recorder.stop()

    # 方式三: 作为上下文管理器
    with EventRecorder("output/recorded.jsonl") as recorder:
        for raw_event in recorder.record(source):
            process(raw_event)
"""

import os
import json
import logging
from typing import Iterator, Optional, List
from datetime import datetime

from models.event import RawEvent

logger = logging.getLogger(__name__)


class EventRecorder:
    """
    事件录制器 — 将 RawEvent 流实时录制为 JSONL 文件。

    录制的文件符合 FileReplayCollector 的数据规范，可直接回放。
    """

    def __init__(self, output_path: str,
                 agent_id: str = "",
                 agent_framework: str = "recorded",
                 header_comments: Optional[List[str]] = None):
        """
        初始化事件录制器。

        参数:
            output_path:       输出 JSONL 文件路径
            agent_id:          默认 agent_id（如事件未指定则使用此值）
            agent_framework:   默认 agent_framework 标识
            header_comments:   文件头部注释行列表（# 开头）
        """
        self._output_path = output_path
        self._default_agent_id = agent_id
        self._default_framework = agent_framework
        self._header_comments = header_comments or []
        self._file_handle = None
        self._event_count = 0
        self._started = False

    @property
    def output_path(self) -> str:
        """录制文件路径"""
        return self._output_path

    @property
    def event_count(self) -> int:
        """已录制的事件数量"""
        return self._event_count

    @property
    def is_recording(self) -> bool:
        """是否正在录制"""
        return self._started and self._file_handle is not None

    def start(self):
        """
        开始录制，打开输出文件并写入头部注释。
        """
        if self._started:
            logger.warning("EventRecorder 已在录制中")
            return

        # 确保输出目录存在
        output_dir = os.path.dirname(self._output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        self._file_handle = open(self._output_path, "w", encoding="utf-8")
        self._started = True
        self._event_count = 0

        # 写入头部注释
        self._file_handle.write(
            f"# Recorded by EventRecorder at "
            f"{datetime.now().isoformat()}\n"
        )
        if self._default_agent_id:
            self._file_handle.write(
                f"# agent_id: {self._default_agent_id}\n"
            )
        for comment in self._header_comments:
            if not comment.startswith("#"):
                comment = f"# {comment}"
            self._file_handle.write(comment + "\n")

        self._file_handle.flush()
        logger.info(
            f"EventRecorder 开始录制: {self._output_path}")

    def stop(self) -> int:
        """
        停止录制，关闭输出文件。

        返回:
            int: 录制的事件总数
        """
        if not self._started:
            logger.warning("EventRecorder 未启动")
            return 0

        if self._file_handle:
            self._file_handle.flush()
            self._file_handle.close()
            self._file_handle = None

        self._started = False
        logger.info(
            f"EventRecorder 停止录制: {self._output_path} "
            f"({self._event_count} 个事件)")
        return self._event_count

    def write(self, event: RawEvent) -> RawEvent:
        """
        写入单个 RawEvent 到 JSONL 文件。

        参数:
            event: 要录制的原始事件

        返回:
            RawEvent: 原样返回输入事件（方便链式调用）
        """
        if not self.is_recording:
            logger.warning("EventRecorder 未录制中，事件被忽略")
            return event

        # 确保 agent_id 和 agent_framework 有值
        data = event.to_dict()
        if not data.get("agent_id") and self._default_agent_id:
            data["agent_id"] = self._default_agent_id
        if not data.get("agent_framework") and self._default_framework:
            data["agent_framework"] = self._default_framework

        # 写入 JSON 行
        self._file_handle.write(json.dumps(data, ensure_ascii=False) + "\n")
        self._file_handle.flush()
        self._event_count += 1

        return event

    def record(self, source: Iterator[RawEvent]) -> Iterator[RawEvent]:
        """
        透明录制 RawEvent 流。

        从 source 迭代器中逐条读取事件，写入 JSONL 文件后原样 yield。
        这是一个透明中间件，不修改、不过滤任何事件。

        参数:
            source: RawEvent 迭代器（来自任意 ICollector.start()）

        Yields:
            RawEvent: 原样传递的原始事件
        """
        if not self.is_recording:
            self.start()

        try:
            for event in source:
                self.write(event)
                yield event
        finally:
            # 迭代器耗尽时自动停止录制
            if self.is_recording:
                self.stop()

    def __enter__(self) -> "EventRecorder":
        """上下文管理器入口"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """上下文管理器退出"""
        self.stop()

    def get_recorded_file_size(self) -> int:
        """获取录制文件当前大小（字节）"""
        if os.path.isfile(self._output_path):
            return os.path.getsize(self._output_path)
        return 0
