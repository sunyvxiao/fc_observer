"""
recorder/ — 录制-回放模块

提供完整的事件流录制与回放能力:
- session_recorder:  SessionRecorder — 会话级录制管理（目录/meta.yaml/events.jsonl）
- replay_engine:     ReplayEngine — 录制回放编排（加载+observer_core 全链路+报告输出）

录制数据存放在项目根目录 records/ 下，每个录制会话一个子目录:
    records/<YYYYMMDD_HHMMSS>/
        meta.yaml          — 录制元信息
        events.jsonl        — 事件数据（兼容 FileReplayCollector）
        replay_output/      — 回放分析输出（仅回放后生成）
"""

from recorder.session_recorder import SessionRecorder
from recorder.replay_engine import ReplayEngine

__all__ = [
    "SessionRecorder",
    "ReplayEngine",
]
