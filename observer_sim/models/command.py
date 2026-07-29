"""
指令数据模型 — Command (反向管道指令)

定义 Python→C++ 反向管道传输的阻断指令结构。
"""

from dataclasses import dataclass
from typing import Optional
from enum import Enum


class CmdType(str, Enum):
    """指令类型枚举 — 反向管道支持的指令类型"""
    ALLOW = "allow"                    # 放行：继续正常处理下一个事件
    BLOCK_EVENT = "block_event"        # 阻止当前事件：模拟返回 EPERM
    TERMINATE_PROCESS = "terminate_process"  # 终止进程：标记目标 pid 及子进程为 terminated
    HEARTBEAT = "heartbeat"            # 心跳探测：回复 ACK


class BlockAction(str, Enum):
    """阻断动作枚举"""
    RETURN_EPERM = "return_eperm"      # 模拟返回 EPERM 错误码
    KILL_PROCESS = "kill_process"      # 终止进程


@dataclass
class Command:
    """
    阻断指令 — Python 通过反向管道下发给 C++ 探针层的控制指令。
    
    字段与定稿中反向指令格式一一对应。
    """
    cmd_id: str
    cmd_type: str           # "allow" | "block_event" | "terminate_process" | "heartbeat"
    target_event_id: Optional[str] = None
    target_pid: Optional[int] = None
    action: Optional[str] = None       # "return_eperm" | "kill_process"
    reason: Optional[str] = None
    timestamp_ns: int = 0

    def to_dict(self) -> dict:
        """序列化为字典（用于 JSON 输出）"""
        return {
            "cmd_id": self.cmd_id,
            "cmd_type": self.cmd_type,
            "target_event_id": self.target_event_id,
            "target_pid": self.target_pid,
            "action": self.action,
            "reason": self.reason,
            "timestamp_ns": self.timestamp_ns,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Command":
        """从字典反序列化"""
        return cls(
            cmd_id=data.get("cmd_id", ""),
            cmd_type=data.get("cmd_type", ""),
            target_event_id=data.get("target_event_id"),
            target_pid=data.get("target_pid"),
            action=data.get("action"),
            reason=data.get("reason"),
            timestamp_ns=data.get("timestamp_ns", 0),
        )

    def to_json_line(self) -> str:
        """序列化为 JSON 行（用于管道传输）"""
        import json
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json_line(cls, line: str) -> "Command":
        """从 JSON 行反序列化"""
        import json
        data = json.loads(line.strip())
        return cls.from_dict(data)

    @classmethod
    def make_allow(cls, cmd_id: str, event_id: str, timestamp_ns: int = 0) -> "Command":
        """创建放行指令"""
        return cls(
            cmd_id=cmd_id,
            cmd_type=CmdType.ALLOW.value,
            target_event_id=event_id,
            action=None,
            reason="放行",
            timestamp_ns=timestamp_ns,
        )

    @classmethod
    def make_block(cls, cmd_id: str, event_id: str, pid: int,
                   reason: str, timestamp_ns: int = 0) -> "Command":
        """创建阻断指令"""
        return cls(
            cmd_id=cmd_id,
            cmd_type=CmdType.BLOCK_EVENT.value,
            target_event_id=event_id,
            target_pid=pid,
            action=BlockAction.RETURN_EPERM.value,
            reason=reason,
            timestamp_ns=timestamp_ns,
        )

    @classmethod
    def make_terminate(cls, cmd_id: str, pid: int,
                       reason: str, timestamp_ns: int = 0) -> "Command":
        """创建终止进程指令"""
        return cls(
            cmd_id=cmd_id,
            cmd_type=CmdType.TERMINATE_PROCESS.value,
            target_pid=pid,
            action=BlockAction.KILL_PROCESS.value,
            reason=reason,
            timestamp_ns=timestamp_ns,
        )

    @classmethod
    def make_heartbeat(cls, cmd_id: str, timestamp_ns: int = 0) -> "Command":
        """创建心跳探测指令"""
        return cls(
            cmd_id=cmd_id,
            cmd_type=CmdType.HEARTBEAT.value,
            timestamp_ns=timestamp_ns,
        )
