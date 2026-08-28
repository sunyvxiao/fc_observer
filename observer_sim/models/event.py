"""
事件数据模型 — RawEvent / NormalizedEvent / AgentContext

定义 C++ 探针层与 Python 引擎之间传输的事件结构。
RawEvent: 从管道接收的原始事件（对应 C++ RawEvent 结构体）
NormalizedEvent: 经过归一化处理后的事件，附带上下文信息
AgentContext: Agent 运行时上下文（进程树、会话追踪等）
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


class EventType(str, Enum):
    """事件类型枚举 — 对应三类探针的捕获范围"""
    EXEC = "exec"           # ProcessProbe: execve/fork/clone
    FILE_OPEN = "file_open"  # FileProbe: openat/unlink/rename
    NET_CONN = "net_conn"   # NetworkProbe: connect/sendto/DNS


@dataclass
class RawEvent:
    """
    原始事件 — 从 C++ 探针层通过命名管道接收的原始数据。
    
    字段与 C++ RawEvent 结构体一一对应，JSON 序列化格式完全一致。
    全量字段，缺失字段填 null（不使用 omitempty）。
    """
    event_id: str
    timestamp_ns: int
    event_type: str           # "exec" | "file_open" | "net_conn"
    pid: int
    ppid: int
    agent_id: str
    agent_framework: str
    # MCP 申报会话（黑盒 Agent 会话维度；探针事件为 None）
    session_id: Optional[str] = None
    # ProcessProbe 字段
    executable: Optional[str] = None
    arguments: Optional[List[str]] = None
    # FileProbe 字段
    file_path: Optional[str] = None
    file_op: Optional[str] = None   # "read" | "write" | "delete" | "rename" | "chmod"
    # NetworkProbe 字段
    remote_addr: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Optional[str] = None  # "TCP" | "UDP"

    def to_dict(self) -> dict:
        """序列化为字典（用于 JSON 输出）"""
        return {
            "event_id": self.event_id,
            "timestamp_ns": self.timestamp_ns,
            "event_type": self.event_type,
            "pid": self.pid,
            "ppid": self.ppid,
            "agent_id": self.agent_id,
            "agent_framework": self.agent_framework,
            "session_id": self.session_id,
            "executable": self.executable,
            "arguments": self.arguments,
            "file_path": self.file_path,
            "file_op": self.file_op,
            "remote_addr": self.remote_addr,
            "remote_port": self.remote_port,
            "protocol": self.protocol,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RawEvent":
        """从字典反序列化（用于 JSON 解析）"""
        return cls(
            event_id=data.get("event_id", ""),
            timestamp_ns=data.get("timestamp_ns", 0),
            event_type=data.get("event_type", ""),
            pid=data.get("pid", 0),
            ppid=data.get("ppid", 0),
            agent_id=data.get("agent_id", ""),
            agent_framework=data.get("agent_framework", ""),
            session_id=data.get("session_id"),
            executable=data.get("executable"),
            arguments=data.get("arguments"),
            file_path=data.get("file_path"),
            file_op=data.get("file_op"),
            remote_addr=data.get("remote_addr"),
            remote_port=data.get("remote_port"),
            protocol=data.get("protocol"),
        )

    def to_json_line(self) -> str:
        """序列化为 JSON 行（用于管道传输/日志写入）"""
        import json
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json_line(cls, line: str) -> "RawEvent":
        """从 JSON 行反序列化"""
        import json
        data = json.loads(line.strip())
        return cls.from_dict(data)


@dataclass
class ProcessNode:
    """进程树节点 — 维护 pid→ppid→agent_id 关联"""
    pid: int
    ppid: int
    agent_id: str
    executable: Optional[str] = None
    terminated: bool = False
    children: List[int] = field(default_factory=list)  # 子进程 pid 列表


@dataclass
class AgentContext:
    """
    Agent 运行时上下文 — 跟踪单个 Agent 的完整运行状态。
    
    包含:
    - agent_id: Agent 唯一标识
    - framework: Agent 使用的框架（LangChain/Dify/AutoGen 等）
    - pids: Agent 关联的所有进程 PID
    - event_count: 该 Agent 已处理的事件总数
    - recent_events: 最近 N 个事件（滑动窗口，用于上下文分析）
    """
    agent_id: str
    framework: str = ""
    pids: List[int] = field(default_factory=list)
    event_count: int = 0
    recent_events: List["NormalizedEvent"] = field(default_factory=list)
    max_recent: int = 10  # 滑动窗口大小

    def add_event(self, event: "NormalizedEvent"):
        """添加事件到上下文，维护滑动窗口"""
        self.event_count += 1
        self.recent_events.append(event)
        if len(self.recent_events) > self.max_recent:
            self.recent_events.pop(0)

    def add_pid(self, pid: int):
        """注册新的进程 PID"""
        if pid not in self.pids:
            self.pids.append(pid)


@dataclass
class NormalizedEvent:
    """
    归一化事件 — 经过 EventNormalizer 处理后的事件。
    
    在 RawEvent 基础上增加了:
    - agent_context: Agent 运行时上下文
    - process_node: 关联的进程树节点
    - command_string: 对于 exec 事件，拼接为完整命令字符串（便于规则匹配）
    - is_blocked: 是否被阻断
    - block_reason: 阻断原因
    """
    raw: RawEvent
    agent_context: Optional[AgentContext] = None
    process_node: Optional[ProcessNode] = None
    command_string: Optional[str] = None
    is_blocked: bool = False
    block_reason: Optional[str] = None

    @property
    def event_id(self) -> str:
        return self.raw.event_id

    @property
    def event_type(self) -> str:
        return self.raw.event_type

    @property
    def agent_id(self) -> str:
        return self.raw.agent_id

    @property
    def pid(self) -> int:
        return self.raw.pid

    @property
    def timestamp_ns(self) -> int:
        return self.raw.timestamp_ns

    def get_match_target(self) -> str:
        """
        获取用于规则匹配的目标字符串。
        根据事件类型返回不同的匹配目标:
        - exec: 完整命令字符串 (executable + arguments)
        - file_open: 文件路径
        - net_conn: 远程地址:端口
        """
        if self.event_type == "exec":
            if self.command_string:
                return self.command_string
            parts = [self.raw.executable or ""]
            if self.raw.arguments:
                parts.extend(self.raw.arguments)
            return " ".join(parts)
        elif self.event_type == "file_open":
            return self.raw.file_path or ""
        elif self.event_type == "net_conn":
            addr = self.raw.remote_addr or ""
            port = self.raw.remote_port
            if port:
                return f"{addr}:{port}"
            return addr
        return ""
