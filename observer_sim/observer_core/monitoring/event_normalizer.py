"""
EventNormalizer — 事件归一化器

职责:
- 补充 Agent 上下文（维护进程树、Agent 会话追踪）
- 关联父子进程（pid→ppid→agent_id 链）
- 维护事件序列窗口（最近 N 个事件，虚拟时钟驱动超时清理）
- 将 RawEvent 转换为 NormalizedEvent

输入: RawEvent + VirtualClock
输出: NormalizedEvent + AgentContext
"""

import logging
from typing import Dict, List, Optional
from abc import ABC, abstractmethod

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.event import RawEvent, NormalizedEvent, AgentContext, ProcessNode
from models.virtual_clock import VirtualClock

logger = logging.getLogger(__name__)


class IEventNormalizer(ABC):
    """事件归一化器抽象接口"""

    @abstractmethod
    def normalize(self, raw: RawEvent) -> NormalizedEvent:
        ...

    @abstractmethod
    def get_agent_context(self, agent_id: str) -> AgentContext:
        ...

    @abstractmethod
    def get_recent_events(self, agent_id: str, n: int) -> List[NormalizedEvent]:
        ...


class EventNormalizer(IEventNormalizer):
    """
    事件归一化器实现。
    
    核心功能:
    1. 进程树维护: pid → ProcessNode，支持父子关联
    2. Agent 会话追踪: agent_id → AgentContext
    3. 事件序列窗口: 每个 Agent 维护最近 N 个事件
    4. 命令字符串拼接: exec 事件的 executable + arguments → 完整命令
    """

    def __init__(self, clock: VirtualClock, window_size: int = 10):
        """
        Args:
            clock: 虚拟时钟实例
            window_size: 事件序列窗口大小（每个 Agent 保留最近 N 个事件）
        """
        self._clock = clock
        self._window_size = window_size

        # 进程树: pid → ProcessNode
        self._process_tree: Dict[int, ProcessNode] = {}

        # Agent 上下文: agent_id → AgentContext
        self._agent_contexts: Dict[str, AgentContext] = {}

        # 统计
        self._total_normalized: int = 0

    def normalize(self, raw: RawEvent) -> NormalizedEvent:
        """
        将 RawEvent 归一化为 NormalizedEvent。
        
        处理步骤:
        1. 注册/更新进程树节点
        2. 获取或创建 Agent 上下文
        3. 拼接命令字符串（exec 事件）
        4. 将事件添加到 Agent 上下文
        5. 构造 NormalizedEvent
        """
        self._total_normalized += 1

        # Step 1: 进程树维护
        self._update_process_tree(raw)

        # Step 2: Agent 上下文
        agent_ctx = self._get_or_create_agent_context(raw)

        # Step 3: 构造 NormalizedEvent
        norm_event = NormalizedEvent(
            raw=raw,
            agent_context=agent_ctx,
            process_node=self._process_tree.get(raw.pid),
        )

        # Step 4: 拼接命令字符串
        if raw.event_type == "exec":
            parts = [raw.executable or ""]
            if raw.arguments:
                parts.extend(raw.arguments)
            norm_event.command_string = " ".join(parts)

        # Step 5: 添加到 Agent 上下文（维护滑动窗口）
        agent_ctx.add_event(norm_event)

        # Step 6: 清理过期事件（基于虚拟时钟）
        self._cleanup_stale_events(agent_ctx)

        return norm_event

    def _update_process_tree(self, raw: RawEvent):
        """更新进程树"""
        pid = raw.pid
        ppid = raw.ppid

        if pid not in self._process_tree:
            # 新进程
            node = ProcessNode(
                pid=pid,
                ppid=ppid,
                agent_id=raw.agent_id,
                executable=raw.executable if raw.event_type == "exec" else None,
            )
            self._process_tree[pid] = node

            # 在父进程的 children 中注册
            if ppid > 0 and ppid in self._process_tree:
                parent = self._process_tree[ppid]
                if pid not in parent.children:
                    parent.children.append(pid)

            logger.debug(f"[Normalizer] New process: pid={pid}, ppid={ppid}, agent={raw.agent_id}")
        else:
            # 已有进程，更新信息
            node = self._process_tree[pid]
            if raw.event_type == "exec" and raw.executable:
                node.executable = raw.executable

    def _get_or_create_agent_context(self, raw: RawEvent) -> AgentContext:
        """获取或创建 Agent 上下文"""
        agent_id = raw.agent_id
        if agent_id not in self._agent_contexts:
            ctx = AgentContext(
                agent_id=agent_id,
                framework=raw.agent_framework,
                max_recent=self._window_size,
            )
            self._agent_contexts[agent_id] = ctx
            logger.debug(f"[Normalizer] New agent context: {agent_id}")

        ctx = self._agent_contexts[agent_id]
        # 注册 PID
        if raw.pid > 0:
            ctx.add_pid(raw.pid)
        return ctx

    def _cleanup_stale_events(self, ctx: AgentContext, max_age_ms: int = 60000):
        """
        清理过期事件（基于虚拟时钟）。
        
        移除超过 max_age_ms 的事件，保持窗口新鲜。
        """
        if not ctx.recent_events:
            return

        now_ns = self._clock.now_ns()
        max_age_ns = max_age_ms * 1_000_000

        # 移除时间戳过旧的事件
        ctx.recent_events = [
            e for e in ctx.recent_events
            if (now_ns - e.timestamp_ns) <= max_age_ns
        ]

    def get_agent_context(self, agent_id: str) -> AgentContext:
        """获取指定 Agent 的上下文"""
        return self._agent_contexts.get(agent_id)

    def get_recent_events(self, agent_id: str, n: int = 10) -> List[NormalizedEvent]:
        """获取指定 Agent 最近 N 个事件"""
        ctx = self._agent_contexts.get(agent_id)
        if not ctx:
            return []
        return ctx.recent_events[-n:]

    def get_process_node(self, pid: int) -> Optional[ProcessNode]:
        """获取进程树节点"""
        return self._process_tree.get(pid)

    def get_all_agents(self) -> List[str]:
        """获取所有已知的 Agent ID"""
        return list(self._agent_contexts.keys())

    def get_process_tree_snapshot(self) -> Dict[int, dict]:
        """获取进程树快照（用于调试/报告）"""
        snapshot = {}
        for pid, node in self._process_tree.items():
            snapshot[pid] = {
                "pid": node.pid,
                "ppid": node.ppid,
                "agent_id": node.agent_id,
                "executable": node.executable,
                "terminated": node.terminated,
                "children": node.children,
            }
        return snapshot

    @property
    def total_normalized(self) -> int:
        return self._total_normalized

    @property
    def process_count(self) -> int:
        return len(self._process_tree)

    @property
    def agent_count(self) -> int:
        return len(self._agent_contexts)
