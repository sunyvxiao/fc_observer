"""
adapter/agent_bridge.py — Pydantic-DeepAgents ↔ observer_core 桥接层

核心职责:
1. 将 pydantic-deep 的 HookInput (tool 调用) 转换为 RawEvent
2. 提供 observer hook handler，供 pydantic-deep Hook 回调
3. 工具名 → 事件类型映射:
   - execute / run_command → exec
   - read_file / read → file_open (read)
   - write_file / edit_file → file_open (write)
   - web_fetch / web_search → net_conn
4. 线程安全的事件队列，供 DeepAgentCollector 消费

不修改 observer_core/ / models/ / scenarios/ / rules/ (零改动约束)。
"""

import re
import time
import logging
import threading
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from queue import Queue, Empty

from models.event import RawEvent

logger = logging.getLogger(__name__)

# ── 已知危险命令模式 ──────────────────────────────────────────────────────────
_DANGEROUS_PATTERNS = [
    re.compile(r'\bsudo\b'),
    re.compile(r'\brm\s+-rf\s+/'),
    re.compile(r'\bcurl\b.*\|\s*(ba)?sh'),
    re.compile(r'\bwget\b.*\|\s*(ba)?sh'),
    re.compile(r'/etc/(shadow|passwd|sudoers)'),
    re.compile(r'\bnc\s+(-[el]|--exec)'),
    re.compile(r'\bchmod\s+[47]'),
]


@dataclass
class BridgeConfig:
    """桥接配置"""
    agent_id: str = "deep-agent"
    agent_framework: str = "pydantic-deep"
    capture_pre_tool: bool = True       # 是否在工具执行前捕获
    capture_post_tool: bool = True      # 是否在工具执行后捕获
    base_timestamp_ns: int = 1718092800_000_000_000  # 基准时间戳
    pid_start: int = 60000              # 模拟 PID 起始值


class AgentBridge:
    """
    Pydantic-DeepAgents ↔ observer_core 桥接器。

    将 pydantic-deep 的 HookInput (工具调用) 转换为 RawEvent，
    通过线程安全队列传递给 DeepAgentCollector。

    用法:
        bridge = AgentBridge(config)

        # 方式 1: 作为 pydantic-deep Hook handler
        hooks = bridge.create_hooks()
        agent = create_deep_agent(hooks=hooks)

        # 方式 2: 手动推送事件 (测试/simulation)
        bridge.push_raw_event(raw_event)

        # 消费事件
        for event in bridge.events():
            process(event)
    """

    def __init__(self, config: Optional[BridgeConfig] = None):
        self._config = config or BridgeConfig()
        self._event_queue: Queue = Queue(maxsize=10000)
        self._seq = 0
        self._pid_counter = self._config.pid_start
        self._lock = threading.Lock()
        self._base_ts = self._config.base_timestamp_ns
        self._event_count = 0

        # 工具名 → 事件类型映射表
        self._tool_map: Dict[str, str] = {
            # Shell 执行
            "execute": "exec",
            "execute_command": "exec",
            "run_command": "exec",
            "shell": "exec",
            "bash": "exec",
            # 文件读取
            "read_file": "file_open",
            "read": "file_open",
            "cat": "file_open",
            "list_files": "file_open",
            "grep": "file_open",
            "glob": "file_open",
            # 文件写入
            "write_file": "file_open",
            "write": "file_open",
            "edit_file": "file_open",
            "edit": "file_open",
            "patch": "file_open",
            # 网络
            "web_fetch": "net_conn",
            "fetch": "net_conn",
            "web_search": "net_conn",
            "browse": "net_conn",
            "curl": "net_conn",
            "http_request": "net_conn",
        }

    # ── Hook 创建 ─────────────────────────────────────────────────────────────

    def create_hooks(self) -> list:
        """
        创建 pydantic-deep Hook 列表。

        返回的 Hook 可在 create_deep_agent(hooks=hooks) 中使用。
        Hook handler 是异步函数，将 HookInput 转换为 RawEvent 并推入队列。
        """
        try:
            from pydantic_deep import Hook, HookEvent
        except ImportError:
            logger.warning("pydantic-deep 未安装，无法创建 Hook")
            return []

        hooks = []

        if self._config.capture_pre_tool:
            hooks.append(Hook(
                event=HookEvent.PRE_TOOL_USE,
                handler=self._handle_pre_tool,
                timeout=5,
            ))

        if self._config.capture_post_tool:
            hooks.append(Hook(
                event=HookEvent.POST_TOOL_USE,
                handler=self._handle_post_tool,
                timeout=5,
            ))

        return hooks

    async def _handle_pre_tool(self, hook_input) -> Any:
        """处理 PRE_TOOL_USE 事件"""
        try:
            raw = self._hook_input_to_raw_event(hook_input, phase="pre")
            if raw:
                self.push_raw_event(raw)
        except Exception as e:
            logger.warning(f"pre_tool hook 处理失败: {e}")

        # 返回 None 表示不干预 (allow)
        return None

    async def _handle_post_tool(self, hook_input) -> Any:
        """处理 POST_TOOL_USE 事件"""
        try:
            raw = self._hook_input_to_raw_event(hook_input, phase="post")
            if raw:
                self.push_raw_event(raw)
        except Exception as e:
            logger.warning(f"post_tool hook 处理失败: {e}")
        return None

    # ── 事件转换 ──────────────────────────────────────────────────────────────

    def _hook_input_to_raw_event(self, hook_input, phase: str = "pre") -> Optional[RawEvent]:
        """
        将 pydantic-deep HookInput 转换为 RawEvent。

        参数:
            hook_input: pydantic_deep.HookInput 实例
            phase:      "pre" 或 "post"

        返回:
            RawEvent 或 None (如果无法映射)
        """
        tool_name = getattr(hook_input, 'tool_name', '') or ''
        tool_input = getattr(hook_input, 'tool_input', {}) or {}

        # 确定事件类型
        event_type = self._tool_map.get(tool_name.lower())
        if event_type is None:
            # 未知工具 → 默认 exec
            event_type = "exec"

        with self._lock:
            self._seq += 1
            seq = self._seq
            pid = self._pid_counter
            if event_type == "exec":
                self._pid_counter += 1

        ts = self._base_ts + seq * 100_000_000  # 100ms 递增

        # 根据事件类型构造字段
        executable = None
        arguments = None
        file_path = None
        file_op = None
        remote_addr = None
        remote_port = None
        protocol = None

        if event_type == "exec":
            cmd = tool_input.get("command", tool_input.get("cmd", tool_name))
            parts = cmd.split() if isinstance(cmd, str) else [str(cmd)]
            executable = parts[0] if parts else tool_name
            arguments = parts

        elif event_type == "file_open":
            file_path = (
                tool_input.get("path")
                or tool_input.get("file_path")
                or tool_input.get("file")
                or ""
            )
            # 读取类工具 → read，写入类工具 → write
            read_tools = {"read_file", "read", "cat", "list_files", "grep", "glob"}
            file_op = "read" if tool_name.lower() in read_tools else "write"

        elif event_type == "net_conn":
            url = (
                tool_input.get("url")
                or tool_input.get("query")
                or tool_input.get("address")
                or ""
            )
            remote_addr = _extract_host(url)
            remote_port = 443
            protocol = "TCP"

        return RawEvent(
            event_id=f"da_{phase}_{seq:06d}",
            timestamp_ns=ts,
            event_type=event_type,
            pid=pid,
            ppid=self._config.pid_start,
            agent_id=self._config.agent_id,
            agent_framework=self._config.agent_framework,
            executable=executable,
            arguments=arguments,
            file_path=file_path,
            file_op=file_op,
            remote_addr=remote_addr,
            remote_port=remote_port,
            protocol=protocol,
        )

    # ── 事件队列 ──────────────────────────────────────────────────────────────

    def push_raw_event(self, event: RawEvent):
        """推入一个 RawEvent 到队列（线程安全）"""
        try:
            self._event_queue.put_nowait(event)
            self._event_count += 1
        except Exception:
            logger.warning("事件队列已满，丢弃事件")

    def push_tool_call(self, tool_name: str, tool_input: dict, phase: str = "pre"):
        """手动推入一个工具调用事件（用于 simulation/测试）"""
        # 构造一个简易 HookInput-like 对象
        pseudo_input = _PseudoHookInput(
            event=f"{phase}_tool_use",
            tool_name=tool_name,
            tool_input=tool_input,
        )
        raw = self._hook_input_to_raw_event(pseudo_input, phase=phase)
        if raw:
            self.push_raw_event(raw)

    def events(self, timeout: float = 0):
        """
        生成器：从队列中消费事件。

        参数:
            timeout: 超时秒数 (0 = 非阻塞，耗尽即返回)
        """
        deadline = time.time() + timeout if timeout > 0 else 0

        while True:
            try:
                event = self._event_queue.get_nowait()
                yield event
            except Empty:
                if deadline > 0 and time.time() < deadline:
                    time.sleep(0.01)
                    continue
                return

    @property
    def event_count(self) -> int:
        """已推送的事件总数"""
        return self._event_count

    @property
    def pending_count(self) -> int:
        """队列中待消费的事件数"""
        return self._event_queue.qsize()


# ── 辅助函数 ──────────────────────────────────────────────────────────────────

@dataclass
class _PseudoHookInput:
    """伪 HookInput，用于 simulation 模式下模拟工具调用"""
    event: str
    tool_name: str
    tool_input: dict
    tool_result: str = ""
    tool_error: str = ""


def _extract_host(url: str) -> str:
    """从 URL 中提取主机地址"""
    if not url:
        return "unknown"
    # 去除协议前缀
    host = url
    for prefix in ("https://", "http://", "ftp://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
            break
    # 去除路径和端口
    host = host.split("/")[0]
    host = host.split("?")[0]
    host = host.split(":")[0]
    return host or "unknown"


def create_observer_hooks(bridge: AgentBridge) -> list:
    """
    便捷函数：创建观察者 Hook 列表。

    用法:
        bridge = AgentBridge()
        hooks = create_observer_hooks(bridge)
        agent = create_deep_agent(hooks=hooks)
    """
    return bridge.create_hooks()
