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
import os
import json
import time
import logging
import threading
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from queue import Queue, Empty

from models.event import RawEvent

# HookRegistry 导入（工具映射单一事实来源；兼容 adapter 包内/顶层 sys.path 两种布局）
try:
    from adapter.hook_registry import get_registry
except ImportError:  # adapter 目录本身位于 sys.path 时
    from hook_registry import get_registry

logger = logging.getLogger(__name__)

# ── HookResult 兼容导入（pydantic_deep 可能未安装）────────────────────
_HOOK_RESULT_AVAILABLE = False
_HookResultClass: Any = None
try:
    from pydantic_deep.features.hooks.capability import HookResult as _HookResultClass
    _HOOK_RESULT_AVAILABLE = True
except ImportError:
    # 定义一个兼容的 fallback HookResult
    @dataclass
    class _FallbackHookResult:
        allow: bool = True
        reason: Optional[str] = None
        modified_args: Optional[Dict[str, Any]] = None
        modified_result: Optional[str] = None

    _HookResultClass = _FallbackHookResult


def _make_hook_result(allow: bool = True, reason: str = "") -> Any:
    """创建一个 HookResult（兼容 pydantic_deep 或 fallback）"""
    return _HookResultClass(allow=allow, reason=reason or None)

# ── FIFO Writer (zero-cost when not in FIFO mode) ───────────────────────────
_FIFO_WRITER_AVAILABLE = False
try:
    from agent_fifo_writer import FifoWriter
    _FIFO_WRITER_AVAILABLE = True
except ImportError:
    pass

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

    支持两种输出模式:
    - queue (默认): 事件推入内部队列，由 DeepAgentCollector 消费
    - fifo:        事件转为 JSON 行写入 FIFO 管道，供 Monitor Daemon 实时消费

    用法:
        bridge = AgentBridge(config)

        # 方式 1: 作为 pydantic-deep Hook handler
        hooks = bridge.create_hooks()
        agent = create_deep_agent(hooks=hooks)

        # 方式 2: 手动推送事件 (测试/simulation)
        bridge.push_raw_event(raw_event)

        # 消费事件 (queue 模式)
        for event in bridge.events():
            process(event)

        # FIFO 模式
        bridge.set_output_mode("fifo", "/tmp/observer_monitoring_pipe")
    """

    def __init__(self, config: Optional[BridgeConfig] = None,
                 output_mode: str = "queue", fifo_path: str = ""):
        self._config = config or BridgeConfig()
        self._event_queue: Queue = Queue(maxsize=10000)
        self._seq = 0
        self._pid_counter = self._config.pid_start
        self._lock = threading.Lock()
        self._base_ts = self._config.base_timestamp_ns
        self._event_count = 0

        # ── 输出模式 ──
        self._output_mode: str = "queue"  # "queue" | "fifo" | "both"
        self._fifo_writer: Optional[Any] = None
        self._fifo_opened: bool = False
        if output_mode in ("fifo", "both") and fifo_path:
            self.set_output_mode(output_mode, fifo_path)

        # 工具映射单一事实来源: HookRegistry(YAML) 优先加载，内置表兜底
        # (YAML 未覆盖的工具保留内置分类，子串 fallback 规则不变)
        registry_config = self._load_registry_config()
        self._tool_map: Dict[str, str] = self._build_tool_map(registry_config)
        self._read_tools: set = self._build_read_tools(registry_config)

        # 工具名子串 → 事件类型的 fallback 规则（按优先级）
        self._tool_pattern_fallbacks: List[tuple] = [
            ("search", "net_conn"),      # web_search, duckduckgo_search
            ("fetch", "net_conn"),        # web_fetch
            ("browse", "net_conn"),       # browser
            ("read", "file_open"),        # read_file, read_memory, read_todos
            ("write", "file_open"),       # write_file, write_todos, write_memory
            ("edit", "file_open"),        # edit_file
            ("file", "file_open"),        # list_files, glob
            ("list", "file_open"),        # list_files, list_skills
            ("grep", "file_open"),
            ("glob", "file_open"),
            ("curl", "net_conn"),
            ("wget", "net_conn"),
            ("request", "net_conn"),
        ]

        # DEBUG 级日志：记录未能识别的工具名（避免重复）
        self._unknown_tools_logged: set = set()

    # ── 工具映射构建（HookRegistry 接线）──────────────────────────────────────

    @staticmethod
    def _builtin_tool_map() -> Dict[str, str]:
        """内置工具映射兜底表（HookRegistry YAML 未覆盖的工具）。"""
        return {
            # Shell 执行
            "execute": "exec",
            "execute_command": "exec",
            "run_command": "exec",
            "shell": "exec",
            "bash": "exec",
            "python3": "exec",
            "python": "exec",
            # 文件读取
            "read_file": "file_open",
            "read": "file_open",
            "cat": "file_open",
            "list_files": "file_open",
            "grep": "file_open",
            "glob": "file_open",
            "read_memory": "file_open",
            "read_todos": "file_open",
            # 文件写入
            "write_file": "file_open",
            "write": "file_open",
            "edit_file": "file_open",
            "edit": "file_open",
            "patch": "file_open",
            "write_todos": "file_open",
            "write_memory": "file_open",
            # 网络
            "web_fetch": "net_conn",
            "fetch": "net_conn",
            "web_search": "net_conn",
            "browse": "net_conn",
            "curl": "net_conn",
            "http_request": "net_conn",
            # pydantic-deep 任务/状态管理 → exec（内部管理操作，非文件/网络）
            "task": "exec",
            "check_task": "exec",
            "wait_tasks": "exec",
            "update_todo_statuses": "exec",
            "list_skills": "exec",
            "ask_user": "exec",
            "search_conversation_history": "exec",
            "read_rules": "exec",
            "create_rule": "exec",
            # 文件/目录列表
            "ls": "file_open",
            "list_files": "file_open",
            "list_directory": "file_open",
        }

    @staticmethod
    def _builtin_read_tools() -> set:
        """内置 file_open 只读工具兜底集合（与历史行为保持一致）。"""
        return {
            "read_file", "read", "cat", "list_files", "grep", "glob",
            "read_memory", "read_todos",
        }

    def _load_registry_config(self):
        """从 HookRegistry 加载当前框架的工具映射配置（失败时返回 None）。"""
        try:
            registry = get_registry()
            config = registry.get_config(self._config.agent_framework)
            if config is not None:
                logger.debug(
                    f"AgentBridge 已从 HookRegistry 加载工具映射: "
                    f"{self._config.agent_framework} "
                    f"({len(config.tool_mappings)} 个工具)")
            else:
                logger.warning(
                    f"HookRegistry 未注册框架 '{self._config.agent_framework}'，"
                    f"使用内置工具映射表")
            return config
        except Exception as e:
            logger.warning(f"HookRegistry 加载失败，使用内置工具映射表: {e}")
            return None

    def _build_tool_map(self, registry_config=None) -> Dict[str, str]:
        """构建工具名→事件类型映射: HookRegistry(YAML) 优先，内置表兜底。"""
        tool_map: Dict[str, str] = dict(self._builtin_tool_map())
        if registry_config is not None:
            for tool_name in registry_config.list_tools():
                tool_map[tool_name.lower()] = \
                    registry_config.get_event_type(tool_name)
        return tool_map

    def _build_read_tools(self, registry_config=None) -> set:
        """构建 file_open 只读工具集合: HookRegistry(YAML) 优先，内置表兜底。"""
        read_tools: set = set(self._builtin_read_tools())
        if registry_config is not None:
            for tool_name in registry_config.list_tools():
                mapping = registry_config.map_tool_to_event(tool_name)
                if mapping is None or mapping.event_type != "file_open":
                    continue
                if '"read"' in mapping.param_rules.get("file_op", ""):
                    read_tools.add(tool_name.lower())
        return read_tools

    # ── 输出模式切换 ──────────────────────────────────────────────────────────

    def set_output_mode(self, mode: str, fifo_path: str = "") -> bool:
        """
        切换输出模式。

        Args:
            mode:      "queue" (仅队列) | "fifo" (仅FIFO) | "both" (双写)
            fifo_path: FIFO 管道路径（fifo/both 模式必需）

        Returns:
            True: 切换成功
            False: 参数无效或 FIFO 不可用
        """
        if mode not in ("queue", "fifo", "both"):
            logger.warning(f"未知输出模式: {mode}")
            return False

        # 关闭旧 FIFO
        if self._fifo_writer is not None:
            self._fifo_writer.close()
            self._fifo_writer = None
            self._fifo_opened = False

        if mode in ("fifo", "both"):
            if not _FIFO_WRITER_AVAILABLE:
                logger.error("FIFO 模式需要 agent_fifo_writer 模块")
                return False
            if not fifo_path:
                logger.error("FIFO 模式需要指定 fifo_path")
                return False

            # 确保 FIFO 存在
            if not os.path.exists(fifo_path):
                logger.warning(f"FIFO 不存在: {fifo_path}，将在首次写入时创建")

            self._fifo_writer = FifoWriter(fifo_path, auto_flush=True)
            # 不立即 open()，由首次事件触发时自动打开

        self._output_mode = mode
        logger.info(f"AgentBridge 输出模式切换: {mode}")
        return True

    @property
    def output_mode(self) -> str:
        """当前输出模式"""
        return self._output_mode

    def _ensure_fifo_open(self) -> bool:
        """确保 FIFO 已打开（懒打开，带重试）。

        Monitor 守护进程启动（创建 FIFO → 打开读端）与 Agent 写端打开之间存在
        时序竞争：os.mkfifo() 返回后，Monitor 需要短暂时间到达 open(fifo, 'r')。
        因此采用渐进式重试策略：首次快速尝试 1s，失败后以 5s/10s 递增重试。
        """
        if self._fifo_opened:
            return True
        if self._fifo_writer is None:
            return False

        # 渐进式超时：首次 1s，后续 5s/10s
        timeouts = [1.0, 5.0, 10.0]
        for attempt, timeout in enumerate(timeouts, 1):
            logger.info(f"[FIFO] 尝试打开 FIFO (第{attempt}次, timeout={timeout}s): "
                        f"{self._fifo_writer._fifo_path}")
            if self._fifo_writer.open(timeout=timeout):
                self._fifo_opened = True
                logger.info(f"[FIFO] FIFO 已连接 (第{attempt}次尝试成功)")
                return True
            logger.warning(f"[FIFO] 第{attempt}次打开 FIFO 失败")

        logger.error(f"[FIFO] 打开 FIFO 最终失败（已重试 {len(timeouts)} 次）")
        return False

    def _write_to_fifo(self, raw: RawEvent):
        """将 RawEvent 以 dict 形式写入 FIFO（非阻塞，失败静默）"""
        if self._output_mode not in ("fifo", "both"):
            return
        if not self._ensure_fifo_open():
            return
        event_dict = {
            "event_id": raw.event_id,
            "timestamp_ns": raw.timestamp_ns,
            "event_type": raw.event_type,
            "pid": raw.pid,
            "ppid": raw.ppid,
            "agent_id": raw.agent_id,
            "agent_framework": raw.agent_framework,
            "executable": raw.executable,
            "arguments": raw.arguments,
            "file_path": raw.file_path,
            "file_op": raw.file_op,
            "remote_addr": raw.remote_addr,
            "remote_port": raw.remote_port,
            "protocol": raw.protocol,
        }
        self._fifo_writer.write_event(event_dict)

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
        except BaseException as e:
            logger.warning(f"pre_tool hook 处理失败 ({type(e).__name__}): {e}")

        # 返回 HookResult(allow=True) 表示不干预
        return _make_hook_result(allow=True)

    async def _handle_post_tool(self, hook_input) -> Any:
        """处理 POST_TOOL_USE 事件"""
        try:
            raw = self._hook_input_to_raw_event(hook_input, phase="post")
            if raw:
                self.push_raw_event(raw)
        except BaseException as e:
            logger.warning(f"post_tool hook 处理失败 ({type(e).__name__}): {e}")
        return _make_hook_result(allow=True)

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

        # 确定事件类型（大小写不敏感）
        tool_lower = tool_name.lower()
        event_type = self._tool_map.get(tool_lower)
        if event_type is None:
            # 子串 fallback 匹配
            for pattern, fallback_type in self._tool_pattern_fallbacks:
                if pattern in tool_lower:
                    event_type = fallback_type
                    break
        if event_type is None:
            # 仍未匹配 → 默认 exec，记录未知工具名
            if tool_lower and tool_lower not in self._unknown_tools_logged:
                self._unknown_tools_logged.add(tool_lower)
                logger.debug(f"未知工具名映射: '{tool_name}' → 默认 exec")
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
            # 根据工具名判定读/写操作（_read_tools 由 HookRegistry + 内置表构建）
            file_op = "read" if tool_lower in self._read_tools else "write"

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
        """推入一个 RawEvent 到队列（线程安全），同时可选写入 FIFO"""
        # ── 写入 FIFO（如果已配置）──
        self._write_to_fifo(event)

        # ── 推入内部队列 ──
        if self._output_mode in ("queue", "both"):
            try:
                self._event_queue.put_nowait(event)
                self._event_count += 1
            except Exception:
                logger.warning("事件队列已满，丢弃事件")
        elif self._output_mode == "fifo":
            # FIFO-only 模式：也记录计数
            self._event_count += 1

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

    def close(self):
        """关闭桥接器，清理 FIFO 资源"""
        if self._fifo_writer is not None:
            self._fifo_writer.close()
            self._fifo_writer = None
            self._fifo_opened = False


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
