"""
collector/deep_agent_collector.py — Pydantic-DeepAgents 采集器

实现 ICollector 接口，桥接 pydantic-deep Agent 工具调用与 observer_core 处理链路。

双模式运行:
  - live:       真实 pydantic-deep Agent 执行 (需 API Key)
                通过 Hook 回调实时捕获工具调用，转换为 RawEvent
  - simulation: 预定义 Agent 行为场景 (无需 API Key)
                从 YAML 场景文件加载模拟 Agent 工具调用序列

不修改 observer_core/ / models/ / scenarios/ / rules/ (零改动约束)。
"""

import os
import time
import logging
import threading
from typing import Iterator, Optional, List

import yaml

from collector.base_collector import ICollector, CollectorCapabilities
from models.event import RawEvent
from adapter.agent_bridge import AgentBridge, BridgeConfig

logger = logging.getLogger(__name__)

# observer_sim/ 目录
_OBSERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class DeepAgentCollector(ICollector):
    """
    Pydantic-DeepAgents 采集器 —— 桥接真实 AI Agent 行为与观察者系统。

    实现 ICollector 接口，observer_core/ 零改动。
    支持 live (真实 Agent) 和 simulation (预定义场景) 两种模式。
    """

    def __init__(self, config: dict):
        """
        初始化 DeepAgent 采集器。

        参数:
            config: 配置字典（从 config.yaml 加载）
        """
        self.config = config
        self.da_config = config.get("deep_agent", {})
        self.target_agent_id = self.da_config.get(
            "target_agent_id", "deep-agent")
        self.mode = self.da_config.get("mode", "simulation")
        self.scenarios_dir = self.da_config.get(
            "scenarios_dir", "scenarios/deep_agent/")

        # 内部状态
        self._attached = False
        self._running = False
        self._bridge: Optional[AgentBridge] = None
        self._scenario_data: Optional[dict] = None  # 完整 YAML 数据
        self._scenario: Optional[dict] = None       # scenario 元信息块
        self._agent_thread: Optional[threading.Thread] = None

    def capabilities(self) -> CollectorCapabilities:
        """返回 DeepAgent 采集器能力描述"""
        return CollectorCapabilities(
            name="DeepAgent",
            can_observe=True,
            can_block_tier2=self.mode == "live",  # live 模式可阻断
            can_block_tier3=False,
            is_transparent=True,
            performance_overhead="low",
            time_source="virtual",
        )

    def attach(self, target_pid: int = 0, agent_id: str = "") -> bool:
        """
        附着到目标 Agent。

        simulation 模式: 加载场景文件
        live 模式: 初始化 AgentBridge + 准备 Hook

        参数:
            target_pid: 忽略 (Agent 不是传统进程)
            agent_id:   Agent 标识
        """
        if agent_id:
            self.target_agent_id = agent_id

        # 创建桥接器
        bridge_config = BridgeConfig(
            agent_id=self.target_agent_id,
            agent_framework="pydantic-deep",
        )
        self._bridge = AgentBridge(bridge_config)

        if self.mode == "simulation":
            # Simulation 模式不需要真实 Agent
            self._attached = True
            logger.info(
                f"DeepAgentCollector attached (simulation, "
                f"agent_id={self.target_agent_id})")
            return True

        elif self.mode == "live":
            # Live 模式: 检查 pydantic-deep 可用性
            try:
                import pydantic_deep
                self._attached = True
                logger.info(
                    f"DeepAgentCollector attached (live, "
                    f"agent_id={self.target_agent_id})")
                return True
            except ImportError:
                logger.error(
                    "pydantic-deep 未安装，无法使用 live 模式。"
                    "请 pip install pydantic-deep 或使用 simulation 模式。")
                return False
        else:
            logger.error(f"未知模式: {self.mode}")
            return False

    def load_scenario(self, scenario_path: str):
        """
        加载 Agent 行为场景文件。

        参数:
            scenario_path: 场景 YAML 文件路径
        """
        if not os.path.isabs(scenario_path):
            scenario_path = os.path.join(_OBSERVER_DIR, scenario_path)

        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        self._scenario_data = data  # 完整 YAML 数据
        self._scenario = data.get("scenario", data)  # 元信息块
        logger.info(f"加载 Agent 场景: {self._scenario.get('id', '?')} "
                    f"({scenario_path})")

    def start(self) -> Iterator[RawEvent]:
        """
        开始采集，yield RawEvent。

        simulation 模式: 从场景生成模拟事件
        live 模式: 通过 Hook 实时捕获 Agent 工具调用
        """
        if not self._attached:
            logger.warning("DeepAgentCollector 未附着")
            return

        if self.mode == "simulation":
            yield from self._start_simulation()
        elif self.mode == "live":
            yield from self._start_live()

    def _start_simulation(self) -> Iterator[RawEvent]:
        """Simulation 模式: 从场景生成事件"""
        if not self._scenario_data:
            # 自动加载默认场景
            default_scenario = os.path.join(
                _OBSERVER_DIR, self.scenarios_dir,
                "da01_data_analysis.yaml")
            if os.path.isfile(default_scenario):
                self.load_scenario(default_scenario)
            else:
                logger.warning("无场景可加载，使用内置默认事件")
                yield from self._builtin_events()
                return

        # 从场景工具调用序列生成事件
        # tool_calls 在 YAML 根级别，scenario 元信息在 scenario 块内
        tool_calls = self._scenario_data.get("tool_calls", [])
        if not tool_calls:
            logger.warning("场景中没有 tool_calls 定义")
            return

        scenario_meta = self._scenario  # scenario: {} 块
        base_ts = scenario_meta.get(
            "base_timestamp_ns",
            self.config.get("virtual_clock", {}).get(
                "start_ns", 1718092800_000_000_000))
        agent_id = scenario_meta.get(
            "agent_id", self.target_agent_id)

        seq = 0
        pid_base = 60000
        for call in tool_calls:
            seq += 1
            tool_name = call.get("tool", "execute")
            tool_input = call.get("input", {})
            delay_ms = call.get("delay_ms", 100)

            # 转换为 RawEvent
            event_type = _map_tool_to_event_type(tool_name)
            ts = base_ts + seq * delay_ms * 1_000_000  # ms → ns

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
                executable = parts[0]
                arguments = parts

            elif event_type == "file_open":
                file_path = (
                    tool_input.get("path")
                    or tool_input.get("file_path")
                    or tool_input.get("file")
                    or ""
                )
                read_tools = {"read_file", "read", "cat", "list_files",
                              "grep", "glob"}
                file_op = "read" if tool_name in read_tools else "write"

            elif event_type == "net_conn":
                url = (
                    tool_input.get("url")
                    or tool_input.get("query")
                    or ""
                )
                remote_addr = _extract_host_from_url(url)
                remote_port = 443
                protocol = "TCP"

            yield RawEvent(
                event_id=f"da_sim_{seq:06d}",
                timestamp_ns=ts,
                event_type=event_type,
                pid=pid_base + seq,
                ppid=pid_base,
                agent_id=agent_id,
                agent_framework="pydantic-deep-sim",
                executable=executable,
                arguments=arguments,
                file_path=file_path,
                file_op=file_op,
                remote_addr=remote_addr,
                remote_port=remote_port,
                protocol=protocol,
            )

    def _builtin_events(self) -> Iterator[RawEvent]:
        """内置默认事件 (无场景文件时使用)"""
        base_ts = self.config.get("virtual_clock", {}).get(
            "start_ns", 1718092800_000_000_000)
        agent_id = self.target_agent_id
        pid_base = 60000

        events = [
            # Agent 读取数据文件
            RawEvent(
                event_id="da_builtin_001", timestamp_ns=base_ts,
                event_type="file_open", pid=pid_base + 1, ppid=pid_base,
                agent_id=agent_id, agent_framework="pydantic-deep-sim",
                file_path="/workspace/data/sales.csv", file_op="read"),
            # Agent 执行 Python 分析脚本
            RawEvent(
                event_id="da_builtin_002", timestamp_ns=base_ts + 100_000_000,
                event_type="exec", pid=pid_base + 2, ppid=pid_base,
                agent_id=agent_id, agent_framework="pydantic-deep-sim",
                executable="/usr/bin/python3",
                arguments=["python3", "-c",
                           "import pandas; df=pandas.read_csv('data/sales.csv')"]),
            # Agent 写入分析报告
            RawEvent(
                event_id="da_builtin_003", timestamp_ns=base_ts + 200_000_000,
                event_type="file_open", pid=pid_base + 3, ppid=pid_base,
                agent_id=agent_id, agent_framework="pydantic-deep-sim",
                file_path="/workspace/data/report.md", file_op="write"),
            # Agent 访问外部 API
            RawEvent(
                event_id="da_builtin_004", timestamp_ns=base_ts + 300_000_000,
                event_type="net_conn", pid=pid_base + 4, ppid=pid_base,
                agent_id=agent_id, agent_framework="pydantic-deep-sim",
                remote_addr="api.example.com", remote_port=443,
                protocol="TCP"),
            # Agent 安装额外依赖
            RawEvent(
                event_id="da_builtin_005", timestamp_ns=base_ts + 400_000_000,
                event_type="exec", pid=pid_base + 5, ppid=pid_base,
                agent_id=agent_id, agent_framework="pydantic-deep-sim",
                executable="/usr/bin/pip",
                arguments=["pip", "install", "matplotlib"]),
        ]

        for evt in events:
            yield evt

    def _start_live(self) -> Iterator[RawEvent]:
        """
        Live 模式: 启动真实 pydantic-deep Agent + Hook 捕获。

        需要:
          - pydantic-deep 已安装
          - OPENAI_API_KEY 环境变量（配置在 .env 文件中）
        """
        import asyncio

        # 获取 Agent 指令
        task = self.da_config.get("task", "列出当前目录文件")
        duration_s = self.da_config.get("duration_s", 60)

        logger.info(f"启动 pydantic-deep Agent (task: {task[:50]}...)")

        # 在后台线程运行 Agent
        self._running = True

        def _run_agent():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._async_run_agent(task))
            except Exception as e:
                logger.error(f"Agent 执行失败: {e}")
            finally:
                self._running = False

        self._agent_thread = threading.Thread(
            target=_run_agent, daemon=True, name="deep-agent")
        self._agent_thread.start()

        # 从桥接器队列消费事件
        deadline = time.time() + duration_s
        while self._running or self._bridge.pending_count > 0:
            for event in self._bridge.events(timeout=1.0):
                yield event
            if time.time() >= deadline:
                break

    async def _async_run_agent(self, task: str):
        """异步运行 pydantic-deep Agent"""
        try:
            from pydantic_deep import create_deep_agent
        except ImportError:
            logger.error("pydantic-deep 未安装")
            return

        # 从环境变量读取 LLM 配置
        from env_config import require_api_key, get_llm_config
        try:
            api_key = require_api_key()
        except EnvironmentError as e:
            logger.error(str(e))
            return

        llm_cfg = get_llm_config()
        hooks = self._bridge.create_hooks()

        # 构建 Agent 参数（从 .env 读取 model 和 base_url）
        agent_kwargs = {
            "instructions": "你是一个数据分析助手。",
            "hooks": hooks,
            "model": llm_cfg["model"],
        }
        if llm_cfg["base_url"]:
            agent_kwargs["base_url"] = llm_cfg["base_url"]

        try:
            agent = create_deep_agent(**agent_kwargs)
            # 运行 Agent
            result = await agent.run(task)
            logger.info(f"Agent 完成: {len(str(result))} chars")
        except Exception as e:
            logger.error(f"Agent 运行异常: {e}")

    def send_command(self, cmd) -> bool:
        """
        发送阻断指令。

        simulation 模式: 不支持
        live 模式: 通过 Hook 的 pre_tool 干预 (第二版实现)
        """
        if self.mode == "live":
            logger.info(f"DeepAgent live 阻断 (第二版): {cmd}")
            # TODO: 通过 BridgeConfig 的阻断回调实现
            return False
        else:
            logger.warning(
                "simulation 模式不支持阻断。"
                "使用 SimulationCollector 进行阻断测试。")
            return False

    def detach(self) -> None:
        """断开采集，清理资源"""
        self._running = False
        self._attached = False
        self._bridge = None
        logger.info("DeepAgentCollector 已断开")

    def get_process_tree(self) -> dict:
        """Agent 不维护传统进程树"""
        return {}

    @property
    def bridge(self) -> Optional[AgentBridge]:
        """获取桥接器实例 (用于高级用法)"""
        return self._bridge


# ── 辅助函数 ──────────────────────────────────────────────────────────────────

def _map_tool_to_event_type(tool_name: str) -> str:
    """将 pydantic-deep 工具名映射到 RawEvent 事件类型"""
    tool = tool_name.lower()

    exec_tools = {
        "execute", "execute_command", "run_command", "shell", "bash",
        "terminal", "command",
    }
    read_tools = {
        "read_file", "read", "cat", "list_files", "grep", "glob",
        "ls", "find", "head", "tail",
    }
    write_tools = {
        "write_file", "write", "edit_file", "edit", "patch",
        "append", "create_file",
    }
    net_tools = {
        "web_fetch", "fetch", "web_search", "browse", "curl",
        "http_request", "download",
    }

    if tool in exec_tools:
        return "exec"
    elif tool in read_tools:
        return "file_open"
    elif tool in write_tools:
        return "file_open"
    elif tool in net_tools:
        return "net_conn"
    else:
        return "exec"


def _extract_host_from_url(url: str) -> str:
    """从 URL 提取主机"""
    if not url:
        return "unknown"
    host = url
    for prefix in ("https://", "http://", "ftp://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
            break
    host = host.split("/")[0].split("?")[0].split(":")[0]
    return host or "unknown"
