#!/usr/bin/env python3
"""
run_agent.py — 独立 Agent 执行脚本

在 Docker 容器或宿主机中运行 pydantic-deep Agent，
执行 Q3 市场分析任务。产生的工具调用通过 Hook 机制被监控系统捕获。

用法:
    # Docker 容器内
    python3 /app/run_agent.py

    # 宿主机（降级模式）
    cd deep-agents-demo
    python3 run_agent.py --task-file task_instruction.txt
"""

import os
import sys
import argparse
import asyncio
import time as _time
import logging
from dataclasses import dataclass, field
from typing import Optional

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("run_agent")


# ── 进度追踪器 ───────────────────────────────────────────────────────────────
@dataclass
class ProgressTracker:
    """追踪 Agent 执行进度，支持流式输出"""
    tool_calls_total: int = 0
    tool_calls_completed: int = 0
    current_operation: str = "初始化..."
    start_time: float = field(default_factory=_time.time)

    def format_progress(self) -> str:
        """格式化进度行: [HH:MM:SS] 已完成 N/M 个操作 | 当前: tool_name(args)"""
        elapsed = max(_time.time() - self.start_time, 0)
        h = int(elapsed // 3600)
        m = int((elapsed % 3600) // 60)
        s = int(elapsed % 60)
        elapsed_str = f"{h:02d}:{m:02d}:{s:02d}"

        if self.tool_calls_total > 0:
            return (f"[{elapsed_str}] 已完成 {self.tool_calls_completed}/"
                    f"{self.tool_calls_total} 个操作 | 当前: {self.current_operation}")
        else:
            return f"[{elapsed_str}] 执行中 | {self.current_operation}"

    def create_hooks(self) -> list:
        """创建用于进度追踪的 Hook 列表"""
        try:
            from pydantic_deep import Hook, HookEvent
            from pydantic_deep.features.hooks.capability import HookResult
        except ImportError:
            return []

        hooks = []
        tracker = self

        async def _on_pre_tool(hook_input):
            """PRE_TOOL_USE: 记录当前操作"""
            try:
                tracker.tool_calls_total += 1
                tool_name = getattr(hook_input, 'tool_name', None) or "tool"
                # 尝试提取参数摘要
                tool_args = getattr(hook_input, 'tool_args', None) or {}
                args_str = ""
                if isinstance(tool_args, dict):
                    # 取第一个有意义的参数值
                    for k, v in tool_args.items():
                        if v:
                            v_str = str(v)[:40]
                            args_str = f"{k}={v_str}"
                            break
                if args_str:
                    tracker.current_operation = f"{tool_name}({args_str})"
                else:
                    tracker.current_operation = f"{tool_name}(...)"
            except Exception:
                pass
            # 返回 HookResult(allow=True) — pydantic_deep 需要对象而非 None
            return HookResult(allow=True)

        async def _on_post_tool(hook_input):
            """POST_TOOL_USE: 计数完成"""
            tracker.tool_calls_completed += 1
            return HookResult(allow=True)

        hooks.append(Hook(
            event=HookEvent.PRE_TOOL_USE,
            handler=_on_pre_tool,
            timeout=3,
        ))
        hooks.append(Hook(
            event=HookEvent.POST_TOOL_USE,
            handler=_on_post_tool,
            timeout=3,
        ))

        return hooks


def main():
    parser = argparse.ArgumentParser(description="DeepAgents Agent Runner")
    parser.add_argument("--task-file", type=str, default="task_instruction.txt",
                        help="任务指令文件路径")
    parser.add_argument("--task", type=str, default="",
                        help="直接传入任务文本（覆盖 --task-file）")
    parser.add_argument("--workspace", type=str, default="workspace",
                        help="Agent 工作目录")
    parser.add_argument("--fifo", type=str, default="",
                        help="FIFO 管道路径（启用 Monitor 实时监测）")
    args = parser.parse_args()

    # 加载 .env（如果有）
    try:
        from dotenv import load_dotenv
        # 尝试项目根目录的 .env
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env_path = os.path.join(project_root, ".env")
        if os.path.isfile(env_path):
            load_dotenv(env_path, override=False)
            logger.info(f"Loaded .env from {env_path}")
        # 也尝试当前目录
        if os.path.isfile(".env"):
            load_dotenv(".env", override=False)
    except ImportError:
        pass

    # 检查 API Key
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        logger.error(
            "未配置 OPENAI_API_KEY。\n"
            "请在 .env 文件中设置或 export OPENAI_API_KEY=your-key")
        return 1

    # 读取任务
    if args.task:
        task_text = args.task
    else:
        task_path = args.task_file
        if not os.path.isabs(task_path):
            task_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     task_path)
        if not os.path.isfile(task_path):
            logger.error(f"任务文件不存在: {task_path}")
            return 1
        with open(task_path, "r", encoding="utf-8") as f:
            task_text = f.read()

    logger.info(f"Task: {task_text[:100]}...")

    # 将相对 FIFO 路径解析为绝对路径（必须在 os.chdir(workspace) 之前）
    if args.fifo:
        args.fifo = os.path.abspath(args.fifo)

    # 切换工作目录
    workspace = args.workspace
    if not os.path.isabs(workspace):
        workspace = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 workspace)
    if os.path.isdir(workspace):
        os.chdir(workspace)
        logger.info(f"Workspace: {workspace}")

    # 运行 Agent
    model = os.environ.get("OPENAI_MODEL", "deepseek-chat")
    base_url = os.environ.get("OPENAI_BASE_URL", "")
    logger.info(f"Model: {model}, Base URL: {base_url or '(default)'}")

    try:
        from pydantic_deep import create_deep_agent, DeepAgentDeps, StateBackend
    except ImportError:
        logger.error("pydantic-deep 未安装: pip install pydantic-deep")
        return 1

    agent_kwargs = {
        "instructions": "你是一位资深市场分析师，擅长数据分析和商业报告撰写。",
        "model": model,
    }
    # 注意：base_url 通过 OPENAI_BASE_URL 环境变量传递（load_dotenv 已加载），
    # 不要直接传给 create_deep_agent，因为底层 Agent.__init__() 不接收此参数

    async def run():
        # ── 进度追踪 ──
        tracker = ProgressTracker()
        progress_hooks = tracker.create_hooks()

        # ── FIFO 监测集成 ──
        hooks = list(progress_hooks)  # 始终启用进度追踪
        bridge = None
        if args.fifo:
            # 将 observer_sim 目录加入 Python 路径
            observer_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "observer_sim")
            if observer_dir not in sys.path:
                sys.path.insert(0, observer_dir)
            try:
                from adapter.agent_bridge import AgentBridge, BridgeConfig
                config = BridgeConfig(
                    agent_id="deep-agent-runner",
                    agent_framework="pydantic-deep",
                )
                bridge = AgentBridge(config=config, output_mode="fifo",
                                     fifo_path=args.fifo)
                hooks.extend(bridge.create_hooks())
                logger.info(f"FIFO 监测已启用: {args.fifo}")
            except ImportError as e:
                logger.warning(f"无法加载 AgentBridge: {e}，FIFO 监测未启用")

        agent_kwargs["hooks"] = hooks
        agent = create_deep_agent(**agent_kwargs)
        deps = DeepAgentDeps(backend=StateBackend())

        # ── 流式进度输出 ──
        progress_stopped = False

        async def _progress_loop():
            """后台任务：每 2 秒打印一行进度"""
            while True:
                await asyncio.sleep(2)
                if progress_stopped:
                    break
                # 使用 \r 覆盖当前行（终端友好）
                print(f"\r{tracker.format_progress()}", end="", flush=True)

        progress_task = asyncio.create_task(_progress_loop())

        try:
            result = await agent.run(task_text, deps=deps)
        finally:
            progress_stopped = True
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass
            # 输出最终进度行并换行
            print(f"\r{tracker.format_progress()}")

        logger.info(f"Agent 完成，输出长度: {len(str(result))} chars")

        if bridge:
            bridge.close()

        # 保存结果
        output_file = os.path.join(workspace, "data", "agent_output.txt")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(str(result))
        logger.info(f"结果已保存到: {output_file}")

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
