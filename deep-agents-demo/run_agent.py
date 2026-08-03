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
import logging

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("run_agent")


def main():
    parser = argparse.ArgumentParser(description="DeepAgents Agent Runner")
    parser.add_argument("--task-file", type=str, default="task_instruction.txt",
                        help="任务指令文件路径")
    parser.add_argument("--task", type=str, default="",
                        help="直接传入任务文本（覆盖 --task-file）")
    parser.add_argument("--workspace", type=str, default="workspace",
                        help="Agent 工作目录")
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
        from pydantic_deep import create_deep_agent
    except ImportError:
        logger.error("pydantic-deep 未安装: pip install pydantic-deep")
        return 1

    agent_kwargs = {
        "instructions": "你是一位资深市场分析师，擅长数据分析和商业报告撰写。",
        "model": model,
    }
    if base_url:
        agent_kwargs["base_url"] = base_url

    async def run():
        agent = create_deep_agent(**agent_kwargs)
        result = await agent.run(task_text)
        logger.info(f"Agent 完成，输出长度: {len(str(result))} chars")
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
