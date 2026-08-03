# ============================================================
# deep-agents-demo/Dockerfile
# Pydantic-DeepAgents Agent 运行环境
# ============================================================
#
# 构建:
#   docker build -t deep-agents-demo .
#
# 运行:
#   docker run --rm -v $(pwd)/workspace:/workspace \
#     --env-file .env \
#     deep-agents-demo python3 /app/run_agent.py
#
# 或使用任务指令文件:
#   docker run --rm deep-agents-demo \
#     --agent-cmd "$(cat task_instruction.txt)"

FROM python:3.10-slim

WORKDIR /app

# 安装 pydantic-deep 和数据分析依赖
RUN pip install --no-cache-dir \
    pydantic-deep \
    pandas \
    matplotlib \
    openpyxl \
    python-dotenv

# 复制 Agent 脚本和任务配置
COPY run_agent.py /app/run_agent.py
COPY task_instruction.txt /app/task_instruction.txt

# 创建工作目录挂载点
VOLUME ["/workspace"]

# 默认入口
ENTRYPOINT ["python3", "/app/run_agent.py"]
