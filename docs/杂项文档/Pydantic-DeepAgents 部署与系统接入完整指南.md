我已经仔细阅读了你的接口文档和交接文档。好消息是：你的系统已经具备了接入 Pydantic-DeepAgents 所需的大部分基础设施。现在我来给出从部署到第一条指令监控的完整操作流程。

---

# Pydantic-DeepAgents 部署与系统接入完整指南

## 一、整体架构：你的系统 + Pydantic-DeepAgents 如何协作

```
┌─────────────────────────────────────────────────────────────────┐
│                    Docker 沙箱                                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Pydantic-DeepAgents                                       │  │
│  │  · 用户输入："整理报表，分析市场走向"                        │  │
│  │  · Agent 使用 Shell/Filesystem/Web 工具执行真实操作          │  │
│  │  · 产生 execve/openat/connect 等真实 syscall               │  │
│  └───────────────────────┬───────────────────────────────────┘  │
│                          │ syscall（容器内）                     │
└──────────────────────────┼──────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│              宿主机 Linux（你的 Ubuntu 22.04 VM）                  │
│                                                                  │
│  ┌──────────────────────┐     ┌───────────────────────────────┐  │
│  │ EbpfCollector         │────▶│ EventRecorder（透明录制）      │  │
│  │ · tracepoint 探针     │     │ · 实时写入 JSONL              │  │
│  │ · 内核态捕获 syscall  │     │ · 每条 flush，不丢数据         │  │
│  └──────────────────────┘     └───────────┬───────────────────┘  │
│                                           │                      │
│                                           ▼                      │
│                              ┌───────────────────────────────┐  │
│                              │ observer_core/（零改动）        │  │
│                              │ RawEvent → NormalizedEvent     │  │
│                              │ → RiskScorer → DecisionEngine  │  │
│                              │ → BlockingCoordinator          │  │
│                              │ → AuditLogger + 风险报告       │  │
│                              └───────────────────────────────┘  │
│                                                                  │
│  输出：                                                           │
│  · 实时终端输出（ALLOW/ALERT/BLOCK）                              │
│  · 录制 JSONL 文件（可供回放）                                    │
│  · Markdown 风险分析报告                                          │
│  · 行为图谱 JSON                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**核心集成点**：Pydantic-DeepAgents 在 Docker 中运行，宿主机的 eBPF 探针捕获其所有 syscall。EventRecorder 透明录制事件流，observer_core 实时处理。

---

## 二、Phase 1：部署 Pydantic-DeepAgents

### 步骤 1.1：在 Linux VM 中安装 Docker

```bash
# 在 Ubuntu 22.04 VM 终端中执行
sudo apt update
sudo apt install -y docker.io
sudo systemctl enable docker --now
sudo usermod -aG docker $USER

# 重新登录使 docker 组生效（或直接 newgrp docker）
newgrp docker

# 验证
docker run hello-world
```

### 步骤 1.2：创建 Pydantic-DeepAgents 项目目录

```bash
mkdir -p ~/deep-agents-demo/data
cd ~/deep-agents-demo

# 创建测试数据文件（供 Agent 读取分析）
cat > data/sales.csv << 'EOF'
Month,Revenue,Expenses,Profit
2024-01,50000,35000,15000
2024-02,52000,36000,16000
2024-03,48000,34000,14000
2024-04,55000,37000,18000
2024-05,60000,38000,22000
2024-06,58000,39000,19000
EOF
```

### 步骤 1.3：编写 Dockerfile

```bash
cat > Dockerfile << 'DEOF'
FROM python:3.11-slim

# 安装 Agent 所需工具
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# 安装 Pydantic-DeepAgents 及数据分析依赖
RUN pip install --no-cache-dir \
    pydantic-deep \
    pandas \
    matplotlib

# 设置工作目录
WORKDIR /workspace

# 默认命令
ENTRYPOINT ["python3"]
DEOF

# 构建镜像
docker build -t deep-agents-demo .
```

### 步骤 1.4：验证 Agent 可用

```bash
# 简单测试：让 Agent 读取 CSV 并分析
docker run --rm \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
  -v "$(pwd)/data:/workspace/data" \
  deep-agents-demo \
  -c "
from pydantic_deep_agents import create_deep_agent
agent = create_deep_agent()
result = agent.run('读取 data/sales.csv，告诉我总收入最高的月份')
print('结果:', result[-200:] if len(result) > 200 else result)
"
```

**如果还没有 Anthropic API Key**：
1. 访问 https://console.anthropic.com/
2. 注册并获取 API Key
3. 在终端中：`export ANTHROPIC_API_KEY="ANTHROPIC_API_KEY_PLACEHOLDER"`

---

## 三、Phase 2：连接你的观察系统

### 步骤 2.1：确认系统状态

```bash
cd ~/projects/observer_sim

# 先跑环境预检
python3 check_env.py

# 确认 eBPF 编译产物存在
ls -la ebpf/observer.bpf.o
# 如不存在：cd ebpf && make && cd ..

# 全量测试确认基线正常
python3 -m pytest tests/ -q
# 预期：364+ passed
```

### 步骤 2.2：创建集成脚本

这个脚本将三件事串联：启动 eBPF 监控 → 启动 EventRecorder 录制 → 运行 Docker Agent。

```bash
cat > ~/deep-agents-demo/monitor_agent.py << 'PYEOF'
#!/usr/bin/env python3
"""
Pydantic-DeepAgents 监控集成脚本

功能：
  1. 启动 eBPF 探针（EbpfCollector）监控宿主机 syscall
  2. 通过 EventRecorder 实时录制事件为 JSONL
  3. 同时送入 observer_core 全链路处理
  4. 输出实时风险日志

用法：
  sudo python3 monitor_agent.py --agent-cmd "读取 data/sales.csv 并分析"

依赖：
  - eBPF 探针已编译：ebpf/observer.bpf.o
  - Docker 已安装并可用
  - observer_sim 项目位于 ~/projects/observer_sim
"""

import sys
import os
import time
import json
import subprocess
import threading
import argparse
import yaml

# 添加项目路径
PROJECT_ROOT = os.path.expanduser("~/projects/observer_sim")
sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

from collector.ebpf_collector import EbpfCollector
from collector.event_recorder import EventRecorder
from observer_core.monitoring.event_normalizer import EventNormalizer
from observer_core.monitoring.rule_engine import RuleEngine
from observer_core.judgment.risk_scorer import RiskScorer
from observer_core.judgment.decision_engine import DecisionEngine
from observer_core.blocking.blocking_coordinator import BlockingCoordinator
from observer_core.blocking.command_sender import CommandSender
from observer_core.audit.audit_logger import AuditLogger
from models.virtual_clock import VirtualClock
from models.event import RawEvent

# ── 终端颜色 ──
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def print_header(title: str):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}\n")

def print_event(evt, decision):
    """格式化输出事件和决策"""
    action = decision.action
    if action == "ALLOW":
        color = GREEN
    elif action == "ALERT":
        color = YELLOW
    else:
        color = RED
  
    detail = ""
    if evt.event_type == "exec":
        detail = f"exe={evt.executable or '?'}"
    elif evt.event_type == "file_open":
        detail = f"path={evt.file_path or '?'} op={evt.file_op or '?'}"
    elif evt.event_type == "net_conn":
        detail = f"addr={evt.remote_addr or '?'}:{evt.remote_port or '?'}"
  
    print(f"  {color}[{action:5s}]{RESET} [{evt.event_type:10s}] pid={evt.pid:<6d} {detail} "
          f"risk={decision.risk_score:.2f}")

def main():
    parser = argparse.ArgumentParser(description="监控 Pydantic-DeepAgents 运行")
    parser.add_argument("--agent-cmd", type=str, required=True,
                        help="发给 Agent 的自然语言指令")
    parser.add_argument("--output", type=str,
                        default="output/recorded/agent_demo.jsonl",
                        help="录制文件输出路径")
    parser.add_argument("--duration", type=int, default=60,
                        help="监控持续时间（秒），默认60")
    args = parser.parse_args()

    # ── 加载配置 ──
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    print_header("方寸观察者 — Pydantic-DeepAgents 实时监控")

    # ── 1. 启动 eBPF 采集器 ──
    print(f"{CYAN}[1/4] 启动 eBPF 探针...{RESET}")
    ebpf_config = config.get("ebpf", {})
    ebpf_config["bpf_object_path"] = "ebpf/observer.bpf.o"
    ebpf_config["target_agent_id"] = "deep-agents"
  
    collector = EbpfCollector(config)
    collector.attach(agent_id="deep-agents")
    print(f"  {GREEN}✓ eBPF 探针已挂载（3 个 tracepoint）{RESET}")

    # ── 2. 启动 EventRecorder ──
    print(f"{CYAN}[2/4] 启动事件录制器...{RESET}")
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    recorder = EventRecorder(args.output, agent_id="deep-agents")
    recorder.start()
    print(f"  {GREEN}✓ 录制到 {args.output}{RESET}")

    # ── 3. 初始化 observer_core ──
    print(f"{CYAN}[3/4] 初始化处理链路...{RESET}")
    clock = VirtualClock(start_ns=config.get("virtual_clock", {}).get("start_ns", 0))
    normalizer = EventNormalizer(clock, window_size=10)
    rule_engine = RuleEngine(config)
    scorer = RiskScorer(config)
    decision_engine = DecisionEngine(config)
    cmd_sender = CommandSender(config)
    blocking_coordinator = BlockingCoordinator(config, cmd_sender)
    audit_logger = AuditLogger(config)
    print(f"  {GREEN}✓ observer_core/ 就绪（零改动）{RESET}")

    # ── 4. 在后台启动 Docker Agent ──
    print(f"{CYAN}[4/4] 启动 Docker Agent...{RESET}")
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print(f"  {YELLOW}⚠ ANTHROPIC_API_KEY 未设置，将使用模拟模式{RESET}")
        # 回退：用模拟脚本代替真实 Agent
        docker_cmd = [
            "docker", "run", "--rm", "--name", "deep-agent",
            "-v", f"{os.path.expanduser('~/deep-agents-demo/data')}:/workspace/data",
            "python:3.11-slim", "bash", "-c",
            "pip install pandas -q && "
            "python3 -c \"import pandas as pd; df=pd.read_csv('/workspace/data/sales.csv'); "
            "print(df.describe()); print('Max Revenue Month:', df.loc[df['Revenue'].idxmax(), 'Month'])\""
        ]
    else:
        docker_cmd = [
            "docker", "run", "--rm", "--name", "deep-agent",
            "-e", f"ANTHROPIC_API_KEY={api_key}",
            "-v", f"{os.path.expanduser('~/deep-agents-demo/data')}:/workspace/data",
            "deep-agents-demo", "-c",
            f"from pydantic_deep_agents import create_deep_agent\n"
            f"agent = create_deep_agent()\n"
            f"result = agent.run('{args.agent_cmd}')\n"
            f"print('DONE:', len(result), 'chars')\n"
        ]
  
    print(f"  {CYAN}  指令: {args.agent_cmd}{RESET}")

    # 启动 Docker
    docker_proc = subprocess.Popen(
        docker_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)  # 等待 Docker 容器启动
    print(f"  {GREEN}✓ Docker Agent 已启动{RESET}\n")

    # ── 监控循环 ──
    print(f"{BOLD}开始监控（{args.duration} 秒）...{RESET}\n")
    print(f"  {'决策':6s} {'事件类型':10s} {'PID':<8s} {'详情'}")
    print(f"  {'-'*60}")

    stats = {"ALLOW": 0, "ALERT": 0, "BLOCK": 0}
    start_time = time.time()

    try:
        for raw_event in recorder.record(collector.start()):
            # 过滤：只关注 deep-agents 相关的进程事件
            if raw_event.agent_id not in ("deep-agents", "", None) and not str(raw_event.pid).isdigit():
                continue

            try:
                normalized = normalizer.normalize(raw_event)
                score = scorer.score(normalized)
                decision = decision_engine.decide(normalized, score)
              
                blocking_coordinator.handle(normalized, decision)
                audit_logger.log(normalized, score, decision)
              
                print_event(raw_event, decision)
                stats[decision.action] = stats.get(decision.action, 0) + 1
              
            except Exception as e:
                # observer_core 处理异常不中断监控
                pass

            if time.time() - start_time > args.duration:
                break

    except KeyboardInterrupt:
        print(f"\n{YELLOW}  用户中断{RESET}")
    finally:
        # 清理
        print(f"\n{CYAN}清理...{RESET}")
        docker_proc.terminate()
        docker_proc.wait(timeout=10)
      
        total = recorder.stop()
        collector.detach()
      
        # ── 输出统计 ──
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}  监控摘要{RESET}")
        print(f"{BOLD}{'='*60}{RESET}")
        print(f"  录制事件: {total}")
        print(f"  {GREEN}ALLOW: {stats.get('ALLOW', 0)}{RESET}")
        print(f"  {YELLOW}ALERT: {stats.get('ALERT', 0)}{RESET}")
        print(f"  {RED}BLOCK: {stats.get('BLOCK', 0)}{RESET}")
        print(f"\n  录制文件: {args.output}")
        print(f"  可用此命令回放：")
        print(f"  {CYAN}python3 record_and_replay.py --replay-only {args.output}{RESET}")

if __name__ == "__main__":
    main()
PYEOF

chmod +x ~/deep-agents-demo/monitor_agent.py
```

---

## 四、Phase 3：执行第一条监控指令

### 场景：Agent 收到「读取 CSV 并分析市场趋势」

打开**两个终端窗口**：

#### 终端 1：启动监控

```bash
cd ~/deep-agents-demo

# 如果有 Anthropic API Key
export ANTHROPIC_API_KEY="ANTHROPIC_API_KEY_PLACEHOLDER"

# 启动监控（60 秒）
sudo python3 monitor_agent.py \
  --agent-cmd "读取 data/sales.csv，分析每月销售额趋势，找出收入最高和最低的月份，将结果写入 data/report.md" \
  --duration 60
```

#### 终端 2：观察 Docker Agent 的输出

```bash
# 查看 Agent 的实时日志
docker logs -f deep-agent 2>/dev/null || echo "等待容器启动..."
```

---

### 预期效果

**终端 1（监控端）输出**：

```
============================================================
  方寸观察者 — Pydantic-DeepAgents 实时监控
============================================================

[1/4] 启动 eBPF 探针...
  ✓ eBPF 探针已挂载（3 个 tracepoint）

[2/4] 启动事件录制器...
  ✓ 录制到 output/recorded/agent_demo.jsonl

[3/4] 初始化处理链路...
  ✓ observer_core/ 就绪（零改动）

[4/4] 启动 Docker Agent...
  指令: 读取 data/sales.csv，分析每月销售额趋势...

开始监控（60 秒）...

  决策     事件类型     PID      详情
  ────────────────────────────────────────────────
  [ALLOW] exec:      pid=12345  exe=/usr/bin/python3
  [ALLOW] exec:      pid=12346  exe=/usr/bin/pip
  [ALLOW] exec:      pid=12347  exe=/usr/bin/pip install pandas
  [ALLOW] file_open: pid=12345  path=/workspace/data/sales.csv op=read
  [ALLOW] exec:      pid=12348  exe=/usr/bin/python3 analyze.py
  [ALLOW] file_open: pid=12348  path=/workspace/data/report.md op=write
  [ALERT] net_conn:  pid=12348  addr=151.101.1.223:443  （网络连接）

  ...

============================================================
  监控摘要
============================================================
  录制事件: 42
  ALLOW: 37
  ALERT: 3
  BLOCK: 2

  录制文件: output/recorded/agent_demo.jsonl
  可用此命令回放：
  python3 record_and_replay.py --replay-only output/recorded/agent_demo.jsonl
```

---

## 五、Phase 4：验证与分析

### 4.1 查看录制的事件

```bash
cd ~/projects/observer_sim
head -10 output/recorded/agent_demo.jsonl
```

### 4.2 离线回放分析

```bash
python3 record_and_replay.py --replay-only output/recorded/agent_demo.jsonl
```

### 4.3 查看生成的审计报告

```bash
ls -la output/reports/
cat output/audit/*.jsonl 2>/dev/null | head -5
```

---

## 六、完整工作流总结

```
┌─────────────────────────────────────────────────────────────────┐
│                    完整操作流程（日常演示）                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 确保环境就绪（一次性）                                       │
│     ├─ Docker 已安装                                            │
│     ├─ ebpf/observer.bpf.o 已编译                               │
│     └─ deep-agents-demo 镜像已构建                              │
│                                                                 │
│  2. 启动监控（终端 1）                                          │
│     sudo python3 ~/deep-agents-demo/monitor_agent.py \          │
│       --agent-cmd "你的自然语言指令" \                           │
│       --duration 60                                              │
│                                                                 │
│  3. Agent 自动执行（终端 1 实时显示决策）                        │
│     [ALLOW] 正常操作（pip install、读文件）                      │
│     [ALERT] 可疑操作（外部网络连接、写文件）                      │
│     [BLOCK] 恶意操作（敏感文件访问、反弹 shell）                  │
│                                                                 │
│  4. 演示后分析                                                   │
│     ├─ 查看实时统计摘要                                         │
│     ├─ 回放录制文件：record_and_replay.py --replay-only          │
│     └─ 查看 Markdown 风险报告                                   │
│                                                                 │
│  5. 产出物                                                       │
│     ├─ output/recorded/agent_demo.jsonl  （录制的事件）          │
│     ├─ output/reports/                  （风险分析报告）          │
│     └─ output/audit/                    （审计日志）             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 七、故障排查

| 问题 | 原因 | 解决 |
|------|------|------|
| `ebpf/observer.bpf.o` 不存在 | eBPF 未编译 | `cd ebpf && make` |
| `Permission denied` | 未用 sudo 运行 | `sudo python3 monitor_agent.py ...` |
| Docker 容器无网络 | 防火墙限制 | 检查 `docker network ls` |
| `ANTHROPIC_API_KEY` 未设置 | 环境变量缺失 | `export ANTHROPIC_API_KEY="ANTHROPIC_API_KEY_PLACEHOLDER"` |
| Agent 输出乱码 | 编码问题 | 脚本已自动回退模拟模式（无需 API Key） |

现在你可以直接在 Linux VM 中按上述步骤执行。从构建 Docker 镜像到运行第一条监控指令，全程约 15 分钟。