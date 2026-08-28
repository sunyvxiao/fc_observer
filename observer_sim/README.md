# 方寸观察者模拟学习系统 (Fangcun Observer Simulation)

> 统一架构的 eBPF 行为监控教学系统，支持 Windows 模拟模式 + Linux eBPF/strace 真实采集模式，三入口自动检测平台并选择采集方案。

## 项目简介

**方寸观察者模拟学习系统**是一个教学原型，通过统一架构支持三种采集模式：

- **Simulation 模式**（Windows/通用）：场景 YAML 驱动 + 虚拟时钟，用于教学演示和回归测试
- **eBPF 模式**（Linux）：内核态 tracepoint 探针，真实采集 execve/openat/connect syscall
- **strace 模式**（Linux 降级）：ptrace 跟踪目标进程，解析 syscall 输出

核心能力：
- **统一采集接口**：`ICollector` 抽象 + 3 个实现类，`start()` 直接 yield `RawEvent`
- **平台自动检测**：启动时检测 `sys.platform`，自动选择采集模式（`--mode auto`）
- **Python 业务逻辑层**：事件归一化、规则匹配、四维风险评分、三级梯度阻断、审计输出
- **核心零改动**：`observer_core/`、`models/`、`scenarios/`、`rules/` 全程不变
- **37 个测试场景**：覆盖正常/异常/边界/多Agent/极端 5 大分类
- **367 个单元测试**：覆盖全部模块（130 原有 + 51 adapter/collector + 114 ebpf/strace/integration + 72 规则/报告优化）

**技术栈**：Python 3.10+ / C++17 / CMake 3.15+ / eBPF (libbpf + clang) / strace
**设计目标**：教学演示 > 生产性能，代码可读性优先，全链路透明可追踪
**运行模式**：命令行交互模式（demo.py）| Web 浏览器模式（app.py）| 批量运行模式（main.py）
**双环境架构**：Windows 宿主机（模拟模式）+ Linux VMware Ubuntu 22.04 LTS（eBPF/strace 模式）

---

## 系统架构

### 统一架构（Phase 7-8 升级后）

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    入口层 (main.py / demo.py / app.py)                     │
│  解析 --mode → 加载 config.yaml → 平台检测 → 创建 Collector → 消费事件     │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ ICollector.start() yield RawEvent
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
  ┌─────────────────┐ ┌───────────────┐ ┌────────────────────┐
  │ Simulation      │ │ Strace        │ │ Ebpf               │
  │ Collector       │ │ Collector     │ │ Collector           │
  │ (Windows/通用)  │ │ (Linux 降级)  │ │ (Linux, eBPF 观测)  │
  │ 场景YAML+Clock  │ │ strace -p PID │ │ libbpf+ring buffer │
  └────────┬────────┘ └──────┬────────┘ └─────────┬──────────┘
           └─────────────────┼────────────────────┘
                             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              核心逻辑层 (observer_core/)              [零改动]             │
│  EventNormalizer → RuleEngine → RiskScorer → DecisionEngine             │
│  → BlockingCoordinator → BehaviorGraph → AuditLogger                    │
└──────────────────────────────────────────────────────────────────────────┘
```

### 适配层 (adapter/)

| 模块 | 职责 |
|------|------|
| `platform_detect.py` | 平台检测 + eBPF 能力查询 + `detect_and_create_collector()` 工厂 |
| `pipe_factory.py` | 管道适配器（Windows 命名管道 / Linux FIFO） |
| `time_source.py` | 时间源抽象（VirtualClock / realtime_monotonic） |

### 采集层 (collector/)

| 采集器 | 平台 | 能力 | 时间源 |
|--------|:---:|------|--------|
| `SimulationCollector` | 通用 | 观测 + Tier2/3 模拟阻断 | VirtualClock (虚拟) |
| `StraceCollector` | Linux | 仅观测（can_block = False） | time.time_ns() |
| `EbpfCollector` | Linux | 仅观测（第一版，can_block = False） | bpf_ktime_get_ns() |
| `FileReplayCollector` | 通用 | 录制文件回放（JSONL → RawEvent） | 录制时的时间戳 |
| `DeepAgentCollector` | Linux | DeepAgent 框架集成采集 | time.time_ns() |

### 录制-回放功能

`event_recorder.py` 提供事件录制能力，`FileReplayCollector` 支持回放：
- **录制**：任意 ICollector 输出可保存为 JSONL 录制文件，便于事后审计和外部数据接入
- **回放**：`--mode file_replay --replay-file <PATH>` 从录制文件重放事件流
- **用途**：跨环境测试数据迁移、外部测试数据导入、历史行为回溯分析

### 传统架构（保留兼容）

```
┌──────────────────────────────────────────────────┐
│  场景 YAML → C++ 探针模拟层 (cpp_probe/)           │
│  ProcessProbe | FileProbe | NetworkProbe          │
└──────────────────┬───────────────────────────────┘
                   │  \\.\pipe\observer_events
                   ▼
┌──────────────────────────────────────────────────┐
│  Python Observer 核心引擎                         │
│  [监测层] PipeReader → Normalizer → RuleEngine    │
│  [评判层] RiskScorer → Baseline → Decision        │
│  [阻断层] BlockingCoordinator → Tier1/2/3         │
│  [审计层] BehaviorGraph + AuditLogger + Report    │
└──────────────────────────────────────────────────┘
```

**核心数据流**：事件采集 → 归一化 → 规则匹配 → 四维评分 → 研判决策 → 阻断执行 → 审计输出

---

## 核心功能模块

### 监测机制 (Phase 2)
- **EventNormalizer**：进程树维护、Agent 上下文追踪、事件窗口管理
- **RuleEngine**：YAML 策略加载、四类模式匹配（pattern/regex/exact/path_glob）
- **21 条安全策略规则（v2.0）**：覆盖命令执行（9）、文件操作（7）、网络（5）三大类

### 评判机制 (Phase 3)
- **RiskScorer**：四维加权评分（规则命中 40% + 基线偏离 25% + 上下文 20% + 序列异常 15%）
- **IRiskDimension 可替换接口**：每个评分维度均可独立替换算法实现
- **BaselineChecker**：正常行为基线构建 + 偏离检测 + 冷启动处理
- **DecisionEngine**：研判矩阵（风险等级 x 规则动作 → ALLOW/ALERT/BLOCK）
- **ChainReportBuilder**：因果链构建 + JSON/Markdown 双格式输出

### 阻断机制 (Phase 4)
- **BlockingCoordinator**：三级路由 + CommandSender 反向管道联动
- **AgentViolationTracker**：虚拟时钟滑动窗口违规升级（Tier1x5→Tier2, Tier2x3→Tier3）
- **三级处理器**：
  - Tier1 SoftReport：放行 + 告警 + allow 指令
  - Tier2 BlockAccess：阻止访问 + 返回 EPERM + block_event 指令
  - Tier3 HardInterrupt：终止进程树 + 紧急写入 + terminate_process 指令

### 审计与输出 (Phase 5)
- **BehaviorGraph**：行为图谱 + 跨 Agent 关联检测 + 结构化 JSON 输出
- **AuditLogger**：JSON 行审计日志，记录完整处理链路
- **ReportExporter**：Markdown 风险分析报告 + 多场景汇总报告
- **RunOutputManager**：输出路径管理器，按分类+时间戳组织输出目录

### 自优化接口预留 (Phase 6)
- **ITraceStore / IPatternMiner / IStrategyGenerator**：为后续迭代预留的自进化接口

### 风险评判规则体系 v2.0

规则库已从 15 条初始规则升级到 **21 条安全策略规则（v2.0）**，分类统计：

| 类别 | 规则数 | 规则 ID | 覆盖范围 |
|------|:---:|------|------|
| 命令执行（command） | 9 | R001, R002, R003, R004, R005, R016, R017, R018, R019 | 高危命令、权限提升、反弹Shell、持久化、痕迹清除 |
| 文件操作（file） | 7 | R006, R007, R007b, R008, R009, R010, R011 | 敏感文件读写、凭据访问、关键系统文件保护 |
| 网络（network） | 5 | R012, R013, R014, R015, R020 | 外部数据外传、可疑端口、恶意IP、非标准出站 |

新增核心规则（6 条 v1.0→v2.0）：
- **R007b**（block）：阻断凭据/密钥文件访问，优先级 100
- **R016**（alert）：告警 shell 脚本执行
- **R017**（alert）：告警 crontab/systemctl 持久化操作
- **R018**（alert）：告警 history -c/shred 等痕迹清除
- **R019**（alert）：告警读取 .sql/.dump/.bak 大数据文件
- **R020**（alert）：告警非标准出站端口（RDP/Redis/MongoDB）

规则配置文件：`rules/default_policy.yaml`（规则定义）、`rules/judgment_pipeline.yaml`（研判阈值与升级规则）、`rules/scoring_dimensions.yaml`（四维评分权重）。

### 报告一致性规范

所有报告模块（时间线、明细表、Agent 摘要、行为图谱）统一以 `BlockingResult` 为唯一数据源：
- **阻断判定**：以 `blocking_result.blocked` 为准（含 ViolationTracker 升级后的结果）
- **最终等级**：以 `blocking_result.tier` 为准（Tier1/Tier2/Tier3）
- **阻断原因**：以 `blocking_result.reason` 为准

四模块输出保证同一事件的状态标记一致，消除 Pre/Post-escalation 数据源不一致导致的自相矛盾。

---

## 环境要求

### Windows 宿主机（模拟模式）

| 依赖 | 版本要求 | 说明 |
|------|---------|------|
| Python | >= 3.10 | 业务逻辑层 |
| CMake | >= 3.15 | C++ 探针层编译（可选） |
| Visual Studio Build Tools | 2019+ | 含 C++ 桌面开发工作负载（可选） |
| pyyaml | 最新版 | `pip install pyyaml` |
| pytest | 最新版 | `pip install pytest` |

### Linux 虚拟机（eBPF/strace 模式）

| 依赖 | 版本要求 | 说明 |
|------|---------|------|
| Ubuntu | 22.04 LTS | 内核 >= 5.15（HWE 内核 6.8+） |
| Python | >= 3.10 | Ubuntu 22.04 自带 3.10 |
| clang | >= 14 | eBPF 探针编译 |
| bpftool | >= 7.x | BTF 生成 + 程序加载验证 |
| libbpf-dev | 1.2+ | Python ctypes 绑定 libbpf.so |
| linux-headers | 与内核匹配 | eBPF 编译依赖 |
| strace | >= 5.x | strace 降级采集模式 |
| pyyaml + pytest | 最新版 | Python 依赖 |

> 详细环境搭建步骤请参考 [迁移方案.md](../docs/杂项文档/迁移方案.md)（从虚拟机创建到完整工具链安装）。

### API 密钥配置

项目使用 `.env` 文件集中管理所有 API 密钥（LLM 密钥 + 演示场景密钥），脚本自动加载，无需修改任何代码：

```bash
# 1. 复制配置模板
cp .env.example .env

# 2. 编辑 .env 填入真实密钥（模拟模式可跳过，使用内置安全占位符）
#    OPENAI_API_KEY=YOUR_KEY_HERE    # LLM API 密钥（live 模式必填）
#    MARKET_DATA_API_KEY=...       # 演示场景密钥（可选）
#    STRIPE_SECRET_KEY=...         # 演示场景密钥（可选）
#    ...

# 3. .env 已被 .gitignore 排除，不会被提交到 GitHub
```

**密钥加载机制**：
- `setup_workspace.sh`：执行时 `source .env`，将密钥注入生成的配置文件
- `run_agent.py`：启动时 `load_dotenv()` 自动读取
- `scripts/deep_agent_monitor.py`：通过 `env_config.load_env_config()` 加载
- 默认值均为安全占位符（全大写英文如 `STRIPE_PLACEHOLDER_KEY`），不会触发 GitHub 推送保护

### 快速环境检查

```bash
# 运行环境预检脚本（Windows 和 Linux 通用）
python check_env.py
```

### Windows 安装步骤

```bash
pip install pyyaml pytest
python check_env.py    # 验证环境
```

### Linux 一键安装（Ubuntu 22.04）

```bash
# Python 依赖
pip3 install pyyaml pytest

# eBPF 工具链
sudo apt update
sudo apt install -y clang llvm libbpf-dev make linux-headers-$(uname -r) strace

# 生成 BTF 头文件
cd observer_sim/ebpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
make    # 编译 eBPF 探针

python3 check_env.py    # 验证环境
```

---

## 快速开始

### 采集模式选择

三个入口（`main.py` / `app.py` / `demo.py`）均支持 `--mode` 参数：

```bash
# 自动检测（默认）—— Windows 选 simulation，Linux 选 ebpf/strace
python main.py --mode auto --scenario all

# 强制模拟模式（Windows/Linux 通用）
python main.py --mode simulation --scenario all

# eBPF 模式（仅 Linux，需 root 权限）
sudo python3 main.py --mode ebpf --pid <TARGET_PID>

# strace 降级模式（仅 Linux）
python3 main.py --mode strace --pid <TARGET_PID>
```

| 模式 | 平台 | 说明 |
|------|:---:|------|
| `auto` | 双端 | 自动检测平台并选择采集模式 |
| `simulation` | 双端 | 强制模拟模式，加载场景 YAML |
| `ebpf` | Linux | eBPF 内核探针采集真实 syscall |
| `strace` | Linux | strace 降级采集 |
| `mcp_report` | Windows | MCP 申报模式（WorkBuddy 降级监测，见下节） |

### MCP 申报模式（Windows WorkBuddy 降级监测）

黑盒 Agent（如 WorkBuddy）无法注入探针时，由 Agent 通过 **MCP 协议主动申报**行为：
本系统作为标准 MCP Server（HTTP+SSE，官方 mcp SDK）暴露三个申报 tools，
`mcp_report_collector` 消费申报流并复用 RawEventFactory 转入统一监测管线。

```bash
# 依赖: pip install mcp
cd observer_sim

# 启动监测守护进程（MCP Server 默认监听 http://127.0.0.1:8765/sse）
python observer.py daemon --mode mcp_report --output output/mcp_monitoring

# 停止: 控制台 Ctrl+C，或向 stdin 写入一行 shutdown/stop/quit
# 停止后自动生成风险分析报告（reports/）与审计日志（audit/）
```

WorkBuddy 以 MCP client 接入 `/sse` 后调用三个申报 tools：

| tool | 用途 |
|------|------|
| `report_tool_call` | 申报一次工具调用（tool_name + tool_args 摘要） |
| `report_action` | 申报一次通用动作（决策/提示等非工具动作） |
| `report_session` | 申报会话生命周期事件（start/end/pause/resume） |

安全与保护机制：
- **申报校验**：schema 校验 + 报文大小限制（64KB）+ 容器字段限制（16KB/100 键）+ 按 agent 限流（60 次/秒），畸形/超限申报被拒绝且 Server 不崩溃
- **浅层语义保护**：工具名→事件类型映射复用 HookRegistry，申报参数自动脱敏（密码/token 等敏感键）与截断，恶意申报不破坏管线
- **能力边界**：定位为「合规留痕 + 风险提示」——事件完整性依赖 Agent 主动申报，
  无交叉校验、无 L2/L3 阻断，不宣称安全防护

环境检测（`python observer.py env`）包含 mcp SDK 可用性检测项；
端到端验证见 `tests/test_mcp_report_e2e.py`（MCP client 模拟器跑正常/异常/畸形申报场景）。

### Web 浏览器模式（推荐）

```bash
cd observer_sim
python app.py
# 可选: python app.py --mode simulation
```

启动后自动打开浏览器，访问 `http://localhost:8080`，提供：
- **可视化界面**：深色终端主题，左侧导航栏 + 右侧主内容区
- **实时推送**：基于 SSE（Server-Sent Events）逐步展示场景运行过程
- **场景浏览**：按 5 大分类浏览 37 个场景，点击运行并实时查看事件处理流水线
- **全量模拟**：一键运行全部场景，进度条 + 统计面板
- **单元测试**：一键运行 130 个测试用例，同步返回结果
- **报告管理**：三级折叠树浏览历史报告，Markdown 渲染，支持三级删除
- **分析面板**：场景运行完成后展示四维分析（威胁评分/规则命中/行为图谱/审计建议）

技术特点：
- 基于 Python 标准库 `ThreadingHTTPServer`，零 pip install 依赖
- 14 个 REST/SSE API 端点，详见 [API 端点列表](#api-端点列表)
- 单文件前端（`static/index.html`），HTML/CSS/JS 内联，约 1100 行
- `StreamScenarioRunner` 适配层将同步场景执行转为生成器，逐步 yield 事件处理数据
- 后台工作线程架构：`queue.Queue` + `threading.Thread`
- 15 秒 SSE 心跳保活 + JSON 回退机制
- 路径遍历安全防护（`os.path.realpath()` + 前缀校验）

### 交互式命令行模式

```bash
python demo.py
```

启动后展示主菜单，包含三个核心选项：

```
┌──────────────────────────────────────────────────────────┐
│              方寸观察者模拟学习系统 — 主菜单               │
├──────────────────────────────────────────────────────────┤
│  1. 运行全部单元测试                                      │
│     调用 pytest 运行 367 个单元测试用例，显示结果摘要       │
│                                                          │
│  2. 运行全量模拟环境测试                                   │
│     静默运行 37 个场景，显示全局数据统计面板               │
│                                                          │
│  3. 按分类浏览并运行场景测试                               │
│     浏览 5 个分类，运行全部或指定单个场景                   │
│                                                          │
├──────────────────────────────────────────────────────────┤
│  0. 退出                                                 │
└──────────────────────────────────────────────────────────┘
```

#### 选项 1：单元测试模式

后台静默调用 `pytest`，运行结束后仅输出结果摘要面板：
- 总用例数、通过数、失败数
- 所有失败用例名称（全部通过则显示"全部通过"）

#### 选项 2：全量模拟模式

静默运行全部 37 个场景，运行结束后输出全局数据统计面板：
- **总体统计**：总事件数、总放行(ALLOW)、总告警(ALERT)、总阻断(BLOCK)
- **分类统计**：5 个分类各自的放行、告警、阻断次数分布

#### 选项 3：分类浏览模式

1. 先选择场景分类（Normal / Anomalous / Boundary / Multi-Agent / Extreme）
2. 进入子菜单：
   - **A. 运行该分类下全部场景**
   - **B. 指定运行某个具体场景**（支持序号或场景 ID，如 `a01`）

### 场景分析面板

每个场景运行结束后，输出 4 维度结构化分析面板：

| 维度 | 内容 |
|------|------|
| 测试目的 | 场景设计意图和验证目标 |
| 风险发现 | 检测到的风险事件、触发规则、最高风险评分 |
| 风险成因（归因分析） | 命中规则、基线偏离、上下文序列触发原因 |
| 综合处置策略 | 联合应对方案（阻断+隔离+审计+建议） |

37 个场景均内置了分析数据映射（`analysis_panels.py` 中的 `SA` 字典，CLI 和 Web 模式共享）。

### 命令行运行

```bash
# 指定场景运行
python demo.py --scenario n01

# 按分类运行
python demo.py --category anomalous

# 全场景自动播放（不暂停）
python demo.py --auto

# main.py 全量运行入口
python main.py --scenario all
python main.py --category boundary
python main.py --scenario a01 --output output
```

### 运行测试

```bash
# 运行全部测试（367 个）
python -m pytest tests/ -v

# 运行特定模块测试
python -m pytest tests/test_blocking.py -v    # Phase 4 阻断机制
python -m pytest tests/test_audit.py -v       # Phase 5 审计输出
python -m pytest tests/test_integration.py -v # Phase 6 集成测试
python -m pytest tests/test_adapter.py -v     # 平台适配层
python -m pytest tests/test_collector_integration.py -v  # 采集层集成
```

测试结果同时输出到 `output/unit_test/` 目录（`test_results.json` + `test_output.txt`），始终只保留最新一次。

---

## 测试场景体系

### 场景分类总览

共 **37 个测试场景**，按 5 大分类组织：

| 大类 | 前缀 | 场景数 | 覆盖重点 |
|------|:---:|:---:|---------|
| N — 正常场景 (Normal) | N01-N08 | 8 | 建立基线、验证系统不误判 |
| A — 异常场景 (Anomalous) | A01-A12 | 12 | 触发告警/阻断、验证规则覆盖率和链式报告 |
| B — 边界场景 (Boundary) | B01-B08 | 8 | 模棱两可的行为、验证评分精度和分级合理性 |
| M — 多 Agent 协作 (Multi-Agent) | M01-M05 | 5 | 跨 Agent 数据流检测、进程树关联 |
| E — 极端/压力场景 (Extreme) | E01-E04 | 4 | 系统容错、降级策略、资源边界 |

### 分阶段优先级

| 阶段 | 场景 | 数量 | 目的 |
|------|------|:---:|------|
| Phase 1（必须） | N01, N02, A01, A02, A03, B01 | 6 | 验证核心链路：正常放行、异常阻断、边界告警 |
| Phase 2（重要） | N03, N04, A04, A06, A07, A08, M01, M02, B02 | 9 | 覆盖更多维度：提权、横向移动、跨 Agent、基线偏离 |
| Phase 3（完整） | N05-N08, A05, A09-A12, B03-B08, M03-M05, E01-E04 | 22 | 全场景覆盖 + 边界 + 压力测试 |

### YAML 场景文件格式

每个场景文件包含以下字段：

```yaml
scenario:
  id: a01-rm-root                    # 场景唯一 ID
  name: A01-高危系统命令:递归删除根目录  # 场景名称
  description: Agent执行rm -rf /      # 场景描述
  expected_result: Tier2 BLOCK        # 预期结果
  category: anomalous                 # 所属分类
  agents:                             # Agent 定义
    - agent_id: rogue-1
      framework: AutoGen
      initial_pid: 20001
  event_sequence:                     # 事件序列
    - seq: 1
      delay_ms: 0
      agent: rogue-1
      type: exec
      executable: /bin/rm
      arguments: [-rf, /, --no-preserve-root]
```

### 场景生成工具

使用 `generate_scenarios.py` 批量生成全部 37 个场景 YAML：

```bash
python generate_scenarios.py
```

---

## 输出目录结构

### 场景运行输出

每次场景运行在 `output/reports/` 下按 **分类 → 场景ID → 时间戳** 三级目录组织：

```
output/
├── reports/
│   ├── normal/
│   │   └── n01-standard-development/
│   │       └── 2026_07_28_12_30_34/        # 时间戳目录
│   │           ├── audit/                   # JSONL 审计日志
│   │           ├── graphs/                  # 行为图谱 JSON
│   │           ├── evidence/                # 阻断证据 JSON（如有）
│   │           └── risk_report_*.md         # Markdown 风险分析报告
│   ├── anomalous/
│   │   └── a01-rm-root/
│   │       └── 2026_07_28_12_30_44/
│   ├── boundary/
│   ├── multi_agent/
│   └── extreme/
│
└── unit_test/                               # 单元测试输出（始终最新一次）
    ├── test_results.json                    # 结构化测试结果
    └── test_output.txt                      # 可读文本摘要
```

- **时间戳格式**：`YYYY_MM_DD_HH_mm_ss`，同秒冲突自动追加 `(1)`, `(2)` 后缀
- **输出管理**：通过 `RunOutputManager`（`output_path_manager.py`）统一管理路径
- **unit_test 目录**：每次运行 pytest 时自动清空旧结果，始终只保留最新一次

---

## 项目目录结构

```
observer_sim/                          # 项目根目录
├── observer_sim/                      # Python 源码包
│   ├── app.py                         # Web 模式入口（ThreadingHTTPServer + SSE，支持 --mode）
│   ├── main.py                        # 全场景批量运行入口（支持 --scenario/--category/--mode）
│   ├── demo.py                        # 交互式命令行演示脚本（主菜单 + 场景分析面板）
│   ├── config.yaml                    # 全局配置（mode/pipeline/simulation/ebpf/strace）
│   ├── check_env.py                   # 环境预检脚本（Windows/Linux 双端检测）
│   ├── conftest.py                    # pytest 插件（unit_test 输出管理）
│   ├── generate_scenarios.py          # 批量生成 37 个场景 YAML 的工具脚本
│   ├── analysis_panels.py             # 37 个场景的分析面板数据（SA 字典，CLI/Web 共享）
│   ├── .gitignore                     # Git 排除规则（保留兼容）
│   │
│   ├── adapter/                       # 平台适配层
│   │   ├── __init__.py
│   │   ├── platform_detect.py         # 平台检测 + eBPF 能力查询 + detect_and_create_collector()
│   │   ├── pipe_factory.py            # 管道适配器（Windows 命名管道 / Linux FIFO）
│   │   └── time_source.py             # 时间源抽象（VirtualClock / realtime_monotonic）
│   │
│   ├── collector/                     # 采集层
│   │   ├── __init__.py                # 导出 ICollector, CollectorCapabilities
│   │   ├── base_collector.py          # ICollector 抽象接口 + CollectorCapabilities 数据类
│   │   ├── simulation_collector.py    # 模拟采集器（封装场景 YAML + VirtualClock）
│   │   ├── ebpf_collector.py          # eBPF 采集器（libbpf ctypes + perf ring buffer）
│   │   ├── strace_collector.py        # strace 采集器（subprocess + 行解析）
│   │   ├── file_replay_collector.py   # 文件回放采集器（JSONL 录制文件回放）
│   │   ├── deep_agent_collector.py    # DeepAgent 采集器（Agent 框架集成）
│   │   └── event_recorder.py          # 事件录制器（ICollector 输出 → JSONL）
│   │
│   ├── ebpf/                          # eBPF 探针 [仅 Linux]
│   │   ├── observer.bpf.c             # eBPF 内核态 C 程序（3 个 tracepoint，仅观测）
│   │   ├── Makefile                   # 编译脚本（make → observer.bpf.o）
│   │   ├── vmlinux.h                  # 内核类型定义（bpftool 生成，.gitignore 排除）
│   │   └── observer.bpf.o             # 编译产物（.gitignore 排除）
│   │
│   ├── static/                        # Web 前端静态文件
│   │   └── index.html                 # 单文件应用（HTML + CSS + JS 内联，深色终端主题）
│   │
│   ├── scenarios/                     # 场景定义 YAML（37 个，按分类组织）
│   │   ├── normal/                    # 正常行为 (N01-N08)
│   │   ├── anomalous/                 # 异常行为 (A01-A12)
│   │   ├── boundary/                  # 边界场景 (B01-B08)
│   │   ├── multi_agent/               # 多Agent协作 (M01-M05)
│   │   ├── deep_agent/                # DeepAgent 演示场景
│   │   └── extreme/                   # 极端场景 (E01-E04)
│   │
│   ├── rules/                         # 安全策略规则库（v2.0）
│   │   ├── default_policy.yaml        # 21 条安全策略规则（命令9/文件7/网络5）
│   │   ├── judgment_pipeline.yaml     # 研判流水线配置（评分阈值 + 升级规则）
│   │   ├── scoring_dimensions.yaml    # 四维评分权重与偏离分配置
│   │   └── evolution_interface.yaml   # 自优化接口配置（预留）
│   │
│   ├── cpp_probe/                     # C++ 探针模拟层（保留兼容）
│   │   ├── CMakeLists.txt
│   │   ├── main.cpp
│   │   ├── iprobe.h / process_probe.h / file_probe.h / network_probe.h
│   │   ├── event_formatter.h / pipe_writer.h / command_reader.h
│   │   ├── process_table.h/.cpp / common.h / ring_buffer.h
│   │   └── build/                     # CMake 编译产物（.gitignore 排除）
│   │
│   ├── observer_core/                 # Python Observer 核心引擎
│   │   ├── monitoring/                # 监测: pipe_reader / event_normalizer / rule_engine
│   │   ├── judgment/                  # 评判: risk_scorer / baseline_checker / decision_engine
│   │   ├── blocking/                  # 阻断: blocking_coordinator / command_sender / violation_tracker
│   │   └── audit/                     # 审计: behavior_graph / audit_logger / report_exporter
│   │
│   ├── evolution/                     # 自优化接口（预留）
│   │   └── interfaces.py              # ITraceStore/IPatternMiner/IStrategyGenerator
│   │
│   ├── models/                        # 共享数据模型
│   │   ├── event.py                   # RawEvent / NormalizedEvent / AgentContext
│   │   ├── risk.py                    # RiskAssessment / Decision / BlockingResult
│   │   ├── command.py                 # Command（反向管道指令）
│   │   └── virtual_clock.py           # VirtualClock 虚拟时钟
│   │
│   ├── tests/                         # 测试套件（500+ 个测试）
│   │   ├── test_virtual_clock.py      # 虚拟时钟
│   │   ├── test_pipe_communication.py # 管道通信
│   │   ├── test_monitoring.py         # 监测机制
│   │   ├── test_judgment.py           # 评判机制
│   │   ├── test_blocking.py           # 阻断机制
│   │   ├── test_audit.py              # 审计输出
│   │   ├── test_integration.py        # 集成测试
│   │   ├── test_adapter.py            # 平台适配层测试
│   │   ├── test_simulation_collector.py # 模拟采集器测试
│   │   ├── test_ebpf_collector.py     # eBPF 采集器测试
│   │   ├── test_strace_collector.py   # strace 采集器测试
│   │   └── test_collector_integration.py # 采集层集成测试
│   │
│   └── output/                        # 运行输出目录（自动生成，.gitignore 排除）
│       ├── reports/                   # 场景报告（按分类+场景+时间戳归档）
│       ├── audit/                     # 审计日志
│       ├── baselines/                 # 行为基线
│       └── unit_test/                 # 单元测试输出
│
├── scripts/                           # 入口脚本与工具
│   ├── test.py                        # 统一测试入口（支持 --all/--unit/--scenario/--e2e）
│   ├── demo_workflow.py               # DeepAgent 演示工作流脚本
│   ├── deep_agent_monitor.py          # DeepAgent 监测脚本（--scenario/--live/--record）
│   ├── start_demo_monitoring.sh       # 启动演示监测的 Shell 脚本
│   └── setup_ebpf_env.sh              # eBPF 环境初始化脚本
│
├── docs/                              # 项目文档
│   ├── 杂项文档/                      # 开发过程文档（PRD/调研/交接/方案）
│   ├── 软件工程文档/                  # 软件工程文档（数据流/状态机/模块设计等）
│   ├── 测试图片/                      # 测试截图
│   └── ARCHITECTURE.md                # 项目架构文档
│
├── assets/
│   └── screenshots/                   # 截图资源
│
├── deep-agents-demo/                  # Agent 演示工作目录
├── tools/                             # 辅助工具
├── records/                           # 录制数据（运行时产物，.gitignore 排除）
├── .monitoring/                       # 监测运行时目录
├── .env / .env.example                # 环境变量配置
├── .gitignore                         # Git 排除规则
└── README.md                          # (此文件位于 observer_sim/ 子目录)
```

---

## 测试说明

项目测试体系共 **367 个测试用例**（Windows 端 367 passed, 0 failed），覆盖全部模块：

| 模块 | 测试文件 | 数量 | 覆盖内容 |
|------|---------|:---:|--------|
| 核心 | test_virtual_clock.py | 16 | 虚拟时钟推进、边界、溢出、窗口判定 |
| 核心 | test_pipe_communication.py | 26 | 事件序列化、指令序列化、Mock 管道 |
| 核心 | test_monitoring.py | 18 | 归一化、进程树、规则匹配 |
| 核心 | test_judgment.py | 21 | 四维评分、基线偏离、研判矩阵 |
| 核心 | test_blocking.py | 16 | 违规升级、三级阻断、反向管道 |
| 核心 | test_audit.py | 16 | 行为图谱、审计日志、报告导出 |
| 核心 | test_integration.py | 17 | 端到端集成、边界条件、自优化接口 |
| 采集 | test_adapter.py | 23 | 平台检测、管道工厂、时间源 |
| 采集 | test_simulation_collector.py | 28 | YAML 加载、多 Agent、VirtualClock |
| 采集 | test_ebpf_collector.py | 30 | event_t→RawEvent 映射、capabilities |
| 采集 | test_strace_collector.py | 45 | strace 行解析、正则表达式、生命周期 |
| 采集 | test_collector_integration.py | 39 | 模式切换、降级逻辑、接口一致性 |
| **合计** | | **367** | **全平台: 367 passed, 0 failed** |

> 测试覆盖双平台，模拟模式在 Windows/Linux 均可全量通过。

```bash
# 运行全部测试
python -m pytest -v

# 运行特定模块测试
python -m pytest tests/test_ebpf_collector.py -v     # eBPF 采集器
python -m pytest tests/test_collector_integration.py -v  # 采集层集成
```

---

## API 端点列表

Web 模式（`app.py`）提供 14 个 REST/SSE 端点：

| 方法 | 路径 | 说明 | 类型 |
|------|------|------|------|
| GET | `/` | 返回 `static/index.html` | 静态 |
| GET | `/api/health` | 健康检查 | JSON |
| GET | `/api/categories` | 场景分类列表（5 大分类） | JSON |
| GET | `/api/scenarios?category={name}` | 分类下场景列表 | JSON |
| POST | `/api/scenario/run` | 启动单个场景（返回 run_id） | JSON |
| GET | `/api/scenario/stream/{run_id}` | SSE 事件流（逐步推送处理结果） | SSE |
| GET | `/api/scenario/run-all?category={name}` | SSE 批量运行全部场景 | SSE |
| GET | `/api/scenario/run-all/progress` | 全量运行进度查询 | JSON |
| GET | `/api/scenario/result/{run_id}` | 场景运行结果 + 分析面板 | JSON |
│ POST | `/api/tests/run` | 同步运行 367 个单元测试 | JSON |
| GET | `/api/reports/list` | 报告文件列表（三级树结构） | JSON |
| GET | `/api/reports/view?path=...` | 报告内容（含路径安全校验） | text |
| POST | `/api/reports/delete` | 删除记录（全部/按分类/按场景） | JSON |
| POST | `/api/server/stop` | 关闭服务器 | JSON |

---

## SSE 流式协议

场景运行通过 SSE（Server-Sent Events）实时推送每个事件的处理结果。

### 事件类型

| 事件类型 | event 字段 | 触发时机 |
|---------|:---:|------|
| 场景步骤 | `step` | 每个事件处理完毕 |
| 场景完成 | `done` | 场景全部事件处理完 |
| 批量-场景开始 | `scenario_start` | run-all 每个场景开始 |
| 批量-场景完成 | `scenario_done` | run-all 每个场景完成 |
| 批量-全部完成 | `all_done` | 37 场景全部完成 |
| 心跳 | `heartbeat` | 每 15 秒（保活） |
| 错误 | `error` | 异常/服务器关闭 |

### step_data 字段定义

每个 `step` 事件包含以下结构化数据：

| 字段 | 类型 | 说明 |
|------|------|------|
| `seq` | int | 当前步骤序号（1-based） |
| `total` | int | 总步骤数 |
| `event_type` | string | exec / file_open / net_conn |
| `raw_input` | string | 原始事件描述 |
| `normalized_summary` | string | 归一化后摘要 |
| `rule_match.hit` | bool | 是否命中规则 |
| `rule_match.rules` | array | 命中规则列表 [{id, name, action}] |
| `risk_score` | float | 综合风险评分 0.0~1.0 |
| `risk_level` | string | LOW / MEDIUM / HIGH / CRITICAL |
| `risk_breakdown` | object | 四维评分 {rule, baseline, context, sequence} |
| `decision_action` | string | ALLOW / ALERT / BLOCK |
| `decision_tier` | string | Tier1 / Tier2 / Tier3 |
| `disposal_summary` | string | 处置结果摘要 |
| `timestamp_ns` | int | 虚拟时钟纳秒 |

### 前端 SSE 消费示例

```javascript
const es = new EventSource(`/api/scenario/stream/${run_id}`);
es.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.type === "step") {
        // 追加日志 + 更新 UI
    } else if (data.type === "done") {
        // 渲染分析面板
        es.close();
    }
};
```

---

## 开发进度

### 原始功能（Phase 1-6 + Web）

| Phase | 内容 | 状态 | 测试 |
|-------|------|:---:|:---:|
| Phase 1 | 数据通道：C++ 探针 + 双向管道 + VirtualClock | ✅ 已完成 | 42 |
| Phase 2 | 监测机制：EventNormalizer + RuleEngine + 21 条规则（v2.0） | ✅ 已完成 | 18 |
| Phase 3 | 评判机制：四维评分 + 基线 + 决策 + 链式报告 | ✅ 已完成 | 21 |
| Phase 4 | 阻断机制：三级阻断 + 违规升级 + 反向管道联动 | ✅ 已完成 | 16 |
| Phase 5 | 审计输出：行为图谱 + 审计日志 + Markdown 报告 | ✅ 已完成 | 16 |
| Phase 6 | 接口预留：自优化接口 + main.py + 集成测试 | ✅ 已完成 | 17 |
| **Web 模式** | **app.py + index.html + SSE 实时推送 + 报告管理** | ✅ **已完成** | **API+SSE** |

### 统一架构升级（eBPF 数据输入模块）

| 阶段 | 环境 | 内容 | 状态 |
|------|:---:|------|:---:|
| Phase 7 (Day 1-2) | Win | adapter/ 平台适配层 + ICollector 接口 + SimulationCollector | ✅ 已完成 |
| Phase 7 (Day 3-4) | Win | 三入口改造 (main.py/demo.py/app.py) + config.yaml + 无回归 | ✅ 已完成 |
| Phase 8 (Day 5-8) | Linux | eBPF C 探针 + EbpfCollector + StraceCollector + 114 测试 | ✅ 已完成 |
| Phase 9 (Day 9) | 双端 | 跨环境集成联调（Windows 端已完成，Linux 端待验证） | 🟡 部分 |
| Phase 10 (Day 10) | 双端 | 全量验证 + README + 环境脚本 + 文档（Windows 端已完成） | 🟡 部分 |

---

## eBPF 开发指南

### eBPF 探针架构

`ebpf/observer.bpf.c` 实现了三个 tracepoint 探针（第一版仅观测，不支持阻断）：

| 探针 | 挂载点 | 捕获参数 |
|------|--------|----------|
| execve | `tracepoint/syscalls/sys_enter_execve` | filename, argv |
| openat | `tracepoint/syscalls/sys_enter_openat` | filename, flags |
| connect | `tracepoint/syscalls/sys_enter_connect` | sockaddr (IP:Port) |

**event_t 结构体**（内核态与用户态共享）：

```c
struct event_t {
    u64  timestamp_ns;       // bpf_ktime_get_ns()
    u32  pid, ppid, uid;
    u8   event_type;         // 0=execve, 1=openat, 2=connect
    u8   blocked;            // 第一版固定为0
    union { exec/file/net }; // 根据 event_type 选择
    char comm[16];            // 进程名
};
```

> 注意：event_t 超过 512 字节 BPF 栈限制，使用 `BPF_MAP_TYPE_PERCPU_ARRAY` 作为事件缓冲区。

### 编译 eBPF 程序

```bash
cd observer_sim/ebpf

# 生成 vmlinux.h（内核类型定义，仅首次需要）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 编译
make    # 产出: observer.bpf.o (~50KB)

# 验证加载
sudo bpftool prog load observer.bpf.o /sys/fs/bpf/observer_test
```

### Python 加载器

`collector/ebpf_collector.py` 通过 Python `ctypes` 绑定 `libbpf.so`：

```python
# 加载 eBPF 程序 + 挂载探针 + 消费事件
from collector.ebpf_collector import EbpfCollector

config = {"ebpf": {"bpf_object_path": "ebpf/observer.bpf.o", "target_agent_id": "my-agent"}}
collector = EbpfCollector(config)
collector.attach(agent_id="my-agent")

for raw_event in collector.start():
    print(f"{raw_event.event_type}: pid={raw_event.pid}")
```

### 第一版限制

- eBPF 第一版仅做观测，`send_command()` 返回 `False`
- 阻断功能留待第二版（kprobe + `bpf_override_return`）
- 需要 root 权限或 `CAP_BPF + CAP_PERFMON` 能力

---

## 双环境开发指南

本项目采用 Windows 宿主机 + Linux 虚拟机的双环境开发架构：

```
┌──────────────────────────────────┐   ┌──────────────────────────────────┐
│ Windows 宿主机                     │   │ Linux VM (Ubuntu 22.04 LTS)        │
│ 模拟模式 + 核心逻辑验证              │   │ eBPF/strace 模式 + 真实采集验证    │
│                                    │   │                                    │
│ python main.py --mode simulation   │   │ sudo python3 main.py --mode ebpf │
│ python demo.py --auto              │   │ python3 main.py --mode strace    │
│ python app.py                      │   │ python3 app.py                   │
└──────────────────────────────────┘   └──────────────────────────────────┘
              │ Git push/pull 同步 │
              └─────────────────────┘
```

**Git 同步流程**：

```bash
# Windows 端开发完成后

git add -A
git commit -m "Day N: ..."
git push

# 切换到 Linux VM
git pull
python3 -m pytest -v     # 确认无回归
```

**环境搭建**：详细步骤请参考 [迁移方案.md](../docs/杂项文档/迁移方案.md)（从 VMware 创建到完整 eBPF 工具链安装）。

**环境预检**：两端均可运行 `python check_env.py`（进入 observer_sim/ 后）检查环境依赖。

---

## 相关文档

- [ARCHITECTURE.md](../docs/ARCHITECTURE.md) - 项目架构文档
- [eBPF 开发方案定稿](../docs/杂项文档/统一架构切换_eBPF%20数据输入模块开发方案定稿.md) - 统一架构设计与排期
- [迁移方案](../docs/杂项文档/迁移方案.md) - Linux 环境搭建指南（VMware + eBPF 工具链）
- [第一次交接](../docs/杂项文档/第一次交接.md) - Windows → Linux 交接文档（Phase 1-2 成果）
- [第二次交接](../docs/杂项文档/第二次交接.md) - Linux → Windows 交接文档（Phase 3 成果）
- [第三次交接](../docs/杂项文档/第三次交接.md) - Windows → Linux 交接文档（Phase 4-5 Windows 部分）
- [前端开发方案定稿](../docs/杂项文档/前端开发方案定稿.md) - Web 模式详细设计
- [测试场景清单](../docs/杂项文档/测试场景描述.md) - 37 个场景的详细描述与验收标准

---

## 扩展指南

本项目为教学原型，代码以可读性为优先。如需扩展：

1. **新增采集模式**：实现 `ICollector` 接口（参考 `collector/base_collector.py`），在 `adapter/platform_detect.py` 注册
2. **新增评分维度**：实现 `IRiskDimension` 接口并注册到 `RiskScorer`
3. **新增安全规则**：编辑 `rules/default_policy.yaml`
4. **新增演示场景**：参考 `scenarios/` 目录下 YAML 格式，或使用 `generate_scenarios.py`
5. **实现 eBPF 阻断**：新增 kprobe 程序 + `block_policy` map + `bpf_override_return`（第二版）
6. **实现自优化**：基于 `evolution/interfaces.py` 中的接口实现具体算法

---

## License

MIT License - 仅供教学与研究使用
