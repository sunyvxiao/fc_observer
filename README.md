# 方寸观察者模拟学习系统（Fangcun Observer Simulation）

> 让每一个 AI Agent 的行为都可控、可追溯、可信赖
> 于方寸之间，洞察秋毫。

**方寸观察者**是一个用于教学演示与概念验证的 **AI Agent 行为监测与响应系统**：模拟真实生产环境中安全监测平台的核心能力，完整复现「无感知采集 → 归一化 → 规则匹配 → 风险评分 → 研判决策 → 分级阻断 → 链式审计」的端到端流水线。系统支持 Windows 与 Linux 双平台、六种采集模式，并可将无法注入探针的黑盒 Agent（WorkBuddy、Qoder CN 等）通过 MCP 申报 / Hooks 确定性申报接入统一监测管线。

---

## 目录

- [项目简介](#项目简介)
- [核心功能](#核心功能)
- [架构总览](#架构总览)
- [快速开始](#快速开始)
- [使用说明](#使用说明)
- [测试与验证](#测试与验证)
- [配置与说明](#配置与说明)
- [相关文档](#相关文档)
- [贡献与维护](#贡献与维护)

---

## 项目简介

### 定位

AI 编程 Agent 正在大规模进入软件开发流程。它们能自主执行命令、读写文件、发起网络连接——**自主性越强，风险越大**：

- **误操作风险**：Agent 可能执行 `rm -rf /` 等破坏性命令，造成不可逆损失；
- **数据泄露风险**：Agent 可能读取凭据/密钥文件并外传；
- **串谋风险**：多个 Agent 协同作案——一个收集数据，一个传输数据；
- **信任缺失**：企业无法判断 Agent 行为是否合规，缺乏监管与追溯手段。

方寸观察者以「教学原型」的形式解决上述问题的**演示与验证**：在单机环境完整复现 Fangcun Observer 产品的核心架构——C++ 探针模拟 eBPF 内核采集、Python 实现全部业务逻辑，产出可观察、可调试、可修改、可扩展的教学级系统。

### 面向场景

| 场景 | 说明 |
|---|---|
| **课堂教学 / 演示汇报** | 37 个预设场景一键运行，Web 界面实时展示每个事件的处理流水线（归一化 → 规则 → 评分 → 研判 → 阻断 → 审计） |
| **安全机制验证** | 四维风险评分、三级梯度阻断、跨 Agent 串谋检测等机制的确定性回归验证 |
| **黑盒 Agent 接入演示** | 对无法注入探针的商业 Agent（WorkBuddy / Qoder CN）通过 MCP 申报与 Hooks 申报实现降级监测（合规留痕 + 风险提示） |
| **外部数据接入** | 录制-回放机制支持外部事件数据（JSONL/CSV）注入分析管线，实现跨环境迁移与事后审计 |

### 设计原则

- **全链路透明**：每个处理阶段的输入/输出均可查看、可追溯，不藏黑盒；
- **模块热插拔**：评分算法、阻断策略、采集方式均为可替换模块（抽象接口 + 工厂模式）；
- **核心零改动**：新增采集模式不触碰 `observer_core/` 核心引擎；
- **数据本地化**：所有输出为本地文件（JSONL / Markdown / JSON），不依赖网络、不上传云端。

---

## 核心功能

### 四大机制层

系统核心引擎（`observer_sim/observer_core/`）按四层机制组织，事件串行流经全链路：

| 层 | 模块 | 职责 |
|---|------|------|
| **监测层** `monitoring/` | `pipe_reader` / `event_normalizer` / `rule_engine` / `raw_event_factory` | 事件接入与归一化（进程树 + Agent 上下文追踪）、YAML 规则加载与匹配（pattern / regex / exact / path_glob 四类模式）、黑盒申报数据构造 |
| **研判层** `judgment/` | `risk_scorer` / `baseline_checker` / `decision_engine` / `chain_report_builder` | 四维加权评分、正常基线构建与偏离检测、研判矩阵决策（ALLOW / ALERT / BLOCK）、因果链报告构建 |
| **阻断层** `blocking/` | `blocking_coordinator` / `command_sender` / `violation_tracker` | 三级梯度阻断路由、反向管道指令下发、虚拟时钟滑动窗口违规升级 |
| **审计层** `audit/` | `behavior_graph` / `audit_logger` / `report_exporter` / `rollup_engine` / `file_manager` 等 | 行为图谱（含跨 Agent 关联与指纹边）、JSONL 审计日志（按天滚动）、Markdown 风险报告、分层日志金字塔（L0-L3）与产物管理 |

#### 1. 监测：全链路行为采集

- **进程事件**：命令执行（executable + arguments）；
- **文件事件**：读写删操作（file_path + file_op）；
- **网络事件**：连接行为（remote_addr + remote_port + protocol）；
- 事件归一化补充进程树关系、Agent 会话上下文与时间窗口信息。

#### 2. 研判：四维风险评分

综合评分 = Σ(维度分 × 权重)，范围 0.0 ~ 1.0，每个维度均可通过 `IRiskDimension` 接口独立替换：

| 维度 | 权重 | 说明 |
|------|:---:|------|
| 规则命中 | 40% | 命中危险模式的优先级得分（多条命中加分） |
| 基线偏离 | 25% | 与历史正常行为基线的偏离程度（冷启动期固定 0.0） |
| 上下文风险 | 20% | 滑动窗口内可疑行为序列（如「读密钥 → 外联」） |
| 序列异常 | 15% | 事件类型频率偏差（简化算法，可替换为马尔可夫链） |

风险等级：`LOW(<0.3)` / `MEDIUM(0.3~0.6)` / `HIGH(0.6~0.9)` / `CRITICAL(>0.9)`；研判矩阵输出 `ALLOW` / `ALERT` / `BLOCK` 决策。

#### 3. 阻断：三级梯度处置

在安全与业务连续性之间建立弹性空间，并通过反向管道将指令回传探针层：

| 级别 | 名称 | 系统动作 | 对 Agent 的影响 |
|:---:|------|---------|----------------|
| Tier1 | 软报告 | 记录告警 + 更新风险画像，下发 `allow` 指令 | 无，操作正常执行 |
| Tier2 | 阻止访问 | 标记 blocked + 阻断原因，下发 `block_event`（模拟 EPERM） | 当前操作被阻止，可继续其他操作 |
| Tier3 | 硬中断 | 终止进程树 + 证据紧急落盘 + 事故报告，下发 `terminate_process` | Agent 被强制终止 |

**违规升级机制**：同一 Agent 在虚拟时钟 5 分钟滑动窗口内累计 5 次 Tier1 → 升级 Tier2；累计 3 次 Tier2 → 升级 Tier3（阈值可配置）。

#### 4. 审计：全链路留痕

- **审计日志**：JSONL 格式，逐事件记录完整处理链路（L0，按天滚动、默认保留 30 天）；
- **行为图谱**：节点-边图结构，支持跨 Agent 关联检测与数据指纹边，结构化 JSON 留存；
- **风险报告**：Markdown 风险分析报告（因果链、评分明细、处置建议）自动生成；
- **分层日志金字塔**：L0 审计 / L1 监测摘要 / L2 分段汇总（含变化点检测与串谋判定）/ L3 最终报告；
- **报告一致性**：时间线、明细表、Agent 摘要、图谱四模块统一以阻断协调器最终判定为唯一数据源，杜绝自相矛盾。

### 六种采集模式

`config.yaml` 的 `mode` 字段支持：

| 模式 | 平台 | 说明 |
|------|:---:|------|
| `simulation` | 双端 | 场景 YAML + 虚拟时钟驱动（默认推荐，教学演示主模式） |
| `ebpf` | Linux | 真实内核 tracepoint 探针（execve/openat/connect），需 root 或 CAP_BPF |
| `strace` | Linux | ptrace 降级采集，无需内核特权 |
| `file_replay` | 双端 | 录制文件回放（JSONL / CSV），外部数据接入与事后审计 |
| `deep_agent` | 双端 | DeepAgent 框架集成采集（simulation / live 两档） |
| `mcp_report` | 双端 | 黑盒 Agent 主动申报模式（MCP 申报 + Hooks 确定性申报，见下） |

### 黑盒 Agent 降级监测（无侵入能力）

对于无法注入探针、无法在 Linux 运行或不开源的黑盒 Agent，系统提供**申报式降级监测**——Agent 行为由 Agent 侧主动申报，复用 `RawEventFactory` 进入统一监测管线，完整保留归一化、规则匹配、风险评分、审计与报告能力。

**已接入目标**：

| 目标 | 通道 | 接入产物 |
|------|------|---------|
| **Qoder CN** | P0：MCP 申报（标准 MCP Server，`http://127.0.0.1:8765/sse`）；P1：Hooks 确定性申报（`.lingma/settings.json` PostToolUse Hook → `scripts/qoder_hook_reporter.py` → `POST /api/hook-report`） | `qoder_report_gateway.py`（统一门面）、`adapter/hook_configs/qoder.yaml`（工具映射）、`qoder_integration/`（接入示例） |
| **WorkBuddy** | MCP 申报（三个申报 tool：`report_tool_call` / `report_action` / `report_session`） | `connect_workbuddy.py`（自动化接入，12 个子命令）、`mcp_report_gateway.py`（网关）、`workbuddy_connect.yaml`（集中配置）、`WorkBuddy降级监测适配/`（适配文档） |

**能力边界（如实声明）**：申报通道定位为「合规留痕 + 风险提示」，**不宣称安全防护**——事件完整性依赖 Agent 主动申报，无 syscall 交叉校验，BLOCK 仅报告层面标记（真实 PreToolUse 拦截回注属 P2 预留，未实现），时间戳为申报时刻。

### 其他能力

- **37 个测试场景**：5 大分类（正常 8 / 异常 12 / 边界 8 / 多 Agent 5 / 极端 4），内置四维分析面板数据；
- **21 条安全策略规则（v2.0）**：命令执行 9 条 + 文件操作 7 条 + 网络 5 条（R001-R020 + R007b）；
- **录制-回放**：任意采集器事件流可录制为 JSONL，经 `record_and_replay.py` 或 `file_replay` 采集器回放复现；
- **监测守护进程**：`observer.py daemon` 常驻实时监测（FIFO/命名管道 + 生命周期管理 + 报告生成）；
- **实时监测视图**：Web 端实时监测、MCP 申报、Qoder CN 三个监测视图，SSE 流式推送（Qoder 视图约 0.2s 上屏，3s 轮询兜底）。

---

## 架构总览

### 数据流

```
采集源（场景 YAML / eBPF / strace / 录制文件 / MCP 申报 / Hooks 申报）
    │  ICollector 抽象接口，统一产出 RawEvent
    ▼
监测层：PipeReader/申报接收 → EventNormalizer（进程树 + Agent 上下文） → RuleEngine（21 条规则）
    ▼
研判层：RiskScorer（四维加权，维度可替换） → BaselineChecker → DecisionEngine → ChainReportBuilder
    ▼
阻断层：BlockingCoordinator（Tier1/2/3 路由） → CommandSender（反向管道指令）
    ▼
审计层：BehaviorGraph（跨 Agent 关联） + AuditLogger（JSONL 按天滚动） + RollupEngine（分段汇总） + ReportExporter（Markdown）
    ▼
产物：output/<分区>/（审计 / 报告 / 摘要 / 图谱，分类归档）
```

核心管线统一由 `observer_core/pipeline_runner.py` 串行驱动；Web 与 CLI 共用同一套核心引擎（零改动）。

### 目录结构（简化）

```
projact3/
├── README.md                          # 本文档
├── observer_sim/                      # 核心项目（Python + C++）
│   ├── observer.py                    # 统一 CLI 入口（10 个子命令）
│   ├── app.py / console.py            # Web 服务 / 交互式控制台
│   ├── main.py / demo.py              # 批量运行 / 交互演示入口（保留兼容）
│   ├── monitor_daemon.py              # 实时监测守护进程
│   ├── monitor_lifecycle.py           # 进程生命周期管理（A 档）
│   ├── connect_workbuddy.py           # WorkBuddy 自动化接入（12 子命令）
│   ├── mcp_report_gateway.py          # WorkBuddy MCP 申报网关
│   ├── qoder_report_gateway.py        # Qoder CN 监测统一门面
│   ├── record_and_replay.py           # 录制-回放
│   ├── config.yaml / workbuddy_connect.yaml   # 全局配置 / WorkBuddy 集中配置
│   ├── observer_core/                 # 核心引擎（monitoring/judgment/blocking/audit + pipeline_runner）
│   ├── collector/                     # 采集层（ICollector + 6 种采集器 + 录制器）
│   ├── adapter/                       # 平台适配（platform_detect/pipe_factory/time_source/hook_configs）
│   ├── mcp_bridge/                    # MCP 服务（server/validation/semantic_guard/http_ingest）
│   ├── models/                        # 数据模型（event/risk/command/virtual_clock）
│   ├── rules/                         # 规则库（default_policy/judgment_pipeline/scoring_dimensions/tuning）
│   ├── scenarios/                     # 37 个场景 YAML（5 大分类）
│   ├── ebpf/                          # eBPF 内核探针 [仅 Linux]
│   ├── cpp_probe/                     # C++ 探针模拟层（CMake，保留兼容）
│   ├── static/index.html              # Web 前端（单文件，10 视图）
│   ├── tests/                         # 测试套件（969 个收集）
│   └── output/                        # 运行产物（运行时生成，gitignore）
├── docs/                              # 文档库（ARCHITECTURE.md + 杂项文档 + 软件工程文档 + 测试图片）
├── WorkBuddy降级监测适配/             # WorkBuddy 适配文档与工具
├── QoderCN监测端到端测试/             # Qoder CN 端到端测试（用例/脚本/验收报告）
├── qoder_integration/                 # Qoder CN 接入示例（mcp.json.example + 注册脚本）
├── scripts/                           # 工具脚本（qoder_hook_reporter.py / test.py 等）
├── tools/                             # 辅助工具
├── deep-agents-demo/                  # DeepAgent 演示工作目录
└── 测试图片/                           # 界面测试截图
```

---

## 快速开始

### 环境要求

| 依赖 | 版本 | 用途 | 必选 |
|------|------|------|:---:|
| Python | >= 3.10 | 全部业务逻辑（已在 3.10 ~ 3.14 验证） | ✅ |
| pyyaml | 最新版 | 配置与场景解析 | ✅ |
| pytest | 7.4+ | 测试套件 | ✅（跑测试时） |
| mcp | 最新版 | MCP 申报模式（黑盒 Agent 监测） | ⬜ 按需 |
| CMake + VS Build Tools | 3.15+ / 2019+ | C++ 探针编译（可选增强） | ⬜ 按需 |
| clang / bpftool / libbpf-dev / linux-headers / strace | — | Linux eBPF/strace 采集 | ⬜ 仅 Linux |

### 安装依赖

```bash
# Windows（PowerShell）
cd observer_sim
pip install pyyaml pytest

# 黑盒 Agent 监测通道（WorkBuddy / Qoder CN）额外需要
pip install mcp
```

Linux 环境完整工具链安装参见 [docs/杂项文档/迁移方案.md](docs/杂项文档/迁移方案.md)。

### 环境预检

```bash
cd observer_sim
python check_env.py        # 或统一入口: python observer.py env
```

预检覆盖基础环境、Python 依赖、项目文件完整性、模块导入、MCP 通道与 C++ 工具链（可选项）。

### 统一入口与最小可用示例

所有能力通过统一入口 `observer.py` 提供（10 个子命令）：

```bash
cd observer_sim

# 1) 运行单个场景（CLI 流水线，含分析面板与报告产物）
python observer.py run --scenario a01

# 2) 启动 Web 服务（默认 http://localhost:8080，自动打开浏览器）
python observer.py serve

# 3) 交互式控制台（编号菜单 + 短命令直达）
python observer.py menu

# 4) 启动实时监测守护进程
python observer.py daemon

# 5) 启动黑盒 Agent 监测（Qoder CN MCP 申报 + Hooks 申报，端口 8765）
python observer.py daemon --mode mcp_report --output output/qoder_monitoring

# 6) 运行测试（unit | api | sse | all）
python observer.py test unit
```

**首次上手建议路径**：`observer.py env` 预检 → `observer.py serve` 打开 Web → 在「场景」视图运行 a01（高危命令）观察实时流水线 → 查看分析面板与风险报告。

---

## 使用说明

### 统一 CLI 子命令一览

| 子命令 | 说明 | 常用参数 |
|--------|------|---------|
| `run` | 运行场景流水线（CLI 模式） | `--scenario a01` `--category anomalous` `--mode simulation` `--output <dir>` |
| `serve` | 启动 Web 服务（转发 app.py） | `--host 127.0.0.1 --port 8080 --no-browser` |
| `daemon` | 实时监测守护进程 | `--mode mcp_report` `--fifo <path>` `--output <dir>` `--ebpf` `--record` `--generate-report` `--pid-file <f>` |
| `demo` | 交互式演示（转发 demo.py） | `--auto` `--scenario a01` `--category anomalous` |
| `files` | 文件管理（六区产物浏览/查看/删除） | `tree` `view <path>` `delete <path>` `del-cat <c>` |
| `reports` | 报告管理（OutputFileManager） | `list` `view <path>` |
| `samples` | 样例与工具（check-env / gen-scenarios） | — |
| `env` | 环境配置检测 | — |
| `test` | 统一测试入口 | `unit` `api` `sse` `all` |
| `menu` | 命令行交互控制台 | 编号菜单 + 短命令（`qoder start`、`files tree` 等） |

### Web 与 CLI 两种交互方式

**Web 模式**（推荐演示）：`python observer.py serve`，浏览器访问 `http://localhost:8080`，提供 10 个视图：

场景浏览运行、实时监测（FIFO daemon）、MCP 申报监测（WorkBuddy）、Qoder CN 监测（启动/注入/SSE 实时流）、Agent 模拟、场景样例、录制回放、文件管理（六区产物树）、测试运行、环境检查。

- 场景运行通过 SSE 逐步推送每个事件的处理结果，结束后展示四维分析面板；
- 报告支持三级折叠树浏览（分类 → 场景 → 时间戳）与删除；
- 前端为零依赖单文件实现（`static/index.html`），服务端基于 Python 标准库。

**CLI 模式**：`python observer.py menu` 或 `python demo.py`，支持编号菜单与短命令直达，适合终端调试与脚本化操作；控制台覆盖场景运行、WorkBuddy / Qoder CN 监测域、文件管理等功能。

### 场景运行

```bash
cd observer_sim

python observer.py run --scenario a01          # 单个场景（A01：rm -rf / 高危命令）
python observer.py run --category anomalous    # 整个分类（12 个异常场景）
python observer.py run --scenario all          # 全量 37 场景

python observer.py demo --auto                 # 演示模式：全场景自动播放
python observer.py demo --category boundary    # 按分类交互浏览
```

场景清单与预期判定见 [docs/杂项文档/测试场景描述.md](docs/杂项文档/测试场景描述.md)；每次运行产物按「分类 → 场景 → 时间戳」归档于 `output/reports/`，同秒冲突自动追加编号，永不覆盖历史。

### 黑盒 Agent 监测

**Qoder CN（当前 IDE）**：

```bash
cd observer_sim
python observer.py daemon --mode mcp_report --output output/qoder_monitoring   # 启动监测（端口 8765）
python -c "import qoder_report_gateway as g; print(g.simulate('run_in_terminal', {'command':'rm -rf /'}))"  # 模拟注入
python -c "import qoder_report_gateway as g; print(g.stop())"                  # 停止并生成报告
```

接入真实环境：注册 MCP（`bash qoder_integration/register_observer_mcp.sh <目标项目目录>`）与 Hooks（`.lingma/settings.json` 注册 `scripts/qoder_hook_reporter.py`），详见 [QoderCN监测端到端测试/使用说明.md](QoderCN监测端到端测试/使用说明.md)。

**WorkBuddy**：

```bash
cd observer_sim
python connect_workbuddy.py --help     # 12 个子命令（start/stop/status/check/smoke/logs/configure-workbuddy/launch-workbuddy/report 等）
python connect_workbuddy.py start      # 启动 MCP 申报 daemon
python connect_workbuddy.py smoke      # 模拟申报烟测
python connect_workbuddy.py stop       # 停止并生成验证报告
```

详见 [WorkBuddy降级监测适配/WorkBuddy降级监测使用说明书.md](WorkBuddy降级监测适配/WorkBuddy降级监测使用说明书.md)。

### 录制与回放

```bash
# 录制：daemon 附加 --record 将管道事件流旁路保存为 JSONL
python observer.py daemon --record --output output/records

# 回放：从录制文件（JSONL / CSV）重放事件流进入监测管线
python record_and_replay.py --replay-only <路径>.jsonl
```

> 说明：`observer.py run --mode` 仅接受 `auto/simulation/strace/ebpf`；`file_replay` 模式通过 `config.yaml` 的 `mode: file_replay` + `data_file` 由采集工厂加载（`loop` / `time_scale` 为预留配置项，尚未实现）。详见 [docs/杂项文档/录制回放使用说明.md](docs/杂项文档/录制回放使用说明.md)。

---

## 测试与验证

### 测试入口

```bash
cd observer_sim
python observer.py test unit          # 单元测试（等价 python -m pytest tests/）
python observer.py test api           # API 端点测试（需 Web 服务运行）
python observer.py test sse           # SSE 流式测试（需 Web 服务运行）
python observer.py test all           # 全部
```

测试结果同时写入 `output/unit_test/`（`test_results.json` + `test_output.txt`，始终保留最新一次）。

### 基线结果

**Windows 端全量回归**（本机，2026-09-03 M2 里程碑复测）：`1014` 个测试收集，`1004 passed + 7 skipped + 3 failed`。

较基线（2026-07-31 实测：`969` 收集，`959 passed + 7 skipped + 3 failed`）**新增 45 个测试全部通过**（开发计划 M1：T1.1 提示词 v2.1 / T1.2 instructions 自动注入 / T1.3 连接器健康看门狗 / T1.4 申报完整性核对 共 21 项；M2：T3.1 进程快照交叉校验 24 项）；3 个失败与基线完全相同（见下），无回归。

> 3 个失败均为「Linux 环境提交在 Windows 端的配套缺失」，**非核心检测管线缺陷**：
>
> 1. `test_monitor_lifecycle.py::test_shutdown_terminates_tracked_process` —— 测试使用 Linux `sleep` 命令与 `/proc` 文件系统，Windows 无此环境；
> 2. `test_monitor_lifecycle.py::test_untracked_process_survives_shutdown` —— 同上；
> 3. `test_qoder_hook_reporter.py::test_lingma_settings_template_valid` —— 校验仓库根 `.lingma/settings.json` Hook 模板文件，该模板需在真实 Qoder CN 环境注册时生成、未随仓库提交。

**Linux 端验证**：Qoder CN 监测通道端到端验收（2026-09-01）——判定能力 **10/11**（唯一缺口：`qoder.yaml` 缺 `delete_file` 映射致 R009 漏报，属配置级小修复）、通道承诺 4/4（覆盖率/字段完整性/生命周期/产物）、Web 实测 6/6。详见 [QoderCN监测端到端测试/验收报告_20260901_193448.md](QoderCN监测端到端测试/验收报告_20260901_193448.md)。

WorkBuddy 通道端到端验证见 [WorkBuddy降级监测适配/端到端验证结果与差距清单.md](WorkBuddy降级监测适配/端到端验证结果与差距清单.md)。

### 端到端测试目录

| 目录 | 内容 |
|------|------|
| `QoderCN监测端到端测试/` | 17 条用例（A~D 组 15 条可模拟注入执行，E 组 2 条需真实 Qoder CN）、`run_e2e.py` 一键脚本（启动 → 注入 11 条判定用例 → 停止 → 审计/产物核验）、验收报告与差距清单 |
| `WorkBuddy降级监测适配/` | 端到端用例、验证差距清单、使用说明与安全提示词方案 |

### 已知差异说明

以下为当前代码实现中的已知情况，如实记录（以代码为准）：

1. **三入口统计口径不一致**：研判矩阵修订 2.1 引入「BLOCK@TIER1 软阻断」（留痕 + 告警，无真实拦截通道）。守护进程（`monitor_daemon.py`）已按修订 2.1 口径统计并显示「🔵 BLOCK(软)」；CLI（`observer.py run`）与 Web 的逐事件统计仍按旧口径，将 BLOCK@TIER1 计为放行（显示 `PASS` / 「放行」）。审计日志与风险报告不受影响，均以研判决策（BLOCK）为准；
2. **file_replay 高级配置未实现**：`config.yaml` 中 `loop` / `time_scale` 为预留配置项，`FileReplayCollector` 尚未实现循环回放与时间缩放；
3. **部分场景 YAML 期望值滞后**：如 `a01_rm_root.yaml` 标注「Tier2 BLOCK」，现行研判矩阵（修订 2.1）下实际为 BLOCK@TIER1（软阻断），报告时间线仍显示 BLOCK；
4. **`.env.example` 模板未入库**：代码提示参考该模板，实际需按 `env_config.py` 的键名自行创建 `.env`。
5. **WorkBuddy 通道无 MCP Hook 拦截机制**：T2.0 实测（2026-09-03）WorkBuddy 无 PreToolUse/PostToolUse Hook 注册与执行机制（UI 无入口 + mcp.json 无 hooks 字段 + 产物静态分析无运行时执行器），事前拦截不可承载、第 2 层关闭；申报仍为「合规留痕 + 风险提示」定位，详见 `WorkBuddy降级监测适配/WorkBuddy Hook 支持性验证报告.md`；
6. **WorkBuddy 申报完整性核对属申报侧口径**：报告「申报完整性核对」小节与覆盖置信度（高/中/低）仅反映申报侧完整性（会话闭合、申报连续性），不代表行为覆盖；`jsonl_dir` 未配置时如实标注「完整性核对跳过」；
7. **instructions 自动注入依赖平台消费**：`configure-workbuddy` 写入的 `mcp.json` `instructions` 字段需 WorkBuddy 消费才生效（2026-09-03 实测本机版本已消费）；不消费时回退手动粘贴提示词路径；
8. **进程快照交叉校验为边界比对（T3.1）**：会话 start/end 两个边界时刻的 psutil 进程快照差异与申报记录比对，窗口内启动又退出的瞬时进程不可见；白名单外新增进程仅标记「疑似二级操作」告警（不拦截、需人工研判）；快照失败时如实标注「不可用」；`crosscheck_process.enabled` 缺省 false，仅 `workbuddy_connect.yaml` 启用后生效；
9. **交叉校验配置链路**：`workbuddy_connect.yaml` 的 `observer.crosscheck_process` 经 `connect_workbuddy.py start` 写入临时 config 的 `mcp_report` 段（`agent_process_dirs` 自动派生自 `workbuddy.install_dir`）；直接 `python observer.py daemon --mode mcp_report` 启动时按 `config.yaml` 的 `crosscheck_process.enabled`（默认 false）。

---

## 配置与说明

### config.yaml 关键配置项

| 配置段 | 关键项 | 说明 |
|--------|--------|------|
| `mode` | `auto` | 默认采集模式（`auto` 自动检测平台） |
| `pipeline` | `win_event_pipe` / `linux_event_fifo` 等 | 跨平台管道名 |
| `simulation` | `scenarios_dir` / `virtual_clock_start_ns` | 模拟模式场景目录与虚拟时钟起点 |
| `ebpf` | `bpf_object_path` / `target_pid` | eBPF 探针产物路径与目标进程（运行时 `--pid` 指定） |
| `strace` | `strace_bin` / `trace_syscalls` | strace 二进制与捕获 syscall 集合 |
| `file_replay` | `data_file`（`loop` / `time_scale` 预留未实现） | 回放文件路径（JSONL / CSV 自动识别） |
| `deep_agent` | `mode`（simulation/live） | DeepAgent 采集档位（live 需 `ANTHROPIC_API_KEY`） |
| `mcp_report` | `framework` / `port` / `hook_ingest` | 黑盒申报通道：框架映射（`qoder`）、监听端口（8765）、Hooks 摄入开关 |
| `scoring` | `dimensions.*.weight` / `risk_levels` | 四维评分权重与风险等级阈值 |
| `blocking` | `violation_window_ms` / `tier1_to_tier2_threshold` | 违规升级窗口与阈值 |
| `output` | `retention_days` | L0 审计文件按天滚动保留天数 |
| `scenarios` | 37 个场景路径清单 | 全量场景注册 |

### 规则与调优文件（rules/）

| 文件 | 说明 |
|------|------|
| `default_policy.yaml` | 21 条安全策略规则（v2.0：命令 9 / 文件 7 / 网络 5），新增规则直接编辑此文件 |
| `judgment_pipeline.yaml` | 研判流水线配置（评分阈值 + 升级规则） |
| `scoring_dimensions.yaml` | 四维评分权重与偏离分配置 |
| `tuning.yaml` | 评分调优参数（基线最小事件数等热/冷参数） |
| `evolution_interface.yaml` | 自进化接口配置（ITraceStore / IPatternMiner / IStrategyGenerator） |

### 其他配置

- **workbuddy_connect.yaml**：WorkBuddy 通道集中配置（daemon 输出目录等，`connect_workbuddy.py` 与 `mcp_report_gateway.py` 共用）；
- **.env**（项目根目录，可选）：`env_config.py` 按「环境变量 > .env > 默认值」优先级加载敏感配置（LLM API Key 等）；代码提示可参考 `.env.example` 模板，但该模板文件未随仓库提交，需按 `env_config.py` 的键名自行创建。模拟模式无需任何密钥；
- **adapter/hook_configs/qoder.yaml**：Qoder CN 工具名 → 事件类型映射（含原生名与兼容名双套），`delete_file` 条目缺口见端到端差距清单 G1。

---

## 相关文档

**核心文档**（`docs/`）：

- [架构文档 ARCHITECTURE.md](docs/ARCHITECTURE.md) —— 目录树、数据流图、接口定义、平台差异与设计决策；
- [开发方案定稿](docs/杂项文档/开发方案定稿.md) —— 完整系统设计与实施计划（四层机制/双向管道/虚拟时钟）；
- [统一架构切换 eBPF 开发方案定稿](docs/杂项文档/统一架构切换_eBPF%20数据输入模块开发方案定稿.md) —— 采集层统一架构设计；
- [第二阶段长期计划](docs/杂项文档/第二阶段长期计划.md) —— 阶段计划与进度记录（含未修复问题/未实现需求清单）；
- [项目描述](docs/杂项文档/项目描述.md) —— 项目背景、功能亮点与演示效果；
- [测试场景描述](docs/杂项文档/测试场景描述.md) —— 37 个场景的详细描述与验收标准；
- [迁移方案](docs/杂项文档/迁移方案.md) —— Linux 环境搭建指南（VMware + eBPF 工具链）；
- [前端开发方案定稿](docs/杂项文档/前端开发方案定稿.md) —— Web 模式详细设计；
- 交接文档（[第一次](docs/杂项文档/第一次交接.md) ~ [第五次](docs/杂项文档/第五次交接.md)）—— 各阶段成果交接记录。

**通道文档**：

- [WorkBuddy 降级监测使用说明书](WorkBuddy降级监测适配/WorkBuddy降级监测使用说明书.md)
- [Qoder CN 端到端测试使用说明](QoderCN监测端到端测试/使用说明.md) ｜ [验收报告](QoderCN监测端到端测试/验收报告_20260901_193448.md) ｜ [差距清单](QoderCN监测端到端测试/端到端验证结果与差距清单.md)

**其他**：`observer_sim/README.md` 为早期阶段详细草稿（部分数字如测试用例数已过时，以本文档为准）。

---

## 贡献与维护

本项目为教学原型，代码以可读性优先。扩展建议：

1. **新增采集模式**：实现 `collector/base_collector.py` 的 `ICollector` 接口，在 `adapter/platform_detect.py` 工厂注册（核心引擎零改动）；
2. **新增评分维度**：实现 `IRiskDimension` 接口并注册到 `RiskScorer`；
3. **新增安全规则**：编辑 `rules/default_policy.yaml`（≤100 条规模，启动时全量加载）；
4. **新增演示场景**：参考 `scenarios/` 下 YAML 格式（或用 `generate_scenarios.py` 批量生成），并补充 `analysis_panels.py` 分析面板数据；
5. **实现真实阻断**：eBPF 第二版（kprobe + `bpf_override_return`）或 MCP PreToolUse 拦截回注（P2 预留）；
6. **实现自优化**：基于 `evolution/interfaces.py` 的三个预留接口（ITraceStore / IPatternMiner / IStrategyGenerator）。

**维护约定**：

- 提交前请运行 `python observer.py test unit` 确认无回归；
- 文档与代码不一致时，以当前代码实现为准，并及时修正文档；
- 运行产物（`output/`、`.monitoring/`、`.pytest_basetemp/` 等）与历史备份（`.backup_*/`）不入库，规则见根目录 `.gitignore`。

---

## License

MIT License —— 仅供教学与研究使用。
