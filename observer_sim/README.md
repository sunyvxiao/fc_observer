# 方寸观察者模拟学习系统 (Fangcun Observer Simulation)

> 模拟 eBPF 行为监控系统的教学原型，通过 C++ 探针层 + Python 业务逻辑，演示 AI Coding Agent 的全链路行为监控与风险研判。

## 项目简介

**方寸观察者模拟学习系统**是一个教学原型，模拟真实 eBPF 行为监控系统的核心功能：

- **C++ 探针模拟层**：三类探针（进程/文件/网络），模拟 eBPF 内核级行为采集
- **Python 业务逻辑层**：事件归一化、规则匹配、四维风险评分、三级梯度阻断、审计输出
- **双向命名管道通信**：正向事件管道 + 反向指令管道，支持实时阻断反馈
- **虚拟时钟驱动**：纳秒级虚拟时间戳，保证全系统时间判定确定可复现
- **37 个测试场景**：覆盖正常/异常/边界/多Agent/极端 5 大分类

**技术栈**：Python 3.10+ / C++17 / CMake 3.15+ / Windows Named Pipe
**设计目标**：教学演示 > 生产性能，代码可读性优先，全链路透明可追踪

---

## 系统架构

```
┌──────────────────────────────────────────────────┐
│  场景 YAML → 事件生成器 → C++ 探针模拟层          │
│  ProcessProbe | FileProbe | NetworkProbe          │
│  EventFormatter + PipeWriter + CommandReader      │
└──────────────────┬───────────────────────────────┘
                   │  \\.\pipe\observer_events (正向 JSON行)
                   │  \\.\pipe\observer_commands (反向 JSON行)
                   ▼
┌──────────────────────────────────────────────────┐
│  Python Observer 核心引擎                         │
│                                                   │
│  [监测层] PipeReader → Normalizer → RuleEngine    │
│  [评判层] RiskScorer → Baseline → Decision        │
│  [阻断层] BlockingCoordinator → Tier1/2/3         │
│  [审计层] BehaviorGraph + AuditLogger + Report    │
│                                                   │
│  [虚拟时钟] VirtualClock 驱动全系统时间判定         │
│  [自优化]   ITraceStore/IPatternMiner/IGenerator  │
└──────────────────────────────────────────────────┘
```

**核心数据流**：事件采集 → 归一化 → 规则匹配 → 四维评分 → 研判决策 → 阻断执行 → 审计输出

---

## 核心功能模块

### 监测机制 (Phase 2)
- **EventNormalizer**：进程树维护、Agent 上下文追踪、事件窗口管理
- **RuleEngine**：YAML 策略加载、四类模式匹配（pattern/regex/exact/path_glob）
- **15 条初始安全策略**：覆盖命令执行（6）、文件操作（5）、网络（4）三大类

### 评判机制 (Phase 3)
- **RiskScorer**：四维加权评分（规则命中 40% + 基线偏离 25% + 上下文 20% + 序列异常 15%）
- **IRiskDimension 可替换接口**：每个评分维度均可独立替换算法实现
- **BaselineChecker**：正常行为基线构建 + 偏离检测 + 冷启动处理
- **DecisionEngine**：研判矩阵（风险等级 x 规则动作 → ALLOW/ALERT/BLOCK）
- **ChainReportBuilder**：因果链构建 + JSON/Markdown 双格式输出

### 阻断机制 (Phase 4)
- **BlockingCoordinator**：三级路由 + CommandSender 反向管道联动
- **AgentViolationTracker**：虚拟时钟滑动窗口违规升级（Tier1x3→Tier2, Tier2x2→Tier3）
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

---

## 环境要求

| 依赖 | 版本要求 | 说明 |
|------|---------|------|
| Python | >= 3.10（推荐 3.14+） | 业务逻辑层 |
| CMake | >= 3.15 | C++ 探针层编译 |
| Visual Studio Build Tools | 2019+ | 含 C++ 桌面开发工作负载 |
| pyyaml | 最新版 | `pip install pyyaml` |

### 安装步骤

```bash
# 1. 安装 Python 依赖
pip install pyyaml

# 2. 验证环境
python --version
cmake --version
```

---

## 快速开始

### 交互式演示（推荐）

```bash
cd observer_sim
python demo.py
```

启动后展示主菜单，包含三个核心选项：

```
┌──────────────────────────────────────────────────────────┐
│              方寸观察者模拟学习系统 — 主菜单               │
├──────────────────────────────────────────────────────────┤
│  1. 运行全部单元测试                                      │
│     调用 pytest 运行 130 个单元测试用例，显示结果摘要       │
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

37 个场景均内置了分析数据映射（`demo.py` 中的 `SA` 字典）。

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
# 运行全部测试（130 个）
python -m pytest -v

# 运行特定模块测试
python -m pytest tests/test_blocking.py -v    # Phase 4 阻断机制
python -m pytest tests/test_audit.py -v       # Phase 5 审计输出
python -m pytest tests/test_integration.py -v # Phase 6 集成测试
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
observer_sim/
├── main.py                         # 全场景运行入口（支持 --scenario/--category/--output）
├── demo.py                         # 交互式演示脚本（主菜单 + 场景分析面板）
├── config.yaml                     # 全局配置（管道名/评分权重/超时参数）
├── conftest.py                     # pytest 插件（unit_test 输出管理）
├── generate_scenarios.py           # 批量生成 37 个场景 YAML 的工具脚本
│
├── scenarios/                      # 场景定义 YAML（37 个，按分类组织）
│   ├── normal/                     # 正常行为 (N01-N08)
│   │   ├── n01_standard_development.yaml
│   │   ├── n02_dependency_install.yaml
│   │   └── ... (共 8 个)
│   ├── anomalous/                  # 异常行为 (A01-A12)
│   │   ├── a01_rm_root.yaml
│   │   ├── a02_curl_pipe_bash.yaml
│   │   └── ... (共 12 个)
│   ├── boundary/                   # 边界场景 (B01-B08)
│   │   ├── b01_rm_temp_dir.yaml
│   │   └── ... (共 8 个)
│   ├── multi_agent/                # 多Agent协作 (M01-M05)
│   │   ├── m01_legitimate_collaboration.yaml
│   │   └── ... (共 5 个)
│   └── extreme/                    # 极端场景 (E01-E04)
│       ├── e01_high_rate_events.yaml
│       └── ... (共 4 个)
│
├── rules/                          # 安全策略规则库
│   └── default_policy.yaml         # 15 条初始规则（命令6/文件5/网络4）
│
├── cpp_probe/                      # C++ 探针模拟层
│   ├── CMakeLists.txt
│   ├── main.cpp                    # 探针入口
│   ├── iprobe.h                    # IProbe 抽象接口
│   ├── process_probe.h             # 进程探针
│   ├── file_probe.h                # 文件探针
│   ├── network_probe.h             # 网络探针
│   ├── event_formatter.h           # 事件格式化器
│   ├── pipe_writer.h               # 正向管道写入器（含 RingBuffer）
│   ├── command_reader.h            # 反向管道读取器
│   ├── process_table.h/.cpp        # 简易进程表
│   ├── common.h                    # 公共数据结构
│   └── ring_buffer.h               # 环形缓冲区
│
├── observer_core/                  # Python Observer 核心引擎
│   ├── monitoring/                 # 监测机制
│   │   ├── pipe_reader.py          # 管道读取器
│   │   ├── event_normalizer.py     # 事件归一化器
│   │   └── rule_engine.py          # 规则引擎
│   ├── judgment/                   # 评判机制
│   │   ├── risk_scorer.py          # 多维评分器
│   │   ├── baseline_checker.py     # 基线检查器
│   │   ├── decision_engine.py      # 研判引擎
│   │   └── chain_report_builder.py # 链式报告构建器
│   ├── blocking/                   # 阻断机制
│   │   ├── blocking_coordinator.py # 三级阻断协调器
│   │   ├── command_sender.py       # 反向管道指令发送器
│   │   └── violation_tracker.py    # 违规追踪与升级
│   └── audit/                      # 审计与输出
│       ├── behavior_graph.py       # 行为图谱
│       ├── audit_logger.py         # JSON 行审计日志
│       ├── report_exporter.py      # Markdown 报告导出
│       └── output_path_manager.py  # 输出路径管理器（RunOutputManager）
│
├── evolution/                      # 自优化接口（预留）
│   └── interfaces.py               # ITraceStore/IPatternMiner/IStrategyGenerator
│
├── models/                         # 共享数据模型
│   ├── event.py                    # RawEvent / NormalizedEvent
│   ├── risk.py                     # RiskAssessment / Decision / BlockingResult
│   ├── command.py                  # Command（反向管道指令）
│   └── virtual_clock.py            # VirtualClock 虚拟时钟
│
├── tests/                          # 测试套件（130 个测试）
│   ├── test_virtual_clock.py       # Phase 1: 虚拟时钟（16）
│   ├── test_pipe_communication.py  # Phase 1: 管道通信（26）
│   ├── test_monitoring.py          # Phase 2: 监测机制（18）
│   ├── test_judgment.py            # Phase 3: 评判机制（21）
│   ├── test_blocking.py            # Phase 4: 阻断机制（16）
│   ├── test_audit.py               # Phase 5: 审计输出（16）
│   └── test_integration.py         # Phase 6: 集成测试（17）
│
└── output/                         # 运行输出目录（自动生成）
    ├── reports/                    # 场景报告（按分类+场景+时间戳归档）
    │   ├── normal/
    │   ├── anomalous/
    │   ├── boundary/
    │   ├── multi_agent/
    │   └── extreme/
    └── unit_test/                  # 单元测试输出（始终最新一次）
```

---

## 测试说明

项目采用四层测试体系，共 **130 个测试用例**，覆盖 Phase 1-6 全部功能：

| Phase | 测试文件 | 测试数量 | 覆盖内容 |
|:---:|---------|:---:|---------|
| 1 | test_virtual_clock.py | 16 | 虚拟时钟推进、边界、溢出、窗口判定 |
| 1 | test_pipe_communication.py | 26 | 事件序列化、指令序列化、Mock 管道、场景 YAML |
| 2 | test_monitoring.py | 18 | 归一化、进程树、规则匹配、Agent 上下文 |
| 3 | test_judgment.py | 21 | 四维评分、基线偏离、研判矩阵、链式报告 |
| 4 | test_blocking.py | 16 | 违规升级、三级阻断、反向管道、终止后丢弃 |
| 5 | test_audit.py | 16 | 行为图谱、审计日志、报告导出、跨 Agent 检测 |
| 6 | test_integration.py | 17 | 虚拟时钟一致性、边界条件、自优化接口、端到端 |
| **合计** | | **130** | **全部通过** |

```bash
# 运行全部测试
python -m pytest -v

# 运行特定 Phase 测试
python -m pytest tests/test_blocking.py -v
```

---

## 开发进度

全部 6 个阶段已完成：

| Phase | 内容 | 状态 | 测试 |
|-------|------|:---:|:---:|
| Phase 1 | 数据通道：C++ 探针 + 双向管道 + VirtualClock | 已完成 | 42 |
| Phase 2 | 监测机制：EventNormalizer + RuleEngine + 15 条规则 | 已完成 | 18 |
| Phase 3 | 评判机制：四维评分 + 基线 + 决策 + 链式报告 | 已完成 | 21 |
| Phase 4 | 阻断机制：三级阻断 + 违规升级 + 反向管道联动 | 已完成 | 16 |
| Phase 5 | 审计输出：行为图谱 + 审计日志 + Markdown 报告 | 已完成 | 16 |
| Phase 6 | 接口预留：自优化接口 + main.py + 集成测试 | 已完成 | 17 |

**后续迭代**：37 场景体系 + 输出目录重构 + demo.py 交互菜单 + conftest.py 插件

---

## 相关文档

- [开发方案定稿](../杂项文档/开发方案定稿.md) - 完整的系统设计与实施计划
- [项目描述](../杂项文档/项目描述.md) - 面向业务方的项目介绍
- [测试场景清单](../杂项文档/测试场景描述.md) - 37 个场景的详细描述与验收标准
- [初步调研报告](../杂项文档/初步调研报告.md) - 技术调研与可行性分析

---

## 扩展指南

本项目为教学原型，代码以可读性为优先。如需扩展：

1. **新增评分维度**：实现 `IRiskDimension` 接口并注册到 `RiskScorer`
2. **新增安全规则**：编辑 `rules/default_policy.yaml`
3. **新增演示场景**：参考 `scenarios/` 目录下分类子目录中的 YAML 格式，或使用 `generate_scenarios.py` 中的辅助函数
4. **实现自优化**：基于 `evolution/interfaces.py` 中的接口实现具体算法

---

## License

MIT License - 仅供教学与研究使用
