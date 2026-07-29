# 方寸观察者模拟学习系统 — 开发方案定稿

> **项目性质**：教学模拟系统 | **目标平台**：Windows 单机 | **语言**：Python（主）+ C++（探针层）| **版本**：v1.0-final

---

## 一、项目定义

### 1.1 一句话描述

模拟 Fangcun Observer「OS 层无感知采集 → 风险评分 → 分级阻断 → 链式审计 → 自进化」完整数据管道。C++ 模拟 eBPF 探针层，Python 实现全部业务逻辑，单机 Windows 环境复现核心架构，产出可观察、可调试、可修改的教学级原型。

### 1.2 产品能力对齐

| 产品核心能力 | 对应模块 | 覆盖度 |
|------------|---------|:---:|
| 无感知 Runtime 观测 | C++ 探针 + 命名管道 + 归一化 | ✅ |
| 实时主动阻断 | 四维评分 → 研判矩阵 → 三级阻断 | ✅ |
| 全链路审计追责 | 链式因果报告 + 行为图谱 + JSON 审计 | ✅ |
| 本地自进化防御 | ITraceStore/IPatternMiner/IStrategyGenerator 接口 | ⚠️ 接口预留 |
| 数据本地不上云 | 全部输出本地文件 | ✅ |

### 1.3 设计原则

- **全链路透明**：每阶段 I/O 可打印可追溯，无黑盒
- **模块热插拔**：评分算法、阻断策略、输出格式均可替换（通过抽象接口）
- **零外部依赖**：Python 仅需 `pyyaml`，C++ 仅标准库 + Win32 API
- **算法可替换**：风险评分各维度均实现 `IRiskDimension` 接口

---

## 二、系统架构

### 2.1 分层架构

```
┌──────────────────────────────────────────────┐
│  场景 YAML → 事件生成器 → C++ 探针模拟层      │
│  ProcessProbe │ FileProbe │ NetworkProbe      │
│  EventFormatter + PipeWriter + CommandReader  │
└──────────────────┬───────────────────────────┘
                   │  \\.\pipe\observer_events (正向·JSON行)
                   │  \\.\pipe\observer_commands (反向·JSON行)
                   ▼
┌──────────────────────────────────────────────┐
│  Python Observer 核心引擎                     │
│                                              │
│  [监测层] PipeReader → Normalizer → RuleEngine│
│  [评判层] RiskScorer → Baseline → Decision   │
│  [阻断层] BlockingCoordinator → Tier1/2/3    │
│  [审计层] BehaviorGraph + AuditLogger + Report│
│                                              │
│  [虚拟时钟] VirtualClock 驱动全系统时间判定    │
│  [自优化接口] ITraceStore/IMiner/IGenerator   │
└──────────────────────────────────────────────┘
```

### 2.2 双向管道通信

| 管道 | 方向 | 名称 | 用途 |
|------|------|------|------|
| 事件管道 | C++ → Python | `observer_events` | 探针上报系统调用事件 |
| 指令管道 | Python → C++ | `observer_commands` | 下发阻断/放行决策 |

**指令类型**：`allow`（放行）、`block_event`（返回 EPERM）、`terminate_process`（终止进程树）、`heartbeat`（心跳）

### 2.3 虚拟时钟

VirtualClock 按场景 `delay_ms` 推进纳秒级虚拟时间，驱动全系统（事件时间戳、滑动窗口、基线分析、升级判定、因果链时间差）统一时钟源，保证运行结果确定、可复现。

---

## 三、监测机制

### 3.1 C++ 探针层

| 探针 | 模拟的系统调用 | 捕获字段 |
|------|-------------|---------|
| ProcessProbe | execve/fork/clone | executable, arguments, env_vars |
| FileProbe | openat/unlink/rename | file_path, file_op, file_flags |
| NetworkProbe | connect/sendto/DNS | remote_addr, remote_port, protocol |

- 维护简易进程表（`pid → ProcessInfo`），execve 自动注册，子进程继承 agent_id
- PipeWriter 内含 RingBuffer(1024)，管道满时暂存，恢复后 FIFO 补发
- CommandReader 每事件处理后非阻塞轮询反向管道，500ms 超时降级放行

### 3.2 事件协议

```json
{
  "event_id": "evt_001", "timestamp_ns": 1718092800000000000,
  "event_type": "execve", "pid": 12345, "ppid": 12340,
  "agent_id": "code-agent-1", "agent_framework": "LangChain",
  "executable": "/bin/rm", "arguments": ["-rf", "/"],
  "file_path": null, "file_op": null,
  "remote_addr": null, "remote_port": null, "protocol": null
}
```

### 3.3 Python 规则引擎

YAML 规则三类 15 条初始规则：

| 类别 | 数量 | 典型规则 |
|------|:---:|---------|
| 命令执行 | 6 | `rm -rf /`、`curl\|bash`、`mkfs`、`dd`、`chmod 777`、sudo 提权 |
| 文件操作 | 5 | 敏感文件(.env/*.pem)、批量删除、写系统目录、权限变更 |
| 网络 | 4 | 外联非白名单 IP、DNS 可疑域名、大流量外传、非标端口 |

匹配流程：**类别筛选 → 模式匹配(pattern/regex/exact/path_glob) → 上下文验证 → 命中收集**

---

## 四、评判机制

### 4.1 四维评分（均可替换）

| 维度 | 权重 | 基础算法 |
|------|:---:|---------|
| D1 规则命中 | 40% | `最高优先级/100 + 多命中加成` |
| D2 基线偏离 | 25% | 时间/路径/网络/频率四子维度加权，冷启动期固定 0.0 |
| D3 上下文风险 | 20% | 滑动窗口内 "读敏感文件+外联" 等可疑序列检测 |
| D4 序列异常 | 15% | 事件类型频率偏差（简化版），冷启动期(<20事件)固定 0.0 |

综合评分 = Σ(维度分 × 权重) | LOW<0.3 | MEDIUM 0.3-0.6 | HIGH>0.6

每维度实现 `IRiskDimension` 接口，`config.yaml` 中切换实现类。

### 4.2 研判矩阵

| 风险\规则 | 命中 block | 命中 alert | 未命中 |
|----------|:---:|:---:|:---:|
| HIGH | **BLOCK** | BLOCK | ALERT |
| MEDIUM | ALERT | ALERT | ALLOW |
| LOW | ALLOW | ALLOW | ALLOW |

### 4.3 链式结构化报告

结构：`报告头 → 因果链(CauseStep[]) → 评分明细 → 影响评估 → 处置建议`

双输出格式：
- **JSON** → `output/audit/chain_report_*.json`（严谨溯源）
- **Markdown** → `output/reports/风险分析报告_*.md`（含评分明细表及因果链，用户可读）

---

## 五、阻断机制

### 5.1 三级梯度

| | Tier 1 软报告 | Tier 2 阻止访问 | Tier 3 硬中断 |
|---|---|---|---|
| **触发** | MEDIUM；或 HIGH+alert 规则 | HIGH+block 规则；或 Tier1×3 | 评分>0.9；或 Tier2×2 |
| **操作** | 放行 | 返回 EPERM | 终止进程树 |
| **反向指令** | `allow` | `block_event` | `terminate_process` |
| **审计** | 标准记录 | 详细记录+阻断原因 | 紧急写入+事故报告 |
| **图谱** | 橙色节点 | 红色节点 | 红色+告警标签 |

### 5.2 升级机制

AgentViolationTracker 在虚拟时钟 5 分钟滑动窗口内计数：
- Tier1 累计 ≥3 次 → 升级 Tier2
- Tier2 累计 ≥2 次 → 升级 Tier3
- 窗口过期自动清除

---

## 六、场景设计

| 场景 | 事件 | 预期阻断 | 预期告警 | 演示重点 |
|------|:---:|:---:|:---:|------|
| 场景1: 正常开发 | 8 | 0 | 0 | 全链路通过，冷启动建立基线 |
| 场景2: 危险操作 | 6 | 2 | 1 | Tier2 阻断 + 链式报告 + 升级路径 |
| 场景3: Multi-Agent 串谋 | 8 | 1 | 2 | 跨 Agent 检测 + 进程树 + 行为图谱 |

执行流程：`加载 config → 启动 C++ 探针 → 初始化 VirtualClock → 逐条事件(推进时钟→探针捕获→管道传输→全链路处理→阻断反馈)→ 导出报告`

---

## 七、核心接口

### C++ 侧

```
IProbe       : attach/capture/detach
EventFormatter: format(RawEvent) → JSON
PipeWriter   : open/write(非阻塞+RingBuffer)/flush/close
CommandReader: open/poll(非阻塞)/close
```

### Python 侧

```
IPipeReader       : connect/read_event(非阻塞)/disconnect
ICommandSender    : connect/send_command/disconnect
IEventNormalizer  : normalize/get_agent_context/get_recent_events
IRuleEngine       : load_rules/match/add_rule/remove_rule
IRiskScorer       : assess/register_dimension
IRiskDimension    : score/name/weight  (可替换算法接口)
IDecisionEngine   : adjudicate/get_escalation_tier
IBlockingExecutor : execute → BlockingResult
IChainReportBuilder: start_chain/add_step/finalize/to_json/to_markdown
IBehaviorGraph    : add_node/add_edge/to_structured_json
```

### 自优化接口（仅定义，不实现）

`ITraceStore` / `IPatternMiner` / `IStrategyGenerator`

---

## 八、开发排期（13 天）

| 阶段 | 天数 | 核心交付 |
|------|:---:|---------|
| Phase 1: 数据通道 | 1-2 | 三类探针 + 双向管道 + VirtualClock + 联调 |
| Phase 2: 监测机制 | 3-4 | Normalizer + RuleEngine + 15 条初始规则 + 场景1 验证 |
| Phase 3: 评判机制 | 5-7 | IRiskDimension + 四维评分 + Baseline + ChainReport + DecisionEngine |
| Phase 4: 阻断机制 | 8-10 | BlockingCoordinator + Tier1/2/3 + ViolationTracker + 反向管道联动 |
| Phase 5: 审计输出 | 11-12 | BehaviorGraph(JSON) + AuditLogger + Markdown 报告导出 |
| Phase 6: 收尾 | 13 | 自优化接口桩 + 边界测试 + 降级清单验证 |

---

## 九、降级清单（排期紧张时）

| 优先级 | 降级项 | 降级方案 |
|:---:|------|------|
| 1 | 图谱可视化 | 仅输出结构化 JSON |
| 2 | 自优化实现 | 保留接口定义文件即可 |
| 3 | C++ 反向管道 | 降级为纯 Python 模拟模式 |
| 4 | 序列异常分 D4 | 固定返回 0.0 |
| 5 | 管道容错 RingBuffer | 写入失败丢弃 + 告警 |

---

## 十、目录结构

```
observer_sim/
├── main.py                    # 入口: python main.py --scenario all
├── config.yaml                # 管道名/评分权重/超时参数
├── scenarios/                 # 三个场景 YAML
├── rules/                     # default_policy.yaml (15条) + evolved_policy.yaml [预留]
├── cpp_probe/                 # IProbe + 三类探针 + PipeWriter + CommandReader
├── observer_core/
│   ├── monitoring/            # PipeReader + Normalizer + RuleEngine
│   ├── judgment/              # IRiskDimension + Scorer + Baseline + ChainReport + Decision
│   ├── blocking/              # Coordinator + CommandSender + Tier1/2/3 + ViolationTracker
│   └── audit/                 # BehaviorGraph + AuditLogger + ReportExporter
├── evolution/                 # [预留] interfaces + 接口桩
├── models/                    # Event/Rule/Risk/Report/Command/VirtualClock
├── output/                    # audit/ | reports/ | graphs/ | baselines/
└── tests/                     # 单元测试 (管道/规则/评分/阻断/报告/时钟)
```

---

## 十一、边界条件与容错

| 场景 | 处理 |
|------|------|
| 管道断开 | PipeReader 指数退避重连（1s/2s/4s，最多3次）；CommandReader 降级全放行 |
| 管道写满 | RingBuffer 暂存，恢复后 FIFO 补发 |
| 冷启动无基线 | 偏离分固定 0.0，场景结束后自动保存基线 |
| 规则文件异常 | 错误规则跳过告警，不中断运行 |
| Agent 已终止后的事件 | 丢弃 + 记录警告 |
| 心跳超时（连续3次） | 标记对端不可达，按降级策略运行 |

---

## 总结

> **C++ 层模拟 eBPF 三类探针，通过双向命名管道与 Python 层 JSON 行通信；Python 层实现「归一化→规则匹配→四维可替换评分→基线偏离→研判→三级梯度阻断→链式报告」完整管道，虚拟时钟驱动全系统；审计纯 JSON 行文件，报告 Markdown 输出；自优化三个接口预留。总代码量 2500-3500 行，三场景一键运行，全链路透明可追踪、算法可替换、报告可阅读。**