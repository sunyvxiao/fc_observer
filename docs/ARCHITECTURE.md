# 方寸观察者模拟学习系统 — 架构文档

> **版本**: v1.0 | **最后更新**: 2026-07  
> **项目性质**: 教学模拟系统 | **技术栈**: Python 3.10+ / C++17 / CMake 3.15+

---

## 一、项目目录树与模块职责

```
projact3/
├── observer_sim/                      # 核心项目目录
│   ├── main.py                        # CLI 入口（全场景运行）
│   ├── demo.py                        # 交互式演示脚本（主菜单 + 分析面板）
│   ├── app.py                         # Web 模式入口（HTTP Server + SSE）
│   ├── config.yaml                    # 全局配置（管道名/评分权重/超时参数）
│   ├── conftest.py                    # pytest 插件（unit_test 输出管理）
│   ├── generate_scenarios.py          # 场景 YAML 批量生成工具
│   ├── analysis_panels.py             # 场景分析面板数据（SA 字典）
│   │
│   ├── cpp_probe/                     # C++ 探针模拟层（模拟 eBPF）
│   │   ├── CMakeLists.txt             # CMake 构建配置
│   │   ├── main.cpp                   # 探针入口
│   │   ├── common.h                   # 公共数据结构（RawEvent/Command/EventSpec）
│   │   ├── iprobe.h                   # IProbe 抽象接口
│   │   ├── process_probe.h            # 进程探针（execve/fork/clone）
│   │   ├── file_probe.h               # 文件探针（openat/unlink/rename）
│   │   ├── network_probe.h            # 网络探针（connect/sendto/DNS）
│   │   ├── event_formatter.h          # 事件格式化器（RawEvent → JSON）
│   │   ├── pipe_writer.h              # 正向管道写入器（含 RingBuffer）
│   │   ├── command_reader.h           # 反向管道读取器（非阻塞轮询）
│   │   ├── process_table.h/.cpp       # 简易进程表（pid → ProcessInfo）
│   │   └── ring_buffer.h              # 环形缓冲区（写入失败暂存）
│   │
│   ├── observer_core/                 # Python Observer 核心引擎
│   │   ├── monitoring/                # 监测机制层
│   │   │   ├── pipe_reader.py         # 管道读取器（正向管道 C++→Python）
│   │   │   ├── event_normalizer.py    # 事件归一化器（进程树 + Agent 上下文）
│   │   │   └── rule_engine.py         # 规则引擎（YAML 策略加载 + 四类匹配）
│   │   │
│   │   ├── judgment/                  # 评判机制层
│   │   │   ├── risk_scorer.py         # 多维风险评分器（四维加权 + IRiskDimension）
│   │   │   ├── baseline_checker.py    # 基线检查器（正常行为基线 + 偏离检测）
│   │   │   ├── decision_engine.py     # 研判引擎（研判矩阵 + 风险定级）
│   │   │   └── chain_report_builder.py# 链式报告构建器（因果链 + JSON/Markdown）
│   │   │
│   │   ├── blocking/                  # 阻断机制层
│   │   │   ├── blocking_coordinator.py# 三级阻断协调器（Tier1/2/3 路由）
│   │   │   ├── command_sender.py      # 反向管道指令发送器（Python→C++）
│   │   │   └── violation_tracker.py   # 违规追踪器（滑动窗口 + 自动升级）
│   │   │
│   │   └── audit/                     # 审计与输出层
│   │       ├── behavior_graph.py      # 行为图谱（节点图 + 跨 Agent 关联）
│   │       ├── audit_logger.py        # JSON 行审计日志
│   │       ├── report_exporter.py     # Markdown 风险分析报告导出
│   │       └── output_path_manager.py # 输出路径管理器（RunOutputManager）
│   │
│   ├── evolution/                     # 自优化接口（预留，不实现）
│   │   └── interfaces.py              # ITraceStore/IPatternMiner/IStrategyGenerator
│   │
│   ├── models/                        # 共享数据模型
│   │   ├── event.py                   # RawEvent / NormalizedEvent / AgentContext
│   │   ├── risk.py                    # RiskAssessment / Decision / BlockingResult
│   │   ├── command.py                 # Command（反向管道指令）
│   │   └── virtual_clock.py           # VirtualClock（虚拟时钟子系统）
│   │
│   ├── scenarios/                     # 场景定义 YAML（37 个，按分类组织）
│   │   ├── normal/                    # 正常行为 (N01-N08, 8 个)
│   │   ├── anomalous/                 # 异常行为 (A01-A12, 12 个)
│   │   ├── boundary/                  # 边界场景 (B01-B08, 8 个)
│   │   ├── multi_agent/               # 多 Agent 协作 (M01-M05, 5 个)
│   │   └── extreme/                   # 极端场景 (E01-E04, 4 个)
│   │
│   ├── rules/                         # 安全策略规则库
│   │   └── default_policy.yaml        # 15 条初始规则（命令6/文件5/网络4）
│   │
│   ├── tests/                         # 测试套件（130 个测试）
│   │   ├── test_virtual_clock.py      # Phase 1: 虚拟时钟（16 个）
│   │   ├── test_pipe_communication.py # Phase 1: 管道通信（26 个）
│   │   ├── test_monitoring.py         # Phase 2: 监测机制（18 个）
│   │   ├── test_judgment.py           # Phase 3: 评判机制（21 个）
│   │   ├── test_blocking.py           # Phase 4: 阻断机制（16 个）
│   │   ├── test_audit.py              # Phase 5: 审计输出（16 个）
│   │   └── test_integration.py        # Phase 6: 集成测试（17 个）
│   │
│   ├── static/                        # Web 前端静态文件
│   │   └── index.html                 # 单页应用
│   │
│   └── output/                        # 运行输出目录（自动生成）
│       ├── reports/                   # 场景报告（按分类+场景+时间戳归档）
│       └── unit_test/                 # 单元测试输出（始终最新一次）
│
└── 杂项文档/                          # 项目文档库
    ├── prd.md                         # 产品需求文档
    ├── 项目描述.md                     # 项目介绍
    ├── 开发方案定稿.md                 # 完整系统设计与实施计划
    ├── 测试场景描述.md                 # 37 个场景详细描述
    └── ...                            # 其他文档
```

---

## 二、核心数据流图

### 2.1 全链路处理流水线

```
场景 YAML 文件
    │
    ▼
[场景加载器] ──读取场景定义──→ [事件生成器] ──逐条生成事件规格──→ [C++ 探针层]
                                                                      │
                                                            ┌─────────┴─────────┐
                                                            │ ProcessProbe      │
                                                            │ FileProbe         │
                                                            │ NetworkProbe      │
                                                            │ EventFormatter    │
                                                            │ PipeWriter        │
                                                            │ CommandReader     │
                                                            └─────────┬─────────┘
                                                                      │
         ┌────────────────────────────────────────────────────────────┘
         │  \\.\pipe\observer_events (正向·JSON行)
         ▼
[PipeReader] ──RawEvent──→ [EventNormalizer] ──NormalizedEvent──→ [RuleEngine]
                              ↑ 维护进程树                              │
                              ↑ 维护Agent上下文                    匹配YAML策略
                              ↑ 虚拟时钟驱动时间窗口               输出命中规则列表
                                                                        │
                                                                        ▼
                                                                  [RiskScorer]
                                                                  四维加权评分
                                                                  (算法可替换)
                                                                        │
                                    ┌───────────────────────────────────┼──────────────────┐
                                    ▼                                   ▼                  ▼
                              [BaselineChecker]                  [DecisionEngine]   [ChainReportBuilder]
                              计算偏离程度                        决定处置等级        构建因果链报告
                                    │                                   │                  │
                                    └───────────────┬───────────────────┘                  │
                                                    ▼                                      │
                              ┌───────────────────────────────────┐                        │
                              │    BlockingCoordinator             │                        │
                              │    + CommandSender (反向管道)      │                        │
                              │  Tier1: 软报告 → 记录+通知         │                        │
                              │  Tier2: 阻止访问 → 返回EPERM       │                        │
                              │  Tier3: 硬中断 → 终止进程           │                        │
                              └───────────────┬───────────────────┘                        │
                                              │                                            │
                          ┌───────────────────┼───────────────────┐                        │
                          ▼                   ▼                   ▼                        │
                    [行为图谱]          [审计日志]          [报告导出器]  ←──────────────────┘
                    简化有向图           JSON行证据链        Markdown风险分析报告
                    (结构化JSON)        (output/audit/)    (output/reports/)
                    (output/graphs/)
```

### 2.2 双向管道通信

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    C++ 探针层 (OS Kernel Layer)                           │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │ ProcessProbe │  │  FileProbe   │  │ NetworkProbe │                   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                   │
│         └─────────────────┼─────────────────┘                           │
│                  ┌────────▼────────┐                                    │
│                  │  EventFormatter │                                    │
│                  └────────┬────────┘                                    │
│                           │                                              │
│              ┌────────────▼────────────┐                                │
│              │      PipeWriter         │                                │
│              │   + RingBuffer (1024)   │                                │
│              └────────────┬────────────┘                                │
│                           │                                              │
│              ┌────────────▼────────────┐                                │
│              │    CommandReader        │                                │
│              │   (非阻塞轮询)           │                                │
│              └────────────┬────────────┘                                │
└───────────────────────────┼──────────────────────────────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │ 事件管道(正向)    │                   │ 指令管道(反向)
         │ \\.\pipe\        │                   │ \\.\pipe\
         │ observer_events  │                   │ observer_commands
         │ JSON行 →         │                   │ ← JSON行
         ▼                  │                   │
┌──────────────────────────────────────────────────────────────────────────┐
│                    Python Observer 核心引擎                               │
│                                                                          │
│  [PipeReader] ──→ [EventNormalizer] ──→ [RuleEngine] ──→ [RiskScorer]   │
│                                                                │         │
│  [CommandSender] ←── [BlockingCoordinator] ←── [DecisionEngine] ←┘       │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.3 虚拟时钟驱动范围

```
VirtualClock (纳秒精度, Python int 任意精度)
    │
    ├─→ EventFormatter: 事件 timestamp_ns 由虚拟时钟生成
    ├─→ EventNormalizer: 事件序列窗口超时清理
    ├─→ AgentViolationTracker: 违规升级的 5 分钟滑动窗口
    ├─→ BaselineChecker: 时间模式偏离分析
    └─→ ChainReportBuilder: 因果链中步骤间时间差
```

---

## 三、关键接口定义与类继承关系

### 3.1 C++ 侧接口

```cpp
// === IProbe (抽象探针接口) ===
class IProbe {
public:
    virtual bool attach(int target_pid, const std::string& agent_id) = 0;
    virtual RawEvent capture(const EventSpec& spec) = 0;
    virtual void detach() = 0;
    virtual std::string name() const = 0;
    virtual ~IProbe() = default;
};

// 继承关系:
// IProbe
//   ├─ ProcessProbe  (execve/fork/clone)
//   ├─ FileProbe     (openat/unlink/rename)
//   └─ NetworkProbe  (connect/sendto/DNS)

// === 数据结构 ===
struct EventSpec { type, agent_id, exe, args, path, op, addr, port, protocol, pid, ppid };
struct RawEvent { event_id, timestamp_ns, event_type, pid, ppid, agent_id, ... };
struct Command { cmd_id, cmd_type, target_event_id, target_pid, action, reason, timestamp_ns };
struct ProcessInfo { pid, ppid, agent_id, executable, terminated, children };

// === 工具类 ===
class EventFormatter { std::string format(const RawEvent& event) const; };
class PipeWriter {
    bool open(const std::string& pipe_name);
    bool write(const std::string& json_line);  // 非阻塞, 失败暂存 RingBuffer
    void flush();                               // 补发 RingBuffer 中的暂存事件
    void close();
private:
    RingBuffer<std::string, 1024> buffer_;
};
class CommandReader {
    bool open(const std::string& pipe_name);
    std::optional<Command> poll();  // 非阻塞轮询, 无数据返回 nullopt
    void close();
};
```

### 3.2 Python 侧核心接口

```python
# === 管道通信接口 ===
class IPipeReader(ABC):
    def connect(self, pipe_name: str) -> bool: ...
    def read_event(self) -> Optional[RawEvent]: ...  # 非阻塞
    def disconnect(self) -> None: ...

class ICommandSender(ABC):
    def connect(self, pipe_name: str) -> bool: ...
    def send_command(self, cmd: Command) -> bool: ...
    def disconnect(self) -> None: ...

# === 监测层接口 ===
class IEventNormalizer(ABC):
    def normalize(self, raw: RawEvent) -> NormalizedEvent: ...
    def get_agent_context(self, agent_id: str) -> AgentContext: ...
    def get_recent_events(self, agent_id: str, n: int) -> List[NormalizedEvent]: ...

class IRuleEngine(ABC):
    def load_rules(self, yaml_path: str) -> None: ...
    def match(self, event: NormalizedEvent) -> MatchResult: ...
    def add_rule(self, rule: PolicyRule) -> None: ...
    def remove_rule(self, rule_id: str) -> None: ...

# === 评判层接口 ===
class IRiskDimension(ABC):
    @abstractmethod
    def score(self, event, match, context, baseline) -> float: ...
    @abstractmethod
    def name(self) -> str: ...
    @property
    @abstractmethod
    def weight(self) -> float: ...

class IRiskScorer(ABC):
    def assess(self, event, match, context, baseline) -> RiskAssessment: ...
    def register_dimension(self, dim: IRiskDimension) -> None: ...

class IDecisionEngine(ABC):
    def adjudicate(self, assessment: RiskAssessment) -> Decision: ...
    def get_escalation_tier(self, agent_id: str) -> Tier: ...

# === 阻断层接口 ===
class IBlockingExecutor(ABC):
    def execute(self, decision: Decision, event: NormalizedEvent) -> BlockingResult: ...

# === 审计层接口 ===
class IChainReportBuilder(ABC):
    def start_chain(self, trigger_event) -> ChainId: ...
    def add_step(self, chain_id, event, causal_link: str) -> None: ...
    def finalize(self, chain_id) -> ChainStructuredReport: ...
    def to_json(self, report) -> str: ...
    def to_markdown(self, report) -> str: ...

class IBehaviorGraph(ABC):
    def add_node(self, event, risk: RiskAssessment): ...
    def add_edge(self, parent_id, child_id, relation: str): ...
    def to_structured_json(self) -> str: ...
    def get_agent_subgraph(self, agent_id: str) -> SubGraph: ...
```

### 3.3 自优化预留接口（不实现，仅定义）

```python
class ITraceStore(ABC):
    def store(self, record: TraceRecord) -> None: ...
    def query(self, filters: TraceQuery) -> List[TraceRecord]: ...
    def export(self, from_ts, to_ts) -> Iterator[TraceRecord]: ...

class IPatternMiner(ABC):
    def mine_sequence_patterns(self, traces) -> List[SequencePattern]: ...
    def mine_frequency_anomalies(self, traces) -> List[FreqAnomaly]: ...

class IStrategyGenerator(ABC):
    def generate(self, patterns) -> List[PolicyRule]: ...
    def validate(self, rule, traces) -> ValidationResult: ...
    def export_to_yaml(self, rules, path: str): ...
```

### 3.4 类继承关系图

```
ABC (抽象基类)
 ├─ IProbe (C++)
 │   ├─ ProcessProbe
 │   ├─ FileProbe
 │   └─ NetworkProbe
 │
 ├─ IPipeReader
 │   └─ PipeReader
 │
 ├─ ICommandSender
 │   └─ CommandSender / MockCommandSender
 │
 ├─ IEventNormalizer
 │   └─ EventNormalizer
 │
 ├─ IRuleEngine
 │   └─ RuleEngine
 │
 ├─ IRiskDimension
 │   ├─ BasicRuleScore (D1: 规则命中分, 40%)
 │   ├─ BasicBaselineScore (D2: 基线偏离分, 25%)
 │   ├─ BasicContextScore (D3: 上下文风险分, 20%)
 │   └─ BasicSequenceScore (D4: 序列异常分, 15%)
 │
 ├─ IRiskScorer
 │   └─ RiskScorer
 │
 ├─ IDecisionEngine
 │   └─ DecisionEngine
 │
 ├─ IBlockingExecutor
 │   └─ BlockingCoordinator
 │
 ├─ IBehaviorGraph
 │   └─ BehaviorGraph
 │
 └─ IChainReportBuilder
     └─ ChainReportBuilder
```

---

## 四、核心数据模型

### 4.1 事件模型

```python
@dataclass
class RawEvent:
    event_id: str
    timestamp_ns: int
    event_type: str           # "exec" | "file_open" | "net_conn"
    pid: int
    ppid: int
    agent_id: str
    agent_framework: str
    executable: Optional[str]
    arguments: Optional[List[str]]
    file_path: Optional[str]
    file_op: Optional[str]
    remote_addr: Optional[str]
    remote_port: Optional[int]
    protocol: Optional[str]

@dataclass
class NormalizedEvent:
    raw: RawEvent
    agent_context: Optional[AgentContext]
    process_node: Optional[ProcessNode]
    command_string: Optional[str]
    is_blocked: bool
    block_reason: Optional[str]

@dataclass
class AgentContext:
    agent_id: str
    framework: str
    pids: List[int]
    event_count: int
    recent_events: List[NormalizedEvent]  # 滑动窗口
    max_recent: int = 10
```

### 4.2 风险模型

```python
class RiskLevel(str, Enum):
    LOW = "LOW"           # < 0.3
    MEDIUM = "MEDIUM"     # 0.3 ~ 0.6
    HIGH = "HIGH"         # 0.6 ~ 0.9
    CRITICAL = "CRITICAL" # > 0.9

class ActionTier(str, Enum):
    TIER1 = "TIER1"  # 软报告
    TIER2 = "TIER2"  # 阻止访问
    TIER3 = "TIER3"  # 硬中断

class DecisionAction(str, Enum):
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    BLOCK = "BLOCK"

@dataclass
class RiskAssessment:
    overall_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    dimension_scores: List[DimensionScore]
    matched_rule_ids: List[str]
    highest_rule_action: str = "allow"
    confidence: float = 0.0

@dataclass
class Decision:
    action: DecisionAction
    tier: ActionTier
    assessment: Optional[RiskAssessment]
    reason: str
    event_id: str
    agent_id: str

@dataclass
class BlockingResult:
    blocked: bool
    tier: ActionTier
    reason: str
    cmd_id: str
    event_id: str
    details: str
```

### 4.3 指令模型

```python
class CmdType(str, Enum):
    ALLOW = "allow"
    BLOCK_EVENT = "block_event"
    TERMINATE_PROCESS = "terminate_process"
    HEARTBEAT = "heartbeat"

@dataclass
class Command:
    cmd_id: str
    cmd_type: str
    target_event_id: Optional[str]
    target_pid: Optional[int]
    action: Optional[str]
    reason: Optional[str]
    timestamp_ns: int

    # 工厂方法
    @classmethod
    def make_allow(cls, cmd_id, event_id, timestamp_ns) -> "Command": ...
    @classmethod
    def make_block(cls, cmd_id, event_id, pid, reason, timestamp_ns) -> "Command": ...
    @classmethod
    def make_terminate(cls, cmd_id, pid, reason, timestamp_ns) -> "Command": ...
    @classmethod
    def make_heartbeat(cls, cmd_id, timestamp_ns) -> "Command": ...
```

---

## 五、平台差异点汇总

### 5.1 Windows 特化

| 组件 | 平台差异 | 说明 |
|------|---------|------|
| **命名管道** | `\\.\pipe\observer_events` | Windows Named Pipe API (CreateFile/WriteFile/ReadFile) |
| **C++ 探针层** | Win32 API | 使用 Windows 命名管道而非 POSIX FIFO |
| **PipeWriter** | 非阻塞写入 | PeekNamedPipe + WriteFile |
| **CommandReader** | 非阻塞轮询 | PeekNamedPipe 检查数据可用性 |

### 5.2 跨平台适配层

| 适配点 | 当前实现 | 跨平台方案 |
|--------|---------|-----------|
| 管道通信 | Windows Named Pipe | POSIX: mkfifo + select/poll |
| JSON 序列化 | C++ 手写 escape_json_string | 可引入 nlohmann/json |
| 进程表 | std::unordered_map | 通用，无平台差异 |
| RingBuffer | 模板类 RingBuffer<T, N> | 通用，无平台差异 |

### 5.3 降级策略

| 场景 | 降级方案 |
|------|---------|
| C++ 编译失败 | 使用 MockCommandSender，纯 Python 模拟模式 |
| 管道连接失败 | 指数退避重连（1s/2s/4s，最多3次） |
| 反向管道超时 | C++ 侧降级为"全放行"模式 |
| 管道写满 | RingBuffer 暂存，恢复后 FIFO 补发 |

---

## 六、配置体系

### 6.1 config.yaml 核心配置

```yaml
pipes:
  events: "\\\\.\\pipe\\observer_events"
  commands: "\\\\.\\pipe\\observer_commands"
  connect_timeout_ms: 5000
  heartbeat_interval_ms: 1000
  heartbeat_max_miss: 3

virtual_clock:
  start_ns: 1718092800000000000  # 2024-06-11 08:00:00 UTC

scoring:
  dimensions:
    rule_match: { weight: 0.40, class: "BasicRuleScore" }
    baseline_deviation: { weight: 0.25, class: "BasicBaselineScore" }
    context_risk: { weight: 0.20, class: "BasicContextScore" }
    sequence_anomaly: { weight: 0.15, class: "BasicSequenceScore" }
  risk_levels:
    low_max: 0.3
    medium_max: 0.6

blocking:
  violation_window_ms: 300000  # 5分钟
  tier1_to_tier2_threshold: 3
  tier2_to_tier3_threshold: 2

monitoring:
  event_window_size: 10
  process_window_ms: 60000

baseline:
  cold_start_deviation: 0.0
  min_events_for_baseline: 20
```

### 6.2 规则文件格式

```yaml
# rules/default_policy.yaml
version: "1.0"
metadata:
  created: "2026-01-01"
  description: "默认安全策略"

rules:
  - rule_id: "R001"
    name: "block-dangerous-commands"
    category: "command"          # command | file | network
    priority: 100                # 0-100, 越高越优先
    enabled: true
    action: block                # block | alert | allow
    description: "阻断已知高危系统命令"
    conditions:
      event_type: "exec"
      match_mode: "pattern"      # pattern | exact | regex | path_glob
      patterns:
        - "rm -rf /"
        - "dd if=/dev/zero"
        - "mkfs"
        - "curl.*\\|.*bash"
```

### 6.3 场景文件格式

```yaml
scenario:
  id: a01-rm-root
  name: A01-高危系统命令:递归删除根目录
  description: Agent执行rm -rf /
  expected_result: Tier2 BLOCK
  category: anomalous
  agents:
    - agent_id: rogue-1
      framework: AutoGen
      initial_pid: 20001
  event_sequence:
    - seq: 1
      delay_ms: 0
      agent: rogue-1
      type: exec
      executable: /bin/rm
      arguments: [-rf, /, --no-preserve-root]
```

---

## 七、输出目录结构

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
│   ├── boundary/
│   ├── multi_agent/
│   └── extreme/
│
└── unit_test/                               # 单元测试输出（始终最新一次）
    ├── test_results.json                    # 结构化测试结果
    └── test_output.txt                      # 可读文本摘要
```

---

## 八、核心设计决策

| 决策点 | 方案 | 理由 |
|--------|------|------|
| C++↔Python 通信 | 双向命名管道 | 解决阻断反馈回路，架构清晰 |
| 事件序列化 | JSON 行协议 | 人类可读，调试友好 |
| 时间模型 | 虚拟时钟 (VirtualClock) | 确定性强，运行速度快，适合教学 |
| 审计存储 | 仅 JSON 行文件 | 教学原型足够，降低开发量 |
| 风险算法 | IRiskDimension 可替换接口 | 先跑通，后续可拓展 |
| 图谱输出 | 结构化 JSON 为主 | 保障严谨溯源，降低开发复杂度 |
| 报告输出 | Markdown + 结构化 JSON | 用户可读 + 程序可解析 |
| 进程树存储 | dict[int, ProcessNode] + 懒删除 | 事件量小，无需外部数据库 |
| 规则加载 | 启动时全量加载到内存 | 规则量小 (<100 条) |
| 管道容错 | RingBuffer 暂存 + 指数退避重连 | 保证事件不丢失 |

---

## 九、扩展指南

### 9.1 新增评分维度

```python
# 1. 实现 IRiskDimension 接口
class MyCustomScore(IRiskDimension):
    def score(self, event, match, context, baseline) -> float:
        # 自定义评分逻辑
        return 0.0
    
    def name(self) -> str:
        return "my_custom_score"
    
    @property
    def weight(self) -> float:
        return 0.10

# 2. 注册到 RiskScorer
scorer = RiskScorer()
scorer.register_dimension(MyCustomScore())

# 3. 在 config.yaml 中配置权重
scoring:
  dimensions:
    my_custom_score:
      weight: 0.10
      class: "MyCustomScore"
```

### 9.2 新增安全规则

编辑 `rules/default_policy.yaml`：

```yaml
- rule_id: "R016"
  name: "detect-crypto-mining"
  category: "command"
  priority: 90
  action: block
  conditions:
    event_type: "exec"
    match_mode: "pattern"
    patterns:
      - "xmrig"
      - "minerd"
      - "cpuminer"
```

### 9.3 新增测试场景

参考 `scenarios/` 目录下分类子目录中的 YAML 格式，或使用 `generate_scenarios.py` 中的辅助函数。

---

*方寸观察者 — 于方寸之间，洞察秋毫。*
