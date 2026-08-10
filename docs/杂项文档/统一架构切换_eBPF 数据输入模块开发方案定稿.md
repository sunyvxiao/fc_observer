# 统一架构切换 & eBPF 数据输入模块 — 开发方案定稿

> **目标**：将当前 Windows 模拟系统升级为 Windows/Linux 统一架构。Windows 保留模拟探针 + 场景回放（测试/训练），Linux 新增 eBPF 探针采集真实 Agent syscall（生产观测）。两套系统共用 `observer_core/`，通过平台检测自动切换采集层。
>
> **定稿说明**：基于初稿审查，修正了以下关键问题：① 数据流路径统一为 ICollector 直接 yield RawEvent（不走管道）；② eBPF 第一版仅做观测，阻断作为后续迭代（规避 `bpf_override_return` 不支持 tracepoint 的技术限制）；③ config.yaml 全量保留现有字段并新增；④ 排期从 8 天调整为 10 天；⑤ 补充了多 Agent 场景适配、Web 模式对接、RawEvent 字段映射等遗漏细节。

---

## 第一部分：总览

### 1.1 一句话定义

在现有模拟系统基础上新增 Linux eBPF 探针采集层，通过 `adapter/` 层封装平台差异（管道、时间模型、采集模式），`collector/` 层封装不同采集方案（模拟探针/strace/eBPF），入口自动检测平台并选择对应模式，`observer_core/` 全程零改动。

### 1.2 核心设计原则

| 原则 | 实现方式 |
|------|---------|
| **核心零改动** | `observer_core/`、`models/`、`scenarios/`、`rules/` 不修改任何代码 |
| **采集层可插拔** | `ICollector` 抽象接口，模拟探针 / strace / eBPF 分别为实现类 |
| **平台差异封装** | `adapter/` 层集中处理管道差异、时间源差异、路径分隔符差异 |
| **模式自动检测** | `main.py` / `demo.py` / `app.py` 启动时检测 `sys.platform`，自动选择采集模式 |
| **直接 yield 数据流** | `ICollector.start()` 返回 `Iterator[RawEvent]`，上层直接消费，不经过管道中转 |
| **CLI/Web 通用** | `demo.py` 和 `app.py` 共用同一套模式选择逻辑 |

### 1.3 架构升级路径

```
升级前 (当前):
  场景 YAML → [C++ 模拟探针] → Windows 命名管道 → [Python Observer (Windows)]
  虚构事件    虚构 syscall                         全管道逻辑

升级后 (统一架构):

  Windows (模拟模式):
    场景 YAML → SimulationCollector(封装YAML→RawEvent) ─┐
                                                        │
  Linux (eBPF 模式):                                    ├→ [Python Observer] → 输出
    真实 Agent → EbpfCollector(eBPF→RawEvent) ──────────┤   observer_core/ 零改动
                                                        │
  Linux (strace 降级模式):                               │
    真实 Agent → StraceCollector(strace→RawEvent) ──────┘
```

> **关键变化**：数据流不再经过管道中转。`ICollector.start()` 直接 yield `RawEvent` 对象，上层（demo.py/app.py/main.py）直接消费并送入 `observer_core/` 处理链路。这保留了现有 demo.py/app.py 的运行模式，同时为 Linux 上的真实采集提供统一接口。

---

## 第二部分：统一架构设计

### 2.1 分层架构图

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    入口层 (main.py / demo.py / app.py)                     │
│                                                                          │
│  职责: 解析 CLI 参数(--mode) → 加载 config.yaml → 平台检测 → 创建Collector │
│        消费 ICollector.start() 返回的 RawEvent 迭代器 → 送入处理链路       │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     适配层 (adapter/)            [新增 ~140 行]            │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐   │
│  │ platform_detect  │  │ pipe_factory      │  │ time_source          │   │
│  │ · sys.platform   │  │ · Win命名管道创建  │  │ · 模拟: VirtualClock │   │
│  │ · 模式决策       │  │ · Linux FIFO创建   │  │ · 真实: time.time_ns │   │
│  │ · 能力查询       │  │ · 统一 open_pipe() │  │                      │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────────┘   │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     采集层 (collector/)          [新增 ~580 行]            │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    ICollector (抽象接口)                           │   │
│  │  + attach(target_pid, agent_id) → bool                           │   │
│  │  + start() → Iterator[RawEvent]   # 直接yield，不走管道          │   │
│  │  + send_command(cmd: Command) → bool   # 反向阻断指令             │   │
│  │  + detach() → None                                               │   │
│  │  + get_process_tree() → dict                                     │   │
│  │  + capabilities → CollectorCapabilities  # 能力查询              │   │
│  └──────────┬───────────────────┬──────────────────┬────────────────┘   │
│             │                   │                  │                    │
│  ┌──────────▼──────┐ ┌─────────▼──────┐ ┌─────────▼──────────────┐    │
│  │ Simulation-     │ │ Strace-        │ │ EbpfCollector           │    │
│  │ Collector       │ │ Collector      │ │                         │    │
│  │ (Windows/通用)  │ │ (Linux降级)    │ │ (Linux, 内核eBPF观测)   │    │
│  │                 │ │                │ │                         │    │
│  │ 场景YAML加载    │ │ subprocess     │ │ libbpf 加载 .bpf.o     │    │
│  │ → RawEvent生成  │ │ strace -p PID  │ │ + perf ring buffer     │    │
│  │ + 虚拟时钟推进   │ │ → RawEvent解析 │ │ → RawEvent构造          │    │
│  │ + 多Agent支持   │ │ · 仅观测       │ │ · 仅观测(第一版)        │    │
│  └─────────────────┘ └───────────────┘ └────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                  CollectorCapabilities (能力描述)                   │   │
│  │  · name: str                 # "Simulation"|"Strace"|"Ebpf"     │   │
│  │  · can_observe: bool         # 是否支持观测                      │   │
│  │  · can_block_tier2: bool     # 是否支持 Tier2 阻断(返回EPERM)    │   │
│  │  · can_block_tier3: bool     # 是否支持 Tier3 阻断(终止进程)     │   │
│  │  · is_transparent: bool      # 对Agent是否无感知                 │   │
│  │  · performance_overhead: str # "low"|"medium"|"high"            │   │
│  │  · time_source: str          # "virtual"|"realtime_monotonic"   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ 统一输出: RawEvent 对象 (直接yield)
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              核心逻辑层 (observer_core/)              [零改动]             │
│                                                                          │
│  EventNormalizer → RuleEngine → RiskScorer                              │
│  → DecisionEngine → BlockingCoordinator → BehaviorGraph → AuditLogger   │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 平台检测与模式决策流程

```
main.py / demo.py / app.py 启动
    │
    ▼
读取 config.yaml → mode 字段 (默认 "auto")
    │
    ├── mode = "simulation" → 强制模拟模式（跳过平台检测）
    │
    ├── mode = "ebpf"       → 强制 eBPF 模式（跳过平台检测，需Linux）
    │
    ├── mode = "strace"     → 强制 strace 模式（跳过平台检测，需Linux）
    │
    └── mode = "auto"       → 自动检测:
            │
            ▼
        sys.platform == "win32" ?
            │
            ├── Yes → SimulationCollector
            │        + 打印: "检测到 Windows 平台，启用模拟模式"
            │
            └── No (linux) →
                    │
                    ▼
                检查 eBPF 能力:
                    · /sys/kernel/btf/vmlinux 存在?
                    · libbpf.so 可用?
                    · 当前用户有 CAP_BPF + CAP_PERFMON?
                    │
                    ├── 全部满足 → EbpfCollector
                    │              + 打印: "检测到 eBPF 支持，启用真实观测模式"
                    │
                    └── 部分缺失 → StraceCollector
                                   + 打印: "eBPF 不可用，降级为 strace 观测模式"
```

**CLI 参数**：三个入口均新增 `--mode` 参数：

```python
parser.add_argument("--mode", type=str, default=None,
                    choices=["auto", "simulation", "strace", "ebpf"],
                    help="采集模式 (默认从 config.yaml 读取)")
```

### 2.3 数据流（统一架构）

```
                    ┌─────────────────────────────┐
                    │     入口层 (三入口统一)        │
                    │  平台检测 → 选择 Collector    │
                    └─────────────┬───────────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
            ▼                     ▼                     ▼
    ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
    │ Simulation    │    │ Strace        │    │ Ebpf          │
    │ Collector     │    │ Collector     │    │ Collector     │
    │ (Windows)     │    │ (Linux)       │    │ (Linux)       │
    └───────┬───────┘    └───────┬───────┘    └───────┬───────┘
            │                    │                    │
            │ 场景YAML           │ strace -p PID      │ eBPF tracepoint
            │ → RawEvent生成     │ → 行解析→RawEvent  │ → ring buffer→RawEvent
            │ + VirtualClock     │ + 系统时间戳        │ + bpf_ktime_get_ns
            │                    │                    │
            └────────────────────┼────────────────────┘
                                 │
                    统一: ICollector.start() yield RawEvent
                                 │
                                 ▼
                    ┌───────────────────────┐
                    │  入口层直接消费:        │
                    │  for raw in collector.start(): │
                    │    norm = normalizer.normalize(raw) │
                    │    match = engine.match(norm)  │
                    │    assess = scorer.assess(...)  │
                    │    decision = engine.decide(...) │
                    │    ...                          │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
                    ▼                       ▼
            ┌──────────────┐        ┌──────────────┐
            │ 阻断指令      │        │ 审计报告     │
            │ (send_command)│        │ 图谱/MD/JSON │
            └──────┬───────┘        └──────────────┘
                   │
                   ▼
            Collector.send_command()
            · Simulation: 模拟阻断(MockCommandSender)
            · Strace: 空实现(不支持,返回False)
            · Ebpf: 第一版空实现(后续迭代:更新eBPF map)
```

### 2.4 时间模型统一

| 模式 | 时间源 | 对 `observer_core/` 的影响 |
|------|--------|:---:|
| 模拟模式 | `VirtualClock`（场景 YAML 的 `delay_ms` 推进） | 零影响——事件 `timestamp_ns` 由 Collector 填充 |
| strace 模式 | `time.time_ns()`（纳秒精度，strace -ttt 提供微秒） | 零影响——同上 |
| eBPF 模式 | `bpf_ktime_get_ns()`（内核 monotonic 时钟，纳秒） | 零影响——同上 |

**关键设计**：`observer_core/` 不关心时间戳来源。它只从 `RawEvent.timestamp_ns` 读取值。Collector 负责生成这个值。

---

## 第三部分：eBPF 数据输入模块设计（重点）

### 3.1 eBPF 探针架构（第一版：仅观测）

```
┌──────────────────────────────────────────────────────────────────┐
│                    eBPF 探针系统 (Linux 内核态 + 用户态)           │
│                                                                  │
│  用户态 (Python)                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  EbpfCollector (collector/ebpf_collector.py, ~250行)        │ │
│  │                                                            │ │
│  │  职责:                                                      │ │
│  │  1. 加载 eBPF 字节码 (observer.bpf.o)                       │ │
│  │  2. 挂载到 tracepoint                                       │ │
│  │  3. 消费 perf ring buffer → 构造 RawEvent → yield 给上层    │ │
│  │  4. 管理 eBPF 程序生命周期 (加载/挂载/卸载/清理)             │ │
│  │  5. send_command() 第一版为空实现(日志记录,返回False)        │ │
│  └──────────────────────┬─────────────────────────────────────┘ │
│                         │                                        │
│                libbpf (Python ctypes 调用)                        │
│                bpf() 系统调用                                     │
│                         │                                        │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
│                         │         用户态 / 内核态边界              │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
│                         │                                        │
│  内核态 (eBPF C 程序)                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  observer.bpf.c (~250行 C)    预编译 → observer.bpf.o       │ │
│  │                                                            │ │
│  │  ┌─────────────────────────────────────────────────────┐  │ │
│  │  │  探针 1: tracepoint/syscalls/sys_enter_execve        │  │ │
│  │  │  · 捕获: filename, argv                              │  │ │
│  │  │  · 进程信息: pid, ppid, uid, comm                    │  │ │
│  │  └─────────────────────────────────────────────────────┘  │ │
│  │                                                            │ │
│  │  ┌─────────────────────────────────────────────────────┐  │ │
│  │  │  探针 2: tracepoint/syscalls/sys_enter_openat        │  │ │
│  │  │  · 捕获: filename, flags (O_RDONLY/O_WRONLY/O_RDWR)  │  │ │
│  │  └─────────────────────────────────────────────────────┘  │ │
│  │                                                            │ │
│  │  ┌─────────────────────────────────────────────────────┐  │ │
│  │  │  探针 3: tracepoint/syscalls/sys_enter_connect       │  │ │
│  │  │  · 捕获: sockaddr (IP+Port), addrlen, family         │  │ │
│  │  └─────────────────────────────────────────────────────┘  │ │
│  │                                                            │ │
│  │  每个探针:                                                  │ │
│  │  1. 从寄存器/栈读取 syscall 参数                            │ │
│  │  2. 构造 event_t 结构体                                     │ │
│  │  3. 推送 event_t 到 perf ring buffer                       │ │
│  │  (第一版不做阻断判断,第二版加入 block_policy map 查询)       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  eBPF Maps (第一版):                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  events (BPF_MAP_TYPE_PERF_EVENT_ARRAY)                    │ │
│  │  · 内核→用户态事件推送                                     │ │
│  │  · 每个 CPU 一个 ring buffer                               │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  eBPF Maps (第二版预留):                                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  block_policy (BPF_MAP_TYPE_HASH) — 第二版新增             │ │
│  │  · key: pid (u32), value: block_flags (u64)               │ │
│  │  · 配合 kprobe 程序实现 bpf_override_return 阻断           │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 eBPF 事件结构体定义

```c
// observer.bpf.c 中的事件结构体 (内核态与用户态共享)
struct event_t {
    u64  timestamp_ns;       // bpf_ktime_get_ns()
    u32  pid;                // bpf_get_current_pid_tgid() >> 32
    u32  ppid;               // 从 task_struct 读取
    u32  uid;                // 从 task_struct 读取
    u8   event_type;         // 0=execve, 1=openat, 2=connect
    u8   blocked;            // 第一版固定为0, 第二版由阻断逻辑设置
    u16  padding;

    // 联合体: 根据 event_type 选择有效字段
    union {
        struct {
            char filename[256];    // execve: 可执行文件路径
            char argv[512];        // execve: 命令行参数 (截断)
        } exec;
        struct {
            char filename[256];    // openat: 文件路径
            u32  flags;            // openat: O_RDONLY=0, O_WRONLY=1, O_RDWR=2
        } file;
        struct {
            u32  ip_addr;          // connect: IPv4 地址 (网络字节序)
            u16  port;             // connect: 端口 (网络字节序)
            u8   protocol;         // 0=TCP, 1=UDP
        } net;
    };

    char comm[16];            // 进程名 (bpf_get_current_comm)
};
```

### 3.3 event_t → RawEvent 字段映射

eBPF `event_t` 与 Python `RawEvent` 的字段映射关系（`EbpfCollector._to_raw_event()` 实现）：

| event_t 字段 | RawEvent 字段 | 转换逻辑 |
|---|---|---|
| `timestamp_ns` | `timestamp_ns` | 直接赋值（u64→int） |
| `event_type` (u8: 0/1/2) | `event_type` (str) | `{0:"exec", 1:"file_open", 2:"net_conn"}` |
| `pid` | `pid` | 直接赋值（u32→int） |
| `ppid` | `ppid` | 直接赋值（u32→int） |
| — | `event_id` | **自增计数器** `f"ebpf_evt_{seq:06d}"` |
| — | `agent_id` | **从 config.ebpf.target_agent_id 读取**（默认 "observed-agent"） |
| — | `agent_framework` | **固定为** `"ebpf"` |
| `exec.filename` | `executable` | `bytes.decode('utf-8', errors='replace')` |
| `exec.argv` | `arguments` | 按 `\0` 分割 → list[str] |
| `file.filename` | `file_path` | `bytes.decode` |
| `file.flags` | `file_op` | `{0:"read", 1:"write", 2:"write"}` 映射 |
| `net.ip_addr` | `remote_addr` | `socket.inet_ntoa(struct.pack('!I', ip))` |
| `net.port` | `remote_port` | `socket.ntohs(port)` |
| `net.protocol` | `protocol` | `{0:"TCP", 1:"UDP"}` |
| `comm` | — | 仅用于调试日志，不映射到 RawEvent |

### 3.4 eBPF 探针三个 tracepoint 的挂载点

| 探针 | 挂载点 | 捕获的关键参数 |
|------|--------|--------------|
| execve | `tracepoint/syscalls/sys_enter_execve` | `ctx->args[0]` → filename 指针, `ctx->args[1]` → argv 指针 |
| openat | `tracepoint/syscalls/sys_enter_openat` | `ctx->args[1]` → filename 指针, `ctx->args[2]` → flags |
| connect | `tracepoint/syscalls/sys_enter_connect` | `ctx->args[1]` → sockaddr 指针, `ctx->args[2]` → addrlen |

**为什么用 tracepoint 而非 kprobe？**
- tracepoint 是内核稳定的 ABI，不会因内核版本变化而失效
- kprobe 可以挂在任意函数上但接口不稳定
- 第一版仅做观测，tracepoint 完全满足需求
- 第二版如需阻断，可额外挂载 kprobe 程序配合 `bpf_override_return`

### 3.5 阻断机制设计（第二版预留）

**第一版限制说明**：`bpf_override_return()` 仅适用于 `BPF_PROG_TYPE_KPROBE` 类型的程序。当前三个探针使用 tracepoint 类型（`BPF_PROG_TYPE_TRACEPOINT`），不支持 `bpf_override_return`。因此第一版 eBPF 仅做观测，阻断功能延后到第二版。

**第二版阻断方案（预留）**：

```
第二版阻断架构:
  观测: 保留 tracepoint 探针（稳定 ABI，观测所有 syscall）
  阻断: 新增 kprobe 程序挂载到 __x64_sys_execve / __x64_sys_openat / __x64_sys_connect
        → bpf_override_return(ctx, -EPERM)
        → 仅在需要阻断时动态挂载 kprobe（平时不挂载，零开销）

阻断数据流:
  Python 研判决策: BLOCK
      │
      ▼
  EbpfCollector.send_command(cmd)
      │
      ▼
  动态挂载 kprobe 程序（如未挂载）
  更新 eBPF map: block_policy[target_pid] = block_flags
      │
      ▼
  Agent 下次调用 syscall → kprobe 触发
      → 查询 block_policy map → bpf_override_return → EPERM
```

**第一版 `send_command()` 行为**：
- `SimulationCollector`：正常工作（通过 MockCommandSender 模拟阻断）
- `StraceCollector`：返回 `False`，记录警告日志
- `EbpfCollector`：返回 `False`，记录警告日志 + 打印 "eBPF 阻断将在第二版实现"

### 3.6 编译 eBPF 程序所需的环境

```bash
# 一次性环境准备（在 VMware Ubuntu 22.04 中）

# 1. 安装编译工具链
sudo apt update
sudo apt install -y clang llvm libbpf-dev make linux-headers-$(uname -r)

# 2. 生成 vmlinux.h（内核类型定义）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

# 3. 编译
cd ebpf/
make
# 产出: ebpf/observer.bpf.o (~50KB)
```

**开发者注意**：`vmlinux.h` 和 `observer.bpf.o` 不需要提交到 Git，已添加到 `.gitignore`。

---

## 第四部分：模块接口定义

### 4.1 `ICollector` 接口（核心抽象）

```python
# collector/base_collector.py

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator, Optional

@dataclass
class CollectorCapabilities:
    """采集器能力描述 —— 供上层查询"""
    name: str                       # "Simulation" | "Strace" | "Ebpf"
    can_observe: bool               # 是否支持观测
    can_block_tier2: bool           # 是否支持 Tier2 阻断（返回 EPERM）
    can_block_tier3: bool           # 是否支持 Tier3 阻断（终止进程）
    is_transparent: bool            # 对 Agent 是否无感知
    performance_overhead: str       # "low" | "medium" | "high"
    time_source: str                # "virtual" | "realtime_monotonic"


class ICollector(ABC):
    """
    采集层统一抽象接口。

    所有采集方案（模拟探针 / strace / eBPF）必须实现此接口。
    上层 (main.py / demo.py / app.py) 通过此接口与采集层交互，
    不关心底层是模拟还是真实采集。
    """

    @abstractmethod
    def capabilities(self) -> CollectorCapabilities:
        """返回采集器能力描述"""
        ...

    @abstractmethod
    def attach(self, target_pid: int = 0, agent_id: str = "") -> bool:
        """
        附着到目标 Agent 进程。

        参数:
            target_pid: Agent 主进程 PID（模拟模式下忽略，eBPF/strace 模式使用）
            agent_id:   Agent 标识字符串

        返回:
            True:  附着成功
            False: 附着失败

        模拟模式: 接受 agent_id 用于场景加载，target_pid 忽略
        strace:   subprocess.Popen(["strace", "-p", str(target_pid), ...])
        eBPF:     通过 libbpf 加载并挂载探针（全局观测，非单进程）
        """
        ...

    @abstractmethod
    def start(self) -> Iterator['RawEvent']:
        """
        开始采集，返回 RawEvent 生成器。
        上层直接 for 循环消费，不需要管道中转。

        Yields:
            RawEvent: 每个捕获到的系统调用事件

        模拟模式: 读取场景 YAML → 逐个生成 RawEvent → yield（含 VirtualClock 推进）
        strace:   逐行读取 strace 输出 → 解析 → yield RawEvent
        eBPF:     消费 perf ring buffer → 构造 RawEvent → yield
        """
        ...

    @abstractmethod
    def send_command(self, cmd: 'Command') -> bool:
        """
        接收阻断指令（反向通道）。

        模拟模式: 通过 MockCommandSender 模拟阻断
        strace:   不支持（返回 False，记录警告）
        eBPF:     第一版不支持（返回 False），第二版更新 eBPF map
        """
        ...

    @abstractmethod
    def detach(self) -> None:
        """断开采集，清理资源。"""
        ...

    @abstractmethod
    def get_process_tree(self) -> dict:
        """
        获取当前追踪的进程树快照。
        返回: {pid: {"ppid": ..., "agent_id": ..., "comm": ...}, ...}

        模拟模式: 返回空 dict {}
        strace/eBPF: 从 /proc/{pid}/stat 构建
        """
        ...
```

### 4.2 `SimulationCollector` 详细设计

```python
# collector/simulation_collector.py (~180行)

class SimulationCollector(ICollector):
    """
    模拟采集器 —— 封装现有场景 YAML + VirtualClock 逻辑。

    从现有 demo.py ScenarioRunner 和 main.py 中提取的采集逻辑：
      1. 加载场景 YAML 文件
      2. 遍历 event_sequence
      3. 推进 VirtualClock
      4. 构造 RawEvent（与现有 create_raw_event() 逻辑一致）
      5. yield RawEvent 给上层

    支持多 Agent 场景：attach() 时 agent_id 可为空（表示全局模式），
    start() 中按场景 YAML 的 agent 字段标注每个 RawEvent 的 agent_id。
    """

    def __init__(self, config: dict):
        self.config = config
        self.scenarios_dir = config.get("simulation", {}).get(
            "scenarios_dir", "scenarios/")
        start_ns = config.get("simulation", {}).get(
            "virtual_clock_start_ns",
            config.get("virtual_clock", {}).get("start_ns", 1718092800000000000))
        self.clock = VirtualClock(start_ns=start_ns)
        self.scenario = None
        self.scenario_path = None

    def capabilities(self) -> CollectorCapabilities:
        return CollectorCapabilities(
            name="Simulation",
            can_observe=True,
            can_block_tier2=True,   # 模拟阻断
            can_block_tier3=True,   # 模拟终止
            is_transparent=False,   # Agent 可感知（模拟环境）
            performance_overhead="low",
            time_source="virtual",
        )

    def attach(self, target_pid: int = 0, agent_id: str = "") -> bool:
        """
        加载场景 YAML。
        target_pid 在模拟模式下忽略。
        agent_id 对应场景文件路径（如 "n01" → 查找 n01*.yaml）。
        也可以由上层直接调用 load_scenario() 设置。
        """
        return True  # 模拟模式始终成功

    def load_scenario(self, scenario_path: str):
        """加载场景文件（兼容现有 ScenarioRunner.load_scenario 逻辑）"""
        with open(scenario_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        self.scenario = data['scenario']
        self.scenario_path = scenario_path

    def start(self) -> Iterator[RawEvent]:
        """
        遍历场景事件序列，yield RawEvent。

        关键实现：复用现有 main.py create_raw_event() 的逻辑，
        包括 VirtualClock 推进（delay_ms）、事件字段填充、
        多 Agent 场景的 agent_id 映射。
        """
        if not self.scenario:
            return

        agents_map = {}
        for agent in self.scenario.get("agents", []):
            agents_map[agent["agent_id"]] = agent

        events = self.scenario.get("event_sequence", [])
        for i, event_data in enumerate(events, 1):
            seq = event_data.get("seq", i)
            delay_ms = event_data.get("delay_ms", 0)
            agent_id = event_data.get("agent", "unknown")
            agent_info = agents_map.get(agent_id, {
                "agent_id": agent_id, "initial_pid": 10001})

            self.clock.advance(delay_ms)

            yield RawEvent(
                event_id=f"evt-{seq:04d}",
                timestamp_ns=self.clock.now_ns(),
                event_type=event_data["type"],
                pid=agent_info.get("initial_pid", 10001),
                ppid=1,
                agent_id=agent_id,
                agent_framework=agent_info.get("framework", "unknown"),
                executable=event_data.get("executable"),
                arguments=event_data.get("arguments"),
                file_path=event_data.get("file_path"),
                file_op=event_data.get("file_op"),
                remote_addr=event_data.get("remote_addr"),
                remote_port=event_data.get("remote_port"),
                protocol=event_data.get("protocol"),
            )

    def send_command(self, cmd) -> bool:
        """模拟模式：记录阻断指令（与现有 MockCommandSender 行为一致）"""
        return True

    def detach(self):
        self.scenario = None

    def get_process_tree(self) -> dict:
        return {}  # 模拟模式不维护真实进程树
```

### 4.3 `EbpfCollector` 设计要点

```
collector/ebpf_collector.py (~250行)

职责:
  1. 加载预编译的 eBPF 字节码 (observer.bpf.o)
  2. 挂载三类 tracepoint 探针（仅观测）
  3. 设置 perf ring buffer 回调
  4. 消费 event_t → 构造 RawEvent → yield 给上层
  5. send_command() 第一版为空实现（日志记录）
  6. 管理 eBPF 生命周期

依赖:
  · libbpf (通过 Python ctypes 调用 libbpf.so)
  · observer.bpf.o (预编译的 eBPF 字节码)

关键实现点:
  · _to_raw_event(event_t): 按 §3.3 映射表转换字段
  · perf ring buffer 消费: perf_buffer__poll(timeout_ms) 轮询
  · 生命周期: attach() → 加载+挂载, detach() → 卸载+清理
  · 错误处理: 权限不足(CAP_BPF) → 降级为 strace; BTF 不存在 → 报错退出
  · atexit 注册清理函数防止异常退出时遗留 eBPF 程序
```

### 4.4 管道适配器接口

```python
# adapter/pipe_factory.py

class PipeAdapter:
    """
    管道适配器：屏蔽 Windows 命名管道与 Linux FIFO 的差异。
    用于 C++ 模拟探针 (Windows) 和未来 eBPF 阻断通道 (Linux) 的管道通信。

    注意：数据流主路径已改为 ICollector.start() 直接 yield RawEvent，
    PipeAdapter 仅用于需要跨进程管道通信的辅助场景（如 C++ 探针控制通道）。
    """

    @staticmethod
    def create(config: dict, platform: 'PlatformInfo') -> 'PipeAdapter':
        """工厂方法：根据平台创建对应的管道适配器。"""
        ...

    def open_event_pipe(self, mode: str):
        """打开正向管道（探针 → Observer）。"""
        ...

    def open_command_pipe(self, mode: str):
        """打开反向管道（Observer → 探针）。"""
        ...

    def cleanup(self):
        """清理管道资源。"""
        ...
```

### 4.5 配置接口（config.yaml 统一架构版）

**保留现有全部配置段**，仅在顶部新增 `mode` + `pipeline` + `simulation` + `ebpf` + `strace` 段：

```yaml
# config.yaml — 统一架构版（完整示例）

# ============================================================
# 运行模式 (新增)
# ============================================================
mode: "auto"
# 可选值: "auto" | "simulation" | "strace" | "ebpf"

# ============================================================
# 管道配置 (新增，替代现有 pipes 段的部分字段)
# ============================================================
pipeline:
  # Windows (命名管道)
  win_event_pipe: "\\\\.\\pipe\\observer_events"
  win_command_pipe: "\\\\.\\pipe\\observer_commands"
  # Linux (FIFO)
  linux_event_fifo: "/tmp/observer/events"
  linux_command_fifo: "/tmp/observer/commands"

# ============================================================
# 模拟模式配置 (新增)
# ============================================================
simulation:
  scenarios_dir: "scenarios/"
  cpp_probe_exe: "cpp_probe/build/cpp_probe"
  virtual_clock_start_ns: 0
  step_by_step: true

# ============================================================
# eBPF 采集模式配置 (新增)
# ============================================================
ebpf:
  bpf_object_path: "ebpf/observer.bpf.o"
  target_pid: null                  # 运行时指定 (--pid 参数)
  target_agent_id: "observed-agent"
  perf_buffer_page_count: 64
  heartbeat_interval_sec: 15

# ============================================================
# strace 采集模式配置 (新增，降级备选)
# ============================================================
strace:
  strace_binary: "/usr/bin/strace"
  trace_syscalls: "execve,openat,connect,unlink,sendto"
  target_pid: null

# ============================================================
# 以下为现有配置段，全部保留不做修改
# ============================================================

# === 管道通信配置 (保留，Windows 模拟模式使用) ===
pipes:
  events: "\\\\.\\pipe\\observer_events"
  commands: "\\\\.\\pipe\\observer_commands"
  connect_timeout_ms: 5000
  heartbeat_interval_ms: 1000
  heartbeat_max_miss: 3

# === 虚拟时钟配置 (保留) ===
virtual_clock:
  start_ns: 1718092800000000000

# === 风险评分权重 (保留，维持 dimensions 嵌套结构) ===
scoring:
  dimensions:
    rule_match:
      weight: 0.40
      class: "BasicRuleScore"
    baseline_deviation:
      weight: 0.25
      class: "BasicBaselineScore"
    context_risk:
      weight: 0.20
      class: "BasicContextScore"
    sequence_anomaly:
      weight: 0.15
      class: "BasicSequenceScore"
  risk_levels:
    low_max: 0.3
    medium_max: 0.6

# === 阻断升级配置 (保留) ===
blocking:
  violation_window_ms: 300000
  tier1_to_tier2_threshold: 3
  tier2_to_tier3_threshold: 2

# === 事件序列窗口 (保留) ===
monitoring:
  event_window_size: 10
  process_window_ms: 60000

# === 基线配置 (保留) ===
baseline:
  cold_start_deviation: 0.0
  min_events_for_baseline: 20

# === 输出配置 (保留) ===
output:
  audit_dir: "output/audit"
  reports_dir: "output/reports"
  graphs_dir: "output/graphs"
  baselines_dir: "output/baselines"
  audit_format: "jsonl"

# === 场景配置 (保留，37个测试场景) ===
scenarios:
  # (完整列表保持不变，此处省略)
  - "scenarios/normal/n01_standard_development.yaml"
  # ... 共37个 ...

# === 日志配置 (保留) ===
logging:
  level: "INFO"
  format: "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
```

### 4.6 模式选择工厂函数

```python
# adapter/platform_detect.py 中的核心函数

def detect_and_create_collector(config: dict, mode_override: str = None) -> ICollector:
    """
    平台检测 + Collector 创建工厂。

    优先级: mode_override > config["mode"] > "auto"

    返回:
        对应平台的 ICollector 实例
    """
    mode = mode_override or config.get("mode", "auto")

    if mode == "simulation":
        return SimulationCollector(config)
    elif mode == "ebpf":
        if sys.platform == "win32":
            raise RuntimeError("eBPF 模式仅支持 Linux")
        return EbpfCollector(config)
    elif mode == "strace":
        if sys.platform == "win32":
            raise RuntimeError("strace 模式仅支持 Linux")
        return StraceCollector(config)
    else:  # auto
        if sys.platform == "win32":
            print("检测到 Windows 平台，启用模拟模式")
            return SimulationCollector(config)
        else:
            if _check_ebpf_capability():
                print("检测到 eBPF 支持，启用真实观测模式")
                return EbpfCollector(config)
            else:
                print("eBPF 不可用，降级为 strace 观测模式")
                return StraceCollector(config)


def _check_ebpf_capability() -> bool:
    """检查 eBPF 能力: BTF + libbpf + CAP_BPF"""
    import os, ctypes
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        return False
    try:
        ctypes.CDLL("libbpf.so")
    except OSError:
        return False
    # CAP_BPF 检查: 读取 /proc/self/status 中的 CapEff
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_hex = int(line.split(":")[1].strip(), 16)
                    # CAP_BPF = 39, CAP_PERFMON = 38
                    return bool(cap_hex & (1 << 39)) and bool(cap_hex & (1 << 38))
    except Exception:
        return False
    return False
```

---

## 第五部分：文件清单与改动范围

### 5.1 新增文件

| 文件 | 行数 | 说明 |
|------|:---:|------|
| `adapter/__init__.py` | ~10 | 导出 PlatformInfo, PipeAdapter, detect_and_create_collector |
| `adapter/platform_detect.py` | ~50 | 平台检测 + eBPF 能力查询 + Collector 工厂 |
| `adapter/pipe_factory.py` | ~60 | 管道工厂（Win命名管道 / Linux FIFO） |
| `adapter/time_source.py` | ~30 | 时间源抽象（VirtualClock / realtime） |
| `collector/__init__.py` | ~10 | 导出 ICollector, CollectorCapabilities |
| `collector/base_collector.py` | ~70 | ICollector 抽象接口 + CollectorCapabilities 定义 |
| `collector/simulation_collector.py` | ~180 | 模拟采集器（封装场景YAML + VirtualClock + 多Agent） |
| `collector/strace_collector.py` | ~150 | strace 采集器（subprocess + 行解析） |
| `collector/ebpf_collector.py` | ~250 | eBPF 采集器（加载.bpf.o + ring buffer消费） |
| `ebpf/observer.bpf.c` | ~250 | eBPF 内核态 C 程序（三类tracepoint探针，仅观测） |
| `ebpf/vmlinux.h` | — | 内核类型定义（bpftool 生成，不提交Git） |
| `ebpf/Makefile` | ~20 | 编译脚本 |
| **新增总计** | **~1080** | |

### 5.2 改动文件

| 文件 | 改动 | 说明 |
|------|:---:|------|
| `config.yaml` | +25 行 | 顶部新增 mode + pipeline + simulation + ebpf + strace 配置段（现有字段全部保留） |
| `main.py` | ~50 行 | 新增 --mode 参数 + 调用 detect_and_create_collector() + 用 Collector 替代直接创建 RawEvent |
| `demo.py` | ~40 行 | ScenarioRunner.__init__ 改为创建 Collector；run_event 改为从 Collector 获取事件 |
| `app.py` | ~60 行 | StreamScenarioRunner 改为使用 SimulationCollector；新增 --mode 参数 |
| `models/event.py` | 0 | 零改动 |
| `models/command.py` | 0 | 零改动 |
| `observer_core/` | 0 | 零改动 |
| `scenarios/` | 0 | 零改动 |
| `rules/` | 0 | 零改动 |
| `cpp_probe/` | 0 | 零改动 |
| `.gitignore` | +5 行 | 新增 ebpf/vmlinux.h, ebpf/*.o, ebpf/*.llc |
| **改动总计** | **~180** | |

### 5.3 项目完整目录树

```
observer_sim/
│
├── main.py                          # [改动] 入口 + 模式选择 + Collector 创建
├── demo.py                          # [改动] CLI 模式（ScenarioRunner 使用 Collector）
├── app.py                           # [改动] Web 模式（StreamScenarioRunner 使用 Collector）
├── config.yaml                      # [改动] 新增配置段 + 保留全部现有配置
├── .gitignore                       # [改动] 新增 eBPF 编译产物排除
│
├── adapter/                         # [新增] 平台适配层
│   ├── __init__.py
│   ├── platform_detect.py           # 平台检测 + eBPF能力查询 + Collector工厂
│   ├── pipe_factory.py              # Win命名管道 / Linux FIFO
│   └── time_source.py              # VirtualClock / realtime
│
├── collector/                       # [新增] 采集层
│   ├── __init__.py
│   ├── base_collector.py            # ICollector + CollectorCapabilities
│   ├── simulation_collector.py      # 模拟采集器 (封装场景YAML+Clock)
│   ├── strace_collector.py          # strace 采集器
│   └── ebpf_collector.py            # eBPF 采集器
│
├── ebpf/                            # [新增] eBPF 探针
│   ├── observer.bpf.c               # eBPF C 程序 (3个tracepoint,仅观测)
│   ├── Makefile                     # 编译脚本
│   ├── vmlinux.h                    # (生成, gitignore)
│   └── observer.bpf.o              # (编译产物, gitignore)
│
├── cpp_probe/                       # [保留] 模拟探针
│   └── ...
│
├── observer_core/                   # [零改动] 核心逻辑
│   └── ...
│
├── models/                          # [零改动] 数据模型
│   └── ...
│
├── scenarios/                       # [零改动] 模拟场景
│   └── ...
│
├── rules/                           # [零改动] 策略规则
│   └── ...
│
├── evolution/                       # [零改动] 自优化接口
│   └── ...
│
└── output/                          # [零改动] 输出目录
    └── ...
```

---

## 第六部分：开发排期（10 天 · 双环境）

### 6.0 双环境开发策略

本项目涉及两套独立开发环境，任务按环境拆分以避免频繁切换：

```
┌────────────────────────────────────────────────────────────────────┐
│                   Windows 宿主机（开发主机）                         │
│                                                                    │
│  D:\Projects\observer_sim\          ← Git 主仓库                   │
│                                                                    │
│  职责:                                                              │
│  · observer_core/ / models/ / scenarios/ / rules/  (零改动，仅验证) │
│  · adapter/ 的 Windows 分支（命名管道、平台检测）                    │
│  · collector/base_collector.py + simulation_collector.py            │
│  · 三入口改造（main.py / demo.py / app.py）                         │
│  · config.yaml 配置变更                                             │
│  · 全部无回归验证（130 单元测试 + 37 场景）                          │
│                                                                    │
│  连续工作日: Day 1 → Day 2 → Day 3 → Day 4（4 天不切换）            │
├────────────────────────────────────────────────────────────────────┤
│                   Linux 虚拟机（VMware Ubuntu 22.04 LTS）            │
│                                                                    │
│  ~/projects/observer_sim/           ← Git 独立克隆                  │
│  /mnt/observer_sim/                 ← 共享文件夹（只读参考）         │
│                                                                    │
│  职责:                                                              │
│  · ebpf/observer.bpf.c（eBPF 内核探针，仅 Linux 可编译）            │
│  · collector/ebpf_collector.py（Python 加载器，依赖 libbpf.so）     │
│  · collector/strace_collector.py（strace 采集器，仅 Linux）          │
│  · adapter/ 的 Linux 分支（FIFO、eBPF 能力查询）验证                │
│  · Linux 端三模式集成联调                                           │
│                                                                    │
│  连续工作日: Day 5 → Day 6 → Day 7 → Day 8（4 天不切换）            │
├────────────────────────────────────────────────────────────────────┤
│                   跨环境协同日                                       │
│                                                                    │
│  Day 9:  Linux 集成联调 + 跨环境验证                                 │
│  Day 10: 双环境全量验证 + 文档收尾                                   │
└────────────────────────────────────────────────────────────────────┘
```

**Git 同步流程**：

```
Windows 完成阶段性代码 → git commit + git push
                          ↓
Linux: git pull → 运行 pytest 验证无回归 → 继续 Linux 端开发
                          ↓
Linux 完成 eBPF/collector 代码 → git commit + git push
                          ↓
Windows: git pull → 运行 pytest 验证模拟模式无回归
```

**日常开发 Checklist**：

| 步骤 | 环境 | 操作 |
|------|:---:|------|
| 开始工作前 | 当前环境 | `git pull` 拉取最新代码 |
| 编码完成后 | 当前环境 | `pytest -v` 确认无回归 |
| 提交代码 | 当前环境 | `git add . && git commit -m "Day N: ..." && git push` |
| 切换环境时 | 目标环境 | `git pull` + `pytest -v` 确认基线正常 |
| 每日结束 | 两端 | 确保无未提交的本地修改 |

### 6.1 时间线总览

```
Day  1  2  3  4  5  6  7  8  9  10
     ├──────────────┤                 Windows: 适配层+接口+入口改造+无回归
                    ├──────────────┤  Linux:   eBPF探针+加载器+strace
                                   ├──────┤   跨环境集成联调
                                         ├────┤ 双环境全量验证+文档

     ◄── Phase 1 ──►◄── Phase 2 ──►◄── Phase 3 ──►◄─ Phase 4 ─►◄── Phase 5 ──►
     Win  Day 1-2    Win  Day 3-4    Linux Day 5-8    Linux Day 9    双端 Day 10
```

> **环境切换仅 2 次**：Day 4→5（Win→Linux）、Day 9 跨环境协同。其余时间在同一环境连续工作。

---

### Phase 1：平台适配层 + 接口定义 + SimulationCollector（Day 1-2）`[Win]`

> **环境**：Windows 宿主机
>
> **目标**：完成 adapter/ 全部代码、collector/ 接口定义和 SimulationCollector 实现，为后续入口改造和 Linux 端开发奠定基础。

**环境预检清单**：

```powershell
# [Win] 预检 — 在 PowerShell 中执行
python --version                              # ≥ 3.10
python -c "import yaml; print('pyyaml OK')"   # pyyaml 已安装
python -m pytest --version                    # pytest 可用
git --version                                 # git 可用
```

```
Day 1 (4h) [Win]:
  ├─ [1h] adapter/__init__.py + platform_detect.py
  │        · sys.platform 检测（Win/Linux 双分支，Linux 分支在 Win 上用 mock 测试）
  │        · eBPF 能力查询（BTF + libbpf + CAP_BPF，Win 上固定返回 False）
  │        · detect_and_create_collector() 工厂函数
  ├─ [1h] adapter/pipe_factory.py — 管道工厂
  │        · WindowsPipeAdapter（命名管道，复用现有 win32pipe 逻辑）
  │        · LinuxFifoAdapter（os.mkfifo，仅定义不测试——Day 5 在 Linux 验证）
  ├─ [0.5h] adapter/time_source.py — 时间源抽象（VirtualClock / RealtimeClock）
  └─ [1.5h] 单元测试: tests/test_adapter.py
           · 平台检测分支覆盖（mock sys.platform="linux"）
           · eBPF 能力查询各分支（mock /sys/kernel/btf/vmlinux）
           · WindowsPipeAdapter 创建/清理命名管道
           · TimeSource 两种实现

Day 2 (4h) [Win]:
  ├─ [1h] collector/__init__.py + base_collector.py
  │        · ICollector 抽象接口（5 个抽象方法）
  │        · CollectorCapabilities 数据类
  ├─ [2h] collector/simulation_collector.py
  │        · 封装场景 YAML 加载 + VirtualClock + RawEvent 生成
  │        · 支持多 Agent 场景（agents_map 映射）
  │        · 兼容现有 main.py create_raw_event() 逻辑
  │        · load_scenario() 兼容现有 ScenarioRunner 的场景查找逻辑
  └─ [1h] 单元测试: tests/test_simulation_collector.py
           · 加载 n01 场景 → yield 正确数量的 RawEvent
           · VirtualClock 按 delay_ms 推进正确
           · 多 Agent 场景 (m01) agent_id 映射正确
           · send_command() 返回 True
           · detach() 清理状态

[Win→Linux 同步节点 A] ← Day 2 结束时
  git add adapter/ collector/ tests/test_adapter.py tests/test_simulation_collector.py
  git commit -m "Phase 1: adapter/ + ICollector + SimulationCollector"
  git push
```

**交付标准**：
- `[Win]` SimulationCollector 通过全部单元测试
- `[Win]` adapter/ 平台检测逻辑覆盖 Win/Linux 分支（Linux 分支用 mock）
- `[Win]` 现有 130 个单元测试无回归

---

### Phase 2：入口层改造 + 无回归验证（Day 3-4）`[Win]`

> **环境**：Windows 宿主机
>
> **目标**：改造 main.py/demo.py/app.py 三个入口使用 Collector 架构，更新 config.yaml，完成 Windows 端全部无回归验证。Phase 2 完成后，Windows 端开发工作全部结束。

**环境预检清单**：

```powershell
# [Win] 预检 — 确认 Phase 1 产物已就位
python -c "from adapter.platform_detect import detect_and_create_collector; print('OK')"
python -c "from collector.simulation_collector import SimulationCollector; print('OK')"
python -m pytest tests/test_adapter.py tests/test_simulation_collector.py -v
```

```
Day 3 (4h) [Win]:
  ├─ [2h] 改造 main.py
  │        · 新增 --mode CLI 参数（choices=[auto,simulation,strace,ebpf]）
  │        · 导入 detect_and_create_collector
  │        · run_scenario_pipeline() 改为从 Collector 获取事件
  │        · 保持现有 discover_scenarios() / load_scenario() / 输出逻辑不变
  ├─ [1h] 改造 demo.py
  │        · ScenarioRunner.__init__() 新增 Collector 创建
  │          （SimulationCollector 替代直接创建 VirtualClock + MockCommandSender）
  │        · run_event() 适配为从 Collector 获取事件
  │        · 保持交互式 CLI / ANSI 彩色输出 / 分析面板不变
  └─ [1h] config.yaml 新增配置段
           · 顶部添加 mode: "auto"
           · 添加 pipeline/simulation/ebpf/strace 配置段
           · 保留全部现有配置段（pipes/scoring/blocking/monitoring/baseline/output/scenarios/logging）

Day 4 (4h) [Win]:
  ├─ [2h] 改造 app.py
  │        · StreamScenarioRunner.__init__() 改为创建 SimulationCollector
  │        · _process_one_event() 适配为从 Collector 获取事件
  │        · 新增 --mode CLI 参数
  │        · 保持 14 个 API 端点 / SSE 推送逻辑不变
  ├─ [0.5h] .gitignore 更新
  │          · 新增: ebpf/vmlinux.h, ebpf/*.o, ebpf/*.llc, __pycache__/
  ├─ [0.5h] 代码整理（清理 import、统一风格）
  └─ [1h] 无回归测试 [Win]
           · python -m pytest -v                     → 130 + 新增测试全部通过
           · python demo.py --auto                    → 37 场景全部通过
           · python main.py --scenario all             → 37 场景全部通过
           · python main.py --mode simulation --scenario n01  → --mode 参数生效
           · python app.py → 浏览器访问 localhost:8080 → Web 前端正常

[Win→Linux 同步节点 B] ← Day 4 结束时（关键！此后切换到 Linux 环境）
  git add main.py demo.py app.py config.yaml .gitignore
  git commit -m "Phase 2: entry points refactored to use Collector + config updated"
  git push
  # → 关闭 Windows IDE，启动 VMware，进入 Linux 环境
```

**交付标准**：
- `[Win]` 三入口全部通过 SimulationCollector 运行，37 场景无回归
- `[Win]` `--mode simulation` 参数在三个入口均生效
- `[Win]` 现有 130 个单元测试 + 新增测试全部通过
- `[Win]` config.yaml 新旧配置段共存，现有功能不受影响

---

### Phase 3：eBPF 探针 + Python 加载器 + strace 采集器（Day 5-8）`[Linux]`

> **环境**：Linux 虚拟机（VMware Ubuntu 22.04 LTS）
>
> **目标**：完成 eBPF C 探针开发编译、Python 加载器、strace 降级采集器，以及 Linux 端的单模块验证。
>
> **依赖**：Phase 1 产出的 `collector/base_collector.py`（ICollector 接口）已通过 Git 同步。

**环境预检清单**（参考迁移方案.md 第三阶段）：

```bash
# [Linux] 预检 — 在 Ubuntu 终端中执行
git pull                                        # 同步 Windows 端 Phase 1-2 代码
python3 --version                               # ≥ 3.10
source venv/bin/activate
pip list | grep -E "pyyaml|pytest"              # pyyaml + pytest 已安装
python -m pytest -v                             # 确认 Windows 端代码在 Linux 无回归

# eBPF 工具链（参考迁移方案.md §3.3）
clang --version                                 # clang 14.x
bpftool version                                 # bpftool v7.x
ls /sys/kernel/btf/vmlinux                      # BTF 支持存在
uname -r                                        # 内核 ≥ 5.15
sudo bpftool prog list                          # eBPF 权限 OK

# C++ 编译（可选，仅当需要在 Linux 编译模拟探针时）
g++ --version                                   # g++ 11.x
cmake --version                                 # cmake 3.22+
```

```
Day 5 (4h) [Linux]:
  ├─ [2h] ebpf/observer.bpf.c — execve tracepoint 探针
  │        · 挂载 tracepoint/syscalls/sys_enter_execve
  │        · 捕获 filename, argv（bpf_probe_read_user_str）
  │        · bpf_perf_event_output 推送事件
  │        · 填充 event_t 结构体（含 timestamp_ns/pid/ppid/comm）
  ├─ [1h] ebpf/Makefile + 编译验证
  │        · 生成 vmlinux.h: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
  │        · clang -target bpf -g -O2 -I. -c observer.bpf.c -o observer.bpf.o
  │        · bpftool prog load observer.bpf.o /sys/fs/bpf/observer_exec 验证加载
  └─ [1h] 用户态测试: 加载 .bpf.o → 运行 ls → 打印 execve 事件
           · 编写简易 C 测试程序或 Python ctypes 脚本验证事件输出

Day 6 (4h) [Linux]:
  ├─ [1.5h] ebpf/observer.bpf.c — openat tracepoint 探针
  │        · 挂载 tracepoint/syscalls/sys_enter_openat
  │        · 捕获 filename, flags（O_RDONLY/O_WRONLY/O_RDWR）
  │        · 区分读/写操作（flags & O_ACCMODE）
  ├─ [1.5h] ebpf/observer.bpf.c — connect tracepoint 探针
  │        · 挂载 tracepoint/syscalls/sys_enter_connect
  │        · 捕获 sockaddr → IP:Port（bpf_probe_read_user）
  │        · 支持 AF_INET (IPv4) 和 AF_INET6 (IPv6) 地址解析
  └─ [1h] 全量编译 + 手动测试三类 syscall 事件
           · make clean && make → 编译全部三个探针
           · 运行 ls（execve）、cat /etc/hostname（openat）、curl example.com（connect）
           · 验证每类事件都被正确捕获并输出

Day 7 (4h) [Linux]:
  ├─ [2.5h] collector/ebpf_collector.py — Python 加载器
  │        · libbpf ctypes 绑定:
  │          bpf_object__open / bpf_object__load / bpf_program__attach
  │          bpf_map__fd / perf_buffer__new / perf_buffer__poll / perf_buffer__free
  │        · perf ring buffer 消费 → _to_raw_event() 转换（按定稿 §3.3 映射表）
  │        · send_command() 空实现（日志记录 "eBPF 阻断将在第二版实现"）
  │        · detach() → 卸载 eBPF 程序 + 清理 maps
  │        · atexit 注册清理函数
  │        · 线程模型: perf_buffer__poll 在独立线程轮询 + queue.Queue 解耦
  ├─ [0.5h] 事件格式验证: 对比 eBPF RawEvent 与 SimulationCollector 的 RawEvent
  │          · 逐字段检查 event_type/pid/ppid/executable/file_path/remote_addr
  └─ [1h] 单元测试: tests/test_ebpf_collector.py
           · _to_raw_event() 字段映射（构造 mock event_t → 验证 RawEvent）
           · 生命周期管理（attach/detach 状态转换）
           · send_command() 返回 False + 日志记录

Day 8 (4h) [Linux]:
  ├─ [2h] collector/strace_collector.py
  │        · subprocess.Popen(["strace", "-f", "-tt", "-e",
  │                            "trace=execve,openat,connect", "-p", pid])
  │        · 逐行解析 strace 输出 → RawEvent
  │          execve: "1234 execve("/bin/ls", ["ls", "-la"], ... ) = 0"
  │          openat: "1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3"
  │          connect: "1234 connect(3, {sa_family=AF_INET, ...}) = 0"
  │        · send_command() 空实现（返回 False）
  │        · detach() → subprocess.terminate() + wait()
  ├─ [1h] 单元测试: tests/test_strace_collector.py
  │        · strace 输出行解析（覆盖 execve/openat/connect 三种格式）
  │        · 进程管理（启动/停止/超时处理）
  │        · send_command() 返回 False
  └─ [1h] 降级测试 [Linux]
           · 模拟 eBPF 不可用（临时重命名 libbpf.so）
           · 启动程序 → 验证自动降级为 StraceCollector
           · 恢复 libbpf.so → 验证恢复正常使用 EbpfCollector

[Linux 阶段提交]
  git add ebpf/ collector/ebpf_collector.py collector/strace_collector.py tests/
  git commit -m "Phase 3: eBPF probe + Python loader + strace collector"
  git push
```

**交付标准**：
- `[Linux]` observer.bpf.o 编译成功，bpftool 验证加载无错误
- `[Linux]` Python 加载器成功加载 + 消费事件
- `[Linux]` 手动运行 ls/cat/curl，ebpf_collector 能捕获其 execve/openat/connect
- `[Linux]` strace_collector 能正确解析 strace 输出为 RawEvent
- `[Linux]` 降级逻辑正常：eBPF 不可用 → 自动切换 strace

---

### Phase 4：跨环境集成联调（Day 9）`[Linux]` + `[Win↔Linux 同步]`

> **环境**：Linux 虚拟机为主，Windows 验证为辅
>
> **目标**：三模式切换联调、跨环境事件格式一致性验证、能力查询测试。

**环境预检清单**：

```bash
# [Linux] 预检
git pull                                        # 确保最新代码
python -m pytest -v                             # 全部单元测试通过
make -C ebpf/                                   # eBPF 编译产物存在
```

```powershell
# [Win] 预检（在切换回 Windows 验证时执行）
git pull                                        # 同步 Linux 端 Phase 3 代码
python -m pytest -v                             # 确认模拟模式不受 Linux 端代码影响
```

```
Day 9 (4h) [Linux 为主]:

  ── 上午: Linux 端三模式集成测试 ──
  ├─ [2h] 端到端集成: 三种模式切换测试 [Linux]
  │        · --mode simulation: 强制模拟模式 → 加载场景 YAML → 37 场景通过
  │        · --mode strace: strace 模式 → 捕获真实 ls/cat/curl syscall
  │        · --mode ebpf: eBPF 模式 → 捕获真实 ls/cat/curl syscall
  │        · mode=auto: 自动检测 → 选择 EbpfCollector（eBPF 可用时）
  │        · mode=auto: 自动检测 → 降级 StraceCollector（eBPF 不可用时）
  ├─ [0.5h] 能力查询测试 [Linux]
  │          · SimulationCollector.capabilities() → can_block_tier2=True
  │          · StraceCollector.capabilities() → can_block_tier2=False
  │          · EbpfCollector.capabilities() → can_block_tier2=False (第一版)
  │          · 各 name/time_source/is_transparent/performance_overhead 正确
  └─ [0.5h] 错误处理测试 [Linux]
           · eBPF 不可用 → 降级 strace + 日志提示
           · strace 不可用 → 报错退出 + 日志提示
           · 无效 --mode 值 → argparse 报错

  ── [Win↔Linux 同步节点 C] ──
  git push (Linux 端)
  # 切换到 Windows 环境
  git pull (Windows 端)

  ── 下午: Windows 端交叉验证 ──
  ├─ [0.5h] Windows 无回归 [Win]
  │          · python -m pytest -v → 全部通过（含新增 adapter/collector 测试）
  │          · python demo.py --auto → 37 场景通过
  │          · --mode simulation → 强制模拟模式正常
  └─ [0.5h] 事件格式一致性验证 [Win]
           · 从 Linux 端保存一份 eBPF RawEvent JSON（ls/cat/curl 各一条）
           · 在 Windows 端用 RawEvent.from_dict() 加载 → 验证字段完整
           · 对比 SimulationCollector 产出的同类型 RawEvent → 字段一致
```

**交付标准**：
- `[Linux]` 三种模式通过 `--mode` 参数可切换
- `[Linux]` 每种模式的事件能被 observer_core/ 正确处理
- `[Linux]` 降级逻辑正常工作
- `[Win]` Linux 端新增代码不影响 Windows 模拟模式
- `[双端]` eBPF RawEvent 与模拟 RawEvent 字段完全一致

---

### Phase 5：双环境全量验证 + 文档（Day 10）`[Win]` + `[Linux]`

> **环境**：双环境（上午 Windows、下午 Linux，或交替进行）
>
> **目标**：全量无回归、性能基准、文档收尾。

**环境预检清单**：

```powershell
# [Win] 预检
git pull
python -m pytest -v --tb=short                  # 全部通过
```

```bash
# [Linux] 预检
git pull
python -m pytest -v --tb=short                  # 全部通过
make -C ebpf/                                   # 编译产物最新
```

```
Day 10 (4h) [Win + Linux]:

  ── Windows 端验证 ──
  ├─ [1h] 全量无回归 [Win]
  │        · python -m pytest -v               → 130 + 新增测试全部通过
  │        · python demo.py --auto              → 37 场景通过 + 分析面板正常
  │        · python main.py --scenario all       → 37 场景通过
  │        · python app.py → 浏览器 localhost:8080 → Web 前端 + SSE 正常
  │        · --mode simulation → 三个入口均正常

  ── Linux 端验证 ──
  ├─ [1h] Linux 三模式验证 [Linux]
  │        · --mode simulation → 37 场景通过
  │        · --mode ebpf → 运行 ls/cat/curl → 事件正确捕获和处理
  │        · --mode strace → 运行 ls/cat/curl → 事件正确捕获和处理
  │        · python app.py → 浏览器访问 → SSE 推送 eBPF 真实事件
  │        · 自动降级测试 → 验证日志输出正确

  ── 性能 & 文档（可选 Linux）──
  ├─ [0.5h] 性能基准 [Linux]
  │        · 模拟模式 vs eBPF 模式事件处理延迟对比
  │        · perf ring buffer 丢失率测试（高负载场景）
  ├─ [0.5h] 环境准备脚本 [Linux]
  │        · scripts/setup_ebpf_env.sh（一键安装 eBPF 工具链）
  │        · 内容参考迁移方案.md §3.3 的安装命令
  └─ [1h] 文档更新 [Win 或 Linux]
           · README.md 新增 eBPF 开发指南章节
           · 新增双环境搭建说明（引用迁移方案.md）
           · 更新项目目录树（新增 adapter/ collector/ ebpf/）
```

**交付标准**：
- `[Win]` 全部测试通过，37 场景 + 130+ 单元测试无回归
- `[Linux]` 三种模式分别验证通过
- `[双端]` 三入口 × 三模式 = 9 种组合全部验证（Windows 3 种 + Linux 6 种）
- `[Linux]` 性能基准数据已记录
- `[双端]` 文档完整，新开发者可按文档从零搭建双环境

---

## 第七部分：测试验证清单

### 7.1 单元测试（新增）

| 测试项 | 模块 | 验证内容 |
|--------|------|---------|
| 平台检测-Windows | adapter/ | mock sys.platform="win32" → 返回 SimulationCollector |
| 平台检测-Linux+eBPF | adapter/ | mock BTF存在+libbpf可用+CAP_BPF → 返回 EbpfCollector |
| 平台检测-Linux-eBPF | adapter/ | mock BTF不存在 → 降级返回 StraceCollector |
| 管道工厂-Windows | adapter/ | 创建/打开/清理命名管道 |
| 管道工厂-Linux | adapter/ | 创建/打开/清理 FIFO |
| 时间源-VirtualClock | adapter/ | advance + now_ns 正确 |
| 时间源-realtime | adapter/ | time.time_ns() 精度 |
| SimCollector-单Agent | collector/ | 加载 n01 → yield 正确数量 RawEvent |
| SimCollector-多Agent | collector/ | 加载 m01 → agent_id 映射正确 |
| SimCollector-时钟推进 | collector/ | delay_ms → VirtualClock 推进正确 |
| StraceCollector-解析 | collector/ | strace 输出行 → RawEvent 字段正确 |
| EbpfCollector-转换 | collector/ | event_t → RawEvent 字段映射正确 |
| 能力查询 | collector/ | 三个 Collector 的 capabilities() 返回正确值 |

### 7.2 集成/验收测试

| 测试项 | 平台 | 通过标准 |
|--------|:---:|---------|
| 模拟模式无回归 | Windows | `python demo.py --auto` → 37 场景全部通过 |
| 130 单元测试无回归 | Windows | `pytest` → 130 passed |
| 平台自动检测 | Windows | 启动日志: "检测到 Windows 平台，启用模拟模式" |
| 平台自动检测 | Linux | 启动日志: "检测到 eBPF 支持，启用真实观测模式" |
| 强制模式覆盖 | Linux | `--mode simulation` 强制使用模拟模式 |
| eBPF 探针加载 | Linux | `observer.bpf.o` 加载成功，dmesg 无错误 |
| execve 捕获 | Linux | 运行 `ls` → eBPF 捕获 filename="/bin/ls" |
| openat 捕获 | Linux | Agent 读文件 → eBPF 捕获文件路径 |
| connect 捕获 | Linux | Agent 调用 API → eBPF 捕获目标 IP:Port |
| 事件格式一致 | Linux | eBPF 产生的 RawEvent 与模拟探针字段完全一致 |
| 降级 strace | Linux | 卸载 libbpf → 启动自动降级 → strace 模式正常运行 |
| Web 前端-模拟 | Windows | `python app.py` → 浏览器 → SSE 推送正常 |
| Web 前端-eBPF | Linux | `python app.py` → 浏览器 → SSE 推送真实 Agent 事件 |
| 三种模式切换 | Linux | `--mode simulation/strace/ebpf` 分别运行正确 |

---

## 第八部分：关键风险与缓解

| 风险 | 概率 | 缓解措施 |
|------|:---:|---------|
| eBPF 编译工具链不全 | 中 | 提供一键安装脚本 (`scripts/setup_ebpf_env.sh`) |
| 内核版本过旧（<5.8） | 低 | Ubuntu 22.04 默认 5.15+; 不支持则降级 strace |
| BTF 未启用 | 低 | 同上; HWE 内核默认启用 |
| CAP_BPF 权限不足 | 中 | `sudo` 运行或 `setcap cap_bpf,cap_perfmon+ep python3` |
| eBPF verifier 拒绝程序 | 中 | 开发阶段用 `bpftool prog load` 预检; 简化探针逻辑 |
| perf ring buffer 丢失事件 | 低 | 增大 `perf_buffer_page_count`; 监控丢失计数 |
| libbpf ctypes 绑定复杂度 | 中 | 可备选使用 `bcc` 或 `libbpf-cffi` 库 |
| SimulationCollector 重构影响现有流程 | 低 | Day 4 全天做无回归测试; 保留原代码路径作为 fallback |
| strace 输出格式多变 | 中 | 针对主要 syscall 格式编写解析器; 其他 syscall 跳过 |

---

## 第九部分：开发指南（给程序员）

### 9.1 eBPF 探针开发注意事项

1. **eBPF 指令数限制**：每个探针最多 100 万条 BPF 指令（Linux 5.2+）。单个探针保持简洁——捕获参数、推送事件，控制在 ~200 条指令内。

2. **字符串读取**：使用 `bpf_probe_read_user_str()` 从用户态内存读取 filename 和 argv。注意缓冲区大小（256 字节足够大多数路径，argv 截断到 512 字节）。

3. **perf ring buffer 推送**：每个 CPU 一个独立的 ring buffer。使用 `BPF_F_CURRENT_CPU` 标志确保事件不跨 CPU。

4. **CO-RE 兼容性**：使用 `bpf_core_read()` 宏读取内核结构体字段，而不是硬编码偏移。这确保同一 `.bpf.o` 在不同内核版本上运行。

5. **第一版不含阻断逻辑**：探针仅做观测和推送。第二版加入 block_policy map 查询和 kprobe 阻断程序。

### 9.2 Python 加载器开发注意事项

1. **libbpf 绑定**：使用 Python 的 `ctypes` 调用 `libbpf.so`。需要定义的函数：`bpf_object__open`、`bpf_object__load`、`bpf_program__attach`、`bpf_map__fd`、`perf_buffer__new`、`perf_buffer__poll`、`perf_buffer__free`。

2. **ring buffer 消费**：`perf_buffer__new` 注册回调函数，`perf_buffer__poll(timeout_ms)` 轮询。回调中将 `event_t` 的 C 结构体转换为 Python RawEvent（按 §3.3 映射表）。

3. **生命周期管理**：`attach()` → 加载+挂载，`detach()` → 卸载+清理 maps。使用 `atexit` 注册清理函数防止异常退出时遗留 eBPF 程序。

4. **线程模型**：`perf_buffer__poll` 需要在独立线程中运行（或使用非阻塞轮询），避免阻塞主处理循环。`start()` 方法中使用 `threading.Thread` + `queue.Queue` 解耦。

### 9.3 SimulationCollector 迁移注意事项

1. **逻辑来源**：从 `main.py` 的 `create_raw_event()`（L67-84）和 `demo.py` 的 `ScenarioRunner.run_event()`（L196-205）提取事件创建逻辑。

2. **保持兼容**：SimulationCollector yield 的 RawEvent 必须与现有 `create_raw_event()` 产生的 RawEvent 字段完全一致，确保 `observer_core/` 无需任何修改。

3. **多 Agent 场景**：场景 YAML 中的 `agents` 列表定义了 agent_id → pid/framework 的映射。`start()` 中需要构建 `agents_map` 字典，为每个事件填充正确的 `agent_id` 和 `agent_framework`。

### 9.4 集成注意事项

1. **事件格式一致性**：三个 Collector 产生的 RawEvent 必须字段完全一致。开发时先对比三个 Collector 输出的事件 JSON，确保 `observer_core/` 可以无缝接收。

2. **时间戳差异**：eBPF 使用 `bpf_ktime_get_ns()`（monotonic clock），模拟模式使用 VirtualClock。`observer_core/` 只读取 `timestamp_ns` 字段，不关心时钟类型。

3. **demo.py/app.py 改造最小化**：改造原则是将"直接创建 RawEvent"替换为"从 Collector 获取 RawEvent"，其余处理链路（normalizer → engine → scorer → decision → blocking → audit）完全不变。

---

## 第十部分：第二版预留（eBPF 阻断）

以下内容不在第一版范围内，作为后续迭代目标：

1. **eBPF 阻断探针**：新增 kprobe 程序挂载到 `__x64_sys_execve` / `__x64_sys_openat` / `__x64_sys_connect`，使用 `bpf_override_return(ctx, -EPERM)` 实现内核态阻断。

2. **block_policy map**：`BPF_MAP_TYPE_HASH`，key=pid(u32)，value=block_flags(u64) 位掩码。

3. **动态挂载**：kprobe 程序仅在需要阻断时动态挂载，平时不挂载，零开销。

4. **EbpfCollector.send_command() 实现**：更新 block_policy map → 内核返回 EPERM → Agent 正常处理错误。

---

## 第十一部分：一句话总结

> **新增 `adapter/`（平台适配，~140行）+ `collector/`（采集层，ICollector 接口 + 3 个实现类，~650行）+ `ebpf/observer.bpf.c`（eBPF 内核探针，~250行C），`observer_core/` 零改动。`ICollector.start()` 直接 yield RawEvent（不走管道），三入口直接消费。eBPF 第一版仅做观测（tracepoint），阻断留待第二版（kprobe + bpf_override_return）。config.yaml 全量保留现有字段并新增 5 个配置段。三模式通过 `--mode` 参数切换。总新增代码 ~1080 行，改动 ~180 行，开发排期 10 天，双环境分工：Day 1-4 Windows（适配层+接口+入口改造+无回归），Day 5-8 Linux VM（eBPF探针+加载器+strace），Day 9 跨环境集成联调，Day 10 双端全量验证+文档。环境切换仅 2 次。**
