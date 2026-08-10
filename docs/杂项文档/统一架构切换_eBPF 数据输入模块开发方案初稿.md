# 统一架构切换 & eBPF 数据输入模块 — 开发方案

> **目标**：将当前 Windows 模拟系统升级为 Windows/Linux 统一架构。Windows 保留模拟探针 + 场景回放（测试/训练），Linux 新增 eBPF 探针采集真实 Agent syscall（生产验证）。两套系统共用 `observer_core/`，通过平台检测自动切换采集层。

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
| **模式自动检测** | `main.py` 启动时检测 `sys.platform`，自动选择采集模式 |
| **CLI/Web 通用** | `demo.py` 和 `app.py` 共用同一套模式选择逻辑 |

### 1.3 架构升级路径

```
升级前 (当前):
  场景 YAML → [C++ 模拟探针] → Windows 命名管道 → [Python Observer (Windows)]
  虚构事件    虚构 syscall                         全管道逻辑

升级后 (统一架构):

  Windows (模拟模式):
    场景 YAML → [C++ 模拟探针] → Windows 命名管道 ─┐
    虚构事件    虚构 syscall                        │
                                                    ├→ [Python Observer] → 输出
  Linux (真实模式):                                  │   observer_core/ 零改动
    真实 Agent → [eBPF 探针] → Linux FIFO ──────────┘
    真实 syscall  内核捕获+阻断
```

---

## 第二部分：统一架构设计

### 2.1 分层架构图

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          入口层 (main.py / demo.py / app.py)              │
│                                                                          │
│  职责: 解析 CLI 参数 → 加载 config.yaml → 平台检测 → 选择采集模式         │
│        创建管道 → 初始化 Observer → 启动                                           │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     适配层 (adapter/)            [新增 ~150 行]            │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐   │
│  │ platform_detect  │  │ pipe_factory      │  │ time_source          │   │
│  │ · sys.platform   │  │ · Win命名管道创建  │  │ · 模拟: VirtualClock │   │
│  │ · 模式决策       │  │ · Linux FIFO创建   │  │ · 真实: time.time()  │   │
│  │ · 能力查询       │  │ · 统一 open_pipe() │  │                      │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────────┘   │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     采集层 (collector/)          [新增 ~500 行]            │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    ICollector (抽象接口)                           │   │
│  │  + attach(target_pid, agent_id) → bool                           │   │
│  │  + start() → Iterator[RawEvent]                                  │   │
│  │  + send_command(cmd: Command) → bool   # 反向阻断指令             │   │
│  │  + detach() → None                                               │   │
│  │  + capabilities → CollectorCapabilities  # 能力查询              │   │
│  └──────────┬───────────────────┬──────────────────┬────────────────┘   │
│             │                   │                  │                    │
│  ┌──────────▼──────┐ ┌─────────▼──────┐ ┌─────────▼──────────────┐    │
│  │ Simulation-     │ │ Strace-        │ │ EbpfCollector           │    │
│  │ Collector       │ │ Collector      │ │                         │    │
│  │ (Windows/通用)  │ │ (Linux)        │ │ (Linux, 内核eBPF)       │    │
│  │                 │ │                │ │                         │    │
│  │ 封装C++探针进程  │ │ subprocess     │ │ libbpf 加载 .bpf.o     │    │
│  │ + 场景YAML注入   │ │ strace -p PID  │ │ + perf ring buffer     │    │
│  │ + 虚拟时钟       │ │ + 行解析       │ │ + eBPF map 阻断        │    │
│  │ + 反向管道模拟   │ │ · 仅观测       │ │ · 观测 + 阻断          │    │
│  └─────────────────┘ └───────────────┘ └────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                  CollectorCapabilities (能力描述)                   │   │
│  │  · can_observe: bool        # 是否支持观测                       │   │
│  │  · can_block: bool          # 是否支持阻断 (Tier2 返回EPERM)      │   │
│  │  · can_terminate: bool      # 是否支持终止进程 (Tier3)            │   │
│  │  · is_transparent: bool     # 对Agent是否无感知                  │   │
│  │  · performance_overhead: str # "low" | "medium" | "high"         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ 统一输出: RawEvent JSON → 管道
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              核心逻辑层 (observer_core/)              [零改动]             │
│                                                                          │
│  PipeReader → EventNormalizer → RuleEngine → RiskScorer                 │
│  → DecisionEngine → BlockingCoordinator → BehaviorGraph → AuditLogger   │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 平台检测与模式决策流程

```
main.py 启动
    │
    ▼
读取 config.yaml → mode 字段
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
                    · libbpf 可用?
                    · 当前用户有 CAP_BPF?
                    │
                    ├── 全部满足 → EbpfCollector
                    │              + 打印: "检测到 eBPF 支持，启用真实采集+阻断模式"
                    │
                    └── 部分缺失 → StraceCollector
                                   + 打印: "eBPF 不可用，降级为 strace 观测模式"
                                   + 提示: "阻断功能受限"
```

### 2.3 数据流（统一架构）

```
                    ┌─────────────────────────────┐
                    │         main.py 入口          │
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
            │ 场景YAML→C++探针   │ strace -p PID      │ eBPF tracepoint
            │ → 虚拟时间戳       │ → 行解析           │ → perf ring buffer
            │                    │ → 系统时间戳        │ → 系统时间戳
            │                    │                    │
            └────────────────────┼────────────────────┘
                                 │
                    统一: RawEvent JSON 行
                                 │
                                 ▼
                    ┌───────────────────────┐
                    │  adapter/pipe_factory  │
                    │  Win命名管道/Linux FIFO│
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │  observer_core/        │
                    │  PipeReader 接收       │
                    │  → 归一化              │
                    │  → 规则匹配            │
                    │  → 风险评分            │
                    │  → 研判决策            │
                    │  → 阻断执行            │
                    │  → 审计输出            │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
                    ▼                       ▼
            ┌──────────────┐        ┌──────────────┐
            │ 阻断指令      │        │ 审计报告     │
            │ (反向管道)    │        │ 图谱/MD/JSON │
            └──────┬───────┘        └──────────────┘
                   │
                   ▼
            Collector.send_command()
            · Simulation: 模拟阻断
            · Strace: 空实现(不支持)
            · Ebpf: 更新eBPF map → 内核返回EPERM
```

### 2.4 时间模型统一

| 模式 | 时间源 | 对 `observer_core/` 的影响 |
|------|--------|:---:|
| 模拟模式 | `VirtualClock`（场景 YAML 的 `delay_ms` 推进） | 零影响——事件 `timestamp_ns` 字段由 Collector 生成 |
| strace 模式 | `time.time()` → 纳秒（`strace -ttt` 提供微秒精度） | 零影响——同上 |
| eBPF 模式 | `bpf_ktime_get_ns()`（内核 monotonic 时钟，纳秒） | 零影响——同上 |

**关键设计**：`observer_core/` 不关心时间戳来源。它只从 `RawEvent.timestamp_ns` 读取值。Collector 负责生成这个值，模拟模式用虚拟时钟，真实模式用系统时钟。

---

## 第三部分：eBPF 数据输入模块设计（重点）

### 3.1 eBPF 探针架构

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
│  │  3. 消费 perf ring buffer → 构造 RawEvent → 推送管道        │ │
│  │  4. 接收阻断指令 → 更新 eBPF map (block_policy)             │ │
│  │  5. 管理 eBPF 程序生命周期 (加载/挂载/卸载/清理)             │ │
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
│  │  observer.bpf.c (~300行 C)    预编译 → observer.bpf.o       │ │
│  │                                                            │ │
│  │  ┌─────────────────────────────────────────────────────┐  │ │
│  │  │  探针 1: tracepoint/syscalls/sys_enter_execve        │  │ │
│  │  │  · 捕获: filename, argv, envp                       │  │ │
│  │  │  · 进程信息: pid, ppid, uid, comm                   │  │ │
│  │  └─────────────────────────────────────────────────────┘  │ │
│  │                                                            │ │
│  │  ┌─────────────────────────────────────────────────────┐  │ │
│  │  │  探针 2: tracepoint/syscalls/sys_enter_openat        │  │ │
│  │  │  · 捕获: filename, flags (O_RDONLY/O_WRONLY/O_RDWR) │  │ │
│  │  └─────────────────────────────────────────────────────┘  │ │
│  │                                                            │ │
│  │  ┌─────────────────────────────────────────────────────┐  │ │
│  │  │  探针 3: tracepoint/syscalls/sys_enter_connect       │  │ │
│  │  │  · 捕获: sockaddr (IP+Port), addrlen, family        │  │ │
│  │  └─────────────────────────────────────────────────────┘  │ │
│  │                                                            │ │
│  │  每个探针:                                                  │ │
│  │  1. 从寄存器/栈读取 syscall 参数                            │ │
│  │  2. 构造 event_t 结构体                                     │ │
│  │  3. 查询 block_policy map → 决定是否阻断                    │ │
│  │     · 命中阻断 → bpf_override_return(ctx, -EPERM)          │ │
│  │     · 未命中 → 正常执行                                    │ │
│  │  4. 推送 event_t 到 perf ring buffer                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  eBPF Maps:                                                      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  events (BPF_MAP_TYPE_PERF_EVENT_ARRAY)                    │ │
│  │  · 内核→用户态事件推送                                     │ │
│  │  · 每个 CPU 一个 ring buffer                               │ │
│  │                                                            │ │
│  │  block_policy (BPF_MAP_TYPE_HASH)                          │ │
│  │  · key: pid (u32)                                          │ │
│  │  · value: block_flags (u64) — 位掩码:                     │ │
│  │      bit 0: 阻断 execve                                    │ │
│  │      bit 1: 阻断 openat (写操作)                            │ │
│  │      bit 2: 阻断 connect                                    │ │
│  │  · 用户态通过 Python 更新此 map 下发阻断指令                 │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 eBPF 事件结构体定义

```
event_t (C 结构体, 内核态与用户态共享):

  u64  timestamp_ns;       // bpf_ktime_get_ns()
  u32  pid;                // bpf_get_current_pid_tgid() >> 32
  u32  ppid;               // 从 task_struct 读取
  u32  uid;                // 从 task_struct 读取
  u8   event_type;         // 0=execve, 1=openat, 2=connect
  u8   blocked;            // 0=未阻断, 1=已阻断 (由探针设置)
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
```

### 3.3 eBPF 探针三个 tracepoint 的挂载点

| 探针 | 挂载点 | 捕获的关键参数 |
|------|--------|--------------|
| execve | `tracepoint/syscalls/sys_enter_execve` | `ctx->args[0]` → filename 指针, `ctx->args[1]` → argv 指针 |
| openat | `tracepoint/syscalls/sys_enter_openat` | `ctx->args[1]` → filename 指针, `ctx->args[2]` → flags |
| connect | `tracepoint/syscalls/sys_enter_connect` | `ctx->args[1]` → sockaddr 指针, `ctx->args[2]` → addrlen |

**为什么用 tracepoint 而非 kprobe？**
- tracepoint 是内核稳定的 ABI，不会因内核版本变化而失效
- kprobe 可以挂在任意函数上但接口不稳定
- 性能差异可忽略

### 3.4 阻断机制的 eBPF 实现

```
阻断数据流:

Python Observer 研判决策: BLOCK
    │
    ▼
CommandSender → 反向管道 → EbpfCollector.send_command()
    │
    ▼
更新 eBPF map: block_policy[target_pid] = block_flags
    │
    ▼
Agent 下次调用 execve/openat/connect:
    │
    ▼
eBPF 探针触发:
    1. 读取当前 pid
    2. 查询 block_policy map: flags = bpf_map_lookup_elem(&block_policy, &pid)
    3. if flags & BLOCK_EXECVE:
           bpf_override_return(ctx, -EPERM)   ← 修改 syscall 返回值
           event.blocked = 1
       else:
           正常执行
    4. 推送 event 到 perf ring buffer（包含 blocked 标志）
    │
    ▼
Agent 进程收到: execve() = -1, errno = EPERM (Operation not permitted)
    │
    ▼
Agent 正常处理错误（等同于遇到权限不足），不会崩溃
```

**阻断粒度设计**：`block_flags` 是位掩码，支持对同一 pid 的不同 syscall 类型独立阻断：

```c
#define BLOCK_EXECVE    (1 << 0)
#define BLOCK_OPENAT_WR (1 << 1)   // 仅阻断写操作
#define BLOCK_CONNECT   (1 << 2)
#define BLOCK_ALL       (BLOCK_EXECVE | BLOCK_OPENAT_WR | BLOCK_CONNECT)
```

### 3.5 编译 eBPF 程序所需的环境

```bash
# 一次性环境准备（在 VMware Ubuntu 22.04 中）

# 1. 安装编译工具链
sudo apt update
sudo apt install -y clang llvm libbpf-dev make linux-headers-$(uname -r)

# 2. 生成 vmlinux.h（内核类型定义）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

# 3. 编译
cd ebpf/
clang -target bpf -g -O2 \
      -I. \
      -c observer.bpf.c \
      -o observer.bpf.o

# 产出: ebpf/observer.bpf.o (~50KB)
# 这是预编译的 eBPF 字节码，跨内核版本兼容（CO-RE）
```

**开发者注意**：`vmlinux.h` 和 `observer.bpf.o` 不需要提交到 Git。`observer.bpf.o` 是编译产物，在目标 Linux 机器上编译一次即可。Python 加载器使用 `libbpf` 的 CO-RE（Compile Once - Run Everywhere）功能，同一个 `.bpf.o` 可以在不同内核版本上运行。

---

## 第四部分：模块接口定义

### 4.1 `ICollector` 接口（核心抽象）

```python
# collector/base_collector.py

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator

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
    上层 (main.py / demo.py) 通过此接口与采集层交互，
    不关心底层是模拟还是真实采集。
    """

    @abstractmethod
    def capabilities(self) -> CollectorCapabilities:
        """返回采集器能力描述"""
        ...

    @abstractmethod
    def attach(self, target_pid: int, agent_id: str) -> bool:
        """
        附着到目标 Agent 进程。
      
        参数:
            target_pid: Agent 主进程 PID（模拟模式下为构造的 pid）
            agent_id:   Agent 标识字符串
      
        返回:
            True:  附着成功
            False: 附着失败（权限不足、进程不存在等）
      
        模拟模式: 返回 True（无需真实附着）
        strace:   subprocess.Popen(["strace", "-p", str(target_pid), ...])
        eBPF:     通过 libbpf 加载并挂载探针
        """
        ...

    @abstractmethod
    def start(self) -> Iterator['RawEvent']:
        """
        开始采集，返回 RawEvent 生成器。
      
        Yields:
            RawEvent: 每个捕获到的系统调用事件
      
        模拟模式: 读取场景 YAML → 逐个生成事件 → yield
        strace:   逐行读取 strace 输出 → 解析 → yield
        eBPF:     消费 perf ring buffer → 构造 RawEvent → yield
        """
        ...

    @abstractmethod
    def send_command(self, cmd: 'Command') -> bool:
        """
        接收阻断指令（反向通道）。
      
        参数:
            cmd: Command 对象，包含 cmd_type, target_pid, action 等
      
        返回:
            True:  指令已下发
            False: 指令下发失败或不支持
      
        模拟模式: 标记事件为 blocked，模拟返回 EPERM
        strace:   不支持（返回 False，记录警告）
        eBPF:     更新 eBPF block_policy map
        """
        ...

    @abstractmethod
    def detach(self) -> None:
        """
        断开采集，清理资源。
      
        模拟模式: 终止 C++ 子进程
        strace:   终止 strace 子进程
        eBPF:     卸载探针 + 清理 maps
        """
        ...

    @abstractmethod
    def get_process_tree(self) -> dict:
        """
        获取当前追踪的进程树快照。
      
        返回:
            {pid: {"ppid": ..., "agent_id": ..., "comm": ...}, ...}
      
        用于 EventNormalizer 初始化或调试。
        """
        ...
```

### 4.2 `EbpfCollector` 设计要点

```
collector/ebpf_collector.py (~250行)

职责:
  1. 加载预编译的 eBPF 字节码 (observer.bpf.o)
  2. 挂载三类 tracepoint 探针
  3. 设置 perf ring buffer 回调
  4. 消费事件 → 构造 RawEvent → 推送管道
  5. 接收阻断指令 → 更新 eBPF map
  6. 管理 eBPF 生命周期

依赖:
  · libbpf (通过 Python ctypes 或 bcc 绑定)
  · observer.bpf.o (预编译的 eBPF 字节码)

关键实现点:
  · perf ring buffer 消费: 设置回调函数，收到 event_t 后构造 RawEvent
  · eBPF map 更新: 通过 libbpf 的 bpf_map_update_elem 写入 block_policy
  · 进程树: 通过读取 /proc/{pid}/stat 构建
  · 错误处理: 权限不足(CAP_BPF) → 降级为 strace; BTF 不存在 → 报错退出
```

### 4.3 `SimulationCollector` 设计要点

```
collector/simulation_collector.py (~150行)

职责:
  封装现有的 C++ 模拟探针 + 场景 YAML 注入逻辑。
  对上层暴露与 EbpfCollector 完全相同的 ICollector 接口。

与现有代码的关系:
  · 复用 cpp_probe/ 的全部代码
  · 复用 scenarios/ 的全部 YAML 文件
  · demo.py 中现有的场景执行逻辑移入此模块
  · demo.py 本身简化为模式选择 + 调用 Collector
```

### 4.4 管道适配器接口

```python
# adapter/pipe_factory.py

class PipeAdapter:
    """
    管道适配器：屏蔽 Windows 命名管道与 Linux FIFO 的差异。
  
    对外暴露统一接口：
        open_event_pipe(mode="r") → file-like object
        open_command_pipe(mode="w") → file-like object
        cleanup() → None
    """

    @staticmethod
    def create(config: dict, platform: 'PlatformInfo') -> 'PipeAdapter':
        """
        工厂方法：根据平台创建对应的管道适配器。
      
        Windows: 使用命名管道 (\\.\pipe\observer_events)
        Linux:   使用 FIFO (/tmp/observer/events)
        """
        ...

    def open_event_pipe(self, mode: str):
        """
        打开正向管道（探针 → Observer）。
        自动处理创建/打开逻辑。
        """
        ...

    def open_command_pipe(self, mode: str):
        """
        打开反向管道（Observer → 探针）。
        """
        ...

    def cleanup(self):
        """
        清理管道资源。
        Linux: 删除 FIFO 文件
        Windows: 断开命名管道
        """
        ...
```

### 4.5 配置接口（config.yaml 完整版）

```yaml
# config.yaml — 统一架构版

# ============================================================
# 运行模式 (必填)
# ============================================================
mode: "auto"
# 可选值:
#   "auto"        — 自动检测 (Windows→simulation, Linux→ebpf)
#   "simulation"  — 强制模拟模式 (场景YAML + C++模拟探针)
#   "strace"      — 强制 strace 观测模式 (仅Linux)
#   "ebpf"        — 强制 eBPF 观测+阻断模式 (仅Linux)

# ============================================================
# 管道配置
# ============================================================
pipeline:
  # Windows (命名管道)
  win_event_pipe: "\\\\.\\pipe\\observer_events"
  win_command_pipe: "\\\\.\\pipe\\observer_commands"

  # Linux (FIFO)
  linux_event_fifo: "/tmp/observer/events"
  linux_command_fifo: "/tmp/observer/commands"

# ============================================================
# 评分权重 (两个模式通用)
# ============================================================
scoring:
  weights:
    rule_match: 0.40
    baseline_deviation: 0.25
    context_risk: 0.20
    sequence_anomaly: 0.15

# ============================================================
# 模拟模式配置
# ============================================================
simulation:
  scenarios_dir: "scenarios/"
  cpp_probe_exe: "cpp_probe/build/cpp_probe"
  virtual_clock_start_ns: 0
  step_by_step: true               # 是否逐步显示事件

# ============================================================
# eBPF 采集模式配置
# ============================================================
ebpf:
  bpf_object_path: "ebpf/observer.bpf.o"   # 预编译的 eBPF 字节码
  target_pid: null                          # 运行时指定 (-p 参数)
  target_agent_id: "observed-agent"
  perf_buffer_page_count: 64               # perf ring buffer 页数
  heartbeat_interval_sec: 15               # SSE 心跳间隔
  block_map_name: "block_policy"           # 阻断策略 map 名称

# ============================================================
# strace 采集模式配置 (降级备选)
# ============================================================
strace:
  strace_binary: "/usr/bin/strace"
  trace_syscalls: "execve,openat,connect,unlink,sendto"
  target_pid: null
```

---

## 第五部分：文件清单与改动范围

### 5.1 新增文件

| 文件 | 行数 | 说明 |
|------|:---:|------|
| `adapter/__init__.py` | ~10 | 导出 PlatformInfo, PipeAdapter, 模式决策 |
| `adapter/platform_detect.py` | ~40 | 平台检测 + eBPF 能力查询 |
| `adapter/pipe_factory.py` | ~60 | 管道工厂（Win命名管道 / Linux FIFO） |
| `adapter/time_source.py` | ~30 | 时间源抽象（VirtualClock / realtime） |
| `collector/__init__.py` | ~10 | 导出 ICollector, CollectorCapabilities |
| `collector/base_collector.py` | ~60 | ICollector 抽象接口定义 |
| `collector/simulation_collector.py` | ~150 | 模拟采集器（封装现有C++探针+场景YAML） |
| `collector/strace_collector.py` | ~150 | strace 采集器 |
| `collector/ebpf_collector.py` | ~250 | eBPF 采集器（加载.bpf.o + ring buffer消费 + map阻断） |
| `ebpf/observer.bpf.c` | ~300 | eBPF 内核态 C 程序（三类tracepoint探针） |
| `ebpf/vmlinux.h` | — | 内核类型定义（bpftool 生成，不提交Git） |
| `ebpf/Makefile` | ~20 | 编译脚本 |
| **新增总计** | **~1080** | |

### 5.2 改动文件

| 文件 | 改动 | 说明 |
|------|:---:|------|
| `config.yaml` | ~40 行 | 新增 mode + ebpf + strace 配置段 |
| `main.py` | ~40 行 | 加入模式选择逻辑 + Collector 创建 |
| `demo.py` | ~20 行 | 委托给 main.py 的模式选择 |
| `app.py` | ~20 行 | 同上（Web 模式） |
| `models/event.py` | 0 | 零改动 |
| `observer_core/` | 0 | 零改动 |
| `scenarios/` | 0 | 零改动 |
| `rules/` | 0 | 零改动 |
| `cpp_probe/` | 0 | 零改动 |
| **改动总计** | **~120** | |

### 5.3 项目完整目录树

```
observer_sim/
│
├── main.py                          # [改动] 入口 + 模式选择
├── demo.py                          # [改动] CLI 模式（委托给 main）
├── app.py                           # [改动] Web 模式（委托给 main）
├── config.yaml                      # [改动] 统一配置
│
├── adapter/                         # [新增] 平台适配层
│   ├── __init__.py
│   ├── platform_detect.py           # sys.platform + eBPF能力查询
│   ├── pipe_factory.py              # Win命名管道 / Linux FIFO
│   └── time_source.py              # VirtualClock / realtime
│
├── collector/                       # [新增] 采集层
│   ├── __init__.py
│   ├── base_collector.py            # ICollector + CollectorCapabilities
│   ├── simulation_collector.py      # 模拟采集器 (封装C++探针)
│   ├── strace_collector.py          # strace 采集器
│   └── ebpf_collector.py            # eBPF 采集器
│
├── ebpf/                            # [新增] eBPF 探针
│   ├── observer.bpf.c               # eBPF C 程序 (3个tracepoint)
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

## 第六部分：开发排期

### Phase 1：平台适配层 + 接口定义（Day 1-2）

```
Day 1 (4h):
  ├─ [1h] adapter/platform_detect.py — 平台检测 + eBPF 能力查询
  ├─ [1h] adapter/pipe_factory.py — 管道工厂
  ├─ [1h] adapter/time_source.py — 时间源抽象
  └─ [1h] 单元测试: Windows 和 Linux 上分别验证平台检测

Day 2 (4h):
  ├─ [1h] collector/base_collector.py — ICollector 接口 + CollectorCapabilities
  ├─ [1h] collector/simulation_collector.py — 封装现有 C++ 探针为新接口
  ├─ [1h] 修改 main.py / demo.py / app.py — 模式选择逻辑
  └─ [1h] 联调: Windows 上模拟模式通过新接口运行，确保无回归

交付标准:
  · Windows: python demo.py → 模拟模式，所有37个场景正常运行
  · Linux:   python demo.py → 自动检测到Linux，提示"eBPF/真实Agent模式"
```

### Phase 2：eBPF C 探针开发 + 编译（Day 3-5）

```
Day 3 (4h):
  ├─ [2h] ebpf/observer.bpf.c — execve tracepoint 探针
  │        · 挂载 tracepoint/syscalls/sys_enter_execve
  │        · 捕获 filename, argv
  │        · bpf_perf_event_output 推送事件
  │        · 查询 block_policy map
  ├─ [1h] ebpf/Makefile + 编译验证
  └─ [1h] 用户态测试程序: 加载 .bpf.o → 打印事件

Day 4 (4h):
  ├─ [1.5h] ebpf/observer.bpf.c — openat tracepoint 探针
  ├─ [1.5h] ebpf/observer.bpf.c — connect tracepoint 探针
  ├─ [0.5h] block_policy map + bpf_override_return 阻断逻辑
  └─ [0.5h] 编译 + 手动测试三类 syscall 事件

Day 5 (4h):
  ├─ [2h] collector/ebpf_collector.py — Python 加载器
  │        · libbpf 加载 observer.bpf.o
  │        · perf ring buffer 消费 → 构造 RawEvent
  │        · send_command → 更新 block_policy map
  │        · detach → 清理
  ├─ [1h] strace_collector.py (降级备选，边写边测)
  └─ [1h] 事件格式验证: eBPF 产生的 RawEvent 与模拟探针格式一致

交付标准:
  · observer.bpf.o 编译成功
  · Python 加载器成功加载 + 消费事件
  · 手动运行 gptme，ebpf_collector 能捕获其 execve/openat/connect
```

### Phase 3：集成联调 + 阻断验证（Day 6-8）

```
Day 6 (4h):
  ├─ [2h] 端到端集成: ebpf_collector → 管道 → observer_core
  │        · 验证: 真实 Agent 的 syscall 被正确归一化/评分/研判
  ├─ [1h] 反向管道联调: BlockingCoordinator → CommandSender → eBPF map
  └─ [1h] 构造测试 Agent: 让它执行 rm -rf / → 验证阻断

Day 7 (4h):
  ├─ [2h] 三种采集器切换测试:
  │        · Windows: simulation_collector 正常运行
  │        · Linux --mode simulation: 强制模拟模式
  │        · Linux --mode strace: strace 降级模式
  │        · Linux --mode ebpf: eBPF 完整模式
  ├─ [1h] 能力查询测试: capabilities() 返回正确的能力描述
  └─ [1h] 错误处理: eBPF 不可用 → 降级 strace; strace 不可用 → 报错

Day 8 (4h):
  ├─ [2h] 完整阻断回路测试:
  │        · Tier2: Agent 执行 rm -rf / → eBPF 返回 EPERM → Agent 不崩溃
  │        · Tier3: Agent 反弹 shell → eBPF map 标记 → SIGKILL
  │        · 验证阻断后审计日志记录正确
  ├─ [1h] 性能基准: 对比模拟模式 vs eBPF 模式的事件处理延迟
  └─ [1h] 文档: README 更新 + eBPF 编译指南

交付标准:
  · 三个模式通过 --mode 参数可切换
  · eBPF 模式: 真实 Agent syscall → 归一化 → 评分 → 研判 → 阻断 → 审计 全链路
  · Tier2 阻断: Agent 收到 EPERM，不崩溃，其他正常操作继续
```

---

## 第七部分：测试验证清单

| 测试项 | 平台 | 通过标准 |
|--------|:---:|---------|
| 模拟模式无回归 | Windows | `python demo.py` → 37 场景全部通过 |
| 平台自动检测 | Windows | 启动日志显示 "检测到 Windows 平台，启用模拟模式" |
| 平台自动检测 | Linux | 启动日志显示 "检测到 eBPF 支持，启用真实采集模式" |
| 强制模式覆盖 | Linux | `--mode simulation` 强制使用模拟模式 |
| eBPF 探针加载 | Linux | `observer.bpf.o` 加载成功，dmesg 无错误 |
| execve 捕获 | Linux | 运行 `ls` → eBPF 捕获 filename="/bin/ls" |
| openat 捕获 | Linux | Agent 读文件 → eBPF 捕获文件路径 |
| connect 捕获 | Linux | Agent 调用 API → eBPF 捕获目标 IP:Port |
| 事件格式一致 | Linux | eBPF 产生的 RawEvent 与模拟探针字段完全一致 |
| Tier2 阻断 | Linux | `rm -rf /` → EPERM → Agent 不崩溃 → 审计日志记录 |
| Tier3 阻断 | Linux | 反弹 shell → SIGKILL → 进程终止 → 证据保留 |
| 降级 strace | Linux | 卸载 libbpf → 启动自动降级 → strace 模式正常运行 |
| 双向管道通信 | Linux | 正向: 事件推送 | 反向: 阻断指令下发 |
| Web 前端 | Linux | `python app.py` → 浏览器访问 → 实时 SSE 推送真实 Agent 事件 |

---

## 第八部分：关键风险与缓解

| 风险 | 概率 | 缓解措施 |
|------|:---:|---------|
| eBPF 编译工具链不全 | 中 | 提供一键安装脚本 (`scripts/setup_ebpf_env.sh`) |
| 内核版本过旧（<5.8） | 低 | Ubuntu 22.04 默认 5.15+; 不支持则降级 strace |
| BTF 未启用 | 低 | 同上; HWE 内核默认启用 |
| CAP_BPF 权限不足 | 中 | `sudo` 运行或 `setcap cap_bpf+ep python3` |
| eBPF verifier 拒绝程序 | 中 | 开发阶段用 `bpftool prog load` 预检; 简化探针逻辑 |
| Agent 可检测到 eBPF | 极低 | eBPF 不修改 Agent 进程的 `/proc` 状态; 无 TracerPid |
| perf ring buffer 丢失事件 | 低 | 增大 `perf_buffer_page_count` (默认 64 页); 监控丢失计数 |

---

## 第九部分：开发指南（给程序员）

### 9.1 eBPF 探针开发注意事项

1. **eBPF 指令数限制**：每个探针最多 100 万条 BPF 指令（Linux 5.2+）。单个探针逻辑保持简洁——捕获参数、查 map、推送事件，控制在 ~200 条指令内。

2. **字符串读取**：使用 `bpf_probe_read_user_str()` 从用户态内存读取 filename 和 argv。注意缓冲区大小（256 字节足够大多数路径，argv 截断到 512 字节）。

3. **阻塞阻断的时机**：`bpf_override_return(ctx, -EPERM)` 必须在探针逻辑的最前面，先判断阻断再推送事件。因为 `bpf_override_return` 之后 syscall 不执行，后续读取文件路径等操作将无意义。

4. **perf ring buffer 推送**：每个 CPU 一个独立的 ring buffer。使用 `BPF_F_CURRENT_CPU` 标志确保事件不跨 CPU。

5. **CO-RE 兼容性**：使用 `bpf_core_read()` 宏读取内核结构体字段，而不是硬编码偏移。这确保同一 `.bpf.o` 在不同内核版本上运行。

### 9.2 Python 加载器开发注意事项

1. **libbpf 绑定**：使用 Python 的 `ctypes` 调用 `libbpf.so`。需要定义的函数：`bpf_object__open`、`bpf_object__load`、`bpf_program__attach`、`bpf_map__fd`、`bpf_map_update_elem`、`perf_buffer__new`。

2. **ring buffer 消费**：`perf_buffer__new` 注册回调函数，`perf_buffer__poll(timeout_ms)` 轮询。回调中将 `event_t` 的 C 结构体转换为 Python RawEvent。

3. **map 更新**：`send_command()` 中通过 `bpf_map_update_elem` 更新 `block_policy` map。key 是 pid（u32），value 是 block_flags（u64）。

4. **生命周期管理**：`attach()` → 加载+挂载，`detach()` → 卸载+清理 maps。使用 `atexit` 注册清理函数防止异常退出时遗留 eBPF 程序。

### 9.3 集成注意事项

1. **事件格式一致性**：`EbpfCollector._to_raw_event(event_t)` 产生的 RawEvent 必须与 `SimulationCollector` 的格式完全一致。开发时先对比两个 Collector 输出同一个场景的事件 JSON，确保 `observer_core/` 可以无缝接收。

2. **时间戳差异**：eBPF 使用 `bpf_ktime_get_ns()`（monotonic clock），模拟模式使用 VirtualClock。`observer_core/` 只读取 `timestamp_ns` 字段，不关心时钟类型。但自进化模块可能需要注意时钟差异。

3. **管道编码**：JSON 行协议保持不变。Linux FIFO 的读写行为与 Windows 命名管道对上层透明（都是阻塞式文件 I/O）。

4. **阻断确认**：阻断指令通过反向管道发送后，eBPF map 的更新是异步的（下次 syscall 调用时才生效）。在 `send_command()` 返回后，不会立即收到"阻断成功"的确认——确认体现在后续事件中 `blocked=1` 字段。

---

## 第十部分：一句话总结

> **新增 `adapter/`（平台适配，~140行）+ `collector/`（采集层，ICollector 接口 + 3个实现类，~550行）+ `ebpf/observer.bpf.c`（eBPF 内核探针，~300行C），`observer_core/` 零改动。`main.py` 启动时检测 `sys.platform`，Windows 自动走 SimulationCollector（保留全部现有功能），Linux 自动走 EbpfCollector（真实内核探针 + 观测 + 阻断）。三模式可通过 `--mode` 参数手动切换。总新增代码 ~1080 行，开发排期 8 天（Day1-2 适配+接口，Day3-5 eBPF开发，Day6-8 集成+阻断验证）。**