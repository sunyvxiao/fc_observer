# eBPF 实时监测与集成阶段 — 开发计划

> 基于 `统一架构切换_eBPF 数据输入模块开发方案定稿.md` 的进度评估，制定本阶段开发计划。
>
> **上一阶段成果**：adapter/ 适配层、collector/ 采集层（Simulation/Strace/Ebpf）、ebpf/ 内核探针（仅观测）、三入口 `--mode` 改造均已完成。Windows 端模拟模式 367 个测试全部通过，商业分析场景准确率 94%。

---

## 第一部分：进度回顾与未完成项

### 1.1 已完成项 (Phase 1-8)

| 阶段 | 内容 | 代码位置 |
|------|------|------|
| Phase 1-2 | adapter/ 平台适配层、ICollector 接口、SimulationCollector | `adapter/`, `collector/base_collector.py`, `simulation_collector.py` |
| Phase 2 | 三入口 `--mode` 改造、config.yaml 新增配置段 | `main.py`, `demo.py`, `app.py`, `config.yaml` |
| Phase 3 | eBPF C 探针 (`observer.bpf.c` + `Makefile`)、EbpfCollector、StraceCollector | `ebpf/`, `collector/ebpf_collector.py`, `strace_collector.py` |
| 额外 | 事件录制器、DeepAgent 采集器、Agent 桥接适配、FileReplayCollector | `collector/event_recorder.py`, `deep_agent_collector.py`, `adapter/agent_bridge.py` |

### 1.2 未完成项（来自原方案第十部分"第二版预留"）

| 编号 | 任务 | 优先级 | 说明 |
|:---:|------|:---:|------|
| U1 | eBPF 阻断探针（kprobe） | **高** | 新增 kprobe 程序挂载到 `__x64_sys_execve/openat/connect`，使用 `bpf_override_return(ctx, -EPERM)` |
| U2 | block_policy eBPF map | **高** | `BPF_MAP_TYPE_HASH`，key=pid(u32)，value=block_flags(u64)，内核态查询决定是否阻断 |
| U3 | EbpfCollector.send_command() 真实实现 | **高** | 更新 block_policy map → 动态挂载 kprobe → Agent syscall 被拦截返回 EPERM |
| U4 | 动态 kprobe 挂载/卸载 | 中 | 仅在阻断决策时挂载 kprobe（平时零开销），阻断完成后卸载 |
| U5 | Linux 端跨环境集成联调 | 中 | 在 VMware Ubuntu 22.04 上完成三模式（simulation/strace/ebpf）端到端验证 |
| U6 | 性能基准测试 | 低 | 模拟 vs eBPF 事件处理延迟对比、ring buffer 丢失率 |

---

## 第二部分：本阶段开发目标

### 2.1 核心目标（3 个）

#### 目标 A：eBPF 阻断能力（实现原方案第十部分预留）

当前 eBPF 第一版仅做观测（tracepoint），`send_command()` 返回 `False`。本阶段实现完整的 eBPF 阻断链路：

```
Python 研判决策: BLOCK @ TIER2
    │
    ▼
EbpfCollector.send_command(cmd)
    │
    ├─ 更新 eBPF map: block_policy[target_pid] = block_flags
    ├─ 动态挂载 kprobe 程序（如尚未挂载）
    │
    ▼
Agent 下一次 syscall → kprobe 触发
    → 查询 block_policy map → bpf_override_return → -EPERM
    → Agent 收到 Permission denied
```

**涉及文件**：
- `ebpf/observer.bpf.c`：新增 `SEC("kprobe/__x64_sys_execve")` 等 3 个 kprobe 程序 + `block_policy` map
- `collector/ebpf_collector.py`：`send_command()` 实现（更新 map + 挂载/卸载 kprobe）
- 新增测试：`tests/test_ebpf_blocking.py`

#### 目标 B：实时监测能力

将监控系统从"录制-回放"模式升级为"实时监测"模式，直接与运行中的 Agent 进程对接：

1. **附着到运行中进程**：`--mode ebpf --pid <PID>` 将 eBPF 探针绑定到已运行的 Agent
2. **启动并监控**：`--mode ebpf --launch <COMMAND>` 启动 Agent 子进程并同时开始 eBPF 监控
3. **进程树追踪**：自动跟踪 Agent fork 的子进程，确保子进程的 syscall 也被捕获
4. **demo.py 实时监测菜单**：新增交互选项"实时监测模式"，替代仅有的场景回放

**涉及文件**：
- `adapter/agent_bridge.py`：完善 Agent 生命周期管理（启动/监控/信号处理/终止）
- `collector/ebpf_collector.py`：支持多 PID 追踪（进程树自动扩展）
- `demo.py`：新增实时监测交互菜单

#### 目标 C：系统自优化功能 —— 明确为远期目标（本阶段不实现）

| 远期目标 | 当前状态 |
|------|------|
| ITraceStore/IPatternMiner/IStrategyGenerator 接口实现 | 仅定义了抽象接口（`evolution/interfaces.py`），无具体实现 |
| 基于历史审计日志的规则自动生成 | 不在本阶段范围 |
| 策略挖掘与行为模式自学习 | 不在本阶段范围 |

这些能力依赖长期运行积累的行为数据，需要更成熟的数据管道和模型训练基础设施，纳入本项目的远期路线图。

---

## 第三部分：开发排期（7 天）

### 总体时间线

```
Day 1  2  3  4  5  6  7
     ├─────────┤              Phase A: eBPF 阻断探针 (Linux, 3天)
               ├─────┤        Phase B: 实时 Agent 对接 (Linux, 2天)
                     ├─────┤  Phase C: 双端验证 + 文档 (双端, 2天)
```

### Phase A：eBPF 阻断探针（Day 1-3, Linux）

> 环境：VMware Ubuntu 22.04 LTS

```
Day 1 (4h): kprobe 程序开发
  ├─ [2h] ebpf/observer.bpf.c 新增 SEC("kprobe/__x64_sys_execve")
  │        · 查询 block_policy map: pid → block_flags
  │        · 如果命中阻断策略: bpf_override_return(ctx, -EPERM)
  │        · 如果未命中: 正常返回（零影响）
  ├─ [1h] 新增 block_policy BPF map (BPF_MAP_TYPE_HASH)
  │        · key: u32 pid, value: u64 block_flags 位掩码
  │        · 用户态通过 bpf_map_update_elem 更新
  └─ [1h] openat + connect kprobe 程序
           · SEC("kprobe/__x64_sys_openat") + SEC("kprobe/__x64_sys_connect")
           · 复用同一 block_policy map

Day 2 (4h): Python 加载器阻断集成
  ├─ [2h] collector/ebpf_collector.py send_command() 实现
  │        · 解析 Command 对象 → 提取 target_pid + block_flags
  │        · ctypes 调用 bpf_map_update_elem 更新 block_policy
  │        · 首次阻断时动态挂载 kprobe 程序
  │        · detach() 时卸载 kprobe 并清理 map
  ├─ [1h] 动态挂载/卸载逻辑
  │        · 维护 kprobe_attached 状态标记
  │        · 挂载: bpf_program__attach_kprobe()
  │        · 卸载: bpf_link__destroy()
  └─ [1h] 手动测试: 编译 → 加载 → 触发阻断 → 验证 EPERM

Day 3 (4h): 测试 + 文档
  ├─ [2h] 单元测试: tests/test_ebpf_blocking.py
  │        · send_command() 更新 map 后查询验证
  │        · kprobe 挂载/卸载状态转换
  │        · 多 PID 独立阻断
  │        · 阻断后解除（清除 map 条目）
  ├─ [1h] 集成测试: Tier2 阻断 → eBPF EPERM → Agent 错误处理
  └─ [1h] 更新 ebpf/README 或注释文档
```

**交付标准**：
- kprobe 程序编译通过，bpftool 验证加载无错误
- `send_command()` 能成功更新 block_policy map
- 被阻断的 Agent syscall 返回 EPERM
- 阻断后解除恢复正常

### Phase B：实时 Agent 对接（Day 4-5, Linux）

> 环境：VMware Ubuntu 22.04 LTS

```
Day 4 (4h): Agent 生命周期管理
  ├─ [2h] adapter/agent_bridge.py 完善
  │        · launch_agent(command): subprocess.Popen + 捕获 PID
  │        · attach_to_agent(pid): 验证 PID 存在 + 获取进程树
  │        · monitor_process_tree(): 监听 /proc 检测 fork
  │        · terminate_agent(pid): SIGTERM → SIGKILL 降级
  ├─ [1h] collector/ebpf_collector.py 多 PID 支持
  │        · attach() 接受 pid_list 而非单一 PID
  │        · 进程树扩展: 新 fork 的子进程自动加入追踪
  └─ [1h] 手动测试: 启动 Python 脚本作为 Agent → eBPF 监控 → 验证事件流

Day 5 (4h): 入口层集成 + 交互菜单
  ├─ [2h] demo.py 新增实时监测菜单
  │        · 选项 "4. 实时监测模式"
  │        · 子菜单: 选择采集模式 (ebpf/strace)
  │        · 输入: 目标 PID 或启动命令
  │        · 实时展示: 每个 syscall → RawEvent → 评分 → 决策
  │        · 支持 'q' 退出监测
  ├─ [1h] main.py --mode ebpf --pid/--launch 集成
  │        · argparse 新增 --pid + --launch 参数
  │        · 启动后持续运行直到 SIGINT
  └─ [1h] 端到端测试: 启动 Agent → 执行危险操作 → 验证阻断
```

**交付标准**：
- `--mode ebpf --pid <PID>` 可附着到运行中进程
- `--mode ebpf --launch <CMD>` 可启动并监控 Agent
- Agent fork 的子进程自动被追踪
- demo.py 实时监测菜单可用

### Phase C：双端验证 + 文档收尾（Day 6-7, 双端）

```
Day 6 (4h): Linux 端完整验证
  ├─ [2h] 三模式端到端（Linux）
  │        · --mode simulation: 37 场景通过
  │        · --mode strace: 附着到 Agent → 捕获 syscall → 评分正确
  │        · --mode ebpf: 附着到 Agent → 捕获 syscall → 阻断正确
  ├─ [1h] 报告一致性验证
  │        · 阻断事件在时间线/明细表/摘要/图谱四模块统一
  └─ [1h] 错误处理验证
           · eBPF 不可用 → 降级 strace
           · strace 不可用 → 报错退出
           · 无效 PID → 明确错误提示

Day 7 (4h): Windows 端无回归 + 文档
  ├─ [2h] Windows 无回归
  │        · pytest 367 测试全部通过
  │        · demo.py --auto 37 场景通过
  │        · app.py Web 前端正常
  └─ [2h] 文档更新
           · README.md 更新开发进度
           · 项目描述.md 更新功能状态
           · 本计划文档归档
```

**交付标准**：
- `[Linux]` 三模式端到端验证通过
- `[Linux]` eBPF 阻断链路完整可用
- `[Win]` 模拟模式无回归
- `[双端]` 所有文档反映最新状态

---

## 第四部分：不实现的功能（远期目标）

以下功能明确不在本阶段实现范围内，纳入项目远期路线图：

| 功能 | 当前状态 | 前置依赖 |
|------|------|------|
| **规则自动生成** | `evolution/interfaces.py` 仅定义了 ITraceStore/IPatternMiner/IStrategyGenerator 抽象接口，无实现 | 需要长期运行积累的行为数据、统计模型训练 |
| **策略挖掘（行为模式自学习）** | 同上 | 需要大量历史审计日志和标注数据 |
| **机器学习评分算法** | 当前四维评分均为基于规则的确定性算法 | 需要标注训练集和模型部署基础设施 |
| **实时监控大屏** | 非核心安全功能 | 可作为 Web 前端增强独立开发 |

---

## 第五部分：关键风险与缓解

| 风险 | 概率 | 缓解措施 |
|------|:---:|---------|
| `bpf_override_return` 仅适用 kprobe，不适用 tracepoint | — | 已知限制，设计已分两层：tracepoint 观测 + kprobe 阻断 |
| kprobe 函数名因内核版本变化（如 `__x64_sys_execve` vs `__arm64_sys_execve`） | 低 | 编译时根据架构条件选择函数名 |
| eBPF verifier 拒绝复杂 kprobe 程序 | 中 | 保持 kprobe 程序逻辑极简（仅查 map + override） |
| 多 PID 追踪时 perf ring buffer 竞争 | 中 | 增大 `perf_buffer_page_count`，监控丢失计数 |
| Agent 进程树快速 fork/exit 导致追踪遗漏 | 低 | 使用 `tracepoint/sched/sched_process_fork` 捕获 fork 事件 |

---

## 第六部分：GitHub 推送操作指南

### 前置条件

- 在 GitHub 上创建空仓库（不要勾选 README/.gitignore/LICENSE 初始化选项）
- 准备好 GitHub Personal Access Token（Settings → Developer settings → Tokens (classic)）


### .gitignore 覆盖确认

根目录 `.gitignore`（主文件）已整合覆盖以下排外项：
- ✅ `observer_sim/output/` — 测试输出
- ✅ `records/` — 录制文件
- ✅ `observer_sim/cpp_probe/build/` — C++ 编译产物
- ✅ `observer_sim/ebpf/vmlinux.h`, `*.o`, `*.llc` — eBPF 编译产物
- ✅ `__pycache__/`, `.pytest_cache/` — Python 运行时缓存
- ✅ `.env` — 敏感配置
- ✅ `deep-agents-demo/workspace/` — Agent 工作目录
- ✅ 保留所有 `scenarios/**/*.yaml`, `tests/**/*.py`, `rules/**/*.yaml`

---

*本计划基于 `统一架构切换_eBPF 数据输入模块开发方案定稿.md` v1.0 评估制定，后续如有调整将更新本文档。*
