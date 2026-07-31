# Windows 端验证清单

> **用途**：供 Windows 端开发者逐项验证统一架构升级后的系统功能完整性。  
> **前置条件**：已执行 `git pull` 获取最新代码，`python --version` ≥ 3.10，`pip install pyyaml pytest` 已安装。  
> **预期测试基线**：366 passed, 1 skipped（1 个 Linux-only 测试在 Windows 上跳过）  
> **最后更新**：2026-07-31

---

## 一、环境预检

### 验证 1.1：环境预检脚本

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `cd observer_sim` | 进入项目目录 |
| 2 | `python check_env.py` | 全部检查项通过（约 25 项），显示"环境就绪" |

**检查要点**：
- Python ≥ 3.10 ✓
- pyyaml 已安装 ✓
- pytest 可用 ✓
- 项目关键文件完整（adapter/、collector/、ebpf/ 等）✓
- 模块导入正常（detect_and_create_collector、SimulationCollector 等）✓
- Linux 专属检查项（clang、bpftool、strace 等）应显示"跳过"

### 验证 1.2：模块导入验证

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -c "from adapter.platform_detect import detect_and_create_collector, PlatformInfo; print('OK')"` | 输出 `OK` |
| 2 | `python -c "from collector.simulation_collector import SimulationCollector; print('OK')"` | 输出 `OK` |
| 3 | `python -c "from collector.ebpf_collector import EbpfCollector; print('OK')"` | 输出 `OK`（仅导入，不实例化） |
| 4 | `python -c "from collector.strace_collector import StraceCollector; print('OK')"` | 输出 `OK`（仅导入，不实例化） |
| 5 | `python -c "from collector.file_replay_collector import FileReplayCollector; print('OK')"` | 输出 `OK` |

---

## 二、全量单元测试

### 验证 2.1：pytest 全量运行

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -m pytest tests/ -v` | **366 passed, 1 skipped**，0 failed |

**验证细节**：
- 16 个测试文件全部被收集，共 367 个测试
- 无 ERROR 或 IMPORT ERROR
- 跳过的 1 个测试：`test_ebpf_edge_cases.py::TestRealProcessTree::test_fork_exec_chain`（Linux-only，需要 root + eBPF）
- 总耗时约 3-6 秒

### 验证 2.2：按测试文件检查关键模块

| 测试文件 | 测试数 | 验证命令 | 预期 |
|---------|:------:|---------|------|
| test_adapter.py | 23 | `pytest tests/test_adapter.py -v` | 23 passed |
| test_simulation_collector.py | 28 | `pytest tests/test_simulation_collector.py -v` | 28 passed |
| test_ebpf_collector.py | 30 | `pytest tests/test_ebpf_collector.py -v` | 30 passed |
| test_strace_collector.py | 45 | `pytest tests/test_strace_collector.py -v` | 45 passed |
| test_collector_integration.py | 41 | `pytest tests/test_collector_integration.py -v` | 41 passed（含 2 个 Windows skip） |
| test_ebpf_field_mapping.py | 14 | `pytest tests/test_ebpf_field_mapping.py -v` | 14 passed |
| test_ebpf_edge_cases.py | 13 | `pytest tests/test_ebpf_edge_cases.py -v` | 12 passed, 1 skipped |
| test_ebpf_performance.py | 4 | `pytest tests/test_ebpf_performance.py -v` | 4 passed |
| test_file_replay_collector.py | 22 | `pytest tests/test_file_replay_collector.py -v` | 22 passed |
| test_monitoring.py | 18 | `pytest tests/test_monitoring.py -v` | 18 passed |
| test_judgment.py | 21 | `pytest tests/test_judgment.py -v` | 21 passed |
| test_blocking.py | 16 | `pytest tests/test_blocking.py -v` | 16 passed |
| test_audit.py | 16 | `pytest tests/test_audit.py -v` | 16 passed |
| test_integration.py | 17 | `pytest tests/test_integration.py -v` | 17 passed |
| test_pipe_communication.py | 26 | `pytest tests/test_pipe_communication.py -v` | 26 passed |
| test_virtual_clock.py | 16 | `pytest tests/test_virtual_clock.py -v` | 16 passed |

> **注**：单独运行文件时测试数可能与全量运行略有差异，以全量运行结果为准。

---

## 三、统一测试入口 test.py

> `test.py` 位于项目根目录，提供交互式菜单和命令行参数两种使用方式。  
> 支持环境自动检测、分类运行、汇总报告输出。

### 验证 3.1：交互式菜单

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `cd` 到项目根目录 | — |
| 2 | `python test.py` | 显示环境能力 + 交互式菜单（8 个选项） |
| 3 | 选择 `[8]` 环境检测 | 显示 Python、Root、strace、BTF、libbpf、eBPF、Web App 能力状态 |
| 4 | 选择 `[7]` 全部运行 | 依次运行 6 个分类，最后显示汇总报告 |

**Windows 上预期**：
- Root: ❌ 否 → 端到端测试自动跳过
- strace: ❌ → 不影响 simulation 模式
- eBPF: ❌ → 不影响 simulation 模式
- 全量运行结果：单元 136 + 采集器 172 + 集成 58 + 场景 37 = **403 passed**

### 验证 3.2：命令行参数

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python test.py --unit` | 仅运行单元测试（136 passed） |
| 2 | `python test.py --collector` | 仅运行采集器测试（172 passed） |
| 3 | `python test.py --integration` | 仅运行集成测试（58 passed） |
| 4 | `python test.py --scenario` | 仅运行场景测试（37 passed） |
| 5 | `python test.py --all` | 全部运行（同交互式选项 7） |
| 6 | `python test.py --check` | 仅显示环境能力 |

### 验证 3.3：test.py 分类说明

| 分类 | 参数 | 说明 | 运行方式 | Windows 可用 |
|------|------|------|---------|:-----------:|
| 单元测试 | `--unit` | 核心模块独立验证 | pytest | ✅ |
| 采集器测试 | `--collector` | simulation/strace/ebpf/replay | pytest | ✅ |
| 集成测试 | `--integration` | 多模块协作 Pipeline | pytest | ✅ |
| 场景测试 | `--scenario` | 37 个 YAML 场景回放 | main.py | ✅ |
| 端到端测试 | `--e2e` | 真实 strace/eBPF | shell 脚本 | ❌ 需 root |
| Web API 测试 | `--web` | API + SSE 推送 | 脚本 | ✅ 需启动 app.py |

---

## 四、平台检测与模式切换

### 验证 4.1：Windows 平台自动检测

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -c "from adapter.platform_detect import PlatformInfo; info=PlatformInfo.detect(); print(f'platform={info.platform}, is_windows={info.is_windows}, has_ebpf={info.has_ebpf}')"` | `platform=windows, is_windows=True, has_ebpf=False` |

### 验证 4.2：auto 模式自动选择 SimulationCollector

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -c "from adapter.platform_detect import detect_and_create_collector; c=detect_and_create_collector({'mode':'auto'}); print(c.capabilities().name)"` | 输出 `Simulation` |

### 验证 4.3：强制 simulation 模式

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -c "from adapter.platform_detect import detect_and_create_collector; c=detect_and_create_collector({}, mode_override='simulation'); print(c.capabilities().name)"` | 输出 `Simulation` |

### 验证 4.4：eBPF/strace 模式在 Windows 上正确报错

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -c "from adapter.platform_detect import detect_and_create_collector; detect_and_create_collector({}, mode_override='ebpf')"` | 抛出 `RuntimeError: eBPF 模式仅支持 Linux` |
| 2 | `python -c "from adapter.platform_detect import detect_and_create_collector; detect_and_create_collector({}, mode_override='strace')"` | 抛出 `RuntimeError: strace 模式仅支持 Linux` |

### 验证 4.5：三种 Collector 能力查询对比

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -c "from collector.simulation_collector import SimulationCollector; c=SimulationCollector({}); caps=c.capabilities(); print(f'name={caps.name} block_t2={caps.can_block_tier2} block_t3={caps.can_block_tier3} time={caps.time_source}')"` | `name=Simulation block_t2=True block_t3=True time=virtual` |

> 注：StraceCollector 和 EbpfCollector 在 Windows 上无法实例化（依赖 Linux 专属库），其能力值由单元测试 mock 验证覆盖。

---

## 五、三入口场景运行

### 验证 5.1：main.py 全量场景（simulation 模式）

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python main.py --mode simulation --scenario all` | 37 个场景全部通过，exit code = 0 |
| 2 | `python main.py --scenario all` | 同上（默认 mode=auto，Windows 上自动选 simulation） |

**检查要点**：
- 日志中显示 "使用 SimulationCollector" 或类似提示
- 37 个场景全部 `[PASS]`
- `output/reports/` 下生成了对应的报告文件

### 验证 5.2：main.py 指定单场景

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python main.py --mode simulation --scenario n01` | n01 场景通过，8 个事件全部 ALLOW |
| 2 | `python main.py --mode simulation --scenario a01` | a01 场景通过，含 BLOCK 事件 |

### 验证 5.3：demo.py 全量自动播放

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python demo.py --auto` | 37 场景自动播放完毕，显示全局统计面板 |
| 2 | `python demo.py --auto --mode simulation` | 同上，显式指定 simulation 模式 |

### 验证 5.4：demo.py 指定场景

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python demo.py --scenario n01` | n01 场景交互式播放（每事件暂停等待 Enter） |
| 2 | `python demo.py --scenario a01 --auto` | a01 场景自动播放 |

### 验证 5.5：app.py Web 前端

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python app.py` | 启动 Web 服务，监听 8080 端口 |
| 2 | 浏览器访问 `http://localhost:8080` | 前端页面正常加载 |
| 3 | 选择一个场景运行 | SSE 事件推送正常，分析面板显示正确 |
| 4 | `python app.py --mode simulation` | 显式指定模式后启动正常 |

---

## 六、config.yaml 配置验证

### 验证 6.1：配置文件解析

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -c "import yaml; c=yaml.safe_load(open('config.yaml')); print('mode:', c.get('mode')); print('sections:', [k for k in c.keys()])"` | `mode: auto`；包含 mode/pipeline/simulation/ebpf/strace 及原有所有配置段 |

### 验证 6.2：新旧配置段共存

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -c "import yaml; c=yaml.safe_load(open('config.yaml')); assert 'pipes' in c; assert 'scoring' in c; assert 'ebpf' in c; assert 'strace' in c; print('OK')"` | 输出 `OK`，新旧配置段共存 |

---

## 七、零改动约束验证

### 验证 7.1：核心目录未被修改

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `git diff --name-only -- observer_core/ models/ scenarios/ rules/` | 无输出（空行） |
| 2 | `git status observer_core/ models/ scenarios/ rules/` | 显示 `nothing to commit` 或仅 untracked 文件 |

---

## 八、文件回放模式验证

### 验证 8.1：FileReplayCollector 基本回放

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -c "from collector.file_replay_collector import FileReplayCollector; c=FileReplayCollector({'file_replay':{'input_file':'test_data/whitebox/normal_dev.jsonl'}}); c.load_data_file('test_data/whitebox/normal_dev.jsonl'); c.attach(agent_id='test'); evts=list(c.start()); print(f'{len(evts)} events'); [print(f'  {e.event_type}') for e in evts]"` | 输出 5 个事件（exec/file_open/net_conn） |

---

## 九、降级逻辑验证

### 验证 9.1：eBPF 不可用时自动降级

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python -c "from adapter.platform_detect import detect_and_create_collector; c=detect_and_create_collector({'mode':'auto'}); print(c.capabilities().name)"` | 输出 `Simulation`（Windows 上 auto 模式直接选择 Simulation） |

### 验证 9.2：无效 mode 值处理

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python main.py --mode invalid` | argparse 报错 `invalid choice: 'invalid'` |

---

## 十、报告生成验证

### 验证 10.1：报告文件生成

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python main.py --mode simulation --scenario a01` | a01 场景运行成功 |
| 2 | `ls output/reports/anomalous/` | 存在 a01 相关的报告目录 |
| 3 | 检查报告目录内容 | 包含 `report.json`（分析面板数据）和 `report.md`（结构化报告） |

### 验证 10.2：test.py 报告输出

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `python test.py --unit` | 运行完毕 |
| 2 | `ls output/test_report/` | 存在测试汇总报告文件 |

---

## 十一、Web API 与 SSE 验证

### 验证 11.1：API 端点测试

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | 启动 `python app.py` | 服务正常运行在 8080 端口 |
| 2 | `python test_api.py` | 13 passed, 0 failed |
| 3 | `python test_sse.py` | 18 passed, 0 failed（SSE 推送 + 场景运行） |

> 注：test_api.py 和 test_sse.py 位于 `observer_sim/` 子目录下（与 app.py 同级）。

### 验证 11.2：SSE 事件推送

| 步骤 | 预期 |
|------|------|
| 运行场景 a01 | SSE 推送 step 事件（含 seq/total/event_type/risk_score/decision_action/rule_match 字段） |
| 场景完成 | 收到 done 事件（含 analysis_panel/files_generated/statistics） |
| 运行场景 n01 | 所有 step 事件的 decision_action 均为 ALLOW |

---

## 十二、C++ Probe 编译验证（Windows 专属）

### 验证 12.1：CMake 编译

| 步骤 | 命令 | 预期结果 |
|------|------|---------|
| 1 | `cd observer_sim/cpp_probe` | 进入 C++ probe 目录 |
| 2 | `mkdir build && cd build` | 创建构建目录 |
| 3 | `cmake ..` | CMake 配置成功 |
| 4 | `cmake --build .` | 编译成功，生成可执行文件 |

> 注：C++ probe 主要为 Windows 设计，Linux 上使用 Python 模拟采集。编译依赖 Windows SDK 或 MinGW。

---

## 附录 A：37 个 YAML 场景完整列表

| 分类 | 场景 ID | 数量 | 说明 |
|------|---------|:----:|------|
| **正常** (normal) | n01-n08 | 8 | 标准开发、依赖安装、配置日志、并行 fork、ETL、Docker、cron、目录扫描 |
| **异常** (anomalous) | a01-a12 | 12 | rm -rf /、curl pipe bash、环境变量窃取、sudo 提权、SSH 后门、端口扫描、反弹 Shell、批量敏感读取、下载执行、系统文件篡改、挖矿、批量数据外泄 |
| **边界** (boundary) | b01-b08 | 8 | 删除临时目录、未知包安装、非工作时间操作、读取系统日志、动态 DNS、杀子进程、符号链接攻击、非标准端口 |
| **多 Agent** (multi_agent) | m01-m05 | 5 | 合法协作、隐蔽数据传输、环境变量投毒、权限提升链、时间分散串谋 |
| **极端** (extreme) | e01-e04 | 4 | 高速率事件、超长命令参数、管道断开恢复、命令超时降级 |

**场景目录位置**：`observer_sim/scenarios/{category}/`

---

## 附录 B：observer_core 六大子系统

| 子系统 | 目录 | 核心类 | 功能 |
|--------|------|--------|------|
| **监控** (monitoring) | `observer_core/monitoring/` | EventNormalizer, PipeReader, RuleEngine | 事件归一化、管道读取、规则引擎匹配 |
| **研判** (judgment) | `observer_core/judgment/` | DecisionEngine, RiskScorer, BaselineChecker, ChainReportBuilder | 风险评分、基线检查、决策引擎、因果链报告 |
| **阻断** (blocking) | `observer_core/blocking/` | BlockingCoordinator, CommandSender, ViolationTracker | 阻断协调、指令发送、违规追踪 |
| **审计** (audit) | `observer_core/audit/` | AuditLogger, BehaviorGraph, ReportExporter, OutputPathManager | 审计日志、行为图谱、报告导出 |
| **模型** (models) | `models/` | Event, Command, RiskPolicy, VirtualClock | 事件/命令/风险数据模型、虚拟时钟 |
| **规则** (rules) | `rules/` | default_policy.yaml | 默认安全策略定义 |

---

## 附录 C：已知限制

| 限制项 | 说明 | Windows 影响 |
|--------|------|-------------|
| eBPF 采集模式 | 仅在 Linux 可用（需要 BTF + libbpf） | 自动降级为 simulation 模式 |
| strace 采集模式 | 仅在 Linux 可用（依赖 strace 命令） | 自动降级为 simulation 模式 |
| 端到端测试 (e2e) | 需要 root 权限运行真实 strace/eBPF | 完全不可用，test.py 自动跳过 |
| C++ probe 编译 | Linux 上未编译验证（设计目标为 Windows） | 需要在 Windows 上编译验证 |
| report_exporter section_num | 无 agent_summaries 时 section_num 可能未定义 | 由 main.py try-except 兜底，不影响正常使用 |
| 管道通信 | Named Pipe 路径 Windows/Linux 不同 | 已做平台适配，单元测试覆盖 |
| test_fork_exec_chain | 需要 Linux root + eBPF | 自动 skip |

---

## 验证结果汇总表

| 序号 | 验证项 | 状态 | 备注 |
|:----:|--------|:---:|------|
| 1.1 | 环境预检脚本 | ☐ | |
| 1.2 | 模块导入验证（5 个） | ☐ | |
| 2.1 | pytest 全量运行 | ☐ | 预期 366 passed, 1 skipped |
| 2.2 | 按文件检查（16 个） | ☐ | |
| 3.1 | test.py 交互式菜单 | ☐ | |
| 3.2 | test.py 命令行参数 | ☐ | |
| 3.3 | test.py 分类说明 | ☐ | |
| 4.1 | Windows 平台自动检测 | ☐ | |
| 4.2 | auto 模式选择 Simulation | ☐ | |
| 4.3 | 强制 simulation 模式 | ☐ | |
| 4.4 | eBPF/strace Windows 报错 | ☐ | |
| 4.5 | Collector 能力查询 | ☐ | |
| 5.1 | main.py 全量场景 | ☐ | 37 场景 |
| 5.2 | main.py 指定单场景 | ☐ | |
| 5.3 | demo.py 全量自动播放 | ☐ | |
| 5.4 | demo.py 指定场景 | ☐ | |
| 5.5 | app.py Web 前端 | ☐ | |
| 6.1 | config.yaml 解析 | ☐ | |
| 6.2 | 新旧配置段共存 | ☐ | |
| 7.1 | 核心目录零改动 | ☐ | |
| 8.1 | FileReplayCollector 回放 | ☐ | |
| 9.1 | eBPF 不可用降级 | ☐ | |
| 9.2 | 无效 mode 值处理 | ☐ | |
| 10.1 | 报告文件生成 | ☐ | |
| 10.2 | test.py 报告输出 | ☐ | |
| 11.1 | API 端点测试 | ☐ | 13 passed |
| 11.2 | SSE 事件推送 | ☐ | 18 passed |
| 12.1 | C++ probe 编译 | ☐ | Windows 专属 |

> **通过标准**：全部 27 项验证均为 ☑。如有失败项，请记录具体错误信息并反馈。
