# Qoder CN 监测接入可行性分析与执行方案

> 调研日期：2026-08-31
> 调研对象：Qoder CN（阿里云，原通义灵码 Lingma）——黑盒编程 Agent，无法注入探针、无法改动内部代码
> 调研方法：官方文档 × 本项目现有代码逐项对照（复用《第二阶段长期计划》的核对方法论）
> 结论先行：**可行，且接入条件优于 WorkBuddy 场景**——Qoder CN 除 MCP client 外，还提供确定性的 Hooks 机制（PreToolUse 可阻断），可复用本项目 MCP 申报管线，并首次为黑盒 Agent 提供真实 L2 阻断可能。

---

## 一、调研对象澄清

Qoder CN 与 WorkBuddy 同属"黑盒 Agent"：进程外部无法注入探针，只能依赖 Agent 主动申报或宿主 IDE 提供的事件挂钩。三条可能的接入面：

| 接入面 | WorkBuddy | Qoder CN |
|---|---|---|
| MCP client 注册外部 Server | ✅（mcp.json 注册 observer） | ✅（`.mcp.json` / `qoderclicn mcp add`） |
| 确定性事件钩子（Hook） | ❌ 无（只能靠模型自觉调用申报工具） | ✅ **五种 Hook 事件，PreToolUse 可阻断** |
| 进程外日志/审计痕迹 | ❌ 无 | ✅ 运行时日志（`[hook]` 前缀）+ 会话 transcript 文件 |

---

## 二、Qoder CN 官方文档证据

### 2.1 MCP client 接入（官方文档确认）

- **CLI 文档**（`help.aliyun.com/zh/lingma/using-the-cli`）：
  - `qoderclicn mcp add playwright -- npx -y @playwright/mcp@latest` 注册 stdio 服务；
  - `-t` 支持四种传输类型：`stdio` / `sse` / `http` / `ws` —— **本项目的 HTTP+SSE MCP Server 可直接被注册**；
  - `-s` 支持三种作用域：`user`（`~/.qoder-cn/settings.json`）、`local`（`${project}/.qoder/settings.local.json`）、`project`（`${project}/.mcp.json`，可随项目共享提交）。
- **IDE 文档**（CloudBase 官方接入指南 `docs.cloudbase.net/ai/cloudbase-ai-toolkit/ide-setup/qoder`）：IDE 设置中有 MCP 页面（My Servers / MCP Square），`mcpServers` JSON 格式注册，保存即生效；MCP 工具仅在 Agent 模式下暴露。
- **本地实证**：本机（Linux）Qoder CN 配置目录 `~/.config/QoderCN/SharedClientCache/projects/-home-syx-projects-observer_sim/mcps/` 下已注册 3 个 MCP Server（browser-use / genui / schedule），证明当前安装的 Qoder CN 具备 MCP client 配置能力。

### 2.2 Hooks 机制（官方文档确认，`help.aliyun.com/zh/lingma/hooks-3032541`）

- 五种事件：`UserPromptSubmit`、`PreToolUse`、`PostToolUse`、`PostToolUseFailure`、`Stop`；
- **`PreToolUse` / `UserPromptSubmit` 可阻断**（脚本 `exit 2` 即拒绝操作，stderr 注入对话）；
- Hook 脚本以 **stdin JSON** 接收事件上下文，通用字段含 `session_id`、`cwd`、`hook_event_name`、`transcript_path`；`PreToolUse` 附 `tool_name` + `tool_input`，`PostToolUse` 附 `tool_response`，`Stop` 附 `last_assistant_message`；
- 与 Prompt 指令不同，**Hooks 是确定性的**——事件触发则脚本必执行，不受模型理解偏差影响（WorkBuddy 申报模式的最大痛点在此被消除）；
- 配置位置三级：`~/.lingma/settings.json`（用户级）→ `.lingma/settings.json`（项目级，可提交 Git 共享）→ `.lingma/settings.local.json`（本地）；暂不支持热加载，改配置需重启 IDE；
- `matcher` 支持正则（如 `mcp__.*` 匹配所有 MCP 工具调用）；工具名两套映射（原生名 ↔ 兼容名）：`run_in_terminal`=Bash、`read_file`=Read、`create_file`=Write、`search_replace`=Edit、`delete_file`、`grep_code`=Grep、`search_file`=Glob、`list_dir`=LS、`task`=Task；
- Hook 脚本默认 30s 超时；执行日志可在 Qoder CN 运行时日志中按 `[hook]` 前缀检索（进程外审计痕迹）。

### 2.3 其他痕迹（兜底）

- `transcript_path`：Hook 输入含"会话上下文 JSON 文件路径"，可被进程外解析（格式未在官方文档披露，需实测）；
- 运行时日志：`[hook]` 前缀条目记录 Hook 调用详情。

---

## 三、本项目现有能力对照（代码证据）

| 本项能力 | 代码位置 | 复用判断 |
|---|---|---|
| MCP 申报 Server（HTTP+SSE，三申报 tools） | [mcp_bridge/server.py](file:///home/syx/projects/observer_sim/observer_sim/mcp_bridge/server.py)（MCPServer + McpReportBroker 队列/JSONL） | ✅ 直接复用 |
| 申报校验/限流/脱敏 | [mcp_bridge/validation.py](file:///home/syx/projects/observer_sim/observer_sim/mcp_bridge/validation.py)（64KB/16KB/100 键/60 次每秒）、[mcp_bridge/semantic_guard.py](file:///home/syx/projects/observer_sim/observer_sim/mcp_bridge/semantic_guard.py) | ✅ 直接复用 |
| 申报流 → RawEvent 采集器 | [collector/mcp_report_collector.py](file:///home/syx/projects/observer_sim/observer_sim/collector/mcp_report_collector.py)（ICollector 接口，broker→RawEvent） | ✅ 直接复用（改 target_agent_id） |
| 工具名→事件类型统一映射 | [observer_core/monitoring/raw_event_factory.py](file:///home/syx/projects/observer_sim/observer_sim/observer_core/monitoring/raw_event_factory.py)（classify_tool：exec/file_open/net_conn） | ✅ 直接复用 |
| 框架级 YAML 映射（HookRegistry） | [adapter/hook_registry.py](file:///home/syx/projects/observer_sim/observer_sim/adapter/hook_registry.py) + [adapter/hook_configs/pydantic_deep.yaml](file:///home/syx/projects/observer_sim/observer_sim/adapter/hook_configs/pydantic_deep.yaml)（YAML 自动发现加载） | ⚠️ 需新增 `hook_configs/qoder.yaml` |
| 监测主循环 + 统一管线 | [monitor_daemon.py:803](file:///home/syx/projects/observer_sim/observer_sim/monitor_daemon.py)（`run_monitor_mcp_report`：broker→collector→PipelineRunner） | ✅ 直接复用 |
| 统一入口 | `observer.py daemon --mode mcp_report`（config.yaml `mcp_report` 段：host/port/target_agent_id） | ✅ 直接复用 |
| 阻断指令下发 | [observer_core/blocking/](file:///home/syx/projects/observer_sim/observer_sim/observer_core/blocking/)（command_sender / blocking_coordinator） | ⚠️ 当前 mcp_report 模式无阻断通道；Hook 可补齐（见方案 P2） |

**关键判断：Qoder CN 监测能否复用现有 MCP 申报通道？**
- 申报链路（Server→Broker→Collector→RawEventFactory→管线）**可 100% 复用**；
- 但"Agent 是否调用申报工具"依赖模型自觉——与 WorkBuddy 相同，事件完整性无保证（本项目文档已如实定位为"合规留痕+风险提示"）；
- Qoder CN 的 **Hooks 提供了 MCP 之外的第二条、且确定性更强的摄入通道**：Hook 脚本天然获得 `session_id`/`tool_name`/`tool_input`，字段与本项目 `report_tool_call` 申报 schema 一一对应，仅差一个"把 Hook stdin JSON POST 到采集端的轻量端点"。**新增一个 HTTP 摄取端点 + 一个 reporter 脚本，即可获得 100% 事件完整性**（WorkBuddy 场景做不到）。

---

## 四、可行性结论

**结论：可行。** 分三档：

1. **保守档（复用 MCP 申报，改动≈0）**：把 observer 的 MCP Server 注册进 Qoder CN（`.mcp.json`），模型在 Agent 模式下可能调用申报工具。能力边界同 WorkBuddy：留痕 + 风险提示，无完整性保证。**今天即可做。**
2. **推荐档（Hooks 确定性申报，小改）**：用 `PostToolUse`（+`PostToolUseFailure`）Hook 驱动一个 reporter 脚本，把每次工具调用 POST 到新增的轻量摄取端点，进入现有 broker→collector→管线。**确定性 100%、事件完整**，是 WorkBuddy 场景不具备的升级。
3. **增强档（Hooks 阻断联动，中改）**：`PreToolUse` Hook 内联调用风险研判 API（或本地规则快查），命中 block 则 `exit 2` 真实拦截。**首次让黑盒 Agent 具备 L2 阻断**，但需评估每次工具调用的往返时延（Hook 30s 超时内）与误杀风险，建议作为可选增强。

---

## 五、推荐技术路线与分阶段执行步骤

### 总体路线

```
Qoder CN Agent 工具调用
   ├─(P1) PostToolUse Hook → qoder_hook_reporter.py ──POST──▶ 新增 /api/hook-report 端点
   │                                        （确定性，主通道）      │
   └─(P0) MCP 申报 tools ──模型自觉调用──▶ 现有 MCP Server（复用，辅通道）
                                                     ▼
                                    McpReportBroker（队列 + JSONL 留痕）
                                                     ▼
                                    McpReportCollector（ICollector，现有）
                                                     ▼
                         RawEventFactory（统一转换，现有）→ 归一化/规则/评分/研判/审计
```

### P0：零改动复用验证（0.5 天）

1. 配置 `observer_sim/config.yaml` `mcp_report` 段：`target_agent_id: "qoder"`、`framework: "qoder"`（暂用 pydantic-deep 兜底）；
2. 在目标项目 `.mcp.json`（或 `~/.qoder-cn/settings.json`）注册 observer MCP Server（`sse` 类型，`http://127.0.0.1:8765/sse`）；
3. `python observer.py daemon --mode mcp_report --output output/mcp_monitoring` 起守护，Qoder CN Agent 模式下发任务，验证申报链路与报告产物。
4. 产出：链路可行性证据（与 WorkBuddy 三轮验证同法）。

### P1：Hooks 确定性申报接入（2~3 天，主交付）

新建/改动模块：

| 模块 | 动作 | 说明 |
|---|---|---|
| `observer_sim/mcp_bridge/http_ingest.py`（新） | 在 MCP Server 同端口 uvicorn 应用上挂一个 **非 MCP 协议** 的 `POST /api/hook-report` 路由 | 入参 schema 与 `ReportToolCallInput` 对齐（tool_name/tool_args/session_id/agent_id/timestamp_ms）；走同一 `ReportValidator` + `RateLimiter`，写入同一 `McpReportBroker`；仅监听 127.0.0.1 |
| `scripts/qoder_hook_reporter.py`（新） | 纯标准库 reporter：读 stdin JSON（Hook 协议）→ 转申报 payload → POST 到 `/api/hook-report` | 必须轻量（Hook 30s 超时、每次工具调用都执行）：禁重型 import；失败静默放行（exit 0，只打本地日志），保证不影响 Agent 正常工作 |
| `observer_sim/adapter/hook_configs/qoder.yaml`（新） | Qoder CN 工具名→事件类型映射 | 原生名为主：`run_in_terminal`→exec、`read_file/list_dir/grep_code/search_file`→file_open(read)、`create_file/search_replace/delete_file`→file_open(write)、`web_search/web_fetch`→net_conn、`task`→exec（子代理）；供 SemanticGuard/HookRegistry 消费 |
| `.lingma/settings.json` 模板（新，放 `QoderCN监测接入/` 或 docs 附件） | 项目级 Hook 配置（可提交共享） | `PostToolUse` matcher 不填（全量）+ `PostToolUseFailure`；`command: python3 scripts/qoder_hook_reporter.py` |
| `config.yaml` `mcp_report` 段（改） | 增加 `hook_ingest: {enabled: true, path: /api/hook-report}` | 关闭时行为不变 |
| 测试（新） | `tests/test_qoder_hook_reporter.py` + `tests/test_http_ingest.py` | 管道模拟 Hook JSON（官方文档调试法 `echo '...' | script`）；畸形/超限/恶意申报复用现有校验断言 |

验收：Qoder CN 中执行 10+ 次工具调用（读文件/写文件/跑命令/搜索），audit JSONL 与报告逐条对应，无遗漏；恶意申报不破坏管线。

### P2：PreToolUse 阻断联动（可选，2~3 天）

- reporter 增加 `--mode pre`：PreToolUse Hook 触发时，将 tool_name+tool_input 送到新增的 `/api/hook-check` 同步研判端点（本地规则快查 + 风险评分，超时兜底放行），返回 `{block: true/false}`；
- Hook 脚本据响应 `exit 2` 或 `exit 0`——**黑盒 Agent 首次获得真实 L2 阻断**；
- 风险：每次工具调用增加一次 HTTP 往返（需 <100ms 预算）；误杀会打断正常开发——默认"仅阻断 Tier2 级规则"（R001 类高危），灰度开关。

### P3：兜底痕迹解析（可选，1~2 天）

- 解析 Qoder CN 运行时日志 `[hook]` 条目与 `transcript_path` 会话文件，作为 Hook 通道故障时的降级证据源（格式未公开，需逆向实测后决定取舍）。

---

## 六、阻塞项与待确认事项

| 项 | 性质 | 说明与替代方案 |
|---|---|---|
| `transcript_path` 文件格式未在官方文档公开 | 待确认 | 仅影响 P3 兜底通道，主通道（P1）不依赖；可实测一次真实会话取证 |
| Hook 配置不支持热加载 | 已知限制 | 接入时需重启 IDE 一次（一次性成本）；文档已明示 |
| Hook 脚本 30s 超时 | 已知限制 | reporter 必须轻量（纯 stdlib + 本地回环 HTTP）；P2 阻断查询需 <100ms 预算，超时兜底放行 |
| MCP 申报（P0）依赖模型自觉 | 已知限制 | 与 WorkBuddy 相同；Hooks 通道（P1）从根本上解决，P0 仅作辅通道/交叉验证 |
| 项目现有 `workbuddy_connect.yaml` 硬编码 Windows 路径（含 `projact3` 拼写错误） | 待修复 | 若在 Windows 复用该管家脚本需修正路径；Linux 接入建议改用 `observer.py daemon --mode mcp_report` 直启，绕开该文件 |
| 安全面：摄取端点暴露 | 需处理 | 仅绑定 127.0.0.1 + 复用现有 64KB/限流/脱敏；生产可加本地 token |

---

## 七、结论摘要

1. Qoder CN **同时具备 MCP client 与确定性 Hooks**（官方文档 + 本机配置实证），接入面优于 WorkBuddy（后者无 Hook）；
2. 现有 MCP 申报管线（Server→Broker→Collector→RawEventFactory→统一管线）**可直接复用**，P0 零改动即可验证；
3. 推荐主路线：**P1 Hooks 确定性申报**——新增一个轻量 HTTP 摄取端点 + 一个 reporter 脚本 + 一份 qoder.yaml 映射，即获得 100% 事件完整性的黑盒监测（较 WorkBuddy 场景的关键升级）；
4. 可选增强 P2 可借 PreToolUse 实现黑盒 Agent 首个真实 L2 阻断；
5. 无硬阻塞项；两个待确认点（transcript 格式、阻断时延预算）均有成熟规避路径。

**依据文件清单**：
- 官方文档：`help.aliyun.com/zh/lingma/hooks-3032541`（Hooks）、`help.aliyun.com/zh/lingma/using-the-cli`（CLI MCP）、`docs.cloudbase.net/ai/cloudbase-ai-toolkit/ide-setup/qoder`（IDE MCP 注册）
- 本项目：[mcp_bridge/server.py](file:///home/syx/projects/observer_sim/observer_sim/mcp_bridge/server.py)、[collector/mcp_report_collector.py](file:///home/syx/projects/observer_sim/observer_sim/collector/mcp_report_collector.py)、[raw_event_factory.py](file:///home/syx/projects/observer_sim/observer_sim/observer_core/monitoring/raw_event_factory.py)、[hook_registry.py](file:///home/syx/projects/observer_sim/observer_sim/adapter/hook_registry.py)、[monitor_daemon.py](file:///home/syx/projects/observer_sim/observer_sim/monitor_daemon.py)、[config.yaml](file:///home/syx/projects/observer_sim/observer_sim/config.yaml)
