# WorkBuddy Hook 支持性验证报告

> 对应开发计划：T2.0 前提验证（阻塞性）
> 验证日期：2026-09-03
> 验证方式：静态分析（app.asar 269MB 打包产物全量扫描）+ 真实 WorkBuddy 会话实测（Computer Use 操作，截图留证）
> 结论：**第 2 层（T2.1 PreToolUse 同步闸门 / T2.2 PostToolUse 确定性钩子）不启动**——WorkBuddy 无 MCP Hook 机制；第 1 层（instructions 自动注入）前提成立且实测生效；监测能力加强转移至第 3 层。

---

## 1. 结论摘要

| 验证项 | 结论 | 分级 |
|---|---|---|
| ① mcp.json `instructions` 字段是否被消费 | **支持**（新会话不粘贴提示词即自发申报） | ✅ |
| ② MCP Hook（PreToolUse/PostToolUse）注册机制 | **不支持**（UI 无任何 Hook 入口；mcp.json 无 hooks 字段；产物代码无运行时执行器） | ❌ |
| ③ PreToolUse 阻止语义 | 不适用（无 Hook 机制可承载） | — |
| ④ PostToolUse 触发确定性 | 不适用（无 Hook 机制可承载） | — |

按开发计划 T2.0 分级决策表：**「均不支持 → 第 2 层关闭，记录『平台能力边界』，加强第 3 层」**。

---

## 2. 验证①：instructions 字段消费（兼作 T1.2 前置）

### 2.1 验证方法

1. 执行 `python connect_workbuddy.py configure-workbuddy`，向 `C:/Users/sunyuxiao/.workbuddy/mcp.json` 的 observer 条目注入 `instructions` 字段（内容为《安全提示词内容.md》v2.1，2133 字符）；
2. 重启 WorkBuddy，新建会话，**不粘贴任何提示词**，直接发送任务「请列出当前工作目录下的文件」；
3. 观察模型行为与观察者侧申报留痕（`output/mcp_monitoring/jsonl/mcp_reports.jsonl`）。

### 2.2 实测结果：支持 ✅

- WorkBuddy 回复中**自发引用**审计约定：「按你既定的**审计约定**，本次只读操作已通过 **observer MCP** 完成完整留痕（pre 事件 `mcp_553e5a2473d5` → 执行 `ls -la` → post 事件 `mcp_ddd29d36a4b7`）」——模型在无用户提示的情况下遵循了 instructions 中的申报义务；
- 观察者侧申报留痕确认收到 2 条申报：

| 序号 | 类型 | tool_name | action_type | received_at_ms |
|---|---|---|---|---|
| 1 | report_tool_call | Bash | pre | 1788413146356 |
| 2 | report_tool_call | Bash | post | 1788413153652 |

- 全程无 MCP 连接错误；连接器列表 observer 显示「3/3 个工具已启用」。

### 2.3 如实记录的边界

本次实测仅产生 pre/post 申报，**未产生 `report_session` start/end 申报**。说明：instructions 注入消除了「忘了粘贴」漏报源头（T1.2 目标达成），但**会话边界申报仍受模型自觉限制**——与第 1 层「合规留痕 + 风险提示」的定位一致，instructions 是引导而非确定性机制。

### 2.4 关联验证：T1.3 preflight 真实环境双场景实测（2026-09-03）

| 场景 | 命令 | 结果 |
|---|---|---|
| 连接器失连（daemon 已停止） | `python connect_workbuddy.py preflight` | RC=15：`2/3 MCP Server 端口: FAIL` → `[FAIL] 会话不可用，请按顺序处理: 1. MCP Server 端口不可达（先执行 start）`，给出分步处理指引 ✅ |
| 正常场景（daemon 运行中） | 同上 | RC=0：`1/3 mcp.json 注册: OK` + `2/3 端口: OK` + `3/3 申报 tools 就绪: OK` → `[OK] 会话可用` ✅ |

对应开发计划 T1.3 验收标准①（失连明确失败并给出指引）与②（正常场景全绿），真实环境实证通过。

---

## 3. 验证②：MCP Hook 注册机制

### 3.1 验证方法

三层证据：

1. **UI 实测**（Computer Use 截图）：遍历系统设置、智能体设置、安全中心、助理设置、连接器管理（observer 详情、配置 MCP）全部界面，寻找 Hook/钩子/事件/触发器相关配置入口；
2. **配置文件检查**：`mcp.json` 编辑器仅可见 `instructions` 字段，无 `hooks` 字段；`.workbuddy/settings.json` 无任何 hooks 配置段；
3. **产物静态分析**：对 `WorkBuddy.exe` 的 `resources/app.asar`（269MB）全量扫描 Claude Code / MCP Hook 协议相关符号。

### 3.2 实测结果：不支持 ❌

**UI 证据**：全部设置/连接器界面**未发现任何** Hook 相关配置入口（截图 B1~B5、A2c/A2d/A3）。

**静态分析证据**（app.asar 全量符号计数）：

| 符号 | 出现次数 | 上下文判定 |
|---|---|---|
| `PreToolUse` | 2 | 均在 `extractHookCommandsFromRecord`——插件详情页 UI 渲染逻辑（展示插件声明的 hooks 命令列表），非运行时执行器 |
| `PostToolUse` | 0 | — |
| `hook_event_name` | 0 | Claude Code hook 协议字段不存在 |
| `transcript_path` | 0 | 同上 |
| `UserPromptSubmit` / `SubagentStop` | 0 | 同上 |
| `executeHook` | 47 | 全部为 DOMPurify（HTML 净化库）内部钩子，与工具调用无关 |

`extractHookCommandsFromRecord` 的定位：`packages/.../plugin-service` 中扫描插件 `hooks/` 目录与 `hooks.json`，仅供**插件市场详情页**渲染命令清单，不存在任何「工具调用前/后执行 hook 命令」的运行时代码路径。

### 3.3 判定

WorkBuddy 当前版本（2026-09 实测）**无 MCP Hook（PreToolUse/PostToolUse）注册与执行机制**。因此：

- **验证③（PreToolUse 阻止语义）与验证④（PostToolUse 触发确定性）均不适用**，无承载机制可测；
- 开发计划约束「T2.1/T2.2 仅在 T2.0 前提验证确认支持后才可启动」→ **T2.1、T2.2 不启动，第 2 层关闭**。

---

## 4. 证据清单

### 4.1 截图（15 张，`observer_sim/output/t20_evidence/`）

| 步骤 | 文件 | 内容 |
|---|---|---|
| A1 | A1_主界面.png | WorkBuddy 主界面 |
| A2 | A2_专家技能连接器_入口.png | 专家/技能/连接器入口 |
| A2 | A2b_连接器列表.png | 连接器列表 |
| A2 | A2c_自定义连接器_MCP列表_observer可见.png | observer 在 MCP 列表可见 |
| A2 | A2d_observer详情_工具已启用.png | observer 详情：3/3 工具已启用，无 instructions 展示、无 hooks 配置区 |
| A2 | A3_配置MCP_mcpjson编辑器.png | mcp.json 编辑器：observer 条目含 instructions 字段、无 hooks 字段 |
| B | B1_用户菜单_设置入口.png | 设置入口 |
| B | B2_设置_系统设置页.png | 系统设置页（无 Hook 入口） |
| B | B3_设置_智能体设置页.png | 智能体设置页（无 Hook 入口） |
| B | B4_设置_安全中心页.png | 安全中心页（无 Hook 入口） |
| B | B5_设置_助理设置页.png | 助理设置页（无 Hook 入口） |
| C | C0_任务C_新会话空界面.png | 新会话（未粘贴提示词） |
| C | C1_任务C_发送后Agent接手.png | 发送任务后 Agent 接手 |
| C | C2_任务C_回复完成.png | 回复完成（自发引用审计约定 + pre/post 事件 ID） |
| C | C3_任务C_10秒后.png | 10 秒后界面 |

### 4.2 申报留痕

- `observer_sim/output/mcp_monitoring/jsonl/mcp_reports.jsonl`：2 条记录（Bash pre / Bash post，时间戳 1788413146356 / 1788413153652）
- `observer_sim/output/mcp_monitoring/monitoring_summary.json`：completeness 字段（checked=true, record_count=2, session_count=0）
- 风险报告（`risk_report_demo_monitoring_20260903_132848.md`）页脚前含「申报完整性核对」小节

### 4.3 静态分析

- app.asar 269MB 全量符号扫描（PreToolUse/PostToolUse/hook_event_name/transcript_path/UserPromptSubmit/SubagentStop/executeHook 等），结论见第 3 节。

---

## 5. 差距清单 Q3 回填

| 项 | 回填前 | 回填后 |
|---|---|---|
| Q3 BLOCK 真实拦截通道 | 「降级监测本质限制（黑盒 Agent 无拦截接口），需 WorkBuddy 侧配合，短期不可行」 | 保持判定，**新增实测依据**：WorkBuddy 无 MCP Hook（PreToolUse/PostToolUse）注册与执行机制（T2.0 实测，2026-09-03），T2.1 同步闸门无承载通道；短期不可行维持，若 WorkBuddy 未来版本引入 Hook 能力，可依据本报告第 3 节方法复测后重启第 2 层 |

---

## 6. 对后续里程碑的影响

1. **第 2 层关闭**：T2.1（PreToolUse 同步闸门）、T2.2（PostToolUse 确定性钩子）不启动，不写拦截回注代码；
2. **第 1 层成果保留**：instructions 自动注入（T1.2）实测生效，继续作为 WorkBuddy 场景的默认加载方式；
3. **第 3 层加强**：进程快照比对（T3.1）、文件快照比对（T3.2）、Windows 审计日志读取（T3.3）作为 WorkBuddy 场景下弥补申报盲区的用户态交叉校验主线，按计划推进；
4. **如实申报定位不变**：WorkBuddy 监测定位仍为「合规留痕 + 风险提示」（无真实拦截），文档不得描述未实现能力。
