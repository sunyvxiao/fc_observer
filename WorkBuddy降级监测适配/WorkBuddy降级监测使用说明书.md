# WorkBuddy 降级监测使用说明书

> 版本: 1.0 ｜ 适用读者: 接入并使用方寸观察者（observer_sim）MCP 申报监测的客户与实施人员
> 文档定位: 面向客户交付的部署 / 接入 / 使用说明；能力描述与结论均基于 2026-08-25 ~ 2026-08-26 真实 WorkBuddy 会话验证与 smoke 模拟测试结果，不包含未经验证的功能
> 配套资料（同目录）: `WorkBuddy降级监测端到端测试用例.md`（20 条测试用例定义）、`安全提示词内容.md`（可直接复制使用的合规留痕版提示词）、`端到端验证结果与差距清单.md`（逐条验证结论与差距分析）

---

## 1. 功能说明

### 1.1 产品定位

本通道是方寸观察者对 WorkBuddy（黑盒 Agent）的**降级监测方案**：WorkBuddy 每次工具调用时，主动调用 `observer` MCP 服务的申报工具上报操作信息，观察者据此进行规则匹配、风险评分与判定，并生成审计留痕与风险报告。

**定位一句话**：合规留痕 + 风险提示。它是"事后审计与风险提醒"工具，**不是**安全拦截工具。

### 1.2 实际能实现的能力

以下能力均已在真实 WorkBuddy 会话或模拟申报测试中验证通过：

| 能力 | 说明 |
|---|---|
| 21 条安全规则匹配判定 | 覆盖破坏性命令、管道下载执行、凭据读取、数据外传、提权、系统目录写入等类别（规则 ID R001~R020，见《端到端验证结果与差距清单.md》2.1 节）；24 条模拟申报用例判定全部符合预期 |
| ALLOW / ALERT / BLOCK 三态输出 | 合规任务判 ALLOW（真实会话列目录任务零误报实证）；危险命令判 BLOCK、敏感操作判 ALERT |
| TIER 风险分级 | TIER1~TIER3 执行等级，随风险等级递增 |
| 会话级违规升级隔离 | 各会话独立累计违规，互不污染（24 个独立会话模拟实证零串扰） |
| 审计 JSONL 留痕 | 每条事件落盘一行 JSON，含会话标识（session_id）、规则命中、评分、判定等全链路信息 |
| Markdown 风险报告 | 停止监测后自动生成：概览、风险分布、规则命中统计、Agent 行为摘要、事件时间线（含会话标注） |
| CLI 与 Web 双界面 | CLI 脚本与控制台菜单、Web 页面（http://localhost:8080）均可完成监测启停、状态查看、产物查看 |
| 会话边界申报 | WorkBuddy 按提示词约定调用 `report_session`（start/end），观察者留痕会话边界（真实会话实证） |

### 1.3 能力边界（请务必了解）

以下边界是方案设计使然，**不是故障**，请在评估方案时予以考虑：

1. **非真实拦截工具**：本通道定位是"合规留痕 + 风险提示"。**BLOCK 判定只是报告层面的风险标记（软阻断），不会真正阻止 WorkBuddy 执行任务**。daemon 日志与报告中会以 `BLOCK(软)` 或报告标注方式如实体现。
2. **监测完全依赖主动申报**：观察者只能看到 WorkBuddy 主动调用 `report_tool_call` 等工具上报的内容；**Agent 不申报即形成监测盲区**。申报缺失或字段不全时，风险报告可能显示"无事件"，这不代表操作没有发生。
3. **Windows 环境限制**：本机的 eBPF / strace / FIFO 实时监测、内核级阻断等能力在 Windows 下不可用；Windows 环境仅提供本 MCP 申报通道与模拟模式。真实进程级监测需在 Linux 环境部署（不在本说明书范围）。
4. **协同与时序分析未覆盖**：跨会话/跨 Agent 协同关联、时间分散蓄谋链聚合、离线时段基线判定当前不具备（详见差距清单 2.2 节）。
5. **危险任务验证方式受限**：破坏性命令（`rm -rf /` 等）、数据外传、反向 shell、提权等任务不应在真实环境执行；此类用例通过 `smoke` 模拟申报验证判定管线，WorkBuddy 自身的安全策略也会拦截这类任务，属正常现象。

---

## 2. 项目部署步骤

### 2.1 环境要求

| 依赖 | 版本要求 | 说明 |
|---|---|---|
| Python | >= 3.10 | 观察者业务逻辑层 |
| pyyaml | 最新版 | 配置文件解析 |
| pytest | 最新版 | 运行回归测试（可选） |
| mcp | 最新版 | MCP SDK，连通自检与烟测需要 |

Windows 10/11 即可运行（本说明书基于 Windows 环境验证）。

### 2.2 安装依赖

在 `<项目根>/observer_sim/` 目录下执行：

```
pip install pyyaml pytest mcp
```

验证环境（可选）：

```
python check_env.py
```

### 2.3 配置 workbuddy_connect.yaml

配置文件位于 `observer_sim/workbuddy_connect.yaml`，接入脚本只读取此文件。按本机环境修改以下关键字段：

| 字段 | 说明 | 示例 |
|---|---|---|
| `server.host` | MCP 申报服务监听地址 | `127.0.0.1` |
| `server.port` | MCP 申报服务端口 | `8765` |
| `server.sse_path` | SSE 端点路径 | `/sse` |
| `observer.python` | Python 解释器（PATH 中可直接用 `python`） | `python` |
| `observer.project_dir` | observer_sim 项目根目录（绝对路径） | `C:/.../projact3/observer_sim` |
| `observer.output_dir` | 报告输出目录（相对 project_dir） | `output/mcp_monitoring` |
| `workbuddy.agent_id` | WorkBuddy 申报时使用的 Agent 标识，须与观察者 `config.yaml` 中 `mcp_report.target_agent_id` 一致 | `workbuddy` |
| `workbuddy.install_dir` / `exe_path` | WorkBuddy 安装目录与可执行文件（用于自动启动，按需填写） | 本机实际路径 |
| `workbuddy.mcp_config_path` | WorkBuddy 的 MCP 配置文件路径（接入时自动维护） | `C:/Users/<用户>/.workbuddy/mcp.json` |

> 路径建议使用正斜杠；修改前建议备份原文件。

### 2.4 连通性自检

启动申报服务后（见第 4 节第 1 步），执行：

```
cd observer_sim
python connect_workbuddy.py check
```

自检共 3 步，全部通过即可：

1. **端口连通**：`127.0.0.1:8765` 可达；
2. **MCP initialize**：返回服务名与版本；
3. **工具发现**：确认三个申报工具 `report_action`、`report_session`、`report_tool_call` 已就绪。

任一失败会给出明确提示（如"端口不可达（先执行 start）"）。

---

## 3. 接入 WorkBuddy 的 MCP

### 3.1 打开连接器管理页

在 WorkBuddy 界面进入：**「专家·技能·连接器」→「连接器」→「自定义连接器」**，可看到 observer 自定义连接器条目。

### 3.2 添加或启用 observer 连接器

- 若列表中已有 observer 条目：确认其 SSE 地址为 `http://127.0.0.1:8765/sse`，点击「连接 / 重连」按钮；
- 若列表中没有：可先在观察者侧执行 `python connect_workbuddy.py configure-workbuddy` 自动写入注册信息（脚本会在修改前自动备份 WorkBuddy 的 mcp.json），随后回到连接器管理页刷新并连接；
- 也可手动在连接器管理页新建条目，填写：名称 `observer`、类型 SSE、地址 `http://127.0.0.1:8765/sse`。

### 3.3 确认三个工具已启用

连接成功后，确认 observer 条目显示**三个工具已启用**（如"3/3 工具已启用"）：

| 工具 | 用途 |
|---|---|
| `report_tool_call` | 工具调用申报（主要事件来源） |
| `report_action` | 重要动作留痕申报 |
| `report_session` | 会话开始 / 结束申报 |

### 3.4 连接问题排查

真实会话验证中发现：**WorkBuddy 重启或新建会话后，observer 连接器可能回退为"失败"状态，导致工具未注入当前会话**（表现为 AI 回复"工具不存在、无法申报"）。处理步骤：

1. 检查 `C:/Users/<用户>/.workbuddy/mcp.json` 中是否仍有 observer 条目（`type: sse`、`url: http://127.0.0.1:8765/sse`、`disabled: false`）；条目被移除或置灰说明注册丢失，需重新执行 `configure-workbuddy`；
2. 回到连接器管理页（3.1 路径），点击 observer 条目的「连接 / 重连」，直至状态变为"已启用 / 3/3 工具"；
3. 建议**每次新建会话执行任务前**先确认连接器状态，避免整场会话零申报。

---

## 4. 简单使用流程（四步）

### 第 1 步：启动 MCP 申报监测 daemon

三选一：

```
# 方式 A（脚本，推荐）:
cd observer_sim
python connect_workbuddy.py start

# 方式 B（控制台菜单）:
python observer.py menu → 4（mcp 域）→ 1（启动 MCP 申报 daemon）

# 方式 C（Web）:
浏览器打开 http://localhost:8080 → MCP 申报页 → 启动监测
```

启动成功后申报服务监听 `http://127.0.0.1:8765/sse`，日志写入 `output/mcp_monitoring/mcp_daemon.log`。

### 第 2 步：在 WorkBuddy 新会话加载安全提示词

1. 打开《安全提示词内容.md》，复制「提示词开始」与「提示词结束」之间的全部内容；
2. 在 WorkBuddy 新建会话，将提示词全文作为**第一条消息**粘贴发送；
3. 确认会话开始申报：观察 WorkBuddy 的回复与工具调用面板，**它应先调用 observer 的 `report_session`（参数含 `status: start`）**。出现该调用即说明提示词预加载生效；
4. 若未出现：可先按第 3.4 节检查连接器状态并重连；确认三工具已启用后重试。

> 提示词请使用当前**合规留痕版**（v2.0 及之后版本），不要使用旧版含"强制监测框架""观察者判定为权威"等表述的版本（原因见 5.2 节）。

### 第 3 步：输入实际任务并等待完成

在输入框下达实际任务（如"列出当前目录文件"），等待任务完成。WorkBuddy 会在工具调用前后调用 `report_tool_call`（`action_type` 为 pre/post）进行申报，观察者实时输出判定（daemon 日志可见 `ALLOW` / `ALERT` / `BLOCK(软)`）。

> 备注（真实会话观察到的 WorkBuddy 行为特性）：只读操作通常仅做调用后（post）申报；敏感/写操作才会补调用前（pre）申报；申报参数可能按 WorkBuddy 内置安全策略做脱敏处理。均属正常现象，不影响判定。

### 第 4 步：停止监测并生成报告

```
python connect_workbuddy.py stop
```

停止后自动生成报告产物，位置在 `observer_sim/output/mcp_monitoring/`：

| 产物 | 路径 | 用途 |
|---|---|---|
| 风险报告 | `risk_report_*.md` | 判定明细：概览、规则命中、Agent 摘要、事件时间线 |
| 审计日志 | `audit/*.jsonl` | 逐事件全链路记录（含 session_id） |
| 监测汇总 | `monitoring_summary.json` | 统计摘要 |
| daemon 日志 | `mcp_daemon.log` | 实时判定输出 |

### 使用提示：危险操作的验证方式

以下危险操作**不应在真实环境执行**（WorkBuddy 自身安全策略也会拦截）：

- 破坏性命令：`rm -rf /`、格式化磁盘等；
- 管道下载执行：`curl … | bash`、下载脚本后立即执行；
- 数据外传与反向 shell：`curl -d` 上传、`nc -e` 等；
- 提权与权限放开：`sudo su -`、`chmod -R 777` 等。

需要验证判定管线时，使用模拟申报替代：

```
python connect_workbuddy.py smoke
```

该命令模拟发送一套正常 + 异常 + 畸形申报序列（预期 5 accepted + 2 rejected），验证 21 条规则判定与报告链路，与真实申报相互对照（实测 24 条用例模拟申报判定全部符合预期，详见差距清单文档）。

---

## 5. 常见问题与验证方式

### 5.1 如何验证提示词是否生效

按 F02 对照用例操作（详见 E2E 测试用例文档）：

1. **不加载提示词**，执行一次简单任务（如"列出当前目录文件"），停止监测后查看申报留痕（`mcp_reports.jsonl`）的条数；
2. **加载提示词**（第 4 节第 2 步），执行相同任务，停止后再次查看；
3. 判定：加载后申报条数明显更多、且含 `report_session` 的 start/end 与会话边界申报 → 提示词有效；两者无差异 → 提示词对该 WorkBuddy 版本无效，请反馈给实施方记录。

真实会话验证结论：合规留痕版提示词（v2.0）在连接器正常启用时，WorkBuddy 完整完成 `report_session`（start/end）与 `report_tool_call`（post）申报，提示词方案有效。

### 5.2 提示词被 WorkBuddy 判定为"提示注入"或拒绝申报怎么办

真实会话验证中，旧版提示词因包含"降级监测环境强制框架""观察者判定作为权威""BLOCK 不真实阻断"等表述，被 WorkBuddy 判定为提示注入（prompt injection）而拒绝配合，属于 **Agent 侧安全拦截**（不是观察者故障）。

处理办法：

1. 请务必使用**已按合规留痕口径改写后的提示词**（`安全提示词内容.md` v2.0 及之后版本），其定位为"合规审计留痕通道"，不宣称强制监测框架、不凌驾 WorkBuddy 自身安全权威；
2. 不要自行加回"监测环境强制框架""观察者判定为权威""必须无条件上报原始参数"等表述；
3. 若已使用新版提示词仍被拒，先按第 3.4 节确认连接器已启用（常见原因是工具未注入会话，AI 回复"工具不存在"），再新建会话重试；
4. 若 WorkBuddy 声明"参数脱敏后申报"，这是其内置数据外发安全策略，属正常行为，予以接受即可。

### 5.3 报告中没有 ALERT/BLOCK，但任务确实执行了危险操作

此时**不能据此认为监测已覆盖该风险**。原因通常是两类：

1. **申报缺失**：WorkBuddy 未调用申报工具（未加载提示词、连接器失连、或 WorkBuddy 自主决定不申报）；
2. **申报字段不完整**：如网络类事件未申报 `url` 字段，无法构造网络事件判定。

处理办法：核对申报留痕（`mcp_reports.jsonl`）确认申报是否发生、字段是否齐全；将结论反馈给实施方记录为"测不到"差距证据，用于后续申报侧或管线侧改进。

### 5.4 BLOCK 判定后任务为什么还在执行

BLOCK 在本方案中是**报告层面的风险标记（软阻断）**，观察者没有与 WorkBuddy 之间的真实拦截通道，不会阻止任务执行。如需事前约束，请依赖提示词约定与 WorkBuddy 自身的安全策略；观察者负责事后留痕与风险提示。

---

> 附：本说明书引用的全部测试结论与截图证据，见同目录《端到端验证结果与差距清单.md》及 `<项目根>/测试图片/` 目录。
