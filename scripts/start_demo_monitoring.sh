#!/usr/bin/env bash
# =============================================================================
# start_demo_monitoring.sh — 一键启动真实生产场景监测演示
#
# 功能:
#   1. 创建 FIFO 命名管道（Agent ↔ Monitor 通信通道）
#   2. 启动 Agent 模拟进程（后台，模拟 Q3 市场分析任务的系统事件）
#   3. 启动 Monitor 守护进程（后台，读取 FIFO 事件，实时风险分析）
#   4. 两者完全解耦：独立的进程，通过 FIFO 通信，无代码依赖
#
# 用法:
#   ./start_demo_monitoring.sh              # 启动监测演示
#   ./start_demo_monitoring.sh --stop       # 停止监测演示
#   ./start_demo_monitoring.sh --status     # 查看运行状态
#   ./start_demo_monitoring.sh --foreground # 前台运行 Monitor（实时看输出）
#
# 进程结构:
#   ┌─────────────────┐     FIFO      ┌─────────────────────┐
#   │  agent_sim.py    │──────────────▶│  monitor_daemon.py   │
#   │  (Agent 模拟)    │  JSON Lines   │  (全链路 Pipeline)   │
#   │  PID: $AGENT_PID │               │  PID: $MONITOR_PID   │
#   └─────────────────┘               └─────────────────────┘
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OBSERVER_DIR="$PROJECT_ROOT/observer_sim"
# 运行时文件全部放在 workspace 内，避免 /tmp 权限/沙箱问题
MONITORING_RUN_DIR="$PROJECT_ROOT/.monitoring"
FIFO_PATH="$MONITORING_RUN_DIR/pipe"
PID_DIR="$MONITORING_RUN_DIR"
AGENT_PID_FILE="$PID_DIR/agent.pid"
MONITOR_PID_FILE="$PID_DIR/monitor.pid"
OUTPUT_DIR="$OBSERVER_DIR/output/demo_monitoring"

# 可选参数
MONITOR_MODE="oneshot"      # oneshot | daemon
EBPF_FLAG=""                # --ebpf (空字符串或 "--ebpf")
TUNING_PATH=""              # --tuning <path>
MONITOR_ONLY=false          # --monitor-only 只启动 Monitor，不启动模拟 Agent

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# =============================================================================
# 工具函数
# =============================================================================

_print_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    方寸观察者 — 实时监测演示 (Production Demo)          ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  场景: Q3 商业报表市场分析                               ║${NC}"
    echo -e "${CYAN}║  Agent: deep-agent-fintech-analyst (独立进程)            ║${NC}"
    echo -e "${CYAN}║  Monitor: observer_sim 全链路 Pipeline (独立进程)        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

_print_instructions() {
    echo -e "${YELLOW}📋 操作说明:${NC}"
    echo "  在 test.py 交互菜单中选择:"
    echo "    [D] 启动监测  — 启动本脚本"
    echo "    [E] 终止监测  — 停止进程并生成报告"
    echo ""
    echo -e "${YELLOW}📊 实时查看 Monitor 输出:${NC}"
    echo "  tail -f $PID_DIR/monitor.log"
    echo ""
    echo -e "${YELLOW}📄 报告位置:${NC}"
    echo "  $OUTPUT_DIR/reports/"
    echo ""
}

_is_running() {
    local pid_file="$1"
    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# =============================================================================
# start — 启动监测演示
# =============================================================================

do_start() {
    local foreground="${1:-false}"

    # 检查是否已在运行
    if _is_running "$MONITOR_PID_FILE"; then
        echo -e "${YELLOW}⚠️  监测已在运行中 (Monitor PID: $(cat "$MONITOR_PID_FILE"))${NC}"
        echo "  如需重启，请先执行: $0 --stop"
        exit 1
    fi

    _print_banner

    # 创建 PID 目录
    mkdir -p "$PID_DIR"
    mkdir -p "$OUTPUT_DIR"/{audit,reports,graphs}

    # 清理旧 FIFO
    if [ -p "$FIFO_PATH" ]; then
        rm -f "$FIFO_PATH"
    fi
    # 创建新 FIFO
    mkfifo "$FIFO_PATH"
    echo -e "${GREEN}✅ FIFO 管道已创建: $FIFO_PATH${NC}"

    # ── 启动 Monitor 守护进程 ──────────────────────────────────
    echo -e "${CYAN}🚀 启动 Monitor 守护进程...${NC}"
    cd "$OBSERVER_DIR"

    if [ "$foreground" = "true" ]; then
        # 前台模式：Monitor 在前台，Agent 在后台
        python3 "$OBSERVER_DIR/agent_sim.py" \
            --fifo "$FIFO_PATH" \
            --speed 1.5 &
        AGENT_PID=$!
        echo "$AGENT_PID" > "$AGENT_PID_FILE"
        echo -e "${GREEN}✅ Agent 已启动 (PID: $AGENT_PID)${NC}"

        # 给 Agent 一点时间连上 FIFO
        sleep 0.5

        # Monitor 在前台运行
        echo -e "${CYAN}📡 Monitor 前台运行中... (Ctrl+C 停止)${NC}"
        echo ""
        python3 "$OBSERVER_DIR/monitor_daemon.py" \
            --fifo "$FIFO_PATH" \
            --output "$OUTPUT_DIR" \
            --mode "$MONITOR_MODE" \
            $EBPF_FLAG

        # Monitor 退出后清理 Agent
        if kill -0 "$AGENT_PID" 2>/dev/null; then
            kill "$AGENT_PID" 2>/dev/null || true
            wait "$AGENT_PID" 2>/dev/null || true
        fi
        rm -f "$AGENT_PID_FILE"
    else
        # 后台模式：两者都在后台运行
        # 启动 Monitor（后台，输出到日志文件）
        LOG_FILE="$PID_DIR/monitor.log"
        python3 "$OBSERVER_DIR/monitor_daemon.py" \
            --fifo "$FIFO_PATH" \
            --output "$OUTPUT_DIR" \
            --mode "$MONITOR_MODE" \
            $EBPF_FLAG \
            > "$LOG_FILE" 2>&1 &
        MONITOR_PID=$!
        echo "$MONITOR_PID" > "$MONITOR_PID_FILE"
        echo -e "${GREEN}✅ Monitor 已启动 (PID: $MONITOR_PID, log: $LOG_FILE)${NC}"

        # 短暂等待 Monitor 打开 FIFO 读端
        sleep 0.3

        if [ "$MONITOR_ONLY" = true ]; then
            # ── Monitor-Only 模式：不启动模拟 Agent，等待外部真实 Agent 连接 ──
            echo -e "${GREEN}✅ Monitor 已启动 (PID: $MONITOR_PID)${NC}"
            echo ""
            echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}🎯 Monitor 守护进程已启动（等待外部 Agent 连接）${NC}"
            echo ""
            echo "  Monitor PID:  $MONITOR_PID"
            echo "  Monitor Log:  $LOG_FILE"
            echo "  FIFO:         $FIFO_PATH"
            echo ""
            echo -e "${YELLOW}📋 在另一个终端启动真实 Agent:${NC}"
            echo "  cd deep-agents-demo"
            echo "  bash setup_workspace.sh"
            echo "  python3 run_agent.py \\"
            echo "      --task-file task_instruction.txt \\"
            echo "      --workspace workspace \\"
            echo "      --fifo $FIFO_PATH"
            echo ""
            echo -e "${YELLOW}💡 提示:${NC}"
            echo "  实时查看:  tail -f $LOG_FILE"
            echo "  停止演示:  $0 --stop"
            echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${YELLOW}⏳ 等待外部 Agent 连接... (按 Ctrl+C 退出等待，Monitor 继续后台运行)${NC}"
            # 阻塞等待，直到用户 Ctrl+C
            wait $MONITOR_PID 2>/dev/null || true
            # Monitor 退出后的清理
            rm -f "$MONITOR_PID_FILE" "$AGENT_PID_FILE" 2>/dev/null || true
            rm -f "$FIFO_PATH" 2>/dev/null || true
            echo -e "${GREEN}🎉 Monitor 已退出。${NC}"
        else
            # ── 正常模式：启动模拟 Agent ──
            # 启动 Agent（后台）
            python3 "$OBSERVER_DIR/agent_sim.py" \
                --fifo "$FIFO_PATH" \
                --speed 1.5 \
                > "$PID_DIR/agent.log" 2>&1 &
            AGENT_PID=$!
            echo "$AGENT_PID" > "$AGENT_PID_FILE"
            echo -e "${GREEN}✅ Agent 已启动 (PID: $AGENT_PID)${NC}"

            echo ""
            echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}🎯 监测演示已启动！${NC}"
            echo ""
            echo "  Agent PID:    $AGENT_PID"
            echo "  Monitor PID:  $MONITOR_PID"
            echo "  Monitor Log:  $LOG_FILE"
            echo "  FIFO:         $FIFO_PATH"
            echo ""
            echo -e "${YELLOW}💡 提示:${NC}"
            echo "  实时查看:  tail -f $LOG_FILE"
            echo "  停止演示:  $0 --stop"
            echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
            echo ""

            _print_instructions

            # 等待两个进程结束，然后自动清理并生成报告
            # （Agent 断开后 Monitor 在 oneshot 模式下自动退出并生成报告）
            if [ "$MONITOR_MODE" = "oneshot" ]; then
                wait $AGENT_PID 2>/dev/null || true
                wait $MONITOR_PID 2>/dev/null || true
                # 清理
                rm -f "$AGENT_PID_FILE" "$MONITOR_PID_FILE"
                rm -f "$FIFO_PATH"
                echo -e "${GREEN}🎉 监测演示完成！报告已生成。${NC}"
            fi
        fi
    fi
}

# =============================================================================
# stop — 停止监测演示
# =============================================================================

do_stop() {
    local stopped_agent=false
    local stopped_monitor=false

    echo -e "${YELLOW}🛑 正在停止监测演示...${NC}"

    # 停止 Agent
    if [ -f "$AGENT_PID_FILE" ]; then
        AGENT_PID=$(cat "$AGENT_PID_FILE")
        if kill -0 "$AGENT_PID" 2>/dev/null; then
            kill "$AGENT_PID" 2>/dev/null || true
            echo "  已发送 SIGTERM → Agent (PID: $AGENT_PID)"
            stopped_agent=true
        fi
        rm -f "$AGENT_PID_FILE"
    fi

    # 停止 Monitor
    if [ -f "$MONITOR_PID_FILE" ]; then
        MONITOR_PID=$(cat "$MONITOR_PID_FILE")
        if kill -0 "$MONITOR_PID" 2>/dev/null; then
            kill "$MONITOR_PID" 2>/dev/null || true
            echo "  已发送 SIGTERM → Monitor (PID: $MONITOR_PID)"
            stopped_monitor=true
        fi
        rm -f "$MONITOR_PID_FILE"
    fi

    # 等待进程退出
    if [ "$stopped_agent" = true ] || [ "$stopped_monitor" = true ]; then
        sleep 2
        echo -e "${GREEN}✅ 监测演示已停止${NC}"
    else
        echo -e "${YELLOW}⚠️  没有正在运行的监测进程${NC}"
    fi

    # 清理 FIFO
    if [ -p "$FIFO_PATH" ]; then
        rm -f "$FIFO_PATH"
        echo "  已清理 FIFO 管道"
    fi
}

# =============================================================================
# status — 查看运行状态
# =============================================================================

do_status() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  监测演示运行状态${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    # Agent 状态
    if _is_running "$AGENT_PID_FILE"; then
        AGENT_PID=$(cat "$AGENT_PID_FILE")
        echo -e "  Agent:    ${GREEN}运行中${NC} (PID: $AGENT_PID)"
    else
        echo -e "  Agent:    ${RED}未运行${NC}"
    fi

    # Monitor 状态
    if _is_running "$MONITOR_PID_FILE"; then
        MONITOR_PID=$(cat "$MONITOR_PID_FILE")
        echo -e "  Monitor:  ${GREEN}运行中${NC} (PID: $MONITOR_PID)"
    else
        echo -e "  Monitor:  ${RED}未运行${NC}"
    fi

    # FIFO 状态
    if [ -p "$FIFO_PATH" ]; then
        echo -e "  FIFO:     ${GREEN}存在${NC} ($FIFO_PATH)"
    else
        echo -e "  FIFO:     ${YELLOW}不存在${NC}"
    fi

    # 报告状态
    REPORT_DIR="$OUTPUT_DIR/reports"
    if [ -d "$REPORT_DIR" ]; then
        REPORT_COUNT=$(find "$REPORT_DIR" -name "risk_report_*.md" 2>/dev/null | wc -l)
        echo -e "  报告:     ${GREEN}${REPORT_COUNT} 份${NC} ($REPORT_DIR)"
        if [ "$REPORT_COUNT" -gt 0 ]; then
            LATEST=$(find "$REPORT_DIR" -name "risk_report_*.md" -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
            if [ -n "$LATEST" ]; then
                echo "            最新: $LATEST"
            fi
        fi
    else
        echo -e "  报告:     ${YELLOW}无${NC}"
    fi

    echo ""
}

# =============================================================================
# 主入口
# =============================================================================

ACTION="start"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stop|-s)
            ACTION="stop"
            shift
            ;;
        --status)
            ACTION="status"
            shift
            ;;
        --foreground|-f)
            ACTION="foreground"
            shift
            ;;
        --daemon)
            MONITOR_MODE="daemon"
            shift
            ;;
        --monitor-only)
            MONITOR_ONLY=true
            MONITOR_MODE="daemon"   # monitor-only 必须用 daemon 模式保持存活
            shift
            ;;
        --ebpf)
            EBPF_FLAG="--ebpf"
            shift
            ;;
        --tuning)
            TUNING_PATH="$2"
            shift 2
            ;;
        --help|-h)
            ACTION="help"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

case "$ACTION" in
    stop)
        do_stop
        ;;
    status)
        do_status
        ;;
    foreground)
        do_start "true"
        ;;
    help)
        echo "用法: $0 [选项]"
        echo ""
        echo "  (无参数)          后台启动监测演示 (oneshot 模式)"
        echo "  --daemon          Monitor 守护模式 (Agent 断开后等待重连)"
        echo "  --monitor-only    仅启动 Monitor 守护进程，不启动模拟 Agent"
        echo "                    (用于配合外部真实 Agent，如 run_agent.py)"
        echo "  --ebpf            启用 eBPF 实时阻断 (需 root 权限)"
        echo "  --tuning <path>   指定调优参数文件"
        echo "  --stop, -s        停止监测演示"
        echo "  --status          查看运行状态"
        echo "  --foreground, -f  前台运行 Monitor（可实时看到彩色输出）"
        echo "  --help, -h        显示此帮助"
        echo ""
        echo "示例:"
        echo "  $0                            # 后台 oneshot 模式"
        echo "  $0 --daemon                   # 后台守护模式"
        echo "  $0 --monitor-only             # 仅 Monitor (配合 run_agent.py)"
        echo "  $0 --daemon --ebpf            # 守护模式 + eBPF 阻断"
        echo "  $0 --foreground --daemon      # 前台守护模式"
        ;;
    start)
        do_start "false"
        ;;
esac
