#!/usr/bin/env bash
# ============================================================
# register_observer_mcp.sh — P0: 把 observer MCP 申报 Server 注册进 Qoder CN
#
# 用法:
#   bash qoder_integration/register_observer_mcp.sh <目标项目目录>
#
# 效果:
#   在 <目标项目目录>/.mcp.json 中注册 observer（sse 类型，
#   http://127.0.0.1:8765/sse）。若文件已存在且非 JSON 对象，
#   脚本拒绝覆盖；已存在 observer 条目时保持不动。
#
# 前置条件（另一终端先启动监测守护进程）:
#   cd observer_sim/observer_sim
#   python observer.py daemon --mode mcp_report --output output/mcp_monitoring
#
# 等价官方 CLI 方式（二选一）:
#   qoderclicn mcp add -t sse -s project observer http://127.0.0.1:8765/sse
#
# 说明:
#   - MCP 工具仅在 Qoder CN Agent 模式下暴露；
#   - .mcp.json 为项目级配置，可提交 Git 团队共享；
#   - 注册后需重启 Qoder CN 生效（不支持热加载）。
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE="$SCRIPT_DIR/mcp.json.example"
TARGET_DIR="${1:-}"

if [[ -z "$TARGET_DIR" ]]; then
    echo "用法: bash $0 <目标项目目录>" >&2
    exit 2
fi
if [[ ! -d "$TARGET_DIR" ]]; then
    echo "ERROR: 目录不存在: $TARGET_DIR" >&2
    exit 2
fi

TARGET="$TARGET_DIR/.mcp.json"

if [[ -f "$TARGET" ]]; then
    # 已存在：仅在无 observer 条目时合并（用 python 标准库，避免额外依赖）
    python3 - "$TARGET" "$EXAMPLE" <<'PYEOF'
import json, sys
target_path, example_path = sys.argv[1], sys.argv[2]
with open(target_path, encoding="utf-8") as f:
    cfg = json.load(f)
if not isinstance(cfg, dict):
    print(f"ERROR: {target_path} 不是 JSON 对象，请手动合并", file=sys.stderr)
    sys.exit(1)
with open(example_path, encoding="utf-8") as f:
    example = json.load(f)
servers = cfg.setdefault("mcpServers", {})
if "observer" in servers:
    print(f"已存在 observer 条目，保持不变: {target_path}")
else:
    servers["observer"] = example["mcpServers"]["observer"]
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"已合并 observer 注册: {target_path}")
PYEOF
else
    cp "$EXAMPLE" "$TARGET"
    echo "已创建: $TARGET"
fi

echo ""
echo "注册完成。下一步："
echo "  1. 启动监测:  python observer.py daemon --mode mcp_report --output output/mcp_monitoring"
echo "  2. 重启 Qoder CN，在 Agent 模式下工作，申报数据将进入监测管线"
