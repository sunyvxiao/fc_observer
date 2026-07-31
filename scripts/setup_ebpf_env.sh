#!/bin/bash
# ============================================================================
# setup_ebpf_env.sh — 方寸观察者 eBPF 开发环境一键配置脚本
#
# 用途: 在 Ubuntu 22.04+ 系统上自动检查和安装 eBPF 开发所需依赖
# 运行: chmod +x scripts/setup_ebpf_env.sh && sudo ./scripts/setup_ebpf_env.sh
# ============================================================================

set -uo pipefail

# ── 颜色码 ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

OK="${GREEN}[OK]${NC}"
WARN="${YELLOW}[WARN]${NC}"
FAIL="${RED}[FAIL]${NC}"
INFO="${CYAN}[INFO]${NC}"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

pass() { echo -e "  ${OK} $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
warn() { echo -e "  ${WARN} $1"; WARN_COUNT=$((WARN_COUNT + 1)); }
fail() { echo -e "  ${FAIL} $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
info() { echo -e "  ${INFO} $1"; }

# ── 前置检查 ─────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  方寸观察者 — eBPF 开发环境配置"
echo "============================================================"
echo ""

# 检查是否以 root 运行
if [[ $EUID -ne 0 ]]; then
    echo -e "${WARN} 建议以 root 运行此脚本以安装系统依赖"
    echo -e "  用法: sudo $0"
    echo ""
    if [[ -t 0 ]]; then
        read -p "继续以当前用户运行? [y/N]: " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "已取消"
            exit 0
        fi
    else
        echo "  (非交互模式，继续运行...)"
    fi
fi

# ── 1. 系统信息 ──────────────────────────────────────────────────
echo ""
echo "── 1. 系统信息 ──"

KERNEL_VERSION=$(uname -r)
echo -e "  内核版本: ${KERNEL_VERSION}"
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
if [[ "$KERNEL_MAJOR" -ge 6 ]] || { [[ "$KERNEL_MAJOR" -eq 5 ]] && [[ "$KERNEL_MINOR" -ge 15 ]]; }; then
    pass "内核版本 >= 5.15 (${KERNEL_VERSION})"
else
    fail "内核版本过旧 (${KERNEL_VERSION}), 需要 >= 5.15"
fi

DISTRIB=$(cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME=" | cut -d'"' -f2 || echo "Unknown")
echo -e "  发行版: ${DISTRIB}"

# ── 2. Python 环境 ───────────────────────────────────────────────
echo ""
echo "── 2. Python 环境 ──"

if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if [[ "$PY_MAJOR" -ge 3 ]] && [[ "$PY_MINOR" -ge 10 ]]; then
        pass "Python 版本 >= 3.10 (${PY_VERSION})"
    else
        fail "Python 版本过旧 (${PY_VERSION}), 需要 >= 3.10"
    fi
else
    fail "python3 未找到"
fi

# pyyaml
if python3 -c "import yaml" 2>/dev/null; then
    pass "pyyaml 已安装"
else
    info "正在安装 pyyaml..."
    pip3 install pyyaml -q 2>/dev/null && pass "pyyaml 安装成功" || fail "pyyaml 安装失败"
fi

# pytest
if python3 -m pytest --version &>/dev/null; then
    pass "pytest 已安装"
else
    info "正在安装 pytest..."
    pip3 install pytest -q 2>/dev/null && pass "pytest 安装成功" || fail "pytest 安装失败"
fi

# ── 3. eBPF 编译工具链 ───────────────────────────────────────────
echo ""
echo "── 3. eBPF 编译工具链 ──"

# clang
if command -v clang &>/dev/null; then
    CLANG_VERSION=$(clang --version 2>&1 | head -1)
    pass "clang 已安装 (${CLANG_VERSION})"
else
    info "正在安装 clang..."
    apt-get install -y clang -qq 2>/dev/null && pass "clang 安装成功" || fail "clang 安装失败"
fi

# llvm
if command -v llvm-strip &>/dev/null || command -v llvm-config &>/dev/null; then
    pass "llvm 工具已安装"
else
    info "正在安装 llvm..."
    apt-get install -y llvm -qq 2>/dev/null && pass "llvm 安装成功" || fail "llvm 安装失败"
fi

# libbpf-dev
if dpkg -l libbpf-dev 2>/dev/null | grep -q "^ii"; then
    LIBBPF_VER=$(dpkg -l libbpf-dev 2>/dev/null | grep "^ii" | awk '{print $3}')
    pass "libbpf-dev 已安装 (${LIBBPF_VER})"
else
    info "正在安装 libbpf-dev..."
    apt-get install -y libbpf-dev -qq 2>/dev/null && pass "libbpf-dev 安装成功" || fail "libbpf-dev 安装失败"
fi

# linux-headers
HEADERS_PKG="linux-headers-${KERNEL_VERSION}"
if dpkg -l "$HEADERS_PKG" 2>/dev/null | grep -q "^ii"; then
    pass "linux-headers 已安装 (${HEADERS_PKG})"
else
    info "正在安装 ${HEADERS_PKG}..."
    apt-get install -y "$HEADERS_PKG" -qq 2>/dev/null && pass "linux-headers 安装成功" || warn "linux-headers 安装失败 (可能已安装通用版本)"
fi

# make
if command -v make &>/dev/null; then
    pass "make 已安装"
else
    info "正在安装 make..."
    apt-get install -y make -qq 2>/dev/null && pass "make 安装成功" || fail "make 安装失败"
fi

# ── 4. bpftool ───────────────────────────────────────────────────
echo ""
echo "── 4. bpftool ──"

if command -v bpftool &>/dev/null; then
    BPFTOOL_VER=$(bpftool version 2>&1 | head -1)
    pass "bpftool 已安装 (${BPFTOOL_VER})"
else
    info "正在安装 bpftool..."
    apt-get install -y linux-tools-common linux-tools-"${KERNEL_VERSION}" -qq 2>/dev/null \
        && pass "bpftool 安装成功" \
        || fail "bpftool 安装失败"
fi

# ── 5. BTF 支持检查 ──────────────────────────────────────────────
echo ""
echo "── 5. BTF 支持 ──"

if [[ -f /sys/kernel/btf/vmlinux ]]; then
    BTF_SIZE=$(stat -c%s /sys/kernel/btf/vmlinux 2>/dev/null || echo "?")
    pass "BTF 文件存在 (/sys/kernel/btf/vmlinux, ${BTF_SIZE} bytes)"
else
    fail "BTF 文件不存在 (/sys/kernel/btf/vmlinux)"
    info "  提示: 需要内核 >= 5.2 且 CONFIG_DEBUG_INFO_BTF=y"
fi

# ── 6. libbpf.so 加载测试 ────────────────────────────────────────
echo ""
echo "── 6. libbpf.so 运行时 ──"

if python3 -c "import ctypes; ctypes.CDLL('libbpf.so')" 2>/dev/null; then
    pass "libbpf.so 可加载"
else
    fail "libbpf.so 无法加载"
    info "  提示: 运行 'sudo ldconfig' 或检查 libbpf-dev 安装"
fi

# ── 7. 权限检查 ──────────────────────────────────────────────────
echo ""
echo "── 7. 权限检查 ──"

if [[ $EUID -eq 0 ]]; then
    pass "以 root 运行 (eBPF 加载需要 CAP_BPF + CAP_PERFMON)"
else
    # 检查 CAP_BPF
    CAP_EFF=$(grep "CapEff:" /proc/self/status 2>/dev/null | awk '{print $2}')
    if [[ -n "$CAP_EFF" ]]; then
        CAP_HEX=$((16#${CAP_EFF}))
        CAP_BPF=$(( (CAP_HEX >> 39) & 1 ))
        CAP_PERFMON=$(( (CAP_HEX >> 38) & 1 ))
        if [[ $CAP_BPF -eq 1 ]] && [[ $CAP_PERFMON -eq 1 ]]; then
            pass "CAP_BPF + CAP_PERFMON 已授予"
        else
            warn "CAP_BPF=${CAP_BPF}, CAP_PERFMON=${CAP_PERFMON} (需要两者均为 1)"
            info "  提示: sudo setcap cap_bpf,cap_perfmon+ep \$(which python3)"
        fi
    fi

    # ptrace_scope
    PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "?")
    if [[ "$PTRACE_SCOPE" == "0" ]]; then
        pass "ptrace_scope = 0 (strace 可附着任意进程)"
    elif [[ "$PTRACE_SCOPE" == "1" ]]; then
        warn "ptrace_scope = 1 (strace 仅可附着子进程, 需要 root 或调整)"
        info "  提示: sudo sysctl -w kernel.yama.ptrace_scope=0"
    else
        warn "ptrace_scope = ${PTRACE_SCOPE}"
    fi
fi

# ── 8. strace ────────────────────────────────────────────────────
echo ""
echo "── 8. strace ──"

if command -v strace &>/dev/null; then
    STRACE_VER=$(strace -V 2>&1 | head -1)
    pass "strace 已安装 (${STRACE_VER})"
else
    info "正在安装 strace..."
    apt-get install -y strace -qq 2>/dev/null && pass "strace 安装成功" || fail "strace 安装失败"
fi

# ── 9. eBPF 编译验证 ─────────────────────────────────────────────
echo ""
echo "── 9. eBPF 编译验证 ──"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EBPF_DIR="${PROJECT_DIR}/observer_sim/ebpf"

if [[ -d "$EBPF_DIR" ]]; then
    info "eBPF 源码目录: ${EBPF_DIR}"
    if [[ -f "${EBPF_DIR}/observer.bpf.c" ]]; then
        pass "observer.bpf.c 存在"
    else
        fail "observer.bpf.c 不存在"
    fi
    if [[ -f "${EBPF_DIR}/Makefile" ]]; then
        pass "Makefile 存在"
    else
        fail "Makefile 不存在"
    fi

    # 尝试编译
    info "尝试编译 eBPF 探针..."
    if make -C "$EBPF_DIR" clean all 2>&1 | tail -1 | grep -q "observer.bpf.o"; then
        pass "编译成功 (observer.bpf.o)"
    elif [[ -f "${EBPF_DIR}/observer.bpf.o" ]]; then
        pass "编译成功 (observer.bpf.o 已存在)"
    else
        warn "编译可能失败，请手动检查: cd ${EBPF_DIR} && make"
    fi
else
    warn "eBPF 目录不存在: ${EBPF_DIR}"
fi

# ── 汇总 ─────────────────────────────────────────────────────────
echo ""
echo "============================================================"
TOTAL=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT))
echo -e "  检查完成: ${GREEN}${PASS_COUNT} 通过${NC}, ${RED}${FAIL_COUNT} 失败${NC}, ${YELLOW}${WARN_COUNT} 警告${NC} (共 ${TOTAL} 项)"

if [[ $FAIL_COUNT -eq 0 ]] && [[ $WARN_COUNT -eq 0 ]]; then
    echo -e "  ${GREEN}✓ eBPF 开发环境就绪！${NC}"
elif [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "  ${YELLOW}△ 基本就绪，部分功能可能受限（见上方警告）${NC}"
else
    echo -e "  ${RED}✗ 存在 ${FAIL_COUNT} 项失败，请根据提示修复${NC}"
fi
echo "============================================================"
echo ""

exit $FAIL_COUNT
