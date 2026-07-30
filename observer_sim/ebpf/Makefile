# eBPF 探针编译脚本
# 用法:
#   make           — 生成 vmlinux.h + 编译 observer.bpf.o
#   make clean     — 清理编译产物
#   make vmlinux   — 仅生成 vmlinux.h
#   make probe     — 仅编译 observer.bpf.o（需已有 vmlinux.h）

CLANG    ?= clang
BPFTOOL  ?= bpftool
LLVM_STRIP ?= llvm-strip

# 内核头文件路径（用于 vmlinux.h 生成）
BTF_PATH := /sys/kernel/btf/vmlinux

# 编译选项
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 \
              -I. \
              -Wall -Werror

.PHONY: all clean vmlinux probe

all: vmlinux probe

# 生成 vmlinux.h（从内核 BTF 信息导出类型定义）
vmlinux: vmlinux.h

vmlinux.h: $(BTF_PATH)
	$(BPFTOOL) btf dump file $(BTF_PATH) format c > vmlinux.h
	@echo "[OK] vmlinux.h 生成完成"

# 编译 eBPF 探针程序
probe: observer.bpf.o

observer.bpf.o: observer.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c observer.bpf.c -o observer.bpf.o
	@echo "[OK] observer.bpf.o 编译完成"

# 清理编译产物（保留 vmlinux.h，因为生成耗时较长）
clean:
	rm -f observer.bpf.o
	rm -f *.llc
	@echo "[OK] 编译产物已清理"

# 完全清理（包含 vmlinux.h）
distclean: clean
	rm -f vmlinux.h
	@echo "[OK] vmlinux.h 已清理"
