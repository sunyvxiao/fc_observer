// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * observer.bpf.c — eBPF 内核探针程序（仅观测，第一版不含阻断）
 *
 * 挂载三类 tracepoint 探针，捕获 Agent 进程的系统调用事件：
 *   1. sys_enter_execve  — 命令执行（filename + argv）
 *   2. sys_enter_openat  — 文件操作（filename + flags）
 *   3. sys_enter_connect — 网络连接（sockaddr → IP:Port）
 *
 * 事件通过 perf ring buffer 推送到用户态 Python 加载器。
 *
 * 注意: event_t 结构体超过 512 字节 BPF 栈限制，
 *       使用 BPF_MAP_TYPE_PERCPU_ARRAY 作为事件缓冲区。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ============================================================
 * 常量定义
 * ============================================================ */

#define EVENT_EXECVE  0
#define EVENT_OPENAT  1
#define EVENT_CONNECT 2

#define FILENAME_MAX  256
#define ARGV_MAX      512
#define COMM_MAX      16

/* ============================================================
 * 事件结构体（内核态与用户态共享）
 * ============================================================ */

struct event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8  event_type;
    __u8  blocked;
    __u16 padding;

    union {
        struct {
            char filename[FILENAME_MAX];
            char argv[ARGV_MAX];
        } exec;
        struct {
            char filename[FILENAME_MAX];
            __u32 flags;
        } file;
        struct {
            __u32 ip_addr;
            __u16 port;
            __u8  protocol;
        } net;
    };

    char comm[COMM_MAX];
};

/* ============================================================
 * Maps
 * ============================================================ */

/* Perf event array: 事件推送到用户态 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/*
 * Per-CPU array: 用作事件缓冲区，避免 BPF 512 字节栈限制。
 * 每个 CPU 一个 event_t 实例，key=0。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct event_t));
    __uint(max_entries, 1);
} event_buf SEC(".maps");

/* ============================================================
 * 辅助函数
 * ============================================================ */

/* 获取 per-cpu 事件缓冲区并清零 */
static __always_inline struct event_t *get_event_buf(void)
{
    __u32 key = 0;
    struct event_t *e = bpf_map_lookup_elem(&event_buf, &key);
    if (!e)
        return NULL;
    __builtin_memset(e, 0, sizeof(*e));
    return e;
}

/* 填充事件头部（公共字段） */
static __always_inline void fill_event_header(struct event_t *e, __u8 event_type)
{
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->blocked = 0;
    e->padding = 0;
    e->event_type = event_type;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);
        e->uid = BPF_CORE_READ(task, cred, uid.val);
    }

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* ============================================================
 * 探针 1: sys_enter_execve
 * ============================================================ */

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t *e = get_event_buf();
    if (!e)
        return 0;

    fill_event_header(e, EVENT_EXECVE);

    /* filename */
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->exec.filename, sizeof(e->exec.filename), filename);

    /* argv: 拼接为 \0 分隔的字符串，最多 15 个参数
     * 每参数最多读 24 字节，总量不超 ARGV_MAX。
     * 不使用 #pragma unroll，避免验证器在多迭代后丢失范围追踪。
     */
    const char *const *argv = (const char *const *)ctx->args[1];
    __u32 argv_offset = 0;

    for (int i = 0; i < 15; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        if (argv_offset >= ARGV_MAX - 24)
            break;
        long len = bpf_probe_read_user_str(
            &e->exec.argv[argv_offset],
            24,
            argp);
        if (len > 0)
            argv_offset += len;
        else
            break;
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}

/* ============================================================
 * 探针 2: sys_enter_openat
 * ============================================================ */

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t *e = get_event_buf();
    if (!e)
        return 0;

    fill_event_header(e, EVENT_OPENAT);

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->file.filename, sizeof(e->file.filename), filename);
    e->file.flags = (__u32)ctx->args[2];

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}

/* ============================================================
 * 探针 3: sys_enter_connect
 * ============================================================ */

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t *e = get_event_buf();
    if (!e)
        return 0;

    fill_event_header(e, EVENT_CONNECT);

    struct sockaddr *uaddr = (struct sockaddr *)ctx->args[1];

    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &uaddr->sa_family);

    if (family == 2) {  /* AF_INET */
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), uaddr);
        e->net.ip_addr = sin.sin_addr.s_addr;
        e->net.port    = sin.sin_port;
        e->net.protocol = 0;  /* TCP */
    } else {
        /* 非 IPv4 暂不处理 */
        return 0;
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
