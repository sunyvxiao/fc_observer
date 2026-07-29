/**
 * process_probe.h — 进程探针 (ProcessProbe)
 * 
 * 模拟 eBPF 对 execve/fork/clone 系统调用的捕获。
 * 接收场景事件规格，补充 pid/ppid/agent_id，构造 exec 事件。
 */

#pragma once

#include "iprobe.h"
#include "process_table.h"
#include <atomic>

namespace observer {

class ProcessProbe : public IProbe {
public:
    explicit ProcessProbe(ProcessTable& proc_table)
        : proc_table_(proc_table), event_counter_(0) {}

    bool attach(int target_pid, const std::string& agent_id) override {
        return proc_table_.register_process(
            static_cast<uint32_t>(target_pid), 0, agent_id);
    }

    RawEvent capture(const EventSpec& spec) override {
        RawEvent evt;
        evt.event_id = "evt_" + std::to_string(++event_counter_);
        evt.event_type = "exec";
        evt.agent_id = spec.agent_id;
        evt.agent_framework = spec.agent_framework;

        // 分配 PID：如果 spec 指定了 pid 则使用，否则自动递增
        uint32_t pid = spec.pid > 0 ? spec.pid : next_pid_++;
        uint32_t ppid = spec.ppid > 0 ? spec.ppid : 0;

        // 如果未指定 ppid，尝试从进程表查找该 agent 的父进程
        if (ppid == 0 && !spec.agent_id.empty()) {
            // 查找该 agent 已有的进程，取最后一个作为 ppid
            auto existing = proc_table_.lookup(pid);
            if (existing.has_value()) {
                ppid = existing->ppid;
            }
        }

        evt.pid = pid;
        evt.ppid = ppid;
        evt.executable = spec.exe;
        evt.arguments = spec.args;

        // 在进程表中注册该进程
        proc_table_.register_process(pid, ppid, spec.agent_id, spec.exe);

        return evt;
    }

    void detach() override {
        // 教学模拟中无需实际 detach 操作
    }

    std::string name() const override { return "ProcessProbe"; }

private:
    ProcessTable& proc_table_;
    std::atomic<uint64_t> event_counter_;
    uint32_t next_pid_ = 20000; // 自动分配 PID 的起始值
};

} // namespace observer
