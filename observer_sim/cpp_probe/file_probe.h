/**
 * file_probe.h — 文件探针 (FileProbe)
 * 
 * 模拟 eBPF 对 openat/unlink/rename 系统调用的捕获。
 * 接收文件操作规格，补充进程上下文，构造 file_open 事件。
 */

#pragma once

#include "iprobe.h"
#include "process_table.h"
#include <atomic>

namespace observer {

class FileProbe : public IProbe {
public:
    explicit FileProbe(ProcessTable& proc_table)
        : proc_table_(proc_table), event_counter_(0) {}

    bool attach(int target_pid, const std::string& agent_id) override {
        // FileProbe 不需要独立的 attach，通过进程表共享上下文
        attached_pid_ = static_cast<uint32_t>(target_pid);
        return true;
    }

    RawEvent capture(const EventSpec& spec) override {
        RawEvent evt;
        evt.event_id = "evt_" + std::to_string(++event_counter_);
        evt.event_type = "file_open";
        evt.agent_id = spec.agent_id;
        evt.agent_framework = spec.agent_framework;

        // 分配 PID
        uint32_t pid = spec.pid > 0 ? spec.pid : attached_pid_;
        evt.pid = pid;
        evt.ppid = spec.ppid > 0 ? spec.ppid : proc_table_.get_ppid(pid);

        // 从进程表补充 agent_id（如果 spec 中未提供）
        if (evt.agent_id.empty()) {
            evt.agent_id = proc_table_.get_agent_id(pid);
        }

        // 文件操作字段
        evt.file_path = spec.path;
        evt.file_op = spec.op;

        return evt;
    }

    void detach() override {
        attached_pid_ = 0;
    }

    std::string name() const override { return "FileProbe"; }

private:
    ProcessTable& proc_table_;
    std::atomic<uint64_t> event_counter_;
    uint32_t attached_pid_ = 0;
};

} // namespace observer
