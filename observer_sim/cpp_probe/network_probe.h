/**
 * network_probe.h — 网络探针 (NetworkProbe)
 * 
 * 模拟 eBPF 对 connect/sendto/DNS 系统调用的捕获。
 * 接收网络操作规格，补充协议信息，构造 net_conn 事件。
 */

#pragma once

#include "iprobe.h"
#include "process_table.h"
#include <atomic>

namespace observer {

class NetworkProbe : public IProbe {
public:
    explicit NetworkProbe(ProcessTable& proc_table)
        : proc_table_(proc_table), event_counter_(0) {}

    bool attach(int target_pid, const std::string& agent_id) override {
        attached_pid_ = static_cast<uint32_t>(target_pid);
        return true;
    }

    RawEvent capture(const EventSpec& spec) override {
        RawEvent evt;
        evt.event_id = "evt_" + std::to_string(++event_counter_);
        evt.event_type = "net_conn";
        evt.agent_id = spec.agent_id;
        evt.agent_framework = spec.agent_framework;

        // 分配 PID
        uint32_t pid = spec.pid > 0 ? spec.pid : attached_pid_;
        evt.pid = pid;
        evt.ppid = spec.ppid > 0 ? spec.ppid : proc_table_.get_ppid(pid);

        // 从进程表补充 agent_id
        if (evt.agent_id.empty()) {
            evt.agent_id = proc_table_.get_agent_id(pid);
        }

        // 网络字段
        evt.remote_addr = spec.addr;
        evt.remote_port = static_cast<uint16_t>(spec.port);
        evt.protocol = spec.protocol.empty() ? "TCP" : spec.protocol;

        return evt;
    }

    void detach() override {
        attached_pid_ = 0;
    }

    std::string name() const override { return "NetworkProbe"; }

private:
    ProcessTable& proc_table_;
    std::atomic<uint64_t> event_counter_;
    uint32_t attached_pid_ = 0;
};

} // namespace observer
