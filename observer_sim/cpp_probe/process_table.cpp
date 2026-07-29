/**
 * process_table.cpp — 简易进程表实现
 */

#include "process_table.h"
#include <iostream>

namespace observer {

bool ProcessTable::register_process(uint32_t pid, uint32_t ppid,
                                     const std::string& agent_id,
                                     const std::string& executable) {
    ProcessInfo info;
    info.pid = pid;
    info.ppid = ppid;
    info.agent_id = agent_id;
    info.executable = executable;
    info.terminated = false;

    table_[pid] = info;

    // 在父进程的 children 列表中添加当前 pid
    if (ppid > 0) {
        auto it = table_.find(ppid);
        if (it != table_.end()) {
            it->second.children.push_back(pid);
        }
    }

    return true;
}

std::optional<ProcessInfo> ProcessTable::lookup(uint32_t pid) const {
    auto it = table_.find(pid);
    if (it == table_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool ProcessTable::terminate(uint32_t pid) {
    auto it = table_.find(pid);
    if (it == table_.end()) {
        return false;
    }
    it->second.terminated = true;

    // 递归终止所有子进程
    for (uint32_t child_pid : it->second.children) {
        terminate(child_pid);
    }
    return true;
}

std::string ProcessTable::get_agent_id(uint32_t pid) const {
    auto it = table_.find(pid);
    if (it != table_.end()) {
        return it->second.agent_id;
    }
    return "";
}

uint32_t ProcessTable::get_ppid(uint32_t pid) const {
    auto it = table_.find(pid);
    if (it != table_.end()) {
        return it->second.ppid;
    }
    return 0;
}

bool ProcessTable::is_terminated(uint32_t pid) const {
    auto it = table_.find(pid);
    if (it != table_.end()) {
        return it->second.terminated;
    }
    return false; // 不存在的进程视为已终止
}

size_t ProcessTable::active_count() const {
    size_t count = 0;
    for (const auto& [pid, info] : table_) {
        if (!info.terminated) count++;
    }
    return count;
}

size_t ProcessTable::total_count() const {
    return table_.size();
}

} // namespace observer
