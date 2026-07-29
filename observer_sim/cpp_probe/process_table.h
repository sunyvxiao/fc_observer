/**
 * process_table.h — 简易进程表
 * 
 * 维护 pid → ProcessInfo 映射，支持:
 * - execve 时自动注册新进程
 * - 文件/网络事件通过 pid 查询补充 agent_id 和 ppid
 * - 进程终止时标记为 terminated（懒删除）
 * - 子进程自动继承 agent_id
 */

#pragma once

#include "common.h"
#include <unordered_map>
#include <string>
#include <vector>
#include <optional>

namespace observer {

class ProcessTable {
public:
    ProcessTable() = default;

    /**
     * 注册新进程 — execve 事件时调用
     * 
     * @param pid 进程 PID
     * @param ppid 父进程 PID
     * @param agent_id Agent 标识
     * @param executable 可执行文件路径
     * @return 是否注册成功
     */
    bool register_process(uint32_t pid, uint32_t ppid,
                          const std::string& agent_id,
                          const std::string& executable = "");

    /**
     * 查询进程信息
     * 
     * @param pid 进程 PID
     * @return 进程信息（不存在返回 nullopt）
     */
    std::optional<ProcessInfo> lookup(uint32_t pid) const;

    /**
     * 终止进程 — 标记为 terminated（懒删除）
     * 
     * @param pid 进程 PID
     * @return 是否找到并标记
     */
    bool terminate(uint32_t pid);

    /**
     * 获取进程的 agent_id（通过 pid 查询，支持继承链）
     * 
     * @param pid 进程 PID
     * @return agent_id（未找到返回空字符串）
     */
    std::string get_agent_id(uint32_t pid) const;

    /**
     * 获取进程的 ppid
     */
    uint32_t get_ppid(uint32_t pid) const;

    /**
     * 检查进程是否已终止
     */
    bool is_terminated(uint32_t pid) const;

    /**
     * 获取所有活跃（未终止）进程数
     */
    size_t active_count() const;

    /**
     * 获取所有进程数（含已终止）
     */
    size_t total_count() const;

private:
    std::unordered_map<uint32_t, ProcessInfo> table_;
};

} // namespace observer
