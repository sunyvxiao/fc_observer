/**
 * iprobe.h — 抽象探针接口
 * 
 * 所有探针（ProcessProbe/FileProbe/NetworkProbe）的基类。
 * 模拟 eBPF 内核探针的 attach/capture/detach 生命周期。
 */

#pragma once

#include "common.h"
#include <string>

namespace observer {

class IProbe {
public:
    virtual ~IProbe() = default;

    /**
     * 附着到目标进程 — 建立 agent_id → pid 映射
     * 
     * @param target_pid 目标进程 PID
     * @param agent_id Agent 唯一标识
     * @return 是否成功附着
     */
    virtual bool attach(int target_pid, const std::string& agent_id) = 0;

    /**
     * 捕获事件 — 根据事件规格生成 RawEvent
     * 
     * 探针接收 EventSpec（场景事件描述），补充进程上下文（pid/ppid/agent_id），
     * 构造完整的 RawEvent 返回。
     * 
     * @param spec 事件规格（从场景 YAML 解析）
     * @return 捕获的原始事件
     */
    virtual RawEvent capture(const EventSpec& spec) = 0;

    /**
     * 脱离目标进程 — 清理资源
     */
    virtual void detach() = 0;

    /**
     * 获取探针名称（用于日志输出）
     */
    virtual std::string name() const = 0;
};

} // namespace observer
