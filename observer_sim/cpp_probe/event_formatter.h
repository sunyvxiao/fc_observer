/**
 * event_formatter.h — 事件格式化器
 * 
 * 将 RawEvent 序列化为 JSON 行格式，用于命名管道传输。
 * 同时负责为事件注入虚拟时钟时间戳（由 Python 侧覆盖）。
 */

#pragma once

#include "common.h"
#include <string>

namespace observer {

class EventFormatter {
public:
    /**
     * 将 RawEvent 格式化为 JSON 行字符串
     * 
     * @param event 原始事件
     * @return JSON 行字符串（不含尾部换行符）
     */
    static std::string format(const RawEvent& event) {
        return serialize_event(event);
    }

    /**
     * 为事件注入虚拟时钟时间戳
     * 
     * Python 侧在事件注入阶段用 VirtualClock 覆盖 timestamp_ns，
     * 保证全系统时间源一致。
     * 
     * @param event 待修改的事件
     * @param timestamp_ns 虚拟时钟时间戳（纳秒）
     */
    static void inject_timestamp(RawEvent& event, uint64_t timestamp_ns) {
        event.timestamp_ns = timestamp_ns;
    }
};

} // namespace observer
