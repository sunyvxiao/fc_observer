/**
 * common.h — 公共数据结构定义
 * 
 * 定义 C++ 探针层与 Python 引擎之间传输的数据结构。
 * 与 Python models/event.py 和 models/command.py 完全对应。
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <sstream>

namespace observer {

/**
 * EventSpec — 事件规格（从场景 YAML 解析后的事件描述）
 * 
 * 由场景加载器生成，传递给探针的 capture() 方法。
 */
struct EventSpec {
    std::string type;           // "exec" | "file_open" | "net_conn"
    std::string agent_id;       // Agent 唯一标识
    std::string agent_framework;// Agent 框架名称
    std::string exe;            // 可执行文件路径 (exec 事件)
    std::vector<std::string> args; // 命令行参数 (exec 事件)
    std::string path;           // 文件路径 (file 事件)
    std::string op;             // 文件操作类型 (file 事件)
    std::string addr;           // 远程地址 (network 事件)
    int port = 0;               // 远程端口 (network 事件)
    std::string protocol;       // 协议类型 (network 事件)
    uint32_t pid = 0;           // 目标进程 PID (0=自动分配)
    uint32_t ppid = 0;          // 父进程 PID (0=自动查找)
};

/**
 * RawEvent — 原始事件（探针捕获后格式化输出的完整事件结构）
 * 
 * 与 Python RawEvent dataclass 字段一一对应。
 * JSON 序列化时全量字段，缺失字段填 null。
 */
struct RawEvent {
    std::string event_id;
    uint64_t timestamp_ns = 0;
    std::string event_type;
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::string agent_id;
    std::string agent_framework;
    // ProcessProbe 字段
    std::string executable;
    std::vector<std::string> arguments;
    // FileProbe 字段
    std::string file_path;
    std::string file_op;
    // NetworkProbe 字段
    std::string remote_addr;
    uint16_t remote_port = 0;
    std::string protocol;
};

/**
 * Command — 阻断指令（从 Python 反向管道接收的控制指令）
 * 
 * 与 Python Command dataclass 字段一一对应。
 */
struct Command {
    std::string cmd_id;
    std::string cmd_type;       // "allow" | "block_event" | "terminate_process" | "heartbeat"
    std::string target_event_id;
    uint32_t target_pid = 0;
    std::string action;         // "return_eperm" | "kill_process"
    std::string reason;
    uint64_t timestamp_ns = 0;
};

/**
 * ProcessInfo — 进程信息（进程表条目）
 */
struct ProcessInfo {
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::string agent_id;
    std::string executable;
    bool terminated = false;
    std::vector<uint32_t> children;
};

/**
 * 简易 JSON 序列化工具（不依赖外部库）
 * 
 * 将 RawEvent 序列化为 JSON 行格式，用于管道传输。
 */
inline std::string escape_json_string(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 10);
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:   result += c; break;
        }
    }
    return result;
}

inline std::string json_string_or_null(const std::string& s) {
    if (s.empty()) return "null";
    return "\"" + escape_json_string(s) + "\"";
}

inline std::string json_int_or_null(int64_t v, bool has_value = true) {
    if (!has_value) return "null";
    return std::to_string(v);
}

/**
 * 将 RawEvent 序列化为 JSON 行（一行一个事件，\n 分隔）
 */
inline std::string serialize_event(const RawEvent& evt) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"event_id\":" << json_string_or_null(evt.event_id) << ",";
    oss << "\"timestamp_ns\":" << evt.timestamp_ns << ",";
    oss << "\"event_type\":" << json_string_or_null(evt.event_type) << ",";
    oss << "\"pid\":" << evt.pid << ",";
    oss << "\"ppid\":" << evt.ppid << ",";
    oss << "\"agent_id\":" << json_string_or_null(evt.agent_id) << ",";
    oss << "\"agent_framework\":" << json_string_or_null(evt.agent_framework) << ",";
    oss << "\"executable\":" << json_string_or_null(evt.executable) << ",";

    // arguments 数组
    oss << "\"arguments\":[";
    for (size_t i = 0; i < evt.arguments.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << escape_json_string(evt.arguments[i]) << "\"";
    }
    oss << "],";

    oss << "\"file_path\":" << json_string_or_null(evt.file_path) << ",";
    oss << "\"file_op\":" << json_string_or_null(evt.file_op) << ",";
    oss << "\"remote_addr\":" << json_string_or_null(evt.remote_addr) << ",";
    oss << "\"remote_port\":" << (evt.remote_port > 0 ? std::to_string(evt.remote_port) : "null") << ",";
    oss << "\"protocol\":" << json_string_or_null(evt.protocol);
    oss << "}";

    return oss.str();
}

/**
 * 简易 JSON 解析工具（解析 Command 指令）
 * 
 * 从 JSON 字符串中提取指定字段的值。
 * 仅支持简单的一级 JSON 对象，不支持嵌套。
 */
inline std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    
    pos += search.size();
    // 跳过空白
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    
    if (pos >= json.size()) return "";
    
    // null 值
    if (json.substr(pos, 4) == "null") return "";
    
    // 字符串值
    if (json[pos] == '"') {
        pos++; // 跳过开始引号
        std::string result;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                pos++;
                switch (json[pos]) {
                    case '"': result += '"'; break;
                    case '\\': result += '\\'; break;
                    case 'n': result += '\n'; break;
                    case 'r': result += '\r'; break;
                    case 't': result += '\t'; break;
                    default: result += json[pos]; break;
                }
            } else {
                result += json[pos];
            }
            pos++;
        }
        return result;
    }
    
    // 数字值（转为字符串）
    std::string result;
    while (pos < json.size() && json[pos] != ',' && json[pos] != '}' && json[pos] != ' ') {
        result += json[pos];
        pos++;
    }
    return result;
}

inline uint32_t json_get_uint(const std::string& json, const std::string& key) {
    std::string val = json_get_string(json, key);
    if (val.empty()) return 0;
    try {
        return static_cast<uint32_t>(std::stoul(val));
    } catch (...) {
        return 0;
    }
}

inline uint64_t json_get_uint64(const std::string& json, const std::string& key) {
    std::string val = json_get_string(json, key);
    if (val.empty()) return 0;
    try {
        return std::stoull(val);
    } catch (...) {
        return 0;
    }
}

/**
 * 从 JSON 行解析 Command 指令
 */
inline Command parse_command(const std::string& json_line) {
    Command cmd;
    cmd.cmd_id = json_get_string(json_line, "cmd_id");
    cmd.cmd_type = json_get_string(json_line, "cmd_type");
    cmd.target_event_id = json_get_string(json_line, "target_event_id");
    cmd.target_pid = json_get_uint(json_line, "target_pid");
    cmd.action = json_get_string(json_line, "action");
    cmd.reason = json_get_string(json_line, "reason");
    cmd.timestamp_ns = json_get_uint64(json_line, "timestamp_ns");
    return cmd;
}

} // namespace observer
