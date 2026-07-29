/**
 * main.cpp — C++ 探针层入口
 * 
 * 职责:
 * 1. 从 stdin 接收场景事件规格（JSON 行格式，由 Python 侧发送）
 * 2. 根据事件类型路由到对应探针（ProcessProbe/FileProbe/NetworkProbe）
 * 3. 探针处理后通过 PipeWriter 写入正向管道
 * 4. 通过 CommandReader 非阻塞轮询反向管道获取阻断指令
 * 5. 执行阻断指令（allow/block/terminate）
 * 
 * 通信架构:
 * - stdin: 接收 Python 发来的事件规格（JSON 行）
 * - \\.\pipe\observer_events: 正向管道，输出 RawEvent 到 Python
 * - \\.\pipe\observer_commands: 反向管道，接收 Python 的阻断指令
 */

#include "common.h"
#include "iprobe.h"
#include "process_probe.h"
#include "file_probe.h"
#include "network_probe.h"
#include "event_formatter.h"
#include "pipe_writer.h"
#include "command_reader.h"
#include "process_table.h"

#include <iostream>
#include <string>
#include <memory>
#include <unordered_map>
#include <functional>

using namespace observer;

/**
 * 从 stdin 读取一行 JSON，解析为 EventSpec
 */
EventSpec parse_event_spec(const std::string& json_line) {
    EventSpec spec;
    spec.type = json_get_string(json_line, "type");
    spec.agent_id = json_get_string(json_line, "agent_id");
    spec.agent_framework = json_get_string(json_line, "agent_framework");
    spec.exe = json_get_string(json_line, "executable");
    spec.path = json_get_string(json_line, "file_path");
    spec.op = json_get_string(json_line, "file_op");
    spec.addr = json_get_string(json_line, "remote_addr");
    spec.protocol = json_get_string(json_line, "protocol");
    spec.pid = json_get_uint(json_line, "pid");
    spec.ppid = json_get_uint(json_line, "ppid");

    // 解析 port
    std::string port_str = json_get_string(json_line, "remote_port");
    if (!port_str.empty()) {
        try { spec.port = std::stoi(port_str); } catch (...) { spec.port = 0; }
    }

    // 解析 arguments 数组（简化: 从 JSON 中提取 "arguments":["a","b"] 格式）
    auto args_pos = json_line.find("\"arguments\"");
    if (args_pos != std::string::npos) {
        auto arr_start = json_line.find('[', args_pos);
        auto arr_end = json_line.find(']', arr_start);
        if (arr_start != std::string::npos && arr_end != std::string::npos) {
            std::string arr_str = json_line.substr(arr_start + 1, arr_end - arr_start - 1);
            // 简单解析: 按逗号分割，去除引号
            std::string current;
            bool in_quotes = false;
            for (char c : arr_str) {
                if (c == '"') {
                    in_quotes = !in_quotes;
                } else if (c == ',' && !in_quotes) {
                    if (!current.empty()) {
                        spec.args.push_back(current);
                        current.clear();
                    }
                } else if (in_quotes) {
                    current += c;
                }
            }
            if (!current.empty()) {
                spec.args.push_back(current);
            }
        }
    }

    return spec;
}

/**
 * 处理阻断指令
 */
void handle_command(const Command& cmd, ProcessTable& proc_table) {
    if (cmd.cmd_type == "allow") {
        std::cout << "[Probe] ALLOW event=" << cmd.target_event_id << std::endl;
    }
    else if (cmd.cmd_type == "block_event") {
        std::cout << "[Probe] BLOCK event=" << cmd.target_event_id
                  << " pid=" << cmd.target_pid
                  << " reason=" << cmd.reason << std::endl;
        // 模拟: 标记该事件被阻断（实际教学中仅记录日志）
    }
    else if (cmd.cmd_type == "terminate_process") {
        std::cout << "[Probe] TERMINATE pid=" << cmd.target_pid
                  << " reason=" << cmd.reason << std::endl;
        proc_table.terminate(cmd.target_pid);
    }
    else if (cmd.cmd_type == "heartbeat") {
        std::cout << "[Probe] HEARTBEAT received" << std::endl;
    }
    else {
        std::cerr << "[Probe] Unknown command type: " << cmd.cmd_type << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=== Observer C++ Probe Layer ===" << std::endl;
    std::cout << "Waiting for events on stdin, outputting to named pipes..." << std::endl;

    // 初始化组件
    ProcessTable proc_table;
    ProcessProbe process_probe(proc_table);
    FileProbe file_probe(proc_table);
    NetworkProbe network_probe(proc_table);
    EventFormatter formatter;
    PipeWriter pipe_writer;
    CommandReader cmd_reader;

    // 管道名称（可通过命令行参数覆盖）
    std::string events_pipe = "\\\\.\\pipe\\observer_events";
    std::string commands_pipe = "\\\\.\\pipe\\observer_commands";
    if (argc >= 2) events_pipe = argv[1];
    if (argc >= 3) commands_pipe = argv[2];

    // 连接管道
    std::cout << "[Init] Connecting to event pipe: " << events_pipe << std::endl;
    bool pipe_ok = pipe_writer.open(events_pipe);
    if (!pipe_ok) {
        std::cerr << "[Init] WARNING: Event pipe not available, using stdout fallback" << std::endl;
    }

    std::cout << "[Init] Connecting to command pipe: " << commands_pipe << std::endl;
    bool cmd_ok = cmd_reader.open(commands_pipe);
    if (!cmd_ok) {
        std::cerr << "[Init] WARNING: Command pipe not available, degraded mode (allow all)" << std::endl;
    }

    // 事件处理循环
    std::string line;
    uint64_t event_count = 0;
    uint64_t blocked_count = 0;

    std::cout << "[Init] Ready. Reading events from stdin..." << std::endl;

    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;

        // 退出指令
        if (line == "__EXIT__" || line == "__QUIT__") {
            std::cout << "[Init] Received exit signal" << std::endl;
            break;
        }

        // 解析事件规格
        EventSpec spec = parse_event_spec(line);

        // 路由到对应探针
        RawEvent raw_event;
        if (spec.type == "exec") {
            raw_event = process_probe.capture(spec);
        } else if (spec.type == "file_open") {
            raw_event = file_probe.capture(spec);
        } else if (spec.type == "net_conn") {
            raw_event = network_probe.capture(spec);
        } else {
            std::cerr << "[Probe] Unknown event type: " << spec.type << std::endl;
            continue;
        }

        event_count++;

        // 格式化为 JSON 行
        std::string json_line = EventFormatter::format(raw_event);

        // 写入正向管道
        if (pipe_writer.is_connected()) {
            pipe_writer.write(json_line);
        }
        // 同时输出到 stdout（便于调试）
        std::cout << "[Event] " << json_line << std::endl;

        // 非阻塞轮询反向管道
        auto cmd = cmd_reader.poll();
        if (cmd.has_value()) {
            handle_command(cmd.value(), proc_table);
            if (cmd.value().cmd_type == "block_event" ||
                cmd.value().cmd_type == "terminate_process") {
                blocked_count++;
            }
        }
    }

    // 清理
    std::cout << "\n=== Probe Layer Summary ===" << std::endl;
    std::cout << "Total events processed: " << event_count << std::endl;
    std::cout << "Blocked events: " << blocked_count << std::endl;
    std::cout << "Active processes: " << proc_table.active_count() << std::endl;
    std::cout << "Total processes (incl. terminated): " << proc_table.total_count() << std::endl;
    std::cout << "Pipe buffer overflow count: " << pipe_writer.buffer_full_count() << std::endl;

    pipe_writer.close();
    cmd_reader.close();

    std::cout << "[Init] Probe layer shutdown complete." << std::endl;
    return 0;
}
