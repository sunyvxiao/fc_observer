/**
 * command_reader.h — 反向管道读取器 (Python → C++)
 * 
 * 从 Python 侧通过反向命名管道接收阻断指令。
 * 管道名: \\.\pipe\observer_commands
 * 方向: Python (客户端) → C++ (服务端)
 * 
 * 关键特性:
 * - 非阻塞轮询（使用 PeekNamedPipe 检查数据可用性）
 * - 无数据时返回 nullopt（不阻塞事件处理流程）
 * - 管道断开时降级为"全放行"模式 + 控制台告警
 * - 支持心跳探测
 */

#pragma once

#include "common.h"
#include <string>
#include <optional>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <fstream>
#include <sstream>
#endif

namespace observer {

class CommandReader {
public:
    CommandReader() : connected_(false), heartbeat_miss_count_(0) {}

    ~CommandReader() {
        close();
    }

    /**
     * 打开反向管道连接
     * 
     * C++ 侧作为服务端创建管道，等待 Python 客户端连接。
     * 或者 C++ 侧作为客户端连接到 Python 创建的管道。
     * 
     * 定稿方案: C++ 作为客户端连接到 Python 创建的管道。
     * 
     * @param pipe_name 管道名称（如 "\\\\.\\pipe\\observer_commands"）
     * @return 是否成功连接
     */
    bool open(const std::string& pipe_name) {
        pipe_name_ = pipe_name;

#ifdef _WIN32
        // 等待管道可用（最多等待 5 秒）
        if (!WaitNamedPipeA(pipe_name.c_str(), 5000)) {
            std::cerr << "[CommandReader] WaitNamedPipe failed: " << GetLastError() << std::endl;
            return false;
        }

        // 以读取模式连接到管道
        handle_ = CreateFileA(
            pipe_name.c_str(),
            GENERIC_READ,        // 读取权限
            0,                   // 不共享
            NULL,                // 默认安全属性
            OPEN_EXISTING,       // 打开已存在的管道
            0,                   // 默认属性（同步模式）
            NULL                 // 无模板
        );

        if (handle_ == INVALID_HANDLE_VALUE) {
            std::cerr << "[CommandReader] CreateFile failed: " << GetLastError() << std::endl;
            return false;
        }

        // 设置管道模式为字节模式
        DWORD mode = PIPE_READMODE_BYTE;
        if (!SetNamedPipeHandleState(handle_, &mode, NULL, NULL)) {
            std::cerr << "[CommandReader] SetNamedPipeHandleState failed: " << GetLastError() << std::endl;
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
            return false;
        }

        connected_ = true;
        std::cout << "[CommandReader] Connected to " << pipe_name << std::endl;
        return true;
#else
        // 非 Windows: 使用文件模拟管道（用于编译测试）
        input_file_.open(pipe_name, std::ios::in);
        connected_ = input_file_.is_open();
        if (connected_) {
            std::cout << "[CommandReader] Opened file " << pipe_name << " (simulated pipe)" << std::endl;
        }
        return connected_;
#endif
    }

    /**
     * 非阻塞轮询反向管道
     * 
     * 检查是否有新的阻断指令:
     * 1. 使用 PeekNamedPipe 检查数据可用性
     * 2. 有数据 → 读取一行 JSON → 解析为 Command
     * 3. 无数据 → 返回 nullopt
     * 4. 管道断开 → 降级为全放行模式
     * 
     * @return 读取到的指令（无数据返回 nullopt）
     */
    std::optional<Command> poll() {
        if (!connected_) {
            // 降级模式: 返回 allow 指令
            heartbeat_miss_count_++;
            if (heartbeat_miss_count_ % 10 == 0) {
                std::cerr << "[CommandReader] Degraded mode: pipe disconnected ("
                          << heartbeat_miss_count_ << " polls)" << std::endl;
            }
            return std::nullopt;
        }

#ifdef _WIN32
        // 使用 PeekNamedPipe 检查是否有数据
        DWORD bytes_available = 0;
        if (!PeekNamedPipe(handle_, NULL, 0, NULL, &bytes_available, NULL)) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                connected_ = false;
                std::cerr << "[CommandReader] Pipe broken, entering degraded mode" << std::endl;
                return std::nullopt;
            }
            return std::nullopt;
        }

        if (bytes_available == 0) {
            return std::nullopt; // 无数据
        }

        // 有数据，读取一行
        std::string line;
        char buffer[4096];
        DWORD bytes_read = 0;

        // 逐字节读取直到遇到换行符（简化实现）
        while (true) {
            DWORD one_byte_read = 0;
            char ch;
            if (!ReadFile(handle_, &ch, 1, &one_byte_read, NULL) || one_byte_read == 0) {
                break;
            }
            if (ch == '\n') {
                break;
            }
            line += ch;
        }

        if (line.empty()) {
            return std::nullopt;
        }

        // 解析 JSON 为 Command
        Command cmd = parse_command(line);
        heartbeat_miss_count_ = 0; // 收到数据，重置心跳计数
        return cmd;
#else
        // 非 Windows: 从文件读取一行
        if (!input_file_.is_open() || input_file_.eof()) {
            return std::nullopt;
        }

        std::string line;
        if (std::getline(input_file_, line) && !line.empty()) {
            Command cmd = parse_command(line);
            return cmd;
        }
        return std::nullopt;
#endif
    }

    /**
     * 关闭管道连接
     */
    void close() {
#ifdef _WIN32
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
#else
        if (input_file_.is_open()) {
            input_file_.close();
        }
#endif
        connected_ = false;
    }

    /** 是否已连接 */
    bool is_connected() const { return connected_; }

    /** 心跳未响应次数 */
    size_t heartbeat_miss_count() const { return heartbeat_miss_count_; }

private:
    std::string pipe_name_;
    bool connected_;
    size_t heartbeat_miss_count_;

#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
    std::ifstream input_file_;
#endif
};

} // namespace observer
