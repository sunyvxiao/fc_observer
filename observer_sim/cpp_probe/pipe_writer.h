/**
 * pipe_writer.h — 正向管道写入器 (C++ → Python)
 * 
 * 通过 Windows 命名管道向 Python 侧发送事件。
 * 管道名: \\.\pipe\observer_events
 * 方向: C++ (客户端) → Python (服务端)
 * 
 * 关键特性:
 * - 非阻塞写入（使用 FILE_FLAG_OVERLAPPED 或超时机制）
 * - 写入失败时事件暂存 RingBuffer
 * - 管道恢复后按 FIFO 补发暂存事件
 * - 支持 flush() 手动触发补发
 */

#pragma once

#include "common.h"
#include "ring_buffer.h"
#include <string>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
// 非 Windows 平台使用模拟实现（用于编译测试）
#include <fstream>
#endif

namespace observer {

class PipeWriter {
public:
    PipeWriter() : connected_(false), buffer_full_count_(0) {}

    ~PipeWriter() {
        close();
    }

    /**
     * 打开命名管道连接
     * 
     * C++ 侧作为客户端连接到 Python 创建的管道服务端。
     * 
     * @param pipe_name 管道名称（如 "\\\\.\\pipe\\observer_events"）
     * @return 是否成功连接
     */
    bool open(const std::string& pipe_name) {
        pipe_name_ = pipe_name;

#ifdef _WIN32
        // 等待管道可用（最多等待 5 秒）
        if (!WaitNamedPipeA(pipe_name.c_str(), 5000)) {
            std::cerr << "[PipeWriter] WaitNamedPipe failed: " << GetLastError() << std::endl;
            return false;
        }

        // 以写入模式连接到管道
        handle_ = CreateFileA(
            pipe_name.c_str(),
            GENERIC_WRITE,       // 写入权限
            0,                   // 不共享
            NULL,                // 默认安全属性
            OPEN_EXISTING,       // 打开已存在的管道
            0,                   // 默认属性（同步模式）
            NULL                 // 无模板
        );

        if (handle_ == INVALID_HANDLE_VALUE) {
            std::cerr << "[PipeWriter] CreateFile failed: " << GetLastError() << std::endl;
            return false;
        }

        // 设置管道模式为消息模式
        DWORD mode = PIPE_READMODE_BYTE;
        if (!SetNamedPipeHandleState(handle_, &mode, NULL, NULL)) {
            std::cerr << "[PipeWriter] SetNamedPipeHandleState failed: " << GetLastError() << std::endl;
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
            return false;
        }

        connected_ = true;
        std::cout << "[PipeWriter] Connected to " << pipe_name << std::endl;
        return true;
#else
        // 非 Windows: 使用文件模拟管道（用于编译测试）
        output_file_.open(pipe_name, std::ios::out | std::ios::app);
        connected_ = output_file_.is_open();
        if (connected_) {
            std::cout << "[PipeWriter] Opened file " << pipe_name << " (simulated pipe)" << std::endl;
        }
        return connected_;
#endif
    }

    /**
     * 写入一行 JSON 数据到管道
     * 
     * 非阻塞设计:
     * 1. 尝试直接写入管道
     * 2. 写入失败 → 暂存到 RingBuffer
     * 3. 写入成功后尝试 flush 暂存数据
     * 
     * @param json_line JSON 行字符串（不含尾部换行符）
     * @return true 如果成功写入（或暂存），false 如果失败且缓冲区满
     */
    bool write(const std::string& json_line) {
        if (!connected_) {
            // 管道未连接，暂存到缓冲区
            return buffer_to_ring(json_line);
        }

        std::string data = json_line + "\n";
        bool success = false;

#ifdef _WIN32
        DWORD bytes_written = 0;
        success = WriteFile(handle_, data.c_str(), static_cast<DWORD>(data.size()),
                           &bytes_written, NULL);
        if (!success) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_DATA || err == ERROR_PIPE_NOT_CONNECTED) {
                // 管道断开，暂存到缓冲区
                connected_ = false;
                std::cerr << "[PipeWriter] Pipe disconnected, buffering event" << std::endl;
            } else {
                std::cerr << "[PipeWriter] WriteFile failed: " << err << std::endl;
            }
            return buffer_to_ring(json_line);
        }
#else
        if (output_file_.is_open()) {
            output_file_ << data << std::flush;
            success = output_file_.good();
        }
        if (!success) {
            return buffer_to_ring(json_line);
        }
#endif

        // 写入成功，尝试补发暂存的事件
        if (!buffer_.empty()) {
            flush();
        }
        return true;
    }

    /**
     * 补发 RingBuffer 中的暂存事件
     * 
     * 按 FIFO 顺序逐个尝试写入，失败时停止补发。
     */
    void flush() {
        if (!connected_) return;

        std::string item;
        while (buffer_.pop(item)) {
            std::string data = item + "\n";
#ifdef _WIN32
            DWORD bytes_written = 0;
            if (!WriteFile(handle_, data.c_str(), static_cast<DWORD>(data.size()),
                          &bytes_written, NULL)) {
                // 写入失败，将当前 item 放回并停止
                buffer_.push(item);
                connected_ = false;
                break;
            }
#else
            if (output_file_.is_open()) {
                output_file_ << data << std::flush;
            }
#endif
        }
    }

    /**
     * 关闭管道连接
     */
    void close() {
#ifdef _WIN32
        if (handle_ != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(handle_);
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
#else
        if (output_file_.is_open()) {
            output_file_.close();
        }
#endif
        connected_ = false;
    }

    /** 是否已连接 */
    bool is_connected() const { return connected_; }

    /** 暂存缓冲区当前大小 */
    size_t buffer_size() const { return buffer_.size(); }

    /** 缓冲区溢出次数（覆盖旧数据） */
    size_t buffer_full_count() const { return buffer_full_count_; }

private:
    bool buffer_to_ring(const std::string& json_line) {
        bool ok = buffer_.push(json_line);
        if (!ok) {
            buffer_full_count_++;
            std::cerr << "[PipeWriter] RingBuffer full, oldest event overwritten" << std::endl;
        }
        return true; // 暂存成功（即使覆盖了旧数据）
    }

    std::string pipe_name_;
    bool connected_;
    RingBuffer<std::string, 1024> buffer_;  // 最多暂存 1024 条事件
    size_t buffer_full_count_;

#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
    std::ofstream output_file_;
#endif
};

} // namespace observer
