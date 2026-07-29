/**
 * ring_buffer.h — 环形缓冲区模板
 * 
 * 用于 PipeWriter 写入失败时的事件暂存。
 * 固定容量，FIFO 顺序，线程安全（单生产者单消费者场景）。
 * 
 * 设计决策:
 * - 固定容量避免动态内存分配
 * - 满时覆盖最旧数据（教学原型可接受少量丢失）
 * - 提供 size()/empty()/full() 查询
 */

#pragma once

#include <array>
#include <cstddef>
#include <mutex>

namespace observer {

template <typename T, size_t Capacity>
class RingBuffer {
public:
    RingBuffer() : head_(0), tail_(0), count_(0) {}

    /**
     * 推入元素。如果缓冲区已满，覆盖最旧的元素。
     * 
     * @param item 要推入的元素
     * @return true 如果正常推入，false 如果覆盖了旧数据
     */
    bool push(const T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool overwritten = false;
        if (count_ == Capacity) {
            // 缓冲区满，覆盖最旧数据
            head_ = (head_ + 1) % Capacity;
            count_--;
            overwritten = true;
        }
        buffer_[tail_] = item;
        tail_ = (tail_ + 1) % Capacity;
        count_++;
        return !overwritten;
    }

    /**
     * 弹出最旧的元素。
     * 
     * @param item 输出参数，弹出的元素
     * @return true 如果成功弹出，false 如果缓冲区为空
     */
    bool pop(T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (count_ == 0) return false;
        item = buffer_[head_];
        head_ = (head_ + 1) % Capacity;
        count_--;
        return true;
    }

    /**
     * 查看最旧的元素但不弹出。
     */
    bool peek(T& item) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (count_ == 0) return false;
        item = buffer_[head_];
        return true;
    }

    /** 当前元素数量 */
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return count_;
    }

    /** 是否为空 */
    bool empty() const {
        return size() == 0;
    }

    /** 是否已满 */
    bool full() const {
        return size() == Capacity;
    }

    /** 缓冲区容量 */
    static constexpr size_t capacity() {
        return Capacity;
    }

    /** 清空缓冲区 */
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        head_ = 0;
        tail_ = 0;
        count_ = 0;
    }

private:
    std::array<T, Capacity> buffer_;
    size_t head_;   // 下一个弹出位置
    size_t tail_;   // 下一个推入位置
    size_t count_;  // 当前元素数
    mutable std::mutex mutex_;
};

} // namespace observer
