#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

namespace fim {

template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t max_size = 0) : m_max_size(max_size) {}

    void setMaxSize(size_t max_size) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_max_size = max_size;
        while (m_queue.size() > m_max_size) {
            m_queue.pop(); // Remove oldest elements if necessary
        }
    }

    bool push(T& value) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (m_queue.size() >= m_max_size) {
            return false; // Queue is full
        }
        m_queue.push(value);
        m_cond_var.notify_one();
        return true;
    }

    bool push(T&& value) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (m_queue.size() >= m_max_size) {
            return false; // Queue is full
        }
        m_queue.push(std::move(value));
        m_cond_var.notify_one();
        return true;
    }

    bool pop(T& out_value, int timeout_ms) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (!m_cond_var.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] { return !m_queue.empty(); })) {
            return false; // Timeout
        }
        out_value = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.empty();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.size();
    }

private:
    std::queue<T> m_queue;
    size_t m_max_size;
    mutable std::mutex m_mutex;
    std::condition_variable m_cond_var;
};

}
