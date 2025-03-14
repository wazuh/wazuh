#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

namespace fim {

/**
 * @brief A thread-safe bounded queue.
 *
 * This class implements a thread-safe queue with a maximum size. It supports
 * pushing and popping elements with optional timeout for popping.
 *
 * @tparam T Type of elements stored in the queue.
 */
template <typename T>
class BoundedQueue {
public:
    /**
     * @brief Construct a new BoundedQueue object.
     *
     * @param max_size Maximum size of the queue. Default is 0 (unbounded).
     */
    explicit BoundedQueue(size_t max_size = 0) : m_max_size(max_size) {}

    /**
     * @brief Set the maximum size of the queue.
     *
     * If the current size of the queue exceeds the new maximum size, the oldest
     * elements will be removed.
     *
     * @param max_size New maximum size of the queue.
     */
    void setMaxSize(size_t max_size) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_max_size = max_size;
        while (m_queue.size() > m_max_size) {
            m_queue.pop(); // Remove oldest elements if necessary
        }
    }

    /**
     * @brief Push an element into the queue.
     *
     * @param value Element to be pushed.
     * @return true if the element was successfully pushed, false if the queue is full.
     */
    bool push(T& value) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (m_queue.size() >= m_max_size) {
            return false; // Queue is full
        }
        m_queue.push(value);
        m_cond_var.notify_one();
        return true;
    }

    /**
     * @brief Push an element into the queue using move semantics.
     *
     * @param value Element to be pushed.
     * @return true if the element was successfully pushed, false if the queue is full.
     */
    bool push(T&& value) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (m_queue.size() >= m_max_size) {
            return false; // Queue is full
        }
        m_queue.push(std::move(value));
        m_cond_var.notify_one();
        return true;
    }

    /**
     * @brief Pop an element from the queue with a timeout.
     *
     * @param out_value Reference to store the popped element.
     * @param timeout_ms Timeout in milliseconds.
     * @return true if an element was successfully popped, false if timeout occurred.
     */
    bool pop(T& out_value, int timeout_ms) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (!m_cond_var.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] { return !m_queue.empty(); })) {
            return false; // Timeout
        }
        out_value = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

    /**
     * @brief Check if the queue is empty.
     *
     * @return true if the queue is empty, false otherwise.
     */
    bool empty() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.empty();
    }

    /**
     * @brief Get the current size of the queue.
     *
     * @return size_t Current size of the queue.
     */
    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.size();
    }

private:
    std::queue<T> m_queue;              ///< The underlying queue.
    size_t m_max_size;                  ///< Maximum size of the queue.
    mutable std::mutex m_mutex;         ///< Mutex for thread safety.
    std::condition_variable m_cond_var; ///< Condition variable for synchronization.
};

}
