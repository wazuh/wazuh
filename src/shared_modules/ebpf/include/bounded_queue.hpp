/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>

namespace wazuh::ebpf {

/**
 * @brief Thread-safe queue with a fixed capacity.
 *
 * Decouples the ring buffer poller from the consumer that processes the events:
 * whatever the consumer does must never stall the kernel ring. When the queue is
 * full push() reports it instead of blocking, so the caller can account for the
 * drop and keep draining the ring.
 */
template<typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t max_size)
        : m_max_size(max_size) {}

    /**
     * @brief Enqueues @p value, or reports the queue is full.
     */
    bool push(T&& value) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_queue.size() >= m_max_size) {
                return false;
            }
            m_queue.push(std::move(value));
        }
        m_cond_var.notify_one();
        return true;
    }

    /**
     * @brief Dequeues into @p out_value, waiting up to @p timeout_ms.
     * @return false when the timeout expires with an empty queue.
     */
    bool pop(T& out_value, int timeout_ms) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (!m_cond_var.wait_for(
                lock, std::chrono::milliseconds(timeout_ms), [this] { return !m_queue.empty(); })) {
            return false;
        }
        out_value = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

private:
    std::queue<T> m_queue;
    const size_t m_max_size;
    std::mutex m_mutex;
    std::condition_variable m_cond_var;
};

} // namespace wazuh::ebpf
