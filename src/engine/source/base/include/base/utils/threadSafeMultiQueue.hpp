/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * April 9, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef THREAD_SAFE_MULTIQUEUE_HPP
#define THREAD_SAFE_MULTIQUEUE_HPP
#include <atomic>
#include <condition_variable>
#include <mutex>

namespace base::utils::queue
{
constexpr auto QUEUE_CHECK_TIME = 5;

template<typename T, typename U, typename Tq>
class TSafeMultiQueue
{

public:
    TSafeMultiQueue()
        : m_canceled {false}
    {
    }
    TSafeMultiQueue& operator=(const TSafeMultiQueue&) = delete;
    TSafeMultiQueue(TSafeMultiQueue& other)
        : TSafeMultiQueue {}
    {
        std::scoped_lock lock {other.m_mutex};
        m_queue = other.m_queue;
    }
    explicit TSafeMultiQueue(Tq&& queue)
        : m_queue {std::move(queue)}
        , m_canceled {false}
    {
    }

    ~TSafeMultiQueue() { cancel(); }

    void push(std::string_view prefix, const T& value)
    {
        std::scoped_lock lock {m_mutex};
        if (!m_canceled)
        {
            m_queue.push(prefix, value);
            m_cv.notify_one();
        }
    }

    std::pair<U, std::string> front()
    {
        std::unique_lock lock {m_mutex};
        auto queueEmpty = true;

        // Wait for 10 seconds to check if the queue receive any data.
        // If not, return an empty pair.
        // we use wait_for instead of wait to check if some postponded data is ready to be processed in next
        // iteration.
        m_cv.wait_for(lock,
                      std::chrono::seconds(QUEUE_CHECK_TIME),
                      [&queueEmpty, this]()
                      {
                          // coverity[missing_lock]
                          queueEmpty = m_queue.empty();
                          return !queueEmpty || m_canceled;
                      });

        if (!m_canceled && !queueEmpty)
        {
            // coverity[missing_lock]
            const auto& columnFamilyName = m_queue.getAvailableColumn();
            return std::make_pair(m_queue.front(columnFamilyName), columnFamilyName);
        }

        return std::pair<U, std::string> {};
    }

    std::pair<U, std::string> getAndPop()
    {
        std::unique_lock lock {m_mutex};
        auto queueEmpty = true;

        // Wait for 10 seconds to check if the queue receive any data.
        // If not, return an empty pair.
        // we use wait_for instead of wait to check if some postponed data is ready to be processed in next
        // iteration.
        m_cv.wait_for(lock,
                      std::chrono::seconds(QUEUE_CHECK_TIME),
                      [&queueEmpty, this]()
                      {
                          // coverity[missing_lock]
                          queueEmpty = m_queue.empty();
                          return !queueEmpty || m_canceled;
                      });

        if (!m_canceled && !queueEmpty)
        {
            // coverity[missing_lock]
            const auto& columnFamilyName = m_queue.getAvailableColumn();
            auto data = std::make_pair(m_queue.front(columnFamilyName), columnFamilyName);
            m_queue.pop(columnFamilyName);
            return data;
        }

        return std::pair<U, std::string> {};
    }

    void pop(std::string_view prefix)
    {
        std::scoped_lock lock {m_mutex};
        if (!m_canceled)
        {
            m_queue.pop(prefix);
        }
    }

    bool empty() const
    {
        std::scoped_lock lock {m_mutex};
        return m_queue.empty();
    }

    void clear(std::string_view prefix)
    {
        std::scoped_lock lock {m_mutex};
        m_queue.clear(prefix);
    }

    size_t size(std::string_view prefix) const
    {
        std::scoped_lock lock {m_mutex};
        return m_queue.size(prefix);
    }

    void cancel()
    {
        std::scoped_lock lock {m_mutex};

        m_canceled = true;
        m_cv.notify_all();
    }

    bool cancelled() const
    {
        std::scoped_lock lock {m_mutex};
        return m_canceled;
    }

    void postpone(std::string_view prefix, const std::chrono::seconds& time) noexcept
    {
        std::scoped_lock lock {m_mutex};
        m_queue.postpone(prefix, time);
    }

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::atomic<bool> m_canceled {};
    Tq m_queue;
};
} // namespace base::utils::queue

#endif // THREAD_SAFE_MULTIQUEUE_HPP
