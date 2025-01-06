/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>

namespace base::utils::queue
{

template<typename T, typename U, typename Tq = std::queue<T>>
class TSafeQueue
{
public:
    TSafeQueue()
        : m_canceled {false}
    {
    }
    TSafeQueue& operator=(const TSafeQueue&) = delete;
    TSafeQueue(TSafeQueue& other)
        : TSafeQueue {}
    {
        std::scoped_lock lock {other.m_mutex};
        m_queue = other.m_queue;
    }
    explicit TSafeQueue(Tq&& queue)
        : m_queue {std::move(queue)}
        , m_canceled {false}
    {
    }
    ~TSafeQueue() { cancel(); }

    void push(const T& value)
    {
        std::scoped_lock lock {m_mutex};

        if (!m_canceled)
        {
            m_queue.push(value);
            m_cv.notify_one();
        }
    }

    bool pop(U& value, const bool wait = true)
    {
        std::unique_lock lock {m_mutex};

        if (wait)
        {
            m_cv.wait(lock, [this]() { return !m_queue.empty() || m_canceled; });
        }

        const bool ret {!m_canceled && !m_queue.empty()};

        if (ret)
        {
            value = std::move(m_queue.front());
            m_queue.pop();
        }

        return ret;
    }

    std::shared_ptr<U> pop(const bool wait = true)
    {
        std::unique_lock lock {m_mutex};

        if (wait)
        {
            m_cv.wait(lock, [this]() { return !m_queue.empty() || m_canceled; });
        }

        if (const bool ret {!m_canceled && !m_queue.empty()}; ret)
        {
            const auto spData {std::make_shared<U>(m_queue.front())};
            m_queue.pop();
            return spData;
        }

        return nullptr;
    }

    std::queue<U> getBulk(const uint64_t elementsQuantity,
                          const std::chrono::seconds& timeout = std::chrono::seconds(5))
    {
        std::unique_lock lock {m_mutex};
        std::queue<U> bulkQueue;

        // If we have less elements than requested, wait for more elements to be pushed.
        // coverity[missing_lock]
        if (m_queue.size() < elementsQuantity)
        {
            m_cv.wait_for(lock,
                          timeout,
                          [this, elementsQuantity]()
                          {
                              // coverity[missing_lock]
                              return m_canceled.load() || m_queue.size() >= elementsQuantity;
                          });
        }

        // If the queue is not canceled, get the elements.
        if (!m_canceled)
        {
            try
            {
                m_queue.frontQueue(bulkQueue, m_queue.size() > elementsQuantity ? elementsQuantity : m_queue.size());
            }
            catch (const std::exception& e)
            {
                bulkQueue = {};
            }
        }

        return bulkQueue;
    }

    void popBulk(const uint64_t elementsQuantity)
    {
        std::scoped_lock lock {m_mutex};
        auto counter = 0ULL;

        while (counter < elementsQuantity && !m_queue.empty())
        {
            m_queue.pop();
            ++counter;
        }
    }

    std::queue<U> getBulkAndPop(const uint64_t elementsQuantity,
                                const std::chrono::seconds& timeout = std::chrono::seconds(5))
    {
        std::unique_lock lock {m_mutex};
        std::queue<U> bulkQueue;

        // If we have less elements than requested, wait for more elements to be pushed.
        // coverity[missing_lock]
        if (m_queue.size() < elementsQuantity)
        {
            m_cv.wait_for(lock,
                          timeout,
                          [this, elementsQuantity]()
                          {
                              // coverity[missing_lock]
                              return m_canceled.load() || m_queue.size() >= elementsQuantity;
                          });
        }

        // If the queue is not canceled, get the elements.
        if (!m_canceled)
        {
            for (auto i = 0; i < elementsQuantity && i < m_queue.size(); ++i)
            {
                bulkQueue.push(std::move(m_queue.at(i)));
            }
        }

        // Pop the elements from the queue after getting them.
        for (auto i = 0; i < elementsQuantity && !m_queue.empty(); ++i)
        {
            m_queue.pop();
        }

        return bulkQueue;
    }

    bool empty() const
    {
        std::scoped_lock lock {m_mutex};
        return m_queue.empty();
    }

    size_t size() const
    {
        std::scoped_lock lock {m_mutex};
        return m_queue.size();
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

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::atomic<bool> m_canceled {};
    Tq m_queue;
};

template<typename T, typename Tq = std::queue<T>>
using SafeQueue = TSafeQueue<T, T, Tq>;
} // namespace base::utils::queue

#endif // THREAD_SAFE_QUEUE_H
