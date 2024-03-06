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

namespace Utils
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
            std::lock_guard<std::mutex> lock {other.m_mutex};
            m_queue = other.m_queue;
        }
        explicit TSafeQueue(Tq&& queue)
            : m_queue {std::move(queue)}
            , m_canceled {false}
        {
        }
        ~TSafeQueue()
        {
            cancel();
        }

        void push(const T& value)
        {
            std::lock_guard<std::mutex> lock {m_mutex};

            if (!m_canceled)
            {
                m_queue.push(value);
                m_cv.notify_one();
            }
        }

        bool pop(U& value, const bool wait = true)
        {
            std::unique_lock<std::mutex> lock {m_mutex};

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
            std::unique_lock<std::mutex> lock {m_mutex};

            if (wait)
            {
                m_cv.wait(lock, [this]() { return !m_queue.empty() || m_canceled; });
            }

            const bool ret {!m_canceled && !m_queue.empty()};

            if (ret)
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
            std::unique_lock<std::mutex> lock {m_mutex};
            std::queue<U> bulkQueue;

            auto timeoutReached = false;

            // Lambda to check if the condition is met
            // (queue size is greater than or equal to the number of elements to be extracted)
            // or if the queue is not empty and the thread has been canceled.
            auto condition = [this, elementsQuantity]()
            {
                return m_queue.size() >= elementsQuantity || (!m_queue.empty() && m_canceled);
            };

            // Wait until the condition is met or the timeout is reached.
            // If the condition is met, extract the elements from the queue.
            // If the timeout is reached, extract the elements from the queue
            while (!condition() && !timeoutReached)
            {
                if (m_cv.wait_for(lock, timeout, condition))
                {
                    break;
                }
                else
                {
                    timeoutReached = true;
                }
            }

            // If the timeout is reached or the queue is not empty and the thread has been canceled,
            // extract the elements from the queue.
            if (!timeoutReached || (!m_queue.empty() && !m_canceled))
            {
                for (auto i = 0; i < elementsQuantity && i < m_queue.size(); ++i)
                {
                    bulkQueue.push(std::move(m_queue.at(i)));
                }
            }

            return bulkQueue;
        }

        void popBulk(const uint64_t elementsQuantity)
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            for (auto i = 0; i < elementsQuantity && !m_queue.empty(); ++i)
            {
                m_queue.pop();
            }
        }

        bool empty() const
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_queue.empty();
        }

        size_t size() const
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_queue.size();
        }

        void cancel()
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_canceled = true;
            m_cv.notify_all();
        }

        bool cancelled() const
        {
            std::lock_guard<std::mutex> lock {m_mutex};
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
} // namespace Utils

#endif // THREAD_SAFE_QUEUE_H
