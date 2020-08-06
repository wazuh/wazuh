/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H
#include <deque>
#include <mutex>
#include <memory>
#include <atomic>
#include <condition_variable>

namespace Utils
{

    template<typename T>
    class SafeQueue
    {
    public:
        SafeQueue()
        : m_canceled{ false }
        {}
        SafeQueue& operator=(const SafeQueue&) = delete;
        SafeQueue(SafeQueue& other)
        : SafeQueue{}
        {
            std::lock_guard<std::mutex> lock{ other.m_mutex };
            m_queue = other.m_queue;
        }
        ~SafeQueue()
        {
            cancel();
        }

        void pushBack(const T& value)
        {
            if (!m_canceled)
            {
                Lock lock{ m_mutex };
                m_queue.push_back(value);
                lock.unlock();
                m_cv.notify_one();
            }
        }

        void pushFront(const T& value)
        {
            if (!m_canceled)
            {
                Lock lock{ m_mutex };
                m_queue.push_front(value);
                lock.unlock();
                m_cv.notify_one();
            }
        }

        bool popFront(T& value, const bool wait = true)
        {
            Lock lock{ m_mutex };
            if (wait)
            {
                m_cv.wait(lock, [this](){return !m_queue.empty() || m_canceled;});
            }
            const bool ret {!m_canceled && !m_queue.empty()};
            if (ret)
            {
                value = m_queue.front();
                m_queue.pop_front();
            }
            return ret;
        }

        std::shared_ptr<T> popFront(const bool wait = true)
        {
            Lock lock{ m_mutex };
            if (wait)
            {
                m_cv.wait(lock, [this](){return !m_queue.empty() || m_canceled;});
            }
            const bool ret {!m_canceled && !m_queue.empty()};
            if (ret)
            {
                const auto spData{ std::make_shared<T>(m_queue.front()) };
                m_queue.pop_front();
                return spData;
            }
            return nullptr;
        }

        bool popBack(T& value, const bool wait = true)
        {
            Lock lock{ m_mutex };
            if (wait)
            {
                m_cv.wait(lock, [this](){return !m_queue.empty() || m_canceled;});
            }
            const bool ret {!m_canceled && !m_queue.empty()};
            if (ret)
            {
                value = m_queue.back();
                m_queue.pop_back();
            }
            return ret;
        }

        std::shared_ptr<T> popBack(const bool wait = true)
        {
            Lock lock{ m_mutex };
            if (wait)
            {
                m_cv.wait(lock, [this](){return !m_queue.empty() || m_canceled;});
            }
            const bool ret {!m_canceled && !m_queue.empty()};
            if (ret)
            {
                const auto spData{ std::make_shared<T>(m_queue.back()) };
                m_queue.pop_back();
                return spData;
            }
            return nullptr;
        }

        bool empty() const
        {
            std::lock_guard<std::mutex> lock{ m_mutex };
            return m_queue.empty();
        }

        size_t size() const
        {
            std::lock_guard<std::mutex> lock{ m_mutex };
            return m_queue.size();
        }

        void cancel()
        {
            Lock lock{ m_mutex };
            m_canceled = true;
            lock.unlock();
            m_cv.notify_all();
        }

        bool cancelled() const
        {
            return m_canceled;
        }
    private:
        using Lock = std::unique_lock<std::mutex>;
        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        std::atomic_bool m_canceled;
        std::deque<T> m_queue;
    };
}//namespace Utils

#endif //THREAD_SAFE_QUEUE_H
