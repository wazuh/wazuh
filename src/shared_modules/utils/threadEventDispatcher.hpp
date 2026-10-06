/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * June 6, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _THREAD_EVENT_DISPATCHER_HPP
#define _THREAD_EVENT_DISPATCHER_HPP

#include "commonDefs.h"
#include "promiseFactory.h"
#include "rocksDBQueue.hpp"
#include "rocksDBQueueCF.hpp"
#include "threadSafeMultiQueue.hpp"
#include "threadSafeQueue.h"
#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <thread>

template<typename T,
         typename U,
         typename Functor,
         typename TQueueType = RocksDBQueue<T, U>,
         typename TSafeQueueType = Utils::TSafeQueue<T, U, RocksDBQueue<T, U>>>
class TThreadEventDispatcher
{
public:
    explicit TThreadEventDispatcher(Functor functor,
                                    const std::string& dbPath,
                                    const uint64_t bulkSize = 1,
                                    const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE,
                                    bool useSharedBuffers = false,
                                    std::function<void(const std::string&)> onDiscard = {})
        : m_functor {std::move(functor)}
        , m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
        , m_onDiscard {std::move(onDiscard)}
        , m_queue {std::make_unique<TSafeQueueType>(TQueueType(dbPath, useSharedBuffers))}
    {
        m_thread = std::thread {&TThreadEventDispatcher<T, U, Functor, TQueueType, TSafeQueueType>::dispatch, this};
    }

    explicit TThreadEventDispatcher(const std::string& dbPath,
                                    const uint64_t bulkSize = 1,
                                    const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE,
                                    std::function<void(const std::string&)> onDiscard = {})
        : m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
        , m_onDiscard {std::move(onDiscard)}
        , m_queue {std::make_unique<TSafeQueueType>(TQueueType(dbPath))}
    {
    }

    TThreadEventDispatcher& operator=(const TThreadEventDispatcher&) = delete;
    TThreadEventDispatcher(TThreadEventDispatcher& other) = delete;
    ~TThreadEventDispatcher()
    {
        cancel();
    }

    void startWorker(Functor functor)
    {
        m_functor = std::move(functor);
        m_thread = std::thread {&TThreadEventDispatcher<T, U, Functor, TQueueType, TSafeQueueType>::dispatch, this};
    }

    void push(const T& value)
    {
        if constexpr (!std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>)
        {
            if (m_running)
            {
                const auto queueSize = m_queue->size();
                if (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || queueSize < m_maxQueueSize)
                {
                    m_queue->push(value);
                    rearmDiscardReport(queueSize);
                }
                else
                {
                    reportDiscard(queueSize, "");
                }
            }
        }
        else
        {
            // static assert to avoid compilation
            static_assert(std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>,
                          "This method is not supported for this queue type");
        }
    }

    void push(std::string_view prefix, const T& value)
    {
        if constexpr (std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>)
        {
            if (m_running)
            {
                const auto queueSize = m_queue->size(prefix);
                if (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || queueSize < m_maxQueueSize)
                {
                    m_queue->push(prefix, value);
                    rearmDiscardReport(queueSize);
                }
                else
                {
                    reportDiscard(queueSize, prefix);
                }
            }
        }
        else
        {
            // static assert to avoid compilation
            static_assert(std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>,
                          "This method is not supported for this queue type");
        }
    }

    void clear(std::string_view prefix = "")
    {
        if constexpr (std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>)
        {
            m_queue->clear(prefix);
        }
        else
        {
            // static assert to avoid compilation
            static_assert(std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>,
                          "This method is not supported for this queue type");
        }
    }

    void cancel()
    {
        m_running = false;
        m_queue->cancel();
        joinThread();
    }

    bool cancelled() const
    {
        return !m_running;
    }

    size_t size() const
    {
        if constexpr (!std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>)
        {
            return m_queue->size();
        }
        else
        {
            static_assert(std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>,
                          "This method is not supported for this queue type");
        }
    }

    size_t size(std::string_view prefix) const
    {
        if constexpr (std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>)
        {
            return m_queue->size(prefix);
        }
        else
        {
            // static assert to avoid compilation
            static_assert(std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>,
                          "This method is not supported for this queue type");
        }
    }

    void postpone(std::string_view prefix, const std::chrono::seconds& time) noexcept
    {
        if constexpr (std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>)
        {
            m_queue->postpone(prefix, time);
        }
        else
        {
            // static assert to avoid compilation
            static_assert(std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>,
                          "This method is not supported for this queue type");
        }
    }

    uint64_t bulkSize() const
    {
        return m_bulkSize;
    }

    void bulkSize(const uint64_t bulkSize)
    {
        m_bulkSize = bulkSize;
    }

private:
    void dispatch()
    {
        std::string lastError;
        auto lastErrorLog = std::chrono::steady_clock::time_point {};

        while (m_running)
        {
            try
            {
                if constexpr (std::is_same_v<Utils::TSafeQueue<T, U, RocksDBQueue<T, U>>, TSafeQueueType>)
                {
                    std::queue<U> data = m_queue->getBulk(m_bulkSize);
                    const auto size = data.size();

                    if (!data.empty())
                    {
                        m_functor(data);
                        m_queue->popBulk(size);
                    }
                }
                else if constexpr (std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>)
                {
                    std::pair<U, std::string> data = m_queue->front();
                    if (!data.second.empty())
                    {
                        m_functor(data.first);
                        m_queue->pop(data.second);
                    }
                }
                else
                {
                    // static assert to avoid compilation
                    static_assert(
                        std::is_same_v<Utils::TSafeQueue<T, U, RocksDBQueue<T, U>>, TSafeQueueType> ||
                            std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>,
                        "This method is not supported for this queue type");
                }
            }
            catch (const std::exception& ex)
            {
                // Sleep for a second to avoid busy loop
                if (m_running)
                {
                    std::this_thread::sleep_for(std::chrono::seconds(1));

                    // The same batch is retried every second: log a new error at once and a persistent one once
                    // a minute.
                    const auto now = std::chrono::steady_clock::now();
                    if (lastError != ex.what() || now - lastErrorLog >= std::chrono::minutes(1))
                    {
                        logWarn(LOGGER_DEFAULT_TAG, "Dispatch handler error, %s", ex.what());
                        lastError = ex.what();
                        lastErrorLog = now;
                    }
                }
                else
                {
                    std::cout << "ThreadEventDispatcher dispatch end.\n";
                }
            }
        }
    }

    // Reports the first discard of an overflow through the injected callback (silent without one). The report is
    // re-armed once the queue is found empty, so a queue that hovers around its limit is reported once per overflow.
    void reportDiscard(const size_t queueSize, std::string_view prefix)
    {
        if (m_onDiscard && !m_discardReported.exchange(true))
        {
            m_onDiscard((prefix.empty() ? std::string {"Queue"} : "Queue '" + std::string {prefix} + "'") +
                        " is full (size: " + std::to_string(queueSize) + ", max: " + std::to_string(m_maxQueueSize) +
                        "). Starting to discard events.");
        }
    }

    void rearmDiscardReport(const size_t queueSize)
    {
        if (queueSize == 0)
        {
            m_discardReported = false;
        }
    }

    void joinThread()
    {
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    // Keep this order to avoid warnings during compilation
    Functor m_functor;
    const size_t m_maxQueueSize;
    std::atomic<uint64_t> m_bulkSize;
    std::function<void(const std::string&)> m_onDiscard;
    std::unique_ptr<TSafeQueueType> m_queue;
    std::thread m_thread;
    std::atomic_bool m_running = true;

    std::atomic_bool m_discardReported {false};
};

template<typename Type, typename Functor>
using ThreadEventDispatcher = TThreadEventDispatcher<Type, Type, Functor>;

#endif // _THREAD_EVENT_DISPATCHER_HPP
