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

#include <atomic>
#include <chrono>
#include <thread>

#include "commonDefs.h"
#include "loggerHelper.h"
#include "promiseFactory.h"
#include "rocksDBQueue.hpp"
#include "rocksDBQueueCF.hpp"
#include "threadSafeMultiQueue.hpp"
#include "threadSafeQueue.h"

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
                                    const size_t retryDelay = 1,
                                    const size_t flushInterval = 20,
                                    bool useSharedBuffers = false)
        : m_functor {std::move(functor)}
        , m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
        , m_retryDelay {retryDelay}
        , m_flushInterval {flushInterval}
        , m_queue {std::make_unique<TSafeQueueType>(TQueueType(dbPath, useSharedBuffers))}
    {
        m_thread = std::thread {&TThreadEventDispatcher<T, U, Functor, TQueueType, TSafeQueueType>::dispatch, this};
    }

    explicit TThreadEventDispatcher(const std::string& dbPath,
                                    const uint64_t bulkSize = 1,
                                    const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE,
                                    const size_t retryDelay = 1,
                                    const size_t flushInterval = 20)
        : m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
        , m_retryDelay {retryDelay}
        , m_flushInterval {flushInterval}
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
            if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue->size() < m_maxQueueSize))
            {
                m_queue->push(value);
                // If we were previously discarding, log that we're accepting again
                if (m_discardedCount.load() > 0)
                {
                    logInfo(LOGGER_DEFAULT_TAG,
                            "Queue size normalized. Resuming event acceptance after %zu discarded events.",
                            m_discardedCount.load());
                    m_discardedCount = 0;
                    m_firstDiscardLogged = false;
                }
            }
            else if (m_running)
            {
                // Increment discard counter
                const auto discarded = ++m_discardedCount;
                const auto now = std::chrono::steady_clock::now();

                // Log the first discard immediately
                if (!m_firstDiscardLogged.exchange(true))
                {
                    logWarn(LOGGER_DEFAULT_TAG,
                            "Queue is full (size: %zu, max: %zu). Starting to discard events. "
                            "Periodic summaries will be logged every %zu seconds.",
                            m_queue->size(),
                            m_maxQueueSize,
                            m_summaryInterval);
                    m_lastSummaryLog = now;
                }
                // Log periodic summary
                else
                {
                    const auto elapsed =
                        std::chrono::duration_cast<std::chrono::seconds>(now - m_lastSummaryLog).count();
                    if (elapsed >= m_summaryInterval)
                    {
                        logWarn(LOGGER_DEFAULT_TAG,
                                "Queue overflow continues: %zu events discarded in the last %lld seconds "
                                "(queue size: %zu, max: %zu, total discarded: %zu).",
                                discarded - m_lastDiscardedCount.load(),
                                elapsed,
                                m_queue->size(),
                                m_maxQueueSize,
                                discarded);
                        m_lastSummaryLog = now;
                        m_lastDiscardedCount = discarded;
                    }
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
            if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue->size(prefix) < m_maxQueueSize))
            {
                m_queue->push(prefix, value);
                // If we were previously discarding, log that we're accepting again
                if (m_discardedCount.load() > 0)
                {
                    logInfo(LOGGER_DEFAULT_TAG,
                            "Queue '%.*s' size normalized. Resuming event acceptance after %zu discarded events.",
                            static_cast<int>(prefix.size()),
                            prefix.data(),
                            m_discardedCount.load());
                    m_discardedCount = 0;
                    m_firstDiscardLogged = false;
                }
            }
            else if (m_running)
            {
                // Increment discard counter
                const auto discarded = ++m_discardedCount;
                const auto now = std::chrono::steady_clock::now();

                // Log the first discard immediately
                if (!m_firstDiscardLogged.exchange(true))
                {
                    logWarn(LOGGER_DEFAULT_TAG,
                            "Queue '%.*s' is full (size: %zu, max: %zu). Starting to discard events. "
                            "Periodic summaries will be logged every %zu seconds.",
                            static_cast<int>(prefix.size()),
                            prefix.data(),
                            m_queue->size(prefix),
                            m_maxQueueSize,
                            m_summaryInterval);
                    m_lastSummaryLog = now;
                }
                // Log periodic summary
                else
                {
                    const auto elapsed =
                        std::chrono::duration_cast<std::chrono::seconds>(now - m_lastSummaryLog).count();
                    if (elapsed >= m_summaryInterval)
                    {
                        logWarn(LOGGER_DEFAULT_TAG,
                                "Queue '%.*s' overflow continues: %zu events discarded in the last %lld seconds "
                                "(queue size: %zu, max: %zu, total discarded: %zu).",
                                static_cast<int>(prefix.size()),
                                prefix.data(),
                                discarded - m_lastDiscardedCount.load(),
                                elapsed,
                                m_queue->size(prefix),
                                m_maxQueueSize,
                                discarded);
                        m_lastSummaryLog = now;
                        m_lastDiscardedCount = discarded;
                    }
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
        while (m_running)
        {
            try
            {
                if constexpr (std::is_same_v<Utils::TSafeQueue<T, U, RocksDBQueue<T, U>>, TSafeQueueType>)
                {
                    std::queue<U> data = m_queue->getBulk(m_bulkSize, std::chrono::seconds(m_flushInterval));
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
                    std::this_thread::sleep_for(std::chrono::seconds(m_retryDelay));
                    logWarn(LOGGER_DEFAULT_TAG, "Dispatch handler error, %s", ex.what());
                }
                else
                {
                    logDebug1(LOGGER_DEFAULT_TAG, "ThreadEventDispatcher dispatch end.");
                }
            }
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
    std::unique_ptr<TSafeQueueType> m_queue;
    std::thread m_thread;
    std::atomic_bool m_running = true;
    const size_t m_retryDelay;
    const size_t m_flushInterval;

    // Rate limiting for discard warnings
    std::atomic<size_t> m_discardedCount {0};
    std::atomic<size_t> m_lastDiscardedCount {0};
    std::atomic_bool m_firstDiscardLogged {false};
    std::chrono::steady_clock::time_point m_lastSummaryLog;
    const size_t m_summaryInterval {30}; // Log summary every 30 seconds
};

template<typename Type, typename Functor>
using ThreadEventDispatcher = TThreadEventDispatcher<Type, Type, Functor>;

#endif // _THREAD_EVENT_DISPATCHER_HPP
