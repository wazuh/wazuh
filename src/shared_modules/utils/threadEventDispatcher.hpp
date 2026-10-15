/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * June 6, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
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

// Number of queued elements from which a queue is reported as growing.
constexpr size_t QUEUE_SIZE_WARNING {100000};

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
        , m_name {dbPath}
        , m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
        , m_retryDelay {retryDelay}
        , m_flushInterval {flushInterval}
        , m_logFn {makeLibLogFn("thread-dispatcher")}
        , m_queue {std::make_unique<TSafeQueueType>(TQueueType(dbPath, useSharedBuffers))}
    {
        m_thread = std::thread {&TThreadEventDispatcher<T, U, Functor, TQueueType, TSafeQueueType>::dispatch, this};
    }

    explicit TThreadEventDispatcher(const std::string& dbPath,
                                    const uint64_t bulkSize = 1,
                                    const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE,
                                    const size_t retryDelay = 1,
                                    const size_t flushInterval = 20)
        : m_name {dbPath}
        , m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
        , m_retryDelay {retryDelay}
        , m_flushInterval {flushInterval}
        , m_logFn {makeLibLogFn("thread-dispatcher")}
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
            const auto queueSize = m_queue->size();
            if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || queueSize < m_maxQueueSize))
            {
                try
                {
                    m_queue->push(value);
                }
                catch (const std::exception& ex)
                {
                    reportPushError(ex);
                    return;
                }
                warnQueueSize(queueSize + 1);

                // If we were previously discarding, log that we're accepting again
                if (m_discardedCount.load() > 0)
                {
                    LOGFN_INFO(m_logFn,
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
                ++m_totalDiscardedCount;
                const auto now = std::chrono::steady_clock::now();

                // Log the first discard immediately
                if (!m_firstDiscardLogged.exchange(true))
                {
                    LOGFN_WARN(m_logFn,
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
                        LOGFN_WARN(m_logFn,
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
                try
                {
                    m_queue->push(prefix, value);
                }
                catch (const std::exception& ex)
                {
                    reportPushError(ex);
                    return;
                }

                // If we were previously discarding, log that we're accepting again
                if (m_discardedCount.load() > 0)
                {
                    LOGFN_INFO(m_logFn,
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
                ++m_totalDiscardedCount;
                const auto now = std::chrono::steady_clock::now();

                // Log the first discard immediately
                if (!m_firstDiscardLogged.exchange(true))
                {
                    LOGFN_WARN(m_logFn,
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
                        LOGFN_WARN(m_logFn,
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

    uint64_t getDroppedEvents() const
    {
        return m_totalDiscardedCount.load();
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
        // Starts one interval back so that the first error is logged at once, even right after the system boots.
        auto lastErrorLog = std::chrono::steady_clock::now() - std::chrono::minutes(1);

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

                    // The same batch is retried after every delay: log the first error at once and at most one per
                    // minute after that, since the text of the error can change on every retry.
                    const auto now = std::chrono::steady_clock::now();
                    if (now - lastErrorLog >= std::chrono::minutes(1))
                    {
                        LOGFN_WARN(m_logFn, "Queue '%s': dispatch handler error, %s", m_name.c_str(), ex.what());
                        lastErrorLog = now;
                    }
                }
                else
                {
                    LOGFN_DEBUG1(m_logFn, "ThreadEventDispatcher dispatch end.");
                }
            }
        }
    }

    // A queue that keeps growing means its consumer is not draining it. It is reported at QUEUE_SIZE_WARNING elements
    // and every time it doubles the size it was reported at, and the report is re-armed once the queue falls under
    // half of the first threshold, so a queue that hovers around it is not reported on every cycle.
    void warnQueueSize(const size_t queueSize)
    {
        auto threshold = m_nextSizeWarning.load();
        if (queueSize >= threshold && m_nextSizeWarning.compare_exchange_strong(threshold, queueSize * 2))
        {
            LOGFN_WARN(m_logFn,
                       "Queue '%s' holds %llu elements and keeps growing. Check that its consumer is draining it.",
                       m_name.c_str(),
                       static_cast<unsigned long long>(queueSize));
        }
        else if (queueSize < QUEUE_SIZE_WARNING / 2)
        {
            m_nextSizeWarning = QUEUE_SIZE_WARNING;
        }
    }

    // A push that fails drops its element, so that the callers, which do not expect an exception, keep working. The
    // failure is reported at most once a minute.
    void reportPushError(const std::exception& ex)
    {
        constexpr auto INTERVAL = std::chrono::steady_clock::duration(std::chrono::minutes(1)).count();
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        auto last = m_lastPushErrorLog.load();
        if ((last == 0 || now - last >= INTERVAL) && m_lastPushErrorLog.compare_exchange_strong(last, now))
        {
            LOGFN_WARN(m_logFn, "Queue '%s': element dropped, %s", m_name.c_str(), ex.what());
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
    const std::string m_name;
    const size_t m_maxQueueSize;
    std::atomic<uint64_t> m_bulkSize;
    const size_t m_retryDelay;
    const size_t m_flushInterval;
    LogFn m_logFn;
    std::unique_ptr<TSafeQueueType> m_queue;
    std::thread m_thread;
    std::atomic_bool m_running = true;

    std::atomic<size_t> m_discardedCount {0}; // Number of events discarded since the last time the queue was normalized
                                              // (reset to 0 when queue resumes accepting events)
    std::atomic<size_t> m_lastDiscardedCount {
        0}; // Number of events discarded at the time of the last periodic summary log (used for interval reporting)
    std::atomic<size_t> m_totalDiscardedCount {0}; // Global accumulator
    std::atomic_bool m_firstDiscardLogged {false};
    std::chrono::steady_clock::time_point m_lastSummaryLog;
    const size_t m_summaryInterval {30}; // Log summary every 30 seconds
    std::atomic<size_t> m_nextSizeWarning {QUEUE_SIZE_WARNING};
    std::atomic<std::chrono::steady_clock::rep> m_lastPushErrorLog {0};
};

template<typename Type, typename Functor>
using ThreadEventDispatcher = TThreadEventDispatcher<Type, Type, Functor>;

#endif // _THREAD_EVENT_DISPATCHER_HPP
