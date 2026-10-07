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
                                    bool useSharedBuffers = false,
                                    std::function<void(const std::string&)> onDiscard = {})
        : m_functor {std::move(functor)}
        , m_name {dbPath}
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
        : m_name {dbPath}
        , m_maxQueueSize {maxQueueSize}
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
                    try
                    {
                        m_queue->push(value);
                    }
                    catch (const std::exception& ex)
                    {
                        reportPushError(ex);
                        return;
                    }
                    rearmDiscardReport(queueSize);
                    warnQueueSize(queueSize + 1);
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
                    try
                    {
                        m_queue->push(prefix, value);
                    }
                    catch (const std::exception& ex)
                    {
                        reportPushError(ex);
                        return;
                    }
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
        // Starts one interval back so that the first error is logged at once, even right after the system boots.
        auto lastErrorLog = std::chrono::steady_clock::now() - std::chrono::minutes(1);

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

                    // The same batch is retried every second: log the first error at once and at most one per minute
                    // after that, since the text of the error can change on every retry.
                    const auto now = std::chrono::steady_clock::now();
                    if (now - lastErrorLog >= std::chrono::minutes(1))
                    {
                        logWarn(LOGGER_DEFAULT_TAG,
                                "Queue '%s': dispatch handler error, %s",
                                m_name.c_str(),
                                ex.what());
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

    // A queue that keeps growing means its consumer is not draining it. It is reported at QUEUE_SIZE_WARNING elements
    // and every time it doubles the size it was reported at, and the report is re-armed once the queue falls under
    // half of the first threshold, so a queue that hovers around it is not reported on every cycle.
    void warnQueueSize(const size_t queueSize)
    {
        auto threshold = m_nextSizeWarning.load();
        if (queueSize >= threshold && m_nextSizeWarning.compare_exchange_strong(threshold, queueSize * 2))
        {
            logWarn(LOGGER_DEFAULT_TAG,
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
            logWarn(LOGGER_DEFAULT_TAG, "Queue '%s': element dropped, %s", m_name.c_str(), ex.what());
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
    const std::string m_name;
    const size_t m_maxQueueSize;
    std::atomic<uint64_t> m_bulkSize;
    std::function<void(const std::string&)> m_onDiscard;
    std::unique_ptr<TSafeQueueType> m_queue;
    std::thread m_thread;
    std::atomic_bool m_running = true;

    std::atomic_bool m_discardReported {false};
    std::atomic<size_t> m_nextSizeWarning {QUEUE_SIZE_WARNING};
    std::atomic<std::chrono::steady_clock::rep> m_lastPushErrorLog {0};
};

template<typename Type, typename Functor>
using ThreadEventDispatcher = TThreadEventDispatcher<Type, Type, Functor>;

#endif // _THREAD_EVENT_DISPATCHER_HPP
