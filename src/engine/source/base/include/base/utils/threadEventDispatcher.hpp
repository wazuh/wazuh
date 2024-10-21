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
#include <iostream>
#include <thread>

#include <base/logging.hpp>

#include "rocksDBQueue.hpp"
#include "threadSafeQueue.hpp"

constexpr auto UNLIMITED_QUEUE_SIZE = 0;
static const unsigned int SINGLE_THREAD = 1;
static const unsigned int MULTI_THREAD = std::thread::hardware_concurrency() > 1 ? std::thread::hardware_concurrency()
                                                                                 : 1;

enum class ThreadEventDispatcherType
{
    SINGLE_THREADED_ORDERED,
    MULTI_THREADED_UNORDERED
};

struct ThreadEventDispatcherParams
{
    const std::string& dbPath;
    const uint64_t bulkSize = 1;
    const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE;
    const ThreadEventDispatcherType dispatcherType = ThreadEventDispatcherType::SINGLE_THREADED_ORDERED;
};

/**
 * @brief Class in charge to dispatch events in a queue to be processed by a functor.
 *
 * @note The Functor function implemented by a caller method will be in charge of processing the events. In case of an
 * exception, all events that remain will be re-inserted into the queue, therefore, the Functor is responsible for
 * handling the exceptions and dropping the events if necessary.
 * and decide if any event throwing an exception should be reinserted to be processed later or discarded.
 *
 */
template<typename T,
         typename U,
         typename Functor,
         typename TQueueType = RocksDBQueue<T, U>,
         typename TSafeQueueType = base::utils::queue::TSafeQueue<T, U, RocksDBQueue<T, U>>>
class TThreadEventDispatcher
{
public:
    explicit TThreadEventDispatcher(Functor functor, const ThreadEventDispatcherParams& threadEventDispatcherParams)
        : m_functor {std::move(functor)}
        , m_maxQueueSize {threadEventDispatcherParams.maxQueueSize}
        , m_bulkSize {threadEventDispatcherParams.bulkSize}
        , m_queue {std::make_unique<TSafeQueueType>(TQueueType(threadEventDispatcherParams.dbPath))}
        , m_dispatcherType {threadEventDispatcherParams.dispatcherType}
    {
        const auto threadsAmount =
            m_dispatcherType == ThreadEventDispatcherType::MULTI_THREADED_UNORDERED ? MULTI_THREAD : SINGLE_THREAD;

        for (unsigned int i = 0; i < threadsAmount; ++i)
        {
            m_threads.push_back(
                std::thread {&TThreadEventDispatcher<T, U, Functor, TQueueType, TSafeQueueType>::dispatch, this});
        }
    }

    explicit TThreadEventDispatcher(const ThreadEventDispatcherParams& threadEventDispatcherParams)
        : m_maxQueueSize {threadEventDispatcherParams.maxQueueSize}
        , m_bulkSize {threadEventDispatcherParams.bulkSize}
        , m_queue {std::make_unique<TSafeQueueType>(TQueueType(threadEventDispatcherParams.dbPath))}
        , m_dispatcherType {threadEventDispatcherParams.dispatcherType}
    {
    }

    TThreadEventDispatcher& operator=(const TThreadEventDispatcher&) = delete;
    TThreadEventDispatcher(TThreadEventDispatcher& other) = delete;
    ~TThreadEventDispatcher() { cancel(); }

    void startWorker(Functor functor)
    {
        const auto threadsAmount =
            m_dispatcherType == ThreadEventDispatcherType::MULTI_THREADED_UNORDERED ? MULTI_THREAD : SINGLE_THREAD;

        m_functor = std::move(functor);
        m_threads.reserve(threadsAmount);

        for (unsigned int i = 0; i < threadsAmount; ++i)
        {
            m_threads.push_back(
                std::thread {&TThreadEventDispatcher<T, U, Functor, TQueueType, TSafeQueueType>::dispatch, this});
        }
    }

    void push(const T& value)
    {
        if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue->size() < m_maxQueueSize))
        {
            m_queue->push(value);
        }
    }

    void push(std::string_view prefix, const T& value)
    {
        if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue->size(prefix) < m_maxQueueSize))
        {
            m_queue->push(prefix, value);
        }
    }

    void clear(std::string_view prefix = "") { m_queue->clear(prefix); }

    void cancel()
    {
        m_running = false;
        m_queue->cancel();
        joinThreads();
    }

    bool cancelled() const { return !m_running; }

    size_t size() const { return m_queue->size(); }

    size_t size(std::string_view prefix) const { return m_queue->size(prefix); }

    void postpone(std::string_view prefix, const std::chrono::seconds& time) noexcept
    {
        m_queue->postpone(prefix, time);
    }

private:
    /**
     * @brief Check if the queue type is a `TSafeQueue`.
     *
     */
    static constexpr bool m_isTSafeQueue =
        std::is_same_v<base::utils::queue::TSafeQueue<T, U, RocksDBQueue<T, U>>, TSafeQueueType>;

    /**
     * @brief Dispatch function to handle queue processing based on the number of threads.
     *
     * This function enters a loop that runs while the dispatcher is active. Depending on the number of threads,
     * it either processes the queue in a single-threaded, ordered manner or in a multi-threaded, unordered manner.
     *
     * - In the single-threaded case, it uses the `singleAndOrdered` method.
     * - In the multi-threaded case, it uses the `multiAndUnordered` method.
     */
    void dispatch()
    {
        // Loop while the dispatcher is running
        while (m_running)
        {
            // If only one thread is used, process the queue in a single-threaded, ordered manner
            if (m_dispatcherType == ThreadEventDispatcherType::SINGLE_THREADED_ORDERED)
            {
                singleAndOrdered();
            }
            // If multiple threads are used, process the queue in a multi-threaded, unordered manner
            else
            {
                multiAndUnordered();
            }
        }
    }

    /**
     * @brief Processes the queue in a single-threaded, ordered manner.
     *
     * This function checks the type of the queue and processes it accordingly. It supports `RocksDBQueue` and
     * `RocksDBQueueCF` queue types. In case of an exception, it logs the error.
     */
    void singleAndOrdered()
    {
        try
        {
            if constexpr (m_isTSafeQueue)
            {
                std::queue<U> data = m_queue->getBulk(m_bulkSize);
                const auto size = data.size();

                if (!data.empty())
                {
                    m_functor(data);
                    m_queue->popBulk(size);
                }
            }
            else
            {
                // static assert to avoid compilation for unsupported queue types
                static_assert(m_isTSafeQueue, "This method is not supported for this queue type");
            }
        }
        catch (const std::exception& ex)
        {
            // Log the error if an exception occurs
            LOG_ERROR("Dispatch handler error: {}", ex.what());
        }
    }

    /**
     * @brief Processes the queue in a multi-threaded, unordered manner.
     *
     * This function handles queue elements based on the type of queue. It supports `RocksDBQueue` and `RocksDBQueueCF`
     * queue types. In case of an exception, it catches the exception and re-inserts the elements back into the queue.
     */
    void multiAndUnordered()
    {
        // Declare data outside the try block to ensure scope in catch block
        std::queue<U> data;
        std::pair<U, std::string> dataPair;
        try
        {
            if constexpr (m_isTSafeQueue)
            {
                data = m_queue->getBulkAndPop(m_bulkSize);

                if (!data.empty())
                {
                    m_functor(data);
                }
            }
            else
            {
                // static assert to avoid compilation for unsupported queue types
                static_assert(m_isTSafeQueue, "This method is not supported for this queue type");
            }
        }
        catch (const std::exception& /*ex*/)
        {
            // Re-insert remaining elements in the queue in case the functor throws an exception.
            while (!data.empty())
            {
                m_queue->push(data.front());
                data.pop();
            }
        }
    }

    void joinThreads()
    {
        for (auto& thread : m_threads)
        {
            if (thread.joinable())
            {
                thread.join();
            }
        }
    }

    Functor m_functor;
    std::unique_ptr<TSafeQueueType> m_queue;
    std::vector<std::thread> m_threads;
    std::atomic_bool m_running = true;

    const size_t m_maxQueueSize;
    const uint64_t m_bulkSize;
    const ThreadEventDispatcherType m_dispatcherType;
};

template<typename Type, typename Functor>
using ThreadEventDispatcher = TThreadEventDispatcher<Type, Type, Functor>;

#endif // _THREAD_EVENT_DISPATCHER_HPP
