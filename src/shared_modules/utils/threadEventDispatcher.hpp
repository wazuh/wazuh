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
#include <iostream>
#include <thread>

template<typename T,
         typename U,
         typename Functor,
         uint8_t TNumberOfThreads = 1,
         typename TQueueType = RocksDBQueue<T, U>,
         typename TSafeQueueType = Utils::TSafeQueue<T, U, RocksDBQueue<T, U>>>
class TThreadEventDispatcher
{
public:
    explicit TThreadEventDispatcher(Functor functor,
                                    const std::string& dbPath,
                                    const uint64_t bulkSize = 1,
                                    const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE)
        : m_functor {std::move(functor)}
        , m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
        , m_queue {std::make_unique<TSafeQueueType>(TQueueType(dbPath))}
    {
        m_threads.reserve(TNumberOfThreads);

        if constexpr (TNumberOfThreads == 1)
        {
            m_threads.push_back(std::thread {
                &TThreadEventDispatcher<T, U, Functor, TNumberOfThreads, TQueueType, TSafeQueueType>::dispatch, this});
        }
        else
        {
            static_assert(isSameType, "T and U are not the same type");
            for (unsigned int i = 0; i < TNumberOfThreads; ++i)
            {
                m_threads.push_back(std::thread {
                    &TThreadEventDispatcher<T, U, Functor, TNumberOfThreads, TQueueType, TSafeQueueType>::dispatch,
                    this});
            }
        }
    }

    explicit TThreadEventDispatcher(const std::string& dbPath,
                                    const uint64_t bulkSize = 1,
                                    const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE)
        : m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
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
        m_threads.reserve(TNumberOfThreads);

        if constexpr (TNumberOfThreads == 1)
        {
            m_threads.push_back(std::thread {
                &TThreadEventDispatcher<T, U, Functor, TNumberOfThreads, TQueueType, TSafeQueueType>::dispatch, this});
        }
        else
        {
            for (unsigned int i = 0; i < TNumberOfThreads; ++i)
            {
                m_threads.push_back(std::thread {
                    &TThreadEventDispatcher<T, U, Functor, TNumberOfThreads, TQueueType, TSafeQueueType>::dispatch,
                    this});
            }
        }
    }

    void push(const T& value)
    {
        if constexpr (!isTSafeMultiQueue)
        {
            if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue->size() < m_maxQueueSize))
            {
                m_queue->push(value);
            }
        }
        else
        {
            // static assert to avoid compilation
            static_assert(isTSafeMultiQueue, "This method is not supported for this queue type");
        }
    }

    void push(std::string_view prefix, const T& value)
    {
        if constexpr (isTSafeMultiQueue)
        {
            if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue->size(prefix) < m_maxQueueSize))
            {
                m_queue->push(prefix, value);
            }
        }
        else
        {
            // static assert to avoid compilation
            static_assert(isTSafeMultiQueue, "This method is not supported for this queue type");
        }
    }

    void clear(std::string_view prefix = "")
    {
        if constexpr (isTSafeMultiQueue)
        {
            m_queue->clear(prefix);
        }
        else
        {
            // static assert to avoid compilation
            static_assert(isTSafeMultiQueue, "This method is not supported for this queue type");
        }
    }

    void cancel()
    {
        m_running = false;
        m_queue->cancel();
        joinThreads();
    }

    bool cancelled() const
    {
        return !m_running;
    }

    size_t size() const
    {
        if constexpr (!isTSafeMultiQueue)
        {
            return m_queue->size();
        }
        else
        {
            static_assert(isTSafeMultiQueue, "This method is not supported for this queue type");
        }
    }

    size_t size(std::string_view prefix) const
    {
        if constexpr (isTSafeMultiQueue)
        {
            return m_queue->size(prefix);
        }
        else
        {
            // static assert to avoid compilation
            static_assert(isTSafeMultiQueue, "This method is not supported for this queue type");
        }
    }

    void postpone(std::string_view prefix, const std::chrono::seconds& time) noexcept
    {
        if constexpr (isTSafeMultiQueue)
        {
            m_queue->postpone(prefix, time);
        }
        else
        {
            // static assert to avoid compilation
            static_assert(isTSafeMultiQueue, "This method is not supported for this queue type");
        }
    }

private:
    /**
     * @brief Check if the queue type is a `TSafeMultiQueue`.
     *
     */
    static constexpr bool isTSafeMultiQueue =
        std::is_same_v<Utils::TSafeMultiQueue<T, U, RocksDBQueueCF<T, U>>, TSafeQueueType>;

    /**
     * @brief Check if the queue type is a `TSafeQueue`.
     *
     */
    static constexpr bool isTSafeQueue = std::is_same_v<Utils::TSafeQueue<T, U, RocksDBQueue<T, U>>, TSafeQueueType>;

    /**
     * @brief Check if the queue value are the same type. This is crucial for the `multiAndUnordered` method.
     *
     */
    static constexpr bool isSameType = std::is_same_v<T, U>;

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
            if constexpr (TNumberOfThreads == 1)
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
            if constexpr (isTSafeQueue)
            {
                std::queue<U> data = m_queue->getBulk(m_bulkSize);
                const auto size = data.size();

                if (!data.empty())
                {
                    m_functor(data);
                    m_queue->popBulk(size);
                }
            }
            else if constexpr (isTSafeMultiQueue)
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
                // static assert to avoid compilation for unsupported queue types
                static_assert(isTSafeQueue || isTSafeMultiQueue, "This method is not supported for this queue type");
            }
        }
        catch (const std::exception& ex)
        {
            // Log the error if an exception occurs
            std::cerr << "Dispatch handler error: " << ex.what() << "\n";
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
        static_assert(isSameType, "T and U are not the same type");
        std::queue<U> data; // Declare data outside the try block to ensure scope in catch block
        try
        {
            if constexpr (isTSafeQueue)
            {
                data = m_queue->getBulkAndPop(m_bulkSize);
                const auto size = data.size();

                if (!data.empty())
                {
                    m_functor(data);
                }
            }
            else if constexpr (isTSafeMultiQueue)
            {
                auto dataPair = m_queue->front();
                if (!dataPair.second.empty())
                {
                    m_functor(dataPair.first);
                    m_queue->pop(dataPair.second);
                }
            }
            else
            {
                // static assert to avoid compilation for unsupported queue types
                static_assert(isTSafeQueue || isTSafeMultiQueue, "This method is not supported for this queue type");
            }
        }
        catch (const std::exception& ex)
        {
            // Reinsert elements in the queue in case of exception on the functor.
            if constexpr (isTSafeQueue)
            {
                while (!data.empty())
                {
                    m_queue->push(data.front());
                    data.pop();
                }
                std::cerr << "Dispatch handler error. Elements reinserted: " << ex.what() << "\n";
            }
            else if constexpr (isTSafeMultiQueue)
            {
                while (!data.empty())
                {
                    m_queue->push(data.front());
                    data.pop();
                }
                std::cerr << "Dispatch handler error. Elements reinserted: " << ex.what() << "\n";
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
};

template<typename Type, typename Functor, uint8_t NumberOfThreads = 1>
using ThreadEventDispatcher = TThreadEventDispatcher<Type, Type, Functor, NumberOfThreads>;

#endif // _THREAD_EVENT_DISPATCHER_HPP
