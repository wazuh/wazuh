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
         typename TQueueType = RocksDBQueue<T, U>,
         typename TSafeQueueType = Utils::TSafeQueue<T, U, RocksDBQueue<T, U>>>
class TThreadEventDispatcher
{
public:
    explicit TThreadEventDispatcher(Functor functor,
                                    const std::string& dbPath,
                                    const uint64_t bulkSize = 1,
                                    const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE,
                                    const uint8_t numberOfThreads = 1)
        : m_functor {std::move(functor)}
        , m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
        , m_queue {std::make_unique<TSafeQueueType>(TQueueType(dbPath))}
        , m_numberOfThreads {numberOfThreads}
    {
        if (m_numberOfThreads <= 0)
        {
            throw std::invalid_argument("Number of threads must be greater than 0.");
        }

        m_threads.reserve(m_numberOfThreads);

        for (unsigned int i = 0; i < m_numberOfThreads; ++i)
        {
            m_threads.push_back(
                std::thread {&TThreadEventDispatcher<T, U, Functor, TQueueType, TSafeQueueType>::dispatch, this});
        }
    }

    explicit TThreadEventDispatcher(const std::string& dbPath,
                                    const uint64_t bulkSize = 1,
                                    const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE,
                                    const uint8_t numberOfThreads = 1)
        : m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
        , m_queue {std::make_unique<TSafeQueueType>(TQueueType(dbPath))}
        , m_numberOfThreads {numberOfThreads}
    {
        if (m_numberOfThreads <= 0)
        {
            throw std::invalid_argument("Number of threads must be greater than 0.");
        }
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
        m_threads.reserve(m_numberOfThreads);

        for (unsigned int i = 0; i < m_numberOfThreads; ++i)
        {
            m_threads.push_back(
                std::thread {&TThreadEventDispatcher<T, U, Functor, TQueueType, TSafeQueueType>::dispatch, this});
        }
    }

    void push(const T& value)
    {
        // static assert to avoid compilation
        static_assert(!isTSafeMultiQueue, "This method is not supported for this queue type");

        if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue->size() < m_maxQueueSize))
        {
            m_queue->push(value);
        }
    }

    void push(std::string_view prefix, const T& value)
    {
        // static assert to avoid compilation
        static_assert(isTSafeMultiQueue, "This method is not supported for this queue type");

        if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue->size(prefix) < m_maxQueueSize))
        {
            m_queue->push(prefix, value);
        }
    }

    void clear(std::string_view prefix = "")
    {
        // static assert to avoid compilation
        static_assert(isTSafeMultiQueue, "This method is not supported for this queue type");

        m_queue->clear(prefix);
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
        // static assert to avoid compilation
        static_assert(!isTSafeMultiQueue, "This method is not supported for this queue type");

        return m_queue->size();
    }

    size_t size(std::string_view prefix) const
    {
        // static assert to avoid compilation
        static_assert(isTSafeMultiQueue, "This method is not supported for this queue type");

        return m_queue->size(prefix);
    }

    void postpone(std::string_view prefix, const std::chrono::seconds& time) noexcept
    {
        // static assert to avoid compilation
        static_assert(isTSafeMultiQueue, "This method is not supported for this queue type");

        m_queue->postpone(prefix, time);
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
            if (m_numberOfThreads == 1)
            {
                singleAndOrdered();
            }
            // If multiple threads are used, process the queue in a multi-threaded, unordered manner
            else if (m_numberOfThreads > 1)
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
        // Declare data outside the try block to ensure scope in catch block
        std::queue<U> data;
        std::pair<U, std::string> dataPair;
        try
        {
            if constexpr (isTSafeQueue)
            {
                data = m_queue->getBulkAndPop(m_bulkSize);

                if (!data.empty())
                {
                    m_functor(data);
                }
            }
            else if constexpr (isTSafeMultiQueue)
            {
                dataPair = m_queue->getAndPop();
                if (!dataPair.second.empty())
                {
                    m_functor(dataPair.first);
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
                if (!dataPair.second.empty())
                {
                    m_queue->push(dataPair.second, dataPair.first);
                }
                std::cerr << "Dispatch handler error. Element reinserted: " << ex.what() << "\n";
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
    const uint8_t m_numberOfThreads;
};

template<typename Type, typename Functor>
using ThreadEventDispatcher = TThreadEventDispatcher<Type, Type, Functor>;

#endif // _THREAD_EVENT_DISPATCHER_HPP
