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
#include "threadSafeQueue.h"
#include <atomic>
#include <functional>
#include <iostream>
#include <thread>

#define ELEMENTS_PER_BULK 50

template<typename Type, typename Functor>
class ThreadEventDispatcher
{
public:
    explicit ThreadEventDispatcher(Functor functor,
                                   const std::string& dbPath,
                                   const uint64_t bulkSize = ELEMENTS_PER_BULK,
                                   const unsigned int numberOfThreads = std::thread::hardware_concurrency(),
                                   const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE)
        : m_functor {functor}
        , m_running {true}
        , m_numberOfThreads {numberOfThreads ? numberOfThreads : 1}
        , m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
    {
        m_queue = std::make_unique<Utils::SafeQueue<Type, RocksDBQueue<Type>>>(RocksDBQueue<Type>(dbPath));
        m_threads.reserve(m_numberOfThreads);

        for (unsigned int i = 0; i < m_numberOfThreads; ++i)
        {
            m_threads.push_back(std::thread {&ThreadEventDispatcher<Type, Functor>::dispatch, this});
        }
    }
    ThreadEventDispatcher& operator=(const ThreadEventDispatcher&) = delete;
    ThreadEventDispatcher(ThreadEventDispatcher& other) = delete;
    ~ThreadEventDispatcher()
    {
        cancel();
    }

    void push(const Type& value)
    {
        if (m_running)
        {
            if (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue->size() < m_maxQueueSize)
            {
                m_queue->push(value);
            }
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

    unsigned int numberOfThreads() const
    {
        return m_numberOfThreads;
    }

    size_t size() const
    {
        return m_queue->size();
    }

private:
    void dispatch()
    {
        try
        {
            while (m_running)
            {
                std::queue<Type> data = m_queue->popBulk(ELEMENTS_PER_BULK);
                if (!data.empty())
                {
                    m_functor(data);
                }
            }
        }
        catch (const std::exception& ex)
        {
            std::cerr << "Dispatch handler error, " << ex.what() << std::endl;
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
    std::unique_ptr<Utils::SafeQueue<Type, RocksDBQueue<Type>>> m_queue;
    std::vector<std::thread> m_threads;
    std::atomic_bool m_running;
    const unsigned int m_numberOfThreads;
    const size_t m_maxQueueSize;
    const uint64_t m_bulkSize;
};

#endif // _THREAD_EVENT_DISPATCHER_HPP
