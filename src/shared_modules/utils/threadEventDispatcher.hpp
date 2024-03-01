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

template<typename T, typename U, typename Functor>
class TThreadEventDispatcher
{
public:
    explicit TThreadEventDispatcher(Functor functor,
                                    const std::string& dbPath,
                                    const uint64_t bulkSize,
                                    const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE)
        : m_functor {std::move(functor)}
        , m_running {true}
        , m_maxQueueSize {maxQueueSize}
        , m_bulkSize {bulkSize}
    {
        m_queue = std::make_unique<Utils::TSafeQueue<T, U, RocksDBQueue<T, U>>>(RocksDBQueue<T, U>(dbPath));
        m_thread = std::thread {&TThreadEventDispatcher<T, U, Functor>::dispatch, this};
    }
    TThreadEventDispatcher& operator=(const TThreadEventDispatcher&) = delete;
    TThreadEventDispatcher(TThreadEventDispatcher& other) = delete;
    ~TThreadEventDispatcher()
    {
        cancel();
    }

    void push(const T& value)
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
        joinThread();
    }

    bool cancelled() const
    {
        return !m_running;
    }

    size_t size() const
    {
        return m_queue->size();
    }

private:
    void dispatch()
    {
        while (m_running)
        {
            try
            {
                std::queue<U> data = m_queue->getBulk(m_bulkSize);
                const auto size = data.size();

                if (!data.empty())
                {
                    m_functor(data);
                    m_queue->popBulk(size);
                }
            }
            catch (const std::exception& ex)
            {
                std::cerr << "Dispatch handler error, " << ex.what() << std::endl;
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

    Functor m_functor;
    std::unique_ptr<Utils::TSafeQueue<T, U, RocksDBQueue<T, U>>> m_queue;
    std::thread m_thread;
    std::atomic_bool m_running;

    const size_t m_maxQueueSize;
    const uint64_t m_bulkSize;
};

template<typename Type, typename Functor>
using ThreadEventDispatcher = TThreadEventDispatcher<Type, Type, Functor>;

#endif // _THREAD_EVENT_DISPATCHER_HPP
