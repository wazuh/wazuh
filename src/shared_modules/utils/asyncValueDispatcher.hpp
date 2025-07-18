/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ASYNC_VALUE_DISPATCHER_HPP
#define ASYNC_VALUE_DISPATCHER_HPP

#include "commonDefs.h"
#include "functionTraits.hpp"
#include "threadSafeQueue.h"
#include <atomic>
#include <iostream>
#include <thread>
#include <type_traits>
#include <vector>

namespace Utils
{
    template<typename Type, typename Functor>
    class AsyncValueDispatcher
    {
    public:
        explicit AsyncValueDispatcher(Functor functor,
                                      const unsigned int numberOfThreads = std::thread::hardware_concurrency(),
                                      const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE)
            : m_functor {functor}
            , m_numberOfThreads {numberOfThreads ? numberOfThreads : 1}
            , m_maxQueueSize {maxQueueSize}
        {
            m_threads.reserve(m_numberOfThreads);

            for (unsigned int i = 0; i < m_numberOfThreads; ++i)
            {
                m_threads.push_back(std::thread {&AsyncValueDispatcher<Type, Functor>::dispatch, this});
            }
        }
        AsyncValueDispatcher& operator=(const AsyncValueDispatcher&) = delete;
        AsyncValueDispatcher(AsyncValueDispatcher& other) = delete;
        ~AsyncValueDispatcher()
        {
            cancel();
        }

        void push(Type&& value)
        {
            if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue.size() < m_maxQueueSize))
            {
                m_queue.push(std::move(value));
            }
        }
        void push(Type& value)
        {
            if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue.size() < m_maxQueueSize))
            {
                m_queue.push(value);
            }
        }

        void cancel()
        {
            m_running = false;
            m_queue.cancel();

            for (auto& thread : m_threads)
            {
                if (thread.joinable())
                {
                    thread.join();
                }
            }
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
            return m_queue.size();
        }

    private:
        void dispatch()
        {
            while (m_running)
            {
                try
                {

                    if (Type value; m_queue.pop(value))
                    {
                        if constexpr (std::is_rvalue_reference_v<
                                          typename function_traits<Functor>::template ArgType<0>>)
                        {
                            m_functor(std::move(value));
                        }
                        else
                        {
                            m_functor(value);
                        }
                    }
                }
                catch (const std::exception& ex)
                {
                    std::cerr << "Dispatch handler error, " << ex.what() << std::endl;
                }
            }
        }

        Functor m_functor;
        SafeQueue<Type> m_queue;
        std::vector<std::thread> m_threads;
        std::atomic_bool m_running = true;
        const unsigned int m_numberOfThreads;
        const size_t m_maxQueueSize;
    };
} // namespace Utils
#endif // ASYNC_VALUE_DISPATCHER_HPP
