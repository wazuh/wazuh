/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef THREAD_DISPATCHER_H
#define THREAD_DISPATCHER_H
#include "commonDefs.h"
#include "promiseFactory.h"
#include "threadSafeQueue.h"
#include <atomic>
#include <functional>
#include <future>
#include <iostream>
#include <thread>
#include <vector>

namespace Utils
{
    // *
    //  * @brief Minimal Dispatcher interface
    //  * @details Handle dispatching of messages of type Type
    //  * to be processed by calling Functor.
    //  *
    //  * @tparam Type Messages types.
    //  * @tparam Functor Entity that processes the messages.

    // template <typename Type, typename Functor>
    // class DispatcherInterface
    // {
    // public:
    //  /**
    //   * @brief Ctor
    //   *
    //   * @param functor Callable entity.
    //   * @param int Maximun number of threads to be used by the dispatcher.
    //   */
    //  DispatcherInterface(Functor functor, const unsigned int numberOfThreads);
    //  *
    //   * @brief Pushes a message to be processed by the functor.
    //   * @details The implementation decides whether the processing is sync or async.
    //   *
    //   * @param data Message value.

    //  void push(const Type& data);
    //  /**
    //   * @brief Rundowns the pending messages until reaches 0.
    //   * @details It should be a blocking call.
    //   */
    //  void rundown();
    //  /**
    //   * @brief Cancels the dispatching.
    //   */
    //  void cancel();
    // };

    template<typename Type, typename Functor>
    class AsyncDispatcher
    {
    public:
        AsyncDispatcher(Functor functor,
                        const unsigned int numberOfThreads = std::thread::hardware_concurrency(),
                        const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE)
            : m_functor {functor}
            , m_running {true}
            , m_numberOfThreads {numberOfThreads ? numberOfThreads : 1}
            , m_maxQueueSize {maxQueueSize}
        {
            m_threads.reserve(m_numberOfThreads);

            for (unsigned int i = 0; i < m_numberOfThreads; ++i)
            {
                m_threads.push_back(std::thread {&AsyncDispatcher<Type, Functor>::dispatch, this});
            }
        }
        AsyncDispatcher& operator=(const AsyncDispatcher&) = delete;
        AsyncDispatcher(AsyncDispatcher& other) = delete;
        ~AsyncDispatcher()
        {
            cancel();
        }

        void push(const Type& value)
        {
            if (m_running)
            {
                if (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue.size() < m_maxQueueSize)
                {
                    m_queue.push([value, this]() { this->m_functor(value); });
                }
            }
        }

        void rundown()
        {
            if (m_running)
            {
                auto promise {PromiseFactory<PROMISE_TYPE>::getPromiseObject()};
                m_queue.push([&promise]() { promise->set_value(); });
                promise->wait();
                cancel();
            }
        }
        void cancel()
        {
            m_running = false;
            m_queue.cancel();
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
            return m_queue.size();
        }

    private:
        void dispatch()
        {
            try
            {
                while (m_running)
                {
                    std::function<void()> fnc;

                    if (m_queue.pop(fnc))
                    {
                        fnc();
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
        SafeQueue<std::function<void()>> m_queue;
        std::vector<std::thread> m_threads;
        std::atomic_bool m_running;
        const unsigned int m_numberOfThreads;
        const size_t m_maxQueueSize;
    };

    template<typename Input, typename Functor>
    class SyncDispatcher
    {
    public:
        SyncDispatcher(Functor functor,
                       const unsigned int /*numberOfThreads = std::thread::hardware_concurrency()*/,
                       const size_t /*maxQueueSize = UNLIMITED_QUEUE_SIZE*/)
            : m_functor {functor}
            , m_running {true}
        {
        }

        SyncDispatcher(Functor functor)
            : m_functor {functor}
            , m_running {true}
        {
        }

        void push(const Input& data)
        {
            if (m_running)
            {
                m_functor(data);
            }
        }
        size_t size() const
        {
            return 0;
        }
        void rundown()
        {
            cancel();
        }
        void cancel()
        {
            m_running = false;
        }
        bool cancelled() const
        {
            return !m_running;
        }
        unsigned int numberOfThreads() const
        {
            return 0;
        }
        ~SyncDispatcher() = default;

    private:
        Functor m_functor;
        bool m_running;
    };
} // namespace Utils
#endif // THREAD_DISPATCHER_H
