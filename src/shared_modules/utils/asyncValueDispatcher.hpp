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

#include <atomic>
#include <thread>
#include <type_traits>
#include <vector>

#include "commonDefs.h"
#include "functionTraits.hpp"
#include "loggerHelper.h"
#include "threadSafeQueue.h"

namespace Utils
{
    /**
     * @brief Asynchronously dispatches queued values to a callable using a fixed set of worker threads.
     *
     * The dispatcher owns a thread-safe queue and starts the worker threads during construction. Each worker waits for
     * values and invokes the supplied functor for every value successfully popped from the queue. If the functor's
     * first argument is an rvalue reference, the queued value is moved into the call; otherwise, it is passed as an
     * lvalue.
     *
     * @tparam Type Value type stored in the queue. It must be default-constructible because workers create a temporary
     *              value before popping from the queue.
     * @tparam Functor Callable type used to process values. It must be compatible with function_traits and callable
     * with either Type& or Type&& depending on its first argument type.
     *
     * @note The same functor instance may be called concurrently by several worker threads. Stateful functors must
     *       provide their own synchronization.
     * @note When a maximum queue size is configured, pushes beyond that size are silently discarded. The size check is
     *       best-effort because other producer or consumer threads can modify the queue concurrently.
     * @note Exceptions thrown by the functor are caught by the worker loop and logged at debug level.
     */
    template<typename Type, typename Functor>
    class AsyncValueDispatcher
    {
    public:
        /**
         * @brief Creates the dispatcher and starts the worker threads.
         *
         * @param functor Callable invoked for each queued value.
         * @param numberOfThreads Number of worker threads to start. If zero is provided, one worker thread is used.
         * @param maxQueueSize Maximum number of pending values accepted by the queue. Use UNLIMITED_QUEUE_SIZE for an
         *                     unbounded queue.
         */
        explicit AsyncValueDispatcher(Functor functor,
                                      std::string logTag,
                                      const unsigned int numberOfThreads = std::thread::hardware_concurrency(),
                                      const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE)
            : m_functor {functor}
            , m_numberOfThreads {numberOfThreads ? numberOfThreads : 1}
            , m_maxQueueSize {maxQueueSize}
            , m_logTag(std::move(logTag))
        {
            m_threads.reserve(m_numberOfThreads);

            for (unsigned int i = 0; i < m_numberOfThreads; ++i)
            {
                m_threads.push_back(std::thread {&AsyncValueDispatcher<Type, Functor>::dispatch, this});
            }
        }

        /**
         * @brief Deleted copy assignment operator.
         */
        AsyncValueDispatcher& operator=(const AsyncValueDispatcher&) = delete;

        /**
         * @brief Deleted copy constructor.
         */
        AsyncValueDispatcher(AsyncValueDispatcher& other) = delete;

        /**
         * @brief Stops the dispatcher and waits for all worker threads to finish.
         */
        ~AsyncValueDispatcher()
        {
            cancel();
        }

        /**
         * @brief Enqueues a value by move for asynchronous dispatch.
         *
         * @param value Value to enqueue.
         *
         * @note If the dispatcher is cancelled or the configured queue limit has been reached, the value is ignored.
         *
         * @return True when the value is accepted for dispatch, false otherwise.
         */
        bool push(Type&& value)
        {
            if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue.size() < m_maxQueueSize))
            {
                m_queue.push(std::move(value));
                return true;
            }
            return false;
        }

        /**
         * @brief Enqueues a value by copy for asynchronous dispatch.
         *
         * @param value Value to enqueue.
         *
         * @note If the dispatcher is cancelled or the configured queue limit has been reached, the value is ignored.
         *
         * @return True when the value is accepted for dispatch, false otherwise.
         */
        bool push(Type& value)
        {
            if (m_running && (UNLIMITED_QUEUE_SIZE == m_maxQueueSize || m_queue.size() < m_maxQueueSize))
            {
                m_queue.push(value);
                return true;
            }
            return false;
        }

        /**
         * @brief Cancels the dispatcher and joins all worker threads.
         *
         * Cancelling wakes any worker blocked on the queue. Values still pending in the queue are not drained after
         * cancellation.
         */
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

        /**
         * @brief Checks whether the dispatcher has been cancelled.
         *
         * @return True when no more values are accepted and worker threads are being stopped or have already stopped.
         */
        bool cancelled() const
        {
            return !m_running;
        }

        /**
         * @brief Gets the configured number of worker threads.
         *
         * @return Number of worker threads created by the dispatcher.
         */
        unsigned int numberOfThreads() const
        {
            return m_numberOfThreads;
        }

        /**
         * @brief Gets the current number of pending values in the queue.
         *
         * @return Queue size at the time of the call.
         */
        size_t size() const
        {
            return m_queue.size();
        }

    private:
        /**
         * @brief Worker loop that pops queued values and invokes the dispatch functor.
         */
        void dispatch()
        {
            while (m_running)
            {
                try
                {
                    if (Type value; m_queue.pop(value))
                    {
                        // Preserve the callable contract: move values only when the handler explicitly asks for an
                        // rvalue reference.
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
                    logDebug1(m_logTag.c_str(), "Dispatch handler error, %s", ex.what());
                }
            }
        }

        /// @brief Callable invoked by worker threads for every dispatched value.
        Functor m_functor;

        /// @brief Thread-safe queue used to hand values from producers to workers.
        SafeQueue<Type> m_queue;

        /// @brief Worker threads that consume values from the queue.
        std::vector<std::thread> m_threads;

        /// @brief Running flag used to stop producers and worker loops.
        std::atomic_bool m_running = true;

        /// @brief Number of worker threads created during construction.
        const unsigned int m_numberOfThreads;

        /// @brief Maximum accepted queue size, or UNLIMITED_QUEUE_SIZE for no limit.
        const size_t m_maxQueueSize;
        std::string m_logTag;
    };
} // namespace Utils
#endif // ASYNC_VALUE_DISPATCHER_HPP
