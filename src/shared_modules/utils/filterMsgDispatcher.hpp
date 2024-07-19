/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * August 28, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _FILTER_MESSAGE_DISPATCHER_HPP_
#define _FILTER_MESSAGE_DISPATCHER_HPP_

#include "commonDefs.h"
#include "threadDispatcher.h"
#include <functional>
#include <map>
#include <shared_mutex>
#include <utility>

namespace Utils
{
    template<typename RawValue, template<class, class> class ThreadDispatcher = AsyncDispatcher>
    class FilterMsgDispatcher final : public ThreadDispatcher<RawValue, std::function<void(const RawValue&)>>
    {
    public:
        /**
         * @brief Constructor.
         * @param callback Callback function to be called when a message is dispatched.
         * @param filterCallback Callback function to be called to filter the message.
         * @param threadPoolSize Number of threads in the thread pool.
         * @param maxQueueSize Maximum size of the queue.
         * @note The filter callback function must return true if the message must be dispatched.
         */
        explicit FilterMsgDispatcher(const std::function<void(RawValue)>& callback,
                                     const std::function<bool(RawValue)>& filterCallback = nullptr,
                                     const unsigned int threadPoolSize = std::thread::hardware_concurrency(),
                                     const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE)
            : ThreadType {std::bind(&DispatcherType::dispatch, this, std::placeholders::_1),
                          threadPoolSize,
                          maxQueueSize}
            , m_callback {callback}
            , m_filterCallback {filterCallback}
        {
            if (!m_callback)
            {
                throw std::invalid_argument {"Callback function must be provided."};
            }
        }
        // LCOV_EXCL_START
        ~FilterMsgDispatcher() = default;
        // LCOV_EXCL_STOP

        /**
         * @brief Dispatches a message to the callback function, if the filter callback returns true or if filter
         * callback is not defined.
         * @param value Message to be dispatched.
         */
        void dispatch(const RawValue& value)
        {
            if (!m_filterCallback || m_filterCallback(value))
            {
                m_callback(value);
            }
        }

    private:
        using ThreadType = ThreadDispatcher<RawValue, std::function<void(const RawValue&)>>;
        using DispatcherType = FilterMsgDispatcher<RawValue, ThreadDispatcher>;

        std::function<void(RawValue)> m_callback;
        std::function<bool(RawValue)> m_filterCallback;
    };
}; // namespace Utils

#endif // _FILTER_MESSAGE_DISPATCHER_HPP_
