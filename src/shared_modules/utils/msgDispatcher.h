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
#ifndef _MESSAGE_DISPATCHER_H_
#define _MESSAGE_DISPATCHER_H_

#include <map>
#include <mutex>
#include <functional>
#include <utility>
#include "commonDefs.h"
#include "threadDispatcher.h"

namespace Utils
{

    template
    <
        typename Key,
        typename Value,
        typename RawValue,
        typename RawValueDecoder,
        template <class, class> class ThreadDispatcher = AsyncDispatcher
        >
    class MsgDispatcher final : public ThreadDispatcher<RawValue, std::function<void(const RawValue&)>>
        , public RawValueDecoder
    {
        public:
            explicit MsgDispatcher(const unsigned int threadPoolSize = std::thread::hardware_concurrency(),
                          const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE)
                : ThreadType
            {
                std::bind(&DispatcherType::dispatch, this, std::placeholders::_1),
                threadPoolSize,
                maxQueueSize
            }
            {
            }
            // LCOV_EXCL_START
            ~MsgDispatcher() = default;
            // LCOV_EXCL_STOP
            bool addCallback(const Key& key, const std::function<void(Value)>& callback)
            {
                std::lock_guard<std::mutex> lock{ m_mutex };
                const auto ret{ m_callbacks.find(key) == m_callbacks.end() };

                if (ret)
                {
                    m_callbacks[key] = callback;
                }

                return ret;
            }
            void removeCallback(const Key& key)
            {
                std::lock_guard<std::mutex> lock{ m_mutex };
                const auto it{ m_callbacks.find(key) };

                if (it != m_callbacks.end())
                {
                    m_callbacks.erase(it);
                }
            }
            void dispatch(const RawValue& raw)
            {
                const auto& data{ RawValueDecoder::decode(raw) };
                const auto& callback{ findCallback(data.first) };

                if (callback)
                {
                    callback(data.second);
                }
            }
        private:
            using ThreadType = ThreadDispatcher<RawValue, std::function<void(const RawValue&)>>;
            using DispatcherType = MsgDispatcher<Key, Value, RawValue, RawValueDecoder, ThreadDispatcher>;

            std::function<void(Value)> findCallback(const Key& key)
            {
                std::function<void(Value)> ret;
                std::lock_guard<std::mutex> lock{ m_mutex };
                const auto it { m_callbacks.find(key) };

                if (it != m_callbacks.end())
                {
                    return it->second;
                }

                return {};
            }
            std::map<Key, std::function<void(Value)>> m_callbacks;
            std::mutex                                m_mutex;
    };
}

#endif //_MESSAGE_DISPATCHER_H_
