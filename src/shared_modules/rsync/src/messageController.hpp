/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 5, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MESSAGECONTROLLER_HPP
#define _MESSAGECONTROLLER_HPP

#include <chrono>
#include <string>
#include <map>
#include <mutex>
#include <shared_mutex>
#include "singleton.hpp"


class MessageController final : public Singleton<MessageController>
{
    private:
        struct ComponentContext
        {
            std::chrono::steady_clock::time_point lastMsgTime;
            std::chrono::seconds intervalTime;
        };
        std::shared_timed_mutex m_mutex;
        std::map<std::string, ComponentContext> m_componentContexts;

    public:
        bool waitToStartSync(const std::string& messageHeaderId)
        {
            auto retVal { false };
            std::shared_lock<std::shared_timed_mutex> lock(m_mutex);
            const auto itCtx { m_componentContexts.find(messageHeaderId) };

            if (itCtx != m_componentContexts.end())
            {
                retVal = std::chrono::steady_clock::now() - itCtx->second.lastMsgTime <= itCtx->second.intervalTime;
            }
            return retVal;
        }

        void setComponentContext(const std::string& messageHeaderId,
                                 const std::chrono::seconds& intervalTime)
        {
            std::unique_lock<std::shared_timed_mutex> lock(m_mutex);

            if (intervalTime.count() > 0)
            {
                m_componentContexts[messageHeaderId] =
                {
                    std::chrono::time_point<std::chrono::steady_clock>(),
                    intervalTime
                };
            }
            else
            {
                m_componentContexts.erase(messageHeaderId);
            }
        }

        void refreshLastMsgTime(const std::string& messageHeaderId)
        {
            std::unique_lock<std::shared_timed_mutex> lock(m_mutex);
            const auto itCtx { m_componentContexts.find(messageHeaderId) };

            if (itCtx != m_componentContexts.end())
            {
                itCtx->second.lastMsgTime = std::chrono::steady_clock::now();
            }
        }

};

#endif // _MESSAGECONTROLLER_HPP
