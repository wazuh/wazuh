/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * October 2, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYNCHRONIZATION_CONTROLLER_HPP
#define _SYNCHRONIZATION_CONTROLLER_HPP

#include "commonDefs.h"
#include "loggerHelper.h"
#include "rsync_exception.h"
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <singleton.hpp>

namespace RSync
{
    class SynchronizationController final : public Singleton<SynchronizationController>
    {
        public:
            void start(const RSYNC_HANDLE key, const int32_t value)
            {
                std::lock_guard<std::mutex> lock{ m_mutex };
                m_data[key] = value;
            }

            void checkId(const RSYNC_HANDLE key, const int32_t value)
            {
                std::lock_guard<std::mutex> lock{ m_mutex };
                const auto it = m_data.find(key);
                if (it == m_data.end())
                {
                    throw rsync_error { HANDLE_NOT_FOUND };
                }
                else
                {
                    if (value < it->second)
                    {
                        it->second =  value;
                    }

                    if (value > it->second)
                    {
                        Log::debugVerbose << "Sync id: " << std::to_string(value) << " is not the current id: "
                            << std::to_string(it->second) << LogEndl;
                        throw std::runtime_error { "Sync id is not the current id" };
                    }
                }
            }
        private:
            std::unordered_map<RSYNC_HANDLE, int32_t> m_data;
            std::mutex m_mutex;
    };
} // namespace RSync
#endif // _SYNCHRONIZATION_CONTROLLER_HPP
