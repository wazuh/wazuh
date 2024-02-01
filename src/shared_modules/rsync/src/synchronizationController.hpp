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
#include "rsync.hpp"

namespace RSync
{
    class SynchronizationController final
    {
        public:
            void start(const RSYNC_HANDLE key, const std::string& table, const int32_t value)
            {
                std::lock_guard<std::mutex> lock{ m_mutex };
                m_data[key][table] = value;
            }

            void stop(const RSYNC_HANDLE key)
            {
                std::lock_guard<std::mutex> lock{ m_mutex };

                if (m_data.find(key) != m_data.end())
                {
                    m_data.erase(key);
                }
            }

            void clear()
            {
                std::lock_guard<std::mutex> lock{ m_mutex };
                m_data.clear();
            }

            void checkId(const RSYNC_HANDLE key, const std::string& table, const int32_t value)
            {
                std::lock_guard<std::mutex> lock{ m_mutex };
                const auto it = m_data.find(key);

                if (it == m_data.end())
                {
                    throw rsync_error { HANDLE_NOT_FOUND };
                }
                else
                {
                    const auto itTable = it->second.find(table);

                    if (itTable != it->second.end())
                    {
                        if (value < itTable->second)
                        {
                            itTable->second = value;
                        }

                        if (value > itTable->second)
                        {
                            logDebug2(RSYNC_LOG_TAG, "Sync id: %d is not the current id: %d for table: %s", value, itTable->second, table.c_str());
                            throw std::runtime_error { "Sync id is not the current id" };
                        }
                    }
                }
            }
        private:
            std::unordered_map<RSYNC_HANDLE, std::unordered_map<std::string, int32_t>> m_data;
            std::mutex m_mutex;
    };
} // namespace RSync
#endif // _SYNCHRONIZATION_CONTROLLER_HPP
