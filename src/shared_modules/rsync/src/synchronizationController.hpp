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
            void set(const RSYNC_HANDLE key, const int32_t value)
            {
                std::lock_guard<std::shared_timed_mutex> lock{ mutex };
                data[key] = value;
            }

            int32_t get(const RSYNC_HANDLE key)
            {
                std::shared_lock<std::shared_timed_mutex> lock{ mutex };
                if (data.find(key) == data.end())
                {
                    throw rsync_error { HANDLE_NOT_FOUND };
                }
                return data[key];
            }
        private:
            std::unordered_map<RSYNC_HANDLE, int32_t> data;
            std::shared_timed_mutex mutex;
    };
} // namespace RSync
#endif // _SYNCHRONIZATION_CONTROLLER_HPP
