/*
 * Wazuh Syscollector
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SCAN_ERROR_LOG_HPP
#define _SCAN_ERROR_LOG_HPP

#include <map>
#include <mutex>
#include <string>
#include "logging_helper.h"

/// @brief Log level of a failed scan task: an error repeated on every scan is logged as an
/// error once, then as debug, until the task succeeds or fails with another message.
class ScanErrorLog final
{
    public:
        /// @brief Records a failure of a task.
        /// @param task Name of the scan task.
        /// @param message Error message of this failure.
        /// @return LOG_ERROR for a new failure, LOG_DEBUG if it repeats the previous one.
        modules_log_level_t failed(const std::string& task, const std::string& message)
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            auto& last = m_lastErrors[task];
            const auto level = last == message ? LOG_DEBUG : LOG_ERROR;
            last = message;
            return level;
        }

        /// @brief Records a successful run of a task, so its next failure is logged as an error.
        /// @param task Name of the scan task.
        void succeeded(const std::string& task)
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_lastErrors.erase(task);
        }

    private:
        std::mutex m_mutex;
        std::map<std::string, std::string> m_lastErrors;
};

#endif // _SCAN_ERROR_LOG_HPP
