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

#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include "logging_helper.h"

/// @brief Log level of a failed scan task: an error repeated on every scan is logged as an
/// error once, then as debug, and as an error again once a day while it lasts, after the task
/// succeeds or when it fails with another message.
class ScanErrorLog final
{
    public:
        using Clock = std::chrono::steady_clock;

        /// @brief Time after which a repeated error is logged as an error again.
        static constexpr std::chrono::hours REMINDER_INTERVAL {24};

        /// @param now Source of the current time.
        explicit ScanErrorLog(std::function<Clock::time_point()> now = Clock::now)
            : m_now {std::move(now)}
        {
        }

        /// @brief Records a failure of a task.
        /// @param task Name of the scan task.
        /// @param message Error message of this failure.
        /// @return LOG_DEBUG if it repeats the error logged for the task less than
        /// REMINDER_INTERVAL ago, LOG_ERROR otherwise.
        modules_log_level_t failed(const std::string& task, const std::string& message)
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            const auto now {m_now()};
            const auto it {m_lastErrors.find(task)};

            if (it != m_lastErrors.end() && it->second.message == message && now - it->second.loggedAt < REMINDER_INTERVAL)
            {
                return LOG_DEBUG;
            }

            m_lastErrors[task] = {message, now};
            return LOG_ERROR;
        }

        /// @brief Records a successful run of a task, so its next failure is logged as an error.
        /// @param task Name of the scan task.
        void succeeded(const std::string& task)
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_lastErrors.erase(task);
        }

        /// @brief Forgets every logged error, so a restarted module logs them as errors again.
        void clear()
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_lastErrors.clear();
        }

    private:
        struct LoggedError
        {
            std::string message;
            Clock::time_point loggedAt;
        };

        std::function<Clock::time_point()> m_now;
        std::mutex m_mutex;
        std::map<std::string, LoggedError> m_lastErrors;
};

#endif // _SCAN_ERROR_LOG_HPP
