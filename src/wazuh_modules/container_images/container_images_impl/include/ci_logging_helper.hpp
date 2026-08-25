/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

// LCOV_EXCL_START

#ifdef __cplusplus
extern "C" {
#endif

#include "logging_helper.h"

#ifdef __cplusplus
} // extern "C"
#endif

#include <functional>
#include <string>

class LoggingHelper
{
    public:
        static LoggingHelper& getInstance()
        {
            static LoggingHelper instance;
            return instance;
        }

        static void setLogCallback(std::function<void(const modules_log_level_t level, const char* log)> callback)
        {
            getInstance().m_externalLogCallback = std::move(callback);
        }

        // Dropping the message is deliberate: every catch handler on the C boundary logs
        // through here, so throwing when no callback is set would take an exception out of
        // an extern "C" function and terminate the process.
        void log(const modules_log_level_t level, const std::string& message) const
        {
            if (m_externalLogCallback)
            {
                m_externalLogCallback(level, message.c_str());
            }
        }

    private:
        LoggingHelper() = default;

        LoggingHelper(const LoggingHelper&) = delete;
        LoggingHelper& operator=(const LoggingHelper&) = delete;
        LoggingHelper(LoggingHelper&&) = delete;
        LoggingHelper& operator=(LoggingHelper&&) = delete;

        std::function<void(const modules_log_level_t level, const char* log)> m_externalLogCallback;
};

// LCOV_EXCL_STOP
