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

namespace containerimages
{
/// @brief Routes the module's log lines to the C glue that owns the module tag.
///
/// Namespaced, and that matters beyond tidiness. This class began as a copy of the one in
/// the SCA module, under the same name in the global namespace, and both are header only,
/// so each module library exported the same weak symbols for it, the guard variable of the
/// function-local static included. Every reference then bound to whichever library
/// `wazuh-modulesd` happened to load first, and the loser's messages were emitted through
/// the winner's callback: container images lines appeared under the `sca` tag, or the
/// reverse, varying between restarts because both modules are loaded lazily.
///
/// The namespace gives this definition a distinct mangled name, so the two no longer
/// collide and each module keeps its own instance.
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
} // namespace containerimages

// Every call site says LoggingHelper::, and there is no reason for them to say otherwise:
// what had to change is the symbol the linker sees, not the name the code reads.
using containerimages::LoggingHelper;

// LCOV_EXCL_STOP
