/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_MODULE_LOG_CAPTURE_HPP
#define _HC_MODULE_LOG_CAPTURE_HPP

#include "https_client.h"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// LOGLEVEL_WARNING / LOGLEVEL_DEBUG as the agent defines them (loggerHelper.h).
inline constexpr int WARNING_LEVEL {2};
inline constexpr int DEBUG_LEVEL {0};

/// The module's log lines while captureModuleLog() is the agent's log callback and a test records
/// them. A C log callback carries no user data, so they live here.
struct ModuleLog
{
    std::mutex mutex;
    std::vector<std::pair<int, std::string>> lines;
    std::atomic<bool> recording {false}; ///< The callback outlives the test: off between tests.
};

inline ModuleLog g_moduleLog;

inline void captureModuleLog(const int level, const char*, const char*, const int, const char*, const char* message,
                             va_list args)
{
    if (!g_moduleLog.recording.load())
    {
        return;
    }

    char line[1024];
    std::vsnprintf(line, sizeof(line), message, args);
    const std::lock_guard<std::mutex> lock(g_moduleLog.mutex);
    g_moduleLog.lines.emplace_back(level, line);
}

/// Points the module's log at captureModuleLog() through an hc_enroll() its transport check
/// rejects before any network I/O: the one entry point that installs a callback without a
/// running handle. The module keeps forwarding to it until another call installs another,
/// which is why recording is switched on only for the test.
inline void captureTheModuleLog()
{
    hc_config_t config {};
    std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
    config.server_port = 9;
    config.verify_mode = HC_VERIFY_FULL;
    hc_enroll_request_t request {};
    request.log = captureModuleLog;
    hc_enroll_result_t result {};
    hc_enroll(&config, &request, &result);

    g_moduleLog.recording.store(true); // After the enrollment's own rejection.
}

inline void stopCapturingTheModuleLog()
{
    g_moduleLog.recording.store(false);
    const std::lock_guard<std::mutex> lock(g_moduleLog.mutex);
    g_moduleLog.lines.clear();
}

/// The captured lines at `level` that contain `needle`.
inline std::vector<std::string> loggedAt(int level, const std::string& needle)
{
    const std::lock_guard<std::mutex> lock(g_moduleLog.mutex);
    std::vector<std::string> found;

    for (const auto& [lineLevel, text] : g_moduleLog.lines)
    {
        if (lineLevel == level && text.find(needle) != std::string::npos)
        {
            found.push_back(text);
        }
    }

    return found;
}

#endif // _HC_MODULE_LOG_CAPTURE_HPP
