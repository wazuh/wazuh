/*
 * Wazuh Indexer Connector - log capture helper for unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _SCOPED_LOG_CAPTURE_HPP
#define _SCOPED_LOG_CAPTURE_HPP

#include "loggerHelper.h"
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

// Captures the log lines written through the global log function while it is alive.
class ScopedLogCapture
{
public:
    ScopedLogCapture()
        : m_previous(Log::GLOBAL_LOG_FUNCTION)
    {
        // assignLogFunction() is a no-op when a function is already installed, so drop the current one first.
        Log::deassignLogFunction();
        Log::assignLogFunction(
            [this](const int level, const char*, const char*, const int, const char*, const char* format, va_list args)
            {
                char buffer[2048];
                va_list copy;
                va_copy(copy, args);
                vsnprintf(buffer, sizeof(buffer), format, copy);
                va_end(copy);
                std::scoped_lock lock(m_mutex);
                m_lines.push_back({level, buffer});
            });
    }

    ~ScopedLogCapture()
    {
        Log::deassignLogFunction();
        Log::assignLogFunction(m_previous);
    }

    ScopedLogCapture(const ScopedLogCapture&) = delete;
    ScopedLogCapture& operator=(const ScopedLogCapture&) = delete;

    bool contains(std::string_view needle) const
    {
        std::scoped_lock lock(m_mutex);
        return std::any_of(m_lines.begin(),
                           m_lines.end(),
                           [needle](const Line& line) { return line.text.find(needle) != std::string::npos; });
    }

    bool containsAtLevel(int level, std::string_view needle) const
    {
        std::scoped_lock lock(m_mutex);
        return std::any_of(m_lines.begin(),
                           m_lines.end(),
                           [level, needle](const Line& line)
                           { return line.level == level && line.text.find(needle) != std::string::npos; });
    }

    size_t countAtLevel(int level, std::string_view needle) const
    {
        std::scoped_lock lock(m_mutex);
        return static_cast<size_t>(
            std::count_if(m_lines.begin(),
                          m_lines.end(),
                          [level, needle](const Line& line)
                          { return line.level == level && line.text.find(needle) != std::string::npos; }));
    }

private:
    struct Line
    {
        int level;
        std::string text;
    };

    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)> m_previous;
    mutable std::mutex m_mutex;
    std::vector<Line> m_lines;
};

#endif // _SCOPED_LOG_CAPTURE_HPP
