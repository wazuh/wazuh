/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_TESTS_COMPONENT_LOG_SINK_HPP
#define _INDEXER_CLIENT_TESTS_COMPONENT_LOG_SINK_HPP

// The process log function of a component case (shared by logSummary_test.cpp and bulkConflict_test.cpp): every line
// the library logs, formatted, with its level. Install it with indexer_client::setLogFunction(sink.function()) while
// no runtime runs and uninstall it (setLogFunction({})) after the runtime is down; the sink must outlive both.

#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

#include "indexer_client/runtime.hpp"

namespace log_component
{
    struct Line final
    {
        int level {0};
        std::string text;
    };

    /// The process log function of the case: every line, formatted, with its level.
    class Sink final
    {
    public:
        indexer_client::LogFunction function()
        {
            return
                [this](
                    const int level, const char*, const char*, const int, const char*, const char* format, va_list args)
            {
                va_list copy;
                va_copy(copy, args);
                char buffer[16384];
                std::vsnprintf(buffer, sizeof(buffer), format, copy);
                va_end(copy);
                std::lock_guard<std::mutex> lock(m_mutex);
                m_lines.push_back({level, buffer});
            };
        }

        std::size_t count(int level, const std::string& part) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::size_t n = 0;
            for (const auto& line : m_lines)
            {
                n += (line.level == level && line.text.find(part) != std::string::npos) ? 1 : 0;
            }
            return n;
        }

        /// Lines at `level` or above containing `part`.
        std::vector<Line> atLeast(int level, const std::string& part) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::vector<Line> out;
            for (const auto& line : m_lines)
            {
                if (line.level >= level && line.text.find(part) != std::string::npos)
                {
                    out.push_back(line);
                }
            }
            return out;
        }

        std::vector<Line> lines() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_lines;
        }

        std::string dump() const
        {
            std::string out;
            for (const auto& line : lines())
            {
                out += "\n[" + std::to_string(line.level) + "] " + line.text;
            }
            return out;
        }

    private:
        mutable std::mutex m_mutex;
        std::vector<Line> m_lines;
    };
} // namespace log_component

#endif // _INDEXER_CLIENT_TESTS_COMPONENT_LOG_SINK_HPP
