/*
 * Wazuh shared UDS HTTP server library - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WAZUH_UDS_TEST_LOG_RECORDER_HPP
#define _WAZUH_UDS_TEST_LOG_RECORDER_HPP

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace wazuh::uds_http::test
{

    /**
     * @brief Process-wide recorder for the library's log output, SHARED across every test file in
     *        this test binary.
     *
     * The library is linked as a STATIC archive, so this binary is the DSO that owns
     * Log::GLOBAL_LOG_FUNCTION (per-DSO hidden visibility). testMain.cpp defines that symbol and
     * points it at testLogCallback below before any test runs -- no module bootstrap involved,
     * unlike the .so-linked consumers' test binaries.
     *
     * Still shared across every .cpp in this binary, not local to one test file: the sink is a
     * single process-wide function, so a per-file recorder would mean only one file's recorder
     * ever saw anything.
     */
    struct LogRecorder
    {
        static std::mutex& mutex()
        {
            static std::mutex instance;
            return instance;
        }

        static std::vector<std::string>& lines()
        {
            static std::vector<std::string> instance;
            return instance;
        }

        static void clear()
        {
            std::lock_guard<std::mutex> lock {mutex()};
            lines().clear();
        }

        /// Whether any recorded message contains @p needle. Polls, because the module logs from its
        /// own worker thread.
        static bool waitForMessageContaining(const std::string& needle,
                                             std::chrono::milliseconds timeout = std::chrono::seconds {5})
        {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (std::chrono::steady_clock::now() < deadline)
            {
                {
                    std::lock_guard<std::mutex> lock {mutex()};
                    for (const auto& line : lines())
                    {
                        if (line.find(needle) != std::string::npos)
                        {
                            return true;
                        }
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds {20});
            }
            return false;
        }

        static bool sawMessageContaining(const std::string& needle)
        {
            std::lock_guard<std::mutex> lock {mutex()};
            for (const auto& line : lines())
            {
                if (line.find(needle) != std::string::npos)
                {
                    return true;
                }
            }
            return false;
        }

        /// How many recorded messages contain @p needle. Needed to pin log CADENCE rather than mere
        /// presence -- e.g. that the first-attempt ERROR is emitted exactly once per incident, which
        /// is what keeps the escalation clock honest.
        static std::size_t countMessagesContaining(const std::string& needle)
        {
            std::lock_guard<std::mutex> lock {mutex()};
            std::size_t count {0};
            for (const auto& line : lines())
            {
                if (line.find(needle) != std::string::npos)
                {
                    ++count;
                }
            }
            return count;
        }
    };

    /// Shared count of every log callback invocation, process-wide (same reasoning as LogRecorder).
    inline std::atomic<int>& logCallCount()
    {
        static std::atomic<int> instance {0};
        return instance;
    }

    inline void testLogCallback(int /*level*/,
                                const char* /*tag*/,
                                const char* /*file*/,
                                int /*line*/,
                                const char* /*func*/,
                                const char* msg,
                                va_list args)
    {
        logCallCount().fetch_add(1, std::memory_order_relaxed);

        // Render exactly as the real logger would. A va_list may only be traversed once, so this
        // consumes it -- fine, nothing downstream of us needs it.
        char buffer[4096];
        if (msg != nullptr)
        {
            std::vsnprintf(buffer, sizeof(buffer), msg, args);
        }
        else
        {
            buffer[0] = '\0';
        }

        std::lock_guard<std::mutex> lock {LogRecorder::mutex()};
        LogRecorder::lines().emplace_back(buffer);
    }

} // namespace wazuh::uds_http::test

#endif // _WAZUH_UDS_TEST_LOG_RECORDER_HPP
