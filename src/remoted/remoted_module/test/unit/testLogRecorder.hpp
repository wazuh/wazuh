/*
 * Wazuh remoted module (C++ worker bridge) - shared test log recorder
 * Copyright (C) 2015, Wazuh Inc.
 * August 15, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_MODULE_TEST_LOG_RECORDER_HPP
#define _REMOTED_MODULE_TEST_LOG_RECORDER_HPP

// Process-wide recorder for the module's log output, SHARED by every test file that starts the
// module through the C-ABI (extracted from remotedModule_test.cpp when adminServer_test.cpp
// became the second such file).
//
// This is the ONLY way a test can observe what the module logs: Log::GLOBAL_LOG_FUNCTION is
// declared with hidden visibility and defined inside libremoted_module.so, so a definition in
// the test binary would be a different object entirely. Going through remoted_module_start()
// installs this callback into the library's own sink.
//
// Must be process-wide rather than per-test: Log::assignLogFunction() only assigns when the sink
// is still empty, and deassignLogFunction() is not reachable from here -- so the FIRST test to
// start the module wins for the lifetime of the process. That is exactly why the recorder lives
// in this shared header: every suite that starts the module passes the SAME testLogCallback, so
// whichever runs first installs it and every other suite's log assertions still hold.

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace remoted::test
{
    /// Total calls the module made into the log sink (any level).
    inline std::atomic<int> g_logCalls {0};

    struct LogRecorder
    {
        struct Line
        {
            int level;
            std::string tag;
            std::string message;
        };

        static std::mutex& mutex()
        {
            static std::mutex instance;
            return instance;
        }

        static std::vector<Line>& lines()
        {
            static std::vector<Line> instance;
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
                        if (line.message.find(needle) != std::string::npos)
                        {
                            return true;
                        }
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds {20});
            }
            return false;
        }
    };

    inline void testLogCallback(int level,
                                const char* tag,
                                const char* /*file*/,
                                int /*line*/,
                                const char* /*func*/,
                                const char* msg,
                                va_list args)
    {
        g_logCalls.fetch_add(1, std::memory_order_relaxed);

        // Render the message exactly as _log() would. A va_list may only be traversed once, so this
        // consumes it -- that is fine, nothing downstream of us needs it.
        char buffer[2048];
        if (msg != nullptr)
        {
            std::vsnprintf(buffer, sizeof(buffer), msg, args);
        }
        else
        {
            buffer[0] = '\0';
        }

        std::lock_guard<std::mutex> lock {LogRecorder::mutex()};
        LogRecorder::lines().push_back({level, tag != nullptr ? tag : "", buffer});
    }

} // namespace remoted::test

#endif // _REMOTED_MODULE_TEST_LOG_RECORDER_HPP
